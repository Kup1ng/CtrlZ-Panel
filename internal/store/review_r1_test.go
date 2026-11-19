package store_test

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/credgen"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// Tests added by the P1 auth Full review, round 1, area "database, roles and
// store" (findings db-r1-1, 3, 4, 5, 6, 7, 8).

// TestUserLockSeesTheUsersOwnPasswordChange is db-r1-1 and db-r1-7 at the store
// level, rewritten for the credential generation (rule credential-generation). A
// user's own change (SetPassword) moves neither must_reset nor password_expires_at
// for an ordinary user, which is how the field-by-field comparison missed it. Now the
// login row the password was verified against carries a stamp, UserLockFor compares it
// by generation and subject, and a rehash is a write that carries the stamp too.
func TestUserLockSeesTheUsersOwnPasswordChange(t *testing.T) {
	f := newFixture(t)
	s := f.db.Store(f.ctx, t, store.RoleTenant)
	super := f.superConn(t)
	// The seeded user has never changed a password through the app.
	if _, err := super.Exec(f.ctx, "UPDATE ctrlz.users SET password_changed_at = NULL, must_reset = false, password_expires_at = NULL WHERE id IN ($1, $2)", f.A.User, f.B.User); err != nil {
		t.Fatal(err)
	}
	login, ok, err := s.Auth().UserByPhone(f.ctx, f.A.Phone)
	if err != nil || !ok {
		t.Fatal(ok, err)
	}
	if login.Cred.Zero() || login.Cred.Subject != f.A.User || login.Cred.Tenant != f.A.Tenant {
		t.Fatalf("UserByPhone stamp: %+v", login.Cred)
	}
	lockFor := func(tenant, user uuid.UUID, issued credgen.Stamp) (l store.UserLock, found bool, err error) {
		f.inTenant(t, s, tenant, func(tx store.Tx) {
			l, found, err = tx.UserLockFor(user, issued)
		})
		return l, found, err
	}
	if l, ok, err := lockFor(f.A.Tenant, f.A.User, login.Cred); err != nil || !ok || l.Cred != login.Cred {
		t.Fatalf("UserLockFor right after the read: %+v %v %v", l, ok, err)
	}

	// A rehash carries the stamp, writes password_hash and so moves the generation; it
	// hands back the stamp that is current now.
	var rehashed credgen.Stamp
	f.inTenant(t, s, f.A.Tenant, func(tx store.Tx) {
		var err error
		if rehashed, err = tx.RehashPassword(login.Cred, secret.New("rehashed")); err != nil {
			t.Fatal(err)
		}
	})
	if rehashed.Gen != login.Cred.Gen+1 || rehashed.Subject != login.Cred.Subject {
		t.Fatalf("rehash returned %+v from %+v", rehashed, login.Cred)
	}
	// The password that was verified is no longer the stored one: its stamp is refused,
	// and a second rehash with it writes nothing.
	if _, _, err := lockFor(f.A.Tenant, f.A.User, login.Cred); !errors.Is(err, credgen.ErrStale) {
		t.Fatalf("a stamp from before the rehash: %v", err)
	}
	f.inTenant(t, s, f.A.Tenant, func(tx store.Tx) {
		if _, err := tx.RehashPassword(login.Cred, secret.New("rehashed-again")); !errors.Is(err, credgen.ErrStale) {
			t.Errorf("a rehash with a stale stamp: %v", err)
		}
	})

	// The user's own change leaves must_reset and the expiry as they were: only the
	// generation shows it.
	f.inTenant(t, s, f.A.Tenant, func(tx store.Tx) {
		if ok, err := tx.SetPassword(f.A.User, secret.New("hash-2")); err != nil || !ok {
			t.Fatal(ok, err)
		}
	})
	l, _, err := lockFor(f.A.Tenant, f.A.User, rehashed)
	_ = l
	if !errors.Is(err, credgen.ErrStale) {
		t.Fatalf("a stamp from before the user's own change: %v", err)
	}
	after, _, err := s.Auth().UserByPhone(f.ctx, f.A.Phone)
	if err != nil {
		t.Fatal(err)
	}
	if after.Cred.Gen != rehashed.Gen+1 {
		t.Fatalf("SetPassword moved the generation from %d to %d, want one step", rehashed.Gen, after.Cred.Gen)
	}
	if _, ok, err := lockFor(f.A.Tenant, f.A.User, after.Cred); err != nil || !ok {
		t.Fatalf("the stamp read after the change is current: %v %v", ok, err)
	}

	// Two tenants: B's user is untouched, B's transaction cannot lock A's row, and A's
	// stamp is no good in B's tenant.
	bLogin, _, err := s.Auth().UserByPhone(f.ctx, f.B.Phone)
	if err != nil {
		t.Fatal(err)
	}
	if bLogin.Cred.Gen != 1 {
		t.Errorf("A's changes moved B's generation to %d", bLogin.Cred.Gen)
	}
	if _, ok, err := lockFor(f.B.Tenant, f.A.User, after.Cred); err != nil || ok {
		t.Errorf("B locked A's user row: %v %v", ok, err)
	}
	if _, _, err := lockFor(f.B.Tenant, f.B.User, after.Cred); !errors.Is(err, credgen.ErrStale) {
		t.Errorf("A's stamp held for B's user: %v", err)
	}
	f.inTenant(t, s, f.B.Tenant, func(tx store.Tx) {
		if _, err := tx.RehashPassword(after.Cred, secret.New("x")); !errors.Is(err, credgen.ErrStale) {
			t.Errorf("B's transaction rehashed with A's stamp: %v", err)
		}
	})
}

// TestOneConnectionPerRequest is db-r1-6, db-r1-8, tenant-r1-1, tenant-r1-7, tenant-r1-11,
// db-r2-3, db-r2-6 and db-r3-3 as one rule (P1 auth review, round 5): a request holds at
// most one database connection at any moment. The handlers used to call store.Auth() from
// inside a WithTenant callback (a ticket put while the user row is locked, a throttle hit);
// each call held a connection and asked for another, so as many parallel requests as the
// pool has connections waited for each other until the acquire timeout. The first fix was
// a second pool, which doubled every role's footprint. There is no second pool now: a
// single-statement call refuses the context of an open transaction, and what must happen
// during one is a method of the transaction.
func TestOneConnectionPerRequest(t *testing.T) {
	f := newFixture(t)
	cfg := f.db.StoreConfig(store.RoleTenant)
	cfg.MaxConns = 4
	cfg.AcquireTimeout = 4 * time.Second
	s, err := store.Open(f.ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	pool := int(cfg.MaxConns)

	// run starts n requests; the first pool-many wait for each other inside their
	// transaction, so together they hold every connection of the pool when the body
	// does its work. A body that asks the pool for anything waits for ever.
	run := func(t *testing.T, n int, body func(tx store.Tx, i int) error) {
		t.Helper()
		var inside sync.WaitGroup
		inside.Add(pool)
		var wg sync.WaitGroup
		errs := make(chan error, n)
		start := time.Now()
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				errs <- s.WithTenant(f.ctx, f.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
					if i < pool {
						inside.Done()
						inside.Wait()
					}
					return body(tx, i)
				})
			}(i)
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Errorf("a request failed after %v: %v", time.Since(start).Round(time.Millisecond), err)
			}
		}
	}

	t.Run("a ticket put on the transaction's connection while the user row is locked", func(t *testing.T) {
		run(t, 2*pool, func(tx store.Tx, i int) error {
			if _, ok, err := tx.UserLock(f.A.User); err != nil || !ok {
				return errors.Join(err, errors.New("no lock"))
			}
			_, ok, err := tx.TicketPut(store.NewTicket{TokenHash: sha32(byte(60 + i)), Kind: store.TicketMFA,
				Tenant: f.A.Tenant, User: f.A.User, FirstFactor: "password", TTL: time.Minute,
				Cred: credgen.Stamp{Tenant: f.A.Tenant, Subject: f.A.User, Gen: 1}})
			if err == nil && !ok {
				err = errors.New("the ticket was refused")
			}
			return err
		})
	})

	t.Run("every single-statement call refuses the context of a transaction", func(t *testing.T) {
		admin := f.db.Store(f.ctx, t, store.RoleAdmin)
		examined := 0
		check := func(t *testing.T, name string, calls any, ctx context.Context) {
			rv := reflect.ValueOf(calls)
			ctxType := reflect.TypeOf((*context.Context)(nil)).Elem()
			errType := reflect.TypeOf((*error)(nil)).Elem()
			for i := 0; i < rv.NumMethod(); i++ {
				m, mt := rv.Type().Method(i), rv.Method(i).Type()
				if mt.NumIn() == 0 || mt.In(0) != ctxType {
					t.Errorf("%s.%s takes no context first: a call that cannot be given the transaction's context cannot be refused", name, m.Name)
					continue
				}
				args := []reflect.Value{reflect.ValueOf(ctx)}
				for j := 1; j < mt.NumIn(); j++ {
					args = append(args, reflect.Zero(mt.In(j)))
				}
				out := rv.Method(i).Call(args)
				var err error
				for _, o := range out {
					if o.Type() == errType && !o.IsNil() {
						err = o.Interface().(error)
					}
				}
				if !errors.Is(err, store.ErrNested) {
					t.Errorf("%s.%s inside a transaction returned %v, want ErrNested", name, m.Name, err)
				}
				examined++
			}
		}
		if err := s.WithTenant(f.ctx, f.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
			check(t, "AuthLookups", s.Auth(), tx.Context())
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if err := admin.WithGlobal(f.ctx, store.TxOpts{}, func(g store.GlobalTx) error {
			check(t, "AdminFns", admin.Admin(), g.Context())
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		// The list is read from the types, so a method added tomorrow is covered the day it
		// exists; this only guards against the reflection looking at nothing.
		if examined < 20 {
			t.Fatalf("only %d single-statement calls were examined", examined)
		}
	})

	t.Run("a nested call returns at once and the pool is untouched", func(t *testing.T) {
		start := time.Now()
		if err := s.WithTenant(f.ctx, f.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
			_, err := s.Auth().ThrottleHit(tx.Context(), "login_phone", sha32(40), 5, time.Minute)
			if !errors.Is(err, store.ErrNested) {
				t.Errorf("ThrottleHit inside a transaction returned %v", err)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if d := time.Since(start); d > 2*time.Second {
			t.Errorf("a refused call took %v", d)
		}
	})

	t.Run("a ticket put or taken in a transaction ends with it", func(t *testing.T) {
		a := s.Auth()
		h := sha32(90)
		stamp := credgen.Stamp{Tenant: f.A.Tenant, Subject: f.A.User, Gen: 1}
		boom := errors.New("later failure")
		// A put that is rolled back leaves no ticket.
		err := s.WithTenant(f.ctx, f.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
			if _, ok, err := tx.TicketPut(store.NewTicket{TokenHash: h, Kind: store.TicketMFA, Tenant: f.A.Tenant, User: f.A.User, TTL: time.Minute, Cred: stamp}); err != nil || !ok {
				return errors.Join(err, errors.New("put refused"))
			}
			return boom
		})
		if !errors.Is(err, boom) {
			t.Fatalf("rollback: %v", err)
		}
		if _, ok, err := a.TicketPeek(f.ctx, h, store.TicketMFA); err != nil || ok {
			t.Errorf("a ticket put in a rolled-back transaction can be read: %v %v", ok, err)
		}
		// A put that commits can be taken; a take that is rolled back does not burn it (tenant-r1-1).
		if err := s.WithTenant(f.ctx, f.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
			_, _, err := tx.TicketPut(store.NewTicket{TokenHash: h, Kind: store.TicketMFA, Tenant: f.A.Tenant, User: f.A.User, TTL: time.Minute, Cred: stamp})
			return err
		}); err != nil {
			t.Fatal(err)
		}
		err = s.WithTenant(f.ctx, f.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
			if _, w, err := tx.TicketTake(h, store.TicketMFA); err != nil || !w.Yes() {
				return errors.Join(err, errors.New("take lost"))
			}
			return boom
		})
		if !errors.Is(err, boom) {
			t.Fatalf("rollback: %v", err)
		}
		if err := s.WithTenant(f.ctx, f.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
			tk, w, err := tx.TicketTake(h, store.TicketMFA)
			if err != nil || !w.Yes() {
				return errors.Join(err, errors.New("a take that was rolled back burned the ticket"))
			}
			if tk.User != f.A.User || tk.Cred != stamp {
				t.Errorf("the ticket came back as %+v", tk)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if _, w, err := a.TicketTake(f.ctx, h, store.TicketMFA); err != nil || w.Yes() {
			t.Errorf("a ticket taken twice: %v %v", w.Yes(), err)
		}
	})

	t.Run("a transaction of one tenant cannot put or take a ticket of another", func(t *testing.T) {
		a := s.Auth()
		h := sha32(91)
		if _, ok, err := a.TicketPut(f.ctx, store.NewTicket{TokenHash: h, Kind: store.TicketReset, Tenant: f.A.Tenant, User: f.A.User, TTL: time.Minute}); err != nil || !ok {
			t.Fatalf("put: %v %v", ok, err)
		}
		err := s.WithTenant(f.ctx, f.B.Tenant, store.TxOpts{}, func(tx store.Tx) error {
			_, _, err := tx.TicketTake(h, store.TicketReset)
			return err
		})
		if !errors.Is(err, store.ErrConstraint) {
			t.Errorf("B's transaction took A's ticket: %v", err)
		}
		// The refusal ended the transaction, so A's ticket was not spent by it.
		if _, w, err := a.TicketTake(f.ctx, h, store.TicketReset); err != nil || !w.Yes() {
			t.Errorf("A's ticket was burned by B's refused take: %v %v", w.Yes(), err)
		}
		err = s.WithTenant(f.ctx, f.B.Tenant, store.TxOpts{}, func(tx store.Tx) error {
			_, _, err := tx.TicketPut(store.NewTicket{TokenHash: sha32(92), Kind: store.TicketReset, Tenant: f.A.Tenant, User: f.A.User, TTL: time.Minute})
			return err
		})
		if !errors.Is(err, store.ErrConstraint) {
			t.Errorf("B's transaction put a ticket for A: %v", err)
		}
	})
}

// TestTicketsAndThrottleHonourTime is db-r1-3. Every other ticket test uses a
// ticket that is five minutes from its end, and none drives the throttle past
// its window, so removing the expiry predicate or inverting the window
// comparison left the suite green.
func TestTicketsAndThrottleHonourTime(t *testing.T) {
	f := newFixture(t)
	s := f.db.Store(f.ctx, t, store.RoleTenant)
	a := s.Auth()
	super := f.superConn(t)

	t.Run("expired tickets", func(t *testing.T) {
		put := func(n byte) []byte {
			h := sha32(n)
			if _, ok, err := a.TicketPut(f.ctx, store.NewTicket{TokenHash: h, Kind: store.TicketMFA, Tenant: f.A.Tenant, User: f.A.User,
				FirstFactor: "password", TTL: 5 * time.Minute}); err != nil || !ok {
				t.Fatal(ok, err)
			}
			return h
		}
		expire := func(h []byte) {
			// Both columns move back, because the table's CHECK ties expires_at to created_at.
			if _, err := super.Exec(f.ctx, `UPDATE ctrlz.auth_tickets SET created_at = now() - interval '10 minutes',
  expires_at = now() - interval '1 second' WHERE token_hash = $1`, h); err != nil {
				t.Fatal(err)
			}
		}
		peeked, taken, control := put(111), put(112), put(113)
		expire(peeked)
		expire(taken)
		if _, ok, err := a.TicketPeek(f.ctx, peeked, store.TicketMFA); err != nil || ok {
			t.Errorf("an expired ticket was peeked: %v %v", ok, err)
		}
		if _, ok, err := a.TicketTake(f.ctx, taken, store.TicketMFA); err != nil || ok.Yes() {
			t.Errorf("an expired ticket was taken: %v %v", ok, err)
		}
		var consumed *time.Time
		if err := super.QueryRow(f.ctx, "SELECT consumed_at FROM ctrlz.auth_tickets WHERE token_hash = $1", taken).Scan(&consumed); err != nil || consumed != nil {
			t.Errorf("a refused take still consumed the ticket: %v %v", consumed, err)
		}
		// The control: an unexpired ticket of the same kind is served.
		if _, ok, err := a.TicketTake(f.ctx, control, store.TicketMFA); err != nil || !ok.Yes() {
			t.Errorf("the control ticket: %v %v", ok, err)
		}
		// Five peeks spend the attempts; the sixth finds nothing.
		five := put(114)
		for i := 0; i < 5; i++ {
			if _, ok, _ := a.TicketPeek(f.ctx, five, store.TicketMFA); !ok {
				t.Fatalf("peek %d found nothing", i+1)
			}
		}
		if _, ok, _ := a.TicketPeek(f.ctx, five, store.TicketMFA); ok {
			t.Error("a sixth peek found the ticket")
		}
	})

	t.Run("throttle window", func(t *testing.T) {
		const scope, max, window = "login_phone", 2, time.Minute
		key, other := sha32(21), sha32(22)
		hit := func(k []byte) store.ThrottleResult {
			t.Helper()
			r, err := a.ThrottleHit(f.ctx, scope, k, max, window)
			if err != nil {
				t.Fatal(err)
			}
			return r
		}
		countOf := func(k []byte) (n int) {
			if err := super.QueryRow(f.ctx, "SELECT count FROM ctrlz.auth_throttle WHERE scope = $1 AND key = $2", scope, k).Scan(&n); err != nil {
				t.Fatal(err)
			}
			return n
		}
		age := func(k []byte, by string) {
			if _, err := super.Exec(f.ctx, "UPDATE ctrlz.auth_throttle SET window_start = now() - $3::interval WHERE scope = $1 AND key = $2", scope, k, by); err != nil {
				t.Fatal(err)
			}
		}

		for i := 1; i <= max; i++ {
			if r := hit(key); !r.Allowed {
				t.Fatalf("hit %d refused", i)
			}
		}
		r := hit(key)
		if r.Allowed || r.RetryAfter < time.Second || r.RetryAfter > window {
			t.Fatalf("hit over the cap: %+v", r)
		}
		// Late in the window the wait is short but never zero.
		age(key, "59 seconds 500 milliseconds")
		if r := hit(key); r.Allowed || r.RetryAfter != time.Second {
			t.Errorf("hit at the end of the window: %+v", r)
		}
		if r := hit(other); !r.Allowed || countOf(other) != 1 {
			t.Errorf("another key was counted with the first: %+v", r)
		}

		// Past the window the key starts again at one.
		age(key, "61 seconds")
		if r := hit(key); !r.Allowed || countOf(key) != 1 {
			t.Fatalf("a hit after the window: %+v, count %d", r, countOf(key))
		}
		// A reset followed by a hit starts from one, and a key that was not reset is untouched.
		if err := a.ThrottleReset(f.ctx, scope, key); err != nil {
			t.Fatal(err)
		}
		if countOf(key) != 0 || countOf(other) != 1 {
			t.Fatalf("reset: key %d, other %d", countOf(key), countOf(other))
		}
		if r := hit(key); !r.Allowed || countOf(key) != 1 {
			t.Fatalf("a hit after the reset: %+v, count %d", r, countOf(key))
		}
	})
}

// TestPhoneMarkVerifiedRefusesEverythingButOwnLoginOrResetOTP is db-r1-4. Only a
// login or reset OTP for the user's own number, consumed in the last ten
// minutes, verifies a phone. Each branch of that rule gets a case that must
// answer invalid and leave the phone unverified, with the right OTP as control.
func TestPhoneMarkVerifiedRefusesEverythingButOwnLoginOrResetOTP(t *testing.T) {
	f := newFixture(t)
	s := f.db.Store(f.ctx, t, store.RoleTenant)
	super := f.superConn(t)
	unverify := func(user uuid.UUID) {
		if _, err := super.Exec(f.ctx, "UPDATE ctrlz.users SET phone_verified_at = NULL WHERE id = $1", user); err != nil {
			t.Fatal(err)
		}
	}
	otp := func(phone, purpose, consumed string) uuid.UUID {
		id := uuid.Must(uuid.NewV7())
		q := `INSERT INTO ctrlz.otp_challenges (id, phone_e164, purpose, code_hash, expires_at, consumed_at)
VALUES ($1, $2, $3, '\x01', now() + interval '5 minutes', ` + consumed + `)`
		if _, err := super.Exec(f.ctx, q, id, phone, purpose); err != nil {
			t.Fatal(err)
		}
		return id
	}
	verified := func(user uuid.UUID) (v bool) {
		if err := super.QueryRow(f.ctx, "SELECT phone_verified_at IS NOT NULL FROM ctrlz.users WHERE id = $1", user).Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	try := func(tenant, user, id uuid.UUID) (out string) {
		f.inTenant(t, s, tenant, func(tx store.Tx) {
			var err error
			if out, err = tx.PhoneMarkVerified(user, id); err != nil {
				t.Fatal(err)
			}
		})
		return out
	}
	unverify(f.A.User)
	unverify(f.B.User)

	signup := otp(f.A.Phone, "signup", "now()")
	cases := []struct {
		name string
		id   uuid.UUID
	}{
		{"purpose signup", signup},
		{"purpose invite", otp(f.A.Phone, "invite", "now()")},
		{"purpose phone_old", otp(f.A.Phone, "phone_old", "now()")},
		{"purpose phone_new", otp(f.A.Phone, "phone_new", "now()")},
		{"another number", otp(f.B.Phone, "login", "now()")},
		{"not consumed", otp(f.A.Phone, "login", "NULL")},
		{"no such challenge", uuid.Must(uuid.NewV7())},
	}
	for _, c := range cases {
		if out := try(f.A.Tenant, f.A.User, c.id); out != "invalid" || verified(f.A.User) {
			t.Errorf("%s: outcome %q, verified %v", c.name, out, verified(f.A.User))
		}
	}
	// A code for this phone that is too old to mark it verified is not invalid but stale (a reset
	// ticket outlives ten minutes and goes on); the phone stays unverified.
	if out := try(f.A.Tenant, f.A.User, otp(f.A.Phone, "login", "now() - interval '11 minutes'")); out != "stale" || verified(f.A.User) {
		t.Errorf("consumed eleven minutes ago: outcome %q, verified %v", out, verified(f.A.User))
	}
	// Tenant B's transaction with A's user id and A's valid OTP: not B's user, nothing verified.
	own := otp(f.A.Phone, "login", "now() - interval '9 minutes'")
	if out := try(f.B.Tenant, f.A.User, own); out != "invalid" || verified(f.A.User) {
		t.Errorf("another tenant's transaction: %q, verified %v", out, verified(f.A.User))
	}
	// Control: the user's own login OTP (and a reset one) verify.
	if out := try(f.A.Tenant, f.A.User, own); out != "ok" || !verified(f.A.User) {
		t.Errorf("own login OTP: %q, verified %v", out, verified(f.A.User))
	}
	if out := try(f.B.Tenant, f.B.User, otp(f.B.Phone, "reset", "now()")); out != "ok" || !verified(f.B.User) {
		t.Errorf("own reset OTP: %q, verified %v", out, verified(f.B.User))
	}
	// An already verified phone answers ok for its own login or reset code and for nothing else
	// (db-r6-7): the shortcut used to come before the code was looked at, so a code for a number
	// the user had left (a phone change moves phone_e164 and keeps the phone verified) opened a
	// session and a reset ticket after the change.
	for name, id := range map[string]uuid.UUID{
		"already verified, purpose signup":    signup,
		"already verified, another number":    otp(f.B.Phone, "login", "now()"),
		"already verified, not consumed":      otp(f.A.Phone, "login", "NULL"),
		"already verified, no such challenge": uuid.Must(uuid.NewV7()),
	} {
		if out := try(f.A.Tenant, f.A.User, id); out != "invalid" {
			t.Errorf("%s: %q", name, out)
		}
	}
	if out := try(f.A.Tenant, f.A.User, otp(f.A.Phone, "login", "now() - interval '30 minutes'")); out != "ok" {
		t.Errorf("already verified, own old login code: %q", out)
	}
	// The phone changes (it stays verified): the code for the number left behind proves nothing.
	left := otp(f.A.Phone, "login", "now()")
	if _, err := super.Exec(f.ctx, "UPDATE ctrlz.users SET phone_e164 = '+989129990077' WHERE id = $1", f.A.User); err != nil {
		t.Fatal(err)
	}
	if out := try(f.A.Tenant, f.A.User, left); out != "invalid" {
		t.Errorf("a code for the number the user left, after the phone change: %q (a login or a reset ticket would survive the change)", out)
	}
	if out := try(f.A.Tenant, f.A.User, otp("+989129990077", "login", "now()")); out != "ok" {
		t.Errorf("a code for the new number: %q", out)
	}
}

// TestConsumedOTPIsNeitherResentNorRefunded is db-r1-5. A worker that died after
// the provider accepted a code but before it cleared delivery_ct leaves a row the
// user has already consumed. It must not be claimed again (a second SMS costs
// money and tells the phone's holder about a login), and when the sweep ends it
// the keys must stay spent, because the message was delivered.
func TestConsumedOTPIsNeitherResentNorRefunded(t *testing.T) {
	f := newFixture(t)
	tenant := f.db.Store(f.ctx, t, store.RoleTenant)
	worker := f.db.Store(f.ctx, t, store.RoleWorker)
	super := f.superConn(t)
	ip := netip.MustParseAddr("198.51.100.79")
	if _, err := super.Exec(f.ctx, "DELETE FROM ctrlz.otp_challenges"); err != nil {
		t.Fatal(err)
	}
	const phone = "+989121110071"
	issued, err := tenant.Auth().OTPIssue(f.ctx, phone, "login", []byte{1}, []byte("sealed"), ip, false)
	if err != nil || !issued.Allowed {
		t.Fatal(issued, err)
	}
	live, err := tenant.Auth().OTPIssue(f.ctx, "+989121110072", "login", []byte{2}, []byte("sealed"), ip, false)
	if err != nil || !live.Allowed {
		t.Fatal(live, err)
	}
	count := func(p string) (n int) {
		if err := super.QueryRow(f.ctx, "SELECT COALESCE((SELECT count FROM ctrlz.sms_counters WHERE scope = 'phone' AND key = $1), 0)", p).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	global := func() (n int) {
		if err := super.QueryRow(f.ctx, "SELECT COALESCE((SELECT count FROM ctrlz.sms_counters WHERE scope = 'global' AND key = 'all' AND day = (now() AT TIME ZONE 'Asia/Tehran')::date), 0)").Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	// The user consumed the first code (the worker's record never came).
	if _, err := super.Exec(f.ctx, "UPDATE ctrlz.otp_challenges SET consumed_at = now() WHERE id = $1", issued.ID); err != nil {
		t.Fatal(err)
	}
	f.global(t, worker, func(g store.GlobalTx) {
		got, err := g.OTPClaim(10, 5)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0].ID != live.ID {
			t.Fatalf("claimed %+v: want only the unconsumed code", got)
		}
	})

	// The row ends: the code is cleared (nothing sealed is left), the keys stay spent.
	if _, err := super.Exec(f.ctx, "UPDATE ctrlz.otp_challenges SET expires_at = now() - interval '1 second', delivery_claimed_until = NULL WHERE id = $1", issued.ID); err != nil {
		t.Fatal(err)
	}
	f.global(t, worker, func(g store.GlobalTx) {
		if n, err := g.OTPExpireUndelivered(); err != nil || n != 0 {
			t.Errorf("a consumed row was refunded: %d %v", n, err)
		}
	})
	var sealed bool
	if err := super.QueryRow(f.ctx, "SELECT delivery_ct IS NOT NULL FROM ctrlz.otp_challenges WHERE id = $1", issued.ID).Scan(&sealed); err != nil || sealed {
		t.Errorf("the consumed row still holds its sealed code: %v %v", sealed, err)
	}
	if count(phone) != 1 || global() != 2 {
		t.Errorf("phone counter %d, global %d: the delivered message was given back", count(phone), global())
	}
	// The exhausted pass has the same rule.
	other, err := tenant.Auth().OTPIssue(f.ctx, "+989121110073", "login", []byte{3}, []byte("sealed"), ip, false)
	if err != nil || !other.Allowed {
		t.Fatal(other, err)
	}
	if _, err := super.Exec(f.ctx, "UPDATE ctrlz.otp_challenges SET consumed_at = now(), delivery_attempts = 5 WHERE id = $1", other.ID); err != nil {
		t.Fatal(err)
	}
	f.global(t, worker, func(g store.GlobalTx) {
		if n, err := g.OTPEndExhausted(5); err != nil || n != 0 {
			t.Errorf("a consumed exhausted row was refunded: %d %v", n, err)
		}
	})
	if count("+989121110073") != 1 || global() != 3 {
		t.Errorf("the exhausted pass gave back a delivered message (phone %d, global %d)", count("+989121110073"), global())
	}
	// Control: an unconsumed row that expires is refunded as before.
	if _, err := super.Exec(f.ctx, "UPDATE ctrlz.otp_challenges SET expires_at = now() - interval '1 second', delivery_claimed_until = NULL WHERE id = $1", live.ID); err != nil {
		t.Fatal(err)
	}
	f.global(t, worker, func(g store.GlobalTx) {
		if n, err := g.OTPExpireUndelivered(); err != nil || n != 1 {
			t.Errorf("the control row: %d %v", n, err)
		}
	})
	// The world-wide slot goes back; the phone's stays spent (sms-r6-1: a decoy is never refunded).
	if global() != 2 || count("+989121110072") != 1 {
		t.Errorf("an unconsumed expired row: global %d (want 2), phone %d (want 1)", global(), count("+989121110072"))
	}
}
