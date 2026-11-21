package store_test

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/adminnotice"
	"github.com/Kup1ng/CtrlZ-Panel/internal/closed"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// Tests of the lock order (P1 auth review, round 5, rule lock-order; spec 4.4;
// internal/lockrank). The static half is TestLockOrderRule in internal/lint; the
// ranks of the database functions are catalog check 21. These are the runtime
// half: a transaction that asks for a lock below one it holds is refused before
// the statement runs, and the writers that share rows do not deadlock in any
// interleaving of their statements.

var adminSeed = uuid.MustParse("00000000-0000-7000-8000-0000000000e1")

func TestLockOrderIsEnforcedAtRuntime(t *testing.T) {
	f := newFixture(t)
	super := f.superConn(t)
	tenant := f.db.Store(f.ctx, t, store.RoleTenant)
	admin := f.db.Store(f.ctx, t, store.RoleAdmin)
	session := f.seededSession(t, super, f.A.Tenant)

	t.Run("refresh insert after the session lock needs the user first", func(t *testing.T) {
		// The db-r4-1 shape: the session is held and the new refresh row wants a key
		// share on the user.
		err := tenant.WithTenant(f.ctx, f.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
			if _, _, err := tx.SessionByIDForUpdate(session); err != nil {
				return err
			}
			_, err := tx.RefreshCreate(store.NewRefresh{SessionID: session, UserID: f.A.User, FamilyID: uuid.New(), TokenHash: sha32(7), ExpiresAt: time.Now().Add(time.Hour)})
			return err
		})
		if !errors.Is(err, store.ErrLockOrder) {
			t.Fatalf("got %v, want ErrLockOrder", err)
		}
	})
	t.Run("the same with the user's key share first passes", func(t *testing.T) {
		err := tenant.WithTenant(f.ctx, f.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
			if _, err := tx.UserKeyShare(f.A.User); err != nil {
				return err
			}
			if _, _, err := tx.SessionByIDForUpdate(session); err != nil {
				return err
			}
			_, err := tx.RefreshCreate(store.NewRefresh{SessionID: session, UserID: f.A.User, FamilyID: uuid.New(), TokenHash: sha32(8), ExpiresAt: time.Now().Add(time.Hour)})
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	})
	t.Run("the user lock after a session write is refused", func(t *testing.T) {
		err := tenant.WithTenant(f.ctx, f.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
			if err := tx.SessionTouch(session, time.Now().Add(time.Hour), time.Now()); err != nil {
				return err
			}
			_, _, err := tx.UserLock(f.A.User)
			return err
		})
		if !errors.Is(err, store.ErrLockOrder) {
			t.Fatalf("got %v, want ErrLockOrder", err)
		}
	})
	t.Run("the audit lock before the admin rows is refused", func(t *testing.T) {
		// The mutant of PutSmsGateway: audit.Admin before noticeGatewayChange.
		err := admin.WithGlobal(f.ctx, store.TxOpts{}, func(g store.GlobalTx) error {
			if _, err := g.AuditAppend(store.AuditEntry{At: time.Now(), AdminID: adminSeed, Action: "sms.gateway.change", Canonical: []byte("x")}); err != nil {
				return err
			}
			_, err := g.AdminNoticeAppendAll(adminnotice.Notice{Kind: adminnotice.SMSGatewayChanged, At: time.Now()})
			return err
		})
		if !errors.Is(err, store.ErrLockOrder) {
			t.Fatalf("got %v, want ErrLockOrder", err)
		}
		// The refused statement did not run: no audit row is left.
		var n int
		if err := super.QueryRow(f.ctx, "SELECT count(*) FROM ctrlz.audit_log WHERE action = 'sms.gateway.change'").Scan(&n); err != nil || n != 0 {
			t.Fatalf("audit rows after a rolled back transaction: %d %v", n, err)
		}
	})
	t.Run("the right order passes", func(t *testing.T) {
		err := admin.WithGlobal(f.ctx, store.TxOpts{}, func(g store.GlobalTx) error {
			if _, err := g.AdminNoticeAppendAll(adminnotice.Notice{Kind: adminnotice.SMSGatewayChanged, At: time.Now()}); err != nil {
				return err
			}
			if _, err := g.SMSGatewaySetCredentials(uuid.MustParse("00000000-0000-7000-8000-0000000000f1"), []byte("ct"), "ab12"); err != nil {
				return err
			}
			_, err := g.AuditAppend(store.AuditEntry{At: time.Now(), AdminID: adminSeed, Action: "sms.gateway.change", Canonical: []byte("x")})
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	})
	t.Run("a refusal names tables and ranks and nothing else", func(t *testing.T) {
		err := tenant.WithTenant(f.ctx, f.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
			if err := tx.SessionTouch(session, time.Now().Add(time.Hour), time.Now()); err != nil {
				return err
			}
			_, _, err := tx.UserLock(f.A.User)
			return err
		})
		if err == nil {
			t.Fatal("no error")
		}
		const want = "store: lock order violated: lock order: users (rank 100) requested while holding sessions (rank 200)"
		if err.Error() != want {
			t.Fatalf("got %q", err.Error())
		}
	})
}

// A writer is one transaction of production code, spelled as the calls it makes
// in the order it makes them. step marks a point where another transaction may
// run: the race test stops the writer there, lets the other one go as far as it
// can, and resumes.
type writer struct {
	name string
	role store.Role
	// tenant writers run in WithTenant(f.A.Tenant); the others in WithGlobal.
	tenant bool
	run    func(e *env, tx store.Tx, g store.GlobalTx, step func()) error
}

type env struct {
	f              *fixture
	user           uuid.UUID
	session        uuid.UUID
	refresh        uuid.UUID
	family         uuid.UUID
	phoneRequest   uuid.UUID
	gateway, admin uuid.UUID
	seq            int
	mu             sync.Mutex
}

// hash is a token hash that was not used before in this run.
func (e *env) hash() []byte {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.seq++
	h := make([]byte, 32)
	binary.BigEndian.PutUint64(h, uint64(e.seq))
	h[31] = 0xAA
	return h
}

func tenantWriters() []writer {
	future := func() time.Time { return time.Now().Add(time.Hour) }
	return []writer{
		{"login", store.RoleTenant, true, func(e *env, tx store.Tx, _ store.GlobalTx, step func()) error {
			if _, _, err := tx.UserLock(e.user); err != nil {
				return err
			}
			step()
			if err := tx.MarkLogin(e.user); err != nil {
				return err
			}
			id, err := tx.SessionCreate(store.NewSession{At: time.Now(), UserID: e.user, TokenHash: e.hash(), IdleExpiresAt: future(), AbsoluteExpiresAt: future(), AuthMethod: "password"})
			if err != nil {
				return err
			}
			step()
			_, err = tx.RefreshCreate(store.NewRefresh{SessionID: id, UserID: e.user, FamilyID: uuid.New(), TokenHash: e.hash(), ExpiresAt: future()})
			return err
		}},
		{"refresh", store.RoleTenant, true, func(e *env, tx store.Tx, _ store.GlobalTx, step func()) error {
			if _, err := tx.UserKeyShare(e.user); err != nil {
				return err
			}
			step()
			sid, _, err := tx.RefreshSession(e.refresh)
			if err != nil {
				return err
			}
			if _, _, err := tx.SessionByIDForUpdate(sid); err != nil {
				return err
			}
			step()
			if _, err := tx.RefreshRotate(e.refresh, future(), time.Now()); err != nil {
				return err
			}
			if _, err := tx.SessionRefreshToken(sid, e.hash(), future(), time.Now()); err != nil {
				return err
			}
			step()
			_, err = tx.RefreshCreate(store.NewRefresh{SessionID: sid, UserID: e.user, FamilyID: e.family, TokenHash: e.hash(), ExpiresAt: future()})
			return err
		}},
		{"reauth", store.RoleTenant, true, func(e *env, tx store.Tx, _ store.GlobalTx, step func()) error {
			if _, _, err := tx.UserLock(e.user); err != nil {
				return err
			}
			step()
			if _, err := tx.SessionRotate(e.session, e.hash(), future(), store.ReauthSet, time.Now(), true); err != nil {
				return err
			}
			step()
			return tx.RefreshRevokeFamily(e.family)
		}},
		{"password change", store.RoleTenant, true, func(e *env, tx store.Tx, _ store.GlobalTx, step func()) error {
			if _, _, err := tx.UserLock(e.user); err != nil {
				return err
			}
			step()
			if _, err := tx.SetPassword(e.user, secret.New("hash")); err != nil {
				return err
			}
			if err := tx.TicketsRevoke(e.user); err != nil {
				return err
			}
			if _, err := tx.SessionsRevokeOthers(e.user, uuid.Nil, time.Now()); err != nil {
				return err
			}
			step()
			if _, err := tx.APITokensRevoke(e.user); err != nil {
				return err
			}
			return nil
		}},
		{"log out all", store.RoleTenant, true, func(e *env, tx store.Tx, _ store.GlobalTx, step func()) error {
			if err := tx.TicketsRevoke(e.user); err != nil {
				return err
			}
			if _, err := tx.SessionsRevokeOthers(e.user, uuid.Nil, time.Now()); err != nil {
				return err
			}
			step()
			if _, err := tx.APITokensRevoke(e.user); err != nil {
				return err
			}
			return nil
		}},
		{"refresh reuse", store.RoleTenant, true, func(e *env, tx store.Tx, _ store.GlobalTx, step func()) error {
			if err := tx.RefreshRevokeFamily(e.family); err != nil {
				return err
			}
			step()
			return tx.AuditAdd(store.TenantAudit{UserID: e.user, Action: "session.refresh_reuse", Params: []byte(`{}`), IP: netip.MustParseAddr("198.51.100.1")})
		}},
		{"admin re-issue", store.RoleAdmin, true, func(e *env, tx store.Tx, _ store.GlobalTx, step func()) error {
			if _, _, err := tx.OneTimePasswordLock(e.user); err != nil {
				return err
			}
			step()
			if _, err := tx.OneTimePasswordReissue(e.user, secret.New("hash")); err != nil {
				return err
			}
			step()
			if _, err := tx.RevokeUserSessions(e.user); err != nil {
				return err
			}
			_, err := tx.AdminAuditAppend(store.AuditEntry{At: time.Now(), AdminID: e.admin, Action: "user.reissue", Canonical: []byte("x")})
			return err
		}},
		{"phone change", store.RoleTenant, true, func(e *env, tx store.Tx, _ store.GlobalTx, step func()) error {
			step()
			_, err := tx.PhoneChangeComplete(e.phoneRequest)
			return err
		}},
		{"enroll authenticator", store.RoleTenant, true, func(e *env, tx store.Tx, _ store.GlobalTx, step func()) error {
			if _, _, err := tx.UserLock(e.user); err != nil {
				return err
			}
			step()
			if _, err := tx.TOTPSetPending(e.user, []byte("seed")); err != nil {
				return err
			}
			step()
			return tx.RecoveryCodesReplace(e.user, [][]byte{e.hash()})
		}},
		{"add passkey", store.RoleTenant, true, func(e *env, tx store.Tx, _ store.GlobalTx, step func()) error {
			if _, _, err := tx.UserLock(e.user); err != nil {
				return err
			}
			step()
			_, _, _, err := tx.PasskeyAdd(store.Credential{UserID: e.user, CredentialID: e.hash(), PublicKey: sha32(1), RPID: "example.test"}, 20)
			return err
		}},
	}
}

func globalWriters() []writer {
	notice := func() adminnotice.Notice {
		return adminnotice.Notice{Kind: adminnotice.SMSGatewayChanged, At: time.Now()}
	}
	audit := func(e *env, g store.GlobalTx) error {
		_, err := g.AuditAppend(store.AuditEntry{At: time.Now(), AdminID: e.admin, Action: "x", Canonical: []byte("x")})
		return err
	}
	return []writer{
		{"admin login", store.RoleAdmin, false, func(e *env, _ store.Tx, g store.GlobalTx, step func()) error {
			if _, _, err := g.AdminUserLockByID(e.admin); err != nil {
				return err
			}
			step()
			if err := g.AdminMarkLogin(e.admin); err != nil {
				return err
			}
			if _, err := g.AdminSessionCreate(store.NewAdminSession{AdminID: e.admin, TokenHash: e.hash(), IdleExpiresAt: time.Now().Add(time.Hour), AbsoluteExpiresAt: time.Now().Add(time.Hour), At: time.Now()}); err != nil {
				return err
			}
			step()
			return audit(e, g)
		}},
		{"gateway change", store.RoleAdmin, false, func(e *env, _ store.Tx, g store.GlobalTx, step func()) error {
			if _, err := g.AdminNoticeAppendAll(notice()); err != nil {
				return err
			}
			step()
			if _, err := g.SMSGatewaySetCredentials(e.gateway, []byte("ct"), "ab12"); err != nil {
				return err
			}
			step()
			return audit(e, g)
		}},
		{"notice ack", store.RoleAdmin, false, func(e *env, _ store.Tx, g store.GlobalTx, step func()) error {
			if _, _, err := g.AdminNoticeAck(e.admin, time.Now()); err != nil {
				return err
			}
			step()
			return audit(e, g)
		}},
		{"admin password change", store.RoleAdmin, false, func(e *env, _ store.Tx, g store.GlobalTx, step func()) error {
			if _, _, err := g.AdminUserLockByID(e.admin); err != nil {
				return err
			}
			step()
			if _, _, err := g.AdminSetPassword(e.admin, secret.New("hash")); err != nil {
				return err
			}
			if _, err := g.AdminSessionsRevokeOthers(e.admin, uuid.Nil); err != nil {
				return err
			}
			step()
			return audit(e, g)
		}},
		{"worker settles a code", store.RoleWorker, false, func(e *env, _ store.Tx, g store.GlobalTx, step func()) error {
			if _, err := g.OTPDeliveryClear(uuid.New()); err != nil {
				return err
			}
			step()
			if _, err := g.GatewayFailed(e.gateway, word("transient"), true); err != nil {
				return err
			}
			step()
			if err := g.CountersRefund(time.Now()); err != nil {
				return err
			}
			step()
			_, err := g.AlertOnce("warning", "sms_gateway", key(e.gateway.String()), closed.Params{})
			return err
		}},
		{"worker records an outbox send", store.RoleWorker, false, func(e *env, _ store.Tx, g store.GlobalTx, step func()) error {
			if _, err := g.OutboxFinish(uuid.New(), "sent", nil); err != nil {
				return err
			}
			step()
			if err := g.GatewayOK(e.gateway); err != nil {
				return err
			}
			step()
			return g.CountersAddCost("100")
		}},
	}
}

// halt is a writer's pause point. Both goroutines of a pair use it the same way.
type halt struct {
	at      int // stop at this step; negative never stops
	n       int
	reached chan struct{}
	resume  chan struct{}
	once    sync.Once
}

func (h *halt) step() {
	if h.at < 0 {
		return
	}
	if h.n == h.at {
		h.n++
		h.once.Do(func() { close(h.reached) })
		<-h.resume
		return
	}
	h.n++
}

// TestWritersOfSharedRowsNeverDeadlock runs every pair of the writers that share
// rows, with one of them stopped after each of its steps while the other runs as
// far as it can, and fails on a deadlock (SQLSTATE 40P01) or on a refused lock
// order. The cut points are the whole point: a pair that only races at random
// passes by luck. A new writer is one line in the lists above; a new store
// method needs no line, because the rank check refuses it at run time wherever
// it breaks the order.
func TestWritersOfSharedRowsNeverDeadlock(t *testing.T) {
	// The shared fixture context lasts two minutes; the pairs below take longer.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	f := newFixture(t)
	super := f.superConn(t)
	e := &env{f: f, user: f.A.User, session: f.seededSession(t, super, f.A.Tenant), admin: adminSeed, gateway: uuid.MustParse("00000000-0000-7000-8000-0000000000f1")}
	if err := super.QueryRow(ctx, "SELECT id, family_id FROM ctrlz.refresh_tokens WHERE tenant_id = $1", f.A.Tenant).Scan(&e.refresh, &e.family); err != nil {
		t.Fatal(err)
	}
	if err := super.QueryRow(ctx, "SELECT id FROM ctrlz.phone_change_requests WHERE tenant_id = $1", f.A.Tenant).Scan(&e.phoneRequest); err != nil {
		t.Fatal(err)
	}
	stores := map[store.Role]*store.Store{}
	for _, r := range []store.Role{store.RoleTenant, store.RoleAdmin, store.RoleWorker} {
		stores[r] = f.db.Store(ctx, t, r)
	}

	runOne := func(w writer, h *halt) error {
		s := stores[w.role]
		if w.tenant {
			return s.WithTenant(ctx, f.A.Tenant, store.TxOpts{}, func(tx store.Tx) error { return w.run(e, tx, store.GlobalTx{}, h.step) })
		}
		return s.WithGlobal(ctx, store.TxOpts{}, func(g store.GlobalTx) error { return w.run(e, store.Tx{}, g, h.step) })
	}

	// bad says whether an error is one the test is looking for. A writer may fail
	// for other reasons (a row it expected is gone after another writer revoked
	// it); that is the behaviour of the code and not a lock problem.
	bad := func(err error) bool {
		if errors.Is(err, store.ErrLockOrder) {
			return true
		}
		var se *store.Error
		return errors.As(err, &se) && se.SQLState() == "40P01"
	}

	// fresh gives the next run a live session and refresh token of its own. The
	// writers revoke and rotate them, and a revoked row is not locked by the next
	// writer's UPDATE, so a run on the rows of the last one would race nothing.
	fresh := func() {
		err := stores[store.RoleTenant].WithTenant(ctx, f.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
			if _, _, err := tx.UserLock(e.user); err != nil {
				return err
			}
			id, err := tx.SessionCreate(store.NewSession{At: time.Now(), UserID: e.user, TokenHash: e.hash(), RememberMe: true, IdleExpiresAt: time.Now().Add(time.Hour), AbsoluteExpiresAt: time.Now().Add(time.Hour), AuthMethod: "password"})
			if err != nil {
				return err
			}
			e.session, e.family = id, uuid.New()
			e.refresh, err = tx.RefreshCreate(store.NewRefresh{SessionID: id, UserID: e.user, FamilyID: e.family, TokenHash: e.hash(), ExpiresAt: time.Now().Add(time.Hour)})
			return err
		})
		if err != nil {
			t.Fatalf("fresh rows: %v", err)
		}
	}
	// runPair runs a to its cut, then b as far as it goes, then both to the end.
	runPair := func(t *testing.T, a, b writer, cut int) {
		fresh()
		ha := &halt{at: cut, reached: make(chan struct{}), resume: make(chan struct{})}
		hb := &halt{at: -1}
		errA := make(chan error, 1)
		errB := make(chan error, 1)
		go func() { errA <- runOne(a, ha) }()
		select {
		case <-ha.reached:
		case err := <-errA:
			// A finished before its cut: it has fewer steps than the cut.
			if bad(err) {
				t.Errorf("cut %d: %s: %v", cut, a.name, err)
			}
			return
		case <-time.After(20 * time.Second):
			t.Fatalf("cut %d: %s never reached its step", cut, a.name)
		}
		go func() { errB <- runOne(b, hb) }()
		// B runs as far as it can. Waiting for a row A holds is the normal case: A
		// is resumed, and both finish.
		var first, second chan error = errB, errA
		select {
		case err := <-errB:
			if bad(err) {
				t.Errorf("cut %d: %s: %v", cut, b.name, err)
			}
			first = nil
		case <-time.After(250 * time.Millisecond):
		}
		close(ha.resume)
		for _, c := range []chan error{first, second} {
			if c == nil {
				continue
			}
			select {
			case err := <-c:
				if bad(err) {
					t.Errorf("cut %d: %s with %s: %v", cut, a.name, b.name, err)
				}
			case <-time.After(30 * time.Second):
				t.Fatalf("cut %d: %s and %s did not finish (a deadlock the server did not break)", cut, a.name, b.name)
			}
		}
	}
	pairs := func(list []writer) {
		for i := range list {
			for j := i; j < len(list); j++ {
				a, b := list[i], list[j]
				t.Run(a.name+" with "+b.name, func(t *testing.T) {
					for cut := 0; cut < 4; cut++ {
						runPair(t, a, b, cut)
						runPair(t, b, a, cut)
					}
				})
			}
		}
	}
	pairs(tenantWriters())
	pairs(globalWriters())
}
