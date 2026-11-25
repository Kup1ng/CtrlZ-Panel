package store_test

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/credstate"
	"github.com/Kup1ng/CtrlZ-Panel/internal/credgen"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// Tests of the tenant-scoped SQL of P1 (tenant_auth.go) and of the lookups
// before a tenant is known. Every tenant-facing method gets the two-tenant
// test of the P0 rules: tenant B calls it with tenant A's ids, and A's rows are
// byte for byte what they were.

func (f *fixture) superConn(t *testing.T) *pgx.Conn {
	t.Helper()
	c, err := f.db.Super(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close(context.Background()) })
	return c
}

// inTenant runs fn in a transaction of the tenant and fails the test on error.
func (f *fixture) inTenant(t *testing.T, s *store.Store, tenant uuid.UUID, fn func(tx store.Tx)) {
	t.Helper()
	if err := s.WithTenant(f.ctx, tenant, store.TxOpts{}, func(tx store.Tx) error { fn(tx); return nil }); err != nil {
		t.Fatalf("WithTenant: %v", err)
	}
}

// snapshot is every auth-related row of a tenant as text, read as the
// superuser. Two snapshots are equal only if nothing changed, updated_at
// included.
func (f *fixture) snapshot(t *testing.T, c *pgx.Conn, tenant uuid.UUID) string {
	t.Helper()
	var out string
	err := c.QueryRow(f.ctx, `SELECT COALESCE(string_agg(x, E'\n' ORDER BY x), '') FROM (
  SELECT 'users ' || to_jsonb(u)::text AS x FROM ctrlz.users u WHERE tenant_id = $1
  UNION ALL SELECT 'sessions ' || to_jsonb(s)::text FROM ctrlz.sessions s WHERE tenant_id = $1
  UNION ALL SELECT 'refresh ' || to_jsonb(r)::text FROM ctrlz.refresh_tokens r WHERE tenant_id = $1
  UNION ALL SELECT 'recovery ' || to_jsonb(r)::text FROM ctrlz.recovery_codes r WHERE tenant_id = $1
  UNION ALL SELECT 'webauthn ' || to_jsonb(w)::text FROM ctrlz.webauthn_credentials w WHERE tenant_id = $1
  UNION ALL SELECT 'phone ' || to_jsonb(p)::text FROM ctrlz.phone_change_requests p WHERE tenant_id = $1
  UNION ALL SELECT 'notifications ' || to_jsonb(n)::text FROM ctrlz.notifications n WHERE tenant_id = $1
  UNION ALL SELECT 'audit ' || to_jsonb(a)::text FROM ctrlz.tenant_audit_log a WHERE tenant_id = $1
  UNION ALL SELECT 'api ' || to_jsonb(a)::text FROM ctrlz.api_tokens a WHERE tenant_id = $1
  UNION ALL SELECT 'tenant ' || to_jsonb(x)::text FROM ctrlz.tenants x WHERE id = $1
  UNION ALL SELECT 'reads ' || to_jsonb(x)::text FROM ctrlz.announcement_reads x WHERE tenant_id = $1
) q`, tenant).Scan(&out)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// seededSession returns the id of the session the seed made for a tenant.
func (f *fixture) seededSession(t *testing.T, c *pgx.Conn, tenant uuid.UUID) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := c.QueryRow(f.ctx, "SELECT id FROM ctrlz.sessions WHERE tenant_id = $1", tenant).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func hash(s string) []byte { return []byte(s) }

func TestAuthLookupsOfP1(t *testing.T) {
	f := newFixture(t)
	s := f.db.Store(f.ctx, t, store.RoleTenant)
	a := s.Auth()

	// The login row has the new fields, and the hash does not print.
	u, ok, err := a.UserByPhone(f.ctx, f.A.Phone)
	if err != nil || !ok {
		t.Fatalf("UserByPhone: %v %v", ok, err)
	}
	if u.EnforceLiftAt != nil || u.State != credstate.Ready || u.PasswordHash.IsZero() {
		t.Errorf("login row: %+v", u)
	}
	if out := fmt.Sprintf("%+v %v %#v", u, u, u); strings.Contains(out, "argon2id") {
		t.Errorf("a formatted UserLogin printed the hash: %s", out)
	}

	sess, ok, err := a.SessionByHash(f.ctx, hash(f.A.Session))
	if err != nil || !ok || sess.State != credstate.Ready || sess.ReauthAt != nil {
		t.Errorf("SessionByHash: %+v %v %v", sess, ok, err)
	}
	p, ok, err := a.PasskeyByCredential(f.ctx, hash(f.A.Passkey))
	if err != nil || !ok || p.BackupEligible || p.BackupState || p.AAGUID != nil || len(p.Transports) != 0 {
		t.Errorf("PasskeyByCredential: %+v %v %v", p, ok, err)
	}

	cfg, err := a.PublicConfig(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	// The seed has a noop gateway as primary, so SMS counts as available.
	if cfg.RegistrationMode != "closed" || cfg.PasskeyEnabled || !cfg.SMSAvailable || cfg.PanelHost != "" || cfg.RPID != "" {
		t.Errorf("PublicConfig: %+v", cfg)
	}

	// Tickets: put, peek spends attempts, take is single use, kinds do not mix.
	h := sha32(101)
	id, ok, err := a.TicketPut(f.ctx, store.NewTicket{TokenHash: h, Kind: store.TicketMFA, Tenant: f.A.Tenant, User: f.A.User,
		RememberMe: true, FirstFactor: "password", Payload: []byte("p"), TTL: 5 * time.Minute})
	if err != nil || !ok || id == uuid.Nil {
		t.Fatalf("TicketPut: %v %v %v", id, ok, err)
	}
	if _, ok, _ := a.TicketPeek(f.ctx, h, store.TicketReset); ok {
		t.Error("a ticket was peeked as another kind")
	}
	tk, ok, err := a.TicketPeek(f.ctx, h, store.TicketMFA)
	if err != nil || !ok || tk.Tenant != f.A.Tenant || tk.User != f.A.User || !tk.RememberMe || tk.FirstFactor != "password" || string(tk.Payload) != "p" {
		t.Errorf("TicketPeek: %+v %v %v", tk, ok, err)
	}
	if _, ok, _ := a.TicketTake(f.ctx, h, store.TicketMFA); !ok.Yes() {
		t.Error("TicketTake found nothing")
	}
	if _, ok, _ := a.TicketTake(f.ctx, h, store.TicketMFA); ok.Yes() {
		t.Error("a ticket was taken twice")
	}
	if _, ok, _ := a.TicketPeek(f.ctx, h, store.TicketMFA); ok {
		t.Error("a consumed ticket was peeked")
	}
	// A ticket with no subject (passkey_login) comes back with nil ids.
	h2 := sha32(102)
	if _, ok, err := a.TicketPut(f.ctx, store.NewTicket{TokenHash: h2, Kind: store.TicketPasskeyLogin, TTL: time.Minute}); err != nil || !ok {
		t.Fatalf("TicketPut without a subject: %v %v", ok, err)
	}
	if tk, ok, _ := a.TicketTake(f.ctx, h2, store.TicketPasskeyLogin); !ok.Yes() || tk.Tenant != uuid.Nil || tk.User != uuid.Nil {
		t.Errorf("subjectless ticket: %+v %v", tk, ok)
	}
	// A bad hash length is refused by the table, a missing lifetime by the function.
	if _, ok, _ := a.TicketPut(f.ctx, store.NewTicket{TokenHash: h, Kind: store.TicketMFA}); ok {
		t.Error("a ticket with no lifetime was stored")
	}

	// Throttle: five allowed, the sixth refused with a wait, reset starts again.
	key := sha32(103)
	for i := 1; i <= 6; i++ {
		r, err := a.ThrottleHit(f.ctx, "login_phone_net", key, 5, 15*time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if r.Allowed != (i <= 5) || (!r.Allowed && (r.RetryAfter <= 0 || r.RetryAfter > 15*time.Minute)) {
			t.Errorf("hit %d: %+v", i, r)
		}
	}
	if err := a.ThrottleReset(f.ctx, "login_phone_net", key); err != nil {
		t.Fatal(err)
	}
	if r, _ := a.ThrottleHit(f.ctx, "login_phone_net", key, 5, 15*time.Minute); !r.Allowed {
		t.Error("a hit after the reset was refused")
	}
	if r, _ := a.ThrottleHit(f.ctx, "admin_login", key, 5, 15*time.Minute); r.Allowed {
		t.Error("the user throttle accepted an admin scope")
	}

	// OTP: a known device passes the trusted flag through.
	iss, err := a.OTPIssue(f.ctx, "+989121234500", "login", []byte{1}, []byte{2}, netip.MustParseAddr("198.51.100.5"), true)
	if err != nil || !iss.Allowed {
		t.Fatalf("OTPIssue trusted: %+v %v", iss, err)
	}
}

func sha32(n byte) []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = n
	}
	return b
}

// TestTenantMethodsDoNotReachAnotherTenant is the two-tenant test of every
// method in tenant_auth.go and fn.go: tenant B holds A's ids and calls them all.
// None may find, change or create anything of A, and A's rows must be the same
// bytes afterwards.
func TestTenantMethodsDoNotReachAnotherTenant(t *testing.T) {
	f := newFixture(t)
	super := f.superConn(t)
	tenant := f.db.Store(f.ctx, t, store.RoleTenant)
	aSession := f.seededSession(t, super, f.A.Tenant)
	var aRefresh, aFamily, aPasskey, aNotification, aPhoneReq uuid.UUID
	for _, q := range []struct {
		sql  string
		dest []any
	}{
		{"SELECT id, family_id FROM ctrlz.refresh_tokens WHERE tenant_id = $1", []any{&aRefresh, &aFamily}},
		{"SELECT id FROM ctrlz.webauthn_credentials WHERE tenant_id = $1", []any{&aPasskey}},
		{"SELECT id FROM ctrlz.notifications WHERE tenant_id = $1", []any{&aNotification}},
		{"SELECT id FROM ctrlz.phone_change_requests WHERE tenant_id = $1", []any{&aPhoneReq}},
	} {
		if err := super.QueryRow(f.ctx, q.sql, f.A.Tenant).Scan(q.dest...); err != nil {
			t.Fatal(err)
		}
	}
	// A tenant-addressed announcement that only A may see, and a ticket of A.
	annA := uuid.Must(uuid.NewV7())
	if _, err := super.Exec(f.ctx, "INSERT INTO ctrlz.announcements (id, audience, tenant_id, body) VALUES ($1, 'tenant', $2, 'for A only')", annA, f.A.Tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := super.Exec(f.ctx, "INSERT INTO ctrlz.auth_tickets (token_hash, kind, subject_tenant, subject_user, expires_at) VALUES ($1, 'mfa', $2, $3, now() + interval '5 minutes')",
		sha32(109), f.A.Tenant, f.A.User); err != nil {
		t.Fatal(err)
	}

	before := f.snapshot(t, super, f.A.Tenant)
	now := time.Now()
	future := now.Add(time.Hour)
	notFoundErr := func(name string, err error) {
		t.Helper()
		if err == nil {
			t.Errorf("%s: expected a constraint error for a user of another tenant", name)
		} else if !errors.Is(err, store.ErrConstraint) {
			t.Errorf("%s: %v", name, err)
		}
	}
	f.inTenant(t, tenant, f.B.Tenant, func(tx store.Tx) {
		must := func(name string, err error) {
			t.Helper()
			// Every call is aimed at another tenant's row, so none holds a lock; the calls
			// are in no production order, and the lock order check would judge them as one
			// transaction.
			tx.ForgetLocks()
			if err != nil {
				t.Errorf("%s: %v", name, err)
			}
		}
		falsy := func(name string, ok bool, err error) {
			t.Helper()
			must(name, err)
			if ok {
				t.Errorf("%s reached tenant A's row", name)
			}
		}
		// Users.
		_, ok, err := tx.User(f.A.User)
		falsy("User", ok, err)
		_, ok, err = tx.UserLock(f.A.User)
		falsy("UserLock", ok, err)
		loc := "en"
		ok, err = tx.UpdatePreferences(f.A.User, store.Preferences{Locale: &loc})
		falsy("UpdatePreferences", ok, err)
		must("MarkLogin", tx.MarkLogin(f.A.User))
		ok, err = tx.SetPassword(f.A.User, secret.New("new-hash"))
		falsy("SetPassword", ok, err)
		if _, err := tx.RehashPassword(credgen.Stamp{Tenant: tx.TenantID(), Subject: f.A.User, Gen: 1}, secret.New("new-hash")); !errors.Is(err, credgen.ErrStale) {
			t.Errorf("RehashPassword reached tenant A's row: %v", err)
		}
		must("SetEnforce", tx.SetEnforce(f.A.User, true))
		_, ok, err = tx.DeferEnforceLift(f.A.User, time.Hour, time.Now())
		falsy("DeferEnforceLift", ok, err)
		must("ClearEnforceLift", tx.ClearEnforceLift(f.A.User))
		must("SetPasskeyReview", tx.SetPasskeyReview(f.A.User, true))
		_, ok, err = tx.UserFlags(f.A.User)
		falsy("UserFlags", ok, err)
		// TOTP and recovery codes.
		ok, err = tx.TOTPSetPending(f.A.User, []byte("x"))
		falsy("TOTPSetPending", ok, err)
		ok, err = tx.TOTPEnable(f.A.User)
		falsy("TOTPEnable", ok, err)
		must("TOTPClearPending", tx.TOTPClearPending(f.A.User))
		must("TOTPDisable", tx.TOTPDisable(f.A.User))
		sw, err := tx.TOTPStepAccept(f.A.User, 99)
		falsy("TOTPStepAccept", sw.Yes(), err)
		sw, err = tx.RecoveryCodeUse(f.A.User, []byte("rc1"))
		falsy("RecoveryCodeUse", sw.Yes(), err)
		// A user of another tenant is not a slot in this one: the cap statement counts and
		// inserts nothing, and says so as a loss rather than as an error (rule
		// caps-and-endings; it used to be a foreign key error).
		_, _, pw, err := tx.PasskeyAdd(store.Credential{UserID: f.A.User, CredentialID: hash("x3"), PublicKey: hash("pk"), RPID: "example.test"}, 20)
		falsy("PasskeyAdd", pw.Yes(), err)
		if n, err := tx.RecoveryCodesLeft(f.A.User); err != nil || n != 0 {
			t.Errorf("RecoveryCodesLeft: %d %v", n, err)
		}
		// Sessions.
		_, ok, err = tx.SessionByID(aSession)
		falsy("SessionByID", ok, err)
		if l, err := tx.SessionsList(f.A.User, time.Now()); err != nil || len(l) != 0 {
			t.Errorf("SessionsList: %d %v", len(l), err)
		}
		must("SessionTouch", tx.SessionTouch(aSession, future, time.Now()))
		ok, err = tx.SessionRotate(aSession, hash("rotated"), future, store.ReauthSet, time.Now(), true)
		falsy("SessionRotate", ok, err)
		ok, err = tx.SessionRefreshToken(aSession, hash("refreshed"), future, time.Now())
		falsy("SessionRefreshToken", ok, err)
		ok, err = tx.SessionRevoke(f.A.User, aSession)
		falsy("SessionRevoke", ok, err)
		if n, err := tx.SessionsRevokeOthers(f.A.User, uuid.Nil, time.Now()); err != nil || n != 0 {
			t.Errorf("SessionsRevokeOthers: %d %v", n, err)
		}
		if n, err := tx.APITokensRevoke(f.A.User); err != nil || n != 0 {
			t.Errorf("APITokensRevoke: %d %v", n, err)
		}
		// Refresh tokens.
		ok, err = tx.RefreshRotate(aRefresh, future, time.Now())
		falsy("RefreshRotate", ok, err)
		must("RefreshRevokeFamily", tx.RefreshRevokeFamily(aFamily))
		// Passkeys.
		if l, err := tx.PasskeysList(f.A.User); err != nil || len(l) != 0 {
			t.Errorf("PasskeysList: %d %v", len(l), err)
		}
		if n, err := tx.PasskeyLiveCount(f.A.User, "example.test"); err != nil || n != 0 {
			t.Errorf("PasskeyLiveCount: %d %v", n, err)
		}
		ok, err = tx.PasskeyRename(f.A.User, aPasskey, "stolen")
		falsy("PasskeyRename", ok, err)
		ok, err = tx.PasskeyDelete(f.A.User, aPasskey)
		falsy("PasskeyDelete", ok, err)
		ok, err = tx.PasskeyUsed(f.A.User, aPasskey, 5, true)
		falsy("PasskeyUsed", ok, err)
		// Phone change.
		_, ok, err = tx.PhoneChangeGet(f.A.User, aPhoneReq)
		falsy("PhoneChangeGet", ok, err)
		if out, err := tx.PhoneChangeComplete(aPhoneReq); err != nil || out != "invalid" {
			t.Errorf("PhoneChangeComplete: %q %v", out, err)
		}
		if out, err := tx.PhoneMarkVerified(f.A.User, uuid.Must(uuid.NewV7())); err != nil || out != "invalid" {
			t.Errorf("PhoneMarkVerified: %q %v", out, err)
		}
		must("TicketsRevoke", tx.TicketsRevoke(f.A.User))
		// Notices.
		ok, err = tx.NotificationRead(aNotification)
		falsy("NotificationRead", ok, err)
		if l, err := tx.NotificationsPage(store.Cursor{}, 50); err != nil || len(l) != 1 {
			t.Errorf("NotificationsPage: %d rows, %v (B has its own seed row only)", len(l), err)
		} else if l[0].ID == aNotification {
			t.Error("NotificationsPage returned A's notification")
		}
		if as, err := tx.AnnouncementsFor(f.B.User); err != nil {
			t.Error(err)
		} else {
			for _, x := range as {
				if x.ID == annA {
					t.Error("AnnouncementsFor returned an announcement addressed to A")
				}
			}
		}
		ok, err = tx.AnnouncementRead(f.B.User, annA)
		falsy("AnnouncementRead", ok, err)
	})
	// Each of these fails the transaction (a constraint error aborts it), so
	// each gets its own.
	for name, fn := range map[string]func(tx store.Tx) error{
		"SessionCreate": func(tx store.Tx) error {
			_, err := tx.SessionCreate(store.NewSession{At: time.Now(), UserID: f.A.User, TokenHash: hash("x1"), IdleExpiresAt: future, AbsoluteExpiresAt: future, AuthMethod: "password"})
			return err
		},
		"RefreshCreate": func(tx store.Tx) error {
			_, err := tx.RefreshCreate(store.NewRefresh{SessionID: aSession, UserID: f.A.User, FamilyID: uuid.New(), TokenHash: hash("x2"), ExpiresAt: future})
			return err
		},
		"PhoneChangeCreate": func(tx store.Tx) error {
			_, err := tx.PhoneChangeCreate(f.A.User, "+989135550000", uuid.New(), uuid.New(), 5*time.Minute)
			return err
		},
		"RecoveryCodesReplace": func(tx store.Tx) error {
			// Every caller holds the user first (the lock order), and the inserted code
			// takes a key share on it.
			if _, _, err := tx.UserLock(f.A.User); err != nil {
				return err
			}
			return tx.RecoveryCodesReplace(f.A.User, [][]byte{hash("rc9")})
		},
	} {
		err := tenant.WithTenant(f.ctx, f.B.Tenant, store.TxOpts{}, func(tx store.Tx) error { return fn(tx) })
		notFoundErr(name, err)
	}
	// B's writes of its own audit row and notice land on B.
	f.inTenant(t, tenant, f.B.Tenant, func(tx store.Tx) {
		if err := tx.AuditAdd(store.TenantAudit{UserID: f.B.User, Action: "login.ok", Params: []byte(`{"method":"password"}`), IP: netip.MustParseAddr("198.51.100.1")}); err != nil {
			t.Error(err)
		}
		if err := tx.NotificationAdd("password_reset", "info", nil); err != nil {
			t.Error(err)
		}
	})

	if after := f.snapshot(t, super, f.A.Tenant); after != before {
		t.Errorf("tenant A's rows changed.\nbefore:\n%s\nafter:\n%s", before, after)
	}
	// A's notice count did not move, B's did.
	f.inTenant(t, tenant, f.A.Tenant, func(tx store.Tx) {
		if n, err := tx.NotificationsUnread(); err != nil || n != 1 {
			t.Errorf("A's unread count: %d %v", n, err)
		}
	})
}

func TestUsersSessionsAndRefresh(t *testing.T) {
	f := newFixture(t)
	s := f.db.Store(f.ctx, t, store.RoleTenant)
	super := f.superConn(t)
	now := time.Now()

	f.inTenant(t, s, f.A.Tenant, func(tx store.Tx) {
		u, ok, err := tx.User(f.A.User)
		if err != nil || !ok || u.Phone != f.A.Phone || u.Locale != "fa" || u.State != credstate.Ready {
			t.Fatalf("User: %+v %v %v", u, ok, err)
		}
		if has, found, err := tx.UserFlags(f.A.User); err != nil || !found || !has {
			t.Errorf("UserFlags: %v %v %v", has, found, err)
		}
		en, dark := "en", "dark"
		if ok, err := tx.UpdatePreferences(f.A.User, store.Preferences{Locale: &en, Theme: &dark, OnboardingHints: []byte(`{"enabled": false}`)}); err != nil || !ok {
			t.Fatalf("UpdatePreferences: %v %v", ok, err)
		}
		u, _, _ = tx.User(f.A.User)
		if u.Locale != "en" || u.Theme != "dark" || !strings.Contains(string(u.OnboardingHints), "false") {
			t.Errorf("preferences not stored: %+v", u)
		}
		// A partial update leaves the rest.
		fa := "fa"
		if _, err := tx.UpdatePreferences(f.A.User, store.Preferences{Locale: &fa}); err != nil {
			t.Fatal(err)
		}
		u, _, _ = tx.User(f.A.User)
		if u.Locale != "fa" || u.Theme != "dark" {
			t.Errorf("partial update: %+v", u)
		}
	})

	// A one-time password session, then the user's own password clears all of it.
	if _, err := super.Exec(f.ctx, "UPDATE ctrlz.users SET must_reset = true, password_expires_at = now() + interval '1 hour' WHERE id = $1", f.A.User); err != nil {
		t.Fatal(err)
	}

	f.inTenant(t, s, f.A.Tenant, func(tx store.Tx) {
		l, found, err := tx.UserLock(f.A.User)
		if err != nil || !found || l.State != credstate.OneTimeLive {
			t.Fatalf("UserLock: %+v %v %v", l, found, err)
		}
		id1, err := tx.SessionCreate(store.NewSession{At: time.Now(), UserID: f.A.User, TokenHash: hash("t1"), IdleExpiresAt: now.Add(2 * time.Hour),
			AbsoluteExpiresAt: now.Add(24 * time.Hour), Restricted: true, AuthMethod: "password", IP: netip.MustParseAddr("::ffff:198.51.100.9"),
			UserAgent: strings.Repeat("ü", 400)})
		if err != nil {
			t.Fatal(err)
		}
		row, ok, err := tx.SessionByID(id1)
		if err != nil || !ok || !row.Restricted || row.IP == nil || row.IP.String() != "198.51.100.9" || len([]rune(row.UserAgent)) != 256 {
			t.Fatalf("SessionByID: %+v %v %v", row, ok, err)
		}
		// Password change: rotate, clear restricted, revoke others, set password.
		id2, err := tx.SessionCreate(store.NewSession{At: time.Now(), UserID: f.A.User, TokenHash: hash("t2"), IdleExpiresAt: now.Add(2 * time.Hour),
			AbsoluteExpiresAt: now.Add(24 * time.Hour), AuthMethod: "otp"})
		if err != nil {
			t.Fatal(err)
		}
		if ok, err := tx.SetPassword(f.A.User, secret.New("hash-2")); err != nil || !ok {
			t.Fatal(ok, err)
		}
		if ok, err := tx.SessionRotate(id1, hash("t1b"), now.Add(2*time.Hour), store.ReauthSet, now, true); err != nil || !ok {
			t.Fatal(ok, err)
		}
		if n, err := tx.SessionsRevokeOthers(f.A.User, id1, now); err != nil || n < 2 {
			t.Errorf("ended sessions: %d %v (the seeded session and id2 were live)", n, err)
		}
		row, _, _ = tx.SessionByID(id1)
		if row.Restricted || row.ReauthAt == nil || row.RevokedAt != nil {
			t.Errorf("rotated session: %+v", row)
		}
		if r2, _, _ := tx.SessionByID(id2); r2.RevokedAt == nil {
			t.Error("the other session survived")
		}
		u, _, _ := tx.User(f.A.User)
		if u.State != credstate.Ready || u.PasswordChangedAt == nil {
			t.Errorf("SetPassword left %+v", u)
		}
		list, err := tx.SessionsList(f.A.User, time.Now())
		if err != nil || len(list) != 1 || list[0].ID != id1 {
			t.Errorf("SessionsList: %d rows %v", len(list), err)
		}
		// Refresh: create, rotate once, rotate again is refused, a refresh of the
		// session token clears reauth, revoking the family ends the session.
		fam := uuid.New()
		rid, err := tx.RefreshCreate(store.NewRefresh{SessionID: id1, UserID: f.A.User, FamilyID: fam, TokenHash: hash("r1"), ExpiresAt: now.Add(30 * 24 * time.Hour)})
		if err != nil {
			t.Fatal(err)
		}
		if ok, err := tx.RefreshRotate(rid, now.Add(10*time.Second), now); err != nil || !ok {
			t.Fatal(ok, err)
		}
		if ok, _ := tx.RefreshRotate(rid, now.Add(10*time.Second), now); ok {
			t.Error("a refresh token was rotated twice")
		}
		if ok, err := tx.SessionRefreshToken(id1, hash("t1c"), now.Add(2*time.Hour), now); err != nil || !ok {
			t.Fatal(ok, err)
		}
		if row, _, _ := tx.SessionByID(id1); row.ReauthAt != nil {
			t.Error("a refresh kept the reauth window")
		}
		// SessionRotate revokes the session's refresh tokens.
		if ok, err := tx.SessionRotate(id1, hash("t1d"), now.Add(2*time.Hour), store.ReauthKeep, now, false); err != nil || !ok {
			t.Fatal(ok, err)
		}
		var revoked *time.Time
		if err := tx.DB().QueryRow(tx.Context(), "SELECT revoked_at FROM ctrlz.refresh_tokens WHERE id = $1", rid).Scan(&revoked); err != nil || revoked == nil {
			t.Errorf("rotation left the refresh token live: %v %v", revoked, err)
		}
		// Reuse: the family goes, and so does the session.
		fam2 := uuid.New()
		if _, err := tx.RefreshCreate(store.NewRefresh{SessionID: id1, UserID: f.A.User, FamilyID: fam2, TokenHash: hash("r2"), ExpiresAt: now.Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
		if err := tx.RefreshRevokeFamily(fam2); err != nil {
			t.Fatal(err)
		}
		if row, _, _ := tx.SessionByID(id1); row.RevokedAt == nil {
			t.Error("reuse did not end the session")
		}
		// Revoke one by id, and log out all.
		id3, _ := tx.SessionCreate(store.NewSession{At: time.Now(), UserID: f.A.User, TokenHash: hash("t3"), IdleExpiresAt: now.Add(time.Hour), AbsoluteExpiresAt: now.Add(time.Hour), AuthMethod: "password"})
		if ok, err := tx.SessionRevoke(f.A.User, id3); err != nil || !ok {
			t.Error(ok, err)
		}
		if ok, _ := tx.SessionRevoke(f.A.User, id3); ok {
			t.Error("a session was revoked twice")
		}
		if n, err := tx.APITokensRevoke(f.A.User); err != nil || n != 1 {
			t.Errorf("APITokensRevoke: %d %v", n, err)
		}
		// Touch slides but never past the absolute limit.
		id4, _ := tx.SessionCreate(store.NewSession{At: time.Now(), UserID: f.A.User, TokenHash: hash("t4"), IdleExpiresAt: now.Add(time.Minute), AbsoluteExpiresAt: now.Add(time.Hour), AuthMethod: "password"})
		if err := tx.SessionTouch(id4, now.Add(5*time.Hour), now); err != nil {
			t.Fatal(err)
		}
		if row, _, _ := tx.SessionByID(id4); row.IdleExpiresAt.After(now.Add(time.Hour + time.Second)) {
			t.Errorf("idle limit %v passed the absolute limit", row.IdleExpiresAt)
		}
		// Enforce and review flags.
		if err := tx.SetEnforce(f.A.User, true); err != nil {
			t.Fatal(err)
		}
		at, ok, err := tx.DeferEnforceLift(f.A.User, 72*time.Hour, time.Now())
		if err != nil || !ok || time.Until(at) < 71*time.Hour {
			t.Fatalf("DeferEnforceLift: %v %v %v", at, ok, err)
		}
		again, _, _ := tx.DeferEnforceLift(f.A.User, time.Hour, time.Now())
		if !again.Equal(at) {
			t.Errorf("a second deferral moved the delay: %v then %v", at, again)
		}
		if err := tx.ClearEnforceLift(f.A.User); err != nil {
			t.Fatal(err)
		}
		if err := tx.SetPasskeyReview(f.A.User, true); err != nil {
			t.Fatal(err)
		}
		u, _, _ = tx.User(f.A.User)
		if !u.EnforcePasskey || u.EnforceLiftAt != nil || u.PasskeyReviewAt == nil {
			t.Errorf("flags: %+v", u)
		}
		if err := tx.SetEnforce(f.A.User, false); err != nil {
			t.Fatal(err)
		}
		if err := tx.MarkLogin(f.A.User); err != nil {
			t.Fatal(err)
		}
	})
}

func TestTOTPRecoveryAndPasskeyMethods(t *testing.T) {
	f := newFixture(t)
	s := f.db.Store(f.ctx, t, store.RoleTenant)
	super := f.superConn(t)

	f.inTenant(t, s, f.A.Tenant, func(tx store.Tx) {
		// Setup, replacement of an unconfirmed secret, confirm.
		if ok, err := tx.TOTPSetPending(f.A.User, []byte("ct1")); err != nil || !ok {
			t.Fatal(ok, err)
		}
		if ok, _ := tx.TOTPSetPending(f.A.User, []byte("ct2")); !ok {
			t.Error("an unconfirmed secret was not replaced")
		}
		if ok, err := tx.TOTPEnable(f.A.User); err != nil || !ok {
			t.Fatal(ok, err)
		}
		if ok, _ := tx.TOTPEnable(f.A.User); ok {
			t.Error("TOTP was enabled twice")
		}
		if ok, _ := tx.TOTPSetPending(f.A.User, []byte("ct3")); ok {
			t.Error("a secret was replaced while TOTP is enabled")
		}
		// The replay rule.
		if ok, _ := tx.TOTPStepAccept(f.A.User, 100); !ok.Yes() {
			t.Error("a fresh step was refused")
		}
		for _, step := range []int64{100, 99} {
			if ok, _ := tx.TOTPStepAccept(f.A.User, step); ok.Yes() {
				t.Errorf("step %d was accepted after 100", step)
			}
		}
		if ok, _ := tx.TOTPStepAccept(f.A.User, 101); !ok.Yes() {
			t.Error("the next step was refused")
		}
		// Recovery codes: replace, use once, count.
		if err := tx.RecoveryCodesReplace(f.A.User, [][]byte{hash("h1"), hash("h2"), hash("h3")}); err != nil {
			t.Fatal(err)
		}
		if n, _ := tx.RecoveryCodesLeft(f.A.User); n != 3 {
			t.Errorf("codes left %d", n)
		}
		if ok, _ := tx.RecoveryCodeUse(f.A.User, hash("h2")); !ok.Yes() {
			t.Error("a valid recovery code was refused")
		}
		if ok, _ := tx.RecoveryCodeUse(f.A.User, hash("h2")); ok.Yes() {
			t.Error("a recovery code was used twice")
		}
		if ok, _ := tx.RecoveryCodeUse(f.A.User, hash("nope")); ok.Yes() {
			t.Error("an unknown recovery code was accepted")
		}
		if n, _ := tx.RecoveryCodesLeft(f.A.User); n != 2 {
			t.Errorf("codes left %d", n)
		}
		if err := tx.RecoveryCodesReplace(f.A.User, nil); err != nil {
			t.Fatal(err)
		}
		if n, _ := tx.RecoveryCodesLeft(f.A.User); n != 0 {
			t.Errorf("codes left after delete %d", n)
		}
		if err := tx.TOTPDisable(f.A.User); err != nil {
			t.Fatal(err)
		}
		u, _, _ := tx.User(f.A.User)
		if u.TOTPEnabledAt != nil || u.TOTPPending {
			t.Errorf("TOTP not disabled: %+v", u)
		}
	})
	// The seed is read through the one function that reaches it, under the tenant setting.
	f.inTenant(t, s, f.A.Tenant, func(tx store.Tx) {
		if ct, ok, err := tx.TOTPSeedCT(f.A.User); err != nil || ok || ct != nil {
			t.Errorf("TOTPSeedCT after disable: %v %v %v", ct, ok, err)
		}
	})

	// An expired pending secret cannot be confirmed.
	f.inTenant(t, s, f.A.Tenant, func(tx store.Tx) {
		if ok, _ := tx.TOTPSetPending(f.A.User, []byte("ct4")); !ok {
			t.Fatal("setup refused")
		}
	})
	if _, err := super.Exec(f.ctx, "UPDATE ctrlz.users SET totp_pending_at = now() - interval '16 minutes' WHERE id = $1", f.A.User); err != nil {
		t.Fatal(err)
	}
	f.inTenant(t, s, f.A.Tenant, func(tx store.Tx) {
		if ok, _ := tx.TOTPEnable(f.A.User); ok {
			t.Error("a pending secret older than 15 minutes was confirmed")
		}
		if err := tx.TOTPClearPending(f.A.User); err != nil {
			t.Fatal(err)
		}
	})

	// Passkeys.
	f.inTenant(t, s, f.A.Tenant, func(tx store.Tx) {
		aaguid := uuid.New()
		id, _, _, err := tx.PasskeyAdd(store.Credential{UserID: f.A.User, CredentialID: hash("cred-new"), PublicKey: hash("pk"), Name: "Passkey 2",
			RPID: "example.test", Transports: []string{"internal"}, AAGUID: &aaguid, BackupEligible: true}, 20)
		if err != nil {
			t.Fatal(err)
		}
		list, err := tx.PasskeysList(f.A.User)
		if err != nil || len(list) != 2 {
			t.Fatalf("PasskeysList: %d %v", len(list), err)
		}
		if n, _ := tx.PasskeyLiveCount(f.A.User, "example.test"); n != 2 {
			t.Errorf("live count %d", n)
		}
		if n, _ := tx.PasskeyLiveCount(f.A.User, "other.test"); n != 0 {
			t.Errorf("live count for another RP ID %d", n)
		}
		_ = id
	})
	// A credential id is globally unique, tenant or not. The failed insert aborts
	// its transaction, so it has one of its own.
	dup := s.WithTenant(f.ctx, f.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
		_, _, _, err := tx.PasskeyAdd(store.Credential{UserID: f.A.User, CredentialID: hash("cred-new"), PublicKey: hash("pk"), RPID: "example.test"}, 20)
		return err
	})
	if !errors.Is(dup, store.ErrConflict) {
		t.Errorf("a duplicate credential id: %v", dup)
	}
	f.inTenant(t, s, f.A.Tenant, func(tx store.Tx) {
		list, _ := tx.PasskeysList(f.A.User)
		var id uuid.UUID
		for _, c := range list {
			if string(c.CredentialID) == "cred-new" {
				id = c.ID
			}
		}
		if ok, err := tx.PasskeyRename(f.A.User, id, "Laptop"); err != nil || !ok {
			t.Fatal(ok, err)
		}
		// The counter rule: zero stays zero (synced), a rise is fine, a repeat is a clone.
		if ok, _ := tx.PasskeyUsed(f.A.User, id, 0, true); !ok {
			t.Error("a synced passkey that reports 0 was refused")
		}
		if ok, _ := tx.PasskeyUsed(f.A.User, id, 5, true); !ok {
			t.Error("a counter that rose from 0 was refused")
		}
		for _, n := range []int64{5, 4, 0} {
			if ok, _ := tx.PasskeyUsed(f.A.User, id, n, true); ok {
				t.Errorf("a counter of %d after 5 was accepted", n)
			}
		}
		if ok, _ := tx.PasskeyUsed(f.A.User, id, 6, false); !ok {
			t.Error("a counter that rose was refused")
		}
		list, _ = tx.PasskeysList(f.A.User)
		for _, c := range list {
			if c.ID == id && (c.Name != "Laptop" || c.SignCount != 6 || c.BackupState || !c.BackupEligible || c.LastUsedAt == nil || c.AAGUID == nil) {
				t.Errorf("stored credential: %+v", c)
			}
		}
		if ok, _ := tx.PasskeyDelete(f.A.User, id); !ok {
			t.Error("delete failed")
		}
	})
}

func TestPhoneChangeNoticesAndSettings(t *testing.T) {
	f := newFixture(t)
	s := f.db.Store(f.ctx, t, store.RoleTenant)
	super := f.superConn(t)

	f.inTenant(t, s, f.A.Tenant, func(tx store.Tx) {
		oldOTP, newOTP := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
		id, err := tx.PhoneChangeCreate(f.A.User, "+989135550001", oldOTP, newOTP, 5*time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		pc, ok, err := tx.PhoneChangeGet(f.A.User, id)
		if err != nil || !ok || pc.NewPhone != "+989135550001" || pc.OldOTP != oldOTP || pc.CompletedAt != nil {
			t.Fatalf("PhoneChangeGet: %+v %v %v", pc, ok, err)
		}
		// Without consumed codes the function refuses, and nothing changes.
		if out, err := tx.PhoneChangeComplete(id); err != nil || out != "invalid" {
			t.Errorf("PhoneChangeComplete without codes: %q %v", out, err)
		}
	})
	// A request that lives longer than 15 minutes is refused by the table.
	err := s.WithTenant(f.ctx, f.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
		_, err := tx.PhoneChangeCreate(f.A.User, "+989135550002", uuid.New(), uuid.New(), 20*time.Minute)
		return err
	})
	if !errors.Is(err, store.ErrConstraint) {
		t.Errorf("a 20 minute request: %v", err)
	}

	// The whole path: both codes consumed, then complete, then mark verified.
	oldID, newID := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	for _, o := range []struct {
		id             uuid.UUID
		phone, purpose string
	}{{oldID, f.A.Phone, "phone_old"}, {newID, "+989135550003", "phone_new"}} {
		if _, err := super.Exec(f.ctx, `INSERT INTO ctrlz.otp_challenges (id, phone_e164, purpose, code_hash, expires_at, consumed_at)
VALUES ($1, $2, $3, '\x01', now() + interval '5 minutes', now() + interval '1 second')`, o.id, o.phone, o.purpose); err != nil {
			t.Fatal(err)
		}
	}
	f.inTenant(t, s, f.A.Tenant, func(tx store.Tx) {
		id, err := tx.PhoneChangeCreate(f.A.User, "+989135550003", oldID, newID, 5*time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		// created_at is now(), the codes were consumed a second after: valid.
		if out, err := tx.PhoneChangeComplete(id); err != nil || out != "ok" {
			t.Fatalf("PhoneChangeComplete: %q %v", out, err)
		}
		u, _, _ := tx.User(f.A.User)
		if u.Phone != "+989135550003" || u.PhoneVerifiedAt == nil {
			t.Errorf("phone not changed: %+v", u)
		}
	})
	// An admin-made user is verified by the first login OTP.
	if _, err := super.Exec(f.ctx, "UPDATE ctrlz.users SET phone_verified_at = NULL WHERE id = $1", f.B.User); err != nil {
		t.Fatal(err)
	}
	loginOTP := uuid.Must(uuid.NewV7())
	if _, err := super.Exec(f.ctx, `INSERT INTO ctrlz.otp_challenges (id, phone_e164, purpose, code_hash, expires_at, consumed_at)
VALUES ($1, $2, 'login', '\x01', now() + interval '5 minutes', now())`, loginOTP, f.B.Phone); err != nil {
		t.Fatal(err)
	}
	f.inTenant(t, s, f.B.Tenant, func(tx store.Tx) {
		if out, err := tx.PhoneMarkVerified(f.B.User, uuid.Must(uuid.NewV7())); err != nil || out != "invalid" {
			t.Errorf("unknown OTP: %q %v", out, err)
		}
		if out, err := tx.PhoneMarkVerified(f.B.User, loginOTP); err != nil || out != "ok" {
			t.Errorf("login OTP: %q %v", out, err)
		}
		if u, _, _ := tx.User(f.B.User); u.PhoneVerifiedAt == nil {
			t.Error("the phone was not verified")
		}
	})

	// Notifications: paging newest first, unread count over all rows, read.
	fresh2 := uuid.Must(uuid.NewV7())
	if _, err := super.Exec(f.ctx, "INSERT INTO ctrlz.announcements (id, audience, body) VALUES ($1, 'all', 'second')", fresh2); err != nil {
		t.Fatal(err)
	}
	f.inTenant(t, s, f.A.Tenant, func(tx store.Tx) {
		for i := 0; i < 5; i++ {
			if err := tx.NotificationAdd("n", "info", []byte(fmt.Sprintf(`{"i":%d}`, i))); err != nil {
				t.Fatal(err)
			}
		}
		page1, err := tx.NotificationsPage(store.Cursor{}, 4)
		if err != nil || len(page1) != 4 {
			t.Fatalf("page 1: %d %v", len(page1), err)
		}
		last := page1[len(page1)-1]
		page2, err := tx.NotificationsPage(store.Cursor{At: last.CreatedAt, ID: last.ID}, 4)
		if err != nil || len(page2) != 2 {
			t.Fatalf("page 2: %d %v (6 rows in all)", len(page2), err)
		}
		seen := map[uuid.UUID]bool{}
		for _, n := range append(page1, page2...) {
			if seen[n.ID] {
				t.Errorf("notification %s on two pages", n.ID)
			}
			seen[n.ID] = true
		}
		if n, _ := tx.NotificationsUnread(); n != 6 {
			t.Errorf("unread %d", n)
		}
		if ok, _ := tx.NotificationRead(page1[0].ID); !ok {
			t.Error("read failed")
		}
		if n, _ := tx.NotificationsUnread(); n != 5 {
			t.Errorf("unread after read %d", n)
		}
		// Announcements: the general one, read flag.
		as, err := tx.AnnouncementsFor(f.A.User)
		if err != nil || len(as) != 2 {
			t.Fatalf("AnnouncementsFor: %+v %v", as, err)
		}
		for _, a := range as {
			if a.ID == fresh2 && a.Read {
				t.Error("a new announcement is already read")
			}
			if a.ID != fresh2 && !a.Read {
				t.Error("the announcement the seed marked read is not read")
			}
		}
		if ok, err := tx.AnnouncementRead(f.A.User, fresh2); err != nil || !ok {
			t.Fatal(ok, err)
		}
		if ok, _ := tx.AnnouncementRead(f.A.User, fresh2); !ok {
			t.Error("reading twice failed")
		}
		as, _ = tx.AnnouncementsFor(f.A.User)
		for _, a := range as {
			if !a.Read {
				t.Errorf("announcement %s is not read", a.ID)
			}
		}
		if ok, _ := tx.AnnouncementRead(f.A.User, uuid.New()); ok {
			t.Error("an unknown announcement was marked read")
		}
		// Another request in production.
		tx.ForgetLocks()
		// Settings.
		if err := tx.SetHomeCountries([]string{"IR", "DE"}); err != nil {
			t.Fatal(err)
		}
		if got, _ := tx.HomeCountries(); strings.Join(got, ",") != "IR,DE" {
			t.Errorf("home countries %v", got)
		}
	})
	// A constraint error aborts its transaction, so it gets one of its own.
	four := s.WithTenant(f.ctx, f.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
		return tx.SetHomeCountries([]string{"IR", "DE", "FR", "US"})
	})
	if !errors.Is(four, store.ErrConstraint) {
		t.Errorf("four home countries: %v", four)
	}
	f.inTenant(t, s, f.B.Tenant, func(tx store.Tx) {
		if got, _ := tx.HomeCountries(); len(got) != 0 {
			t.Errorf("tenant B's home countries %v", got)
		}
		if st, err := tx.TenantStatus(); err != nil || st != "active" {
			t.Errorf("status %q %v", st, err)
		}
	})
	// Limits: the default, and an override of one tenant only.
	if _, err := super.Exec(f.ctx, "UPDATE ctrlz.tenant_entitlements SET max_profiles = 3, max_ip_claims = 7 WHERE tenant_id = $1", f.A.Tenant); err != nil {
		t.Fatal(err)
	}
	f.inTenant(t, s, f.A.Tenant, func(tx store.Tx) {
		l, err := tx.Limits()
		if err != nil || l.MaxProfiles != 3 || l.MaxIPClaims != 7 || l.MaxEndpoints != 50 {
			t.Errorf("A's limits: %+v %v", l, err)
		}
	})
	f.inTenant(t, s, f.B.Tenant, func(tx store.Tx) {
		l, err := tx.Limits()
		if err != nil || l.MaxProfiles != 20 || l.MaxIPClaims != 50 {
			t.Errorf("B's limits: %+v %v", l, err)
		}
	})

	// Plans (D56): B moves to a plan of its own with a distinct value for every limit. Its Limits are that plan's
	// values, the override of B beats the plan's value for that column only, and A, on the default plan with its
	// own override, is untouched by any of it.
	var small uuid.UUID
	if err := super.QueryRow(f.ctx, `INSERT INTO ctrlz.plans (name, max_profiles, max_endpoints, max_clients_per_endpoint,
  max_authorized_ips, max_api_tokens, max_rules_per_request, max_rules_per_profile, max_wildcards_per_profile,
  max_realtime_sessions, max_publishes_per_hour, max_ip_claims) VALUES ('Small', 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12) RETURNING id`).Scan(&small); err != nil {
		t.Fatal(err)
	}
	if _, err := super.Exec(f.ctx, "UPDATE ctrlz.tenants SET plan_id = $1 WHERE id = $2", small, f.B.Tenant); err != nil {
		t.Fatal(err)
	}
	wantSmall := store.Limits{MaxProfiles: 2, MaxEndpoints: 3, MaxClientsPerEndpoint: 4, MaxAuthorizedIPs: 5, MaxAPITokens: 6,
		MaxRulesPerRequest: 7, MaxRulesPerProfile: 8, MaxWildcardsPerProfile: 9, MaxRealtimeSessions: 10, MaxPublishesPerHour: 11, MaxIPClaims: 12}
	limitsOf := func(tenant uuid.UUID) (l store.Limits) {
		t.Helper()
		f.inTenant(t, s, tenant, func(tx store.Tx) {
			var err error
			if l, err = tx.Limits(); err != nil {
				t.Fatal(err)
			}
		})
		return l
	}
	if got := limitsOf(f.B.Tenant); got != wantSmall {
		t.Errorf("B on the Small plan: %+v, want %+v", got, wantSmall)
	}
	if _, err := super.Exec(f.ctx, "UPDATE ctrlz.tenant_entitlements SET max_profiles = 9 WHERE tenant_id = $1", f.B.Tenant); err != nil {
		t.Fatal(err)
	}
	wantOverride := wantSmall
	wantOverride.MaxProfiles = 9
	if got := limitsOf(f.B.Tenant); got != wantOverride {
		t.Errorf("B with an override of max_profiles: %+v, want %+v", got, wantOverride)
	}
	// Lowering the plan changes B and nobody else.
	if _, err := super.Exec(f.ctx, "UPDATE ctrlz.plans SET max_endpoints = 0 WHERE id = $1", small); err != nil {
		t.Fatal(err)
	}
	if got := limitsOf(f.B.Tenant); got.MaxEndpoints != 0 || got.MaxProfiles != 9 {
		t.Errorf("B after lowering its plan: %+v", got)
	}
	if got := limitsOf(f.A.Tenant); got.MaxEndpoints != 50 || got.MaxProfiles != 3 || got.MaxIPClaims != 7 {
		t.Errorf("A after B's plan changed: %+v", got)
	}
}

// RefreshSession (A3) is the one lookup of the refresh rotation that needs a
// tenant: B asking for A's refresh token id finds nothing.
func TestRefreshSessionIsTenantScoped(t *testing.T) {
	f := newFixture(t)
	s := f.db.Store(f.ctx, t, store.RoleTenant)
	var refreshA, sessionA uuid.UUID
	const q = `SELECT id, session_id FROM ctrlz.refresh_tokens LIMIT 1`
	f.inTenant(t, s, f.A.Tenant, func(tx store.Tx) {
		if err := tx.DB().QueryRow(f.ctx, q).Scan(&refreshA, &sessionA); err != nil {
			t.Fatal(err)
		}
		got, ok, err := tx.RefreshSession(refreshA)
		if err != nil || !ok || got != sessionA {
			t.Fatalf("A's own refresh token: %v %v %v", got, ok, err)
		}
	})
	f.inTenant(t, s, f.B.Tenant, func(tx store.Tx) {
		if _, ok, err := tx.RefreshSession(refreshA); err != nil || ok {
			t.Fatalf("B read A's refresh token: ok=%v err=%v", ok, err)
		}
		if _, ok, err := tx.RefreshSession(uuid.New()); err != nil || ok {
			t.Fatalf("an unknown id: ok=%v err=%v", ok, err)
		}
	})
}

// TestTOTPSeedCTIsTenantScoped covers Tx.TOTPSeedCT (A5): a route reads the
// sealed seed inside its own transaction, and tenant B asking for tenant A's
// user gets nothing, with A's rows unchanged.
func TestTOTPSeedCTIsTenantScoped(t *testing.T) {
	f := newFixture(t)
	s := f.db.Store(f.ctx, t, store.RoleTenant)
	super := f.superConn(t)

	f.inTenant(t, s, f.A.Tenant, func(tx store.Tx) {
		if _, ok, err := tx.TOTPSeedCT(f.A.User); err != nil || ok {
			t.Fatalf("a user with no seed: ok=%v err=%v", ok, err)
		}
		if ok, err := tx.TOTPSetPending(f.A.User, []byte("sealed-A")); err != nil || !ok {
			t.Fatal(ok, err)
		}
		ct, ok, err := tx.TOTPSeedCT(f.A.User)
		if err != nil || !ok || string(ct) != "sealed-A" {
			t.Fatalf("own seed: %q ok=%v err=%v", ct, ok, err)
		}
	})
	before := f.snapshot(t, super, f.A.Tenant)
	f.inTenant(t, s, f.B.Tenant, func(tx store.Tx) {
		if ct, ok, err := tx.TOTPSeedCT(f.A.User); err != nil || ok || ct != nil {
			t.Fatalf("B read A's seed: %q ok=%v err=%v", ct, ok, err)
		}
	})
	if after := f.snapshot(t, super, f.A.Tenant); after != before {
		t.Fatal("A's rows changed")
	}
}
