package store_test

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/credstate"
	"github.com/Kup1ng/CtrlZ-Panel/internal/credgen"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// globalSerializable is global for the one function that refuses any other isolation level
// (admin_account_bootstrap, db-r7-1).
func (f *fixture) globalSerializable(t *testing.T, s *store.Store, fn func(g store.GlobalTx)) {
	t.Helper()
	if err := s.WithGlobal(f.ctx, store.TxOpts{Isolation: store.Serializable}, func(g store.GlobalTx) error { fn(g); return nil }); err != nil {
		t.Fatalf("WithGlobal: %v", err)
	}
}

func (f *fixture) global(t *testing.T, s *store.Store, fn func(g store.GlobalTx)) {
	t.Helper()
	if err := s.WithGlobal(f.ctx, store.TxOpts{}, func(g store.GlobalTx) error { fn(g); return nil }); err != nil {
		t.Fatalf("WithGlobal: %v", err)
	}
}

func TestAdminFnsAreForTheAdminRoleOnly(t *testing.T) {
	f := newFixture(t)
	for _, role := range []store.Role{store.RoleTenant, store.RoleWorker, store.RoleHub, store.RoleCompiler} {
		a := f.db.Store(f.ctx, t, role).Admin()
		if _, _, err := a.CreateUser(f.ctx, "+989121110001", secret.New("h"), "fa"); !errors.Is(err, store.ErrWrongRole) {
			t.Errorf("%s CreateUser: %v", role, err)
		}
		if _, err := a.ThrottleHit(f.ctx, "admin_login", sha32(1), 5, time.Minute); !errors.Is(err, store.ErrWrongRole) {
			t.Errorf("%s ThrottleHit: %v", role, err)
		}
		if err := a.ThrottleReset(f.ctx, "admin_login", nil); !errors.Is(err, store.ErrWrongRole) {
			t.Errorf("%s ThrottleReset: %v", role, err)
		}
	}
	admin := f.db.Store(f.ctx, t, store.RoleAdmin)
	// WithGlobal is refused to the tenant role, which is what keeps it out of
	// the admin tables.
	if err := f.db.Store(f.ctx, t, store.RoleTenant).WithGlobal(f.ctx, store.TxOpts{}, func(store.GlobalTx) error { return nil }); !errors.Is(err, store.ErrWrongRole) {
		t.Errorf("tenant WithGlobal: %v", err)
	}

	reg, ok, err := admin.Admin().CreateUser(f.ctx, "+989121110001", secret.New("one-time-hash"), "")
	if err != nil || !ok || reg.TenantID == uuid.Nil {
		t.Fatalf("CreateUser: %+v %v %v", reg, ok, err)
	}
	if _, ok, _ := admin.Admin().CreateUser(f.ctx, "+989121110001", secret.New("x"), "fa"); ok {
		t.Error("a taken phone was created twice")
	}
	// The new user logs in with the one-time password and is restricted.
	u, ok, err := f.db.Store(f.ctx, t, store.RoleTenant).Auth().UserByPhone(f.ctx, "+989121110001")
	if err != nil || !ok || u.State != credstate.OneTimeLive || u.PasswordHash.Reveal() != "one-time-hash" {
		t.Fatalf("created user: %+v %v %v", u, ok, err)
	}
	if d := f.expiresIn(t, "SELECT password_expires_at - now() FROM ctrlz.users WHERE phone_e164 = $1", "+989121110001"); d < 71*time.Hour || d > 73*time.Hour {
		t.Errorf("one-time password lives %v (password.UserOneTimeLife)", d)
	}

	// The admin throttle: its own scopes, a whole-scope reset with a nil key.
	for i := 1; i <= 6; i++ {
		r, err := admin.Admin().ThrottleHit(f.ctx, "admin_login", sha32(7), 5, 15*time.Minute)
		if err != nil || r.Allowed != (i <= 5) {
			t.Errorf("hit %d: %+v %v", i, r, err)
		}
	}
	if r, _ := admin.Admin().ThrottleHit(f.ctx, "login_net", sha32(7), 5, 15*time.Minute); r.Allowed {
		t.Error("the admin throttle accepted a user scope")
	}
	if err := admin.Admin().ThrottleReset(f.ctx, "admin_login", nil); err != nil {
		t.Fatal(err)
	}
	if r, _ := admin.Admin().ThrottleHit(f.ctx, "admin_login", sha32(7), 5, 15*time.Minute); !r.Allowed {
		t.Error("the scope reset did not clear the key")
	}
}

func TestAdminAccountsSessionsAndAudit(t *testing.T) {
	f := newFixture(t)
	s := f.db.Store(f.ctx, t, store.RoleAdmin)
	now := time.Now()

	// Bootstrap: one winner, also under a race at Serializable. The seed made an
	// admin, so first show that bootstrap refuses to add a second, then remove it.
	f.globalSerializable(t, s, func(g store.GlobalTx) {
		if _, ok, err := g.AdminBootstrap("second", secret.New("h")); err != nil || ok {
			t.Errorf("bootstrap with an admin present: %v %v", ok, err)
		}
	})
	if _, err := f.superConn(t).Exec(f.ctx, "DELETE FROM ctrlz.admin_users"); err != nil {
		t.Fatal(err)
	}
	var wins int
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for try := 0; try < 10; try++ {
				var ok bool
				err := s.WithGlobal(f.ctx, store.TxOpts{Isolation: store.Serializable}, func(g store.GlobalTx) error {
					var err error
					_, ok, err = g.AdminBootstrap("root", secret.New("tmp-hash"))
					return err
				})
				if errors.Is(err, store.ErrRetry) {
					continue
				}
				if err != nil && !errors.Is(err, store.ErrConflict) {
					t.Errorf("bootstrap: %v", err)
				}
				if ok {
					mu.Lock()
					wins++
					mu.Unlock()
				}
				return
			}
		}()
	}
	wg.Wait()
	// The lifetimes are read by another connection, so each is checked after a commit.
	var id uuid.UUID
	var u store.AdminUser
	f.global(t, s, func(g store.GlobalTx) {
		if wins != 1 {
			t.Errorf("%d bootstraps won, want exactly one", wins)
		}
		seeded, ok, err := g.AdminUserByName("root")
		if err != nil || !ok {
			t.Fatal(ok, err)
		}
		id = seeded.ID
		if byID, ok, _ := g.AdminUserByID(id); !ok || byID.Username != "root" || byID.PasswordHash.IsZero() {
			t.Errorf("AdminUserByID: %+v %v", byID, ok)
		}
		// Password, TOTP and notice.
		if ok, err := g.AdminReset(id, secret.New("otp-hash"), false); err != nil || !ok {
			t.Fatal(ok, err)
		}
		u, _, _ = g.AdminUserByID(id)
		if u.State != credstate.OneTimeLive {
			t.Errorf("after reset: %+v", u)
		}
	})
	if d := f.expiresIn(t, "SELECT password_expires_at - now() FROM ctrlz.admin_users WHERE id = $1", id); d < 23*time.Hour || d > 25*time.Hour {
		t.Errorf("a console one-time password lives %v (password.AdminOneTimeLife)", d)
	}
	f.global(t, s, func(g store.GlobalTx) {
		if st, ok, _ := g.AdminSetPassword(id, secret.New("mine")); !ok || st != credstate.ChosenNoSecondFactor {
			t.Fatal("set password", st, ok)
		}
		u, _, _ = g.AdminUserByID(id)
		// No authenticator yet: the chosen password keeps an hour (admin-r2-2).
		if u.State != credstate.ChosenNoSecondFactor || u.PasswordChangedAt == nil {
			t.Errorf("after set: %+v", u)
		}
	})
	if d := f.expiresIn(t, "SELECT password_expires_at - now() FROM ctrlz.admin_users WHERE id = $1", id); d < 50*time.Minute || d > 70*time.Minute {
		t.Errorf("a chosen password without an authenticator lives %v", d)
	}
	f.global(t, s, func(g store.GlobalTx) {
		if ok, _ := g.AdminTOTPSetPending(id, []byte("ct")); !ok {
			t.Fatal("pending")
		}
		if st, ok, _ := g.AdminTOTPEnable(id, 50); !ok || st != credstate.Ready {
			t.Fatal("enable", st, ok)
		}
		if u, _, _ = g.AdminUserByID(id); u.State != credstate.Ready {
			t.Errorf("after enabling TOTP: %+v", u)
		}
	})
	if f.hasExpiry(t, "admin_users", id) {
		t.Error("enabling TOTP left the password expiry")
	}
	f.global(t, s, func(g store.GlobalTx) {
		if _, ok, _ := g.AdminTOTPEnable(id, 51); ok {
			t.Error("enabled twice")
		}
		if ok, _ := g.AdminTOTPStepAccept(id, 50); ok.Yes() {
			t.Error("the confirming step was replayable")
		}
		if ok, _ := g.AdminTOTPStepAccept(id, 51); !ok.Yes() {
			t.Error("the next step was refused")
		}
		if err := g.AdminNoticeSet(id, []byte(`{"kind":"totp_reset"}`)); err != nil {
			t.Fatal(err)
		}
		if u, _, _ = g.AdminUserByID(id); !strings.Contains(string(u.PendingNotice), "totp_reset") {
			t.Errorf("notice: %s", u.PendingNotice)
		}
		if err := g.AdminNoticeSet(id, nil); err != nil {
			t.Fatal(err)
		}
		if ok, err := g.AdminReset(id, secret.New("otp-hash-2"), true); err != nil || !ok {
			t.Fatal(ok, err)
		}
		if u, _, _ = g.AdminUserByID(id); u.TOTPEnabledAt != nil || u.TOTPSecretCT != nil || u.PendingNotice != nil {
			t.Errorf("after TOTP reset: %+v", u)
		}
		if err := g.AdminMarkLogin(id); err != nil {
			t.Fatal(err)
		}

		// Sessions.
		sid, err := g.AdminSessionCreate(store.NewAdminSession{AdminID: id, TokenHash: hash("as1"), IdleExpiresAt: now.Add(15 * time.Minute),
			AbsoluteExpiresAt: now.Add(8 * time.Hour), TOTPVerified: true, At: now, IP: netip.MustParseAddr("203.0.113.5"), UserAgent: "test"})
		if err != nil {
			t.Fatal(err)
		}
		info, ok, err := g.AdminSessionByHash(hash("as1"))
		if err != nil || !ok || info.AdminID != id || info.Username != "root" || info.TOTPVerifiedAt == nil || info.TOTPEnabledAt != nil {
			t.Fatalf("AdminSessionByHash: %+v %v %v", info, ok, err)
		}
		if err := g.AdminSessionTouch(sid, now.Add(time.Hour*24)); err != nil {
			t.Fatal(err)
		}
		if info, _, _ = g.AdminSessionByHash(hash("as1")); info.IdleExpiresAt.After(now.Add(8*time.Hour + time.Second)) {
			t.Error("the idle limit passed the absolute limit")
		}
		if ok, _ := g.AdminSessionRotate(sid, hash("as1b"), now.Add(15*time.Minute)); !ok {
			t.Fatal("rotate")
		}
		if _, ok, _ := g.AdminSessionByHash(hash("as1")); ok {
			t.Error("the old token still resolves")
		}
		if _, ok, _ := g.AdminSessionFresh(sid, time.Now()); !ok {
			t.Fatal("fresh")
		}
		other, _ := g.AdminSessionCreate(store.NewAdminSession{AdminID: id, TokenHash: hash("as2"), IdleExpiresAt: now.Add(time.Minute), AbsoluteExpiresAt: now.Add(time.Hour), At: now})
		if n, err := g.AdminSessionsRevokeOthers(id, sid); err != nil || n != 1 {
			t.Errorf("revoke others: %d %v", n, err)
		}
		if info, _, _ := g.AdminSessionByHash(hash("as2")); info.RevokedAt == nil || info.SessionID != other {
			t.Errorf("other session: %+v", info)
		}
		if err := g.AdminSessionRevoke(sid); err != nil {
			t.Fatal(err)
		}
		if _, err := g.AdminSessionsDeleteExpiredBatch(time.Now(), 1000); err != nil {
			t.Fatal(err)
		}
		// The sweep is a bounded batch (rule bounded-sweeps): three sessions a day past
		// their end go two and then one, never more than the limit in a call.
		for i := 0; i < 3; i++ {
			if _, err := g.AdminSessionCreate(store.NewAdminSession{AdminID: id, TokenHash: hash(fmt.Sprintf("old%d", i)),
				IdleExpiresAt: now.Add(-72 * time.Hour), AbsoluteExpiresAt: now.Add(-48 * time.Hour), At: now.Add(-80 * time.Hour)}); err != nil {
				t.Fatal(err)
			}
		}
		for _, want := range []int{2, 1, 0} {
			if n, err := g.AdminSessionsDeleteExpiredBatch(now, 2); err != nil || n != want {
				t.Errorf("AdminSessionsDeleteExpiredBatch(limit 2): %d %v, want %d", n, err, want)
			}
		}
		if _, err := g.AdminSessionsDeleteExpiredBatch(now, 0); err == nil {
			t.Error("a batch size of zero was accepted")
		}

		// The audit chain: each hash is SHA-256(prev || canonical), and a row
		// from inside WithTenant joins the same chain.
		var ids []int64
		for i, c := range []string{`{"a":1}`, `{"a":2}`, `{"a":3}`} {
			aid, err := g.AuditAppend(store.AuditEntry{At: now, AdminID: id, Action: "admin.login", Target: "admin:x", Params: []byte(`{}`),
				IP: netip.MustParseAddr("203.0.113.5"), Canonical: []byte(c)})
			if err != nil {
				t.Fatalf("append %d: %v", i, err)
			}
			ids = append(ids, aid)
		}
		if _, err := g.AuditAppend(store.AuditEntry{At: now, Action: "admin.bootstrap", Canonical: []byte(`{"b":1}`)}); err != nil {
			t.Fatal(err)
		}
		rows, err := g.AuditChain(0, 100)
		if err != nil || len(rows) != 4 {
			t.Fatalf("AuditChain: %d %v", len(rows), err)
		}
		var prev []byte
		canon := []string{`{"a":1}`, `{"a":2}`, `{"a":3}`, `{"b":1}`}
		for i, r := range rows {
			if string(r.PrevHash) != string(prev) {
				t.Errorf("row %d prev_hash does not link", i)
			}
			sum := sha256.Sum256(append(append([]byte{}, prev...), canon[i]...))
			if string(r.EntryHash) != string(sum[:]) {
				t.Errorf("row %d entry_hash is not SHA-256(prev || canonical)", i)
			}
			prev = r.EntryHash
		}
		if rows[0].PrevHash != nil || rows[3].AdminID != nil || rows[0].IP == nil {
			t.Errorf("first row prev %v, last admin %v, first ip %v", rows[0].PrevHash, rows[3].AdminID, rows[0].IP)
		}
		page, err := g.AuditPage(0, "", 2)
		if err != nil || len(page) != 2 || page[0].ID != rows[3].ID {
			t.Errorf("AuditPage: %d %v", len(page), err)
		}
		page, err = g.AuditPage(page[1].ID, "admin.login", 10)
		if err != nil || len(page) != 2 || page[0].ID != ids[1] {
			t.Errorf("AuditPage with a cursor and an action: %+v %v", page, err)
		}
	})
	// Two writers at once do not fork the chain.
	var wg2 sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg2.Add(1)
		go func() {
			defer wg2.Done()
			_ = s.WithGlobal(f.ctx, store.TxOpts{}, func(g store.GlobalTx) error {
				_, err := g.AuditAppend(store.AuditEntry{At: time.Now(), Action: "race", Canonical: []byte("x")})
				return err
			})
		}()
	}
	wg2.Wait()
	f.global(t, s, func(g store.GlobalTx) {
		rows, _ := g.AuditChain(0, 100)
		for i := 1; i < len(rows); i++ {
			if string(rows[i].PrevHash) != string(rows[i-1].EntryHash) {
				t.Errorf("the chain forks at row %d", i)
			}
		}
		if len(rows) != 10 {
			t.Errorf("%d rows, want 10", len(rows))
		}
	})
}

func TestAdminSettingsUsersAndInvites(t *testing.T) {
	f := newFixture(t)
	s := f.db.Store(f.ctx, t, store.RoleAdmin)
	super := f.superConn(t)
	if _, err := super.Exec(f.ctx, "UPDATE ctrlz.users SET enforce_passkey = true WHERE id = $1", f.A.User); err != nil {
		t.Fatal(err)
	}
	if _, err := super.Exec(f.ctx, "DELETE FROM ctrlz.admin_jobs"); err != nil {
		t.Fatal(err)
	}
	f.global(t, s, func(g store.GlobalTx) {
		// Registration.
		r, err := g.RegistrationLock()
		if err != nil || r.Mode != "closed" || r.OpenGraceDays != 14 {
			t.Fatalf("RegistrationLock: %+v %v", r, err)
		}
		imp, err := g.RegistrationImpact()
		if err != nil || imp.Graced != 2 || imp.SuspendedAtOnce != 0 {
			t.Errorf("impact: %+v %v (both seeded claims are active and unproven)", imp, err)
		}
		days := 30
		if err := g.RegistrationSet("open", &days); err != nil {
			t.Fatal(err)
		}
		if r, _ := g.RegistrationGet(); r.Mode != "open" || r.OpenGraceDays != 30 {
			t.Errorf("after set: %+v", r)
		}
		if err := g.RegistrationSet("invite", nil); err != nil {
			t.Fatal(err)
		}
		if r, _ := g.RegistrationGet(); r.Mode != "invite" || r.OpenGraceDays != 30 {
			t.Errorf("a nil grace changed the days: %+v", r)
		}
		if err := g.RegistrationGraceSet(7); err != nil {
			t.Fatal(err)
		}
		// Passkey configuration and its impact, through admin_read.
		wi, err := g.WebauthnImpact("other.test")
		if err != nil || wi.Credentials != 2 || wi.Users != 2 || wi.EnforcedUsers != 1 {
			t.Errorf("WebauthnImpact: %+v %v", wi, err)
		}
		if wi, _ := g.WebauthnImpact("example.test"); wi.Credentials != 0 {
			t.Errorf("a matching RP ID counted %d", wi.Credentials)
		}
		if err := g.WebauthnConfigSet(store.WebauthnConfig{RPID: "panel.localhost", AllowedOrigins: []string{"https://panel.localhost"}, Enabled: true}); err != nil {
			t.Fatal(err)
		}
		c, err := g.WebauthnConfigLock()
		if err != nil || c.RPID != "panel.localhost" || !c.Enabled || len(c.AllowedOrigins) != 1 {
			t.Errorf("config: %+v %v", c, err)
		}
		// Jobs: one active job of a kind.
		adminID := uuid.Nil
		if _, err := g.AdminJobInsert("registration_transition", []byte(`{"from":"closed","to":"open"}`), adminID); err != nil {
			t.Fatal(err)
		}
	})
	err := s.WithGlobal(f.ctx, store.TxOpts{}, func(g store.GlobalTx) error {
		_, err := g.AdminJobInsert("registration_transition", nil, uuid.Nil)
		return err
	})
	if !errors.Is(err, store.ErrConflict) {
		t.Errorf("a second active job of one kind: %v", err)
	}
	// The login page sees the settings the admin just wrote.
	cfg, err := f.db.Store(f.ctx, t, store.RoleTenant).Auth().PublicConfig(f.ctx)
	if err != nil || cfg.RegistrationMode != "invite" || !cfg.PasskeyEnabled || cfg.RPID != "panel.localhost" {
		t.Errorf("PublicConfig: %+v %v", cfg, err)
	}

	f.global(t, s, func(g store.GlobalTx) {
		// Users: both tenants, the prefix filter, paging.
		all, err := g.AdminUsersPage("", uuid.Nil, 10)
		if err != nil || len(all) != 2 {
			t.Fatalf("AdminUsersPage: %d %v", len(all), err)
		}
		for _, r := range all {
			if r.OneTimePasswordExpiresAt != nil || r.TenantStatus != "active" {
				t.Errorf("row %+v", r)
			}
		}
		if one, _ := g.AdminUsersPage(f.B.Phone, uuid.Nil, 10); len(one) != 1 || one[0].UserID != f.B.User {
			t.Errorf("prefix filter: %+v", one)
		}
		if p1, _ := g.AdminUsersPage("", uuid.Nil, 1); len(p1) != 1 {
			t.Fatal("page 1")
		} else if p2, _ := g.AdminUsersPage("", p1[0].UserID, 1); len(p2) != 1 || p2[0].UserID == p1[0].UserID {
			t.Errorf("page 2: %+v", p2)
		}
		if has, _ := g.PhoneHasAccount(f.A.Phone); !has {
			t.Error("PhoneHasAccount missed a phone")
		}
		if has, _ := g.PhoneHasAccount("+989000000001"); has {
			t.Error("PhoneHasAccount found a phone that has no account")
		}
		// Invites.
		id, err := g.InviteCreate(store.NewInvite{TokenHash: hash("inv-1"), Phone: "+989121110005", Locale: "en", TTL: 72 * time.Hour})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := g.InviteCreate(store.NewInvite{TokenHash: hash("inv-2"), Phone: "+989121110006", Locale: "fa", TTL: -time.Hour}); err != nil {
			t.Fatal(err)
		}
		rows, err := g.InvitesPage(uuid.Nil, 10)
		if err != nil || len(rows) != 2 || rows[0].State != "expired" || rows[1].State != "pending" || rows[1].ID != id {
			t.Errorf("InvitesPage: %+v %v", rows, err)
		}
		if ok, _ := g.InviteRevoke(id); !ok {
			t.Error("revoke")
		}
		if ok, _ := g.InviteRevoke(id); ok {
			t.Error("revoked twice")
		}
		if rows, _ = g.InvitesPage(uuid.Nil, 10); rows[1].State != "revoked" {
			t.Errorf("state after revoke: %s", rows[1].State)
		}
	})
	// An invite is found by the pre-tenant lookup until it is revoked.
	inv, ok, err := f.db.Store(f.ctx, t, store.RoleTenant).Auth().InviteByHash(f.ctx, hash("inv-1"))
	if err != nil || !ok || inv.RevokedAt == nil || inv.Phone != "+989121110005" {
		t.Errorf("InviteByHash: %+v %v %v", inv, ok, err)
	}
}

func TestAdminSMSSettings(t *testing.T) {
	f := newFixture(t)
	s := f.db.Store(f.ctx, t, store.RoleAdmin)
	f.global(t, s, func(g store.GlobalTx) {
		gwA, err := g.SMSGatewayEnsure(uuid.New(), "sms_ir")
		if err != nil {
			t.Fatal(err)
		}
		again, _ := g.SMSGatewayEnsure(uuid.New(), "sms_ir")
		if again != gwA {
			t.Errorf("a second ensure made a new gateway: %s then %s", gwA, again)
		}
		if _, err := g.SMSGatewayEnsure(uuid.New(), "melipayamak"); err != nil {
			t.Fatal(err)
		}
		// Routing needs credentials.
		if ok, _ := g.SMSRoutingSet("sms_ir", ""); ok {
			t.Error("a gateway with no credentials got a role")
		}
	})
	// The refused routing above leaves the roles as they were (the caller rolls
	// back); start clean in a new transaction.
	f.global(t, s, func(g store.GlobalTx) {
		gws, _ := g.SMSGateways()
		var ir, meli store.SMSGatewayRow
		for _, r := range gws {
			switch r.Provider {
			case "sms_ir":
				ir = r
			case "melipayamak":
				meli = r
			}
		}
		if ok, err := activate(g, ir.ID, "sms_ir", []byte("sealed-1"), "ab12"); err != nil || !ok {
			t.Fatal(ok, err)
		}
		if ok, _ := activate(g, meli.ID, "melipayamak", []byte("sealed-2"), "user"); !ok {
			t.Fatal("meli")
		}
		cost := "1250.5"
		if ok, _ := g.SMSGatewaySetCost(ir.ID, &cost); !ok {
			t.Fatal("cost")
		}
		if ok, err := g.SMSRoutingSet("sms_ir", "melipayamak"); err != nil || !ok {
			t.Fatalf("routing: %v %v", ok, err)
		}
		// A swap in one request does not trip the partial unique index.
		if ok, err := g.SMSRoutingSet("melipayamak", "sms_ir"); err != nil || !ok {
			t.Fatalf("swap: %v %v", ok, err)
		}
		gws, _ = g.SMSGateways()
		for _, r := range gws {
			if r.Provider == "noop" { // the seed's gateway lost its role to the routing above
				if r.Role != "disabled" {
					t.Errorf("noop kept the role %s", r.Role)
				}
				continue
			}
			want := map[string]string{"melipayamak": "primary", "sms_ir": "fallback"}[r.Provider]
			if r.Role != want || !r.Configured {
				t.Errorf("%s: role %s configured %v", r.Provider, r.Role, r.Configured)
			}
			if r.Provider == "sms_ir" && (r.CostPerMessage == nil || !strings.HasPrefix(*r.CostPerMessage, "1250.5") || r.Hint != "ab12") {
				t.Errorf("sms_ir row: %+v", r)
			}
		}
		// Templates and mappings.
		// Separate admin requests in production; one transaction here for brevity.
		g.ForgetLocks()
		tpls, err := g.SMSTemplates()
		if err != nil || len(tpls) != 12 { // the ten of 0011 less the two invite rows, plus the four of the notices (0062)
			t.Fatalf("templates: %d %v", len(tpls), err)
		}
		if ok, _ := g.SMSTemplateSet("otp", "en", "Code {code}"); !ok {
			t.Error("template update")
		}
		if ok, _ := g.SMSTemplateSet("nope", "en", "x"); ok {
			t.Error("a template that does not exist was updated")
		}
		g.ForgetLocks() // another request in production
		if err := g.SMSProviderTemplateSet(ir.ID, "otp", "fa", "123456", []string{"CODE"}); err != nil {
			t.Fatal(err)
		}
		if err := g.SMSProviderTemplateSet(ir.ID, "otp", "fa", "654321", []string{"CODE"}); err != nil {
			t.Fatal(err)
		}
		maps, _ := g.SMSProviderTemplates()
		var ours []store.SMSProviderTemplate
		for _, m := range maps {
			if m.Provider == "sms_ir" {
				ours = append(ours, m)
			}
		}
		if len(maps) != 2 || len(ours) != 1 || ours[0].ProviderTemplateID != "654321" {
			t.Errorf("mappings: %+v", maps)
		}
		// Limits.
		l, err := g.SMSLimitsGet()
		if err != nil || l.CapPhone != 5 || l.CapPhoneNet != 3 || l.CapIP != 20 || l.CapNet24 != 100 || l.CapGlobal != 5000 ||
			l.CooldownSeconds != 60 || l.SoftPercent != 80 || l.OutboxCapDaily != 200 || l.CostCapDaily != nil {
			t.Errorf("default limits: %+v %v", l, err)
		}
		// Separate admin requests in production; one transaction here for brevity.
		g.ForgetLocks()
		cap := "5000"
		l.CostCapDaily, l.CapGlobal = &cap, 100
		if err := g.SMSLimitsSet(l); err != nil {
			t.Fatal(err)
		}
		if l2, _ := g.SMSLimitsGet(); l2.CapGlobal != 100 || l2.CostCapDaily == nil {
			t.Errorf("limits not stored: %+v", l2)
		}
		// Outbox: queue, status, no phone in the status.
		g.ForgetLocks() // another request in production
		oid := uuid.New()
		if err := g.SMSOutboxInsert(store.NewOutbox{ID: oid, Kind: "test", GatewayID: ir.ID, Phone: "+989121110009", TemplateKey: "otp", Locale: "fa", ParamsCT: []byte("ct")}); err != nil {
			t.Fatal(err)
		}
		st, ok, err := g.SMSOutboxStatus(oid)
		if err != nil || !ok || st.State != "pending" {
			t.Errorf("status: %+v %v %v", st, ok, err)
		}
		if _, ok, _ := g.SMSOutboxStatus(uuid.New()); ok {
			t.Error("status of an unknown row")
		}
		// The seed logged one accepted delivery of the noop gateway.
		if days, gw, err := g.SMSStats(7); err != nil || len(days) != 0 || len(gw) != 1 || gw[0].Provider != "noop" || gw[0].Accepted != 1 {
			t.Errorf("stats: %v %v %v", days, gw, err)
		}
	})
	// A bad value in the limits is a constraint error, not a stored value.
	err := s.WithGlobal(f.ctx, store.TxOpts{}, func(g store.GlobalTx) error {
		l, _ := g.SMSLimitsGet()
		l.CooldownSeconds = 1
		return g.SMSLimitsSet(l)
	})
	if !errors.Is(err, store.ErrConstraint) {
		t.Errorf("cooldown of 1 second: %v", err)
	}
}

// TestAdminReissuesAOneTimePassword is the database half of T-536 (10.7): the
// whole sequence as ctrlz_admin inside WithTenant, with the refusals.
func TestAdminReissuesAOneTimePassword(t *testing.T) {
	f := newFixture(t)
	admin := f.db.Store(f.ctx, t, store.RoleAdmin)
	tenant := f.db.Store(f.ctx, t, store.RoleTenant)
	super := f.superConn(t)

	reg, ok, err := admin.Admin().CreateUser(f.ctx, "+989121110020", secret.New("first-otp"), "fa")
	if err != nil || !ok {
		t.Fatal(ok, err)
	}
	user := reg.UserID
	// The user logged in with it: a restricted session and an open mfa ticket.
	var sess uuid.UUID
	if err := tenant.WithTenant(f.ctx, reg.TenantID, store.TxOpts{}, func(tx store.Tx) error {
		var err error
		sess, err = tx.SessionCreate(store.NewSession{At: time.Now(), UserID: user, TokenHash: hash("otp-sess"), IdleExpiresAt: time.Now().Add(time.Hour),
			AbsoluteExpiresAt: time.Now().Add(time.Hour), Restricted: true, AuthMethod: "password"})
		if err != nil {
			return err
		}
		_, err = tx.RefreshCreate(store.NewRefresh{SessionID: sess, UserID: user, FamilyID: uuid.New(), TokenHash: hash("otp-ref"), ExpiresAt: time.Now().Add(time.Hour)})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := tenant.Auth().TicketPut(f.ctx, store.NewTicket{TokenHash: sha32(5), Kind: store.TicketMFA, Tenant: reg.TenantID, User: user, TTL: time.Minute}); err != nil || !ok {
		t.Fatal(ok, err)
	}
	var before *time.Time
	if err := super.QueryRow(f.ctx, "SELECT password_changed_at FROM ctrlz.users WHERE id = $1", user).Scan(&before); err != nil {
		t.Fatal(err)
	}

	err = admin.WithTenant(f.ctx, reg.TenantID, store.TxOpts{}, func(tx store.Tx) error {
		st, found, err := tx.OneTimePasswordLock(user)
		if err != nil || !found || st.State != credstate.OneTimeLive || !st.NoSecondFactor || st.TenantStatus != "active" {
			t.Errorf("OneTimePasswordLock: %+v %v %v", st, found, err)
		}
		expires, err := tx.OneTimePasswordSet(user, secret.New("second-otp"))
		if err != nil || time.Until(expires) < 71*time.Hour {
			t.Errorf("OneTimePasswordSet: %v %v", expires, err)
		}
		// Tickets first: they rank before sessions (internal/lockrank), as in the route.
		if err := tx.TicketsRevoke(user); err != nil {
			t.Errorf("TicketsRevoke as admin: %v", err)
		}
		if n, err := tx.RevokeUserSessions(user); err != nil || n != 1 {
			t.Errorf("revoked sessions: %d %v", n, err)
		}
		if _, err := tx.AdminAuditAppend(store.AuditEntry{At: time.Now(), Action: "user.password_reissue", Target: "tenant:" + reg.TenantID.String(),
			Params: []byte(`{"was_expired":false}`), Canonical: []byte("c")}); err != nil {
			t.Errorf("AdminAuditAppend: %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	u, ok, err := tenant.Auth().UserByPhone(f.ctx, "+989121110020")
	if err != nil || !ok || u.PasswordHash.Reveal() != "second-otp" || u.State != credstate.OneTimeLive {
		t.Fatalf("after the re-issue: %+v %v %v", u, ok, err)
	}
	var after *time.Time
	var revoked, tickets, refresh int
	for _, q := range []struct {
		sql  string
		dest any
	}{
		{"SELECT password_changed_at FROM ctrlz.users WHERE id = $1", &after},
		{"SELECT count(*) FROM ctrlz.sessions WHERE user_id = $1 AND revoked_at IS NOT NULL", &revoked},
		{"SELECT count(*) FROM ctrlz.auth_tickets WHERE subject_user = $1 AND consumed_at IS NOT NULL", &tickets},
		{"SELECT count(*) FROM ctrlz.refresh_tokens WHERE user_id = $1 AND revoked_at IS NOT NULL", &refresh},
	} {
		if err := super.QueryRow(f.ctx, q.sql, user).Scan(q.dest); err != nil {
			t.Fatal(err)
		}
	}
	if (before == nil) != (after == nil) || revoked != 1 || tickets != 1 || refresh != 1 {
		t.Errorf("password_changed_at moved or something was not revoked: before %v after %v, sessions %d tickets %d refresh %d", before, after, revoked, tickets, refresh)
	}
	if _, ok, _ := tenant.Auth().SessionByHash(f.ctx, hash("otp-sess")); !ok {
		t.Fatal("the session row is gone")
	} else if info, _, _ := tenant.Auth().SessionByHash(f.ctx, hash("otp-sess")); info.RevokedAt == nil {
		t.Error("the restricted session is still live")
	}

	// Two tenants: A's own password is not a one-time password, and a user of
	// another tenant is not found from this tenant's transaction.
	_ = admin.WithTenant(f.ctx, f.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
		st, found, err := tx.OneTimePasswordLock(f.A.User)
		if err != nil || !found || st.State != credstate.Ready {
			t.Errorf("a user with a password of their own: %+v %v %v", st, found, err)
		}
		if _, found, _ := tx.OneTimePasswordLock(user); found {
			t.Error("a user of another tenant was found")
		}
		if _, err := tx.OneTimePasswordSet(user, secret.New("hijack")); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("a user of another tenant was re-issued from this tenant: %v", err)
		}
		return nil
	})
	if u2, _, _ := tenant.Auth().UserByPhone(f.ctx, "+989121110020"); u2.PasswordHash.Reveal() != "second-otp" {
		t.Error("the cross-tenant attempt changed the hash")
	}
	// The CHECK: an expiry without must_reset is not a one-time password.
	if _, err := super.Exec(f.ctx, "UPDATE ctrlz.users SET password_expires_at = now() WHERE id = $1", f.A.User); err == nil {
		t.Error("an expiry on a user with must_reset false was accepted")
	}
	// A suspended tenant stays eligible, a deleting one is read as such.
	if _, err := super.Exec(f.ctx, "UPDATE ctrlz.tenants SET status = 'deleting' WHERE id = $1", reg.TenantID); err != nil {
		t.Fatal(err)
	}
	_ = admin.WithTenant(f.ctx, reg.TenantID, store.TxOpts{}, func(tx store.Tx) error {
		if st, found, _ := tx.OneTimePasswordLock(user); !found || st.TenantStatus != "deleting" {
			t.Errorf("deleting tenant: %+v %v", st, found)
		}
		return nil
	})
	// A user with a passkey is not eligible.
	if _, err := super.Exec(f.ctx, "UPDATE ctrlz.tenants SET status = 'active' WHERE id = $1", reg.TenantID); err != nil {
		t.Fatal(err)
	}
	_ = tenant.WithTenant(f.ctx, reg.TenantID, store.TxOpts{}, func(tx store.Tx) error {
		_, _, _, err := tx.PasskeyAdd(store.Credential{UserID: user, CredentialID: hash("cred-otp"), PublicKey: hash("pk"), RPID: "example.test"}, 20)
		return err
	})
	_ = admin.WithTenant(f.ctx, reg.TenantID, store.TxOpts{}, func(tx store.Tx) error {
		if st, found, _ := tx.OneTimePasswordLock(user); !found || st.NoSecondFactor {
			t.Errorf("a user with a passkey: %+v %v", st, found)
		}
		return nil
	})
}

func TestTOTPDeclareLostStore(t *testing.T) {
	f := newFixture(t)
	keytool := f.db.Store(f.ctx, t, store.RoleKeytool)
	worker := f.db.Store(f.ctx, t, store.RoleWorker)
	admin := f.db.Store(f.ctx, t, store.RoleAdmin)
	super := f.superConn(t)
	// Both users are sealed under key 1 ("CZ", version 1, key number 1).
	for _, u := range []uuid.UUID{f.A.User, f.B.User} {
		if _, err := super.Exec(f.ctx, "UPDATE ctrlz.users SET totp_secret_ct = decode('435a010001' || repeat('00', 40), 'hex'), totp_enabled_at = now(), totp_last_step = 4 WHERE id = $1", u); err != nil {
			t.Fatal(err)
		}
	}
	// What the tool passes: the seeds it read and could not open (round 13, admin-r13-3).
	var aSeed []byte
	if err := super.QueryRow(f.ctx, "SELECT totp_secret_ct FROM ctrlz.users WHERE id = $1", f.A.User).Scan(&aSeed); err != nil {
		t.Fatal(err)
	}
	lostA := []store.TOTPSecret{{User: f.A.User, CT: aSeed}}
	// The admin role cannot call it, whatever tenant it opens (db-r3-1, db-r3-5).
	if err := admin.WithTenant(f.ctx, f.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
		_, err := tx.TOTPDeclareLost(1, lostA)
		return err
	}); err == nil {
		t.Fatal("the admin role cleared a user's second factor")
	}
	// Nor can the long-running worker, which reads login codes (db-r4-3, db-r4-6).
	if err := worker.WithTenant(f.ctx, f.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
		_, err := tx.TOTPDeclareLost(1, lostA)
		return err
	}); err == nil {
		t.Fatal("the worker role cleared a user's second factor")
	}
	// A key number that names no seed clears nothing.
	if err := keytool.WithTenant(f.ctx, f.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
		n, err := tx.TOTPDeclareLost(2, lostA)
		if n != 0 {
			t.Errorf("key 2 cleared %d users sealed under key 1", n)
		}
		// A seed that is sealed under key 1 and not listed is not lost: B's seed is under key 1 as
		// well, and so is a listed seed of another tenant.
		n, err = tx.TOTPDeclareLost(1, []store.TOTPSecret{{User: f.B.User, CT: aSeed}})
		if n != 0 {
			t.Errorf("another tenant's user was cleared: %d", n)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := keytool.WithTenant(f.ctx, f.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
		n, err := tx.TOTPDeclareLost(1, lostA)
		if n != 1 {
			t.Errorf("cleared %d users", n)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	for u, want := range map[uuid.UUID]bool{f.A.User: false, f.B.User: true} {
		var enabled bool
		var codes int
		if err := super.QueryRow(f.ctx, "SELECT totp_enabled_at IS NOT NULL AND totp_secret_ct IS NOT NULL FROM ctrlz.users WHERE id = $1", u).Scan(&enabled); err != nil {
			t.Fatal(err)
		}
		if err := super.QueryRow(f.ctx, "SELECT count(*) FROM ctrlz.recovery_codes WHERE user_id = $1", u).Scan(&codes); err != nil {
			t.Fatal(err)
		}
		if enabled != want || codes != 1 { // the recovery codes stay (8.5)
			t.Errorf("user %s: TOTP kept %v, codes %d, want kept=%v and one code", u, enabled, codes, want)
		}
	}
	// The notice and the audit row came with the change, for A only.
	for tenant, want := range map[uuid.UUID]int{f.A.Tenant: 1, f.B.Tenant: 0} {
		var notices, audits int
		if err := super.QueryRow(f.ctx, "SELECT count(*) FROM ctrlz.notifications WHERE tenant_id = $1 AND kind = 'totp_lost'", tenant).Scan(&notices); err != nil {
			t.Fatal(err)
		}
		if err := super.QueryRow(f.ctx, "SELECT count(*) FROM ctrlz.tenant_audit_log WHERE tenant_id = $1 AND action = 'totp.declared_lost'", tenant).Scan(&audits); err != nil {
			t.Fatal(err)
		}
		if notices != want || audits != want {
			t.Errorf("tenant %s: %d notices, %d audit rows, want %d each", tenant, notices, audits, want)
		}
	}
}

// TestAdminJobsSupersede is admin-r5-2 at the store: an unfinished job of a kind is ended by the
// admin so that the next one can be queued, only the three columns that end a job are the
// admin's to write, a job another kind or one already finished is left alone, and a worker that
// was still on the old one loses its finish.
func TestAdminJobsSupersede(t *testing.T) {
	f := newFixture(t)
	admin := f.db.Store(f.ctx, t, store.RoleAdmin)
	worker := f.db.Store(f.ctx, t, store.RoleWorker)
	super := f.superConn(t)
	if _, err := super.Exec(f.ctx, "DELETE FROM ctrlz.admin_jobs"); err != nil {
		t.Fatal(err)
	}
	var reg, rp uuid.UUID
	f.global(t, admin, func(g store.GlobalTx) {
		var err error
		if reg, err = g.AdminJobInsert("registration_transition", nil, uuid.Nil); err != nil {
			t.Fatal(err)
		}
		if rp, err = g.AdminJobInsert("webauthn_rp_change", nil, uuid.Nil); err != nil {
			t.Fatal(err)
		}
	})
	// A running job is ended too, and only the kind asked for.
	if _, err := super.Exec(f.ctx, "UPDATE ctrlz.admin_jobs SET state = 'running', started_at = now() WHERE id = $1", reg); err != nil {
		t.Fatal(err)
	}
	f.global(t, admin, func(g store.GlobalTx) {
		n, err := g.AdminJobsSupersede("registration_transition")
		if err != nil || n != 1 {
			t.Fatalf("AdminJobsSupersede: %d %v", n, err)
		}
		if n, _ := g.AdminJobsSupersede("registration_transition"); n != 0 {
			t.Errorf("a second supersede ended %d jobs", n)
		}
		if _, err := g.AdminJobInsert("registration_transition", nil, uuid.Nil); err != nil {
			t.Errorf("the slot of the kind is still taken: %v", err)
		}
	})
	var state, progress string
	if err := super.QueryRow(f.ctx, "SELECT state, progress::text FROM ctrlz.admin_jobs WHERE id = $1", reg).Scan(&state, &progress); err != nil {
		t.Fatal(err)
	}
	if state != "failed" || !strings.Contains(progress, "superseded") {
		t.Errorf("the superseded job is %s %s", state, progress)
	}
	if err := super.QueryRow(f.ctx, "SELECT state FROM ctrlz.admin_jobs WHERE id = $1", rp).Scan(&state); err != nil || state != "queued" {
		t.Errorf("a job of another kind was ended: %s %v", state, err)
	}
	// The worker that was walking it finds it ended: the hold fails and its finish is a loss.
	if err := worker.WithTenant(f.ctx, f.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
		held, err := tx.AdminJobHold(reg)
		if err != nil || held {
			t.Errorf("AdminJobHold on a superseded job: %v %v", held, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	f.global(t, worker, func(g store.GlobalTx) {
		if w, err := g.AdminJobFinish(reg, "done", nil); err != nil || w.Yes() {
			t.Errorf("the worker finished a superseded job: %v %v", w.Yes(), err)
		}
	})
	// The admin may end a job and change nothing else of it.
	for col, want := range map[string]bool{"state": true, "progress": true, "finished_at": true,
		"kind": false, "params": false, "created_by": false, "created_at": false, "started_at": false} {
		var got bool
		if err := super.QueryRow(f.ctx, "SELECT has_column_privilege('ctrlz_admin', 'ctrlz.admin_jobs', $1, 'UPDATE')", col).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("ctrlz_admin UPDATE on admin_jobs.%s = %v, want %v", col, got, want)
		}
	}
	var del bool
	if err := super.QueryRow(f.ctx, "SELECT has_table_privilege('ctrlz_admin', 'ctrlz.admin_jobs', 'DELETE')").Scan(&del); err != nil || del {
		t.Errorf("ctrlz_admin can DELETE admin_jobs: %v %v", del, err)
	}

}

// theSeedAdmin is the admin the global seed makes (the id of seedAdmin in clock_boundary_test.go,
// which compiles only on Windows, so a test that must run on the Linux CI keeps its own copy).
var theSeedAdmin = uuid.MustParse("00000000-0000-7000-8000-0000000000e1")

// TestAdminRehashIsACompareAndSetOnTheGeneration is admin-r10-1 at the store: a rehash carries the
// stamp of the password that was verified and writes only while the row still has that generation.
// A reset, a password change or any other credential change that committed after the check leaves
// the stamp stale: no write, a zero stamp and ok false. Without the compare the hash of the old
// password lands over the new one and the old password works again.
func TestAdminRehashIsACompareAndSetOnTheGeneration(t *testing.T) {
	f := newFixture(t)
	s := f.db.Store(f.ctx, t, store.RoleAdmin)
	hashOf := func() (h string) {
		f.global(t, s, func(g store.GlobalTx) {
			u, ok, err := g.AdminUserByID(theSeedAdmin)
			if err != nil || !ok {
				t.Fatal(ok, err)
			}
			h = u.PasswordHash.Reveal()
		})
		return h
	}
	stampOf := func() (st credgen.Stamp) {
		f.global(t, s, func(g store.GlobalTx) {
			u, ok, err := g.AdminUserLockByID(theSeedAdmin)
			if err != nil || !ok {
				t.Fatal(ok, err)
			}
			st = u.Stamp()
		})
		return st
	}
	rehash := func(st credgen.Stamp, h string) (next credgen.Stamp, ok bool) {
		f.global(t, s, func(g store.GlobalTx) {
			var err error
			if next, ok, err = g.AdminRehash(st, secret.New(h)); err != nil {
				t.Fatal(err)
			}
		})
		return next, ok
	}

	// A current stamp writes, and the write moves the generation.
	issued := stampOf()
	next, ok := rehash(issued, "rehash-1")
	if !ok || next.Gen == issued.Gen || next.Subject != theSeedAdmin || hashOf() != "rehash-1" {
		t.Fatalf("a current stamp: ok %v, %+v after %+v, hash %q", ok, next, issued, hashOf())
	}

	// The stamp of the write just made is stale now: the generation moved with it.
	if again, ok := rehash(issued, "rehash-stale"); ok || !again.Zero() || hashOf() != "rehash-1" {
		t.Fatalf("a stamp from before the last write: ok %v, %+v, hash %q", ok, again, hashOf())
	}

	// Each change of the password leaves a stamp taken before it stale.
	for name, change := range map[string]func(g store.GlobalTx) (bool, error){
		"console reset": func(g store.GlobalTx) (bool, error) { return g.AdminReset(theSeedAdmin, secret.New("otp-hash"), false) },
		"password change": func(g store.GlobalTx) (bool, error) {
			_, ok, err := g.AdminSetPassword(theSeedAdmin, secret.New("chosen-hash"))
			return ok, err
		},
	} {
		before := stampOf()
		f.global(t, s, func(g store.GlobalTx) {
			if ok, err := change(g); err != nil || !ok {
				t.Fatalf("%s: %v %v", name, ok, err)
			}
		})
		kept := hashOf()
		if got, ok := rehash(before, "rehash-of-the-old-password"); ok || !got.Zero() || hashOf() != kept {
			t.Errorf("a rehash after a %s: ok %v, %+v, hash %q (was %q)", name, ok, got, hashOf(), kept)
		}
	}

	// A stamp that is zero, names another subject, or belongs to a tenant writes nothing.
	cur := stampOf()
	kept := hashOf()
	for name, st := range map[string]credgen.Stamp{
		"zero":          {},
		"other subject": {Subject: uuid.New(), Gen: cur.Gen},
		"tenant stamp":  {Tenant: uuid.New(), Subject: theSeedAdmin, Gen: cur.Gen},
	} {
		if got, ok := rehash(st, "rehash-refused"); ok || !got.Zero() || hashOf() != kept {
			t.Errorf("%s stamp: ok %v, %+v, hash %q", name, ok, got, hashOf())
		}
	}
}
