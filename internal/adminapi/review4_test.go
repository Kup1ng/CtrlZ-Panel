package adminapi

import (
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/marker"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/password"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/session"
	"github.com/Kup1ng/CtrlZ-Panel/internal/credgen"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// Tests of review round 4 for the admin API (admin-r4-N).

// within fails when a and b are more than d apart.
func within(t *testing.T, what string, a, b time.Time, d time.Duration) {
	t.Helper()
	if diff := a.Sub(b); diff > d || diff < -d {
		t.Fatalf("%s: %v apart (%v and %v), want within %v", what, diff, a, b, d)
	}
}

// TestAdminSessionClocksUseTheApplicationClock covers admin-r4-1. The five minute
// window and the notice cutoff are compared with the application clock, so the
// session columns they read must be stamped with it. They were stamped by the
// database's now(): a database 3 hours ahead kept the window open for hours, one
// behind closed it on arrival, and a database behind the application let a
// thief's session clear the banner it had just caused. Both directions run.
func TestAdminSessionClocksUseTheApplicationClock(t *testing.T) {
	for name, skew := range map[string]time.Duration{"app ahead of database": 3 * time.Hour, "app behind database": -3 * time.Hour} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			r.syncClock()
			r.ck.add(skew)
			seed := r.setupAdmin(t, true)
			b := r.browser()
			b.mustLogin(seed)

			var verified, created time.Time
			r.env.Scan(t, `SELECT totp_verified_at, created_at FROM ctrlz.admin_sessions WHERE admin_id = $1`, []any{seedAdmin}, &verified, &created)
			within(t, "totp_verified_at against the application clock", verified, r.ck.now(), 2*time.Second)
			within(t, "created_at against the application clock", created, r.ck.now(), 2*time.Second)

			// The window opened by the login lasts five minutes of application time.
			b.put("/settings/registration", map[string]any{"mode": "closed"}).want(200, "")
			var me struct {
				FreshUntil *time.Time `json:"fresh_until"`
			}
			b.get("/me").want(200, "").json(&me)
			if me.FreshUntil == nil {
				t.Fatal("no fresh_until right after a login with a code")
			}
			within(t, "fresh_until", *me.FreshUntil, r.ck.now().Add(5*time.Minute), 2*time.Second)
			r.ck.add(4 * time.Minute)
			b.put("/settings/registration", map[string]any{"mode": "closed"}).want(200, "")
			r.ck.add(2 * time.Minute)
			b.put("/settings/registration", map[string]any{"mode": "closed"}).want(403, "totp_fresh_required")

			// A fresh code reopens it from the application time as well.
			r.freeStep(t)
			var win struct {
				FreshUntil time.Time `json:"fresh_until"`
			}
			b.post("/auth/totp/fresh", map[string]any{"code": totpNow(seed)}).want(200, "").json(&win)
			within(t, "fresh_until after /auth/totp/fresh", win.FreshUntil, r.ck.now().Add(5*time.Minute), 2*time.Second)
			r.env.Scan(t, `SELECT totp_verified_at FROM ctrlz.admin_sessions WHERE admin_id = $1`, []any{seedAdmin}, &verified)
			within(t, "totp_verified_at after /auth/totp/fresh", verified, r.ck.now(), 2*time.Second)
			b.put("/settings/registration", map[string]any{"mode": "closed"}).want(200, "")
		})
	}
}

// TestNoticeAckCutoffUsesTheApplicationClock is the notice half of admin-r4-1: the
// session that made a gateway change cannot dismiss the notice whichever way the
// database clock is off, because created_at and the notice time share a clock.
func TestNoticeAckCutoffUsesTheApplicationClock(t *testing.T) {
	for name, skew := range map[string]time.Duration{"app ahead of database": 3 * time.Hour, "app behind database": -3 * time.Hour} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			r.syncClock()
			r.ck.add(skew)
			thief, _ := r.admin(t)
			thief.put("/sms/gateways/sms_ir", map[string]any{"credentials": map[string]string{"api_key": "attacker-account-key-123456"}}).want(200, "")
			thief.put("/sms/routing", map[string]any{"primary": "sms_ir"}).want(200, "")
			thief.post("/me/notices/ack", map[string]any{}).want(204, "")
			var me struct {
				Notices []struct {
					Kind string `json:"kind"`
				} `json:"notices"`
			}
			thief.get("/me").want(200, "").json(&me)
			if len(me.Notices) != 2 {
				t.Fatalf("the session dismissed its own banner under a %v skew: %d notices left, want 2", skew, len(me.Notices))
			}
		})
	}
}

// TestAdminPasswordExpiryUsesTheDatabaseClock is the same class for the one-hour
// expiry of a chosen password before TOTP is enrolled. Round 4 counted it on the
// application clock; round 5 (rule one-time-state) moved it to the database, the clock
// ctrlz.credential_state compares it with, so a skewed application host cannot stretch
// or close the hour: it is the database's now() plus an hour whatever the host says.
func TestAdminPasswordExpiryUsesTheDatabaseClock(t *testing.T) {
	for name, skew := range map[string]time.Duration{"app ahead of database": 3 * time.Hour, "app behind database": -3 * time.Hour} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			r.syncClock()
			r.ck.add(skew)
			r.setupAdmin(t, false)
			b := r.browser()
			b.login(adminPW, "").want(200, "")
			b.post("/me/password", map[string]any{"current_password": adminPW, "new_password": adminNewPW}).want(204, "")
			var untilExpiry time.Duration
			r.env.Scan(t, `SELECT password_expires_at - now() FROM ctrlz.admin_users WHERE id = $1`, []any{seedAdmin}, &untilExpiry)
			if untilExpiry < 59*time.Minute || untilExpiry > 61*time.Minute {
				t.Fatalf("the chosen password lives %v under a %v skew of the application clock, want an hour of database time", untilExpiry, skew)
			}
			// Inside the hour the password opens a setup session, past it the same password
			// is a wrong one, whatever the application clock says.
			r.env.Exec(t, `UPDATE ctrlz.admin_users SET password_expires_at = now() + interval '1 minute' WHERE id = $1`, seedAdmin)
			r.browser().login(adminNewPW, "").want(200, "")
			r.env.Exec(t, `UPDATE ctrlz.admin_users SET password_expires_at = now() - interval '1 minute' WHERE id = $1`, seedAdmin)
			r.browser().login(adminNewPW, "").want(401, "invalid_credentials")
		})
	}
}

// TestDeviceMarkerIsReissuedAfterCredentialChanges covers admin-r4-4. A chosen
// password and a confirmed authenticator each move the credential generation,
// and the response must carry a marker under the new one; otherwise the admin's
// own browser counts on admin_login_user again after the first setup.
func TestDeviceMarkerIsReissuedAfterCredentialChanges(t *testing.T) {
	r := newRig(t)
	r.setupAdmin(t, false)
	svc := marker.New(r.keys, r.ck.now)
	generation := func() credgen.Stamp {
		t.Helper()
		var gen credgen.Stamp
		if err := r.adm.WithGlobal(r.env.Ctx, store.TxOpts{}, func(g store.GlobalTx) error {
			u, ok, err := g.AdminUserByID(seedAdmin)
			if !ok {
				t.Fatal("admin not found")
			}
			gen = u.Stamp()
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return gen
	}
	b := r.browser()
	b.login(adminPW, "").want(200, "")

	// A call that moved the generation hands out a marker that matches the new one
	// and no longer matches the old one.
	assertMarker := func(step string, before credgen.Stamp) credgen.Stamp {
		t.Helper()
		c := b.jar[session.CookieAdminDevice]
		if c == nil {
			t.Fatalf("%s: no device marker in the response", step)
		}
		now := generation()
		if now == before {
			t.Fatalf("%s: the credential generation did not move", step)
		}
		if !svc.Open(marker.Admin, c.Value).Holds(now) {
			t.Fatalf("%s: the marker does not match the account's new generation", step)
		}
		if svc.Open(marker.Admin, c.Value).Holds(before) {
			t.Fatalf("%s: the marker still matches the old generation", step)
		}
		return now
	}

	before := generation()
	r.ck.add(time.Minute)
	b.post("/me/password", map[string]any{"current_password": adminPW, "new_password": adminNewPW}).want(204, "")
	after := assertMarker("password change", before)

	var setup struct {
		Secret string `json:"secret"`
	}
	b.post("/me/totp/setup", map[string]any{}).want(200, "").json(&setup)
	seed := seedFromBase32(t, setup.Secret)
	r.ck.add(time.Minute)
	b.post("/me/totp/confirm", map[string]any{"code": totpNow(seed)}).want(204, "")
	assertMarker("totp confirm", after)
}

// TestBusyGateAnswersAreTheRecordedPriceOfOneTimeLogin records the decision of
// admin-r4-6. With the one-slot Argon2 gate held, an unknown username and an
// account with a password the admin chose both wait and answer 503, while an
// account holding a console one-time password is answered at once (its hash is
// cheap and takes no slot, admin-r3-11), so the status code and the time tell
// that account apart. Hiding it would mean making the one-time login wait for the
// gate, which is what admin-r3-11 removed so that strangers cannot keep the owner
// out of the first login. The leak needs a saturated gate, costs the attacker
// the login budgets, and names a username the console just reset; spec 10.2
// records it. If this test fails because the three answers became the same, the
// spec paragraph is stale.
func TestBusyGateAnswersAreTheRecordedPriceOfOneTimeLogin(t *testing.T) {
	r := newRig(t)
	r.setupAdmin(t, false)
	const otp = "ONETIMEPASSWORDXYZ234567"
	oneTime, err := r.hasher.HashOneTime(secretOf(otp))
	if err != nil {
		t.Fatal(err)
	}
	r.env.Exec(t, `UPDATE ctrlz.admin_users SET password_hash = $2, password_expires_at = now() + interval '24 hours' WHERE id = $1`, seedAdmin, oneTime.Reveal())
	gate := password.NewGate(1, 100*time.Millisecond)
	rel, err := gate.Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer rel()
	busy, err := password.NewHasher(password.Params{MemoryKiB: 64, Time: 1, Threads: 1}, gate)
	if err != nil {
		t.Fatal(err)
	}
	h := r.handler(t, func(d *Deps) { d.Hasher = busy })
	login := func(user, pw string) *aresp {
		return r.browser().callOn(h, adminHost, "POST", "/auth/login", map[string]any{"username": user, "password": pw})
	}
	login("nobody-here", "wrong-wrong-wrong-1").want(503, "server_busy")
	login(adminName, "wrong-wrong-wrong-1").want(401, "invalid_credentials") // the one-time account
	full, err := r.hasher.Hash(r.env.Ctx, secretOf(adminNewPW))
	if err != nil {
		t.Fatal(err)
	}
	r.env.Exec(t, `UPDATE ctrlz.admin_users SET password_hash = $2, must_change_password = false, password_expires_at = NULL WHERE id = $1`, seedAdmin, full.Reveal())
	login(adminName, "wrong-wrong-wrong-1").want(503, "server_busy") // a chosen password: the same as an unknown name
}
