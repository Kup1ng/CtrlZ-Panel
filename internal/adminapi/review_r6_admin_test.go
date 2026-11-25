package adminapi

import (
	"context"
	"errors"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/password"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/totp"
	"github.com/Kup1ng/CtrlZ-Panel/internal/authtest"
	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
	"github.com/google/uuid"
	"net/netip"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/session"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/throttle"
	"github.com/Kup1ng/CtrlZ-Panel/internal/budget"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testwait"
)

// TestOneAddressCannotSpendTheUsernameScope is admin-r6-4. admin_login (username and network, 5)
// exists so that one place cannot lock the owner out; admin_login_user (username alone, 30) is
// shared by every browser without a device marker, a new device, a marker older than its life and
// every browser after a credential change among them. Round 5 charged all three scopes on every
// attempt, so one address that its own pair had long turned away still spent the shared scope,
// and the owner on any other network got 429 with the right password and code.
func TestOneAddressCannotSpendTheUsernameScope(t *testing.T) {
	r := newRig(t)
	seed := r.setupAdmin(t, true)
	attacker := r.browser()
	for i := 0; i < 8; i++ {
		r.ck.add(time.Minute) // the rate class of the login is not the bound under test
		if i < 5 {
			attacker.login("wrong-wrong-wrong-1", "").want(401, "invalid_credentials")
		} else {
			attacker.login("wrong-wrong-wrong-1", "").want(429, "too_many_attempts")
		}
	}
	// The attacker keeps going at the rate of its network for much longer than a window.
	svc := throttle.NewAdmin(r.adm.Admin(), r.keys)
	for i := 0; i < 100; i++ {
		_, err := svc.AdminLoginHits(r.env.Ctx, adminName, netip.MustParseAddr(attacker.ip), "")
		if err != nil {
			t.Fatal(err)
		}
	}
	pol, _ := throttle.PolicyOf(throttle.AdminLogin)
	if got := scopeSum(t, r, "admin_login_user"); got > pol.Max {
		t.Fatalf("one address spent admin_login_user %d times, more than the %d its own pair allows", got, pol.Max)
	}
	// The owner, on another network and with no marker, still signs in with the right proofs.
	r.browser().mustLogin(seed)
}

// TestACopyOfTheCookieCannotSpendTheOwnersLogin is admin-r6-5, and the abuse test that the
// rule's addition asks for: every scope that a session cookie alone can charge is filled from a
// copy of the cookie, and then a login with the owner's marker, password and code must pass. The
// set of scopes is read from the registry (Bucket.SessionReach), and a scope with no driver here
// fails, so a new one cannot be declared without being driven.
func TestACopyOfTheCookieCannotSpendTheOwnersLogin(t *testing.T) {
	drivers := map[string]func(thief *browser){
		"admin_totp_session": func(thief *browser) { thief.post("/auth/totp/fresh", map[string]any{"code": "000000"}) },
		"admin_reauth": func(thief *browser) {
			thief.post("/me/password", map[string]any{"current_password": "wrong-wrong-wrong-1", "new_password": adminNewPW})
		},
	}
	for _, b := range budget.Of(budget.Throttle, budget.Admin) {
		if !b.SessionReach {
			continue
		}
		drive, ok := drivers[b.Name]
		if !ok {
			t.Errorf("%s can be charged by a bare session cookie and this test has no driver for it", b.Name)
			continue
		}
		t.Run(b.Name, func(t *testing.T) {
			r := newRig(t)
			owner, seed := r.admin(t)
			// The owner's browser holds a marker; the thief holds only the session cookie.
			sessionName := session.AdminCookie(secretOf("x")).Name
			thief := r.browser()
			trusted := r.browser()
			for name, c := range owner.jar {
				if name == sessionName {
					thief.jar[name] = c
				} else {
					trusted.jar[name] = c
				}
			}
			if len(thief.jar) == 0 || len(trusted.jar) == 0 {
				t.Fatalf("expected a session cookie and a device marker in the jar, got %d and %d", len(thief.jar), len(trusted.jar))
			}
			for i := 0; i < 12; i++ {
				drive(thief)
			}
			if got := scopeSum(t, r, "admin_totp"); got != 0 {
				t.Fatalf("a copy of the cookie moved admin_totp by %d", got)
			}
			// The owner's browser with its marker, the right password and the current code.
			r.freeStep(t)
			trusted.login(adminPW, totpNow(seed)).want(200, "")
			// And a browser with no marker at all, on a network of its own.
			r.freeStep(t)
			r.browser().login(adminPW, totpNow(seed)).want(200, "")
		})
	}
}

// TestMoneyCapAndPriceWritersDoNotRace is admin-r6-3. "A money cap needs a price on every routed
// gateway" is checked by three writers (the limits, a gateway's price, the routing), each of which
// writes one table and then reads the other under Read Committed. The interleaving is driven here
// by hand, with no luck in it: both writers write, both then look at the other table, and only then
// does either commit. Without the settings row lock a cap and an unpriced primary both commit; with
// it the second writer's check waits for the first's commit and reads it, so one of them is refused.
func TestMoneyCapAndPriceWritersDoNotRace(t *testing.T) {
	cases := map[string]struct {
		// b is the writer that can open the gap on the gateway side.
		b func(g store.GlobalTx, unpriced, primary uuid.UUID) error
	}{
		"price removal": {func(g store.GlobalTx, _, primary uuid.UUID) error {
			_, err := g.SMSGatewaySetCost(primary, nil)
			return err
		}},
		"routing an unpriced gateway": {func(g store.GlobalTx, _, _ uuid.UUID) error {
			failed, err := g.SMSRoutingSetNamed("", "sms_ir")
			if err == nil && failed != "" {
				err = errors.New("routing refused: " + failed)
			}
			return err
		}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			r.env.ResetSMS(t)
			primary := r.env.AddGateway(t, r.keys, authtest.Gateway{Provider: "melipayamak", Role: "primary", Credentials: `{"username":"u","password":"p"}`, Price: "95"})
			unpriced := r.env.AddGateway(t, r.keys, authtest.Gateway{Provider: "sms_ir", Role: "disabled", Credentials: `{"api_key":"TESTKEY-abcdef-1234567"}`})
			r.env.Exec(t, `UPDATE ctrlz.system_settings SET sms_cost_cap_daily = NULL`)

			ctx := r.env.Ctx
			dailyCap := "250000"
			cur := func() store.SMSLimits {
				var l store.SMSLimits
				_ = r.deps.Store.WithGlobal(ctx, store.TxOpts{ReadOnly: true}, func(g store.GlobalTx) (err error) { l, err = g.SMSLimitsGet(); return })
				return l
			}
			limits := cur()
			limits.CostCapDaily = &dailyCap

			aWrote, bWrote, aChecked, bChecked := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
			errA, errB := make(chan error, 1), make(chan error, 1)
			wait := func(ch chan struct{}, limit time.Duration) { testwait.Bound(ch, limit) }
			go func() {
				errA <- r.deps.Store.WithGlobal(ctx, store.TxOpts{}, func(g store.GlobalTx) error {
					if err := g.SMSLimitsSet(limits); err != nil {
						return err
					}
					close(aWrote)
					wait(bWrote, 20*time.Second)
					err := requirePriceUnderCap(g, "sms_cost_cap_daily")
					close(aChecked)
					// Commit only after the other writer has looked too, so neither sees the other's
					// commit. With the row lock the other is waiting for this commit and never looks
					// before it, so the limit lets this writer go.
					wait(bChecked, 2*time.Second)
					return err
				})
			}()
			go func() {
				errB <- r.deps.Store.WithGlobal(ctx, store.TxOpts{}, func(g store.GlobalTx) error {
					wait(aWrote, 20*time.Second)
					if err := c.b(g, unpriced, primary); err != nil {
						return err
					}
					close(bWrote)
					err := requirePriceUnderCap(g, "primary")
					close(bChecked)
					wait(aChecked, 20*time.Second)
					return err
				})
			}()
			ea, eb := <-errA, <-errB
			if ea != nil && eb != nil {
				t.Fatalf("both writers were refused (a: %v, b: %v): the test has lost its race and shows nothing", ea, eb)
			}
			var capSet bool
			r.env.Scan(t, `SELECT sms_cost_cap_daily IS NOT NULL FROM ctrlz.system_settings`, nil, &capSet)
			unpricedRouted := r.count(t, `SELECT count(*) FROM ctrlz.sms_gateways WHERE role IN ('primary', 'fallback') AND (cost_per_message IS NULL OR cost_per_message = 0)`)
			if capSet && unpricedRouted > 0 {
				t.Fatalf("a money cap is armed and %d routed gateway(s) have no price: both writers committed (a: %v, b: %v)", unpricedRouted, ea, eb)
			}
		})
	}
}

// TestEveryDocumentedAdminErrorIsReal is admin-r6-1 and admin-r6-6, and the tests the lint of rule
// spec-fact-drift (internal/lint TestEveryDocumentedAdminErrorCodeIsAssertedByATest) asks for: each
// code that api/admin-openapi.yaml lists after `Errors:` for the operations below is produced by
// a real request here, with the status the web client will see. A code that cannot be produced is
// taken out of the sentence instead (POST /me/password never answers totp_invalid: a wrong or
// missing code is 401 invalid_credentials, so that the answer does not say the password was right).
func TestEveryDocumentedAdminErrorIsReal(t *testing.T) {
	r := newRig(t)
	seed := r.setupAdmin(t, true)
	b := r.browser()
	b.mustLogin(seed)

	{ // impact routes
		b.get("/settings/webauthn/impact?rp_id=not%20a%20host").want(422, "validation_failed")
		b.get("/settings/registration/impact?to=bogus").want(400, "bad_request")
	}
	{ // invite
		b.post("/invites", map[string]any{"phone": "09125550101", "ttl_hours": 1, "locale": "fa"}).want(201, "")
		b.post("/invites", map[string]any{"phone": "09125550102", "ttl_hours": maxInviteHours + 1}).want(400, "bad_request")
		b.post("/invites", map[string]any{"phone": "09125550102", "locale": "xx"}).want(400, "bad_request")
	}
	{ // password change
		// A code that was already spent at login is refused after the password verified.
		r.freeStep(t)
		code := totpNow(seed)
		b2 := r.browser()
		b2.login(adminPW, code).want(200, "")
		b2.post("/me/password", map[string]any{"current_password": adminPW, "new_password": adminNewPW, "totp_code": code}).want(401, "totp_step_reused")
		// A wrong code is the answer of a wrong password.
		b2.post("/me/password", map[string]any{"current_password": adminPW, "new_password": adminNewPW, "totp_code": "000000"}).want(401, "invalid_credentials")
		// A full gate is a 503 before anything is written.
		gate := password.NewGate(1, 50*time.Millisecond)
		release, err := gate.Acquire(r.env.Ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer release()
		busy, err := password.NewHasher(password.Params{MemoryKiB: 64, Time: 1, Threads: 1}, gate)
		if err != nil {
			t.Fatal(err)
		}
		h := r.handler(t, func(d *Deps) { d.Hasher = busy })
		r.freeStep(t)
		b2.callOn(h, adminHost, "POST", "/me/password", map[string]any{"current_password": adminPW, "new_password": adminNewPW, "totp_code": totpNow(seed)}).want(503, "server_busy")
		b2.callOn(h, adminHost, "POST", "/users", map[string]any{"phone": "09125550103"}).want(503, "server_busy")
	}
	{ // sms test message
		r.env.ResetSMS(t)
		b.fresh(seed)
		b.post("/sms/gateways/sms_ir/test", map[string]any{"phone": "09125550104", "template": "otp"}).want(404, "not_found")
	}
	{ // registration and passkey jobs
		b.fresh(seed)
		b.put("/settings/registration", map[string]any{"mode": "bogus"}).want(400, "bad_request")
		b.put("/settings/registration", map[string]any{"mode": "closed", "open_grace_days": 1000}).want(400, "bad_request")
		r.ck.add(6 * time.Minute) // past the five minute fresh window, inside the 15 minute idle life
		b.put("/settings/webauthn", map[string]any{"rp_id": "example.test", "enabled": false}).want(403, "totp_fresh_required")
		b.fresh(seed)
		// conflict is two changes at the same moment, not a job left behind (a newer change ends
		// that one, admin-r5-2): another admin's insert of the same kind is in flight and commits
		// while this one waits on the unique index.
		r.env.Exec(t, `DELETE FROM ctrlz.admin_jobs`)
		heldConflict := func(kind string, send func() *aresp) *aresp {
			r.env.Exec(t, `UPDATE ctrlz.webauthn_config SET rp_id = 'other.example.test'`)
			r.env.Exec(t, `UPDATE ctrlz.system_settings SET registration_mode = 'closed'`)
			release := r.holdUpdate(t, `INSERT INTO ctrlz.admin_jobs (kind, params) VALUES ($1, '{}')`, kind)
			done := make(chan *aresp, 1)
			go func() { done <- send() }()
			r.waitBlocked(t)
			release()
			res := <-done
			r.env.Exec(t, `DELETE FROM ctrlz.admin_jobs`)
			return res
		}
		heldConflict("registration_transition", func() *aresp {
			return b.put("/settings/registration", map[string]any{"mode": "open"})
		}).want(409, "conflict")
		heldConflict("webauthn_rp_change", func() *aresp {
			return b.put("/settings/webauthn", map[string]any{"rp_id": "example.test", "enabled": false})
		}).want(409, "conflict")
	}
}

// TestTotpConfirmErrorsOfAnEnrolment is the other half of admin-r6-1: POST /me/totp/confirm answers
// totp_not_pending before a secret was made, totp_step_reused for a step that was already spent and
// too_many_attempts after five wrong codes, each with the status the document promises.
func TestTotpConfirmErrorsOfAnEnrolment(t *testing.T) {
	r := newRig(t)
	r.setupAdmin(t, false)
	b := r.browser()
	b.login(adminPW, "").want(200, "")
	b.post("/me/password", map[string]any{"current_password": adminPW, "new_password": adminNewPW}).want(204, "")
	b.post("/me/totp/confirm", map[string]any{"code": "000000"}).want(409, "totp_not_pending")
	b.post("/me/totp/setup", map[string]any{}).want(200, "")
	var ct []byte
	r.env.Scan(t, `SELECT totp_secret_ct FROM ctrlz.admin_users WHERE id = $1`, []any{seedAdmin}, &ct)
	seed, err := r.keys.Open(keyring.DomainAdminTOTP, totp.AdminAAD(seedAdmin), ct)
	if err != nil {
		t.Fatal(err)
	}
	// The current step is already spent: the right code is a replay.
	r.env.Exec(t, `UPDATE ctrlz.admin_users SET totp_last_step = $2 WHERE id = $1`, seedAdmin, time.Now().Unix()/30+1)
	b.post("/me/totp/confirm", map[string]any{"code": totpNow(seed)}).want(401, "totp_step_reused") // clock-safe: last_step is set one step ahead, so the right code is spent on either side of a boundary
	for i := 0; i < 5; i++ {
		b.post("/me/totp/confirm", map[string]any{"code": "000000"})
	}
	b.post("/me/totp/confirm", map[string]any{"code": "000000"}).want(429, "too_many_attempts")
}

// TestBusyAdminLoginsDoNotSpendTheThrottle is primitives-r6-9. The admin verify is gate-free only
// for a console one-time hash; an ordinary admin password and the dummy hash of an unknown name
// wait for a slot of the Argon2 gate and answer 503 when it stays full. Those attempts looked at
// no password, and used to stay counted on admin_login, admin_login_user and admin_login_net, so
// strangers who kept the gate busy turned the owner's next five tries into a 429 that lasted after
// the load had gone. Known and unknown names are given back alike.
func TestBusyAdminLoginsDoNotSpendTheThrottle(t *testing.T) {
	r := newRig(t)
	seed := r.setupAdmin(t, true)
	gate := password.NewGate(1, 50*time.Millisecond)
	release, err := gate.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	busy, err := password.NewHasher(password.Params{MemoryKiB: 64, Time: 1, Threads: 1}, gate)
	if err != nil {
		t.Fatal(err)
	}
	h := r.handler(t, func(d *Deps) { d.Hasher = busy })
	b := r.browser()
	for i := 0; i < 8; i++ {
		r.ck.add(time.Minute) // the rate class of the login is not the bound under test
		b.callOn(h, adminHost, "POST", "/auth/login", map[string]any{"username": adminName, "password": "wrong-wrong-wrong-1"}).want(503, "server_busy")
		r.ck.add(time.Minute)
		b.callOn(h, adminHost, "POST", "/auth/login", map[string]any{"username": "nobody-here", "password": "wrong-wrong-wrong-1"}).want(503, "server_busy")
	}
	for _, sc := range []string{"admin_login", "admin_login_user", "admin_login_net"} {
		if n := scopeSum(t, r, sc); n != 0 {
			t.Errorf("%s still counts %d after only busy answers", sc, n)
		}
	}
	release()
	r.ck.add(time.Minute)
	r.browser().mustLogin(seed)
}

// TestBusyAdminPasswordChangesDoNotSpendTheirScope is tenant-r6-8 on the admin side. POST
// /me/password counts admin_reauth, verifies the current password without a gate slot and then
// hashes the new one in the Argon2 gate; a busy gate answered 503 server_busy and the try stayed
// counted, so the owner's tries ran out under load and were a 429 after it. The same lint that
// found the tenant reauth (internal/lint TestAChargeBeforeAGateIsGivenBackWhenTheGateIsFull) found
// this function.
func TestBusyAdminPasswordChangesDoNotSpendTheirScope(t *testing.T) {
	r := newRig(t)
	r.setupAdmin(t, false)
	b := r.browser()
	b.login(adminPW, "").want(200, "")
	gate := password.NewGate(1, 50*time.Millisecond)
	release, err := gate.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	busy, err := password.NewHasher(password.Params{MemoryKiB: 64, Time: 1, Threads: 1}, gate)
	if err != nil {
		t.Fatal(err)
	}
	h := r.handler(t, func(d *Deps) { d.Hasher = busy })
	for i := 0; i < 8; i++ {
		r.ck.add(time.Minute) // the rate class of the route is not the bound under test
		b.callOn(h, adminHost, "POST", "/me/password", map[string]any{"current_password": adminPW, "new_password": adminNewPW}).want(503, "server_busy")
	}
	if n := scopeSum(t, r, "admin_login"); n != 0 {
		t.Errorf("admin_reauth (stored under admin_login) counts %d after only busy answers", n)
	}
	release()
	r.ck.add(time.Minute)
	b.post("/me/password", map[string]any{"current_password": adminPW, "new_password": adminNewPW}).want(204, "")
}
