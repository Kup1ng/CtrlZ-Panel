package adminapi

import (
	"context"
	"encoding/base32"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/session"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/throttle"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testwait"
)

// seedFromBase32 is what an authenticator app does with the secret shown beside
// the QR code.
func seedFromBase32(t *testing.T, s string) secret.Bytes {
	t.Helper()
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
	if err != nil {
		t.Fatalf("setup secret is not base32: %v", err)
	}
	return secret.NewBytes(raw)
}

// auditActions lists the actions of the chain, oldest first.
func (r *rig) auditActions(t *testing.T) []string {
	t.Helper()
	var out []string
	if err := r.adm.WithGlobal(r.env.Ctx, store.TxOpts{}, func(g store.GlobalTx) error {
		rows, err := g.AuditChain(0, 1000)
		for _, row := range rows {
			out = append(out, row.Action)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func has(list []string, want string) int {
	n := 0
	for _, s := range list {
		if s == want {
			n++
		}
	}
	return n
}

// TestAdminSetupFlow walks the first login of a bootstrapped admin (T-323,
// 10.3): the one-time password opens a setup session, nothing but the setup
// routes works, the password change rotates the session, and enrolling TOTP
// makes the account ready.
func TestAdminSetupFlow(t *testing.T) {
	r := newRig(t)
	r.setupAdmin(t, false)
	b := r.browser()

	var res struct {
		State string `json:"state"`
	}
	lr := b.login(adminPW, "").want(200, "")
	lr.json(&res)
	if res.State != "setup_required" {
		t.Fatalf("state = %q", res.State)
	}
	// Exact cookie attributes (3.2): host-only, Strict, no Domain.
	c := lr.cookie(session.CookieAdmin)
	if c == nil || !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Path != "/" || c.Domain != "" || c.MaxAge != 0 {
		t.Fatalf("session cookie = %+v", c)
	}

	var me struct {
		Username           string `json:"username"`
		MustChangePassword bool   `json:"must_change_password"`
		TotpEnrolled       bool   `json:"totp_enrolled"`
	}
	b.get("/me").want(200, "").json(&me)
	if me.Username != adminName || !me.MustChangePassword || me.TotpEnrolled {
		t.Fatalf("me = %+v", me)
	}
	// Setup session: everything else is refused (T-323).
	b.get("/users").want(403, "setup_required")
	b.get("/audit").want(403, "setup_required")

	// POST /me/password: a wrong current password, a weak new one, the same one.
	old := b.jar[session.CookieAdmin].Value
	b.post("/me/password", map[string]any{"current_password": "wrong-wrong-wrong-1", "new_password": adminNewPW}).want(401, "invalid_credentials")
	b.post("/me/password", map[string]any{"current_password": adminPW, "new_password": "short"}).want(422, "password_weak")
	b.post("/me/password", map[string]any{"current_password": adminPW, "new_password": adminPW}).want(422, "validation_failed")
	pw := b.post("/me/password", map[string]any{"current_password": adminPW, "new_password": adminNewPW}).want(204, "")
	// The session was rotated: the old cookie is dead and the new one works.
	if pw.cookie(session.CookieAdmin) == nil || b.jar[session.CookieAdmin].Value == old {
		t.Fatal("the password change did not rotate the session")
	}
	stale := b.r.browser()
	stale.jar[session.CookieAdmin] = &http.Cookie{Name: session.CookieAdmin, Value: old}
	stale.get("/me").want(401, "session_expired")
	b.get("/me").want(200, "")
	// A password change does not enrol TOTP: still setup.
	b.get("/users").want(403, "setup_required")

	// TOTP: setup, a wrong code, the right code.
	var setup struct {
		Secret     string `json:"secret"`
		OtpauthURI string `json:"otpauth_uri"`
	}
	b.post("/me/totp/setup", map[string]any{}).want(200, "").json(&setup)
	if !strings.HasPrefix(setup.OtpauthURI, "otpauth://totp/") || strings.Contains(setup.OtpauthURI, adminNewPW) {
		t.Fatalf("otpauth uri = %q", setup.OtpauthURI)
	}
	seed := seedFromBase32(t, setup.Secret)
	b.post("/me/totp/confirm", map[string]any{"code": "000000"}).want(401, "totp_invalid")
	before := b.jar[session.CookieAdmin].Value
	b.post("/me/totp/confirm", map[string]any{"code": totpNow(seed)}).want(204, "")
	if b.jar[session.CookieAdmin].Value == before {
		t.Fatal("TOTP confirm did not rotate the session")
	}
	// Ready now, and the confirm code opened the fresh window.
	b.get("/users").want(200, "")
	var me2 struct {
		FreshUntil *time.Time `json:"fresh_until"`
		Enrolled   bool       `json:"totp_enrolled"`
	}
	b.get("/me").want(200, "").json(&me2)
	if !me2.Enrolled || me2.FreshUntil == nil {
		t.Fatalf("me after confirm = %+v", me2)
	}
	b.post("/me/totp/setup", map[string]any{}).want(409, "totp_already_enabled")
	b.post("/me/totp/confirm", map[string]any{"code": totpNow(seed)}).want(409, "totp_already_enabled")

	// The login and the changes are in the chain.
	acts := r.auditActions(t)
	for _, want := range []string{"admin.login", "admin.password_change", "admin.totp_enroll"} {
		if has(acts, want) != 1 {
			t.Errorf("audit %s: %d rows in %v", want, has(acts, want), acts)
		}
	}
	// The next login needs the code; the old password is gone.
	b2 := r.browser()
	r.freeStep(t)
	b2.login(adminNewPW, "").want(401, "invalid_credentials") // the old password is gone: adminPW no longer works
	r.assertQuiet(t, setup.Secret, totpNow(seed))
}

// TestAdminLoginWithTOTP covers 10.2 step 4: a missing and a wrong code look
// like a wrong password, a spent step is told apart, and a good login opens a
// ready session whose TOTP check counts as fresh.
func TestAdminLoginWithTOTP(t *testing.T) {
	r := newRig(t)
	seed := r.setupAdmin(t, true)

	// Wrong password, missing code, wrong code and unknown username are one answer.
	var answers []string
	for _, c := range []struct{ user, pw, code string }{
		{adminName, "wrong-wrong-wrong-1", totpNow(seed)},
		{adminName, adminPW, ""},
		{adminName, adminPW, "000000"},
		{"nobody", adminPW, totpNow(seed)},
	} {
		b := r.browser()
		body := map[string]any{"username": c.user, "password": c.pw}
		if c.code != "" {
			body["totp_code"] = c.code
		}
		w := b.post("/auth/login", body).want(401, "invalid_credentials")
		if w.cookie(session.CookieAdmin) != nil {
			t.Fatalf("a refused login set a cookie: %+v", c)
		}
		answers = append(answers, strings.Join(strings.Fields(string(stripRequestID(w.Body))), ""))
	}
	for _, a := range answers[1:] {
		if a != answers[0] {
			t.Fatalf("refusals differ: %q vs %q", a, answers[0])
		}
	}
	if n := has(r.auditActions(t), "admin.login_failed"); n != 4 {
		t.Fatalf("admin.login_failed rows = %d, want 4", n)
	}
	// No failed row holds the username (13.2): an unknown name records nothing of it.
	if r.count(t, `SELECT count(*) FROM ctrlz.audit_log WHERE action = 'admin.login_failed' AND (params::text LIKE '%nobody%' OR target LIKE '%nobody%')`) != 0 {
		t.Fatal("a failed login recorded the typed username")
	}

	// A good login is ready, and its TOTP check counts as fresh (10.5).
	r.freeStep(t)
	b := r.browser()
	var res struct {
		State string `json:"state"`
	}
	good := totpNow(seed)
	b.login(adminPW, good).want(200, "").json(&res)
	if res.State != "ready" {
		t.Fatalf("state = %q", res.State)
	}
	b.put("/settings/registration", map[string]any{"mode": "closed"}).want(200, "") // admin-fresh, with no extra code

	// The same code again is a spent step: told apart, since it needs the password.
	b2 := r.browser()
	b2.login(adminPW, good).want(401, "totp_step_reused")

	// A disabled account and an expired one-time password are refused too.
	r.freeStep(t)
	r.env.Exec(t, `UPDATE ctrlz.admin_users SET disabled_at = now() WHERE id = $1`, seedAdmin)
	r.browser().login(adminPW, totpNow(seed)).want(401, "invalid_credentials")
	r.env.Exec(t, `UPDATE ctrlz.admin_users SET disabled_at = NULL, must_change_password = true, password_expires_at = now() - interval '1 minute' WHERE id = $1`, seedAdmin)
	r.freeStep(t)
	r.browser().login(adminPW, totpNow(seed)).want(401, "invalid_credentials")
	// A session of a disabled account is dead at once (10.3).
	r.env.Exec(t, `UPDATE ctrlz.admin_users SET disabled_at = now() WHERE id = $1`, seedAdmin)
	b.get("/me").want(401, "session_expired")
}

// stripRequestID removes the per-request id so two refusals can be compared.
func stripRequestID(body []byte) []byte {
	s := string(body)
	i := strings.Index(s, `"request_id":"`)
	if i < 0 {
		return body
	}
	j := strings.Index(s[i+14:], `"`)
	return []byte(s[:i] + s[i+14+j+1:])
}

// TestAdminFreshTOTP covers 10.5: a stale window refuses every admin-fresh
// route, a code opens it, the same code cannot open it twice, and five wrong
// codes lock the scope.
func TestAdminFreshTOTP(t *testing.T) {
	r := newRig(t)
	seed := r.setupAdmin(t, true)
	b := r.browser()
	b.mustLogin(seed)

	stale := func() {
		r.env.Exec(t, `UPDATE ctrlz.admin_sessions SET totp_verified_at = now() - interval '10 minutes'`)
	}
	stale()
	b.put("/settings/registration", map[string]any{"mode": "closed"}).want(403, "totp_fresh_required")
	var me struct {
		FreshUntil *time.Time `json:"fresh_until"`
	}
	b.get("/me").want(200, "").json(&me)
	if me.FreshUntil != nil {
		t.Fatalf("fresh_until = %v for a stale window", me.FreshUntil)
	}

	r.freeStep(t)
	c := totpNow(seed)
	var win struct {
		FreshUntil time.Time `json:"fresh_until"`
	}
	b.post("/auth/totp/fresh", map[string]any{"code": c}).want(200, "").json(&win)
	if d := time.Until(win.FreshUntil); d < 4*time.Minute || d > 5*time.Minute+5*time.Second {
		t.Fatalf("fresh_until is %v away", d)
	}
	b.put("/settings/registration", map[string]any{"mode": "closed"}).want(200, "")
	// The same step cannot open the window again.
	stale()
	b.post("/auth/totp/fresh", map[string]any{"code": c}).want(401, "totp_step_reused")
	b.put("/settings/registration", map[string]any{"mode": "closed"}).want(403, "totp_fresh_required")

	// Five wrong codes, then the scope refuses even the right one.
	r.clearAdminThrottle(t)
	for i := 0; i < 5; i++ {
		b.post("/auth/totp/fresh", map[string]any{"code": "000000"}).want(401, "totp_invalid")
		r.ck.add(time.Second)
	}
	r.freeStep(t)
	w := b.post("/auth/totp/fresh", map[string]any{"code": totpNow(seed)}).want(429, "too_many_attempts")
	if w.H.Get("Retry-After") == "" {
		t.Fatal("no Retry-After on too_many_attempts")
	}
	if has(r.auditActions(t), "admin.totp_fresh") != 1 {
		t.Fatalf("admin.totp_fresh rows: %v", r.auditActions(t))
	}
}

// TestPasswordChangeOfAReadyAdmin covers 10.3: a ready admin can change the
// password through the same route, and it needs a TOTP code then.
func TestPasswordChangeOfAReadyAdmin(t *testing.T) {
	r := newRig(t)
	seed := r.setupAdmin(t, true)
	b := r.browser()
	b.mustLogin(seed)
	other := r.browser()
	r.freeStep(t)
	other.login(adminPW, totpNow(seed)).want(200, "")

	body := map[string]any{"current_password": adminPW, "new_password": adminNewPW}
	b.post("/me/password", body).want(401, "invalid_credentials") // the right password without a code looks like a wrong one (10.3)
	r.freeStep(t)
	body["totp_code"] = totpNow(seed)
	b.post("/me/password", body).want(204, "")
	// The other session ended (3.7 for an admin).
	other.get("/me").want(401, "session_expired")
	b.get("/me").want(200, "")
	r.freeStep(t)
	r.browser().login(adminNewPW, totpNow(seed)).want(200, "")
}

// TestAdminBruteForce covers the admin rows of 18.5. The login class lets five
// attempts a minute through per network, so the throttle's own refusal is
// reached by moving the clock the rate limiter reads.
func TestAdminBruteForce(t *testing.T) {
	r := newRig(t)
	seed := r.setupAdmin(t, true)
	attacker := r.browser()
	for i := 0; i < 5; i++ {
		attacker.login("wrong-wrong-wrong-1", "000000").want(401, "invalid_credentials")
	}
	// The sixth attempt from that network: 5 per username and network.
	r.ck.add(time.Minute)
	w := attacker.login(adminPW, totpNow(seed)).want(429, "too_many_attempts")
	if w.H.Get("Retry-After") == "" {
		t.Fatal("no Retry-After")
	}
	// The refusal of an admin scope is counted and written like a tenant one (tenant-r18-19), with the bucket and the
	// kind of key and nothing that names the network.
	if !strings.Contains(r.logs.String(), "a bucket refused an attempt") {
		t.Error("the refusal of an admin throttle scope wrote no refusal line")
	}
	// The real admin, on another network, is not locked out by that stranger.
	r.freeStep(t)
	r.browser().login(adminPW, totpNow(seed)).want(200, "")
}

// TestAdminLockedOutByStrangersAndUnlock covers the per-username scope (30) and
// `unlock`: strangers on many networks can lock a username for every browser
// that has no admin device marker, and the console clears it. A browser that has
// the marker is not locked out: TestKnownAdminDeviceIsNotLockedOutByStrangers.
func TestAdminLockedOutByStrangersAndUnlock(t *testing.T) {
	if testing.Short() {
		t.Skip("30 logins at the 500 ms floor")
	}
	r := newRig(t)
	seed := r.setupAdmin(t, true)
	for i := 0; i < 30; i++ {
		r.browser().login("wrong-wrong-wrong-1", "").want(401, "invalid_credentials")
	}
	r.freeStep(t)
	r.browser().login(adminPW, totpNow(seed)).want(429, "too_many_attempts")
	// `ctrlz-admin unlock` clears admin_login and admin_login_user; here its
	// store calls stand in for it (the CLI test runs the command itself).
	r.clearAdminThrottle(t)
	r.freeStep(t)
	r.browser().login(adminPW, totpNow(seed)).want(200, "")
}

// clearAdminThrottle is what the unlock command does.
func (r *rig) clearAdminThrottle(t *testing.T) {
	t.Helper()
	r.env.Exec(t, `DELETE FROM ctrlz.auth_throttle WHERE scope LIKE 'admin_%'`)
}

// TestAbandonedEnrolmentDoesNotLeavePasswordOnlyLogin covers review round 2
// (admin-r2-2). After the first password change and before the authenticator is
// confirmed, the password must not open a setup session for as long as anyone
// likes: whoever phished it could enrol their own authenticator and, with the
// confirm, end the real admin's sessions. The chosen password expires after an
// hour until TOTP is enabled; the admin who is in the session can still finish,
// and the confirm clears the expiry.
func TestAbandonedEnrolmentDoesNotLeavePasswordOnlyLogin(t *testing.T) {
	r := newRig(t)
	r.setupAdmin(t, false)
	b := r.browser()
	b.login(adminPW, "").want(200, "")
	b.post("/me/password", map[string]any{"current_password": adminPW, "new_password": adminNewPW}).want(204, "")

	expiry := func() *time.Time {
		var at *time.Time
		r.env.Scan(t, `SELECT password_expires_at FROM ctrlz.admin_users WHERE id = $1`, []any{seedAdmin}, &at)
		return at
	}
	at := expiry()
	if at == nil || time.Until(*at) < 50*time.Minute || time.Until(*at) > 70*time.Minute {
		t.Fatalf("password_expires_at after the first change = %v, want about an hour ahead", at)
	}
	// Inside the hour the password still opens a setup session (the admin who
	// closed the tab comes back).
	r.browser().login(adminNewPW, "").want(200, "")

	// The hour passes with enrolment unfinished: password alone is refused, like
	// any expired one-time password.
	r.env.Exec(t, `UPDATE ctrlz.admin_users SET password_expires_at = now() - interval '1 minute' WHERE id = $1`, seedAdmin)
	r.browser().login(adminNewPW, "").want(401, "invalid_credentials")

	// The session that is open can still enrol, and the confirm ends the expiry.
	var setup struct {
		Secret string `json:"secret"`
	}
	b.post("/me/totp/setup", map[string]any{}).want(200, "").json(&setup)
	seed := seedFromBase32(t, setup.Secret)
	b.post("/me/totp/confirm", map[string]any{"code": totpNow(seed)}).want(204, "")
	if at := expiry(); at != nil {
		t.Fatalf("password_expires_at after TOTP confirm = %v, want NULL", at)
	}
	r.freeStep(t)
	r.browser().login(adminNewPW, totpNow(seed)).want(200, "")

	// A ready admin's password change leaves no expiry either.
	r.freeStep(t)
	b.post("/me/password", map[string]any{"current_password": adminNewPW, "new_password": adminPW, "totp_code": totpNow(seed)}).want(204, "")
	if at := expiry(); at != nil {
		t.Fatalf("password_expires_at after a ready admin's change = %v, want NULL", at)
	}
}

// TestStrangerCannotKeepTheOwnerOutOfTheFirstLogin covers review round 2
// (admin-r2-7). The first login after bootstrap or a console reset has no device
// marker, so a stranger who knows the username could keep admin_login_user spent
// and `unlock` would lose the race. The right console-issued one-time password
// (120 bits) is let through a spent scope; nothing else is.
func TestStrangerCannotKeepTheOwnerOutOfTheFirstLogin(t *testing.T) {
	r := newRig(t)
	r.setupAdmin(t, false)
	r.env.Exec(t, `UPDATE ctrlz.admin_users SET password_expires_at = now() + interval '24 hours' WHERE id = $1`, seedAdmin)
	spend := func() {
		svc := throttle.NewAdmin(r.adm.Admin(), r.keys)
		for i := 0; i < 100; i++ {
			if err := svc.Charge(r.env.Ctx, throttle.AdminLoginUser, throttle.Who{Username: adminName}); err != nil {
				return
			}
		}
		t.Fatal("admin_login_user never refused")
	}
	spend()

	// A stranger with a wrong password is refused by the scope, before Argon2.
	r.browser().login("wrong-wrong-wrong-1", "").want(429, "too_many_attempts")
	// The owner with the console password gets in, although the scope is spent.
	owner := r.browser()
	owner.login(adminPW, "").want(200, "")
	owner.get("/me").want(200, "")

	// The success cleared the scope, so it is not spent for the next stranger.
	r.browser().login("wrong-wrong-wrong-1", "").want(401, "invalid_credentials")

	// A password the admin chose is not 120 bits, so it gets no such exception: the
	// scope is spent again, the account is past its first change, and the right
	// password is refused like a wrong one.
	owner.post("/me/password", map[string]any{"current_password": adminPW, "new_password": adminNewPW}).want(204, "")
	spend()
	r.browser().login(adminNewPW, "").want(429, "too_many_attempts")

	// A console one-time password past its expiry is not let through either.
	r.env.Exec(t, `UPDATE ctrlz.admin_users SET must_change_password = true, password_expires_at = now() - interval '1 minute' WHERE id = $1`, seedAdmin)
	r.browser().login(adminNewPW, "").want(429, "too_many_attempts")
}

// TestAdminLoginAndPasswordChangeWithDatabaseDown is the fault row of 18.3 for
// the admin login and POST /me/password (review round 2, admin-r2-4). With
// Postgres gone a login for a known and for an unknown username is the same clean
// 503 behind the 500 ms floor, with no driver text, so the point where the
// request stopped tells nothing about the account; a password change is a clean
// 503 too. After the restart both work, and nothing was half-done.
func TestAdminLoginAndPasswordChangeWithDatabaseDown(t *testing.T) {
	r := newRig(t)
	b, seed := r.admin(t)

	stopCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := cluster.StopPostgres(stopCtx); err != nil {
		t.Fatalf("stop postgres: %v", err)
	}
	restarted := false
	restart := func() {
		if !restarted {
			restarted = true
			if err := cluster.StartPostgres(context.Background()); err != nil {
				t.Errorf("restart postgres: %v", err)
			}
		}
	}
	t.Cleanup(restart)

	noLeak := func(what string, res *aresp) {
		t.Helper()
		body := strings.ToLower(string(res.Body))
		for _, leak := range []string{"sqlstate", "pgx", "refused", "5432", "dial", "connect", "postgres", strings.ToLower(adminPW), strings.ToLower(adminNewPW)} {
			if strings.Contains(body, leak) {
				t.Errorf("%s: the 503 body leaks %q", what, leak)
			}
		}
	}
	for _, c := range []struct{ name, user string }{{"known", adminName}, {"unknown", "no-such-admin"}} {
		res := r.browser().post("/auth/login", map[string]any{"username": c.user, "password": adminPW, "totp_code": totpNow(seed)})
		res.want(503, "service_unavailable")
		noLeak(c.name+" login", res)
		if res.Dur < floorLogin-20*time.Millisecond {
			t.Errorf("%s login answered in %v, before the %v floor", c.name, res.Dur, floorLogin)
		}
		if res.cookie(session.CookieAdmin) != nil || res.cookie(session.CookieAdminDevice) != nil {
			t.Errorf("%s login set a cookie while failing", c.name)
		}
	}
	pw := b.post("/me/password", map[string]any{"current_password": adminPW, "new_password": adminNewPW, "totp_code": totpNow(seed)})
	pw.want(503, "service_unavailable")
	noLeak("password change", pw)

	restart()
	var res *aresp
	if !testwait.Holds(60*time.Second, time.Second, func() bool {
		r.freeStep(t)
		res = r.browser().login(adminPW, totpNow(seed))
		return res.Code == 200
	}) {
		t.Fatalf("the admin could not log in after the restart: %d %s", res.Code, res.Body)
	}
	// The failed password change changed nothing: the old password still works.
	if r.count(t, `SELECT count(*) FROM ctrlz.audit_log WHERE action = 'admin.password_change'`) != 0 {
		t.Fatal("a password change was recorded while the database was down")
	}
}
