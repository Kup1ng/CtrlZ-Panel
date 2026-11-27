package adminapi

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/audit"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/password"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/session"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testwait"
)

// Tests of review round 3 for the admin API (admin-r3-N).

// liveAdminSessions counts the sessions of the seeded admin that are not revoked.
func (r *rig) liveAdminSessions(t *testing.T) int {
	t.Helper()
	return r.count(t, `SELECT count(*) FROM ctrlz.admin_sessions WHERE admin_id = $1 AND revoked_at IS NULL`, seedAdmin)
}

// syncClock moves the rig's clock to the database's time. The rig's clock stands still,
// and a notice carries the handler's time while a session carries the database's,
// so a test about which comes first needs both on the same clock.
func (r *rig) syncClock() {
	r.t.Helper()
	// The database's clock, which stamps the sessions: a container VM can run a
	// little off the host's.
	var now time.Time
	r.env.Scan(r.t, `SELECT now()`, nil, &now)
	r.ck.mu.Lock()
	r.ck.t = now.UTC()
	r.ck.mu.Unlock()
}

// heldHasher is a hasher whose gate has one slot, taken by the test, and a long
// wait: a login that reaches Argon2 waits there until release is called. The
// parameters are the rig's, so it verifies the rig's hashes.
func heldHasher(t *testing.T) (h *password.Hasher, release func()) {
	t.Helper()
	h, _, release = heldHasherGate(t)
	return h, release
}

// heldHasherGate is heldHasher with the gate, for a test that has to know when a login has reached it
// (Gate.Attempts counts every Acquire, the test's own first).
func heldHasherGate(t *testing.T) (h *password.Hasher, gate *password.Gate, release func()) {
	t.Helper()
	gate = password.NewGate(1, 10*time.Second)
	rel, err := gate.Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	h, err = password.NewHasher(password.Params{MemoryKiB: 64, Time: 1, Threads: 1}, gate)
	if err != nil {
		t.Fatal(err)
	}
	return h, gate, rel
}

// TestGatewayChangerCannotDismissItsOwnBanner covers admin-r3-1 and admin-r3-8.
// A thief's session with one fresh code points the SMS gateway at its own
// account; the banner of 10.7 is the owner's only in-product warning, and the
// thief's own POST /me/notices/ack must not erase it. With one admin, which is
// the usual install, the acting admin is the owner. The ack drops only notices
// that predate the session, writes an audit row, and a notice that arrives after
// the client read GET /me survives an ack as well.
func TestGatewayChangerCannotDismissItsOwnBanner(t *testing.T) {
	r := newRig(t)
	thief, seed := r.admin(t)
	r.syncClock()

	thief.put("/sms/gateways/sms_ir", map[string]any{"credentials": map[string]string{"api_key": "attacker-account-key-123456"}}).want(200, "")
	confirmAtConsole(t, r, "sms_ir") // the console makes credentials active (admin-r18-1); routing needs them
	thief.put("/sms/routing", map[string]any{"primary": "sms_ir"}).want(200, "")
	thief.post("/me/notices/ack", map[string]any{}).want(204, "")
	var me struct {
		Notices []struct {
			Kind string `json:"kind"`
		} `json:"notices"`
	}
	thief.get("/me").want(200, "").json(&me)
	if len(me.Notices) != 2 {
		t.Fatalf("the thief's session dismissed the banner: %d notices left", len(me.Notices))
	}
	// The refusal is on the record: what was kept, never what the notices said.
	var params string
	r.env.Scan(t, `SELECT params::text FROM ctrlz.audit_log WHERE action = 'admin.notices_ack' ORDER BY id DESC LIMIT 1`, nil, &params)
	if !strings.Contains(params, `"cleared": 0`) && !strings.Contains(params, `"cleared":0`) {
		t.Fatalf("audit params = %s", params)
	}
	if !strings.Contains(params, `"kept": 2`) && !strings.Contains(params, `"kept":2`) {
		t.Fatalf("audit params = %s", params)
	}

	// The owner signs in later: a new session, and the banner is there to read.
	r.ck.add(time.Second)
	owner := r.browser()
	owner.mustLogin(seed)
	owner.get("/me").want(200, "").json(&me)
	if len(me.Notices) != 2 {
		t.Fatalf("the owner sees %d notices at the next login, want 2", len(me.Notices))
	}
	// A notice made after the owner read GET /me (a second session of a thief) is
	// not dropped by the owner's ack: it postdates the owner's session.
	r.ck.add(time.Second)
	thief.put("/sms/routing", map[string]any{"primary": "sms_ir"}).want(200, "")
	owner.post("/me/notices/ack", map[string]any{}).want(204, "")
	thief.get("/me").want(200, "").json(&me)
	if len(me.Notices) != 1 || me.Notices[0].Kind != "sms_gateway_changed" {
		t.Fatalf("after the owner's ack: %+v, want the newer notice only", me.Notices)
	}
	// The same ack is routine and answers the same when there is nothing to clear.
	r.env.Exec(t, `UPDATE ctrlz.admin_users SET pending_notice = NULL WHERE id = $1`, seedAdmin)
	owner.post("/me/notices/ack", map[string]any{}).want(204, "")
}

// TestLoginInFlightDoesNotSurviveAReset covers admin-r3-2. The login reads the
// row, verifies the password with Argon2 (here: waits for the gate), and only
// then opens its transaction. A console reset that commits in between has
// already revoked the sessions that exist, so a session inserted after it would
// outlive the reset, and after reset-totp it would be a setup session that can
// enrol the intruder's authenticator. The transaction re-reads the row under a
// lock and refuses when it is no longer the one that was verified.
func TestLoginInFlightDoesNotSurviveAReset(t *testing.T) {
	for _, tc := range []struct {
		name  string
		ready bool
		reset string
	}{
		{"password reset of a ready admin", true,
			`UPDATE ctrlz.admin_users SET password_hash = '$argon2id$v=19$m=64,t=1,p=1$c29tZXNhbHRzb21lc2FsdA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', must_change_password = true, password_expires_at = now() + interval '24 hours' WHERE id = $1`},
		{"reset-totp of a ready admin", true,
			`UPDATE ctrlz.admin_users SET password_hash = '$argon2id$v=19$m=64,t=1,p=1$c29tZXNhbHRzb21lc2FsdA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', must_change_password = true, password_expires_at = now() + interval '24 hours', totp_secret_ct = NULL, totp_enabled_at = NULL WHERE id = $1`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t)
			seed := r.setupAdmin(t, tc.ready)
			held, gate, release := heldHasherGate(t)
			h := r.handler(t, func(d *Deps) { d.Hasher = held })

			done := make(chan *aresp, 1)
			go func() {
				b := r.browser()
				body := map[string]any{"username": adminName, "password": adminPW}
				if tc.ready {
					body["totp_code"] = totpNow(seed)
				}
				done <- b.callOn(h, adminHost, "POST", "/auth/login", body)
			}()
			// The login has counted, read the row and is waiting for Argon2's slot: the gate has seen a second
			// Acquire (the test's own is the first). A fixed sleep stood here and passed vacuously on a slow host,
			// where the reset landed before the login had read the row (admin-r16-10).
			testwait.UntilEvery(t, 30*time.Second, 10*time.Millisecond, "the login to reach the Argon2 gate (the test proves nothing without it)", func() bool { return gate.Attempts() >= 2 })
			r.env.Exec(t, tc.reset, seedAdmin)
			r.env.Exec(t, `UPDATE ctrlz.admin_sessions SET revoked_at = now() WHERE admin_id = $1 AND revoked_at IS NULL`, seedAdmin)
			release()
			res := <-done
			res.want(401, "invalid_credentials")
			if n := r.liveAdminSessions(t); n != 0 {
				t.Fatalf("%d live sessions after the reset", n)
			}
		})
	}
}

// TestGatewayChangeAndLoginDoNotDeadlock covers admin-r3-3. A gateway change
// used to take the audit lock and then the rows of admin_users; a login or a
// password change takes the row and then the audit lock. Here one transaction
// holds the row and wants the audit lock while the PUT is in flight: with the
// rows first on both sides the PUT simply waits, and both finish. With the old
// order Postgres aborted one of them as a deadlock.
func TestGatewayChangeAndLoginDoNotDeadlock(t *testing.T) {
	r := newRig(t)
	b, _ := r.admin(t)
	locked, hold := make(chan struct{}), make(chan struct{})
	tx := make(chan error, 1)
	go func() {
		tx <- r.adm.WithGlobal(r.env.Ctx, store.TxOpts{}, func(g store.GlobalTx) error {
			if _, _, err := g.AdminUserLockByID(seedAdmin); err != nil {
				return err
			}
			close(locked)
			<-hold
			_, err := audit.Admin(g, r.ck.now(), seedAdmin, netip.MustParseAddr("198.51.100.7"), audit.AdminLogin{Admin: seedAdmin})
			return err
		})
	}()
	<-locked
	put := make(chan *aresp, 1)
	go func() {
		put <- b.put("/sms/gateways/sms_ir", map[string]any{"credentials": map[string]string{"api_key": "some-key-1234567890"}})
	}()
	r.waitBlocked(t) // the PUT is waiting for the row: Postgres says so, a sleep only hoped (admin-r16-10)
	close(hold)
	if err := <-tx; err != nil {
		t.Fatalf("the transaction holding the row failed: %v", err)
	}
	(<-put).want(200, "")
}

// TestEnrolBeforeChoosingAPasswordKeepsTheOneTimeExpiry covers admin-r3-4 and
// admin-r3-12. The setup routes run in any order. An admin who enrols the
// authenticator while the password is still the console's one-time password must
// not lose its 24-hour expiry: it would then be a valid first factor for ever.
func TestEnrolBeforeChoosingAPasswordKeepsTheOneTimeExpiry(t *testing.T) {
	r := newRig(t)
	r.setupAdmin(t, false)
	// The expiry is on the database clock (rule one-time-state); pin a known value.
	r.env.Exec(t, `UPDATE ctrlz.admin_users SET password_expires_at = now() + interval '24 hours' WHERE id = $1`, seedAdmin)
	var expires time.Time
	r.env.Scan(t, `SELECT password_expires_at FROM ctrlz.admin_users WHERE id = $1`, []any{seedAdmin}, &expires)

	b := r.browser()
	b.login(adminPW, "").want(200, "")
	var setup struct {
		Secret string `json:"secret"`
	}
	b.post("/me/totp/setup", map[string]any{}).want(200, "").json(&setup)
	seed := seedFromBase32(t, setup.Secret)
	b.post("/me/totp/confirm", map[string]any{"code": totpNow(seed)}).want(204, "")

	var must bool
	var at *time.Time
	r.env.Scan(t, `SELECT must_change_password, password_expires_at FROM ctrlz.admin_users WHERE id = $1`, []any{seedAdmin}, &must, &at)
	if !must || at == nil || !at.Equal(expires) {
		t.Fatalf("after enrolling first: must_change_password=%v, password_expires_at=%v, want true and %v", must, at, expires)
	}
	// Past its day the one-time password is a wrong password, authenticator or not.
	r.env.Exec(t, `UPDATE ctrlz.admin_users SET password_expires_at = now() - interval '1 minute' WHERE id = $1`, seedAdmin)
	r.freeStep(t)
	r.browser().login(adminPW, totpNow(seed)).want(401, "invalid_credentials")
}

// TestRightPasswordWrongCodeCostsOneArgonRun covers admin-r3-5. The replacement
// hash used to be made as soon as the password was right, before the code was
// looked at, so a right password with a wrong code cost two runs and a wrong
// password one, and the response time told them apart. Now the rehash comes
// after the code passed, so both cost one run, and a good login still upgrades
// the stored hash.
func TestRightPasswordWrongCodeCostsOneArgonRun(t *testing.T) {
	r := newRig(t)
	seed := r.setupAdmin(t, true)
	old, err := password.NewHasher(password.Params{MemoryKiB: 96, Time: 1, Threads: 1}, password.NewGate(2, 5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	oldHash, err := old.Hash(r.env.Ctx, secretOf(adminPW))
	if err != nil {
		t.Fatal(err)
	}
	r.env.Exec(t, `UPDATE ctrlz.admin_users SET password_hash = $2 WHERE id = $1`, seedAdmin, oldHash.Reveal())

	runs := r.hasher.Runs()
	r.browser().login(adminPW, "000000").want(401, "invalid_credentials")
	r.browser().login("wrong-wrong-wrong-1", "000000").want(401, "invalid_credentials")
	if got := r.hasher.Runs() - runs; got != 2 {
		t.Fatalf("a wrong code and a wrong password cost %d runs together, want 1 each", got)
	}
	var h string
	r.env.Scan(t, `SELECT password_hash FROM ctrlz.admin_users WHERE id = $1`, []any{seedAdmin}, &h)
	if h != oldHash.Reveal() {
		t.Fatal("a login that failed on the code rewrote the hash")
	}
	// The good login pays for the upgrade after the factor passed.
	r.freeStep(t)
	r.browser().login(adminPW, totpNow(seed)).want(200, "")
	r.env.Scan(t, `SELECT password_hash FROM ctrlz.admin_users WHERE id = $1`, []any{seedAdmin}, &h)
	if h == oldHash.Reveal() || r.hasher.NeedsRehash(secretOf(h)) {
		t.Fatal("a good login did not upgrade the stored hash")
	}
}

// TestOneTimeLoginDoesNotWaitForTheArgonGate covers admin-r3-11. While an
// account holds a console one-time password, a spent per-username scope lets the
// right password through to Argon2; strangers could keep the one-slot gate full
// and the owner's first login would then be 503. The one-time hash is cheap and
// takes no slot, so the login is answered while the gate is held. A password the
// admin chose still needs the gate.
func TestOneTimeLoginDoesNotWaitForTheArgonGate(t *testing.T) {
	r := newRig(t)
	r.setupAdmin(t, false)
	const otp = "ONETIMEPASSWORDXYZ234567"
	hash, err := r.hasher.HashOneTime(secretOf(otp))
	if err != nil {
		t.Fatal(err)
	}
	r.env.Exec(t, `UPDATE ctrlz.admin_users SET password_hash = $2, password_expires_at = now() + interval '24 hours' WHERE id = $1`, seedAdmin, hash.Reveal())

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

	b := r.browser()
	// The gate is held: a name with no account verifies against the dummy hash and waits.
	b.callOn(h, adminHost, "POST", "/auth/login", map[string]any{"username": "nobody-here", "password": "wrong-wrong-wrong-1"}).want(503, "server_busy")
	// A wrong password for the account is refused without waiting for it either.
	b.callOn(h, adminHost, "POST", "/auth/login", map[string]any{"username": adminName, "password": "wrong-wrong-wrong-1"}).want(401, "invalid_credentials")
	b.callOn(h, adminHost, "POST", "/auth/login", map[string]any{"username": adminName, "password": otp}).want(200, "")

	// A chosen password is a full-cost hash and waits for the gate like any other.
	full, err := r.hasher.Hash(r.env.Ctx, secretOf(adminNewPW))
	if err != nil {
		t.Fatal(err)
	}
	r.env.Exec(t, `UPDATE ctrlz.admin_users SET password_hash = $2, must_change_password = false, password_expires_at = NULL WHERE id = $1`, seedAdmin, full.Reveal())
	r.browser().callOn(h, adminHost, "POST", "/auth/login", map[string]any{"username": adminName, "password": adminNewPW}).want(503, "server_busy")
}

// TestDeviceMarkerDoesNotSurviveAReset covers admin-r3-14. A browser that was
// used to break in carries a marker, which skips the per-username counter. A
// console reset moves the account's credential generation, so the marker stops
// counting as known; the admin's own browser gets a new one at the next login.
func TestDeviceMarkerDoesNotSurviveAReset(t *testing.T) {
	if testing.Short() {
		t.Skip("60 logins at the 500 ms floor")
	}
	r := newRig(t)
	seed := r.setupAdmin(t, true)
	intruder := r.browser()
	intruder.mustLogin(seed)
	if intruder.jar[session.CookieAdminDevice] == nil {
		t.Fatal("no marker after login")
	}
	spend := func() {
		t.Helper()
		for i := 0; i < 30; i++ {
			r.browser().login("wrong-wrong-wrong-1", "").want(401, "invalid_credentials")
		}
	}
	spend()
	// The scope is spent for strangers; the marker still opens the door.
	r.freeStep(t)
	intruder.login(adminPW, totpNow(seed)).want(200, "")

	// The password is replaced (a change or a reset moves password_changed_at or the
	// expiry; the generation hashes them all). The intruder knows the new one, as
	// a phisher would, and only the counter stands in the way.
	r.clearAdminThrottle(t)
	r.env.Exec(t, `UPDATE ctrlz.admin_users SET password_changed_at = now() WHERE id = $1`, seedAdmin)
	spend()
	r.freeStep(t)
	intruder.login(adminPW, totpNow(seed)).want(429, "too_many_attempts")
}
