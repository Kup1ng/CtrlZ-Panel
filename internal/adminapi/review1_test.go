package adminapi

import (
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/marker"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/password"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/session"
	"github.com/Kup1ng/CtrlZ-Panel/internal/authtest"
	"github.com/Kup1ng/CtrlZ-Panel/internal/credgen"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
)

// Tests for the fixes of the P1 auth Full review, round 1, admin API area.

// body is a response body with the per-request id removed, so two refusals can
// be compared.
func body(w *aresp) string {
	return strings.Join(strings.Fields(string(stripRequestID(w.Body))), "")
}

// A typo in the new password is plain input validation. It must not spend the
// admin_login budget, or five weak passwords lock the admin out (admin-r1-4).
func TestWeakNewPasswordDoesNotSpendTheBudget(t *testing.T) {
	r := newRig(t)
	seed := r.setupAdmin(t, true)
	b := r.browser()
	b.mustLogin(seed)
	for i := 0; i < 7; i++ {
		b.post("/me/password", map[string]any{"current_password": adminPW, "new_password": "short"}).want(422, "password_weak")
	}
	// The budget is whole: a right change still goes through.
	r.freeStep(t)
	b.post("/me/password", map[string]any{"current_password": adminPW, "new_password": adminNewPW, "totp_code": totpNow(seed)}).want(204, "")
}

// A stolen cookie must not test passwords without limit by changing networks,
// and the answer must not say which factor was wrong (admin-r1-12).
func TestStolenCookieCannotTestPasswordsAcrossNetworks(t *testing.T) {
	r := newRig(t)
	seed := r.setupAdmin(t, true)
	b := r.browser()
	b.mustLogin(seed)
	// The right password without a code and a wrong password are one answer, and
	// cost the same Argon2 work (a verify and a hash).
	var answers []string
	runsBefore := r.hasher.Runs()
	for _, cur := range []string{adminPW, "wrong-wrong-wrong-1"} {
		w := b.post("/me/password", map[string]any{"current_password": cur, "new_password": adminNewPW}).want(401, "invalid_credentials")
		answers = append(answers, body(w))
	}
	if answers[0] != answers[1] {
		t.Fatalf("a right password and a wrong one differ: %q vs %q", answers[0], answers[1])
	}
	if runs := r.hasher.Runs() - runsBefore; runs != 4 {
		t.Fatalf("Argon2 runs = %d for two attempts, want 4", runs)
	}
	// Three more guesses, each from a network no earlier request used. The cookie
	// is the same, so the budget must follow the admin and not the network.
	for i := 0; i < 3; i++ {
		b.ip = freshIP()
		b.post("/me/password", map[string]any{"current_password": "wrong-wrong-wrong-1", "new_password": adminNewPW}).want(401, "invalid_credentials")
	}
	b.ip = freshIP()
	w := b.post("/me/password", map[string]any{"current_password": "wrong-wrong-wrong-2", "new_password": adminNewPW}).want(429, "too_many_attempts")
	if w.H.Get("Retry-After") == "" {
		t.Fatal("no Retry-After")
	}
}

// A spent admin_totp scope must not turn the login into a password oracle
// (admin-r1-14): a right password and a wrong one get the same answer.
func TestSpentTOTPScopeDoesNotRevealThePassword(t *testing.T) {
	r := newRig(t)
	seed := r.setupAdmin(t, true)
	// admin_totp is spent the way a stranger who knows the password spends it: right password,
	// wrong code, five times, each from a network of its own. (Before round 6 a copy of a session
	// cookie could spend it through POST /auth/totp/fresh as well; that route counts on a scope of
	// its own now, admin-r6-5, and TestACopyOfTheCookieCannotSpendTheOwnersLogin holds it.)
	for i := 0; i < 5; i++ {
		r.browser().login(adminPW, "000000").want(401, "invalid_credentials")
	}

	r.freeStep(t)
	var answers []string
	for _, pw := range []string{adminPW, "wrong-wrong-wrong-1"} {
		w := r.browser().login(pw, totpNow(seed)).want(401, "invalid_credentials")
		if w.H.Get("Retry-After") != "" {
			t.Fatal("a Retry-After tells the password was right")
		}
		answers = append(answers, body(w))
	}
	if answers[0] != answers[1] {
		t.Fatalf("answers differ: %q vs %q", answers[0], answers[1])
	}
	if n := has(r.auditActions(t), "admin.login_failed"); n != 7 {
		t.Fatalf("admin.login_failed rows = %d, want 7 (five spending the scope, two after it)", n)
	}
}

// A hash made under old parameters is replaced at the next login, and nothing
// else about the account changes (admin-r1-3, admin-r1-16, spec 4.1).
func TestAdminLoginRehashesAnOldHash(t *testing.T) {
	r := newRig(t)
	seed := r.setupAdmin(t, true)
	old, err := password.NewHasher(password.Params{MemoryKiB: 96, Time: 1, Threads: 1}, password.NewGate(2, 5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	oldHash, err := old.Hash(r.env.Ctx, secret.New(adminPW))
	if err != nil {
		t.Fatal(err)
	}
	r.env.Exec(t, `UPDATE ctrlz.admin_users SET password_hash = $2, password_changed_at = now() - interval '3 days',
	  must_change_password = false WHERE id = $1`, seedAdmin, oldHash.Reveal())
	read := func() (hash string, changed time.Time, must bool) {
		r.env.Scan(t, `SELECT password_hash, password_changed_at, must_change_password FROM ctrlz.admin_users WHERE id = $1`,
			[]any{seedAdmin}, &hash, &changed, &must)
		return
	}
	_, changedBefore, _ := read()

	// A login that fails on the code leaves the old hash alone.
	r.freeStep(t)
	r.browser().login(adminPW, "000000").want(401, "invalid_credentials")
	if h, _, _ := read(); h != oldHash.Reveal() {
		t.Fatal("the hash changed on a failed login")
	}

	r.freeStep(t)
	runs := r.hasher.Runs()
	r.browser().login(adminPW, totpNow(seed)).want(200, "")
	// Verify, then the new hash: two runs on this path.
	if got := r.hasher.Runs() - runs; got != 2 {
		t.Fatalf("Argon2 runs = %d on a rehash login, want 2", got)
	}
	h, changedAfter, must := read()
	if h == oldHash.Reveal() || r.hasher.NeedsRehash(secret.New(h)) {
		t.Fatal("the hash was not replaced by one under the current parameters")
	}
	if ok, err := r.hasher.Verify(r.env.Ctx, secret.New(adminPW), secret.New(h)); err != nil || !ok {
		t.Fatalf("the new hash does not verify the password: %v %v", ok, err)
	}
	if !changedAfter.Equal(changedBefore) || must {
		t.Fatalf("password_changed_at %v -> %v, must_change %v: a rehash must touch nothing but the hash", changedBefore, changedAfter, must)
	}
	// The next login costs one run again.
	r.freeStep(t)
	r.ck.add(time.Minute)
	runs = r.hasher.Runs()
	r.browser().login(adminPW, totpNow(seed)).want(200, "")
	if got := r.hasher.Runs() - runs; got != 1 {
		t.Fatalf("Argon2 runs = %d on a normal login, want 1", got)
	}
}

// The TOTP paths take their throttle hit before the transaction opens, so a
// request never holds the only pooled connection while it waits for a second
// one (admin-r1-5). A pool of one proves it: the old order waits for the
// acquire timeout and fails.
func TestAdminTOTPPathsNeedOnlyOneConnection(t *testing.T) {
	r := newRigOn(t, authtest.AdminKeys(t), 1)
	seed := r.setupAdmin(t, true)
	b := r.browser()
	b.mustLogin(seed) // login with a code
	b.fresh(seed)     // POST /auth/totp/fresh
	r.freeStep(t)
	b.post("/me/password", map[string]any{"current_password": adminPW, "new_password": adminNewPW, "totp_code": totpNow(seed)}).want(204, "")
}

// A browser the admin signed in from keeps working while strangers spend the
// per-username scope; a browser without the marker does not (admin-r1-13).
func TestKnownAdminDeviceIsNotLockedOutByStrangers(t *testing.T) {
	if testing.Short() {
		t.Skip("30 logins at the 500 ms floor")
	}
	r := newRig(t)
	seed := r.setupAdmin(t, true)
	home := r.browser()
	home.mustLogin(seed)
	mk := home.jar[session.CookieAdminDevice]
	if mk == nil || !mk.Secure || !mk.HttpOnly || mk.SameSite != http.SameSiteStrictMode || mk.Domain != "" || mk.Path != "/" {
		t.Fatalf("device cookie = %+v", mk)
	}
	for i := 0; i < 30; i++ {
		r.browser().login("wrong-wrong-wrong-1", "").want(401, "invalid_credentials")
	}
	// A stranger now gets 429 even with the right password.
	r.freeStep(t)
	r.browser().login(adminPW, totpNow(seed)).want(429, "too_many_attempts")
	// The admin's own browser still signs in.
	r.freeStep(t)
	home.login(adminPW, totpNow(seed)).want(200, "")

	// The mk is the admin's only: another name, a forged value and a damaged
	// one do not skip the scope.
	svc := marker.New(r.keys, r.ck.now)
	opens := func(v string) bool { return !svc.Open(marker.Admin, v).Zero() }
	if opens(mk.Value[:len(mk.Value)-2]+"AA") || opens("") || opens("not-a-mk") {
		t.Fatal("a damaged mk was accepted")
	}
	if !opens(mk.Value) {
		t.Fatal("the admin's own mk was refused")
	}
	// The mk is the admin's only: it holds for the account it was issued to and for
	// no other subject.
	var mine credgen.Stamp
	r.env.Scan(t, `SELECT id, credential_gen FROM ctrlz.admin_users WHERE id = $1`, []any{seedAdmin}, &mine.Subject, &mine.Gen)
	if !svc.Open(marker.Admin, mk.Value).Holds(mine) {
		t.Fatal("the mk does not hold for the account it was issued to")
	}
	mine.Subject = uuid.New()
	if svc.Open(marker.Admin, mk.Value).Holds(mine) {
		t.Fatal("a mk issued to one admin held for another")
	}
}

// The noop gateway can be given a role through the API in dev and test, and a
// refusal names the field of the gateway that failed (admin-r1-6).
func TestNoopGatewayCanBeRouted(t *testing.T) {
	r := newRig(t)
	b, _ := r.admin(t)
	b.put("/sms/routing", map[string]any{"primary": "noop"}).want(200, "")
	var role string
	r.env.Scan(t, `SELECT role FROM ctrlz.sms_gateways WHERE provider = 'noop'`, nil, &role)
	if role != "primary" {
		t.Fatalf("noop role = %q", role)
	}
	// sms_ir has no row and no credentials: the fallback is the one that failed.
	w := b.put("/sms/routing", map[string]any{"primary": "noop", "fallback": "sms_ir"}).want(422, "validation_failed")
	if !strings.Contains(string(w.Body), `"fallback"`) || strings.Contains(string(w.Body), `"primary"`) {
		t.Fatalf("the refusal names the wrong field: %s", w.Body)
	}
	// The refusal rolled back: noop is still the primary.
	r.env.Scan(t, `SELECT role FROM ctrlz.sms_gateways WHERE provider = 'noop'`, nil, &role)
	if role != "primary" {
		t.Fatalf("a refused change moved noop to %q", role)
	}
	// Production still refuses it.
	prod := r.handler(t, func(d *Deps) { d.Env = EnvProduction })
	b.callOn(prod, adminHost, "PUT", "/sms/routing", map[string]any{"primary": "noop"}).want(422, "validation_failed")
}

// The same oracle through the login route itself (primitives-r1-11): five right
// passwords with wrong codes use up admin_totp from the login, and the next
// attempt from another network, right password or wrong, must look alike.
func TestSpentTOTPScopeFromLoginsDoesNotRevealThePassword(t *testing.T) {
	r := newRig(t)
	seed := r.setupAdmin(t, true)
	attacker := r.browser()
	for i := 0; i < 5; i++ {
		attacker.login(adminPW, "000000").want(401, "invalid_credentials")
	}
	r.freeStep(t)
	var answers []string
	for _, pw := range []string{adminPW, "wrong-wrong-wrong-1"} {
		w := r.browser().login(pw, totpNow(seed)).want(401, "invalid_credentials")
		if w.H.Get("Retry-After") != "" {
			t.Fatal("a Retry-After tells the password was right")
		}
		answers = append(answers, body(w)+"|"+w.H.Get("Content-Type")+"|"+w.H.Get("Set-Cookie"))
	}
	if answers[0] != answers[1] {
		t.Fatalf("answers differ: %q vs %q", answers[0], answers[1])
	}
}

// raceSameCode sends the same request from n browsers at once and returns the
// responses.
func raceSameCode(n int, send func(i int) *aresp) []*aresp {
	out := make([]*aresp, n)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			out[i] = send(i)
		}(i)
	}
	close(start)
	wg.Wait()
	return out
}

// TestAdminTOTPCodeUsedInParallelPassesOnce is the "TOTP replay" row of 18.5
// against the real admin step UPDATE (primitives-r1-14), on the login and on the
// fresh window. Two racers, because the admin pool is three connections.
func TestAdminTOTPCodeUsedInParallelPassesOnce(t *testing.T) {
	check := func(t *testing.T, what string, rs []*aresp) {
		t.Helper()
		ok, reused := 0, 0
		for _, w := range rs {
			switch {
			case w.Code == 200:
				ok++
			case w.Code == 401 && strings.Contains(string(w.Body), "totp_step_reused"):
				reused++
			default:
				t.Errorf("%s: a racer got %d %s", what, w.Code, w.Body)
			}
		}
		if ok != 1 || reused != len(rs)-1 {
			t.Fatalf("%s: %d passed and %d were totp_step_reused, want 1 and %d", what, ok, reused, len(rs)-1)
		}
	}

	t.Run("login", func(t *testing.T) {
		r := newRig(t)
		seed := r.setupAdmin(t, true)
		r.freeStep(t)
		code := totpNow(seed)
		bs := []*browser{r.browser(), r.browser()}
		check(t, "login", raceSameCode(len(bs), func(i int) *aresp { return bs[i].login(adminPW, code) }))
	})

	t.Run("fresh", func(t *testing.T) {
		r := newRig(t)
		seed := r.setupAdmin(t, true)
		b := r.browser()
		b.mustLogin(seed)
		r.freeStep(t)
		code := totpNow(seed)
		// One session, two requests at once: each gets its own copy of the jar,
		// because the recorder's jar is a plain map.
		bs := make([]*browser, 2)
		for i := range bs {
			bs[i] = &browser{r: r, ip: b.ip, jar: map[string]*http.Cookie{}}
			for k, v := range b.jar {
				bs[i].jar[k] = v
			}
		}
		check(t, "fresh", raceSameCode(len(bs), func(i int) *aresp {
			return bs[i].post("/auth/totp/fresh", map[string]any{"code": code})
		}))
	})
}
