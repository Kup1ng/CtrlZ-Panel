package api

import (
	"context"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/password"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/pwstrength"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/session"
)

// Tests of the P1 auth review, round 5, area "HTTP spine and tenant API": the throttle around
// the password login and the OTP checks (tenant-r5-1, -3 and -9).

// busyFrig is a rig whose Argon2 gate has one slot and a short wait, with the slot taken, so a
// password check answers 503 server_busy at once. release frees the slot.
func busyFrig(t *testing.T, o frigOpts) (f *frig, release func()) {
	t.Helper()
	f = newFrig(t, o)
	h, err := password.NewHasher(password.Params{MemoryKiB: 64, Time: 1, Threads: 1}, password.NewGate(1, 50*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	f.hasher, f.deps.Hasher = h, h
	f.setLimiter(f.deps.Limiter)
	f.setPassword(f.env.A.Tenant, f.env.A.User, pwA)
	f.setPassword(f.env.B.Tenant, f.env.B.User, pwB)
	rel, err := h.Gate().Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return f, rel
}

// scopeCount is the sum of the counters of a scope, whoever they belong to.
func (f *frig) scopeCount(scope string) int {
	f.t.Helper()
	return f.count(`SELECT coalesce(sum(count), 0)::int FROM ctrlz.auth_throttle WHERE scope = $1`, scope)
}

// TestBusyLoginsDoNotSpendTheThrottle is tenant-r5-1. Attempts that the full Argon2 gate turned
// away looked at no password. Before the refund, five of them spent login_phone_net (5 a window)
// and the next try, with the right password and after the load had gone, was a 429 for 15 minutes.
// The phone is the key whether or not it has an account, so an unknown number is given back
// the same.
func TestBusyLoginsDoNotSpendTheThrottle(t *testing.T) {
	f, release := busyFrig(t, frigOpts{})
	f.clearThrottle()
	A := f.env.A
	c := f.client()
	for i := 0; i < 8; i++ {
		c.loginPassword(A.Phone, pwA, false).want(503, "server_busy")
	}
	for i := 0; i < 8; i++ {
		c.loginPassword("+989129990001", pwA, false).want(503, "server_busy") // no such account
	}
	c.loginPassword("not a phone", pwA, false).want(503, "server_busy")
	for _, sc := range []string{"login_phone_net", "login_phone", "login_net", "login_net48"} {
		if n := f.scopeCount(sc); n != 0 {
			t.Errorf("%s still counts %d after only busy answers", sc, n)
		}
	}
	release()
	c.mustLogin(A.Phone, pwA)
}

// TestBusyRegisterGivesBackTheNetworkCheck: a register that proved its code and met a full gate is
// not a guess, and gives its otp_verify_net count back.
func TestBusyRegisterGivesBackTheNetworkCheck(t *testing.T) {
	f, release := busyFrig(t, frigOpts{mode: "open"})
	defer release()
	f.clearThrottle()
	c := f.client()
	phone := "+989127770001"
	var iss struct {
		ID string `json:"challenge_id"`
	}
	c.post("/auth/otp/request", map[string]any{"phone": phone, "purpose": "signup", "locale": "fa"}).want(202, "").json(&iss)
	code := f.codes.Last()
	c.post("/auth/register", map[string]any{
		"phone": phone, "challenge_id": iss.ID, "code": code, "password": "Granite-Falcon-Meadow-4417",
	}).want(503, "server_busy")
	if n := f.scopeCount("otp_verify_net"); n != 0 {
		t.Errorf("otp_verify_net counts %d after a busy register of a right code", n)
	}
}

// TestASuccessfulSignInGivesTheNetworkAttemptBack is tenant-r5-3: a network scope counts failed
// guesses, so honest sign-ins behind one carrier address group do not fill it.
func TestASuccessfulSignInGivesTheNetworkAttemptBack(t *testing.T) {
	f := newFrig(t, frigOpts{})
	f.clearThrottle()
	A := f.env.A
	c := f.client()
	for i := 0; i < 3; i++ {
		c.mustLogin(A.Phone, pwA)
	}
	for _, sc := range []string{"login_net", "login_phone_net", "login_phone"} {
		if n := f.scopeCount(sc); n != 0 {
			t.Errorf("%s counts %d after three right sign-ins", sc, n)
		}
	}
	c.loginPassword(A.Phone, "wrong-Password-1234", false).want(401, "invalid_credentials")
	if n := f.scopeCount("login_net"); n != 1 {
		t.Errorf("login_net counts %d after one wrong password, want 1", n)
	}
	// The same for the code: a right one is not a guess, a wrong one is.
	var iss struct {
		ID string `json:"challenge_id"`
	}
	f.clearOTP()
	c.post("/auth/otp/request", map[string]any{"phone": A.Phone, "purpose": "login", "locale": "fa"}).want(202, "").json(&iss)
	code := f.codes.Last()
	c.post("/auth/login/otp", map[string]any{"phone": A.Phone, "challenge_id": iss.ID, "code": "000000"}).want(401, "otp_invalid")
	if n := f.scopeCount("otp_verify_net"); n != 1 {
		t.Errorf("otp_verify_net counts %d after one wrong code, want 1", n)
	}
	c.post("/auth/login/otp", map[string]any{"phone": A.Phone, "challenge_id": iss.ID, "code": code}).want(200, "")
	if n := f.scopeCount("otp_verify_net"); n != 1 {
		t.Errorf("otp_verify_net counts %d after the right code, want it unchanged at 1", n)
	}
}

// TestAnOwnersMarkerKeepsLoginWhenStrangersFillLoginPhone is tenant-r5-9. login_phone is keyed on
// the phone alone, so four networks of five wrong passwords each filled it and kept the owner's
// right password at 429 for the rest of the hour. The owner's browser holds a device marker no
// stranger can make for this account, and its guesses count on the marker's own scope. Another
// account's marker, or none, does not help.
func TestAnOwnersMarkerKeepsLoginWhenStrangersFillLoginPhone(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A, B := f.env.A, f.env.B
	owner, other := f.client(), f.client()
	owner.mustLogin(A.Phone, pwA) // the first sign-in sets the marker
	other.mustLogin(B.Phone, pwB)
	if owner.jar[session.CookieDevice] == nil || other.jar[session.CookieDevice] == nil {
		t.Fatal("a sign-in left no device marker, so the case proves nothing")
	}
	for n := 0; n < 4; n++ {
		stranger := f.client()
		for i := 0; i < 5; i++ {
			stranger.loginPassword(A.Phone, "wrong-Password-9999", false).want(401, "invalid_credentials")
		}
	}
	if got := f.scopeCount("login_phone"); got != 20 {
		t.Fatalf("login_phone counts %d, the strangers should have spent all 20", got)
	}
	// Without a marker, or with the marker of another account, the right password is refused.
	f.client().loginPassword(A.Phone, pwA, false).want(429, "too_many_attempts")
	imposter := f.client()
	imposter.jar[session.CookieDevice] = other.jar[session.CookieDevice]
	imposter.loginPassword(A.Phone, pwA, false).want(429, "too_many_attempts")
	// The owner's browser, from a network that has spent nothing, signs in with the right password.
	owner.ip = f.freshIP()
	owner.mustLogin(A.Phone, pwA)
	// The marker has a budget of its own: wrong guesses from the owner's browser are bounded too.
	guesser := f.client()
	guesser.jar[session.CookieDevice] = owner.jar[session.CookieDevice]
	refused := 0
	for i := 0; i < 15; i++ {
		guesser.ip = f.freshIP()
		if guesser.loginPassword(A.Phone, "wrong-Password-9999", false).Code == 429 {
			refused++
		}
	}
	if refused == 0 {
		t.Error("a marker that holds was never refused: its own scope has no limit")
	}
}

// TestAMarkerEndsWithTheCredentials: a marker issued before the password changed does not hold, so
// a former intruder's marker does not buy the owner's budget.
func TestAMarkerEndsWithTheCredentials(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A := f.env.A
	old := f.client()
	old.mustLogin(A.Phone, pwA)
	marker := old.jar[session.CookieDevice]
	if marker == nil {
		t.Fatal("no marker")
	}
	f.setPassword(A.Tenant, A.User, "Changed-Harbor-Quartz-2048")
	for n := 0; n < 4; n++ {
		stranger := f.client()
		for i := 0; i < 5; i++ {
			stranger.loginPassword(A.Phone, "wrong-Password-9999", false).want(401, "invalid_credentials")
		}
	}
	c := f.client()
	c.jar[session.CookieDevice] = marker
	c.loginPassword(A.Phone, "Changed-Harbor-Quartz-2048", false).want(429, "too_many_attempts")
}

// TestResetWithAWrongSecondFactorDoesNoHeavyWork is tenant-r5-6. A caller who holds the SMS
// ticket and not the authenticator (a SIM swap) used to get the scoring and an Argon2 hash for
// every wrong code. The code is looked at first now, so a wrong TOTP code, a wrong recovery code
// and no code all end before the scoring gate and the hasher are touched. They still cost a try
// on totp_user where a code was sent, and the right code still works and does the work once.
func TestResetWithAWrongSecondFactorDoesNoHeavyWork(t *testing.T) {
	f := newFrig(t, frigOpts{})
	B := f.env.B
	anon := pwstrength.NewWithLimit(2, time.Second)
	f.deps.StrengthUnauthenticated = anon
	f.setLimiter(f.deps.Limiter)
	f.clearThrottle()
	seed := f.enableTOTP(B.Tenant, B.User)
	const newPw = "Cobalt-meadow-Falcon-4417"
	c := f.client()
	v := c.verifyReset(B.Phone)
	runs := f.hasher.Runs()
	c.post("/auth/password/reset/complete", map[string]any{"ticket": v.Ticket, "new_password": newPw}).want(401, "totp_invalid")
	c.post("/auth/password/reset/complete", map[string]any{"ticket": v.Ticket, "new_password": newPw, "totp_code": "000000"}).want(401, "totp_invalid")
	c.post("/auth/password/reset/complete", map[string]any{"ticket": v.Ticket, "new_password": newPw, "recovery_code": "aaaa-bbbb-cccc"}).want(401, "totp_invalid")
	if anon.Scorings() != 0 || f.hasher.Runs() != runs {
		t.Fatalf("wrong second factors reached the heavy work: %d scorings, %d Argon2 runs", anon.Scorings(), f.hasher.Runs()-runs)
	}
	// The TOTP code is counted in the window and in the daily ceiling of totp_sms (round 8, primitives-r8-4; the
	// reset ticket is an SMS ticket, round 9), the recovery code once, in the window of recovery_user, which has no
	// ceiling because it cannot be walked (primitives-r9-4). All of them are stored under the database scope totp_user.
	if n := f.scopeCount("totp_user"); n != 2+1 {
		t.Errorf("totp_user counts %d, want 3: the code in the window and the ceiling, the recovery code in its window", n)
	}
	f.freeStep(B.Tenant)
	c.post("/auth/password/reset/complete", map[string]any{"ticket": v.Ticket, "new_password": newPw, "totp_code": codeAt(seed, time.Now())}).want(204, "")
	if anon.Scorings() != 1 {
		t.Errorf("the right code did %d scorings, want 1", anon.Scorings())
	}
}

// TestBusyResetGivesBackTheSecondFactorTry is tenant-r5-1 for the reset: the second factor is
// counted before the password is scored, and a full gate looked at nothing.
func TestBusyResetGivesBackTheSecondFactorTry(t *testing.T) {
	f := newFrig(t, frigOpts{})
	B := f.env.B
	anon := pwstrength.NewWithLimit(1, time.Nanosecond)
	f.deps.StrengthUnauthenticated = anon
	f.setLimiter(f.deps.Limiter)
	f.clearThrottle()
	seed := f.enableTOTP(B.Tenant, B.User)
	const newPw = "Cobalt-meadow-Falcon-4417"
	c := f.client()
	v := c.verifyReset(B.Phone)
	release, err := anon.Gate().Acquire(f.env.Ctx)
	if err != nil {
		t.Fatal(err)
	}
	f.freeStep(B.Tenant)
	c.post("/auth/password/reset/complete", map[string]any{"ticket": v.Ticket, "new_password": newPw, "totp_code": codeAt(seed, time.Now())}).want(503, "server_busy")
	if n := f.scopeCount("totp_user"); n != 0 {
		t.Errorf("totp_user counts %d after a busy answer, want 0", n)
	}
	release()
	c.post("/auth/password/reset/complete", map[string]any{"ticket": v.Ticket, "new_password": newPw, "totp_code": codeAt(seed, time.Now())}).want(204, "")
}
