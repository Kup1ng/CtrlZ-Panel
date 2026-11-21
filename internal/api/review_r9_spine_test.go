package api

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/pwstrength"
)

// Tests of the P1 auth review, round 9, area "HTTP spine and tenant API".

// TestALiveInviteStillGetsItsCodeWhenStrangersFillTheNetwork is tenant-r9-1. The otp-send class (5 a minute,
// 30 an hour, per source /24) was charged in the pipeline with no proof to stand in for the network but a
// device marker, and a first-time invitee has none, so thirty junk code requests from anybody on the carrier
// /24 refused the one request that registration in the closed mode needs, for up to an hour. A live invite
// is a proof now: the pipeline hands the refusal over, the handler reads the invite and settles it on the
// invite's own buckets. The flood comes first. The controls: a token that is not live, a request of another
// purpose and an invite that was already used get the plain answer, and the invite's own bucket bounds it.
func TestALiveInviteStillGetsItsCodeWhenStrangersFillTheNetwork(t *testing.T) {
	f := newFrig(t, frigOpts{})
	f.clearThrottle()
	const phone = "+989125553009"
	const other = "+989125553010"
	code := f.plantInvite(phone, time.Hour, false)
	second := f.plantInvite(other, time.Hour, false)
	const bad = "AAAAA-AAAAA-AAAAA-AAAAA"

	on := func(last int) *client { c := f.client(); c.ip = fmt.Sprintf("203.0.113.%d", last); return c }
	// The flood: strangers on the /24 fill the plain bucket with numbers nobody has.
	limited := 0
	for i := 0; i < 12; i++ {
		if on(10+i).post("/auth/otp/request", map[string]any{"phone": fmt.Sprintf("0912555%04d", i), "purpose": "login"}).Code == http.StatusTooManyRequests {
			limited++
		}
	}
	if limited == 0 {
		t.Fatal("the strangers were never refused: the plain bucket was not filled and the test proves nothing")
	}
	f.clearOTP()
	on(100).post("/auth/otp/request", map[string]any{"phone": "09125559991", "purpose": "login"}).want(429, "")

	// The controls: nothing but a live invite gets through the filled bucket.
	on(101).requestOTP(phone, "invite", map[string]any{"invite_token": bad}).want(429, "")
	on(102).requestOTP(phone, "invite", map[string]any{"invite_token": "not a code"}).want(429, "")
	on(103).requestOTP(phone, "signup", nil).want(429, "")
	on(104).requestOTP(phone, "invite", nil).want(429, "")

	// The invitee, on the same /24, gets his code; the invite's own bucket bounds him to the class's five.
	var iss issued
	on(110).requestOTP(phone, "invite", map[string]any{"invite_token": code}).want(202, "").json(&iss)
	answered := 1
	for i := 0; i < 8; i++ {
		if on(111+i).requestOTP(phone, "invite", map[string]any{"invite_token": code}).Code == http.StatusAccepted {
			answered++
		}
	}
	if answered != 5 {
		t.Fatalf("a live invite was answered %d times in a minute from a filled network, want its own 5", answered)
	}
	// Another invite on the same network shares nothing with it.
	on(130).requestOTP(other, "invite", map[string]any{"invite_token": second}).want(202, "")
	// The junk did not spend what the invite needed: the invitee registers from the same network.
	f.clearOTP()
	f.ck.add(2 * time.Minute)
	c := on(140)
	c.requestOTP(phone, "invite", map[string]any{"invite_token": code}).want(202, "").json(&iss)
	c.post("/auth/register", map[string]any{
		"invite_token": code, "challenge_id": iss.ID, "code": f.codes.Last(), "password": "Marble-Island-Copper-6620",
	}).want(201, "")
}

// TestAnInviteRequestDoesNotSpendTheNetworkBucketOfStrangers: the other half of the same rule. On a network
// the strangers have not filled, an invitee's request is charged to the invite and the plain token goes back,
// so the five a minute of the /24 are all still there for everybody else.
func TestAnInviteRequestDoesNotSpendTheNetworkBucketOfStrangers(t *testing.T) {
	f := newFrig(t, frigOpts{})
	f.clearThrottle()
	const phone = "+989125553011"
	code := f.plantInvite(phone, time.Hour, false)
	on := func(last int) *client { c := f.client(); c.ip = fmt.Sprintf("203.0.114.%d", last); return c }
	for i := 0; i < 5; i++ {
		on(10+i).requestOTP(phone, "invite", map[string]any{"invite_token": code}).want(202, "")
	}
	for i := 0; i < 5; i++ {
		on(30+i).requestOTP(fmt.Sprintf("0912555%04d", 100+i), "login", nil).want(202, "")
	}
	on(50).requestOTP("09125550999", "login", nil).want(429, "")
}

// TestAWaivedPasswordChangeLooksAtTheCodeBeforeTheHeavyWork is tenant-r9-2. A session opened by the
// one-time password of a user with an authenticator needs no reauth window and is asked for a code
// instead, and the route scored and hashed the new password before it looked at the code, so a request
// with no code, or with one that cannot be right, paid for both and ended in totp_invalid, up to the
// sensitive limit of every session. The code is looked at without being spent first now (as in the
// reset), and the scoring and the hash are for a caller whose code could be right.
func TestAWaivedPasswordChangeLooksAtTheCodeBeforeTheHeavyWork(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A := f.env.A
	strong := pwstrength.NewWithLimit(2, 100*time.Millisecond)
	f.deps.Strength = strong
	f.setLimiter(f.deps.Limiter)
	const newPw = "Cobalt-meadow-Falcon-4417"
	const oneTime = "One-Time-Pass-8842x"
	h, _ := f.hasher.Hash(f.env.Ctx, secretString(oneTime))
	f.env.Exec(t, `UPDATE ctrlz.users SET password_hash = $2, must_reset = true, password_expires_at = now() + interval '72 hours' WHERE id = $1`, A.User, h.Reveal())
	seed := f.enableTOTP(A.Tenant, A.User)
	f.clearThrottle()
	cl := f.client()
	tk := cl.mfaLogin(A.Phone, oneTime)
	now := time.Now()
	cl.post("/auth/login/totp", map[string]any{"ticket": tk, "totp_code": codeAt(seed, now)}).want(200, "")

	runs, scored := f.hasher.Runs(), strong.Scorings()
	cl.post("/account/password", map[string]any{"new_password": newPw}).want(401, "totp_invalid")
	// A code that is no code at all, and one that is a well-formed guess at another time of day.
	cl.post("/account/password", map[string]any{"new_password": newPw, "totp_code": "abc"}).want(401, "totp_invalid")
	wrong := codeAt(seed, now.Add(10*time.Hour))
	cl.post("/account/password", map[string]any{"new_password": newPw, "totp_code": wrong}).want(401, "totp_invalid")
	if got := f.hasher.Runs() - runs; got != 0 {
		t.Errorf("a code that cannot be right cost %d Argon2 runs before it was refused", got)
	}
	if got := strong.Scorings() - scored; got != 0 {
		t.Errorf("a code that cannot be right cost %d scorings before it was refused", got)
	}
	// The right code still changes the password, and does the work once.
	cl.post("/account/password", map[string]any{"new_password": newPw, "totp_code": codeAt(seed, now.Add(30*time.Second))}).want(204, "")
	if got := strong.Scorings() - scored; got != 1 {
		t.Errorf("the right code scored the password %d times, want once", got)
	}
}
