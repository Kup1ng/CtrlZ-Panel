package api

import (
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/passkey/passkeytest"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/session"
	"github.com/Kup1ng/CtrlZ-Panel/internal/ratelimit"
)

// Tests of the P1 auth review, round 2, area "HTTP spine and tenant API".

// TestNULInFreeTextIsA422 is tenant-r2-2: Postgres refuses a NUL in text and
// jsonb, and store.sanitize gives that no kind, so the unchecked value used to
// come back as a 500 and a warning in the log. The name says 422 for history: since
// round 5 (rule boundary-input) the pipeline answers 400 bad_request first.
func TestNULInFreeTextIsA422(t *testing.T) {
	f := newFrig(t, frigOpts{passkey: true})
	A := f.env.A
	c := f.client()
	c.mustLogin(A.Phone, pwA)
	c.reauthPassword(pwA).want(204, "")
	var added struct {
		Passkey pkRow `json:"passkey"`
	}
	c.addPasskey(passkeytest.New(pkOrigin, pkRP)).want(201, "").json(&added)

	// Raw bodies: the NUL is a JSON escape the decoder turns into a real byte. Round 5
	// (rule boundary-input) moved the answer from the handler's 422 to the pipeline's
	// 400: no string of the document may hold one, so no handler has the check.
	c.do("PATCH", "/account/passkeys/"+added.Passkey.ID, `{"name":"a\u0000b"}`).want(400, "bad_request")
	c.do("PATCH", "/account/preferences", `{"onboarding_state":{"x":"\u0000"}}`).want(400, "bad_request")
	c.do("PATCH", "/account/preferences", `{"onboarding_state":{"a\u0000":1}}`).want(400, "bad_request")
	c.do("PATCH", "/account/preferences", `{"onboarding_state":{"deep":[{"k":["v\u0000"]}]}}`).want(400, "bad_request")
	if strings.Contains(f.logs.String(), "request failed") {
		t.Errorf("a NUL byte reached the database and was logged as a failure:\n%s", f.logs)
	}
	// Ordinary values still pass. A nested onboarding_state is no longer one of them.
	c.do("PATCH", "/account/passkeys/"+added.Passkey.ID, map[string]any{"name": "Laptop"}).want(200, "")
	c.do("PATCH", "/account/preferences", map[string]any{"onboarding_state": map[string]any{"step": 2, "dismissed": true, "tour": "done"}}).want(200, "")
	c.do("PATCH", "/account/preferences", map[string]any{"onboarding_state": map[string]any{"deep": []any{map[string]any{"k": "v"}}}}).want(400, "bad_request")
}

// TestPasswordAndOTPLoginBeyondThePoolDoNotStall is tenant-r2-3: the storm of
// round 1 left out the two first-factor routes that hold the user row lock and
// then need a throttle hit, an mfa ticket and an auth lookup: all made before the transaction or on its own connection now (rule one-connection-per-request).
func TestPasswordAndOTPLoginBeyondThePoolDoNotStall(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A, B := f.env.A, f.env.B
	const n = 6 // the test pool has 4 connections
	f.enableTOTP(A.Tenant, A.User)
	probe := f.makeSession(B.Tenant, B.User)
	allowed := func(t *testing.T, route string, statuses []int, ok ...int) {
		t.Helper()
		for _, s := range statuses {
			good := s == 429
			for _, o := range ok {
				good = good || s == o
			}
			if !good {
				t.Errorf("%s answered %d", route, s)
			}
		}
	}

	t.Run("login/password, a TOTP user", func(t *testing.T) {
		f.clearThrottle()
		clients := make([]*client, n)
		for i := range clients {
			clients[i] = f.client()
		}
		got := f.stormTx(t, "login/password", n, probe, inTxByCode("mfa_required"), 1, func(i int) *resp {
			return clients[i].loginPassword(A.Phone, pwA, false)
		})
		allowed(t, "login/password", got, 200)
	})

	t.Run("login/otp", func(t *testing.T) {
		f.clearThrottle()
		f.clearOTP()
		ids := make([]string, n)
		codes := make([]string, n)
		clients := make([]*client, n)
		for i := range clients {
			clients[i] = f.client()
			var iss issued
			clients[i].post("/auth/otp/request", map[string]any{"phone": A.Phone, "purpose": "login"}).want(202, "").json(&iss)
			ids[i], codes[i] = iss.ID, f.codes.Last()
			// Only the cooldown goes (the challenges are backdated, not deleted), so all n are live.
			f.env.Exec(t, `TRUNCATE ctrlz.sms_counters`)
			f.env.Exec(t, `UPDATE ctrlz.otp_challenges SET created_at = created_at - interval '2 minutes'`)
		}
		got := f.stormTx(t, "login/otp", n, probe, inTxByStatus(200), 1, func(i int) *resp {
			return clients[i].post("/auth/login/otp", map[string]any{"phone": A.Phone, "challenge_id": ids[i], "code": codes[i]})
		})
		allowed(t, "login/otp", got, 200, 401)
	})
}

// TestResetWeakPasswordsSpendOneReadEach is tenant-r2-4 as rule proof-before-work settles
// it. Round 2 scored the password before the ticket was read so that a weak password
// would cost none of the ticket's five reads, and round 3 had to give that scoring its own
// gate because any client with a made-up ticket reached it. The two aims meet in one
// order: a password that is wrong by its length is refused before the ticket is looked at
// and costs nothing; a ticket nobody issued is refused before the scoring and costs
// nothing; a holder of a live ticket pays one read for each password the scoring refuses,
// the price of the work it asks for.
func TestResetWeakPasswordsSpendOneReadEach(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A := f.env.A
	const newPw = "Cobalt-meadow-Falcon-4417"
	reads := func() int {
		return f.count(`SELECT COALESCE(max(attempts), 0) FROM ctrlz.auth_tickets WHERE kind = 'reset' AND subject_user = $1`, A.User)
	}
	c := f.client()
	v := c.verifyReset(A.Phone)
	if v.SecondFactor != "none" {
		t.Fatalf("second factor = %q", v.SecondFactor)
	}
	for i := 0; i < 8; i++ { // more than the five reads
		c.post("/auth/password/reset/complete", map[string]any{"ticket": v.Ticket, "new_password": "short"}).want(422, "password_weak")
	}
	if got := reads(); got != 0 {
		t.Fatalf("%d reads spent by a password that is too short", got)
	}
	// An unknown ticket is a 401 whatever the password, and nothing scores it.
	f.client().post("/auth/password/reset/complete", map[string]any{"ticket": "nope", "new_password": "short"}).want(422, "password_weak")
	f.client().post("/auth/password/reset/complete", map[string]any{"ticket": "nope", "new_password": "password12345"}).want(401, "ticket_invalid")
	f.client().post("/auth/password/reset/complete", map[string]any{"ticket": "nope", "new_password": newPw}).want(401, "ticket_invalid")
	// A live ticket pays one read for each refusal of the scoring, the phone-derived
	// password included.
	digits := strings.NewReplacer("+", "", "-", "", " ", "").Replace(A.Phone)
	for i, weak := range []string{"password12345", "qwertyuiop1234", "Marble-" + digits[len(digits)-7:] + "-Island"} {
		c.post("/auth/password/reset/complete", map[string]any{"ticket": v.Ticket, "new_password": weak}).want(422, "password_weak")
		if got := reads(); got != i+1 {
			t.Fatalf("after %d weak passwords the ticket has %d reads, want %d", i+1, got, i+1)
		}
	}
	c.post("/auth/password/reset/complete", map[string]any{"ticket": v.Ticket, "new_password": newPw}).want(204, "")
	f.setPassword(A.Tenant, A.User, pwA)
}

// TestPasskeyBeginSurvivesAnAnonymousFlood is tenant-r2-5 under the budget-keying rule.
// Strangers on the owner's network empty the network bucket of the auth class; a browser
// with a valid device marker is charged to its marker and still gets through, a forged
// marker is anonymous, and one marker's bucket is capped wherever it comes from.
func TestPasskeyBeginSurvivesAnAnonymousFlood(t *testing.T) {
	f := newFrig(t, frigOpts{passkey: true})
	A, B := f.env.A, f.env.B
	ownerA, ownerB := f.client(), f.client()
	ownerA.mustLogin(A.Phone, pwA)
	ownerB.mustLogin(B.Phone, pwB)
	markerA, markerB := ownerA.jar[session.CookieDevice], ownerB.jar[session.CookieDevice]
	if markerA == nil || markerB == nil {
		t.Fatal("a password login should leave a device marker")
	}
	withMarker := func(v, ip string) *client {
		c := f.client()
		c.ip = ip
		c.jar[session.CookieDevice] = &http.Cookie{Name: session.CookieDevice, Value: v}
		return c
	}

	// Strangers on one /24 empty its bucket.
	const shared = "203.0.113.9"
	flood := f.client()
	flood.ip = shared
	class, _ := ratelimit.Lookup(ratelimit.Tenant, "auth")
	for i := 0; i < class.Limits[0].Max; i++ {
		flood.post("/auth/passkey/login/begin", map[string]any{}).want(200, "")
	}
	flood.post("/auth/passkey/login/begin", map[string]any{}).want(429, "rate_limited")
	withMarker("forged-"+markerA.Value, shared).post("/auth/passkey/login/begin", map[string]any{}).want(429, "rate_limited")

	// Both tenants' known browsers, on that same network, still begin a login.
	withMarker(markerA.Value, shared).post("/auth/passkey/login/begin", map[string]any{}).want(200, "")
	withMarker(markerB.Value, shared).post("/auth/passkey/login/begin", map[string]any{}).want(200, "")

	// A's own bucket is capped wherever the requests come from, and B's is not
	// touched by A's use of it.
	refused := 0
	for i := 0; i < class.Limits[0].Max+5; i++ {
		if withMarker(markerA.Value, f.freshIP()).post("/auth/passkey/login/begin", map[string]any{}).Code == 429 {
			refused++
		}
	}
	if refused != 6 { // the call above already spent one token
		t.Errorf("%d known-device calls refused, want 6", refused)
	}
	withMarker(markerB.Value, f.freshIP()).post("/auth/passkey/login/begin", map[string]any{}).want(200, "")
}

// TestRestrictedSessionLosesTheWaiverWhenTheOneTimePasswordExpires is
// tenant-r2-6: the waiver of 4.4 rests on the one-time password having just
// proved knowledge, so it ends when that password expires, also for a Remember
// me session that is still alive.
func TestRestrictedSessionLosesTheWaiverWhenTheOneTimePasswordExpires(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A, B := f.env.A, f.env.B
	const oneTime = "One-Time-Pass-8842x"
	const newPw = "Cobalt-meadow-Falcon-4417"
	h, _ := f.hasher.Hash(f.env.Ctx, secretString(oneTime))
	setOneTime := func(user uuid.UUID) {
		f.env.Exec(t, `UPDATE ctrlz.users SET password_hash = $2, must_reset = true, password_expires_at = now() + interval '72 hours' WHERE id = $1`, user, h.Reveal())
	}
	setOneTime(A.User)
	setOneTime(B.User)

	login := func(phone string) *client {
		c := f.client()
		c.loginPassword(phone, oneTime, true).want(200, "") // Remember me
		if !c.me().User.MustReset {
			t.Fatal("not a setup session")
		}
		return c
	}
	a, b := login(A.Phone), login(B.Phone)

	// The one-time password expires; both sessions are still alive.
	f.env.Exec(t, `UPDATE ctrlz.users SET password_expires_at = now() - interval '1 hour' WHERE id = $1`, A.User)
	a.post("/auth/refresh", nil).want(204, "") // Remember me keeps it going
	a.post("/account/password", map[string]any{"new_password": newPw}).want(403, "reauth_required")
	if f.count(`SELECT count(*) FROM ctrlz.users WHERE id = $1 AND must_reset`, A.User) != 1 {
		t.Fatal("the refused call changed the user")
	}
	// Tenant B's still-live one-time password is unaffected.
	b.post("/account/password", map[string]any{"new_password": newPw}).want(204, "")
}
