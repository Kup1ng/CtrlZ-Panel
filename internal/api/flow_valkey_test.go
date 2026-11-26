package api

import (
	"context"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/passkey/passkeytest"
	"github.com/Kup1ng/CtrlZ-Panel/internal/ratelimit"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testvalkey"
)

// TestValkeyDownAndBack covers the two Valkey rows of 18.3 over HTTP. With the
// server down, password login, OTP verify, TOTP and Passkey login work, OTP
// send answers 503 sms_unavailable for known and unknown phones alike, the
// limits fall back in process, and the Postgres throttle still blocks. When the
// server returns, the same handler (no restart) sends OTPs again.
func TestValkeyDownAndBack(t *testing.T) {
	if testing.Short() {
		t.Skip("-short: container tests skipped")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	vk, err := testvalkey.Start(ctx)
	if err != nil {
		t.Fatalf("start valkey: %v", err)
	}
	t.Cleanup(func() { _ = vk.Terminate(context.Background()) })

	f := newFrig(t, frigOpts{passkey: true})
	A, B := f.env.A, f.env.B
	// The timeouts are generous on purpose: this is a test of what happens when Valkey is
	// GONE, and with the production defaults (250 ms a call, 1 s a dial) a Valkey that was
	// merely slow on a machine running four container packages at once also failed the
	// up-phase send (round 13, CI run: 503 sms_unavailable at the first OTP, before any stop).
	// The down phase pays one timeout in all, as the cooldown holds the backend off.
	backend := ratelimit.NewValkey(ratelimit.ValkeyConfig{Addr: vk.Addr, DialTimeout: 3 * time.Second})
	t.Cleanup(backend.Close)
	// Not LocalOnly: this is the production limiter. The cooldown is short so the
	// recovery step does not wait a real 30 seconds.
	f.setLimiter(ratelimit.New(ratelimit.Config{Service: ratelimit.Tenant, Backend: backend, Now: f.ck.now, Cooldown: time.Second, Timeout: 5 * time.Second}))

	// Everything the down phase needs is made while Valkey is up: a passkey, a
	// TOTP user and a pending login challenge.
	key := passkeytest.New(pkOrigin, pkRP)
	owner := f.client()
	owner.mustLogin(A.Phone, pwA)
	owner.reauthPassword(pwA).want(204, "")
	owner.addPasskey(key).want(201, "")
	seed := f.enableTOTP(B.Tenant, B.User)
	var iss issued
	f.client().requestOTP(A.Phone, "login", nil).want(202, "").json(&iss)
	code := f.codes.Last()

	if err := vk.Stop(ctx); err != nil {
		t.Fatalf("stop valkey: %v", err)
	}
	resumed := false
	resume := func() {
		if !resumed {
			resumed = true
			if err := vk.Resume(context.Background()); err != nil {
				t.Errorf("resume valkey: %v", err)
			}
		}
	}
	t.Cleanup(resume)

	// Down: what must keep working.
	f.clearThrottle()
	f.client().mustLogin(A.Phone, pwA)
	f.client().post("/auth/login/otp", map[string]any{"phone": A.Phone, "challenge_id": iss.ID, "code": code}).want(200, "")
	f.freeStep(B.Tenant)
	cl := f.client()
	tk := cl.mfaLogin(B.Phone, pwB)
	cl.post("/auth/login/totp", map[string]any{"ticket": tk, "totp_code": codeAt(seed, time.Now())}).want(200, "")
	f.client().passkeyLogin(key).want(200, "")

	// Down: what must refuse. Known and unknown phones answer alike.
	for _, phone := range []string{A.Phone, "09127776655"} {
		f.clearOTP()
		f.client().post("/auth/otp/request", map[string]any{"phone": phone, "purpose": "login"}).want(503, "sms_unavailable")
	}

	// Down: the Postgres throttle still blocks password spraying, whatever the
	// in-process fallback does.
	f.clearThrottle()
	spray := f.client()
	blocked := false
	for i := 0; i < 12 && !blocked; i++ {
		r := spray.loginPassword(A.Phone, "Wrong-Guess-Heron-"+string(rune('a'+i))+"-77", false)
		if r.Code == 429 {
			blocked = r.code() == "too_many_attempts" || r.code() == "rate_limited"
		}
	}
	if !blocked {
		t.Fatal("password spraying was never blocked with Valkey down")
	}

	// Back: no restart, no new handler. The limiter retries after its cooldown.
	resume()
	f.ck.add(5 * time.Second)
	f.clearOTP()
	f.clearThrottle()
	deadline := time.Now().Add(30 * time.Second)
	for {
		f.ck.add(2 * time.Second)
		r := f.client().post("/auth/otp/request", map[string]any{"phone": B.Phone, "purpose": "login"})
		if r.Code == 202 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("OTP send did not recover after Valkey returned: %d %s", r.Code, r.Body)
		}
		f.clearOTP()
		time.Sleep(time.Second)
	}
}
