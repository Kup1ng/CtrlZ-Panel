package api

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/password"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// fullwidth maps ASCII to the fullwidth forms NFKC folds back, which is how a
// phone keyboard in some input modes types a password.
func fullwidth(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r > 0x20 && r < 0x7f {
			r += 0xFEE0
		}
		b.WriteRune(r)
	}
	return b.String()
}

// TestUnicodePasswordsAreNormalised is the "Unicode" row of 18.5 over HTTP: a
// password set in fullwidth form logs in in ASCII form and the other way round,
// because both pass through NFKC (4.2). Persian and Arabic digits in a phone
// normalise (TestOTPLogin covers the request side).
func TestUnicodePasswordsAreNormalised(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A := f.env.A
	const ascii = "Cobalt-meadow-Falcon-4417"
	c := f.client()
	c.mustLogin(A.Phone, pwA)
	c.reauthPassword(pwA).want(204, "")
	c.post("/account/password", map[string]any{"new_password": fullwidth(ascii)}).want(204, "")
	f.clearThrottle()
	f.client().mustLogin(A.Phone, ascii)
	f.client().mustLogin(A.Phone, fullwidth(ascii))
	f.client().loginPassword(A.Phone, pwA, false).want(401, "invalid_credentials")
	// Persian digits in the phone.
	f.client().mustLogin("۰۹۱۲۰۰۰۰۰۰۱", ascii)
}

// TestOTPBruteForceMeetsTheNetworkLimitOnEveryRoute is the "OTP brute force"
// row of 18.5: the three public routes that verify a code each spend
// otp_verify_net first, so one network gets 30 tries in 15 minutes whichever route it
// uses, and the 31st is 429 too_many_attempts. The two signed-in routes have a subject,
// so they count on reauth_user (5) and never on the network (rule budget-keying). The challenge ids are random, so every
// try is a plain miss and no per-challenge lock gets in the way.
func TestOTPBruteForceMeetsTheNetworkLimitOnEveryRoute(t *testing.T) {
	f := newFrig(t, frigOpts{})
	B := f.env.B
	f.setMode("open") // register verifies a code only when signup is open

	// burst sends one try per call until the network is refused and returns how
	// many tries were answered before that. A rate-limit 429 is not the throttle:
	// it waits out the minute on the fake clock and tries again.
	burst := func(name string, limit int, try func() *resp) {
		t.Helper()
		answered := 0
		for i := 0; i < 60; i++ {
			var r *resp
			for attempt := 0; attempt < 6; attempt++ {
				r = try()
				if r.Code == 429 && r.code() == "rate_limited" {
					f.ck.add(time.Minute)
					continue
				}
				break
			}
			if r.Code == 429 && r.code() == "too_many_attempts" {
				if r.H.Get("Retry-After") == "" {
					t.Errorf("%s: 429 without Retry-After", name)
				}
				if answered != limit {
					t.Errorf("%s: refused after %d tries, want %d", name, answered, limit)
				}
				return
			}
			if r.Code == 429 {
				t.Fatalf("%s: unexpected 429 %s", name, r.Body)
			}
			answered++
		}
		t.Errorf("%s: 60 wrong codes from one network were never refused", name)
	}

	miss := func() string { return uuid.NewString() }
	fresh := func() *client { f.clearThrottle(); return f.client() }

	c := fresh()
	burst("login/otp", 30, func() *resp {
		return c.post("/auth/login/otp", map[string]any{"phone": f.env.A.Phone, "challenge_id": miss(), "code": "000000"})
	})
	c = fresh()
	burst("register", 30, func() *resp {
		return c.post("/auth/register", map[string]any{"phone": "09125550777", "challenge_id": miss(), "code": "000000", "password": "Marble-Island-Copper-6620"})
	})
	c = fresh()
	burst("reset/verify", 30, func() *resp {
		return c.post("/auth/password/reset/verify", map[string]any{"phone": f.env.A.Phone, "challenge_id": miss(), "code": "000000"})
	})

	// The two session routes. A session is made directly, with a live reauth window.
	sess := f.makeSession(f.env.A.Tenant, f.env.A.User)
	f.env.Exec(t, `UPDATE ctrlz.sessions SET reauth_at = now() WHERE user_id = $1`, f.env.A.User)
	burst("phone change confirm", 5, func() *resp {
		return sess.post("/account/phone/change/"+miss()+"/confirm", map[string]any{"old_code": "000000", "new_code": "000000"})
	})
	// Reauth by OTP is for an OTP-only user.
	f.env.Exec(t, `UPDATE ctrlz.users SET password_hash = NULL WHERE tenant_id = $1`, B.Tenant)
	defer f.setPassword(B.Tenant, B.User, pwB)
	osess := f.makeSession(B.Tenant, B.User)
	// Reauth by SMS is stopped sooner, by its per-user scope: 5 tries (tenant-r1-15).
	burst("reauth", 5, func() *resp {
		return osess.post("/auth/reauth", map[string]any{"otp_challenge_id": miss(), "otp_code": "000000"})
	})
}

// TestRecoveryCodeUsedInParallelPassesOnce is the "Recovery reuse" row of 18.5:
// the same recovery code in six logins at the same instant lets exactly one in.
// Six is more than the 4 connections of the test pool: every login holds a pooled
// connection while it waits for the user row. Its throttle call used to need a
// second one, which starved the pool (the holder of the row waited for a connection
// its waiters held, until lock_timeout); a request now holds one connection at a time
// (review round 1, tenant-r1-1 and -7; rule one-connection-per-request), so all six
// are answered.
func TestRecoveryCodeUsedInParallelPassesOnce(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A := f.env.A
	f.enableTOTP(A.Tenant, A.User)
	codes, hashes := newRecoveryFixtures(t)
	if err := f.st.WithTenant(f.env.Ctx, A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
		// The user first, as every route does (lock order).
		if _, _, err := tx.UserLock(A.User); err != nil {
			return err
		}
		return tx.RecoveryCodesReplace(A.User, hashes)
	}); err != nil {
		t.Fatal(err)
	}

	const racers = 6 // more than the 4 connections of the test pool
	clients := make([]*client, racers)
	tickets := make([]string, racers)
	for i := range clients {
		f.clearThrottle()
		clients[i] = f.client()
		tickets[i] = clients[i].mfaLogin(A.Phone, pwA)
	}
	f.clearThrottle()

	var wg sync.WaitGroup
	statuses := make([]int, racers)
	start := make(chan struct{})
	for i := range clients {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			r := clients[i].post("/auth/login/totp", map[string]any{"ticket": tickets[i], "recovery_code": codes[0]})
			statuses[i] = r.Code
		}(i)
	}
	close(start)
	wg.Wait()
	ok := 0
	for _, s := range statuses {
		if s == 200 {
			ok++
		} else if s != 401 && s != 429 { // 429: the sixth try of totp_user (5 in 15 minutes)
			t.Errorf("a racer got %d", s)
		}
	}
	if ok != 1 {
		t.Fatalf("%d logins passed with one recovery code, want 1 (%v)", ok, statuses)
	}
	if m := f.count(`SELECT count(*) FROM ctrlz.recovery_codes WHERE user_id = $1 AND used_at IS NOT NULL`, A.User); m != 1 {
		t.Fatalf("%d recovery codes marked used", m)
	}
}

// TestArgon2FloodIsAnsweredWithServerBusy is the "Argon2 flood" row of 18.5: 100
// logins at once against a gate of two slots. The service answers every one,
// the excess with 503 server_busy and Retry-After, and never runs more than the
// gate allows, which is what keeps api under its memory limit. Memory itself is
// the gate size times the cost of one hash (4.1), and the container limit is
// checked by the Compose lint.
func TestArgon2FloodIsAnsweredWithServerBusy(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A := f.env.A
	heavy, err := password.NewHasher(password.Params{MemoryKiB: 32 * 1024, Time: 3, Threads: 1}, password.NewGate(2, 15*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	f.hasher = heavy
	f.deps.Hasher = heavy
	f.setLimiter(f.deps.Limiter)
	f.setPassword(A.Tenant, A.User, pwA) // stored with the heavy parameters

	const n = 100
	clients := make([]*client, n)
	for i := range clients {
		clients[i] = f.client() // one network each: no throttle or rate limit is what refuses
	}
	var wg sync.WaitGroup
	res := make([]*resp, n)
	start := make(chan struct{})
	for i := range clients {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			// A phone nobody has: the login still runs one Argon2 hash against the
			// dummy (4.5), through the same gate, and no per-phone throttle gets in
			// the way as it would for one phone tried a hundred times.
			res[i] = clients[i].loginPassword(fmt.Sprintf("0912666%04d", i), pwA, false)
		}(i)
	}
	close(start)
	wg.Wait()
	var ok, busy int
	for i, r := range res {
		switch {
		case r.Code == 401 && r.code() == "invalid_credentials":
			ok++
		case r.Code == 503 && r.code() == "server_busy":
			busy++
			if r.H.Get("Retry-After") == "" {
				t.Errorf("request %d: 503 without Retry-After", i)
			}
		default:
			t.Errorf("request %d: %d %s", i, r.Code, r.Body)
		}
	}
	if ok == 0 || busy == 0 {
		t.Fatalf("%d logins were answered and %d were turned away; a flood against a gate of two must do both", ok, busy)
	}
	t.Logf("flood of %d: %d passed, %d server_busy", n, ok, busy)
}

// TestTOTPCodeUsedInParallelPassesOnce is the "TOTP replay" row of 18.5 against
// the real step UPDATE (primitives-r1-14): the same code in three logins at the
// same instant lets one in, and the others get totp_step_reused. A rewrite of
// totp_step_accept as a SELECT and an UPDATE, or a login that stops locking the
// user row first, would let two through. Three racers for the pool reason given
// at TestRecoveryCodeUsedInParallelPassesOnce.
func TestTOTPCodeUsedInParallelPassesOnce(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A, B := f.env.A, f.env.B
	seed := f.enableTOTP(A.Tenant, A.User)
	f.enableTOTP(B.Tenant, B.User)
	f.freeStep(A.Tenant)
	f.freeStep(B.Tenant)

	const racers = 3
	clients := make([]*client, racers)
	tickets := make([]string, racers)
	for i := range clients {
		f.clearThrottle()
		clients[i] = f.client()
		tickets[i] = clients[i].mfaLogin(A.Phone, pwA)
	}
	f.clearThrottle()
	code := codeAt(seed, time.Now())

	var wg sync.WaitGroup
	results := make([]*resp, racers)
	start := make(chan struct{})
	for i := range clients {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			results[i] = clients[i].post("/auth/login/totp", map[string]any{"ticket": tickets[i], "totp_code": code})
		}(i)
	}
	close(start)
	wg.Wait()
	ok, reused := 0, 0
	for _, r := range results {
		switch {
		case r.Code == 200:
			ok++
		case r.Code == 401 && r.code() == "totp_step_reused":
			reused++
		default:
			t.Errorf("a racer got %d %s", r.Code, r.code())
		}
	}
	if ok != 1 || reused != racers-1 {
		t.Fatalf("%d passed and %d were totp_step_reused with one code, want 1 and %d", ok, reused, racers-1)
	}
	// Two-tenant: the other tenant's user keeps no step from this race.
	if n := f.count(`SELECT count(*) FROM ctrlz.users WHERE tenant_id = $1 AND totp_last_step IS NOT NULL`, B.Tenant); n != 0 {
		t.Fatalf("tenant B has %d users with a spent step", n)
	}
}
