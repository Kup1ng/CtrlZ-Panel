package api

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/pwstrength"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/session"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/token"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/totp"
	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
)

// enableTOTP turns TOTP on for a user directly in the database, sealing a fresh
// seed the way the route does. It returns the seed.
func (f *frig) enableTOTP(tenant, user uuid.UUID) secret.Bytes {
	f.t.Helper()
	seed, err := totp.NewSecret()
	if err != nil {
		f.t.Fatal(err)
	}
	ct, err := f.keys.Seal(keyring.DomainUserTOTP, totp.UserAAD(tenant, user), seed.Reveal())
	if err != nil {
		f.t.Fatal(err)
	}
	f.env.Exec(f.t, `UPDATE ctrlz.users SET totp_secret_ct = $3, totp_enabled_at = now(), totp_pending_at = NULL, totp_last_step = NULL
		WHERE tenant_id = $1 AND id = $2`, tenant, user, ct)
	return seed
}

type resetVerified struct {
	Ticket       string `json:"ticket"`
	SecondFactor string `json:"second_factor"`
}

// verifyReset requests a reset code for phone and checks it.
func (c *client) verifyReset(phone string) resetVerified {
	c.f.t.Helper()
	c.f.clearOTP()
	var iss struct {
		ID string `json:"challenge_id"`
	}
	c.post("/auth/otp/request", map[string]any{"phone": phone, "purpose": "reset"}).want(202, "").json(&iss)
	var v resetVerified
	c.post("/auth/password/reset/verify", map[string]any{"phone": phone, "challenge_id": iss.ID, "code": c.f.codes.Last()}).want(200, "").json(&v)
	return v
}

// TestForgotPassword covers 4.4 for the second factors that need no passkey (T-098).
func TestForgotPassword(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A, B := f.env.A, f.env.B
	const newPw = "Cobalt-meadow-Falcon-4417"

	t.Run("no second factor", func(t *testing.T) {
		owner := f.client()
		owner.mustLogin(A.Phone, pwA)
		owner.loginPassword(A.Phone, pwA, true).want(200, "")
		f.env.Exec(t, `INSERT INTO ctrlz.api_tokens (tenant_id, user_id, name, kind, token_hash, token_prefix) VALUES ($1, $2, 'x', 'read', '\x0c0d'::bytea, 'czt_y')`, A.Tenant, A.User)

		c := f.client()
		// A wrong code does not give a ticket.
		var iss struct {
			ID string `json:"challenge_id"`
		}
		f.clearOTP()
		c.post("/auth/otp/request", map[string]any{"phone": A.Phone, "purpose": "reset"}).want(202, "").json(&iss)
		c.post("/auth/password/reset/verify", map[string]any{"phone": A.Phone, "challenge_id": iss.ID, "code": "000000"}).want(401, "otp_invalid")
		var v resetVerified
		r := c.post("/auth/password/reset/verify", map[string]any{"phone": A.Phone, "challenge_id": iss.ID, "code": f.codes.Last()}).want(200, "")
		r.json(&v)
		if v.SecondFactor != "none" || v.Ticket == "" {
			t.Fatalf("verified = %+v", v)
		}
		if r.Dur < 150*time.Millisecond {
			t.Errorf("verify answered in %v, under its 200 ms floor", r.Dur)
		}

		// A weak password keeps the ticket.
		c.post("/auth/password/reset/complete", map[string]any{"ticket": v.Ticket, "new_password": "short"}).want(422, "password_weak")
		c.post("/auth/password/reset/complete", map[string]any{"ticket": v.Ticket, "new_password": "password12345"}).want(422, "password_weak")
		// A reset ticket is no login ticket.
		c.post("/auth/login/totp", map[string]any{"ticket": v.Ticket, "totp_code": "000000"}).want(401, "ticket_invalid")
		c.post("/auth/password/reset/complete", map[string]any{"ticket": v.Ticket, "new_password": newPw}).want(204, "")

		// Everything ended: sessions, refresh tokens, API tokens.
		owner.get("/me").want(401, "session_expired")
		if n := f.count(`SELECT count(*) FROM ctrlz.sessions WHERE user_id = $1 AND revoked_at IS NULL AND idle_expires_at > now()`, A.User); n != 0 {
			t.Fatalf("%d sessions survived", n)
		}
		if n := f.count(`SELECT count(*) FROM ctrlz.refresh_tokens WHERE user_id = $1 AND revoked_at IS NULL`, A.User); n != 0 {
			t.Fatalf("%d refresh tokens survived", n)
		}
		if n := f.count(`SELECT count(*) FROM ctrlz.api_tokens WHERE user_id = $1 AND revoked_at IS NULL`, A.User); n != 0 {
			t.Fatalf("%d API tokens survived", n)
		}
		if f.count(`SELECT count(*) FROM ctrlz.users WHERE id = $1 AND phone_verified_at IS NOT NULL`, A.User) != 1 {
			t.Fatal("the reset code proved the phone")
		}
		for _, a := range []string{"password.reset"} {
			if f.count(`SELECT count(*) FROM ctrlz.tenant_audit_log WHERE action = $1`, a) != 1 {
				t.Fatalf("no %s row", a)
			}
		}
		// The ticket is spent; the new password logs in, the old one does not.
		c.post("/auth/password/reset/complete", map[string]any{"ticket": v.Ticket, "new_password": newPw}).want(401, "ticket_invalid")
		f.clearThrottle()
		f.client().loginPassword(A.Phone, pwA, false).want(401, "invalid_credentials")
		f.client().mustLogin(A.Phone, newPw)
		f.setPassword(A.Tenant, A.User, pwA)
	})

	t.Run("an open mfa or reset ticket dies with the password change", func(t *testing.T) {
		f.enableTOTP(B.Tenant, B.User)
		f.clearThrottle()
		tk := f.client().mfaLogin(B.Phone, pwB) // an open mfa ticket of B
		owner := f.client()
		f.env.Exec(t, `UPDATE ctrlz.users SET totp_enabled_at = NULL, totp_secret_ct = NULL WHERE id = $1`, B.User)
		owner.mustLogin(B.Phone, pwB)
		owner.reauthPassword(pwB).want(204, "")
		owner.post("/account/password", map[string]any{"new_password": newPw}).want(204, "")
		f.enableTOTP(B.Tenant, B.User)
		f.client().post("/auth/login/totp", map[string]any{"ticket": tk, "totp_code": "000000"}).want(401, "ticket_invalid")
		f.setPassword(B.Tenant, B.User, pwB)
		f.env.Exec(t, `UPDATE ctrlz.users SET totp_enabled_at = NULL, totp_secret_ct = NULL WHERE id = $1`, B.User)
	})

	t.Run("TOTP is the second factor", func(t *testing.T) {
		seed := f.enableTOTP(B.Tenant, B.User)
		c := f.client()
		v := c.verifyReset(B.Phone)
		if v.SecondFactor != "totp" {
			t.Fatalf("second_factor = %q", v.SecondFactor)
		}
		// SMS alone does not take such an account over.
		c.post("/auth/password/reset/complete", map[string]any{"ticket": v.Ticket, "new_password": newPw}).want(401, "totp_invalid")
		c.post("/auth/password/reset/complete", map[string]any{"ticket": v.Ticket, "new_password": newPw, "totp_code": "000000"}).want(401, "totp_invalid")
		f.freeStep(B.Tenant)
		// One code, generated once, for both uses below: a second codeAt(time.Now()) is a code of
		// the NEXT step whenever a 30 second boundary falls between the two (a loaded CI machine
		// spends seconds in the login and the verify between them), and the server then rightly
		// accepts it instead of answering totp_step_reused (CI, round 7: a failure in one run of three).
		code := codeAt(seed, time.Now())
		c.post("/auth/password/reset/complete", map[string]any{"ticket": v.Ticket, "new_password": newPw, "totp_code": code}).want(204, "")
		f.clearThrottle()
		tk := f.client().mfaLogin(B.Phone, newPw)
		_ = tk

		// The same code twice.
		v = c.verifyReset(B.Phone)
		c.post("/auth/password/reset/complete", map[string]any{"ticket": v.Ticket, "new_password": pwB, "totp_code": code}).want(401, "totp_step_reused")
		// A recovery code works too.
		codes := f.recoveryCodesFor(B.Tenant, B.User)
		c.post("/auth/password/reset/complete", map[string]any{"ticket": v.Ticket, "new_password": pwB, "recovery_code": codes[0]}).want(204, "")
		f.client().mfaLogin(B.Phone, pwB)
	})

	t.Run("a suspended tenant gets a decoy and cannot verify", func(t *testing.T) {
		f.env.Exec(t, `UPDATE ctrlz.tenants SET status = 'suspended' WHERE id = $1`, A.Tenant)
		defer f.env.Exec(t, `UPDATE ctrlz.tenants SET status = 'active' WHERE id = $1`, A.Tenant)
		f.clearOTP()
		c := f.client()
		var iss struct {
			ID string `json:"challenge_id"`
		}
		c.post("/auth/otp/request", map[string]any{"phone": A.Phone, "purpose": "reset"}).want(202, "").json(&iss)
		c.post("/auth/password/reset/verify", map[string]any{"phone": A.Phone, "challenge_id": iss.ID, "code": f.codes.Last()}).want(401, "otp_invalid")
	})

	_ = session.CookieSession
}

// recoveryCodesFor plants recovery codes for a user and returns them.
func (f *frig) recoveryCodesFor(tenant, user uuid.UUID) []string {
	f.t.Helper()
	c := f.client()
	_ = c
	// Same generator and hash as the route.
	codes, hashes := newRecoveryFixtures(f.t)
	f.env.Exec(f.t, `DELETE FROM ctrlz.recovery_codes WHERE tenant_id = $1 AND user_id = $2`, tenant, user)
	for _, h := range hashes {
		f.env.Exec(f.t, `INSERT INTO ctrlz.recovery_codes (tenant_id, user_id, code_hash) VALUES ($1, $2, $3)`, tenant, user, h)
	}
	return codes
}

// TestResetFloodWithMadeUpTicketsCostsNoScoring is primitives-r3-6 under rule
// proof-before-work. Round 3 gave the pre-ticket scoring of POST
// /auth/password/reset/complete a gate of its own, so a flood of made-up tickets would
// fill that gate and no other. The scoring now comes after the ticket is read, so a
// made-up ticket never reaches any gate: every one of them is a 401, none takes a scoring
// slot, and a signed-in password change, which has its own gate anyway, is untouched.
func TestResetFloodWithMadeUpTicketsCostsNoScoring(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A := f.env.A
	anon, signed := pwstrength.NewWithLimit(1, time.Nanosecond), pwstrength.NewWithLimit(1, time.Nanosecond)
	f.deps.StrengthUnauthenticated, f.deps.Strength = anon, signed
	f.setLimiter(f.deps.Limiter)

	owner := f.client()
	owner.mustLogin(A.Phone, pwA)
	owner.reauthPassword(pwA).want(204, "")

	// A long, non-repeating l33t password: the expensive case for zxcvbn.
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#$%^&*"
	flood := make([]rune, 100)
	for i, x := 0, 7; i < len(flood); i++ {
		x = (x*31 + 17) % len(alphabet)
		flood[i] = rune(alphabet[(x+i*5)%len(alphabet)])
	}

	const n = 24
	clients := make([]*client, n)
	tickets := make([]string, n)
	for i := range clients {
		clients[i] = f.client()
		tok, err := token.New()
		if err != nil {
			t.Fatal(err)
		}
		tickets[i] = tok.Reveal()
	}
	var other atomic.Int32
	var wg sync.WaitGroup
	for i := range clients {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if r := clients[i].post("/auth/password/reset/complete", map[string]any{"ticket": tickets[i], "new_password": string(flood)}); r.Code != 401 {
				other.Add(1)
			}
		}()
	}
	owner.post("/account/password", map[string]any{"new_password": "Cobalt-meadow-Falcon-4417"}).want(204, "")
	wg.Wait()
	if other.Load() != 0 {
		t.Errorf("%d made-up tickets were not answered 401", other.Load())
	}
	if got := anon.Scorings(); got != 0 {
		t.Errorf("made-up tickets took %d scoring slots", got)
	}
	f.setPassword(A.Tenant, A.User, pwA)
}

// TestResetScoringDoesNotUseTheSignedInGate: a caller who holds a live reset ticket and no
// session scores on the gate of such callers (primitives-r3-6, round 4 tenant-r4-2), so
// when that gate is full the answer is 503 and a signed-in password change still passes.
func TestResetScoringDoesNotUseTheSignedInGate(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A := f.env.A
	anon, signed := pwstrength.NewWithLimit(1, time.Nanosecond), pwstrength.NewWithLimit(1, time.Nanosecond)
	f.deps.StrengthUnauthenticated, f.deps.Strength = anon, signed
	f.setLimiter(f.deps.Limiter)
	const newPw = "Cobalt-meadow-Falcon-4417"

	owner := f.client()
	owner.mustLogin(A.Phone, pwA)
	owner.reauthPassword(pwA).want(204, "")
	v := f.client().verifyReset(A.Phone)

	release, err := anon.Gate().Acquire(f.env.Ctx)
	if err != nil {
		t.Fatal(err)
	}
	f.client().post("/auth/password/reset/complete", map[string]any{"ticket": v.Ticket, "new_password": newPw}).want(503, "server_busy")
	owner.post("/account/password", map[string]any{"new_password": newPw + "x"}).want(204, "")
	if signed.Scorings() == 0 || anon.Scorings() == 0 {
		t.Errorf("scorings: signed-in %d, reset %d; each route should have used its own gate", signed.Scorings(), anon.Scorings())
	}
	release()
	// The change revoked the user's tickets (4.4), so the ticket is dead; a new one completes.
	v = f.client().verifyReset(A.Phone)
	f.client().post("/auth/password/reset/complete", map[string]any{"ticket": v.Ticket, "new_password": newPw}).want(204, "")
	f.setPassword(A.Tenant, A.User, pwA)
}
