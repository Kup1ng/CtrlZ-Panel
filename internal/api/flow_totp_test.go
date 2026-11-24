package api

import (
	"encoding/base32"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/session"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/totp"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
)

func codeAt(seed secret.Bytes, at time.Time) string { return totp.Generate(seed, at) }

// freeStep forgets the last spent step, so one code can be used again inside
// its 30 seconds. Only a test can do this; the replay tests do not use it.
func (f *frig) freeStep(tenant uuid.UUID) {
	f.t.Helper()
	f.env.Exec(f.t, `UPDATE ctrlz.users SET totp_last_step = NULL WHERE tenant_id = $1`, tenant)
}

// mfaLogin does a password login and returns the ticket of mfa_required.
func (c *client) mfaLogin(phone, pw string) string {
	c.f.t.Helper()
	var res loginBody
	c.loginPassword(phone, pw, false).want(200, "").json(&res)
	if res.Status != "mfa_required" || res.Ticket == "" || len(res.Method) != 2 {
		c.f.t.Fatalf("login = %+v, want mfa_required", res)
	}
	return res.Ticket
}

// TestTOTP covers 6 and T-101, T-102.
func TestTOTP(t *testing.T) {
	f := newFrig(t, frigOpts{})
	var recoveryCodes []string // shared between the steps below
	A := f.env.A

	other, c := f.client(), f.client()
	other.mustLogin(A.Phone, pwA)
	c.mustLogin(A.Phone, pwA)

	c.post("/account/totp/setup", nil).want(403, "reauth_required")
	c.reauthPassword(pwA).want(204, "")

	var setup struct {
		Secret string `json:"secret"`
		URI    string `json:"otpauth_uri"`
	}
	c.post("/account/totp/setup", nil).want(200, "").json(&setup)
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(setup.Secret)
	if err != nil || len(raw) != 20 {
		t.Fatalf("secret = %q (%v)", setup.Secret, err)
	}
	seed := secret.NewBytes(raw)
	if !strings.HasPrefix(setup.URI, "otpauth://totp/Ctrl%20Z:") || !strings.Contains(setup.URI, "secret="+setup.Secret) ||
		strings.Contains(setup.URI, "9120000001") {
		t.Fatalf("otpauth URI = %q (the label must carry the masked number only)", setup.URI)
	}
	if f.count(`SELECT count(*) FROM ctrlz.users WHERE id = $1 AND totp_secret_ct IS NOT NULL AND totp_enabled_at IS NULL AND totp_pending_at IS NOT NULL`, A.User) != 1 {
		t.Fatal("setup must store a pending, sealed secret")
	}
	if f.count(`SELECT count(*) FROM ctrlz.users WHERE totp_secret_ct = $1`, setup.Secret) != 0 {
		t.Fatal("the seed is stored in clear")
	}

	t.Run("confirm", func(t *testing.T) {
		now := time.Now()
		c.post("/account/totp/confirm", map[string]any{"code": codeAt(seed, now), "saved": false}).want(422, "validation_failed")
		c.post("/account/totp/confirm", map[string]any{"code": "000000", "saved": true}).want(401, "totp_invalid")
		// Two steps back is outside the window of one.
		c.post("/account/totp/confirm", map[string]any{"code": codeAt(seed, now.Add(-90*time.Second)), "saved": true}).want(401, "totp_invalid")

		// A pending secret older than 15 minutes is cleared and refused.
		f.env.Exec(t, `UPDATE ctrlz.users SET totp_pending_at = now() - interval '16 minutes' WHERE id = $1`, A.User)
		c.post("/account/totp/confirm", map[string]any{"code": codeAt(seed, now), "saved": true}).want(409, "totp_not_pending")
		if f.count(`SELECT count(*) FROM ctrlz.users WHERE id = $1 AND totp_secret_ct IS NULL`, A.User) != 1 {
			t.Fatal("a stale pending secret must be cleared")
		}
		c.post("/account/totp/confirm", map[string]any{"code": codeAt(seed, now), "saved": true}).want(409, "totp_not_pending")
		// A fresh setup, then the real confirm.
		c.post("/account/totp/setup", nil).want(200, "").json(&setup)
		raw, _ = base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(setup.Secret)
		seed = secret.NewBytes(raw)

		live := f.count(`SELECT count(*) FROM ctrlz.sessions WHERE user_id = $1 AND revoked_at IS NULL`, A.User)
		old := *c.jar[session.CookieSession]
		var done struct {
			Codes []string `json:"recovery_codes"`
			Ended int      `json:"ended_sessions"`
		}
		c.post("/account/totp/confirm", map[string]any{"code": codeAt(seed, time.Now()), "saved": true}).want(200, "").json(&done)
		if len(done.Codes) != 10 || done.Ended != live-1 {
			t.Fatalf("codes = %d, ended = %d (live before = %d)", len(done.Codes), done.Ended, live)
		}
		other.get("/me").want(401, "session_expired")
		stale := f.client()
		stale.jar[session.CookieSession] = &old
		stale.get("/me").want(401, "session_expired")
		m := c.me()
		if !m.Security.TOTPEnabled || m.Security.RecoveryCodesLeft != 10 {
			t.Fatalf("me.security = %+v", m.Security)
		}
		// Enrolling ended the reauth window the password earned (tenant-r10-1): a new reauth, with the code, comes first.
		f.ck.add(time.Minute) // the sensitive class of the steps above
		c.reauthTOTP(pwA, seed)
		c.post("/account/totp/setup", nil).want(409, "totp_already_enabled")
		// Recovery codes are stored as hashes only.
		for _, code := range done.Codes {
			if f.count(`SELECT count(*) FROM ctrlz.recovery_codes WHERE code_hash = convert_to($1, 'UTF8')`, code) != 0 {
				t.Fatal("a recovery code is stored in clear")
			}
		}
		recoveryCodes = done.Codes
	})

	t.Run("login needs the second factor", func(t *testing.T) {
		f.clearThrottle()
		f.freeStep(A.Tenant)
		cl := f.client()
		ticket := cl.mfaLogin(A.Phone, pwA)
		// Wrong code: the ticket survives.
		cl.post("/auth/login/totp", map[string]any{"ticket": ticket, "totp_code": "000000"}).want(401, "totp_invalid")
		cl.post("/auth/login/totp", map[string]any{"ticket": ticket}).want(401, "totp_invalid")
		r := cl.post("/auth/login/totp", map[string]any{"ticket": ticket, "totp_code": codeAt(seed, time.Now())}).want(200, "")
		var res loginBody
		r.json(&res)
		if res.Status != "authenticated" || r.cookie(session.CookieSession) == nil {
			t.Fatalf("totp login = %+v", res)
		}
		if f.count(`SELECT count(*) FROM ctrlz.sessions WHERE user_id = $1 AND auth_method = 'password' AND revoked_at IS NULL`, A.User) < 1 {
			t.Fatal("the session keeps the first factor as its method")
		}
		// The ticket is single use.
		cl.post("/auth/login/totp", map[string]any{"ticket": ticket, "totp_code": codeAt(seed, time.Now().Add(30*time.Second))}).want(401, "ticket_invalid")
		cl.post("/auth/login/totp", map[string]any{"ticket": "junk"}).want(401, "ticket_invalid")
	})

	t.Run("the same code twice is totp_step_reused, on every route", func(t *testing.T) {
		f.clearThrottle()
		f.freeStep(A.Tenant)
		code := codeAt(seed, time.Now())

		cl := f.client()
		t1 := cl.mfaLogin(A.Phone, pwA)
		cl.post("/auth/login/totp", map[string]any{"ticket": t1, "totp_code": code}).want(200, "")
		t2 := f.client().mfaLogin(A.Phone, pwA)
		f.client().post("/auth/login/totp", map[string]any{"ticket": t2, "totp_code": code}).want(401, "totp_step_reused")

		// Reauth with the spent code.
		cl.post("/auth/reauth", map[string]any{"password": pwA, "totp_code": code}).want(401, "totp_step_reused")
		// A code of an earlier step than the last spent one.
		cl.post("/auth/reauth", map[string]any{"password": pwA, "totp_code": codeAt(seed, time.Now().Add(-30*time.Second))}).want(401, "totp_step_reused") // clock-safe: the step before now is spent on either side of a boundary
		// The next step is fresh.
		cl.post("/auth/reauth", map[string]any{"password": pwA, "totp_code": codeAt(seed, time.Now().Add(30*time.Second))}).want(204, "")
		// The reauth just proved the code, so the password change inside its window
		// asks for none: a second code protected nothing (disabling TOTP needs the
		// same window only) and cost a wait for the next step (4.4, review round 1).
		const newPw = "Cobalt-meadow-Falcon-4417"
		cl.post("/account/password", map[string]any{"new_password": newPw}).want(204, "")
		f.setPassword(A.Tenant, A.User, pwA) // back to the fixture's password
	})

	t.Run("reauth wants the password and a code", func(t *testing.T) {
		f.clearThrottle()
		f.freeStep(A.Tenant)
		cl := f.client()
		cl.mfaLoginComplete(A.Phone, pwA, codeAt(seed, time.Now()))
		cl.post("/auth/reauth", map[string]any{"password": pwA}).want(401, "totp_invalid")
		cl.post("/auth/reauth", map[string]any{"totp_code": codeAt(seed, time.Now().Add(30*time.Second))}).want(401, "invalid_credentials")
		cl.post("/auth/reauth", map[string]any{"password": pwA, "totp_code": codeAt(seed, time.Now().Add(30*time.Second))}).want(204, "")
	})

	t.Run("recovery codes", func(t *testing.T) {
		f.clearThrottle()
		cl := f.client()
		tk := cl.mfaLogin(A.Phone, pwA)
		cl.post("/auth/login/totp", map[string]any{"ticket": tk, "recovery_code": "AAAA-AAAA-AAAA-AAAA"}).want(401, "totp_invalid")
		cl.post("/auth/login/totp", map[string]any{"ticket": tk, "recovery_code": "not a code"}).want(401, "totp_invalid")
		// Lower case, spaces and no hyphens are accepted.
		typed := strings.ToLower(strings.ReplaceAll(recoveryCodes[0], "-", " "))
		cl.post("/auth/login/totp", map[string]any{"ticket": tk, "recovery_code": typed}).want(200, "")
		if m := cl.me(); m.Security.RecoveryCodesLeft != 9 {
			t.Fatalf("codes left = %d, want 9", m.Security.RecoveryCodesLeft)
		}
		// Used once.
		tk = f.client().mfaLogin(A.Phone, pwA)
		f.client().post("/auth/login/totp", map[string]any{"ticket": tk, "recovery_code": recoveryCodes[0]}).want(401, "totp_invalid")
		if f.count(`SELECT count(*) FROM ctrlz.tenant_audit_log WHERE action = 'recovery.used'`) != 1 {
			t.Fatal("no recovery.used row")
		}

		// Regenerating replaces all of them and rotates the session.
		f.freeStep(A.Tenant)
		cl.reauthTOTP(pwA, seed)
		// The enable that made the first set told nobody: the notice is for a regeneration (tenant-r18-14).
		if n := f.count(`SELECT count(*) FROM ctrlz.notifications WHERE kind = 'recovery_codes_regenerated'`); n != 0 {
			t.Fatalf("%d recovery_codes_regenerated notices before any regeneration, want 0", n)
		}
		var out struct {
			Codes []string `json:"recovery_codes"`
		}
		cl.post("/account/totp/recovery-codes", nil).want(200, "").json(&out)
		if len(out.Codes) != 10 || out.Codes[0] == recoveryCodes[0] {
			t.Fatalf("regenerated = %v", out.Codes)
		}
		tk = f.client().mfaLogin(A.Phone, pwA)
		f.client().post("/auth/login/totp", map[string]any{"ticket": tk, "recovery_code": recoveryCodes[1]}).want(401, "totp_invalid")
		// The owner is told that new codes exist (tenant-r18-5), in the tenant that made them only.
		if n := f.count(`SELECT count(*) FROM ctrlz.notifications WHERE tenant_id = $1 AND kind = 'recovery_codes_regenerated'`, A.Tenant); n != 1 {
			t.Fatalf("%d recovery_codes_regenerated notices, want 1", n)
		}
		if n := f.count(`SELECT count(*) FROM ctrlz.notifications WHERE tenant_id <> $1 AND kind = 'recovery_codes_regenerated'`, A.Tenant); n != 0 {
			t.Fatalf("another tenant has %d recovery_codes_regenerated notices", n)
		}
		recoveryCodes = out.Codes
	})

	t.Run("brute force is stopped after five tries", func(t *testing.T) {
		f.clearThrottle()
		cl := f.client()
		tk := cl.mfaLogin(A.Phone, pwA)
		for i := 0; i < 5; i++ {
			cl.post("/auth/login/totp", map[string]any{"ticket": tk, "totp_code": "000000"}).want(401, "totp_invalid")
		}
		// The ticket itself allows five reads; the sixth is a dead ticket.
		cl.post("/auth/login/totp", map[string]any{"ticket": tk, "totp_code": "000000"}).want(401, "ticket_invalid")
		// A new ticket meets the totp_user throttle.
		tk = cl.mfaLogin(A.Phone, pwA)
		r := cl.post("/auth/login/totp", map[string]any{"ticket": tk, "totp_code": codeAt(seed, time.Now())}).want(429, "too_many_attempts")
		if r.H.Get("Retry-After") == "" {
			t.Fatal("no Retry-After")
		}
	})

	t.Run("disable", func(t *testing.T) {
		f.clearThrottle()
		f.freeStep(A.Tenant)
		cl := f.client()
		cl.mfaLoginComplete(A.Phone, pwA, codeAt(seed, time.Now()))
		other := f.client()
		other.mustLoginTOTP(A.Phone, pwA, seed, f)
		cl.post("/account/totp/disable", nil).want(403, "reauth_required")
		cl.reauthTOTP(pwA, seed)
		var out struct {
			Ended int `json:"ended_sessions"`
		}
		cl.post("/account/totp/disable", nil).want(200, "").json(&out)
		if out.Ended < 1 {
			t.Fatalf("ended = %d", out.Ended)
		}
		other.get("/me").want(401, "session_expired")
		if m := cl.me(); m.Security.TOTPEnabled || m.Security.RecoveryCodesLeft != 0 {
			t.Fatalf("security after disable = %+v", m.Security)
		}
		if f.count(`SELECT count(*) FROM ctrlz.users WHERE id = $1 AND totp_secret_ct IS NULL AND totp_last_step IS NULL`, A.User) != 1 {
			t.Fatal("the seed must be gone")
		}
		cl.post("/account/totp/disable", nil).want(409, "totp_not_enabled")
		cl.post("/account/totp/recovery-codes", nil).want(409, "totp_not_enabled")
		f.client().mustLogin(A.Phone, pwA) // password alone logs in again
	})

	f.assertQuiet(append(recoveryCodes, setup.Secret)...)
}

// mfaLoginComplete signs in with a password and a code.
func (c *client) mfaLoginComplete(phone, pw, code string) {
	c.f.t.Helper()
	tk := c.mfaLogin(phone, pw)
	c.post("/auth/login/totp", map[string]any{"ticket": tk, "totp_code": code}).want(200, "")
}

func (c *client) mustLoginTOTP(phone, pw string, seed secret.Bytes, f *frig) {
	c.f.t.Helper()
	f.freeStep(f.env.A.Tenant)
	c.mfaLoginComplete(phone, pw, codeAt(seed, time.Now()))
}

// reauthTOTP opens a reauth window for a user with a password and TOTP, using a
// code of the next step so it cannot collide with a step a test already spent.
func (c *client) reauthTOTP(pw string, seed secret.Bytes) {
	c.f.t.Helper()
	c.f.freeStep(c.f.env.A.Tenant)
	c.post("/auth/reauth", map[string]any{"password": pw, "totp_code": codeAt(seed, time.Now())}).want(204, "")
}
