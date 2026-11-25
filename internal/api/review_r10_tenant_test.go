package api

import (
	"encoding/base32"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
)

// TestAReauthWindowEarnedBeforeTheAuthenticatorDoesNotSurviveEnrolling is tenant-r10-1. The
// window proved the password only; after the enrolment every route that says "the window
// already proved the second factor" (TOTP disable, the password change) must ask again, for
// the holder of the cookie the confirm hands out.
func TestAReauthWindowEarnedBeforeTheAuthenticatorDoesNotSurviveEnrolling(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A := f.env.A
	c := f.client()
	c.mustLogin(A.Phone, pwA)
	c.reauthPassword(pwA).want(204, "")

	var setup struct {
		Secret string `json:"secret"`
	}
	c.post("/account/totp/setup", nil).want(200, "").json(&setup)
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(setup.Secret)
	if err != nil {
		t.Fatal(err)
	}
	seed := secret.NewBytes(raw)
	c.post("/account/totp/confirm", map[string]any{"code": codeAt(seed, time.Now()), "saved": true}).want(200, "")

	// The new cookie is the one an attacker would hold. Neither route may take it without a code.
	c.post("/account/totp/disable", nil).want(403, "reauth_required")
	c.post("/account/password", map[string]any{"new_password": "an-entirely-different-passphrase-7"}).want(403, "reauth_required")
	if f.count(`SELECT count(*) FROM ctrlz.users WHERE id = $1 AND totp_enabled_at IS NOT NULL`, A.User) != 1 {
		t.Fatal("TOTP was switched off with no code")
	}

	// A reauth that carries the code opens the window again and the routes serve.
	c.reauthTOTP(pwA, seed)
	c.post("/account/totp/disable", nil).want(200, "")
}

// TestNoStrangerWhoHoldsOneProofCanKeepTheOwnersRecoveryCodeRefused is tenant-r10-2, the recovery half of
// the round 9 test (the stranger of that test never sent a recovery code, so it could not fail). The recovery
// window was one scope keyed on the account, so a password holder or a SIM holder spent five tries every fifteen
// minutes and the owner who had lost his authenticator was refused on every door. Each stranger now fills the
// recovery window of the one door he holds, shown full (429), and the owner's recovery code serves on every door the
// stranger lacks: the others of password ticket, SMS ticket and known device.
func TestNoStrangerWhoHoldsOneProofCanKeepTheOwnersRecoveryCodeRefused(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A := f.env.A
	seed := f.enableTOTP(A.Tenant, A.User)
	codes := f.recoveryCodesFor(A.Tenant, A.User)
	const junk = "AAAA-AAAA-AAAA-AAAA"
	const newPw = "Cobalt-meadow-Falcon-4417"

	device := f.client()
	device.mustLoginTOTP(A.Phone, pwA, seed, f)
	f.clearThrottle()

	passwordTicket := func(c *client) string { return c.mfaLogin(A.Phone, pwA) }
	otpTicket := func(c *client) string {
		var iss issued
		c.requestOTP(A.Phone, "login", nil).want(202, "").json(&iss)
		var res loginBody
		c.post("/auth/login/otp", map[string]any{"phone": A.Phone, "challenge_id": iss.ID, "code": f.codes.Last()}).want(200, "").json(&res)
		if res.Status != "mfa_required" || res.Ticket == "" {
			t.Fatalf("an OTP login of an account with an authenticator = %+v, want mfa_required", res)
		}
		return res.Ticket
	}
	markerTicket := func(*client) string { return device.mfaLogin(A.Phone, pwA) }
	totpJunk := func(c *client, tk, code string) *resp {
		return c.post("/auth/login/totp", map[string]any{"ticket": tk, "recovery_code": code})
	}
	resetTicket := func(c *client) string { return c.verifyReset(A.Phone).Ticket }
	resetJunk := func(c *client, tk, code string) *resp {
		return c.post("/auth/password/reset/complete", map[string]any{"ticket": tk, "new_password": newPw, "recovery_code": code})
	}
	// fill sends junk recovery codes, three to a ticket, until a try is refused with 429: that is the window shown full.
	fill := func(name string, ticket func(*client) string, send func(*client, string, string) *resp) {
		t.Helper()
		sent := 0
		for round := 0; round < 4; round++ {
			c := f.client()
			if name == "the known device" {
				c = device
			}
			tk := ticket(c)
			for i := 0; i < 3; i++ {
				r := send(c, tk, junk)
				if r.Code == 429 {
					if sent < 5 {
						t.Fatalf("%s: refused after %d tries, want 5", name, sent)
					}
					return
				}
				sent++
			}
		}
		t.Fatalf("%s: %d junk recovery codes and the window never filled", name, sent)
	}
	// serves signs in with a REAL recovery code on a door, and the answer must be 200.
	next := 0
	serves := func(name string, ticket func(*client) string) {
		t.Helper()
		c := f.client()
		if name == "the known device" {
			c = device
		}
		tk := ticket(c)
		r := totpJunk(c, tk, codes[next])
		next++
		if r.Code != 200 {
			t.Fatalf("%s: the owner's recovery code got %d %s while a stranger holding another door filled his window", name, r.Code, r.Body)
		}
	}

	t.Run("a password holder", func(t *testing.T) {
		fill("a password ticket", passwordTicket, totpJunk)
		serves("an SMS ticket", otpTicket)
		serves("the known device", markerTicket)
	})
	f.clearThrottle()
	t.Run("a SIM holder", func(t *testing.T) {
		fill("a reset ticket", resetTicket, resetJunk)
		serves("a password ticket", passwordTicket)
		serves("the known device", markerTicket)
	})
	f.clearThrottle()
	t.Run("another tenant is untouched", func(t *testing.T) {
		B := f.env.B
		seedB := f.enableTOTP(B.Tenant, B.User)
		codesB := f.recoveryCodesFor(B.Tenant, B.User)
		_ = seedB
		fill("a password ticket", passwordTicket, totpJunk)
		c := f.client()
		tk := c.mfaLogin(B.Phone, pwB)
		if r := totpJunk(c, tk, codesB[0]); r.Code != 200 {
			t.Fatalf("tenant B's recovery code got %d %s while tenant A's window was full", r.Code, r.Body)
		}
	})
}
