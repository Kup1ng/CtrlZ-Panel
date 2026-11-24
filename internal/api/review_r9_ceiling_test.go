package api

import (
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/budget"
)

// Tests of the P1 auth review, round 9, area "crypto primitives, secrets and sessions".

// TestNoStrangerWhoHoldsLessThanTheWholeLoginCanLockTheOwnersSecondFactor is primitives-r9-4, the abuse test the
// finding asked for. The daily ceiling of the tenant's second factor was one count keyed on the account, so whoever
// could charge it at all filled it: a holder of nothing but an SMS code (a SIM swap, a reset ticket, an OTP login of
// an account with an authenticator) needed about twenty requests to refuse the owner's TOTP login, recovery codes
// included, for a day, and a success needed a check the ceiling refused. The ceiling is now split by what proved the
// first step (password ticket, SMS ticket, device marker that holds) and a recovery code has a scope of its own with
// no ceiling.
//
// Both strangers fill the ceiling of the scope they can reach, past the registry's limit, and the full ceiling is
// shown to refuse them (a test that never saw it full proves nothing). Then the owner's own doors must all serve:
// the password ticket against the stranger who held only the SMS, the recovery code against both, the known device's
// marker against both, and a success on one door ends the run on the others (there is no console command for a tenant
// account, so the owner's own success is the unlock).
func TestNoStrangerWhoHoldsLessThanTheWholeLoginCanLockTheOwnersSecondFactor(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A := f.env.A
	seed := f.enableTOTP(A.Tenant, A.User)
	codes := f.recoveryCodesFor(A.Tenant, A.User)
	const wrong = "000000"
	const newPw = "Cobalt-meadow-Falcon-4417"
	sms, _ := budget.FindScope("totp_sms")
	pw, _ := budget.FindScope("totp_user")
	if sms.CeilingMax < 1 || pw.CeilingMax < 1 {
		t.Fatal("the scopes of the password ticket and of the SMS ticket declare no ceiling")
	}

	// The owner's known device: a full sign-in with the second factor leaves the marker in its jar.
	device := f.client()
	device.mustLoginTOTP(A.Phone, pwA, seed, f)
	f.clearThrottle()

	// The ways to get a ticket, and to send a wrong code with it.
	resetTicket := func(c *client) string { return c.verifyReset(A.Phone).Ticket }
	resetWrong := func(c *client, tk string) *resp {
		return c.post("/auth/password/reset/complete", map[string]any{"ticket": tk, "new_password": newPw, "totp_code": wrong})
	}
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
	passwordTicket := func(c *client) string { return c.mfaLogin(A.Phone, pwA) }
	totpWrong := func(c *client, tk string) *resp {
		return c.post("/auth/login/totp", map[string]any{"ticket": tk, "totp_code": wrong})
	}
	// fill sends wrong codes, with as many tickets as it takes, until the scope has taken `want` of them. The
	// windows of the database move back an hour between rounds (the scopes of a login count on the database
	// clock), so the 15 minute window is never what stops the loop, and the ceiling of a day is.
	fill := func(want int, ticket func(*client) string, send func(*client, string) *resp) {
		t.Helper()
		charged := 0
		for round := 0; charged < want; round++ {
			if round > 4*want {
				t.Fatalf("%d wrong codes counted in %d rounds: the scope never filled", charged, round)
			}
			c := f.client()
			tk := ticket(c)
			for i := 0; i < 3 && charged < want; i++ {
				r := send(c, tk)
				if r.Code == 429 {
					break
				}
				charged++
			}
			f.env.Exec(t, `UPDATE ctrlz.auth_throttle SET window_start = window_start - interval '61 minutes'`)
		}
	}
	refused := func(what string, ticket func(*client) string, send func(*client, string) *resp) {
		t.Helper()
		c := f.client()
		tk := ticket(c)
		if r := send(c, tk); r.Code != 429 {
			t.Fatalf("%s: %d %s after the ceiling was filled, want 429: the ceiling is not what the test thinks it is", what, r.Code, r.Body)
		}
	}

	// ---- The stranger who holds only an SMS code: reset tickets and OTP logins. ----
	fill(sms.CeilingMax, resetTicket, resetWrong)
	refused("a reset ticket", resetTicket, resetWrong)
	// An OTP login's ticket is the SMS scope too: the same ceiling.
	refused("an OTP login's ticket", otpTicket, totpWrong)

	// The owner signs in with the password and the code: not refused, though the SMS ceiling is full.
	owner := f.client()
	owner.mustLoginTOTP(A.Phone, pwA, seed, f)
	// A success ends the run of guesses for the account: the SMS door serves again.
	f.env.Exec(t, `UPDATE ctrlz.auth_throttle SET window_start = window_start - interval '61 minutes'`) // the short windows
	if r := resetWrong(f.client(), resetTicket(f.client())); r.Code == 429 {
		t.Fatalf("after the owner's own right code the SMS door still refuses: %d %s", r.Code, r.Body)
	}

	// ---- Both doors a stranger can reach are full: the password ticket (a phished password, no authenticator) ----
	// ---- and the SMS ticket. The owner's other doors must still serve. ----
	f.clearThrottle()
	fill(pw.CeilingMax, passwordTicket, totpWrong)
	fill(sms.CeilingMax, resetTicket, resetWrong)
	refused("a password ticket", passwordTicket, totpWrong)
	refused("a reset ticket", resetTicket, resetWrong)
	f.env.Exec(t, `UPDATE ctrlz.auth_throttle SET window_start = window_start - interval '61 minutes'`)

	// The owner's escape route first: a recovery code works while the ceilings of the code are full, because a
	// recovery code has a scope of its own with no ceiling.
	rc := f.client()
	tk := rc.mfaLogin(A.Phone, pwA)
	rc.post("/auth/login/totp", map[string]any{"ticket": tk, "recovery_code": codes[0]}).want(200, "")
	// Its success ended the run on the account's other doors (the owner's own way out, since a console unlock for a
	// tenant account does not exist): the SMS door serves again.
	if r := resetWrong(f.client(), resetTicket(f.client())); r.Code == 429 {
		t.Fatalf("after the owner's recovery code the SMS door still refuses: %d %s", r.Code, r.Body)
	}

	// Both doors full again, and now the known device: its marker holds for the account, so its second factor is
	// counted on a bucket of its own, which neither stranger can reach.
	f.clearThrottle()
	fill(pw.CeilingMax, passwordTicket, totpWrong)
	fill(sms.CeilingMax, resetTicket, resetWrong)
	refused("a password ticket", passwordTicket, totpWrong)
	refused("a reset ticket", resetTicket, resetWrong)
	f.env.Exec(t, `UPDATE ctrlz.auth_throttle SET window_start = window_start - interval '61 minutes'`)
	f.freeStep(A.Tenant)
	device.mfaLoginComplete(A.Phone, pwA, codeAt(seed, time.Now()))

	// Another tenant's account is untouched by all of it (two tenants: B has its own counters and its own ceilings).
	B := f.env.B
	seedB := f.enableTOTP(B.Tenant, B.User)
	f.freeStep(B.Tenant)
	f.client().mfaLoginComplete(B.Phone, pwB, codeAt(seedB, time.Now()))

	// The marker's success ended the run on the other doors too (it carries the account for that reason).
	f.env.Exec(t, `UPDATE ctrlz.auth_throttle SET window_start = window_start - interval '61 minutes'`)
	f.client().mustLoginTOTP(A.Phone, pwA, seed, f)
	if r := resetWrong(f.client(), resetTicket(f.client())); r.Code == 429 {
		t.Fatalf("after the known device's right code the SMS door still refuses: %d %s", r.Code, r.Body)
	}
}
