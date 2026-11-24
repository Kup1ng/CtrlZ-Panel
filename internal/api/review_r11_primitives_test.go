package api

import "testing"

// TestAWindowEarnedBySMSDoesNotSurviveTheFirstPassword is primitives-r11-4. POST /account/password is a
// password change for a user who has a password and the FIRST password of an OTP-only one, and the second
// raises what a reauth asks for from an SMS code to the password (3.5: SMS never satisfies reauth when a
// password exists). The event used to keep the window by its name alone. The holder of the rotated cookie is the
// person who just proved the SMS code, so the harm is small, and the rule is the one of round 10: a window
// proves what the account asked for when it was earned. The control is the user who already had a password,
// whose change keeps the window (a new password is no higher bar).
func TestAWindowEarnedBySMSDoesNotSurviveTheFirstPassword(t *testing.T) {
	f := newFrig(t, frigOpts{})
	B := f.env.B
	const strong = "Cobalt-meadow-Falcon-4417"

	t.Run("an OTP-only user sets a first password", func(t *testing.T) {
		f.env.Exec(t, `UPDATE ctrlz.users SET password_hash = NULL WHERE tenant_id = $1`, B.Tenant)
		defer f.setPassword(B.Tenant, B.User, pwB)
		f.clearOTP()
		f.clearThrottle()
		c := f.client()
		var iss struct {
			ID string `json:"challenge_id"`
		}
		c.post("/auth/otp/request", map[string]any{"phone": B.Phone, "purpose": "login"}).want(202, "").json(&iss)
		c.post("/auth/login/otp", map[string]any{"phone": B.Phone, "challenge_id": iss.ID, "code": f.codes.Last()}).want(200, "")
		f.clearOTP()
		c.post("/auth/reauth/otp/request", nil).want(202, "")
		var id string
		f.env.Scan(t, `SELECT id::text FROM ctrlz.otp_challenges WHERE phone_e164 = $1`, []any{B.Phone}, &id)
		c.post("/auth/reauth", map[string]any{"otp_challenge_id": id, "otp_code": f.codes.Last()}).want(204, "")
		// The window is open: a reauth route answers.
		c.post("/account/totp/setup", nil).want(200, "")
		// The first password, inside the window the SMS opened.
		c.post("/account/password", map[string]any{"new_password": strong}).want(204, "")
		// The account has a password now, and an SMS code is no proof of it: the window is gone.
		c.post("/account/totp/setup", nil).want(403, "reauth_required")
		// The way back is the password itself.
		c.reauthPassword(strong).want(204, "")
		c.post("/account/totp/setup", nil).want(200, "")
	})

	t.Run("a user with a password changes it and keeps the window", func(t *testing.T) {
		f.clearThrottle()
		c := f.client()
		c.mustLogin(B.Phone, pwB)
		c.reauthPassword(pwB).want(204, "")
		c.post("/account/password", map[string]any{"new_password": strong}).want(204, "")
		defer f.setPassword(B.Tenant, B.User, pwB)
		c.post("/account/totp/setup", nil).want(200, "")
	})
}
