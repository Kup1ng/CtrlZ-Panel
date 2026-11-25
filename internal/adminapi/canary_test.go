package adminapi

import (
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/totp"
	"github.com/Kup1ng/CtrlZ-Panel/internal/authtest"
)

// TestAdminCanaries is the admin half of the canary test of spec 18.4 (the
// tenant half is internal/api/canary_test.go, which uses the same sinks): the
// admin password, the TOTP seed and codes, the one-time password that
// POST /users returns, the one the re-issue route returns (the generator is the
// test's, so both are known), an invite code, an SMS API key and a Melipayamak
// password. None of them may be in the process log, in any sink table or in the
// Postgres server log. The bootstrap and reset-password output have their own
// test in internal/admincli (TestCLIOutputCanaries) and in the Compose smoke.
func TestAdminCanaries(t *testing.T) {
	r := newRig(t)
	b, seed := r.admin(t)
	const apiKey = "CANARY-ADMIN-IR-KEY-5c19"
	const meliPW = "CANARY-ADMIN-MELI-PW-8e03"

	canaries := []string{adminPW, totp.Base32(seed).Reveal()}

	// A wrong password and a wrong TOTP code on the login route.
	b2 := r.browser()
	b2.login("Canary-Wrong-Thistle-11235-Basalt", "000000").want(401, "invalid_credentials")
	canaries = append(canaries, "Canary-Wrong-Thistle-11235-Basalt")

	// A fresh TOTP code and a password change with it.
	b.fresh(seed)
	code := totpNow(seed)
	canaries = append(canaries, code)
	r.freeStep(t)
	b.post("/me/password", map[string]any{"current_password": adminPW, "new_password": adminNewPW, "totp_code": totpNow(seed)}).want(204, "")
	canaries = append(canaries, adminNewPW)
	for _, c := range b.jar {
		canaries = append(canaries, c.Value)
	}

	// POST /users and the re-issue: both one-time passwords come from the test's generator.
	u := r.newOTUser(t, b)
	_, got := r.reissue(t, b, u)
	canaries = append(canaries, u.Password, got.Password)
	canaries = append(canaries, r.once.issued()...)

	// An invite code and the phone of the invitee.
	var inv struct {
		Code string `json:"code"`
	}
	b.post("/invites", map[string]any{"phone": "09125559191", "send_sms": false}).want(201, "").json(&inv)
	canaries = append(canaries, inv.Code, "+989125559191")

	// SMS credentials.
	b.put("/sms/gateways/sms_ir", map[string]any{"credentials": map[string]string{"api_key": apiKey}, "cost_per_message": "10"}).want(200, "")
	b.put("/sms/gateways/melipayamak", map[string]any{"credentials": map[string]string{"username": "canary-admin-user", "password": meliPW}}).want(200, "")
	canaries = append(canaries, apiKey, meliPW)

	authtest.AssertTextClean(t, "the process log", r.logs.String(), canaries...)
	r.env.AssertSinksClean(t, canaries...)
	r.env.AssertServerLogClean(t, canaries...)
	if len(r.once.issued()) < 2 {
		t.Fatal("the one-time generator was not used")
	}
}
