package api

import (
	"encoding/base32"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/authtest"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
)

// Canary values of spec 18.4. Each is a string no code of ours would print, so
// finding one in a sink is proof that something wrote a secret there. The
// values stand for the secrets of the flows below; the admin ones (bootstrap
// password, reset-password output, the one-time passwords of POST /users and of
// the re-issue, the SMS API key) have their own canary tests next to the code
// that handles them, on the same sinks and the same helpers:
//
//	internal/adminapi   TestReissueCanary, TestAdminCanaries
//	internal/admincli   TestCLIOutputCanaries
//	internal/worker/smssend   TestMain's rig (assertLogsClean) and the dead-host runs
//	                    of the two drivers (smsir, melipayamak)
const (
	canaryLoginPW   = "Canary-Login-Zebra-31337-Quartz"
	canaryChangedPW = "Canary-Changed-Lichen-48151-Ember"
	canaryResetPW   = "Canary-Reset-Walnut-62342-Harbor"
	canaryRegPW     = "Canary-Signup-Pewter-90210-Maple"
	canaryWrongPW   = "Canary-Wrong-Thistle-11235-Basalt"
	canaryPhoneE164 = "+989125559090"
	canaryPhoneNat  = "09125559090"
)

// TestCanaries drives the flows that handle a secret, with fixed canaries for
// the password, its hash, every OTP code, the TOTP seed and codes, recovery
// codes, session, refresh, device and ticket values, an invite code and a phone
// number. Then it looks for every one of them in the process log, in each sink
// table of 18.4 and in the Postgres server log.
func TestCanaries(t *testing.T) {
	f := newFrig(t, frigOpts{})
	f.codes.start = 837200 // six digits that no timestamp or pid is likely to contain
	A := f.env.A
	var canaries []string
	add := func(vals ...string) {
		for _, v := range vals {
			if v != "" {
				canaries = append(canaries, v)
			}
		}
	}

	// Password login with Remember me: session, refresh and device cookies.
	f.setPassword(A.Tenant, A.User, canaryLoginPW)
	c := f.client()
	c.loginPassword(A.Phone, canaryLoginPW, true).want(200, "")
	add(canaryLoginPW)
	add(c.cookieValues()...)
	// A wrong password and a failed login for an unknown phone.
	f.client().loginPassword(A.Phone, canaryWrongPW, false).want(401, "invalid_credentials")
	f.client().loginPassword("09127776655", canaryWrongPW, false).want(401, "invalid_credentials")
	add(canaryWrongPW)

	// Password change, with reauth.
	c.reauthPassword(canaryLoginPW).want(204, "")
	c.post("/account/password", map[string]any{"new_password": canaryChangedPW}).want(204, "")
	add(canaryChangedPW)
	// A weak password refused with a reason: the reason must not echo it.
	c.reauthPassword(canaryChangedPW).want(204, "")
	c.post("/account/password", map[string]any{"new_password": "password12345"}).want(422, "password_weak")

	// TOTP: setup, confirm, an mfa ticket, the second factor, a recovery code.
	var setup struct {
		Secret string `json:"secret"`
		URI    string `json:"otpauth_uri"`
	}
	c.post("/account/totp/setup", nil).want(200, "").json(&setup)
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(setup.Secret)
	if err != nil {
		t.Fatal(err)
	}
	seed := secret.NewBytes(raw)
	add(setup.Secret)
	var done struct {
		Codes []string `json:"recovery_codes"`
	}
	code1 := codeAt(seed, time.Now())
	c.post("/account/totp/confirm", map[string]any{"code": code1, "saved": true}).want(200, "").json(&done)
	if len(done.Codes) != 10 {
		t.Fatalf("recovery codes: %d", len(done.Codes))
	}
	add(code1)
	add(done.Codes...)
	f.clearThrottle()
	f.freeStep(A.Tenant)
	cl := f.client()
	ticket := cl.mfaLogin(A.Phone, canaryChangedPW)
	add(ticket)
	code2 := codeAt(seed, time.Now().Add(30*time.Second))
	cl.post("/auth/login/totp", map[string]any{"ticket": ticket, "totp_code": code2}).want(200, "")
	add(code2)
	add(cl.cookieValues()...)
	// A recovery code login, and a replayed recovery code.
	f.clearThrottle()
	tk := f.client().mfaLogin(A.Phone, canaryChangedPW)
	add(tk)
	rc := f.client()
	rc.post("/auth/login/totp", map[string]any{"ticket": tk, "recovery_code": done.Codes[0]}).want(200, "")
	add(rc.cookieValues()...)
	tk = f.client().mfaLogin(A.Phone, canaryChangedPW)
	f.client().post("/auth/login/totp", map[string]any{"ticket": tk, "recovery_code": done.Codes[0]}).want(401, "totp_invalid")
	add(tk)

	// OTP login and Forgot Password (the second factor is TOTP, so the reset
	// ticket needs a code, which is itself a canary).
	f.env.Exec(t, `UPDATE ctrlz.users SET totp_enabled_at = NULL, totp_secret_ct = NULL WHERE id = $1`, A.User)
	oc := f.client()
	var iss issued
	oc.requestOTP(A.Phone, "login", map[string]any{"locale": "fa"}).want(202, "").json(&iss)
	oc.post("/auth/login/otp", map[string]any{"phone": A.Phone, "challenge_id": iss.ID, "code": f.codes.Last(), "remember_me": true}).want(200, "")
	add(oc.cookieValues()...)
	rs := f.client()
	v := rs.verifyReset(A.Phone)
	add(v.Ticket)
	rs.post("/auth/password/reset/complete", map[string]any{"ticket": v.Ticket, "new_password": canaryResetPW}).want(204, "")
	add(canaryResetPW)

	// Signup by invite: an invite code, a phone number of a stranger, a new
	// password, and the unique violations of a taken phone.
	code := f.plantInvite(canaryPhoneE164, time.Hour, false)
	add(code)
	ic := f.client()
	var ii issued
	ic.requestOTP(canaryPhoneNat, "invite", map[string]any{"invite_token": code, "locale": "fa"}).want(202, "").json(&ii)
	ic.post("/auth/register", map[string]any{"invite_token": code, "challenge_id": ii.ID, "code": f.codes.Last(), "password": canaryRegPW}).want(201, "")
	add(canaryRegPW)
	add(ic.cookieValues()...)
	add(canaryPhoneE164, canaryPhoneNat)
	// The same invite again, and a login by the new account.
	f.client().post("/auth/invites/lookup", map[string]any{"token": code}).want(404, "invite_invalid")
	f.clearThrottle()
	f.client().loginPassword(canaryPhoneNat, canaryRegPW, false).want(200, "")

	// Every OTP code that was made.
	f.codes.mu.Lock()
	otpCodes := append([]string(nil), f.codes.hist...)
	f.codes.mu.Unlock()
	if len(otpCodes) < 3 {
		t.Fatalf("only %d codes were issued; the flows did not run", len(otpCodes))
	}
	add(otpCodes...)

	// The password hash, as stored. It is read as the superuser; no role of the
	// services can.
	var hashes []string
	for _, u := range [][2]any{{A.Tenant, A.User}} {
		var h []byte
		f.env.Scan(t, `SELECT password_hash FROM ctrlz.users WHERE tenant_id = $1 AND id = $2`, []any{u[0], u[1]}, &h)
		if len(h) < 20 {
			t.Fatalf("the stored hash is %d bytes", len(h))
		}
		hashes = append(hashes, string(h))
	}
	add(hashes...)

	// Sink 1: the process log (slog). The API has no access log and no stderr
	// writer of its own; the server's error logger is the sanitised one of
	// httpx (TestErrorLogKeepsOnlyTheClass), so a panic text cannot carry a
	// request either (TestRecoverLogsTheTypeAndNothingOfTheRequest).
	authtest.AssertTextClean(t, "the process log", f.logs.String(), canaries...)

	// Sink 2: the tables of 18.4, and Sink 3: the Postgres server log, which the
	// test cluster runs with the settings of deploy/compose/postgres.
	f.env.AssertSinksClean(t, canaries...)
	f.env.AssertServerLogClean(t, canaries...)

	// A store.UserLogin printed with %+v shows the redaction marker, never the
	// hash (8.6).
	ul, found, err := f.st.Auth().UserByPhone(f.env.Ctx, canaryPhoneE164)
	if err != nil || !found {
		t.Fatalf("user lookup: %v %v", found, err)
	}
	var h []byte
	f.env.Scan(t, `SELECT password_hash FROM ctrlz.users WHERE phone_e164 = $1`, []any{canaryPhoneE164}, &h)
	for _, shown := range []string{fmt.Sprintf("%+v", ul), fmt.Sprintf("%v", ul), fmt.Sprintf("%#v", ul)} {
		if strings.Contains(shown, string(h)) || strings.Contains(shown, "$argon2") {
			t.Fatalf("a printed store.UserLogin holds the hash: %q", shown)
		}
	}
	// The sessions this test made are all in the jar values checked above; make
	// sure the checks had something to find.
	if len(canaries) < 40 {
		t.Fatalf("only %d canaries; a flow above did not run", len(canaries))
	}
}
