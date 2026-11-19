package api

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/invite"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/session"
)

// setMode changes registration_mode and waits out the 30 second public-config
// cache with the fake clock.
func (f *frig) setMode(mode string) {
	f.t.Helper()
	f.env.Exec(f.t, `UPDATE ctrlz.system_settings SET registration_mode = $1`, mode)
	f.ck.add(31 * time.Second)
}

// plantInvite inserts an invite and returns the code a person would type.
func (f *frig) plantInvite(phone string, ttl time.Duration, revoked bool) string {
	f.t.Helper()
	code, hash, err := invite.New()
	if err != nil {
		f.t.Fatal(err)
	}
	f.env.Exec(f.t, `INSERT INTO ctrlz.invites (token_hash, phone_e164, expires_at, revoked_at) VALUES ($1, $2, now() + make_interval(secs => $3),
		CASE WHEN $4::boolean THEN now() ELSE NULL END)`, hash, phone, ttl.Seconds(), revoked)
	return code.Reveal()
}

type issued struct {
	ID string `json:"challenge_id"`
}

func (c *client) requestOTP(phone, purpose string, extra map[string]any) *resp {
	c.f.clearOTP()
	body := map[string]any{"phone": phone, "purpose": purpose}
	for k, v := range extra {
		body[k] = v
	}
	return c.post("/auth/otp/request", body)
}

// TestRegistration covers 5.6, 11 and 18.2's registration row (T-095, T-112, T-331).
func TestRegistration(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A := f.env.A
	tenants := func() int { return f.count(`SELECT count(*) FROM ctrlz.tenants`) }

	t.Run("closed mode refuses self-signup", func(t *testing.T) {
		c := f.client()
		c.requestOTP("09125550001", "signup", nil).want(403, "registration_closed")
		c.post("/auth/register", map[string]any{"phone": "09125550001", "challenge_id": uuid.NewString(), "code": "123456"}).want(403, "registration_closed")
	})

	t.Run("open mode", func(t *testing.T) {
		f.setMode("open")
		before := tenants()
		c := f.client()

		// A weak password does not burn the code.
		var iss issued
		c.requestOTP("09125550001", "signup", nil).want(202, "").json(&iss)
		code := f.codes.Last()
		c.post("/auth/register", map[string]any{"phone": "09125550001", "challenge_id": iss.ID, "code": code, "password": "short"}).want(422, "password_weak")
		c.post("/auth/register", map[string]any{"phone": "09125550001", "challenge_id": iss.ID, "code": "000000", "password": pwA}).want(401, "otp_invalid")
		r := c.post("/auth/register", map[string]any{"phone": "09125550001", "challenge_id": iss.ID, "code": code, "password": "Marble-Island-Copper-6620", "locale": "en"}).want(201, "")
		if r.cookie(session.CookieSession) == nil {
			t.Fatal("registration must open a session")
		}
		m := c.me()
		if m.Tenant.Status != "active" || !m.User.HasPassword || m.User.Locale != "en" || m.Tenant.ID == A.Tenant {
			t.Fatalf("me = %+v", m)
		}
		if tenants() != before+1 {
			t.Fatal("no tenant was created")
		}
		if f.count(`SELECT count(*) FROM ctrlz.tenant_audit_log WHERE action = 'register' AND params->>'via' = 'open'`) != 1 {
			t.Fatal("no register row")
		}
		// The new account logs in with its password.
		f.client().loginPassword("+989125550001", "Marble-Island-Copper-6620", false).want(200, "")

		// An OTP-only account.
		c2 := f.client()
		c2.requestOTP("۰۹۱۲۵۵۵۰۰۰۲", "signup", nil).want(202, "").json(&iss) // Persian digits
		c2.post("/auth/register", map[string]any{"phone": "۰۹۱۲۵۵۵۰۰۰۲", "challenge_id": iss.ID, "code": f.codes.Last()}).want(201, "")
		if m := c2.me(); m.User.HasPassword {
			t.Fatal("no password was given")
		}
	})

	t.Run("a taken phone looks like a free one", func(t *testing.T) {
		before := tenants()
		c := f.client()
		var iss issued
		c.requestOTP(A.Phone, "signup", nil).want(202, "").json(&iss)
		// Whoever asked does not hold the SIM; even the code of this challenge is
		// useless against a taken number.
		c.post("/auth/register", map[string]any{"phone": A.Phone, "challenge_id": iss.ID, "code": f.codes.Last(), "password": pwA}).want(401, "otp_invalid")
		if tenants() != before {
			t.Fatal("a tenant was created for a taken phone")
		}
	})

	t.Run("a code of another purpose is refused", func(t *testing.T) {
		c := f.client()
		var iss issued
		c.requestOTP("09125550003", "login", nil).want(202, "").json(&iss)
		c.post("/auth/register", map[string]any{"phone": "09125550003", "challenge_id": iss.ID, "code": f.codes.Last()}).want(401, "otp_invalid")
	})

	t.Run("invites work in every mode", func(t *testing.T) {
		for _, mode := range []string{"closed", "invite"} {
			f.setMode(mode)
			phone := map[string]string{"closed": "+989125551001", "invite": "+989125551002"}[mode]
			code := f.plantInvite(phone, time.Hour, false)
			c := f.client()
			var info struct {
				Masked string `json:"phone_masked"`
			}
			c.post("/auth/invites/lookup", map[string]any{"token": code}).want(200, "").json(&info)
			if info.Masked == phone || info.Masked == "" {
				t.Fatalf("the lookup must mask the phone, got %q", info.Masked)
			}
			// The phone of the request is ignored: the invite's own phone is used.
			var iss issued
			c.requestOTP("09120000001", "invite", map[string]any{"invite_token": code, "locale": "fa"}).want(202, "").json(&iss)
			if f.count(`SELECT count(*) FROM ctrlz.otp_challenges WHERE phone_e164 = $1 AND purpose = 'invite'`, phone) != 1 {
				t.Fatal("the challenge must be for the invite's phone")
			}
			r := c.post("/auth/register", map[string]any{"invite_token": code, "challenge_id": iss.ID, "code": f.codes.Last(), "password": "Marble-Island-Copper-6620"}).want(201, "")
			if r.cookie(session.CookieSession) == nil || c.me().Tenant.ID == A.Tenant {
				t.Fatal("the invite did not create an account")
			}
			// Used up.
			f.client().post("/auth/invites/lookup", map[string]any{"token": code}).want(404, "invite_invalid")
			f.client().requestOTP(phone, "invite", map[string]any{"invite_token": code}).want(404, "invite_invalid")
		}
	})

	t.Run("a bad invite is one error", func(t *testing.T) {
		for name, tok := range map[string]string{
			"unknown":   "AAAAA-AAAAA-AAAAA-AAAAA",
			"malformed": "nope",
			"expired":   f.plantInvite("+989125552001", -time.Minute, false),
			"revoked":   f.plantInvite("+989125552002", time.Hour, true),
		} {
			r := f.client().post("/auth/invites/lookup", map[string]any{"token": tok}).want(404, "invite_invalid")
			if string(r.Body[:20]) != `{"code":"invite_inva` {
				t.Errorf("%s: body = %s", name, r.Body)
			}
		}
		f.setMode("open")
		// An invite cannot be accepted with the code of another challenge.
		code := f.plantInvite("+989125552003", time.Hour, false)
		c := f.client()
		var iss issued
		c.requestOTP("09125552004", "signup", nil).want(202, "").json(&iss)
		c.post("/auth/register", map[string]any{"invite_token": code, "challenge_id": iss.ID, "code": f.codes.Last()}).want(401, "otp_invalid")
	})

	t.Run("guessing invites is limited by network", func(t *testing.T) {
		c := f.client()
		for i := 0; i < 10; i++ {
			c.post("/auth/invites/lookup", map[string]any{"token": "AAAAA-AAAAA-AAAAA-AAAAA"}).want(404, "invite_invalid")
			f.ck.add(5 * time.Second) // stay under the rate class of the route
		}
		r := c.post("/auth/invites/lookup", map[string]any{"token": "AAAAA-AAAAA-AAAAA-AAAAA"}).want(429, "too_many_attempts")
		if r.H.Get("Retry-After") == "" {
			t.Fatal("no Retry-After")
		}
	})

	t.Run("Passkey routes are 404 while it is switched off", func(t *testing.T) {
		c := f.client()
		c.mustLogin(A.Phone, pwA)
		c.reauthPassword(pwA).want(204, "")
		c.get("/account/passkeys").want(404, "passkey_unavailable")
		c.post("/account/passkeys/begin", nil).want(404, "passkey_unavailable")
		c.post("/account/passkeys/review", nil).want(404, "passkey_unavailable")
		c.post("/auth/reauth/passkey/begin", nil).want(404, "passkey_unavailable")
		f.client().post("/auth/passkey/login/begin", nil).want(404, "passkey_unavailable")
		c.do("PUT", "/account/passkey-enforcement", map[string]any{"enabled": true}).want(409, "enforce_precondition_failed")
	})
}
