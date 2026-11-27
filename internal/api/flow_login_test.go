package api

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/session"
)

type loginBody struct {
	Status string   `json:"status"`
	Ticket string   `json:"ticket"`
	Method []string `json:"methods"`
}

// TestPasswordLogin covers T-092, T-096 and the enumeration rules of 4.5 and 18.5.
func TestPasswordLogin(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A, B := f.env.A, f.env.B

	t.Run("config", func(t *testing.T) {
		var cfg struct {
			Mode string `json:"registration_mode"`
			SMS  bool   `json:"sms_available"`
			PK   bool   `json:"passkey_enabled"`
		}
		f.client().get("/auth/config").want(200, "")
		f.client().get("/auth/config").json(&cfg)
		if cfg.Mode != "closed" || !cfg.SMS || cfg.PK {
			t.Fatalf("config = %+v", cfg)
		}
	})

	t.Run("success sets exactly the cookies of 3.2", func(t *testing.T) {
		c := f.client()
		r := c.loginPassword(A.Phone, pwA, false).want(200, "")
		var res loginBody
		r.json(&res)
		if res.Status != "authenticated" {
			t.Fatalf("status = %q", res.Status)
		}
		for _, ck := range r.cookies() {
			if ck.Domain != "" || !ck.Secure || !ck.HttpOnly || ck.Path != "/" || ck.SameSite != http.SameSiteLaxMode {
				t.Errorf("cookie %s has the wrong attributes: %+v", ck.Name, ck)
			}
		}
		if s := r.cookie(session.CookieSession); s == nil || s.MaxAge != 0 {
			t.Fatalf("the session cookie must be a browser session cookie: %+v", s)
		}
		// Without Remember me the answer deletes any refresh cookie the browser holds
		// (primitives-r3-7): a left-over one of another account would otherwise take
		// over this login on the next 401.
		if rc := r.cookie(session.CookieRefresh); rc == nil || rc.MaxAge >= 0 || rc.Value != "" {
			t.Fatalf("a login without Remember me must expire the refresh cookie: %+v", rc)
		}
		if d := r.cookie(session.CookieDevice); d == nil || d.MaxAge != 365*24*3600 {
			t.Fatalf("device cookie = %+v", d)
		}
		if m := c.me(); m.User.ID != A.User || m.Tenant.ID != A.Tenant || !m.User.HasPassword {
			t.Fatalf("me = %+v", m)
		}
		if got := r.H.Get("Cache-Control"); got != "no-store" {
			t.Fatalf("Cache-Control = %q", got)
		}
	})

	t.Run("remember me adds a 30 day refresh cookie", func(t *testing.T) {
		c := f.client()
		r := c.loginPassword(A.Phone, pwA, true).want(200, "")
		rc := r.cookie(session.CookieRefresh)
		if rc == nil || rc.MaxAge != 30*24*3600 {
			t.Fatalf("refresh cookie = %+v", rc)
		}
	})

	// Primitives-r3-7, two tenants on one shared computer. A signs in with Remember
	// me and leaves; B signs in on the same browser without it. B's login deletes
	// A's refresh cookie, so when B's session ends api-client's /auth/refresh finds
	// nothing to swap in and B is not handed A's account.
	t.Run("a login without remember me removes another account's refresh cookie", func(t *testing.T) {
		c := f.client()
		c.loginPassword(A.Phone, pwA, true).want(200, "")
		if c.jar[session.CookieRefresh] == nil {
			t.Fatal("A's refresh cookie should be in the browser")
		}
		c.loginPassword(B.Phone, pwB, false).want(200, "")
		if c.jar[session.CookieRefresh] != nil {
			t.Fatal("A's refresh cookie survived B's login")
		}
		// B's session ends (the browser keeps no session cookie), the client retries
		// through /auth/refresh as it does on any 401, and gets nothing.
		c.forget(session.CookieSession)
		c.post("/auth/refresh", nil).want(401, "session_expired")
		if c.jar[session.CookieSession] != nil {
			t.Fatal("a session cookie came out of /auth/refresh")
		}
	})

	t.Run("a known and an unknown phone are indistinguishable", func(t *testing.T) {
		before := f.hasher.Runs()
		c1, c2, c3 := f.client(), f.client(), f.client()
		wrong := c1.loginPassword(A.Phone, "not the password at all 1", false)
		unknown := c2.loginPassword("09129999999", "not the password at all 1", false)
		badFormat := c3.loginPassword("12", "not the password at all 1", false)
		for name, r := range map[string]*resp{"wrong": wrong, "unknown": unknown, "bad format": badFormat} {
			r.want(401, "invalid_credentials")
			if r.Dur < 450*time.Millisecond {
				t.Errorf("%s answered in %v, under the 500 ms floor", name, r.Dur)
			}
		}
		if string(wrong.Body[:len(`{"code":"invalid_credentials"`)]) != `{"code":"invalid_credentials"` {
			t.Fatalf("body = %s", wrong.Body)
		}
		for _, h := range []string{"Content-Type", "Cache-Control"} {
			if wrong.H.Get(h) != unknown.H.Get(h) || wrong.H.Get(h) != badFormat.H.Get(h) {
				t.Errorf("header %s differs between the cases", h)
			}
		}
		if len(wrong.cookies()) != 0 || len(unknown.cookies()) != 0 {
			t.Fatal("a failed login set a cookie")
		}
		if runs := f.hasher.Runs() - before; runs != 3 {
			t.Fatalf("Argon2 ran %d times for three attempts; it must run once on every path", runs)
		}
		f.after.Wait() // the row is written after the floor, off the request (tenant-r13-2)
		// Only the real account has a failure on record.
		if n := f.count(`SELECT count(*) FROM ctrlz.tenant_audit_log WHERE action = 'login.failed'`); n != 1 {
			t.Fatalf("login.failed rows = %d, want 1", n)
		}
	})

	t.Run("spraying is stopped in Postgres", func(t *testing.T) {
		c := f.client()
		for i := 0; i < 5; i++ {
			c.loginPassword(B.Phone, "wrong wrong wrong wrong 7", false).want(401, "invalid_credentials")
		}
		r := c.loginPassword(B.Phone, pwB, false).want(429, "too_many_attempts")
		if r.H.Get("Retry-After") == "" {
			t.Fatal("no Retry-After")
		}
		// The right password from another network still works: the attacker's
		// counter is keyed on the network too.
		f.client().loginPassword(B.Phone, pwB, false).want(200, "")
	})

	t.Run("a cookie sent to login is ignored", func(t *testing.T) {
		c := f.client()
		c.mustLogin(A.Phone, pwA)
		old := c.jar[session.CookieSession].Value
		r := c.loginPassword(A.Phone, pwA, false).want(200, "")
		if got := r.cookie(session.CookieSession); got == nil || got.Value == old {
			t.Fatal("login must issue a new token whatever cookie the request carried")
		}
		// The old session is not revoked by a login (3.7: Login keeps the others).
		c2 := f.client()
		c2.jar[session.CookieSession] = c.jar[session.CookieSession]
		c2.jar[session.CookieSession].Value = old
		c2.get("/me").want(200, "")
	})

	t.Run("an oversized password is refused before Argon2", func(t *testing.T) {
		before := f.hasher.Runs()
		f.client().post("/auth/login/password", `{"phone":"`+A.Phone+`","password":"`+strings.Repeat("x", 1<<20)+`"}`).want(413, "too_large")
		if f.hasher.Runs() != before {
			t.Fatal("Argon2 ran for a 1 MiB body")
		}
		// 129 code points: fails like any wrong password, one Argon2 run.
		f.client().loginPassword(A.Phone, strings.Repeat("é", 129), false).want(401, "invalid_credentials")
	})

	t.Run("a suspended tenant", func(t *testing.T) {
		f.env.Exec(t, `UPDATE ctrlz.tenants SET status = 'suspended' WHERE id = $1`, B.Tenant)
		defer f.env.Exec(t, `UPDATE ctrlz.tenants SET status = 'active' WHERE id = $1`, B.Tenant)
		f.clearThrottle()
		f.client().loginPassword(B.Phone, pwB, false).want(403, "account_suspended")
	})

	t.Run("the one-time password past its expiry", func(t *testing.T) {
		f.clearThrottle()
		f.env.Exec(t, `UPDATE ctrlz.users SET must_reset = true, password_expires_at = now() - interval '1 minute' WHERE tenant_id = $1`, B.Tenant)
		f.client().loginPassword(B.Phone, pwB, false).want(401, "invalid_credentials")
		f.env.Exec(t, `UPDATE ctrlz.users SET must_reset = false, password_expires_at = NULL WHERE tenant_id = $1`, B.Tenant)
	})

	c := f.client()
	c.mustLogin(A.Phone, pwA)
	f.assertQuiet(c.cookieValues()...)
}

// TestOTPLogin covers T-093 and the decoy of 5.3.
func TestOTPLogin(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A := f.env.A

	req := func(c *client, phone, purpose string) *resp {
		return c.post("/auth/otp/request", map[string]any{"phone": phone, "purpose": purpose, "locale": "fa"})
	}

	t.Run("request and login", func(t *testing.T) {
		c := f.client()
		r := req(c, A.Phone, "login").want(202, "")
		var iss struct {
			ID      string `json:"challenge_id"`
			Expires int    `json:"expires_in_s"`
			Resend  int    `json:"resend_after_s"`
		}
		r.json(&iss)
		if iss.ID == "" || iss.Expires != 300 || iss.Resend != 60 {
			t.Fatalf("issued = %+v", iss)
		}
		if r.Dur < 250*time.Millisecond {
			t.Errorf("OTP request answered in %v, under the 300 ms floor", r.Dur)
		}
		code := f.codes.Last()
		// A wrong code, then the right one.
		c.post("/auth/login/otp", map[string]any{"phone": A.Phone, "challenge_id": iss.ID, "code": "000000"}).want(401, "otp_invalid")
		r = c.post("/auth/login/otp", map[string]any{"phone": A.Phone, "challenge_id": iss.ID, "code": code, "remember_me": true}).want(200, "")
		var res loginBody
		r.json(&res)
		if res.Status != "authenticated" || r.cookie(session.CookieRefresh) == nil {
			t.Fatalf("otp login = %+v", res)
		}
		if f.count(`SELECT count(*) FROM ctrlz.users WHERE id = $1 AND phone_verified_at IS NOT NULL`, A.User) != 1 {
			t.Fatal("an OTP login must verify the phone")
		}
		// The code is single use.
		c.post("/auth/login/otp", map[string]any{"phone": A.Phone, "challenge_id": iss.ID, "code": code}).want(401, "otp_expired")
	})

	t.Run("an unknown phone gets the same 202 and can never log in", func(t *testing.T) {
		f.clearOTP()
		c := f.client()
		known := req(c, A.Phone, "login").want(202, "")
		f.clearOTP()
		unknown := req(f.client(), "09127776655", "login").want(202, "")
		var k, u map[string]any
		known.json(&k)
		unknown.json(&u)
		if len(k) != len(u) || k["expires_in_s"] != u["expires_in_s"] || k["resend_after_s"] != u["resend_after_s"] {
			t.Fatalf("bodies differ: %v vs %v", k, u)
		}
		code := f.codes.Last()
		f.client().post("/auth/login/otp", map[string]any{"phone": "09127776655", "challenge_id": u["challenge_id"], "code": code}).want(401, "otp_invalid")
		// Only a decoy was made: nothing is waiting for the worker.
		if n := f.count(`SELECT count(*) FROM ctrlz.otp_challenges WHERE phone_e164 = '+989127776655' AND delivery_ct IS NOT NULL`); n != 0 {
			t.Fatalf("a decoy has a delivery payload (%d)", n)
		}
	})

	t.Run("limits are the same for both", func(t *testing.T) {
		f.clearOTP()
		c := f.client()
		req(c, A.Phone, "login").want(202, "")
		req(c, A.Phone, "login").want(429, "otp_limited") // the 60 second cooldown
		req(c, "09127776655", "login").want(202, "")
		req(c, "09127776655", "login").want(429, "otp_limited")
	})

	t.Run("a code of one purpose is refused for another", func(t *testing.T) {
		f.clearOTP()
		c := f.client()
		var iss struct {
			ID string `json:"challenge_id"`
		}
		req(c, A.Phone, "login").want(202, "").json(&iss)
		code := f.codes.Last()
		c.post("/auth/password/reset/verify", map[string]any{"phone": A.Phone, "challenge_id": iss.ID, "code": code}).want(401, "otp_invalid")
	})

	t.Run("invalid phone and bad purpose", func(t *testing.T) {
		c := f.client()
		req(c, "123", "login").want(422, "invalid_phone")
		c.post("/auth/otp/request", map[string]any{"phone": A.Phone, "purpose": "bogus"}).want(400, "bad_request")
		req(c, A.Phone, "signup").want(403, "registration_closed")
	})

	t.Run("persian digits are accepted", func(t *testing.T) {
		f.clearOTP()
		req(f.client(), "۰۹۱۲۰۰۰۰۰۰۱", "login").want(202, "")
	})

	f.assertQuiet()
}
