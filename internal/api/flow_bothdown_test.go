package api

import (
	"errors"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/session"
	"github.com/Kup1ng/CtrlZ-Panel/internal/authtest"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms/melipayamak"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms/smsir"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testtls"
)

// TestBothGatewaysDown is T-099 (spec p1-auth.md 18.3): the SMS provider is the one dependency a password
// login must not have. With the primary and the fallback both failing until both breakers are open (the state
// of worker/smssend TestBothDownRefundsAndOpensTheBreakers), a correct password still signs in, a session
// that exists keeps working and refreshes, and the code request of a phone with an account and one without
// still answer alike, so the outage is no oracle for which phone is registered.
func TestBothGatewaysDown(t *testing.T) {
	w := newOracleWorld(t)
	f, A := w.f, w.f.env.A

	// A second gateway, melipayamak as the fallback, pointing at the same failing fake as the primary. The
	// world's Build knows sms.ir only, so it is widened here and nowhere else.
	f.env.AddGateway(t, w.ring, authtest.Gateway{Provider: "melipayamak", Role: "fallback", Credentials: `{"username":"u","password":"p"}`, Price: "10"})
	w.src.Build = func(provider string, creds secret.Bytes) (sms.Sender, error) {
		switch provider {
		case "sms_ir":
			c, err := smsir.ParseCredentials(creds.Reveal())
			if err != nil {
				return nil, err
			}
			return smsir.New(smsir.Config{Credentials: c, BaseURL: w.gwURL + "/v1", RootCAs: testtls.Roots()})
		case "melipayamak":
			c, err := melipayamak.ParseCredentials(creds.Reveal())
			if err != nil {
				return nil, err
			}
			return melipayamak.New(melipayamak.Config{Credentials: c, BaseURL: w.gwURL + "/api/SendSMS", RootCAs: testtls.Roots()})
		}
		return nil, errors.New("unknown provider")
	}
	w.router.Invalidate()

	// A session that exists before the outage, with a refresh cookie.
	live := f.client()
	live.loginPassword(A.Phone, pwA, true).want(200, "")
	if live.jar[session.CookieRefresh] == nil {
		t.Fatal("a Remember me login must hold a refresh cookie")
	}

	// Both gateways go down. A real request is made for the known phone and then failed three times by the
	// worker, which opens both breakers, as in the smssend test.
	w.setReply("500")
	req := func(c *client, phone string) *resp {
		f.clearOTP()
		r := c.post("/auth/otp/request", map[string]any{"phone": phone, "purpose": "login", "locale": "fa"})
		w.work.Release()
		return r
	}
	req(f.client(), A.Phone).want(202, "")
	w.drain(w.good, false)
	if n := f.count(`SELECT count(*) FROM ctrlz.sms_gateways WHERE role IN ('primary','fallback') AND breaker_open_until IS NOT NULL`); n != 2 {
		t.Fatalf("%d breakers are open, want both", n)
	}
	w.router.Invalidate()
	f.ck.add(2 * time.Minute) // past the resend cooldown of the first request, inside every session lifetime

	t.Run("a correct password still signs in", func(t *testing.T) {
		c := f.client()
		var res loginBody
		r := c.loginPassword(A.Phone, pwA, false).want(200, "")
		r.json(&res)
		if res.Status != "authenticated" || r.cookie(session.CookieSession) == nil {
			t.Fatalf("password login with both gateways down = %+v", res)
		}
		if m := c.me(); m.User.ID != A.User {
			t.Fatal("the session of the login is not the user's")
		}
	})

	t.Run("an existing session keeps working and refreshes", func(t *testing.T) {
		if m := live.me(); m.User.ID != A.User {
			t.Fatal("the session that existed before the outage stopped working")
		}
		live.post("/auth/refresh", nil).want(204, "")
		if m := live.me(); m.User.ID != A.User {
			t.Fatal("the session does not work after a refresh during the outage")
		}
	})

	t.Run("the code request of a known and an unknown phone look alike", func(t *testing.T) {
		kr := req(f.client(), A.Phone).want(202, "")
		ur := req(f.client(), oracleUnknown).want(202, "")
		var k, u map[string]any
		kr.json(&k)
		ur.json(&u)
		if len(k) != len(u) || k["expires_in_s"] != u["expires_in_s"] || k["resend_after_s"] != u["resend_after_s"] {
			t.Fatalf("bodies differ: %v vs %v", k, u)
		}
		// The same limits too: a second request inside the cooldown is refused for both.
		req(f.client(), A.Phone).want(429, "otp_limited")
		req(f.client(), oracleUnknown).want(429, "otp_limited")
	})
}
