package api

import (
	"encoding/base32"
	"fmt"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
)

// pastes are what a copy from a right-to-left editor, a contacts app or a chat carries around
// or inside a number: direction marks, the embeddings and isolates, the zero-width joiners, the
// byte order mark and a tab. Each entry is the text before the value, a mark inside it, and the
// text after (round 14, tenant-r14-1).
type pasteCase struct{ name, pre, mid, post string }

var pastes = []pasteCase{
	{"lrm", "\u200e", "\u200e", "\u200e"},
	{"rlm", "\u200f", "\u200f", "\u200f"},
	{"zwnj", "", "\u200c", "\u200c"},
	{"embedding", "\u202a", "", "\u202c"},
	{"isolate", "\u2066", "", "\u2069"},
	{"bom", "\ufeff", "\ufeff", ""},
	{"arabic letter mark", "\u061c", "\u061c", ""},
	{"tab", "\t", "", "\t"},
}

func (p pasteCase) wrap(s string) string { return p.pre + s + p.post }

// inner puts the mid mark between the first two characters, where a keyboard layout would
// split a typed group.
func (p pasteCase) inner(s string) string {
	if len(s) < 2 {
		return s
	}
	return s[:1] + p.mid + s[1:]
}

// A fold is reachable only if the request schema lets its input through. The schema test
// (boundary.TestAPastedCodeReachesTheHandler) stops at the validator; this one goes through the
// real server and the real services and asks for the success path: a code or a phone number
// pasted with each mark signs in, verifies a reset, and a recovery code and an authenticator
// code do too. Before round 14 every one of them was 400 `bad_request` with no field.
func TestPastedCodesAndPhonesSucceedOverHTTP(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A := f.env.A

	t.Run("sms code and phone sign in", func(t *testing.T) {
		for _, p := range pastes {
			t.Run(p.name, func(t *testing.T) {
				f.clearThrottle()
				c := f.client()
				var iss struct {
					ID string `json:"challenge_id"`
				}
				c.requestOTP(p.wrap(A.Phone), "login", map[string]any{"locale": "fa"}).want(202, "").json(&iss)
				code := f.codes.Last()
				// The mark inside the code, and around the phone.
				c.post("/auth/login/otp", map[string]any{"phone": p.wrap(A.Phone), "challenge_id": iss.ID, "code": p.wrap(p.inner(code))}).want(200, "")
			})
		}
	})

	t.Run("password login takes a pasted phone", func(t *testing.T) {
		for _, p := range pastes {
			f.clearThrottle()
			f.client().loginPassword(p.wrap(A.Phone), pwA, false).want(200, "")
		}
	})

	t.Run("reset verify takes a pasted code and phone", func(t *testing.T) {
		for _, p := range pastes {
			t.Run(p.name, func(t *testing.T) {
				f.clearThrottle()
				c := f.client()
				f.clearOTP()
				var iss struct {
					ID string `json:"challenge_id"`
				}
				c.post("/auth/otp/request", map[string]any{"phone": p.wrap(A.Phone), "purpose": "reset"}).want(202, "").json(&iss)
				c.post("/auth/password/reset/verify", map[string]any{"phone": p.wrap(A.Phone), "challenge_id": iss.ID, "code": p.wrap(f.codes.Last())}).want(200, "")
			})
		}
	})

	t.Run("authenticator and recovery codes", func(t *testing.T) {
		f.clearThrottle()
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
		var done struct {
			Codes []string `json:"recovery_codes"`
		}
		// The confirm itself takes a pasted code.
		c.post("/account/totp/confirm", map[string]any{"code": pastes[0].wrap(codeAt(seed, time.Now())), "saved": true}).want(200, "").json(&done)
		if len(done.Codes) != 10 {
			t.Fatalf("recovery codes: %d", len(done.Codes))
		}
		for i, p := range pastes {
			f.clearThrottle()
			f.freeStep(A.Tenant)
			tk := f.client().mfaLogin(A.Phone, pwA)
			f.client().post("/auth/login/totp", map[string]any{"ticket": tk, "totp_code": p.wrap(p.inner(codeAt(seed, time.Now())))}).want(200, "")

			f.clearThrottle()
			tk = f.client().mfaLogin(A.Phone, pwA)
			f.client().post("/auth/login/totp", map[string]any{"ticket": tk, "recovery_code": p.wrap(p.inner(done.Codes[i]))}).want(200, "")
		}
	})
}

// persianDigits writes the ASCII digits of s as a Persian keyboard types them.
func persianDigits(s string) string {
	out := []rune(s)
	for i, r := range out {
		if r >= '0' && r <= '9' {
			out[i] = '۰' + (r - '0')
		}
	}
	return string(out)
}

// The invite code is a typed code too (round 15, tenant-r15-1 and -5): it comes in a Persian SMS
// and is copied into the invite page, so a paste carries direction marks. It was the one code
// whose schema still refused them, and the lookup, the code request and the register route
// answered a bare 400 where the SMS code box next to it accepted the same paste.
func TestAPastedInviteCodeWorksOnEveryInviteRoute(t *testing.T) {
	f := newFrig(t, frigOpts{})
	f.setMode("closed")
	cases := append([]pasteCase{{"persian digits", "", "", ""}}, pastes...)
	for i, p := range cases {
		t.Run(p.name, func(t *testing.T) {
			f.clearThrottle()
			phone := fmt.Sprintf("+98912556%04d", 1000+i)
			code := f.plantInvite(phone, time.Hour, false)
			typed := p.wrap(p.inner(code))
			if p.name == "persian digits" {
				typed = persianDigits(code)
			}
			c := f.client()
			c.post("/auth/invites/lookup", map[string]any{"token": typed}).want(200, "")
			var iss issued
			c.requestOTP("09120000001", "invite", map[string]any{"invite_token": typed, "locale": "fa"}).want(202, "").json(&iss)
			c.post("/auth/register", map[string]any{"invite_token": typed, "challenge_id": iss.ID, "code": f.codes.Last(), "password": "Marble-Island-Copper-6620"}).want(201, "")
			// Used up, whichever spelling asks.
			f.client().post("/auth/invites/lookup", map[string]any{"token": code}).want(404, "invite_invalid")
		})
	}
}
