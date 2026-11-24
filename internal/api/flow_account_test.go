package api

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/session"
)

type phoneChangeBody struct {
	RequestID string `json:"request_id"`
	OldID     string `json:"old_challenge_id"`
	NewID     string `json:"new_challenge_id"`
	Expires   int    `json:"expires_in_s"`
}

// startChange asks for a phone change and returns the body, the old-number code and the new-number code
// (the new number is issued first, then the old one: 5.6 step 3).
func (c *client) startChange(newPhone string) (phoneChangeBody, string, string) {
	c.f.t.Helper()
	c.f.ck.add(time.Minute) // the otp-send class allows 5 a minute
	c.f.clearOTP()
	var b phoneChangeBody
	c.post("/account/phone/change", map[string]any{"new_phone": newPhone}).want(202, "").json(&b)
	return b, c.f.codes.Back(1), c.f.codes.Back(2)
}

// TestPhoneChange covers 5.6 and T-110.
func TestPhoneChange(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A, B := f.env.A, f.env.B
	const newPhone = "+989128880001"
	confirm := func(c *client, id, oldCode, newCode string) *resp {
		return c.post("/account/phone/change/"+id+"/confirm", map[string]any{"old_code": oldCode, "new_code": newCode})
	}

	owner, other := f.client(), f.client()
	owner.mustLogin(A.Phone, pwA)
	other.mustLogin(A.Phone, pwA)

	owner.post("/account/phone/change", map[string]any{"new_phone": newPhone}).want(403, "reauth_required")
	owner.reauthPassword(pwA).want(204, "")
	owner.post("/account/phone/change", map[string]any{"new_phone": A.Phone}).want(422, "validation_failed")
	owner.post("/account/phone/change", map[string]any{"new_phone": "12"}).want(422, "invalid_phone")

	t.Run("a typo in one code does not lose the other", func(t *testing.T) {
		b, oldCode, newCode := owner.startChange(newPhone)
		if b.Expires != 300 {
			t.Fatalf("expires_in_s = %d", b.Expires)
		}
		r := confirm(owner, b.RequestID, "000000", newCode).want(401, "otp_invalid")
		if string(r.Body[:60]) == "" || !contains(r.Body, `"name":"old_code"`) {
			t.Fatalf("the error must name the field: %s", r.Body)
		}
		// The new code was not consumed (the old one failed first); now the new one is wrong.
		r = confirm(owner, b.RequestID, oldCode, "000000").want(401, "otp_invalid")
		if !contains(r.Body, `"name":"new_code"`) {
			t.Fatalf("the error must name the field: %s", r.Body)
		}
		// The old code is consumed now and still counts; a right new code finishes it.
		oldCookie := *owner.jar[session.CookieSession]
		done := confirm(owner, b.RequestID, oldCode, newCode).want(204, "")
		if done.cookie(session.CookieSession) == nil || done.cookie(session.CookieSession).Value == oldCookie.Value {
			t.Fatal("a phone change rotates the session")
		}
		other.get("/me").want(401, "session_expired")
		if m := owner.me(); m.User.PhoneMasked == "" || m.User.PhoneMasked[len(m.User.PhoneMasked)-4:] != "0001" {
			t.Fatalf("phone_masked = %q", m.User.PhoneMasked)
		}
		if f.count(`SELECT count(*) FROM ctrlz.users WHERE id = $1 AND phone_e164 = $2`, A.User, newPhone) != 1 {
			t.Fatal("the phone did not change")
		}
		if f.count(`SELECT count(*) FROM ctrlz.tenant_audit_log WHERE action = 'phone.change' AND params->>'new_masked' = '+98912*****01' AND params::text NOT LIKE '%8880001%'`) != 1 {
			t.Fatal("the audit row must hold masked numbers only")
		}
		if f.count(`SELECT count(*) FROM ctrlz.notifications WHERE tenant_id = $1 AND kind = 'phone_changed'`, A.Tenant) != 1 {
			t.Fatal("no phone_changed notification")
		}
		// A finished request cannot be replayed.
		confirm(owner, b.RequestID, oldCode, newCode).want(401, "otp_invalid")
		// The old number no longer logs in; the new one does.
		f.clearThrottle()
		f.client().loginPassword(A.Phone, pwA, false).want(401, "invalid_credentials")
		f.client().mustLogin(newPhone, pwA)
	})

	t.Run("the old number cannot be the new one", func(t *testing.T) {
		owner.reauthPassword(pwA).want(204, "")
		owner.post("/account/phone/change", map[string]any{"new_phone": newPhone}).want(422, "validation_failed")
	})

	t.Run("a number that belongs to someone else", func(t *testing.T) {
		b, oldCode, newCode := owner.startChange(B.Phone)
		// The request is accepted like any other; the code for the taken number is a decoy that was never sent
		// anywhere, and since question 15 it carries no tenant (a decoy is written with none), so even the code the
		// test reads out of it cannot complete the change: the answer is the same wrong-code error as for any
		// other code, where it used to be phone_unavailable for a person who held that SIM and the code.
		confirm(owner, b.RequestID, oldCode, "000000").want(401, "otp_invalid")
		confirm(owner, b.RequestID, oldCode, newCode).want(401, "otp_invalid")
		if f.count(`SELECT count(*) FROM ctrlz.users WHERE id = $1 AND phone_e164 = $2`, A.User, newPhone) != 1 {
			t.Fatal("the number changed")
		}
		if f.count(`SELECT count(*) FROM ctrlz.users WHERE phone_e164 = $1`, B.Phone) != 1 {
			t.Fatal("B lost its number")
		}
	})

	t.Run("a number that someone takes after its code was sent", func(t *testing.T) {
		const late = "+989128880006"
		b, oldCode, newCode := owner.startChange(late)
		// The code is real (nobody had the number when it was issued) and carries the tenant, so the confirm gets as
		// far as the database, which finds the number taken by now: the one case of phone_unavailable (5.6).
		f.env.Exec(t, `UPDATE ctrlz.users SET phone_e164 = $1 WHERE id = $2`, late, B.User)
		defer f.env.Exec(t, `UPDATE ctrlz.users SET phone_e164 = $1 WHERE id = $2`, B.Phone, B.User)
		confirm(owner, b.RequestID, oldCode, newCode).want(409, "phone_unavailable")
		if f.count(`SELECT count(*) FROM ctrlz.users WHERE id = $1 AND phone_e164 = $2`, A.User, newPhone) != 1 {
			t.Fatal("the number changed")
		}
	})

	t.Run("codes of an earlier attempt are useless", func(t *testing.T) {
		_, oldCode1, newCode1 := owner.startChange("+989128880002")
		b2, _, _ := owner.startChange("+989128880003")
		confirm(owner, b2.RequestID, oldCode1, newCode1).want(401, "otp_invalid")
	})

	t.Run("expiry", func(t *testing.T) {
		b, oldCode, newCode := owner.startChange("+989128880004")
		f.env.Exec(t, `UPDATE ctrlz.otp_challenges SET expires_at = now() - interval '1 minute'`)
		r := confirm(owner, b.RequestID, oldCode, newCode).want(401, "otp_invalid")
		if !contains(r.Body, `"code":"expired"`) {
			t.Fatalf("body = %s", r.Body)
		}
	})

	t.Run("another tenant's request is a 404", func(t *testing.T) {
		b, oldCode, newCode := owner.startChange("+989128880005")
		bc := f.client()
		bc.mustLogin(B.Phone, pwB)
		confirm(bc, b.RequestID, oldCode, newCode).want(404, "not_found")
		confirm(bc, "not-a-uuid", oldCode, newCode).want(400, "bad_request")
		var phone string
		f.env.Scan(t, `SELECT phone_e164 FROM ctrlz.users WHERE id = $1`, []any{B.User}, &phone)
		if phone != B.Phone {
			t.Fatal("B's number changed")
		}
	})
}

func contains(b []byte, sub string) bool {
	return len(sub) == 0 || (len(b) >= len(sub) && indexOf(string(b), sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// TestAccountSettings covers 12.1: /me, preferences, Home Countries, limits,
// notifications and announcements, and the suspended tenant.
func TestAccountSettings(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A, B := f.env.A, f.env.B
	a, b := f.client(), f.client()
	a.mustLogin(A.Phone, pwA)
	b.mustLogin(B.Phone, pwB)

	t.Run("me", func(t *testing.T) {
		var raw map[string]any
		a.get("/me").want(200, "").json(&raw)
		user := raw["user"].(map[string]any)
		if user["phone_masked"] == A.Phone || user["onboarding_hints"].(map[string]any)["enabled"] != true {
			t.Fatalf("user = %v", user)
		}
		if _, ok := raw["security"].(map[string]any)["enforce_lift_at"]; ok {
			t.Fatal("enforce_lift_at must be absent when unset")
		}
	})

	t.Run("preferences", func(t *testing.T) {
		a.do("PATCH", "/account/preferences", map[string]any{"locale": "en", "theme": "dark", "onboarding_hints": map[string]any{"enabled": false}, "onboarding_state": map[string]any{"step": 2}}).want(200, "")
		var raw struct {
			User struct {
				Locale string         `json:"locale"`
				Theme  string         `json:"theme"`
				Hints  map[string]any `json:"onboarding_hints"`
				State  map[string]any `json:"onboarding_state"`
			} `json:"user"`
		}
		a.get("/me").want(200, "").json(&raw)
		if raw.User.Locale != "en" || raw.User.Theme != "dark" || raw.User.Hints["enabled"] != false || raw.User.State["step"] != float64(2) {
			t.Fatalf("user = %+v", raw.User)
		}
		a.do("PATCH", "/account/preferences", map[string]any{"locale": "de"}).want(400, "bad_request") // an enum of the schema, refused before the handler (rule boundary-input)
		a.do("PATCH", "/account/preferences", map[string]any{"theme": "neon"}).want(400, "bad_request")
		a.do("PATCH", "/account/preferences", map[string]any{}).want(200, "")
		if m := b.me(); m.User.Locale != "fa" || m.User.Theme == "dark" {
			t.Fatalf("B's preferences moved: %+v", m.User)
		}
	})

	t.Run("home countries", func(t *testing.T) {
		var out struct {
			Countries []string `json:"countries"`
		}
		a.do("PUT", "/account/home-countries", map[string]any{"countries": []string{"ir", "DE"}}).want(200, "").json(&out)
		if fmt.Sprint(out.Countries) != "[IR DE]" {
			t.Fatalf("countries = %v", out.Countries)
		}
		a.do("PUT", "/account/home-countries", map[string]any{"countries": []string{"IR", "DE", "FR", "US"}}).want(400, "bad_request") // maxItems 3, refused by the schema first
		a.do("PUT", "/account/home-countries", map[string]any{"countries": []string{"XX"}}).want(422, "validation_failed")
		a.do("PUT", "/account/home-countries", map[string]any{"countries": []string{"IR", "IR"}}).want(422, "validation_failed")
		a.do("PUT", "/account/home-countries", map[string]any{"countries": []string{}}).want(200, "")
		var home []string
		f.env.Scan(t, `SELECT home_countries::text[] FROM ctrlz.tenants WHERE id = $1`, []any{B.Tenant}, &home)
		if len(home) != 0 {
			t.Fatalf("B's home countries = %v", home)
		}
	})

	t.Run("limits", func(t *testing.T) {
		var l map[string]int
		a.get("/account/limits").want(200, "").json(&l)
		for _, k := range []string{"max_profiles", "max_endpoints", "max_clients_per_endpoint", "max_authorized_ips", "max_api_tokens", "max_rules_per_request", "max_rules_per_profile", "max_wildcards_per_profile", "max_realtime_sessions", "max_publishes_per_hour", "max_ip_claims"} {
			if l[k] <= 0 {
				t.Errorf("%s = %d", k, l[k])
			}
		}
	})

	t.Run("notifications", func(t *testing.T) {
		base := time.Now().UTC().Add(-time.Hour)
		for i := 0; i < 4; i++ {
			f.env.Exec(t, `INSERT INTO ctrlz.notifications (tenant_id, kind, severity, params, created_at) VALUES ($1, $2, 'warning', '{"n": 1}', $3)`,
				A.Tenant, fmt.Sprintf("kind%d", i), base.Add(time.Duration(i)*time.Minute))
		}
		type page struct {
			Items []struct {
				ID       string         `json:"id"`
				Kind     string         `json:"kind"`
				Severity string         `json:"severity"`
				Params   map[string]any `json:"params"`
				ReadAt   *string        `json:"read_at"`
			} `json:"items"`
			Next   string `json:"next_cursor"`
			Unread int    `json:"unread_count"`
		}
		var p1, p2, p3 page
		a.get("/notifications?limit=2").want(200, "").json(&p1)
		if len(p1.Items) != 2 || p1.Next == "" || p1.Unread != 5 || p1.Items[0].Kind != "welcome" || p1.Items[1].Kind != "kind3" || p1.Items[1].Params["n"] != float64(1) {
			t.Fatalf("page 1 = %+v", p1)
		}
		a.get("/notifications?limit=2&cursor="+p1.Next).want(200, "").json(&p2)
		a.get("/notifications?limit=2&cursor="+p2.Next).want(200, "").json(&p3)
		if len(p2.Items) != 2 || len(p3.Items) != 1 || p3.Next != "" || p2.Items[0].ID == p1.Items[1].ID {
			t.Fatalf("pages = %+v / %+v", p2, p3)
		}
		a.get("/notifications?cursor=!!!").want(400, "bad_request")
		a.get("/notifications?cursor=bm90IGEgY3Vyc29y").want(400, "bad_request")

		a.post("/notifications/"+p1.Items[0].ID+"/read", nil).want(204, "")
		var again page
		a.get("/notifications?limit=1").want(200, "").json(&again)
		if again.Unread != 4 || again.Items[0].ReadAt == nil {
			t.Fatalf("after read: %+v", again)
		}
		// B sees none of A's and counts its own.
		var pb page
		b.get("/notifications").want(200, "").json(&pb)
		for _, it := range pb.Items {
			if it.Kind != "welcome" {
				t.Fatalf("B sees %q", it.Kind)
			}
		}
		if pb.Unread != 1 {
			t.Fatalf("B unread = %d", pb.Unread)
		}
		b.post("/notifications/"+p1.Items[1].ID+"/read", nil).want(404, "not_found")
	})

	t.Run("announcements", func(t *testing.T) {
		for i, tgt := range []struct{ tenant, body string }{{A.Tenant.String(), "for A"}, {B.Tenant.String(), "for B"}} {
			f.env.Exec(t, `INSERT INTO ctrlz.announcements (audience, tenant_id, body, starts_at) VALUES ('tenant', $1, $2, now() - make_interval(mins => $3))`, tgt.tenant, tgt.body, i+1)
		}
		type page struct {
			Items []struct {
				ID   string `json:"id"`
				Body string `json:"body"`
				Read bool   `json:"read"`
			} `json:"items"`
			Next   string `json:"next_cursor"`
			Unread int    `json:"unread_count"`
		}
		var pa, pb page
		a.get("/announcements").want(200, "").json(&pa)
		b.get("/announcements").want(200, "").json(&pb)
		has := func(p page, body string) bool {
			for _, it := range p.Items {
				if it.Body == body {
					return true
				}
			}
			return false
		}
		if !has(pa, "for A") || has(pa, "for B") || !has(pb, "for B") || has(pb, "for A") || !has(pa, "hello") {
			t.Fatalf("A = %+v, B = %+v", pa, pb)
		}
		if pa.Unread != 1 || pb.Unread != 1 { // the seeded "hello" is read; the tenant one is not
			t.Fatalf("unread: A %d, B %d", pa.Unread, pb.Unread)
		}
		var id string
		for _, it := range pa.Items {
			if it.Body == "for A" {
				id = it.ID
			}
		}
		b.post("/announcements/"+id+"/read", nil).want(404, "not_found")
		a.post("/announcements/"+id+"/read", nil).want(204, "")
		a.post("/announcements/"+id+"/read", nil).want(204, "")
		var one page
		a.get("/announcements?limit=1").want(200, "").json(&one)
		if one.Unread != 0 || len(one.Items) != 1 || one.Next == "" {
			t.Fatalf("after read: %+v", one)
		}
		var rest page
		a.get("/announcements?limit=5&cursor="+one.Next).want(200, "").json(&rest)
		if len(rest.Items) != 1 || rest.Items[0].ID == one.Items[0].ID {
			t.Fatalf("second page = %+v", rest)
		}
	})

	t.Run("a suspended tenant", func(t *testing.T) {
		c := f.client()
		c.mustLogin(A.Phone, pwA)
		f.env.Exec(t, `UPDATE ctrlz.tenants SET status = 'suspended' WHERE id = $1`, A.Tenant)
		var m struct {
			Tenant struct {
				Status string `json:"status"`
			} `json:"tenant"`
		}
		c.get("/me").want(200, "").json(&m)
		if m.Tenant.Status != "suspended" {
			t.Fatalf("status = %q", m.Tenant.Status)
		}
		for _, p := range []string{"/account/sessions", "/notifications", "/account/limits"} {
			c.get(p).want(403, "account_suspended")
		}
		c.post("/auth/reauth", map[string]any{"password": pwA}).want(403, "account_suspended")
		c.post("/auth/logout", nil).want(204, "")
		f.env.Exec(t, `UPDATE ctrlz.tenants SET status = 'deleting' WHERE id = $1`, A.Tenant)
		d := f.makeSession(A.Tenant, A.User)
		d.get("/me").want(401, "session_expired")
		f.env.Exec(t, `UPDATE ctrlz.tenants SET status = 'active' WHERE id = $1`, A.Tenant)
	})

	_ = json.Marshal
}
