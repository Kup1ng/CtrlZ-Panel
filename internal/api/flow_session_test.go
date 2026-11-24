package api

import (
	"net/http"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"

	apidoc "github.com/Kup1ng/CtrlZ-Panel/api"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/session"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

type sessionRow struct {
	ID         string `json:"id"`
	Current    bool   `json:"current"`
	CreatedAt  string `json:"created_at"`
	AuthMethod string `json:"auth_method"`
	IP         string `json:"ip"`
	UserAgent  string `json:"user_agent"`
}

func (c *client) sessions() []sessionRow {
	c.f.t.Helper()
	var out struct {
		Sessions []sessionRow `json:"sessions"`
	}
	c.get("/account/sessions").want(200, "").json(&out)
	return out.Sessions
}

func current(rows []sessionRow) sessionRow {
	for _, r := range rows {
		if r.Current {
			return r
		}
	}
	return sessionRow{}
}

// TestSessionsRefreshAndReauth covers 3.3 to 3.7 and 12.1.
func TestSessionsRefreshAndReauth(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A, B := f.env.A, f.env.B

	t.Run("an older session can be ended with no proof, a newer one needs reauth", func(t *testing.T) {
		old, newer := f.client(), f.client()
		old.mustLogin(A.Phone, pwA)
		newer.mustLogin(A.Phone, pwA)
		oldRow := current(old.sessions())
		newRow := current(newer.sessions())
		if oldRow.ID == "" || oldRow.AuthMethod != "password" || oldRow.UserAgent != "flow-test" || oldRow.IP == "" {
			t.Fatalf("session row = %+v", oldRow)
		}

		// The thief (older cookie) cannot end the owner's newer session.
		old.do("DELETE", "/account/sessions/"+newRow.ID, nil).want(403, "reauth_required")
		// The owner on the newer session ends the older one at once.
		newer.do("DELETE", "/account/sessions/"+oldRow.ID, nil).want(204, "")
		old.get("/me").want(401, "session_expired")
		// Ending the current session this way is refused: use logout.
		newer.do("DELETE", "/account/sessions/"+newRow.ID, nil).want(422, "validation_failed")

		// An older session after a reauth can end a newer one.
		c3 := f.client()
		c3.mustLogin(A.Phone, pwA)
		c3Row := current(c3.sessions())
		newer.reauthPassword(pwA).want(204, "")
		newer.do("DELETE", "/account/sessions/"+c3Row.ID, nil).want(204, "")
		c3.get("/me").want(401, "session_expired")
	})

	t.Run("another tenant's session id is a 404 and changes nothing", func(t *testing.T) {
		a, b := f.client(), f.client()
		a.mustLogin(A.Phone, pwA)
		b.mustLogin(B.Phone, pwB)
		aRow := current(a.sessions())
		b.do("DELETE", "/account/sessions/"+aRow.ID, nil).want(404, "not_found")
		a.get("/me").want(200, "")
		for _, r := range b.sessions() {
			if r.ID == aRow.ID {
				t.Fatal("B lists A's session")
			}
		}
	})

	t.Run("reauth rotates the token and keeps created_at", func(t *testing.T) {
		c := f.client()
		c.mustLogin(A.Phone, pwA)
		before := current(c.sessions())
		oldCookie := *c.jar[session.CookieSession]
		c.reauthPassword("wrong wrong wrong wrong 1").want(401, "invalid_credentials")
		r := c.reauthPassword(pwA).want(204, "")
		fresh := r.cookie(session.CookieSession)
		if fresh == nil || fresh.Value == oldCookie.Value {
			t.Fatal("reauth must rotate the session token (3.7)")
		}
		after := current(c.sessions())
		if after.ID != before.ID || after.CreatedAt != before.CreatedAt {
			t.Fatal("rotation must keep the row and its created_at")
		}
		stale := f.client()
		stale.jar[session.CookieSession] = &oldCookie
		stale.get("/me").want(401, "session_expired")
		// The window is open now: a reauth route works, and ends with the window.
		c.post("/account/totp/disable", nil).want(409, "totp_not_enabled") // a reauth route: the gate passes, the route answers
		f.ck.add(11 * time.Minute)
		c.post("/account/totp/disable", nil).want(403, "reauth_required")
	})

	t.Run("a user with a password cannot reauth by SMS", func(t *testing.T) {
		c := f.client()
		c.mustLogin(A.Phone, pwA)
		c.post("/auth/reauth/otp/request", nil).want(409, "conflict")
		c.post("/auth/reauth", map[string]any{"otp_challenge_id": "00000000-0000-7000-8000-000000000001", "otp_code": "123456"}).want(401, "invalid_credentials")
	})

	t.Run("an OTP-only user reauths by SMS to their own number", func(t *testing.T) {
		f.env.Exec(t, `UPDATE ctrlz.users SET password_hash = NULL WHERE tenant_id = $1`, B.Tenant)
		defer f.setPassword(B.Tenant, B.User, pwB)
		f.clearOTP()
		f.clearThrottle()
		c := f.client()
		// Sign in by SMS.
		var iss struct {
			ID string `json:"challenge_id"`
		}
		c.post("/auth/otp/request", map[string]any{"phone": B.Phone, "purpose": "login"}).want(202, "").json(&iss)
		c.post("/auth/login/otp", map[string]any{"phone": B.Phone, "challenge_id": iss.ID, "code": f.codes.Last()}).want(200, "")
		if m := c.me(); m.User.HasPassword {
			t.Fatal("has_password must be false")
		}
		f.clearOTP()
		// The request takes no body; whatever it is sent, the code goes to B's number.
		c.do("POST", "/auth/reauth/otp/request", `{"phone":"`+A.Phone+`"}`).want(202, "")
		if n := f.count(`SELECT count(*) FROM ctrlz.otp_challenges WHERE phone_e164 = $1 AND purpose = 'login'`, []any{B.Phone}...); n != 1 {
			t.Fatalf("challenges for B's number = %d", n)
		}
		if n := f.count(`SELECT count(*) FROM ctrlz.otp_challenges WHERE phone_e164 = $1`, []any{A.Phone}...); n != 0 {
			t.Fatal("the code was aimed at another number")
		}
		var id string
		f.env.Scan(t, `SELECT id::text FROM ctrlz.otp_challenges WHERE phone_e164 = $1`, []any{B.Phone}, &id)
		c.post("/auth/reauth", map[string]any{"otp_challenge_id": id, "otp_code": "000000"}).want(401, "otp_invalid")
		c.post("/auth/reauth", map[string]any{"otp_challenge_id": id, "otp_code": f.codes.Last()}).want(204, "")
	})

	t.Run("lifetimes follow the fake clock", func(t *testing.T) {
		c := f.client()
		c.mustLogin(A.Phone, pwA)
		f.ck.add(119 * time.Minute)
		c.get("/me").want(200, "") // the idle limit slides
		f.ck.add(119 * time.Minute)
		c.get("/me").want(200, "")
		f.ck.add(121 * time.Minute)
		c.get("/me").want(401, "session_expired") // idle
		c2 := f.client()
		c2.mustLogin(A.Phone, pwA)
		for i := 0; i < 12; i++ {
			f.ck.add(110 * time.Minute)
			if i < 10 {
				c2.get("/me").want(200, "")
			}
		}
		c2.get("/me").want(401, "session_expired") // absolute: 24 h
	})

	t.Run("logout and logout-all", func(t *testing.T) {
		c, other := f.client(), f.client()
		c.mustLogin(A.Phone, pwA)
		other.mustLogin(A.Phone, pwA)
		r := c.post("/auth/logout", nil).want(204, "")
		if ck := r.cookie(session.CookieSession); ck == nil || ck.MaxAge >= 0 {
			t.Fatal("logout must clear the session cookie")
		}
		other.get("/me").want(200, "") // logout keeps the others
		other.post("/auth/logout-all", nil).want(204, "")
		other.get("/me").want(401, "session_expired")
	})
}

// TestRefresh covers Remember me (3.4).
func TestRefresh(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A := f.env.A

	c := f.client()
	c.loginPassword(A.Phone, pwA, true).want(200, "")
	c.reauthPassword(pwA).want(204, "")
	// The rotation of the reauth gave a new refresh token and revoked the old one.
	if c.jar[session.CookieRefresh] == nil {
		t.Fatal("a Remember me session keeps a refresh cookie through rotation")
	}

	t.Run("the refresh cookie alone, as after a browser restart", func(t *testing.T) {
		c.forget(session.CookieSession)
		c.get("/me").want(401, "session_expired")
		oldRefresh := *c.jar[session.CookieRefresh]
		r := c.post("/auth/refresh", nil).want(204, "")
		if r.cookie(session.CookieSession) == nil || r.cookie(session.CookieRefresh) == nil {
			t.Fatal("refresh must set both cookies")
		}
		c.get("/me").want(200, "")
		// A refresh never inherits a reauth window.
		c.post("/account/totp/disable", nil).want(403, "reauth_required")

		// A second tab holding the old cookie inside the 10 second grace gets 204
		// with no cookies; after the grace the same cookie ends the family.
		tab := f.client()
		tab.jar[session.CookieRefresh] = &oldRefresh
		g := tab.post("/auth/refresh", nil).want(204, "")
		if len(g.cookies()) != 0 {
			t.Fatal("a concurrent tab must get no cookies")
		}
		f.ck.add(11 * time.Second)
		tab.post("/auth/refresh", nil).want(401, "session_expired")
		c.get("/me").want(401, "session_expired") // the session died with its family
		if n := f.count(`SELECT count(*) FROM ctrlz.tenant_audit_log WHERE action = 'session.refresh_reuse'`); n != 1 {
			t.Fatalf("refresh_reuse rows = %d", n)
		}
	})

	t.Run("no cookie, junk cookie", func(t *testing.T) {
		f.client().post("/auth/refresh", nil).want(401, "session_expired")
		x := f.client()
		x.jar[session.CookieRefresh] = &http.Cookie{Name: session.CookieRefresh, Value: "junk"}
		x.post("/auth/refresh", nil).want(401, "session_expired")
	})
}

// TestPasswordChange covers 4.4 and the rotation table of 3.7.
func TestPasswordChange(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A := f.env.A
	const newPw = "Cobalt-meadow-Falcon-4417"

	keep, c := f.client(), f.client()
	keep.mustLogin(A.Phone, pwA)
	c.loginPassword(A.Phone, pwA, true).want(200, "")

	// A reauth window is needed first.
	c.post("/account/password", map[string]any{"new_password": newPw}).want(403, "reauth_required")
	c.reauthPassword(pwA).want(204, "")

	t.Run("a weak password is refused with a reason", func(t *testing.T) {
		r := c.post("/account/password", map[string]any{"new_password": "short"}).want(422, "password_weak")
		var e struct {
			Fields []struct{ Name, Code string } `json:"fields"`
		}
		r.json(&e)
		if len(e.Fields) != 1 || e.Fields[0].Name != "new_password" || e.Fields[0].Code != "too_short" {
			t.Fatalf("fields = %+v", e.Fields)
		}
		c.post("/account/password", map[string]any{"new_password": "password12345"}).want(422, "password_weak")
		c.post("/account/password", map[string]any{"new_password": "09120000001-9120000001"}).want(422, "password_weak")
	})

	t.Run("success rotates this session and ends the others", func(t *testing.T) {
		f.env.Exec(t, `INSERT INTO ctrlz.api_tokens (tenant_id, user_id, name, kind, token_hash, token_prefix) VALUES ($1, $2, 'x', 'read', '\x0a0b'::bytea, 'czt_x')`, A.Tenant, A.User)
		old := *c.jar[session.CookieSession]
		r := c.post("/account/password", map[string]any{"new_password": newPw}).want(204, "")
		if r.cookie(session.CookieSession) == nil || r.cookie(session.CookieRefresh) == nil {
			t.Fatal("the rotated session needs both cookies")
		}
		c.get("/me").want(200, "")
		keep.get("/me").want(401, "session_expired")
		stale := f.client()
		stale.jar[session.CookieSession] = &old
		stale.get("/me").want(401, "session_expired")
		if n := f.count(`SELECT count(*) FROM ctrlz.api_tokens WHERE user_id = $1 AND revoked_at IS NULL`, A.User); n != 0 {
			t.Fatalf("%d API tokens survived a password change", n)
		}
		if f.count(`SELECT count(*) FROM ctrlz.tenant_audit_log WHERE action = 'password.change'`) != 1 {
			t.Fatal("no password.change row")
		}
		// Old password out, new one in.
		f.clearThrottle()
		f.client().loginPassword(A.Phone, pwA, false).want(401, "invalid_credentials")
		f.client().loginPassword(A.Phone, newPw, false).want(200, "")
	})

	t.Run("a one-time password session sets its password with no reauth", func(t *testing.T) {
		B := f.env.B
		h, _ := f.hasher.Hash(f.env.Ctx, secretString("One-Time-Pass-8842x"))
		f.env.Exec(t, `UPDATE ctrlz.users SET password_hash = $3, must_reset = true, password_expires_at = now() + interval '72 hours' WHERE tenant_id = $1 AND id = $2`, B.Tenant, B.User, h.Reveal())
		ot := f.client()
		ot.mustLogin(B.Phone, "One-Time-Pass-8842x")
		if m := ot.me(); !m.User.MustReset {
			t.Fatal("must_reset should show in /me")
		}
		// Restricted: only the setup routes work.
		ot.get("/account/sessions").want(403, "password_change_required")
		ot.post("/auth/logout-all", nil).want(403, "password_change_required")
		ot.post("/account/password", map[string]any{"new_password": pwB}).want(204, "")
		if m := ot.me(); m.User.MustReset {
			t.Fatal("must_reset should be cleared")
		}
		ot.get("/account/sessions").want(200, "") // no longer restricted
		if f.count(`SELECT count(*) FROM ctrlz.users WHERE id = $1 AND password_expires_at IS NULL AND NOT must_reset`, B.User) != 1 {
			t.Fatal("the expiry and the flag must clear together")
		}
	})
}

// TestTheSessionListIsBoundedAndKeepsTheCallersOwn is tenant-r17-2. Nothing caps the live sessions of an
// account, and GET /account/sessions read and serialised every row, which broke the maxItems of the
// document (1000) and let one account make the shared API and database carry tens of thousands. The list is
// the newest SessionListLimit sessions; the caller's own is shown even when it is older than all of them;
// another tenant's account is not in it; and the constant is the document's own bound.
func TestTheSessionListIsBoundedAndKeepsTheCallersOwn(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A, B := f.env.A, f.env.B
	doc, err := openapi3.NewLoader().LoadFromData(apidoc.Tenant())
	if err != nil {
		t.Fatal(err)
	}
	if got := doc.Components.Schemas["SessionList"].Value.Properties["sessions"].Value.MaxItems; got == nil || *got != uint64(store.SessionListLimit) {
		t.Fatalf("the document bounds SessionList.sessions at %v and the store at %d: they are one number", got, store.SessionListLimit)
	}
	// The oldest session is the one the caller holds; 1005 newer ones follow it.
	own := f.makeSession(A.Tenant, A.User)
	bs := f.makeSession(B.Tenant, B.User)
	bBefore := len(bs.sessions())
	// The rows are written with SQL: since tenant-r18-2 a login past caps.MaxSessions ends the oldest session of the
	// account, which would end the caller's own one before the list is read, and the list bound is the guard of a
	// state that has to hold whatever else keeps the table small (a row written outside the login, a lowered cap).
	f.env.Exec(t, `INSERT INTO ctrlz.sessions (tenant_id, user_id, token_hash, idle_expires_at, absolute_expires_at, last_seen_at, created_at)
		SELECT $1, $2, sha256(convert_to('bulk-' || g, 'UTF8')), '2100-01-01', '2100-01-01', now(),
		       (SELECT min(created_at) FROM ctrlz.sessions WHERE tenant_id = $1 AND user_id = $2) + make_interval(secs => g)
		FROM generate_series(1, $3) g`, A.Tenant, A.User, store.SessionListLimit+5)
	rows := own.sessions()
	if len(rows) != store.SessionListLimit {
		t.Fatalf("%d sessions listed, want %d", len(rows), store.SessionListLimit)
	}
	if cur := current(rows); cur.ID == "" {
		t.Error("the caller's own session, older than the 1000 newest, is not in its list")
	} else if rows[len(rows)-1].ID != cur.ID {
		t.Error("the caller's own session is older than all the rest and must be last")
	}
	for i := 1; i < len(rows); i++ {
		if rows[i-1].CreatedAt < rows[i].CreatedAt {
			t.Fatalf("the list is not newest first at %d", i)
			break
		}
	}
	// The other tenant's account lists what it had before and none of the 1005 of tenant A.
	if got := bs.sessions(); len(got) != bBefore || current(got).ID == "" {
		t.Errorf("tenant B lists %d sessions, want the %d it had", len(got), bBefore)
	}
}
