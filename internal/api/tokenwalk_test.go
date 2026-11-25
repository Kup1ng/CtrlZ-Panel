package api

import (
	"strings"
	"testing"
	"time"

	apidoc "github.com/Kup1ng/CtrlZ-Panel/api"
	"github.com/Kup1ng/CtrlZ-Panel/internal/apispec"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/session"
	"github.com/Kup1ng/CtrlZ-Panel/internal/authtest/boundary"
	"github.com/Kup1ng/CtrlZ-Panel/internal/ratelimit"
)

// TestTokenWalk is rule E1 of docs/specs/p3-endpoints.md 11.2 over every operation of the tenant document: what each credential gets
// is read from x-ctrlz-token and 6.3, and every refusal is one that comes before the handler, so the walk changes nothing. The
// expected answer is never taken from the code under test: an operation that takes no token refuses every bearer, an operation that
// takes one refuses what 6.3 lists, and a token that passes every gate reaches the handler (anything but a token refusal; the
// handler may say 404 or 422 for the baseline's made-up ids).
func TestTokenWalk(t *testing.T) {
	r := newTokenRig(t)
	f := r.f
	A := f.env.A

	ops, err := apispec.Parse(apidoc.Tenant(), ratelimit.Tenant)
	if err != nil {
		t.Fatal(err)
	}
	byKey := apispec.Index(ops)
	cases, err := boundary.Cases(apidoc.Tenant())
	if err != nil {
		t.Fatal(err)
	}
	var baselines []boundary.Case
	for _, c := range cases {
		if c.Baseline && !c.Edge && strings.HasSuffix(c.Name, "/baseline") {
			baselines = append(baselines, c)
		}
	}
	if len(baselines) != len(ops) {
		t.Fatalf("%d baselines for %d operations", len(baselines), len(ops))
	}

	read, readRow := r.make(r.a, map[string]any{"name": "walk reader", "kind": "read", "allowed_ips": []string{"203.0.113.0/24"}})
	write, writeRow := r.make(r.a, map[string]any{"name": "walk writer", "kind": "write", "allowed_ips": []string{"203.0.113.0/24"}})
	alive, _ := r.make(r.a, map[string]any{"name": "walk alive", "kind": "write"})
	inside := "203.0.113.50"
	outside := "198.51.100.50"

	sent := 0
	send := func(c boundary.Case, value, ip string, extra map[string]string) *resp {
		t.Helper()
		sent++
		if sent%20 == 0 {
			f.ck.add(time.Minute) // token-write is 60 a minute for a token, token-tenant 600 for the tenant
		}
		cl := r.bearer(value, ip)
		if value == "" {
			delete(cl.hdr, "Authorization")
		}
		if ip == "" {
			cl.ip = r.f.freshIP()
		}
		h := map[string]string{}
		for k, v := range c.Header {
			h[k] = v
		}
		for k, v := range extra {
			h[k] = v
		}
		var body any
		if c.Body != nil {
			body = c.Body
		}
		return cl.do(c.Method, c.Path, body, h)
	}
	must := func(name string, w *resp, status int, code string) {
		t.Helper()
		if w.Code != status || w.code() != code {
			t.Errorf("%s: %d %s, want %d %s", name, w.Code, w.Body, status, code)
		}
	}
	isTokenRefusal := func(w *resp) bool {
		switch w.Code {
		case 401:
			return w.code() == "token_invalid"
		case 403:
			switch w.code() {
			case "token_not_allowed", "token_read_only", "token_ip_not_allowed", "account_suspended":
				return true
			}
		}
		return false
	}

	both := f.makeSession(A.Tenant, A.User)
	cookie := both.jar[session.CookieSession]
	takes := 0
	for _, c := range baselines {
		op, ok := byKey[c.Key]
		if !ok {
			t.Fatalf("no operation for %s", c.Key)
		}
		takes += map[bool]int{true: 1}[op.Token != "none"]
		name := op.ID

		// An operation that takes no token refuses every bearer, a junk one and one with a session cookie included.
		if op.Token == "none" {
			must(name+" with a write token", send(c, write, inside, nil), 403, "token_not_allowed")
			must(name+" with a junk token", send(c, "ctz_"+strings.Repeat("A", 64), inside, nil), 403, "token_not_allowed")
			continue
		}

		// No credential: the session path, which asks for a session.
		if w := send(c, "", inside, nil); w.Code != 401 || w.code() != "session_expired" {
			t.Errorf("%s with no credential: %d %s", name, w.Code, w.Body)
		}
		// A value that is not a token, and one whose tag fails.
		must(name+" with junk", send(c, "junk", inside, nil), 401, "token_invalid")
		must(name+" with a bad tag", send(c, write[:67]+"x", inside, nil), 401, "token_invalid")
		// A session cookie as well is one credential too many.
		must(name+" with a cookie too", send(c, write, inside, map[string]string{"Cookie": cookie.Name + "=" + cookie.Value}), 400, "bad_request")
		// From outside allowed_ips, each kind.
		must(name+" from outside, read", send(c, read, outside, nil), 403, "token_ip_not_allowed")
		must(name+" from outside, write", send(c, write, outside, nil), 403, "token_ip_not_allowed")
		// A read token on an operation that writes.
		if op.Token == "write" {
			must(name+" with a read token", send(c, read, inside, nil), 403, "token_read_only")
		} else if w := send(c, read, inside, nil); isTokenRefusal(w) || w.Code >= 500 {
			t.Errorf("%s with a read token: %d %s", name, w.Code, w.Body)
		}
		// A read operation with the write token reaches the handler too (a write one is judged in the flow tests: it changes rows).
		if op.Method == "GET" {
			if w := send(c, write, inside, nil); isTokenRefusal(w) || w.Code >= 500 {
				t.Errorf("%s with a write token: %d %s", name, w.Code, w.Body)
			}
		}
	}
	if takes == 0 {
		t.Fatal("no operation of the document takes a token")
	}

	// The states of the token itself, on every operation that takes a token (E1; p3-D6-r1-3 and -14). A route wired outside the token
	// branch, or one that looks at the token's state later than the others, would answer one of these differently from the rest.
	var tokenOps []boundary.Case
	for _, c := range baselines {
		if byKey[c.Key].Token != "none" {
			tokenOps = append(tokenOps, c)
		}
	}
	walk := func(state, value string, status int, code string) {
		t.Helper()
		for _, c := range tokenOps {
			must(state+", "+byKey[c.Key].ID, send(c, value, inside, nil), status, code)
		}
	}
	for _, tc := range []struct {
		name   string
		arm    func()
		undo   func()
		value  string
		status int
		code   string
	}{
		{"a revoked token", func() {
			f.env.Exec(t, `UPDATE ctrlz.api_tokens SET revoked_at = $2 WHERE id = $1`, writeRow.Token.ID, f.ck.now())
		}, nil, write, 401, "token_invalid"},
		{"a deleted token", func() { f.env.Exec(t, `DELETE FROM ctrlz.api_tokens WHERE id = $1`, readRow.Token.ID) }, nil, read, 401, "token_invalid"},
		{"a suspended tenant", func() { f.env.Exec(t, `UPDATE ctrlz.tenants SET status = 'suspended' WHERE id = $1`, A.Tenant) },
			func() { f.env.Exec(t, `UPDATE ctrlz.tenants SET status = 'active' WHERE id = $1`, A.Tenant) }, alive, 403, "account_suspended"},
	} {
		tc.arm()
		walk(tc.name, tc.value, tc.status, tc.code)
		if tc.undo != nil {
			tc.undo()
		}
	}

	// An expired token is refused at the screen, on every operation.
	f.ck.add(366 * 24 * time.Hour)
	walk("an expired token", alive, 401, "token_invalid")
}
