package api

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// The API tokens end to end (docs/specs/p3-endpoints.md 6, 11.1, 11.2 E1, 11.4 "Tokens"): the management routes with a session, and
// the token path with a bearer and no session, through the real pipeline and the real database.

// tokenRig is tenant A and tenant B, each with a session of its own, and a client that holds no cookie.
type tokenRig struct {
	f    *frig
	a, b *client
}

func newTokenRig(t *testing.T) *tokenRig {
	f := newFrig(t, frigOpts{})
	r := &tokenRig{f: f, a: f.makeSession(f.env.A.Tenant, f.env.A.User), b: f.makeSession(f.env.B.Tenant, f.env.B.User)}
	r.reauth(f.env.A.Tenant, f.env.A.User)
	r.reauth(f.env.B.Tenant, f.env.B.User)
	return r
}

// reauth opens the reauth window of the user's newest session now (by the clock of the API, which the gate reads).
func (r *tokenRig) reauth(tenant, user uuid.UUID) {
	r.f.env.Exec(r.f.t, `UPDATE ctrlz.sessions SET reauth_at = $3 WHERE tenant_id = $1 AND id = (
		SELECT id FROM ctrlz.sessions WHERE user_id = $2 ORDER BY created_at DESC, id DESC LIMIT 1)`, tenant, user, r.f.ck.now())
}

// make creates a token of the client's tenant through the route and returns its value and row.
func (r *tokenRig) make(c *client, body map[string]any) (value string, out tokenCreated) {
	r.f.t.Helper()
	if body["name"] == nil {
		body["name"] = "flow token"
	}
	c.post("/api-tokens", body).want(201, "").json(&out)
	if !strings.HasPrefix(out.Value, "ctz_") || len(out.Value) != 68 {
		r.f.t.Fatalf("the value is %q", out.Value)
	}
	return out.Value, out
}

// bearer is a client with no cookie that sends the token.
func (r *tokenRig) bearer(value, ip string) *client {
	c := r.f.client()
	if ip != "" {
		c.ip = ip
	}
	c.hdr["Authorization"] = "Bearer " + value
	return c
}

func TestAPITokenManagement(t *testing.T) {
	r := newTokenRig(t)
	f := r.f
	A := f.env.A

	// Create needs a live reauth window.
	f.env.Exec(t, `UPDATE ctrlz.sessions SET reauth_at = NULL WHERE tenant_id = $1`, A.Tenant)
	r.a.post("/api-tokens", map[string]any{"name": "no window", "kind": "read"}).want(403, "reauth_required")
	r.reauth(A.Tenant, A.User)

	// The value is returned once, in the answer of the create, and nowhere else.
	value, made := r.make(r.a, map[string]any{"name": "ci", "kind": "read", "allowed_ips": []string{"203.0.113.0/24", "203.0.113.0/24", "2001:db8::1"}})
	if made.Token.Kind != "read" || made.Token.Ended || len(made.Token.AllowedIPs) != 2 || made.Token.ExpiresAt == "" {
		t.Errorf("the token row: %+v", made.Token)
	}
	if made.Token.TokenPrefix == "" || len(made.Token.TokenPrefix) != 6 || !strings.Contains(value, made.Token.TokenPrefix) {
		t.Errorf("the prefix %q is not part of the value", made.Token.TokenPrefix)
	}
	list := r.a.get("/api-tokens").want(200, "")
	if strings.Contains(string(list.Body), value[4:]) || strings.Contains(string(list.Body), value) {
		t.Error("the list shows the value")
	}
	var listed struct {
		Tokens []struct {
			ID string `json:"id"`
		} `json:"tokens"`
	}
	list.json(&listed)
	found := false
	for _, tk := range listed.Tokens {
		found = found || tk.ID == made.Token.ID
	}
	if !found {
		t.Error("the new token is not in the list")
	}

	// No row of any table keeps the value, and no log line or audit row does either.
	if n := f.count(`SELECT count(*) FROM ctrlz.tenant_audit_log WHERE tenant_id = $1 AND action = 'api_token.create' AND params->>'token_id' = $2 AND params::text NOT LIKE '%ctz_%'`, A.Tenant, made.Token.ID); n != 1 {
		t.Errorf("%d audit rows of the create without the value, want 1", n)
	}
	if strings.Contains(f.logs.String(), value[4:]) {
		t.Error("the value reached a log")
	}

	// Edit: the name and the list; an empty list is anywhere; the kind cannot change.
	var patched tokenCreated
	r.a.do("PATCH", "/api-tokens/"+made.Token.ID, map[string]any{"name": "renamed", "allowed_ips": []string{}}).want(200, "").json(&patched.Token)
	if patched.Token.Name != "renamed" || len(patched.Token.AllowedIPs) != 0 || patched.Token.Kind != "read" {
		t.Errorf("after the edit: %+v", patched.Token)
	}
	r.a.do("PATCH", "/api-tokens/"+made.Token.ID, map[string]any{"kind": "write"}).want(400, "")
	// Text that cannot be an address at all (a space, a letter past F) is refused by the pattern of the schema as a bad request; text that
	// has the shape of one and is none (an octet of 999) reaches ParseAllowed and is named by its index.
	r.a.do("PATCH", "/api-tokens/"+made.Token.ID, map[string]any{"allowed_ips": []string{"not an address"}}).want(400, "")
	r.a.do("PATCH", "/api-tokens/"+made.Token.ID, map[string]any{"allowed_ips": []string{"999.1.1.1"}}).want(422, "validation_failed")
	r.a.do("PATCH", "/api-tokens/"+made.Token.ID, map[string]any{"allowed_ips": []string{"203.0.113.9/24"}}).want(422, "validation_failed")
	r.a.do("PATCH", "/api-tokens/"+made.Token.ID, map[string]any{}).want(400, "")
	f.env.Exec(t, `UPDATE ctrlz.sessions SET reauth_at = NULL WHERE tenant_id = $1`, A.Tenant)
	r.a.do("PATCH", "/api-tokens/"+made.Token.ID, map[string]any{"name": "x"}).want(403, "reauth_required")

	// Delete: the value stops working at once; a second delete and another tenant's id are 404.
	r.bearer(value, "").get("/account/limits").want(200, "")
	r.a.do("DELETE", "/api-tokens/"+made.Token.ID, nil).want(204, "")
	r.bearer(value, "").get("/account/limits").want(401, "token_invalid")
	r.a.do("DELETE", "/api-tokens/"+made.Token.ID, nil).want(404, "not_found")
	r.reauth(A.Tenant, A.User)
	_, bs := r.make(r.b, map[string]any{"name": "b's"})
	r.a.do("DELETE", "/api-tokens/"+bs.Token.ID, nil).want(404, "not_found")
	r.a.do("PATCH", "/api-tokens/"+bs.Token.ID, map[string]any{"name": "mine now"}).want(404, "not_found")
	if n := f.count(`SELECT count(*) FROM ctrlz.api_tokens WHERE id = $1 AND name = 'b''s'`, bs.Token.ID); n != 1 {
		t.Error("A changed B's token")
	}
	for _, action := range []string{"api_token.create", "api_token.update", "api_token.delete"} {
		if n := f.count(`SELECT count(*) FROM ctrlz.tenant_audit_log WHERE tenant_id = $1 AND action = $2`, A.Tenant, action); n == 0 {
			t.Errorf("no audit row %s", action)
		}
	}
}

func TestAPITokenQuota(t *testing.T) {
	r := newTokenRig(t)
	f := r.f
	A := f.env.A
	have := f.count(`SELECT count(*) FROM ctrlz.api_tokens WHERE tenant_id = $1`, A.Tenant)
	f.env.Exec(t, `UPDATE ctrlz.tenant_entitlements SET max_api_tokens = $2 WHERE tenant_id = $1`, A.Tenant, have+1)
	r.make(r.a, map[string]any{"name": "last room", "kind": "read"})
	var full struct {
		Fields []struct{ Name, Code string } `json:"fields"`
	}
	r.a.post("/api-tokens", map[string]any{"name": "one too many", "kind": "read"}).want(422, "validation_failed").json(&full)
	if len(full.Fields) != 1 || full.Fields[0].Name != "max_api_tokens" || full.Fields[0].Code != "exceeded" {
		t.Errorf("the refusal names %+v", full.Fields)
	}
	// B's limit is its own.
	r.make(r.b, map[string]any{"name": "b first", "kind": "read"})
	// A day's creates are bounded by token-create (20 a day for a tenant), delete or not.
	f.env.Exec(t, `UPDATE ctrlz.tenant_entitlements SET max_api_tokens = 1000 WHERE tenant_id = $1`, A.Tenant)
	refused := 0
	for i := 0; i < 30; i++ {
		f.ck.add(10 * time.Second) // sensitive is 10 a minute for a session
		r.reauth(A.Tenant, A.User)
		resp := r.a.post("/api-tokens", map[string]any{"name": fmt.Sprintf("loop %d", i), "kind": "read"})
		switch resp.Code {
		case 201:
			var out tokenCreated
			resp.json(&out)
			r.a.do("DELETE", "/api-tokens/"+out.Token.ID, nil).want(204, "")
		case 429:
			refused++
		default:
			t.Fatalf("create %d: %d %s", i, resp.Code, resp.Body)
		}
	}
	if refused == 0 {
		t.Error("a create-then-delete loop of 30 was never stopped by token-create")
	}
}

func TestAPITokenPath(t *testing.T) {
	r := newTokenRig(t)
	f := r.f
	A, B := f.env.A, f.env.B
	read, _ := r.make(r.a, map[string]any{"name": "reader", "kind": "read"})
	write, wrow := r.make(r.a, map[string]any{"name": "writer", "kind": "write"})
	bWrite, _ := r.make(r.b, map[string]any{"name": "b writer", "kind": "write"})

	// A read token reads and cannot write; a write token does both.
	var mine struct {
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
	}
	r.bearer(read, "").get("/profiles").want(200, "").json(&mine)
	r.bearer(read, "").post("/profiles", map[string]any{"name": "by a reader", "kind": "custom"}).want(403, "token_read_only")
	r.bearer(write, "").post("/profiles", map[string]any{"name": "by a writer", "kind": "custom"}).want(201, "")
	if n := f.count(`SELECT count(*) FROM ctrlz.profiles WHERE tenant_id = $1 AND name = 'by a writer'`, A.Tenant); n != 1 {
		t.Errorf("the profile of the write token: %d rows", n)
	}

	// The token acts for its own tenant only: B's ids are 404 for A's token, and A's list never holds B's profile.
	r.bearer(write, "").get("/profiles/"+B.Profile.String()).want(404, "not_found")
	r.bearer(write, "").do("PATCH", "/profiles/"+B.Profile.String(), map[string]any{"name": "taken"}).want(404, "not_found")
	for _, it := range mine.Items {
		if it.ID == B.Profile.String() {
			t.Error("A's token lists B's profile")
		}
	}
	if n := f.count(`SELECT count(*) FROM ctrlz.profiles WHERE id = $1 AND name = 'taken'`, B.Profile); n != 0 {
		t.Error("A's token renamed B's profile")
	}
	r.bearer(bWrite, "").get("/profiles/"+A.Profile.String()).want(404, "not_found")

	// An operation whose token is none refuses every bearer, a bearer with a session cookie is one credential too many, and a value
	// that is not ours is 401 with nothing charged.
	r.bearer(write, "").get("/account/sessions").want(403, "token_not_allowed")
	r.bearer(write, "").post("/auth/logout", nil).want(403, "token_not_allowed")
	r.bearer(write, "").post("/api-tokens", map[string]any{"name": "by a token", "kind": "write"}).want(403, "token_not_allowed")
	r.bearer(write, "").post("/feedback", map[string]any{"kind": "contact", "body": "by a token"}).want(403, "token_not_allowed")
	r.bearer(write, "").post("/profiles/"+A.Profile.String()+"/lock", map[string]any{"password": "x"}).want(403, "token_not_allowed")
	both := r.f.makeSession(A.Tenant, A.User)
	both.hdr["Authorization"] = "Bearer " + write
	both.get("/profiles").want(400, "bad_request")
	// On an operation that takes no token the bearer is refused first, cookie or not (6.3 step 1: the order is 403 before 400).
	both.get("/account/sessions").want(403, "token_not_allowed")
	r.bearer("ctz_"+strings.Repeat("A", 64), "").get("/profiles").want(401, "token_invalid")
	r.bearer("junk", "").get("/profiles").want(401, "token_invalid")
	r.bearer(badTag(write), "").get("/profiles").want(401, "token_invalid")

	// Allowed IPs: outside the list is 403, inside is served, and the list can be changed.
	r.reauth(A.Tenant, A.User)
	r.a.do("PATCH", "/api-tokens/"+wrow.Token.ID, map[string]any{"allowed_ips": []string{"203.0.113.0/24"}}).want(200, "")
	r.bearer(write, "198.51.100.7").get("/profiles").want(403, "token_ip_not_allowed")
	r.bearer(write, "203.0.113.77").get("/profiles").want(200, "")
	r.a.do("PATCH", "/api-tokens/"+wrow.Token.ID, map[string]any{"allowed_ips": []string{}}).want(200, "")
	r.bearer(write, "198.51.100.7").get("/profiles").want(200, "")

	// A suspended tenant's token is 403 account_suspended, and works again when the tenant does.
	f.env.Exec(t, `UPDATE ctrlz.tenants SET status = 'suspended' WHERE id = $1`, A.Tenant)
	r.bearer(write, "").get("/profiles").want(403, "account_suspended")
	f.env.Exec(t, `UPDATE ctrlz.tenants SET status = 'active' WHERE id = $1`, A.Tenant)
	r.bearer(write, "").get("/profiles").want(200, "")

	// An ended token (a credential change sets revoked_at) is 401 and stays so, with no lookup the second time.
	f.env.Exec(t, `UPDATE ctrlz.api_tokens SET revoked_at = $2 WHERE id = $1`, wrow.Token.ID, f.ck.now())
	r.bearer(write, "").get("/profiles").want(401, "token_invalid")
	var ended struct {
		Tokens []struct {
			ID    string `json:"id"`
			Ended bool   `json:"ended"`
		} `json:"tokens"`
	}
	r.a.get("/api-tokens").want(200, "").json(&ended)
	for _, tk := range ended.Tokens {
		if tk.ID == wrow.Token.ID && !tk.Ended {
			t.Error("the list does not mark the ended token")
		}
	}

	// A token past its expiry is 401 at the screen, and the list marks it by its expires_at.
	f.ck.add(366 * 24 * time.Hour)
	r.bearer(read, "").get("/profiles").want(401, "token_invalid")
}

// last_used_at is written by the first request and then at most once in ten minutes, by the transaction of the request itself.
func TestAPITokenLastUsed(t *testing.T) {
	r := newTokenRig(t)
	f := r.f
	read, row := r.make(r.a, map[string]any{"name": "reader", "kind": "read"})
	lastUsed := func() (at time.Time, null bool) {
		var p *time.Time
		f.env.Scan(t, `SELECT last_used_at FROM ctrlz.api_tokens WHERE id = $1`, []any{row.Token.ID}, &p)
		if p == nil {
			return time.Time{}, true
		}
		return *p, false
	}
	if _, null := lastUsed(); !null {
		t.Fatal("a token that was never used has a last_used_at")
	}
	r.bearer(read, "").get("/profiles").want(200, "")
	first, null := lastUsed()
	if null || !first.Equal(f.ck.now().Truncate(time.Microsecond)) {
		t.Fatalf("after the first use: %v null %v, want the application time %v", first, null, f.ck.now())
	}
	f.ck.add(9 * time.Minute)
	r.bearer(read, "").get("/profiles").want(200, "")
	if again, _ := lastUsed(); !again.Equal(first) {
		t.Errorf("a use inside ten minutes moved last_used_at to %v", again)
	}
	f.ck.add(2 * time.Minute)
	r.bearer(read, "").get("/profiles").want(200, "")
	if later, _ := lastUsed(); !later.Equal(f.ck.now().Truncate(time.Microsecond)) {
		t.Errorf("a use after ten minutes left last_used_at at %v", later)
	}
	// A request that is refused for its gates writes nothing: a read token on a write, from outside nothing here, never touches.
	f.ck.add(30 * time.Minute)
	r.bearer(read, "").post("/profiles", map[string]any{"name": "x", "kind": "custom"}).want(403, "token_read_only")
	if again, _ := lastUsed(); again.Equal(f.ck.now().Truncate(time.Microsecond)) {
		t.Error("a refused request wrote last_used_at")
	}
}

// A request made with a token creates no session: the sessions table is as it was after it.
func TestAPITokenRequestMakesNoSession(t *testing.T) {
	r := newTokenRig(t)
	f := r.f
	write, _ := r.make(r.a, map[string]any{"name": "writer", "kind": "write"})
	before := f.count(`SELECT count(*) FROM ctrlz.sessions`)
	r.bearer(write, "").get("/profiles").want(200, "")
	r.bearer(write, "").post("/profiles", map[string]any{"name": "no session", "kind": "custom"}).want(201, "")
	if after := f.count(`SELECT count(*) FROM ctrlz.sessions`); after != before {
		t.Errorf("sessions %d before and %d after the requests of a token", before, after)
	}
}
