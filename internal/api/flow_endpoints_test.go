package api

import (
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
)

// The Endpoint routes end to end (docs/specs/p3-endpoints.md 9, 11.4): create with an idempotency key, the pages and their
// orders, the CSV, the lock password through the real throttle and Argon2 gate, and the two-tenant cases.

type pEndpoint struct {
	ID         uuid.UUID `json:"id"`
	Name       string    `json:"name"`
	ResolverID string    `json:"resolver_id"`
	AdminState string    `json:"admin_state"`
	Status     string    `json:"status"`
}

type pEndpointPage struct {
	Items      []pEndpoint    `json:"items"`
	NextCursor string         `json:"next_cursor"`
	ByType     map[string]int `json:"by_type"`
	ByStatus   struct{ Pending, Active int }
}

func (f *frig) endpointType() string {
	var typ string
	f.env.Scan(f.t, `SELECT key FROM ctrlz.endpoint_types ORDER BY position LIMIT 1`, nil, &typ)
	return typ
}

func TestEndpointFlow(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A, B := f.env.A, f.env.B
	a := f.makeSession(A.Tenant, A.User)
	b := f.makeSession(B.Tenant, B.User)
	typ := f.endpointType()

	var types struct {
		Types []struct{ Key string } `json:"types"`
	}
	a.get("/endpoint-types").want(200, "").json(&types)
	if len(types.Types) == 0 {
		t.Fatal("no endpoint types")
	}
	var zones struct {
		Zones []string `json:"zones"`
	}
	a.get("/catalog/timezones").want(200, "").json(&zones)
	found := false
	for _, z := range zones.Zones {
		found = found || z == "Asia/Tehran"
	}
	if !found {
		t.Error("Asia/Tehran is not listed")
	}

	// Create: an idempotency key is required, a replay answers the first answer, and another body with the key is refused.
	body := map[string]any{"type": typ, "names": []string{"=cmd|calc", "beta", "alpha"}, "profile_id": A.Profile.String()}
	a.post("/endpoints", body).want(400, "bad_request")
	var created struct {
		Endpoints []pEndpoint `json:"endpoints"`
	}
	a.do("POST", "/endpoints", body, idem("ep-flow-create-1")).want(201, "").json(&created)
	if len(created.Endpoints) != 3 || created.Endpoints[0].Status != "pending" || created.Endpoints[0].AdminState != "enabled" {
		t.Fatalf("created %+v", created.Endpoints)
	}
	var replay struct {
		Endpoints []pEndpoint `json:"endpoints"`
	}
	a.do("POST", "/endpoints", body, idem("ep-flow-create-1")).want(201, "").json(&replay)
	if len(replay.Endpoints) != 3 || replay.Endpoints[0].ID != created.Endpoints[0].ID {
		t.Error("a replay made other Endpoints")
	}
	a.do("POST", "/endpoints", map[string]any{"type": typ, "names": []string{"other"}, "profile_id": A.Profile.String()}, idem("ep-flow-create-1")).want(409, "idempotency_key_reused")
	var n int
	f.env.Scan(f.t, `SELECT count(*) FROM ctrlz.endpoints WHERE tenant_id = $1 AND name IN ('=cmd|calc', 'beta', 'alpha')`, []any{A.Tenant}, &n)
	if n != 3 {
		t.Errorf("%d Endpoints after a create and a replay, want 3", n)
	}

	// B's profile and B's ids are 404 for A, and B sees none of A's Endpoints.
	a.do("POST", "/endpoints", map[string]any{"type": typ, "names": []string{"x"}, "profile_id": B.Profile.String()}, idem("ep-flow-create-2")).want(404, "not_found")
	a.get("/endpoints/"+B.Endpoint.String()).want(404, "not_found")
	var bPage pEndpointPage
	b.get("/endpoints").want(200, "").json(&bPage)
	for _, e := range bPage.Items {
		if e.Name == "beta" {
			t.Error("B lists A's Endpoint")
		}
	}

	// Pages: newest first by default, alphabetical by name, each with its own cursor, and a cursor does not cross orders.
	var p1, p2 pEndpointPage
	a.get("/endpoints?sort=name&limit=2").want(200, "").json(&p1)
	if len(p1.Items) != 2 || p1.NextCursor == "" {
		t.Fatalf("first page %+v", p1)
	}
	a.get("/endpoints?sort=name&limit=2&cursor="+p1.NextCursor).want(200, "").json(&p2)
	if len(p2.Items) == 0 || strings.ToLower(p2.Items[0].Name) <= strings.ToLower(p1.Items[1].Name) {
		t.Errorf("second page %+v after %+v", p2.Items, p1.Items)
	}
	a.get("/endpoints?limit=2&cursor="+p1.NextCursor).want(400, "bad_request")
	var byType pEndpointPage
	a.get("/endpoints?type="+typ+"&q=ALP").want(200, "").json(&byType)
	if len(byType.Items) != 1 || byType.Items[0].Name != "alpha" {
		t.Errorf("filter: %+v", byType.Items)
	}
	if byType.ByStatus.Pending == 0 {
		t.Error("the status facet is empty")
	}

	// CSV: a byte order mark, every cell quoted, a formula cell neutralised, no DoH token.
	r := a.get("/endpoints/export").want(200, "")
	text := string(r.Body)
	if !strings.HasPrefix(text, string(rune(0xFEFF))) || !strings.Contains(text, `"'=cmd|calc"`) || strings.Contains(text, "doh_token") {
		t.Errorf("csv: %.200q", text)
	}
	if ct := r.H.Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
		t.Errorf("content type %q", ct)
	}

	// Patch and the groups.
	id := created.Endpoints[1].ID.String()
	var patched pEndpoint
	a.do("PATCH", "/endpoints/"+id, map[string]any{"name": "gamma", "comment": "note"}).want(200, "").json(&patched)
	if patched.Name != "gamma" {
		t.Errorf("patched %+v", patched)
	}
	a.do("PATCH", "/endpoints/"+id, map[string]any{"require_authorized_ips": true}).want(422, "validation_failed")
	var g struct {
		ID uuid.UUID `json:"id"`
	}
	a.post("/endpoint-groups", map[string]any{"name": "home", "endpoint_ids": []string{id}}).want(201, "").json(&g)
	a.do("PATCH", "/endpoint-groups/"+g.ID.String(), map[string]any{"name": "house"}).want(200, "")
	a.do("DELETE", "/endpoint-groups/"+g.ID.String(), nil).want(204, "")
	a.do("DELETE", "/endpoint-groups/"+g.ID.String(), nil).want(404, "not_found")
	b.do("DELETE", "/endpoint-groups/"+g.ID.String(), nil).want(404, "not_found")
}

// The lock password of a profile an Endpoint leaves, through the routes: the real throttle scopes and the Argon2 gate.
func TestEndpointLockPasswordFlow(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A := f.env.A
	a := f.makeSession(A.Tenant, A.User)
	typ := f.endpointType()
	locked := uuid.Must(uuid.NewV7())
	f.env.Exec(t, `INSERT INTO ctrlz.profiles (tenant_id, id, name) VALUES ($1, $2, 'locked')`, A.Tenant, locked)
	var created struct {
		Endpoints []pEndpoint `json:"endpoints"`
	}
	a.do("POST", "/endpoints", map[string]any{"type": typ, "names": []string{"kids tablet"}, "profile_id": locked.String()}, idem("ep-flow-lock-1")).want(201, "").json(&created)
	ep := created.Endpoints[0].ID.String()
	hash, err := f.hasher.Hash(f.env.Ctx, secret.New("correct horse"))
	if err != nil {
		t.Fatal(err)
	}
	f.env.Exec(t, `UPDATE ctrlz.profiles SET lock_state = 'locked', lock_password_hash = $2 WHERE id = $1`, locked, hash.Reveal())

	// Renaming needs nothing; disabling needs the password.
	a.do("PATCH", "/endpoints/"+ep, map[string]any{"name": "tablet"}).want(200, "")
	a.do("PATCH", "/endpoints/"+ep, map[string]any{"admin_state": "soft_disabled"}).want(423, "profile_locked")
	a.do("PATCH", "/endpoints/"+ep, map[string]any{"admin_state": "soft_disabled",
		"lock_passwords": []map[string]any{{"profile_id": locked.String(), "password": "wrong horse battery"}}}).want(401, "invalid_credentials")
	var state string
	f.env.Scan(t, `SELECT admin_state FROM ctrlz.endpoints WHERE id = $1`, []any{created.Endpoints[0].ID}, &state)
	if state != "enabled" {
		t.Errorf("a refused change left the state %s", state)
	}
	var used, failed int
	f.env.Scan(t, `SELECT count(*) FROM ctrlz.tenant_audit_log WHERE tenant_id = $1 AND action = 'profile.lock_password_failed'`, []any{A.Tenant}, &failed)
	if failed != 1 {
		t.Errorf("%d audit rows for the wrong password", failed)
	}
	// A password that is too short is refused before any charge.
	a.do("PATCH", "/endpoints/"+ep, map[string]any{"admin_state": "soft_disabled",
		"lock_passwords": []map[string]any{{"profile_id": locked.String(), "password": "abc"}}}).want(422, "validation_failed")
	a.do("PATCH", "/endpoints/"+ep, map[string]any{"admin_state": "soft_disabled",
		"lock_passwords": []map[string]any{{"profile_id": locked.String(), "password": "correct horse"}}}).want(200, "")
	f.env.Scan(t, `SELECT count(*) FROM ctrlz.tenant_audit_log WHERE tenant_id = $1 AND action = 'profile.lock_password_used'`, []any{A.Tenant}, &used)
	if used != 1 {
		t.Errorf("%d audit rows for the use", used)
	}
	// Deleting it is the same rule.
	a.post("/endpoints/"+ep+":delete", map[string]any{}).want(423, "profile_locked")
	a.post("/endpoints/"+ep+":delete", map[string]any{"lock_passwords": []map[string]any{{"profile_id": locked.String(), "password": "correct horse"}}}).want(204, "")
	a.get("/endpoints/"+ep).want(404, "not_found")
}
