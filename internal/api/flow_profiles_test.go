package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
)

// The profile routes end to end (docs/specs/p2-profiles.md 8, 10.4): create from a type, rules and folders, the D42
// refusal, export and import, idempotency, the lock, and the two-tenant cases.

type pProfile struct {
	ID     uuid.UUID `json:"id"`
	Name   string    `json:"name"`
	Kind   string    `json:"kind"`
	Locked bool      `json:"locked"`
	Counts struct {
		Filters, Services, Rules, Options int
	} `json:"counts"`
}

func (c *client) mustProfile(name, kind string) pProfile {
	c.f.t.Helper()
	var out struct {
		Profile pProfile `json:"profile"`
		Flagged int      `json:"flagged"`
	}
	c.post("/profiles", map[string]any{"name": name, "kind": kind}).want(201, "").json(&out)
	return out.Profile
}

func idem(key string) map[string]string { return map[string]string{"Idempotency-Key": key} }

func TestProfileFlow(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A, B := f.env.A, f.env.B
	a := f.makeSession(A.Tenant, A.User)
	b := f.makeSession(B.Tenant, B.User)

	// The catalog is readable and holds the 20 Native filters.
	var cf struct {
		Filters []struct{ ID, Kind string } `json:"filters"`
	}
	a.get("/catalog/filters").want(200, "").json(&cf)
	native := 0
	for _, x := range cf.Filters {
		if x.Kind == "native" {
			native++
		}
	}
	if native != 20 {
		t.Fatalf("native filters = %d, want 20", native)
	}

	// A type creates a profile whose content is the preset (the seeded tenants already hold profiles of their own).
	var list struct {
		Items []pProfile `json:"items"`
	}
	a.get("/profiles").want(200, "").json(&list)
	seeded := len(list.Items)
	kids := a.mustProfile("Kids", "kids")
	if kids.Counts.Filters == 0 || kids.Counts.Options != 2 {
		t.Fatalf("a Kids profile has %+v", kids.Counts)
	}
	a.get("/profiles").want(200, "").json(&list)
	if len(list.Items) != seeded+1 {
		t.Fatalf("profiles = %d, want %d", len(list.Items), seeded+1)
	}
	// Another tenant sees none of it, and its ids are 404.
	b.get("/profiles").want(200, "").json(&list)
	for _, p := range list.Items {
		if p.ID == kids.ID {
			t.Fatal("tenant B lists a profile of A")
		}
	}
	b.get("/profiles/"+kids.ID.String()).want(404, "not_found")
	b.get("/profiles/"+kids.ID.String()+"/rules").want(404, "not_found")
	b.do("PATCH", "/profiles/"+kids.ID.String(), map[string]any{"name": "x"}).want(404, "not_found")

	// Rules: a batch of patterns, a duplicate is refused with its pointer, a folder.
	base := "/profiles/" + kids.ID.String()
	a.post(base+"/rules", map[string]any{"patterns": []string{"example.com", "*.example.org", "@IR"}, "action": "block"}).want(201, "")
	r := a.post(base+"/rules", map[string]any{"patterns": []string{"new.example", "example.com"}, "action": "block"}).want(422, "validation_failed")
	var ve struct {
		Fields []struct{ Name, Code string } `json:"fields"`
	}
	r.json(&ve)
	if len(ve.Fields) != 1 || ve.Fields[0].Name != "/patterns/1" || ve.Fields[0].Code != "exists" {
		t.Fatalf("fields = %+v", ve.Fields)
	}
	var rules struct {
		Items []struct {
			ID      uuid.UUID `json:"id"`
			Pattern string    `json:"pattern"`
		} `json:"items"`
	}
	a.get(base+"/rules").want(200, "").json(&rules)
	if len(rules.Items) != 3 {
		t.Fatalf("rules = %d (the failed create wrote %v)", len(rules.Items), rules.Items)
	}
	// D42: a Redirect on an Iranian name is refused, a Redirect on another name is accepted.
	host := map[string]any{"kind": "host", "host": "proxy.example.net"}
	a.post(base+"/rules", map[string]any{"patterns": []string{"shop.ir"}, "action": "redirect", "target": host}).want(422, "validation_failed")
	a.post(base+"/rules", map[string]any{"patterns": []string{"news.example"}, "action": "redirect", "target": host}).want(201, "")
	var fold struct {
		ID uuid.UUID `json:"id"`
	}
	a.post(base+"/folders", map[string]any{"name": "Work", "kind": "standard", "action": "block"}).want(201, "").json(&fold)
	a.post(base+"/rules:batch", map[string]any{"op": "move", "ids": []uuid.UUID{rules.Items[0].ID}, "dest_folder_id": fold.ID}).want(400, "") // the header is required

	// Idempotency: the same key and the same body give one effect and one answer.
	body := map[string]any{"op": "move", "ids": []uuid.UUID{rules.Items[0].ID}, "dest_folder_id": fold.ID}
	first := a.do("POST", base+"/rules:batch", body, idem("move-1")).want(200, "")
	again := a.do("POST", base+"/rules:batch", body, idem("move-1")).want(200, "")
	if !jsonEqual(first.Body, again.Body) {
		t.Fatalf("a replay differs: %s vs %s", first.Body, again.Body)
	}
	other := map[string]any{"op": "move", "ids": []uuid.UUID{rules.Items[1].ID}, "dest_folder_id": fold.ID}
	a.do("POST", base+"/rules:batch", other, idem("move-1")).want(409, "idempotency_key_reused")
	// A rule id of tenant A under tenant B's own profile is 404.
	bp := b.mustProfile("Mine", "custom")
	b.do("POST", "/profiles/"+bp.ID.String()+"/rules:batch", body, idem("x-1")).want(404, "not_found")

	// Export is byte-stable, and an import of it gives the same export under another name.
	e1 := a.get(base+"/export").want(200, "")
	e2 := a.get(base+"/export").want(200, "")
	if !bytes.Equal(e1.Body, e2.Body) {
		t.Fatal("two exports of one profile differ")
	}
	imp := map[string]any{"document": base64.StdEncoding.EncodeToString(bytes.Replace(e1.Body, []byte(`"name":"Kids"`), []byte(`"name":"Kids copy"`), 1))}
	var created struct {
		Profile pProfile `json:"profile"`
	}
	a.do("POST", "/profiles:import", imp, idem("imp-1")).want(201, "").json(&created)
	a.do("POST", "/profiles:import", imp, idem("imp-1")).want(201, "")
	a.get("/profiles").want(200, "").json(&list)
	if len(list.Items) != seeded+2 {
		t.Fatalf("an import replayed once made %d profiles, want %d in all", len(list.Items), seeded+2)
	}
	e3 := a.get("/profiles/"+created.Profile.ID.String()+"/export").want(200, "")
	if !bytes.Equal(bytes.Replace(e3.Body, []byte(`"name":"Kids copy"`), []byte(`"name":"Kids"`), 1), e1.Body) {
		t.Fatalf("import then export changed the document:\n%s\n%s", e1.Body, e3.Body)
	}
	// A document with a problem names it by pointer and echoes nothing of the file.
	bad := base64.StdEncoding.EncodeToString([]byte(`{"format":"ctrlz-profile","version":1,"kind":"custom","name":"x","rules":[{"pattern":"bad..name","action":"block"}]}`))
	r = a.do("POST", "/profiles:import", map[string]any{"document": bad}, idem("imp-2")).want(422, "validation_failed")
	r.json(&ve)
	if len(ve.Fields) != 1 || ve.Fields[0].Name != "/rules/0/pattern" {
		t.Fatalf("fields = %+v", ve.Fields)
	}
	// A heavy request is checked after its session and its class (spec 6.5), so the 400 of a missing header costs a token of the
	// session's own 10 a minute like any other: the minute moves before the next four.
	f.ck.add(time.Minute)
	for _, doc := range []string{`{"format":"nope","version":1}`, `{"format":"ctrlz-profile","version":9,"kind":"custom"}`, `{"a":1,"a":2}`, `[1]`} {
		a.do("POST", "/profiles:import", map[string]any{"document": base64.StdEncoding.EncodeToString([]byte(doc))}, idem(fmt.Sprintf("bad-%d", len(doc)))).want(422, "validation_failed")
	}

	f.ck.add(time.Minute)
	// Options and filters.
	a.do("PATCH", base+"/options", map[string]any{"block_ttl": 60, "ecs": map[string]any{"mode": "none"}}).want(200, "")
	a.do("PATCH", base+"/options", map[string]any{"block_ttl": 0}).want(400, "")
	a.do("PUT", base+"/filters/malware", map[string]any{"enabled": true, "mode": "nope"}).want(422, "validation_failed")
	a.do("PUT", base+"/filters/malware", map[string]any{"enabled": true, "mode": "strict"}).want(200, "")

	// The lock: it needs a live reauth, refuses every guarded write with 423, and only its password lifts it.
	lock := map[string]any{"password": "p4ssw0rd!", "message": "back at 5"}
	a.post(base+"/lock", lock).want(403, "reauth_required")
	a.reauthPassword(pwA).want(204, "")
	a.post(base+"/lock", map[string]any{"password": "12"}).want(422, "validation_failed")
	a.post(base+"/lock", lock).want(204, "")
	a.post(base+"/lock", lock).want(409, "conflict")
	a.do("PATCH", base, map[string]any{"name": "Nope"}).want(423, "profile_locked")
	a.post(base+"/rules", map[string]any{"patterns": []string{"late.example"}, "action": "block"}).want(423, "profile_locked")
	a.do("DELETE", base, nil).want(423, "profile_locked")
	a.get(base+"/export").want(200, "")
	a.do("POST", base+":duplicate", map[string]any{"name": "Kids 2"}, idem("dup-1")).want(201, "")
	a.post(base+"/unlock", map[string]any{"password": "wrong-one"}).want(401, "invalid_credentials")
	a.post(base+"/unlock", map[string]any{"password": "p4ssw0rd!"}).want(204, "")
	a.post(base+"/rules", map[string]any{"patterns": []string{"late.example"}, "action": "block"}).want(201, "")
	for _, action := range []string{"profile.lock", "profile.unlock", "profile.unlock_failed"} {
		var n int
		f.env.Scan(t, `SELECT count(*) FROM ctrlz.tenant_audit_log WHERE tenant_id = $1 AND action = $2`, []any{A.Tenant, action}, &n)
		if n != 1 {
			t.Errorf("audit rows of %s = %d, want 1", action, n)
		}
	}
	// A profile is deleted, and then it is gone.
	a.do("DELETE", base, nil).want(204, "")
	a.get(base).want(404, "not_found")
}

func jsonEqual(a, b []byte) bool {
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	p, _ := json.Marshal(x)
	q, _ := json.Marshal(y)
	return bytes.Equal(p, q)
}
