package api

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/authtest/isolation"
)

// The scenario table of the 37 operations of P2 (docs/specs/p2-profiles.md 8.2, 10.1, 10.2). One table gives each operation
// its state, its success call and the calls that name another tenant's id in one place at a time, and three kinds of test
// read it: the two-tenant harness (TestIsolation), the structural walks of 10.2 (p2walks_test.go) and the flow tests. A
// walk over the table is a walk over every operation of the document, because TestTheScenarioTableHoldsEveryOperation
// compares the two, including the places each operation takes a row id.

// p2Spec is one request.
type p2Spec struct {
	method, path string
	body         any
	hdr          map[string]string
}

// scn is one tenant's state for one scenario: a pool of sessions with a live reauth (a session that is used leaves a row,
// so the pool is made before the digests are read and no call makes one), two profiles, two folders and three rules.
type scn struct {
	f      *frig
	tenant uuid.UUID
	user   uuid.UUID
	who    string
	pool   []*client
	ids    map[string]string
	keys   int
	salt   string // makes a key unique to this scenario: a key lives 24 hours, and another scenario of the tenant must not meet it
	lockPW string
}

// scnPool is how many sessions a scenario holds: the most calls any operation makes in one case (a rules:batch has eight
// places a row id is taken, and one call of its own) plus the set-up.
const scnPool = 14

// reauthed opens a session of the tenant with a live reauth window, the way the isolation harness does.
func (f *frig) reauthed(tenant, user uuid.UUID) *client {
	f.t.Helper()
	c := f.makeSession(tenant, user)
	f.env.Exec(f.t, `UPDATE ctrlz.sessions SET reauth_at = $3 WHERE tenant_id = $1 AND id = (
		SELECT id FROM ctrlz.sessions WHERE user_id = $2 ORDER BY created_at DESC, id DESC LIMIT 1)`, tenant, user, f.ck.now())
	return c
}

// newScn builds the base state of a tenant through the routes: profile and profile2 (both of the type custom), the folders
// folder and folder2, and in the root of the first profile the rules a.example, b.example and c.example (rule, rule2, rule3).
// The names carry the tenant, so an answer that holds one proves it read this tenant's rows.
func newScn(f *frig, tenant, user uuid.UUID, who string) *scn {
	f.t.Helper()
	s := &scn{f: f, tenant: tenant, user: user, who: who, ids: map[string]string{}, lockPW: "lock-password-" + who, salt: uuid.NewString()[:12]}
	for i := 0; i < scnPool; i++ {
		s.pool = append(s.pool, f.reauthed(tenant, user))
	}
	c := s.take()
	s.ids["profile"] = c.mustProfile("Iso "+who, "custom").ID.String()
	s.ids["profile2"] = c.mustProfile("Iso two "+who, "custom").ID.String()
	base := "/profiles/" + s.ids["profile"]
	for _, fo := range []struct{ key, name string }{{"folder", "Work"}, {"folder2", "Other"}} {
		var out struct {
			ID uuid.UUID `json:"id"`
		}
		c.post(base+"/folders", map[string]any{"name": fo.name, "kind": "standard"}).want(201, "").json(&out)
		s.ids[fo.key] = out.ID.String()
	}
	c.post(base+"/rules", map[string]any{"patterns": []string{"a.example", "b.example", "c.example"}, "action": "block"}).want(201, "")
	var page struct {
		Items []struct {
			ID      uuid.UUID `json:"id"`
			Pattern string    `json:"pattern"`
		} `json:"items"`
		Next string `json:"next_cursor"`
	}
	c.get(base+"/rules?sort=pattern").want(200, "").json(&page)
	if len(page.Items) != 3 {
		f.t.Fatalf("the base state has %d rules, want 3", len(page.Items))
	}
	for i, k := range []string{"rule", "rule2", "rule3"} {
		s.ids[k] = page.Items[i].ID.String()
	}
	page.Next = ""
	c.get(base+"/rules?sort=pattern&limit=1").want(200, "").json(&page)
	if page.Next == "" {
		f.t.Fatal("a page of one rule of three has no cursor")
	}
	s.ids["cursor"] = page.Next
	// The seed queues one job for each tenant: the jobs routes read it.
	var job string
	f.env.Scan(f.t, `SELECT id::text FROM ctrlz.batch_jobs WHERE tenant_id = $1 ORDER BY id LIMIT 1`, []any{tenant}, &job)
	s.ids["job"] = job
	return s
}

// take hands out the next session of the pool.
func (s *scn) take() *client {
	s.f.t.Helper()
	if len(s.pool) == 0 {
		s.f.t.Fatalf("the session pool of scenario %s is empty: raise scnPool", s.who)
	}
	c := s.pool[0]
	s.pool = s.pool[1:]
	return c
}

// key is an Idempotency-Key no other request of the scenario used.
func (s *scn) key() map[string]string {
	s.keys++
	return map[string]string{"Idempotency-Key": fmt.Sprintf("iso-%s-%d-%s", s.who, s.keys, s.salt)}
}

// send makes the request with a session of its own.
func (s *scn) send(sp p2Spec) *resp {
	s.f.t.Helper()
	var hdr []map[string]string
	if sp.hdr != nil {
		hdr = append(hdr, sp.hdr)
	}
	return s.take().do(sp.method, sp.path, sp.body, hdr...)
}

// refs says which id each place of a call takes: the scenario's own, except at the one place under test, which takes the
// other tenant's. A call that never names a place cannot be asked about it.
type refs struct {
	s, other *scn
	at       string
}

func (r refs) id(loc, kind string) string {
	if loc == r.at {
		return r.other.ids[kind]
	}
	return r.s.ids[kind]
}

// foreign says the place under test is loc. A location of a Redirect target is a row of a global table, so what this puts
// there is an id that is in no set, and the refusal is the one of a location that is not in the set (spec 4.2).
func (r refs) foreign(loc string) bool { return loc == r.at }

func locTarget() map[string]any {
	return map[string]any{"kind": "location", "location_id": uuid.NewString()}
}

// p2Status is the refusal a place gives: a row of another tenant is 404, a cursor that carries another tenant is 400, a
// location outside the set is 422.
func p2Status(loc string) int {
	switch {
	case loc == "query:cursor":
		return 400
	case strings.HasSuffix(loc, "target.location_id"):
		return 422
	}
	return 404
}

// p2Case is one operation of the scenario table.
type p2Case struct {
	op     string
	locs   []string // the places the operation takes a row id, as the document lists them, sorted
	effect isolation.Effect
	status int
	// writes: the operation changes the content of an existing profile, so its lock must be guard, lock or unlock (S1).
	writes bool
	// prep is the state the call needs beyond the base; the walks run it before they lock the profile.
	prep func(s *scn)
	call func(s *scn, r refs) p2Spec
	sees func(s *scn) []string
	// alt is another body for the same request, for the walks that need a request with another body under one key.
	alt func(s *scn) p2Spec
}

func prof(r refs) string { return "/profiles/" + r.id("path:id", "profile") }

func get(path string) func(*scn, refs) p2Spec {
	return func(*scn, refs) p2Spec { return p2Spec{method: "GET", path: path} }
}

func onProfile(method, suffix string, body any) func(*scn, refs) p2Spec {
	return func(_ *scn, r refs) p2Spec { return p2Spec{method: method, path: prof(r) + suffix, body: body} }
}

func profileID(s *scn) []string { return []string{s.ids["profile"]} }

// lockWith locks the profile through the route, which is what a user does.
func lockWith(s *scn, id string) {
	s.f.t.Helper()
	s.take().post("/profiles/"+id+"/lock", map[string]any{"password": s.lockPW}).want(204, "")
}

const rulesDoc = `{"format":"ctrlz-rules","version":1,"rules":[{"pattern":"up.example","action":"block"}]}`
const profileDoc = `{"format":"ctrlz-profile","version":1,"kind":"custom","name":"Imported","rules":[{"pattern":"imp.example","action":"block"}]}`

// p2Cases is the table. It is a function, as the workspace lint bans package-level state.
func p2Cases() []p2Case {
	return []p2Case{
		{op: "listCatalogFilters", effect: isolation.Shows, status: 200, call: get("/catalog/filters")},
		{op: "listCatalogServices", effect: isolation.Shows, status: 200, call: get("/catalog/services")},
		{op: "listProfiles", effect: isolation.Shows, status: 200, call: get("/profiles"), sees: profileID},
		{op: "createProfile", effect: isolation.Changes, status: 201,
			call: func(*scn, refs) p2Spec {
				return p2Spec{method: "POST", path: "/profiles", body: map[string]any{"name": "Created", "kind": "kids"}}
			}},
		{op: "importProfile", effect: isolation.Changes, status: 201,
			call: func(s *scn, _ refs) p2Spec {
				return p2Spec{method: "POST", path: "/profiles:import", body: map[string]any{"document": b64(profileDoc)}, hdr: s.key()}
			},
			alt: func(s *scn) p2Spec {
				return p2Spec{method: "POST", path: "/profiles:import", body: map[string]any{"document": b64(strings.Replace(profileDoc, "Imported", "Imported two", 1))}}
			}},
		{op: "getProfile", locs: []string{"path:id"}, effect: isolation.Shows, status: 200, call: onProfile("GET", "", nil), sees: profileID},
		{op: "renameProfile", locs: []string{"path:id"}, effect: isolation.Changes, status: 200, writes: true,
			call: onProfile("PATCH", "", map[string]any{"name": "Renamed"})},
		{op: "deleteProfile", locs: []string{"path:id"}, effect: isolation.Changes, status: 204, writes: true, call: onProfile("DELETE", "", nil)},
		{op: "duplicateProfile", locs: []string{"path:id"}, effect: isolation.Changes, status: 201,
			call: func(s *scn, r refs) p2Spec {
				return p2Spec{method: "POST", path: prof(r) + ":duplicate", body: map[string]any{"name": "Copy"}, hdr: s.key()}
			},
			alt: func(s *scn) p2Spec {
				return p2Spec{method: "POST", path: "/profiles/" + s.ids["profile"] + ":duplicate", body: map[string]any{"name": "Copy two"}}
			}},
		{op: "exportProfile", locs: []string{"path:id"}, effect: isolation.Shows, status: 200, call: onProfile("GET", "/export", nil),
			sees: func(s *scn) []string { return []string{"Iso " + s.who} }},
		{op: "disableProfile", locs: []string{"path:id"}, effect: isolation.Changes, status: 200, writes: true,
			call: onProfile("PUT", "/disabled", map[string]any{"for": "1h"})},
		{op: "enableProfile", locs: []string{"path:id"}, effect: isolation.Changes, status: 200, writes: true,
			prep: func(s *scn) {
				s.take().do("PUT", "/profiles/"+s.ids["profile"]+"/disabled", map[string]any{"for": "1h"}).want(200, "")
			},
			call: onProfile("DELETE", "/disabled", nil)},
		{op: "lockProfile", locs: []string{"path:id"}, effect: isolation.Changes, status: 204,
			call: func(s *scn, r refs) p2Spec {
				return p2Spec{method: "POST", path: prof(r) + "/lock", body: map[string]any{"password": s.lockPW, "message": "back at five"}}
			}},
		{op: "unlockProfile", locs: []string{"path:id"}, effect: isolation.Changes, status: 204,
			prep: func(s *scn) { lockWith(s, s.ids["profile"]) },
			call: func(s *scn, r refs) p2Spec {
				return p2Spec{method: "POST", path: prof(r) + "/unlock", body: map[string]any{"password": s.lockPW}}
			}},
		{op: "getProfileLocations", locs: []string{"path:id"}, effect: isolation.Shows, status: 200, call: onProfile("GET", "/locations", nil)},
		{op: "listProfileFilters", locs: []string{"path:id"}, effect: isolation.Shows, status: 200, call: onProfile("GET", "/filters", nil)},
		{op: "setProfileFilter", locs: []string{"path:id"}, effect: isolation.Changes, status: 200, writes: true,
			call: onProfile("PUT", "/filters/malware", map[string]any{"enabled": true})},
		{op: "listProfileServices", locs: []string{"path:id"}, effect: isolation.Shows, status: 200, call: onProfile("GET", "/services", nil)},
		{op: "setProfileService", locs: []string{"body:target.location_id", "path:id"}, effect: isolation.Changes, status: 200, writes: true,
			call: func(_ *scn, r refs) p2Spec {
				body := map[string]any{"enabled": true, "action": "block"}
				if r.foreign("body:target.location_id") {
					body = map[string]any{"enabled": true, "action": "redirect", "target": locTarget()}
				}
				return p2Spec{method: "PUT", path: prof(r) + "/services/youtube", body: body}
			}},
		{op: "deleteProfileService", locs: []string{"path:id"}, effect: isolation.Changes, status: 204, writes: true,
			prep: func(s *scn) {
				s.take().do("PUT", "/profiles/"+s.ids["profile"]+"/services/youtube", map[string]any{"enabled": true, "action": "block"}).want(200, "")
			},
			call: onProfile("DELETE", "/services/youtube", nil)},
		{op: "batchProfileServices", locs: []string{"body:target.location_id", "path:id"}, effect: isolation.Changes, status: 200, writes: true,
			call: func(_ *scn, r refs) p2Spec {
				body := map[string]any{"op": "set", "slugs": []string{"youtube", "netflix"}, "enabled": true, "action": "block"}
				if r.foreign("body:target.location_id") {
					body["action"], body["target"] = "redirect", locTarget()
				}
				return p2Spec{method: "POST", path: prof(r) + "/services:batch", body: body}
			}},
		{op: "listFolders", locs: []string{"path:id"}, effect: isolation.Shows, status: 200, call: onProfile("GET", "/folders", nil),
			sees: func(s *scn) []string { return []string{s.ids["folder"]} }},
		{op: "createFolder", locs: []string{"body:target.location_id", "path:id"}, effect: isolation.Changes, status: 201, writes: true,
			call: func(_ *scn, r refs) p2Spec {
				body := map[string]any{"name": "New", "kind": "standard"}
				if r.foreign("body:target.location_id") {
					body["action"], body["target"] = "redirect", locTarget()
				}
				return p2Spec{method: "POST", path: prof(r) + "/folders", body: body}
			}},
		{op: "updateFolder", locs: []string{"body:target.location_id", "path:folder_id", "path:id"}, effect: isolation.Changes, status: 200, writes: true,
			call: func(_ *scn, r refs) p2Spec {
				body := map[string]any{"name": "Renamed"}
				if r.foreign("body:target.location_id") {
					body["action"], body["target"] = "redirect", locTarget()
				}
				return p2Spec{method: "PATCH", path: prof(r) + "/folders/" + r.id("path:folder_id", "folder"), body: body}
			}},
		{op: "deleteFolder", locs: []string{"path:folder_id", "path:id"}, effect: isolation.Changes, status: 204, writes: true,
			call: func(_ *scn, r refs) p2Spec {
				return p2Spec{method: "DELETE", path: prof(r) + "/folders/" + r.id("path:folder_id", "folder")}
			}},
		{op: "exportFolderRules", locs: []string{"path:folder_id", "path:id"}, effect: isolation.Shows, status: 200,
			call: func(_ *scn, r refs) p2Spec {
				return p2Spec{method: "GET", path: prof(r) + "/folders/" + r.id("path:folder_id", "folder") + "/export"}
			}},
		{op: "uploadFolderRules", locs: []string{"path:folder_id", "path:id"}, effect: isolation.Changes, status: 200, writes: true,
			call: func(s *scn, r refs) p2Spec {
				return p2Spec{method: "POST", path: prof(r) + "/folders/" + r.id("path:folder_id", "folder") + ":upload",
					body: map[string]any{"document": b64(rulesDoc)}, hdr: s.key()}
			},
			alt: func(s *scn) p2Spec {
				return p2Spec{method: "POST", path: "/profiles/" + s.ids["profile"] + "/folders/" + s.ids["folder"] + ":upload",
					body: map[string]any{"document": b64(rulesDoc), "mode": "upsert"}}
			}},
		{op: "listRules", locs: []string{"path:id", "query:cursor", "query:folder"}, effect: isolation.Shows, status: 200,
			call: func(_ *scn, r refs) p2Spec {
				path := prof(r) + "/rules"
				switch {
				case r.foreign("query:cursor"):
					path += "?limit=1&cursor=" + r.id("query:cursor", "cursor")
				case r.foreign("query:folder"):
					path += "?folder=" + r.id("query:folder", "folder")
				}
				return p2Spec{method: "GET", path: path}
			},
			sees: func(s *scn) []string { return []string{s.ids["rule"]} }},
		{op: "createRules", locs: []string{"body:folder_id", "body:target.location_id", "path:id"}, effect: isolation.Changes, status: 201, writes: true,
			call: func(_ *scn, r refs) p2Spec {
				body := map[string]any{"patterns": []string{"new1.example"}, "action": "block"}
				switch {
				case r.foreign("body:folder_id"):
					body["folder_id"] = r.id("body:folder_id", "folder")
				case r.foreign("body:target.location_id"):
					body["action"], body["target"] = "redirect", locTarget()
				}
				return p2Spec{method: "POST", path: prof(r) + "/rules", body: body}
			}},
		{op: "updateRule", locs: []string{"body:folder_id", "body:target.location_id", "path:id", "path:rule_id"}, effect: isolation.Changes, status: 200, writes: true,
			call: func(_ *scn, r refs) p2Spec {
				body := map[string]any{"enabled": false}
				switch {
				case r.foreign("body:folder_id"):
					body["folder_id"] = r.id("body:folder_id", "folder")
				case r.foreign("body:target.location_id"):
					body["action"], body["target"] = "redirect", locTarget()
				}
				return p2Spec{method: "PATCH", path: prof(r) + "/rules/" + r.id("path:rule_id", "rule"), body: body}
			}},
		{op: "deleteRule", locs: []string{"path:id", "path:rule_id"}, effect: isolation.Changes, status: 204, writes: true,
			call: func(_ *scn, r refs) p2Spec {
				return p2Spec{method: "DELETE", path: prof(r) + "/rules/" + r.id("path:rule_id", "rule")}
			}},
		{op: "transferRule", locs: []string{"body:dest_folder_id", "body:dest_profile_id", "body:new_folder.target.location_id", "path:id", "path:rule_id"},
			effect: isolation.Changes, status: 200, writes: true,
			call: func(_ *scn, r refs) p2Spec {
				body := map[string]any{"op": "move", "dest_folder_id": r.id("body:dest_folder_id", "folder2")}
				switch {
				case r.foreign("body:dest_profile_id"):
					body = map[string]any{"op": "copy", "dest_profile_id": r.id("body:dest_profile_id", "profile2"), "dest_root": true}
				case r.foreign("body:new_folder.target.location_id"):
					body = map[string]any{"op": "move", "new_folder": map[string]any{"name": "NF", "kind": "standard", "action": "redirect", "target": locTarget()}}
				}
				return p2Spec{method: "POST", path: prof(r) + "/rules/" + r.id("path:rule_id", "rule") + ":transfer", body: body}
			}},
		{op: "batchRules", locs: []string{"body:dest_folder_id", "body:dest_profile_id", "body:ids[]", "body:new_folder.target.location_id", "body:selector.folder",
			"body:set.folder_id", "body:set.target.location_id", "path:id"}, effect: isolation.Changes, status: 200, writes: true,
			call: func(s *scn, r refs) p2Spec {
				body := map[string]any{"op": "move", "ids": []string{r.id("body:ids[]", "rule"), s.ids["rule2"]}, "dest_folder_id": r.id("body:dest_folder_id", "folder2")}
				switch {
				case r.foreign("body:dest_profile_id"):
					body = map[string]any{"op": "copy", "ids": []string{s.ids["rule"]}, "dest_profile_id": r.id("body:dest_profile_id", "profile2"), "dest_root": true}
				case r.foreign("body:new_folder.target.location_id"):
					body = map[string]any{"op": "move", "ids": []string{s.ids["rule"]},
						"new_folder": map[string]any{"name": "NF", "kind": "standard", "action": "redirect", "target": locTarget()}}
				case r.foreign("body:selector.folder"):
					body = map[string]any{"op": "disable", "selector": map[string]any{"folder": r.id("body:selector.folder", "folder")}}
				case r.foreign("body:set.folder_id"):
					body = map[string]any{"op": "edit", "ids": []string{s.ids["rule"]}, "set": map[string]any{"folder_id": r.id("body:set.folder_id", "folder")}}
				case r.foreign("body:set.target.location_id"):
					body = map[string]any{"op": "edit", "ids": []string{s.ids["rule"]}, "set": map[string]any{"action": "redirect", "target": locTarget()}}
				}
				return p2Spec{method: "POST", path: prof(r) + "/rules:batch", body: body, hdr: s.key()}
			},
			alt: func(s *scn) p2Spec {
				return p2Spec{method: "POST", path: "/profiles/" + s.ids["profile"] + "/rules:batch",
					body: map[string]any{"op": "disable", "ids": []string{s.ids["rule"]}}}
			}},
		{op: "getOptions", locs: []string{"path:id"}, effect: isolation.Shows, status: 200, call: onProfile("GET", "/options", nil)},
		{op: "patchOptions", locs: []string{"body:default_rule.target.location_id", "path:id"}, effect: isolation.Changes, status: 200, writes: true,
			call: func(_ *scn, r refs) p2Spec {
				body := map[string]any{"block_ttl": 60}
				if r.foreign("body:default_rule.target.location_id") {
					body = map[string]any{"default_rule": map[string]any{"action": "redirect", "target": locTarget()}}
				}
				return p2Spec{method: "PATCH", path: prof(r) + "/options", body: body}
			}},
		{op: "getActiveJob", effect: isolation.Shows, status: 200, call: get("/jobs/active"),
			sees: func(s *scn) []string { return []string{s.ids["job"]} }},
		{op: "getJob", locs: []string{"path:id"}, effect: isolation.Shows, status: 200,
			call: func(_ *scn, r refs) p2Spec { return p2Spec{method: "GET", path: "/jobs/" + r.id("path:id", "job")} },
			sees: func(s *scn) []string { return []string{s.ids["job"]} }},
	}
}

// p2Fixtures is the success fixture of every operation of the table, with the Cross calls for each place it takes a row id.
func (e *isoEnv) p2Fixtures() map[string]isolation.Fixture {
	f := e.f
	out := map[string]isolation.Fixture{}
	for _, c := range p2Cases() {
		a := func() *scn { return e.n[isolation.A].sc }
		b := func() *scn { return e.n[isolation.B].sc }
		fx := isolation.Fixture{
			Effect: c.effect, Status: c.status,
			Arrange: func(w isolation.Who) {
				n := e.n[w]
				tenant, user, _ := e.ids(n)
				n.sc = newScn(f, tenant, user, w.String())
				if c.prep != nil {
					c.prep(n.sc)
				}
			},
			Call: func() isolation.Result {
				return result(b().send(c.call(b(), refs{s: b(), other: a()})))
			},
		}
		if c.sees != nil {
			fx.Sees = func() []string { return c.sees(b()) }
		}
		if len(c.locs) > 0 {
			cross := func(loc string) func() isolation.Result {
				return func() isolation.Result {
					return result(b().send(c.call(b(), refs{s: b(), other: a(), at: loc})))
				}
			}
			fx.Cross, fx.CrossStatus = cross(c.locs[0]), p2Status(c.locs[0])
			if len(c.locs) > 1 {
				fx.CrossAt, fx.CrossAtStatus = map[string]func() isolation.Result{}, map[string]int{}
				for _, loc := range c.locs[1:] {
					fx.CrossAt[loc] = cross(loc)
					fx.CrossAtStatus[loc] = p2Status(loc)
				}
			}
		}
		out[c.op] = fx
	}
	return out
}

// TestTheScenarioTableHoldsEveryOperation: the table has a case for each of the 37 operations of the profile routes and for
// no other, and the places a case varies are the places the document takes a row id, so a route added or a field added to a
// body cannot slip past the walks (spec 10.1, 10.2).
func TestTheScenarioTableHoldsEveryOperation(t *testing.T) {
	takes := opsThatTakeAnID(t)
	cases := p2Cases()
	seen := map[string]bool{}
	for _, c := range cases {
		if seen[c.op] {
			t.Errorf("%s has two cases", c.op)
		}
		seen[c.op] = true
		if want := takes[c.op]; !slices.Equal(c.locs, want) {
			t.Errorf("%s: the case varies %v, the document takes a row id in %v", c.op, c.locs, want)
		}
		if !slices.IsSorted(c.locs) {
			t.Errorf("%s: its places are not sorted", c.op)
		}
	}
	if len(cases) != 37 {
		t.Errorf("the table has %d cases, want the 37 operations of spec 8.2", len(cases))
	}
}

// TestACatalogKeyInAPathIsNotARowReference: a path value the document marks x-ctrlz-rowref false (a filter id, a service
// slug) is no place a row of another tenant can be named, and one with no mark still is (P2, B8).
func TestACatalogKeyInAPathIsNotARowReference(t *testing.T) {
	takes := opsThatTakeAnID(t)
	for _, op := range []string{"setProfileFilter", "setProfileService", "deleteProfileService"} {
		for _, loc := range takes[op] {
			if loc == "path:filter_id" || loc == "path:slug" {
				t.Errorf("%s lists %s, a key of a global catalog", op, loc)
			}
		}
	}
	for _, op := range []string{"deleteFolder", "deleteRule"} {
		if !slices.Contains(takes[op], "path:id") {
			t.Errorf("%s no longer lists its profile id: %v", op, takes[op])
		}
	}
}
