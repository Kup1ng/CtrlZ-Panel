package api

import (
	"slices"
	"testing"

	"github.com/google/uuid"
)

// siblingPlaces are the places of the scenario table that take the id of something a profile owns (a rule, a folder). The id of
// the profile itself and of a catalog key are not among them.
func siblingPlaces() []string {
	return []string{"path:folder_id", "path:rule_id", "body:ids[]", "body:folder_id", "body:dest_folder_id", "body:set.folder_id",
		"body:selector.folder", "query:folder"}
}

// siblingOf builds, for the profile2 of a scenario, the state newScn builds for the first profile: two folders and three rules, with
// the ids under the same keys and the two profiles swapped. A call made with it names its own profile and its own rows
// everywhere, so the one place a test puts an id of the first profile is the only thing that can be refused.
func siblingOf(s *scn) *scn {
	s.f.t.Helper()
	y := &scn{f: s.f, tenant: s.tenant, user: s.user, who: s.who, ids: map[string]string{}, salt: uuid.NewString()[:12], lockPW: s.lockPW}
	y.ids["profile"], y.ids["profile2"] = s.ids["profile2"], s.ids["profile"]
	y.ids["cursor"], y.ids["job"] = s.ids["cursor"], s.ids["job"]
	c := s.take()
	base := "/profiles/" + y.ids["profile"]
	for _, fo := range []struct{ key, name string }{{"folder", "Work"}, {"folder2", "Other"}} {
		var out struct {
			ID uuid.UUID `json:"id"`
		}
		c.post(base+"/folders", map[string]any{"name": fo.name, "kind": "standard"}).want(201, "").json(&out)
		y.ids[fo.key] = out.ID.String()
	}
	c.post(base+"/rules", map[string]any{"patterns": []string{"y1.example", "y2.example", "y3.example"}, "action": "block"}).want(201, "")
	for i, key := range []string{"rule", "rule2", "rule3"} {
		var id string
		s.f.env.Scan(s.f.t, `SELECT id::text FROM ctrlz.rules WHERE profile_id = $1 AND rule_key = $2`, []any{y.ids["profile"], []string{"y1.example", "y2.example", "y3.example"}[i]}, &id)
		y.ids[key] = id
	}
	// The scenario hands its remaining sessions to the sibling: each call of a case takes one.
	y.pool, s.pool = s.pool, nil
	return y
}

// TestS10AnIdOfOneProfileUnderAnotherProfileOfTheSameTenantIsNotFound: row level security cannot tell two profiles of one tenant
// apart, so only the profile bound of each statement keeps a rule or a folder of a locked profile out of the reach of a request
// on an unlocked one (the attack of a child account, spec 3.1, 10.1). For every operation and every place that takes the id of
// a rule or a folder, the id of the locked profile put under the unlocked profile of the same tenant answers 404, and nothing
// the tenant owns changes (digest and outbox).
func TestS10AnIdOfOneProfileUnderAnotherProfileOfTheSameTenantIsNotFound(t *testing.T) {
	w := newWalkRig(t)
	pairs := 0
	for _, c := range p2Cases() {
		var places []string
		for _, loc := range c.locs {
			if slices.Contains(siblingPlaces(), loc) {
				places = append(places, loc)
			}
		}
		if len(places) == 0 {
			continue
		}
		x := w.scn(c)
		y := siblingOf(x)
		// The first profile is the locked one: its rows are what the other profile's request must not reach.
		w.lockRow(x.ids["profile"])
		for _, loc := range places {
			before, box := w.digest(), w.outbox()
			spec := c.call(y, refs{s: y, other: x, at: loc})
			r := y.send(spec)
			if r.Code != 404 {
				t.Errorf("%s: %s %s with the id of the other profile at %s answered %d %s, want 404", c.op, spec.method, spec.path, loc, r.Code, r.Body)
			}
			if d := changed(before, w.digest()); d != "" {
				t.Errorf("%s at %s: a refused request changed %s", c.op, loc, d)
			}
			if added := since(box, w.outbox()); len(added) != 0 {
				t.Errorf("%s at %s: a refused request wrote the outbox rows %+v", c.op, loc, added)
			}
			pairs++
		}
	}
	if pairs < 12 {
		t.Fatalf("only %d places were driven: the sibling walk is not reading the table", pairs)
	}
}
