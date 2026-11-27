package api

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

// T-127 and T-137: what GET /profiles says about each profile beyond its name, through the route with two tenants. The screens
// test the same fields only against the mock, which supplies them ready-made.

type listedEndpoint struct {
	ID   uuid.UUID `json:"id"`
	Name string    `json:"name"`
}

type listedProfile struct {
	ID              uuid.UUID        `json:"id"`
	Name            string           `json:"name"`
	Endpoints       []listedEndpoint `json:"endpoints"`
	DefaultRedirect *struct {
		Kind    string `json:"kind"`
		Country string `json:"country"`
		Label   string `json:"label"`
	} `json:"default_redirect"`
}

func (f *frig) listProfiles(c *client) map[uuid.UUID]listedProfile {
	f.t.Helper()
	var page struct {
		Items []listedProfile `json:"items"`
	}
	c.get("/profiles").want(200, "").json(&page)
	out := map[uuid.UUID]listedProfile{}
	for _, p := range page.Items {
		out[p.ID] = p
	}
	return out
}

func endpointNames(es []listedEndpoint) string {
	var out []string
	for _, e := range es {
		out = append(out, e.Name)
	}
	return strings.Join(out, ",")
}

// TestProfileListDefaultRedirectFlag: the flag on a profile of the list says where the Default Rule redirects (kind, and the
// country or the label of a location) and is absent when the Default Rule does not redirect. Tenant B's list carries its own
// flags and none of A's profiles (spec 9.3 Profile.default_redirect, T-127). Make profileOut set the flag whatever the action
// and the Block and Bypass profiles fail; drop the location lookup and the country and label are lost.
func TestProfileListDefaultRedirectFlag(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A, B := f.env.A, f.env.B
	a := func() *client { return f.fresh(A.Tenant, A.User) }
	b := func() *client { return f.fresh(B.Tenant, B.User) }

	// Frankfurt (country DE, a city) and a label-only location, both on the two nodes of the global pair.
	edge := uuid.Must(uuid.NewV7())
	f.env.Exec(t, `INSERT INTO ctrlz.locations (id, wire_id, label) VALUES ($1, 77, 'edge-lab')`, edge)
	f.env.Exec(t, `INSERT INTO ctrlz.location_availability (node_id, location_id)
		SELECT n.id, l.id FROM ctrlz.nodes n CROSS JOIN ctrlz.locations l`)
	frankfurt := uuid.MustParse("00000000-0000-7000-8000-0000000000a1")

	redirect := func(target map[string]any) map[string]any {
		return map[string]any{"default_rule": map[string]any{"action": "redirect", "target": target}}
	}
	cases := []struct {
		name          string
		body          map[string]any
		kind          string
		country, labl string
		flagged       bool
	}{
		{"to a city", redirect(map[string]any{"kind": "location", "location_id": frankfurt.String()}), "location", "DE", "", true},
		{"to a label", redirect(map[string]any{"kind": "location", "location_id": edge.String()}), "location", "", "edge-lab", true},
		{"to a host", redirect(map[string]any{"kind": "host", "host": "proxy.example.net"}), "host", "", "", true},
		{"to an ip", redirect(map[string]any{"kind": "ip", "ipv4": "192.0.2.7"}), "ip", "", "", true},
		{"to auto", redirect(map[string]any{"kind": "auto"}), "auto", "", "", true},
		{"block", map[string]any{"default_rule": map[string]any{"action": "block"}}, "", "", "", false},
		{"bypass", map[string]any{"default_rule": map[string]any{"action": "bypass"}}, "", "", "", false},
	}
	ids := map[string]uuid.UUID{}
	for _, c := range cases {
		p := a().mustProfile("Default "+c.name, "custom")
		a().do("PATCH", "/profiles/"+p.ID.String()+"/options", c.body).want(200, "")
		ids[c.name] = p.ID
	}
	plain := a().mustProfile("Default plain", "custom").ID
	// Tenant B has one profile that redirects to a host and one to the same Frankfurt as A's.
	bHost := b().mustProfile("B host", "custom")
	b().do("PATCH", "/profiles/"+bHost.ID.String()+"/options", redirect(map[string]any{"kind": "host", "host": "b-proxy.example.net"})).want(200, "")

	got := f.listProfiles(a())
	for _, c := range cases {
		row, ok := got[ids[c.name]]
		if !ok {
			t.Errorf("%s: the profile is not on the list", c.name)
			continue
		}
		if !c.flagged {
			if row.DefaultRedirect != nil {
				t.Errorf("%s: the Default Rule does not redirect and the row has the flag %+v", c.name, *row.DefaultRedirect)
			}
			continue
		}
		d := row.DefaultRedirect
		if d == nil {
			t.Errorf("%s: no flag on a profile whose Default Rule redirects", c.name)
			continue
		}
		if d.Kind != c.kind || d.Country != c.country || d.Label != c.labl {
			t.Errorf("%s: the flag is %+v, want kind %q country %q label %q", c.name, *d, c.kind, c.country, c.labl)
		}
	}
	if row, ok := got[plain]; !ok || row.DefaultRedirect != nil {
		t.Errorf("a new custom profile has the flag %+v (listed %v)", row.DefaultRedirect, ok)
	}

	// Tenant B sees its own flag and none of A's profiles.
	bGot := f.listProfiles(b())
	if row, ok := bGot[bHost.ID]; !ok || row.DefaultRedirect == nil || row.DefaultRedirect.Kind != "host" || row.DefaultRedirect.Country != "" {
		t.Errorf("tenant B's own profile: %+v (listed %v)", row.DefaultRedirect, ok)
	}
	for id := range ids {
		if _, leaked := bGot[ids[id]]; leaked {
			t.Errorf("tenant B lists A's profile %q", id)
		}
	}
	if _, leaked := bGot[plain]; leaked {
		t.Error("tenant B lists A's plain profile")
	}
	if _, leaked := got[bHost.ID]; leaked {
		t.Error("tenant A lists B's profile")
	}
}

// TestProfileListEndpointsInEveryRole: the Endpoints of a profile on the list are those that use it in the base stack, in
// slot 2, in a schedule window and for a client, each once, by name in order, and tenant B never sees A's names and cannot
// push its own onto A's profile (spec 9.3 Profile.endpoints, T-137). Take the DISTINCT out of qProfileEndpointRefs and the
// Endpoint that uses the profile twice is listed twice; drop one UNION ALL arm and one role goes missing.
func TestProfileListEndpointsInEveryRole(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A, B := f.env.A, f.env.B
	a := func() *client { return f.fresh(A.Tenant, A.User) }
	b := func() *client { return f.fresh(B.Tenant, B.User) }
	typ := f.endpointType()

	pAll := a().mustProfile("Used in every role", "custom")
	pBase := a().mustProfile("Used as the base", "custom")
	pNone := a().mustProfile("Used nowhere", "custom")

	create := func(c *client, body map[string]any, key string) pEndpoint {
		t.Helper()
		var made struct {
			Endpoints []pEndpoint `json:"endpoints"`
		}
		body["type"] = typ
		c.do("POST", "/endpoints", body, idem(key+"-"+uuid.NewString()[:8])).want(201, "").json(&made)
		return made.Endpoints[0]
	}
	// mike: the base stack, and a client of its own, so two roles on one Endpoint.
	mike := create(a(), map[string]any{"names": []string{"mike"}, "profile_id": pAll.ID.String()}, "mike")
	a().post("/endpoints/"+mike.ID.String()+"/clients", map[string]any{"alias": "laptop", "profile_id": pAll.ID.String()}).want(201, "")
	// bravo: slot 2.
	create(a(), map[string]any{"names": []string{"bravo"}, "profile_id": pBase.ID.String(), "profile2_id": pAll.ID.String()}, "bravo")
	// kilo: a schedule window.
	kilo := create(a(), map[string]any{"names": []string{"kilo"}, "profile_id": pBase.ID.String()}, "kilo")
	a().do("PUT", "/endpoints/"+kilo.ID.String()+"/schedule", map[string]any{"timezone": "Asia/Tehran",
		"windows": []map[string]any{{"start": 0, "end": 60, "profile_id": pAll.ID.String()}}}).want(200, "")
	// delta: a client in its own right, on the second slot of the client.
	delta := create(a(), map[string]any{"names": []string{"delta"}, "profile_id": pBase.ID.String()}, "delta")
	a().post("/endpoints/"+delta.ID.String()+"/clients", map[string]any{"alias": "phone", "profile_id": pBase.ID.String(), "profile2_id": pAll.ID.String()}).want(201, "")

	// Tenant B names an Endpoint "mike" too, on its own profile.
	bMike := create(b(), map[string]any{"names": []string{"mike"}, "profile_id": B.Profile.String()}, "b-mike")
	b().do("POST", "/endpoints", map[string]any{"type": typ, "names": []string{"x"}, "profile_id": pAll.ID.String()}, idem("p23-b-onto-a")).want(404, "not_found")

	got := f.listProfiles(a())
	if n := endpointNames(got[pAll.ID].Endpoints); n != "bravo,delta,kilo,mike" {
		t.Errorf("the Endpoints of the profile used in every role: %q, want bravo,delta,kilo,mike", n)
	}
	if n := endpointNames(got[pBase.ID].Endpoints); n != "bravo,delta,kilo" {
		t.Errorf("the Endpoints of the profile used as the base: %q, want bravo,delta,kilo", n)
	}
	if n := endpointNames(got[pNone.ID].Endpoints); n != "" {
		t.Errorf("a profile no Endpoint uses lists %q", n)
	}
	for _, e := range got[pAll.ID].Endpoints {
		if e.Name == "mike" && e.ID != mike.ID {
			t.Errorf("A's profile lists the id of another tenant's Endpoint named mike")
		}
	}

	// B sees its own Endpoint on its own profile and nothing of A's.
	bGot := f.listProfiles(b())
	var bAll []string
	for _, p := range bGot {
		for _, e := range p.Endpoints {
			bAll = append(bAll, e.Name)
			if e.Name == "bravo" || e.Name == "kilo" || e.Name == "delta" || (e.Name == "mike" && e.ID != bMike.ID) {
				t.Errorf("tenant B's list holds A's Endpoint %q", e.Name)
			}
		}
	}
	found := false
	for _, e := range bGot[B.Profile].Endpoints {
		found = found || e.ID == bMike.ID
	}
	if !found {
		t.Errorf("tenant B's profile does not list its own Endpoint (all names %v)", bAll)
	}
	if _, leaked := bGot[pAll.ID]; leaked {
		t.Error("tenant B lists A's profile")
	}
}
