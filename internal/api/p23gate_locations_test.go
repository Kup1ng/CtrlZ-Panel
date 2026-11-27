package api

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/google/uuid"

	shared "github.com/Kup1ng/CtrlZ-Shared/locations"
)

// T-063 and T-166: the locations-sets vectors that need an Endpoint (a pair override) or a service (a regional limit), driven
// through GET /profiles/{id}/locations over real Endpoints, a real pair override and the real catalog tables. The cases that
// the global pair alone decides are TestLocationSetVectorsThroughTheRoute, over the in-memory catalog.

// locRig is the catalog of one test: four nodes (the two the seed makes, which are the global pair, and two more), the
// locations the cases name, and two Endpoints of tenant A that carry the pair override of a case.
type locRig struct {
	f    *frig
	t    *testing.T
	node map[string]uuid.UUID // N1 to N4
	eps  []uuid.UUID          // two Endpoints of tenant A
	p    pProfile             // the profile under test
	park pProfile             // where an Endpoint rests when a case gives the profile no pair
}

func newLocRig(f *frig) *locRig {
	t := f.t
	A := f.env.A
	r := &locRig{f: f, t: t, node: map[string]uuid.UUID{
		"N1": uuid.MustParse("00000000-0000-7000-8000-0000000000c1"),
		"N2": uuid.MustParse("00000000-0000-7000-8000-0000000000c2"),
		"N3": uuid.MustParse("00000000-0000-7000-8000-0000000000c3"),
		"N4": uuid.MustParse("00000000-0000-7000-8000-0000000000c4"),
	}}
	// The seed holds nodes 1 and 2, which are the global pair; the cases need four.
	f.env.Exec(t, `INSERT INTO ctrlz.nodes (id, slot, name, status, dns_advertised_ip) VALUES
		('00000000-0000-7000-8000-0000000000c3', 3, 'node-3', 'active', '192.0.2.3'),
		('00000000-0000-7000-8000-0000000000c4', 4, 'node-4', 'active', '192.0.2.4')`)
	a := f.fresh(A.Tenant, A.User)
	r.p = a.mustProfile("Locations of a pair", "custom")
	r.park = a.mustProfile("Resting place", "custom")
	var made struct {
		Endpoints []pEndpoint `json:"endpoints"`
	}
	a.do("POST", "/endpoints", map[string]any{"type": f.endpointType(), "names": []string{"pair-one", "pair-two"}, "profile_id": r.park.ID.String()},
		idem("p23gate-locs-"+uuid.NewString())).want(201, "").json(&made)
	if len(made.Endpoints) != 2 {
		t.Fatalf("made %d Endpoints, want 2", len(made.Endpoints))
	}
	for _, e := range made.Endpoints {
		r.eps = append(r.eps, e.ID)
	}
	return r
}

// loc finds the location row of a key, or makes it. The unique index on (country, city) is case-sensitive, so the catalog can
// hold Tehran and tehran as two rows; each spelling gets its own row, so the cases locset-007 to 009 reach the route as two
// rows and only the fold in the library and the route makes them one place.
func (r *locRig) loc(k shared.Key) uuid.UUID {
	r.t.Helper()
	var where string
	var args []any
	switch {
	case k.Country == "":
		where, args = `country_code IS NULL AND label = $1`, []any{k.Label}
	case k.City == "":
		where, args = `country_code = $1 AND city IS NULL`, []any{k.Country}
	default:
		where, args = `country_code = $1 AND city = $2`, []any{k.Country, k.City}
	}
	var found string
	r.f.env.Scan(r.t, `SELECT coalesce(min(id::text), '') FROM ctrlz.locations WHERE `+where, args, &found)
	if found != "" {
		return uuid.MustParse(found)
	}
	id := uuid.Must(uuid.NewV7())
	var wire int
	r.f.env.Scan(r.t, `SELECT coalesce(max(wire_id), 0) + 1 FROM ctrlz.locations`, nil, &wire)
	var cc, city, label any
	if k.Country == "" {
		label = k.Label
	} else {
		cc = k.Country
		if k.City != "" {
			city = k.City
		}
	}
	r.f.env.Exec(r.t, `INSERT INTO ctrlz.locations (id, wire_id, country_code, city, label) VALUES ($1, $2, $3, $4, $5)`, id, wire, cc, city, label)
	return id
}

// nodes replaces what every node has with the given sets, by node name.
func (r *locRig) nodes(sets map[string][]shared.Key) {
	r.t.Helper()
	r.f.env.Exec(r.t, `DELETE FROM ctrlz.location_availability`)
	for name, keys := range sets {
		id, ok := r.node[name]
		if !ok {
			r.t.Fatalf("a case names the node %q", name)
		}
		for _, k := range keys {
			r.f.env.Exec(r.t, `INSERT INTO ctrlz.location_availability (node_id, location_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`, id, r.loc(k))
		}
	}
}

// usePairs puts the profile on the Endpoints with these pair overrides, one Endpoint for each pair; the Endpoints the pairs do
// not need go back to the resting profile on the global pair.
func (r *locRig) usePairs(role string, pairs [][2]string) {
	r.t.Helper()
	if len(pairs) > len(r.eps) {
		r.t.Fatalf("%d pairs, the rig has %d Endpoints", len(pairs), len(r.eps))
	}
	for i, id := range r.eps {
		if i >= len(pairs) {
			r.f.env.Exec(r.t, `UPDATE ctrlz.endpoints SET profile_id = $2, profile2_id = NULL, pair_override_node_a = NULL, pair_override_node_b = NULL WHERE id = $1`, id, r.park.ID)
			continue
		}
		a, b := r.node[pairs[i][0]], r.node[pairs[i][1]]
		if role == "profile2" {
			r.f.env.Exec(r.t, `UPDATE ctrlz.endpoints SET profile_id = $2, profile2_id = $3, pair_override_node_a = $4, pair_override_node_b = $5 WHERE id = $1`, id, r.park.ID, r.p.ID, a, b)
		} else {
			r.f.env.Exec(r.t, `UPDATE ctrlz.endpoints SET profile_id = $2, profile2_id = NULL, pair_override_node_a = $3, pair_override_node_b = $4 WHERE id = $1`, id, r.p.ID, a, b)
		}
	}
}

// setOf reads the route: the keys of the answer in the notation of the vectors, in lower case and sorted (the one row of a
// place shows one of its spellings, and which one is the library's own vector, so the comparison here is folded).
func setOf(r *resp) []string {
	r.t.Helper()
	var set struct {
		Locations []struct{ Country, City, Label string } `json:"locations"`
	}
	r.want(200, "").json(&set)
	var got []string
	for _, l := range set.Locations {
		switch {
		case l.Country == "":
			got = append(got, "~"+l.Label)
		case l.City == "":
			got = append(got, l.Country)
		default:
			got = append(got, l.Country+":"+l.City)
		}
	}
	return foldedList(got)
}

func foldedList(in []string) []string {
	var out []string
	for _, s := range in {
		if s = strings.ToLower(s); s != "" {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func splitExpect(s string) []string { return foldedList(strings.Split(s, ",")) }

// TestLocationSetVectorsOverRealEndpointsAndPairOverrides: every loc_allowed case of locations-sets, pair cases included, through
// the route. Each case writes what its nodes have, puts the profile on one Endpoint for each of its pairs (a real Endpoint with
// a real pair override), and the route answers what the case expects. A tenant B whose Endpoint sits on a pair of its own sees
// its own set and cannot read A's profile at all (spec 10.3, 4.2, T-063). Remove the loop over pairs in usePairs and the pair
// cases answer the global pair's set; drop the profile2_id arm of qProfilePairs and the slot-2 check below fails.
func TestLocationSetVectorsOverRealEndpointsAndPairOverrides(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A, B := f.env.A, f.env.B
	r := newLocRig(f)
	b := f.fresh(B.Tenant, B.User)
	// Tenant B's one Endpoint is on the pair of nodes 3 and 4, with B's own profile.
	f.env.Exec(t, `UPDATE ctrlz.endpoints SET pair_override_node_a = $2, pair_override_node_b = $3 WHERE id = $1`, B.Endpoint, r.node["N3"], r.node["N4"])
	base := "/profiles/" + r.p.ID.String() + "/locations"
	pairCases, driven := 0, 0
	for _, c := range vectorCases(t, "locations-sets") {
		if c.Op != "loc_allowed" {
			continue
		}
		sets := map[string][]shared.Key{}
		var pairs [][2]string
		for _, a := range c.Args {
			k, v, _ := strings.Cut(a, "=")
			switch k {
			case "pairs":
				for _, p := range strings.Split(v, ",") {
					if p == "" {
						continue
					}
					x, y, _ := strings.Cut(p, "-")
					pairs = append(pairs, [2]string{x, y})
				}
			case "global":
				// The seed's global pair is nodes 1 and 2, the pair every case names.
				if v != "N1-N2" {
					t.Fatalf("%s: the global pair is %s, the rig has N1-N2", c.ID, v)
				}
			default:
				sets[k] = memKeys(v)
			}
		}
		r.nodes(sets)
		r.usePairs("profile", pairs)
		got := setOf(f.fresh(A.Tenant, A.User).get(base))
		if want := splitExpect(c.Expect); strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%s (%s): the route answers %v, want %v", c.ID, c.Why, got, want)
		}
		if len(pairs) > 0 {
			pairCases++
		}
		driven++
		if c.ID == "locset-003" {
			// B's pair is 3-4 and holds US; A's profile is on 1-2. Neither set shows in the other tenant's answer, and B cannot
			// name A's profile.
			if bset := setOf(b.get("/profiles/" + B.Profile.String() + "/locations")); strings.Join(bset, ",") != "us" {
				t.Errorf("%s: tenant B's set is %v, want [us] from its own pair", c.ID, bset)
			}
			b.get(base).want(404, "not_found")
		}
	}
	// 009, 008, 007 hold one place in three spellings, so every pair case counts: the two-pair cases need both Endpoints.
	if driven < 9 || pairCases < 7 {
		t.Fatalf("%d cases driven, %d with a pair: the loop did not reach the cases it is for", driven, pairCases)
	}

	// The second slot counts like the first (SC 10.1: an Endpoint uses a profile in any role).
	r.nodes(map[string][]shared.Key{
		"N1": memKeys("DE:Frankfurt,US"), "N2": memKeys("DE:Frankfurt,US"),
		"N3": memKeys("DE:Frankfurt"), "N4": memKeys("DE:Frankfurt,US"),
	})
	r.usePairs("profile", nil)
	if got := setOf(f.fresh(A.Tenant, A.User).get(base)); strings.Join(got, ",") != "de:frankfurt,us" {
		t.Fatalf("the global pair's set is %v", got)
	}
	r.usePairs("profile2", [][2]string{{"N3", "N4"}})
	if got := setOf(f.fresh(A.Tenant, A.User).get(base)); strings.Join(got, ",") != "de:frankfurt" {
		t.Errorf("a profile on the second slot of an Endpoint with a pair override has the set %v, want de:frankfurt", got)
	}
}

// regionsOf is the region list a service holds for a set of keys: a country, or CC-City, one for each key (a label-only
// location is never in a limited service's set, so it has no region).
func regionsOf(keys []shared.Key) []string {
	out := []string{}
	for _, k := range keys {
		switch {
		case k.Country == "":
		case k.City == "":
			out = append(out, k.Country)
		default:
			out = append(out, k.Country+"-"+k.City)
		}
	}
	return out
}

// TestServiceVectorsThroughTheLocationsRoute: the loc_service and loc_selection cases of locations-sets through
// GET /profiles/{id}/locations?services=, with the regions written on real catalog rows. One slug limits the profile's set to
// the service's regions (a country, a city, no limit, none), and two slugs give the intersection of what each service may use
// (spec 4.2, 10.3, T-166). Make the route ignore ?services= and the limited cases return the whole set; make it use the union
// of two services and the selection cases return too much.
func TestServiceVectorsThroughTheLocationsRoute(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A := f.env.A
	r := newLocRig(f)
	r.usePairs("profile", nil) // no Endpoint uses the profile: the global pair, nodes 1 and 2, decides
	base := "/profiles/" + r.p.ID.String() + "/locations"
	setRegions := func(slug string, regions []string) {
		t.Helper()
		f.env.Exec(t, `UPDATE ctrlz.catalog_service SET allowed_regions = $2 WHERE slug = $1`, slug, regions)
	}
	both := func(keys []shared.Key) {
		t.Helper()
		r.nodes(map[string][]shared.Key{"N1": keys, "N2": keys})
	}
	services, selections := 0, 0
	for _, c := range vectorCases(t, "locations-sets") {
		switch c.Op {
		case "loc_service":
			both(memKeys(c.Input))
			var regions []string // nil: the column is NULL, no limit
			if c.Args[0] != "*" {
				regions = []string{}
				if c.Args[0] != "" {
					regions = strings.Split(c.Args[0], ",")
				}
			}
			setRegions("youtube", regions)
			got := setOf(f.fresh(A.Tenant, A.User).get(base + "?services=youtube"))
			if want := splitExpect(c.Expect); strings.Join(got, ",") != strings.Join(want, ",") {
				t.Errorf("%s (%s): the route answers %v, want %v", c.ID, c.Why, got, want)
			}
			services++
		case "loc_selection":
			var all []shared.Key
			for _, a := range c.Args {
				all = append(all, memKeys(a)...)
			}
			both(all)
			setRegions("youtube", regionsOf(memKeys(c.Args[0])))
			setRegions("hulu", regionsOf(memKeys(c.Args[1])))
			got := setOf(f.fresh(A.Tenant, A.User).get(base + "?services=youtube,hulu"))
			if want := splitExpect(c.Expect); strings.Join(got, ",") != strings.Join(want, ",") {
				t.Errorf("%s (%s): the route answers %v, want %v", c.ID, c.Why, got, want)
			}
			selections++
		}
	}
	if services < 5 || selections < 2 {
		t.Fatalf("%d service cases and %d selection cases were driven", services, selections)
	}

	// The bounds of the query. A slug the catalog does not have, and more than 100 slugs, are each a field error at /services,
	// and neither reads the profile's set.
	var fl fieldList
	f.fresh(A.Tenant, A.User).get(base+"?services=youtube,no-such-service").want(422, "validation_failed").json(&fl)
	if !fl.has("/services", "unknown") {
		t.Errorf("an unknown slug: fields %+v, want unknown at /services", fl.Fields)
	}
	slugs := func(n int) string {
		out := make([]string, n)
		for i := range out {
			out[i] = fmt.Sprintf("s%d", i)
		}
		return strings.Join(out, ",")
	}
	fl = fieldList{}
	f.fresh(A.Tenant, A.User).get(base+"?services="+slugs(101)).want(422, "validation_failed").json(&fl)
	if !fl.has("/services", "exceeded") {
		t.Errorf("101 slugs: fields %+v, want exceeded at /services", fl.Fields)
	}
	// 100 slugs are within the bound: the first unknown one is what the route names, not the count.
	fl = fieldList{}
	f.fresh(A.Tenant, A.User).get(base+"?services="+slugs(100)).want(422, "validation_failed").json(&fl)
	if !fl.has("/services", "unknown") {
		t.Errorf("100 slugs: fields %+v, want unknown at /services (the bound is above 100)", fl.Fields)
	}
}
