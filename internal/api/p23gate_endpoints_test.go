package api

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// T-216: the facets and the filters of GET /endpoints through the route, with two tenants (spec P3 9.3 EndpointPage, 11.4).

type endpointListing struct {
	Items    []pEndpoint    `json:"items"`
	ByType   map[string]int `json:"by_type"`
	ByStatus struct {
		Pending int `json:"pending"`
		Active  int `json:"active"`
	} `json:"by_status"`
}

func listedNames(l endpointListing) []string {
	var out []string
	for _, e := range l.Items {
		out = append(out, e.Name)
	}
	return out
}

// facetsOf reads the same numbers from the table, per tenant, as the oracle of the route.
func (f *frig) facetsOf(tenant uuid.UUID) (byType string, pending, total int) {
	f.t.Helper()
	f.env.Scan(f.t, `SELECT coalesce(string_agg(type || '=' || n, ',' ORDER BY type), '') FROM (SELECT type, count(*) AS n FROM ctrlz.endpoints WHERE tenant_id = $1 GROUP BY type) s`,
		[]any{tenant}, &byType)
	f.env.Scan(f.t, `SELECT count(*) FILTER (WHERE first_query_at IS NULL), count(*) FROM ctrlz.endpoints WHERE tenant_id = $1`, []any{tenant}, &pending, &total)
	return
}

func (l endpointListing) typeString() string {
	var keys []string
	for k := range l.ByType {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", k, l.ByType[k]))
	}
	return strings.Join(parts, ",")
}

// TestEndpointListFacetsAndFilters: by_type holds the exact count of each type and sums to the tenant's total whatever the
// filters are; by_status.pending and .active are exact; status=pending returns exactly the Not Configured Endpoints; the group,
// type, status and q filters combine, in both orders (newest, name); and tenant B's Endpoints are in neither tenant's numbers
// (spec P3 9.3 EndpointPage, 11.4, T-216). Let the facet query follow the filters and the second block of checks fails; count
// the first_query_at test the wrong way round and pending and active swap.
func TestEndpointListFacetsAndFilters(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A, B := f.env.A, f.env.B
	a := func() *client { return f.fresh(A.Tenant, A.User) }
	b := func() *client { return f.fresh(B.Tenant, B.User) }
	var group struct {
		ID uuid.UUID `json:"id"`
	}
	a().post("/endpoint-groups", map[string]any{"name": "home"}).want(201, "").json(&group)

	n := 0
	make1 := func(c *client, typ, name string, profile uuid.UUID, grp *uuid.UUID) uuid.UUID {
		t.Helper()
		body := map[string]any{"type": typ, "names": []string{name}, "profile_id": profile.String()}
		if grp != nil {
			body["group_id"] = grp.String()
		}
		n++
		var made struct {
			Endpoints []pEndpoint `json:"endpoints"`
		}
		c.do("POST", "/endpoints", body, idem(fmt.Sprintf("p23-facets-%d-%s", n, uuid.NewString()[:8]))).want(201, "").json(&made)
		return made.Endpoints[0].ID
	}
	// A: three windows (one in the group, one active), two ios (one in the group, one active), one chrome. Each is its own request,
	// so the order of creation is the order of the newest-first list.
	wAlpha := make1(a(), "windows", "w-alpha", A.Profile, &group.ID)
	wBeta := make1(a(), "windows", "w-beta", A.Profile, nil)
	make1(a(), "windows", "w-gamma", A.Profile, nil)
	iOne := make1(a(), "ios", "i-one", A.Profile, &group.ID)
	iTwo := make1(a(), "ios", "i-two", A.Profile, nil)
	make1(a(), "chrome", "c-one", A.Profile, nil)
	// B: two windows (one active) and a chrome, with names that overlap A's search texts.
	bOne := make1(b(), "windows", "w-beta", B.Profile, nil)
	make1(b(), "windows", "w-b2", B.Profile, nil)
	make1(b(), "chrome", "c-b", B.Profile, nil)
	for _, id := range []uuid.UUID{wBeta, iTwo, bOne} {
		f.env.Exec(t, `UPDATE ctrlz.endpoints SET first_query_at = now() WHERE id = $1`, id)
	}

	get := func(c func() *client, q string) endpointListing {
		t.Helper()
		var l endpointListing
		path := "/endpoints"
		if q != "" {
			path += "?" + q
		}
		c().get(path).want(200, "").json(&l)
		return l
	}

	// The facets, with no filter: the exact counts the test made, the sum of the tenant's rows, and the status split.
	all := get(a, "")
	for typ, want := range map[string]int{"windows": 3, "ios": 2, "chrome": 1} {
		if all.ByType[typ] != want {
			t.Errorf("by_type[%s] = %d, want %d", typ, all.ByType[typ], want)
		}
	}
	byType, pending, total := f.facetsOf(A.Tenant)
	sum := 0
	for _, c := range all.ByType {
		sum += c
	}
	if all.typeString() != byType || sum != total {
		t.Errorf("by_type %s (sum %d) does not match the table: %s (%d rows)", all.typeString(), sum, byType, total)
	}
	if all.ByStatus.Pending != pending || all.ByStatus.Active != total-pending || all.ByStatus.Active < 2 {
		t.Errorf("by_status %+v, the table has %d pending of %d, and at least the two made active", all.ByStatus, pending, total)
	}

	// No filter moves a facet.
	for _, q := range []string{"type=windows", "status=pending", "status=active", "group=" + group.ID.String(), "q=beta", "type=ios&status=active&sort=name"} {
		got := get(a, q)
		if got.typeString() != all.typeString() || got.ByStatus != all.ByStatus {
			t.Errorf("%s: the facets moved to %s %+v, they are %s %+v", q, got.typeString(), got.ByStatus, all.typeString(), all.ByStatus)
		}
	}

	// status=pending is exactly the Not Configured Endpoints, status=active the others, and together they are the tenant's.
	var pendingNames, activeNames string
	f.env.Scan(t, `SELECT coalesce(string_agg(name, ','), '') FROM ctrlz.endpoints WHERE tenant_id = $1 AND first_query_at IS NULL`, []any{A.Tenant}, &pendingNames)
	f.env.Scan(t, `SELECT coalesce(string_agg(name, ','), '') FROM ctrlz.endpoints WHERE tenant_id = $1 AND first_query_at IS NOT NULL`, []any{A.Tenant}, &activeNames)
	if got := strings.Join(listedNames(get(a, "status=pending")), ","); sortedJoin(strings.Split(got, ",")) != sortedJoin(strings.Split(pendingNames, ",")) {
		t.Errorf("status=pending lists %q, the table has %q", got, pendingNames)
	}
	if got := strings.Join(listedNames(get(a, "status=active")), ","); sortedJoin(strings.Split(got, ",")) != sortedJoin(strings.Split(activeNames, ",")) {
		t.Errorf("status=active lists %q, the table has %q", got, activeNames)
	}

	// The filters together, in each order.
	for _, c := range []struct {
		query string
		want  string // in the order of the answer
	}{
		{"type=windows&sort=name", "w-alpha,w-beta,w-gamma"},
		{"type=windows&sort=created", "w-gamma,w-beta,w-alpha"},
		{"type=ios&sort=created", "i-two,i-one"},
		{"type=ios&sort=name&limit=1", "i-one"},
		{"type=windows&q=BETA", "w-beta"},
		{"type=ios&q=beta", ""},
		{"type=windows&status=active", "w-beta"},
		{"type=windows&status=pending&sort=name", "w-alpha,w-gamma"},
		{"group=" + group.ID.String() + "&sort=name", "i-one,w-alpha"},
		{"group=" + group.ID.String() + "&type=ios", "i-one"},
		{"group=" + group.ID.String() + "&status=active", ""},
		{"group=" + group.ID.String() + "&status=pending&type=windows", "w-alpha"},
		{"q=w-&status=active&sort=name", "w-beta"},
	} {
		if got := strings.Join(listedNames(get(a, c.query)), ","); got != c.want {
			t.Errorf("%s: %q, want %q", c.query, got, c.want)
		}
	}

	// Tenant B: its own numbers, and nothing of A's in them or in its lists.
	bAll := get(b, "")
	bType, bPending, bTotal := f.facetsOf(B.Tenant)
	if bAll.typeString() != bType || bAll.ByType["windows"] != 2 || bAll.ByType["chrome"] != 1 || bAll.ByType["ios"] != 0 {
		t.Errorf("tenant B's by_type is %s (the table has %s), want windows 2, chrome 1 and no ios", bAll.typeString(), bType)
	}
	if bAll.ByStatus.Pending != bPending || bAll.ByStatus.Pending+bAll.ByStatus.Active != bTotal {
		t.Errorf("tenant B's by_status %+v against %d pending of %d", bAll.ByStatus, bPending, bTotal)
	}
	if got := strings.Join(listedNames(get(b, "q=beta")), ","); got != "w-beta" {
		t.Errorf("tenant B's search for beta lists %q", got)
	}
	for _, e := range get(b, "").Items {
		if e.ID == wAlpha || e.ID == wBeta || e.ID == iOne || e.ID == iTwo {
			t.Errorf("tenant B lists A's Endpoint %s", e.Name)
		}
	}
	b().get("/endpoints?group="+group.ID.String()).want(404, "not_found")
}
