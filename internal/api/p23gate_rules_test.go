package api

import (
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// T-196: the filters of GET /profiles/{id}/rules through the route, with two tenants. The screen test of the same row checks
// only that the mock receives the parameters.

type listedRule struct {
	ID      uuid.UUID `json:"id"`
	Key     string    `json:"key"`
	Action  string    `json:"action"`
	Enabled bool      `json:"enabled"`
}

// rulePages reads every page of a query to the end and returns the keys in page order, and fails on a repeated rule.
func rulePages(t *testing.T, c func() *client, base, query string) []string {
	t.Helper()
	var keys []string
	seen := map[uuid.UUID]bool{}
	cursor := ""
	for page := 0; page < 20; page++ {
		path := base + "?limit=2"
		if query != "" {
			path += "&" + query
		}
		if cursor != "" {
			path += "&cursor=" + url.QueryEscape(cursor)
		}
		var out struct {
			Items      []listedRule `json:"items"`
			NextCursor string       `json:"next_cursor"`
		}
		c().get(path).want(200, "").json(&out)
		for _, r := range out.Items {
			if seen[r.ID] {
				t.Errorf("%s: the rule %s is on two pages", query, r.Key)
			}
			seen[r.ID] = true
			keys = append(keys, r.Key)
		}
		if out.NextCursor == "" {
			return keys
		}
		cursor = out.NextCursor
	}
	t.Fatalf("%s: more than 20 pages of two", query)
	return nil
}

func sortedJoin(in []string) string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return strings.Join(out, ",")
}

// TestRulesListFiltersThroughTheRoute: q in Unicode and in Punycode finds the same IDN rule; status enabled, disabled and
// expired; action block, bypass, redirect and inherit; the root and a folder; each filter combined with each sort and walked
// page by page; and tenant B's rules, which carry the same names, never appear in A's answers and the other way round (spec 8.3
// RulePage, 10.4 Rules, T-196). Make the status filter ignore the expiry and enabled lists the expired rule; make q skip the
// A-label conversion and the Unicode query finds nothing.
func TestRulesListFiltersThroughTheRoute(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A, B := f.env.A, f.env.B
	a := func() *client { return f.fresh(A.Tenant, A.User) }
	b := func() *client { return f.fresh(B.Tenant, B.User) }
	p := a().mustProfile("Rules list", "custom")
	base := "/profiles/" + p.ID.String() + "/rules"
	var folder struct {
		ID uuid.UUID `json:"id"`
	}
	a().post("/profiles/"+p.ID.String()+"/folders", map[string]any{"name": "Work", "kind": "standard", "action": "block"}).want(201, "").json(&folder)

	create := func(c *client, base string, body map[string]any) string {
		t.Helper()
		var out struct {
			Rules []struct {
				Key string `json:"key"`
			} `json:"rules"`
		}
		c.post(base, body).want(201, "").json(&out)
		if len(out.Rules) != 1 {
			t.Fatalf("created %d rules", len(out.Rules))
		}
		return out.Rules[0].Key
	}
	host := map[string]any{"kind": "host", "host": "proxy.example.net"}
	idn := create(a(), base, map[string]any{"patterns": []string{"bücher.example"}, "action": "block"})
	alpha := create(a(), base, map[string]any{"patterns": []string{"alpha.example.com"}, "action": "block"})
	beta := create(a(), base, map[string]any{"patterns": []string{"beta.example.com"}, "action": "bypass", "enabled": false})
	gamma := create(a(), base, map[string]any{"patterns": []string{"gamma.example.com"}, "action": "redirect", "target": host})
	delta := create(a(), base, map[string]any{"patterns": []string{"delta.example.com"}, "action": "inherit", "folder_id": folder.ID.String()})
	inside := create(a(), base, map[string]any{"patterns": []string{"inside.example.com"}, "action": "block", "folder_id": folder.ID.String()})
	// An expired rule: the route refuses a past expires_at, so the row is planted, as the clock passing its expiry would leave it.
	expired := "expired.example.com"
	f.env.Exec(t, `INSERT INTO ctrlz.rules (tenant_id, profile_id, rule_key, match_kind, action, expires_at) VALUES ($1, $2, $3, 'domain', 'block', $4)`,
		A.Tenant, p.ID, expired, f.ck.now().Add(-time.Hour))
	if !strings.HasPrefix(idn, "xn--") {
		t.Fatalf("the IDN rule is stored as %q, want its A-label", idn)
	}

	// Tenant B holds rules with the same names, in a profile of its own.
	pb := b().mustProfile("Rules list B", "custom")
	bBase := "/profiles/" + pb.ID.String() + "/rules"
	bAlpha := create(b(), bBase, map[string]any{"patterns": []string{"alpha.example.com"}, "action": "block"})
	bOnly := create(b(), bBase, map[string]any{"patterns": []string{"only-b.example.com"}, "action": "block"})

	all := []string{idn, alpha, beta, gamma, delta, inside, expired}
	cases := []struct {
		name, query string
		want        []string
	}{
		{"q in Unicode", "q=" + url.QueryEscape("bücher.example"), []string{idn}},
		{"q in Punycode", "q=" + url.QueryEscape(idn), []string{idn}},
		{"q by one Unicode label", "q=" + url.QueryEscape("bücher"), []string{idn}},
		{"q in upper case", "q=ALPHA", []string{alpha}},
		{"q on a shared suffix", "q=example.com", []string{alpha, beta, gamma, delta, inside, expired}},
		{"q with no match", "q=nothing-here", nil},
		{"status enabled", "status=enabled", []string{idn, alpha, gamma, delta, inside}},
		{"status disabled", "status=disabled", []string{beta}},
		{"status expired", "status=expired", []string{expired}},
		{"action block", "action=block", []string{idn, alpha, inside, expired}},
		{"action bypass", "action=bypass", []string{beta}},
		{"action redirect", "action=redirect", []string{gamma}},
		{"action inherit", "action=inherit", []string{delta}},
		{"the root", "folder=root", []string{idn, alpha, beta, gamma, expired}},
		{"a folder", "folder=" + folder.ID.String(), []string{delta, inside}},
		{"no filter", "", all},
		{"action and status", "action=block&status=enabled", []string{idn, alpha, inside}},
		{"folder and action", "folder=" + folder.ID.String() + "&action=block", []string{inside}},
		{"q and status", "q=example.com&status=enabled", []string{alpha, gamma, delta, inside}},
		{"all four", "q=example&action=block&status=enabled&folder=root", []string{idn, alpha}},
	}
	for _, c := range cases {
		for _, order := range []string{"pattern", "created", "updated"} {
			q := c.query
			if q != "" {
				q += "&"
			}
			q += "sort=" + order
			got := rulePages(t, a, base, q)
			if sortedJoin(got) != sortedJoin(c.want) {
				t.Errorf("%s (sort %s): got %v, want %v", c.name, order, got, c.want)
			}
		}
	}

	// Another tenant's rules never appear, though the names are the same, and its profile and folder ids are 404.
	for _, key := range rulePages(t, a, base, "q=alpha") {
		if key != alpha {
			t.Errorf("A's search for alpha returned %q", key)
		}
	}
	if bGot := rulePages(t, b, bBase, ""); sortedJoin(bGot) != sortedJoin([]string{bAlpha, bOnly}) {
		t.Errorf("tenant B lists %v, want its two rules", bGot)
	}
	aIDs := map[uuid.UUID]bool{}
	var page struct {
		Items []listedRule `json:"items"`
	}
	a().get(base+"?q=alpha").want(200, "").json(&page)
	for _, r := range page.Items {
		aIDs[r.ID] = true
	}
	b().get(bBase+"?q=alpha").want(200, "").json(&page)
	for _, r := range page.Items {
		if aIDs[r.ID] {
			t.Errorf("the same rule id %s is in both tenants' answers", r.ID)
		}
	}
	b().get(base).want(404, "not_found")
	b().get(bBase+"?folder="+folder.ID.String()).want(404, "not_found")
	a().get(base+"?folder="+uuid.NewString()).want(404, "not_found")
}
