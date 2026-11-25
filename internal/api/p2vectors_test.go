package api

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/google/uuid"

	shared "github.com/Kup1ng/CtrlZ-Shared/locations"
	"github.com/Kup1ng/CtrlZ-Shared/vectors"

	"github.com/Kup1ng/CtrlZ-Panel/internal/locations"
)

// The golden vectors of spec 10.3 driven through the routes: the tokens group through rule create, the upload group through
// the upload route, the sets of locations through GET /profiles/{id}/locations over the in-memory catalog, and the
// no-redirect group (D42) through every operation that takes a pattern (10.2 S4).

func vectorCases(t *testing.T, group string) []vectors.TextCase {
	t.Helper()
	g, err := vectors.ReadGroup(group)
	if err != nil {
		t.Fatal(err)
	}
	var cases []vectors.TextCase
	if err := json.Unmarshal(g.Cases, &cases); err != nil {
		t.Fatal(err)
	}
	return cases
}

// fresh is a session of its own, so no case meets the rate bucket of an earlier one.
func (f *frig) fresh(tenant, user uuid.UUID) *client { return f.makeSession(tenant, user) }

// TestTokenVectorsThroughTheRoute: each case of the tokens group through POST /profiles/{id}/rules gives the case's rule_key,
// match_kind and negated read back, or the case's error as a pattern code (spec 10.3, T-180, T-181).
func TestTokenVectorsThroughTheRoute(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A := f.env.A
	p := f.fresh(A.Tenant, A.User).mustProfile("Tokens", "custom")
	base := "/profiles/" + p.ID.String()
	valid, refused := 0, 0
	for _, c := range vectorCases(t, "tokens") {
		if c.Op != "rules_parse" || c.Repeat > 1 || strings.TrimSpace(c.Input) == "" {
			continue
		}
		f.env.Exec(t, `DELETE FROM ctrlz.rules WHERE profile_id = $1`, p.ID)
		r := f.fresh(A.Tenant, A.User).post(base+"/rules", map[string]any{"patterns": []string{c.Input}, "action": "block"})
		if c.Error {
			if r.Code == 400 {
				continue // the schema of the request refuses the characters before the parser sees them
			}
			var fl fieldList
			r.want(422, "validation_failed").json(&fl)
			if len(fl.Fields) != 1 || fl.Fields[0].Name != "/patterns/0" || !strings.HasPrefix(fl.Fields[0].Code, "pattern_") {
				t.Errorf("%s (%q): fields %+v, want one pattern code", c.ID, c.Input, fl.Fields)
			}
			refused++
			continue
		}
		var out struct {
			Rules []struct {
				Key       string `json:"key"`
				MatchKind string `json:"match_kind"`
				Negated   bool   `json:"negated"`
			} `json:"rules"`
		}
		r.want(201, "").json(&out)
		if len(out.Rules) != 1 {
			t.Errorf("%s: %d rules", c.ID, len(out.Rules))
			continue
		}
		for _, part := range strings.Fields(c.Expect) {
			k, v, _ := strings.Cut(part, "=")
			// The route answers the key, the kind and the sign; the other members of an expectation (the literal counts) are the
			// compiler's and have no field of a rule.
			got, known := map[string]string{"key": out.Rules[0].Key, "kind": out.Rules[0].MatchKind, "negated": fmt.Sprint(out.Rules[0].Negated)}[k]
			if known && got != v {
				t.Errorf("%s (%q): %s = %q, want %q", c.ID, c.Input, k, got, v)
			}
		}
		valid++
	}
	if valid < 10 || refused < 15 {
		t.Fatalf("the tokens group gave %d valid and %d refused cases through the route: it is not being read", valid, refused)
	}
}

// TestUploadVectorsThroughTheRoute: each case of the upload group, with its existing items seeded, gives the case's counts and
// resulting rows through the upload route (spec 10.3, T-195), a key repeated inside one file included: the route merges it as
// two uploads in a row, as the bare merge does.
func TestUploadVectorsThroughTheRoute(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A := f.env.A
	p := f.fresh(A.Tenant, A.User).mustProfile("Upload vectors", "custom")
	base := "/profiles/" + p.ID.String()
	folders := map[string]string{}
	for _, n := range []string{"f1", "f2"} {
		var out struct {
			ID uuid.UUID `json:"id"`
		}
		f.fresh(A.Tenant, A.User).post(base+"/folders", map[string]any{"name": n, "kind": "standard"}).want(201, "").json(&out)
		folders[n] = out.ID.String()
	}
	cases := vectorCases(t, "upload")
	if len(cases) < 8 {
		t.Fatalf("the upload group has %d cases", len(cases))
	}
	for _, c := range cases {
		f.env.Exec(t, `DELETE FROM ctrlz.rules WHERE profile_id = $1`, p.ID)
		var items []string
		for _, a := range c.Args {
			parts := strings.Split(a, "|")
			if len(parts) != 4 {
				t.Fatalf("%s: bad item %q", c.ID, a)
			}
			switch parts[0] {
			case "E":
				f.env.Exec(t, `INSERT INTO ctrlz.rules (tenant_id, profile_id, folder_id, rule_key, match_kind, action) VALUES ($1, $2, $3, $4, 'domain', $5)`,
					A.Tenant, p.ID, folders[parts[2]], parts[1], parts[3])
			default:
				items = append(items, fmt.Sprintf(`{"pattern":%q,"action":%q}`, parts[1], parts[3]))
			}
		}
		doc := `{"format":"ctrlz-rules","version":1,"rules":[` + strings.Join(items, ",") + `]}`
		var in struct{ folder string }
		for _, a := range c.Args {
			if parts := strings.Split(a, "|"); parts[0] == "I" {
				in.folder = parts[2]
				break
			}
		}
		up := base + "/folders/" + folders[in.folder] + ":upload"
		body := map[string]any{"document": b64(doc), "mode": c.Input}
		r := f.fresh(A.Tenant, A.User).do("POST", up, body, idem("up-"+c.ID))
		var res struct{ Created, Updated, Skipped, Conflict int }
		r.want(200, "").json(&res)
		var rows string
		f.env.Scan(t, `SELECT coalesce(string_agg(r.rule_key || ':' || fo.name || ':' || r.action, ',' ORDER BY r.rule_key), '') FROM ctrlz.rules r JOIN ctrlz.rule_folders fo ON fo.id = r.folder_id WHERE r.profile_id = $1`, []any{p.ID}, &rows)
		got := fmt.Sprintf("created=%d updated=%d skipped=%d conflicts=%d merged=%s", res.Created, res.Updated, res.Skipped, res.Conflict, rows)
		if got != c.Expect {
			t.Errorf("%s: %s\nwant %s", c.ID, got, c.Expect)
		}
	}
}

// TestLocationSetVectorsThroughTheRoute: the cases of locations-sets whose answer does not need an Endpoint (the global pair
// decides) drive GET /profiles/{id}/locations over the in-memory catalog built from the case, and the route answers the keys the
// case expects (spec 10.3, T-063, T-166, T-176). The cases that name a pair are the library's own: a profile has an Endpoint
// only from P3.
func TestLocationSetVectorsThroughTheRoute(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A := f.env.A
	p := f.fresh(A.Tenant, A.User).mustProfile("Locations", "custom")
	driven := 0
	for _, c := range vectorCases(t, "locations-sets") {
		if c.Op != "loc_allowed" {
			continue
		}
		m := locations.Memory{Nodes: map[string][]shared.Key{}}
		usesPair := false
		seenKey := map[shared.Key]bool{}
		for _, a := range c.Args {
			k, v, _ := strings.Cut(a, "=")
			switch k {
			case "pairs":
				usesPair = usesPair || v != ""
			case "global":
				a, b, _ := strings.Cut(v, "-")
				m.GlobalA, m.GlobalB = a, b
			default:
				for _, key := range memKeys(v) {
					m.Nodes[k] = append(m.Nodes[k], key)
					if !seenKey[key] {
						seenKey[key] = true
						m.Locations = append(m.Locations, key)
					}
				}
			}
		}
		if usesPair || m.GlobalA == "" {
			continue
		}
		f.deps.Locations = m
		f.setLimiter(f.deps.Limiter)
		var set struct {
			Locations []struct {
				Country, City, Label string
			} `json:"locations"`
		}
		f.fresh(A.Tenant, A.User).get("/profiles/"+p.ID.String()+"/locations").want(200, "").json(&set)
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
		sort.Strings(got)
		want := strings.Split(c.Expect, ",")
		if c.Expect == "" {
			want = nil
		}
		sort.Strings(want)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%s: the route answers %v, want %v", c.ID, got, want)
		}
		driven++
	}
	if driven < 1 {
		t.Fatal("no case of locations-sets was driven through the route")
	}
}

func memKeys(s string) []shared.Key {
	var out []shared.Key
	if s == "" {
		return out
	}
	for _, p := range strings.Split(s, ",") {
		if strings.HasPrefix(p, "~") {
			out = append(out, shared.Key{Label: p[1:]})
			continue
		}
		cc, city, _ := strings.Cut(p, ":")
		out = append(out, shared.Key{Country: cc, City: city})
	}
	return out
}

// TestNoRedirectVectorsThroughEveryOperationThatTakesAPattern: S4. Each case of the no-redirect group, with the entries it names in
// the list, through the rule create route, the upload route and the import route, gives the case's answer at the pointer of
// that route, and a refusal writes nothing (spec 10.2 S4, T-525).
func TestNoRedirectVectorsThroughEveryOperationThatTakesAPattern(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A := f.env.A
	p := f.fresh(A.Tenant, A.User).mustProfile("D42", "custom")
	base := "/profiles/" + p.ID.String()
	var fold struct {
		ID uuid.UUID `json:"id"`
	}
	f.fresh(A.Tenant, A.User).post(base+"/folders", map[string]any{"name": "In", "kind": "standard"}).want(201, "").json(&fold)
	host := map[string]any{"kind": "host", "host": "proxy.example.net"}
	cases := vectorCases(t, "no-redirect")
	ran := 0
	for _, c := range cases {
		f.env.Exec(t, `DELETE FROM ctrlz.catalog_no_redirect_domain WHERE pattern IN ('digikala.com', 'shop.example.com')`)
		for _, a := range c.Args {
			scope, name, _ := strings.Cut(a, ":")
			f.env.Exec(t, `INSERT INTO ctrlz.catalog_no_redirect_domain (pattern, scope) VALUES ($1, $2) ON CONFLICT (pattern) DO UPDATE SET scope = EXCLUDED.scope`, name, scope)
		}
		f.env.Exec(t, `DELETE FROM ctrlz.rules WHERE profile_id = $1`, p.ID)
		type route struct {
			name, pointer string
			send          func() *resp
		}
		ruleDoc := fmt.Sprintf(`{"pattern":%q,"action":"redirect","target":{"kind":"host","host":"proxy.example.net"}}`, c.Input)
		routes := []route{
			{"create", "/patterns/0", func() *resp {
				return f.fresh(A.Tenant, A.User).post(base+"/rules", map[string]any{"patterns": []string{c.Input}, "action": "redirect", "target": host})
			}},
			{"upload", "/rules/0/pattern", func() *resp {
				return f.fresh(A.Tenant, A.User).do("POST", base+"/folders/"+fold.ID.String()+":upload",
					map[string]any{"document": b64(`{"format":"ctrlz-rules","version":1,"rules":[` + ruleDoc + `]}`)}, idem(uuid.NewString()))
			}},
			{"import", "/rules/0/pattern", func() *resp {
				return f.fresh(A.Tenant, A.User).do("POST", "/profiles:import",
					map[string]any{"document": b64(`{"format":"ctrlz-profile","version":1,"kind":"custom","name":"D42 import","rules":[` + ruleDoc + `]}`)}, idem(uuid.NewString()))
			}},
		}
		for _, rt := range routes {
			r := rt.send()
			if c.Error && r.Code == 400 {
				continue // the schema of the request refuses these characters before the parser sees them
			}
			switch {
			case c.Error:
				var fl fieldList
				r.want(422, "validation_failed").json(&fl)
				ok := false
				for _, x := range fl.Fields {
					ok = ok || strings.HasPrefix(x.Code, "pattern_")
				}
				if !ok {
					t.Errorf("%s via %s: fields %+v, want a pattern code", c.ID, rt.name, fl.Fields)
				}
			case c.Expect == "iranian_name":
				var fl fieldList
				r.want(422, "validation_failed").json(&fl)
				if !fl.has(rt.pointer, "iranian_name") {
					t.Errorf("%s via %s: fields %+v, want iranian_name at %s", c.ID, rt.name, fl.Fields, rt.pointer)
				}
			default:
				if r.Code < 200 || r.Code > 299 {
					t.Errorf("%s via %s: %d %s, want it allowed", c.ID, rt.name, r.Code, r.Body)
				}
			}
			ran++
			f.env.Exec(t, `DELETE FROM ctrlz.profiles WHERE tenant_id = $1 AND name = 'D42 import'`, A.Tenant)
			f.env.Exec(t, `DELETE FROM ctrlz.rules WHERE profile_id = $1`, p.ID)
		}
	}
	if ran < 3*len(cases)/2 {
		t.Fatalf("only %d runs for %d cases", ran, len(cases))
	}
}

// TestD42ThroughTheServiceRoutesAndTheGrandfatheredRows: S4's service walk and its grandfathered rows. A Redirect on a service
// whose catalog row says redirect_allowed is false is refused on the single and the batch route with iranian_name, and one
// on a service that allows it is accepted. A row that already holds an Iranian Redirect stays as it is under every
// write that leaves its checked values alone and carries nothing (switch it off, a comment), and Copy, Move to another
// profile, Duplicate and Import of the profile's own export refuse it and write nothing (spec 3.7, 10.2 S4).
func TestD42ThroughTheServiceRoutesAndTheGrandfatheredRows(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A := f.env.A
	p := f.fresh(A.Tenant, A.User).mustProfile("D42 services", "custom")
	base := "/profiles/" + p.ID.String()
	p2 := f.fresh(A.Tenant, A.User).mustProfile("D42 other", "custom")
	host := map[string]any{"kind": "host", "host": "proxy.example.net"}
	redirect := map[string]any{"enabled": true, "action": "redirect", "target": host}
	var fl fieldList
	f.fresh(A.Tenant, A.User).do("PUT", base+"/services/digikala", redirect).want(422, "validation_failed").json(&fl)
	// The pointer is the slug of the request, so the UI can name the service it refuses (spec 3.6); on the batch route it is
	// the index of the Iranian one among the slugs.
	if !fl.has("/slugs/0", "iranian_name") {
		t.Errorf("a Redirect on an Iranian service: fields %+v, want iranian_name at /slugs/0", fl.Fields)
	}
	var bfl fieldList
	f.fresh(A.Tenant, A.User).post(base+"/services:batch", map[string]any{"op": "set", "slugs": []string{"youtube", "snapp"}, "enabled": true, "action": "redirect", "target": host}).want(422, "validation_failed").json(&bfl)
	if !bfl.has("/slugs/1", "iranian_name") || bfl.has("/slugs/0", "iranian_name") {
		t.Errorf("a batch Redirect on youtube and snapp: fields %+v, want iranian_name at /slugs/1 only", bfl.Fields)
	}
	f.fresh(A.Tenant, A.User).do("PUT", base+"/services/youtube", redirect).want(200, "")
	var n int
	f.env.Scan(t, `SELECT count(*) FROM ctrlz.profile_services WHERE profile_id = $1 AND service_slug IN ('digikala', 'snapp')`, []any{p.ID}, &n)
	if n != 0 {
		t.Fatalf("a refused service write left %d rows", n)
	}

	// A grandfathered Iranian Redirect, planted as a catalog update would have made it.
	f.env.Exec(t, `INSERT INTO ctrlz.rules (tenant_id, profile_id, rule_key, match_kind, action, target_kind, target_host) VALUES ($1, $2, 'shop.ir', 'domain', 'redirect', 'host', 'proxy.example.net')`, A.Tenant, p.ID)
	f.env.Exec(t, `INSERT INTO ctrlz.profile_services (tenant_id, profile_id, service_slug, action, target_kind, target_host) VALUES ($1, $2, 'snapp', 'redirect', 'host', 'proxy.example.net')`, A.Tenant, p.ID)
	var rid uuid.UUID
	f.env.Scan(t, `SELECT id FROM ctrlz.rules WHERE profile_id = $1 AND rule_key = 'shop.ir'`, []any{p.ID}, &rid)
	rule := base + "/rules/" + rid.String()
	f.fresh(A.Tenant, A.User).do("PATCH", rule, map[string]any{"enabled": false}).want(200, "")
	f.fresh(A.Tenant, A.User).do("PATCH", rule, map[string]any{"comment": "kept"}).want(200, "")
	f.fresh(A.Tenant, A.User).do("PUT", base+"/services/snapp", map[string]any{"enabled": false, "action": "redirect", "target": host}).want(200, "")

	digestOf := func() string {
		var s string
		f.env.Scan(t, `SELECT (SELECT count(*) FROM ctrlz.profiles WHERE tenant_id = $1)::text || '/' || (SELECT count(*) FROM ctrlz.rules WHERE tenant_id = $1)::text || '/' ||
			(SELECT count(*) FROM ctrlz.rules WHERE profile_id = $2)::text`, []any{A.Tenant, p2.ID}, &s)
		return s
	}
	before := digestOf()
	refused := func(name string, r *resp) {
		t.Helper()
		var fs fieldList
		r.want(422, "validation_failed").json(&fs)
		found := false
		for _, x := range fs.Fields {
			found = found || x.Code == "iranian_name"
		}
		if !found {
			t.Errorf("%s: fields %+v, want iranian_name", name, fs.Fields)
		}
	}
	refused("copy", f.fresh(A.Tenant, A.User).do("POST", rule+":transfer", map[string]any{"op": "copy", "dest_profile_id": p2.ID, "dest_root": true}))
	refused("move", f.fresh(A.Tenant, A.User).do("POST", rule+":transfer", map[string]any{"op": "move", "dest_profile_id": p2.ID, "dest_root": true}))
	refused("duplicate", f.fresh(A.Tenant, A.User).do("POST", base+":duplicate", map[string]any{"name": "D42 copy"}, idem(uuid.NewString())))
	exp := f.fresh(A.Tenant, A.User).get(base+"/export").want(200, "")
	refused("import", f.fresh(A.Tenant, A.User).do("POST", "/profiles:import",
		map[string]any{"document": b64(strings.Replace(string(exp.Body), `"name":"D42 services"`, `"name":"D42 again"`, 1))}, idem(uuid.NewString())))
	if after := digestOf(); after != before {
		t.Errorf("a refused Copy, Move, Duplicate or Import wrote something: %s, was %s", after, before)
	}
}
