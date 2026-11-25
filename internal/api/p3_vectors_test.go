package api

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Shared/appleprofile"
	"github.com/Kup1ng/CtrlZ-Shared/identity"
	"github.com/Kup1ng/CtrlZ-Shared/names"

	"github.com/Kup1ng/CtrlZ-Panel/internal/endpoints"
)

// The golden vectors and files of docs/specs/p3-endpoints.md 11.3 driven through the routes: the appleprofile group through both
// Apple routes, the .mobileconfig files of the builder through the download, the identity group through client create and the
// Resolver view, and the schedule groups through the schedule PUT and Grid.

// freshSession is a session of tenant A of its own, so no case meets the rate bucket of an earlier one.
func (r *linkRig) freshSession() *client { return r.f.fresh(r.f.env.A.Tenant, r.f.env.A.User) }

// seedCommon replaces the common domains the Apple builder reads (the current catalog version, or version 0 while none is
// current, spec 7.3) with the list of a vector.
func (r *linkRig) seedCommon(list []string) {
	r.f.t.Helper()
	var version int64
	r.f.env.Scan(r.f.t, `SELECT COALESCE(max(version), 0) FROM ctrlz.catalog_versions WHERE state = 'current'`, nil, &version)
	r.f.env.Exec(r.f.t, `DELETE FROM ctrlz.catalog_common_domains WHERE version = $1`, version)
	for _, d := range list {
		r.f.env.Exec(r.f.t, `INSERT INTO ctrlz.catalog_common_domains (version, pattern) VALUES ($1, $2) ON CONFLICT DO NOTHING`, version, d)
	}
}

// TestAppleProfileVectorsThroughTheRoute: each case of the appleprofile group's apple_expand and apple_hash ops, sent as the
// request body of POST /endpoints/{id}/apple-profile, stores the canonical params and the hash the case expects, or is refused
// as the case says (spec 11.3, T-246, T-247).
func TestAppleProfileVectorsThroughTheRoute(t *testing.T) {
	r := newLinkRig(t)
	f := r.f
	path := "/endpoints/" + r.ep.ID.String() + "/apple-profile"
	stored, refused, hashed := 0, 0, 0
	for _, c := range vectorCases(t, "appleprofile") {
		if c.Op != "apple_expand" && c.Op != "apple_hash" {
			continue
		}
		f.env.Exec(t, `DELETE FROM ctrlz.profile_download_tokens WHERE endpoint_id = $1`, r.ep.ID)
		var common []string
		if len(c.Args) > 0 && c.Args[0] != "" {
			if err := json.Unmarshal([]byte(c.Args[0]), &common); err != nil {
				t.Fatalf("%s: %v", c.ID, err)
			}
		}
		r.seedCommon(common)
		got := r.freshSession().do("POST", path, []byte(c.Input))
		if c.Error {
			if got.Code != 400 && got.Code != 422 {
				t.Errorf("%s (%s): status %d, want a refusal", c.ID, c.Why, got.Code)
				continue
			}
			// A refusal that names a member (apple-018) names the same member and code through the route, when the schema let it
			// as far as the builder's rules.
			if pointer, code, ok := strings.Cut(c.ErrorContains, ": "); ok && strings.HasPrefix(pointer, "/") && got.Code == 422 {
				var fl fieldList
				got.json(&fl)
				if !fl.has(pointer, code) {
					t.Errorf("%s: fields %+v, want %s %s", c.ID, fl.Fields, pointer, code)
				}
			}
			refused++
			continue
		}
		got.want(201, "")
		if c.Op == "apple_hash" {
			var hash string
			f.env.Scan(t, `SELECT encode(params_hash, 'hex') FROM ctrlz.profile_download_tokens WHERE endpoint_id = $1 ORDER BY created_at DESC LIMIT 1`, []any{r.ep.ID}, &hash)
			if hash != c.Expect {
				t.Errorf("%s: params_hash %s, want %s", c.ID, hash, c.Expect)
			}
			hashed++
			continue
		}
		var raw string
		f.env.Scan(t, `SELECT params::text FROM ctrlz.profile_download_tokens WHERE endpoint_id = $1 ORDER BY created_at DESC LIMIT 1`, []any{r.ep.ID}, &raw)
		p, err := appleprofile.ParseParams([]byte(raw))
		if err != nil {
			t.Errorf("%s: the stored params do not read back: %v", c.ID, err)
			continue
		}
		canon, err := p.Canonical()
		if err != nil || string(canon) != c.Expect {
			t.Errorf("%s (%s): stored %s, want %s (%v)", c.ID, c.Why, canon, c.Expect, err)
		}
		stored++
	}
	if stored < 4 || refused < 8 || hashed < 2 {
		t.Fatalf("the appleprofile group gave %d stored, %d refused and %d hashed cases through the route: it is not being read", stored, refused, hashed)
	}
}

// The .mobileconfig of each accepted case equals a checked-in file byte for byte (11.3). The files of internal/mobileconfig are
// written for a fixed Endpoint; the route builds for this one, so the six identifiers, the host, the token, the two addresses
// and the display name of the file are replaced by this Endpoint's before the comparison, and nothing else is.
func TestAppleDownloadEqualsTheCheckedInFiles(t *testing.T) {
	r := newLinkRig(t)
	f := r.f
	var name = "Home phone"
	r.a.do("PATCH", "/endpoints/"+r.ep.ID.String(), map[string]any{"name": name}).want(200, "")
	r.seedCommon(nil)
	const (
		fixedID    = "0197a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b"
		fixedRID   = "abcdefghijklmnopqrstuvwxy2"
		fixedToken = "abcdefghijklmnopqrstuvwxyz234567"
		fixedZone  = "dns.example.com"
	)
	cases := []struct {
		file   string
		params map[string]any
	}{
		{"doh-minimal", map[string]any{"protocol": "doh"}},
		{"dot-minimal", map[string]any{"protocol": "dot"}},
		{"doh-client-full", map[string]any{"client": "kid", "protocol": "doh", "prohibit_disablement": true,
			"excluded_ssids": []string{"Home Wi-Fi", "خانه"}, "excluded_domains": []string{"captive.apple.com", "example.com", "local"}}},
		{"dot-domains-only", map[string]any{"protocol": "dot", "excluded_domains": []string{"example.com"}}},
		{"doh-ssid-only", map[string]any{"protocol": "doh", "excluded_ssids": []string{"Office"}}},
		{"doh-ssid-markup", map[string]any{"protocol": "doh", "excluded_ssids": []string{"<&>]]>", `a"b'c`}}},
	}
	for _, c := range cases {
		client, _ := c.params["client"].(string)
		var view struct {
			Host      string   `json:"host"`
			DohURL    string   `json:"doh_url"`
			Bootstrap []string `json:"bootstrap"`
		}
		query := ""
		if client != "" {
			query = "?client=" + client
		}
		r.freshSession().get("/endpoints/"+r.ep.ID.String()+"/resolvers"+query).want(200, "").json(&view)
		if len(view.Bootstrap) != 2 {
			t.Fatalf("%s: bootstrap %v", c.file, view.Bootstrap)
		}
		token := strings.TrimPrefix(view.DohURL, "https://"+view.Host+"/")

		golden, err := os.ReadFile(filepath.Join("..", "mobileconfig", "testdata", c.file+".mobileconfig"))
		if err != nil {
			t.Fatal(err)
		}
		fixed, err := appleprofile.Identify(fixedID, client)
		if err != nil {
			t.Fatal(err)
		}
		real, err := appleprofile.Identify(r.ep.ID.String(), client)
		if err != nil {
			t.Fatal(err)
		}
		pairs := []string{
			fixed.PayloadIdentifier, real.PayloadIdentifier, fixed.PayloadUUID, real.PayloadUUID,
			fixed.ContentIdentifier, real.ContentIdentifier, fixed.ContentUUID, real.ContentUUID,
			fixed.RootIdentifier, real.RootIdentifier, fixed.RootUUID, real.RootUUID,
			fixedToken, token, fixedRID, r.ep.ResolverID, fixedZone, linkZone,
			"203.0.113.10", view.Bootstrap[0], "203.0.113.11", view.Bootstrap[1],
			">Home phone<", ">" + name + "<",
		}
		want := strings.NewReplacer(pairs...).Replace(string(golden))

		var link pLinkURL
		r.freshSession().post("/endpoints/"+r.ep.ID.String()+"/apple-profile", c.params).want(201, "").json(&link)
		got := r.download(valueOf(t, link.URL)).want(200, "")
		if !bytes.Equal(got.Body, []byte(want)) {
			at := 0
			for at < len(got.Body) && at < len(want) && got.Body[at] == want[at] {
				at++
			}
			lo := max(at-80, 0)
			t.Errorf("%s: the download differs from testdata/%s.mobileconfig at byte %d\n--- got ---\n%.200s\n--- want ---\n%.200s",
				c.file, c.file, at, got.Body[lo:min(len(got.Body), at+120)], want[lo:min(len(want), at+120)])
		}
		f.env.Exec(t, `DELETE FROM ctrlz.profile_download_tokens WHERE endpoint_id = $1`, r.ep.ID)
	}
}

// TestIdentityVectorsThroughTheRoutes: the labels of the slug_client cases through client create (the alias gives the label, or
// is refused when nothing remains), and each client label of the host and path cases through the Resolver view, whose host and
// path parse back to this Endpoint's id, token and the same label (spec 11.3, T-258).
func TestIdentityVectorsThroughTheRoutes(t *testing.T) {
	r := newLinkRig(t)
	f := r.f
	ep := "/endpoints/" + r.ep.ID.String()
	f.env.Exec(t, `UPDATE ctrlz.tenant_entitlements SET max_clients_per_endpoint = 1000 WHERE tenant_id = $1`, f.env.A.Tenant)
	made, refused := 0, 0
	for _, c := range vectorCases(t, "identity") {
		if c.Op != "slug_client" || c.Repeat > 1 {
			continue
		}
		f.env.Exec(t, `DELETE FROM ctrlz.clients WHERE endpoint_id = $1`, r.ep.ID)
		got := r.freshSession().post(ep+"/clients", map[string]any{"alias": c.Input})
		if c.Error {
			if got.Code != 422 && got.Code != 400 {
				t.Errorf("%s (%s): status %d for %q, want a refusal", c.ID, c.Why, got.Code, c.Input)
			}
			refused++
			continue
		}
		var out struct {
			Label string `json:"label"`
		}
		got.want(201, "").json(&out)
		if out.Label != c.Expect {
			t.Errorf("%s (%s): label %q, want %q", c.ID, c.Why, out.Label, c.Expect)
		}
		made++
	}
	if made < 4 || refused < 2 {
		t.Fatalf("the slug cases gave %d labels and %d refusals through the route: they are not being read", made, refused)
	}

	// The labels the host and path cases use, through the view.
	zone, err := names.ParseUser(linkZone)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, c := range vectorCases(t, "identity") {
		var label string
		switch c.Op {
		case "parse_host":
			if _, rest, ok := strings.Cut(c.Expect, " client="); ok && strings.HasPrefix(c.Expect, "resolver ") {
				label = rest
			}
		case "parse_doh_path":
			if _, rest, ok := strings.Cut(c.Expect, " client="); ok {
				label = rest
			}
		}
		if label == "" || seen[label] || !identity.ValidClient(label) {
			continue
		}
		seen[label] = true
		var view struct {
			Host   string `json:"host"`
			DohURL string `json:"doh_url"`
			Client string `json:"client"`
		}
		r.freshSession().get(ep+"/resolvers?client="+label).want(200, "").json(&view)
		h := identity.ParseHost(view.Host, []names.Name{zone})
		if h.RID != r.ep.ResolverID || h.Client != label || view.Client != label {
			t.Errorf("%s: the host %q parses to %+v, want rid %s client %s", c.ID, view.Host, h, r.ep.ResolverID, label)
		}
		p, err := identity.ParseDoHPath(strings.TrimPrefix(view.DohURL, "https://"+view.Host))
		if err != nil || !identity.ValidDoHToken(p.Token) {
			t.Errorf("%s: the path of %q does not parse: %+v %v", c.ID, view.DohURL, p, err)
		}
	}
	if len(seen) < 3 {
		t.Fatalf("%d client labels were read from the host and path cases: they are not being read", len(seen))
	}
}

// scheduleFixture is the part of fixtures/base.json the schedule vectors use: the windows of an Endpoint and the cells they fill.
type scheduleFixture struct {
	Endpoints map[string]struct {
		Schedule *struct {
			BaseOffset int `json:"base_offset"`
			Windows    []struct {
				ID string `json:"id"`
			} `json:"windows"`
			Fill []struct {
				From, To, Window int
			} `json:"fill"`
		} `json:"schedule"`
	} `json:"endpoints"`
}

// TestScheduleVectorsThroughThePUT: the windows of the schedule fixtures (an Endpoint with a Tehran base offset and a week of
// three windows, and one window over the whole week in UTC) go through PUT /endpoints/{id}/schedule, and Grid over the rows that
// were stored gives the cells the fixture fills, byte for byte; and every zone of the schedule-zones group is accepted by the PUT
// while an unknown one is refused (spec 11.3, T-252, T-254).
func TestScheduleVectorsThroughThePUT(t *testing.T) {
	r := newLinkRig(t)
	f := r.f
	raw, err := os.ReadFile(filepath.Join("..", "..", "shared", "vectors", "fixtures", "base.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fx scheduleFixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatal(err)
	}
	A := f.env.A
	profiles := []uuid.UUID{A.Profile, A.Profile2}
	ep := "/endpoints/" + r.ep.ID.String() + "/schedule"
	for _, c := range []struct{ fixture, zone string }{{"e-sched", "Asia/Tehran"}, {"e-client", "UTC"}} {
		s := fx.Endpoints[c.fixture].Schedule
		if s == nil || len(s.Fill) == 0 {
			t.Fatalf("fixture %s has no schedule", c.fixture)
		}
		// Each fill range is one window row, whose profile is the one of its fixture window (a window of the fixture with two
		// ranges is two rows, as the editor splits a window across the week's end, spec 3.2).
		var windows []map[string]any
		profileOfRow := map[int]int{} // start minute to the fixture window's index
		for _, fill := range s.Fill {
			w := (fill.Window - 1) % len(profiles)
			windows = append(windows, map[string]any{"start": fill.From * 30, "end": (fill.To + 1) * 30, "profile_id": profiles[w].String()})
			profileOfRow[fill.From*30] = w
		}
		var out struct {
			Timezone string `json:"timezone"`
			Windows  []struct {
				Start     int       `json:"start"`
				End       int       `json:"end"`
				ProfileID uuid.UUID `json:"profile_id"`
			} `json:"windows"`
		}
		r.freshSession().do("PUT", ep, map[string]any{"timezone": c.zone, "windows": windows}).want(200, "").json(&out)
		if out.Timezone != c.zone || len(out.Windows) != len(windows) {
			t.Fatalf("%s: answer %+v", c.fixture, out)
		}
		var ws []endpoints.Window
		for _, w := range out.Windows {
			ws = append(ws, endpoints.Window{ID: uuid.New(), Start: w.Start, End: w.End})
		}
		got := endpoints.Grid(ws)
		// The grid the fixture describes: cell c holds the 1-based position, by start, of the row that covers it.
		var want [336]byte
		order := make([]int, 0, len(s.Fill))
		for _, fill := range s.Fill {
			order = append(order, fill.From)
		}
		for i := range order {
			for j := i + 1; j < len(order); j++ {
				if order[j] < order[i] {
					order[i], order[j] = order[j], order[i]
				}
			}
		}
		for _, fill := range s.Fill {
			pos := 0
			for k, from := range order {
				if from == fill.From {
					pos = k + 1
				}
			}
			for cell := fill.From; cell <= fill.To; cell++ {
				want[cell] = byte(pos)
			}
		}
		if !bytes.Equal(got[:], want[:]) {
			t.Errorf("%s: the grid of the stored windows is %v, the fixture fills %v", c.fixture, got[:], want[:])
		}
		// A row is the window of the profile its fixture window names.
		for _, w := range out.Windows {
			if want := profiles[profileOfRow[w.Start]]; w.ProfileID != want {
				t.Errorf("%s: the window at %d has profile %s, want %s", c.fixture, w.Start, w.ProfileID, want)
			}
		}
		// The schedule reads back as it was put.
		var back struct {
			Windows []struct{ Start, End int } `json:"windows"`
		}
		r.freshSession().get(ep).want(200, "").json(&back)
		if len(back.Windows) != len(windows) {
			t.Errorf("%s: %d windows read back, want %d", c.fixture, len(back.Windows), len(windows))
		}
	}

	// The zones of the schedule-zones group: every one the compiler will build transitions for is a zone the PUT takes.
	accepted, refused := 0, 0
	for _, c := range vectorCases(t, "schedule-zones") {
		if c.Op != "build_transitions" {
			continue
		}
		got := r.freshSession().do("PUT", ep, map[string]any{"timezone": c.Input, "windows": []any{}})
		if c.Error {
			if got.Code != 400 && got.Code != 422 {
				t.Errorf("%s: the zone %q gave %d, want a refusal", c.ID, c.Input, got.Code)
			}
			refused++
			continue
		}
		got.want(200, "")
		accepted++
	}
	if accepted < 4 || refused < 1 {
		t.Fatalf("the zone cases gave %d accepted and %d refused through the PUT: they are not being read", accepted, refused)
	}
	// Default zone and the empty schedule: a fresh Endpoint is in Asia/Tehran with no window.
	var created struct {
		Endpoints []pEndpoint `json:"endpoints"`
	}
	r.a.do("POST", "/endpoints", map[string]any{"type": f.endpointType(), "names": []string{"default zone"}, "profile_id": A.Profile.String()}, idem("sched-default-zone")).want(201, "").json(&created)
	var sc struct {
		Timezone string `json:"timezone"`
		Windows  []any  `json:"windows"`
	}
	r.freshSession().get("/endpoints/"+created.Endpoints[0].ID.String()+"/schedule").want(200, "").json(&sc)
	if sc.Timezone != "Asia/Tehran" || len(sc.Windows) != 0 {
		t.Errorf("a new Endpoint's schedule is %+v, want Asia/Tehran with no window", sc)
	}
}
