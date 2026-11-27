package profiles_test

import (
	"strings"
	"testing"

	shared "github.com/Kup1ng/CtrlZ-Shared/locations"
	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/locations"
	"github.com/Kup1ng/CtrlZ-Panel/internal/profiles"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

func redirectTo(loc uuid.UUID) profiles.Act {
	return profiles.Act{Action: "redirect", Target: profiles.Target{Kind: "location", LocationID: loc}}
}

// TestLocationSets: an item write refuses a location outside the profile's set and Auto or Random on an empty set;
// a service uses the set limited to its regions; the checks run only on the values a request sets (4.2, 3.7).
func TestLocationSets(t *testing.T) {
	f := newFx(t)
	p := f.newProfile(t, f.A.Tenant, "loc")
	frankfurt, ny, la := f.loc(t, "DE", "Frankfurt"), f.loc(t, "US", "New York"), f.loc(t, "US", "Los Angeles")
	create := func(a profiles.Act, pattern string) error {
		return f.in(f.A.Tenant, func(tx store.Tx) error {
			_, err := f.env.CreateRules(tx, p, profiles.RuleIn{Patterns: []string{pattern}, Act: a})
			return err
		})
	}
	if err := create(redirectTo(frankfurt), "a.example.com"); err != nil {
		t.Errorf("a location both nodes have: %v", err)
	}
	// The profile has no Endpoint of its own with a pair override, so its set is the global pair's: Los Angeles
	// exists (it has a row) but only one node has it.
	err := create(redirectTo(la), "b.example.com")
	if e, ok := err.(*profiles.Error); !ok || !hasField(e, "/target/location", "location_not_allowed") {
		t.Errorf("a location one node lacks: %v", err)
	}
	err = create(redirectTo(uuid.New()), "c.example.com")
	if e, ok := err.(*profiles.Error); !ok || !hasField(e, "/target/location", "unknown") {
		t.Errorf("a location with no row: %v", err)
	}
	if err := create(profiles.Act{Action: "redirect", Target: profiles.Target{Kind: "auto"}}, "d.example.com"); err != nil {
		t.Errorf("auto on a non-empty set: %v", err)
	}
	// IP and host targets.
	for _, c := range []struct {
		name string
		t    profiles.Target
		code string
	}{
		{"v4 in ipv6", profiles.Target{Kind: "ip", IPv6: "192.0.2.1"}, "invalid"},
		{"v6 in ipv4", profiles.Target{Kind: "ip", IPv4: "2001:db8::1"}, "invalid"},
		{"none", profiles.Target{Kind: "ip"}, "required"},
		{"zone", profiles.Target{Kind: "ip", IPv6: "fe80::1%eth0"}, "invalid"},
		{"bad host", profiles.Target{Kind: "host", Host: "not a host"}, "invalid"},
	} {
		err := create(profiles.Act{Action: "redirect", Target: c.t}, "ip-"+c.name[:2]+".example.com")
		if e, ok := err.(*profiles.Error); !ok || len(e.Fields) != 1 || e.Fields[0].Code != c.code {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	if err := create(profiles.Act{Action: "redirect", Target: profiles.Target{Kind: "ip", IPv4: "192.0.2.1", IPv6: "2001:db8::1"}}, "both.example.com"); err != nil {
		t.Errorf("both families: %v", err)
	}

	// A service limited to US regions: its set is the profile's set limited to US, so New York is in it and Frankfurt is not.
	st := func(slug string, a profiles.Act) error {
		return f.in(f.A.Tenant, func(tx store.Tx) error {
			_, err := f.env.SetServices(tx, p, []string{slug}, profiles.ServiceState{Enabled: true, Act: a})
			return err
		})
	}
	if err := st("hulu", redirectTo(ny)); err != nil {
		t.Errorf("a US service to New York: %v", err)
	}
	err = st("hulu", redirectTo(frankfurt))
	if e, ok := err.(*profiles.Error); !ok || !hasField(e, "/slugs/0/target/location", "location_not_allowed") {
		t.Errorf("a US service to Frankfurt: %v", err)
	}
	// A group action uses the intersection of the sets: youtube and hulu share only the US locations.
	err = f.in(f.A.Tenant, func(tx store.Tx) error {
		_, err := f.env.SetServices(tx, p, []string{"youtube", "hulu"}, profiles.ServiceState{Enabled: true, Act: redirectTo(frankfurt)})
		return err
	})
	if e, ok := err.(*profiles.Error); !ok || len(e.Fields) == 0 {
		t.Errorf("a group Redirect outside the shared set: %v", err)
	}

	// An unchanged value is not checked again: a rule whose location left the set stays editable.
	f.exec(t, `INSERT INTO ctrlz.rules (tenant_id, profile_id, rule_key, match_kind, action, target_kind, target_location_id, location_unavailable)
VALUES ($1, $2, 'flagged.example.com', 'domain', 'redirect', 'location', $3, true)`, f.A.Tenant, p, la)
	var flagged uuid.UUID
	if err := f.db.Scan(f.ctx, `SELECT id FROM ctrlz.rules WHERE rule_key = 'flagged.example.com'`, nil, &flagged); err != nil {
		t.Fatal(err)
	}
	c := "still editable"
	f.must(t, f.A.Tenant, func(tx store.Tx) error {
		_, err := f.env.UpdateRule(tx, p, flagged, profiles.RulePatch{Comment: &c, Act: &profiles.Act{Action: "redirect", Target: profiles.Target{Kind: "location", LocationID: la}}})
		return err
	})
}

// TestEmptySetRefusesAutoAndRandom: with no location at all (a production stack before P4b) Auto and Random are
// refused on an item write, and the Default Rule is no exception.
func TestEmptySetRefusesAutoAndRandom(t *testing.T) {
	f := newFx(t)
	f.env.Catalog = locations.Memory{} // no node, no location
	p := f.newProfile(t, f.A.Tenant, "empty")
	for _, kind := range []string{"auto", "random"} {
		e := f.refusal(t, f.A.Tenant, func(tx store.Tx) error {
			_, err := f.env.CreateRules(tx, p, profiles.RuleIn{Patterns: []string{"a.example.com"}, Act: profiles.Act{Action: "redirect", Target: profiles.Target{Kind: kind}}})
			return err
		})
		if !hasField(e, "/target/kind", "no_shared_destination") {
			t.Errorf("%s: %v", kind, e)
		}
	}
	e := f.refusal(t, f.A.Tenant, func(tx store.Tx) error {
		_, err := f.env.PatchOptions(tx, p, profiles.OptionsPatch{DefaultRule: &profiles.DefaultRule{Act: profiles.Act{Action: "redirect", Target: profiles.Target{Kind: "auto"}}}})
		return err
	})
	if !hasField(e, "/default_rule/target/kind", "no_shared_destination") {
		t.Errorf("default rule: %v", e)
	}
}

// TestSetsOfTheMemoryCatalog drives the in-memory catalog the vector cases use: the same code answers as for the
// database (SC 10.1).
func TestSetsOfTheMemoryCatalog(t *testing.T) {
	m := locations.Memory{
		Locations: []shared.Key{{Country: "DE", City: "Frankfurt"}, {Country: "NL"}, {Label: "lab"}},
		Nodes: map[string][]shared.Key{
			"a": {{Country: "DE", City: "Frankfurt"}, {Country: "NL"}, {Label: "lab"}},
			"b": {{Country: "DE", City: "frankfurt"}, {Label: "lab"}},
		},
		GlobalA: "a", GlobalB: "b",
	}
	snap, err := m.Snapshot(store.Tx{})
	if err != nil {
		t.Fatal(err)
	}
	set := shared.AllowedLocations(nil, snap.Global, snap.Nodes)
	if len(set) != 2 {
		t.Errorf("the set is %v, want Frankfurt and the label", set)
	}
	if _, ok := snap.Find(shared.Key{Country: "de", City: " FRANKFURT "}); !ok {
		t.Error("Find does not compare a city folded")
	}
	if locations.AutoRandom(set[:1]) || !locations.AutoRandom(set) {
		t.Error("Auto and Random need two locations")
	}
}

// TestFilters walks the modes: every multi-mode filter with each of its modes, a one-mode filter with none, a mode of
// another filter refused, any mode on a one-mode filter (standard included) refused, and the default on first
// enable (T-144 to T-146).
func TestFilters(t *testing.T) {
	f := newFx(t)
	p := f.newProfile(t, f.A.Tenant, "filters")
	set := func(filter string, enabled bool, mode string) (store.FilterRow, error) {
		var r store.FilterRow
		err := f.in(f.A.Tenant, func(tx store.Tx) (err error) { r, err = f.env.SetFilter(tx, p, filter, enabled, mode); return })
		return r, err
	}
	multi, single := map[string][]string{}, []string{}
	// One line per filter: its id and its modes in wire order, joined by commas.
	var listing string
	if err := f.db.Scan(f.ctx, `SELECT string_agg(l, ';' ORDER BY l) FROM (SELECT f.id || ':' || string_agg(m.mode, ',' ORDER BY m.wire_id) AS l
		FROM ctrlz.catalog_filter f JOIN ctrlz.catalog_filter_mode m ON m.filter_id = f.id GROUP BY f.id) x`, nil, &listing); err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(listing, ";") {
		id, list, _ := strings.Cut(line, ":")
		modes := strings.Split(list, ",")
		if len(modes) > 1 {
			multi[id] = modes
		} else {
			single = append(single, id)
		}
	}
	if len(multi) == 0 || len(single) == 0 {
		t.Fatalf("the seed has %d multi-mode and %d one-mode filters", len(multi), len(single))
	}
	for id, modes := range multi {
		r, err := set(id, true, "")
		if err != nil || r.Mode != modes[0] {
			t.Errorf("%s: first enable gave %+v %v, want the default mode %s", id, r, err, modes[0])
		}
		for _, m := range modes {
			if r, err := set(id, true, m); err != nil || r.Mode != m {
				t.Errorf("%s %s: %+v %v", id, m, r, err)
			}
		}
		// Off keeps the mode, and a mode of another filter is refused.
		if r, err := set(id, false, ""); err != nil || r.Mode != modes[len(modes)-1] || r.Enabled {
			t.Errorf("%s: off gave %+v %v", id, r, err)
		}
		if _, err := set(id, true, "no-such-mode"); err == nil {
			t.Errorf("%s: an unknown mode was accepted", id)
		}
	}
	for _, id := range single {
		if r, err := set(id, true, ""); err != nil || r.Mode != "" {
			t.Errorf("%s: %+v %v", id, r, err)
		}
		for _, m := range []string{"standard", "strict"} {
			if _, err := set(id, true, m); err == nil {
				t.Errorf("%s: mode %q on a one-mode filter was accepted", id, m)
			}
		}
	}
	if _, err := set("nope", true, ""); err == nil {
		t.Error("an unknown filter was accepted")
	}
}

// TestOptions: every option set, read and cleared; each bound of the option row on its route (3.7).
func TestOptions(t *testing.T) {
	f := newFx(t)
	p := f.newProfile(t, f.A.Tenant, "options")
	yes := true
	ttl := func(n int) *int { return &n }
	var got store.OptionsRow
	f.must(t, f.A.Tenant, func(tx store.Tx) (err error) {
		got, err = f.env.PatchOptions(tx, p, profiles.OptionsPatch{
			DefaultRule: &profiles.DefaultRule{Act: redirectHost("proxy.example.net")}, BlockExfiltration: &yes, RebindProtection: &yes,
			DisableDNSSEC: &yes, BlockTTL: ttl(1), RedirectTTL: ttl(86400), BypassTTL: ttl(60),
			BlockResponse: &profiles.BlockResponse{Mode: "custom", V4: "203.0.113.9", V6: "2001:db8::9"},
			ECS:           &profiles.ECS{Mode: "custom", V4: "198.51.100.0/24", V6: "2001:db8::/48"},
			DNS64:         &yes, CNAMEFlattening: &yes, SafeSearch: &yes, RestrictedYouTube: &yes})
		return
	})
	if got.DefaultAction != "redirect" || got.DefaultTarget.Host != "proxy.example.net" || got.ECSV4 != "198.51.100.0/24" || *got.RedirectTTL != 86400 {
		t.Errorf("read back %+v", got)
	}
	fail := func(name string, patch profiles.OptionsPatch, field, code string) {
		t.Run(name, func(t *testing.T) {
			before := f.digest(t, p)
			e := f.refusal(t, f.A.Tenant, func(tx store.Tx) error { _, err := f.env.PatchOptions(tx, p, patch); return err })
			if !hasField(e, field, code) {
				t.Errorf("got %v, want %s %s", e, field, code)
			}
			if f.digest(t, p) != before {
				t.Error("a refusal wrote something")
			}
		})
	}
	fail("ttl zero", profiles.OptionsPatch{BlockTTL: ttl(0)}, "/block_ttl", "out_of_range")
	fail("ttl too long", profiles.OptionsPatch{BypassTTL: ttl(86401)}, "/bypass_ttl", "out_of_range")
	fail("branded", profiles.OptionsPatch{BlockResponse: &profiles.BlockResponse{Mode: "branded"}}, "/block_response/mode", "not_available")
	fail("custom with none", profiles.OptionsPatch{BlockResponse: &profiles.BlockResponse{Mode: "custom"}}, "/block_response/v4", "required")
	fail("custom v4 in v6", profiles.OptionsPatch{BlockResponse: &profiles.BlockResponse{Mode: "custom", V6: "192.0.2.1"}}, "/block_response/v6", "invalid")
	fail("ecs host bits", profiles.OptionsPatch{ECS: &profiles.ECS{Mode: "custom", V4: "198.51.100.7/24"}}, "/ecs/v4", "invalid")
	fail("ecs v6 host bits", profiles.OptionsPatch{ECS: &profiles.ECS{Mode: "custom", V6: "2001:db8::1/48"}}, "/ecs/v6", "invalid")
	fail("ecs shape", profiles.OptionsPatch{ECS: &profiles.ECS{Mode: "custom", V4: "198.51.100.0"}}, "/ecs/v4", "invalid")
	fail("ecs prefix out of range", profiles.OptionsPatch{ECS: &profiles.ECS{Mode: "custom", V4: "198.51.100.0/33"}}, "/ecs/v4", "invalid")
	fail("ecs custom with none", profiles.OptionsPatch{ECS: &profiles.ECS{Mode: "custom"}}, "/ecs/v4", "required")
	fail("ecs mode", profiles.OptionsPatch{ECS: &profiles.ECS{Mode: "weird"}}, "/ecs/mode", "invalid")
	fail("unknown clear", profiles.OptionsPatch{Clear: []string{"nope"}}, "/clear", "invalid")

	// A Redirect Default Rule is the declared exception of D42: it is accepted.
	f.must(t, f.A.Tenant, func(tx store.Tx) (err error) {
		got, err = f.env.PatchOptions(tx, p, profiles.OptionsPatch{Clear: profiles.OptionNames()})
		return
	})
	if got.DefaultAction != "" || got.BlockTTL != nil || got.ECSMode != "" || got.SafeSearch != nil || got.BlockResponse != "" {
		t.Errorf("not cleared: %+v", got)
	}
}

// TestRulesBatch walks the group operations (8.3).
func TestRulesBatch(t *testing.T) {
	f := newFx(t)
	src := f.newProfile(t, f.A.Tenant, "src")
	dst := f.newProfile(t, f.A.Tenant, "dst")
	var ids []uuid.UUID
	f.must(t, f.A.Tenant, func(tx store.Tx) error {
		rs, err := f.env.CreateRules(tx, src, profiles.RuleIn{Patterns: []string{"a.example.com", "b.example.com", "*.c.example.com"}, Act: block()})
		for _, r := range rs {
			ids = append(ids, r.ID)
		}
		return err
	})
	run := func(profile uuid.UUID, in profiles.BatchIn) (res profiles.BatchResult, err error) {
		err = f.in(f.A.Tenant, func(tx store.Tx) (e error) { res, e = f.env.RulesBatch(tx, profile, in); return })
		return
	}
	// enable and disable by ids.
	if r, err := run(src, profiles.BatchIn{Op: "disable", IDs: ids}); err != nil || r.Updated != 3 {
		t.Errorf("disable: %+v %v", r, err)
	}
	if r, err := run(src, profiles.BatchIn{Op: "disable", IDs: ids}); err != nil || r.Skipped != 3 {
		t.Errorf("disable again: %+v %v", r, err)
	}
	if r, err := run(src, profiles.BatchIn{Op: "enable", Selector: &profiles.Selector{Status: "disabled"}}); err != nil || r.Updated != 3 {
		t.Errorf("enable by selector: %+v %v", r, err)
	}
	// edit: set a comment and an expiry, then clear them.
	c := "edited"
	if r, err := run(src, profiles.BatchIn{Op: "edit", IDs: ids, Set: &profiles.EditSet{Comment: &c, Expiry: &profiles.Expiry{In: "1w"}}}); err != nil || r.Updated != 3 {
		t.Errorf("edit: %+v %v", r, err)
	}
	if n := f.count(t, `SELECT count(*) FROM ctrlz.rules WHERE profile_id = $1 AND comment = 'edited' AND expires_at IS NOT NULL`, src); n != 3 {
		t.Errorf("%d rules carry the edit", n)
	}
	if _, err := run(src, profiles.BatchIn{Op: "edit", IDs: ids, Clear: []string{"comment", "expires"}}); err != nil {
		t.Error(err)
	}
	// A new folder made by the move, in the same transaction.
	boxBefore := f.outbox(t, src)
	if r, err := run(src, profiles.BatchIn{Op: "move", IDs: ids[:1], NewFolder: &profiles.FolderIn{Name: "moved", Kind: "standard"}}); err != nil || r.Updated != 1 {
		t.Errorf("move into a new folder: %+v %v", r, err)
	}
	if f.outbox(t, src) != boxBefore+1 {
		t.Error("the move wrote no outbox row, or more than one")
	}
	// copy to another profile: created, and a second copy is all conflicts.
	if r, err := run(src, profiles.BatchIn{Op: "copy", IDs: ids, DestProfile: dst, DestRoot: true}); err != nil || r.Created != 3 {
		t.Errorf("copy: %+v %v", r, err)
	}
	if r, err := run(src, profiles.BatchIn{Op: "copy", IDs: ids, DestProfile: dst, DestRoot: true}); err != nil || r.Conflict != 3 || r.Created != 0 {
		t.Errorf("copy again: %+v %v", r, err)
	}
	if f.count(t, `SELECT count(*) FROM ctrlz.rules WHERE profile_id = $1`, dst) != 3 || f.count(t, `SELECT count(*) FROM ctrlz.rules WHERE profile_id = $1`, src) != 3 {
		t.Error("a copy changed the source or wrote the wrong count")
	}
	// Copy reads a locked source (7.3) and writes only the destination: its outbox row is the destination's.
	f.lock(t, src)
	other := f.newProfile(t, f.A.Tenant, "other")
	srcBox, srcDigest := f.outbox(t, src), f.digest(t, src)
	if r, err := run(src, profiles.BatchIn{Op: "copy", IDs: ids, DestProfile: other, DestRoot: true}); err != nil || r.Created != 3 {
		t.Errorf("copy from a locked source: %+v %v", r, err)
	}
	if f.digest(t, src) != srcDigest || f.outbox(t, src) != srcBox {
		t.Error("a copy from a locked source touched it")
	}
	// Move needs both unlocked, and a locked destination refuses a copy.
	e := f.refusal(t, f.A.Tenant, func(tx store.Tx) error {
		_, err := f.env.RulesBatch(tx, src, profiles.BatchIn{Op: "move", IDs: ids, DestProfile: other, DestRoot: true})
		return err
	})
	if e.Kind != profiles.KindLocked {
		t.Errorf("move from a locked source: %v", e)
	}
	f.unlock(t, src)
	f.lock(t, dst)
	e = f.refusal(t, f.A.Tenant, func(tx store.Tx) error {
		_, err := f.env.RulesBatch(tx, src, profiles.BatchIn{Op: "copy", IDs: ids, DestProfile: dst, DestRoot: true})
		return err
	})
	if e.Kind != profiles.KindLocked {
		t.Errorf("copy into a locked destination: %v", e)
	}
	f.unlock(t, dst)
	// A move to another profile removes the source rows it moved and marks both profiles under one batch id.
	mover := f.newProfile(t, f.A.Tenant, "mover")
	if r, err := run(src, profiles.BatchIn{Op: "move", IDs: ids, DestProfile: mover, DestRoot: true}); err != nil || r.Created != 3 {
		t.Errorf("move: %+v %v", r, err)
	}
	if f.count(t, `SELECT count(*) FROM ctrlz.rules WHERE profile_id = $1`, src) != 0 || f.count(t, `SELECT count(*) FROM ctrlz.rules WHERE profile_id = $1`, mover) != 3 {
		t.Error("the move left rows behind or lost some")
	}
	if n := f.count(t, `SELECT count(DISTINCT batch_id) FROM ctrlz.policy_outbox WHERE aggregate_id IN ($1, $2) AND created_at > now() - interval '1 minute' AND batch_id = (SELECT batch_id FROM ctrlz.policy_outbox WHERE aggregate_id = $2 ORDER BY id DESC LIMIT 1)`, src, mover); n != 1 {
		t.Errorf("the pair of a move shares %d batch ids, want 1", n)
	}
	// delete, and the bound of a request: more selector matches than the tenant's limit is exceeded.
	moved, _ := run(mover, profiles.BatchIn{Op: "delete", Selector: &profiles.Selector{}})
	if moved.Updated != 3 {
		t.Errorf("delete by selector: %+v", moved)
	}
	f.exec(t, `UPDATE ctrlz.tenant_entitlements SET max_rules_per_request = 2 WHERE tenant_id = $1`, f.A.Tenant)
	e = f.refusal(t, f.A.Tenant, func(tx store.Tx) error {
		_, err := f.env.RulesBatch(tx, dst, profiles.BatchIn{Op: "delete", Selector: &profiles.Selector{}})
		return err
	})
	if !hasField(e, "max_rules_per_request", "exceeded") {
		t.Errorf("3 matches over a limit of 2: %v", e)
	}
}

// TestJobsAndKeys: above the threshold a request is queued with its outbox row in one transaction; a second is
// job_running and GET /jobs/active would return the first; a missing or locked profile is refused before any job;
// an Idempotency-Key replays, and another body under it is reused (3.5).
func TestJobsAndKeys(t *testing.T) {
	f := newFx(t)
	p := f.newProfile(t, f.A.Tenant, "jobs")
	var job uuid.UUID
	f.must(t, f.A.Tenant, func(tx store.Tx) (err error) {
		job, err = f.env.QueueJob(tx, profiles.JobRequest{Kind: "rules_batch", Profile: p, Total: 2000, Input: []byte(`{"items":[]}`)})
		return
	})
	if f.count(t, `SELECT count(*) FROM ctrlz.job_outbox WHERE tenant_id = $1 AND kind = 'batch_job' AND args->>'job_id' = $2`, f.A.Tenant, job.String()) != 1 {
		t.Error("the job has no outbox row")
	}
	e := f.refusal(t, f.A.Tenant, func(tx store.Tx) error {
		_, err := f.env.QueueJob(tx, profiles.JobRequest{Kind: "rules_batch", Profile: p, Total: 2000, Input: []byte(`{}`)})
		return err
	})
	if e.Kind != profiles.KindJobRunning {
		t.Errorf("a second job: %v", e)
	}
	f.must(t, f.A.Tenant, func(tx store.Tx) error {
		j, ok, err := tx.JobActive()
		if err != nil || !ok || j.ID != job {
			t.Errorf("the active job is %v %v %v", j.ID, ok, err)
		}
		return err
	})
	// Tenant B sees none of it and can queue its own.
	pb := f.newProfile(t, f.B.Tenant, "jobs-b")
	f.must(t, f.B.Tenant, func(tx store.Tx) error {
		if _, ok, err := tx.JobActive(); err != nil || ok {
			t.Errorf("B sees a job: %v %v", ok, err)
		}
		if _, ok, err := tx.Job(job); err != nil || ok {
			t.Errorf("B reads A's job: %v %v", ok, err)
		}
		_, err := f.env.QueueJob(tx, profiles.JobRequest{Kind: "rules_batch", Profile: pb, Total: 2000, Input: []byte(`{}`)})
		return err
	})
	f.exec(t, `UPDATE ctrlz.batch_jobs SET state = 'done' WHERE id = $1`, job)
	f.lock(t, p)
	e = f.refusal(t, f.A.Tenant, func(tx store.Tx) error {
		_, err := f.env.QueueJob(tx, profiles.JobRequest{Kind: "rules_batch", Profile: p, Total: 2000, Input: []byte(`{}`)})
		return err
	})
	if e.Kind != profiles.KindLocked {
		t.Errorf("a locked profile: %v", e)
	}
	e = f.refusal(t, f.A.Tenant, func(tx store.Tx) error {
		_, err := f.env.QueueJob(tx, profiles.JobRequest{Kind: "rules_batch", Profile: uuid.New(), Total: 2000, Input: []byte(`{}`)})
		return err
	})
	if e.Kind != profiles.KindNotFound {
		t.Errorf("a missing profile: %v", e)
	}
	if f.count(t, `SELECT count(*) FROM ctrlz.batch_jobs WHERE tenant_id = $1 AND state IN ('queued', 'running')`, f.A.Tenant) != 0 {
		t.Error("a refused request left a job")
	}

	// Idempotency: the first request does its work, a replay gets the stored answer and no second effect.
	req := profiles.Request{Key: "key-1", Method: "POST", Path: "/api/v1/profiles/" + p.String() + "/rules:batch", Body: []byte(`{"op":"disable"}`)}
	f.must(t, f.A.Tenant, func(tx store.Tx) error {
		proceed, _, err := f.env.BeginKey(tx, req)
		if err != nil || !proceed {
			t.Fatalf("first: %v %v", proceed, err)
		}
		return f.env.FinishKey(tx, req, 200, []byte(`{"created":0}`))
	})
	f.must(t, f.A.Tenant, func(tx store.Tx) error {
		proceed, replay, err := f.env.BeginKey(tx, req)
		if err != nil || proceed || replay.Status != 200 || strings.ReplaceAll(string(replay.Body), " ", "") != `{"created":0}` {
			t.Errorf("replay: %v %+v %v", proceed, replay, err)
		}
		return err
	})
	other := req
	other.Body = []byte(`{"op":"enable"}`)
	e = f.refusal(t, f.A.Tenant, func(tx store.Tx) error { _, _, err := f.env.BeginKey(tx, other); return err })
	if e.Kind != profiles.KindKeyReused {
		t.Errorf("another body: %v", e)
	}
	other = req
	other.Path += "x"
	e = f.refusal(t, f.A.Tenant, func(tx store.Tx) error { _, _, err := f.env.BeginKey(tx, other); return err })
	if e.Kind != profiles.KindKeyReused {
		t.Errorf("another path: %v", e)
	}
	// The same key in tenant B is its own key.
	f.must(t, f.B.Tenant, func(tx store.Tx) error {
		proceed, _, err := f.env.BeginKey(tx, req)
		if err != nil || !proceed {
			t.Errorf("B: %v %v", proceed, err)
		}
		return err
	})
	if !profiles.ValidKey("a_b-9") || profiles.ValidKey("") || profiles.ValidKey("a b") || profiles.ValidKey(string(make([]byte, 65))) {
		t.Error("the key grammar is wrong")
	}
}

// TestPatternCodes: every error the rule parser gives for a case of the tokens vectors has a code of the closed set
// (spec 3.7), and every valid token through the route comes back with the key, kind and sign the case names.
func TestPatternCodes(t *testing.T) {
	known := map[string]bool{}
	for _, c := range profiles.PatternCodes() {
		known[c] = true
	}
	for _, c := range tokenErrorCases(t) {
		if code := profiles.PatternCode(c.err); !known[code] {
			t.Errorf("%q: %v has the code %q, which is not in the closed set", c.input, c.err, code)
		}
	}
	f := newFx(t)
	p := f.newProfile(t, f.A.Tenant, "tokens")
	for _, c := range tokenValidCases(t) {
		f.exec(t, `DELETE FROM ctrlz.rules WHERE profile_id = $1`, p)
		var got []store.RuleRow
		err := f.in(f.A.Tenant, func(tx store.Tx) (err error) {
			got, err = f.env.CreateRules(tx, p, profiles.RuleIn{Patterns: []string{c.input}, Act: block()})
			return
		})
		if err != nil {
			t.Errorf("%q: %v", c.input, err)
			continue
		}
		if got[0].Key != c.key || got[0].MatchKind != c.kind || got[0].Negated != c.negated {
			t.Errorf("%q: read back key=%s kind=%s negated=%v, want %s %s %v", c.input, got[0].Key, got[0].MatchKind, got[0].Negated, c.key, c.kind, c.negated)
		}
	}
}

// TestSearchText: a Unicode name finds its rule by whole labels (8.3).
func TestSearchText(t *testing.T) {
	if got := profiles.SearchText("  München.DE "); got != "xn--mnchen-3ya.de" {
		t.Errorf("got %q", got)
	}
	if got := profiles.SearchText("Example.COM"); got != "example.com" {
		t.Errorf("got %q", got)
	}
	f := newFx(t)
	p := f.newProfile(t, f.A.Tenant, "search")
	f.must(t, f.A.Tenant, func(tx store.Tx) error {
		_, err := f.env.CreateRules(tx, p, profiles.RuleIn{Patterns: []string{"münchen.de", "other.example.com"}, Act: block()})
		return err
	})
	for _, q := range []string{"münchen", "xn--mnchen-3ya", "MÜNCHEN.de"} {
		var n int
		f.must(t, f.A.Tenant, func(tx store.Tx) error {
			ids, err := tx.RuleIDsMatching(p, store.RuleSelector{Q: profiles.SearchText(q), MaxResult: 10})
			n = len(ids)
			return err
		})
		if n != 1 {
			t.Errorf("search %q found %d rules, want 1", q, n)
		}
	}
}

// TestTheWorkerRunsTheSamePath: a job runs through the same code as a request, as the worker role, whose grants
// (migration 0070) must therefore reach every statement of it: create a profile, fill it, copy and move between
// profiles, set filters, services and options, claim and finish a job.
func TestTheWorkerRunsTheSamePath(t *testing.T) {
	f := newFx(t)
	w := f.db.Store(f.ctx, t, store.RoleWorker)
	var p, q uuid.UUID
	if err := w.WithTenant(f.ctx, f.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
		pr, err := f.env.CreateProfile(tx, "from a job", "kids")
		if err != nil {
			return err
		}
		p = pr.ID
		qr, err := f.env.CreateProfile(tx, "second", "custom")
		if err != nil {
			return err
		}
		q = qr.ID
		fo, err := f.env.CreateFolder(tx, p, profiles.FolderIn{Name: "f", Kind: "standard", Act: profiles.Act{Action: "bypass"}})
		if err != nil {
			return err
		}
		rs, err := f.env.CreateRules(tx, p, profiles.RuleIn{Patterns: []string{"a.example.com", "*.b.example.com"}, Act: profiles.Act{Action: "inherit"}, FolderID: fo.ID})
		if err != nil {
			return err
		}
		if _, err := f.env.RulesBatch(tx, p, profiles.BatchIn{Op: "copy", IDs: []uuid.UUID{rs[0].ID}, DestProfile: q, DestRoot: true}); err == nil {
			t.Error("an inheriting rule was copied to the top level")
		}
		var ids []uuid.UUID
		for _, r := range rs {
			ids = append(ids, r.ID)
		}
		if _, err := f.env.RulesBatch(tx, p, profiles.BatchIn{Op: "edit", IDs: ids, Set: &profiles.EditSet{Act: &profiles.Act{Action: "block"}}}); err != nil {
			return err
		}
		if _, err := f.env.RulesBatch(tx, p, profiles.BatchIn{Op: "move", IDs: ids, DestProfile: q, DestRoot: true}); err != nil {
			return err
		}
		if _, err := f.env.SetFilter(tx, p, "phishing", true, ""); err != nil {
			return err
		}
		if _, err := f.env.SetServices(tx, p, []string{"youtube"}, profiles.ServiceState{Enabled: true, Act: redirectHost("proxy.example.net")}); err != nil {
			return err
		}
		yes := true
		_, err = f.env.PatchOptions(tx, p, profiles.OptionsPatch{SafeSearch: &yes, DefaultRule: &profiles.DefaultRule{Act: profiles.Act{Action: "redirect", Target: profiles.Target{Kind: "auto"}}}})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if f.count(t, `SELECT count(*) FROM ctrlz.rules WHERE profile_id = $1`, q) != 2 {
		t.Error("the moved rules are not in the second profile")
	}
	// A job: queued by the tenant, claimed and finished by the worker.
	var job uuid.UUID
	f.must(t, f.A.Tenant, func(tx store.Tx) (err error) {
		job, err = f.env.QueueJob(tx, profiles.JobRequest{Kind: "rules_batch", Profile: p, Total: 3, Input: []byte(`{"items":[1,2,3]}`)})
		return
	})
	if err := w.WithTenant(f.ctx, f.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
		work, won, err := tx.JobClaim(job)
		if err != nil || !won.Yes() || work.Kind != "rules_batch" || string(work.Input) == "" {
			t.Errorf("claim: %+v %v %v", work, won.Yes(), err)
		}
		done, err := tx.JobFinish(job, []byte(`{"created":3}`), uuid.Nil)
		if err == nil && !done.Yes() {
			t.Error("the job did not finish")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	// A job of tenant A named from tenant B's transaction finds nothing, and a job_outbox row of B that names it
	// leaves it alone.
	if err := w.WithTenant(f.ctx, f.B.Tenant, store.TxOpts{}, func(tx store.Tx) error {
		_, won, err := tx.JobClaim(job)
		if err == nil && won.Yes() {
			t.Error("B claimed A's job")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}
