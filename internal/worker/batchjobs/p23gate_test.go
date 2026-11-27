package batchjobs_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/profiles"
)

// TestATransferJobAboveTheThresholdChecksTheDestinationAgain: a copy of 1,001 rules is a job, and the job is the code of the
// route: a destination that would pass its rule limit is refused with exceeded and a Redirect whose location the destination's
// set lacks is refused with location_not_allowed at /ids/<i>/target/location, each with the job failed once and nothing written
// in either profile or in tenant B (spec 8.3 batch semantics, 4.2, T-193). Take the cap check out of the insert of a transfer
// and the first job ends done with 1,006 rules in the destination.
func TestATransferJobAboveTheThresholdChecksTheDestinationAgain(t *testing.T) {
	f := newFx(t)
	src := f.seedProfile(t, f.A.Tenant, "Src")
	dst := f.seedProfile(t, f.A.Tenant, "Dst", "d1.example.com", "d2.example.com", "d3.example.com", "d4.example.com", "d5.example.com")
	f.exec(t, `INSERT INTO ctrlz.rules (tenant_id, profile_id, rule_key, match_kind, action)
		SELECT $1, $2, 'bulk' || g || '.example.com', 'domain', 'block' FROM generate_series(1, 1001) g`, f.A.Tenant, src)
	// A location only node 1 has: the global pair (nodes 1 and 2) does not have it, so it is outside the destination's set.
	oslo := uuid.Must(uuid.NewV7())
	f.exec(t, `INSERT INTO ctrlz.locations (id, wire_id, country_code, city) VALUES ($1, 200, 'NO', 'Oslo')`, oslo)
	f.exec(t, `INSERT INTO ctrlz.location_availability (node_id, location_id) VALUES ('00000000-0000-7000-8000-0000000000c1', $1)`, oslo)

	ids := f.ruleIDs(t, f.A.Tenant, src)
	if len(ids) != 1001 {
		t.Fatalf("the source holds %d rules, want 1001", len(ids))
	}
	f.start(t)
	type refusal struct {
		Code   string `json:"code"`
		Fields []struct {
			Name string `json:"name"`
			Code string `json:"code"`
		} `json:"fields"`
	}
	run := func(in profiles.BatchIn) refusal {
		t.Helper()
		digestB := f.contentDigest(t, f.B.Tenant)
		id := f.queueTransfer(t, f.A.Tenant, src, in, false)
		state, e := f.untilEnded(t, id)
		var got refusal
		if state != "failed" || json.Unmarshal([]byte(e), &got) != nil || got.Code != "validation_failed" {
			t.Fatalf("the job is %s with %s, want failed with validation_failed", state, e)
		}
		if n := f.ruleCount(t, dst); n != 5 {
			t.Errorf("a refused job left %d rules in the destination, want 5", n)
		}
		if n := f.ruleCount(t, src); n < 1001 {
			t.Errorf("a refused copy left %d rules in the source", n)
		}
		if f.contentDigest(t, f.B.Tenant) != digestB {
			t.Error("a job of tenant A changed tenant B")
		}
		return got
	}

	// The destination holds 5 rules and may hold 1,005: 1,001 more is one too many.
	f.exec(t, `UPDATE ctrlz.tenant_entitlements SET max_rules_per_profile = 1005 WHERE tenant_id = $1`, f.A.Tenant)
	got := run(profiles.BatchIn{Op: "copy", IDs: ids, DestProfile: dst, DestRoot: true})
	found := false
	for _, x := range got.Fields {
		found = found || (x.Name == "max_rules_per_profile" && x.Code == "exceeded")
	}
	if !found {
		t.Errorf("the job's error is %+v, want exceeded at max_rules_per_profile", got.Fields)
	}
	f.exec(t, `UPDATE ctrlz.tenant_entitlements SET max_rules_per_profile = NULL WHERE tenant_id = $1`, f.A.Tenant)

	// One Redirect to a location the destination lacks among 1,002 rules refuses the whole job.
	f.exec(t, `INSERT INTO ctrlz.rules (tenant_id, profile_id, rule_key, match_kind, action, target_kind, target_location_id)
		VALUES ($1, $2, 'oslo.example.com', 'domain', 'redirect', 'location', $3)`, f.A.Tenant, src, oslo)
	ids = f.ruleIDs(t, f.A.Tenant, src)
	got = run(profiles.BatchIn{Op: "copy", IDs: ids, DestProfile: dst, DestRoot: true})
	found = false
	for _, x := range got.Fields {
		found = found || (strings.HasPrefix(x.Name, "/ids/") && strings.HasSuffix(x.Name, "/target/location") && x.Code == "location_not_allowed")
	}
	if !found || len(got.Fields) != 1 {
		t.Errorf("the job's error is %+v, want one location_not_allowed at /ids/<i>/target/location", got.Fields)
	}
}
