package store_test

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// Round 13 of package B3 (p2-B3-r13-2, r13-4, r13-7, r13-8): a statement about one profile must visit the rows that name that
// profile and no others. Without clients_profile_idx and clients_profile2_idx (migration 0091) the location set and the client
// lock of a profile read every client of the tenant, and the counters of one profile counted the rules of all of them.

// relVisited adds the rows that the plan nodes over the table produced or threw away, times their loops, and says whether one
// of them is a sequential scan.
func relVisited(n map[string]any, rel string) (int, bool) {
	visited, seq := 0, false
	if n["Relation Name"] == rel {
		f := func(k string) float64 { v, _ := n[k].(float64); return v }
		visited += int((f("Actual Rows") + f("Rows Removed by Filter") + f("Rows Removed by Index Recheck")) * f("Actual Loops"))
		seq = n["Node Type"] == "Seq Scan"
	}
	if kids, ok := n["Plans"].([]any); ok {
		for _, k := range kids {
			v, s := relVisited(k.(map[string]any), rel)
			visited += v
			seq = seq || s
		}
	}
	return visited, seq
}

func (e *raceEnv) plan(t *testing.T, sql string) map[string]any {
	t.Helper()
	var raw []byte
	if err := e.super.QueryRow(e.ctx, `EXPLAIN (ANALYZE, FORMAT JSON) `+sql).Scan(&raw); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
	var plan []struct{ Plan map[string]any }
	if err := json.Unmarshal(raw, &plan); err != nil {
		t.Fatal(err)
	}
	return plan[0].Plan
}

func TestProfileStatementsReadOnlyWhatNamesTheProfile(t *testing.T) {
	e := newRaceEnv(t)
	// Tenant A: two profiles of 10,000 rules each, and a third that no client, window or endpoint uses except three clients.
	e.seedFullProfile(t, e.A.Tenant, e.A.Profile)
	e.exec(t, `INSERT INTO ctrlz.rules (tenant_id, profile_id, rule_key, match_kind, action)
	  SELECT $1, $2, 'o' || g || '.other.example', 'domain', 'block' FROM generate_series(1, 10000) g`, e.A.Tenant, e.A.Profile2)
	third := uuid.New()
	e.exec(t, `INSERT INTO ctrlz.profiles (tenant_id, id, name) VALUES ($1, $2, 'three')`, e.A.Tenant, third)
	// 20,000 clients of the one endpoint that name no profile, three that name the third, and tenant B's seeded endpoint with
	// clients that name B's profiles (another tenant's rows are in the same table and the same index).
	e.exec(t, `INSERT INTO ctrlz.clients (tenant_id, endpoint_id, label) SELECT $1, $2, 'c' || g FROM generate_series(1, 20000) g`, e.A.Tenant, e.A.Endpoint)
	e.exec(t, `INSERT INTO ctrlz.clients (tenant_id, endpoint_id, label, profile_id) VALUES ($1, $2, 'n1', $3), ($1, $2, 'n2', $3)`, e.A.Tenant, e.A.Endpoint, third)
	e.exec(t, `INSERT INTO ctrlz.clients (tenant_id, endpoint_id, label, profile2_id) VALUES ($1, $2, 'n3', $3)`, e.A.Tenant, e.A.Endpoint, third)
	e.exec(t, `INSERT INTO ctrlz.clients (tenant_id, endpoint_id, label, profile_id) SELECT $1, $2, 'b' || g, $3 FROM generate_series(1, 2000) g`, e.B.Tenant, e.B.Endpoint, e.B.Profile)
	for _, tbl := range []string{"clients", "rules", "endpoints", "schedule_windows", "profiles"} {
		e.exec(t, `VACUUM ANALYZE ctrlz.`+tbl)
	}
	profileRules := e.count(t, `SELECT count(*) FROM ctrlz.rules WHERE tenant_id = $1 AND profile_id = $2`, e.A.Tenant, e.A.Profile)

	lit := func(q string, args ...uuid.UUID) string {
		for i, a := range args {
			q = strings.ReplaceAll(q, "$"+string(rune('1'+i)), "'"+a.String()+"'")
		}
		return q
	}
	for _, c := range []struct{ name, sql string }{
		{"location pairs", lit(store.QProfilePairs, e.A.Tenant, third)},
		{"client lock", lit(store.QProfileClientsLock, e.A.Tenant, third)},
	} {
		visited, seq := relVisited(e.plan(t, c.sql), "clients")
		if seq {
			t.Errorf("%s: the plan reads the clients with a sequential scan", c.name)
		}
		// The three clients that name the profile, and a little slack for the index probes; the tenant has 20,003.
		if visited > 10 {
			t.Errorf("%s: the plan visited %d client rows for a profile that three clients name", c.name, visited)
		}
	}
	// The counters of one profile count the rules of that profile: not those of the other profile of the tenant, and not
	// those of the tenant\x27s other profiles together (20,000 here).
	if visited, seq := relVisited(e.plan(t, lit(store.QProfileCountsOne, e.A.Tenant, e.A.Profile)), "rules"); seq || visited > profileRules {
		t.Errorf("counters of one profile: visited %d rule rows (sequential %v), the profile holds %d", visited, seq, profileRules)
	}

	// The answers are right, and a tenant sees only its own.
	if err := e.tenant.WithTenant(e.ctx, e.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
		pairs, err := tx.ProfilePairs(third)
		if err != nil || len(pairs) != 1 {
			t.Errorf("pairs of the third profile: %v, %v (one endpoint uses it through its clients)", pairs, err)
		}
		if pairs, err = tx.ProfilePairs(e.B.Profile); err != nil || len(pairs) != 0 {
			t.Errorf("tenant A read the pairs of tenant B\x27s profile: %v, %v", pairs, err)
		}
		if err := tx.ProfileClientsLock(third); err != nil {
			t.Errorf("client lock: %v", err)
		}
		one, err := tx.ProfileCountsOf(e.A.Profile)
		if err != nil || one.Rules != profileRules {
			t.Errorf("counters of one profile: %d rules (%v), want %d", one.Rules, err, profileRules)
		}
		if other, err := tx.ProfileCountsOf(e.B.Profile); err != nil || other != (store.ProfileCounts{}) {
			t.Errorf("tenant A read counters of tenant B\x27s profile: %+v, %v", other, err)
		}
		all, err := tx.ProfileCountsAll()
		if err != nil || all[e.A.Profile].Rules != profileRules || all[e.A.Profile2].Rules != 10000 {
			t.Errorf("counters of all: %+v, %v", all, err)
		}
		if _, leaked := all[e.B.Profile]; leaked {
			t.Errorf("the counters of all name tenant B\x27s profile")
		}
		opts, err := tx.OptionsAll()
		if err != nil {
			t.Errorf("options of all: %v", err)
		}
		if _, leaked := opts[e.B.Profile]; leaked {
			t.Errorf("the options of all name tenant B\x27s profile")
		}
		for id := range opts {
			if id != e.A.Profile && id != e.A.Profile2 && id != third {
				t.Errorf("the options of all hold a profile that is not tenant A\x27s: %s", id)
			}
			one, ok, err := tx.Options(id)
			if err != nil || !ok || !reflect.DeepEqual(one, opts[id]) {
				t.Errorf("OptionsAll and Options differ for %s", id)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
