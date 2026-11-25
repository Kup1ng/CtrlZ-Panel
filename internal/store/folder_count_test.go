package store_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// The rule count of a folder must visit only the rules of that folder (p2-B3-r12-2). Without the index
// rules_folder_idx and the profile in the count, each of 500 folders walked every rule of the tenant, so one
// rules page of a full profile took millions of row visits and held a pooled connection for seconds.

// seedFullProfile gives the profile 500 folders and 10,000 rules spread over them, and returns the folder ids.
func (e *raceEnv) seedFullProfile(t *testing.T, tenant, profile uuid.UUID) {
	t.Helper()
	e.exec(t, `INSERT INTO ctrlz.rule_folders (tenant_id, profile_id, name) SELECT $1, $2, 'fx' || g FROM generate_series(1, 500) g`, tenant, profile)
	e.exec(t, `INSERT INTO ctrlz.rules (tenant_id, profile_id, folder_id, rule_key, match_kind, action)
	  SELECT $1, $2, f.id, 'k' || g || '.full.example', 'domain', 'block'
	  FROM generate_series(1, 10000) g
	  JOIN (SELECT id, row_number() OVER (ORDER BY id) - 1 AS n FROM ctrlz.rule_folders WHERE tenant_id = $1 AND profile_id = $2 AND name LIKE 'fx%') f ON f.n = g % 500`,
		tenant, profile)
}

func TestFolderCountReadsOnlyItsOwnRules(t *testing.T) {
	e := newRaceEnv(t)
	// The other profiles and the other tenant hold rules too: a count that ignores the profile, or has no index,
	// visits them all.
	e.seedFullProfile(t, e.A.Tenant, e.A.Profile)
	e.exec(t, `INSERT INTO ctrlz.rules (tenant_id, profile_id, rule_key, match_kind, action)
	  SELECT $1, $2, 'o' || g || '.other.example', 'domain', 'block' FROM generate_series(1, 10000) g`, e.A.Tenant, e.A.Profile2)
	e.seedFullProfile(t, e.B.Tenant, e.B.Profile)
	e.exec(t, `VACUUM ANALYZE ctrlz.rules`)
	e.exec(t, `VACUUM ANALYZE ctrlz.rule_folders`)

	profileRules := e.count(t, `SELECT count(*) FROM ctrlz.rules WHERE tenant_id = $1 AND profile_id = $2`, e.A.Tenant, e.A.Profile)
	inFolders := e.count(t, `SELECT count(*) FROM ctrlz.rules WHERE tenant_id = $1 AND profile_id = $2 AND folder_id IS NOT NULL`, e.A.Tenant, e.A.Profile)
	folder := uuid.UUID{}
	if err := e.super.QueryRow(e.ctx, `SELECT id FROM ctrlz.rule_folders WHERE tenant_id = $1 AND profile_id = $2 ORDER BY id LIMIT 1`, e.A.Tenant, e.A.Profile).Scan(&folder); err != nil {
		t.Fatal(err)
	}
	inFolder := e.count(t, `SELECT count(*) FROM ctrlz.rules WHERE tenant_id = $1 AND folder_id = $2`, e.A.Tenant, folder)

	lit := func(q string, args ...uuid.UUID) string {
		for i, a := range args {
			q = strings.ReplaceAll(q, "$"+string(rune('1'+i)), "'"+a.String()+"'")
		}
		return q
	}
	cases := []struct {
		name  string
		sql   string
		limit int
	}{
		{"list", lit(store.QFoldersList, e.A.Tenant, e.A.Profile), profileRules},
		{"one folder", lit(store.QFolderCounted, e.A.Tenant, e.A.Profile, folder), inFolder},
	}
	for _, c := range cases {
		var raw []byte
		if err := e.super.QueryRow(e.ctx, `EXPLAIN (ANALYZE, FORMAT JSON) `+c.sql).Scan(&raw); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		var plan []struct{ Plan map[string]any }
		if err := json.Unmarshal(raw, &plan); err != nil {
			t.Fatal(err)
		}
		visited, seq := rulesVisited(plan[0].Plan)
		if seq {
			t.Errorf("%s: the plan reads the rules with a sequential scan", c.name)
		}
		if visited > c.limit {
			t.Errorf("%s: the plan visited %d rule rows, more than the %d the profile (or folder) holds", c.name, visited, c.limit)
		}
	}

	// The counts are right and belong to the tenant: B's folders are not visible to A, and the bare read has none.
	var got, bare []store.FolderRow
	if err := e.tenant.WithTenant(e.ctx, e.A.Tenant, store.TxOpts{ReadOnly: true}, func(tx store.Tx) (err error) {
		if got, err = tx.Folders(e.A.Profile); err != nil {
			return err
		}
		bare, err = tx.FoldersBare(e.A.Profile)
		if err != nil {
			return err
		}
		if other, err := tx.Folders(e.B.Profile); err != nil || len(other) != 0 {
			t.Errorf("tenant A read %d folders of tenant B's profile (err %v)", len(other), err)
		}
		one, ok, err := tx.FolderCounted(e.A.Profile, folder)
		if err != nil || !ok || one.RuleCount != inFolder {
			t.Errorf("FolderCounted: %d rules (ok %v, err %v), want %d", one.RuleCount, ok, err, inFolder)
		}
		bareOne, ok, err := tx.Folder(e.A.Profile, folder)
		if err != nil || !ok || bareOne.RuleCount != 0 {
			t.Errorf("Folder: count %d (ok %v, err %v), want the bare 0", bareOne.RuleCount, ok, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) != len(bare) || len(got) < 500 {
		t.Fatalf("the lists have %d and %d folders", len(got), len(bare))
	}
	total := 0
	for i := range got {
		total += got[i].RuleCount
		if bare[i].ID != got[i].ID || bare[i].RuleCount != 0 {
			t.Fatalf("the bare list differs at %d", i)
		}
	}
	if total != inFolders {
		t.Errorf("the counts add up to %d, the profile holds %d in folders", total, inFolders)
	}
}

// rulesVisited adds the rows that the plan nodes over ctrlz.rules produced or threw away, times their loops, and says
// whether one of them is a sequential scan.
func rulesVisited(n map[string]any) (int, bool) {
	visited, seq := 0, false
	if n["Relation Name"] == "rules" {
		f := func(k string) float64 { v, _ := n[k].(float64); return v }
		loops := f("Actual Loops")
		visited += int((f("Actual Rows") + f("Rows Removed by Filter") + f("Rows Removed by Index Recheck")) * loops)
		seq = n["Node Type"] == "Seq Scan"
	}
	if kids, ok := n["Plans"].([]any); ok {
		for _, k := range kids {
			v, s := rulesVisited(k.(map[string]any))
			visited += v
			seq = seq || s
		}
	}
	return visited, seq
}
