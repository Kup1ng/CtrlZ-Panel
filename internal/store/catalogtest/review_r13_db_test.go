package catalogtest_test

import (
	"context"
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store/catalogtest"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

type checkFn = func(context.Context, catalogtest.Querier, *catalogtest.Fixtures) ([]string, error)

// runCheck applies the statements in a transaction, runs one check and rolls back.
func runCheck(t *testing.T, h *harness, check checkFn, fx *catalogtest.Fixtures, sql ...string) []string {
	t.Helper()
	tx, err := h.super.Begin(h.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	for _, s := range sql {
		if _, err := tx.Exec(h.ctx, s); err != nil {
			t.Fatalf("statement %.100q does not apply: %v", s, err)
		}
	}
	v, err := check(h.ctx, tx, fx)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// TestNonFiniteCheckCanFail is the proof for db-r13-2: check 27 asked about NaN only, so an
// unbounded numeric or a float with `CHECK (x >= 0 AND x <> 'NaN')` passed and still held Infinity,
// which as a cap is never reached and as a spend is always reached and cannot be lowered. Every column
// shape that holds an infinity is reported, and a typed numeric(p, s), whose type refuses it, is not.
// A NaN line that is NOT ENFORCED or NOT VALID counts for nothing (db-r13-3).
func TestNonFiniteCheckCanFail(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	for _, m := range []struct {
		name, want string
		sql        []string
	}{
		{"an unbounded numeric with a lower bound and a NaN line", "accepts Infinity:", []string{`ALTER TABLE ctrlz.alerts ADD COLUMN zz_probe numeric CHECK (zz_probe >= 0 AND zz_probe <> 'NaN'::numeric)`}},
		{"a float with only a NaN line", "accepts Infinity, -Infinity", []string{`ALTER TABLE ctrlz.alerts ADD COLUMN zz_probe double precision CHECK (zz_probe <> 'NaN')`}},
		{"a real with a lower bound", "accepts NaN, Infinity", []string{`ALTER TABLE ctrlz.alerts ADD COLUMN zz_probe real CHECK (zz_probe >= 0)`}},
		{"an unbounded numeric with an upper bound only", "accepts -Infinity", []string{`ALTER TABLE ctrlz.alerts ADD COLUMN zz_probe numeric CHECK (zz_probe < 'Infinity'::numeric)`}},
		{"a typed numeric with a lower bound still holds NaN", "accepts NaN", []string{`ALTER TABLE ctrlz.alerts ADD COLUMN zz_probe numeric(14,4) CHECK (zz_probe >= 0)`}},
		{"a NaN line that is NOT ENFORCED", "accepts NaN", []string{`ALTER TABLE ctrlz.alerts ADD COLUMN zz_probe numeric(14,4) CHECK (zz_probe <> 'NaN'::numeric) NOT ENFORCED`}},
		{"a NaN line that is NOT VALID", "accepts NaN", []string{
			`ALTER TABLE ctrlz.alerts ADD COLUMN zz_probe numeric(14,4)`,
			`ALTER TABLE ctrlz.alerts ADD CONSTRAINT zz_nv CHECK (zz_probe <> 'NaN'::numeric) NOT VALID`}},
	} {
		t.Run(m.name, func(t *testing.T) {
			v := runCheck(t, h, catalogtest.CheckNaN, h.fx, m.sql...)
			if !strings.Contains(strings.Join(v, "\n"), m.want) {
				t.Errorf("check 27 did not report %q; it said %v", m.want, v)
			}
		})
	}
	// A typed numeric refuses an infinity by its type, so one NaN line is enough; a BETWEEN refuses all three.
	for _, sql := range []string{
		`ALTER TABLE ctrlz.alerts ADD COLUMN zz_probe numeric(14,4) CHECK (zz_probe >= 0 AND zz_probe <> 'NaN'::numeric)`,
		`ALTER TABLE ctrlz.alerts ADD COLUMN zz_probe numeric CHECK (zz_probe BETWEEN 0 AND 1)`,
		`ALTER TABLE ctrlz.alerts ADD COLUMN zz_probe double precision CHECK (zz_probe BETWEEN 0 AND 1)`,
	} {
		if v := runCheck(t, h, catalogtest.CheckNaN, h.fx, sql); len(v) != 0 {
			t.Errorf("check 27 reported a column that is fine (%s): %v", sql, v)
		}
	}
}

// TestEnforcementChecksCanFail is the proof for db-r13-3 and db-r13-4: a constraint that is NOT
// ENFORCED or NOT VALID, and a rewrite rule, are each reported, while the migrated database is clean
// for both checks and a schema outside the two the service owns is not judged for constraints.
func TestEnforcementChecksCanFail(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	var fkName string
	if err := h.super.QueryRow(h.ctx, `SELECT conname FROM pg_constraint WHERE contype = 'f' AND conrelid = 'ctrlz.refresh_tokens'::regclass AND confrelid = 'ctrlz.sessions'::regclass`).Scan(&fkName); err != nil {
		t.Fatal(err)
	}
	for name, check := range map[string]checkFn{"check 28": catalogtest.CheckConstraintsEnforced, "check 29": catalogtest.CheckNoRules} {
		if v := runCheck(t, h, check, h.fx); len(v) != 0 {
			t.Fatalf("the migrated database is not clean for %s: %v", name, v)
		}
	}
	for _, m := range []struct {
		name  string
		check checkFn
		want  string
		sql   []string
	}{
		{"a CHECK NOT ENFORCED", catalogtest.CheckConstraintsEnforced, "NOT ENFORCED", []string{`ALTER TABLE ctrlz.alerts ADD CONSTRAINT zz CHECK (true) NOT ENFORCED`}},
		{"a CHECK NOT VALID", catalogtest.CheckConstraintsEnforced, "NOT VALID", []string{`ALTER TABLE ctrlz.alerts ADD CONSTRAINT zz CHECK (true) NOT VALID`}},
		{"a foreign key NOT ENFORCED", catalogtest.CheckConstraintsEnforced, "NOT ENFORCED", []string{
			`ALTER TABLE ctrlz.refresh_tokens ALTER CONSTRAINT ` + fkName + ` NOT ENFORCED`}},
		{"a rule on a table", catalogtest.CheckNoRules, "rewrite rule plant on ctrlz.sessions", []string{
			`CREATE RULE plant AS ON INSERT TO ctrlz.sessions DO ALSO UPDATE ctrlz.users SET enforce_passkey = false WHERE tenant_id = NEW.tenant_id AND id = NEW.user_id`}},
		{"a DO INSTEAD NOTHING rule on UPDATE", catalogtest.CheckNoRules, "DO INSTEAD", []string{
			`CREATE RULE keep AS ON UPDATE TO ctrlz.sessions WHERE NEW.revoked_at IS NOT NULL DO INSTEAD NOTHING`}},
		{"an extra rule on a listed view", catalogtest.CheckNoRules, "rewrite rule hide on ctrlz.tenant_profile_counts", []string{
			`CREATE RULE hide AS ON INSERT TO ctrlz.tenant_profile_counts DO INSTEAD NOTHING`}},
		{"a view nobody listed", catalogtest.CheckNoRules, "ctrlz.zz_view", []string{
			`CREATE VIEW ctrlz.zz_view WITH (security_invoker = true) AS SELECT 1 AS x`}},
		{"a rule outside ctrlz", catalogtest.CheckNoRules, "zz_other.t", []string{
			`CREATE SCHEMA zz_other`, `CREATE TABLE zz_other.t (id int)`, `CREATE RULE r AS ON INSERT TO zz_other.t DO INSTEAD NOTHING`}},
	} {
		t.Run(m.name, func(t *testing.T) {
			v := strings.Join(runCheck(t, h, m.check, h.fx, m.sql...), "\n")
			if !strings.Contains(v, m.want) {
				t.Errorf("did not report %q; it said %q", m.want, v)
			}
		})
	}
	// Check 28 judges the two schemas the service owns, so another schema's unenforced constraint is not its business.
	if v := runCheck(t, h, catalogtest.CheckConstraintsEnforced, h.fx, `CREATE SCHEMA zz`, `CREATE TABLE zz.t (id int CHECK (id > 0) NOT ENFORCED)`); len(v) != 0 {
		t.Errorf("check 28 judged a schema that is not ctrlz or river: %v", v)
	}
}
