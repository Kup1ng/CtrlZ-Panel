package catalogtest_test

import (
	"context"
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store/catalogtest"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

// Round 12, database area (db-r12-1, db-r12-2, db-r12-3).

// TestNaNIsRefusedInTheSpendAndInTheCapForEveryWriter is db-r12-1 and db-r12-3. Postgres sorts
// NaN above every number, so `>= 0` accepted it in the two money columns the cap itself reads. A
// NaN spend is "reached" for every cap and no UPDATE can lower it (every real value is below it,
// and the guard refuses a falling spend): one write by the sender would have refused every OTP of
// every tenant for the Tehran day. A NaN cap is never reached, so the money cap would silently
// stop stopping anything. Two lines, each tried alone: the guard (42501, every role) and the
// CHECK (23514, which holds when the trigger is off or replaced).
func TestNaNIsRefusedInTheSpendAndInTheCapForEveryWriter(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	h.seedCounters()

	type try struct {
		name, role string // role "" is the superuser
		replica    bool   // triggers off: only the CHECK stands
		sql        string
		code       string // "" means the statement must be accepted
	}
	var tries []try
	spend := func(role string, replica bool, code string) {
		who := role
		if who == "" {
			who = "superuser"
		}
		if replica {
			who += " with the triggers off"
		}
		// The sender may write only the two global rows, so its new row is the outbox one.
		newKey := "outbox-nan"
		if role == "worker" {
			newKey = "outbox"
		}
		for _, c := range []struct{ name, sql string }{
			{"a NaN spend on a new row", `INSERT INTO ctrlz.sms_counters (day, scope, key, count, cost) VALUES (` + cToday + `, 'global', '` + newKey + `-new', 0, 'NaN')`},
			{"a NaN added by an upsert", `INSERT INTO ctrlz.sms_counters AS c (day, scope, key, count, cost) VALUES (` + cToday + `, 'global', 'all', 0, 'NaN'::numeric) ON CONFLICT (day, scope, key) DO UPDATE SET cost = c.cost + EXCLUDED.cost`},
			{"a NaN written over the global spend", `UPDATE ctrlz.sms_counters SET cost = 'NaN' WHERE day = ` + cToday + ` AND scope = 'global' AND key = 'all'`},
			{"a sum that turns NaN", `UPDATE ctrlz.sms_counters SET cost = cost + 'NaN'::numeric WHERE day = ` + cToday + ` AND scope = 'global' AND key = 'all'`},
		} {
			sql := c.sql
			if role == "worker" {
				// The sender's one new row must be a key it may create; the guard runs first.
				sql = strings.ReplaceAll(sql, "'outbox-new'", "'outbox'")
			}
			tries = append(tries, try{who + " " + c.name, role, replica, sql, code})
		}
	}
	for _, role := range []string{"worker", "migrator", ""} {
		spend(role, false, "42501")
	}
	// The per-subject rows carry a cost column too, and the guard judges it as well.
	for _, role := range []string{"migrator", ""} {
		tries = append(tries, try{role + " a NaN written over a per-phone spend", role, false,
			`UPDATE ctrlz.sms_counters SET cost = 'NaN' WHERE scope = 'phone' AND key = 'p-today'`, "42501"})
	}
	spend("", true, "23514")
	tries = append(tries,
		// The CHECK is the line that is left when the guard is replaced.
		try{"a replaced guard still meets the CHECK on a per-phone row", "", true,
			`UPDATE ctrlz.sms_counters SET cost = 'NaN' WHERE scope = 'phone' AND key = 'p-today'`, "23514"},
		// Controls: a real spend still goes in, for the sender too.
		try{"the sender adds a plain price", "worker", false,
			`UPDATE ctrlz.sms_counters SET cost = cost + 0.5 WHERE day = ` + cToday + ` AND scope = 'global' AND key = 'all'`, ""},
		try{"the sender adds a price by upsert", "worker", false,
			`INSERT INTO ctrlz.sms_counters AS c (day, scope, key, count, cost) VALUES (` + cToday + `, 'global', 'all', 0, 1.5) ON CONFLICT (day, scope, key) DO UPDATE SET cost = c.cost + EXCLUDED.cost`, ""},
	)
	// The cap: the admin role holds a direct UPDATE, and the owner with the triggers off meets the CHECK.
	for _, c := range []struct {
		name, role string
		replica    bool
		value      string
		refused    bool
	}{
		{"the admin role", "admin", false, "'NaN'", true},
		{"the owner with the triggers off", "", true, "'NaN'", true},
		{"the admin role sets zero", "admin", false, "0", false},
		{"the admin role sets a plain cap", "admin", false, "5000.5", false},
		{"the admin role clears the cap", "admin", false, "NULL", false},
	} {
		code := ""
		if c.refused {
			code = "23514"
		}
		tries = append(tries, try{"the cap by " + c.name, c.role, c.replica,
			`UPDATE ctrlz.system_settings SET sms_cost_cap_daily = ` + c.value + `::numeric`, code})
	}

	for _, c := range tries {
		t.Run(c.name, func(t *testing.T) {
			tx, err := h.super.Begin(h.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			if c.replica {
				if _, err := tx.Exec(h.ctx, `SET LOCAL session_replication_role = replica`); err != nil {
					t.Fatal(err)
				}
			}
			if c.role != "" {
				if _, err := tx.Exec(h.ctx, `SET LOCAL ROLE ctrlz_`+c.role); err != nil {
					t.Fatal(err)
				}
			}
			_, err = tx.Exec(h.ctx, c.sql)
			switch {
			case c.code == "" && err != nil:
				t.Fatalf("a real value was refused: %v", err)
			case c.code != "" && err == nil:
				t.Fatal("NaN was written")
			case c.code != "":
				if pe := pgErr(err); pe == nil || pe.Code != c.code {
					t.Fatalf("want SQLSTATE %s, got %v", c.code, err)
				}
			}
		})
	}
}

// TestNaNCapIsReachedAndASpendOfNaNToo pins the comparison itself (db-r12-3): a cap nothing can be
// compared with is reached, and a NaN spend reaches every cap, so a NaN that got past the two lines
// above is a stopped service, which an operator sees, and not a silently open cap.
func TestNaNCapIsReachedAndASpendOfNaNToo(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	for _, c := range []struct {
		spent, cap string
		want       bool
	}{
		{"5", "'NaN'", true}, {"0", "'NaN'", true}, {"NULL", "'NaN'", true},
		{"'NaN'", "1000", true}, {"'NaN'", "NULL", false},
		{"5", "NULL", false}, {"5", "6", false},
	} {
		var got bool
		if err := h.super.QueryRow(h.ctx, `SELECT ctrlz.cap_reached(`+c.spent+`::numeric, `+c.cap+`::numeric)`).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != c.want {
			t.Errorf("cap_reached(%s, %s) = %v, want %v", c.spent, c.cap, got, c.want)
		}
	}
}

// TestNaNCheckCanFail is the proof for check 27 (rule tests-that-cannot-fail): the same shape that
// db-r11-1 closed for one column and db-r12-1 found in two more, a lower bound alone on a numeric
// column, is reported wherever it appears, for a column nobody has heard of, and every spelling that
// does refuse NaN is accepted. The exemption list is held to the same standard: an entry that is
// stale, for a column that is not there, or has no reason is reported.
func TestNaNCheckCanFail(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	run := func(fx *catalogtest.Fixtures, sql ...string) []string {
		t.Helper()
		tx, err := h.super.Begin(h.ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(context.Background())
		for _, s := range sql {
			if _, err := tx.Exec(h.ctx, s); err != nil {
				t.Fatalf("mutation %.100q does not apply: %v", s, err)
			}
		}
		v, err := catalogtest.CheckNaN(h.ctx, tx, fx)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	if v := run(h.fx); len(v) != 0 {
		t.Fatalf("the migrated database is not clean for check 27: %v", v)
	}
	withExempt := func(e ...catalogtest.NaNExempt) *catalogtest.Fixtures {
		fx := *h.fx
		fx.Tables.NaNExempt = e
		return &fx
	}
	for _, m := range []struct {
		name, want string
		sql        []string
		fx         *catalogtest.Fixtures
	}{
		// The two columns of db-r12-1 and the one of db-r11-1, each with only its lower bound left.
		{"the spend loses its NaN line", "sms_counters.cost", []string{`ALTER TABLE ctrlz.sms_counters DROP CONSTRAINT sms_counters_cost_not_nan`}, nil},
		{"the cap loses its NaN line", "system_settings.sms_cost_cap_daily", []string{`ALTER TABLE ctrlz.system_settings DROP CONSTRAINT system_settings_sms_cost_cap_not_nan`}, nil},
		{"the price loses its NaN line", "sms_gateways.cost_per_message", []string{
			`ALTER TABLE ctrlz.sms_gateways DROP CONSTRAINT sms_gateways_cost_not_negative`,
			`ALTER TABLE ctrlz.sms_gateways ADD CONSTRAINT sms_gateways_cost_not_negative CHECK (cost_per_message >= 0)`}, nil},
		// A column added tomorrow.
		{"a new money column with only a lower bound", "alerts.zz_probe", []string{`ALTER TABLE ctrlz.alerts ADD COLUMN zz_probe numeric(14,4) CHECK (zz_probe >= 0)`}, nil},
		{"a new money column with no check", "alerts.zz_probe", []string{`ALTER TABLE ctrlz.alerts ADD COLUMN zz_probe numeric`}, nil},
		{"a double precision column with no check", "alerts.zz_probe", []string{`ALTER TABLE ctrlz.alerts ADD COLUMN zz_probe double precision`}, nil},
		{"a real column with a lower bound", "alerts.zz_probe", []string{`ALTER TABLE ctrlz.alerts ADD COLUMN zz_probe real CHECK (zz_probe >= 0)`}, nil},
		{"a number array", "alerts.zz_probe", []string{`ALTER TABLE ctrlz.alerts ADD COLUMN zz_probe numeric[]`}, nil},
		{"a check over two columns is not a line on the column", "alerts.zz_probe", []string{
			`ALTER TABLE ctrlz.alerts ADD COLUMN zz_probe numeric, ADD COLUMN zz_other numeric`,
			`ALTER TABLE ctrlz.alerts ADD CONSTRAINT zz_two CHECK (zz_probe <> 'NaN'::numeric AND zz_other <> 'NaN'::numeric)`}, nil},
		// The exemption list.
		{"an exemption for a column that already refuses NaN", "sms_counters.cost is listed in nan_exempt", nil,
			withExempt(catalogtest.NaNExempt{Table: "sms_counters", Column: "cost", Reason: "x"})},
		{"an exemption for a column that is not there", "nan_exempt names alerts.nothing", nil,
			withExempt(catalogtest.NaNExempt{Table: "alerts", Column: "nothing", Reason: "x"})},
		{"an exemption with no reason", "has no reason", nil,
			withExempt(catalogtest.NaNExempt{Table: "alerts", Column: "zz_probe"})},
	} {
		t.Run(m.name, func(t *testing.T) {
			fx := m.fx
			if fx == nil {
				fx = h.fx
			}
			v := run(fx, m.sql...)
			if !strings.Contains(strings.Join(v, "\n"), m.want) {
				t.Errorf("check 27 did not report %q; it said %v", m.want, v)
			}
		})
	}
	// What must stay accepted: every spelling that does refuse NaN, and a listed exemption.
	for _, m := range []struct {
		name string
		sql  []string
		fx   *catalogtest.Fixtures
	}{
		{"an explicit NaN refusal on a typed numeric", []string{`ALTER TABLE ctrlz.alerts ADD COLUMN zz_probe numeric(14,4) CHECK (zz_probe >= 0 AND zz_probe <> 'NaN'::numeric)`}, nil},
		{"an unbounded numeric with both bounds", []string{`ALTER TABLE ctrlz.alerts ADD COLUMN zz_probe numeric CHECK (zz_probe >= 0 AND zz_probe < 'Infinity'::numeric)`}, nil},
		{"an upper bound that NaN fails", []string{`ALTER TABLE ctrlz.alerts ADD COLUMN zz_probe numeric(5,4) CHECK (zz_probe BETWEEN 0 AND 1)`}, nil},
		{"a float that is finite by two lines", []string{`ALTER TABLE ctrlz.alerts ADD COLUMN zz_probe double precision CHECK (zz_probe < 'Infinity' AND zz_probe > '-Infinity')`}, nil},
		{"a listed exemption with a reason", []string{`ALTER TABLE ctrlz.alerts ADD COLUMN zz_probe numeric`},
			withExempt(catalogtest.NaNExempt{Table: "alerts", Column: "zz_probe", Reason: "a display figure that no cap reads"})},
	} {
		t.Run("accepts "+m.name, func(t *testing.T) {
			fx := m.fx
			if fx == nil {
				fx = h.fx
			}
			if v := run(fx, m.sql...); len(v) != 0 {
				t.Errorf("check 27 reported a column that is fine: %v", v)
			}
		})
	}
}
