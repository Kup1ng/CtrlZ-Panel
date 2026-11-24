package caps_test

import (
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/caps"
)

// TestWholeRowOfLimitTableIsAnAllowList (sms-r17-19): the guard is an allow list over the select and
// RETURNING lists of a statement that names a limit table, so a spelling nobody thought of fails. Each
// bad case is a way to read a whole row, and each good case is a shape the module's own statements have.
func TestWholeRowOfLimitTableIsAnAllowList(t *testing.T) {
	bad := map[string]string{
		"a star":                          "SELECT * FROM ctrlz.system_settings",
		"a column alias list with AS":     "SELECT a7 FROM ctrlz.system_settings AS s(a1, a2, a3, a4, a5, a6, a7)",
		"a column alias list":             "SELECT a3 FROM ctrlz.system_settings s(a1, a2, a3)",
		"an alias list on a join":         "SELECT t.id FROM ctrlz.tenants t JOIN ctrlz.tenant_entitlements e(a, b, c) ON e.a = t.id",
		"an alias list on the bare table": "SELECT a FROM ctrlz.system_settings(a, b)",
		"a qualified star":                "SELECT s.* FROM ctrlz.system_settings s",
		"RETURNING a star":                "UPDATE ctrlz.system_settings SET open_grace_days = $1 RETURNING *",
		"a bare alias":                    "SELECT s FROM ctrlz.system_settings s",
		"a bare alias with AS":            "SELECT s FROM ctrlz.system_settings AS s",
		"a bare table name":               "SELECT system_settings FROM ctrlz.system_settings",
		"a bare schema-qualified table":   "SELECT ctrlz.system_settings FROM ctrlz.system_settings",
		"a bare alias given an alias":     "SELECT s AS row FROM ctrlz.system_settings s",
		"a bare alias given one with AS":  "SELECT s r FROM ctrlz.system_settings s",
		"a cast of the alias":             "SELECT s::text FROM ctrlz.system_settings s",
		"a cast of the alias to jsonb":    "SELECT s::jsonb FROM ctrlz.system_settings s",
		"a row in parentheses":            "SELECT (s).* FROM ctrlz.system_settings s",
		"to_jsonb":                        "SELECT to_jsonb(s) FROM ctrlz.system_settings s",
		"row_to_json":                     "SELECT row_to_json(s) FROM ctrlz.system_settings s",
		"ROW(":                            "SELECT ROW(s.*) FROM ctrlz.system_settings s",
		"TABLE":                           "TABLE ctrlz.system_settings",
		"VALUES over the table":           "VALUES ((SELECT s FROM ctrlz.system_settings s))",
		"a second item that is the row":   "SELECT registration_mode, s FROM ctrlz.system_settings s",
		"a sub-select with the row":       "SELECT registration_mode FROM ctrlz.system_settings WHERE EXISTS (SELECT s FROM ctrlz.system_settings s)",
		"DISTINCT":                        "SELECT DISTINCT s FROM ctrlz.system_settings s",
		"DISTINCT ON":                     "SELECT DISTINCT ON (registration_mode) s FROM ctrlz.system_settings s",
		"a row through unnest":            "SELECT x FROM unnest(ARRAY(SELECT s FROM ctrlz.system_settings s)) x",
		"a CTE":                           "WITH r AS (SELECT * FROM ctrlz.system_settings) SELECT registration_mode FROM r",
		"INSERT ... SELECT":               "INSERT INTO ctrlz.t SELECT s FROM ctrlz.system_settings s",
		"DELETE RETURNING the row":        "DELETE FROM ctrlz.tenant_entitlements e WHERE tenant_id = $1 RETURNING e",
		"another limit table":             "SELECT * FROM ctrlz.entitlement_defaults",
		"a correlated bare alias in a select over another table": "SELECT 1 FROM ctrlz.system_settings s WHERE EXISTS (SELECT s FROM generate_series(1, 1))",
		"a row test":            "SELECT 1 FROM ctrlz.system_settings s WHERE s IS NOT NULL",
		"a parenthesised alias": "SELECT (s).registration_mode FROM ctrlz.system_settings s",
		"a star of another alias beside a limit table": "SELECT t.* FROM ctrlz.tenants t JOIN ctrlz.tenant_entitlements e ON e.tenant_id = t.id",
		"a star in a CTE":                "WITH r AS (SELECT * FROM ctrlz.tenant_entitlements) SELECT 1 FROM r",
		"a qualified star in a where":    "SELECT 1 FROM ctrlz.system_settings s WHERE (SELECT count(s.*)) > 0",
		"EXPLAIN":                        "EXPLAIN SELECT 1 FROM ctrlz.system_settings",
		"in a lower case with a comment": "select /* x */ S from ctrlz.system_settings s",
		"a quoted alias":                 `SELECT "s" FROM ctrlz.system_settings "s"`,
		"a USING alias":                  "DELETE FROM ctrlz.t USING ctrlz.system_settings s RETURNING s",
		"a join alias":                   "SELECT j FROM ctrlz.t JOIN ctrlz.system_settings j ON true",
	}
	for name, sql := range bad {
		if got := caps.WholeRowOfLimitTable(sql); got == "" {
			t.Errorf("%s: %q passed", name, sql)
		}
	}
	good := map[string]string{
		"plain columns":                               "SELECT registration_mode, open_grace_days, takeover_idle_days FROM ctrlz.system_settings",
		"a literal":                                   "SELECT 1 FROM ctrlz.system_settings",
		"true":                                        "SELECT true FROM ctrlz.system_settings s WHERE s.registration_mode = $1",
		"a qualified column with an alias":            "SELECT s.registration_mode AS m, s.open_grace_days n FROM ctrlz.system_settings s",
		"a parameter":                                 "SELECT $1 FROM ctrlz.system_settings",
		"an update with no list":                      "UPDATE ctrlz.system_settings SET registration_mode = $1, open_grace_days = COALESCE($2::integer, open_grace_days)",
		"an update returning a column":                "UPDATE ctrlz.system_settings SET registration_mode = $1 RETURNING registration_mode",
		"for update":                                  "SELECT registration_mode FROM ctrlz.system_settings FOR UPDATE SKIP LOCKED",
		"a sub-select of plain columns":               "SELECT registration_mode FROM ctrlz.system_settings WHERE EXISTS (SELECT 1 FROM ctrlz.system_settings s WHERE s.registration_mode IS NOT NULL)",
		"a text that names no limit table":            "SELECT * FROM ctrlz.users",
		"a call of the shared expression":             "SELECT NOT ctrlz.cap_reached(0, (SELECT s.sms_outbox_cap_daily FROM ctrlz.system_settings s)) AS room",
		"a join of a table that is not it":            "SELECT t.id FROM ctrlz.tenants t JOIN ctrlz.tenant_entitlements e ON e.tenant_id = t.id",
		"a DISTINCT column":                           "SELECT DISTINCT registration_mode FROM ctrlz.system_settings",
		"a call over plain columns":                   "SELECT coalesce(registration_mode, 'x'), open_grace_days + 1 FROM ctrlz.system_settings",
		"count of rows":                               "SELECT count(*) FROM ctrlz.system_settings",
		"a gate CTE":                                  "WITH money AS (SELECT NOT ctrlz.cap_reached(0, s.sms_cost_cap_daily) AS room FROM ctrlz.system_settings s) SELECT 1 FROM money WHERE money.room",
		"a star over a CTE of plain columns":          "WITH r AS (SELECT registration_mode FROM ctrlz.system_settings) SELECT * FROM r",
		"a bare alias of a table that is not a limit": "SELECT t FROM ctrlz.tenants t JOIN ctrlz.tenant_entitlements e ON e.tenant_id = t.id",
		"an insert column list":                       "INSERT INTO ctrlz.tenant_entitlements (tenant_id, max_profiles) VALUES ($1, $2)",
		"an insert with an alias and a list":          "INSERT INTO ctrlz.tenant_entitlements AS e (tenant_id) VALUES ($1)",
		"a where twice":                               "SELECT 1 FROM ctrlz.system_settings WHERE registration_mode = $1 AND EXISTS (SELECT 1 FROM ctrlz.t WHERE id = $2)",
		"a word in a string":                          "SELECT registration_mode FROM ctrlz.system_settings WHERE registration_mode <> 'select * from system_settings s where s is not null'",
	}
	for name, sql := range good {
		if got := caps.WholeRowOfLimitTable(sql); got != "" {
			t.Errorf("%s: %q refused: %s", name, sql, got)
		}
	}
	if got := caps.WholeRowOfLimitTable("SELECT * FROM ctrlz.system_settings"); !strings.Contains(got, "a star") {
		t.Errorf("the reason of a star: %q", got)
	}
}
