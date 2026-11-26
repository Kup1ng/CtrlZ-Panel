package caps_test

import (
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/caps"
)

// TestSharedArgsAreValues (sms-r18-11): the arguments of ctrlz.cap_reached are an allow list over what a
// value can be, so a limit compared by hand INSIDE the call (a CASE, a comparison operator, a function that
// compares, a second call, a limit named in a predicate of a subselect) fails, and the argument shapes the
// module's own statements and functions use pass. Each good text is a real shape.
func TestSharedArgsAreValues(t *testing.T) {
	bad := map[string]string{
		"the finding: a CASE over a limit": "SELECT 1 WHERE ctrlz.cap_reached(CASE WHEN $1 > (SELECT s.otp_cap_global FROM ctrlz.system_settings s) THEN 1 ELSE 0 END, 1)",
		"a comparison in the spent":        "SELECT 1 WHERE ctrlz.cap_reached(a.count > b.count, $1)",
		"an equality":                      "SELECT 1 WHERE ctrlz.cap_reached(a.count = 1, $1)",
		"a negation operator":              "SELECT 1 WHERE ctrlz.cap_reached(a.count != 1, $1)",
		"between":                          "SELECT 1 WHERE ctrlz.cap_reached(a.count BETWEEN 1 AND 2, $1)",
		"is null":                          "SELECT 1 WHERE ctrlz.cap_reached(a.count IS NULL, $1)",
		"greatest":                         "SELECT 1 WHERE ctrlz.cap_reached(GREATEST(a.count, $2), $1)",
		"least in the cap":                 "SELECT 1 WHERE ctrlz.cap_reached(a.count, LEAST($1, $2))",
		"a function that is not a value":   "SELECT 1 WHERE ctrlz.cap_reached(num_nonnulls(a.count), $1)",
		"a nested call":                    "SELECT 1 WHERE ctrlz.cap_reached(ctrlz.cap_reached(1, 2)::int, $1)",
		"a boolean word":                   "SELECT 1 WHERE ctrlz.cap_reached(a.count AND b.count, $1)",
		"a limit named in a predicate":     "SELECT 1 WHERE ctrlz.cap_reached((SELECT k.cost FROM ctrlz.sms_counters k WHERE k.cost > (SELECT s.sms_cost_cap_daily FROM ctrlz.system_settings s)), $1)",
		"a limit in an ON":                 "SELECT 1 WHERE ctrlz.cap_reached((SELECT k.cost FROM ctrlz.sms_counters k JOIN ctrlz.system_settings s ON k.cost < s.sms_cost_cap_daily), $1)",
		"an operator that concatenates":    "SELECT 1 WHERE ctrlz.cap_reached(a.count || 'x', $1)",
		"a cast with a comparison":         "SELECT 1 WHERE ctrlz.cap_reached((a.count > 1)::int, $1)",
		"in the plpgsql form":              "BEGIN IF ctrlz.cap_reached(CASE WHEN v_cfg.otp_cap_global < v_n THEN 1 END, 1) THEN RETURN; END IF; END",
		"a second call after a clean one":  "SELECT ctrlz.cap_reached(a.n, $1), ctrlz.cap_reached(CASE WHEN a.n > $2 THEN 1 END, $1)",
	}
	for name, sql := range bad {
		if got := caps.SharedArgsProblem(sql); got == "" {
			t.Errorf("%s: no problem for %q", name, sql)
		}
	}
	// The argument shapes in use: a parameter with a cast, a count, a column, the day's spend as a
	// subselect with a predicate that names no limit, an element of an array, arithmetic over a row
	// variable (the soft limit), a literal, a subselect of exactly one limit column.
	good := map[string]string{
		"a parameter with a cast":   "SELECT NOT ctrlz.cap_reached(count(*), $3::int) FROM ctrlz.webauthn_credentials WHERE tenant_id = $1",
		"a column":                  "SELECT 1 WHERE NOT ctrlz.cap_reached(n.count, $13::int)",
		"the spend of the day":      "SELECT 1 WHERE NOT ctrlz.cap_reached((SELECT k.cost FROM ctrlz.sms_counters k WHERE k.day = (now() AT TIME ZONE 'Asia/Tehran')::date AND k.scope = 'global' AND k.key = 'all'), (SELECT s.sms_cost_cap_daily FROM ctrlz.system_settings s))",
		"a limit column":            "SELECT NOT ctrlz.cap_reached(0, s.sms_cost_cap_daily) AS room FROM ctrlz.system_settings s",
		"a literal":                 "SELECT NOT ctrlz.cap_reached(0, (SELECT s.sms_outbox_cap_daily FROM ctrlz.system_settings s))",
		"an array element":          "UPDATE ctrlz.sms_counters c SET count = c.count + 1 WHERE NOT ctrlz.cap_reached(c.count, v_caps[i])",
		"arithmetic over variables": "IF ctrlz.cap_reached(v_gcount::numeric * 100, v_cfg.otp_cap_global::numeric * v_cfg.otp_soft_pct) THEN",
		"a coalesce of a sum":       "SELECT ctrlz.cap_reached((SELECT COALESCE(sum(k.cost), 0) FROM ctrlz.sms_counters k WHERE k.day = $1), $2)",
		"a numeric type with args":  "SELECT ctrlz.cap_reached($1::numeric(10, 2), $2)",
		"a text with no call":       "SELECT a > b FROM t WHERE c < d",
	}
	for name, sql := range good {
		if got := caps.SharedArgsProblem(sql); got != "" {
			t.Errorf("%s: %s", name, got)
		}
	}
	if got := caps.SharedArgsProblem("SELECT ctrlz.cap_reached(a, b"); !strings.Contains(got, "never closed") {
		t.Errorf("an unclosed call: %q", got)
	}
}
