package authtest

import (
	"encoding/hex"
	"regexp"
	"strings"
	"testing"
)

// The sink tables of spec 18.4. Each query counts the rows whose whole text
// holds a canary, either as written or as the hex a bytea column prints. The
// text of a row covers every column, jsonb ones included. Constant SQL only:
// the SQL lint bans anything built at run time.
// (a function, not a variable: the workspace lint bans package-level state)
func sinkQueries() []struct{ table, sql string } {
	return []struct{ table, sql string }{
		{"tenant_audit_log", `SELECT count(*) FROM ctrlz.tenant_audit_log t WHERE strpos(t::text, $1) > 0 OR strpos(t::text, $2) > 0`},
		{"audit_log", `SELECT count(*) FROM ctrlz.audit_log t WHERE strpos(t::text, $1) > 0 OR strpos(t::text, $2) > 0`},
		{"sms_deliveries", `SELECT count(*) FROM ctrlz.sms_deliveries t WHERE strpos(t::text, $1) > 0 OR strpos(t::text, $2) > 0`},
		{"alerts", `SELECT count(*) FROM ctrlz.alerts t WHERE strpos(t::text, $1) > 0 OR strpos(t::text, $2) > 0`},
		{"job_outbox", `SELECT count(*) FROM ctrlz.job_outbox t WHERE strpos(t::text, $1) > 0 OR strpos(t::text, $2) > 0`},
		{"notifications", `SELECT count(*) FROM ctrlz.notifications t WHERE strpos(t::text, $1) > 0 OR strpos(t::text, $2) > 0`},
		{"admin_jobs", `SELECT count(*) FROM ctrlz.admin_jobs t WHERE strpos(t::text, $1) > 0 OR strpos(t::text, $2) > 0`},
		// The tables the P2 write path keeps what a request carried: the stored answer of an idempotent request, the input,
		// result and error of a batch job (spec 10.5, lock secrets), and River's own table, where the arguments of a job live
		// (R21: "river args"; its args, metadata and errors are in the text of the row).
		{"idempotency_keys", `SELECT count(*) FROM ctrlz.idempotency_keys t WHERE strpos(t::text, $1) > 0 OR strpos(t::text, $2) > 0`},
		{"batch_jobs", `SELECT count(*) FROM ctrlz.batch_jobs t WHERE strpos(t::text, $1) > 0 OR strpos(t::text, $2) > 0`},
		{"river_job", `SELECT count(*) FROM river.river_job t WHERE strpos(t::text, $1) > 0 OR strpos(t::text, $2) > 0`},
	}
}

// AssertSinksClean fails if any canary is in one of the database sinks of
// spec 18.4: tenant_audit_log, audit_log, sms_deliveries, alerts, job_outbox,
// the notification rows, the admin job rows, and (P2) the idempotency keys, the batch jobs and River's jobs. It reads as the superuser, so
// row level security and column grants cannot hide a leak.
func (e *Env) AssertSinksClean(t *testing.T, canaries ...string) {
	t.Helper()
	for _, c := range canaries {
		if c == "" {
			t.Fatal("authtest: an empty canary matches everything")
		}
		hexForm := hex.EncodeToString([]byte(c))
		for _, q := range sinkQueries() {
			var n int
			e.Scan(t, q.sql, []any{c, hexForm}, &n)
			if n != 0 {
				t.Errorf("a canary (%d characters starting %q) is in %s", len(c), c[:min(3, len(c))], q.table)
			}
		}
	}
}

// AssertServerLogClean fails if a canary is in the Postgres server log. The
// container logs the way Compose configures it: no statement text on errors,
// terse verbosity, so a failing INSERT leaves no row detail (spec 8.6).
func (e *Env) AssertServerLogClean(t *testing.T, canaries ...string) {
	t.Helper()
	log, err := e.DB.ServerLog(e.Ctx)
	if err != nil {
		t.Fatalf("read the Postgres log: %v", err)
	}
	AssertTextClean(t, "the Postgres server log", log, canaries...)
}

// noise is what a log holds that a program drew at random or read from a clock: a UUID (request,
// row and job ids) and the value of a "time" attribute. A canary is a short string, a code of six
// digits or a phone prefix of five, and a canary that short turns up inside a random identifier
// by chance: "09121" sat in the id "01a1d7aa-573c-774e-a2ba-091213706079" of a log line and failed
// the full CI run once in a while (round 8, a flake is a finding). The text is scrubbed of this noise
// before it is searched, so the check is a function of what the program chose to write and not of
// what the random number generator drew. A canary never has the shape of a UUID, and a secret that
// was written next to one is still found.
// (a function, not a variable: the workspace lint bans package-level state)
func noise() *regexp.Regexp {
	return regexp.MustCompile(`(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|"time":"[^"]*"`)
}

// ScrubNoise returns text without the random and clock values of noise.
func ScrubNoise(text string) string { return noise().ReplaceAllString(text, " ") }

// AssertTextClean fails if a canary is in text, and says which sink and how long
// the canary was, never the canary itself.
func AssertTextClean(t *testing.T, sink, text string, canaries ...string) {
	t.Helper()
	text = ScrubNoise(text)
	for _, c := range canaries {
		if c == "" {
			t.Fatal("authtest: an empty canary matches everything")
		}
		if strings.Contains(text, c) {
			t.Errorf("a canary (%d characters starting %q) is in %s", len(c), c[:min(3, len(c))], sink)
		}
	}
}
