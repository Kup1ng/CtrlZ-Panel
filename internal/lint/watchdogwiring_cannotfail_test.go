package lint_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestComposeWatchdogLintCanFail plants each defect of the wiring in the real files, one at a time, and
// requires the comparison to say so; the unplanted files must be clean. A lint that cannot fail proves
// nothing, and this one sat unwritten because the wiring "was not run, only the script and SQL" (db-r16-4).
func TestComposeWatchdogLintCanFail(t *testing.T) {
	root := repoRoot(t)
	read := func(rel string) string {
		b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	compose, entry, script := read("deploy/compose/docker-compose.yml"), read("deploy/compose/postgres/entrypoint.sh"), read("deploy/compose/postgres/watchdog.sh")
	hba, conf := read("deploy/compose/postgres/pg_hba.conf"), read("deploy/compose/postgres/postgresql.conf")
	realLS := func(dir string) []string { return listDir(t, filepath.Join(root, filepath.FromSlash(dir))) }

	if got := watchdogWiringProblems(compose, entry, script, hba, conf, realLS); len(got) != 0 {
		t.Fatalf("the real files are not clean: %v", got)
	}
	replace := func(s, old, new string) string {
		if strings.Count(s, old) != 1 {
			t.Fatalf("the plant %q occurs %d times, want 1", old, strings.Count(s, old))
		}
		return strings.Replace(s, old, new, 1)
	}
	cases := []struct {
		name, want string
		compose    string
		entry      string
		script     string
		hba, conf  string
		ls         func(string) []string
	}{
		{"a typo in the mount of the script", "is not mounted", replace(compose, "/ctrlz-postgres/watchdog.sh:ro", "/ctrlz-postgres/watchdogg.sh:ro"), entry, script, hba, conf, realLS},
		{"the script mounted from another file", "is mounted from", replace(compose, "./postgres/watchdog.sh:/ctrlz-postgres/watchdog.sh", "./postgres/entrypoint.sh:/ctrlz-postgres/watchdog.sh"), entry, script, hba, conf, realLS},
		{"a healthcheck that does not ask the watchdog", "healthcheck does not run", replace(compose, " && sh /ctrlz-postgres/watchdog.sh --healthy", ""), entry, script, hba, conf, realLS},
		{"the bootstrap directory is not mounted", "of the watchdog's SQL is not mounted", replace(compose, "      - ../../migrations/postgres/bootstrap:/ctrlz-bootstrap:ro\n", ""), entry, script, hba, conf, realLS},
		{"the SQL is not in the mounted directory", "is not in the mounted directory", compose, entry, script, hba, conf, func(string) []string { return []string{"10-cluster.sql"} }},
		{"a setting the script reads and Compose does not pass", "does not pass", replace(compose, "      CTRLZ_PG_WATCHDOG_MAX_BLOCK: ${CTRLZ_PG_WATCHDOG_MAX_BLOCK:-2}\n", ""), entry, script, hba, conf, realLS},
		{"a setting Compose passes and the script does not read", "does not read", compose, entry, replace(script, "block=${CTRLZ_PG_WATCHDOG_MAX_BLOCK:-2}", "block=2"), hba, conf, realLS},
		{"a default that differs", "one decision, one number", replace(compose, "${CTRLZ_PG_WATCHDOG_INTERVAL:-2}", "${CTRLZ_PG_WATCHDOG_INTERVAL:-3}"), entry, script, hba, conf, realLS},
		{"a bound with a unit", "whole number of seconds", replace(compose, "${CTRLZ_PG_WATCHDOG_MAX_TX:-300}", "${CTRLZ_PG_WATCHDOG_MAX_TX:-5m}"), entry, script, hba, conf, realLS},
		{"an age bound below the transaction timeout", "must be above the role's transaction_timeout", replace(compose, "${CTRLZ_PG_WATCHDOG_MAX_TX:-300}", "${CTRLZ_PG_WATCHDOG_MAX_TX:-100}"), entry, replace(script, "max=${CTRLZ_PG_WATCHDOG_MAX_TX:-300}", "max=${CTRLZ_PG_WATCHDOG_MAX_TX:-100}"), hba, conf, realLS},
		{"a lock bound at the lock timeout", "must be below the roles' lock_timeout", replace(compose, "${CTRLZ_PG_WATCHDOG_MAX_BLOCK:-2}", "${CTRLZ_PG_WATCHDOG_MAX_BLOCK:-5}"), entry, replace(script, "block=${CTRLZ_PG_WATCHDOG_MAX_BLOCK:-2}", "block=${CTRLZ_PG_WATCHDOG_MAX_BLOCK:-5}"), hba, conf, realLS},
		{"a sweep that can miss a waiter", "can miss a waiter", replace(compose, "${CTRLZ_PG_WATCHDOG_INTERVAL:-2}", "${CTRLZ_PG_WATCHDOG_INTERVAL:-15}"), entry, replace(script, "every=${CTRLZ_PG_WATCHDOG_INTERVAL:-2}", "every=${CTRLZ_PG_WATCHDOG_INTERVAL:-15}"), hba, conf, realLS},
		{"a hold bound at the lock timeout", "hold bound (5 s) must be above the roles' transaction_timeout", replace(compose, "${CTRLZ_PG_WATCHDOG_MAX_HOLD:-150}", "${CTRLZ_PG_WATCHDOG_MAX_HOLD:-5}"), entry, replace(script, "hold=${CTRLZ_PG_WATCHDOG_MAX_HOLD:-150}", "hold=${CTRLZ_PG_WATCHDOG_MAX_HOLD:-5}"), hba, conf, realLS},
		// db-r17-16: the first form of the hold bound was 15 s, above lock_timeout and far below what an honest
		// transaction that makes progress can reach (statement_timeout 30 s, transaction_timeout 120 s).
		{"the first hold bound: above the lock timeout, below the transaction timeout", "hold bound (15 s) must be above the roles' transaction_timeout", replace(compose, "${CTRLZ_PG_WATCHDOG_MAX_HOLD:-150}", "${CTRLZ_PG_WATCHDOG_MAX_HOLD:-15}"), entry, replace(script, "hold=${CTRLZ_PG_WATCHDOG_MAX_HOLD:-150}", "hold=${CTRLZ_PG_WATCHDOG_MAX_HOLD:-15}"), hba, conf, realLS},
		{"a hold bound at the transaction timeout", "hold bound (120 s) must be above the roles' transaction_timeout", replace(compose, "${CTRLZ_PG_WATCHDOG_MAX_HOLD:-150}", "${CTRLZ_PG_WATCHDOG_MAX_HOLD:-120}"), entry, replace(script, "hold=${CTRLZ_PG_WATCHDOG_MAX_HOLD:-150}", "hold=${CTRLZ_PG_WATCHDOG_MAX_HOLD:-120}"), hba, conf, realLS},
		{"a hold bound above the age bound", "must be below the age bound", replace(compose, "${CTRLZ_PG_WATCHDOG_MAX_HOLD:-150}", "${CTRLZ_PG_WATCHDOG_MAX_HOLD:-300}"), entry, replace(script, "hold=${CTRLZ_PG_WATCHDOG_MAX_HOLD:-150}", "hold=${CTRLZ_PG_WATCHDOG_MAX_HOLD:-300}"), hba, conf, realLS},
		{"a new variable nobody wired", "does not pass", compose, entry, script + "\nx=${CTRLZ_PG_WATCHDOG_NEW:-1}\n", hba, conf, realLS},
		{"a socket directory that is not the script's", "puts the socket in", compose, entry, script, hba, conf + "\nunix_socket_directories = '/tmp'\n", realLS},
		{"a pg_hba line that is not peer", "peer authentication", compose, entry, script, regexp.MustCompile(`(?m)^(local\s+all\s+postgres\s+)peer`).ReplaceAllString(hba, "${1}scram-sha-256"), conf, realLS},
		{"a pg_hba reject before the peer line", "peer authentication", compose, entry, script, "local   all       all                       reject\n" + hba, conf, realLS},
		{"the entrypoint names another script path", "exactly one watchdog script path", compose, entry + "\nsh /elsewhere/watchdog.sh &\n", script, hba, conf, realLS},
	}
	for _, c := range cases {
		got := watchdogWiringProblems(c.compose, c.entry, c.script, c.hba, c.conf, c.ls)
		found := false
		for _, p := range got {
			if strings.Contains(p, c.want) {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: want a problem containing %q, got %v", c.name, c.want, got)
		}
	}
}
