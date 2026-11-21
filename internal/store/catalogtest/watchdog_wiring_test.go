package catalogtest_test

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

// The watchdog's wiring, run: the Compose file's entrypoint, scripts, configuration and healthcheck in the
// pinned image (db-r16-4 and db-r16-10). The earlier tests ran the script with `docker exec` in a plain
// server, so everything that decides whether the process runs in production was read and never run: a
// watchdog that never started, one whose psql could not get in (a changed socket directory or pg_hba
// line), one that died. Two further defects sat in the wiring: the watchdog was an untracked child of the
// postmaster, so its death by a signal made Postgres terminate every backend and run crash recovery; and
// a bad setting made the script exit 1 with one stderr line while the stack ran with no watchdog.

// healthy runs the watchdog half of the Compose healthcheck, as root, the way Docker runs it.
func healthy(ctx context.Context, w *testpg.Wiring) bool {
	_, code, err := w.Exec(ctx, "", "sh", "/ctrlz-postgres/watchdog.sh", "--healthy")
	return err == nil && code == 0
}

func waitFor(t *testing.T, what string, limit time.Duration, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(limit)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %s waiting for: %s", limit, what)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func TestTheWatchdogRunsInTheContainerTheComposeFileStarts(t *testing.T) {
	testpg.Need(t, cluster)
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	w, err := testpg.StartWiring(ctx, "../../..", map[string]string{
		"CTRLZ_PG_WATCHDOG_INTERVAL": "1", "CTRLZ_PG_WATCHDOG_MAX_TX": "300", "CTRLZ_PG_WATCHDOG_MAX_BLOCK": "2",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Terminate(context.Background())
	psql := func(sql string) string {
		t.Helper()
		out, code, err := w.Exec(ctx, "postgres", "psql", "-h", "/var/run/postgresql", "-U", "postgres", "-d", "postgres", "-X", "-At", "-c", sql)
		if err != nil || code != 0 {
			t.Fatalf("psql %q: %q exit %d: %v", sql, out, code, err)
		}
		return strings.TrimSpace(out)
	}

	// 1. The watchdog started, got in over the socket by peer authentication, and says so.
	waitFor(t, "the watchdog's first successful sweep (the healthcheck half)", 90*time.Second, func() bool {
		_, code, err := w.Exec(ctx, "postgres", "psql", "-h", "/var/run/postgresql", "-U", "postgres", "-d", "postgres", "-X", "-At", "-c", "SELECT 1")
		return err == nil && code == 0 && healthy(ctx, w)
	})
	started := psql("SELECT pg_postmaster_start_time()")

	// 2. The watchdog's process is killed by a signal, the way the OOM killer or pkill would. The
	// postmaster is not its parent: no backend is terminated, the server does not run crash recovery, and
	// the container starts the watchdog again.
	scan := `{ for p in /proc/[0-9]*; do [ "$p" = "/proc/$$" ] && continue; c=$(tr '\000' ' ' < $p/cmdline 2>/dev/null); case "$c" in *"sh /ctrlz-postgres/watchdog.sh"*) echo ${p#/proc/};; esac; done; } 2>/dev/null`
	pids, code, err := w.Exec(ctx, "", "sh", "-c", scan)
	if err != nil || code != 0 || strings.TrimSpace(pids) == "" {
		t.Fatalf("no watchdog process found: %q exit %d: %v", pids, code, err)
	}
	for _, p := range strings.Fields(pids) {
		if _, err := strconv.Atoi(p); err != nil {
			continue
		}
		if out, code, err := w.Exec(ctx, "", "kill", "-9", p); err != nil || code != 0 {
			t.Fatalf("kill -9 %s: %q %d %v", p, out, code, err)
		}
	}
	time.Sleep(4 * time.Second)
	if got := psql("SELECT pg_postmaster_start_time()"); got != started {
		t.Errorf("the postmaster restarted after the watchdog was killed (%s, then %s)", started, got)
	}
	logs, err := w.Logs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(logs, "untracked child") || strings.Contains(logs, "terminating any other active server processes") {
		t.Errorf("Postgres treated the watchdog's death as a crash of its own:\n%s", logs)
	}
	if !strings.Contains(logs, "ctrlz postgres watchdog: ended, starting it again") {
		t.Error("the container did not say it started the watchdog again")
	}
	waitFor(t, "a fresh sweep after the watchdog was started again", 30*time.Second, func() bool { return healthy(ctx, w) })

	// 3. A watchdog that runs and cannot do its job turns the container unhealthy: the SQL it runs is
	// gone (a mount typo), the beat goes stale, and the healthcheck says so. Nothing in Postgres'
	// own health shows it.
	if out, code, err := w.Exec(ctx, "", "sh", "-c", "mv /ctrlz-bootstrap/watchdog.sql /ctrlz-bootstrap/watchdog.sql.away && touch -d '10 minutes ago' /tmp/ctrlz-watchdog.beat"); err != nil || code != 0 {
		t.Fatalf("breaking the mount: %q %d %v", out, code, err)
	}
	time.Sleep(3 * time.Second)
	if healthy(ctx, w) {
		t.Error("the healthcheck accepts a watchdog whose sweeps no longer run")
	}
	if out, code, err := w.Exec(ctx, "", "mv", "/ctrlz-bootstrap/watchdog.sql.away", "/ctrlz-bootstrap/watchdog.sql"); err != nil || code != 0 {
		t.Fatalf("repairing the mount: %q %d %v", out, code, err)
	}
	waitFor(t, "the healthcheck to pass again once sweeps run", 30*time.Second, func() bool { return healthy(ctx, w) })

	// 3b. A psql that hangs (db-r16-30). The sweep runs under timeout, so the loop is not stuck behind it: the
	// hung psql is killed and the next sweep is tried (two starts of the fake in about half a minute), and
	// while it keeps hanging no sweep runs, no beat is written, and the healthcheck turns the container
	// unhealthy. With the real psql back, the next sweep runs and the container is healthy again.
	hang := `P=$(command -v psql) && mv "$P" "$P.real" && printf '#!/bin/sh\necho x >> /tmp/psql-calls\nexec sleep 1000\n' > "$P" && chmod +x "$P" && rm -f /tmp/psql-calls && touch -d '10 minutes ago' /tmp/ctrlz-watchdog.beat`
	if out, code, err := w.Exec(ctx, "", "sh", "-c", hang); err != nil || code != 0 {
		t.Fatalf("making psql hang: %q %d %v", out, code, err)
	}
	calls := func() int {
		out, _, _ := w.Exec(ctx, "", "sh", "-c", "wc -l < /tmp/psql-calls 2>/dev/null || echo 0")
		n, _ := strconv.Atoi(strings.TrimSpace(out))
		return n
	}
	waitFor(t, "the loop to start a second sweep after the first one hung", 60*time.Second, func() bool { return calls() >= 2 })
	if healthy(ctx, w) {
		t.Error("the healthcheck accepts a watchdog whose psql hangs and runs no sweep")
	}
	if out, code, err := w.Exec(ctx, "", "sh", "-c", `P=$(command -v psql) && mv -f "$P.real" "$P"`); err != nil || code != 0 {
		t.Fatalf("restoring psql: %q %d %v", out, code, err)
	}
	_, _, _ = w.Exec(ctx, "", "sh", "-c", "pkill -f 'sleep 1000' || true")
	waitFor(t, "the healthcheck to pass again once psql answers", 60*time.Second, func() bool { return healthy(ctx, w) })

	// 4. A stop is a clean shutdown of Postgres with its own exit status, not a kill after the grace period.
	exit, took, err := w.Stop(ctx, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if exit != 0 {
		t.Errorf("the container ended with status %d, want 0 (Postgres' own status after a fast shutdown)", exit)
	}
	if took > 20*time.Second {
		t.Errorf("the stop took %s: the stop signal did not reach the postmaster", took)
	}
	logs, _ = w.Logs(ctx)
	if !strings.Contains(logs, "database system is shut down") {
		t.Errorf("Postgres did not shut down cleanly on the stop signal:\n%s", logs)
	}
}

// TestTheContainerRefusesToStartWithAWatchdogSettingThatIsNotValid is the silent half of db-r16-10: a
// bound that is not a whole number made the script exit 1 with one stderr line, and the stack ran with no
// watchdog. Now the container does not start.
func TestTheContainerRefusesToStartWithAWatchdogSettingThatIsNotValid(t *testing.T) {
	testpg.Need(t, cluster)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	for name, env := range map[string]map[string]string{
		"a bound with a unit":              {"CTRLZ_PG_WATCHDOG_MAX_TX": "5m"},
		"a zero lock bound":                {"CTRLZ_PG_WATCHDOG_MAX_BLOCK": "0"},
		"an interval that is not a number": {"CTRLZ_PG_WATCHDOG_INTERVAL": "abc"},
	} {
		t.Run(name, func(t *testing.T) {
			w, err := testpg.StartWiring(ctx, "../../..", env)
			if err != nil {
				t.Fatal(err)
			}
			defer w.Terminate(context.Background())
			waitFor(t, "the container to stop", 60*time.Second, func() bool {
				running, _, err := w.Running(ctx)
				return err == nil && !running
			})
			_, code, _ := w.Running(ctx)
			if code != 1 {
				t.Errorf("exit status %d, want 1", code)
			}
			logs, _ := w.Logs(ctx)
			if !strings.Contains(logs, "not starting") {
				t.Errorf("the container did not say why it stopped:\n%s", logs)
			}
			if strings.Contains(logs, "database system is ready to accept connections") {
				t.Error("Postgres started although the watchdog's settings were not valid")
			}
		})
	}
}
