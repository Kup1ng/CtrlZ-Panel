package catalogtest_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	pgmigrations "github.com/Kup1ng/CtrlZ-Panel/migrations/postgres"

	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

// Round 18, database area (db-r18-9, db-r18-10): two defects of the watchdog's lock rule, both found by
// running it against what it was written to judge.

// TestTheWatchdogMeasuresTheWaitNotTheStatement is db-r18-9. The first form took the waiter's state_change (when
// its STATEMENT began) as the start of its wait. A statement that works for a while and then waits a moment on
// a row therefore read as a long waiter, and an honest holder that was merely between two statements (idle in
// its transaction past the block bound) was named the blocker of a long wait that had not happened and ended.
// pg_locks.waitstart is when the wait began. The waiter here is a DO block that spends 4 s before it asks for
// the row, so its statement is older than the 3 s bound while its wait is milliseconds old: the sweep leaves the
// holder alone; once the wait itself is older than the bound the same holder is ended.
func TestTheWatchdogMeasuresTheWaitNotTheStatement(t *testing.T) {
	c := testpg.Need(t, cluster)
	h := newHarness(t, c)
	ctx := h.ctx
	sweep := sweeper(t, c, h, installWatchdog(t, c, h))

	holder := zeroedTenantTx(t, h)
	if _, err := holder.Exec(ctx, lockRowOfA, h.A.Tenant); err != nil {
		t.Fatal(err)
	}
	owner, err := h.db.Super(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close(context.Background())
	waiterDone := make(chan error, 1)
	go func() {
		_, err := owner.Exec(ctx, fmt.Sprintf(`DO $$ BEGIN PERFORM pg_catalog.pg_sleep(4);
  UPDATE ctrlz.tenants SET status = status WHERE id = '%s'; END $$`, h.A.Tenant))
		waiterDone <- err
	}()
	awaitLockWaiters(t, ctx, h.fresh(), 1)

	// The holder has been idle in its transaction since before the waiter's statement began, so the old
	// reading (a statement older than the bound) named it. The wait itself is younger than the bound.
	if got := sweep("3600", "3"); got != "0" {
		t.Fatalf("a holder was ended for a wait that began moments ago because the waiting STATEMENT is 4 s old (%q)", got)
	}
	ended := ""
	for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline) && ended != "1"; {
		if ended = sweep("3600", "3"); ended != "1" {
			time.Sleep(500 * time.Millisecond)
		}
	}
	if ended != "1" {
		t.Fatal("a holder that is idle in its transaction while a session has waited past the bound was never ended")
	}
	select {
	case err := <-waiterDone:
		if err != nil {
			t.Fatalf("the waiter failed: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("the waiter is still blocked after the holder was ended")
	}
}

// TestTheWatchdogEndsAServiceBackendThatHoldsATableLock is db-r18-10. Postgres lets a role with a table-level
// UPDATE, DELETE, TRUNCATE or MAINTAIN run LOCK TABLE in any mode (a column grant does not count), and a mode
// above ROW EXCLUSIVE stops every statement on the table for every tenant. The age and hold rules judge a
// holder by its time and would leave it for hold_secs per holder. Every mode no ordinary statement takes is
// ended at the next sweep whatever the age of the backend (a transaction seconds old, no waiter at all), and
// the three modes every SELECT, INSERT, UPDATE, DELETE and FOR UPDATE takes are left alone.
func TestTheWatchdogEndsAServiceBackendThatHoldsATableLock(t *testing.T) {
	c := testpg.Need(t, cluster)
	h := newHarness(t, c)
	ctx := h.ctx
	sweep := sweeper(t, c, h, installWatchdog(t, c, h))

	for _, tc := range []struct {
		mode string
		ends bool
	}{
		{"ACCESS SHARE", false}, {"ROW SHARE", false}, {"ROW EXCLUSIVE", false},
		{"SHARE UPDATE EXCLUSIVE", true}, {"SHARE", true}, {"SHARE ROW EXCLUSIVE", true},
		{"EXCLUSIVE", true}, {"ACCESS EXCLUSIVE", true},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			conn := zeroedTenantTx(t, h)
			if _, err := conn.Exec(ctx, "LOCK TABLE ctrlz.sessions IN "+tc.mode+" MODE"); err != nil {
				t.Fatalf("the premise of the finding (a service role may take the lock) does not hold: %v", err)
			}
			want := "0"
			if tc.ends {
				want = "1"
			}
			// Neither a waiter nor an old transaction: only the mode is judged.
			if got := sweep("3600", "3600"); got != want {
				t.Fatalf("a service backend holding %s: the sweep ended %q backends, want %s", tc.mode, got, want)
			}
			_, err := conn.Exec(ctx, "SELECT 1")
			if tc.ends && err == nil {
				t.Errorf("the backend that held %s is still alive", tc.mode)
			}
			if !tc.ends && err != nil {
				t.Errorf("an honest backend (%s) was ended: %v", tc.mode, err)
			}
		})
	}
}

// TestASweepThatCannotReadTheLockTableErrorsAndTheHealthCheckSaysSo is the failure behaviour of rule (d) of
// watchdog.sql (db-r18-10, db-r18-21): the rule reads pg_locks, and a sweep that cannot (a view that is gone or
// renamed by a Postgres version, a permission nobody expected) must neither end nobody and call itself well
// nor end everybody. The statement errors as a whole (ON_ERROR_STOP), so the script prints no number and does
// not touch its heartbeat, and the container's healthcheck (`watchdog.sh --healthy`) fails: the stack does not
// start with a watchdog that cannot judge. The broken text is the real SQL with every reference to pg_locks
// pointed at a relation that does not exist, so the test also fails if a reference to the lock table is
// ever spelled so that the substitution misses it.
func TestASweepThatCannotReadTheLockTableErrorsAndTheHealthCheckSaysSo(t *testing.T) {
	c := testpg.Need(t, cluster)
	h := newHarness(t, c)
	dir := installWatchdog(t, c, h)
	real, err := pgmigrations.Bootstrap.ReadFile("bootstrap/watchdog.sql")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(real), "pg_catalog.pg_locks") {
		t.Fatal("the watchdog SQL no longer reads pg_catalog.pg_locks; the premise of this test is gone")
	}
	broken := strings.ReplaceAll(string(real), "pg_catalog.pg_locks", "pg_catalog.pg_locks_unreadable")
	// Only the code is judged: a comment may name the view.
	for _, ln := range strings.Split(broken, "\n") {
		if code, _, _ := strings.Cut(ln, "--"); strings.Contains(strings.ReplaceAll(code, "pg_locks_unreadable", ""), "pg_locks") {
			t.Fatalf("the watchdog SQL reads the lock table through a spelling this test does not replace: %q", ln)
		}
	}
	if err := c.CopyIn(h.ctx, dir+"/broken.sql", []byte(broken), 0o644); err != nil {
		t.Fatal(err)
	}
	run := func(sqlFile, beat string, args ...string) (string, int) {
		t.Helper()
		out, code, err := c.Exec(h.ctx, "postgres", []string{
			"CTRLZ_PG_WATCHDOG_ONCE=1", "CTRLZ_DB_NAME=" + h.db.Name, "CTRLZ_PG_WATCHDOG_MAX_TX=3600", "CTRLZ_PG_WATCHDOG_MAX_BLOCK=3600",
			"CTRLZ_PG_WATCHDOG_SQL=" + dir + "/" + sqlFile, "CTRLZ_PG_WATCHDOG_BEAT=" + beat,
		}, append([]string{"sh", dir + "/watchdog.sh"}, args...)...)
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(out), code
	}
	exists := func(path string) bool {
		_, code, err := c.Exec(h.ctx, "postgres", nil, "test", "-f", path)
		if err != nil {
			t.Fatal(err)
		}
		return code == 0
	}

	beat := "/tmp/ctrlz-wd-beat-broken" // /tmp is writable by the postgres user; the directory of the copied script is root's
	if out, code := run("broken.sql", beat); out != "" || code != 0 {
		t.Fatalf("a sweep that cannot read the lock table printed %q (exit %d), want nothing", out, code)
	}
	if exists(beat) {
		t.Fatal("a sweep that failed touched the heartbeat")
	}
	if _, code := run("broken.sql", beat, "--healthy"); code == 0 {
		t.Fatal("the health check passes for a watchdog that has never completed a sweep")
	}

	good := "/tmp/ctrlz-wd-beat-good"
	if out, code := run("watchdog.sql", good); out == "" || code != 0 {
		t.Fatalf("the real sweep printed %q (exit %d), want a count", out, code)
	}
	if !exists(good) {
		t.Fatal("a sweep that ran did not touch the heartbeat")
	}
	if _, code := run("watchdog.sql", good, "--healthy"); code != 0 {
		t.Fatal("the health check fails right after a sweep that ran")
	}
}
