package catalogtest_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	pgmigrations "github.com/Kup1ng/CtrlZ-Panel/migrations/postgres"

	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

// TestTheWatchdogEndsATransactionThatSetItsOwnTimeoutsToZero is db-r15-7. The premise of round 14 was
// that a session-level advisory lock outlives the idle and statement timeouts while a row lock does
// not. It does: all of them are settings, any role may SET them to 0 in its own session, and
// statement_timeout bounds one statement and not a transaction anyway. So a compromised service
// could hold a row lock for ever through its own legitimate grants: the tenant API (UPDATE on
// tenants.home_countries, WithTenant for any tenant) could stop the owner suspending a tenant, and
// any role that can run auth_otp_issue could keep the global counter row locked and stop every
// message. Only a party the role does not control can end such a transaction: the watchdog of the
// postgres container (deploy/compose/postgres/watchdog.sh, bootstrap/watchdog.sql).
//
// The test runs the real script, with the real SQL, in the real container as the postgres user, over
// the local socket, the way entrypoint.sh starts it: a service role that has zeroed every timeout and
// holds a row lock is ended once its transaction is older than the bound; a younger one, a session
// that is not in a transaction, and the migrator (whose migrations may run long) are left alone.
func TestTheWatchdogEndsATransactionThatSetItsOwnTimeoutsToZero(t *testing.T) {
	c := testpg.Need(t, cluster)
	h := newHarness(t, c)
	ctx := h.ctx

	script, err := os.ReadFile("../../../deploy/compose/postgres/watchdog.sh")
	if err != nil {
		t.Fatal(err)
	}
	sqlText, err := pgmigrations.Bootstrap.ReadFile("bootstrap/watchdog.sql")
	if err != nil {
		t.Fatal(err)
	}
	dir := "/tmp/ctrlz-wd"
	if out, code, err := c.Exec(ctx, "", nil, "mkdir", "-p", dir); err != nil || code != 0 {
		t.Fatalf("mkdir: %q %d %v", out, code, err)
	}
	if err := c.CopyIn(ctx, dir+"/watchdog.sh", script, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := c.CopyIn(ctx, dir+"/watchdog.sql", sqlText, 0o644); err != nil {
		t.Fatal(err)
	}
	sweep := func(maxSecs string) string {
		t.Helper()
		out, code, err := c.Exec(ctx, "postgres", []string{
			"CTRLZ_PG_WATCHDOG_ONCE=1", "CTRLZ_DB_NAME=" + h.db.Name, "CTRLZ_PG_WATCHDOG_MAX_TX=" + maxSecs,
			"CTRLZ_PG_WATCHDOG_SQL=" + dir + "/watchdog.sql",
		}, "sh", dir+"/watchdog.sh")
		if err != nil || code != 0 {
			t.Fatalf("watchdog.sh: %q exit %d: %v", out, code, err)
		}
		return strings.TrimSpace(out)
	}

	// A tenant API session that has taken every bound off itself and holds the row of tenant A.
	tenant, err := h.db.Conn(ctx, "ctrlz_tenant")
	if err != nil {
		t.Fatal(err)
	}
	defer tenant.Close(context.Background())
	for _, sql := range []string{
		"SET statement_timeout = 0", "SET lock_timeout = 0", "SET idle_in_transaction_session_timeout = 0", "SET transaction_timeout = 0",
		"BEGIN",
	} {
		if _, err := tenant.Exec(ctx, sql); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	if _, err := tenant.Exec(ctx, "SELECT pg_catalog.set_config('ctrlz.tenant_id', $1, true)", h.A.Tenant.String()); err != nil {
		t.Fatal(err)
	}
	if tag, err := tenant.Exec(ctx, "UPDATE ctrlz.tenants SET home_countries = home_countries WHERE id = $1", h.A.Tenant); err != nil || tag.RowsAffected() != 1 {
		t.Fatalf("the tenant session could not lock its row: %v", err)
	}
	// A migrator transaction of the same age, and a service session that is not in a transaction.
	migrator, err := h.db.Conn(ctx, "ctrlz_migrator")
	if err != nil {
		t.Fatal(err)
	}
	defer migrator.Close(context.Background())
	if _, err := migrator.Exec(ctx, "BEGIN"); err != nil {
		t.Fatal(err)
	}
	if _, err := migrator.Exec(ctx, "SELECT 1"); err != nil {
		t.Fatal(err)
	}
	idle, err := h.db.Conn(ctx, "ctrlz_hub")
	if err != nil {
		t.Fatal(err)
	}
	defer idle.Close(context.Background())
	if _, err := idle.Exec(ctx, "SELECT 1"); err != nil {
		t.Fatal(err)
	}

	// The premise: the row is held, and the owner's suspension waits.
	blocked := func() bool {
		tx, err := h.super.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		if _, err := tx.Exec(ctx, "SET LOCAL lock_timeout = '400ms'"); err != nil {
			t.Fatal(err)
		}
		_, err = tx.Exec(ctx, "UPDATE ctrlz.tenants SET status = status WHERE id = $1", h.A.Tenant)
		return err != nil
	}
	if !blocked() {
		t.Fatal("the tenant session does not hold the row: the test proves nothing")
	}

	// Younger than the bound: nothing is ended.
	if got := sweep("3600"); got != "0" {
		t.Errorf("a sweep with a bound of an hour ended %q, want 0", got)
	}
	if !blocked() {
		t.Error("the row was released by a sweep that had nothing to end")
	}
	time.Sleep(2 * time.Second)
	// Older than a one second bound: the tenant session goes, the migrator and the idle one stay.
	if got := sweep("1"); got != "1" {
		t.Fatalf("a sweep with a bound of one second ended %q, want exactly 1 (the tenant session; not the migrator, not a session outside a transaction)", got)
	}
	if blocked() {
		t.Error("the row is still held after the watchdog ended the session")
	}
	if _, err := tenant.Exec(ctx, "SELECT 1"); err == nil {
		t.Error("the tenant session still answers after it was ended")
	}
	if _, err := migrator.Exec(ctx, "SELECT 1"); err != nil {
		t.Errorf("the migrator's transaction was ended: %v", err)
	}
	if _, err := idle.Exec(ctx, "SELECT 1"); err != nil {
		t.Errorf("a session outside a transaction was ended: %v", err)
	}

	// The script refuses a bound that is not a whole number of seconds, which would reach the SQL.
	for _, bad := range []string{"1; DROP TABLE x", "0", "-5", "1.5"} {
		out, code, err := c.Exec(ctx, "postgres", []string{"CTRLZ_PG_WATCHDOG_ONCE=1", "CTRLZ_PG_WATCHDOG_MAX_TX=" + bad}, "sh", dir+"/watchdog.sh")
		if err != nil {
			t.Fatal(err)
		}
		if code == 0 {
			t.Errorf("a bound of %q was accepted: %q", bad, out)
		}
	}
}
