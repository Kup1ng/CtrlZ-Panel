package catalogtest_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	pgmigrations "github.com/Kup1ng/CtrlZ-Panel/migrations/postgres"

	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

// zeroedTenantTx opens a ctrlz_tenant connection whose session took every bound off itself, starts a
// transaction and names tenant A (the caller runs the UPDATE it wants).
func zeroedTenantTx(t *testing.T, h *harness) *pgx.Conn {
	t.Helper()
	conn, err := h.db.Conn(h.ctx, "ctrlz_tenant")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close(context.Background()) })
	for _, sql := range []string{
		"SET statement_timeout = 0", "SET lock_timeout = 0", "SET idle_in_transaction_session_timeout = 0", "SET transaction_timeout = 0",
		"BEGIN",
	} {
		if _, err := conn.Exec(h.ctx, sql); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	if _, err := conn.Exec(h.ctx, "SELECT pg_catalog.set_config('ctrlz.tenant_id', $1, true)", h.A.Tenant.String()); err != nil {
		t.Fatal(err)
	}
	return conn
}

// installWatchdog copies the real script and SQL into the server's container and returns the directory.
func installWatchdog(t *testing.T, c *testpg.Cluster, h *harness) string {
	t.Helper()
	script, err := os.ReadFile("../../../deploy/compose/postgres/watchdog.sh")
	if err != nil {
		t.Fatal(err)
	}
	sqlText, err := pgmigrations.Bootstrap.ReadFile("bootstrap/watchdog.sql")
	if err != nil {
		t.Fatal(err)
	}
	dir := "/tmp/ctrlz-wd"
	if out, code, err := c.Exec(h.ctx, "", nil, "mkdir", "-p", dir); err != nil || code != 0 {
		t.Fatalf("mkdir: %q %d %v", out, code, err)
	}
	if err := c.CopyIn(h.ctx, dir+"/watchdog.sh", script, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := c.CopyIn(h.ctx, dir+"/watchdog.sql", sqlText, 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// sweeper returns a function that runs one sweep of the real script with the given bounds and returns
// the count it prints.
func sweeper(t *testing.T, c *testpg.Cluster, h *harness, dir string) func(maxTx, block string, extra ...string) string {
	return func(maxTx, block string, extra ...string) string {
		t.Helper()
		out, code, err := c.Exec(h.ctx, "postgres", append([]string{
			"CTRLZ_PG_WATCHDOG_ONCE=1", "CTRLZ_DB_NAME=" + h.db.Name, "CTRLZ_PG_WATCHDOG_MAX_TX=" + maxTx, "CTRLZ_PG_WATCHDOG_MAX_BLOCK=" + block,
			"CTRLZ_PG_WATCHDOG_SQL=" + dir + "/watchdog.sql",
		}, extra...), "sh", dir+"/watchdog.sh")
		if err != nil || code != 0 {
			t.Fatalf("watchdog.sh: %q exit %d: %v", out, code, err)
		}
		return strings.TrimSpace(out)
	}
}

const lockRowOfA = "UPDATE ctrlz.tenants SET home_countries = home_countries WHERE id = $1"

// TestTheWatchdogEndsALockThatIsHandedOverNotOnlyAnOldTransaction is db-r16-3 and db-r16-14. Round 15
// bounded one TRANSACTION. The hazard is the LOCK a role keeps: Postgres gives a released row lock to
// the first waiter in the queue, so a compromised role with two connections starts the second one's
// transaction before the first one's bound and queues it for the same row; when the age rule ends the
// first, the second holds the row, younger than the bound, and the cycle goes on while the owner's
// suspension (queued behind the relay) waits. The test runs that relay with the real script and SQL
// against two handing-over connections of ctrlz_tenant, and the owner's UPDATE as a waiter of another
// role:
//
//	stage 1: the age rule alone ends the old holder; the second connection inherits the row and the
//	         owner is still blocked (the premise: round 15's bound is not enough);
//	stage 2: the lock rule ends the handed-over holder, because it blocks a session that has waited
//	         more than the bound, and the owner's UPDATE goes through.
func TestTheWatchdogEndsALockThatIsHandedOverNotOnlyAnOldTransaction(t *testing.T) {
	c := testpg.Need(t, cluster)
	h := newHarness(t, c)
	ctx := h.ctx
	sweep := sweeper(t, c, h, installWatchdog(t, c, h))

	a := zeroedTenantTx(t, h)
	if _, err := a.Exec(ctx, lockRowOfA, h.A.Tenant); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Second) // A is old; B and the owner are younger than the bound of stage 1 (6 s: a sweep is a docker exec, and on a loaded machine B was past the old 4 s bound, a flake on main)

	b := zeroedTenantTx(t, h)
	bDone := make(chan error, 1)
	go func() { _, err := b.Exec(ctx, lockRowOfA, h.A.Tenant); bDone <- err }()
	awaitLockWaiters(t, ctx, h.fresh(), 1) // B is queued on the row before the owner starts (a condition, not a time)

	owner, err := h.db.Super(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close(context.Background())
	ownerDone := make(chan error, 1)
	go func() {
		_, err := owner.Exec(ctx, "UPDATE ctrlz.tenants SET status = status WHERE id = $1", h.A.Tenant)
		ownerDone <- err
	}()
	time.Sleep(2500 * time.Millisecond) // both have now waited longer than the block bound of stage 2

	// Stage 1: only the age rule. A is the one old transaction.
	if got := sweep("6", "3600"); got != "1" {
		t.Fatalf("the age rule ended %q backends, want exactly 1 (the old holder)", got)
	}
	select {
	case err := <-bDone:
		if err != nil {
			t.Fatalf("the second connection did not inherit the row: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the second connection never got the row after the first one was ended")
	}
	select {
	case err := <-ownerDone:
		t.Fatalf("the owner got the row although the relay holds it (%v): the premise of the test is gone", err)
	case <-time.After(700 * time.Millisecond):
	}

	// Stage 2: the lock rule ends the handed-over holder, which has made no progress (it is idle in its
	// transaction for longer than the bound), and the owner proceeds.
	time.Sleep(1200 * time.Millisecond)
	if got := sweep("3600", "1"); got != "1" {
		t.Fatalf("the lock rule ended %q backends, want exactly 1 (the handed-over holder)", got)
	}
	select {
	case err := <-ownerDone:
		if err != nil {
			t.Fatalf("the owner's UPDATE failed after the relay was ended: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("the owner is still blocked after the watchdog ended the holder of the row")
	}
	for name, conn := range map[string]*pgx.Conn{"first": a, "second": b} {
		if _, err := conn.Exec(ctx, "SELECT 1"); err == nil {
			t.Errorf("the %s connection of the relay still answers", name)
		}
	}
	// The owner's own session is not a service backend and was never a candidate.
	if _, err := owner.Exec(ctx, "SELECT 1"); err != nil {
		t.Errorf("the owner's session was ended: %v", err)
	}
}

// TestTheWatchdogLeavesAnHonestWaiterAndItsHolderAlone is the other side of the lock rule: a service
// transaction that holds a row while another session has waited for less than the bound is not ended,
// and a holder that is the migrator is never a candidate however long it blocks.
func TestTheWatchdogLeavesAnHonestWaiterAndItsHolderAlone(t *testing.T) {
	c := testpg.Need(t, cluster)
	h := newHarness(t, c)
	ctx := h.ctx
	sweep := sweeper(t, c, h, installWatchdog(t, c, h))

	holder := zeroedTenantTx(t, h)
	if _, err := holder.Exec(ctx, lockRowOfA, h.A.Tenant); err != nil {
		t.Fatal(err)
	}
	// The holder has been idle in its transaction for longer than the bound before the waiter arrives, so
	// the waiter's own wait is the only thing that keeps it from being ended (the mutant that counts a
	// waiter that has just arrived ends it).
	time.Sleep(2500 * time.Millisecond)
	waiter := make(chan error, 1)
	w, err := h.db.Super(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close(context.Background())
	go func() {
		_, err := w.Exec(ctx, "UPDATE ctrlz.tenants SET status = status WHERE id = $1", h.A.Tenant)
		waiter <- err
	}()
	time.Sleep(500 * time.Millisecond)
	if got := sweep("3600", "2"); got != "0" {
		t.Fatalf("a waiter that has waited half a second, against a bound of 2 s, got %q backends ended", got)
	}
	if _, err := holder.Exec(ctx, "COMMIT"); err != nil {
		t.Fatalf("the honest holder was ended: %v", err)
	}
	select {
	case err := <-waiter:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the waiter did not get the row after the holder committed")
	}

	// The migrator may hold a row for as long as a migration needs, and is never ended by the lock rule.
	mig, err := h.db.Conn(ctx, "ctrlz_migrator")
	if err != nil {
		t.Fatal(err)
	}
	defer mig.Close(context.Background())
	if _, err := mig.Exec(ctx, "BEGIN"); err != nil {
		t.Fatal(err)
	}
	if _, err := mig.Exec(ctx, "UPDATE ctrlz.tenants SET status = status WHERE id = $1", h.A.Tenant); err != nil {
		t.Fatal(err)
	}
	w2, err := h.db.Super(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer w2.Close(context.Background())
	go func() { _, _ = w2.Exec(ctx, "UPDATE ctrlz.tenants SET status = status WHERE id = $1", h.A.Tenant) }()
	time.Sleep(2200 * time.Millisecond)
	if got := sweep("3600", "1"); got != "0" {
		t.Errorf("the lock rule ended %q backends, among them the migrator's transaction", got)
	}
	if _, err := mig.Exec(ctx, "COMMIT"); err != nil {
		t.Errorf("the migrator's transaction was ended: %v", err)
	}
}
