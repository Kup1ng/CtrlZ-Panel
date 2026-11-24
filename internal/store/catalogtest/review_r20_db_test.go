package catalogtest_test

import (
	"context"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

// TestTheWatchdogEndsAQueueOfTableLockRequestsNotOnlyTheHolder is db-r20-2. Rule (d) first judged only a
// GRANTED table lock, so connections of one role that each queue for ACCESS EXCLUSIVE on sessions took
// the lock in turn, one per sweep, while the holder stayed active (pg_sleep) and so was never "stuck":
// Postgres queues every later reader behind a waiting ACCESS EXCLUSIVE request, so every honest read of
// the table failed at its lock_timeout for as long as the role kept the queue full. The mode requested
// is judged as the mode held, so the first sweep ends the holder and the whole queue and the reader,
// which arrived last, goes through. The test fails on the first form: two sweeps end two of the four.
func TestTheWatchdogEndsAQueueOfTableLockRequestsNotOnlyTheHolder(t *testing.T) {
	c := testpg.Need(t, cluster)
	h := newHarness(t, c)
	ctx := h.ctx
	sweep := sweeper(t, c, h, installWatchdog(t, c, h))

	const attackers = 4
	done := make(chan error, attackers)
	// The first one takes the lock and stays active (a statement chain no age rule reaches).
	first := zeroedTenantTx(t, h)
	if _, err := first.Exec(ctx, "LOCK TABLE ctrlz.sessions IN ACCESS EXCLUSIVE MODE"); err != nil {
		t.Fatalf("the premise of the finding (a service role may take the lock) does not hold: %v", err)
	}
	go func() { _, err := first.Exec(ctx, "SELECT pg_catalog.pg_sleep(120)"); done <- err }()
	probe := h.fresh()
	if err := testpg.AwaitSleepers(ctx, func(ctx context.Context, sql string) (int, error) {
		var n int
		err := probe.QueryRow(ctx, sql).Scan(&n)
		return n, err
	}, 1); err != nil {
		t.Fatal(err)
	}
	// The others queue for the same mode, and each sleeps once it has it.
	for i := 1; i < attackers; i++ {
		conn := zeroedTenantTx(t, h)
		go func() {
			if _, err := conn.Exec(ctx, "LOCK TABLE ctrlz.sessions IN ACCESS EXCLUSIVE MODE"); err != nil {
				done <- err
				return
			}
			_, err := conn.Exec(ctx, "SELECT pg_catalog.pg_sleep(120)")
			done <- err
		}()
	}
	awaitLockWaiters(t, ctx, probe, attackers-1)

	// The honest reader of another role, last in the queue, with a bound longer than two sweeps.
	reader := h.fresh()
	readerDone := make(chan error, 1)
	go func() {
		if _, err := reader.Exec(ctx, "SET lock_timeout = '8s'"); err != nil {
			readerDone <- err
			return
		}
		_, err := reader.Exec(ctx, "SELECT count(*) FROM ctrlz.sessions")
		readerDone <- err
	}()
	awaitLockWaiters(t, ctx, probe, attackers)

	for i := 0; i < 2; i++ {
		sweep("3600", "3600")
	}
	for i := 0; i < attackers; i++ {
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("a backend that held or queued for ACCESS EXCLUSIVE finished normally")
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("after two sweeps only %d of %d backends that held or queued for ACCESS EXCLUSIVE were ended", i, attackers)
		}
	}
	select {
	case err := <-readerDone:
		if err != nil {
			t.Fatalf("the honest reader failed: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the honest reader is still blocked after two sweeps")
	}
}
