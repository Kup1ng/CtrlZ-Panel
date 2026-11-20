package catalogtest_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

// The lock rule of the watchdog and honest load (db-r16-23). The first form ended every service backend that
// held, or queued ahead of, a session that had waited longer than the block bound. A burst of honest
// requests on one hot row queues each behind a few milliseconds of work; a waiter at the back crosses the
// bound; the sweep then ended every honest holder and every request ahead of it, which were retried and made
// the queue longer. These tests run the real script and SQL against honest contention longer than the bound,
// against a holder that is working but never idle, and against a stuck role together with its queue.

// TestTheWatchdogLeavesAnHonestQueueOnAHotRowAlone: twelve honest transactions of one role queue on one
// row, each holds it for 400 ms. The last waits about 4.4 s, far past the block bound of 1 s, and a sweep
// every 600 ms runs the whole time. Nothing is ended, and every transaction commits.
func TestTheWatchdogLeavesAnHonestQueueOnAHotRowAlone(t *testing.T) {
	c := testpg.Need(t, cluster)
	h := newHarness(t, c)
	ctx := h.ctx
	sweep := sweeper(t, c, h, installWatchdog(t, c, h))

	const n = 12
	var wg sync.WaitGroup
	errs := make(chan error, n)
	ready := make(chan struct{})
	for i := 0; i < n; i++ {
		conn, err := h.db.Conn(ctx, "ctrlz_tenant")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close(context.Background()) })
		wg.Add(1)
		go func(conn *pgx.Conn) {
			defer wg.Done()
			<-ready
			tx, err := conn.Begin(ctx)
			if err != nil {
				errs <- err
				return
			}
			if _, err := tx.Exec(ctx, "SELECT pg_catalog.set_config('ctrlz.tenant_id', $1, true)", h.A.Tenant.String()); err != nil {
				errs <- err
				return
			}
			if _, err := tx.Exec(ctx, lockRowOfA, h.A.Tenant); err != nil {
				errs <- fmt.Errorf("an honest request was ended or refused: %w", err)
				return
			}
			if _, err := tx.Exec(ctx, "SELECT pg_catalog.pg_sleep(0.4)"); err != nil {
				errs <- err
				return
			}
			errs <- tx.Commit(ctx)
		}(conn)
	}
	close(ready)
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	ended := 0
	for waiting := true; waiting; {
		select {
		case <-done:
			waiting = false
		case <-time.After(600 * time.Millisecond):
			if got := sweep("3600", "1"); got != "0" {
				ended++
				t.Errorf("a sweep during honest contention ended %q backends", got)
			}
		}
	}
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("an honest transaction failed: %v", err)
		}
	}
	if ended > 0 {
		t.Fatal("the watchdog ended honest transactions")
	}
}

// TestTheWatchdogEndsAHolderThatNeverGoesIdle: a holder that chains statements (here a long pg_sleep) holds
// the row without ever being idle for the block bound. It is left alone while its transaction is younger than
// the hold bound, however long the waiter has waited, and ended once it is older, so a role cannot keep a row
// by staying busy.
func TestTheWatchdogEndsAHolderThatNeverGoesIdle(t *testing.T) {
	c := testpg.Need(t, cluster)
	h := newHarness(t, c)
	ctx := h.ctx
	sweep := sweeper(t, c, h, installWatchdog(t, c, h))

	holder := zeroedTenantTx(t, h)
	if _, err := holder.Exec(ctx, lockRowOfA, h.A.Tenant); err != nil {
		t.Fatal(err)
	}
	busy := make(chan error, 1)
	go func() { _, err := holder.Exec(ctx, "SELECT pg_catalog.pg_sleep(60)"); busy <- err }()
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
	time.Sleep(3 * time.Second)

	if got := sweep("3600", "1"); got != "0" {
		t.Fatalf("a working holder whose transaction is younger than the hold bound was ended (%q)", got)
	}
	if got := sweep("3600", "1", "CTRLZ_PG_WATCHDOG_MAX_HOLD=2"); got != "1" {
		t.Fatalf("a holder busy past the hold bound ended %q backends, want exactly 1", got)
	}
	select {
	case err := <-ownerDone:
		if err != nil {
			t.Fatalf("the owner's UPDATE failed: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("the owner is still blocked after the busy holder was ended")
	}
	<-busy
}

// TestTheWatchdogEndsTheQueuedMembersOfAStuckRoleOnly: a stuck holder of ctrlz_tenant (idle in its
// transaction) with a second tenant connection and a console (ctrlz_admin) connection queued ahead of the owner. The sweep
// ends the holder and the tenant member of the relay in one pass; the console, another role, is not part of
// the relay and stays queued.
func TestTheWatchdogEndsTheQueuedMembersOfAStuckRoleOnly(t *testing.T) {
	c := testpg.Need(t, cluster)
	h := newHarness(t, c)
	ctx := h.ctx
	sweep := sweeper(t, c, h, installWatchdog(t, c, h))

	holder := zeroedTenantTx(t, h)
	if _, err := holder.Exec(ctx, lockRowOfA, h.A.Tenant); err != nil {
		t.Fatal(err)
	}
	member := zeroedTenantTx(t, h)
	memberDone := make(chan error, 1)
	go func() { _, err := member.Exec(ctx, lockRowOfA, h.A.Tenant); memberDone <- err }()
	time.Sleep(300 * time.Millisecond)

	other, err := h.db.Conn(ctx, "ctrlz_admin")
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close(context.Background())
	otherDone := make(chan error, 1)
	go func() {
		// The console's role suspends a tenant: an UPDATE of the same row, queued behind the stuck holder.
		// It names tenant A, as the console does, so row security lets it reach (and queue on) the row; an
		// UPDATE that matched no row would never queue and the test would not tell the roles apart.
		var err error
		for _, sql := range []string{"BEGIN", "SELECT pg_catalog.set_config('ctrlz.tenant_id', '" + h.A.Tenant.String() + "', true)"} {
			if _, err = other.Exec(ctx, sql); err != nil {
				otherDone <- err
				return
			}
		}
		var tag pgconn.CommandTag
		tag, err = other.Exec(ctx, "UPDATE ctrlz.tenants SET status = status WHERE id = $1", h.A.Tenant)
		if err == nil && tag.RowsAffected() != 1 {
			err = fmt.Errorf("the console's UPDATE matched %d rows, so it never queued", tag.RowsAffected())
		}
		if err == nil {
			_, err = other.Exec(ctx, "COMMIT") // the row goes on to the owner
		}
		otherDone <- err
	}()
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
	time.Sleep(2500 * time.Millisecond)

	got := sweep("3600", "1")
	if got != "2" {
		t.Fatalf("the sweep ended %q backends, want 2 (the stuck holder and the member of its role queued ahead)", got)
	}
	select {
	case err := <-memberDone:
		if err == nil {
			t.Error("the queued member of the stuck role was not ended")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the queued member never returned")
	}
	select {
	case err := <-ownerDone:
		if err != nil {
			t.Fatalf("the owner's UPDATE failed: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("the owner is still blocked")
	}
	select {
	case err := <-otherDone:
		if err != nil {
			t.Fatalf("the console's update failed (it is another role and must not be ended): %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("the console's update never returned")
	}
}
