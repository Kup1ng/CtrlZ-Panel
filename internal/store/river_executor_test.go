package store_test

import (
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/riverqueue/river/riverdriver"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// The worker logged "Error attempting to resign ... permission denied for function pg_notify" on every shutdown: River's
// resignation SQL notifies unless the executor's cached capabilities say it cannot, and pg_notify is closed to every login
// role. The revoke stays (a role that can notify can fill the cluster's notification queue), so the driver's executors
// resign without the notification. Before the fix the resign below failed with 42501 and the leader row stayed.
func TestLeaderResignNeedsNoNotify(t *testing.T) {
	f := newFixture(t)
	worker := f.db.Store(f.ctx, t, store.RoleWorker)
	super := f.superConn(t)

	// The premise: the worker still cannot notify.
	wc, err := f.db.Conn(f.ctx, "ctrlz_worker")
	if err != nil {
		t.Fatal(err)
	}
	defer wc.Close(f.ctx)
	var pe *pgconn.PgError
	if _, err := wc.Exec(f.ctx, `SELECT pg_catalog.pg_notify('river.leadership', '')`); !errors.As(err, &pe) || pe.Code != "42501" {
		t.Fatalf("pg_notify by the worker: %v, want 42501 (the revoke is the reason this driver exists)", err)
	}

	drv, err := worker.RiverDriver()
	if err != nil {
		t.Fatal(err)
	}
	leaders := func() int {
		var n int
		if err := super.QueryRow(f.ctx, "SELECT count(*) FROM river.river_leader").Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	elect := func(id string) *riverdriver.Leader {
		l, err := drv.GetExecutor().LeaderAttemptElect(f.ctx, &riverdriver.LeaderElectParams{LeaderID: id, Schema: "river", TTL: time.Minute})
		if err != nil || l == nil {
			t.Fatalf("elect %s: %v %v", id, l, err)
		}
		return l
	}
	resign := func(ex riverdriver.Executor, l *riverdriver.Leader, id string) {
		t.Helper()
		_, err := ex.LeaderResign(f.ctx, &riverdriver.LeaderResignParams{ElectedAt: l.ElectedAt, LeaderID: id, LeadershipTopic: "leadership", Schema: "river"})
		if err != nil {
			t.Fatalf("resign %s: %v", id, err)
		}
	}

	// Through the pool's executor.
	l := elect("ctrlz-test-a")
	if leaders() != 1 {
		t.Fatalf("leader rows after the election: %d", leaders())
	}
	resign(drv.GetExecutor(), l, "ctrlz-test-other") // someone else's id deletes nothing
	if leaders() != 1 {
		t.Fatal("a resignation by another client removed the leader row")
	}
	resign(drv.GetExecutor(), l, "ctrlz-test-a")
	if leaders() != 0 {
		t.Fatal("the leader row stands after its resignation")
	}

	// Through a transaction's executor, and a subtransaction of it.
	l = elect("ctrlz-test-b")
	tx, err := drv.GetExecutor().Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	sub, err := tx.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	resign(sub, l, "ctrlz-test-b")
	if err := sub.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	if leaders() != 0 {
		t.Fatal("the leader row stands after a resignation in a transaction")
	}

	// The calls that would notify are refused or silent, never a 42501 that aborts a transaction.
	if err := drv.GetExecutor().NotifyMany(f.ctx, &riverdriver.NotifyManyParams{Topic: "x", Payload: []string{"{}"}, Schema: "river"}); err != nil {
		t.Fatalf("NotifyMany: %v", err)
	}
	if _, err := drv.GetExecutor().JobCancel(f.ctx, &riverdriver.JobCancelParams{ID: 1, Schema: "river"}); err == nil {
		t.Fatal("JobCancel ran")
	} else if errors.As(err, &pe) {
		t.Fatalf("JobCancel reached the database: %v", err)
	}
}
