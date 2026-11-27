package store_test

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// The lease of an outbox claim starts when the claim statement runs, like an OTP claim's: the
// claim transaction has already ended the exhausted rows and can have waited on the counter row
// for lock_timeout, and a lease stamped at the start of the transaction (now()) would be spent
// by the wait. The outbox statement moved to clock_timestamp() in round 6 with no test that
// would fail if it went back (sms-r7-3).
func TestTheOutboxClaimLeaseStartsWhenTheClaimRunsNotWhenTheTransactionBegan(t *testing.T) {
	f := newFixture(t)
	worker := f.db.Store(f.ctx, t, store.RoleWorker)
	super := f.superConn(t)
	holder := f.superConn(t)
	if _, err := super.Exec(f.ctx, "DELETE FROM ctrlz.sms_outbox"); err != nil {
		t.Fatal(err)
	}
	id := uuid.New()
	if _, err := super.Exec(f.ctx, `INSERT INTO ctrlz.sms_outbox (id, kind, phone_e164, template_key, locale, params_ct)
	  VALUES ($1, 'test', '+989121110091', 'otp', 'fa', '\x01')`, id); err != nil {
		t.Fatal(err)
	}
	// A transaction that ends an exhausted OTP row first, and waits for the global counter row that
	// another transaction holds, before it claims the outbox row.
	const hold = 3 * time.Second
	done := make(chan error, 1)
	go func() {
		_, err := holder.Exec(f.ctx, `WITH l AS (INSERT INTO ctrlz.sms_counters AS c (day, scope, key, count)
		  VALUES ((now() AT TIME ZONE 'Asia/Tehran')::date, 'global', 'all', 0)
		  ON CONFLICT (day, scope, key) DO UPDATE SET count = c.count RETURNING 1) SELECT pg_sleep($1) FROM l`, hold.Seconds())
		done <- err
	}()
	time.Sleep(500 * time.Millisecond)

	start := time.Now()
	var claimed []store.OutboxItem
	err := worker.WithGlobal(f.ctx, store.TxOpts{}, func(g store.GlobalTx) error {
		// Anything that takes the shared counter row waits for the holder; the claim comes after.
		if err := g.CountersAddCost("0"); err != nil {
			return err
		}
		var err error
		claimed, err = g.OutboxClaim(5)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if waited := time.Since(start); waited < 2*time.Second {
		t.Fatalf("the claim waited %v: the test did not hold the counter row", waited)
	}
	if len(claimed) != 1 || claimed[0].ID != id {
		t.Fatalf("claimed %+v", claimed)
	}
	var lease float64
	if err := super.QueryRow(f.ctx, `SELECT extract(epoch FROM claimed_until - $1::timestamptz)::float8 FROM ctrlz.sms_outbox WHERE id = $2`,
		start, id).Scan(&lease); err != nil {
		t.Fatal(err)
	}
	if min := store.OTPClaimLease.Seconds() + 1.5; lease < min {
		t.Errorf("the outbox lease ends %.1f s after the transaction began, want at least %.1f: the wait came out of the send's time", lease, min)
	}
}

// ClaimLeaseLeft is what the worker bounds a send by. It is measured by the database when asked,
// so a wait between the claim and the question comes off it, it is the shortest of the rows
// asked about, and a row that is gone or no longer claimed counts as no lease (sms-r7-3,
// sms-r7-8).
func TestClaimLeaseLeftIsMeasuredWhenAskedAndTakesTheShortestRow(t *testing.T) {
	f := newFixture(t)
	worker := f.db.Store(f.ctx, t, store.RoleWorker)
	super := f.superConn(t)
	if _, err := super.Exec(f.ctx, "DELETE FROM ctrlz.sms_outbox"); err != nil {
		t.Fatal(err)
	}
	if _, err := super.Exec(f.ctx, "DELETE FROM ctrlz.otp_challenges"); err != nil {
		t.Fatal(err)
	}
	first, second := uuid.New(), uuid.New()
	for _, id := range []uuid.UUID{first, second} {
		if _, err := super.Exec(f.ctx, `INSERT INTO ctrlz.sms_outbox (id, kind, phone_e164, template_key, locale, params_ct)
		  VALUES ($1, 'test', '+989121110092', 'otp', 'fa', '\x01')`, id); err != nil {
			t.Fatal(err)
		}
	}
	var claimed []store.OutboxItem
	var left time.Duration
	err := worker.WithGlobal(f.ctx, store.TxOpts{}, func(g store.GlobalTx) error {
		var err error
		if claimed, err = g.OutboxClaim(5); err != nil {
			return err
		}
		time.Sleep(1500 * time.Millisecond) // the part of the transaction that waits
		left, err = g.ClaimLeaseLeft(nil, []uuid.UUID{first, second})
		return err
	})
	if err != nil || len(claimed) != 2 {
		t.Fatal(claimed, err)
	}
	if max := store.OTPClaimLease - time.Second; left > max {
		t.Errorf("%v left right after a wait of 1.5 s, want at most %v", left, max)
	}
	if left < 10*time.Second {
		t.Errorf("%v left, want most of the lease", left)
	}
	// A row nobody claimed has no lease.
	err = worker.WithGlobal(f.ctx, store.TxOpts{}, func(g store.GlobalTx) error {
		var err error
		left, err = g.ClaimLeaseLeft(nil, []uuid.UUID{uuid.New()})
		return err
	})
	if err != nil || left != 0 {
		t.Errorf("an unknown row has %v left (%v), want none", left, err)
	}
}
