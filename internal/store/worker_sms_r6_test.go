package store_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// The 20 second claim of an OTP row is the promise that nobody else sends or ends the row
// while a worker is sending it. It starts when the claim statement runs, and not when the
// claim transaction began: that transaction first ends the exhausted rows and can wait for
// lock_timeout on a counter row before it claims (the refund of an unsent code takes a shard
// of the global count that nobody holds and never waits since 0055, so the wait here is the
// cost the transaction adds itself), and a lease that began before the wait would have been
// spent before the send started (sms-r6-7).
func TestTheClaimLeaseStartsWhenTheClaimRunsNotWhenTheTransactionBegan(t *testing.T) {
	f := newFixture(t)
	tenant := f.db.Store(f.ctx, t, store.RoleTenant)
	worker := f.db.Store(f.ctx, t, store.RoleWorker)
	super := f.superConn(t)
	holder := f.superConn(t)
	ip := netip.MustParseAddr("198.51.100.81")
	if _, err := super.Exec(f.ctx, "DELETE FROM ctrlz.otp_challenges"); err != nil {
		t.Fatal(err)
	}
	spent, err := tenant.Auth().OTPIssue(f.ctx, "+989121110081", "login", []byte{1}, []byte("sealed"), ip, false)
	if err != nil || !spent.Allowed {
		t.Fatal(spent, err)
	}
	fresh, err := tenant.Auth().OTPIssue(f.ctx, "+989121110082", "login", []byte{2}, []byte("sealed"), ip, false)
	if err != nil || !fresh.Allowed {
		t.Fatal(fresh, err)
	}
	// One row has used its three claims: the claim transaction ends it first, then adds a price to the
	// day's spend, which needs the global row 'all' that another transaction holds for a while. The row is
	// made first: the issue function picks one of sixteen shards at random and may not have made this one.
	if _, err := super.Exec(f.ctx, `INSERT INTO ctrlz.sms_counters (day, scope, key, count) VALUES ((now() AT TIME ZONE 'Asia/Tehran')::date, 'global', 'all', 0) ON CONFLICT DO NOTHING`); err != nil {
		t.Fatal(err)
	}
	if _, err := super.Exec(f.ctx, "UPDATE ctrlz.otp_challenges SET delivery_attempts = 3 WHERE id = $1", spent.ID); err != nil {
		t.Fatal(err)
	}
	const hold = 3 * time.Second
	locked := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		// One statement is one implicit transaction: the row stays locked while pg_sleep runs.
		close(locked)
		_, err := holder.Exec(f.ctx, `WITH l AS (SELECT 1 FROM ctrlz.sms_counters WHERE scope = 'global' AND key = 'all'
		  AND day = (now() AT TIME ZONE 'Asia/Tehran')::date FOR UPDATE) SELECT pg_sleep($1) FROM l`, hold.Seconds())
		done <- err
	}()
	<-locked
	time.Sleep(500 * time.Millisecond) // the holder has the row

	start := time.Now()
	var claimed []store.OTPDelivery
	err = worker.WithGlobal(f.ctx, store.TxOpts{}, func(g store.GlobalTx) error {
		if n, err := g.OTPEndExhausted(3); err != nil || n != 1 {
			t.Errorf("OTPEndExhausted: %d %v", n, err)
		}
		if err := g.CountersAddCost("0"); err != nil {
			return err
		}
		var err error
		claimed, err = g.OTPClaim(5, 3)
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
	if len(claimed) != 1 || claimed[0].ID != fresh.ID {
		t.Fatalf("claimed %+v, want the fresh row only", claimed)
	}
	var lease float64
	if err := super.QueryRow(f.ctx, `SELECT extract(epoch FROM delivery_claimed_until - $1::timestamptz)::float8 FROM ctrlz.otp_challenges WHERE id = $2`,
		start, fresh.ID).Scan(&lease); err != nil {
		t.Fatal(err)
	}
	// The lease counts from the moment the claim statement ran, after the wait, so it reaches
	// the lease plus most of the wait past the start of the transaction. A lease stamped with
	// the transaction's now() reads about 20 seconds.
	if min := store.OTPClaimLease.Seconds() + 1.5; lease < min {
		t.Errorf("the lease ends %.1f s after the transaction began, want at least %.1f: the wait on the counter row came out of the send's time", lease, min)
	}
}
