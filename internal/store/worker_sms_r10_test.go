package store_test

import (
	"net/netip"
	"testing"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// Review round 10 of the SMS layer (sms-r10-5).

// A record of an accepted send that meets a lock timeout is retried, and between two runs it holds
// no lock on its row. If the lease has lapsed by then, the exhausted pass, the expiry and the
// stale-outbox sweep could take the row: the first two refund the global slot of a code the provider
// had accepted (the count then shows a message fewer than were sent), the third fails an invite that
// was delivered. The statements wait store.RecordBudget past the lapse, which is the longest a record
// can still be running. Under the budget they leave the row, over it they end it once.
func TestTheEndingStatementsWaitARecordBudgetPastTheLease(t *testing.T) {
	f := newFixture(t)
	tenant := f.db.Store(f.ctx, t, store.RoleTenant)
	worker := f.db.Store(f.ctx, t, store.RoleWorker)
	super := f.superConn(t)
	ip := netip.MustParseAddr("198.51.100.91")
	for _, q := range []string{"DELETE FROM ctrlz.otp_challenges", "DELETE FROM ctrlz.sms_outbox"} {
		if _, err := super.Exec(f.ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	exhausted, err := tenant.Auth().OTPIssue(f.ctx, "+989121110091", "login", []byte{1}, []byte("sealed"), ip, false)
	if err != nil || !exhausted.Allowed {
		t.Fatal(exhausted, err)
	}
	expired, err := tenant.Auth().OTPIssue(f.ctx, "+989121110092", "login", []byte{1}, []byte("sealed"), ip, false)
	if err != nil || !expired.Allowed {
		t.Fatal(expired, err)
	}
	var outbox uuid.UUID
	if err := super.QueryRow(f.ctx, `INSERT INTO ctrlz.sms_outbox (kind, phone_e164, template_key, locale, params_ct, attempts)
VALUES ('test', '+989121110093', 'otp', 'fa', '\x01', $1) RETURNING id`, store.OutboxMaxAttempts).Scan(&outbox); err != nil {
		t.Fatal(err)
	}
	globalCount := func() int {
		var n int
		if err := super.QueryRow(f.ctx, "SELECT COALESCE((SELECT sum(count) FROM ctrlz.sms_counters WHERE scope = 'global' AND (key = 'all' OR key LIKE 'all:%') AND day = (now() AT TIME ZONE 'Asia/Tehran')::date), 0)").Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if globalCount() != 2 {
		t.Fatalf("global count %d before the test, want 2", globalCount())
	}
	// lapsed puts every claim `ago` seconds past its lease and arms the three endings: the first code
	// has used its claims, the second has expired, the message has used its claims.
	lapsed := func(ago int) {
		t.Helper()
		for _, c := range []struct {
			q  string
			id uuid.UUID
		}{
			{`UPDATE ctrlz.otp_challenges SET delivery_attempts = 3, expires_at = now() + interval '3 minutes', delivery_claimed_until = now() - make_interval(secs => $1) WHERE id = $2`, exhausted.ID},
			{`UPDATE ctrlz.otp_challenges SET delivery_attempts = 1, expires_at = now() - interval '1 second', delivery_claimed_until = now() - make_interval(secs => $1) WHERE id = $2`, expired.ID},
			{`UPDATE ctrlz.sms_outbox SET claimed_until = now() - make_interval(secs => $1) WHERE id = $2`, outbox},
		} {
			if _, err := super.Exec(f.ctx, c.q, float64(ago), c.id); err != nil {
				t.Fatal(err)
			}
		}
	}
	budget := int(store.RecordBudget.Seconds())

	// The lease lapsed, but a record may still be between two runs: nothing ends.
	lapsed(budget / 2)
	f.global(t, worker, func(g store.GlobalTx) {
		if n, err := g.OTPEndExhausted(3); err != nil || n != 0 {
			t.Errorf("the exhausted pass took a row whose record may still run: %d %v", n, err)
		}
		if n, err := g.OTPExpireUndelivered(); err != nil || n != 0 {
			t.Errorf("the expiry took a row whose record may still run: %d %v", n, err)
		}
	})
	f.global(t, worker, func(g store.GlobalTx) {
		if n, err := g.OutboxFailStaleBatch(1000); err != nil || n != 0 {
			t.Errorf("the stale sweep ended a message whose record may still run: %d %v", n, err)
		}
	})
	if globalCount() != 2 {
		t.Errorf("global count %d: a slot was refunded for a code that may have been sent", globalCount())
	}

	// A record that lands in the pause still wins its ending, because nothing ended the row first.
	f.global(t, worker, func(g store.GlobalTx) {
		if w, err := g.OTPDeliveryClear(exhausted.ID); err != nil || !w.Yes() {
			t.Errorf("the record lost its row to an ending: %v %v", w, err)
		}
	})
	lapsed(budget / 2)
	// the row is cleared now; arm it again for the second half of the test.
	if _, err := super.Exec(f.ctx, `UPDATE ctrlz.otp_challenges SET delivery_ct = '\x01' WHERE id = $1`, exhausted.ID); err != nil {
		t.Fatal(err)
	}

	// Past the budget no record can be running: each ending acts once.
	lapsed(budget + 5)
	f.global(t, worker, func(g store.GlobalTx) {
		if n, err := g.OTPEndExhausted(3); err != nil || n != 1 {
			t.Errorf("the exhausted pass after the budget: %d %v", n, err)
		}
		if n, err := g.OTPExpireUndelivered(); err != nil || n != 1 {
			t.Errorf("the expiry after the budget: %d %v", n, err)
		}
	})
	// Its own transaction: the lock order puts the outbox before the counters the two above took.
	f.global(t, worker, func(g store.GlobalTx) {
		if n, err := g.OutboxFailStaleBatch(1000); err != nil || n != 1 {
			t.Errorf("the stale sweep after the budget: %d %v", n, err)
		}
	})
	if globalCount() != 0 {
		t.Errorf("global count %d: each of the two unsent codes gives back its slot once", globalCount())
	}
}
