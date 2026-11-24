package store_test

import (
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// TestTheSpendSaturatesAtTheColumnMax is the proof for db-r13-1. The price of an accepted message is
// added after the provider has taken the message, so an add that raised 22003 (a price typed with too
// many digits, or a long day) rolled the record back and the same code was sent and billed again for
// every later send. The sum must saturate at the column's maximum, never raise, and the money cap must
// read the parked spend as reached.
func TestTheSpendSaturatesAtTheColumnMax(t *testing.T) {
	f := newFixture(t)
	worker := f.db.Store(f.ctx, t, store.RoleWorker)
	super := f.superConn(t)

	// The constant is the maximum of the column it guards, read from the catalog, so a change of the
	// column type that leaves the constant behind fails here and not in production.
	var prec, scale int
	if err := super.QueryRow(f.ctx, `SELECT numeric_precision, numeric_scale FROM information_schema.columns
WHERE table_schema = 'ctrlz' AND table_name = 'sms_counters' AND column_name = 'cost'`).Scan(&prec, &scale); err != nil {
		t.Fatal(err)
	}
	max := store.CostSaturation
	var same bool
	if err := super.QueryRow(f.ctx, `SELECT $3::numeric = power(10::numeric, $1::int - $2::int) - power(10::numeric, -$2::int)`, prec, scale, max).Scan(&same); err != nil {
		t.Fatal(err)
	}
	if !same {
		t.Fatalf("CostSaturation is %s but numeric(%d, %d) holds a different maximum", max, prec, scale)
	}

	spent := func() string {
		var s string
		if err := super.QueryRow(f.ctx, `SELECT cost::text FROM ctrlz.sms_counters
WHERE day = (now() AT TIME ZONE 'Asia/Tehran')::date AND scope = 'global' AND key = 'all'`).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	// A spend never falls and today's row stays for its retention, so the test starts over the way a
	// migration does: with the guard off for that one statement.
	reset := func() {
		t.Helper()
		if _, err := super.Exec(f.ctx, `ALTER TABLE ctrlz.sms_counters DISABLE TRIGGER sms_counters_guard; DELETE FROM ctrlz.sms_counters; ALTER TABLE ctrlz.sms_counters ENABLE TRIGGER sms_counters_guard`); err != nil {
			t.Fatal(err)
		}
	}
	add := func(price string) {
		t.Helper()
		f.global(t, worker, func(g store.GlobalTx) {
			if err := g.CountersAddCost(price); err != nil {
				t.Fatalf("an accepted send of price %s could not be recorded: %v", price, err)
			}
		})
	}
	reset()
	if _, err := super.Exec(f.ctx, `UPDATE ctrlz.system_settings SET sms_cost_cap_daily = NULL`); err != nil {
		t.Fatal(err)
	}

	// The scenario of the finding: a price of 6e9 (a typo for 6000), twice, with no cap.
	add("6000000000")
	if got := spent(); got != "6000000000.0000" {
		t.Fatalf("the first add left %s", got)
	}
	add("6000000000")
	if got := spent(); got != max {
		t.Fatalf("the second add left %s, want the column maximum %s", got, max)
	}
	// Parked at the maximum, later sends still record, the spend stays put and a normal price adds nothing.
	add("600")
	add(max)
	if got := spent(); got != max {
		t.Fatalf("a spend at the maximum moved to %s", got)
	}

	// One price below the maximum, a normal price lands exactly on it (not on a smaller bound).
	reset()
	add("9999999999.9998")
	add("1")
	if got := spent(); got != max {
		t.Fatalf("9999999999.9998 plus 1 left %s, want %s", got, max)
	}

	// The cap reads the parked spend as reached, so a typo stops the sends instead of billing them.
	if _, err := super.Exec(f.ctx, `UPDATE ctrlz.system_settings SET sms_cost_cap_daily = $1::numeric`, max); err != nil {
		t.Fatal(err)
	}
	f.global(t, worker, func(g store.GlobalTx) {
		if w, _ := g.OutboxRetryGate(); w.Yes() {
			t.Error("a spend parked at the column maximum did not reach a cap of the same value")
		}
	})
}
