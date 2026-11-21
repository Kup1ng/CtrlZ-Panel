package catalogtest_test

import (
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

// db-r17-1. worker_sweep_throttle took its rows as `(scope, key) = ANY (ARRAY(SELECT (scope, key) ...))`, a
// comparison of a row value with an array of records, which neither an index nor a hash can serve: Postgres
// ran record_eq against every element of the array for every row of the table, so one batch of 5000 over a
// table of 300000 took 14 s (and past the role's statement_timeout on a loaded host, so the backlog never
// drained). Every test before this seeded a handful of rows. This one seeds the production shape (the batch
// the sweeper really asks for, a table far larger than the batch, every batch full) and bounds the time.
//
// The bound is generous (the fixed statement takes about a tenth of a second; the quadratic one took 8 seconds at
// a batch of 5000 and 34 at 10000, the largest batch the function takes, on the development host): it asks for the
// complexity, not for a speed. Run 44855288724 let the mutant that brings the row comparison back pass, because the
// runner did a batch of 5000 in under the old bound of five seconds, so the batch is now the largest there is,
// where the quadratic cost is four times higher and the fixed one is not.
func TestTheThrottleSweepOfAFullBatchIsNotQuadratic(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	const batch, total = 10000, 200000
	h.exec(`
INSERT INTO ctrlz.auth_throttle (scope, key, window_start, count)
SELECT 'admin_login', pg_catalog.decode(pg_catalog.lpad(pg_catalog.to_hex(g), 64, '0'), 'hex'),
       CASE WHEN g <= 10000 THEN now() - interval '2 days' ELSE now() END, 1
FROM generate_series(1, 200000) g`)

	conn := h.fresh()
	tx, err := conn.Begin(h.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(h.ctx)
	if _, err := tx.Exec(h.ctx, `SET LOCAL ROLE ctrlz_worker`); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	var n int
	if err := tx.QueryRow(h.ctx, `SELECT ctrlz_fn.worker_sweep_throttle($1)`, batch).Scan(&n); err != nil {
		t.Fatal(err)
	}
	took := time.Since(start)
	t.Logf("one full batch of %d over %d rows took %v", batch, total, took)
	if n != batch {
		t.Fatalf("the sweep removed %d of %d expired rows in one batch", n, batch)
	}
	if took > 2*time.Second {
		t.Fatalf("one full batch over %d rows took %v: the sweep is quadratic in its batch again", total, took)
	}
}
