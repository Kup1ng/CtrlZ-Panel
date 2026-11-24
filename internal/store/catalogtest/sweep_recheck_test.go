package catalogtest_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

// Review round 5, db-r5-7, and round 16, db-r16-21. A sweep of the shape "pk IN (SELECT pk ... WHERE p LIMIT n)"
// bounds its batch, and under READ COMMITTED it lost the predicate: a row that another transaction updated after
// the statement's snapshot is re-read for the outer statement and judged by the OUTER WHERE alone, so a predicate
// that only the subselect carries was not asked again on the new version. The sweep then cleared a TOTP setup the
// user had just restarted, or deleted a throttle window a hit had just reopened.
//
// Round 16 gave the sweeps the one shape of internal/store/locks.go: the rows are picked once, in key order, with
// FOR UPDATE SKIP LOCKED, so a sweep never waits for a row somebody holds, and a row that was updated after the
// snapshot is locked at its new version and judged again by the subselect's own predicate (the outer statement
// repeats it as well). Each case holds the row with an uncommitted update (the restart, the reopening), runs the
// sweep, and expects it to return at once, without waiting for the row, and to leave the row alone; after the
// update commits a second sweep leaves it alone too, because the new version is not expired.

// TestSweepsLeaveARowThatIsBeingUpdatedAlone is the behaviour test of internal/lint TestBoundedSweeps's re-check
// requirement and of the never-waits half of rule lock-order.
func TestSweepsLeaveARowThatIsBeingUpdatedAlone(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))

	h.exec(`UPDATE ctrlz.users SET totp_secret_ct = '\x01', totp_pending_at = now() - interval '20 minutes', totp_enabled_at = NULL WHERE id = $1`, h.A.User)
	h.exec(`INSERT INTO ctrlz.auth_throttle (scope, key, window_start, count) VALUES ('admin_login', decode(repeat('0d', 32), 'hex'), now() - interval '2 days', 3)`)

	for _, c := range []struct {
		name   string
		update string // what the concurrent transaction does to the row
		sweep  string // the sweep, run as the worker
		tenant bool   // set the tenant setting for the sweep
		left   string // a query that must still return 1 afterwards
	}{
		{
			name:   "a TOTP setup the user restarted",
			update: fmt.Sprintf(`UPDATE ctrlz.users SET totp_secret_ct = '\x02', totp_pending_at = now() WHERE id = '%s'`, h.A.User),
			sweep:  `SELECT ctrlz_fn.worker_sweep_pending_totp(10)`,
			tenant: true,
			left:   fmt.Sprintf(`SELECT count(*) FROM ctrlz.users WHERE id = '%s' AND totp_secret_ct = '\x02' AND totp_pending_at IS NOT NULL`, h.A.User),
		},
		{
			name:   "a throttle window a hit reopened",
			update: `UPDATE ctrlz.auth_throttle SET window_start = now(), count = 1 WHERE scope = 'admin_login' AND key = decode(repeat('0d', 32), 'hex')`,
			sweep:  `SELECT ctrlz_fn.worker_sweep_throttle(10)`,
			left:   `SELECT count(*) FROM ctrlz.auth_throttle WHERE scope = 'admin_login' AND key = decode(repeat('0d', 32), 'hex') AND count = 1`,
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			h.t = t
			writer, sweeper := h.fresh(), h.fresh()
			wtx, err := writer.Begin(h.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer wtx.Rollback(h.ctx)
			if _, err := wtx.Exec(h.ctx, c.update); err != nil {
				t.Fatal(err)
			}

			stx, err := sweeper.Begin(h.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer stx.Rollback(h.ctx)
			if _, err := stx.Exec(h.ctx, `SET LOCAL ROLE ctrlz_worker`); err != nil {
				t.Fatal(err)
			}
			if c.tenant {
				if _, err := stx.Exec(h.ctx, `SELECT pg_catalog.set_config('ctrlz.tenant_id', $1, true)`, h.A.Tenant.String()); err != nil {
					t.Fatal(err)
				}
			}
			type answer struct {
				n   int
				err error
			}
			run := func() answer {
				done := make(chan answer, 1)
				go func() {
					var n int
					err := stx.QueryRow(h.ctx, c.sweep).Scan(&n)
					done <- answer{n, err}
				}()
				select {
				case a := <-done:
					return a
				case <-time.After(10 * time.Second):
					t.Fatal("the sweep waited for a row that another transaction holds: a sweep skips what is held")
					return answer{}
				}
			}
			if got := run(); got.err != nil || got.n != 0 {
				t.Fatalf("the sweep of a row that is being updated: %d rows, err %v, want 0 and no error", got.n, got.err)
			}
			if err := wtx.Commit(h.ctx); err != nil {
				t.Fatal(err)
			}
			if got := run(); got.err != nil || got.n != 0 {
				t.Errorf("the sweep removed %d rows of a row that was updated after its snapshot, want 0 (err %v)", got.n, got.err)
			}
			if _, err := stx.Exec(h.ctx, `RESET ROLE`); err != nil {
				t.Fatal(err)
			}
			var left int
			if err := stx.QueryRow(h.ctx, c.left).Scan(&left); err != nil || left != 1 {
				t.Errorf("the updated row did not survive the sweep (%d rows match, err %v)", left, err)
			}
		})
	}
}
