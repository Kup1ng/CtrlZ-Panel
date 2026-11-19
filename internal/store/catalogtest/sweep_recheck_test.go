package catalogtest_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

// Review round 5, db-r5-7. A sweep of the shape "pk IN (SELECT pk ... WHERE p LIMIT n)"
// bounds its batch, and under READ COMMITTED it loses the predicate: a row that another
// transaction updated after the statement's snapshot is re-read for the outer statement
// and judged by the OUTER WHERE alone, so a predicate that only the subselect carries is
// not asked again on the new version. The sweep then clears a TOTP setup the user has just
// restarted, or deletes a throttle window a hit has just reopened.
//
// Each case holds the row with an uncommitted update, starts the sweep (which reads the old
// version in its subselect and waits for the row lock in its outer statement), commits the
// update, and expects the sweep to leave the row alone.

// TestSweepsRecheckTheirPredicateOnAConcurrentlyUpdatedRow is the behaviour test of
// internal/lint TestBoundedSweeps's re-check requirement.
func TestSweepsRecheckTheirPredicateOnAConcurrentlyUpdatedRow(t *testing.T) {
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
			var pid int
			if err := stx.QueryRow(h.ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
				t.Fatal(err)
			}
			type answer struct {
				n   int
				err error
			}
			done := make(chan answer, 1)
			go func() {
				var n int
				err := stx.QueryRow(h.ctx, c.sweep).Scan(&n)
				done <- answer{n, err}
			}()
			waitUntilBlocked(t, h, pid)
			if err := wtx.Commit(h.ctx); err != nil {
				t.Fatal(err)
			}
			var got answer
			select {
			case got = <-done:
			case <-time.After(30 * time.Second):
				t.Fatal("the sweep never finished after the update committed")
			}
			if got.err != nil {
				t.Fatalf("sweep: %v", got.err)
			}
			if got.n != 0 {
				t.Errorf("the sweep removed %d rows of a row that was updated after its snapshot, want 0", got.n)
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

// waitUntilBlocked waits until the backend is waiting for a lock.
func waitUntilBlocked(t *testing.T, h *harness, pid int) {
	t.Helper()
	for i := 0; i < 400; i++ {
		var n int
		if err := h.super.QueryRow(h.ctx, "SELECT count(*) FROM pg_stat_activity WHERE pid = $1 AND wait_event_type = 'Lock'", pid).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n == 1 {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("the sweep never waited for the row lock")
}
