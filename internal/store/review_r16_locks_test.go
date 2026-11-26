package store_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// The rows of one table (db-r16-19; rule lock-order). Two statements that can touch several rows of the same
// table locked them in the order each one scanned them, and the worker's sweep of expired sessions (a
// subselect) and a user's "log out all" (its own predicate) scan by different paths: they lock the same two
// rows in opposite orders and one of them is a deadlock (40P01, a 503 for the user's request).
//
// These tests do not hope for the interleaving. They make the physical order of the rows the reverse of the
// key order, hold one row in the middle, and look at WHICH rows the statement had locked when it stopped
// there: key order means exactly the rows below the held one. A statement that locked in scan order (the
// reverse here) holds the rows above it instead.
//
// The fixture is proved to tell the two orders apart (db-r16-20). The first version relied on the planner
// scanning the old statement in heap order, and it did not: it scanned by an index that is ordered by id, so
// the test passed on the code it was written to catch. Now the database of the test has index and bitmap scans
// switched off (a seq scan returns the rows in physical order, which is the reverse of the key order here), and
// every case first runs the PREVIOUS statement text as a control and requires that it locked rows above the held
// one. A fixture that cannot tell the orders apart fails the test instead of passing it.

// forceHeapOrderScans makes every statement of this test database scan a table in physical order.
func forceHeapOrderScans(t *testing.T, f *fixture) {
	t.Helper()
	super := f.superConn(t)
	var db string
	if err := super.QueryRow(f.ctx, `SELECT current_database()`).Scan(&db); err != nil {
		t.Fatal(err)
	}
	for _, setting := range []string{"enable_indexscan", "enable_bitmapscan", "enable_indexonlyscan"} {
		if _, err := super.Exec(f.ctx, `ALTER DATABASE `+pgx.Identifier{db}.Sanitize()+` SET `+setting+` = off`); err != nil {
			t.Fatal(err)
		}
	}
}

// reverseHeapOrder puts the tuples of the rows (keys, in key order) in the reverse of key order on the page: an
// UPDATE writes the new version after every existing one, so updating from the highest key down leaves the
// highest key first. It fails when the physical order is not the exact reverse.
func reverseHeapOrder(t *testing.T, f *fixture, table, where string, args ...any) []uuid.UUID {
	t.Helper()
	super := f.superConn(t)
	ids := idsOf(t, f, super, table, where, "id", args...)
	if len(ids) < 3 {
		t.Fatalf("%s: %d rows, want at least 3", table, len(ids))
	}
	for i := len(ids) - 1; i >= 0; i-- {
		if _, err := super.Exec(f.ctx, `UPDATE ctrlz.`+table+` SET id = id WHERE id = $1`, ids[i]); err != nil {
			t.Fatal(err)
		}
	}
	heap := idsOf(t, f, super, table, where, "ctid", args...)
	rev := slices.Clone(ids)
	slices.Reverse(rev)
	if !slices.Equal(heap, rev) {
		t.Fatalf("%s: the tuples are not in the reverse of key order on the page: the test cannot tell the two orders apart", table)
	}
	return ids
}

func idsOf(t *testing.T, f *fixture, c *pgx.Conn, table, where, orderBy string, args ...any) []uuid.UUID {
	t.Helper()
	rows, err := c.Query(f.ctx, `SELECT id FROM ctrlz.`+table+` WHERE `+where+` ORDER BY `+orderBy, args...)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		out = append(out, id)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// lockedRows says, for each id of the table, whether another session holds a row lock on it (a NOWAIT lock fails).
func lockedRows(t *testing.T, f *fixture, table string, ids []uuid.UUID) map[uuid.UUID]bool {
	t.Helper()
	probe, err := f.db.Super(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close(context.Background())
	out := map[uuid.UUID]bool{}
	for _, id := range ids {
		tx, err := probe.Begin(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		_, err = tx.Exec(f.ctx, `SELECT 1 FROM ctrlz.`+table+` WHERE id = $1 FOR NO KEY UPDATE NOWAIT`, id)
		var pe *pgconn.PgError
		switch {
		case err == nil:
		case errors.As(err, &pe) && pe.Code == "55P03":
			out[id] = true
		default:
			t.Fatal(err)
		}
		_ = tx.Rollback(f.ctx)
	}
	return out
}

// stalledAtTheHeldRow holds the row in the middle of ids, starts run, waits until it has locked what it could,
// reports which rows it holds, then releases the row and requires that run finishes.
func stalledAtTheHeldRow(t *testing.T, f *fixture, table string, ids []uuid.UUID, run func() error) map[uuid.UUID]bool {
	t.Helper()
	mid := len(ids) / 2
	holder, err := f.db.Super(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close(context.Background())
	if _, err := holder.Exec(f.ctx, "BEGIN"); err != nil {
		t.Fatal(err)
	}
	if _, err := holder.Exec(f.ctx, `SELECT 1 FROM ctrlz.`+table+` WHERE id = $1 FOR NO KEY UPDATE`, ids[mid]); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- run() }()
	// The statement has locked what it could and is parked on the held row.
	probe, err := f.db.Super(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close(context.Background())
	awaitLockWaiters(t, f.ctx, probe, 1)
	select {
	case err := <-done:
		t.Fatalf("the statement finished although a row of its set is held: %v", err)
	default:
	}
	locked := lockedRows(t, f, table, ids)
	if _, err := holder.Exec(f.ctx, "ROLLBACK"); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("the statement failed after the row was released: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("the statement did not finish after the row was released")
	}
	return locked
}

// lockOrderCase is one statement of the class. old is the text the statement had before it took the shape.
type lockOrderCase struct {
	name, table, where string
	args               func(f *fixture) []any
	seed               func(t *testing.T, f *fixture)
	run                func(f *fixture, tx store.Tx) error
	old                string
	oldArgs            func(f *fixture) []any
}

func lockOrderCases() []lockOrderCase {
	userA := func(f *fixture) []any { return []any{f.A.Tenant, f.A.User} }
	return []lockOrderCase{
		{
			name: "revoke the other sessions of a user", table: "sessions", where: "tenant_id = $1 AND user_id = $2", args: userA,
			seed: func(t *testing.T, f *fixture) {
				tenant := f.db.Store(f.ctx, t, store.RoleTenant)
				for i := 0; i < 9; i++ {
					if err := tenant.WithTenant(f.ctx, f.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
						if _, _, err := tx.UserLock(f.A.User); err != nil {
							return err
						}
						now := time.Now()
						_, err := tx.SessionCreate(store.NewSession{At: now, UserID: f.A.User, TokenHash: []byte(uuid.NewString()), IdleExpiresAt: now.Add(time.Hour),
							AbsoluteExpiresAt: now.Add(time.Hour), AuthMethod: "password"})
						return err
					}); err != nil {
						t.Fatalf("session %d: %v", i, err)
					}
				}
			},
			run: func(f *fixture, tx store.Tx) error {
				if _, _, err := tx.UserLock(f.A.User); err != nil {
					return err
				}
				_, err := tx.SessionsRevokeOthers(f.A.User, uuid.Nil, time.Now())
				return err
			},
			old:     `UPDATE ctrlz.sessions SET revoked_at = now() WHERE tenant_id = $1 AND user_id = $2 AND id <> $3 AND revoked_at IS NULL`,
			oldArgs: func(f *fixture) []any { return []any{f.A.Tenant, f.A.User, uuid.Nil} },
		},
		{
			name: "revoke the API tokens of a user", table: "api_tokens", where: "tenant_id = $1 AND user_id = $2", args: userA,
			seed: func(t *testing.T, f *fixture) {
				super := f.superConn(t)
				for i := 0; i < 9; i++ {
					if _, err := super.Exec(f.ctx, `INSERT INTO ctrlz.api_tokens (tenant_id, user_id, name, kind, token_hash, token_prefix, expires_at) VALUES ($1, $2, 'x', 'read', sha256($3::bytea), 'czt_x', now() + interval '1 day')`,
						f.A.Tenant, f.A.User, []byte(uuid.NewString())); err != nil {
						t.Fatal(err)
					}
				}
			},
			run: func(f *fixture, tx store.Tx) error {
				if _, _, err := tx.UserLock(f.A.User); err != nil {
					return err
				}
				_, err := tx.APITokensRevoke(f.A.User)
				return err
			},
			old:     `UPDATE ctrlz.api_tokens SET revoked_at = now() WHERE tenant_id = $1 AND user_id = $2 AND revoked_at IS NULL`,
			oldArgs: userA,
		},
		{
			name: "delete the recovery codes of a user", table: "recovery_codes", where: "tenant_id = $1 AND user_id = $2", args: userA,
			seed: func(t *testing.T, f *fixture) {
				super := f.superConn(t)
				for i := 0; i < 9; i++ {
					if _, err := super.Exec(f.ctx, `INSERT INTO ctrlz.recovery_codes (tenant_id, user_id, code_hash) VALUES ($1, $2, sha256($3::bytea))`,
						f.A.Tenant, f.A.User, []byte(uuid.NewString())); err != nil {
						t.Fatal(err)
					}
				}
			},
			run: func(f *fixture, tx store.Tx) error {
				if _, _, err := tx.UserLock(f.A.User); err != nil {
					return err
				}
				return tx.RecoveryCodesReplace(f.A.User, nil)
			},
			old:     `DELETE FROM ctrlz.recovery_codes WHERE tenant_id = $1 AND user_id = $2`,
			oldArgs: userA,
		},
	}
}

// TestAMultiRowWriteLocksItsRowsInKeyOrder runs the control (the previous text) and then the statement of the
// store, for each statement that took the shape. The control must lock rows ABOVE the held one (scan order, the
// reverse here); the statement must lock exactly the rows BELOW it.
func TestAMultiRowWriteLocksItsRowsInKeyOrder(t *testing.T) {
	for _, c := range lockOrderCases() {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t)
			forceHeapOrderScans(t, f)
			c.seed(t, f)
			ids := reverseHeapOrder(t, f, c.table, c.where, c.args(f)...)
			mid := len(ids) / 2

			// The control: the old text, as the superuser, in a transaction that is rolled back.
			control, err := f.db.Super(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer control.Close(context.Background())
			if _, err := control.Exec(f.ctx, "BEGIN"); err != nil {
				t.Fatal(err)
			}
			locked := stalledAtTheHeldRow(t, f, c.table, ids, func() error {
				_, err := control.Exec(f.ctx, c.old, c.oldArgs(f)...)
				return err
			})
			if _, err := control.Exec(f.ctx, "ROLLBACK"); err != nil {
				t.Fatal(err)
			}
			above := 0
			for i := mid + 1; i < len(ids); i++ {
				if locked[ids[i]] {
					above++
				}
			}
			if above == 0 {
				t.Fatalf("the control (the statement before the shape) holds no row above the held one: this fixture cannot tell scan order from key order for %s", c.table)
			}

			// The statement under test.
			tenant := f.db.Store(f.ctx, t, store.RoleTenant)
			locked = stalledAtTheHeldRow(t, f, c.table, ids, func() error {
				return tenant.WithTenant(f.ctx, f.A.Tenant, store.TxOpts{}, func(tx store.Tx) error { return c.run(f, tx) })
			})
			for i, id := range ids {
				switch {
				case i < mid && !locked[id]:
					t.Errorf("row %d of %d (below the held row) is not locked: the statement does not lock in key order", i, len(ids))
				case i > mid && locked[id]:
					t.Errorf("row %d of %d (above the held row) is locked: the statement locked in scan order, which is the reverse of key order here", i, len(ids))
				}
			}
		})
	}
}

// TestTheSweepOfExpiredSessionsLocksItsRowsInKeyOrder is the other half. The sweep of expired sessions took the
// rows of its batch in the order of its plan, so it and a user's revocation met them in opposite orders. The
// worker cannot lock a row (SELECT ... FOR UPDATE needs the UPDATE privilege it does not hold), so the sweep
// deletes its rows one keyed statement at a time in key order. With one row held in the middle it has deleted
// exactly the rows below it when it stops, and it finishes when the row is released. The control is the sweep
// as it was (an IN over a limited subselect), which must lock rows above the held one.
func TestTheSweepOfExpiredSessionsLocksItsRowsInKeyOrder(t *testing.T) {
	f := newFixture(t)
	forceHeapOrderScans(t, f)
	lockOrderCases()[0].seed(t, f)
	super := f.superConn(t)
	if _, err := super.Exec(f.ctx, `UPDATE ctrlz.sessions SET idle_expires_at = now() - interval '3 days', absolute_expires_at = now() - interval '3 days' WHERE tenant_id = $1 AND user_id = $2`, f.A.Tenant, f.A.User); err != nil {
		t.Fatal(err)
	}
	ids := reverseHeapOrder(t, f, "sessions", "tenant_id = $1 AND user_id = $2", f.A.Tenant, f.A.User)
	mid := len(ids) / 2

	control, err := f.db.Super(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close(context.Background())
	if _, err := control.Exec(f.ctx, "BEGIN"); err != nil {
		t.Fatal(err)
	}
	locked := stalledAtTheHeldRow(t, f, "sessions", ids, func() error {
		_, err := control.Exec(f.ctx, `DELETE FROM ctrlz.sessions WHERE tenant_id = $1 AND id IN
  (SELECT id FROM ctrlz.sessions WHERE tenant_id = $1 AND absolute_expires_at < $3::timestamptz - interval '1 day' LIMIT $2)`, f.A.Tenant, 100, time.Now())
		return err
	})
	if _, err := control.Exec(f.ctx, "ROLLBACK"); err != nil {
		t.Fatal(err)
	}
	above := 0
	for i := mid + 1; i < len(ids); i++ {
		if locked[ids[i]] {
			above++
		}
	}
	if above == 0 {
		t.Fatal("the control (the sweep as it was) holds no row above the held one: this fixture cannot tell scan order from key order")
	}

	worker := f.db.Store(f.ctx, t, store.RoleWorker)
	var n int
	locked = stalledAtTheHeldRow(t, f, "sessions", ids, func() error {
		return worker.WithTenant(f.ctx, f.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
			var err error
			n, err = tx.SweepTenantBatch(store.TenantSweepSessions, 100, time.Now())
			return err
		})
	})
	for i, id := range ids {
		switch {
		case i < mid && !locked[id]:
			t.Errorf("row %d of %d (below the held row) is not locked: the sweep does not take its rows in key order", i, len(ids))
		case i > mid && locked[id]:
			t.Errorf("row %d of %d (above the held row) is locked: the sweep took its rows in scan order", i, len(ids))
		}
	}
	if n != len(ids) {
		t.Errorf("the sweep deleted %d rows, want %d", n, len(ids))
	}
}
