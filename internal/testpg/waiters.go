package testpg

import (
	"context"
	"fmt"
	"time"
)

// Count runs a query that returns one integer, however the caller reaches the database (a pgx connection, a
// pool, the Store of a test environment). It is what the waits below need and nothing more.
type Count func(ctx context.Context, sql string) (int, error)

// Two conditions a test means when it would otherwise sleep for a while (round 17, tenant-r17-18):
//
//   - a backend is WAITING FOR A LOCK: the call under test is now parked on the row another session holds;
//   - a backend is INSIDE pg_sleep: the holder statement of the test, `WITH l AS (SELECT ... FOR UPDATE) SELECT
//     pg_sleep(n) FROM l`, has taken the row and is holding it. A holder whose CTE finds no row never reaches
//     pg_sleep, so the wait fails and the test says its setup did not hold what it meant to hold, where a sleep
//     passed without noticing.
//
// Both read pg_stat_activity of the current database, so a wait of any role is seen, and both count iterations
// (3000 of 10 ms) instead of reading a clock. They return an error and never call a testing function, so a
// goroutine other than the test's may use them.
const (
	lockWaiters = `SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock'`
	sleepers    = `SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND wait_event = 'PgSleep'`
)

// AwaitLockWaiters returns when at least n backends of the current database are waiting for a lock.
func AwaitLockWaiters(ctx context.Context, count Count, n int) error {
	return await(ctx, count, lockWaiters, n, "waiting for a lock")
}

// AwaitSleepers returns when at least n backends of the current database are inside pg_sleep.
func AwaitSleepers(ctx context.Context, count Count, n int) error {
	return await(ctx, count, sleepers, n, "inside pg_sleep")
}

func await(ctx context.Context, count Count, query string, n int, what string) error {
	got := 0
	for i := 0; i < 3000; i++ {
		var err error
		if got, err = count(ctx, query); err != nil {
			return err
		}
		if got >= n {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
	return fmt.Errorf("%d backend(s) %s, want %d: the other side of the test never got there", got, what, n)
}
