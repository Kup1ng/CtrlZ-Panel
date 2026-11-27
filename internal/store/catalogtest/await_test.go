package catalogtest_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

// awaitLockWaiters waits, on a connection of its own, until n backends are waiting for a lock: the condition a
// test means by "the other statement is now parked on the row", where it used to sleep for a while and passed
// without the race when the goroutine was scheduled late (round 17, tenant-r17-18). The connection must not be
// one that is inside a transaction of the test.
func awaitLockWaiters(t *testing.T, ctx context.Context, probe *pgx.Conn, n int) {
	t.Helper()
	err := testpg.AwaitLockWaiters(ctx, func(ctx context.Context, sql string) (int, error) {
		var c int
		err := probe.QueryRow(ctx, sql).Scan(&c)
		return c, err
	}, n)
	if err != nil {
		t.Fatal(err)
	}
}
