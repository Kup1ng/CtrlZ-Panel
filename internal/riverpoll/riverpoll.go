// Package riverpoll holds the one SQL statement the module sends to River's own tables itself: the leader's resignation without
// pg_notify. It is a package of its own so the lock-order lint, which reads every statement of the module as a ctrlz table
// write, can leave it alone (lint.sqlExempt), as it leaves the migration runner: River's tables are not ours.
package riverpoll

import (
	"context"
	"errors"

	"github.com/riverqueue/river/riverdriver"
	"github.com/riverqueue/river/rivertype"
)

// River's driver decides about NOTIFY in two places. The client asks Driver.SupportsListenNotify, which Driver
// answers with false. The executor asks its own cached capabilities, read from an unexported field of the embedded
// driver that only a Yugabyte server turns off, and passes them as a flag into the SQL of the leader's resignation
// (and of JobCancel): that SQL calls pg_notify when the flag is true. pg_notify is closed to every login role
// (bootstrap/20-database.sql, db-r16-17), so on every shutdown the elector's resignation failed with 42501, was retried
// three times with a growing timeout, and gave up: the leader row then stood until its TTL (the elect interval plus ten
// seconds), so a restarted worker waited that long before it led, and the shutdown itself was slowed by the retries.
//
// The revoke has a reason that still holds (a role that can notify can fill the cluster's one notification queue), so the
// fix is not a grant. The executors this package wraps (Driver hands them out) replace the three calls that would notify, and nothing else.

// Driver is River's driver that says it cannot listen and notify, and hands out the wrapped executors. River's client sends a
// NOTIFY on every insert unless the driver says it has none, and PollOnly in the client config does not stop that: the function
// pg_notify is revoked from every role (catalog_reach.yaml, wal-writes-and-notifications; nothing of the module notifies, rule
// no-notify), so the call would fail with 42501, abort the transaction of the insert, and the drain would never move a row. The
// worker polls. It is generic over the driver's transaction type so that this package names no database driver and the store
// (the only place that may) picks the type: River's UnwrapTx has to return it, and River is the only caller.
type Driver[TTx any] struct{ riverdriver.Driver[TTx] }

// NewDriver wraps River's driver d.
func NewDriver[TTx any](d riverdriver.Driver[TTx]) *Driver[TTx] { return &Driver[TTx]{Driver: d} }

// GetExecutor is River's executor with the calls that would notify replaced.
func (d *Driver[TTx]) GetExecutor() riverdriver.Executor { return Executor(d.Driver.GetExecutor()) }

// UnwrapExecutor is River's executor of a driver transaction, with the same replacement.
func (d *Driver[TTx]) UnwrapExecutor(tx TTx) riverdriver.ExecutorTx {
	return ExecutorTx(d.Driver.UnwrapExecutor(tx))
}

// UnwrapTx gives back the transaction of an executor this driver handed out. River's own UnwrapTx asserts the concrete type of
// its executor, which the wrapper is not, so the wrapper is taken off first. In River v0.51.2 only its test helper calls it;
// when River is bumped, re-check this method together with GetExecutor and UnwrapExecutor.
func (d *Driver[TTx]) UnwrapTx(e riverdriver.ExecutorTx) TTx { return d.Driver.UnwrapTx(Unwrap(e)) }

// SupportsListener says there is no LISTEN.
func (*Driver[TTx]) SupportsListener() bool { return false }

// SupportsListenNotify says there is no NOTIFY.
func (*Driver[TTx]) SupportsListenNotify() bool { return false }

// pollExecutor wraps River's executor of the pool.
type pollExecutor struct{ riverdriver.Executor }

// pollExecutorTx wraps River's executor of a transaction (the drain inserts through one).
type pollExecutorTx struct{ riverdriver.ExecutorTx }

// Executor wraps River's executor of the pool with the notifying calls replaced.
func Executor(e riverdriver.Executor) riverdriver.Executor { return pollExecutor{e} }

// ExecutorTx wraps River's executor of a transaction with the notifying calls replaced.
func ExecutorTx(e riverdriver.ExecutorTx) riverdriver.ExecutorTx { return pollExecutorTx{e} }

// Unwrap takes the wrapper off an executor of a transaction. River's own driver turns an executor back into its pgx
// transaction (Driver.UnwrapTx) with a forced assertion on its own concrete type, so a wrapped one would panic there. An
// executor that is not one of ours is returned as it is.
func Unwrap(e riverdriver.ExecutorTx) riverdriver.ExecutorTx {
	if w, ok := e.(pollExecutorTx); ok {
		return w.ExecutorTx
	}
	return e
}

func (e pollExecutor) Begin(ctx context.Context) (riverdriver.ExecutorTx, error) {
	tx, err := e.Executor.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return pollExecutorTx{tx}, nil
}

func (e pollExecutorTx) Begin(ctx context.Context) (riverdriver.ExecutorTx, error) {
	tx, err := e.ExecutorTx.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return pollExecutorTx{tx}, nil
}

func (e pollExecutor) LeaderResign(ctx context.Context, p *riverdriver.LeaderResignParams) (bool, error) {
	return leaderResign(ctx, e.Executor, p)
}

func (e pollExecutorTx) LeaderResign(ctx context.Context, p *riverdriver.LeaderResignParams) (bool, error) {
	return leaderResign(ctx, e.ExecutorTx, p)
}

// NotifyMany sends nothing: the client already skips it, and this keeps a call of River's own API from reaching pg_notify.
func (pollExecutor) NotifyMany(context.Context, *riverdriver.NotifyManyParams) error { return nil }

// NotifyMany sends nothing, as that of pollExecutor.
func (pollExecutorTx) NotifyMany(context.Context, *riverdriver.NotifyManyParams) error { return nil }

// errCancelUnsupported is what River's Cancel returns here: its SQL notifies the job's producer, and nothing in this
// module cancels a job from outside the job (a handler ends itself with river.JobCancel, which is not this call).
var errCancelUnsupported = errors.New("riverpoll: River's Cancel is not available: it notifies, and the worker polls")

func (pollExecutor) JobCancel(context.Context, *riverdriver.JobCancelParams) (*rivertype.JobRow, error) {
	return nil, errCancelUnsupported
}

func (pollExecutorTx) JobCancel(context.Context, *riverdriver.JobCancelParams) (*rivertype.JobRow, error) {
	return nil, errCancelUnsupported
}

// leaderResign is River's DELETE of the leader row without its pg_notify. The notification only wakes the other clients'
// electors early; they poll for the vacancy every elect interval, so the row going away is all that matters. River uses the
// answer only for a debug line, and Exec gives no row count, so a statement that ran counts as a resignation.
func leaderResign(ctx context.Context, exec riverdriver.Executor, p *riverdriver.LeaderResignParams) (bool, error) {
	// The statement is a constant (no dynamic SQL in this package): the one schema River has here is river, as Config.Schema says.
	if p.Schema != "" && p.Schema != "river" {
		return false, errors.New("riverpoll: unexpected River schema")
	}
	if err := exec.Exec(ctx, qRiverLeaderResign, p.ElectedAt, p.LeaderID); err != nil {
		return false, err
	}
	return true, nil
}

const qRiverLeaderResign = `DELETE FROM river.river_leader WHERE elected_at = $1 AND leader_id = $2`
