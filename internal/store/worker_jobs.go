package store

import (
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river/riverdriver"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"

	"github.com/Kup1ng/CtrlZ-Panel/internal/riverpoll"
)

// The worker's side of the batch jobs (docs/specs/p2-profiles.md 3.5): the drain of job_outbox into River, the sweep of
// the rows River can no longer end, and the retention of finished jobs and idempotency keys.

// RiverDriver is River's driver over the pool of the worker role. River's own statements (fetching, completing, its
// maintenance) go through its own handle on the pool, and bypass the statement guard of this package: they name only the
// tables of schema river, which nothing else of the module touches. Only the worker role may ask for it.
func (s *Store) RiverDriver() (*PollDriver, error) {
	if s.role != RoleWorker {
		return nil, ErrWrongRole
	}
	return &PollDriver{Driver: riverpgxv5.New(s.pool)}, nil
}

// PollDriver is River's pgx driver that says it cannot listen and notify. River's client sends a NOTIFY (the function pg_notify) on
// every insert unless the driver says it has none, and PollOnly in the client config does not stop that: the function is
// revoked from every role (catalog_reach.yaml, wal-writes-and-notifications; nothing of the module notifies, rule no-notify), so
// the call fails with 42501 and aborts the transaction of the insert, and the drain never moves a row. The worker polls.
type PollDriver struct{ *riverpgxv5.Driver }

// GetExecutor is River's executor with the calls that would notify replaced (see package riverpoll: the executor decides about
// NOTIFY on its own, for the leader's resignation, and the revoke of pg_notify would fail it at every shutdown).
func (d *PollDriver) GetExecutor() riverdriver.Executor {
	return riverpoll.Executor(d.Driver.GetExecutor())
}

// UnwrapExecutor is River's executor of a pgx transaction, with the same replacement.
func (d *PollDriver) UnwrapExecutor(tx pgx.Tx) riverdriver.ExecutorTx {
	return riverpoll.ExecutorTx(d.Driver.UnwrapExecutor(tx))
}

// UnwrapTx gives back the pgx transaction of an executor this driver handed out. River's own UnwrapTx asserts the concrete
// type of its executor, which riverpoll's wrapper is not, so the wrapper is taken off first. In River v0.51.2 only its test
// helper calls it; when River is bumped, re-check this method together with GetExecutor and UnwrapExecutor.
func (d *PollDriver) UnwrapTx(e riverdriver.ExecutorTx) pgx.Tx {
	return d.Driver.UnwrapTx(riverpoll.Unwrap(e))
}

// SupportsListener says there is no LISTEN.
func (*PollDriver) SupportsListener() bool { return false }

// SupportsListenNotify says there is no NOTIFY.
func (*PollDriver) SupportsListenNotify() bool { return false }

// JobOutboxRow is a claimed row of job_outbox: the tenant is the column of the row, never a value of its args.
type JobOutboxRow struct {
	Tenant uuid.UUID
	ID     uuid.UUID
	Kind   string
	JobID  string
}

// Only the rows of kind batch_job are taken: job_outbox is the general outbox (a hub or admin job, a welcome message have
// other consumers), and a drain that took them would delete them and cancel their River job (p2-B3-r3-4).
// Delete the rows and read them in one statement: of two drains that meet on a row, one gets it and the other finds it
// deleted (spec 3.5: delete the row, then insert the River job in the same transaction, so a failed insert puts it back).
const qJobOutboxTake = `DELETE FROM ctrlz.job_outbox WHERE kind = 'batch_job' AND id IN (SELECT o.id FROM ctrlz.job_outbox o WHERE o.kind = 'batch_job' ORDER BY o.created_at, o.id LIMIT $1)
RETURNING tenant_id, id, kind, args ->> 'job_id'`

// JobOutboxTake claims up to limit rows of the outbox across tenants, oldest first (the worker's drain policy).
func (g GlobalTx) JobOutboxTake(limit int) ([]JobOutboxRow, error) {
	rows, err := g.tx.Query(g.ctx, qJobOutboxTake, int32(limit))
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []JobOutboxRow
	for rows.Next() {
		var r JobOutboxRow
		var job *string
		if err := rows.Scan(&r.Tenant, &r.ID, &r.Kind, &job); err != nil {
			return nil, sanitize(err)
		}
		if job != nil {
			r.JobID = *job
		}
		out = append(out, r)
	}
	return out, sanitize(rows.Err())
}

// RiverTx is the transaction type River's generic client is instantiated with. It is the pgx transaction under another name, so the
// one package that imports pgx stays internal/store (rule pgx-only-in-the-store): the worker names the type through here.
type RiverTx = pgx.Tx

// RiverInsert hands River's InsertTx the transaction's own pgx.Tx, so the River job commits with the deletion of its outbox
// row or not at all. It is the one place a pgx.Tx leaves this package. River's statements are not read by the statement
// guard, so the call declares the river tables last in the lock order (rule 1): any guarded statement that follows in
// this transaction would take a lock below them and is refused.
func (g GlobalTx) RiverInsert(insert func(tx pgx.Tx) error) error {
	if err := g.tx.st.AcquireRiver(); err != nil {
		return err
	}
	return sanitize(insert(g.tx.tx))
}

const qJobStale = `SELECT j.id FROM ctrlz.batch_jobs j WHERE j.tenant_id = $1 AND j.state IN ('queued', 'running') AND j.updated_at < $2::timestamptz
  AND NOT EXISTS (SELECT 1 FROM ctrlz.job_outbox o WHERE o.tenant_id = $1 AND o.args ->> 'job_id' = j.id::text)
ORDER BY j.id LIMIT $3::int`

// JobStale lists the tenant's active jobs not touched since the cutoff that have no outbox row: candidates for the job
// sweep, which asks River whether a live job of its own still holds each one (spec 3.5).
func (t Tx) JobStale(cutoff time.Time, limit int) ([]uuid.UUID, error) {
	rows, err := t.tx.Query(t.ctx, qJobStale, t.tenant, cutoff, int32(limit))
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, sanitize(err)
		}
		out = append(out, id)
	}
	return out, sanitize(rows.Err())
}

const qJobEndStale = `UPDATE ctrlz.batch_jobs SET state = 'failed', error = '{"code":"job_attempts_exhausted"}'::jsonb, input = NULL
WHERE tenant_id = $1 AND id = $2 AND state IN ('queued', 'running') RETURNING id`

// JobEndStale marks the given rows failed with job_attempts_exhausted where they are still active, so the tenant's one
// job slot is free again, one keyed statement for each row. It returns how many it ended.
func (t Tx) JobEndStale(ids []uuid.UUID) (int, error) {
	n := 0
	for _, id := range ids {
		var got uuid.UUID
		ok, err := notFound(t.tx.QueryRow(t.ctx, qJobEndStale, t.tenant, id).Scan(&got))
		if err != nil {
			return n, err
		}
		if ok {
			n++
		}
	}
	return n, nil
}

// A bounded batch, locked in key order and skipping what another sweep holds; the outer WHERE repeats the predicate of the
// subselect, so a row that changed after the snapshot is judged again.
const qJobsPurge = `DELETE FROM ctrlz.batch_jobs WHERE tenant_id = $1 AND state IN ('done', 'failed') AND updated_at < $2::timestamptz
  AND id = ANY (ARRAY(SELECT j.id FROM ctrlz.batch_jobs j
    WHERE j.tenant_id = $1 AND j.state IN ('done', 'failed') AND j.updated_at < $2::timestamptz` + keyOrder + ` LIMIT $3::int` + lockUpdateSkipLocked + `))`

// JobsPurge deletes finished jobs older than the cutoff, at most limit of them.
func (t Tx) JobsPurge(cutoff time.Time, limit int) (int64, error) {
	tag, err := t.tx.Exec(t.ctx, qJobsPurge, t.tenant, cutoff, int32(limit))
	return tag.RowsAffected(), sanitize(err)
}

// The batch is bounded by the whole primary key (tenant, key), the form the sweep rule reads for a table whose key is not one
// column (sweepPrimaryKeys); the worker holds no UPDATE on this table, so the rows are not locked first (the table is on
// rowOrderExempt).
const qIdempotencyPurge = `DELETE FROM ctrlz.idempotency_keys WHERE tenant_id = $1 AND expires_at < $2::timestamptz
  AND (tenant_id, key) IN (SELECT k.tenant_id, k.key FROM ctrlz.idempotency_keys k WHERE k.tenant_id = $1 AND k.expires_at < $2::timestamptz LIMIT $3::int)`

// IdempotencyPurge deletes keys that expired before the cutoff, at most limit of them (a key lives 24 hours).
func (t Tx) IdempotencyPurge(cutoff time.Time, limit int) (int64, error) {
	tag, err := t.tx.Exec(t.ctx, qIdempotencyPurge, t.tenant, cutoff, int32(limit))
	return tag.RowsAffected(), sanitize(err)
}
