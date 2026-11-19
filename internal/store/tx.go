package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

// rollbackTimeout bounds the rollback of a failed transaction. The rollback
// must survive the cancellation of the request (a cancelled request would
// otherwise leave the transaction to the server timeout), but it must not wait
// for ever on a connection that has stopped answering: each handler returning
// an error would park in Rollback and hold its pool slot until TCP gave up, and
// a small pool would drain (review L2-F21).
const rollbackTimeout = 5 * time.Second

// DBTX is what generated query code (sqlc, pgx/v5 flavour) needs from a
// transaction. The static queries of the services take it as their argument.
//
// Every statement passed to it must be a constant. Dynamic SQL is banned in
// the tenant path (R5), and TestNoDynamicSQL fails the build on a violation.
//
// Query returns pgx.Rows so that the output of sqlc keeps compiling, but the
// rows it returns are a wrapper whose Conn() is nil: the raw connection is the
// way to run a session-level set_config or SQL the lint cannot see.
type DBTX interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

// txDB is what DB() returns: the three methods of DBTX and nothing else. It is
// a struct of its own, not the pgx.Tx, so a caller cannot type-assert the value
// back to a pgx.Tx or reach its Conn() and run a session-level set_config that
// would outlive the transaction and scope the next one on the connection.
type txDB struct{ tx *guardTx }

// The errors of the three calls are sanitized here, because they come back to
// the caller of the callback and driver errors can repeat an argument (pgx
// prints the value it could not encode, and a failed scan can print the text it
// could not parse). Application errors of the callback itself are not touched.

func (d txDB) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	tag, err := d.tx.Exec(ctx, sql, args...) // lint:sql-const forwarded; every caller of DB().Exec is checked
	return tag, sanitize(err)
}

func (d txDB) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	rows, err := d.tx.Query(ctx, sql, args...) // lint:sql-const forwarded; every caller of DB().Query is checked
	if err != nil {
		return nil, sanitize(err)
	}
	return safeRows{rows}, nil
}

func (d txDB) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	return safeRow{d.tx.QueryRow(ctx, sql, args...)} // lint:sql-const forwarded; every caller of DB().QueryRow is checked
}

// safeRow sanitizes the error of Scan.
type safeRow struct{ r pgx.Row }

func (s safeRow) Scan(dest ...any) error { return sanitize(s.r.Scan(dest...)) }

// safeRows is pgx.Rows without the connection: Conn() is nil, and the errors
// are sanitized. The generated sqlc code and pgx.CollectRows use only the other
// methods.
type safeRows struct{ r pgx.Rows }

func (s safeRows) Close()                                       { s.r.Close() }
func (s safeRows) Err() error                                   { return sanitize(s.r.Err()) }
func (s safeRows) CommandTag() pgconn.CommandTag                { return s.r.CommandTag() }
func (s safeRows) FieldDescriptions() []pgconn.FieldDescription { return s.r.FieldDescriptions() }
func (s safeRows) Next() bool                                   { return s.r.Next() }
func (s safeRows) Scan(dest ...any) error                       { return sanitize(s.r.Scan(dest...)) }
func (s safeRows) RawValues() [][]byte                          { return s.r.RawValues() }
func (s safeRows) TypeMap() *pgtype.Map                         { return s.r.TypeMap() }
func (safeRows) Conn() *pgx.Conn                                { return nil }

func (s safeRows) Values() ([]any, error) {
	v, err := s.r.Values()
	return v, sanitize(err)
}

// txMarker is stored in the context handed to the callback, so a call that
// starts another transaction from inside it is caught. The guard is best
// effort: it sees the context the callback was given, not the goroutine. A
// callback that calls WithTenant with a context captured from outside runs an
// independent transaction on another connection with its own tenant setting;
// that is a design mistake but not an isolation hole, because every
// transaction sets and loses its own transaction-local tenant.
type txMarker struct{}

// Tx is an open tenant-scoped transaction. It is only valid inside the
// callback of WithTenant.
type Tx struct {
	tx     *guardTx
	ctx    context.Context
	tenant uuid.UUID
	batch  uuid.UUID
}

// Context returns the context the callback must use for everything it does.
// It carries the nesting marker; a context taken from outside the callback
// would let WithTenant be called again from inside.
func (t Tx) Context() context.Context { return t.ctx }

// TenantID is the tenant this transaction is scoped to.
func (t Tx) TenantID() uuid.UUID { return t.tenant }

// BatchID groups the policy_outbox rows written in this transaction.
func (t Tx) BatchID() uuid.UUID { return t.batch }

// DB gives generated code its handle on the transaction.
func (t Tx) DB() DBTX { return txDB{t.tx} }

const setTenantSQL = `SELECT pg_catalog.set_config('ctrlz.tenant_id', $1, true)`

// clearTenantSQL masks any session-level value of the setting for the length of
// a global transaction. Fail-closed depends on every setter being
// transaction-local; if one ever were not (a stray SET, a set_config with false
// in a helper), the value would stay on the pooled connection and silently
// scope the next global job to that tenant. This makes a global transaction
// start from no tenant whatever the connection carries. The lint test bans the
// session forms in the first place.
const clearTenantSQL = `SELECT pg_catalog.set_config('ctrlz.tenant_id', '', true)`

// WithTenant runs fn in one transaction scoped to tenant.
//
//  1. A nil tenant and a nested call are errors, before any SQL.
//  2. BEGIN with the requested isolation and access mode.
//  3. set_config('ctrlz.tenant_id', tenant, true). The third argument makes it
//     local to the transaction, so the connection goes back to the pool with
//     the setting empty, which current_tenant_id() treats as no tenant.
//  4. fn runs. The tenant policy is enforced by Postgres on every statement.
//  5. COMMIT if fn returned nil, ROLLBACK otherwise, including on panic.
//
// One tenant per transaction. Work across tenants runs one transaction each.
func (s *Store) WithTenant(ctx context.Context, tenant uuid.UUID, opts TxOpts, fn func(Tx) error) error {
	if tenant == uuid.Nil {
		return ErrNilTenant
	}
	if ctx.Value(txMarker{}) != nil {
		return ErrNested
	}
	batch, err := uuid.NewV7()
	if err != nil {
		return fmt.Errorf("store: batch id: %w", err)
	}
	return s.run(ctx, opts, func(ctx context.Context, tx *guardTx) error {
		if _, err := tx.Exec(ctx, setTenantSQL, tenant.String()); err != nil {
			return sanitize(err)
		}
		return fn(Tx{tx: tx, ctx: ctx, tenant: tenant, batch: batch})
	})
}

// GlobalTx is an open transaction with no tenant. Row level security hides
// every tenant row from it, except where a named policy gives the role a
// cross-tenant read (policies.yaml).
type GlobalTx struct {
	tx  *guardTx
	ctx context.Context
}

// Context returns the context the callback must use.
func (t GlobalTx) Context() context.Context { return t.ctx }

// DB gives generated code its handle on the transaction.
func (t GlobalTx) DB() DBTX { return txDB{t.tx} }

// WithGlobal runs fn in one transaction with no tenant set. It is for the hub,
// compiler, worker and admin; the tenant role has no business here and gets
// ErrWrongRole.
func (s *Store) WithGlobal(ctx context.Context, opts TxOpts, fn func(GlobalTx) error) error {
	if s.role == RoleTenant {
		return ErrWrongRole
	}
	if ctx.Value(txMarker{}) != nil {
		return ErrNested
	}
	return s.run(ctx, opts, func(ctx context.Context, tx *guardTx) error {
		if _, err := tx.Exec(ctx, clearTenantSQL); err != nil {
			return sanitize(err)
		}
		return fn(GlobalTx{tx: tx, ctx: ctx})
	})
}

// run is the shared transaction shell.
func (s *Store) run(ctx context.Context, opts TxOpts, body func(context.Context, *guardTx) error) (err error) {
	s.asked.Add(1)
	bctx, release := s.acquireCtx(ctx)
	tx, err := s.pool.BeginTx(bctx, opts.pgx())
	release() // the deadline was for getting the connection, not for the transaction
	if err != nil {
		return sanitize(err)
	}
	inner := context.WithValue(ctx, txMarker{}, struct{}{})
	done := false
	defer func() {
		if done {
			return
		}
		// Roll back with a context that survives cancellation of ctx, or a
		// cancelled request would leave the transaction to the server timeout,
		// and with a deadline, or a dead connection would hold this goroutine
		// and its pool slot (rollbackTimeout).
		rb, cancel := context.WithTimeout(context.WithoutCancel(ctx), rollbackTimeout)
		defer cancel()
		_ = tx.Rollback(rb)
		if r := recover(); r != nil {
			panic(r)
		}
	}()
	if err := body(inner, &guardTx{tx: tx, own: &s.lockCache}); err != nil {
		return wrap(err)
	}
	if err := tx.Commit(ctx); err != nil {
		done = true
		return sanitize(err)
	}
	done = true
	return nil
}

// wrap removes driver detail from database errors and leaves everything else,
// such as an application's own sentinel, matchable with errors.Is.
func wrap(err error) error {
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		return sanitize(err)
	}
	return err
}
