package store

import (
	"context"
	"errors"
	"io"
	"net"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Sentinel errors. A caller tests them with errors.Is and shows one generic
// message: the reason a write was refused may say who owns a conflicting row.
var (
	// ErrConflict covers unique and exclusion violations, and the refusal of
	// the database to delete a suspended claim (SQLSTATE CZ001), which a route
	// answers as it answers the zero rows of a pinned Endpoint.
	ErrConflict = errors.New("store: conflict")
	// ErrConstraint covers foreign key, check and not-null violations.
	ErrConstraint = errors.New("store: constraint violated")
	// ErrPermission means the database refused the statement: a missing grant,
	// or a row that row level security hid.
	ErrPermission = errors.New("store: permission denied")
	// ErrRetry means the transaction lost a race (serialization failure or
	// deadlock, or a lock timeout) and may be run again as a whole.
	ErrRetry = errors.New("store: retry the transaction")
	// ErrConnection means the connection to the database failed or was cut:
	// the server restarted, the backend was terminated, a socket timed out. The
	// transaction did not commit.
	ErrConnection = errors.New("store: database connection failed")
	// ErrDriver is every other failure of the driver itself, such as an
	// argument it could not encode or a column it could not scan. The driver's
	// own text is dropped because it can repeat the value.
	ErrDriver = errors.New("store: database driver error")

	// ErrNotFound is returned by the few methods that have no found flag in their
	// result and are asked for a row that is not there (or not the tenant's).
	ErrNotFound = errors.New("store: not found")

	// ErrNilTenant is returned by WithTenant before any SQL runs.
	ErrNilTenant = errors.New("store: tenant id is the nil uuid")
	// ErrNested is returned when a transaction starts inside another one, and when a
	// single-statement call (Auth, Admin) is given the context of an open transaction:
	// either would hold the transaction's connection and ask the pool for a second
	// (rule one-connection-per-request).
	ErrNested = errors.New("store: nested transaction")
	// ErrWrongRole is returned when an entry point is not allowed for the
	// role the store logged in as.
	ErrWrongRole = errors.New("store: not allowed for this role")
)

// sqlstateSuspendedClaim is raised by the trigger on ip_claims that refuses to
// delete a suspended claim while its tenant exists (migration 0010). It is a
// state of our own, not one the server defines, so no other failure can have it.
const sqlstateSuspendedClaim = "CZ001"

// Error is a database error with the driver's detail removed. The driver's
// message can carry column values and constraint details, so it never leaves
// this package: only the SQLSTATE does.
type Error struct {
	code string
	kind error
}

func (e *Error) Error() string { return "store: database error (SQLSTATE " + e.code + ")" }

// Is lets errors.Is match the sentinel for this error's class.
func (e *Error) Is(target error) bool { return e.kind != nil && target == e.kind }

// driverClass is the coarse class of an error that is not a database error.
func driverClass(err error) error {
	var ne net.Error
	var ce *pgconn.ConnectError
	if errors.As(err, &ne) || errors.As(err, &ce) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, net.ErrClosed) || pgconn.SafeToRetry(err) {
		return ErrConnection
	}
	return ErrDriver
}

// SQLState returns the five character SQLSTATE code.
func (e *Error) SQLState() string { return e.code }

// sanitize turns any error that came from the driver into one that carries no
// detail. A database error becomes an *Error with its SQLSTATE; a context error
// becomes the bare context error; pgx.ErrNoRows, which has no text of its own to
// leak, is kept so callers can test for it; anything else is one of two fixed
// errors, ErrConnection or ErrDriver. The original is never wrapped:
// pgx puts the argument it could not encode, "%#v", into its error text, and
// that argument may be an OTP or a hash (review L2-F15).
func sanitize(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return context.DeadlineExceeded
	case errors.Is(err, context.Canceled):
		return context.Canceled
	case errors.Is(err, ErrLockOrder):
		// Raised by guardTx before any SQL ran; its text holds table names and ranks only.
		return err
	case errors.Is(err, pgx.ErrNoRows):
		return pgx.ErrNoRows
	}
	var refusal *roleRefusal
	if errors.As(err, &refusal) {
		return refusal
	}
	var pg *pgconn.PgError
	if !errors.As(err, &pg) {
		return driverClass(err)
	}
	e := &Error{code: pg.Code}
	switch pg.Code {
	case "23505", "23P01", sqlstateSuspendedClaim:
		e.kind = ErrConflict
	case "23503", "23514", "23502", "23000", "22P02", "22001", "22003":
		e.kind = ErrConstraint
	case "42501":
		e.kind = ErrPermission
	default:
		// Everything that describes the server's state and not the request is decided
		// in one place, by named code or by class (rule sqlstate-class). 40001 and 40P01
		// are class 40 and need no line of their own.
		e.kind = kindOfClass(pg.Code)
	}
	return e
}

// namedKind lists the codes that describe the server's pressure and whose CLASS does not
// say so (rule sqlstate-class). Each round of the review found one more of them answered as
// a bug, so they live in this one table, next to the reason, and the test lists every code
// of PostgreSQL's appendix A with a decision.
//
//   - 55P03 lock_not_available: lock_timeout, the transaction waited too long for a row
//     lock. A lost race like a deadlock; a 503 with a retry hint is honest, a 500 would read
//     as a bug (spec 18.3, pool and lock pressure).
//   - 57014 query_canceled: what the roles' statement_timeout (60 s) raises, behind a lock
//     queue or on a large table (db-r5-3). A client that went away is reported by the driver
//     as the context error before it gets here, so this code is the server's own timeout or
//     an operator's pg_cancel_backend, neither of which is the caller's fault.
//   - 25P03 idle_in_transaction_session_timeout and 25P04 transaction_timeout: every
//     service role sets the first (120 s, roles.yaml) and both are FATAL, so the server has
//     closed the connection under a transaction that stalled (a hung Valkey or SMS call, a
//     paused process). The statement that finds out gets this code, and it is a lost
//     connection like class 57, not a defect of the program (db-r6-1).
//
// The rest of class 25 (a read-only transaction after a failover, a transaction already
// active) stays unclassified: it is the program's or the deployment's business.
func namedKind(code string) error {
	switch code {
	case "55P03", "57014":
		return ErrRetry
	case "25P03", "25P04":
		return ErrConnection
	}
	return nil
}

// kindOfClass decides the operating conditions of the server by the SQLSTATE CLASS, not by
// the codes somebody remembered. Each round found one more code of the same few classes
// answered as a bug (a lock timeout, then a statement timeout, 55P03 and 57014), so the
// classes are the rule and the single codes above are only the ones that are not decided by
// their class (rule sqlstate-class). The classes where the failure is the server's state and
// not the caller's request:
//
//   - 08 connection exception, 57 operator intervention (admin shutdown, crash shutdown,
//     cannot connect now, database dropped, idle session timeout): the connection is gone or
//     the server is going away, ErrConnection;
//   - 40 transaction rollback (serialization failure, deadlock, statement completion
//     unknown) and 53 insufficient resources (disk full, out of memory, too many
//     connections): the transaction may be run again as a whole, ErrRetry.
//
// Every other class (data, integrity, syntax, access) stays unclassified: it describes the
// request or the program, and answering it as pressure would hide a defect behind a 503.
func kindOfClass(code string) error {
	if len(code) != 5 {
		return nil
	}
	if k := namedKind(code); k != nil {
		return k
	}
	switch code[:2] {
	case "08", "57":
		return ErrConnection
	case "40", "53":
		return ErrRetry
	}
	return nil
}
