// Package store is the only door to Postgres for the services.
//
// The pool is unexported and there is no exported way to run SQL outside the
// entry points here:
//
//   - WithTenant runs a transaction scoped to one tenant. This is the path of
//     every tenant request and tenant job.
//   - WithGlobal runs a transaction with no tenant, for the roles that read or
//     write global tables. It refuses to run under ctrlz_tenant.
//   - Auth returns the lookups that must work before the tenant is known. Each
//     method calls one SECURITY DEFINER function and nothing else, on a
//     connection of its own, and is refused (ErrNested) when the context it is
//     given belongs to an open transaction. A call that must happen during a
//     transaction is a method of Tx or GlobalTx, on the transaction's connection.
//
// A request holds at most one database connection at any moment (rule
// one-connection-per-request, internal/lint).
//
// Row level security is the boundary; this package is what makes it hard to
// use wrongly. See docs/specs/postgres-schema.md section 10.
package store

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
)

// Role is the database role a service logs in as.
type Role string

// The six roles a service may log in as. ctrlz_migrator belongs to
// internal/migrate, and ctrlz_auth and ctrlz_backfill cannot log in.
const (
	RoleTenant   Role = "ctrlz_tenant"
	RoleHub      Role = "ctrlz_hub"
	RoleCompiler Role = "ctrlz_compiler"
	RoleWorker   Role = "ctrlz_worker"
	RoleAdmin    Role = "ctrlz_admin"
	// RoleKeytool is the one-shot key tool (`ctrlz rekey` and `ctrlz declare-lost`).
	// It has a login of its own so that the long-running worker, which reads login
	// codes, holds nothing that can rewrite or switch off a second factor.
	RoleKeytool Role = "ctrlz_keytool"
)

func (r Role) valid() bool {
	switch r {
	case RoleTenant, RoleHub, RoleCompiler, RoleWorker, RoleAdmin, RoleKeytool:
		return true
	}
	return false
}

// Config says how to reach the database. Role is both the login name and the
// role the service expects to be: Open refuses to start if the server says
// otherwise.
type Config struct {
	Host     string
	Port     uint16
	Database string
	Role     Role
	Password secret.String
	SSLMode  string // "disable" inside the Compose network, "require" elsewhere

	MaxConns       int32
	MinConns       int32
	ConnectTimeout time.Duration
	// AcquireTimeout bounds the wait for a free pooled connection. Zero uses
	// ConnectTimeout, and zero there means no bound beyond the caller's context.
	// Without it a request on an exhausted pool waits until the client gives up
	// (spec 18.3: "Pool exhausted: 503 within the connect timeout").
	AcquireTimeout  time.Duration
	MaxConnLifetime time.Duration
	ApplicationName string
}

// Store owns the connection pool. Create it with Open and share it.
type Store struct {
	pool *pgxpool.Pool
	role Role
	// acquire is the longest a call waits for a connection; zero is no limit.
	acquire time.Duration
	// lockCache remembers how each statement text was classified for the lock
	// order (guardTx.admit). The texts are constants, so it stays small.
	lockCache sync.Map
	// asked counts the calls that asked the pool for a connection (a transaction or a one-row
	// lookup), refused and failed ones too. It is the twin of password.Gate.Attempts: the rule
	// known-unknown-oracle says whether an account exists may not choose how many times a request
	// asks the pool, because under a busy pool each ask is a wait that the answer's floor must
	// hide, and the oracle test compares this number for a known and an unknown subject.
	asked atomic.Uint64
}

// Asked is the number of times the store asked its pool for a connection since it opened.
func (s *Store) Asked() uint64 { return s.asked.Load() }

// acquireCtx gives a call a deadline for getting a connection. The returned
// cancel must be called once the connection is held (or the query is done).
func (s *Store) acquireCtx(ctx context.Context) (context.Context, context.CancelFunc) {
	if s.acquire <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, s.acquire)
}

// Open connects and checks the role. Every connection the pool makes is
// checked, not only the first: a service must never run as a role that can
// bypass row level security, so a mismatch is fatal at startup rather than a
// silent privilege change later.
func Open(ctx context.Context, cfg Config) (*Store, error) {
	return open(ctx, cfg, true)
}

// OpenLazy builds the pool without connecting. A service uses it when Open
// failed with ErrConnection at start: the database is down or still starting,
// which is not a reason to exit and leave /readyz unanswered (spec 18.3,
// "Postgres down at start"). Requests then answer 503 until a connection
// succeeds, and every connection the pool makes still runs the role assertion.
// A wrong password or the wrong role is not a connection failure and still
// stops the process in Open.
func OpenLazy(ctx context.Context, cfg Config) (*Store, error) {
	return open(ctx, cfg, false)
}

func open(ctx context.Context, cfg Config, ping bool) (*Store, error) {
	if !cfg.Role.valid() {
		return nil, fmt.Errorf("store: %q is not a service role", cfg.Role)
	}
	ssl := cfg.SSLMode
	if ssl == "" {
		ssl = "disable"
	}
	app := cfg.ApplicationName
	if app == "" {
		app = "ctrlz"
	}
	// The password is set on the parsed config, never put into a DSN string,
	// so a parse or connect error cannot repeat it.
	dsn := fmt.Sprintf("host=%s port=%d dbname=%s user=%s sslmode=%s application_name=%s",
		cfg.Host, cfg.Port, cfg.Database, string(cfg.Role), ssl, app)
	want := cfg.Role
	pc, err := poolConfig(dsn, cfg, want)
	if err != nil {
		return nil, err
	}
	pool, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		return nil, errors.New("store: cannot create pool")
	}
	s := &Store{pool: pool, role: want, acquire: acquireTimeout(cfg)}
	// NewWithConfig does not connect. Ping makes the first connection, which
	// runs the role assertion.
	if !ping {
		return s, nil
	}
	if err := pool.Ping(ctx); err != nil {
		s.Close()
		cause := sanitize(err)
		// A server that accepts the connection and never answers (a stopped
		// container behind a port proxy, a host that drops packets) ends in the
		// connect timeout, which sanitize reduces to a bare deadline error. That is
		// the database being unreachable, exactly like a refused connection, and the
		// service must start lazily on it (spec 18.3) instead of exiting. A deadline
		// or cancel of the caller's own is not: ctx.Err() tells them apart, because
		// the connect timeout is applied inside pgx and leaves ctx untouched.
		if errors.Is(cause, context.DeadlineExceeded) && ctx.Err() == nil {
			cause = ErrConnection
		}
		return nil, fmt.Errorf("store: cannot reach the database as %s: %w", want, cause)
	}
	return s, nil
}

// poolConfig builds the settings of the one pool a store has. A request holds one
// connection at a time (rule one-connection-per-request), so the pool size is the
// number of requests in flight and the role's CONNECTION LIMIT is that plus the
// one-connection command-line tools beside the service.
func poolConfig(dsn string, cfg Config, want Role) (*pgxpool.Config, error) {
	pc, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, errors.New("store: invalid connection settings")
	}
	pc.ConnConfig.Password = cfg.Password.Reveal()
	if cfg.MaxConns > 0 {
		pc.MaxConns = cfg.MaxConns
	}
	if cfg.MinConns > 0 {
		pc.MinConns = cfg.MinConns
	}
	if cfg.ConnectTimeout > 0 {
		pc.ConnConfig.ConnectTimeout = cfg.ConnectTimeout
	}
	if cfg.MaxConnLifetime > 0 {
		pc.MaxConnLifetime = cfg.MaxConnLifetime
	}
	// JIT is off for every connection. Postgres decides to JIT from the planner's
	// cost estimate, and a table that was never analysed (a singleton such as
	// system_settings, which autovacuum leaves alone) is estimated at hundreds of
	// rows, so the three-way join of ctrlz_fn.auth_public_config() is "expensive"
	// (cost 2.8M against jit_above_cost 100000) and every call compiled 15 LLVM
	// functions: 350 to 850 ms for a query that returns one row. This is an OLTP
	// service of short statements; JIT can only add latency, and under CPU load it
	// pushed the first public-config load past its 3 s bound (503).
	pc.ConnConfig.RuntimeParams["jit"] = "off"
	pc.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
		return assertRole(ctx, c, want)
	}
	return pc, nil
}

const roleCheckSQL = `SELECT rolsuper, rolbypassrls, current_user::text FROM pg_catalog.pg_roles WHERE rolname = current_user`

// assertRole is the startup assertion of spec section 10.
func assertRole(ctx context.Context, c *pgx.Conn, want Role) error {
	var super, bypass bool
	var user string
	if err := c.QueryRow(ctx, roleCheckSQL).Scan(&super, &bypass, &user); err != nil {
		return fmt.Errorf("role check failed: %w", sanitize(err))
	}
	if super || bypass {
		return &roleRefusal{fmt.Sprintf("refusing to run: role %s can bypass row level security", user)}
	}
	if user != string(want) {
		return &roleRefusal{fmt.Sprintf("refusing to run: connected as %s, expected %s", user, want)}
	}
	return nil
}

// roleRefusal is the startup assertion failing. Its text holds role names and
// nothing else, so sanitize lets it through: an operator needs to read it, and
// the driver wraps it in its own connect error.
type roleRefusal struct{ msg string }

func (e *roleRefusal) Error() string { return e.msg }

// Close releases the pool.
func (s *Store) Close() {
	s.pool.Close()
}

// Role reports the role this store logged in as.
func (s *Store) Role() Role { return s.role }

// Ping checks that a connection can be made. Readiness probes use it.
func (s *Store) Ping(ctx context.Context) error {
	if err := s.pool.Ping(ctx); err != nil {
		return sanitize(err)
	}
	return nil
}

// Isolation is the transaction isolation level.
type Isolation int

// Isolation levels. The zero value is Postgres's default, read committed.
const (
	ReadCommitted Isolation = iota
	RepeatableRead
	Serializable
)

// TxOpts are the options of a transaction.
type TxOpts struct {
	Isolation Isolation
	ReadOnly  bool
}

func (o TxOpts) pgx() pgx.TxOptions {
	iso := pgx.ReadCommitted
	switch o.Isolation {
	case RepeatableRead:
		iso = pgx.RepeatableRead
	case Serializable:
		iso = pgx.Serializable
	}
	access := pgx.ReadWrite
	if o.ReadOnly {
		access = pgx.ReadOnly
	}
	return pgx.TxOptions{IsoLevel: iso, AccessMode: access}
}

// There is no Listen and no NOTIFY anywhere in the module (P1 auth review round 15, db-r15-1 and
// db-r15-6). Postgres has one notification queue for the whole cluster and no privilege for LISTEN or
// NOTIFY, so any login role that listens and stops reading, then sends, fills it; from then on every
// transaction that notified fails at COMMIT with 54000, for every tenant. A wake-up that can take a
// request's commit down with it is not a hint. The SMS worker polls its outbox (smssend.Config.Poll,
// 500 ms); internal/lint TestNoNotifyAndNoListen and catalog test TestNoFunctionNotifies hold it.

func acquireTimeout(cfg Config) time.Duration {
	if cfg.AcquireTimeout > 0 {
		return cfg.AcquireTimeout
	}
	return cfg.ConnectTimeout
}
