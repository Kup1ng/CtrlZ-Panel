// Package migrate applies the embedded Postgres migrations as ctrlz_migrator.
//
// It is the only place besides internal/store that opens a database
// connection. Migrations are DDL, and the migrator has no RLS bypass and no
// policy, so a plain SELECT on a tenant table returns nothing. That is the
// whole of the guarantee, and it is not a security boundary against the
// migrator's secret: it owns every table, so it can ALTER ... NO FORCE ROW
// LEVEL SECURITY, and it may SET ROLE ctrlz_auth, whose policies see more.
// Whoever holds the migrator password can read every tenant's data. The
// protection is that the role is reachable only from the migrate container
// (pg_hba.conf), not that it cannot.
package migrate

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"

	"github.com/Kup1ng/CtrlZ-Panel/internal/reachcheck"
	pgmigrations "github.com/Kup1ng/CtrlZ-Panel/migrations/postgres"
)

// VersionTable is where goose records what has been applied. It sits in ctrlz
// and appears in the catalog fixture as a global table with no grants.
const VersionTable = "ctrlz.schema_migrations"

// Config says how to reach the database. The password is read by the caller
// from a Docker secret and arrives as a plain string only here, at the
// driver boundary.
type Config struct {
	Host     string
	Port     uint16
	Database string
	User     string // must be ctrlz_migrator
	Password string
	SSLMode  string // "disable" inside the Compose network, "require" elsewhere
}

// connConfig builds the pgx config from parts, not from a DSN string, so a
// parse error can never echo a password back.
func (c Config) connConfig() (*pgx.ConnConfig, error) {
	ssl := c.SSLMode
	if ssl == "" {
		ssl = "disable"
	}
	cc, err := pgx.ParseConfig(fmt.Sprintf("host=%s port=%d dbname=%s user=%s sslmode=%s application_name=ctrlz-migrate",
		c.Host, c.Port, c.Database, c.User, ssl))
	if err != nil {
		return nil, errors.New("migrate: invalid connection settings")
	}
	cc.Password = c.Password
	return cc, nil
}

// Open returns a *sql.DB on one migrator connection.
func Open(cfg Config) (*sql.DB, error) {
	cc, err := cfg.connConfig()
	if err != nil {
		return nil, err
	}
	db := stdlib.OpenDB(*cc)
	// One session at a time: goose's advisory lock lives on a session, and a
	// migration that sets a role must not leak it into another connection.
	db.SetMaxOpenConns(2)
	return db, nil
}

func provider(db *sql.DB, fsys fs.FS) (*goose.Provider, error) {
	locker, err := lock.NewPostgresSessionLocker()
	if err != nil {
		return nil, fmt.Errorf("migrate: lock: %w", err)
	}
	p, err := goose.NewProvider(goose.DialectPostgres, db, fsys,
		goose.WithTableName(VersionTable),
		goose.WithSessionLocker(locker),
		goose.WithLogger(slogLogger{}),
	)
	if err != nil {
		return nil, fmt.Errorf("migrate: provider: %w", err)
	}
	return p, nil
}

// Up applies every pending migration and returns how many ran. It is safe to
// run from two containers at once: goose takes an advisory lock.
func Up(ctx context.Context, db *sql.DB) (int, error) {
	// goose keeps its version table in ctrlz, so the schema must exist before
	// the first migration. 0001 uses IF NOT EXISTS for the same reason.
	if err := ensureSchema(ctx, db); err != nil {
		return 0, fmt.Errorf("migrate: create schema: %w", err)
	}
	p, err := provider(db, pgmigrations.Migrations)
	if err != nil {
		return 0, err
	}
	res, err := p.Up(ctx)
	if err != nil {
		return len(res), fmt.Errorf("migrate: up: %w", err)
	}
	return len(res), nil
}

// UpTo applies the pending migrations up to and including version, and returns how many ran. It
// exists for the tests that prove a migration's data cleanup: a database is taken to the version
// before it, rows a real install could hold are planted, and the one migration then runs on them
// (every other test migrates an empty database, where such a statement never touches a row). The
// binary never calls it: an install always runs Up.
func UpTo(ctx context.Context, db *sql.DB, version int64) (int, error) {
	if err := ensureSchema(ctx, db); err != nil {
		return 0, fmt.Errorf("migrate: create schema: %w", err)
	}
	p, err := provider(db, pgmigrations.Migrations)
	if err != nil {
		return 0, err
	}
	res, err := p.UpTo(ctx, version)
	if err != nil {
		return len(res), fmt.Errorf("migrate: up to %d: %w", version, err)
	}
	return len(res), nil
}

// ensureSchema is CREATE SCHEMA IF NOT EXISTS that survives a concurrent
// twin. IF NOT EXISTS is not atomic in Postgres: two sessions can both pass the
// existence check and the second then fails on the unique index of
// pg_namespace (23505) or with duplicate_schema (42P06). This runs before goose
// takes its advisory lock, so two migrate containers starting together hit it.
// Either error means the other session made the schema, which is what was
// wanted.
func ensureSchema(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, "CREATE SCHEMA IF NOT EXISTS ctrlz")
	var pg *pgconn.PgError
	if errors.As(err, &pg) && (pg.Code == "23505" || pg.Code == "42P06") {
		return nil
	}
	return err
}

// Status is one migration and whether it has been applied.
type Status struct {
	Version int64
	Source  string
	Applied bool
}

// List reports every embedded migration and its state.
func List(ctx context.Context, db *sql.DB) ([]Status, error) {
	p, err := provider(db, pgmigrations.Migrations)
	if err != nil {
		return nil, err
	}
	st, err := p.Status(ctx)
	if err != nil {
		return nil, fmt.Errorf("migrate: status: %w", err)
	}
	out := make([]Status, 0, len(st))
	for _, s := range st {
		out = append(out, Status{Version: s.Source.Version, Source: s.Source.Path, Applied: s.State == goose.StateApplied})
	}
	return out, nil
}

// slogLogger is goose's logger. A log message is a constant and its attributes are
// closed values (rule closed-values-in-logs), and goose's lines are formatted text,
// so only the fact that a step ran or failed is kept. The file that failed is in the
// error Up returns, which the caller reports; the count of applied files is logged by
// the caller.
type slogLogger struct{}

func (slogLogger) Fatalf(string, ...any) { slog.Error("migration step failed") }
func (slogLogger) Printf(string, ...any) { slog.Info("migration step") }

// WaitReady pings until the database answers or limit passes. Roles start in
// no fixed order, and Postgres may still be finishing its first-start
// initialisation; waiting beats failing the whole stack. The error never
// repeats the driver's message, which can name the host and the user.
func WaitReady(ctx context.Context, db *sql.DB, limit time.Duration, waiting func()) error {
	deadline := time.Now().Add(limit)
	delay := 250 * time.Millisecond
	for {
		pctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		err := db.PingContext(pctx)
		cancel()
		if err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if time.Now().Add(delay).After(deadline) {
			return errors.New("migrate: database did not become reachable in time")
		}
		if waiting != nil {
			waiting()
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
		if delay < 2*time.Second {
			delay *= 2
		}
	}
}

// ReachError is returned by CheckReach when the live database lets a role or PUBLIC do what the
// bootstrap and the reviewed lists close. It names each object and role (never a value), and the files
// whose statements close it.
type ReachError struct {
	Violations []string
	// Repairs are the bootstrap files that close the findings that have one, sorted. A finding with
	// none (an open function no family names) says in its own text which statement closes it.
	Repairs []string
}

func (e *ReachError) Error() string {
	msg := "migrate: the live database lets a role do what the bootstrap closes"
	if len(e.Repairs) > 0 {
		// The command, not only the file names: the files need the variables of the container's environment, which
		// only repair.sh sets (db-r16-26).
		msg += " (repair with `docker compose exec -u postgres postgres sh /ctrlz-bootstrap/repair.sh`, which runs migrations/postgres/" + strings.Join(e.Repairs, " and migrations/postgres/") + " with the container's own settings; they are idempotent)"
	}
	return msg + ": " + strings.Join(e.Violations, "; ")
}

// CheckReach asks the live database four questions of internal/reachcheck, the judgement that CI
// asks of a fresh cluster (catalog checks 30, 31 and the shape of 08):
//
//  1. PUBLIC and every ctrlz role hold exactly the pg_catalog privileges
//     migrations/catalog/catalog_reach.yaml names (check 30);
//  2. nothing else of pg_catalog is open to PUBLIC that the reviewed list
//     migrations/catalog/pg_catalog_open.golden does not hold (check 31, db-r16-11);
//  3. every ctrlz role still has the attributes, connection limit and role defaults of roles.yaml,
//     none of them zero (db-r16-5);
//  4. the rest of what the superuser bootstrap sets once: no privilege of PUBLIC on the database or the
//     public schema, CONNECT only for the login roles, the memberships and schema owners of roles.yaml
//     (JudgeBootstrapState, db-r16-24).
//
// The REVOKEs and the role defaults live in superuser steps that run once, on an empty data
// directory, and the migrator is not the owner of pg_catalog, so no migration can close them. Without
// this call an installed database whose bootstrap was not re-run after 0047, a restored dump, a
// cluster upgraded to a Postgres that adds a function, or a role that rewrote its own defaults stays
// open while every migration reports success and the stack starts (db-r15-2, db-r15-8). It runs after
// Up on every start of the migrate container, which the services wait for, so a failure stops the stack.
// It reads the catalog only.
//
// It refuses only on what is a hole (a Security finding). A name in catalog_reach.yaml that matches no
// object, a family with no member and a role named for a privilege it lacks are the files' hygiene and
// belong to CI: the first Postgres that drops a listed function would otherwise keep the stack down on
// a condition that no bootstrap re-run repairs (db-r16-6).
func CheckReach(ctx context.Context, db *sql.DB) error {
	file, roles, err := reachcheck.Embedded()
	if err != nil {
		return err
	}
	spec, err := reachcheck.EmbeddedRoles()
	if err != nil {
		return err
	}
	golden, err := reachcheck.OpenGolden()
	if err != nil {
		return err
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("migrate: reach check: %w", sanitizeConn(err))
	}
	defer conn.Close()
	var findings []reachcheck.Finding
	err = conn.Raw(func(dc any) error {
		sc, ok := dc.(*stdlib.Conn)
		if !ok {
			return errors.New("migrate: reach check: not a pgx connection")
		}
		pc := sc.Conn()
		q := reachcheck.QueryFunc(func(ctx context.Context, sql string, args ...any) (reachcheck.Rows, error) {
			return pc.Query(ctx, sql, args...)
		})
		existing, err := reachcheck.Existing(ctx, q, roles)
		if err != nil {
			return err
		}
		reach, err := reachcheck.Judge(ctx, q, file, existing)
		if err != nil {
			return err
		}
		open, err := reachcheck.Open(ctx, q)
		if err != nil {
			return err
		}
		bounds, err := reachcheck.JudgeRoleBounds(ctx, q, spec)
		if err != nil {
			return err
		}
		state, err := reachcheck.JudgeBootstrapState(ctx, q, spec)
		if err != nil {
			return err
		}
		findings = append(findings, reachcheck.SecurityOnly(reach)...)
		findings = append(findings, reachcheck.JudgeOpen(open, golden)...)
		findings = append(findings, reachcheck.SecurityOnly(bounds)...)
		findings = append(findings, reachcheck.SecurityOnly(state)...)
		return nil
	})
	if err != nil {
		return fmt.Errorf("migrate: reach check: %w", sanitizeConn(err))
	}
	if len(findings) == 0 {
		return nil
	}
	re := &ReachError{Violations: reachcheck.Texts(findings)}
	seen := map[string]bool{}
	for _, f := range findings {
		if f.Repair != "" && !seen[f.Repair] {
			seen[f.Repair] = true
			re.Repairs = append(re.Repairs, f.Repair)
		}
	}
	sort.Strings(re.Repairs)
	return re
}

// sanitizeConn keeps a driver error's class and drops its text, which can name the host and the user.
func sanitizeConn(err error) error {
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		return fmt.Errorf("SQLSTATE %s", pg.Code)
	}
	return errors.New("connection error")
}
