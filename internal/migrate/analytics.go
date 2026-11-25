package migrate

import (
	"context"
	"crypto/tls"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/pressly/goose/v3"

	"github.com/Kup1ng/CtrlZ-Panel/internal/logattr"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
	chmigrations "github.com/Kup1ng/CtrlZ-Panel/migrations/clickhouse"
)

// AnalyticsVersionTable is where goose records the ClickHouse migrations. It is in its own database so that
// every table of `ctrlz` holds tenant data and has tenant_id first in its sorting key (P5 3.4), which the
// row policy and the structural check of 11.2 A4 rely on.
const AnalyticsVersionTable = "ctrlz_meta.schema_migrations"

// AnalyticsConfig says how to reach ClickHouse. The password arrives as a plain string only at the driver
// boundary, like Config does for Postgres.
type AnalyticsConfig struct {
	Addr     string // host:port of the native protocol
	User     string // must be ctrlz_migrator
	Password string
	// TLS is nil inside the Compose network, whose `backend` network has no route out.
	TLS *tls.Config
}

// OpenAnalytics returns a *sql.DB on ClickHouse as the migrator. It opens nothing until the first
// statement, so WaitAnalyticsReady is what finds out whether the server answers.
func OpenAnalytics(cfg AnalyticsConfig) *sql.DB {
	db := clickhouse.OpenDB(&clickhouse.Options{
		Addr: []string{cfg.Addr},
		Auth: clickhouse.Auth{Database: "default", Username: cfg.User, Password: cfg.Password},
		TLS:  cfg.TLS,
		Settings: clickhouse.Settings{
			// A DDL statement on a big table can take a while; the server's own default is 0 for the
			// migrator, this keeps a hung statement from holding the one-shot for ever.
			"max_execution_time": 600,
		},
		DialTimeout: 5 * time.Second,
	})
	// One session: the migrations run one after another and a second connection would only add a
	// place for a half-applied step to hide.
	db.SetMaxOpenConns(1)
	return db
}

func analyticsProvider(db *sql.DB) (*goose.Provider, error) {
	p, err := goose.NewProvider(goose.DialectClickHouse, db, chmigrations.Migrations,
		goose.WithTableName(AnalyticsVersionTable),
		goose.WithLogger(slogLogger{}),
	)
	if err != nil {
		return nil, fmt.Errorf("migrate: analytics provider: %w", err)
	}
	return p, nil
}

// UpAnalytics applies the access statements (row policies and the quota) and then every pending ClickHouse
// migration, and returns how many migrations ran. ClickHouse has no transaction and no advisory lock, so a
// second run at the same time is refused by the stack and not by this function: Compose runs one
// migrate-analytics container.
func UpAnalytics(ctx context.Context, db *sql.DB) (int, error) {
	return upAnalytics(ctx, db, 0)
}

// UpAnalyticsTo is UpAnalytics that stops after the migration of that version. The container test uses it to
// look at the server between the first table and the rest, which is where a run that fails or is killed would
// leave a real install.
func UpAnalyticsTo(ctx context.Context, db *sql.DB, version int64) (int, error) {
	return upAnalytics(ctx, db, version)
}

func upAnalytics(ctx context.Context, db *sql.DB, to int64) (int, error) {
	if _, err := db.ExecContext(ctx, "CREATE DATABASE IF NOT EXISTS ctrlz_meta"); err != nil {
		return 0, errors.New("migrate: create ctrlz_meta: " + errClass(err))
	}
	// First, before any table: a table with no row policy is read without a filter (access.sql says why).
	if err := EnsureAnalyticsAccess(ctx, db); err != nil {
		return 0, err
	}
	p, err := analyticsProvider(db)
	if err != nil {
		return 0, err
	}
	var res []*goose.MigrationResult
	if to > 0 {
		res, err = p.UpTo(ctx, to)
	} else {
		res, err = p.Up(ctx)
	}
	if err != nil {
		return len(res), fmt.Errorf("migrate: analytics up: %w", err)
	}
	return len(res), nil
}

// EnsureAnalyticsAccess makes the row policies and the reader quota of access.sql, replacing any that exist.
// It runs on every start of migrate-analytics, outside goose's version record, because the access entities
// live in the server's access directory and the record lives in the database: after a restore of the data
// alone the record says nothing is pending while the policies are gone.
func EnsureAnalyticsAccess(ctx context.Context, db *sql.DB) error {
	text, err := chmigrations.Access()
	if err != nil {
		return err
	}
	for i, stmt := range accessStatements(text) {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("migrate: analytics access statement %d: %s", i+1, errClass(err))
		}
	}
	return nil
}

// accessStatements splits access.sql into statements. A comment may hold a semicolon, so whole-line comments
// go first; the file has no inline comments and no string with one.
func accessStatements(text string) []string {
	var code []string
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "--") {
			continue
		}
		code = append(code, line)
	}
	var out []string
	for _, stmt := range strings.Split(strings.Join(code, "\n"), ";") {
		if stmt = strings.TrimSpace(stmt); stmt != "" {
			out = append(out, stmt)
		}
	}
	return out
}

// errClass says what kind of failure a driver error was without repeating its text, which can name the
// host, the user or a statement.
func errClass(err error) string {
	var ex *clickhouse.Exception
	if errors.As(err, &ex) {
		return fmt.Sprintf("server code %d", ex.Code)
	}
	return "driver error"
}

// WaitAnalyticsReady pings until ClickHouse answers or limit passes. ClickHouse starts after its wrapper
// has written the users and may take a minute on a first start; the one-shot waits for it, and a limit
// that passes ends the process non-zero so that Compose restarts it (restart: on-failure).
func WaitAnalyticsReady(ctx context.Context, db *sql.DB, limit time.Duration) error {
	return WaitReady(ctx, db, limit, nil)
}

// RunAnalytics is the whole of `ctrlz migrate-analytics`: read the password from its file, wait for the
// server, apply the migrations. The error it returns names a step and a server code and never a value, and
// the caller prints it.
func RunAnalytics(ctx context.Context, addr, user, passwordFile string, wait time.Duration) error {
	pw, err := secret.FromFile(passwordFile)
	if err != nil {
		return errors.New("migrate-analytics: the password file cannot be read")
	}
	db := OpenAnalytics(AnalyticsConfig{Addr: addr, User: user, Password: pw.Reveal()})
	defer func() { _ = db.Close() }()
	if err := WaitAnalyticsReady(ctx, db, wait); err != nil {
		return errors.New("migrate-analytics: ClickHouse did not answer in time")
	}
	n, err := UpAnalytics(ctx, db)
	if err != nil {
		return err
	}
	slog.Info("migrate-analytics: ok", logattr.Int("applied", n))
	return nil
}
