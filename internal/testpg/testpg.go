// Package testpg starts a real Postgres 18 in a container for tests, creates
// the roles and the database the way the installer does, and applies the
// real migrations.
//
// Tests of tenant isolation are worthless against a mock, so nothing here
// fakes Postgres. The package is imported only from _test files and from the
// catalog test package.
package testpg

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/Kup1ng/CtrlZ-Panel/deploy"
	"github.com/Kup1ng/CtrlZ-Panel/internal/migrate"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
	pgmigrations "github.com/Kup1ng/CtrlZ-Panel/migrations/postgres"
)

// DefaultImage is the Postgres under test: the reference docker-compose.yml pins, read through deploy.Image so
// this package keeps no tag of its own (round 16, admin-r16-1; the database area pins the same digest).
func DefaultImage() string { return deploy.Image("POSTGRES_IMAGE") }

// RoleNames are the six roles that log in, plus the migrator.
func loginRoles() []string {
	return []string{"ctrlz_migrator", "ctrlz_tenant", "ctrlz_hub", "ctrlz_compiler", "ctrlz_worker", "ctrlz_admin", "ctrlz_keytool"}
}

const (
	superUser  = "postgres"
	templateDB = "ctrlz_template"
)

// Cluster is one running Postgres with the roles created and a migrated
// template database to clone test databases from.
type Cluster struct {
	container *postgres.PostgresContainer
	host      string
	port      uint16
	superPW   string
	passwords map[string]string
	seq       atomic.Int64
}

// RunMain is a TestMain body. It starts the cluster unless -short is set,
// hands it to use, runs the tests and tears the container down. A missing
// Docker is a failure, not a skip: a silent skip would let isolation tests
// report green without running.
func RunMain(m *testing.M, use func(*Cluster)) int {
	flag.Parse() // testing.Short needs the flags parsed
	if testing.Short() {
		return m.Run()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	c, err := Start(ctx)
	cancel()
	if err != nil {
		fmt.Fprintf(os.Stderr, "testpg: cannot start Postgres (Docker is required; use -short to skip): %v\n", err)
		return 1
	}
	use(c)
	code := m.Run()
	_ = c.Terminate(context.Background())
	return code
}

// Need returns t's cluster or skips under -short.
func Need(t testing.TB, c *Cluster) *Cluster {
	t.Helper()
	if c == nil {
		if testing.Short() {
			t.Skip("-short: container tests skipped")
		}
		t.Fatal("no Postgres cluster; TestMain did not start one")
	}
	return c
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // the system RNG failing is not recoverable
	}
	return hex.EncodeToString(b)
}

// startAttempts is how many times Start picks a new port when Docker finds the
// one it was given taken. See PortTaken.
const startAttempts = 5

// PortTaken reports whether err is Docker failing to publish the host port
// freePort chose. The port is free when freePort looks and can be taken before
// Docker binds it: by another package of the same `go test -p`, by another
// agent's container, or on Windows by an outgoing connection, which draws from
// the same dynamic range. The window cannot be closed from here (Docker does
// the bind), so the start is repeated with a new port. Without it the full CI
// run failed one package in three on a busy machine, and a failure that says
// nothing about the code under test teaches nobody anything.
func PortTaken(err error) bool {
	if err == nil {
		return false
	}
	m := err.Error()
	return strings.Contains(m, "address already in use") || strings.Contains(m, "port is already allocated")
}

// Start runs the container, bootstraps roles, creates the template database
// and migrates it. A host port that is taken between the choice and the bind
// is retried with another one.
func Start(ctx context.Context) (*Cluster, error) { return StartWithArgs(ctx) }

// StartWithArgs is Start with more server settings ("-c", "name=value", ...), for a test that needs a
// cluster of its own: a server setting that only a restart changes (max_notify_queue_pages) cannot be
// turned on in the shared cluster the other tests of the package are using.
func StartWithArgs(ctx context.Context, extra ...string) (*Cluster, error) {
	var err error
	for attempt := 0; attempt < startAttempts; attempt++ {
		var c *Cluster
		if c, err = start(ctx, extra); err == nil || !PortTaken(err) {
			return c, err
		}
	}
	return nil, err
}

func start(ctx context.Context, extra []string) (*Cluster, error) {
	// There is no override here: CTRLZ_TEST_PG_IMAGE took any reference (admin-r16-19), so a run could judge
	// bytes nobody reviewed. A developer who wants another build sets POSTGRES_IMAGE, which deploy.Image
	// accepts only pinned by digest.
	image := DefaultImage()
	c := &Cluster{superPW: randHex(16), passwords: map[string]string{}}
	for _, r := range loginRoles() {
		c.passwords[r] = randHex(16)
	}
	// A fixed host port, so that the server can be stopped and started again
	// (the fault tests do) and every Store opened earlier finds it where it was.
	// With a random mapping Docker would give a restarted container a new port.
	hostPort, err := freePort()
	if err != nil {
		return nil, err
	}
	ctr, err := postgres.Run(ctx, image,
		postgres.WithDatabase("postgres"),
		postgres.WithUsername(superUser),
		postgres.WithPassword(c.superPW),
		// fsync off: the data is thrown away, and tests run faster.
		// The logging settings of deploy/compose/postgres/postgresql.conf, so the
		// canary test of spec 18.4 reads the server log a deployment would write.
		testcontainers.WithCmdArgs(append([]string{"-c", "fsync=off", "-c", "max_connections=200",
			"-c", "log_statement=none", "-c", "log_min_error_statement=panic", "-c", "log_error_verbosity=terse",
			"-c", "log_min_duration_statement=-1"}, extra...)...),
		testcontainers.WithHostConfigModifier(func(hc *container.HostConfig) {
			hc.PortBindings = network.PortMap{network.MustParsePort("5432/tcp"): {{HostPort: strconv.Itoa(hostPort)}}}
		}),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").WithOccurrence(2).WithStartupTimeout(90*time.Second),
		),
	)
	if err != nil {
		if ctr != nil {
			// Docker creates the container before it binds the port; a retry
			// would otherwise leave one behind per attempt.
			_ = ctr.Terminate(ctx)
		}
		return nil, fmt.Errorf("start container: %w", err)
	}
	c.container = ctr
	host, err := ctr.Host(ctx)
	if err != nil {
		_ = ctr.Terminate(ctx)
		return nil, err
	}
	// "localhost" is resolved on every new connection, and the Windows resolver
	// timed out doing it while the whole suite was running (A7). The published
	// port listens on every interface, so the address does the same job.
	if host == "localhost" {
		host = "127.0.0.1"
	}
	port, err := ctr.MappedPort(ctx, "5432/tcp")
	if err != nil {
		_ = ctr.Terminate(ctx)
		return nil, err
	}
	c.host, c.port = host, port.Num()

	if err := c.bootstrap(ctx); err != nil {
		_ = ctr.Terminate(ctx)
		return nil, fmt.Errorf("bootstrap: %w", err)
	}
	return c, nil
}

// freePort asks the OS for a TCP port nobody listens on.
func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// StopPostgres stops the server the way `docker stop` does: SIGTERM, then a
// fast shutdown. The data stays in the container, so StartPostgres brings the
// same databases back on the same address. For the fault tests: a pool open
// across the stop must recover on its own.
func (c *Cluster) StopPostgres(ctx context.Context) error {
	timeout := 30 * time.Second
	return c.container.Stop(ctx, &timeout)
}

// StartPostgres starts a stopped server and returns when it accepts
// connections.
func (c *Cluster) StartPostgres(ctx context.Context) error {
	if err := c.container.Start(ctx); err != nil {
		return err
	}
	deadline := time.Now().Add(60 * time.Second)
	for {
		conn, err := c.superConn(ctx, "postgres")
		if err == nil {
			conn.Close(ctx)
			return nil
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return fmt.Errorf("postgres did not come back: %w", err)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// Logs returns everything the server has written to its log since the cluster
// started, for the canary test (spec 18.4): no secret may be in it. The text is
// returned to the test and is never printed by it.
func (c *Cluster) Logs(ctx context.Context) (string, error) {
	rd, err := c.container.Logs(ctx)
	if err != nil {
		return "", err
	}
	defer rd.Close()
	b, err := io.ReadAll(rd)
	return string(b), err
}

// Terminate stops and removes the container.
func (c *Cluster) Terminate(ctx context.Context) error {
	if c.container == nil {
		return nil
	}
	return c.container.Terminate(ctx)
}

// Version returns the server version string, for the test log.
func (c *Cluster) Version(ctx context.Context) (string, error) {
	conn, err := c.superConn(ctx, "postgres")
	if err != nil {
		return "", err
	}
	defer conn.Close(ctx)
	var v string
	err = conn.QueryRow(ctx, "SHOW server_version").Scan(&v)
	return v, err
}

func (c *Cluster) superConn(ctx context.Context, db string) (*pgx.Conn, error) {
	cc, err := pgx.ParseConfig(fmt.Sprintf("host=%s port=%d dbname=%s user=%s sslmode=disable", c.host, c.port, db, superUser))
	if err != nil {
		return nil, err
	}
	cc.Password = c.superPW
	return pgx.ConnectConfig(ctx, cc)
}

// psqlVars returns the variables the bootstrap files expect.
func (c *Cluster) psqlVars(db string) map[string]string {
	return map[string]string{
		"db_name":           db,
		"pw_migrator":       c.passwords["ctrlz_migrator"],
		"pw_tenant":         c.passwords["ctrlz_tenant"],
		"pw_hub":            c.passwords["ctrlz_hub"],
		"pw_compiler":       c.passwords["ctrlz_compiler"],
		"pw_worker":         c.passwords["ctrlz_worker"],
		"pw_admin":          c.passwords["ctrlz_admin"],
		"pw_keytool":        c.passwords["ctrlz_keytool"],
		"conn_migrator":     "20",
		"conn_tenant":       "60",
		"conn_hub":          "20",
		"conn_compiler":     "20",
		"conn_worker":       "20",
		"conn_admin":        "20",
		"conn_keytool":      "20",
		"statement_timeout": "60s",
		"lock_timeout":      "10s",
		"idle_tx_timeout":   "120s",
		"tx_timeout":        "120s",
	}
}

var (
	reQuoted = regexp.MustCompile(`:'([a-z_][a-z0-9_]*)'`)
	reIdent  = regexp.MustCompile(`:"([a-z_][a-z0-9_]*)"`)
	reRaw    = regexp.MustCompile(`(^|[^:A-Za-z0-9_'"])` + `:([a-z_][a-z0-9_]*)`)
)

// ExpandPSQLVars substitutes the three psql variable forms (:'x' as a quoted
// literal, :"x" as a quoted identifier, :x as raw text) the way psql -v does,
// so the very same bootstrap files run from the installer and from the tests.
// An unknown name is an error.
func ExpandPSQLVars(sqlText string, vars map[string]string) (string, error) {
	var missing []string
	look := func(name string) (string, bool) {
		v, ok := vars[name]
		if !ok {
			missing = append(missing, name)
		}
		return v, ok
	}
	out := reQuoted.ReplaceAllStringFunc(sqlText, func(m string) string {
		v, _ := look(reQuoted.FindStringSubmatch(m)[1])
		return "'" + strings.ReplaceAll(v, "'", "''") + "'"
	})
	out = reIdent.ReplaceAllStringFunc(out, func(m string) string {
		v, _ := look(reIdent.FindStringSubmatch(m)[1])
		return `"` + strings.ReplaceAll(v, `"`, `""`) + `"`
	})
	// Comments mention variable names in prose; only expand outside comments.
	var lines []string
	for _, ln := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(ln), "--") {
			lines = append(lines, ln)
			continue
		}
		ln = reRaw.ReplaceAllStringFunc(ln, func(m string) string {
			sub := reRaw.FindStringSubmatch(m)
			v, _ := look(sub[2])
			return sub[1] + v
		})
		lines = append(lines, ln)
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return "", fmt.Errorf("unknown bootstrap variables: %s", strings.Join(missing, ", "))
	}
	return strings.Join(lines, "\n"), nil
}

func (c *Cluster) runBootstrapFile(ctx context.Context, conn *pgx.Conn, file, db string) error {
	b, err := fs.ReadFile(pgmigrations.Bootstrap, "bootstrap/"+file)
	if err != nil {
		return err
	}
	text, err := ExpandPSQLVars(string(b), c.psqlVars(db))
	if err != nil {
		return fmt.Errorf("%s: %w", file, err)
	}
	// One statement at a time: CREATE DATABASE cannot run in the implicit
	// transaction that a multi-statement simple query would open. The
	// splitStatements keeps a dollar-quoted DO block whole.
	for _, stmt := range splitStatements(text) {
		if _, err := conn.Exec(ctx, stmt); err != nil {
			return fmt.Errorf("%s: %w", file, err)
		}
	}
	return nil
}

func (c *Cluster) bootstrap(ctx context.Context) error {
	conn, err := c.superConn(ctx, "postgres")
	if err != nil {
		return err
	}
	// 10-cluster.sql creates the roles and the first database.
	if err := c.runBootstrapFile(ctx, conn, "10-cluster.sql", templateDB); err != nil {
		conn.Close(ctx)
		return err
	}
	// 15-role-bounds.sql sets the connection limits and the role defaults. It is a file of its own so
	// that an installed database can run it again (db-r16-5).
	if err := c.runBootstrapFile(ctx, conn, "15-role-bounds.sql", templateDB); err != nil {
		conn.Close(ctx)
		return err
	}
	conn.Close(ctx)

	conn, err = c.superConn(ctx, templateDB)
	if err != nil {
		return err
	}
	if err := c.runBootstrapFile(ctx, conn, "20-database.sql", templateDB); err != nil {
		conn.Close(ctx)
		return err
	}
	conn.Close(ctx)

	if err := c.migrateDB(ctx, templateDB); err != nil {
		return err
	}
	return nil
}

func (c *Cluster) migrateDB(ctx context.Context, db string) error {
	sdb, err := migrate.Open(migrate.Config{
		Host: c.host, Port: c.port, Database: db,
		User: "ctrlz_migrator", Password: c.passwords["ctrlz_migrator"],
	})
	if err != nil {
		return err
	}
	defer sdb.Close()
	_, err = migrate.Up(ctx, sdb)
	return err
}

// MigratorDB opens the migrator's *sql.DB for a database, for tests of the
// migration runner itself.
func (c *Cluster) MigratorDB(db string) (*sql.DB, error) {
	return migrate.Open(migrate.Config{
		Host: c.host, Port: c.port, Database: db,
		User: "ctrlz_migrator", Password: c.passwords["ctrlz_migrator"],
	})
}

// DB is one database cloned from the migrated template.
type DB struct {
	c    *Cluster
	Name string
}

// NewDB clones the template into a fresh database and drops it when the test
// ends. The clone does not carry the database ACL, so the per-database
// bootstrap step runs again, exactly as the installer runs it.
func (c *Cluster) NewDB(ctx context.Context, t testing.TB) *DB {
	t.Helper()
	name := fmt.Sprintf("ctrlz_t%d_%s", c.seq.Add(1), randHex(3))
	conn, err := c.superConn(ctx, "postgres")
	if err != nil {
		t.Fatalf("testpg: connect: %v", err)
	}
	defer conn.Close(ctx)
	if _, err := conn.Exec(ctx, fmt.Sprintf(`CREATE DATABASE %s TEMPLATE %s OWNER ctrlz_migrator`, pgx.Identifier{name}.Sanitize(), templateDB)); err != nil {
		t.Fatalf("testpg: clone template: %v", err)
	}
	d := &DB{c: c, Name: name}
	t.Cleanup(func() {
		cctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		cn, err := c.superConn(cctx, "postgres")
		if err != nil {
			return
		}
		defer cn.Close(cctx)
		_, _ = cn.Exec(cctx, fmt.Sprintf(`DROP DATABASE IF EXISTS %s WITH (FORCE)`, pgx.Identifier{name}.Sanitize()))
	})
	sc, err := c.superConn(ctx, name)
	if err != nil {
		t.Fatalf("testpg: connect clone: %v", err)
	}
	defer sc.Close(ctx)
	if err := c.runBootstrapFile(ctx, sc, "20-database.sql", name); err != nil {
		t.Fatalf("testpg: bootstrap clone: %v", err)
	}
	return d
}

// NewEmptyDB creates a database with the bootstrap applied but no migrations,
// for tests of the migration runner.
func (c *Cluster) NewEmptyDB(ctx context.Context, t testing.TB) *DB {
	t.Helper()
	name := fmt.Sprintf("ctrlz_e%d_%s", c.seq.Add(1), randHex(3))
	conn, err := c.superConn(ctx, "postgres")
	if err != nil {
		t.Fatalf("testpg: connect: %v", err)
	}
	defer conn.Close(ctx)
	if _, err := conn.Exec(ctx, fmt.Sprintf(`CREATE DATABASE %s OWNER ctrlz_migrator`, pgx.Identifier{name}.Sanitize())); err != nil {
		t.Fatalf("testpg: create db: %v", err)
	}
	t.Cleanup(func() {
		cctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		cn, err := c.superConn(cctx, "postgres")
		if err != nil {
			return
		}
		defer cn.Close(cctx)
		_, _ = cn.Exec(cctx, fmt.Sprintf(`DROP DATABASE IF EXISTS %s WITH (FORCE)`, pgx.Identifier{name}.Sanitize()))
	})
	sc, err := c.superConn(ctx, name)
	if err != nil {
		t.Fatalf("testpg: connect: %v", err)
	}
	defer sc.Close(ctx)
	if err := c.runBootstrapFile(ctx, sc, "20-database.sql", name); err != nil {
		t.Fatalf("testpg: bootstrap: %v", err)
	}
	return &DB{c: c, Name: name}
}

// Super connects as the superuser. Only seeding and catalog mutation use it.
func (d *DB) Super(ctx context.Context) (*pgx.Conn, error) { return d.c.superConn(ctx, d.Name) }

// Conn connects as one of the ctrlz login roles. The session starts with a
// search_path of pg_catalog only, so deparsed expressions in pg_policies show
// schema-qualified names and compare equal to the fixture text.
func (d *DB) Conn(ctx context.Context, role string) (*pgx.Conn, error) {
	pw, ok := d.c.passwords[role]
	if !ok {
		return nil, errors.New("testpg: unknown role " + role)
	}
	cc, err := pgx.ParseConfig(fmt.Sprintf("host=%s port=%d dbname=%s user=%s sslmode=disable", d.c.host, d.c.port, d.Name, role))
	if err != nil {
		return nil, err
	}
	cc.Password = pw
	return pgx.ConnectConfig(ctx, cc)
}

// StoreConfig returns a store.Config for the database and role.
func (d *DB) StoreConfig(role store.Role) store.Config {
	return store.Config{
		Host: d.c.host, Port: d.c.port, Database: d.Name, Role: role,
		Password: secret.New(d.c.passwords[string(role)]),
		MaxConns: 4,
	}
}

// Store opens a store as a service role.
func (d *DB) Store(ctx context.Context, t testing.TB, role store.Role) *store.Store {
	t.Helper()
	s, err := store.Open(ctx, d.StoreConfig(role))
	if err != nil {
		t.Fatalf("testpg: open store as %s: %v", role, err)
	}
	t.Cleanup(s.Close)
	return s
}

// RunBootstrapFile runs one superuser bootstrap file again for this database, the way the installer
// does: 10-cluster.sql and 15-role-bounds.sql connected to the postgres database, 20-database.sql to
// this one. For the tests of the standing questions (migrate.CheckReach), which break a bootstrapped
// database and then repair it with the file the error names.
func (d *DB) RunBootstrapFile(ctx context.Context, file string) error {
	db := d.Name
	if file != "20-database.sql" {
		db = "postgres"
	}
	conn, err := d.c.superConn(ctx, db)
	if err != nil {
		return err
	}
	defer conn.Close(ctx)
	return d.c.runBootstrapFile(ctx, conn, file, d.Name)
}

// MigratorDB opens the migrator's *sql.DB for this database.
func (d *DB) MigratorDB() (*sql.DB, error) { return d.c.MigratorDB(d.Name) }

// splitStatements drops comment lines and splits on semicolons that are not inside a
// dollar-quoted body ($tag$ ... $tag$), so a DO block of a bootstrap file (the pg_catalog
// reach of 20-database.sql, db-r14-3) runs as one statement, as psql runs it.
func splitStatements(text string) []string {
	var kept []string
	for _, ln := range strings.Split(text, "\n") {
		if strings.HasPrefix(strings.TrimSpace(ln), "--") {
			continue
		}
		kept = append(kept, ln)
	}
	src := strings.Join(kept, "\n")
	var out []string
	start, tag := 0, ""
	for i := 0; i < len(src); i++ {
		switch {
		case tag != "":
			if strings.HasPrefix(src[i:], tag) {
				i += len(tag) - 1
				tag = ""
			}
		case src[i] == '$':
			if m := dollarTag.FindString(src[i:]); m != "" {
				tag = m
				i += len(m) - 1
			}
		case src[i] == ';':
			if s := strings.TrimSpace(src[start:i]); s != "" {
				out = append(out, s)
			}
			start = i + 1
		}
	}
	if s := strings.TrimSpace(src[start:]); s != "" {
		out = append(out, s)
	}
	return out
}

// dollarTag matches the opening of a dollar-quoted string: $$ or $name$.
var dollarTag = regexp.MustCompile(`^\$([A-Za-z_][A-Za-z0-9_]*)?\$`)

// Addr returns the host and port of the database server.
func (d *DB) Addr() (string, uint16) { return d.c.host, d.c.port }

// Password returns the password of one of the login roles, for tests that
// pass it to a service the way Docker secrets do, through a file.
func (d *DB) Password(role string) secret.String { return secret.New(d.c.passwords[role]) }

// Exec runs one statement as the superuser on a connection of its own. It is
// for test setup that no service role may do (planting a row, ageing a
// timestamp), and it keeps pgx out of the packages that are not allowed to
// import it.
func (d *DB) Exec(ctx context.Context, sql string, args ...any) error {
	c, err := d.Super(ctx)
	if err != nil {
		return err
	}
	defer c.Close(ctx)
	_, err = c.Exec(ctx, sql, args...)
	return err
}

// Scan runs a query that returns one row as the superuser and scans it into
// dest. It is how a test reads back a column that no service role may read.
func (d *DB) Scan(ctx context.Context, sql string, args []any, dest ...any) error {
	c, err := d.Super(ctx)
	if err != nil {
		return err
	}
	defer c.Close(ctx)
	return c.QueryRow(ctx, sql, args...).Scan(dest...)
}

// ServerLog is the Postgres server log of the whole cluster (see Cluster.Logs).
func (d *DB) ServerLog(ctx context.Context) (string, error) { return d.c.Logs(ctx) }

// OTPExpiredUnsentSet is the SET clause of an UPDATE on ctrlz.otp_challenges that makes
// a row look as if it ran out while no worker was up: created_at about six minutes back,
// expires_at already past.
//
// The row must stay on the Tehran day it was issued. A refund goes to the counters of
// the day of created_at (the day the keys were charged), so a test that moved created_at
// across Tehran midnight sent the refund to yesterday's counters and failed, only in the
// six minutes after midnight there (round 5: TestFastRefundsOTPsThatExpiredUnsent, run at
// 00:00:49 Tehran). created_at is therefore clamped to the start of the current day, and
// expires_at is put just after it, so the row is expired whatever the time of day. Use it
// in place of "created_at = now() - interval ..." on this table.
const OTPExpiredUnsentSet = `created_at = GREATEST(now() - interval '6 minutes', date_trunc('day', now() AT TIME ZONE 'Asia/Tehran') AT TIME ZONE 'Asia/Tehran'),
  expires_at = GREATEST(now() - interval '6 minutes', date_trunc('day', now() AT TIME ZONE 'Asia/Tehran') AT TIME ZONE 'Asia/Tehran') + interval '1 millisecond'`

// PlantCounters wraps a seed of sms_counters that the guard would refuse as a NEW row (a day that
// is not today, a count above one) so that the triggers do not fire for it: the guard of
// migration 0040 holds a new row to "today, at most one, no negative spend" for every writer,
// the superuser included, and a test that needs an old day or a counter that is already high
// has to write it the way a restored backup would. SET LOCAL lasts to the end of the one
// implicit transaction of a multi-statement simple query, which is also why the wrapped text
// must be sent with no arguments, and why it is never put inside a transaction a test goes on
// using (the triggers would stay off for the code under test). CHECK constraints still apply.
func PlantCounters(sql string) string {
	return "SET LOCAL session_replication_role = replica; " + strings.TrimRight(strings.TrimSpace(sql), "; ") +
		"; SET LOCAL session_replication_role = origin"
}
