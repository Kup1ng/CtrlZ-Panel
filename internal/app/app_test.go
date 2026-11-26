package app_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/app"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testwait"
)

var cluster *testpg.Cluster

// spoolDir is the spool directory every api the tests start uses: CTRLZ_SPOOL_DIR is required outside the test environment
// and a test that runs the api as production needs one.
var spoolDir string

func TestMain(m *testing.M) {
	var err error
	if spoolDir, err = os.MkdirTemp("", "ctrlz-app-spool-"); err != nil {
		panic(err)
	}
	code := testpg.RunMain(m, func(c *testpg.Cluster) { cluster = c })
	_ = os.RemoveAll(spoolDir)
	os.Exit(code)
}

// env serves a variable map as the process environment. CTRLZ_ENV defaults to
// test here, because production (the real default) refuses to start without key
// files; the tests of that refusal set CTRLZ_ENV themselves.
func env(m map[string]string) app.Getenv {
	return func(k string) string {
		if v, ok := m[k]; ok {
			return v
		}
		switch k {
		case "CTRLZ_ENV":
			return "test"
		case "CTRLZ_SPOOL_DIR":
			return spoolDir
		}
		return ""
	}
}

// syncBuffer lets the test read what the server logged while it runs.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// start runs a role and returns its address, a stop function that waits for
// the role to return, and its log.
func start(t *testing.T, role app.Role, vars map[string]string) (addr string, stop func() error, log *syncBuffer) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan string, 1)
	done := make(chan error, 1)
	log = &syncBuffer{}
	if _, ok := vars["CTRLZ_LISTEN"]; !ok {
		vars["CTRLZ_LISTEN"] = "127.0.0.1:0"
	}
	go func() { done <- app.Run(ctx, role, app.Options{Getenv: env(vars), Stdout: log, Ready: ready}) }()
	var startErr error
	exited := false
	if !testwait.Holds(30*time.Second, 20*time.Millisecond, func() bool {
		select {
		case addr = <-ready:
			return true
		case startErr = <-done:
			exited = true
			return true
		default:
			return false
		}
	}) {
		cancel()
		t.Fatalf("%s did not start in time", role)
	}
	if exited {
		cancel()
		t.Fatalf("%s did not start: %v", role, startErr)
	}
	var once sync.Once
	var result error
	stop = func() error {
		once.Do(func() {
			cancel()
			var stopped bool
			if result, stopped = testwait.TryReceive(done, 20*time.Second); !stopped {
				t.Errorf("%s did not stop", role)
			}
		})
		return result
	}
	t.Cleanup(func() { _ = stop() })
	return addr, stop, log
}

func get(t *testing.T, url string) (int, string) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// TestStubRolesStartAndStop covers the four long-running roles with no
// database: they start, report healthy and not ready, and stop on cancel.
func TestStubRolesStartAndStop(t *testing.T) {
	for _, role := range []app.Role{app.RoleAPI, app.RoleAdmin, app.RoleWorker, app.RoleHub} {
		t.Run(string(role), func(t *testing.T) {
			addr, stop, log := start(t, role, map[string]string{})
			code, body := get(t, "http://"+addr+"/healthz")
			if code != 200 || !strings.Contains(body, `"role":"`+string(role)+`"`) {
				t.Errorf("/healthz: %d %q", code, body)
			}
			if code, _ := get(t, "http://"+addr+"/readyz"); code != 503 {
				t.Errorf("/readyz without a database: %d, want 503", code)
			}
			if code, _ := get(t, "http://"+addr+"/anything?token=SECRET-IN-URL"); code != 404 {
				t.Errorf("unknown path: %d", code)
			}
			if err := stop(); err != nil {
				t.Errorf("stop: %v", err)
			}
			out := log.String()
			if !strings.Contains(out, `"msg":"started"`) || !strings.Contains(out, `"msg":"stopped"`) {
				t.Errorf("log lacks start and stop lines: %s", out)
			}
			// No access log: a URL can carry a token (R21).
			if strings.Contains(out, "SECRET-IN-URL") || strings.Contains(out, "/anything") {
				t.Errorf("the request URL reached the log: %s", out)
			}
		})
	}
}

func TestConfigErrors(t *testing.T) {
	for name, c := range map[string]struct {
		role app.Role
		vars map[string]string
		want string
	}{
		"db host without a password": {app.RoleAPI, map[string]string{"CTRLZ_DB_HOST": "db"}, "CTRLZ_DB_PASSWORD_FILE"},
		"bad port":                   {app.RoleAPI, map[string]string{"CTRLZ_DB_PORT": "http"}, "CTRLZ_DB_PORT"},
		"bad pool size":              {app.RoleAPI, map[string]string{"CTRLZ_DB_MAX_CONNS": "0"}, "CTRLZ_DB_MAX_CONNS"},
		"migrate without a host":     {app.RoleMigrate, map[string]string{}, "CTRLZ_DB_HOST"},
		"compiler password on api":   {app.RoleAPI, map[string]string{"CTRLZ_DB_COMPILER_PASSWORD_FILE": "/x"}, "worker only"},
		"artifacts dir on the hub":   {app.RoleHub, map[string]string{"CTRLZ_ARTIFACTS_DIR": "/x"}, "worker only"},
		"proof key on api":           {app.RoleAPI, map[string]string{"CTRLZ_PROOF_KEY_FILE": "/x"}, "hub only"},
		"proof key on admin":         {app.RoleAdmin, map[string]string{"CTRLZ_PROOF_KEY_FILE": "/x"}, "hub only"},
		"proof key on worker":        {app.RoleWorker, map[string]string{"CTRLZ_PROOF_KEY_FILE": "/x"}, "hub only"},
		"proof key file missing":     {app.RoleHub, map[string]string{"CTRLZ_PROOF_KEY_FILE": "/no/such/proof"}, "/no/such/proof"},
		"missing secret file":        {app.RoleAPI, map[string]string{"CTRLZ_DB_PASSWORD_FILE": "/no/such/file"}, "/no/such/file"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := app.LoadConfig(c.role, env(c.vars))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("got %v, want an error mentioning %q", err, c.want)
			}
		})
	}
	if _, err := app.ParseRole("root"); err == nil {
		t.Error("an unknown role was accepted")
	}
	for _, r := range app.Roles() {
		if got, err := app.ParseRole(string(r)); err != nil || got != r {
			t.Errorf("role %s: %v", r, err)
		}
	}
}

func writeSecret(t *testing.T, name, value string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(value+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func dbEnv(t *testing.T, d *testpg.DB, dbRole string) map[string]string {
	host, port := d.Addr()
	return map[string]string{
		"CTRLZ_DB_HOST":          host,
		"CTRLZ_DB_PORT":          strconv.Itoa(int(port)),
		"CTRLZ_DB_NAME":          d.Name,
		"CTRLZ_DB_PASSWORD_FILE": writeSecret(t, "pw", d.Password(dbRole).Reveal()),
	}
}

// TestRolesAgainstARealDatabase starts each service role with its own
// credentials. Each one logs in as its own database role, which the startup
// assertion checks, and reports ready.
func TestRolesAgainstARealDatabase(t *testing.T) {
	c := testpg.Need(t, cluster)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	d := c.NewDB(ctx, t)
	for role, dbRole := range map[app.Role]string{
		app.RoleAPI: "ctrlz_tenant", app.RoleAdmin: "ctrlz_admin", app.RoleHub: "ctrlz_hub", app.RoleWorker: "ctrlz_worker",
	} {
		t.Run(string(role), func(t *testing.T) {
			vars := dbEnv(t, d, dbRole)
			if role == app.RoleWorker {
				// The compiler job runs on its own pool and credentials.
				vars["CTRLZ_DB_COMPILER_PASSWORD_FILE"] = writeSecret(t, "cpw", d.Password("ctrlz_compiler").Reveal())
				vars["CTRLZ_ARTIFACTS_DIR"] = t.TempDir() // the compiler needs both, or the worker does not start
			}
			addr, stop, log := start(t, role, vars)
			if code, body := get(t, "http://"+addr+"/readyz"); code != 200 {
				t.Errorf("/readyz: %d %q", code, body)
			}
			_ = stop()
			out := log.String()
			if !strings.Contains(out, `"db_role":"`+dbRole+`"`) {
				t.Errorf("log does not name the database role: %s", out)
			}
			if role == app.RoleWorker && !strings.Contains(out, "ctrlz_compiler") {
				t.Errorf("the worker did not open the compiler pool: %s", out)
			}
			if strings.Contains(out, d.Password(dbRole).Reveal()) {
				t.Errorf("the database password reached the log")
			}
		})
	}
}

// TestWrongPasswordRefusesToStart: the process exits with an error that does
// not repeat the password.
func TestWrongPasswordRefusesToStart(t *testing.T) {
	c := testpg.Need(t, cluster)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	d := c.NewDB(ctx, t)
	vars := dbEnv(t, d, "ctrlz_tenant")
	bad := "not-the-password-5d1c"
	vars["CTRLZ_DB_PASSWORD_FILE"] = writeSecret(t, "bad", bad)
	vars["CTRLZ_LISTEN"] = "127.0.0.1:0"
	var log syncBuffer
	err := app.Run(ctx, app.RoleAPI, app.Options{Getenv: env(vars), Stdout: &log})
	if err == nil {
		t.Fatal("started with a wrong password")
	}
	if strings.Contains(err.Error(), bad) || strings.Contains(log.String(), bad) {
		t.Errorf("the password was repeated: %v / %s", err, log.String())
	}
}

// TestMigrateRole runs `ctrlz migrate` against an empty database.
func TestMigrateRole(t *testing.T) {
	c := testpg.Need(t, cluster)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	d := c.NewEmptyDB(ctx, t)
	vars := dbEnv(t, d, "ctrlz_migrator")
	var log syncBuffer
	if err := app.Run(ctx, app.RoleMigrate, app.Options{Getenv: env(vars), Stdout: &log}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if !strings.Contains(log.String(), `"msg":"migrations applied"`) {
		t.Errorf("log: %s", log.String())
	}
	// A second run changes nothing.
	log = syncBuffer{}
	if err := app.Run(ctx, app.RoleMigrate, app.Options{Getenv: env(vars), Stdout: &log}); err != nil || !strings.Contains(log.String(), `"count":0`) {
		t.Errorf("second migrate: %v %s", err, log.String())
	}
	// The migrator is the wrong login for a service.
	vars = dbEnv(t, d, "ctrlz_tenant")
	if err := app.Run(ctx, app.RoleMigrate, app.Options{Getenv: env(vars), Stdout: io.Discard}); err == nil {
		t.Error("migrate ran with the tenant password")
	}
}

func TestHealthCheck(t *testing.T) {
	addr, _, _ := start(t, app.RoleAPI, map[string]string{})
	ctx := context.Background()
	if err := app.HealthCheck(ctx, "http://"+addr+"/healthz"); err != nil {
		t.Errorf("healthy server: %v", err)
	}
	if err := app.HealthCheck(ctx, "http://"+addr+"/readyz"); err == nil {
		t.Error("a 503 must fail the health check")
	}
	if err := app.HealthCheck(ctx, "http://127.0.0.1:1/healthz"); err == nil {
		t.Error("a closed port must fail the health check")
	}
}

// TestProofKeyIsHubOnlyAndNeverPrinted: the hub reads the proof_key secret from
// a file; no other role accepts the variable; the value does not print.
func TestProofKeyIsHubOnlyAndNeverPrinted(t *testing.T) {
	const key = "proof-key-canary-9f3a"
	file := writeSecret(t, "proof_key", key)
	c, err := app.LoadConfig(app.RoleHub, env(map[string]string{"CTRLZ_PROOF_KEY_FILE": file}))
	if err != nil {
		t.Fatal(err)
	}
	if c.ProofKey.IsZero() || c.ProofKey.Reveal() != key {
		t.Fatal("the hub did not load the proof key")
	}
	for _, shown := range []string{fmt.Sprintf("%v", c), fmt.Sprintf("%+v", c), fmt.Sprintf("%#v", c), fmt.Sprint(c.ProofKey)} {
		if strings.Contains(shown, key) {
			t.Errorf("the proof key was printed: %s", shown)
		}
	}
	for _, role := range []app.Role{app.RoleAPI, app.RoleAdmin, app.RoleWorker} {
		if _, err := app.LoadConfig(role, env(map[string]string{"CTRLZ_PROOF_KEY_FILE": file})); err == nil {
			t.Errorf("%s accepted the proof key", role)
		}
	}
}

// TestAHealthOnlyRoleRefusesAnAddressOthersCanReach is admin-r10-4. The hub and the worker serve only the
// health mux in P1; its /readyz takes a pooled database connection and /healthz names the role and the
// release, with no authentication. Compose published the hub's port to the internet, so any scanner could
// fingerprint the deployment and spend the hub's four connections. The role now refuses to start on an
// address that is not loopback, whatever the Compose file says, and the defaults are loopback.
func TestAHealthOnlyRoleRefusesAnAddressOthersCanReach(t *testing.T) {
	// Port 0 and a short context: a check that lets the address through must fail the test (the role
	// starts, then stops with the context), not hang it or collide with a port of the host.
	refused := []string{":0", "0.0.0.0:0", "[::]:0", "10.1.2.3:0", "example.test:0"}
	for _, role := range []app.Role{app.RoleHub, app.RoleWorker} {
		for _, listen := range refused {
			t.Run(string(role)+"/"+listen, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				err := app.Run(ctx, role, app.Options{Getenv: env(map[string]string{"CTRLZ_LISTEN": listen}), Stdout: &syncBuffer{}})
				if err == nil || !strings.Contains(err.Error(), "loopback") {
					t.Fatalf("%s on %s started or failed for another reason: %v", role, listen, err)
				}
			})
		}
		// Loopback in each spelling starts (the control: the refusal above is the check, not a start failure).
		for _, listen := range []string{"127.0.0.1:0", "[::1]:0", "localhost:0"} {
			if listen == "[::1]:0" && !ipv6Loopback() {
				continue
			}
			t.Run(string(role)+"/"+listen, func(t *testing.T) {
				_, stop, _ := start(t, role, map[string]string{"CTRLZ_LISTEN": listen})
				if err := stop(); err != nil {
					t.Errorf("stop: %v", err)
				}
			})
		}
	}
	// A role that serves routes, with its database, may listen on every interface; the same role with
	// no database serves the health mux alone and may not.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err := app.Run(ctx, app.RoleAPI, app.Options{Getenv: env(map[string]string{"CTRLZ_LISTEN": ":0"}), Stdout: &syncBuffer{}})
	if err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Errorf("an api with no database on every interface: %v", err)
	}
	// The defaults of the two health-only roles are loopback.
	for _, role := range []app.Role{app.RoleHub, app.RoleWorker} {
		cfg, err := app.LoadConfig(role, env(nil))
		if err != nil || !strings.HasPrefix(cfg.Listen, "127.0.0.1:") {
			t.Errorf("%s default listen %q (%v), want loopback", role, cfg.Listen, err)
		}
	}
}

func ipv6Loopback() bool {
	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		return false
	}
	_ = ln.Close()
	return true
}

// TestRunMigrateAsksTheReachQuestion is db-r15-2 and db-r15-8 at the place that matters: the migrate
// container. The bootstrap that revokes the pg_catalog functions from PUBLIC runs once, on an empty
// data directory, so a database that was installed before 0047 (or restored, or moved to a newer
// Postgres) is migrated without error and stays open. `ctrlz migrate` now ends with the standing
// question, so the stack that waits for it does not start on an open database, and starts again once
// the bootstrap's revokes have been run.
func TestRunMigrateAsksTheReachQuestion(t *testing.T) {
	c := testpg.Need(t, cluster)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	d := c.NewEmptyDB(ctx, t)
	vars := dbEnv(t, d, "ctrlz_migrator")
	sup, err := d.Super(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer sup.Close(context.Background())
	if _, err := sup.Exec(ctx, "GRANT EXECUTE ON FUNCTION pg_catalog.pg_advisory_lock(bigint) TO PUBLIC"); err != nil {
		t.Fatal(err)
	}
	var log syncBuffer
	err = app.Run(ctx, app.RoleMigrate, app.Options{Getenv: env(vars), Stdout: &log})
	if err == nil || !strings.Contains(err.Error(), "bootstrap/20-database.sql") || !strings.Contains(err.Error(), "pg_advisory_lock") {
		t.Fatalf("migrate on a database open to PUBLIC: %v, want the reach error naming the bootstrap file", err)
	}
	if _, err := sup.Exec(ctx, "REVOKE EXECUTE ON FUNCTION pg_catalog.pg_advisory_lock(bigint) FROM PUBLIC"); err != nil {
		t.Fatal(err)
	}
	if err := app.Run(ctx, app.RoleMigrate, app.Options{Getenv: env(vars), Stdout: io.Discard}); err != nil {
		t.Errorf("migrate after the revoke: %v", err)
	}
}
