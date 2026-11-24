package lint_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/deploy"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testwait"
)

func readDeploy(t *testing.T, rel ...string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(append([]string{repoRoot(t), "deploy", "compose"}, rel...)...))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// confValue returns the last value of a key in a postgresql.conf, comments
// stripped and quotes removed.
func confValue(conf, key string) (string, bool) {
	val, found := "", false
	for _, ln := range strings.Split(conf, "\n") {
		if i := strings.Index(ln, "#"); i >= 0 {
			ln = ln[:i]
		}
		k, v, ok := strings.Cut(strings.TrimSpace(ln), "=")
		if ok && strings.TrimSpace(k) == key {
			val, found = strings.Trim(strings.TrimSpace(v), "'"), true
		}
	}
	return val, found
}

// TestPostgresDoesNotLogRows: log_statement = none keeps statements out of the
// log, but an ERROR line carries a DETAIL line with the failing row ("Failing
// row contains (...)", "Key (phone_e164)=(...) already exists"). Every global
// table has no row level security, which is what hides DETAIL on tenant
// tables, so a CHECK or unique violation on otp_challenges, admin_users or
// invites logged a phone, a code hash or a password hash (review F01). terse
// drops DETAIL, HINT, QUERY and CONTEXT.
func TestPostgresDoesNotLogRows(t *testing.T) {
	conf := readDeploy(t, "postgres", "postgresql.conf")
	for key, want := range map[string]string{
		"log_error_verbosity":               "terse",
		"log_statement":                     "none",
		"log_min_duration_statement":        "-1",
		"log_min_error_statement":           "panic",
		"log_connections":                   "off",
		"log_parameter_max_length":          "", // unset: the default of -1 logs no parameters with statements anyway
		"log_parameter_max_length_on_error": "",
	} {
		got, found := confValue(conf, key)
		if want == "" {
			if found && got != "0" {
				t.Errorf("%s = %q: bind values must not be logged", key, got)
			}
			continue
		}
		if !found || got != want {
			t.Errorf("postgresql.conf: %s = %q (set %v), want %q", key, got, found, want)
		}
	}
	// A -c on the command line overrides the file; none may weaken these.
	compose := readDeploy(t, "docker-compose.yml")
	for _, key := range []string{"log_error_verbosity", "log_statement", "log_min_error_statement", "log_parameter_max_length_on_error"} {
		if strings.Contains(compose, key) {
			t.Errorf("docker-compose.yml sets %s on the command line, which overrides postgresql.conf", key)
		}
	}
}

// TestMigratorLogsInOnlyFromTheMigrateContainer: ctrlz_migrator owns every
// table, can SET ROLE ctrlz_auth and can undo FORCE ROW LEVEL SECURITY, so its
// password is worth the whole database. pg_hba.conf lets it in from one
// address, the one the compose file gives the migrate container, and from no
// "samenet" line (review F09).
func TestMigratorLogsInOnlyFromTheMigrateContainer(t *testing.T) {
	hba := readDeploy(t, "postgres", "pg_hba.conf")
	var lines []string
	for _, ln := range strings.Split(hba, "\n") {
		if i := strings.Index(ln, "#"); i >= 0 {
			ln = ln[:i]
		}
		if strings.TrimSpace(ln) != "" {
			lines = append(lines, ln)
		}
	}
	var migratorLines []string
	for _, ln := range lines {
		f := strings.Fields(ln)
		if len(f) < 5 || f[0] != "host" {
			continue
		}
		for _, u := range strings.Split(f[2], ",") {
			if u == "ctrlz_migrator" || u == "all" && f[len(f)-1] != "reject" {
				migratorLines = append(migratorLines, ln)
			}
		}
	}
	if len(migratorLines) != 1 {
		t.Fatalf("%d pg_hba lines let ctrlz_migrator in, want exactly one: %q", len(migratorLines), migratorLines)
	}
	f := strings.Fields(migratorLines[0])
	addr, err := netip.ParsePrefix(f[3])
	if err != nil || addr.Bits() != 32 {
		t.Fatalf("the migrator's pg_hba address must be one host (a /32), got %q", f[3])
	}

	c := loadCompose(t)
	got := c.Services["migrate"].Networks.addr["backend"]
	if got != addr.Addr().String() {
		t.Errorf("migrate has address %q on backend, but pg_hba.conf allows %s", got, addr.Addr())
	}
	for name, s := range c.Services {
		if name != "migrate" && s.Networks.addr["backend"] == addr.Addr().String() {
			t.Errorf("%s has the migrator's address", name)
		}
	}
	// The address is in the subnet and outside the pool Docker hands out to
	// everyone else.
	n := c.Networks["backend"].IPAM.Config
	if len(n) != 1 {
		t.Fatalf("backend needs one ipam config, has %d", len(n))
	}
	subnet, err1 := netip.ParsePrefix(n[0].Subnet)
	pool, err2 := netip.ParsePrefix(n[0].IPRange)
	if err1 != nil || err2 != nil {
		t.Fatalf("backend subnet %q or ip_range %q: %v %v", n[0].Subnet, n[0].IPRange, err1, err2)
	}
	if !subnet.Contains(addr.Addr()) || pool.Contains(addr.Addr()) {
		t.Errorf("the migrator's %s must be inside %s and outside the dynamic pool %s", addr.Addr(), subnet, pool)
	}
	// Every other role stays on the same-network rule.
	if !strings.Contains(hba, "ctrlz_tenant,ctrlz_hub,ctrlz_compiler,ctrlz_worker,ctrlz_admin") {
		t.Error("pg_hba.conf lost the line for the service roles")
	}
}

// TestKeytoolLogsInOnlyFromTheRekeyContainer: ctrlz_keytool can rewrite and
// switch off users' second factor (the key tool, db-r4-3 and db-r4-6), so like the
// migrator it logs in from the one address the compose file gives the rekey
// container, and no "samenet" line names it.
func TestKeytoolLogsInOnlyFromTheRekeyContainer(t *testing.T) {
	hba := readDeploy(t, "postgres", "pg_hba.conf")
	var lines []string
	for _, ln := range strings.Split(hba, "\n") {
		if i := strings.Index(ln, "#"); i >= 0 {
			ln = ln[:i]
		}
		f := strings.Fields(ln)
		if len(f) < 5 || f[0] != "host" {
			continue
		}
		for _, u := range strings.Split(f[2], ",") {
			if u == "ctrlz_keytool" || u == "all" && f[len(f)-1] != "reject" {
				lines = append(lines, ln)
			}
		}
	}
	if len(lines) != 1 {
		t.Fatalf("%d pg_hba lines let ctrlz_keytool in, want exactly one: %q", len(lines), lines)
	}
	f := strings.Fields(lines[0])
	addr, err := netip.ParsePrefix(f[3])
	if err != nil || addr.Bits() != 32 {
		t.Fatalf("the key tool's pg_hba address must be one host (a /32), got %q", f[3])
	}
	c := loadCompose(t)
	if got := c.Services["rekey"].Networks.addr["backend"]; got != addr.Addr().String() {
		t.Errorf("rekey has address %q on backend, but pg_hba.conf allows %s", got, addr.Addr())
	}
	for name, s := range c.Services {
		if name != "rekey" && s.Networks.addr["backend"] == addr.Addr().String() {
			t.Errorf("%s has the key tool's address", name)
		}
	}
	n := c.Networks["backend"].IPAM.Config
	if len(n) != 1 {
		t.Fatalf("backend needs one ipam config, has %d", len(n))
	}
	subnet, err1 := netip.ParsePrefix(n[0].Subnet)
	pool, err2 := netip.ParsePrefix(n[0].IPRange)
	if err1 != nil || err2 != nil {
		t.Fatalf("backend subnet %q or ip_range %q: %v %v", n[0].Subnet, n[0].IPRange, err1, err2)
	}
	if !subnet.Contains(addr.Addr()) || pool.Contains(addr.Addr()) {
		t.Errorf("the key tool's %s must be inside %s and outside the dynamic pool %s", addr.Addr(), subnet, pool)
	}
}

// TestCaddyKeepsRequestsOutOfBothLogs (static): the access logger is filtered
// by the quiet_log snippet, and the separate http.log.error logger, which
// writes the whole URI and the client address when an upstream is down, is
// routed to a sink that deletes the same fields and is kept out of the default
// one (review F02).
func TestCaddyKeepsRequestsOutOfBothLogs(t *testing.T) {
	cf := readDeploy(t, "caddy", "Caddyfile")
	global := cf[:strings.Index(cf, "\n}\n")]
	for _, want := range []string{
		"log default {", "exclude http.log.error http.handlers.reverse_proxy http.log.access",
		"log errors {", "include http.log.error http.handlers.reverse_proxy",
	} {
		if !strings.Contains(global, want) {
			t.Errorf("the global block lacks %q", want)
		}
	}
	errBlock := global[strings.Index(global, "log errors {"):]
	for _, field := range []string{"request>uri", "request>headers", "request>remote_ip", "request>remote_port", "request>client_ip"} {
		if !regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(field) + `\s+delete\s*$`).MatchString(errBlock) {
			t.Errorf("the error log does not delete %s", field)
		}
	}
}

// caddyLab runs the committed Caddyfile in Caddy and sends canary requests
// through it. It needs Docker, like the database tests.
type caddyLab struct {
	t       *testing.T
	name    string
	network string
	port    string
	port80  string
}

func (l *caddyLab) docker(args ...string) string {
	l.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	out, err := deploy.Docker(ctx, args...).CombinedOutput()
	if err != nil {
		l.t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

// run starts the lab's image (the pinned reference of the Compose file) detached, with the flags given and the
// command after the image. The image is not a parameter of the caller: it goes through deploy.DockerRun, which
// refuses anything but a pinned reference (admin-r17-10).
func (l *caddyLab) run(flags []string, cmd ...string) string {
	l.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	out, err := deploy.DockerRun(ctx, l.image(), flags, cmd...).CombinedOutput()
	if err != nil {
		l.t.Fatalf("docker run: %v\n%s", err, out)
	}
	return strings.TrimSpace(string(out))
}

func newCaddyLab(t *testing.T) *caddyLab {
	t.Helper()
	if testing.Short() {
		t.Skip("-short: container tests skipped")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatal("docker is required for this test (use -short to skip)")
	}
	suffix := strings.ReplaceAll(time.Now().Format("150405.000"), ".", "")
	l := &caddyLab{t: t, name: "ctrlz-caddy-test-" + suffix, network: "ctrlz-caddy-net-" + suffix}
	l.docker("network", "create", l.network)
	t.Cleanup(func() {
		_ = deploy.Docker(context.Background(), "rm", "-f", l.name).Run()
		_ = deploy.Docker(context.Background(), "rm", "-f", l.name+"-up").Run()
		_ = deploy.Docker(context.Background(), "network", "rm", l.network).Run()
	})
	return l
}

func (l *caddyLab) image() string { return deploy.Image("CADDY_IMAGE") }

// upstream starts a server that the Caddyfile reaches as api:8080 and that
// answers 200 with a Content-Length it never fulfils: it sends a few bytes and
// closes, which makes Caddy log "aborting with incomplete response" from the
// reverse proxy's own logger. The Caddy image is Alpine, so its busybox nc is
// the whole server and no other image is needed. The reply waits a second so the request is read first; a server that closes with unread request bytes sends a reset and Caddy answers 502 instead.
func (l *caddyLab) upstream() {
	l.t.Helper()
	// The reply waits a second so the request is read first: a server that
	// closes with unread request bytes sends a reset, and Caddy answers 502
	// instead of seeing a cut body.
	script := `while true; do (sleep 1; printf 'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 100000\r\n\r\npartial') | nc -l -p 8080; done`
	l.run([]string{"-d", "--name", l.name + "-up", "--network", l.network, "--network-alias", "api", "--entrypoint", "sh"}, "-c", script)
	l.waitListening(l.name+"-up", "1F90") // 8080
}

// waitListening blocks until the container has a TCP socket in LISTEN state on the port
// (upper-case hex, as /proc/net/tcp writes it). `docker run -d` returns before the shell has
// started nc, and on a loaded machine (the full CI run starts Postgres containers beside this
// test) the single canary request used to reach Caddy while nothing listened: it answered 502,
// and the abort path the test is about was never exercised. A probe connection is no way to wait,
// because nc serves exactly one, so the socket table is read instead.
func (l *caddyLab) waitListening(container, hexPort string) {
	l.t.Helper()
	testwait.UntilEvery(l.t, 60*time.Second, 250*time.Millisecond, "the fake upstream "+container+" to listen on port "+hexPort, func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		return deploy.Docker(ctx, "exec", container, "sh", "-c",
			"grep -qE ':"+hexPort+" [0-9A-F:]+ 0A ' /proc/net/tcp /proc/net/tcp6").Run() == nil
	})
}

// start runs Caddy with the committed Caddyfile.
func (l *caddyLab) start() *http.Client {
	l.t.Helper()
	caddyfile, err := filepath.Abs(filepath.Join(repoRoot(l.t), "deploy", "compose", "caddy", "Caddyfile"))
	if err != nil {
		l.t.Fatal(err)
	}
	l.run([]string{"-d", "--name", l.name, "--network", l.network, "-v", caddyfile + ":/etc/caddy/Caddyfile:ro", "-p", "127.0.0.1::443", "-p", "127.0.0.1::80"})
	port := l.docker("port", l.name, "443/tcp")
	l.port = port[strings.LastIndex(port, ":")+1:]
	port = l.docker("port", l.name, "80/tcp")
	l.port80 = port[strings.LastIndex(port, ":")+1:]
	return &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "panel.localhost"}, // Caddy's own private CA
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, "127.0.0.1:"+l.port)
			},
			DisableKeepAlives: true,
		},
	}
}

const (
	canaryPath  = "CANARYSHARETOKEN"
	canaryQuery = "CANARYQUERYVALUE"
)

// ready waits until Caddy completes a TLS handshake. Docker accepts the
// connection before Caddy listens, so a plain dial proves nothing.
func (l *caddyLab) ready() {
	l.t.Helper()
	testwait.UntilEvery(l.t, 40*time.Second, 500*time.Millisecond, "Caddy to complete a TLS handshake", func() bool {
		c, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", "127.0.0.1:"+l.port,
			&tls.Config{InsecureSkipVerify: true, ServerName: "panel.localhost"}) // Caddy's own private CA
		if err != nil {
			return false
		}
		c.Close()
		return true
	})
}

// send makes the canary request once. status is 0 when no response arrived
// (Caddy cut the connection, which is what an aborted body does when the
// response is still being compressed); err is the first error of the request or
// of reading the body.
func (l *caddyLab) send(client *http.Client) (status int, err error) {
	l.ready()
	req, _ := http.NewRequest("GET", "https://panel.localhost/api/v1/s/"+canaryPath+"?tok="+canaryQuery, nil)
	req.Header.Set("Authorization", "Bearer CANARYBEARER")
	req.Header.Set("X-Forwarded-For", "CANARYFORWARDED")
	req.AddCookie(&http.Cookie{Name: "session", Value: "CANARYCOOKIE"})
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, err = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, err
}

// logsWhen reads the container's log until the condition holds on it, and returns what it read. The log is
// written after the response, so a test that asserts something is ABSENT from it has to wait for something it
// knows will be present (the line of the very request it made), and not for a clock: a fixed sleep passed
// vacuously on a slow runner, with the line not yet written, which made "no canary in the log" prove nothing
// (admin-r16-20). The wait ends when the condition holds or after a deadline, and the caller then asserts the
// condition too, so a log that never says it fails loudly.
func (l *caddyLab) logsWhen(cond func(logs string) bool) string {
	l.t.Helper()
	var logs string
	if !testwait.Holds(40*time.Second, 100*time.Millisecond, func() bool {
		logs = l.docker("logs", l.name)
		return cond(logs)
	}) {
		l.t.Errorf("the log never satisfied the condition within 40 s; log:\n%s", logs)
	}
	return logs
}

func (l *caddyLab) wantClean(wantLogger string) {
	l.t.Helper()
	logs := l.logsWhen(func(s string) bool { return strings.Contains(s, wantLogger) })
	for _, canary := range []string{canaryPath, canaryQuery, "CANARYBEARER", "CANARYCOOKIE", "CANARYFORWARDED"} {
		if strings.Contains(logs, canary) {
			l.t.Errorf("Caddy's log contains %q:\n%s", canary, logs)
		}
	}
	if !strings.Contains(logs, wantLogger) {
		l.t.Errorf("no %s line in the output, so that error path was not logged at all:\n%s", wantLogger, logs)
	}
}

// TestCaddyErrorLogHasNoRequestURI (live): the upstream is down, a request with
// a canary token in its path and query gets a 502, and the canary must appear
// nowhere in what Caddy logged. This is the check that "caddy log had no URI"
// skipped: it was made on the success path only.
func TestCaddyErrorLogHasNoRequestURI(t *testing.T) {
	l := newCaddyLab(t)
	client := l.start()
	status, _ := l.send(client)
	if status != http.StatusBadGateway {
		t.Fatalf("got status %d; with no upstream the proxy should answer 502 (the test is not exercising the error path)", status)
	}
	l.wantClean("http.log.error")
}

// TestCaddyAbortedBodyLogHasNoRequestURI (live): the upstream closes in the
// middle of the body. The reverse proxy's own logger then writes "aborting with
// incomplete response" with the URI and the client address, a third logger the
// first fix did not cover (review L2-F02, second round).
func TestCaddyAbortedBodyLogHasNoRequestURI(t *testing.T) {
	l := newCaddyLab(t)
	l.upstream()
	client := l.start()
	status, err := l.send(client)
	if err == nil || (status != 0 && status != http.StatusOK) {
		t.Fatalf("status %d, error %v; the request should fail or the body be cut short (the test is not exercising the abort path)", status, err)
	}
	l.wantClean("http.handlers.reverse_proxy")
}

// TestCaddyUnmatchedHostLogHasNoRequestURI (live): the quiet_log filter hangs on
// the two site blocks, so a request whose Host matches neither goes to the
// default logger. Before http.log.access was excluded from it, a share link
// opened through the server's IP address, with a trailing dot on the host name,
// or under any other name wrote the whole URI and the client address to the
// Docker log. The correct host must still be logged, with the filter, so the
// exclusion is not just silencing the access log.
func TestCaddyUnmatchedHostLogHasNoRequestURI(t *testing.T) {
	l := newCaddyLab(t)
	secure := l.start()
	l.ready()
	plain := &http.Client{
		Timeout:       20 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, "127.0.0.1:"+l.port80)
			},
			DisableKeepAlives: true,
		},
	}
	get := func(client *http.Client, scheme, host string) {
		t.Helper()
		req, _ := http.NewRequest("GET", scheme+"://panel.localhost/s/"+canaryPath+"?tok="+canaryQuery, nil)
		req.Host = host
		req.Header.Set("Authorization", "Bearer CANARYBEARER")
		req.Header.Set("X-Forwarded-For", "CANARYFORWARDED")
		req.AddCookie(&http.Cookie{Name: "session", Value: "CANARYCOOKIE"})
		resp, err := client.Do(req)
		if err != nil {
			t.Logf("%s %s: %v", scheme, host, err) // an aborted body is fine here; only the log matters
			return
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	for _, host := range []string{"127.0.0.1:" + l.port, "other.example", "panel.localhost."} {
		get(secure, "https", host)
		get(plain, "http", host)
	}
	// The correct host, so the site logger has written at least one line.
	get(secure, "https", "panel.localhost")

	// The last request is the one whose line the site's own logger writes; its line is what the wait is for.
	// The earlier requests (to other hosts) finished before it began, and a stream of lines is read in order.
	logs := l.logsWhen(func(s string) bool { return strings.Contains(s, "http.log.access.log0") })
	for _, canary := range []string{canaryPath, canaryQuery, "CANARYBEARER", "CANARYCOOKIE", "CANARYFORWARDED"} {
		if strings.Contains(logs, canary) {
			t.Errorf("Caddy's log contains %q:\n%s", canary, logs)
		}
	}
	if !strings.Contains(logs, "http.log.access.log0") {
		t.Errorf("the site's own access logger wrote nothing, so the test is not showing that it still works:\n%s", logs)
	}
}

// clickhouseLab runs the entrypoint wrapper of the clickhouse service exactly
// as the compose file writes it, in the real image, with a secret file the test
// chooses. It needs Docker, like the Caddy tests.
type clickhouseLab struct {
	t      *testing.T
	script string
	env    string
}

func newClickHouseLab(t *testing.T) *clickhouseLab {
	t.Helper()
	if testing.Short() {
		t.Skip("-short: container tests skipped")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatal("docker is required for this test (use -short to skip)")
	}
	ch := loadCompose(t).Services["clickhouse"]
	if len(ch.Entrypoint) != 3 || ch.Entrypoint[0] != "/bin/sh" || ch.Entrypoint[1] != "-c" {
		t.Fatalf("the clickhouse entrypoint is not /bin/sh -c <script>: %q", ch.Entrypoint)
	}
	if ch.Environment["CLICKHOUSE_SKIP_USER_SETUP"] != "1" {
		t.Fatal("clickhouse: CLICKHOUSE_SKIP_USER_SETUP is not 1")
	}
	return &clickhouseLab{
		t: t,
		// Compose writes a literal dollar as two.
		script: strings.ReplaceAll(ch.Entrypoint[2], "$$", "$"),
		env:    "CLICKHOUSE_SKIP_USER_SETUP=1",
	}
}

func (l *clickhouseLab) image() string { return deploy.Image("CLICKHOUSE_IMAGE") }

// run starts the wrapper with the given content of the secret file and returns
// the container name. usersReadOnly mounts an empty users.d read-only, which is
// how a failed write of the user file is provoked: the rest of the filesystem
// stays writable, so only the wrapper can notice.
func (l *clickhouseLab) run(secretFile []byte, usersReadOnly bool) string {
	l.t.Helper()
	dir := l.t.TempDir()
	secretPath := filepath.Join(dir, "clickhouse_password")
	if err := os.WriteFile(secretPath, secretFile, 0o444); err != nil {
		l.t.Fatal(err)
	}
	conf, err := filepath.Abs(filepath.Join(repoRoot(l.t), "deploy", "compose", "clickhouse", "ctrlz.xml"))
	if err != nil {
		l.t.Fatal(err)
	}
	name := fmt.Sprintf("ctrlz-ch-test-%016x", rand.Uint64())
	args := []string{"-d", "--name", name,
		"-e", l.env, "-e", "CH_MAX_SERVER_MEMORY_USAGE=2000000000",
		"-v", secretPath + ":/run/secrets/clickhouse_password:ro",
		"-v", conf + ":/etc/clickhouse-server/config.d/ctrlz.xml:ro",
		"--ulimit", "nofile=262144:262144"}
	if usersReadOnly {
		args = append(args, "-v", l.t.TempDir()+":/etc/clickhouse-server/users.d:ro")
	}
	args = append(args, "--entrypoint", "/bin/sh")
	if out, err := deploy.DockerRun(context.Background(), l.image(), args, "-c", l.script).CombinedOutput(); err != nil {
		l.t.Fatalf("docker run: %v\n%s", err, out)
	}
	l.t.Cleanup(func() { _ = deploy.Docker(context.Background(), "rm", "-f", name).Run() })
	return name
}

func (l *clickhouseLab) running(name string) bool {
	out, err := deploy.Docker(context.Background(), "inspect", "-f", "{{.State.Running}}", name).Output()
	if err != nil {
		l.t.Fatalf("docker inspect: %v", err)
	}
	return strings.TrimSpace(string(out)) == "true"
}

// wantStopped waits for the container to exit by itself and returns its exit
// code and its output. A wrapper that goes on to start the server fails here
// by still running.
func (l *clickhouseLab) wantStopped(name string) (int, string) {
	l.t.Helper()
	if !testwait.Holds(40*time.Second, 250*time.Millisecond, func() bool { return !l.running(name) }) {
		logs, _ := deploy.Docker(context.Background(), "logs", "--tail", "5", name).CombinedOutput()
		l.t.Fatalf("the container kept running; it should have stopped before the entrypoint. Last output:\n%s", logs)
	}
	out, _ := deploy.Docker(context.Background(), "inspect", "-f", "{{.State.ExitCode}}", name).Output()
	code, _ := strconv.Atoi(strings.TrimSpace(string(out)))
	logs, _ := deploy.Docker(context.Background(), "logs", name).CombinedOutput()
	return code, string(logs)
}

// login runs clickhouse-client inside the container and returns what it
// printed and whether it succeeded.
func (l *clickhouseLab) login(name, user, password string) (string, bool) {
	out, err := deploy.Docker(context.Background(), "exec", name, "clickhouse-client", "--user", user, "--password", password,
		"--query", "SELECT currentUser()").CombinedOutput()
	return strings.TrimSpace(string(out)), err == nil
}

// wantReady waits until the ctrlz user can log in with the password.
func (l *clickhouseLab) wantReady(name, password string) {
	l.t.Helper()
	testwait.UntilEvery(l.t, 120*time.Second, time.Second, "ClickHouse to accept the ctrlz login", func() bool {
		if !l.running(name) {
			logs, _ := deploy.Docker(context.Background(), "logs", "--tail", "10", name).CombinedOutput()
			l.t.Fatalf("the container stopped:\n%s", logs)
		}
		out, ok := l.login(name, "ctrlz", password)
		if ok && out != "ctrlz" {
			l.t.Fatalf("currentUser() is %q", out)
		}
		return ok
	})
}

// wantRefused checks that a login that must not work does not.
func (l *clickhouseLab) wantRefused(name, user, password, what string) {
	l.t.Helper()
	if out, ok := l.login(name, user, password); ok {
		l.t.Errorf("%s: logged in as %q", what, out)
	}
}

// TestClickHouseWrapperStopsOnAnEmptySecret: an empty password file must stop
// the container, not turn into a user without a password. The file is empty
// when gen-secrets.sh or an operator leaves it so; a file of only CR and LF is
// empty to the Go services (secret.FromFile) and must be empty here as well.
func TestClickHouseWrapperStopsOnAnEmptySecret(t *testing.T) {
	lab := newClickHouseLab(t)
	for _, tc := range []struct {
		name string
		file string
	}{
		{"empty", ""},
		{"line feed only", "\n"},
		{"carriage return and line feed only", "\r\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := *lab
			l.t = t
			t.Parallel()
			code, logs := l.wantStopped(l.run([]byte(tc.file), false))
			if code == 0 {
				t.Errorf("exit code 0, want non-zero\n%s", logs)
			}
			if !strings.Contains(logs, "clickhouse: ") {
				t.Errorf("no line on stderr that names the cause:\n%s", logs)
			}
			if strings.Contains(logs, "Starting ClickHouse") || strings.Contains(logs, "Processing configuration file") {
				t.Errorf("the server started:\n%s", logs)
			}
		})
	}
}

// TestClickHouseWrapperStopsWhenUsersFileCannotBeWritten: with the user setup
// switched off, a failed write would leave the built-in default user in place
// without the localhost-only fallback of the official entrypoint.
func TestClickHouseWrapperStopsWhenUsersFileCannotBeWritten(t *testing.T) {
	l := newClickHouseLab(t)
	code, logs := l.wantStopped(l.run([]byte("a-real-looking-value"), true))
	if code == 0 {
		t.Errorf("exit code 0, want non-zero\n%s", logs)
	}
	if strings.Contains(logs, "Starting ClickHouse") || strings.Contains(logs, "Processing configuration file") {
		t.Errorf("the server started although users.d could not be written:\n%s", logs)
	}
}

// TestClickHouseWrapperSetsTheUser: a real secret gives a working ctrlz login
// and no other, including when the file ends in CR LF, which the shell and Go
// would trim differently if the wrapper left it to the shell.
func TestClickHouseWrapperSetsTheUser(t *testing.T) {
	lab := newClickHouseLab(t)
	for _, tc := range []struct {
		name string
		file string
	}{
		{"as gen-secrets.sh writes it", "Zq3vNn7hQw1xKs9d"},
		{"ending in CR LF", "Zq3vNn7hQw1xKs9d\r\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := *lab
			l.t = t
			t.Parallel()
			path := filepath.Join(t.TempDir(), "pw")
			if err := os.WriteFile(path, []byte(tc.file), 0o600); err != nil {
				t.Fatal(err)
			}
			// What the Go services send is the authority.
			want, err := secret.FromFile(path)
			if err != nil {
				t.Fatal(err)
			}
			name := l.run([]byte(tc.file), false)
			l.wantReady(name, want.Reveal())
			l.wantRefused(name, "ctrlz", "", "empty password")
			l.wantRefused(name, "ctrlz", "wrong", "wrong password")
			l.wantRefused(name, "ctrlz", want.Reveal()+"\r", "the password with the CR the shell would have kept")
			l.wantRefused(name, "default", "", "the built-in default user")
		})
	}
}

// TestPostgresAllowsNoPreparedTransactions is db-r17-7: the watchdog ends backends and a prepared transaction
// belongs to none. The file pins the setting to 0 and no -c flag of the Compose file or of a profile may raise
// it (a flag overrides the file). reachcheck.JudgeBootstrapState asks the live server on every start.
func TestPostgresAllowsNoPreparedTransactions(t *testing.T) {
	conf := readDeploy(t, "postgres", "postgresql.conf")
	if got, found := confValue(conf, "max_prepared_transactions"); !found || got != "0" {
		t.Errorf("postgresql.conf: max_prepared_transactions = %q (set %v), want 0", got, found)
	}
	for _, f := range []string{"docker-compose.yml"} {
		if strings.Contains(readDeploy(t, f), "max_prepared_transactions") {
			t.Errorf("%s sets max_prepared_transactions on the command line, which overrides postgresql.conf", f)
		}
	}
	profiles, err := filepath.Glob(filepath.Join(repoRoot(t), "deploy", "compose", "profiles", "*.env"))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range profiles {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), "max_prepared_transactions") {
			t.Errorf("%s mentions max_prepared_transactions: a profile may not raise it", p)
		}
	}
}
