package lint_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/deploy"
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

// wantClean waits until holds is true of the log (a line of the path the test exercises) and then requires that no
// canary is anywhere in it.
func (l *caddyLab) wantClean(what string, holds func(logs string) bool) {
	l.t.Helper()
	logs := l.logsWhen(holds)
	for _, canary := range []string{canaryPath, canaryQuery, "CANARYBEARER", "CANARYCOOKIE", "CANARYFORWARDED"} {
		if strings.Contains(logs, canary) {
			l.t.Errorf("Caddy's log contains %q:\n%s", canary, logs)
		}
	}
	if !holds(logs) {
		l.t.Errorf("no %s in the output, so that path was not logged at all:\n%s", what, logs)
	}
}

// siteAccessLogger is the name of an access logger that one of the SITES owns. The sites' loggers are named log0,
// log1 and so on in the order Caddy meets the site blocks, and the catch-all :443 site and the port 80 site each
// added one, so the number is not a fact this test relies on: the default logger excludes http.log.access, so a
// line from any http.log.access.log<N> is a site's own.
var siteAccessLogger = regexp.MustCompile(`^http\.log\.access\.log[0-9]+$`)

// siteAccessLine reports whether the log holds an access line that a site's own logger wrote for a request to host
// with this status, and whose request has neither a uri nor headers (the quiet_log filter removed them).
func siteAccessLine(logs, host string, status int) bool {
	for _, ln := range strings.Split(logs, "\n") {
		var line struct {
			Logger  string `json:"logger"`
			Status  int    `json:"status"`
			Request struct {
				Host    string          `json:"host"`
				URI     json.RawMessage `json:"uri"`
				Headers json.RawMessage `json:"headers"`
			} `json:"request"`
		}
		if json.Unmarshal([]byte(ln), &line) != nil || !siteAccessLogger.MatchString(line.Logger) {
			continue
		}
		if line.Request.Host == host && line.Status == status && line.Request.URI == nil && line.Request.Headers == nil {
			return true
		}
	}
	return false
}

// TestCaddyErrorLogHasNoRequestURI (live): the upstream is down, a request with
// a canary token in its path and query gets a 502, and the canary must appear
// nowhere in what Caddy logged. This is the check that "caddy log had no URI"
// skipped: it was made on the success path only. The site has a handle_errors block, which makes Caddy treat a
// refused upstream as handled, so no http.log.error line is written any more; what is logged for the request is its
// access line, and that line must show the 502 and carry no URI.
func TestCaddyErrorLogHasNoRequestURI(t *testing.T) {
	l := newCaddyLab(t)
	client := l.start()
	status, _ := l.send(client)
	if status != http.StatusBadGateway {
		t.Fatalf("got status %d; with no upstream the proxy should answer 502 (the test is not exercising the error path)", status)
	}
	l.wantClean("access line of the site with status 502 and no request uri", func(logs string) bool {
		return siteAccessLine(logs, "panel.localhost", http.StatusBadGateway)
	})
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
	l.wantClean("http.handlers.reverse_proxy line", func(logs string) bool { return strings.Contains(logs, "http.handlers.reverse_proxy") })
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
	// The logger is found by what it is (a site's access logger) and not by its number: the catch-all :443 site and
	// the port 80 site have a quiet_log of their own, so the name of the panel site's logger is not a fact of this file.
	// The upstream is down, so the correct host answers 502, as TestCaddyErrorLogHasNoRequestURI shows.
	logs := l.logsWhen(func(s string) bool { return siteAccessLine(s, "panel.localhost", http.StatusBadGateway) })
	for _, canary := range []string{canaryPath, canaryQuery, "CANARYBEARER", "CANARYCOOKIE", "CANARYFORWARDED"} {
		if strings.Contains(logs, canary) {
			t.Errorf("Caddy's log contains %q:\n%s", canary, logs)
		}
	}
	if !siteAccessLine(logs, "panel.localhost", http.StatusBadGateway) {
		t.Errorf("the site's own access logger wrote nothing, so the test is not showing that it still works:\n%s", logs)
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

// TestSiteAccessLineJudgesWhatItClaims is the container-free check of the helper the two live Caddy tests wait on: a
// helper that accepted any line would let "no canary in the log" pass on a log that holds nothing of the request.
func TestSiteAccessLineJudgesWhatItClaims(t *testing.T) {
	line := func(logger, host string, status int, request string) string {
		return fmt.Sprintf(`{"level":"info","logger":%q,"msg":"handled request","request":{"proto":"HTTP/2.0","method":"GET","host":%q%s},"status":%d}`, logger, host, request, status)
	}
	good := line("http.log.access.log1", "panel.localhost", 502, "")
	if !siteAccessLine("noise\n"+good+"\n", "panel.localhost", 502) {
		t.Fatal("a site's filtered access line was not recognised")
	}
	for name, logs := range map[string]string{
		"a line that still has the uri":     line("http.log.access.log0", "panel.localhost", 502, `,"uri":"/s/x"`),
		"a line that still has the headers": line("http.log.access.log0", "panel.localhost", 502, `,"headers":{}`),
		"the default logger's line":         line("http.log.access", "panel.localhost", 502, ""),
		"another status":                    line("http.log.access.log0", "panel.localhost", 200, ""),
		"another host":                      line("http.log.access.log0", "other.example", 502, ""),
		"the error logger":                  line("http.log.error", "panel.localhost", 502, ""),
		"an empty log":                      "",
	} {
		if siteAccessLine(logs, "panel.localhost", 502) {
			t.Errorf("%s was accepted as the site's filtered access line", name)
		}
	}
}
