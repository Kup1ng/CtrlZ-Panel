package lint_test

import (
	"context"
	"fmt"
	"math/rand/v2"
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

// chUserNames are the five ClickHouse users of P5 3.4, by the word the secret file and the user name share:
// the secret of ctrlz_api is clickhouse_api_password.
var chUserNames = []string{"migrator", "ingest", "api", "preview", "janitor"}

// clickhouseLab runs the entrypoint wrapper of the clickhouse service exactly as the compose file writes it,
// in the real image, with the five secret files the test chooses, the same two XML files and the same CH_
// numbers (the small profile's, which the file defaults to). It needs Docker, like the Caddy tests, and is
// run on GitHub only (D69).
type clickhouseLab struct {
	t      *testing.T
	script string
	env    []string // KEY=value, in the form docker run -e takes
	// without names a config file the test leaves out: "users" or "server". Docker turns a missing bind source
	// into a directory, which is what an upgrade that copied only the Compose file leaves behind.
	without string
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
	var env []string
	for k, v := range ch.Environment {
		// ${NAME:-default} is the default, which is the small profile's number.
		if m := regexp.MustCompile(`^\$\{[A-Z_]+:-(.*)\}$`).FindStringSubmatch(v); m != nil {
			v = m[1]
		}
		env = append(env, k+"="+v)
	}
	return &clickhouseLab{
		t: t,
		// Compose writes a literal dollar as two.
		script: strings.ReplaceAll(ch.Entrypoint[2], "$$", "$"),
		env:    env,
	}
}

func (l *clickhouseLab) image() string { return deploy.Image("CLICKHOUSE_IMAGE") }

// run starts the wrapper with the same content in all five secret files and returns the container name.
// usersReadOnly mounts an empty users.d read-only, which is how a failed write of the user file is
// provoked: the rest of the filesystem stays writable, so only the wrapper can notice.
func (l *clickhouseLab) run(secretFile []byte, usersReadOnly bool) string {
	files := map[string][]byte{}
	for _, u := range chUserNames {
		files[u] = secretFile
	}
	return l.runWith(files, usersReadOnly, false)
}

// runWith starts the wrapper with one content for each user (by the names of chUserNames). publish also
// publishes the native port on a free port of the loopback, for the tests that talk to the server.
func (l *clickhouseLab) runWith(files map[string][]byte, usersReadOnly, publish bool) string {
	l.t.Helper()
	dir := l.t.TempDir()
	abs := func(parts ...string) string {
		p, err := filepath.Abs(filepath.Join(append([]string{repoRoot(l.t), "deploy", "compose", "clickhouse"}, parts...)...))
		if err != nil {
			l.t.Fatal(err)
		}
		return p
	}
	name := fmt.Sprintf("ctrlz-ch-test-%016x", rand.Uint64())
	args := []string{"-d", "--name", name}
	for _, e := range l.env {
		args = append(args, "-e", e)
	}
	for _, u := range chUserNames {
		p := filepath.Join(dir, "clickhouse_"+u+"_password")
		if err := os.WriteFile(p, files[u], 0o444); err != nil {
			l.t.Fatal(err)
		}
		args = append(args, "-v", p+":/run/secrets/clickhouse_"+u+"_password:ro")
	}
	if l.without == "server" {
		args = append(args, "-v", l.t.TempDir()+":/etc/clickhouse-server/config.d/ctrlz.xml:ro")
	} else {
		args = append(args, "-v", abs("ctrlz.xml")+":/etc/clickhouse-server/config.d/ctrlz.xml:ro")
	}
	args = append(args, "--ulimit", "nofile=262144:262144")
	switch {
	case l.without == "users":
		args = append(args, "-v", l.t.TempDir()+":/etc/clickhouse-server/users.d/ctrlz-users.xml:ro")
	case usersReadOnly:
		// users.d holds the real users.xml, so the wrapper's file check passes and only the write of its own
		// file fails (a directory that is read-only as a whole).
		ro := l.t.TempDir()
		b, err := os.ReadFile(abs("users.xml"))
		if err != nil {
			l.t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(ro, "ctrlz-users.xml"), b, 0o444); err != nil {
			l.t.Fatal(err)
		}
		args = append(args, "-v", ro+":/etc/clickhouse-server/users.d:ro")
	default:
		args = append(args, "-v", abs("users.xml")+":/etc/clickhouse-server/users.d/ctrlz-users.xml:ro")
	}
	if publish {
		args = append(args, "-p", "127.0.0.1::9000")
	}
	args = append(args, "--entrypoint", "/bin/sh")
	if out, err := deploy.DockerRun(context.Background(), l.image(), args, "-c", l.script).CombinedOutput(); err != nil {
		l.t.Fatalf("docker run: %v\n%s", err, out)
	}
	l.t.Cleanup(func() { _ = deploy.Docker(context.Background(), "rm", "-f", name).Run() })
	return name
}

// nativeAddr is the loopback host:port the native port of a published container answers on.
func (l *clickhouseLab) nativeAddr(name string) string {
	l.t.Helper()
	out, err := deploy.Docker(context.Background(), "port", name, "9000/tcp").Output()
	if err != nil {
		l.t.Fatalf("docker port: %v", err)
	}
	first := strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0])
	if first == "" {
		l.t.Fatal("docker port printed nothing for 9000/tcp")
	}
	return first
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

// wantReady waits until the user can log in with the password.
func (l *clickhouseLab) wantReady(name, user, password string) {
	l.t.Helper()
	testwait.UntilEvery(l.t, 120*time.Second, time.Second, "ClickHouse to accept the login of "+user, func() bool {
		if !l.running(name) {
			logs, _ := deploy.Docker(context.Background(), "logs", "--tail", "10", name).CombinedOutput()
			l.t.Fatalf("the container stopped:\n%s", logs)
		}
		out, ok := l.login(name, user, password)
		if ok && out != user {
			l.t.Fatalf("currentUser() is %q, want %q", out, user)
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
// One empty file among five good ones stops it as well: the check of all five
// comes before the first byte is written.
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
	for _, empty := range chUserNames {
		t.Run("only the secret of "+empty+" is empty", func(t *testing.T) {
			l := *lab
			l.t = t
			t.Parallel()
			files := map[string][]byte{}
			for _, u := range chUserNames {
				files[u] = []byte("Zq3vNn7hQw1xKs9d-" + u)
			}
			files[empty] = nil
			code, logs := l.wantStopped(l.runWith(files, false, false))
			if code == 0 || !strings.Contains(logs, "ctrlz_"+empty) {
				t.Errorf("exit code %d, and the log should name ctrlz_%s:\n%s", code, empty, logs)
			}
			if strings.Contains(logs, "Starting ClickHouse") || strings.Contains(logs, "Processing configuration file") {
				t.Errorf("the server started with one empty password file:\n%s", logs)
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

// TestClickHouseWrapperStopsWhenAConfigFileIsMissing: users.xml carries the grants, profiles and constraints
// and ctrlz.xml the row-policy and system-table switches. Without either the five users would start with
// every right (a config user with no grants gets ALL), so the wrapper stops. Docker makes the missing bind
// source a directory, which is what an upgrade that copied only the Compose file leaves.
func TestClickHouseWrapperStopsWhenAConfigFileIsMissing(t *testing.T) {
	lab := newClickHouseLab(t)
	for _, without := range []string{"users", "server"} {
		t.Run(without, func(t *testing.T) {
			l := *lab
			l.t = t
			l.without = without
			t.Parallel()
			code, logs := l.wantStopped(l.run([]byte("a-real-looking-value"), false))
			if code == 0 || !strings.Contains(logs, "not a regular file") {
				t.Errorf("exit code %d, and the log should say the file is not a regular file:\n%s", code, logs)
			}
			if strings.Contains(logs, "Starting ClickHouse") || strings.Contains(logs, "Processing configuration file") {
				t.Errorf("the server started without its %s config file:\n%s", without, logs)
			}
		})
	}
}

// TestClickHouseWrapperSetsTheUsers: a real secret gives a working login for each of the five users and
// no other, including when a file ends in CR LF, which the shell and Go would trim differently if the
// wrapper left it to the shell. Every user has a password of its own, so a login with another user's
// password is refused (a wrapper that wrote one hash for all would pass the first half alone).
func TestClickHouseWrapperSetsTheUsers(t *testing.T) {
	lab := newClickHouseLab(t)
	for _, tc := range []struct {
		name string
		end  string
	}{
		{"as gen-secrets.sh writes it", ""},
		{"ending in CR LF", "\r\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := *lab
			l.t = t
			t.Parallel()
			files := map[string][]byte{}
			want := map[string]string{}
			for _, u := range chUserNames {
				path := filepath.Join(t.TempDir(), "pw")
				content := "Zq3vNn7hQw1xKs9d-" + u + tc.end
				if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
					t.Fatal(err)
				}
				// What the Go services send is the authority.
				pw, err := secret.FromFile(path)
				if err != nil {
					t.Fatal(err)
				}
				files[u], want[u] = []byte(content), pw.Reveal()
			}
			name := l.runWith(files, false, false)
			for _, u := range chUserNames {
				l.wantReady(name, "ctrlz_"+u, want[u])
			}
			for _, u := range chUserNames {
				l.wantRefused(name, "ctrlz_"+u, "", "ctrlz_"+u+" with an empty password")
				l.wantRefused(name, "ctrlz_"+u, "wrong", "ctrlz_"+u+" with a wrong password")
				l.wantRefused(name, "ctrlz_"+u, want[u]+"\r", "ctrlz_"+u+" with the CR the shell would have kept")
				other := chUserNames[(indexOf(chUserNames, u)+1)%len(chUserNames)]
				l.wantRefused(name, "ctrlz_"+u, want[other], "ctrlz_"+u+" with the password of ctrlz_"+other)
			}
			l.wantRefused(name, "default", "", "the built-in default user")
			l.wantRefused(name, "ctrlz", want["api"], "the single user of the earlier layout")
		})
	}
}

func indexOf(list []string, s string) int {
	for i, v := range list {
		if v == s {
			return i
		}
	}
	return -1
}
