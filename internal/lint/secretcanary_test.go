package lint_test

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// scripts/secret-canary.sh is the check of scripts/compose-smoke.sh that none of the stack's secrets
// reached a container log or a row (round 8, admin-r8-6). The smoke grepped for the two one-time
// passwords and the admin hash only, while the stack holds the key root, six key files, nine database
// and ClickHouse passwords, two Valkey passwords and the proof key, and the Go canary tests run in
// process, so a later `echo` in the Valkey start line or a `set -x` in a wrapper would have left a
// secret in `docker logs` with the smoke printing ok. The script needs no Docker, so it is run here
// on planted files: it must find each secret in each form a careless log line gives it, name the
// file and never the value, and fail when it looked at nothing.

func runCanary(t *testing.T, secrets string, sinks ...string) (string, error) {
	t.Helper()
	sh, err := exec.LookPath("sh")
	if err != nil {
		git := `C:\Program Files\Git\usr\bin\sh.exe`
		if _, statErr := os.Stat(git); statErr != nil {
			t.Skip("no sh on PATH")
		}
		sh = git
	}
	script := filepath.ToSlash(filepath.Join(repoRoot(t), "scripts", "secret-canary.sh"))
	args := []string{script, filepath.ToSlash(secrets)}
	for _, s := range sinks {
		args = append(args, filepath.ToSlash(s))
	}
	out, err := exec.Command(sh, args...).CombinedOutput()
	return string(out), err
}

// plantedStack writes a secrets directory shaped like the real one and returns it with the values.
func plantedStack(t *testing.T) (dir string, root []byte, valkey, keyLine, pg string) {
	t.Helper()
	dir = t.TempDir()
	root = bytes.Repeat([]byte{0xA7, 0x13, 0xC4, 0x5E}, 8)
	valkey = "valkeyAdminSecretPassword0123456789abcdef"
	keyLine = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-abcdE"
	pg = "pgWorkerPasswordWithManyCharacters9876543210"
	files := map[string][]byte{
		"kek_root":              root,
		"kek_admin_totp":        []byte("# ctrlz key file: admin_totp\n1 " + keyLine + "\n"),
		"valkey_password_admin": []byte(valkey + "\r\n"), // the Valkey start line reads it with its CR LF off
		"pg_worker_password":    []byte(pg + "\n"),
		"tiny":                  []byte("short\n"), // too short to look for, and must not decide the result
	}
	for n, c := range files {
		if err := os.WriteFile(filepath.Join(dir, n), c, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir, root, valkey, keyLine, pg
}

func TestSecretCanaryFindsEverySecretInEveryFormAndNeverPrintsOne(t *testing.T) {
	dir, root, valkey, keyLine, pg := plantedStack(t)
	clean := filepath.Join(t.TempDir(), "clean.log")
	if err := os.WriteFile(clean, []byte("2026-11-13 started\nlistening on :8080\nshort word\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := runCanary(t, dir, clean); err != nil || !strings.Contains(out, "secret-canary: ok") {
		t.Fatalf("a clean log must pass: %v\n%s", err, out)
	}

	cases := []struct{ name, line, secretFile string }{
		{"a text secret with a prefix", "ACL SETUSER admin >" + valkey, "valkey_password_admin"},
		{"a key line as written", "1 " + keyLine, "kek_admin_totp"},
		{"the key alone", "key=" + keyLine, "kek_admin_totp"},
		{"a database password", "PGPASSWORD=" + pg + " psql", "pg_worker_password"},
		{"the root as hex", hex.EncodeToString(root), "kek_root"},
		{"the root as upper case hex", strings.ToUpper(hex.EncodeToString(root)), "kek_root"},
		{"the root as base64", base64.StdEncoding.EncodeToString(root), "kek_root"},
		{"the root as base64url", base64.RawURLEncoding.EncodeToString(root), "kek_root"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sink := filepath.Join(t.TempDir(), "docker.log")
			if err := os.WriteFile(sink, []byte("noise\n"+c.line+"\nmore noise\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			out, err := runCanary(t, dir, clean, sink)
			if err == nil {
				t.Fatalf("a log that holds %s passed\n%s", c.name, out)
			}
			if !strings.Contains(out, "the content of "+c.secretFile+" is in docker.log") {
				t.Errorf("the failure does not name the secret file and the sink:\n%s", out)
			}
			for _, v := range []string{valkey, keyLine, pg, hex.EncodeToString(root), base64.StdEncoding.EncodeToString(root)} {
				if strings.Contains(out, v) {
					t.Errorf("the output holds a secret value")
				}
			}
		})
	}
}

func TestSecretCanaryRefusesToLookAtNothing(t *testing.T) {
	sink := filepath.Join(t.TempDir(), "docker.log")
	if err := os.WriteFile(sink, []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	empty := t.TempDir()
	if out, err := runCanary(t, empty, sink); err == nil {
		t.Errorf("an empty secrets directory passed:\n%s", out)
	}
	onlyShort := t.TempDir()
	if err := os.WriteFile(filepath.Join(onlyShort, "tiny"), []byte("short\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := runCanary(t, onlyShort, sink); err == nil {
		t.Errorf("a directory with nothing long enough to look for passed:\n%s", out)
	}
	dir, _, _, _, _ := plantedStack(t)
	if out, err := runCanary(t, dir, filepath.Join(t.TempDir(), "missing.log")); err == nil {
		t.Errorf("a sink that does not exist passed:\n%s", out)
	}
}

// TestComposeSmokeRunsTheSecretCanary: the smoke must call the script over its own secrets directory
// and the logs and rows it collected, or the check is a file that nobody runs.
func TestComposeSmokeRunsTheSecretCanary(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(repoRoot(t), "scripts", "compose-smoke.sh"))
	if err != nil {
		t.Fatal(err)
	}
	var call string
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "sh scripts/secret-canary.sh") {
			call = l
		}
	}
	if call == "" {
		t.Fatal("scripts/compose-smoke.sh does not run scripts/secret-canary.sh")
	}
	for _, want := range []string{`"$secrets"`, `"$logs"`, `"$work/rows"`, "|| fail"} {
		if !strings.Contains(call, want) {
			t.Errorf("the call %q lacks %s", call, want)
		}
	}
}

// runCanaryEnv is runCanary with extra environment, for the consumer check.
func runCanaryEnv(t *testing.T, env []string, secrets string, sinks ...string) (string, error) {
	t.Helper()
	sh, err := exec.LookPath("sh")
	if err != nil {
		git := `C:\Program Files\Git\usr\bin\sh.exe`
		if _, statErr := os.Stat(git); statErr != nil {
			t.Skip("no sh on PATH")
		}
		sh = git
	}
	script := filepath.ToSlash(filepath.Join(repoRoot(t), "scripts", "secret-canary.sh"))
	args := []string{script, filepath.ToSlash(secrets)}
	for _, s := range sinks {
		args = append(args, filepath.ToSlash(s))
	}
	cmd := exec.Command(sh, args...)
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// TestSecretCanaryFailsWhenTheContainerThatReadsASecretLoggedNothing is round 9, admin-r9-4: the
// Compose smoke started api, admin and worker only, so the logs it searched for the Valkey, ClickHouse
// and proof-key secrets belonged to containers that never read them, and the canary said ok. The
// smoke now hands the script who reads which secret; a consumer whose log is empty, and a secret file
// nobody reads, fail the run and name the file and the container.
func TestSecretCanaryFailsWhenTheContainerThatReadsASecretLoggedNothing(t *testing.T) {
	dir, _, _, _, _ := plantedStack(t)
	tmp := t.TempDir()
	sink := filepath.Join(tmp, "docker.log")
	logOf := func(name, body string) string {
		p := filepath.Join(tmp, name+".log")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return filepath.ToSlash(p)
	}
	if err := os.WriteFile(sink, []byte("noise\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	full, empty := logOf("valkey", "Ready to accept connections\n"), logOf("hub", "")
	consumers := func(lines ...string) []string {
		p := filepath.Join(tmp, "consumers")
		if err := os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return []string{"CTRLZ_CANARY_CONSUMERS=" + filepath.ToSlash(p)}
	}
	// The files of plantedStack: every one needs a consumer (tiny is under the length and still a file).
	all := []string{
		"kek_root valkey " + full, "kek_admin_totp valkey " + full, "valkey_password_admin valkey " + full,
		"pg_worker_password valkey " + full, "tiny valkey " + full,
	}

	if out, err := runCanaryEnv(t, consumers(all...), dir, sink); err != nil || !strings.Contains(out, "secret-canary: ok") {
		t.Fatalf("every consumer logged and every secret is read: %v\n%s", err, out)
	}

	silent := append(append([]string{}, all[:4]...), "tiny hub "+empty)
	out, err := runCanaryEnv(t, consumers(silent...), dir, sink)
	if err == nil || !strings.Contains(out, "hub reads tiny and its log is empty") {
		t.Errorf("a consumer with an empty log passed or was not named: %v\n%s", err, out)
	}

	unread := all[:4] // tiny has no consumer
	out, err = runCanaryEnv(t, consumers(unread...), dir, sink)
	if err == nil || !strings.Contains(out, "no container of the stack reads tiny") {
		t.Errorf("a secret file nothing reads passed or was not named: %v\n%s", err, out)
	}
	// Naming it as unconsumed is the explicit, reviewed way out.
	out, err = runCanaryEnv(t, append(consumers(unread...), "CTRLZ_CANARY_UNCONSUMED=tiny"), dir, sink)
	if err != nil {
		t.Errorf("a secret named as unconsumed was refused: %v\n%s", err, out)
	}
}

// The smoke must derive the consumers from the Compose file and pass them on, or the check above is a
// script option nobody uses.
func TestComposeSmokeStartsEveryServiceAndHandsTheCanaryItsConsumers(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(repoRoot(t), "scripts", "compose-smoke.sh"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{
		"dc up -d >/dev/null", // every service, not a list that leaves the stores out
		"for s in api admin worker hub valkey-api valkey-admin clickhouse", // each of them is waited for
		"export CTRLZ_CANARY_CONSUMERS=",
		"ctrlz-admin unlock --user smoke-admin",
		`grep -q '^warning: ' "$work/unlock.stderr"`,
		"the clear has something to read and UNLINK", // a login first, or an empty index hides a dropped +unlink
	} {
		if !strings.Contains(s, want) {
			t.Errorf("scripts/compose-smoke.sh lacks %q", want)
		}
	}
	if strings.Contains(s, "dc up -d api") {
		t.Error("scripts/compose-smoke.sh starts a list of services again; the stores and the hub never run")
	}
}

// TestMaintainPasswordCanary is round 15, admin-r15-3. The maintenance password of Valkey is made inside
// the container and is in no secret file, so the canary, which looks for the content of the files of the
// secrets directory, never searched for it, and a line of maintain.sh that printed it (an error branch
// with `echo "auth failed with $pw"`) passed every test. The smoke now reads it out of the running
// container into CTRLZ_CANARY_RUNTIME_DIR, whose files the canary treats as secrets with the Valkey log as
// their consumer. This test runs the script on a planted runtime directory (the printed password is found
// and named by file, a clean log passes, an empty log fails) and holds the smoke to reading it with the
// sed expression that matches the line the start line really writes.
func TestMaintainPasswordCanary(t *testing.T) {
	dir, _, _, _, _ := plantedStack(t)
	tmp := t.TempDir()
	runtime := filepath.Join(tmp, "runtime")
	if err := os.MkdirAll(runtime, 0o700); err != nil {
		t.Fatal(err)
	}
	const maintPW = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a6978"
	if err := os.WriteFile(filepath.Join(runtime, "valkey_password_maint"), []byte(maintPW), 0o600); err != nil {
		t.Fatal(err)
	}
	logOf := func(name, body string) string {
		p := filepath.Join(tmp, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return filepath.ToSlash(p)
	}
	started := logOf("valkey.log", "valkey: the ACL file is written, starting the server\nvalkey: the limiter scripts are loaded\n")
	leaky := logOf("sink.log", "valkey: auth failed with "+maintPW+"\n")
	clean := logOf("clean.log", "noise\n")
	consumers := logOf("consumers", "kek_root valkey "+started+"\nkek_admin_totp valkey "+started+"\nvalkey_password_admin valkey "+started+
		"\npg_worker_password valkey "+started+"\ntiny valkey "+started+"\nvalkey_password_maint valkey "+started+"\n")
	env := []string{"CTRLZ_CANARY_CONSUMERS=" + consumers, "CTRLZ_CANARY_RUNTIME_DIR=" + filepath.ToSlash(runtime)}
	if out, err := runCanaryEnv(t, env, dir, clean); err != nil || !strings.Contains(out, "secret-canary: ok") {
		t.Fatalf("a clean log must pass: %v\n%s", err, out)
	}
	out, err := runCanaryEnv(t, env, dir, clean, leaky)
	if err == nil || !strings.Contains(out, "content of valkey_password_maint is in sink.log") {
		t.Errorf("the maintenance password in a log passed or was not named: %v\n%s", err, out)
	}
	if strings.Contains(out, maintPW) {
		t.Error("the canary printed the password")
	}
	// A runtime secret nobody reads would be looked for in no log.
	noConsumer := logOf("consumers2", strings.ReplaceAll(readFile(t, consumers), "valkey_password_maint valkey "+started+"\n", ""))
	out, err = runCanaryEnv(t, []string{"CTRLZ_CANARY_CONSUMERS=" + noConsumer, "CTRLZ_CANARY_RUNTIME_DIR=" + filepath.ToSlash(runtime)}, dir, clean)
	if err == nil || !strings.Contains(out, "no container of the stack reads valkey_password_maint") {
		t.Errorf("a runtime secret with no consumer passed: %v\n%s", err, out)
	}
	// The smoke reads it out of the container with a sed that has to match the line the start line writes.
	smoke := readFile(t, filepath.Join(repoRoot(t), "scripts", "compose-smoke.sh"))
	m := regexp.MustCompile(`sed -n "(s/\^user maint on[^"]*)" /tmp/users.acl`).FindStringSubmatch(smoke)
	if m == nil {
		t.Fatal("scripts/compose-smoke.sh does not read the maintenance password out of /tmp/users.acl")
	}
	for _, want := range []string{"export CTRLZ_CANARY_RUNTIME_DIR=", "valkey_password_maint_$zone valkey-$zone "} {
		if !strings.Contains(smoke, strings.TrimSuffix(want, `"`)) {
			t.Errorf("scripts/compose-smoke.sh lacks %q", want)
		}
	}
	acl := logOf("users.acl", "user default off\nuser maint on >"+maintPW+" ~ctrlz:rl:* -@all +ping\nuser api on >other ~ctrlz:rl:api:* -@all +hello\n")
	sh, err := exec.LookPath("sh")
	if err != nil {
		sh = `C:\Program Files\Git\usr\bin\sh.exe`
	}
	got, err := exec.Command(sh, "-c", `sed -n "`+m[1]+`" `+acl).CombinedOutput()
	if err != nil || strings.TrimSpace(string(got)) != maintPW {
		t.Errorf("the smoke's sed reads %q (%v) from an ACL file with the maintenance line, want the password", got, err)
	}
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
