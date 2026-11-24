package admincli_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/admincli"
	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
)

// oneTimeShape is what a one-time password looks like (24 characters of base32),
// so the check finds a password it was not told about.
var oneTimeShape = regexp.MustCompile(`[A-Z2-7]{24}`)

// TestSecretNeverReachesStdoutOrStderr is the behaviour half of the rule
// admin-cli-secret-output (P1 auth review round 5, spec 10.1, 18.4), and the
// replacement for the terminal-rule test of rounds 1 to 4. ctrlz-admin cannot tell
// a terminal from a log and does not try: every command is run with stdout and
// stderr as a buffer and as a character device (the null device, which is one on
// every platform and is what a TTY looks like to the old test), and none prints a
// secret. The old rule varied the process id and its parent; no code reads them
// now (the lint TestAdminCLINeverWritesASecretOutsideAFile bans the calls), so
// the two cannot change an outcome, and the character-device run is the one
// observable the old rule depended on.
//
// The compose smoke repeats this with docker logs of real containers.
func TestSecretNeverReachesStdoutOrStderr(t *testing.T) {
	r := newRig(t)
	r.noAdmin()
	dev, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer dev.Close()

	secrets := map[string]bool{}
	// A password command gives stdout the path and nothing else, and the password
	// only the file.
	issue := func(args ...string) {
		t.Helper()
		if code := r.run(args...); code != 0 {
			t.Fatalf("%v: exit %d, stderr %q", args, code, r.errb.String())
		}
		if want := r.lastOut + "\n"; r.out.String() != want {
			// The length only: a failure here may mean the stdout holds a password.
			t.Fatalf("%v: stdout is %d bytes, want only the path (%d bytes)", args, r.out.Len(), len(r.lastOut)+1)
		}
		pw := r.printed()
		secrets[pw] = true
		if oneTimeShape.MatchString(r.out.String()+r.errb.String()) || strings.Contains(r.out.String()+r.errb.String(), pw) {
			t.Fatalf("%v: a one-time password is on stdout or stderr", args)
		}
	}
	issue("bootstrap", "--username", "root")
	issue("reset-password", "--user", "root")
	issue("reset-totp", "--user", "root")

	// The same commands with the character device as both streams. The exit code is
	// the same, the file holds the password, and what the device received is
	// unobservable, so what must hold is that the code path is the same one: the
	// file is written and no error about a terminal comes back.
	devEnv := r.cliEnv(dev, dev)
	for _, args := range [][]string{
		{"reset-password", "--user", "root", "--out-file", filepath.Join(r.outDir, "dev-reset")},
		{"reset-totp", "--user", "root", "--out-file", filepath.Join(r.outDir, "dev-totp")},
	} {
		if code := admincli.RunWith(r.env.Ctx, args, devEnv); code != 0 {
			t.Fatalf("%v on a character device: exit %d", args, code)
		}
		raw, err := os.ReadFile(args[len(args)-1])
		if err != nil || !oneTimeShape.Match(raw) {
			t.Fatalf("%v on a character device: no password in the file (%v)", args, err)
		}
	}

	// Without --out-file every password command is refused as a usage error with
	// nothing changed, nothing created and nothing secret printed, whatever the
	// streams are.
	var hash string
	r.env.Scan(t, `SELECT password_hash FROM ctrlz.admin_users WHERE username = 'root'`, nil, &hash)
	auditBefore := r.count(`SELECT count(*) FROM ctrlz.audit_log`)
	for _, args := range [][]string{{"bootstrap", "--username", "second"}, {"reset-password", "--user", "root"}, {"reset-totp", "--user", "root"}} {
		for _, streams := range []struct {
			name string
			env  admincli.Env
		}{{"buffers", r.cliEnv(&r.out, &r.errb)}, {"character device", devEnv}} {
			r.out.Reset()
			r.errb.Reset()
			if code := admincli.RunWith(r.env.Ctx, args, streams.env); code != admincli.ExitUsage {
				t.Fatalf("%v on %s: exit %d, want a usage error", args, streams.name, code)
			}
			if streams.name == "buffers" && (r.out.Len() != 0 || oneTimeShape.MatchString(r.errb.String()) || !strings.Contains(r.errb.String(), "--out-file")) {
				t.Fatalf("%v: stdout %d bytes (want none), stderr %d bytes, stderr names --out-file %v", args, r.out.Len(), r.errb.Len(), strings.Contains(r.errb.String(), "--out-file"))
			}
		}
	}
	var after string
	r.env.Scan(t, `SELECT password_hash FROM ctrlz.admin_users WHERE username = 'root'`, nil, &after)
	if after != hash || r.count(`SELECT count(*) FROM ctrlz.audit_log`) != auditBefore || r.count(`SELECT count(*) FROM ctrlz.admin_users`) != 1 {
		t.Fatal("a refused command changed something")
	}

	// Every other command, on the same streams, prints no password: the names of
	// domains and counts, nothing that looks like a secret and none of the ones
	// issued above.
	var all bytes.Buffer
	for _, args := range [][]string{
		{"unlock", "--user", "root"},
		{"keys", "status", "admin_totp"},
		{"keys", "status", "sms_cred"},
		{"rekey", "admin_totp"},
		{"audit-note", "key.rotated", "--domain", "admin_totp", "--key-number", "2"},
		{"audit", "verify"},
		{"keys", "declare-lost", "sms_cred", "--key-number", "9", "--yes"},
		{"nonsense"},
		{"--help"},
	} {
		r.runBare(args...)
		all.WriteString(r.out.String())
		all.WriteString(r.errb.String())
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "kek_root"), bytes.Repeat([]byte{0x42}, 32), 0o400); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := admincli.RunKeys(context.Background(), []string{"derive", "--dir", dir}, admincli.Env{Stdout: &out, Stderr: &errb}); code != 0 {
		t.Fatalf("derive: %d %q", code, errb.String())
	}
	all.Write(out.Bytes())
	all.Write(errb.Bytes())
	// The key text itself, as a file holds it, must not be in the output either.
	for _, d := range keyring.Domains() {
		raw, err := os.ReadFile(filepath.Join(dir, "kek_"+d))
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range strings.Fields(string(raw)) {
			if len(f) >= 16 && strings.Contains(all.String(), f) {
				t.Fatalf("the key text of %s is in the output", d)
			}
		}
	}
	for pw := range secrets {
		if strings.Contains(all.String(), pw) {
			t.Fatal("a one-time password is in the output of another command")
		}
	}
	if oneTimeShape.MatchString(all.String()) {
		t.Fatal("something shaped like a one-time password is in the output")
	}
}
