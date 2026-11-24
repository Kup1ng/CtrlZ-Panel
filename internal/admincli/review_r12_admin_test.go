package admincli_test

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/admincli"
)

// halfWriter is an out-file that the OS created for real (O_EXCL, 0600) and whose write then fails
// after a part of the line, as a full or failing mount does.
type halfWriter struct{ f *os.File }

func (h halfWriter) Write(p []byte) (int, error) {
	n, _ := h.f.Write(p[:len(p)/2])
	return n, io.ErrShortWrite
}
func (h halfWriter) Close() error { return h.f.Close() }

func failingOpen(name string, flag int, perm os.FileMode) (io.WriteCloser, error) {
	f, err := os.OpenFile(name, flag, perm)
	if err != nil {
		return nil, err
	}
	return halfWriter{f}, nil
}

// TestAFailedWriteOfTheOneTimePasswordLeavesNoFileBehind is admin-r12-1. The change is committed
// before the password is written, so a write that fails leaves the operator one way on: run the
// command again with the same --out-file. The file created with O_EXCL used to stay (cut or empty),
// and the same path then answered "the file already exists".
func TestAFailedWriteOfTheOneTimePasswordLeavesNoFileBehind(t *testing.T) {
	for _, cmd := range []string{"bootstrap", "reset-password", "reset-totp"} {
		t.Run(cmd, func(t *testing.T) {
			r := newRig(t)
			args := []string{cmd}
			if cmd == "bootstrap" {
				r.noAdmin()
				args = append(args, "--username", "root")
			} else {
				if code := r.run("bootstrap", "--username", "root"); code != 1 { // the seeded admin exists: refused
					t.Fatalf("setup: exit %d", code)
				}
				var name string
				r.env.Scan(t, `SELECT username FROM ctrlz.admin_users LIMIT 1`, nil, &name)
				args = append(args, "--user", name)
			}
			file := filepath.Join(t.TempDir(), "otp")
			env := r.cliEnv(&r.out, &r.errb)
			env.OpenOut = failingOpen
			r.out.Reset()
			r.errb.Reset()
			code := admincli.RunWith(r.env.Ctx, append(append([]string(nil), args...), "--out-file", file), env)
			if code != 1 || !strings.Contains(r.errb.String(), "could not be written") || r.out.Len() != 0 {
				t.Fatalf("exit %d, stdout %q, stderr %q", code, r.out.String(), r.errb.String())
			}
			if _, err := os.Stat(file); err == nil {
				t.Fatal("a failed write left the out-file behind: the same path is now refused")
			}
			// The command the message tells the operator to run works with the same path.
			rerun := append([]string(nil), args...)
			if cmd == "bootstrap" {
				rerun = []string{"reset-password", "--user", "root"}
			}
			r.lastOut = file
			if code := r.runBare(append(rerun, "--out-file", file)...); code != 0 {
				t.Fatalf("rerun with the same path: exit %d, stderr %q", code, r.errb.String())
			}
			if r.printed() == "" {
				t.Fatal("no password in the file of the rerun")
			}
		})
	}
}
