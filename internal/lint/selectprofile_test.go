package lint_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestSelectProfileForceKeepsTheOldEnv (round 17 fix gate, admin-r17-25): the marker error of Compose and the
// README send an install that is upgrading to `scripts/select-profile.sh --force`, which writes the whole .env
// again from .env.example and a profile. The host names, ports and secret directory of that install were lost
// with no way back, so the script keeps the old file first, under the first free name, and never overwrites a
// backup. The script runs in a scratch tree that has only the files it reads.
func TestSelectProfileForceKeepsTheOldEnv(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		git := `C:\Program Files\Git\usr\bin\sh.exe`
		if _, statErr := os.Stat(git); statErr != nil {
			t.Skip("no sh on PATH")
		}
		sh = git
	}
	tree := t.TempDir()
	write := func(rel, content string) {
		p := filepath.Join(tree, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	script, err := os.ReadFile(filepath.Join(repoRoot(t), "scripts", "select-profile.sh"))
	if err != nil {
		t.Fatal(err)
	}
	write("scripts/select-profile.sh", string(script))
	write("deploy/compose/.env.example", "CTRLZ_PANEL_HOST=panel.localhost\n")
	write("deploy/compose/profiles/small.env", "MEM_API=64m\n")
	run := func(args ...string) (string, error) {
		cmd := exec.Command(sh, append([]string{filepath.ToSlash(filepath.Join(tree, "scripts", "select-profile.sh"))}, args...)...)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	read := func(rel string) string {
		b, err := os.ReadFile(filepath.Join(tree, filepath.FromSlash(rel)))
		if err != nil {
			return "<" + err.Error() + ">"
		}
		return string(b)
	}
	// A first run writes the file and keeps nothing: there was nothing to keep.
	if out, err := run("small"); err != nil {
		t.Fatalf("the first run failed: %v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(tree, "deploy", "compose", ".env.bak")); err == nil {
		t.Error("a backup was made although there was no .env to keep")
	}
	// An operator's own values, then --force: the values are in the backup and the new file is the template.
	write("deploy/compose/.env", "CTRLZ_PANEL_HOST=panel.example.org\nCTRLZ_SECRETS_DIR=/srv/secrets\n")
	if out, err := run("small"); err == nil {
		t.Fatalf("an existing .env was replaced without --force:\n%s", out)
	}
	if got := read("deploy/compose/.env"); !strings.Contains(got, "panel.example.org") {
		t.Fatalf("a refused run changed the .env: %q", got)
	}
	if out, err := run("small", "--force"); err != nil || !strings.Contains(out, ".env.bak") {
		t.Fatalf("--force failed or did not say where the old file went: %v\n%s", err, out)
	}
	if got := read("deploy/compose/.env.bak"); !strings.Contains(got, "panel.example.org") || !strings.Contains(got, "/srv/secrets") {
		t.Errorf("the backup does not hold the operator's values: %q", got)
	}
	if got := read("deploy/compose/.env"); strings.Contains(got, "panel.example.org") || !strings.Contains(got, "panel.localhost") {
		t.Errorf("the new .env is not the template: %q", got)
	}
	// A second --force keeps the first backup and writes the next name.
	write("deploy/compose/.env", "CTRLZ_PANEL_HOST=second.example.org\n")
	if out, err := run("small", "--force"); err != nil {
		t.Fatalf("the second --force failed: %v\n%s", err, out)
	}
	if got := read("deploy/compose/.env.bak"); !strings.Contains(got, "panel.example.org") {
		t.Errorf("the first backup was overwritten: %q", got)
	}
	if got := read("deploy/compose/.env.bak.2"); !strings.Contains(got, "second.example.org") {
		t.Errorf("the second backup is not the file that was replaced: %q", got)
	}
}
