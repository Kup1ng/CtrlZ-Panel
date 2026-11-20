package migrategen_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/migrategen"
)

// The earlier manifest, found where the repository itself keeps it (P1 auth review round 16, db-r16-28; rule
// applied-migrations-are-frozen).
//
// VerifyAppendOnly was a command nothing called: TestTheRealManifestExtendsItself compared the manifest with
// itself, and the publisher that holds the snapshot it replaces is outside this repository. A hand edit of a
// hash and of its line passed every check of one tree. The one fact such an edit cannot also rewrite is an
// EARLIER copy of the manifest, and git history is one the repository carries wherever it is cloned with
// history. This test finds it and runs the same comparison:
//
//   - CTRLZ_EARLIER_MANIFEST, when set, is the file to compare with (the publisher passes the snapshot it
//     replaces; scripts/ci.sh runs `genmig -against` with it too);
//   - otherwise the manifest of the merge base with CTRLZ_BASE_REF, origin/main or main (a branch), or of the
//     parent commit when HEAD is that branch itself (a commit on main), read with `git show`.
//
// Contract. It judges applied.sum against that one earlier copy and nothing else (the files against the
// manifest are genmig -check). Where there is no earlier copy (no git, a clone without history, a first
// commit) it skips, and under CTRLZ_CI=1 (the CI jobs, which fetch history) that is a failure, because a guard
// that quietly looks at nothing is the thing this finding was about. A change that was decided on purpose is
// named in CTRLZ_MANIFEST_ALLOW, comma separated.

func git(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	out, err := cmd.Output()
	return strings.TrimSpace(string(out)), err
}

// earlierManifest returns the path of the earlier applied.sum and a description of where it came from.
func earlierManifest(t *testing.T, root string) (string, string) {
	t.Helper()
	if p := os.Getenv("CTRLZ_EARLIER_MANIFEST"); p != "" {
		return p, "CTRLZ_EARLIER_MANIFEST"
	}
	head, err := git(root, "rev-parse", "HEAD")
	if err != nil {
		return "", ""
	}
	var rev string
	for _, ref := range []string{os.Getenv("CTRLZ_BASE_REF"), "origin/main", "main"} {
		if ref == "" {
			continue
		}
		base, err := git(root, "merge-base", "HEAD", ref)
		if err != nil || base == "" {
			continue
		}
		if base != head {
			rev = base
			break
		}
	}
	if rev == "" {
		// HEAD is the base branch itself (or an ancestor of it): compare with the commit before it.
		parent, err := git(root, "rev-parse", "--verify", "-q", "HEAD~1")
		if err != nil || parent == "" {
			return "", ""
		}
		rev = parent
	}
	text, err := git(root, "show", rev+":migrations/postgres/applied.sum")
	if err != nil || text == "" {
		return "", ""
	}
	p := filepath.Join(t.TempDir(), "earlier.sum")
	if err := os.WriteFile(p, []byte(text+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return p, "git " + rev[:12]
}

func TestTheManifestOnlyGrowsAgainstTheEarlierCopyTheRepositoryCarries(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	earlier, from := earlierManifest(t, root)
	if earlier == "" {
		if os.Getenv("CTRLZ_CI") != "" {
			t.Fatal("no earlier applied.sum to compare with (no git history and no CTRLZ_EARLIER_MANIFEST): fetch the history in the CI job, or the manifest is checked against itself only")
		}
		t.Skip("no earlier applied.sum to compare with (no git history and no CTRLZ_EARLIER_MANIFEST)")
	}
	var allow []string
	for _, f := range strings.Split(os.Getenv("CTRLZ_MANIFEST_ALLOW"), ",") {
		if f = strings.TrimSpace(f); f != "" {
			allow = append(allow, f)
		}
	}
	if err := migrategen.VerifyAppendOnly(filepath.Join(root, "migrations/postgres/applied.sum"), earlier, allow); err != nil {
		t.Fatalf("applied.sum against %s: %v", from, err)
	}
}

// TestTheGitFinderSeesAHandEditedHash plants the edit the finding is about, in a throwaway repository: a
// published line whose hash is rewritten and committed. The finder must hand back the manifest of the
// commit before, and the comparison must refuse the edit; a commit that only adds a line is accepted.
func TestTheGitFinderSeesAHandEditedHash(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	const (
		h1 = "1111111111111111111111111111111111111111111111111111111111111111"
		h2 = "2222222222222222222222222222222222222222222222222222222222222222"
		h3 = "3333333333333333333333333333333333333333333333333333333333333333"
		h9 = "9999999999999999999999999999999999999999999999999999999999999999"
	)
	repo := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		if _, err := git(repo, append([]string{"-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false"}, args...)...); err != nil {
			t.Fatalf("git %v: %v", args, err)
		}
	}
	write := func(text string) {
		t.Helper()
		p := filepath.Join(repo, "migrations/postgres/applied.sum")
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
		run("add", "-A")
		run("commit", "-q", "-m", "x")
	}
	manifest := func(newest string, lines ...string) string {
		return "# header\n# newest: " + newest + "\n" + strings.Join(lines, "\n") + "\n"
	}
	run("init", "-q")
	write(manifest("0002_b.sql", h1+"  0001_a.sql", h2+"  0002_b.sql"))

	write(manifest("0003_c.sql", h1+"  0001_a.sql", h2+"  0002_b.sql", h3+"  0003_c.sql"))
	earlier, from := earlierManifest(t, repo)
	if earlier == "" {
		t.Fatal("the finder found no earlier manifest in a repository with two commits")
	}
	if err := migrategen.VerifyAppendOnly(filepath.Join(repo, "migrations/postgres/applied.sum"), earlier, nil); err != nil {
		t.Errorf("a commit that only added a line was refused (%s): %v", from, err)
	}

	write(manifest("0003_c.sql", h1+"  0001_a.sql", h9+"  0002_b.sql", h3+"  0003_c.sql"))
	earlier, from = earlierManifest(t, repo)
	if err := migrategen.VerifyAppendOnly(filepath.Join(repo, "migrations/postgres/applied.sum"), earlier, nil); err == nil || !strings.Contains(err.Error(), "0002_b.sql was listed with another hash") {
		t.Errorf("a hand-edited hash that was committed was not refused (%s): %v", from, err)
	}
}
