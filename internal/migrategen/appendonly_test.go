package migrategen_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/migrategen"
)

// TestManifestMustOnlyGrowAgainstTheEarlierOne is db-r16-9 and db-r16-18. The checks of one tree cannot
// see a hand edit of applied.sum: the hash is rewritten with the file, or the manifest and the line of the
// newest migration are deleted together, or the newest line is lowered with the lines. The one fact such an
// edit cannot also rewrite is the manifest the last published snapshot carried, so the check compares the
// two: a published line is never changed or removed and the newest line never moves back; a line may be
// added; and a change that was decided on purpose is named on the command line.
func TestManifestMustOnlyGrowAgainstTheEarlierOne(t *testing.T) {
	const (
		h1 = "1111111111111111111111111111111111111111111111111111111111111111"
		h2 = "2222222222222222222222222222222222222222222222222222222222222222"
		h3 = "3333333333333333333333333333333333333333333333333333333333333333"
		h9 = "9999999999999999999999999999999999999999999999999999999999999999"
	)
	manifest := func(newest string, lines ...string) string {
		return "# header\n# newest: " + newest + "\n" + strings.Join(lines, "\n") + "\n"
	}
	earlier := manifest("0002_b.sql", h1+"  0001_a.sql", h2+"  0002_b.sql")
	cases := []struct {
		name, current string
		allow         []string
		want          string // "" is accepted
	}{
		{"the same manifest", earlier, nil, ""},
		{"a migration added", manifest("0003_c.sql", h1+"  0001_a.sql", h2+"  0002_b.sql", h3+"  0003_c.sql"), nil, ""},
		{"a hash edited by hand", manifest("0002_b.sql", h1+"  0001_a.sql", h9+"  0002_b.sql"), nil, "0002_b.sql was listed with another hash"},
		{"the edit regenerated with the newest line deleted", manifest("0001_a.sql", h1+"  0001_a.sql"), nil, "its line is gone"},
		{"the newest line lowered with the lines", manifest("0001_a.sql", h1+"  0001_a.sql"), nil, "the newest line moved back"},
		{"a line deleted from the middle", manifest("0003_c.sql", h2+"  0002_b.sql", h3+"  0003_c.sql"), nil, "0001_a.sql was listed in the earlier manifest and its line is gone"},
		{"an edit decided on purpose", manifest("0002_b.sql", h1+"  0001_a.sql", h9+"  0002_b.sql"), []string{"0002_b.sql"}, ""},
		{"an edit that was not the one decided", manifest("0002_b.sql", h9+"  0001_a.sql", h2+"  0002_b.sql"), []string{"0002_b.sql"}, "0001_a.sql was listed with another hash"},
	}
	for _, c := range cases {
		dir := t.TempDir()
		cur, was := filepath.Join(dir, "now.sum"), filepath.Join(dir, "was.sum")
		if err := os.WriteFile(cur, []byte(c.current), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(was, []byte(earlier), 0o644); err != nil {
			t.Fatal(err)
		}
		err := migrategen.VerifyAppendOnly(cur, was, c.allow)
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%s: %v", c.name, err)
		case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
			t.Errorf("%s: %v, want an error containing %q", c.name, err, c.want)
		}
	}
	// A manifest that is missing is an error, never an accepted empty one.
	if err := migrategen.VerifyAppendOnly(filepath.Join(t.TempDir(), "absent.sum"), "applied.sum", nil); err == nil {
		t.Error("a missing manifest was accepted")
	}
}

// TestTheRealManifestExtendsItself runs the check on the real file against itself, which is the
// publisher's call on a tree that changed no migration, and shows the command's input is readable.
func TestTheRealManifestExtendsItself(t *testing.T) {
	if err := migrategen.VerifyAppendOnly("../../migrations/postgres/applied.sum", "../../migrations/postgres/applied.sum", nil); err != nil {
		t.Fatal(err)
	}
}
