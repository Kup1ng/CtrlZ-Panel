package lint_test

import (
	"go/build"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// ignoredTestFiles are the test files that the Go tool does NOT compile for linux/amd64, which is
// what every CI shard builds, each with the reason and the place that does run it. A test file that
// is not compiled where the review is judged holds a property that no published snapshot checks
// (db-r16-2: clock_windows_test.go held the boundary tests of the clock-source rule and ran on one
// developer machine only; db-r16-13: the timing test sits behind a build tag no job sets).
//
// Contract: this guard judges every package directory of the module (shared/ is a separate module
// and is judged by its own repository). It is a fail-closed allow list: a *_test.go file that
// go/build ignores for linux/amd64 and is not named here fails, whatever the reason it is ignored
// (a file name suffix, a //go:build line, a +build line), and an entry whose file is compiled (or
// gone) fails, so the list cannot collect names. It does not judge whether the named job exists:
// that is a fact of the CI repository, written down here so a reader finds it.
var ignoredTestFiles = map[string]string{
	"internal/api/timing_test.go": "build tag timing; the nightly job of spec 18.5 runs `go test -tags timing -run TestTiming ./internal/api` (wall-clock medians are too noisy for a shard)",
}

func TestNoTestFileIsSilentlyIgnoredOnLinux(t *testing.T) {
	root := repoRoot(t)
	got, unreadable := ignoredTestsUnder(t, root, "linux", "amd64")
	for _, u := range unreadable {
		t.Errorf("go/build cannot read %s: its test files cannot be judged, so fix the directory", u)
	}
	for _, p := range got {
		if _, ok := ignoredTestFiles[p]; !ok {
			t.Errorf("%s is not compiled for linux/amd64, so no CI shard runs it: rename it (no _<goos>/_<goarch> suffix, no //go:build line) or list it in ignoredTestFiles with the job that runs it", p)
		}
	}
	seen := map[string]bool{}
	for _, p := range got {
		seen[p] = true
	}
	var names []string
	for p := range ignoredTestFiles {
		names = append(names, p)
	}
	sort.Strings(names)
	for _, p := range names {
		if !seen[p] {
			t.Errorf("ignoredTestFiles names %s, which linux/amd64 compiles (or which does not exist): remove the entry", p)
		}
	}
}

// ignoredTestsUnder lists, as slash paths relative to root, the test files go/build leaves out for
// the given platform. go/build is the tool's own decision (the same code `go list` uses), so no
// spelling of a constraint can hide from it.
func ignoredTestsUnder(t *testing.T, root, goos, goarch string) (ignored, unreadable []string) {
	t.Helper()
	ctx := build.Default
	ctx.GOOS, ctx.GOARCH, ctx.CgoEnabled = goos, goarch, false
	ctx.UseAllFiles = false
	var out []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		if rel == "shared" || rel == ".git" || d.Name() == "node_modules" || d.Name() == ".next" || d.Name() == "testdata" {
			return fs.SkipDir
		}
		pkg, err := ctx.ImportDir(p, 0)
		if err != nil {
			if _, none := err.(*build.NoGoError); none {
				// A directory whose every file is ignored has no package at all; its ignored files are
				// still reported through the error's package value.
				if pkg == nil {
					return nil
				}
			} else if _, multi := err.(*build.MultiplePackageError); !multi {
				// Fail closed (db-r16-27): a directory go/build cannot read (a malformed constraint, an
				// unreadable file) hides every ignored test file in it, and the guard promises to judge
				// whatever the reason a file is ignored. It is a finding, never a skip.
				unreadable = append(unreadable, rel+": "+err.Error())
				return nil
			}
		}
		for _, f := range pkg.IgnoredGoFiles {
			if strings.HasSuffix(f, "_test.go") {
				out = append(out, strings.TrimPrefix(filepath.ToSlash(filepath.Join(rel, f)), "./"))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(out)
	sort.Strings(unreadable)
	return out, unreadable
}

// TestIgnoredTestGuardCanFail plants one file for each way go/build leaves a test out and requires
// the scan to find it, and one compiled file it must leave alone.
func TestIgnoredTestGuardCanFail(t *testing.T) {
	dir := t.TempDir()
	write := func(name, src string) {
		t.Helper()
		if err := writeFile(filepath.Join(dir, name), src); err != nil {
			t.Fatal(err)
		}
	}
	write("a.go", "package p\n")
	write("ok_test.go", "package p\n")
	write("x_windows_test.go", "package p\n")
	write("y_arm64_test.go", "package p\n")
	write("z_test.go", "//go:build nightly\n\npackage p\n")
	write("w_test.go", "//go:build !linux\n\npackage p\n")
	got, unreadable := ignoredTestsUnder(t, dir, "linux", "amd64")
	if len(unreadable) != 0 {
		t.Fatalf("the planted good-faith directory was unreadable: %v", unreadable)
	}
	want := []string{"w_test.go", "x_windows_test.go", "y_arm64_test.go", "z_test.go"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("scan found %v, want %v", got, want)
	}
}

func writeFile(path, src string) error { return os.WriteFile(path, []byte(src), 0o644) }

// TestIgnoredTestGuardFailsForADirectoryGoBuildCannotRead plants a directory that go/build refuses (a
// malformed //go:build line) beside a well-formed one, and requires the scan to report it rather than skip
// it, so a test file in it cannot hide (db-r16-27).
func TestIgnoredTestGuardFailsForADirectoryGoBuildCannotRead(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad")
	if err := os.MkdirAll(bad, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, src := range map[string]string{
		"a.go":        "package p\n",
		"bad_test.go": "//go:build (linux &&\n\npackage p\n",
	} {
		if err := writeFile(filepath.Join(bad, name), src); err != nil {
			t.Fatal(err)
		}
	}
	good := filepath.Join(dir, "good")
	if err := os.MkdirAll(good, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := writeFile(filepath.Join(good, "a.go"), "package p\n"); err != nil {
		t.Fatal(err)
	}
	_, unreadable := ignoredTestsUnder(t, dir, "linux", "amd64")
	if len(unreadable) != 1 || !strings.HasPrefix(unreadable[0], "bad:") {
		t.Fatalf("the unreadable directory was not reported: %v", unreadable)
	}
}
