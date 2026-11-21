package lint_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// The Go files of the tree, and which lint reads which set (owner decision D63, item 8; the round 16
// run on GitHub, 44732890797, judged the CI overlay of the published tree as Panel packages because
// the guards walked the file tree).
//
// Two sets, on purpose.
//
//   - The guards of the product (parseRepo, parseSharedTree: the import rules, the SQL rules, the
//     SMS rules and the rest) read the packages of one module as the toolchain defines them:
//     `go list ./...` leaves out the directories whose names begin with a dot or an underscore,
//     testdata and the modules nested in the module (shared/ is a module of its own, asked for on
//     its own), and then the packages of the module that those files import are added, because the
//     compiler builds an imported directory whatever it is called (parseModuleFiles). A name-skip list
//     of directories is a guard of the forbidden-names kind and was wrong the first time a script
//     added one. A package is read with every Go file of its directory that the toolchain knows: the
//     files built on the platform asked for, the files a build constraint leaves out
//     (IgnoredGoFiles), cgo files and test files, for linux and windows and the host
//     (goListPlatforms), so a directory whose only Go files are named for another platform is not
//     missed.
//   - The escape-hatch ban reads EVERY Go file under the repository (parseEveryModule), whatever the
//     directory is called and whatever its build constraints say, except the store of the version
//     control system, the installed packages of the web code and the CI overlay of the published tree
//     (unreadPrefixes), which no Go package may import (unreadImportProblems). It is the one guard
//     that does not trust go list to say what a build compiles, because what it refuses is what
//     defeats a guard: a file in a directory go list does not name is still built by `go run file.go`,
//     by an import of its path, or on another architecture.
//
// What neither reads: files that no Go toolchain command reads at all and that are outside these
// directories. Toolchain flags (-toolexec, -overlay, -ldflags) are the business of the commands that
// pass them, not of a lint of the source.

// goListPlatforms are the GOOS values go list is asked for: the two platforms the project builds for
// (linux for the images and the CI, windows for the developers' machines) and the host, whatever it
// is. The same set on every host, so a file of one of them is read wherever the lint runs.
func goListPlatforms() []string {
	out := []string{"linux", "windows"}
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		out = append(out, runtime.GOOS)
	}
	return out
}

// listEntry is the memo of one go list run: asking again for the same module and platform in the same
// test process costs nothing, which matters on a loaded machine (a run takes seconds).
type listEntry struct {
	once sync.Once
	out  []byte
	err  error
}

var listCache sync.Map

// goListOutput runs go list over the module in modDir for one platform.
func goListOutput(modDir, goos string) ([]byte, error) {
	v, _ := listCache.LoadOrStore(canonPath(modDir)+"|"+goos, &listEntry{})
	e := v.(*listEntry)
	e.once.Do(func() {
		cmd := exec.Command("go", "list", "-find", "-e", goListRequest(), "./...")
		cmd.Dir = modDir
		// cgo is on whatever the host has set: with it off a file that imports "C" is left out of the
		// package and listed under no kind at all, and the question is what the toolchain WOULD build in.
		// GOWORK and GOFLAGS are cleared so that neither a workspace file nor a developer's flags change
		// the set of packages or the files they are made of.
		cmd.Env = append(os.Environ(), "CGO_ENABLED=1", "GOWORK=off", "GOFLAGS=", "GOOS="+goos)
		e.out, e.err = cmd.Output()
		if e.err != nil {
			e.err = fmt.Errorf("go list failed in %s for GOOS=%s: %w", modDir, goos, e.err)
		}
	})
	return e.out, e.err
}

// goListAll runs go list for every module and platform at once, so the first test of a process that
// needs them waits for the slowest run and not for the sum of four (q9-6: on a loaded host one run
// took minutes and the tests that read the tree timed out in sequence). The runs share nothing, and
// goListOutput remembers each result.
func goListAll(mods []string) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, 4)
	for _, m := range mods {
		for _, goos := range goListPlatforms() {
			wg.Add(1)
			go func() {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				_, _ = goListOutput(m, goos)
			}()
		}
	}
	wg.Wait()
}

// treeFile is one Go file of a module.
type treeFile struct {
	abs, rel string // rel is slash-separated and relative to the repository root
	test     bool
}

// moduleGoFiles lists the Go files of every package go list names in the module whose root is modDir,
// with paths relative to root (the repository), sorted.
func moduleGoFiles(root, modDir string) ([]treeFile, error) {
	base := canonPath(root)
	seen := map[string]treeFile{}
	goListAll([]string{modDir})
	for _, goos := range goListPlatforms() {
		out, err := goListOutput(modDir, goos)
		if err != nil {
			return nil, err
		}
		dec := json.NewDecoder(bytes.NewReader(out))
		for dec.More() {
			var r struct {
				Dir                                                          string
				GoFiles, CgoFiles, IgnoredGoFiles, TestGoFiles, XTestGoFiles []string
			}
			if err := dec.Decode(&r); err != nil {
				return nil, fmt.Errorf("go list output of %s cannot be read: %w", modDir, err)
			}
			dir := canonPath(r.Dir)
			for _, group := range [][]string{r.GoFiles, r.CgoFiles, r.IgnoredGoFiles, r.TestGoFiles, r.XTestGoFiles} {
				for _, n := range group {
					abs := filepath.Join(dir, n)
					rel, err := filepath.Rel(base, abs)
					if err != nil {
						return nil, err
					}
					seen[abs] = treeFile{abs: abs, rel: filepath.ToSlash(rel), test: strings.HasSuffix(n, "_test.go")}
				}
			}
		}
	}
	out := make([]treeFile, 0, len(seen))
	for _, f := range seen {
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].rel < out[j].rel })
	return out, nil
}

// parseModuleFiles parses the files moduleGoFiles lists, test files only if tests is set, and then
// the packages of the same module that those files import and go list does not name (a package under
// testdata, a directory that begins with a dot or an underscore, which `go list ./...` leaves out and
// the compiler builds all the same when somebody imports it, q9-12): each is read with the files the
// compiler would take (not the ones that begin with _ or a dot), and what they import is followed in
// turn. A guard that reads the module through parseRepo therefore sees every package the build of
// the module compiles. Imports of another module are the business of the guards that read that
// module, and the ban reads every Go file of every module (parseEveryModule).
func parseModuleFiles(fset *token.FileSet, root, modDir string, mode parser.Mode, tests bool) ([]file, error) {
	listed, err := moduleGoFiles(root, modDir)
	if err != nil {
		return nil, err
	}
	var out []file
	seenDirs := map[string]bool{}
	for _, lf := range listed {
		if lf.test && !tests {
			continue
		}
		f, err := parser.ParseFile(fset, lf.abs, nil, mode)
		if err != nil {
			return nil, err
		}
		out = append(out, file{path: lf.rel, test: lf.test, ast: f})
		seenDirs[filepath.ToSlash(filepath.Dir(lf.rel))] = true
	}
	modPath, err := modulePathOf(modDir)
	if err != nil {
		return nil, err
	}
	base := canonPath(root)
	for i := 0; i < len(out); i++ {
		if out[i].test {
			continue
		}
		for _, im := range out[i].ast.Imports {
			p, err := strconv.Unquote(im.Path.Value)
			if err != nil || (p != modPath && !strings.HasPrefix(p, modPath+"/")) {
				continue
			}
			dir := canonPath(filepath.Join(modDir, filepath.FromSlash(strings.TrimPrefix(strings.TrimPrefix(p, modPath), "/"))))
			rel, err := filepath.Rel(base, dir)
			if err != nil || seenDirs[filepath.ToSlash(rel)] {
				continue
			}
			seenDirs[filepath.ToSlash(rel)] = true
			ents, err := os.ReadDir(dir)
			if err != nil {
				continue // an import of a directory that is not there does not compile; nothing to read
			}
			for _, e := range ents {
				n := e.Name()
				if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") || strings.HasPrefix(n, "_") || strings.HasPrefix(n, ".") {
					continue
				}
				f, err := parser.ParseFile(fset, filepath.Join(dir, n), nil, mode)
				if err != nil {
					return nil, err
				}
				out = append(out, file{path: filepath.ToSlash(filepath.Join(rel, n)), ast: f})
			}
		}
	}
	return out, nil
}

// modulePathOf reads the module path from the go.mod of a module directory.
func modulePathOf(modDir string) (string, error) {
	b, err := os.ReadFile(filepath.Join(modDir, "go.mod"))
	if err != nil {
		return "", err
	}
	for _, l := range strings.Split(string(b), "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(l), "module "); ok {
			return strings.Trim(strings.TrimSpace(rest), `"`), nil
		}
	}
	return "", fmt.Errorf("%s has no module line", modDir)
}

// unreadDirName says whether a directory name holds other people's files, which the ban does not read:
// the version control store and the installed packages of the web code.
func unreadDirName(n string) bool { return n == ".git" || n == "node_modules" }

// unreadPrefixes are paths under the repository the ban does not read, with the reason. .github/ci
// exists in the published tree only (the overlay of the CI jobs: ci/github/<repo>/.github/ci in the
// workspace): programs the workflow runs with `go run` from outside every package. Nothing may import
// them, which unreadImportProblems checks, so no binary of the module holds them.
var unreadPrefixes = map[string]string{
	".github/ci": "the CI overlay of the published tree: programs the GitHub workflow runs with go run, imported by nothing",
}

func unreadRel(rel string) bool {
	for _, part := range strings.Split(rel, "/") {
		if unreadDirName(part) {
			return true
		}
	}
	for p := range unreadPrefixes {
		if rel == p || strings.HasPrefix(rel, p+"/") {
			return true
		}
	}
	return false
}

// parseEveryModule parses EVERY Go file under root, test files included, whatever the directory is
// called and whatever its build constraints say: a directory that go list leaves out (testdata, a name
// that begins with a dot or an underscore, a package whose files are all excluded on the platforms
// asked, a lone `//go:build ignore` generator) is no less a place for an escape hatch, and a file such
// as _x.go or x_arm64.go is built by some command or on some host (q9-4, q9-8, q9-12). The only
// directories it does not read are those of unreadDirName and unreadPrefixes. It is for the ban, which
// judges every module of the tree (the Panel's, shared/ and any added later) by the same lists.
func parseEveryModule(fset *token.FileSet, root string, mode parser.Mode) ([]file, error) {
	base := canonPath(root)
	var out []file
	err := filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(base, p)
		if rerr != nil {
			return rerr
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if rel != "." && unreadRel(rel) {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, p, nil, mode)
		if perr != nil {
			return perr
		}
		out = append(out, file{path: rel, test: strings.HasSuffix(d.Name(), "_test.go"), ast: f})
		return nil
	})
	return out, err
}

// unreadImportProblems reports every non-test file that imports a package of the module or of shared/
// from a directory the ban does not read: the build compiles it, so nothing the ban says about the
// directories it reads holds for it.
func unreadImportProblems(fset *token.FileSet, files []file) []string {
	var out []string
	for _, f := range files {
		if f.test {
			continue
		}
		for _, im := range f.ast.Imports {
			p, err := strconv.Unquote(im.Path.Value)
			if err != nil {
				continue
			}
			var rel string
			switch {
			case strings.HasPrefix(p, module+"/"):
				rel = strings.TrimPrefix(p, module+"/")
			case strings.HasPrefix(p, sharedModule+"/"):
				rel = "shared/" + strings.TrimPrefix(p, sharedModule+"/")
			default:
				continue
			}
			if unreadRel(rel) {
				out = append(out, fmt.Sprintf("%s: imports %s, a directory the ban does not read (the web code's packages, the version control store, the CI overlay of the published tree): code the build compiles is code the ban judges (q9-12)", fset.Position(im.Pos()), p))
			}
		}
	}
	sort.Strings(out)
	return out
}

// plantTree writes files under a fresh directory for the tests of the readers of the tree.
func plantTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, body := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// pkgSrc is a Go file of the package named after its directory that imports unsafe.
func pkgSrc(rel string) string {
	return "package " + path.Base(path.Dir(rel)) + "\n\nimport _ \"unsafe\"\n"
}

func relPaths(files []file) []string {
	var out []string
	for _, f := range files {
		out = append(out, f.path)
	}
	sort.Strings(out)
	return out
}

// TestJudgedSetIsWhatGoListNames plants Go packages where a walk of the tree would find them and go
// list does not (under a directory that begins with a dot, one that begins with an underscore, and
// testdata, the places the published tree puts the CI overlay .github/ci), and where go list finds
// them and a careless reader would not (a file left out by a build constraint, a package of the other
// platform only, a nested module), and shows that the files the guards of the product read
// (parseModuleFiles) are the go list set plus the packages that set imports. A guard that walked the
// tree judged .github/ci/plan as a Panel package and failed the published tree (run 44732890797); a
// guard that read go list alone never saw a package under testdata that the build imports (q9-12).
func TestJudgedSetIsWhatGoListNames(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("no go tool on PATH")
	}
	files := map[string]string{
		"go.mod":        "module " + module + "\n\ngo 1.22\n",
		"shared/go.mod": "module " + sharedModule + "\n\ngo 1.22\n",
		// Read: packages of the module and of shared/, a file a constraint leaves out, a test file, the
		// files of the platform that is not the host's.
		"internal/e/e.go":       "package e\n",
		"internal/e/ignored.go": "//go:build ignore\n\n" + pkgSrc("internal/e/ignored.go"),
		// A nested module is a module of its own, read through its own go list wherever it stands, under a
		// directory that begins with a dot included.
		"tools/inner/go.mod": "module example.com/inner\n\ngo 1.22\n",
		".hidden/mod/go.mod": "module example.com/hidden\n\ngo 1.22\n",
		// A file that imports C is read as the toolchain reads it, with cgo on whatever the host has set.
		"internal/cgo/c.go": "package cgo\n\n// int one(void) { return 1; }\nimport \"C\"\n",
		"internal/y/y.go":   "package y\n",
		// An importer of directories go list does not name: the compiler builds them all the same.
		"internal/a/a.go": "package a\n\nimport (\n\t_ \"" + module + "/internal/x/testdata/c\"\n\t_ \"" + module + "/_hid/h\"\n\t_ \"" + module + "/internal/x/.dot/d\"\n)\n",
		// Not read: a file the compiler ignores in a directory it builds.
		"internal/x/testdata/c/_skip.go": "package c\n\nimport _ \"unsafe\"\n",
		// Not read: what nothing imports and go list leaves out.
		".github/ci/plan/main.go": "package main\n\nimport \"os/exec\"\n",
		"_scratch/d/d.go":         "package d\n",
		"testdata/t.go":           "package t\n",
		"internal/x/.hidden/h.go": "package h\n",
		"internal/y/_ignored.go":  "package y\n",
	}
	for _, p := range []string{"internal/c/c.go", "internal/c/c_test.go", "internal/lonely/lonely_linux.go",
		"internal/lonely2/lonely2_windows.go", "internal/e/other_" + otherGOOS() + ".go", "shared/s/s.go", "tools/inner/i.go", ".hidden/mod/m.go",
		"internal/x/testdata/c/c.go", "_hid/h/h.go", "internal/x/.dot/d/d.go"} {
		files[p] = pkgSrc(p)
	}
	root := plantTree(t, files)

	panel, err := parseModuleFiles(token.NewFileSet(), root, root, parser.ParseComments, true)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"_hid/h/h.go", "internal/a/a.go", "internal/c/c.go", "internal/c/c_test.go", "internal/cgo/c.go", "internal/e/e.go", "internal/e/ignored.go",
		"internal/e/other_" + otherGOOS() + ".go", "internal/lonely/lonely_linux.go", "internal/lonely2/lonely2_windows.go",
		"internal/x/.dot/d/d.go", "internal/x/testdata/c/c.go", "internal/y/y.go",
	}
	sort.Strings(want)
	if got := relPaths(panel); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("the module's files are\n  %s\nand go list plus its imports name\n  %s", strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}
	// The modules are found wherever they stand, under a directory that begins with a dot included.
	mods, err := goModDirs(root)
	if err != nil {
		t.Fatal(err)
	}
	foundHidden := false
	for _, m := range mods {
		foundHidden = foundHidden || strings.HasSuffix(filepath.ToSlash(m), "/.hidden/mod")
	}
	if !foundHidden {
		t.Errorf("goModDirs does not find a module under a dot directory: %v", mods)
	}
	for _, c := range []struct{ dir, want string }{{"shared", "shared/s/s.go"}, {"tools/inner", "tools/inner/i.go"}, {".hidden/mod", ".hidden/mod/m.go"}} {
		got, err := parseModuleFiles(token.NewFileSet(), root, filepath.Join(root, filepath.FromSlash(c.dir)), parser.ParseComments, true)
		if err != nil {
			t.Fatal(err)
		}
		if g := relPaths(got); len(g) != 1 || g[0] != c.want {
			t.Errorf("the files of module %s are %v, want [%s]", c.dir, g, c.want)
		}
	}
}

// TestBanReadsEveryGoFileOfTheTree plants the places where go list does not look and an escape hatch
// can be built all the same, and shows that the ban's reader finds them, and that an import of a
// directory it does not read is a problem of its own.
func TestBanReadsEveryGoFileOfTheTree(t *testing.T) {
	files := map[string]string{
		"go.mod":        "module " + module + "\n\ngo 1.22\n",
		"shared/go.mod": "module " + sharedModule + "\n\ngo 1.22\n",
		// Directories go list ./... does not name, and ones it does not name because of a constraint.
		"internal/a/_x.go": "package a\n", "testdata/t.go": "package t\n", "_scratch/d/d.go": "package d\n", ".dot/p/p.go": "package p\n",
		"internal/arm/x_arm64.go": "package arm\n", "internal/riscv/x_riscv64.go": "package riscv\n", "internal/tag/x.go": "//go:build sometag\n\npackage tag\n",
		"internal/gen/main.go": "//go:build ignore\n\npackage main\n", "shared/s/_u.go": "package s\n", "shared/s/s_test.go": "package s\n",
		// Not read: the version control store, installed packages of the web code, the published CI overlay.
		".git/hooks/x.go": "package x\n", "apps/web/node_modules/p/x.go": "package p\n", ".github/ci/plan/main.go": "package main\n", ".github/ci/shardrun/main.go": "package main\n",
		// The importers of unread directories.
		"internal/bad/b.go": "package bad\n\nimport (\n\t_ \"" + module + "/.github/ci/plan\"\n\t_ \"" + sharedModule + "/node_modules/q\"\n\t_ \"" + module + "/apps/web/node_modules/p\"\n)\n",
		"internal/ok/o.go":  "package ok\n\nimport _ \"" + module + "/internal/a\"\n",
	}
	root := plantTree(t, files)
	fset := token.NewFileSet()
	got, err := parseEveryModule(fset, root, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	have := strings.Join(relPaths(got), "\n")
	for _, w := range []string{"internal/a/_x.go", "testdata/t.go", "_scratch/d/d.go", ".dot/p/p.go", "internal/arm/x_arm64.go", "internal/riscv/x_riscv64.go",
		"internal/tag/x.go", "internal/gen/main.go", "shared/s/_u.go", "shared/s/s_test.go", "internal/bad/b.go"} {
		if !strings.Contains(have, w) {
			t.Errorf("the ban's reader does not read %s", w)
		}
	}
	for _, w := range []string{".git/", "node_modules", ".github/ci"} {
		if strings.Contains(have, w) {
			t.Errorf("the ban's reader read %s, which is not its business", w)
		}
	}
	problems := filepath.ToSlash(strings.Join(unreadImportProblems(fset, got), "\n"))
	for _, w := range []string{".github/ci/plan", "node_modules/q", "apps/web/node_modules/p"} {
		if !strings.Contains(problems, w) {
			t.Errorf("an import of the unread directory %s is not a problem:\n%s", w, problems)
		}
	}
	if strings.Contains(problems, "internal/a") {
		t.Errorf("an import of a directory the ban reads is a problem:\n%s", problems)
	}
	// The escape hatches planted in those places are judged like any other file.
	for _, p := range []string{"internal/a/_x.go", "testdata/t.go", "internal/arm/x_arm64.go", "internal/gen/main.go", "shared/s/_u.go"} {
		src := "package " + path.Base(path.Dir(p)) + "\nimport _ \"unsafe\"\n"
		if strings.HasSuffix(p, "main.go") {
			src = "//go:build ignore\n\npackage main\nimport \"os/exec\"\n"
		}
		pf := plantTree(t, map[string]string{"go.mod": "module " + module + "\n\ngo 1.22\n", p: src})
		fs2 := token.NewFileSet()
		fl, err := parseEveryModule(fs2, pf, parser.ParseComments)
		if err != nil {
			t.Fatal(err)
		}
		if len(capabilityProblems(fs2, fl, escapePolicy{safeStd: map[string]string{}, directiveSafe: goDirectiveSafe}, false)) == 0 {
			t.Errorf("an escape hatch in %s is not refused", p)
		}
	}
}

// otherGOOS is a platform that is neither the host's nor linux, whose file in a package that has a
// file for the host is still read (IgnoredGoFiles).
func otherGOOS() string {
	if runtime.GOOS == "darwin" {
		return "plan9"
	}
	return "darwin"
}
