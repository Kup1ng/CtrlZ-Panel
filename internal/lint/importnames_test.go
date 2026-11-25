package lint_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// Rule one-name-per-import (round 18, primitives-r18-6 and -10; the class of rules clock-source,
// argon2-memory-budget, one-primitive-per-key, budget-keying and the RFC 6238 rule of spec 6.3).
//
// Many lints find a package in a file by the name the file gives it: they read the import list, take
// the local name and judge every selector `name.Member`. Go lets one path be imported twice under two
// names (`a "x/totp"` and `b "x/totp"`), and `_ "time"` beside `"time"`, and a lint that keeps one
// name per path (the last one read) then never judges the selectors of the other: a call through `a`
// passed the RFC 6238 rule, `time.Now()` passed the machine-clock rule, `argon2.IDKey` passed the
// memory budget. Rounds 16 and 17 closed one spelling at a time (an alias, a blank, a dot).
//
// The class is closed at its source and once. A non-test file of the module or of shared/ imports each
// path at most once and with no dot (importShapeProblems): then a file has one name per package, and
// every lint that reads it is right by construction. localNames is the one reading of those names for a
// lint, and it returns every name of the path, so a lint built on it judges all of them even if the
// invariant is ever broken. Test files are free: a lint never judges them, and a test may import a
// package twice.

// localNames is every name the file gives the package at importPath, in source order: the alias when
// there is one (including "_" and "."), else the last element of the path, which is the package name
// of every package a lint here follows. A file that does not import the path returns none. A lint
// treats "." as a refusal (its members are bare identifiers that no selector leads back to the
// package) and "_" as no name.
func localNames(f *ast.File, importPath string) []string {
	return localNamesWhere(f, func(p string) bool { return p == importPath })
}

// localNamesWhere is localNames for every import whose path match accepts (the RFC 6238 rule follows
// the path by its suffix).
func localNamesWhere(f *ast.File, match func(importPath string) bool) []string {
	var out []string
	for _, imp := range f.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil || !match(p) {
			continue
		}
		if imp.Name != nil {
			out = append(out, imp.Name.Name)
			continue
		}
		out = append(out, importedName(p))
	}
	return out
}

// importedName is the package name of an import path with no alias: its last element, or the one before it
// when the last is a major-version suffix ("math/rand/v2" is package rand, not v2; primitives-r18-23: the
// last element alone made a lint that followed math/rand/v2 look for selectors written through "v2").
func importedName(p string) string {
	base := path.Base(p)
	if dir := path.Dir(p); dir != "." && len(base) >= 2 && base[0] == 'v' && strings.Trim(base[1:], "0123456789") == "" {
		return path.Base(dir)
	}
	return base
}

// usableNames are the names of localNames a selector can be written with: every one except "_" and
// ".".
func usableNames(names []string) []string {
	var out []string
	for _, n := range names {
		if n != "_" && n != "." {
			out = append(out, n)
		}
	}
	return out
}

// hasDot says whether one of the names is a dot import.
func hasDot(names []string) bool {
	for _, n := range names {
		if n == "." {
			return true
		}
	}
	return false
}

// importShapeProblems judges the non-test files for the rule above.
func importShapeProblems(fset *token.FileSet, files []file) []string {
	var out []string
	for _, f := range files {
		if f.test {
			continue
		}
		seen := map[string]*ast.ImportSpec{}
		for _, imp := range f.ast.Imports {
			p, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				continue // the capability ban reports a path it cannot read
			}
			if imp.Name != nil && imp.Name.Name == "." {
				out = append(out, fset.Position(imp.Pos()).String()+": a dot import of "+p+" makes its members bare identifiers that no lint that follows the package by its name can judge; use the package name")
			}
			if first, dup := seen[p]; dup {
				out = append(out, fset.Position(imp.Pos()).String()+": "+p+" is imported twice in one file (first at "+fset.Position(first.Pos()).String()+"); a lint that finds a package by its local name judges one of the names only, so a second import hides every selector written through it (round 18, primitives-r18-6)")
				continue
			}
			seen[p] = imp
		}
	}
	sort.Strings(out)
	return out
}

func TestEveryFileImportsAPathOnceAndWithoutADot(t *testing.T) {
	fset := token.NewFileSet()
	files, err := parseEveryModule(fset, repoRoot(t), parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) < 200 {
		t.Fatalf("only %d files were read: the rule judges nothing", len(files))
	}
	for _, p := range importShapeProblems(fset, files) {
		t.Error(p)
	}
}

// TestImportShapeLintCanFail plants each shape Go allows: one path under two aliases, a path under its
// own name and an alias, a blank import beside the normal one, a dot import alone and beside a normal
// one, and the clean forms (one import, a test file that imports twice, a blank import alone).
func TestImportShapeLintCanFail(t *testing.T) {
	cases := []struct {
		name, path, src string
		want            int
	}{
		{"one import", "internal/api/x.go", "import \"time\"\nvar _ = time.Second", 0},
		{"one alias", "internal/api/x.go", "import clk \"time\"\nvar _ = clk.Second", 0},
		{"a blank import alone", "internal/api/x.go", "import _ \"time\"", 0},
		{"two aliases of one path", "internal/api/x.go", "import a \"time\"\nimport b \"time\"\nvar _ = a.Second + b.Second", 1},
		{"the name and an alias", "internal/api/x.go", "import \"time\"\nimport clk \"time\"\nvar _ = time.Second + clk.Second", 1},
		{"a blank import beside the normal one", "internal/api/x.go", "import \"time\"\nimport _ \"time\"\nvar _ = time.Second", 1},
		{"a dot import alone", "internal/api/x.go", "import . \"time\"\nvar _ = Second", 1},
		{"a dot import beside the normal one", "internal/api/x.go", "import . \"time\"\nimport \"time\"\nvar _ = Second + time.Second", 2},
		{"an internal package twice", "internal/api/x.go", "import a \"github.com/Kup1ng/CtrlZ-Panel/internal/auth/totp\"\nimport b \"github.com/Kup1ng/CtrlZ-Panel/internal/auth/totp\"\nvar _ = a.Check\nvar _ = b.Generate", 1},
		{"a test file may import twice", "internal/api/x_test.go", "import \"time\"\nimport clk \"time\"\nvar _ = time.Second + clk.Second", 0},
		{"a file of shared/", "shared/quarantine/x.go", "import \"time\"\nimport clk \"time\"\nvar _ = time.Second + clk.Second", 1},
	}
	for _, c := range cases {
		fset := token.NewFileSet()
		fs := parsePlanted(t, fset, []planted{{c.path, c.src}})
		if got := importShapeProblems(fset, fs); len(got) != c.want {
			t.Errorf("%s: %d problems %v, want %d", c.name, len(got), got, c.want)
		}
	}
}

func TestLocalNamesReturnsEveryName(t *testing.T) {
	fset := token.NewFileSet()
	af, err := parser.ParseFile(fset, "x.go", "package x\nimport (\n\t\"time\"\n\tclk \"time\"\n\t_ \"time\"\n\t. \"strings\"\n\t\"golang.org/x/crypto/argon2\"\n)\n", parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(localNames(af, "time"), ","); got != "time,clk,_" {
		t.Errorf("time: %q", got)
	}
	if got := strings.Join(usableNames(localNames(af, "time")), ","); got != "time,clk" {
		t.Errorf("usable names of time: %q", got)
	}
	if !hasDot(localNames(af, "strings")) {
		t.Error("a dot import of strings was not seen")
	}
	if got := localNames(af, "golang.org/x/crypto/argon2"); len(got) != 1 || got[0] != "argon2" {
		t.Errorf("argon2: %v", got)
	}
	if importedName("math/rand/v2") != "rand" || importedName("golang.org/x/crypto/argon2") != "argon2" || importedName("v2") != "v2" || importedName("example.com/v") != "v" {
		t.Error("the package name of a path with a major-version suffix")
	}
	if got := localNames(af, "os"); len(got) != 0 {
		t.Errorf("os: %v", got)
	}
}
