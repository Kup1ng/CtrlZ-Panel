// Package hygiene holds tests that read the module's own source to enforce
// the package rules of contract section 1 and the definition of done in
// section 17. Nothing here ships in a binary; it exists so a rule that is only
// written in a document cannot be broken by a quiet commit.
package hygiene

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const modulePath = "github.com/Kup1ng/CtrlZ-Shared"

// sourceFiles lists the hand-written, non-test .go files of the module. gen/ is
// generated code (it imports unsafe on purpose) and cmd/ is the one place the
// contract allows file I/O.
func sourceFiles(t *testing.T) map[string]*ast.File {
	t.Helper()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]*ast.File{}
	fset := token.NewFileSet()
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if rel == "gen" || rel == "cmd" || rel == "internal" || (rel != "." && strings.HasPrefix(filepath.Base(rel), ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, p, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		out[rel] = f
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) < 20 {
		t.Fatalf("found only %d source files: wrong root?", len(out))
	}
	return out
}

func importsOf(f *ast.File) []string {
	var out []string
	for _, im := range f.Imports {
		p, _ := strconv.Unquote(im.Path.Value)
		out = append(out, p)
	}
	return out
}

// TestPackageRules: no unsafe, no file or process or network I/O, no clock
// reads, no goroutines, outside cmd/ (contract 1 and 17). The evaluator takes
// time and lookups as inputs precisely so these can stay true.
func TestPackageRules(t *testing.T) {
	banned := map[string]string{
		"unsafe": "unsafe", "os": "file and process access", "os/exec": "starting processes", "net": "network access (net/netip is fine)",
		"net/http": "network access", "syscall": "system calls", "io/ioutil": "file access", "database/sql": "a database driver",
	}
	for rel, f := range sourceFiles(t) {
		for _, imp := range importsOf(f) {
			if why, bad := banned[imp]; bad {
				t.Errorf("%s imports %q: %s is not allowed in shared outside cmd/", rel, imp, why)
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.GoStmt:
				t.Errorf("%s: goroutine started; shared packages are synchronous", rel)
			case *ast.SelectorExpr:
				if id, ok := x.X.(*ast.Ident); ok && id.Name == "time" {
					switch x.Sel.Name {
					case "Now", "Since", "Until", "Sleep", "After", "Tick", "NewTimer", "NewTicker":
						t.Errorf("%s: time.%s reads the clock; pass the time in", rel, x.Sel.Name)
					}
				}
			}
			return true
		})
	}
}

// TestNoPackageLevelMutableState: contract 1. A package-level var is allowed
// only if it is an error sentinel or in this explicit list of values that are
// written once at start and only read afterwards. Adding to the list is a
// review decision, which is the point.
func TestNoPackageLevelMutableState(t *testing.T) {
	allowed := map[string]bool{
		"blob.le": true, "gtable.le": true, // binary.LittleEndian
		"identity.b32":            true, // a base32 encoding value
		"policy.defaultEffective": true, // computed once from empty options
		"policy.flagNames":        true, // fixed names
		"sysnames.table":          true, // the compiled system-names table
		"vectors.files":           true, // go:embed
		"wire.urlAuthority":       true, // a regexp compiled once, only read
	}
	for rel, f := range sourceFiles(t) {
		pkg := f.Name.Name
		for _, d := range f.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.VAR {
				continue
			}
			for _, spec := range gd.Specs {
				vs := spec.(*ast.ValueSpec)
				for _, name := range vs.Names {
					if name.Name == "_" || strings.HasPrefix(name.Name, "Err") || strings.HasPrefix(name.Name, "err") {
						continue
					}
					if !allowed[pkg+"."+name.Name] {
						t.Errorf("%s: package-level var %s.%s is not allowed (contract 1: no package-level mutable state)", rel, pkg, name.Name)
					}
				}
			}
		}
	}
}

// TestImportDirection: names is the leaf; blob, gtable and policy do not touch
// the generated protobuf code; gen imports nothing from this module.
func TestImportDirection(t *testing.T) {
	files := sourceFiles(t)
	pkgOf := func(rel string) string { return strings.SplitN(rel, "/", 2)[0] }
	local := func(imp string) (string, bool) {
		if !strings.HasPrefix(imp, modulePath+"/") {
			return "", false
		}
		return strings.SplitN(strings.TrimPrefix(imp, modulePath+"/"), "/", 2)[0], true
	}
	deps := map[string]map[string]bool{}
	for rel, f := range files {
		p := pkgOf(rel)
		if deps[p] == nil {
			deps[p] = map[string]bool{}
		}
		for _, imp := range importsOf(f) {
			if q, ok := local(imp); ok && q != p {
				deps[p][q] = true
			}
		}
	}
	// Transitive closure.
	reach := func(from string) map[string]bool {
		seen := map[string]bool{}
		var walk func(string)
		walk = func(p string) {
			for q := range deps[p] {
				if !seen[q] {
					seen[q] = true
					walk(q)
				}
			}
		}
		walk(from)
		return seen
	}
	if len(deps["names"]) != 0 {
		t.Errorf("names is the leaf but imports %v", sorted(deps["names"]))
	}
	for _, p := range []string{"names", "blob", "gtable", "policy", "rules", "locations", "schedule", "sysnames", "netclass", "identity", "reason"} {
		if reach(p)["gen"] {
			t.Errorf("%s reaches the generated protobuf code (gen); only wire, quarantine and manifest may", p)
		}
	}
	for _, bad := range []string{"wire", "quarantine", "vectors", "manifest"} {
		if reach("names")[bad] || reach("blob")[bad] || reach("policy")[bad] {
			t.Errorf("a core package imports %s", bad)
		}
	}
	// Dependency cycle check for the policy layer.
	for _, p := range []string{"blob", "gtable", "schedule", "sysnames", "locations", "netclass"} {
		if reach(p)["policy"] {
			t.Errorf("%s imports policy: cycle", p)
		}
	}
}

// TestAllowedDependencies: contract 1 allows protobuf, grpc (generated stubs
// only) and golang.org/x/net. golang.org/x/text is used for NFKC in SlugClient
// and is already in the module graph through x/net/idna; it is listed here so
// that any further third-party import fails this test until someone decides.
func TestAllowedDependencies(t *testing.T) {
	allowed := []string{"google.golang.org/protobuf", "golang.org/x/net/", "golang.org/x/text/unicode/norm"}
	for rel, f := range sourceFiles(t) {
		for _, imp := range importsOf(f) {
			if !strings.Contains(strings.SplitN(imp, "/", 2)[0], ".") || strings.HasPrefix(imp, modulePath) {
				continue
			}
			ok := false
			for _, a := range allowed {
				if strings.HasPrefix(imp, a) {
					ok = true
				}
			}
			if !ok {
				t.Errorf("%s imports %q, which is not on the allowed list (contract 1)", rel, imp)
			}
		}
	}
}

func sorted(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
