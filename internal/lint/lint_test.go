// Package lint holds source-level rules that no compiler checks. They are
// tests, so `go test ./...` enforces them without another tool in CI.
//
// The rules come from docs/specs/postgres-schema.md section 10 (R5):
//
//  1. pgx is imported only where the database is meant to be reached.
//  2. No SQL text is built at run time on the tenant path: whatever reaches
//     Exec, Query or QueryRow is a constant.
//  3. The store's pool and connections never leave the package.
//
// A line may opt out of rule 2 with a comment `lint:sql-const` where the
// string is a parameter that every caller fills with a constant (the helper
// `one` in internal/store); the callers are then checked instead.
package lint_test

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const module = "github.com/Kup1ng/CtrlZ-Panel"

// repoRoot finds the directory holding go.mod.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := repoRootErr()
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

// repoRootErr is repoRoot for code that has no *testing.T: a table computed once for the whole
// package, such as the request fields the server folds (foldfields_test.go).
func repoRootErr() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("go.mod not found")
		}
		dir = parent
	}
}

type file struct {
	path string // slash-separated, relative to the root
	test bool
	ast  *ast.File
}

func parseRepo(t *testing.T) (*token.FileSet, []file) {
	t.Helper()
	fset, files, err := parseRepoAt(repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	return fset, files
}

// parseRepoAt reads every Go file of the packages go list names in the module under root (gotree_test.go
// says why the set comes from the toolchain and not from a walk of the directories).
func parseRepoAt(root string) (*token.FileSet, []file, error) {
	fset := token.NewFileSet()
	files, err := parseModuleFiles(fset, root, root, parser.ParseComments, true)
	if err != nil {
		return nil, nil, err
	}
	if len(files) < 10 {
		return nil, nil, fmt.Errorf("only %d Go files found under %s", len(files), root)
	}
	return fset, files, nil
}

// pgxAllowed are the places that may import pgx: the store, the migration
// runner, the test harness, and test files under internal/store.
func pgxAllowed(f file) bool {
	switch {
	case strings.HasPrefix(f.path, "internal/store/"):
		return true
	case strings.HasPrefix(f.path, "internal/migrate/"):
		return true
	case strings.HasPrefix(f.path, "internal/testpg/"):
		return true
	}
	return false
}

func TestPgxOnlyWhereItBelongs(t *testing.T) {
	_, files := parseRepo(t)
	for _, f := range files {
		for _, imp := range f.ast.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			if (strings.HasPrefix(p, "github.com/jackc/pgx") || p == "database/sql") && !pgxAllowed(f) {
				t.Errorf("%s imports %s; database access belongs in internal/store", f.path, p)
			}
		}
	}
}

// TestPoolDoesNotEscape checks that no exported declaration of internal/store
// hands out the pool or a raw connection.
func TestPoolDoesNotEscape(t *testing.T) {
	_, files := parseRepo(t)
	bad := func(e ast.Expr) bool {
		found := false
		ast.Inspect(e, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok {
				if id, ok := sel.X.(*ast.Ident); ok && id.Name == "pgxpool" {
					found = true
				}
				if id, ok := sel.X.(*ast.Ident); ok && id.Name == "pgx" && (sel.Sel.Name == "Conn" || sel.Sel.Name == "Tx") {
					found = true
				}
			}
			return true
		})
		return found
	}
	for _, f := range files {
		if f.test || filepath.ToSlash(filepath.Dir(f.path)) != "internal/store" {
			continue
		}
		for _, d := range f.ast.Decls {
			switch d := d.(type) {
			case *ast.FuncDecl:
				if !d.Name.IsExported() || d.Type.Results == nil {
					continue
				}
				// safeRows implements pgx.Rows, which has a Conn method; its
				// version returns nil and nothing else, which is what keeps the
				// connection out of reach of whoever holds the rows.
				if d.Name.Name == "Conn" && returnsOnlyNil(d) {
					continue
				}
				for _, r := range d.Type.Results.List {
					if bad(r.Type) {
						t.Errorf("%s: exported %s returns a pgx pool or connection", f.path, d.Name.Name)
					}
				}
			case *ast.GenDecl:
				for _, s := range d.Specs {
					ts, ok := s.(*ast.TypeSpec)
					if !ok || !ts.Name.IsExported() {
						continue
					}
					st, ok := ts.Type.(*ast.StructType)
					if !ok {
						continue
					}
					for _, fld := range st.Fields.List {
						for _, n := range fld.Names {
							if n.IsExported() && bad(fld.Type) {
								t.Errorf("%s: exported field %s.%s exposes the pool or a connection", f.path, ts.Name.Name, n.Name)
							}
						}
					}
				}
			}
		}
	}
}

// returnsOnlyNil reports whether a function body is exactly "return nil".
func returnsOnlyNil(d *ast.FuncDecl) bool {
	if d.Body == nil || len(d.Body.List) != 1 {
		return false
	}
	r, ok := d.Body.List[0].(*ast.ReturnStmt)
	if !ok || len(r.Results) != 1 {
		return false
	}
	id, ok := r.Results[0].(*ast.Ident)
	return ok && id.Name == "nil"
}

// TestNoPackageLevelMutableState enforces the Go rule of the workspace: no
// package-level var except in tests and main, and except errors, which are
// sentinels, and compiled regular expressions and templates, which never
// change after initialisation.
func TestNoPackageLevelMutableState(t *testing.T) {
	_, files := parseRepo(t)
	var bad []string
	for _, f := range files {
		if f.test || f.path == "tools/genmig/main.go" || strings.HasPrefix(f.path, "internal/testpg/") {
			continue
		}
		for _, d := range f.ast.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.VAR {
				continue
			}
			for _, s := range gd.Specs {
				vs := s.(*ast.ValueSpec)
				if isEmbedFS(vs.Type) {
					continue // read-only files baked in at build time
				}
				for i, n := range vs.Names {
					if n.Name == "_" {
						continue
					}
					if i < len(vs.Values) && allowedVarInit(vs.Values[i]) {
						continue
					}
					bad = append(bad, f.path+": var "+n.Name)
				}
			}
		}
	}
	sort.Strings(bad)
	for _, b := range bad {
		t.Errorf("package-level mutable state: %s", b)
	}
}

// allowedVarInit accepts errors.New, regexp.MustCompile, template.Must and
// sync.OnceValue(s), which computes a value once and never changes it.
func allowedVarInit(e ast.Expr) bool {
	call, ok := e.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	switch pkg.Name + "." + sel.Sel.Name {
	case "errors.New", "regexp.MustCompile", "template.Must", "sync.OnceValue", "sync.OnceValues":
		return true
	}
	return false
}

func isEmbedFS(e ast.Expr) bool {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "embed" && sel.Sel.Name == "FS"
}
