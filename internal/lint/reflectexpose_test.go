package lint_test

import (
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The reflect pass of the escape-hatch ban (rule escape-hatch-ban, round 18, primitives-r18-12) must
// know the type of every receiver, and a reflect.Type reaches a directory through the API of another
// standard package (the Type field of encoding/json's UnmarshalTypeError, ColumnType.ScanType of
// database/sql) with no import of reflect or unsafe in that directory. Type-checking the whole standard
// library from source to follow it is minutes of work, so the packages to check are DERIVED: a standard
// package that the tree imports and whose exported API names a type of package reflect. The source of the
// derivation is the standard library itself (GOROOT/src, parsed and not type-checked), so a package the
// standard library adds or changes later is found without a line of ours, and one that imports reflect
// only inside its functions (fmt, net/http) is not needed.

// stdExposingReflect returns, sorted, the standard packages among importPaths whose exported declarations
// (a function or method signature, an exported struct field, an exported type, variable or constant, an
// interface method) mention a selector of package reflect.
func stdExposingReflect(importPaths []string) ([]string, error) {
	root := filepath.Join(build.Default.GOROOT, "src")
	var out []string
	for _, p := range importPaths {
		if !isStdPath(p) || p == "reflect" || p == "unsafe" || strings.HasPrefix(p, "internal/") || strings.Contains(p, "/internal/") {
			continue
		}
		dir := filepath.Join(root, filepath.FromSlash(p))
		ents, err := os.ReadDir(dir)
		if err != nil {
			continue // a vendored or missing package is not one the tree can import by this path
		}
		found := false
		for _, e := range ents {
			name := e.Name()
			if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			f, err := parser.ParseFile(token.NewFileSet(), filepath.Join(dir, name), nil, parser.SkipObjectResolution)
			if err != nil {
				return nil, err
			}
			if exposesReflect(f) {
				found = true
				break
			}
		}
		if found {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out, nil
}

// exposesReflect says whether an exported declaration of f names a type of package reflect.
func exposesReflect(f *ast.File) bool {
	names := map[string]bool{}
	for _, im := range f.Imports {
		if p, err := strconv.Unquote(im.Path.Value); err == nil && p == "reflect" {
			n := path.Base(p)
			if im.Name != nil {
				n = im.Name.Name
			}
			names[n] = true
		}
	}
	if len(names) == 0 {
		return false
	}
	mentions := func(n ast.Node) bool {
		hit := false
		ast.Inspect(n, func(x ast.Node) bool {
			if sx, ok := x.(*ast.SelectorExpr); ok {
				if id, ok := sx.X.(*ast.Ident); ok && names[id.Name] {
					hit = true
				}
			}
			return !hit
		})
		return hit
	}
	for _, d := range f.Decls {
		switch x := d.(type) {
		case *ast.FuncDecl:
			if !ast.IsExported(x.Name.Name) {
				continue
			}
			if x.Recv != nil && len(x.Recv.List) == 1 && !ast.IsExported(receiverTypeName(x.Recv.List[0].Type)) {
				continue
			}
			if mentions(x.Type) {
				return true
			}
		case *ast.GenDecl:
			for _, s := range x.Specs {
				switch sp := s.(type) {
				case *ast.TypeSpec:
					if ast.IsExported(sp.Name.Name) && exportedTypeMentions(sp.Type, mentions) {
						return true
					}
				case *ast.ValueSpec:
					for _, n := range sp.Names {
						if ast.IsExported(n.Name) && sp.Type != nil && mentions(sp.Type) {
							return true
						}
					}
				}
			}
		}
	}
	return false
}

// exportedTypeMentions looks at the parts of a type declaration a user of the package can reach: the
// exported fields of a struct (and its embedded ones), the methods of an interface, and the whole of any
// other type expression.
func exportedTypeMentions(t ast.Expr, mentions func(ast.Node) bool) bool {
	switch x := t.(type) {
	case *ast.StructType:
		for _, fl := range x.Fields.List {
			exported := len(fl.Names) == 0
			for _, n := range fl.Names {
				exported = exported || ast.IsExported(n.Name)
			}
			if exported && mentions(fl.Type) {
				return true
			}
		}
		return false
	case *ast.InterfaceType:
		for _, m := range x.Methods.List {
			exported := len(m.Names) == 0
			for _, n := range m.Names {
				exported = exported || ast.IsExported(n.Name)
			}
			if exported && mentions(m.Type) {
				return true
			}
		}
		return false
	}
	return mentions(t)
}

// importedStdPaths lists the standard-library import paths of files (every module of the tree).
func importedStdPaths(files []file) []string {
	seen := map[string]bool{}
	for _, f := range files {
		for _, im := range f.ast.Imports {
			if p, err := strconv.Unquote(im.Path.Value); err == nil && isStdPath(p) {
				seen[p] = true
			}
		}
	}
	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// TestStdExposingReflectFindsTheKnownOnes holds the derivation to the three packages the finding named,
// and to the ones that import reflect and expose none.
func TestStdExposingReflectFindsTheKnownOnes(t *testing.T) {
	got, err := stdExposingReflect([]string{"encoding/json", "encoding/xml", "database/sql", "fmt", "net/http", "strings", "reflect", "os"})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"encoding/json": true, "encoding/xml": true, "database/sql": true}
	for _, p := range got {
		if !want[p] {
			t.Errorf("%s was found to expose reflect and the standard library's own API says it does not", p)
		}
		delete(want, p)
	}
	for p := range want {
		t.Errorf("%s exposes a type of reflect through its API (UnmarshalTypeError.Type, UnsupportedTypeError.Type, ColumnType.ScanType) and was not found", p)
	}
}
