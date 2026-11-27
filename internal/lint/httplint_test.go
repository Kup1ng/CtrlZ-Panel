package lint_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path"
	"strconv"
	"strings"
	"testing"
)

// The request-logging ban (spec 2.3 step 1, R21). chi's middleware.Logger and
// middleware.Recoverer print the request URL, and Recoverer prints the headers
// with the panic; httputil.DumpRequest writes the whole request, cookies and
// body included. A URL can carry a token and a header a session, so none of them
// may appear anywhere in the module. httpx.Recover and the sanitised server
// ErrorLog are what the services use instead.

// bannedSymbols maps an import path to the identifiers of it that are banned.
func bannedSymbols() map[string][]string {
	return map[string][]string{
		"github.com/go-chi/chi/v5/middleware": {"Logger", "DefaultLogger", "RequestLogger", "Recoverer", "PrintPrettyStack", "DefaultLogFormatter"},
		"net/http/httputil":                   {"DumpRequest", "DumpRequestOut", "DumpResponse"},
	}
}

// bannedUses returns "line: pkg.Name" for each use of a banned identifier in f.
func bannedUses(fset *token.FileSet, f *ast.File) []string {
	local := map[string]string{} // local name -> import path
	for _, imp := range f.Imports {
		p, _ := strconv.Unquote(imp.Path.Value)
		if _, ok := bannedSymbols()[p]; !ok {
			continue
		}
		name := path.Base(p)
		if p == "github.com/go-chi/chi/v5/middleware" {
			name = "middleware"
		}
		if imp.Name != nil {
			name = imp.Name.Name
		}
		if name == "_" {
			continue
		}
		local[name] = p
		if name == "." {
			// A dot import would hide the package name from this scan.
			return []string{fset.Position(imp.Pos()).String() + ": dot import of " + p}
		}
	}
	if len(local) == 0 {
		return nil
	}
	var out []string
	ast.Inspect(f, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		id, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		p, ok := local[id.Name]
		if !ok {
			return true
		}
		for _, banned := range bannedSymbols()[p] {
			if sel.Sel.Name == banned {
				out = append(out, fset.Position(sel.Pos()).String()+": "+id.Name+"."+banned)
			}
		}
		return true
	})
	return out
}

func TestNoRequestLogging(t *testing.T) {
	fset, files := parseRepo(t)
	for _, f := range files {
		for _, u := range bannedUses(fset, f.ast) {
			t.Errorf("%s: %s prints request data; use httpx.Recover and the sanitised ErrorLog (R21)", f.path, u)
		}
	}
}

// TestRequestLoggingBanFires checks the checker: a rule that never fires would
// pass for ever.
func TestRequestLoggingBanFires(t *testing.T) {
	cases := map[string]int{
		`package x
import "github.com/go-chi/chi/v5/middleware"
func f() { _ = middleware.Logger }`: 1,
		`package x
import mw "github.com/go-chi/chi/v5/middleware"
func f() { _ = mw.Recoverer; _ = mw.RequestLogger }`: 2,
		`package x
import "net/http/httputil"
func f() { httputil.DumpRequest(nil, true) }`: 1,
		`package x
import "net/http/httputil"
func f() { _ = httputil.NewSingleHostReverseProxy }`: 0,
		`package x
import "github.com/go-chi/chi/v5/middleware"
func f() { _ = middleware.RealIP }`: 0,
		`package x
import . "net/http/httputil"
func f() {}`: 1,
	}
	for src, want := range cases {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, "x.go", src, 0)
		if err != nil {
			t.Fatal(err)
		}
		if got := bannedUses(fset, f); len(got) != want {
			t.Errorf("%q: %d findings %v, want %d", strings.Split(src, "\n")[1], len(got), got, want)
		}
	}
}
