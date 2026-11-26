package lint_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strings"
	"testing"
)

// Rule strength-gate-corpus, round 7 (primitives-r7-5). The strength gate takes a
// password.Prepared, which holds what was typed and its NFKC form, so a route cannot hand the scorer
// the normalised text alone. The type is only as good as the ways to make one: Prepare is the door
// every route uses, and Typed (the same without the minimum, for the gate's own too_short answer
// and for tests) must not become a second door that wraps an NFKC string as if it were typed.

// preparedProblems flags a call of password.Typed outside internal/auth/password in a non-test file.
func preparedProblems(fset *token.FileSet, files []file) []string {
	var out []string
	for _, f := range files {
		if f.test || strings.HasPrefix(f.path, "internal/auth/password/") {
			continue
		}
		ast.Inspect(f.ast, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Typed" {
				return true
			}
			if x, ok := sel.X.(*ast.Ident); ok && x.Name == "password" {
				out = append(out, fset.Position(call.Pos()).String()+": password.Typed makes a Prepared with no minimum and treats its argument as what was typed; a route calls password.Prepare")
			}
			return true
		})
	}
	sort.Strings(out)
	return out
}

func TestPreparedIsMadeOnlyByPrepare(t *testing.T) {
	fset, files := parseRepo(t)
	if got := preparedProblems(fset, files); len(got) > 0 {
		t.Errorf("%d calls of password.Typed in non-test code:\n%s", len(got), strings.Join(got, "\n"))
	}
}

func TestPreparedLintCanFail(t *testing.T) {
	cases := []struct {
		name, path, src string
		want            int
	}{
		{"a route wraps the NFKC text", "internal/api/x.go", `func f(n S) { password.Typed(n) }`, 1},
		{"the admin routes too", "internal/adminapi/x.go", `func f(n S) { password.Typed(n) }`, 1},
		{"Prepare is the door", "internal/api/x.go", `func f(n S) { password.Prepare(n, password.User) }`, 0},
		{"the password package may", "internal/auth/password/x.go", `func f(n S) { password.Typed(n) }`, 0},
		{"a test may", "internal/auth/pwstrength/x_test.go", `func f(n S) { password.Typed(n) }`, 0},
		{"another Typed is not judged", "internal/api/x.go", `func f(p P) { p.Typed() }`, 0},
	}
	for _, c := range cases {
		fset := token.NewFileSet()
		af, err := parser.ParseFile(fset, c.path, "package x\n"+c.src, 0)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		got := preparedProblems(fset, []file{{path: c.path, test: strings.HasSuffix(c.path, "_test.go"), ast: af}})
		if len(got) != c.want {
			t.Errorf("%s: %d problems %v, want %d", c.name, len(got), got, c.want)
		}
	}
}
