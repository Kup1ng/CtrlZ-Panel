package admincli

import (
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strconv"
	"testing"
)

// TestCommandsMatchTheDispatch reads RunWith and fails when its switch and Commands
// differ, so the list the credential-state coverage test walks is the real command set.
func TestCommandsMatchTheDispatch(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "admincli.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		fd, ok := n.(*ast.FuncDecl)
		if !ok || fd.Name.Name != "RunWith" {
			return true
		}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			cc, ok := n.(*ast.CaseClause)
			if !ok {
				return true
			}
			for _, e := range cc.List {
				if l, ok := e.(*ast.BasicLit); ok && l.Kind == token.STRING {
					s, _ := strconv.Unquote(l.Value)
					if len(s) > 0 && s[0] != '-' && s != "help" {
						got[s] = true
					}
				}
			}
			return true
		})
		return false
	})
	var want []string
	for _, c := range Commands() {
		want = append(want, c)
		if !got[c] {
			t.Errorf("Commands lists %q, which RunWith does not dispatch", c)
		}
		delete(got, c)
	}
	var extra []string
	for c := range got {
		extra = append(extra, c)
	}
	sort.Strings(extra)
	if len(extra) > 0 {
		t.Errorf("RunWith dispatches %v, which Commands does not list", extra)
	}
	if len(want) < 8 {
		t.Errorf("Commands has %d entries", len(want))
	}
}
