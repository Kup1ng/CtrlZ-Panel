package app_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// The api role builds the queue of work owed after an answer (failed-login trail rows) itself,
// so the process can wait for it: the close function runs after the server has stopped taking
// requests and before the pool closes, and a row still queued then would meet a closed pool and
// vanish with no line (round 14, tenant-r14-3). The wiring is a few lines of serviceHandler, which
// a unit test cannot start without a database and a stopped server, so this reads the function:
// a queue built there must be handed to the api and drained. The queue's own behaviour is
// internal/afterwork's tests (TestDropsAreReportedOncePerMinuteAndAtDrain).
func TestAPIRoleDrainsItsAfterWorkQueueBeforeThePoolCloses(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "http.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var fn *ast.FuncDecl
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Name.Name == "serviceHandler" {
			fn = fd
		}
	}
	if fn == nil {
		t.Fatal("serviceHandler not found")
	}
	var built, handed, drained bool
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CallExpr:
			if s, ok := x.Fun.(*ast.SelectorExpr); ok {
				if p, ok := s.X.(*ast.Ident); ok && p.Name == "afterwork" && s.Sel.Name == "New" {
					built = true
				}
				if s.Sel.Name == "Drain" {
					drained = true
				}
			}
		case *ast.KeyValueExpr:
			if k, ok := x.Key.(*ast.Ident); ok && k.Name == "After" {
				handed = true
			}
		}
		return true
	})
	if !built || !handed || !drained {
		t.Fatalf("serviceHandler: queue built=%v handed to api.Deps.After=%v drained=%v; a queue the process cannot wait for loses rows at shutdown", built, handed, drained)
	}
}
