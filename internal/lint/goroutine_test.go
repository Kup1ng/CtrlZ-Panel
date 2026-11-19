package lint_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"sort"
	"testing"
)

// Rule goroutine-recover (P1 auth review round 14, tenant-r14-2; tightened in round 15,
// tenant-r15-3). Go ends the whole process on a panic in any goroutine, and the request recover of
// the pipeline covers only the request's own. Two goroutines of the api had none: the queue of work
// owed after an answer and the load of the config cache, both reached by an anonymous client, so a
// bug in either was a stop of the service for every tenant.
//
// The rule: every `go` statement of non-test code starts a function that keeps ALL of its panics,
// which only one shape does. The first statement of the function is a deferred function that calls
// recover itself (a literal, or a function or method of the module whose own top level calls it): a
// panic anywhere after that statement ends in it. The round 14 version accepted a recover anywhere in
// the body and a same-named function that recovers anywhere in the program, so `_ = recover();
// work()` and `work(); protect(...)` passed while the panic of `work` ended the process. Three more
// shapes are accepted:
//
//   - a function whose only statement is one call to a function of the first shape, so a goroutine
//     can be a thin line over a method that guards itself;
//   - a function that only waits, signals and counts down: sync.WaitGroup.Wait and Done and the
//     builtin close, and nothing else, which cannot panic on anyone's data;
//   - a file on the reviewed list below, with the reason.
//
// Callees are resolved by the type checker (a method of the module, by object), not by name, so a
// function that shares a name with one that recovers is not mistaken for it, and a callee the checker
// cannot resolve (a function value, an interface method) is not covered: the rule fails closed.

// goroutineUnrecovered lists the files whose goroutines are not covered, each with why. A stale
// entry (a file with no uncovered `go` statement) fails.
var goroutineUnrecovered = map[string]string{
	"internal/app/app.go":               "the serve loop: net/http bodyRecovers a handler's panic itself, and the shutdown path has the process's own recover",
	"internal/app/http.go":              "the admin role's session sweep: one loop of fixed store statements in a process that serves one operator; a panic ends the process and Compose restarts it",
	"internal/app/worker.go":            "the worker role's own loops: the worker serves no request, its panic ends the process and Compose restarts it",
	"internal/worker/smssend/worker.go": "the worker role (see internal/app/worker.go)",
	"internal/worker/sweep/sweep.go":    "the worker role (see internal/app/worker.go)",
	"internal/mutant/run.go":            "the mutant runner is a test tool and never ships in a service",
}

// panicKeeper answers the questions of the rule from one type-checked set of files.
type panicKeeper struct {
	info  *types.Info
	decls map[types.Object]*ast.FuncDecl
}

func newPanicKeeper(fset *token.FileSet, files []file) (*panicKeeper, bool) {
	info, ok := typeInfoReal(fset, files, "sync")
	if !ok {
		return nil, false
	}
	k := &panicKeeper{info: info, decls: map[types.Object]*ast.FuncDecl{}}
	for _, f := range files {
		for _, d := range f.ast.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Body != nil {
				if o := info.Defs[fd.Name]; o != nil {
					k.decls[o] = fd
				}
			}
		}
	}
	return k, true
}

// callee is the declaration a call goes to, when it is a function or method of the checked files.
// A generic method is looked up by its origin.
func (k *panicKeeper) callee(c *ast.CallExpr) *ast.FuncDecl {
	var obj types.Object
	switch fun := unparen(c.Fun).(type) {
	case *ast.Ident:
		obj = k.info.Uses[fun]
	case *ast.SelectorExpr:
		if s := k.info.Selections[fun]; s != nil {
			obj = s.Obj()
		} else {
			obj = k.info.Uses[fun.Sel]
		}
	}
	fn, ok := obj.(*types.Func)
	if !ok {
		return nil
	}
	return k.decls[fn.Origin()]
}

// builtin reports a call of the named builtin (recover, close), so a local that shadows the name does
// not count.
func (k *panicKeeper) builtin(c *ast.CallExpr, name string) bool {
	id, ok := unparen(c.Fun).(*ast.Ident)
	if !ok {
		return false
	}
	b, ok := k.info.Uses[id].(*types.Builtin)
	return ok && b.Name() == name
}

// waitGroupMethod reports a call of sync.WaitGroup's method of that name.
func (k *panicKeeper) waitGroupMethod(c *ast.CallExpr, name string) bool {
	sel, ok := unparen(c.Fun).(*ast.SelectorExpr)
	if !ok {
		return false
	}
	s := k.info.Selections[sel]
	if s == nil {
		return false
	}
	fn, ok := s.Obj().(*types.Func)
	if !ok || fn.Name() != name || fn.Pkg() == nil || fn.Pkg().Path() != "sync" {
		return false
	}
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return false
	}
	t := sig.Recv().Type()
	if p, ok := t.(*types.Pointer); ok {
		t = p.Elem()
	}
	n, ok := t.(*types.Named)
	return ok && n.Obj().Name() == "WaitGroup"
}

// recoversAtTop reports a call of the builtin recover in the body itself. A nested literal is not
// looked into: recover stops a panic only when the deferred function calls it directly, so a recover
// one literal deeper stops nothing.
func (k *panicKeeper) recoversAtTop(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.CallExpr:
			if k.builtin(x, "recover") {
				found = true
			}
		}
		return !found
	})
	return found
}

// guardsItself reports the first shape: the first statement is a deferred function that recovers.
// It must be the first, or the statements before it are outside the guard.
func (k *panicKeeper) guardsItself(body *ast.BlockStmt) bool {
	if len(body.List) == 0 {
		return false
	}
	d, ok := body.List[0].(*ast.DeferStmt)
	if !ok {
		return false
	}
	if lit, ok := unparen(d.Call.Fun).(*ast.FuncLit); ok {
		return k.recoversAtTop(lit.Body)
	}
	if fd := k.callee(d.Call); fd != nil {
		return k.recoversAtTop(fd.Body)
	}
	return false
}

// thinLine reports the second shape: one statement, a call of a function that guards itself.
func (k *panicKeeper) thinLine(body *ast.BlockStmt) bool {
	if len(body.List) != 1 {
		return false
	}
	es, ok := body.List[0].(*ast.ExprStmt)
	if !ok {
		return false
	}
	c, ok := es.X.(*ast.CallExpr)
	if !ok {
		return false
	}
	fd := k.callee(c)
	return fd != nil && k.guardsItself(fd.Body)
}

// onlyWaits reports the third shape.
func (k *panicKeeper) onlyWaits(body *ast.BlockStmt) bool {
	for _, s := range body.List {
		switch s := s.(type) {
		case *ast.ExprStmt:
			c, ok := s.X.(*ast.CallExpr)
			if !ok || !(k.waitGroupMethod(c, "Wait") || k.builtin(c, "close")) {
				return false
			}
		case *ast.DeferStmt:
			if !(k.waitGroupMethod(s.Call, "Done") || k.builtin(s.Call, "close")) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// panicKeepProblems judges every `go` statement of the given non-test files.
func panicKeepProblems(fset *token.FileSet, files []file, allowed map[string]string) []string {
	k, ok := newPanicKeeper(fset, files)
	if !ok {
		return []string{"type information unavailable"}
	}
	var out []string
	used := map[string]bool{}
	for _, f := range files {
		ast.Inspect(f.ast, func(n ast.Node) bool {
			g, ok := n.(*ast.GoStmt)
			if !ok {
				return true
			}
			var body *ast.BlockStmt
			if lit, isLit := unparen(g.Call.Fun).(*ast.FuncLit); isLit {
				body = lit.Body
			} else if fd := k.callee(g.Call); fd != nil {
				body = fd.Body
			}
			if body != nil && (k.guardsItself(body) || k.thinLine(body) || k.onlyWaits(body)) {
				return true
			}
			if _, listed := allowed[f.path]; listed {
				used[f.path] = true
				return true
			}
			out = append(out, f.path+": a goroutine that does not keep its panic (its first statement must be a deferred function that calls recover); a panic here ends the process for every tenant")
			return true
		})
	}
	for p := range allowed {
		if !used[p] {
			out = append(out, p+" is on goroutineUnrecovered and has no uncovered goroutine; delete the entry")
		}
	}
	sort.Strings(out)
	return out
}

// parsePanicFiles parses planted sources into one file set.
func parsePanicFiles(t *testing.T, src map[string]string) (*token.FileSet, []file) {
	t.Helper()
	fset := token.NewFileSet()
	var fs []file
	for name, s := range src {
		f, err := parser.ParseFile(fset, name, s, 0)
		if err != nil {
			t.Fatal(err)
		}
		fs = append(fs, file{path: name, ast: f})
	}
	sort.Slice(fs, func(i, j int) bool { return fs[i].path < fs[j].path })
	return fset, fs
}

func TestEveryGoroutineKeepsItsPanic(t *testing.T) {
	fset, files := parseRepo(t)
	var gf []file
	goStatements := 0
	for _, f := range files {
		if f.test {
			continue
		}
		gf = append(gf, f)
		ast.Inspect(f.ast, func(n ast.Node) bool {
			if _, ok := n.(*ast.GoStmt); ok {
				goStatements++
			}
			return true
		})
	}
	if goStatements < 10 {
		t.Fatalf("the lint saw %d goroutines; it is looking in the wrong place", goStatements)
	}
	for _, p := range panicKeepProblems(fset, gf, goroutineUnrecovered) {
		t.Error(p)
	}
}

// The lint can fail: each shape is planted, and the covered shapes pass.
func TestGoroutineLintCanFail(t *testing.T) {
	const pre = "package p\nimport \"sync\"\nvar _ sync.Mutex\nfunc work() {}\nfunc decode(b []byte) []byte { return b }\n"
	bad := map[string]string{
		"literal":                        "func f() { go func() { work() }() }",
		"named":                          "func g() { go run() }\nfunc run() { work() }",
		"method":                         "type L struct{}\nfunc (l *L) h() { go l.run() }\nfunc (l *L) run() { work() }",
		"a recover that is not deferred": "func f() { go func() { _ = recover(); work() }() }",
		"work before a helper": "type Q struct{}\nfunc (q *Q) protect(fn func()) { defer func() { _ = recover() }(); fn() }\n" +
			"func f(q *Q) { go func() { row := decode(nil); q.protect(func() { _ = row }) }() }",
		"the deferred guard is not first":  "func f() { go func() { work(); defer func() { _ = recover() }() }() }",
		"defer recover directly":           "func f() { go func() { defer recover(); work() }() }",
		"a recover one literal too deep":   "func f() { go func() { defer func() { func() { _ = recover() }() }(); work() }() }",
		"a shadowed recover":               "func f() { recover := func() any { return nil }; go func() { defer func() { _ = recover() }(); work() }() }",
		"a Wait that is not a WaitGroup's": "type W struct{}\nfunc (W) Wait() {}\nfunc f(w W, c chan int) { go func() { w.Wait(); close(c) }() }",
		"a same name that is not the guard": "func protect() { defer func() { _ = recover() }() }\ntype R struct{}\nfunc (R) protect() {}\n" +
			"func f(r R) { go func() { defer r.protect(); work() }() }",
		"an interface callee":      "type I interface{ Run() }\nfunc f(i I) { go i.Run() }",
		"a function value":         "func f(fn func()) { go fn() }",
		"a thin line over a plain": "func f() { go func() { plain() }() }\nfunc plain() { work() }",
	}
	for name, src := range bad {
		fset, fs := parsePanicFiles(t, map[string]string{"p/x.go": pre + src})
		if got := panicKeepProblems(fset, fs, nil); len(got) != 1 {
			t.Errorf("%s: %v, want one problem", name, got)
		}
	}
	good := map[string]string{
		"own":             "func f() { go func() { defer func() { _ = recover() }(); work() }() }",
		"named":           "func g() { go run() }\nfunc run() { defer func() { _ = recover() }(); work() }",
		"deferred helper": "func keep() { _ = recover() }\nfunc g() { go run() }\nfunc run() { defer keep(); work() }",
		"a method guard":  "type Q struct{}\nfunc (q *Q) keep() { _ = recover() }\nfunc (q *Q) g() { go q.run() }\nfunc (q *Q) run() { defer q.keep(); work() }",
		"a thin line":     "func f() { go func() { guarded() }() }\nfunc guarded() { defer func() { _ = recover() }(); work() }",
		"wait":            "func f(wg *sync.WaitGroup, c chan int) { go func() { wg.Wait(); close(c) }() }",
		"count down":      "func f(wg *sync.WaitGroup, c chan int) { go func() { defer wg.Done(); defer close(c) }() }",
	}
	for name, src := range good {
		fset, fs := parsePanicFiles(t, map[string]string{"p/x.go": pre + src})
		if got := panicKeepProblems(fset, fs, nil); len(got) != 0 {
			t.Errorf("%s: %v, want none", name, got)
		}
	}
	// A listing covers its file, and a stale one fails.
	fset, fs := parsePanicFiles(t, map[string]string{"p/x.go": pre + "func f() { go func() { work() }() }"})
	if got := panicKeepProblems(fset, fs, map[string]string{"p/x.go": "why"}); len(got) != 0 {
		t.Errorf("a listed file was judged: %v", got)
	}
	fset, fs = parsePanicFiles(t, map[string]string{"p/y.go": "package p\n"})
	if got := panicKeepProblems(fset, fs, map[string]string{"p/y.go": "why"}); len(got) != 1 {
		t.Errorf("a stale entry passed: %v", got)
	}
}
