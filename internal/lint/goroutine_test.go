package lint_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"sort"
	"strings"
	"testing"
)

// Rule goroutine-recover (P1 auth review round 14, tenant-r14-2; tightened in round 15, tenant-r15-3;
// rebuilt in round 18, sms-r18-1, D64 goroutine-panic). Go ends the whole process on a panic in any
// goroutine, and the request recover of the pipeline covers only the request's own. Rounds 14, 15 and
// 17 each found a goroutine with no recover, and the lint that looked for one followed only the callees
// the type checker could resolve, so `go fn()` through a function value or an interface method, and
// every shape the next round invented, passed or needed one more case.
//
// The rule is now a construction and not a search. Non-test code starts a goroutine in exactly one
// place, internal/safego (Go, which keeps the panic of the function it runs, logs the unit and counts
// it), and this lint is purely syntactic about the rest: a `go` statement anywhere else is a finding,
// whatever it calls, so no callee has to be resolved. The statements that remain are the top-level
// loops that must NOT keep a panic, because a loop kept after a panic is a process that looks healthy
// to Compose and does nothing (the serve loop, the admin role's session sweep, the mutant runner of
// a test tool); each is listed by function, with its reason, and a stale entry fails.
//
// The one `go` statement of safego is read for its guard: its function must start with a deferred
// function that calls recover itself (a literal, or a function or method of the module whose own top
// level calls it), so a mutant that removes the recover is killed here, where no runtime test can kill
// it (a panic in a goroutine ends the test binary, which the registry reads as INVALID, sms-r17-14).
//
// Judged: every non-test Go file of every module under the repository (parseEveryModule, so shared/,
// a generator and a directory go list leaves out are read). Not judged: test files, which are not
// shipped; the function a goroutine runs (safego keeps its panic whatever it is); whether a top-level
// loop's reason is true (review reads it).

// topLoop is one entry of goroutineTopLevel: how many `go` statements the function holds and why they
// keep no panic. The count is part of the entry (sms-r18-15): an entry that listed the function only
// would let a second statement added to the same function, app.Run above all, pass unseen.
type topLoop struct {
	Statements int
	Why        string
}

// goroutineTopLevel lists the `go` statements outside internal/safego, by function ("path#Func" or
// "path#(Recv).Func", the unit of enclosing), each with how many and why they keep no panic.
var goroutineTopLevel = map[string]topLoop{
	"internal/app/app.go#Run":             {1, "the serve loop: net/http bodyRecovers a handler's panic itself, and a panic of Serve is a process that must end so Compose restarts it; kept, it would leave a listener nobody serves"},
	"internal/app/http.go#serviceHandler": {1, "the admin role's session sweep, a loop of fixed store statements in a process that serves one operator: kept after a panic it would end for good while the process looks healthy, so it crashes and Compose restarts it"},
	"internal/mutant/run.go#Run":          {1, "the mutant runner is a test tool and never ships in a service"},
}

// callbackSync lists the callees outside the module that are handed a function of no arguments and
// run it on the caller's own goroutine (key "path.Type.Method" or "path.Func"), each with why. Every
// other call outside the module that is handed such a function is a finding (sms-r18-14): a library
// that runs the function later or elsewhere (time.AfterFunc, context.AfterFunc, sync.WaitGroup.Go, an
// errgroup, a server's shutdown hook) starts a goroutine with no `go` statement, and a panic in it
// ends the process like an unguarded one. A stale entry fails.
var callbackSync = map[string]string{
	"sync.Once.Do":           "runs the function at once, on the caller's goroutine; a panic is the caller's own",
	"sync.OnceValue":         "returns a function that runs the one given on the first call, on that caller's goroutine; nothing is started here",
	"sync.OnceFunc":          "returns a function that runs the one given on the first call, on that caller's goroutine; nothing is started here",
	"testing.TB.Cleanup":     "the interface form of the same: the test runs it when it ends, on its own goroutine",
	"testing.common.Cleanup": "runs when the test ends, on the test's goroutine; the helper files that take a *testing.T are never part of a service (the method is promoted from the unexported common)",
}

// safegoDir is the one package that starts goroutines.
const safegoDir = "internal/safego/"

// panicKeeper answers the questions of the guard shape from one type-checked set of files.
type panicKeeper struct {
	info  *types.Info
	decls map[types.Object]*ast.FuncDecl
}

// newPanicKeeper type-checks the files with the real sync, time, context and testing packages, so the
// members of those that start work resolve by object whatever the import is called; every other
// package outside the module is an empty stub, and a call into it resolves to nothing, which the
// callback rule reads as outside the module (fail closed).
func newPanicKeeper(fset *token.FileSet, files []file) (*panicKeeper, bool) {
	info, ok := typeInfoReal(fset, files, "sync", "time", "context", "testing")
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
// A generic function is looked up by its origin, with or without an explicit instantiation.
func (k *panicKeeper) callee(c *ast.CallExpr) *ast.FuncDecl {
	var obj types.Object
	fun := unparen(c.Fun)
	if ix, ok := fun.(*ast.IndexExpr); ok { // Keep[K](...)
		fun = unparen(ix.X)
	}
	switch fun := fun.(type) {
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

// builtin reports a call of the named builtin (recover), so a local that shadows the name does not
// count.
func (k *panicKeeper) builtin(c *ast.CallExpr, name string) bool {
	id, ok := unparen(c.Fun).(*ast.Ident)
	if !ok {
		return false
	}
	b, ok := k.info.Uses[id].(*types.Builtin)
	return ok && b.Name() == name
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

// guardsItself reports the guard shape: the first statement is a deferred function that recovers.
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

// niladicFunc reports a function type that takes nothing and returns nothing or one error: the shape
// of the work a library is handed to run (func(), and func() error of an errgroup).
func niladicFunc(t types.Type) bool {
	if t == nil {
		return false
	}
	s, ok := t.Underlying().(*types.Signature)
	if !ok || s.Params().Len() != 0 {
		return false
	}
	switch s.Results().Len() {
	case 0:
		return true
	case 1:
		n, ok := s.Results().At(0).Type().(*types.Named)
		return ok && n.Obj().Pkg() == nil && n.Obj().Name() == "error"
	}
	return false
}

// calleeKey names a call's callee for the callback rule. inModule is true for a function or method
// with a body in the checked files: what it does with a function it is given is read where it is
// written, so a `go`, a time.AfterFunc or any other starter inside it is a finding of its own. Every
// other callee is outside: a package of the standard library or another module, an interface method,
// a function value, a field of function type, a method value, and anything the checker could not
// resolve. The key is "path.Func" or "path.Type.Method" when the callee is a declared function.
func (k *panicKeeper) calleeKey(c *ast.CallExpr) (key string, inModule, skip bool) {
	if tv, ok := k.info.Types[c.Fun]; ok && tv.IsType() {
		return "", false, true // a conversion
	}
	fun := unparen(c.Fun)
	switch ix := fun.(type) {
	case *ast.IndexExpr:
		fun = unparen(ix.X)
	case *ast.IndexListExpr:
		fun = unparen(ix.X)
	}
	var obj types.Object
	switch fun := fun.(type) {
	case *ast.Ident:
		obj = k.info.Uses[fun]
	case *ast.SelectorExpr:
		if s := k.info.Selections[fun]; s != nil {
			obj = s.Obj()
		} else {
			obj = k.info.Uses[fun.Sel]
		}
	}
	if _, isBuiltin := obj.(*types.Builtin); isBuiltin {
		return "", false, true
	}
	fn, ok := obj.(*types.Func)
	if !ok || fn.Pkg() == nil {
		return "?" + types.ExprString(c.Fun), false, false
	}
	if k.decls[fn.Origin()] != nil {
		return "", true, false
	}
	key = fn.Pkg().Path() + "."
	if sig, ok := fn.Type().(*types.Signature); ok && sig.Recv() != nil {
		rt := sig.Recv().Type()
		if p, ok := rt.(*types.Pointer); ok {
			rt = p.Elem()
		}
		if n, ok := rt.(*types.Named); ok {
			key += n.Obj().Name() + "."
		}
	}
	return key + fn.Name(), false, false
}

// callbackProblems judges every call outside the module that is handed a function of no arguments, in
// the given non-test files. Judged: calls, by type-checked object, so an alias of the import, a method
// value, an interface value and a wrapper in the same package are seen alike. A call inside
// internal/safego is held to the shape of its `go` statement: the function it is handed must be a
// literal that starts with the guard. Not judged: a callback that takes arguments (a finalizer is
// refused by the capability guard's runtime member list, an http hook by its net/http list), and a
// function stored in a struct or a slice and run later by the module's own code, which is a call of
// a function value and is read where it is made.
func (k *panicKeeper) callbackProblems(files []file, listed map[string]string) []string {
	var out []string
	used := map[string]bool{}
	for _, f := range files {
		inSafego := strings.HasPrefix(f.path, safegoDir)
		ast.Inspect(f.ast, func(n ast.Node) bool {
			c, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			key, inModule, skip := k.calleeKey(c)
			if inModule || skip {
				return true
			}
			for _, a := range c.Args {
				if !niladicFunc(k.info.Types[a].Type) {
					if lit, isLit := unparen(a).(*ast.FuncLit); !isLit || len(lit.Type.Params.List) != 0 {
						continue
					}
				}
				if _, sync := listed[key]; sync {
					used[key] = true
					continue
				}
				if lit, isLit := unparen(a).(*ast.FuncLit); inSafego && isLit && k.guardsItself(lit.Body) {
					continue
				}
				where := "in " + enclosing(f.ast, c.Pos())
				if inSafego {
					out = append(out, f.path+": a callback of safego that does not keep its panic ("+where+"; the literal it hands over must start with a deferred function that calls recover)")
				} else {
					out = append(out, f.path+": a function handed to "+strings.TrimPrefix(key, "?")+" "+where+", which may run it in a goroutine of its own; use safego (Go, After, OnDone), which keeps its panic (a panic in any goroutine ends the process for every tenant); a library call that runs it at once on the caller's goroutine is listed in callbackSync with the reason")
				}
			}
			return true
		})
	}
	for p := range listed {
		if !used[p] {
			out = append(out, p+" is on callbackSync and nothing is handed to it; delete the entry")
		}
	}
	return out
}

// goStatementProblems judges every `go` statement of the given non-test files, and every library call
// that starts one for the module (callbackProblems). allowed is goroutineTopLevel and listed is
// callbackSync, parameters so the can-fail test can pass its own.
func goStatementProblems(fset *token.FileSet, files []file, allowed map[string]topLoop, listed map[string]string) []string {
	var out []string
	count := map[string]int{}
	k, ok := newPanicKeeper(fset, files)
	if !ok {
		return []string{"type information unavailable"}
	}
	safegoStatements := 0
	for _, f := range files {
		ast.Inspect(f.ast, func(n ast.Node) bool {
			g, ok := n.(*ast.GoStmt)
			if !ok {
				return true
			}
			if strings.HasPrefix(f.path, safegoDir) {
				safegoStatements++
				var body *ast.BlockStmt
				if lit, isLit := unparen(g.Call.Fun).(*ast.FuncLit); isLit {
					body = lit.Body
				} else if fd := k.callee(g.Call); fd != nil {
					body = fd.Body
				}
				if body == nil || !k.guardsItself(body) {
					out = append(out, f.path+": a goroutine of safego that does not keep its panic (its first statement must be a deferred function that calls recover); every other goroutine of the module is started through it")
				}
				return true
			}
			key := f.path + "#" + enclosing(f.ast, g.Pos())
			if _, listed := allowed[key]; listed {
				count[key]++
				return true
			}
			out = append(out, f.path+": `go` statement in "+enclosing(f.ast, g.Pos())+" outside internal/safego; start the goroutine with safego.Go, which keeps its panic (a panic in any goroutine ends the process for every tenant)")
			return true
		})
	}
	if safegoStatements == 0 {
		out = append(out, "internal/safego has no go statement; the lint is looking at the wrong place or Go was removed")
	}
	for p, e := range allowed {
		switch n := count[p]; {
		case n == 0:
			out = append(out, p+" is on goroutineTopLevel and has no go statement; delete the entry")
		case n > e.Statements:
			out = append(out, fmt.Sprintf("%s holds %d go statements and goroutineTopLevel lists %d; a new one is started with safego.Go, not added to the list", p, n, e.Statements))
		case n < e.Statements:
			out = append(out, fmt.Sprintf("%s holds %d go statements and goroutineTopLevel lists %d; lower the count", p, n, e.Statements))
		}
	}
	out = append(out, k.callbackProblems(files, listed)...)
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
	fset := token.NewFileSet()
	all, err := parseEveryModule(fset, repoRoot(t), parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	var gf []file
	for _, f := range all {
		if !f.test {
			gf = append(gf, f)
		}
	}
	if len(gf) < 100 {
		t.Fatalf("the lint saw %d non-test files; it is looking in the wrong place", len(gf))
	}
	for _, p := range goStatementProblems(fset, gf, goroutineTopLevel, callbackSync) {
		t.Error(p)
	}
}

// The lint can fail: every form a goroutine can be started in is planted outside safego and each is
// one problem, whatever it calls; the guard of safego is read; the listing is by function.
func TestGoroutineLintCanFail(t *testing.T) {
	const safeGood = "package safego\nfunc Keep() { _ = recover() }\nfunc Go(fn func()) { go func() { defer Keep(); fn() }() }\n"
	const pre = "package p\nimport \"sync\"\nvar _ sync.Mutex\nfunc work() {}\n"
	bad := map[string]string{
		"literal":                "func f() { go func() { work() }() }",
		"named":                  "func g() { go run() }\nfunc run() { work() }",
		"method":                 "type L struct{}\nfunc (l *L) h() { go l.run() }\nfunc (l *L) run() { work() }",
		"a guarded literal":      "func f() { go func() { defer func() { _ = recover() }(); work() }() }", // guarded, but not by safego
		"a guarded named":        "func g() { go run() }\nfunc run() { defer func() { _ = recover() }(); work() }",
		"an interface callee":    "type I interface{ Run() }\nfunc f(i I) { go i.Run() }",
		"a function value":       "func f(fn func()) { go fn() }",
		"a thin line":            "func f() { go func() { guarded() }() }\nfunc guarded() { defer func() { _ = recover() }(); work() }",
		"only waits":             "func f(wg *sync.WaitGroup, c chan int) { go func() { wg.Wait(); close(c) }() }",
		"a count-down":           "func f(wg *sync.WaitGroup) { go func() { defer wg.Done(); work() }() }",
		"a package-level var":    "var _ = func() int { go work(); return 0 }()",
		"a method value":         "type L struct{}\nfunc (L) run() {}\nfunc f(l L) { m := l.run; go m() }",
		"a name that looks safe": "func Go(fn func()) { go fn() }\nfunc f() { Go(work) }",
	}
	for name, src := range bad {
		fset, fs := parsePanicFiles(t, map[string]string{"p/x.go": pre + src, safegoDir + "safego.go": safeGood})
		got := goStatementProblems(fset, fs, nil, nil)
		if len(got) != 1 || !strings.Contains(got[0], "outside internal/safego") {
			t.Errorf("%s: %v, want one problem outside safego", name, got)
		}
	}
	// A file of another module and a generator are read the same way: the lint judges files, not packages.
	fset, fs := parsePanicFiles(t, map[string]string{"shared/s/s.go": pre + "func f() { go work() }", "tools/gen/main.go": pre + "func main() { go work() }", safegoDir + "safego.go": safeGood})
	if got := goStatementProblems(fset, fs, nil, nil); len(got) != 2 {
		t.Errorf("shared and tools: %v, want two problems", got)
	}
	// The guard of safego is read: each way to lose it is one problem.
	for name, src := range map[string]string{
		"no recover":                     "package safego\nfunc Go(fn func()) { go func() { fn() }() }\n",
		"a recover that is not deferred": "package safego\nfunc Go(fn func()) { go func() { _ = recover(); fn() }() }\n",
		"the guard is not first":         "package safego\nfunc Keep() { _ = recover() }\nfunc Go(fn func()) { go func() { fn(); defer Keep() }() }\n",
		"defer recover directly":         "package safego\nfunc Go(fn func()) { go func() { defer recover(); fn() }() }\n",
		"a recover one literal too deep": "package safego\nfunc Go(fn func()) { go func() { defer func() { func() { _ = recover() }() }(); fn() }() }\n",
		"a shadowed recover":             "package safego\nfunc Go(fn func()) { recover := func() any { return nil }; go func() { defer func() { _ = recover() }(); fn() }() }\n",
		"a guard that does not recover":  "package safego\nfunc Keep() {}\nfunc Go(fn func()) { go func() { defer Keep(); fn() }() }\n",
		"a function value":               "package safego\nfunc Go(fn func()) { go fn() }\n",
	} {
		fset, fs := parsePanicFiles(t, map[string]string{safegoDir + "safego.go": src})
		got := goStatementProblems(fset, fs, nil, nil)
		if len(got) != 1 || !strings.Contains(got[0], "does not keep its panic") {
			t.Errorf("safego, %s: %v, want one problem", name, got)
		}
	}
	// Good: the guarded shapes of safego, a generic guard with and without an explicit instantiation.
	for name, src := range map[string]string{
		"a literal guard":           "package safego\nfunc Go(fn func()) { go func() { defer func() { _ = recover() }(); fn() }() }\n",
		"a deferred helper":         safeGood,
		"a generic guard":           "package safego\nfunc Keep[K ~string](k K) { if recover() != nil { _ = k } }\nfunc Go[K ~string](k K, fn func()) { go func() { defer Keep(k); fn() }() }\n",
		"an explicit instantiation": "package safego\nfunc Keep[K ~string](k K) { if recover() != nil { _ = k } }\nfunc Go[K ~string](k K, fn func()) { go func() { defer Keep[K](k); fn() }() }\n",
	} {
		fset, fs := parsePanicFiles(t, map[string]string{safegoDir + "safego.go": src})
		if got := goStatementProblems(fset, fs, nil, nil); len(got) != 0 {
			t.Errorf("safego, %s: %v, want none", name, got)
		}
	}
	// A listing covers its function and no other function of the same file, and a stale one fails.
	two := pre + "func f() { go work() }\nfunc g() { go work() }"
	fset, fs = parsePanicFiles(t, map[string]string{"p/x.go": two, safegoDir + "safego.go": safeGood})
	if got := goStatementProblems(fset, fs, map[string]topLoop{"p/x.go#f": {1, "why"}}, nil); len(got) != 1 || !strings.Contains(got[0], "in g outside") {
		t.Errorf("a listed function hid its sibling: %v", got)
	}
	if got := goStatementProblems(fset, fs, map[string]topLoop{"p/x.go#f": {1, "why"}, "p/x.go#g": {1, "why"}}, nil); len(got) != 0 {
		t.Errorf("two listed functions were judged: %v", got)
	}
	fset, fs = parsePanicFiles(t, map[string]string{"p/y.go": "package p\n", safegoDir + "safego.go": safeGood})
	if got := goStatementProblems(fset, fs, map[string]topLoop{"p/y.go#f": {1, "why"}}, nil); len(got) != 1 {
		t.Errorf("a stale entry passed: %v", got)
	}
	// A tree with no safego go statement is the lint looking in the wrong place.
	fset, fs = parsePanicFiles(t, map[string]string{"p/y.go": "package p\n"})
	if got := goStatementProblems(fset, fs, nil, nil); len(got) != 1 {
		t.Errorf("no safego statement passed: %v", got)
	}
}

// A second statement in a listed function is a finding, and a listed count that is too high is stale
// (sms-r18-15).
func TestGoroutineTopLevelListingCountsStatements(t *testing.T) {
	const safeGood = "package safego\nfunc Keep() { _ = recover() }\nfunc Go(fn func()) { go func() { defer Keep(); fn() }() }\n"
	const pre = "package p\nfunc work() {}\n"
	two := pre + "func f() { go work(); go work() }"
	fset, fs := parsePanicFiles(t, map[string]string{"p/x.go": two, safegoDir + "safego.go": safeGood})
	if got := goStatementProblems(fset, fs, map[string]topLoop{"p/x.go#f": {1, "why"}}, nil); len(got) != 1 || !strings.Contains(got[0], "holds 2 go statements") {
		t.Errorf("a second statement in a listed function passed: %v", got)
	}
	if got := goStatementProblems(fset, fs, map[string]topLoop{"p/x.go#f": {2, "why"}}, nil); len(got) != 0 {
		t.Errorf("a listed count was refused: %v", got)
	}
	one := pre + "func f() { go work() }"
	fset, fs = parsePanicFiles(t, map[string]string{"p/x.go": one, safegoDir + "safego.go": safeGood})
	if got := goStatementProblems(fset, fs, map[string]topLoop{"p/x.go#f": {2, "why"}}, nil); len(got) != 1 || !strings.Contains(got[0], "lower the count") {
		t.Errorf("a count above the statements passed: %v", got)
	}
}

// Rule goroutine-recover also covers the library calls that start a goroutine with no `go` statement
// (sms-r18-14): every call outside the module that is handed a function of no arguments is a finding
// unless it is listed as synchronous. Each form Go allows is planted: the member by import, by an
// alias of the import, a method value, an interface value, a field of function type, a wrapper in the
// same package, a package of another module that the checker cannot read, and a file of shared/.
func TestCallbackLintCanFail(t *testing.T) {
	const safeGood = "package safego\nfunc Keep() { _ = recover() }\nfunc Go(fn func()) { go func() { defer Keep(); fn() }() }\n"
	const pre = "package p\nimport (\n\t\"context\"\n\t\"net/http\"\n\t\"sync\"\n\t\"time\"\n\ttm \"time\"\n\t\"golang.org/x/sync/errgroup\"\n)\nvar _ sync.Mutex\nvar _ = time.Now\nvar _ = tm.Now\nvar _ context.Context\nvar _ errgroup.Group\nvar _ http.Server\nfunc work() {}\n"
	bad := map[string]string{
		"sync.WaitGroup.Go":     "func f(wg *sync.WaitGroup) { wg.Go(work) }",
		"time.AfterFunc":        "func f() { time.AfterFunc(0, work) }",
		"a literal":             "func f() { time.AfterFunc(0, func() { panic(1) }) }",
		"an alias of import":    "func f() { tm.AfterFunc(0, work) }",
		"context.AfterFunc":     "func f(ctx context.Context) { context.AfterFunc(ctx, work) }",
		"an errgroup":           "func f(g *errgroup.Group) { g.Go(func() error { return nil }) }",
		"a server hook":         "func f(s *http.Server) { s.RegisterOnShutdown(work) }",
		"a method value":        "func f(wg *sync.WaitGroup) { m := wg.Go; m(work) }",
		"an interface value":    "type S interface{ Go(func()) }\nfunc f(s S) { s.Go(work) }",
		"a function field":      "type H struct{ Start func(func()) }\nfunc f(h H) { h.Start(work) }",
		"a wrapper":             "func start(fn func()) { time.AfterFunc(0, fn) }\nfunc f() { start(work) }",
		"sync.Once.Do unlisted": "func f(o *sync.Once) { o.Do(work) }",
	}
	for name, src := range bad {
		fset, fs := parsePanicFiles(t, map[string]string{"p/x.go": pre + src, safegoDir + "safego.go": safeGood})
		got := goStatementProblems(fset, fs, nil, nil)
		if len(got) != 1 || !strings.Contains(got[0], "goroutine of its own") {
			t.Errorf("%s: %v, want one problem", name, got)
		}
	}
	fset, fs := parsePanicFiles(t, map[string]string{"shared/s/s.go": pre + "func f() { time.AfterFunc(0, work) }", safegoDir + "safego.go": safeGood})
	if got := goStatementProblems(fset, fs, nil, nil); len(got) != 1 {
		t.Errorf("shared: %v, want one problem", got)
	}
	// A listed synchronous callee passes, and a listing nothing uses is stale.
	use := pre + "func f(o *sync.Once) { o.Do(work) }"
	fset, fs = parsePanicFiles(t, map[string]string{"p/x.go": use, safegoDir + "safego.go": safeGood})
	if got := goStatementProblems(fset, fs, nil, map[string]string{"sync.Once.Do": "why"}); len(got) != 0 {
		t.Errorf("a listed callee was refused: %v", got)
	}
	fset, fs = parsePanicFiles(t, map[string]string{"p/x.go": pre, safegoDir + "safego.go": safeGood})
	if got := goStatementProblems(fset, fs, nil, map[string]string{"sync.Once.Do": "why"}); len(got) != 1 || !strings.Contains(got[0], "callbackSync") {
		t.Errorf("a stale listing passed: %v", got)
	}
	// Inside safego a callback is held to the shape of the go statement.
	const sp = "package safego\nimport \"time\"\nfunc Keep() { _ = recover() }\nfunc Go(fn func()) { go func() { defer Keep(); fn() }() }\n"
	for name, c := range map[string]struct {
		src string
		bad bool
	}{
		"a guarded callback":   {"func After(d time.Duration, fn func()) *time.Timer { return time.AfterFunc(d, func() { defer Keep(); fn() }) }", false},
		"a function value":     {"func After(d time.Duration, fn func()) *time.Timer { return time.AfterFunc(d, fn) }", true},
		"an unguarded literal": {"func After(d time.Duration, fn func()) *time.Timer { return time.AfterFunc(d, func() { fn() }) }", true},
		"a guard not first":    {"func After(d time.Duration, fn func()) *time.Timer { return time.AfterFunc(d, func() { fn(); defer Keep() }) }", true},
	} {
		fset, fs := parsePanicFiles(t, map[string]string{safegoDir + "safego.go": sp + c.src})
		got := goStatementProblems(fset, fs, nil, nil)
		if c.bad != (len(got) == 1 && strings.Contains(got[0], "callback of safego")) || (!c.bad && len(got) != 0) {
			t.Errorf("safego, %s: %v", name, got)
		}
	}
}
