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

// The cache-loader rule (P1 auth review, round 5, topic 15; spec 2.3, 9.8, 14.1, 18.3).
//
// Three hand-written caches (the public configuration, the Valkey client, the SMS router
// snapshot) each wrote their own lock, reload, retry and invalidation, and in turn held a
// mutex across I/O, retried on every request after a failure, lost an Invalidate that came
// during a reload, or served a stale snapshot to a send that needed what had just been
// saved. The structural answer is internal/cachex: one generic loader that loads outside its
// lock, runs a single flight, serves a stale value while it revalidates, backs off after a
// failure, checks a generation on invalidation and has a Fresh call. This file is the
// enforcement that does not depend on anyone remembering to use it:
//
//	No function holds a mutex across a call that takes a context.Context, or across a wait.
//
// A call that takes a context is the I/O (a query, a dial, an HTTP call); the waits that
// hold the same hazard without a context are a channel receive or send, a select without a
// default, time.Sleep and WaitGroup.Wait. "Holds" is read from the source of one function:
// from x.Lock() (or RLock) until the matching x.Unlock() (or RUnlock) on the same
// expression, or to the end of the function after `defer x.Unlock()`. The walk follows the
// control flow well enough that a branch that unlocks and returns does not release the lock
// for the code after the branch, which is exactly the shape of "load the snapshot under
// r.mu": an early return on the fresh path, an Unlock in it, and the load further down.
//
// A function literal that is passed to a call or called on the spot runs under the lock
// that is held there; one that is stored, or started with go, does not and is judged on its
// own. A lock taken in one function and released in another is not followed: the callee's
// own body is judged, and the cachex loader is the only place that should be that clever.
//
// There is no opt-out comment. A cache that needs I/O under a lock needs the loader.

// lockIOStdlib is type-checked from source, so that context.Context, sync.Mutex,
// sync.WaitGroup and time.Sleep are the real objects and not names.
var lockIOStdlib = []string{"context", "sync", "time"}

// lockIOWalker walks one function's statements in control-flow order.
type lockIOWalker struct {
	fset *token.FileSet
	info *types.Info
	// fn names the enclosing declaration for messages.
	fn       string
	problems *[]string
	// lits are function literals that are not run on the spot; they are judged alone.
	lits []*ast.FuncLit
	// deferred holds the mutexes that have a deferred unlock registered: they stay held
	// to the end of the function, and a later defer runs before the unlock does.
	deferred map[string]bool
	// breaks collects the held sets at a `break`, for the statement that is left.
	breaks []heldSet
	// locks counts the Lock calls seen, so the test can tell it is looking at something.
	locks *int
}

// heldSet maps the text of a mutex expression to where it was locked.
type heldSet map[string]token.Pos

func (h heldSet) clone() heldSet {
	c := make(heldSet, len(h))
	for k, v := range h {
		c[k] = v
	}
	return c
}

// join is the union: a mutex held on any path that reaches the join is treated as held.
func join(sets ...heldSet) heldSet {
	out := heldSet{}
	for _, s := range sets {
		for k, v := range s {
			if _, ok := out[k]; !ok {
				out[k] = v
			}
		}
	}
	return out
}

func (w *lockIOWalker) at(p token.Pos) string { return w.fset.Position(p).String() }

// syncMethod returns the name of the sync package method a call invokes ("Lock",
// "Unlock", "Wait", ...) and the text of its receiver, or "" when it is none.
func (w *lockIOWalker) syncMethod(call *ast.CallExpr) (name, recv string) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return "", ""
	}
	fn, ok := w.info.ObjectOf(sel.Sel).(*types.Func)
	if !ok || fn.Pkg() == nil || fn.Pkg().Path() != "sync" {
		return "", ""
	}
	return fn.Name(), exprText(sel.X)
}

// blocking says why a call waits without a context, or "".
func (w *lockIOWalker) blocking(call *ast.CallExpr) string {
	if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
		if fn, ok := w.info.ObjectOf(sel.Sel).(*types.Func); ok && fn.Pkg() != nil {
			switch {
			case fn.Pkg().Path() == "time" && fn.Name() == "Sleep":
				return "time.Sleep"
			case fn.Pkg().Path() == "sync" && fn.Name() == "Wait" && exprIsWaitGroup(w.info, sel.X):
				return "WaitGroup.Wait"
			}
		}
	}
	return ""
}

func exprIsWaitGroup(info *types.Info, e ast.Expr) bool {
	t := info.TypeOf(e)
	if p, ok := t.(*types.Pointer); ok {
		t = p.Elem()
	}
	n, ok := t.(*types.Named)
	return ok && n.Obj().Name() == "WaitGroup"
}

func (w *lockIOWalker) heldText(h heldSet) string {
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return fmt.Sprintf("%s (locked at %s)", keys[0], w.at(h[keys[0]]))
}

func (w *lockIOWalker) report(pos token.Pos, what string, h heldSet) {
	*w.problems = append(*w.problems, fmt.Sprintf("%s: %s %s while holding %s; load outside the lock with internal/cachex", w.at(pos), w.fn, what, w.heldText(h)))
}

// callTakesContext reports whether any argument of the call is a context.Context.
func (w *lockIOWalker) callTakesContext(call *ast.CallExpr) bool {
	for _, a := range call.Args {
		if tv, ok := w.info.Types[a]; ok && !tv.IsType() && tv.Type != nil && isContextType(tv.Type) {
			return true
		}
	}
	return false
}

// expr judges every call, receive and function literal inside an expression.
func (w *lockIOWalker) expr(e ast.Node, h heldSet) {
	if e == nil {
		return
	}
	ast.Inspect(e, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.FuncLit:
			// Reached directly (an assignment, a return, a composite literal): stored for
			// later, so it does not run under this lock.
			w.lits = append(w.lits, n)
			return false
		case *ast.UnaryExpr:
			if n.Op == token.ARROW && len(h) > 0 {
				w.report(n.Pos(), "receives from a channel", h)
			}
		case *ast.CallExpr:
			if len(h) > 0 {
				if w.callTakesContext(n) {
					w.report(n.Pos(), "calls "+exprText(n.Fun)+" with a context", h)
				} else if what := w.blocking(n); what != "" {
					w.report(n.Pos(), "calls "+what, h)
				}
			}
			// A literal given to a call, or called on the spot, runs under the lock.
			args := append([]ast.Expr{n.Fun}, n.Args...)
			for _, a := range args {
				if lit, ok := a.(*ast.FuncLit); ok {
					w.block(lit.Body.List, h.clone())
				} else {
					w.expr(a, h)
				}
			}
			return false
		}
		return true
	})
}

// block walks statements and returns the held set at the end, and whether the block
// always leaves (return, panic, break, continue, goto) before reaching its end.
func (w *lockIOWalker) block(list []ast.Stmt, h heldSet) (heldSet, bool) {
	for _, s := range list {
		var leaves bool
		h, leaves = w.stmt(s, h)
		if leaves {
			return h, true
		}
	}
	return h, false
}

func (w *lockIOWalker) stmt(s ast.Stmt, h heldSet) (heldSet, bool) {
	switch s := s.(type) {
	case *ast.ExprStmt:
		if call, ok := s.X.(*ast.CallExpr); ok {
			switch name, recv := w.syncMethod(call); name {
			case "Lock", "RLock":
				*w.locks++
				h = h.clone()
				h[recv] = call.Pos()
				return h, false
			case "Unlock", "RUnlock":
				h = h.clone()
				delete(h, recv)
				return h, false
			}
			if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "panic" {
				w.expr(s.X, h)
				return h, true
			}
		}
		w.expr(s.X, h)
	case *ast.DeferStmt:
		if name, recv := w.syncMethod(s.Call); name == "Unlock" || name == "RUnlock" {
			w.deferred[recv] = true
			return h, false
		}
		// Deferred calls run last-in first-out: one registered after a deferred unlock
		// runs while that mutex is still held.
		for k := range h {
			if w.deferred[k] && w.callTakesContext(s.Call) {
				w.report(s.Pos(), "defers "+exprText(s.Call.Fun)+" with a context", heldSet{k: h[k]})
				break
			}
		}
		// A deferred closure unlocking is the same as `defer x.Unlock()`.
		if lit, ok := s.Call.Fun.(*ast.FuncLit); ok {
			ast.Inspect(lit.Body, func(n ast.Node) bool {
				if c, ok := n.(*ast.CallExpr); ok {
					if name, recv := w.syncMethod(c); name == "Unlock" || name == "RUnlock" {
						w.deferred[recv] = true
					}
				}
				return true
			})
			return h, false
		}
		for _, a := range s.Call.Args {
			w.expr(a, h)
		}
	case *ast.GoStmt:
		for _, a := range s.Call.Args {
			w.expr(a, h)
		}
		if lit, ok := s.Call.Fun.(*ast.FuncLit); ok {
			w.lits = append(w.lits, lit)
		}
	case *ast.SendStmt:
		if len(h) > 0 {
			w.report(s.Pos(), "sends on a channel", h)
		}
		w.expr(s.Chan, h)
		w.expr(s.Value, h)
	case *ast.AssignStmt:
		for _, x := range s.Rhs {
			w.expr(x, h)
		}
		for _, x := range s.Lhs {
			w.expr(x, h)
		}
	case *ast.DeclStmt:
		w.expr(s.Decl, h)
	case *ast.IncDecStmt:
		w.expr(s.X, h)
	case *ast.ReturnStmt:
		for _, x := range s.Results {
			w.expr(x, h)
		}
		return h, true
	case *ast.BranchStmt:
		if s.Tok == token.BREAK {
			w.breaks = append(w.breaks, h)
		}
		return h, s.Tok != token.FALLTHROUGH
	case *ast.LabeledStmt:
		return w.stmt(s.Stmt, h)
	case *ast.BlockStmt:
		return w.block(s.List, h)
	case *ast.IfStmt:
		if s.Init != nil {
			h, _ = w.stmt(s.Init, h)
		}
		w.expr(s.Cond, h)
		thenH, thenLeaves := w.block(s.Body.List, h.clone())
		elseH, elseLeaves := h, false
		if s.Else != nil {
			elseH, elseLeaves = w.stmt(s.Else, h.clone())
		}
		return w.merge([]heldSet{thenH, elseH}, []bool{thenLeaves, elseLeaves})
	case *ast.ForStmt:
		if s.Init != nil {
			h, _ = w.stmt(s.Init, h)
		}
		w.expr(s.Cond, h)
		return w.loop(s.Body, s.Post, h)
	case *ast.RangeStmt:
		w.expr(s.X, h)
		return w.loop(s.Body, nil, h)
	case *ast.SwitchStmt:
		if s.Init != nil {
			h, _ = w.stmt(s.Init, h)
		}
		w.expr(s.Tag, h)
		return w.clauses(s.Body, h, false)
	case *ast.TypeSwitchStmt:
		if s.Init != nil {
			h, _ = w.stmt(s.Init, h)
		}
		w.stmt(s.Assign, h)
		return w.clauses(s.Body, h, false)
	case *ast.SelectStmt:
		return w.clauses(s.Body, h, true)
	}
	return h, false
}

// merge joins the states that leave an if or a switch.
func (w *lockIOWalker) merge(hs []heldSet, leaves []bool) (heldSet, bool) {
	var live []heldSet
	for i, h := range hs {
		if !leaves[i] {
			live = append(live, h)
		}
	}
	if len(live) == 0 {
		return heldSet{}, true
	}
	return join(live...), false
}

// loop walks a loop body once. The body may run zero times, and a break leaves with the
// state it had.
func (w *lockIOWalker) loop(body *ast.BlockStmt, post ast.Stmt, h heldSet) (heldSet, bool) {
	saved := w.breaks
	w.breaks = nil
	bodyH, _ := w.block(body.List, h.clone())
	if post != nil {
		w.stmt(post, bodyH)
	}
	out := join(h, bodyH, join(w.breaks...))
	w.breaks = saved
	return out, false
}

// clauses walks the cases of a switch or select. A select without a default waits.
func (w *lockIOWalker) clauses(body *ast.BlockStmt, h heldSet, isSelect bool) (heldSet, bool) {
	saved := w.breaks
	w.breaks = nil
	hasDefault := false
	for _, c := range body.List {
		switch c := c.(type) {
		case *ast.CaseClause:
			hasDefault = hasDefault || c.List == nil
		case *ast.CommClause:
			hasDefault = hasDefault || c.Comm == nil
		}
	}
	if isSelect && !hasDefault && len(h) > 0 {
		w.report(body.Pos(), "waits in a select", h)
	}
	var hs []heldSet
	var leaves []bool
	for _, c := range body.List {
		switch c := c.(type) {
		case *ast.CaseClause:
			for _, e := range c.List {
				w.expr(e, h)
			}
			ch, l := w.block(c.Body, h.clone())
			hs, leaves = append(hs, ch), append(leaves, l)
		case *ast.CommClause:
			ch := h.clone()
			// The communication of a select is the wait the select was already judged
			// for; only its calls and literals are looked at.
			if c.Comm != nil {
				w.commCalls(c.Comm, ch)
			}
			ch, l := w.block(c.Body, ch)
			hs, leaves = append(hs, ch), append(leaves, l)
		}
	}
	if !hasDefault && !isSelect {
		hs, leaves = append(hs, h), append(leaves, false)
	}
	for _, b := range w.breaks {
		hs, leaves = append(hs, b), append(leaves, false)
	}
	w.breaks = saved
	if len(hs) == 0 {
		return h, false
	}
	return w.merge(hs, leaves)
}

// commCalls judges the calls inside a select case's communication, not the receive itself.
func (w *lockIOWalker) commCalls(s ast.Stmt, h heldSet) {
	switch s := s.(type) {
	case *ast.ExprStmt:
		if u, ok := s.X.(*ast.UnaryExpr); ok && u.Op == token.ARROW {
			w.expr(u.X, h)
			return
		}
		w.expr(s.X, h)
	case *ast.AssignStmt:
		for _, r := range s.Rhs {
			if u, ok := r.(*ast.UnaryExpr); ok && u.Op == token.ARROW {
				w.expr(u.X, h)
			} else {
				w.expr(r, h)
			}
		}
	case *ast.SendStmt:
		w.expr(s.Chan, h)
		w.expr(s.Value, h)
	}
}

// lockIOProblems judges every function of the non-test files under dirs (a prefix match
// on the slash path). It returns the problems and how many Lock calls it saw.
func lockIOProblems(fset *token.FileSet, files []file, info *types.Info) ([]string, int) {
	var problems []string
	locks := 0
	for _, f := range files {
		if f.test || strings.HasPrefix(f.path, "shared/") {
			continue
		}
		judge := func(name string, body *ast.BlockStmt) {
			if body == nil {
				return
			}
			w := &lockIOWalker{fset: fset, info: info, fn: name, problems: &problems, deferred: map[string]bool{}, locks: &locks}
			w.block(body.List, heldSet{})
			// Literals that were stored are judged alone, and so are theirs.
			for i := 0; i < len(w.lits); i++ {
				sub := &lockIOWalker{fset: fset, info: info, fn: name + " (function literal)", problems: &problems, deferred: map[string]bool{}, locks: &locks}
				sub.block(w.lits[i].Body.List, heldSet{})
				w.lits = append(w.lits, sub.lits...)
			}
		}
		for _, d := range f.ast.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok {
				judge(fd.Name.Name, fd.Body)
			}
		}
		// Package-level function literals (var x = func() {...}).
		for _, d := range f.ast.Decls {
			if gd, ok := d.(*ast.GenDecl); ok {
				ast.Inspect(gd, func(n ast.Node) bool {
					if lit, ok := n.(*ast.FuncLit); ok {
						judge("a package-level function literal", lit.Body)
						return false
					}
					return true
				})
			}
		}
	}
	sort.Strings(problems)
	return dedupe(problems), locks
}

func TestNoMutexAcrossIO(t *testing.T) {
	fset, files := parseRepo(t)
	info, ok := typeInfoReal(fset, files, lockIOStdlib...)
	if !ok {
		t.Fatal("type information unavailable")
	}
	problems, locks := lockIOProblems(fset, files, info)
	for _, p := range problems {
		t.Error(p)
	}
	// The lint must be seeing the locks. The module has dozens; a type-check that lost
	// package sync would make every Lock call invisible and the rule pass for ever.
	if locks < 10 {
		t.Fatalf("only %d Lock calls were seen; the lint is not recognising sync.Mutex", locks)
	}
}

// TestNoMutexAcrossIOCanFail plants each way a function could hold a mutex across I/O, and
// the shapes that must stay allowed (a lock released first, a map guarded without a call).
func TestNoMutexAcrossIOCanFail(t *testing.T) {
	const pre = `package x
import (
	"context"
	"sync"
	"time"
)
var _ = time.Second
type src struct{}
func (src) Load(ctx context.Context) (int, error) { return 0, nil }
func use(int) {}
func plain(int) {}
type cache struct {
	mu  sync.Mutex
	rw  sync.RWMutex
	src src
	val int
	ch  chan int
	wg  sync.WaitGroup
}
type embedded struct {
	sync.Mutex
	src src
}
`
	cases := []struct {
		name string
		src  string
		want int
	}{
		// The mutant of the rule: the router loads its snapshot under its mutex.
		{"load under the lock", `func (c *cache) f(ctx context.Context) {
	c.mu.Lock()
	v, _ := c.src.Load(ctx)
	c.val = v
	c.mu.Unlock()
}`, 1},
		{"load under a deferred unlock", `func (c *cache) f(ctx context.Context) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, _ := c.src.Load(ctx)
	return v
}`, 1},
		{"load after a branch that unlocks and returns (the router's shape)", `func (c *cache) f(ctx context.Context) int {
	c.mu.Lock()
	if c.val > 0 {
		v := c.val
		c.mu.Unlock()
		return v
	}
	v, _ := c.src.Load(ctx)
	c.mu.Unlock()
	return v
}`, 1},
		{"load in a switch case that did not unlock", `func (c *cache) f(ctx context.Context) {
	c.mu.Lock()
	switch {
	case c.val > 0:
		c.mu.Unlock()
		return
	default:
		_, _ = c.src.Load(ctx)
	}
	c.mu.Unlock()
}`, 1},
		{"load in a loop under the lock", `func (c *cache) f(ctx context.Context) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := 0; i < 3; i++ {
		_, _ = c.src.Load(ctx)
	}
}`, 1},
		{"a derived context", `func (c *cache) f(ctx context.Context) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	_, _ = c.src.Load(cctx)
}`, 2},
		{"a read lock", `func (c *cache) f(ctx context.Context) {
	c.rw.RLock()
	defer c.rw.RUnlock()
	_, _ = c.src.Load(ctx)
}`, 1},
		{"an embedded mutex", `func (e *embedded) f(ctx context.Context) {
	e.Lock()
	defer e.Unlock()
	_, _ = e.src.Load(ctx)
}`, 1},
		{"a local mutex", `func f(ctx context.Context, s src) {
	var mu sync.Mutex
	mu.Lock()
	_, _ = s.Load(ctx)
	mu.Unlock()
}`, 1},
		{"a closure passed to a call runs under the lock", `func run(fn func()) { fn() }
func (c *cache) f(ctx context.Context) {
	c.mu.Lock()
	defer c.mu.Unlock()
	run(func() { _, _ = c.src.Load(ctx) })
}`, 1},
		{"a closure called on the spot", `func (c *cache) f(ctx context.Context) {
	c.mu.Lock()
	defer c.mu.Unlock()
	func() { _, _ = c.src.Load(ctx) }()
}`, 1},
		{"a channel receive", `func (c *cache) f() {
	c.mu.Lock()
	defer c.mu.Unlock()
	<-c.ch
}`, 1},
		{"a channel send", `func (c *cache) f() {
	c.mu.Lock()
	c.ch <- 1
	c.mu.Unlock()
}`, 1},
		{"a select that waits", `func (c *cache) f(ctx context.Context) {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-ctx.Done():
	case <-c.ch:
	}
}`, 1},
		{"a sleep", `func (c *cache) f() {
	c.mu.Lock()
	defer c.mu.Unlock()
	time.Sleep(time.Second)
}`, 1},
		{"a wait group", `func (c *cache) f() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.wg.Wait()
}`, 1},
		{"a deferred call with a context runs before the deferred unlock", `func (c *cache) f(ctx context.Context) {
	c.mu.Lock()
	defer c.mu.Unlock()
	defer c.src.Load(ctx)
}`, 1},
		{"unlocking another mutex does not release this one", `func (c *cache) f(ctx context.Context) {
	c.mu.Lock()
	c.rw.Lock()
	c.rw.Unlock()
	_, _ = c.src.Load(ctx)
	c.mu.Unlock()
}`, 1},
		{"unlocked in one branch only", `func (c *cache) f(ctx context.Context, b bool) {
	c.mu.Lock()
	if b {
		c.mu.Unlock()
	}
	_, _ = c.src.Load(ctx)
}`, 1},
		{"a stored literal is judged alone and catches its own lock", `func (c *cache) f(ctx context.Context) {
	g := func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		_, _ = c.src.Load(ctx)
	}
	g()
}`, 1},

		// Shapes that must pass.
		{"the loader's shape: lock, read, unlock, then load", `func (c *cache) f(ctx context.Context) int {
	c.mu.Lock()
	v := c.val
	c.mu.Unlock()
	n, _ := c.src.Load(ctx)
	c.mu.Lock()
	c.val = n
	c.mu.Unlock()
	return v
}`, 0},
		{"every branch unlocks before the load", `func (c *cache) f(ctx context.Context, b bool) {
	c.mu.Lock()
	if b {
		c.mu.Unlock()
	} else {
		c.mu.Unlock()
	}
	_, _ = c.src.Load(ctx)
}`, 0},
		{"a loop that locks and unlocks each round", `func (c *cache) f(ctx context.Context) {
	for i := 0; i < 3; i++ {
		c.mu.Lock()
		c.val++
		c.mu.Unlock()
		_, _ = c.src.Load(ctx)
	}
}`, 0},
		{"a context call with no lock", `func (c *cache) f(ctx context.Context) { _, _ = c.src.Load(ctx) }`, 0},
		{"a plain call under the lock", `func (c *cache) f() {
	c.mu.Lock()
	defer c.mu.Unlock()
	plain(c.val)
	use(len(c.ch.String()))
}`, 0},
		{"a select with a default does not wait", `func (c *cache) f() {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case c.ch <- 1:
	default:
	}
}`, 0},
		{"a goroutine started under the lock runs without it", `func (c *cache) f(ctx context.Context) {
	c.mu.Lock()
	defer c.mu.Unlock()
	go func() { _, _ = c.src.Load(ctx) }()
}`, 0},
		{"a context method that is no argument", `func (c *cache) f(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return ctx.Err()
}`, 0},
		{"a branch that locks, works and unlocks inside itself", `func (c *cache) f(ctx context.Context, b bool) {
	if b {
		c.mu.Lock()
		c.val++
		c.mu.Unlock()
	}
	_, _ = c.src.Load(ctx)
}`, 0},
	}
	for _, c := range cases {
		fset := token.NewFileSet()
		// The stub receiver type is declared by the prelude; plain() above keeps the
		// "plain call" case compiling without importing anything.
		src := strings.ReplaceAll(pre, "use(len(c.ch.String()))", "") + c.src + "\n"
		af, err := parser.ParseFile(fset, "internal/x/x.go", src, parser.ParseComments)
		if err != nil {
			t.Fatalf("%s: %v\n%s", c.name, err, src)
		}
		fs := []file{{path: "internal/x/x.go", ast: af}}
		info, ok := typeInfoReal(fset, fs, lockIOStdlib...)
		if !ok {
			t.Fatalf("%s: no type information", c.name)
		}
		got, _ := lockIOProblems(fset, fs, info)
		if len(got) != c.want {
			t.Errorf("%s: %d findings %s, want %d", c.name, len(got), strings.Join(got, "; "), c.want)
		}
	}
}

// The second half of the rule: a cache of outside state is not written by hand. A struct
// that holds a mutex together with a time.Time or a channel is a cache with its own
// reload (a timestamp for the TTL or the backoff, a channel for the flight in progress),
// which is the shape all three hand-written caches had. The generic loader is the one place
// allowed to be that struct. Nothing else is: a struct that needs a mutex and a clock
// value for another reason keeps them in two structs (the lock-guarded map and the record
// with the time, as ratelimit's local and bucket do), or asks for the loader.
const cacheStructHome = "internal/cachex/"

func handRolledCacheProblems(fset *token.FileSet, files []file) ([]string, int) {
	var problems []string
	structs := 0
	for _, f := range files {
		if f.test || strings.HasPrefix(f.path, cacheStructHome) || strings.HasPrefix(f.path, "shared/") {
			continue
		}
		ast.Inspect(f.ast, func(n ast.Node) bool {
			ts, ok := n.(*ast.TypeSpec)
			if !ok {
				return true
			}
			st, ok := ts.Type.(*ast.StructType)
			if !ok {
				return true
			}
			structs++
			var mutex, clock, ch bool
			for _, fld := range st.Fields.List {
				ft := fld.Type
				if star, ok := ft.(*ast.StarExpr); ok {
					ft = star.X
				}
				switch t := ft.(type) {
				case *ast.ChanType:
					ch = true
				case *ast.SelectorExpr:
					if x, ok := t.X.(*ast.Ident); ok {
						switch x.Name + "." + t.Sel.Name {
						case "sync.Mutex", "sync.RWMutex":
							mutex = true
						case "time.Time":
							clock = true
						}
					}
				}
			}
			if mutex && (clock || ch) {
				problems = append(problems, fmt.Sprintf("%s: type %s holds a mutex with a time.Time or a channel: a cache of outside state is an internal/cachex Loader, not a hand-written reload", fset.Position(ts.Pos()), ts.Name.Name))
			}
			return true
		})
	}
	sort.Strings(problems)
	return problems, structs
}

func TestNoHandRolledCache(t *testing.T) {
	fset, files := parseRepo(t)
	problems, structs := handRolledCacheProblems(fset, files)
	for _, p := range problems {
		t.Error(p)
	}
	if structs < 100 {
		t.Fatalf("only %d struct types were examined", structs)
	}
}

// TestHandRolledCacheLintCanFail plants the shapes of the three caches this rule replaced.
func TestHandRolledCacheLintCanFail(t *testing.T) {
	cases := []struct {
		name, src string
		want      int
	}{
		{"mutex and a timestamp (the config cache)", "import (\"sync\"; \"time\")\ntype c struct { mu sync.Mutex; at time.Time }", 1},
		{"mutex and a flight channel (the router, the Valkey client)", "import \"sync\"\ntype c struct { mu sync.RWMutex; loading chan struct{} }", 1},
		{"a pointer mutex and a timestamp", "import (\"sync\"; \"time\")\ntype c struct { mu *sync.Mutex; retryAt time.Time }", 1},
		{"a mutex guarding a map", "import \"sync\"\ntype c struct { mu sync.Mutex; m map[string]int }", 0},
		{"a timestamp without a mutex", "import \"time\"\ntype c struct { at time.Time }", 0},
		{"a duration is not a clock value", "import (\"sync\"; \"time\")\ntype c struct { mu sync.Mutex; ttl time.Duration }", 0},
	}
	for _, c := range cases {
		fset := token.NewFileSet()
		af, err := parser.ParseFile(fset, "internal/x/x.go", "package x\n"+c.src+"\n", parser.ParseComments)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		got, _ := handRolledCacheProblems(fset, []file{{path: "internal/x/x.go", ast: af}})
		if len(got) != c.want {
			t.Errorf("%s: %d findings %v, want %d", c.name, len(got), got, c.want)
		}
	}
	// The loader's own home is exempt.
	fset := token.NewFileSet()
	af, _ := parser.ParseFile(fset, "internal/cachex/loader.go", "package cachex\nimport (\"sync\"; \"time\")\ntype c struct { mu sync.Mutex; at time.Time }\n", 0)
	if got, _ := handRolledCacheProblems(fset, []file{{path: "internal/cachex/loader.go", ast: af}}); len(got) != 0 {
		t.Errorf("cachex itself was flagged: %v", got)
	}
}

// TestCacheUsersAreBuiltOnTheLoader pins the three caches the rule was written for to the
// loader, so that a later rewrite back to a hand-written reload shows here by name and not
// only as a hand-rolled struct somewhere.
func TestCacheUsersAreBuiltOnTheLoader(t *testing.T) {
	_, files := parseRepo(t)
	want := map[string]bool{
		"internal/api/config_cache.go": false,
		"internal/ratelimit/valkey.go": false,
		"internal/sms/router.go":       false,
	}
	for _, f := range files {
		if _, ok := want[f.path]; !ok {
			continue
		}
		for _, imp := range f.ast.Imports {
			if imp.Path.Value == `"`+module+`/internal/cachex"` {
				want[f.path] = true
			}
		}
	}
	for p, ok := range want {
		if !ok {
			t.Errorf("%s does not import internal/cachex", p)
		}
	}
}
