package budget_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/budget"
	"github.com/Kup1ng/CtrlZ-Panel/internal/ratelimit"
)

// Rule budget-keying, deferred classes (round 8, admin-r8-1 and -4; round 9, admin-r9-3). The pipeline
// used to answer a spent network class with a 429 before it read the body or touched the pool.
// Deferring the class (round 7) moved the answer into the handler, and the handler did the work first:
// one source with no marker could queue the whole admin pool behind junk logins. The class of the
// mistake is "a handler of a deferred class does work before it has a reason the declared request
// could exist", so the registry names the gate (Bucket.DeferredGate, a function of the request alone)
// and the bound (Bucket.DeferredBound, a non-blocking slot) and this test reads the handler.
//
// Round 9 found that the first version of this test checked only WHERE calls sat, so a handler that
// ignored the gate's answer, put a heavy call in the gate's own arguments, or skipped the slot passed
// it. The shape it requires now, inside the branch that handles a refusal, in this order:
//
//	if !gate(<fields and secret.New only>) { return <the refusal> }
//	rel, ok := <x>.bound()
//	if !ok { return <the refusal> }
//
// and no call before the end of the second `if` may reach the store, the hasher or a floor.

// deferredHeavy are the calls that cost a pooled connection, an Argon2 slot or a goroutine held for a
// floor. The walk is by name over the package, as reachedCalls is.
var deferredHeavy = []string{
	"WithGlobal", "WithTenant", "readGlobal", "global", "tenant", "inTenant", "inTenantOwner",
	"Floor", "FloorWith", "hasher.Verify", "hasher.VerifyGateFree", "hasher.Hash",
}

func stripParens(e ast.Expr) ast.Expr {
	for {
		p, ok := e.(*ast.ParenExpr)
		if !ok {
			return e
		}
		e = p.X
	}
}

// calledName is the name a call is made by: the method or function, without its receiver.
func calledName(ce *ast.CallExpr) string {
	switch f := ce.Fun.(type) {
	case *ast.SelectorExpr:
		return f.Sel.Name
	case *ast.Ident:
		return f.Name
	}
	return ""
}

func isNotCall(e ast.Expr, name string) (*ast.CallExpr, bool) {
	u, ok := stripParens(e).(*ast.UnaryExpr)
	if !ok || u.Op != token.NOT {
		return nil, false
	}
	ce, ok := stripParens(u.X).(*ast.CallExpr)
	if !ok || calledName(ce) != name {
		return nil, false
	}
	return ce, true
}

// deferredOrderProblems reads handler in pc and returns what breaks the rule for a deferred class
// whose gate is gate and whose bound is bound.
func deferredOrderProblems(pc pkgCode, handler, gate, bound string) []string {
	decls := pc.funcs[handler]
	if len(decls) == 0 || decls[0].Body == nil {
		return []string{handler + ": no handler"}
	}
	body := decls[0].Body

	// The refusal values: what DeferredRefusal returns and the names it is copied to. The branch that
	// handles a refusal is the first `if x != nil` over one of them.
	refusal := map[string]bool{}
	isRefusal := func(e ast.Expr) bool {
		switch x := stripParens(e).(type) {
		case *ast.CallExpr:
			return calledName(x) == "DeferredRefusal"
		case *ast.Ident:
			return refusal[x.Name]
		}
		return false
	}
	learn := func(as *ast.AssignStmt) {
		for i, r := range as.Rhs {
			if i >= len(as.Lhs) || !isRefusal(r) {
				continue
			}
			if id, ok := as.Lhs[i].(*ast.Ident); ok {
				refusal[id.Name] = true
			}
		}
	}
	var branch *ast.IfStmt
	refusalAt, gateAt := token.NoPos, token.NoPos
	ast.Inspect(body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.AssignStmt:
			learn(x)
		case *ast.IfStmt:
			if as, ok := x.Init.(*ast.AssignStmt); ok {
				learn(as)
			}
			if be, ok := stripParens(x.Cond).(*ast.BinaryExpr); ok && be.Op == token.NEQ && branch == nil && isRefusal(be.X) {
				if id, ok := be.Y.(*ast.Ident); ok && id.Name == "nil" {
					branch = x
				}
			}
		case *ast.CallExpr:
			switch calledName(x) {
			case "DeferredRefusal":
				if refusalAt == token.NoPos {
					refusalAt = x.Pos()
				}
			case gate:
				if gateAt == token.NoPos {
					gateAt = x.Pos()
				}
			}
		}
		return true
	})
	if refusalAt == token.NoPos {
		return []string{handler + " never calls httpx.DeferredRefusal itself: the class would refuse nobody"}
	}
	var problems []string
	if gateAt != token.NoPos && gateAt < refusalAt {
		problems = append(problems, fmt.Sprintf("%s calls %s before it knows the request was refused", handler, gate))
	}
	if branch == nil {
		return append(problems, handler+" asks for the refusal and never branches on it (`if refusal != nil`)")
	}

	returnsRefusal := func(b *ast.BlockStmt) bool {
		if b == nil || len(b.List) == 0 {
			return false
		}
		ret, ok := b.List[len(b.List)-1].(*ast.ReturnStmt)
		if !ok {
			return false
		}
		found := false
		for _, r := range ret.Results {
			ast.Inspect(r, func(n ast.Node) bool {
				if id, ok := n.(*ast.Ident); ok && refusal[id.Name] {
					found = true
				}
				return true
			})
		}
		return found
	}

	list := branch.Body.List
	gateIdx := -1
	var gateCall *ast.CallExpr
	for i, st := range list {
		if is, ok := st.(*ast.IfStmt); ok {
			if ce, ok := isNotCall(is.Cond, gate); ok {
				gateIdx, gateCall = i, ce
				if is.Else != nil || !returnsRefusal(is.Body) {
					problems = append(problems, fmt.Sprintf("%s: when %s says no the handler must return the refusal and nothing else", handler, gate))
				}
				break
			}
		}
	}
	if gateIdx < 0 {
		called := false
		ast.Inspect(branch.Body, func(n ast.Node) bool {
			if ce, ok := n.(*ast.CallExpr); ok && calledName(ce) == gate {
				called = true
			}
			return true
		})
		if called {
			return append(problems, fmt.Sprintf("%s calls its gate %s but its answer is not the condition of `if !%s(...) { return <refusal> }`: a false answer would refuse nobody", handler, gate, gate))
		}
		return append(problems, fmt.Sprintf("%s never calls its gate %s in the branch that handles a refusal", handler, gate))
	}

	// The gate reads the request alone: its arguments are fields and secret.New, never a store call.
	allowedArg := map[*ast.CallExpr]bool{}
	for _, a := range gateCall.Args {
		ast.Inspect(a, func(n ast.Node) bool {
			ce, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if sel, isSel := ce.Fun.(*ast.SelectorExpr); isSel {
				if x, isID := sel.X.(*ast.Ident); isID && x.Name == "secret" && sel.Sel.Name == "New" {
					allowedArg[ce] = true
					return true
				}
			}
			problems = append(problems, fmt.Sprintf("%s: the arguments of gate %s call %s; a gate may read the request only (fields and secret.New)", handler, gate, calledName(ce)))
			return true
		})
	}

	// The bound: taken right after the gate, and its answer is the condition of an if that returns.
	endOfGuards := list[gateIdx].End()
	var boundCall *ast.CallExpr
	var boundIf *ast.IfStmt
	for i := gateIdx + 1; i < len(list); i++ {
		as, ok := list[i].(*ast.AssignStmt)
		if !ok || len(as.Rhs) != 1 {
			continue
		}
		ce, ok := stripParens(as.Rhs[0]).(*ast.CallExpr)
		if !ok || calledName(ce) != bound {
			continue
		}
		boundCall = ce
		okName := ""
		if id, isID := as.Lhs[len(as.Lhs)-1].(*ast.Ident); isID && id.Name != "_" {
			okName = id.Name
		}
		if i+1 < len(list) {
			if is, ok := list[i+1].(*ast.IfStmt); ok && okName != "" && is.Else == nil {
				if u, ok := stripParens(is.Cond).(*ast.UnaryExpr); ok && u.Op == token.NOT {
					if id, ok := stripParens(u.X).(*ast.Ident); ok && id.Name == okName && returnsRefusal(is.Body) {
						boundIf = is
					}
				}
			}
		}
		break
	}
	switch {
	case boundCall == nil:
		problems = append(problems, fmt.Sprintf("%s never takes its bound %s after the gate: every well-shaped request would read the store, and one source could fill the pool", handler, bound))
	case boundIf == nil:
		problems = append(problems, fmt.Sprintf("%s takes its bound %s and does not return the refusal when it says no", handler, bound))
	default:
		endOfGuards = boundIf.End()
	}

	// Nothing before the end of the guards may cost database, hashing or floor work. The gate, the
	// bound, the refusal source, secret.New in the gate's arguments and what the two refusing ifs
	// return are the calls the guards are made of.
	type site struct {
		name string
		call *ast.CallExpr
	}
	var sites []site
	ast.Inspect(body, func(n ast.Node) bool {
		ce, ok := n.(*ast.CallExpr)
		if !ok || ce.Pos() >= endOfGuards {
			return true
		}
		name := calledName(ce)
		if sel, ok := ce.Fun.(*ast.SelectorExpr); ok {
			if x, ok := sel.X.(*ast.SelectorExpr); ok && x.Sel.Name == "hasher" {
				name = "hasher." + sel.Sel.Name
			}
		}
		sites = append(sites, site{name, ce})
		return true
	})
	inReturnOfAGuard := func(ce *ast.CallExpr) bool {
		for _, st := range list[gateIdx : gateIdx+1] {
			if is, ok := st.(*ast.IfStmt); ok && ce.Pos() >= is.Body.Pos() && ce.End() <= is.Body.End() {
				return true
			}
		}
		return boundIf != nil && ce.Pos() >= boundIf.Body.Pos() && ce.End() <= boundIf.Body.End()
	}
	for _, s := range sites {
		if s.call == gateCall || s.call == boundCall || allowedArg[s.call] || inReturnOfAGuard(s.call) || s.name == "DeferredRefusal" {
			continue
		}
		reached := reachedCalls(pc, strings.TrimPrefix(s.name, "hasher."))
		reached[s.name] = true
		for _, h := range deferredHeavy {
			if reached[h] {
				problems = append(problems, fmt.Sprintf("%s calls %s (which reaches %s) before its gate %s and bound %s are through: a refused request would cost database, hashing or floor work", handler, s.name, h, gate, bound))
				break
			}
		}
	}
	return problems
}

func TestADeferredHandlerRefusesBeforeItWorks(t *testing.T) {
	checked := 0
	for svc, ops := range serviceCharges(t) {
		dir := filepath.Join("..", "api")
		if svc == budget.Admin {
			dir = filepath.Join("..", "adminapi")
		}
		pc := parsePkg(t, dir)
		for _, oc := range ops {
			c, ok := ratelimit.Lookup(ratelimit.Service(svc), oc.op.Rate)
			if !ok || !c.Deferred {
				continue
			}
			b, ok := budget.Find(budget.RateClass, svc, oc.op.Rate)
			if !ok {
				t.Errorf("%s: class %s is not in the registry", oc.op.ID, oc.op.Rate)
				continue
			}
			if b.HeldProof != "" {
				// A marker is the whole of the declared request there, and the pipeline only hands the
				// refusal over for a request that carries one (httpx pipeline, Held): the handler's work is
				// bounded by the marker's own buckets (TestAbuseAHeldProofStandsInForTheNetworkOnlyWhereItHolds).
				continue
			}
			for _, p := range deferredOrderProblems(pc, capitalize(oc.op.ID), b.DeferredGate, b.DeferredBound) {
				t.Error(p)
			}
			checked++
		}
	}
	if checked == 0 {
		t.Error("no operation uses a deferred class without a held proof: the test proves nothing")
	}
}

// TestDeferredGateIsDeclaredExactlyWhereItIsNeeded: a deferred class without a held proof says which
// function decides and which bound it takes, and a class with one (or none deferred) says neither.
func TestDeferredGateIsDeclaredExactlyWhereItIsNeeded(t *testing.T) {
	for _, b := range budget.All() {
		switch {
		case b.Deferred != "" && b.HeldProof == "" && (b.DeferredGate == "" || b.DeferredBound == ""):
			t.Errorf("%s: a deferred class names the gate that tells the declared request from the rest and the bound its passers take (DeferredGate, DeferredBound)", b.Name)
		case (b.Deferred == "" || b.HeldProof != "") && (b.DeferredGate != "" || b.DeferredBound != ""):
			t.Errorf("%s: DeferredGate and DeferredBound are only for a deferred class without a held proof", b.Name)
		}
	}
}

func pkgFromSource(t *testing.T, src string) pkgCode {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), "x.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	pc := pkgCode{funcs: map[string][]*ast.FuncDecl{}}
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok {
			pc.funcs[fd.Name.Name] = append(pc.funcs[fd.Name.Name], fd)
		}
	}
	return pc
}

// TestDeferredOrderLintCanFail plants the shapes the round 7 handler had, the ones that look like the
// fix and are not, and the two the round 9 review probed against a copy of HEAD (a handler that
// ignores the gate's answer, and one that never takes a slot).
func TestDeferredOrderLintCanFail(t *testing.T) {
	const prelude = `package x
func (s *S) readGlobal() {}
func (s *S) login()      { s.readGlobal() }
`
	const ok = `rel, ok := s.slots.try(); if !ok { return nil, adminError(d) }; defer rel()`
	cases := []struct {
		name, body string
		want       string // substring of the first problem; "" = clean
	}{
		{"the real shape", `deferred := httpx.DeferredRefusal(ctx)
			if d := deferred; d != nil {
				if !password.MayBeOneTime(secret.New(b.Password)) { return nil, adminError(d) }
				` + ok + `
			}
			httpx.Floor(ctx, 1, func() { s.login() })`, ""},
		{"inline refusal", `if d := httpx.DeferredRefusal(ctx); d != nil {
				if !password.MayBeOneTime(secret.New(b.Password)) { return nil, adminError(d) }
				` + ok + `
			}
			httpx.Floor(ctx, 1, func() { s.login() })`, ""},
		{"account read before the gate (the round 7 shape)", `if d := httpx.DeferredRefusal(ctx); d != nil { s.login(); if !password.MayBeOneTime(x) { return d }; ` + ok + ` }`, "reaches readGlobal"},
		{"floor before the gate", `if d := httpx.DeferredRefusal(ctx); d != nil { httpx.Floor(ctx, 1, nil); if !password.MayBeOneTime(x) { return d }; ` + ok + ` }`, "reaches Floor"},
		{"hasher before the gate", `if d := httpx.DeferredRefusal(ctx); d != nil { s.hasher.Verify(x); if !password.MayBeOneTime(x) { return d }; ` + ok + ` }`, "reaches hasher.Verify"},
		{"read between the gate and the slot", `if d := httpx.DeferredRefusal(ctx); d != nil { if !password.MayBeOneTime(x) { return d }; s.login(); ` + ok + ` }`, "reaches readGlobal"},
		{"gate before the refusal is known", `password.MayBeOneTime(x); if d := httpx.DeferredRefusal(ctx); d != nil { }`, "before it knows"},
		{"gate never called", `if d := httpx.DeferredRefusal(ctx); d != nil { }`, "never calls its gate"},
		{"refusal never asked", `password.MayBeOneTime(x)`, "never calls httpx.DeferredRefusal"},
		{"refusal asked and never branched on", `httpx.DeferredRefusal(ctx); password.MayBeOneTime(x)`, "never branches"},
		// The two the round 9 review planted against HEAD.
		{"gate's answer ignored", `if d := httpx.DeferredRefusal(ctx); d != nil { _ = password.MayBeOneTime(secret.New(b.Password)) }
			httpx.Floor(ctx, 1, func() { s.login() })`, "its answer is not the condition"},
		{"no bound", `if d := httpx.DeferredRefusal(ctx); d != nil { if !password.MayBeOneTime(x) { return d } }
			httpx.Floor(ctx, 1, func() { s.login() })`, "never takes its bound"},
		{"the gate's own arguments read the store", `if d := httpx.DeferredRefusal(ctx); d != nil { if !password.MayBeOneTime(secret.New(s.login())) { return d }; ` + ok + ` }`, "the arguments of gate"},
		{"inverted gate", `if d := httpx.DeferredRefusal(ctx); d != nil { if password.MayBeOneTime(x) { return d }; ` + ok + ` }`, "its answer is not the condition"},
		{"gate says no and the handler goes on", `if d := httpx.DeferredRefusal(ctx); d != nil { if !password.MayBeOneTime(x) { s.log() }; ` + ok + ` }`, "must return the refusal"},
		{"gate says no and the handler returns something else", `if d := httpx.DeferredRefusal(ctx); d != nil { if !password.MayBeOneTime(x) { return nil, nil }; ` + ok + ` }`, "must return the refusal"},
		{"bound's answer dropped", `if d := httpx.DeferredRefusal(ctx); d != nil { if !password.MayBeOneTime(x) { return d }; rel, _ := s.slots.try(); defer rel() }`, "does not return the refusal"},
		{"bound refused with a different return", `if d := httpx.DeferredRefusal(ctx); d != nil { if !password.MayBeOneTime(x) { return d }; rel, ok := s.slots.try(); if !ok { return nil, nil }; defer rel() }`, "does not return the refusal"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pc := pkgFromSource(t, prelude+"func (s *S) H(ctx any) {\n"+c.body+"\n}\n")
			got := deferredOrderProblems(pc, "H", "MayBeOneTime", "try")
			switch {
			case c.want == "" && len(got) > 0:
				t.Fatalf("clean handler refused: %v", got)
			case c.want != "" && (len(got) == 0 || !strings.Contains(got[0], c.want)):
				t.Fatalf("problems = %v, want one containing %q", got, c.want)
			}
		})
	}
}
