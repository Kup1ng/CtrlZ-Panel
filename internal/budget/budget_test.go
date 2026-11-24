package budget_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/api"
	"github.com/Kup1ng/CtrlZ-Panel/internal/apispec"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/throttle"
	"github.com/Kup1ng/CtrlZ-Panel/internal/budget"
	"github.com/Kup1ng/CtrlZ-Panel/internal/ratelimit"
)

// The enforcement of rule budget-keying (P1 auth review round 5). The registry in
// budget.go is the only place a bucket is declared; these tests fail for a bucket
// that exists anywhere else, for a registry row that breaks the key-source rule,
// for a public route with no subject-keyed bound, and for a scope that `unlock`
// cannot clear. The behaviour of each bucket under strangers and under a moving
// proof is in abuse_test.go.

func TestRegistryRowsFollowTheKeySourceRule(t *testing.T) {
	seen := map[string]bool{}
	for _, b := range budget.All() {
		id := strconv.Itoa(int(b.Layer)) + "/" + string(b.Service) + "/" + b.Name
		if seen[id] {
			t.Errorf("%s is declared twice", id)
		}
		seen[id] = true
		if b.Layer != budget.RateClass && b.Layer != budget.Throttle {
			t.Errorf("%s has no layer", id)
		}
		if b.Service != budget.Tenant && b.Service != budget.Admin {
			t.Errorf("%s has no service", id)
		}
		// The closed set: there is no bucket for the whole service.
		if b.Source != budget.Subject && b.Source != budget.Proof && b.Source != budget.Network {
			t.Errorf("%s has key source %v, which is not in the closed set", id, b.Source)
		}
		if len(b.Parts) == 0 {
			t.Errorf("%s has no key parts", id)
		}
		if b.HasNetwork() != (b.Source == budget.Network || b.Narrow) {
			t.Errorf("%s: a network part is for a Network bucket or a declared Narrow one, and a Network bucket must have one", id)
		}
		if b.Narrow && b.Source != budget.Subject {
			t.Errorf("%s: only a Subject bucket can be narrowed by the network", id)
		}
		switch b.Layer {
		case budget.RateClass:
			if len(b.Limits) == 0 {
				t.Errorf("%s has no limits", id)
			}
			if b.ProofBucket != "" {
				t.Errorf("%s: a rate class takes a ProofPart, not a ProofBucket", id)
			}
			if b.HeldProof != "" && (b.Source != budget.Network || b.HeldProof != budget.PartMarker || b.Deferred == "") {
				t.Errorf("%s: HeldProof is for a Deferred Network class (the handler tells whether the proof holds), and the only proof the pipeline checks without I/O is a marker", id)
			}
			if b.HeldInvite && b.HeldProof == "" {
				t.Errorf("%s: HeldInvite is a second proof of a HeldProof class (the handler tells whether the invite is live)", id)
			}
			if b.ProofPart != "" && (b.Source != budget.Network || b.ProofPart != budget.PartMarker) {
				t.Errorf("%s: ProofPart is for a Network class, and the only proof the pipeline checks without I/O is a marker", id)
			}
		case budget.Throttle:
			if b.Max <= 0 || b.Window <= 0 {
				t.Errorf("%s has no policy", id)
			}
			if b.ProofPart != "" {
				t.Errorf("%s: a scope takes a ProofBucket, not a ProofPart", id)
			}
			if b.Source == budget.Network && b.ResetOnSuccess {
				t.Errorf("%s: a network scope must not be cleared by a success", id)
			}
		}
		// Every bucket that a network can fill says what a request with a proof does.
		if b.HasNetwork() {
			n := 0
			for _, set := range []bool{b.ProofPart != "", b.ProofBucket != "", b.HeldProof != "", b.NoProof != ""} {
				if set {
					n++
				}
			}
			if n != 1 {
				t.Errorf("%s holds the network and must name exactly one of ProofPart, ProofBucket, HeldProof and NoProof, has %d", id, n)
			}
		} else if b.ProofPart != "" || b.ProofBucket != "" || b.HeldProof != "" || b.NoProof != "" {
			t.Errorf("%s holds no network and has nothing to say about a proof", id)
		}
		if b.ProofBucket != "" {
			sib, ok := budget.Find(budget.Throttle, b.Service, b.ProofBucket)
			switch {
			case !ok:
				t.Errorf("%s: proof bucket %s is not registered", id, b.ProofBucket)
			case sib.HasNetwork() || sib.Source == budget.Network:
				t.Errorf("%s: proof bucket %s holds the network", id, b.ProofBucket)
			}
		}
		// Parts are the closed set.
		for _, p := range b.Parts {
			switch p {
			case budget.PartNetwork, budget.PartWide, budget.PartPhone, budget.PartUsername, budget.PartUser,
				budget.PartAdmin, budget.PartSession, budget.PartCookie, budget.PartTokenSession, budget.PartMarker, budget.PartInvite, budget.PartAdminSession, budget.PartUserSession, budget.PartChallenge:
			default:
				t.Errorf("%s has a key part %q that is not in the closed set", id, p)
			}
		}
	}
}

// Unlock walks the registry, so a scope that is not marked cannot be cleared: every
// admin scope must be.
func TestEveryAdminScopeIsClearedByUnlock(t *testing.T) {
	n := 0
	for _, b := range budget.Of(budget.Throttle, budget.Admin) {
		n++
		if !b.Unlock {
			t.Errorf("admin scope %s is not cleared by unlock and the resets", b.Name)
		}
	}
	for _, b := range budget.Of(budget.Throttle, budget.Tenant) {
		if b.Unlock {
			t.Errorf("tenant scope %s is marked for the admin console", b.Name)
		}
	}
	if n == 0 {
		t.Fatal("no admin scopes")
	}
}

// The registry and the two layers agree both ways.
func TestLayersAreBuiltFromTheRegistry(t *testing.T) {
	for _, svc := range []budget.Service{budget.Tenant, budget.Admin} {
		classes := ratelimit.Classes(ratelimit.Service(svc))
		reg := budget.Of(budget.RateClass, svc)
		if len(classes) != len(reg) {
			t.Errorf("%s: %d classes, %d registered", svc, len(classes), len(reg))
		}
		for _, b := range reg {
			c, ok := ratelimit.Lookup(ratelimit.Service(svc), b.Name)
			if !ok {
				t.Errorf("%s/%s is registered and not a class", svc, b.Name)
				continue
			}
			wantNet := b.Source == budget.Network
			if (c.Key == ratelimit.ByNetwork) != wantNet || c.FailClosed != b.FailClosed || c.ProofAlt != (b.ProofPart != "") || c.Held != (b.HeldProof != "") || c.HeldInvite != b.HeldInvite || len(c.Limits) != len(b.Limits) {
				t.Errorf("%s/%s: class %+v does not match its registry row", svc, b.Name, c)
			}
		}
	}
	for _, b := range budget.All() {
		if b.Layer != budget.Throttle {
			continue
		}
		p, ok := throttle.PolicyOf(throttle.Scope(b.Name))
		if !ok || p.Max != b.Max || p.Window != b.Window || p.ResetOnSuccess != b.ResetOnSuccess {
			t.Errorf("scope %s: policy %+v does not match its registry row", b.Name, p)
		}
	}
}

// Every operation of both documents is charged to a registered class whose key source
// suits it: a route that carries a session is never charged to the network, and a
// session class needs a session.
func TestEveryOperationIsChargedToASuitableClass(t *testing.T) {
	for _, tc := range []struct {
		svc ratelimit.Service
		doc []byte
	}{{ratelimit.Tenant, api.Tenant()}, {ratelimit.Admin, api.Admin()}} {
		ops, err := apispec.Parse(tc.doc, tc.svc)
		if err != nil {
			t.Fatal(err)
		}
		used := map[string]bool{}
		for _, op := range ops {
			b, ok := budget.Find(budget.RateClass, budget.Service(tc.svc), op.Rate)
			if !ok {
				t.Errorf("%s %s: class %s is not registered", tc.svc, op.ID, op.Rate)
				continue
			}
			used[op.Rate] = true
			switch {
			case b.Source == budget.Network && op.Auth.NeedsSession():
				t.Errorf("%s %s carries a session and is charged to the network class %s", tc.svc, op.ID, op.Rate)
			case b.Source != budget.Network && !op.Auth.NeedsSession():
				t.Errorf("%s %s carries no session and is charged to the %s class %s", tc.svc, op.ID, b.Source, op.Rate)
			}
		}
		for _, b := range budget.Of(budget.RateClass, budget.Service(tc.svc)) {
			if !used[b.Name] && !ratelimit.ChargedByThePipeline(b.Name) {
				t.Errorf("%s: class %s is registered and no operation uses it", tc.svc, b.Name)
			}
		}
	}
}

// Every public operation, and every signed-in one that checks a secret, has a bound
// on guesses that does not follow the caller across networks.
func TestEveryVerifyPathHasASubjectKeyedBound(t *testing.T) {
	listed := map[string]budget.Verify{}
	for _, v := range budget.Verifies() {
		key := string(v.Service) + "/" + v.Op
		if _, dup := listed[key]; dup {
			t.Errorf("%s is classified twice", key)
		}
		listed[key] = v
		switch v.Bound {
		case budget.BoundScope:
			b, ok := budget.FindScope(v.Scope)
			switch {
			case !ok || b.Service != v.Service:
				t.Errorf("%s: scope %q is not a registered scope of the service", key, v.Scope)
			case b.Source == budget.Network:
				t.Errorf("%s: scope %s is keyed on the network, which is no bound for a caller that moves", key, v.Scope)
			}
		case budget.BoundRow, budget.BoundEntropy, budget.BoundNone:
			if v.Why == "" {
				t.Errorf("%s: %v needs the row or the secret named", key, v.Bound)
			}
		default:
			t.Errorf("%s has no bound", key)
		}
	}
	for _, tc := range []struct {
		svc ratelimit.Service
		doc []byte
	}{{ratelimit.Tenant, api.Tenant()}, {ratelimit.Admin, api.Admin()}} {
		ops, err := apispec.Parse(tc.doc, tc.svc)
		if err != nil {
			t.Fatal(err)
		}
		ids := map[string]bool{}
		for _, op := range ops {
			ids[op.ID] = true
			if op.Auth == apispec.None {
				if _, ok := listed[string(tc.svc)+"/"+op.ID]; !ok {
					t.Errorf("%s %s takes no session and is not classified in budget.Verifies", tc.svc, op.ID)
				}
			}
		}
		for key := range listed {
			if svc, id, _ := strings.Cut(key, "/"); svc == string(tc.svc) && !ids[id] {
				t.Errorf("%s is classified and is not an operation of the document", key)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// The AST walk: a bucket declaration that is not in the registry fails.

type finding struct{ file, what string }

func (f finding) String() string { return f.file + ": " + f.what }

// sources parses every non-test Go file of the module's own code.
func sources(t *testing.T) map[string]*ast.File {
	t.Helper()
	root := filepath.Join("..", "..")
	fset := token.NewFileSet()
	out := map[string]*ast.File{}
	for _, dir := range []string{"internal", "cmd"} {
		_ = filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				if d.Name() == "gen" || d.Name() == "testdata" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			src, rerr := os.ReadFile(path)
			if rerr != nil {
				t.Fatal(rerr)
			}
			f, perr := parser.ParseFile(fset, path, src, 0)
			if perr != nil {
				t.Fatal(perr)
			}
			rel, _ := filepath.Rel(root, path)
			out[filepath.ToSlash(rel)] = f
			return nil
		})
	}
	if len(out) < 50 {
		t.Fatalf("only %d source files found; the walk is looking in the wrong place", len(out))
	}
	return out
}

// walk reports the findings of one rule over all files.
func walk(files map[string]*ast.File, rule func(file string, f *ast.File) []finding) []finding {
	var all []finding
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		all = append(all, rule(n, files[n])...)
	}
	return all
}

// classLiterals finds a ratelimit.Class composite literal: with the package
// qualifier outside the package, bare inside it.
func classLiterals(file string, f *ast.File) []finding {
	var out []finding
	inRatelimit := f.Name.Name == "ratelimit"
	// isClass says the type expression names ratelimit.Class (bare inside the package).
	isClass := func(e ast.Expr) bool {
		switch ty := e.(type) {
		case *ast.SelectorExpr:
			id, ok := ty.X.(*ast.Ident)
			return ok && id.Name == "ratelimit" && ty.Sel.Name == "Class"
		case *ast.Ident:
			return inRatelimit && ty.Name == "Class"
		}
		return false
	}
	ast.Inspect(f, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok || len(lit.Elts) == 0 { // Class{} is the zero value, not a declaration
			return true
		}
		switch ty := lit.Type.(type) {
		case *ast.ArrayType:
			// []Class{{Name: "x"}}: the elements have no type of their own, and a class
			// declared that way is the usual way a table grows.
			if isClass(ty.Elt) {
				for range lit.Elts {
					out = append(out, finding{file, "Class element of a slice literal"})
				}
			}
		case *ast.MapType:
			if isClass(ty.Value) {
				for range lit.Elts {
					out = append(out, finding{file, "Class element of a map literal"})
				}
			}
		default:
			if isClass(lit.Type) {
				out = append(out, finding{file, "Class literal"})
			}
		}
		return true
	})
	return out
}

// A Class is built in one place only, from the registry: Classes in class.go.
func TestNoRateClassIsDeclaredOutsideTheRegistry(t *testing.T) {
	var bad []finding
	for _, f := range walk(sources(t), classLiterals) {
		if f.file == "internal/ratelimit/class.go" {
			continue
		}
		bad = append(bad, f)
	}
	for _, f := range bad {
		t.Errorf("%v: a rate class is declared in internal/budget and built by ratelimit.Classes", f)
	}
	// And the one allowed place builds exactly one, from the registry.
	n := 0
	for _, f := range walk(sources(t), classLiterals) {
		if f.file == "internal/ratelimit/class.go" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("class.go builds %d Class literals, want the one in Classes", n)
	}
}

// Every Scope constant is a registered throttle scope and every registered scope is
// a constant, so a scope cannot be added on one side only; a Scope made from a
// string literal anywhere else is a scope the registry does not know.
func TestEveryThrottleScopeConstantIsRegistered(t *testing.T) {
	files := sources(t)
	declared := map[string]string{} // value -> file
	var conv []finding
	for name, f := range files {
		for _, d := range f.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, sp := range gd.Specs {
				vs := sp.(*ast.ValueSpec)
				id, ok := vs.Type.(*ast.Ident)
				if !ok || id.Name != "Scope" || f.Name.Name != "throttle" {
					continue
				}
				for _, v := range vs.Values {
					if lit, ok := v.(*ast.BasicLit); ok {
						s, _ := strconv.Unquote(lit.Value)
						declared[s] = name
					}
				}
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) != 1 {
				return true
			}
			if _, isLit := call.Args[0].(*ast.BasicLit); !isLit {
				return true
			}
			switch fn := call.Fun.(type) {
			case *ast.SelectorExpr:
				if id, ok := fn.X.(*ast.Ident); ok && id.Name == "throttle" && fn.Sel.Name == "Scope" {
					conv = append(conv, finding{name, "throttle.Scope made from a literal"})
				}
			case *ast.Ident:
				if f.Name.Name == "throttle" && fn.Name == "Scope" {
					conv = append(conv, finding{name, "Scope made from a literal"})
				}
			}
			return true
		})
	}
	for _, c := range conv {
		t.Errorf("%v: use a constant of the registry", c)
	}
	reg := map[string]bool{}
	for _, b := range budget.All() {
		if b.Layer == budget.Throttle {
			reg[b.Name] = true
			if _, ok := declared[b.Name]; !ok {
				t.Errorf("scope %s is registered and has no throttle.Scope constant", b.Name)
			}
		}
	}
	for v, file := range declared {
		if !reg[v] {
			t.Errorf("%s: throttle.Scope %q is not in internal/budget", file, v)
		}
	}
}

// The limiter is charged by the pipeline and by nothing else: a handler that spends a
// class by hand has chosen its own key and its own charge point, which is what the
// rule removes.
func TestOnlyThePipelineChargesTheRateLimiter(t *testing.T) {
	bad := walk(sources(t), func(file string, f *ast.File) []finding {
		if f.Name.Name == "httpx" || f.Name.Name == "ratelimit" {
			return nil
		}
		var out []finding
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || (sel.Sel.Name != "Allow" && sel.Sel.Name != "Refund") {
				return true
			}
			switch x := sel.X.(type) {
			case *ast.SelectorExpr:
				if strings.EqualFold(x.Sel.Name, "limiter") {
					out = append(out, finding{file, "Limiter." + sel.Sel.Name + " outside the pipeline"})
				}
			case *ast.Ident:
				if strings.EqualFold(x.Name, "limiter") {
					out = append(out, finding{file, "limiter." + sel.Sel.Name + " outside the pipeline"})
				}
			}
			return true
		})
		return out
	})
	for _, f := range bad {
		t.Errorf("%v", f)
	}
}

// A signed-in route that checks a secret charges its scope for a request that holds nothing but a
// cookie, so the scope must say so (SessionReach), and a scope that says so must not be the bound of
// a public route: a copy of the cookie would spend what the owner's login is refused by.
func TestNoScopeASessionCanSpendRefusesAPublicRoute(t *testing.T) {
	signedIn := map[string]bool{}
	public := map[string]string{}
	for _, tc := range []struct {
		svc ratelimit.Service
		doc []byte
	}{{ratelimit.Tenant, api.Tenant()}, {ratelimit.Admin, api.Admin()}} {
		ops, err := apispec.Parse(tc.doc, tc.svc)
		if err != nil {
			t.Fatal(err)
		}
		auth := map[string]apispec.Auth{}
		for _, op := range ops {
			auth[op.ID] = op.Auth
		}
		for _, v := range budget.Verifies() {
			if string(v.Service) != string(tc.svc) || v.Bound != budget.BoundScope {
				continue
			}
			if auth[v.Op] == apispec.None {
				public[v.Scope] = v.Op
			} else {
				signedIn[v.Scope] = true
			}
		}
	}
	for scope := range signedIn {
		b, ok := budget.FindScope(scope)
		if !ok {
			t.Fatalf("%s is not registered", scope)
		}
		if !b.SessionReach {
			t.Errorf("%s is charged by a signed-in route for a bare cookie and does not say SessionReach", scope)
		}
	}
	for scope, op := range public {
		b, _ := budget.FindScope(scope)
		if b.SessionReach {
			t.Errorf("%s bounds the public route %s and a session cookie alone can spend it: give the session its own scope", scope, op)
		}
	}
	// A scope that says SessionReach is bound by some signed-in route, or the flag is a claim nothing proves.
	for _, b := range budget.All() {
		if b.Layer == budget.Throttle && b.SessionReach && !signedIn[b.Name] {
			t.Errorf("%s says SessionReach and no signed-in operation of budget.Verifies is bound by it", b.Name)
		}
	}
}

// TestNoBudgetOfACookieIsKeyedOnTheAccount is the structural rule of round 8 (tenant-r8-3) for the key of
// anything charged to what a COOKIE says. Whoever holds a copy of a cookie, live or dead, can spend the
// budgets keyed on it, so such a budget must be keyed on the smallest thing the cookie is (the cookie, or
// the one session it opens) and never on something wider that other, honest requests share: the account.
// Round 7 keyed the dead-cookie class on the account the cookie was issued to, and the dead cookies of one
// stolen session then refused every live session of the owner, the ones he opened after logout-all
// included. The test reads the registry, so a row added tomorrow is held to it: a row whose parts include
// the cookie, the session a cookie opens or the live session id must name no account, phone or username.
func TestNoBudgetOfACookieIsKeyedOnTheAccount(t *testing.T) {
	cookieDerived := map[budget.Part]bool{
		budget.PartCookie: true, budget.PartTokenSession: true, budget.PartSession: true,
		budget.PartUserSession: true, budget.PartAdminSession: true,
	}
	wider := map[budget.Part]bool{
		budget.PartUser: true, budget.PartAdmin: true, budget.PartPhone: true, budget.PartUsername: true,
	}
	seen := 0
	for _, b := range budget.All() {
		hasCookie, hasWider := false, false
		for _, p := range b.Parts {
			hasCookie = hasCookie || cookieDerived[p]
			hasWider = hasWider || wider[p]
		}
		if !hasCookie {
			continue
		}
		seen++
		if hasWider {
			t.Errorf("%s/%s is keyed on what a cookie says AND on an account, phone or username: a holder of a copy of the cookie spends a budget the account's other sessions share", b.Service, b.Name)
		}
	}
	if seen == 0 {
		t.Fatal("no row is keyed on a cookie: the test proves nothing")
	}
}

// TestPasskeyLoginFinishIsNotBoundByARow is tenant-r18-10. The ceremony ticket of the passkey login is sealed
// and stateless (ticket.OpenCeremony: one HMAC, no row, no attempt counted), so the registry may not claim a
// counter on a row for it: that was the false reason this test pins. The bound is the signature itself.
func TestPasskeyLoginFinishIsNotBoundByARow(t *testing.T) {
	for _, v := range budget.Verifies() {
		if v.Service == budget.Tenant && v.Op == "passkeyLoginFinish" {
			if v.Bound != budget.BoundEntropy {
				t.Fatalf("passkeyLoginFinish is classified %v; a sealed ceremony ticket has no row to count on", v.Bound)
			}
			return
		}
	}
	t.Fatal("passkeyLoginFinish is not classified")
}
