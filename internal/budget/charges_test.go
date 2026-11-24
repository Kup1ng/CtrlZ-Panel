package budget_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/api"
	"github.com/Kup1ng/CtrlZ-Panel/internal/apispec"
	"github.com/Kup1ng/CtrlZ-Panel/internal/budget"
	"github.com/Kup1ng/CtrlZ-Panel/internal/ratelimit"
	"gopkg.in/yaml.v3"
)

// The rule "what a route charges is derived, not declared" (P1 auth review round 7, rule budget-keying,
// tenant-r7-2 and -7).
//
// Rounds 5 and 6 each proved a property of budget.Verifies, which is a declaration: the scope a route
// "is bound by". The scopes a route actually spends were never read, so a route could charge a scope it
// had not declared and every test stayed green: resetPasskeyFinish was a BoundRow route and charged
// reauth_user, which any copy of a session cookie could spend; reauth_user was SessionReach and the test
// never saw it on a public route; the tenant totp_user sat in a "known exceptions" list for a round.
//
// Here the set is read from the code. For every operation of both OpenAPI documents the test finds the
// handler (the strict-server method of the same name), follows every call to a function or method of the
// same package by name, and collects every throttle scope the code names (a `throttle.<Scope>` constant,
// or a wrapper of the Service that spends a fixed set). Over-approximation is the safe side: a name that
// collides with another function only makes the test look at more code. The rules over that set:
//
//   - a scope that a signed-in route spends must say SessionReach, and a SessionReach scope is spent by no
//     public route (a copy of a cookie must not spend what a login is refused by);
//   - a subject-keyed scope that a route spends is the one it declares in Verifies, or is listed below
//     with the reason (a charge that follows a proof the route has already checked);
//   - a Verifies row that names a scope is spent by that route;
//   - an entry point of throttle.Service that this test does not know fails, so a new wrapper cannot
//     spend a scope the rules cannot see.

// scopeWrappers is what each wrapper of throttle.Service spends. A wrapper that is not here and is not
// one of the generic entry points fails the test.
var scopeWrappers = map[string][]string{
	"LoginHits":            {"login_phone_net", "login_phone", "login_net", "login_net48"},
	"LoginHitsFor":         {"login_phone_net", "login_phone", "login_marker", "login_net", "login_net48"},
	"LoginRefund":          {"login_phone_net", "login_phone", "login_marker", "login_net", "login_net48"},
	"LoginSuccess":         {"login_phone_net", "login_phone", "login_marker"},
	"LoginHitsMalformed":   {"login_net", "login_net48"},
	"LoginRefundMalformed": {"login_net", "login_net48"},
	"OTPVerifyHit":         {"otp_verify_net", "otp_verify_challenge"},
	"OTPVerifyRefund":      {"otp_verify_net", "otp_verify_challenge"},
	"InviteHit":            {"invite_net", "invite_net48", "invite_use"},
	"AdminLoginHits":       {"admin_login", "admin_login_user", "admin_login_net", "admin_login_marker"},
	"AdminLoginRefund":     {"admin_login", "admin_login_user", "admin_login_net", "admin_login_marker"},
	"AdminLoginSuccess":    {"admin_login", "admin_login_user", "admin_login_marker"},
}

// genericEntryPoints take the scope as an argument, so the constant is at the call site and is found there.
var genericEntryPoints = map[string]bool{
	"Charge": true, "ChargeProof": true, "Clear": true, "Refund": true, "Counted": true,
	// Not request paths: the console command and the wiring.
	"Unlock": true, "WithRefund": true, "WithCeilingHook": true, "WithRefusalHook": true,
}

// alsoSpent lists a subject-keyed scope that a route spends and does not declare in Verifies. Each is a
// charge that FOLLOWS a proof the route has checked, so a bare cookie or a stranger cannot reach it.
var alsoSpent = map[string]string{
	"adminLogin/admin_totp":              "after a right password, as the second factor of the login",
	"changeAdminPassword/admin_totp":     "after the password check of the route, the second factor of a password change",
	"reauthPasskeyFinish/reauth_session": "cleared and never charged: an assertion of the owner's authenticator ends the run of guesses at the password and the code of the session",
	// What proved the first step of a ticket picks the scope its second factor is counted on, and the route
	// names the choice (ticketFactorScope; round 9, primitives-r9-4). A ticket is a proof the route has read.
	"loginTotp/totp_sms":          "the second factor of an mfa ticket that an SMS code opened (an OTP login), picked from the ticket",
	"loginTotp/recovery_user":     "a recovery code in place of the code, on the scope of its own that no ceiling refuses",
	"loginTotp/recovery_sms":      "a recovery code on a ticket an SMS code opened, on the scope of that door",
	"resetComplete/totp_user":     "never for a reset ticket, which an SMS code opened; the name is reached through the helper loginTotp shares",
	"resetComplete/recovery_user": "a recovery code in place of the code, on the scope of its own that no ceiling refuses",
	"resetComplete/recovery_sms":  "a recovery code on a reset ticket, which an SMS code opened, on the scope of that door",
}

type pkgCode struct {
	funcs map[string][]*ast.FuncDecl // by name; methods and functions share the namespace on purpose
}

func parsePkg(t *testing.T, dir string) pkgCode {
	t.Helper()
	fset := token.NewFileSet()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	pc := pkgCode{funcs: map[string][]*ast.FuncDecl{}}
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, n), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok {
				pc.funcs[fd.Name.Name] = append(pc.funcs[fd.Name.Name], fd)
			}
		}
	}
	return pc
}

// scopeConstants maps the Go name of every throttle.Scope constant to its scope name, and lists the
// exported methods of throttle.Service.
func scopeConstants(t *testing.T) (consts map[string]string, methods []string) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filepath.Join("..", "auth", "throttle", "throttle.go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	consts = map[string]string{}
	for _, d := range f.Decls {
		switch d := d.(type) {
		case *ast.GenDecl:
			for _, sp := range d.Specs {
				vs, ok := sp.(*ast.ValueSpec)
				if !ok || vs.Type == nil {
					continue
				}
				if id, ok := vs.Type.(*ast.Ident); !ok || id.Name != "Scope" {
					continue
				}
				for i, nm := range vs.Names {
					if lit, ok := vs.Values[i].(*ast.BasicLit); ok {
						v, _ := strconv.Unquote(lit.Value)
						consts[nm.Name] = v
					}
				}
			}
		case *ast.FuncDecl:
			if d.Recv == nil || !d.Name.IsExported() || len(d.Recv.List) == 0 {
				continue
			}
			if star, ok := d.Recv.List[0].Type.(*ast.StarExpr); ok {
				if id, ok := star.X.(*ast.Ident); ok && id.Name == "Service" {
					methods = append(methods, d.Name.Name)
				}
			}
		}
	}
	return consts, methods
}

// spent returns the scopes the code reachable from the function named root can spend, and the entry points of
// the Service it calls that the test does not know.
func spent(pc pkgCode, root string, consts map[string]string) (scopes map[string]bool, unknown []string) {
	scopes = map[string]bool{}
	seen := map[string]bool{}
	queue := []string{root}
	known := map[string]bool{}
	for w := range scopeWrappers {
		known[w] = true
	}
	for g := range genericEntryPoints {
		known[g] = true
	}
	for len(queue) > 0 {
		name := queue[0]
		queue = queue[1:]
		if seen[name] {
			continue
		}
		seen[name] = true
		for _, fd := range pc.funcs[name] {
			if fd.Body == nil {
				continue
			}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.SelectorExpr:
					if id, ok := x.X.(*ast.Ident); ok && id.Name == "throttle" {
						if v, ok := consts[x.Sel.Name]; ok {
							scopes[v] = true
						}
					}
					if ws, ok := scopeWrappers[x.Sel.Name]; ok && isThrottleField(x.X) {
						for _, w := range ws {
							scopes[w] = true
						}
					}
				case *ast.CallExpr:
					if sel, ok := x.Fun.(*ast.SelectorExpr); ok {
						if isThrottleField(sel.X) && !known[sel.Sel.Name] {
							unknown = append(unknown, sel.Sel.Name)
						}
						queue = append(queue, sel.Sel.Name)
					} else if id, ok := x.Fun.(*ast.Ident); ok {
						queue = append(queue, id.Name)
					}
				}
				return true
			})
		}
	}
	return scopes, unknown
}

// isThrottleField says the expression is the throttle service of the server, `s.throttle`. A bare
// `throttle` is the package, which is only ever selected from with a scope constant, a type or a
// constructor, and the callers above handle those.
func isThrottleField(e ast.Expr) bool {
	x, ok := e.(*ast.SelectorExpr)
	return ok && x.Sel.Name == "throttle"
}

func capitalize(s string) string { return strings.ToUpper(s[:1]) + s[1:] }

// chargesOf is every operation of a service with the scopes its handler can spend.
type opCharges struct {
	op     apispec.Operation
	scopes map[string]bool
}

func chargesOf(t *testing.T, svc budget.Service, dir string, doc []byte) []opCharges {
	t.Helper()
	rs := ratelimit.Tenant
	if svc == budget.Admin {
		rs = ratelimit.Admin
	}
	ops, err := apispec.Parse(doc, rs)
	if err != nil {
		t.Fatal(err)
	}
	consts, methods := scopeConstants(t)
	for _, m := range methods {
		if _, ok := scopeWrappers[m]; !ok && !genericEntryPoints[m] {
			t.Errorf("throttle.Service.%s is an entry point this test does not know: add what it spends to scopeWrappers (or to genericEntryPoints if it takes the scope as an argument)", m)
		}
	}
	pc := parsePkg(t, dir)
	var out []opCharges
	for _, op := range ops {
		h := capitalize(op.ID)
		if len(pc.funcs[h]) == 0 {
			t.Errorf("%s: no handler method %s in %s", op.ID, h, dir)
			continue
		}
		scopes, unknown := spent(pc, h, consts)
		for _, u := range unknown {
			t.Errorf("%s reaches throttle.Service.%s, which this test does not know", op.ID, u)
		}
		out = append(out, opCharges{op: op, scopes: scopes})
	}
	return out
}

func serviceCharges(t *testing.T) map[budget.Service][]opCharges {
	return map[budget.Service][]opCharges{
		budget.Tenant: chargesOf(t, budget.Tenant, filepath.Join("..", "api"), api.Tenant()),
		budget.Admin:  chargesOf(t, budget.Admin, filepath.Join("..", "adminapi"), api.Admin()),
	}
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestWhatARouteSpendsFollowsTheRegistry is the derived twin of TestNoScopeASessionCanSpendRefusesAPublicRoute
// and TestEveryVerifyPathHasASubjectKeyedBound: the same rules over the scopes the handlers name.
func TestWhatARouteSpendsFollowsTheRegistry(t *testing.T) {
	all := serviceCharges(t)
	verifies := map[string]budget.Verify{}
	for _, v := range budget.Verifies() {
		verifies[string(v.Service)+"/"+v.Op] = v
	}
	usedExtra := map[string]bool{}
	for svc, ops := range all {
		signedIn := map[string]string{}
		public := map[string]string{}
		for _, oc := range ops {
			v, declared := verifies[string(svc)+"/"+oc.op.ID]
			for _, scope := range sortedKeys(oc.scopes) {
				b, ok := budget.FindScope(scope)
				if !ok {
					t.Errorf("%s names the scope %q, which is not in the registry", oc.op.ID, scope)
					continue
				}
				if oc.op.Auth == apispec.None {
					public[scope] = oc.op.ID
				} else if _, excused := afterProof(scope, oc.op.ID); !excused {
					// Judged per route: a map of the last route to name the scope let an excused route hide the
					// others (round 9: reauthPasskeyFinish, which only clears reauth_session, came last and the
					// mutant that dropped SessionReach survived).
					signedIn[scope] = oc.op.ID
				}
				// A subject-keyed scope is a bound on guessing: the route declares which one, or says why it has another.
				if b.Source == budget.Subject && !b.Narrow {
					key := oc.op.ID + "/" + scope
					switch {
					case declared && v.Bound == budget.BoundScope && v.Scope == scope:
					case alsoSpent[key] != "":
						usedExtra[key] = true
					default:
						t.Errorf("%s spends the subject-keyed scope %s and budget.Verifies does not say so (declared: %+v): declare it, or list it in alsoSpent with the reason", oc.op.ID, scope, v)
					}
				}
			}
			// A declared scope is spent by its route.
			if declared && v.Bound == budget.BoundScope && !oc.scopes[v.Scope] {
				t.Errorf("%s declares the bound %s and its handler never names it", oc.op.ID, v.Scope)
			}
		}
		for scope, op := range signedIn {
			b, _ := budget.FindScope(scope)
			if !b.SessionReach {
				t.Errorf("%s is spent by the signed-in route %s for a request that may hold only a cookie, and does not say SessionReach", scope, op)
			}
		}
		for scope, op := range public {
			b, _ := budget.FindScope(scope)
			if b.SessionReach {
				t.Errorf("%s is spent by the public route %s and is SessionReach: a copy of a session cookie could spend what that route is refused by", scope, op)
			}
		}
		for _, b := range budget.Of(budget.Throttle, svc) {
			if b.SessionReach && signedIn[b.Name] == "" {
				t.Errorf("%s says SessionReach and no signed-in handler names it", b.Name)
			}
		}
	}
	for k := range alsoSpent {
		if !usedExtra[k] {
			t.Errorf("alsoSpent lists %s and no handler spends it that way any more: delete the entry", k)
		}
	}
}

// afterProof says a signed-in route's charge of a scope follows a proof of the route (alsoSpent), so the
// scope need not be SessionReach for it.
func afterProof(scope, op string) (string, bool) {
	r, ok := alsoSpent[op+"/"+scope]
	return r, ok
}

// reachedCalls is the name of every function or method the code reachable from root calls, by the same
// name-based walk as spent.
func reachedCalls(pc pkgCode, root string) map[string]bool {
	out := map[string]bool{}
	seen := map[string]bool{}
	queue := []string{root}
	for len(queue) > 0 {
		name := queue[0]
		queue = queue[1:]
		if seen[name] {
			continue
		}
		seen[name] = true
		for _, fd := range pc.funcs[name] {
			if fd.Body == nil {
				continue
			}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				if call, ok := n.(*ast.CallExpr); ok {
					switch f := call.Fun.(type) {
					case *ast.SelectorExpr:
						out[f.Sel.Name] = true
						// The hasher is told from the other packages that have a Hash or a Verify of their own
						// (invite.Hash, recovery.Hash) by its field name.
						if x, ok := f.X.(*ast.SelectorExpr); ok && x.Sel.Name == "hasher" {
							out["hasher."+f.Sel.Name] = true
						}
						queue = append(queue, f.Sel.Name)
					case *ast.Ident:
						out[f.Name] = true
						queue = append(queue, f.Name)
					}
				}
				return true
			})
		}
	}
	return out
}

// TestARouteThatTakesAnArgon2SlotSaysServerBusy is tenant-r7-4 as a rule. A route that waits for a slot of
// the Argon2 gate or of the scoring gate can answer 503 server_busy (password.ErrBusy), and a client
// generated from the document has no handling for an error the document does not list. register was the
// one that had been missed when the others got it in round 6. The routes are found by what their handlers
// reach: a Verify or Hash of the hasher, or one of the preparePassword helpers (scoring and hash).
func TestARouteThatTakesAnArgon2SlotSaysServerBusy(t *testing.T) {
	heavy := []string{"hasher.Verify", "hasher.Hash", "preparePassword", "preparePasswordOn"}
	for _, tc := range []struct {
		svc ratelimit.Service
		dir string
		doc []byte
	}{{ratelimit.Tenant, filepath.Join("..", "api"), api.Tenant()}, {ratelimit.Admin, filepath.Join("..", "adminapi"), api.Admin()}} {
		descr := map[string]string{}
		var d struct {
			Paths map[string]map[string]struct {
				ID          string `yaml:"operationId"`
				Description string `yaml:"description"`
			} `yaml:"paths"`
		}
		if err := yaml.Unmarshal(tc.doc, &d); err != nil {
			t.Fatal(err)
		}
		for _, methods := range d.Paths {
			for _, op := range methods {
				descr[op.ID] = op.Description
			}
		}
		ops, err := apispec.Parse(tc.doc, tc.svc)
		if err != nil {
			t.Fatal(err)
		}
		pc := parsePkg(t, tc.dir)
		reaches := 0
		for _, op := range ops {
			calls := reachedCalls(pc, capitalize(op.ID))
			takesSlot := false
			for _, h := range heavy {
				takesSlot = takesSlot || calls[h]
			}
			if !takesSlot {
				continue
			}
			reaches++
			if !strings.Contains(descr[op.ID], "server_busy") {
				t.Errorf("%s: %s reaches the Argon2 or the scoring gate and its description does not list server_busy", tc.svc, op.ID)
			}
		}
		if reaches == 0 {
			t.Errorf("%s: no operation reaches a gate; the walk found nothing, so it proves nothing", tc.svc)
		}
	}
}
