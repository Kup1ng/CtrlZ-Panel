package lint_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/api"
	"github.com/Kup1ng/CtrlZ-Panel/internal/ratelimit"
)

// Rule spec-fact-drift, round 6 (admin-r6-1, admin-r6-6). The `Errors:` sentence of an operation in
// api/admin-openapi.yaml is prose, and the web-admin client is written from it. Rounds 1 to 5
// compared the sentences with the spec's route table, which is another copy of the same prose, so
// both could say `totp_invalid` for a route that answers `invalid_credentials` by design, or
// `conflict (a transition is still running)` after the job had become supersedable.
//
// The rule: every code an operation documents must be ASSERTED by a test that drives that
// operation. A test function drives an operation when it holds a string that is the operation's
// path (a path parameter matches any segment, a Sprintf verb too), and asserts a code when the
// same function calls `.want(status, "code")` or compares `errCode()` with it. A documented code
// that no test asserts is a claim nobody checked, and fails here; the fix is a test or a shorter
// sentence. The list of exceptions can only shrink (an entry that no test needs fails), and each
// carries the reason no flow test can reach it.

// errorCodeGrandfathered lists "METHOD /path code" claims of the admin document that no test
// asserts yet. It is the debt of the rule's first run, listed so the rule can start failing for
// every new claim; an entry is removed when a test asserts the code or the sentence drops it.
var errorCodeGrandfathered = map[string]string{}

// assertion is one asserted code and the path of the request it was asserted on.
type assertion struct{ path, code string }

type testFuncFacts struct {
	name    string
	asserts []assertion
}

// testFuncFacts reads every top-level function of the _test.go files of a package directory.
func readTestFuncs(t *testing.T, dir string, httpxConsts map[string]string) []testFuncFacts {
	t.Helper()
	fset := token.NewFileSet()
	files, err := filepath.Glob(filepath.Join(dir, "*_test.go"))
	if err != nil {
		t.Fatal(err)
	}
	var out []testFuncFacts
	for _, f := range files {
		af, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range af.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			out = append(out, factsOf(fd, httpxConsts))
		}
	}
	return out
}

func litString(e ast.Expr, httpxConsts map[string]string) (string, bool) {
	switch v := e.(type) {
	case *ast.BasicLit:
		if v.Kind == token.STRING {
			s, err := strconv.Unquote(v.Value)
			return s, err == nil
		}
	case *ast.SelectorExpr:
		if x, ok := v.X.(*ast.Ident); ok && x.Name == "httpx" {
			s, ok := httpxConsts[v.Sel.Name]
			return s, ok
		}
	}
	return "", false
}

// requestHelpers are the helper methods and functions of the flow tests that send a fixed path, so
// an assertion chained on them belongs to that path. A reviewed list: the helper must really send
// only that path (flow_helpers_test.go, flow_reissue_test.go).
var requestHelpers = map[string]string{
	"login":       "/auth/login",
	"reissuePath": "/tenants/x/users/x/one-time-password",
	"reissue":     "/tenants/x/users/x/one-time-password",
}

// pathsIn returns the string literals of an expression that look like a path.
func pathsIn(e ast.Expr, httpxConsts map[string]string) []string {
	var out []string
	ast.Inspect(e, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			name := ""
			switch fn := call.Fun.(type) {
			case *ast.SelectorExpr:
				name = fn.Sel.Name
			case *ast.Ident:
				name = fn.Name
			}
			if p, ok := requestHelpers[name]; ok {
				out = append(out, p)
			}
		}
		if bl, ok := n.(*ast.BasicLit); ok {
			if s, ok := litString(bl, httpxConsts); ok && strings.HasPrefix(s, "/") {
				out = append(out, s)
			}
		}
		return true
	})
	return out
}

// factsOf reads what a test function asserts and on which request. An assertion belongs to the
// path of the request it is chained on (`b.post("/me/password", ...).want(401, "x")`) or of the
// variable that holds the response (`res := b.post("/me/password", ...)` and later
// `res.want(...)` or `res.errCode() == "x"`). A function that sends a path somewhere and asserts a
// code somewhere else claims nothing about either: the first version of this rule matched on the
// function and so passed for the very `totp_invalid` it was written for.
func factsOf(fd *ast.FuncDecl, httpxConsts map[string]string) testFuncFacts {
	f := testFuncFacts{name: fd.Name.Name}
	held := map[string][]string{} // variable name -> the paths of the request it was assigned from
	pathsOf := func(recv ast.Expr) []string {
		if id, ok := recv.(*ast.Ident); ok {
			return held[id.Name]
		}
		return pathsIn(recv, httpxConsts)
	}
	add := func(recv ast.Expr, code string) {
		for _, p := range pathsOf(recv) {
			f.asserts = append(f.asserts, assertion{p, code})
		}
	}
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.AssignStmt:
			for i, l := range v.Lhs {
				// `res, _ := r.reissue(...)` has one call on the right for several names on the left.
				rhs := v.Rhs[0]
				if len(v.Lhs) == len(v.Rhs) {
					rhs = v.Rhs[i]
				}
				if id, ok := l.(*ast.Ident); ok {
					if ps := pathsIn(rhs, httpxConsts); len(ps) > 0 {
						held[id.Name] = ps
					}
				}
			}
		case *ast.CallExpr:
			if sel, ok := v.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "want" && len(v.Args) == 2 {
				if s, ok := litString(v.Args[1], httpxConsts); ok && s != "" {
					add(sel.X, s)
				}
			}
		case *ast.BinaryExpr:
			if v.Op != token.EQL && v.Op != token.NEQ {
				return true
			}
			for _, pair := range [][2]ast.Expr{{v.X, v.Y}, {v.Y, v.X}} {
				if call, ok := pair[0].(*ast.CallExpr); ok {
					if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "errCode" {
						if s, ok := litString(pair[1], httpxConsts); ok {
							add(sel.X, s)
						}
					}
				}
			}
		}
		return true
	})
	return f
}

// pathMatches says a path a test sends is the operation's: the whole path, or the front of one that a
// test completes at run time (`"/users/" + id` is the literal "/users/").
func pathMatches(m *regexp.Regexp, opPath, lit string) bool {
	lit = normalisePathLiteral(lit)
	return m.MatchString(lit) || (strings.HasSuffix(lit, "/") && strings.HasPrefix(opPath, lit))
}

func normalisePathLiteral(s string) string {
	s, _, _ = strings.Cut(s, "?")
	return regexp.MustCompile(`%[sdvq]`).ReplaceAllString(s, "x")
}

// errorCodeGaps returns the claims no test asserts: "METHOD /path code".
func errorCodeGaps(ops map[string]routeFact, funcs []testFuncFacts) []string {
	var gaps []string
	for key, op := range ops {
		_, path, _ := strings.Cut(key, " ")
		// The paths of the document carry no server prefix; the tests send "/auth/login" too. A path
		// parameter matches one segment.
		param := regexp.MustCompile(`\{[^/}]+\}`)
		var quoted []string
		for _, part := range param.Split(path, -1) {
			quoted = append(quoted, regexp.QuoteMeta(part))
		}
		matcher := regexp.MustCompile(`^` + strings.Join(quoted, `[^/]+`) + `$`)
		for _, code := range op.Errors {
			found := false
			for _, f := range funcs {
				for _, a := range f.asserts {
					if a.code == code && pathMatches(matcher, path, a.path) {
						found = true
					}
				}
			}
			if !found {
				gaps = append(gaps, key+" "+code)
			}
		}
	}
	sort.Strings(gaps)
	return gaps
}

func httpxCodeConsts(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	fset := token.NewFileSet()
	files, _ := filepath.Glob(filepath.Join(root, "internal", "httpx", "*.go"))
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range af.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, sp := range gd.Specs {
				vs := sp.(*ast.ValueSpec)
				for i, id := range vs.Names {
					if i < len(vs.Values) && strings.HasPrefix(id.Name, "Code") {
						if s, ok := litString(vs.Values[i], nil); ok {
							out[id.Name] = s
						}
					}
				}
			}
		}
	}
	return out
}

func TestEveryDocumentedAdminErrorCodeIsAssertedByATest(t *testing.T) {
	root := repoRoot(t)
	funcs := readTestFuncs(t, filepath.Join(root, "internal", "adminapi"), httpxCodeConsts(t, root))
	ops := routeFacts(t, api.Admin())
	gaps := errorCodeGaps(ops, funcs)
	seen := map[string]bool{}
	for _, g := range gaps {
		seen[g] = true
		if _, ok := errorCodeGrandfathered[g]; !ok {
			t.Errorf("api/admin-openapi.yaml documents %q and no test of internal/adminapi asserts it (`.want(status, code)` in a function that sends that path): "+
				"drive the case, or take the code out of the sentence", g)
		}
	}
	for g := range errorCodeGrandfathered {
		if !seen[g] {
			t.Errorf("errorCodeGrandfathered lists %q and it is asserted now (or no longer documented): delete the entry", g)
		}
	}
	if len(ops) == 0 {
		t.Fatal("no operations read")
	}
}

// TestErrorCodeLintCanFail plants the shapes the rule must tell apart. The first version of it
// matched on the function and let a documented `totp_invalid` pass, because another request of the
// same function asserted it.
func TestErrorCodeLintCanFail(t *testing.T) {
	const src = `package x
func TestA(t *testing.T) {
	b.post("/me/password", nil).want(401, "invalid_credentials")
	b.post("/auth/totp/fresh", nil).want(401, "totp_invalid") // another request of the same function
	res := b.get("/users/" + id)
	res.want(404, "not_found")
	r2, _ := r.reissue(t, b, u)
	r2.want(409, "password_not_one_time")
	if b.post("/invites", nil).errCode() != "phone_unavailable" {
	}
}
`
	fset := token.NewFileSet()
	af, err := parser.ParseFile(fset, "x_test.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	var funcs []testFuncFacts
	for _, d := range af.Decls {
		funcs = append(funcs, factsOf(d.(*ast.FuncDecl), nil))
	}
	ops := map[string]routeFact{
		"POST /me/password":                             {Errors: []string{"invalid_credentials", "totp_invalid", "totp_step_reused"}},
		"POST /auth/totp/fresh":                         {Errors: []string{"totp_invalid"}},
		"GET /users/{id}":                               {Errors: []string{"not_found", "conflict"}},
		"POST /tenants/{t}/users/{u}/one-time-password": {Errors: []string{"password_not_one_time"}},
		"POST /invites":                                 {Errors: []string{"phone_unavailable", "invalid_phone"}},
	}
	want := []string{
		"GET /users/{id} conflict",       // never asserted
		"POST /invites invalid_phone",    // never asserted
		"POST /me/password totp_invalid", // asserted on another request of the same function
		"POST /me/password totp_step_reused",
	}
	got := errorCodeGaps(ops, funcs)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("gaps =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// Round 8 (admin-r8-3). The rule above runs one way: every documented code is asserted by a test.
// The other way had no lint, so the documented set could be a subset of what the handler answers:
// since round 7 a request refused by the deferred class admin-login is answered by the handler
// itself with `rate_limited`, and the login's sentence listed only `too_many_attempts` (the
// refusal of a scope of one account), so a client written from the sentence had no branch for the
// class's wait message. The rule closes the class the finding was an instance of, over the registry and not over the cases seen:
// an operation whose rate class is deferred (the pipeline hands its refusal to the handler) documents
// `rate_limited`, in its sentence or by pointing at the shared RateLimited response. The general
// converse (every code a test asserts on an operation is documented) is NOT built: a test assertion
// carries a path and no method, so a test of POST /users would be read as an answer of GET /users, and
// the first run listed 24 false claims; it needs the method in the assertion first (rule
// spec-fact-drift, noted for the next round).

// sharedResponseCodes is the code each shared response of api/admin-openapi.yaml documents.
var sharedResponseCodes = map[string]string{
	"RateLimited":    "rate_limited",
	"SessionExpired": "session_expired",
	"Unavailable":    "service_unavailable",
}

// documentedCodes is what an operation tells its client: its sentence and its shared responses.
func documentedCodes(op routeFact) map[string]bool {
	out := map[string]bool{}
	for _, c := range op.Errors {
		out[c] = true
	}
	for _, r := range op.Refs {
		if c, ok := sharedResponseCodes[r]; ok {
			out[c] = true
		}
	}
	return out
}

// deferredWithoutRefusal returns the operations of a deferred class that do not document it.
func deferredWithoutRefusal(ops map[string]routeFact, deferred func(rate string) bool) []string {
	var out []string
	for key, op := range ops {
		if deferred(op.Rate) && !documentedCodes(op)["rate_limited"] {
			out = append(out, key)
		}
	}
	sort.Strings(out)
	return out
}

func TestEveryDeferredClassOperationDocumentsItsRefusal(t *testing.T) {
	ops := routeFacts(t, api.Admin())
	deferred := func(rate string) bool {
		c, ok := ratelimit.Lookup(ratelimit.Admin, rate)
		return ok && c.Deferred
	}
	n := 0
	for _, op := range ops {
		if deferred(op.Rate) {
			n++
		}
	}
	if n == 0 {
		t.Fatal("no admin operation has a deferred class: the test proves nothing")
	}
	for _, key := range deferredWithoutRefusal(ops, deferred) {
		t.Errorf("%s uses a deferred rate class and does not document `rate_limited` (its sentence, or a 429 pointing at the shared RateLimited response): its handler answers the class's refusal itself", key)
	}
}

// TestDeferredRefusalLintCanFail plants the round 7 shape (a refusal the handler answers and the
// sentence does not name) and the two ways of being documented that must pass.
func TestDeferredRefusalLintCanFail(t *testing.T) {
	ops := map[string]routeFact{
		"POST /auth/login":  {Rate: "admin-login", Errors: []string{"invalid_credentials", "too_many_attempts"}},
		"POST /auth/other":  {Rate: "admin-login", Errors: []string{"invalid_credentials"}, Refs: []string{"RateLimited"}},
		"POST /auth/third":  {Rate: "admin-login", Errors: []string{"rate_limited"}},
		"GET /me":           {Rate: "admin-read", Errors: []string{"session_expired"}},
		"POST /auth/ticket": {Rate: "admin-login", Refs: []string{"SessionExpired"}},
	}
	got := deferredWithoutRefusal(ops, func(rate string) bool { return rate == "admin-login" })
	if strings.Join(got, ",") != "POST /auth/login,POST /auth/ticket" {
		t.Fatalf("deferred operations without the refusal = %v", got)
	}
}
