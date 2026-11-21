package lint_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// Rule budget-keying, round 5 (admin-r5-9): the Argon2 gate serves a request that carries a proof
// before any stranger (password.Proved). The priority is worth what the callers that ask for it
// are worth: a route that marked every request as proved would hand the strangers the same lane.
// So the callers are one reviewed list, and a call anywhere else fails:
//
//   - internal/adminapi/server.go: the resolver of an admin session that passed its gate;
//
//   - internal/adminapi/routes_auth.go: the login whose device marker opened under its seal and
//     holds for the account found.
//
//   - internal/api/resolver.go: a tenant session that passed its gate (tenant-r6-1);
//
//   - internal/api/routes_login.go: the tenant login whose device marker holds for the account;
//
//   - internal/auth/proof/proof.go: the Work step of a Spec whose Check passed (a code, a ticket,
//     an invite, a sealed ceremony): the one place a route's own proof becomes the lane. A
//     first-factor password is not given it there.
var provedCallers = map[string]string{
	"internal/adminapi/server.go":      "an admin session that passed its gate is a proof",
	"internal/adminapi/routes_auth.go": "a device marker that opened under its seal and holds for the account found is a proof",
	"internal/api/resolver.go":         "a tenant session that passed its gate is a proof",
	"internal/api/routes_login.go":     "a device marker that opened under its seal and holds for the account found is a proof",
	"internal/auth/proof/proof.go":     "the Work step of a Spec whose Check passed is a request with a proof; a first-factor password is not",
}

// subjectBound lists the callers whose proof can be used again and again (a session, a device marker). They
// must ask for the lane with password.ProvedAs, which bounds an account to one hash in it at a time, and
// not with the plain Proved, which would hand one account holder the whole lane through any number of
// sessions (round 7, tenant-r7-6). The admin callers are not listed: admin accounts are made at the
// console by the owner, and the admin gate has one slot.
var subjectBound = map[string]bool{
	"internal/api/resolver.go":     true,
	"internal/api/routes_login.go": true,
}

const passwordPkgDir = "internal/auth/password/"

// provedProblems returns every call of password.Proved (or a Proved of the password package under
// another name) in a file that is not on the list. Test files and the package itself are free.
func provedProblems(path string, f *ast.File) []string {
	if strings.HasSuffix(path, "_test.go") || strings.HasPrefix(path, passwordPkgDir) {
		return nil
	}
	local := ""
	for _, imp := range f.Imports {
		p := strings.Trim(imp.Path.Value, `"`)
		if p != "github.com/Kup1ng/CtrlZ-Panel/internal/auth/password" {
			continue
		}
		local = "password"
		if imp.Name != nil {
			local = imp.Name.Name
		}
	}
	var out []string
	if local == "." {
		return append(out, path+" imports the password package with a dot, which hides its calls from this lint")
	}
	if local == "" || local == "_" {
		return nil
	}
	if _, ok := provedCallers[path]; ok {
		if subjectBound[path] {
			for _, sel := range provedUses(f, local) {
				if sel.Sel.Name == "Proved" {
					out = append(out, path+": a proof that can be used again (a session, a device marker) asks for the gate lane with password.ProvedAs, so that one account holds one hash in it at a time")
				}
			}
		}
		return out
	}
	for range provedUses(f, local) {
		out = append(out, path+": password.Proved is the priority lane of the Argon2 gate and only the callers listed in provedCallers may ask for it")
	}
	return out
}

// provedUses lists the selectors local.Proved of a file.
func provedUses(f *ast.File, local string) []*ast.SelectorExpr {
	var out []*ast.SelectorExpr
	ast.Inspect(f, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok || (sel.Sel.Name != "Proved" && sel.Sel.Name != "ProvedAs") {
			return true
		}
		if x, ok := sel.X.(*ast.Ident); ok && x.Name == local {
			out = append(out, sel)
		}
		return true
	})
	return out
}

func TestGatePriorityIsGivenOnlyByProofs(t *testing.T) {
	_, files := parseRepo(t)
	found := map[string]bool{}
	for _, f := range files {
		for _, p := range provedProblems(f.path, f.ast) {
			t.Error(p)
		}
		if _, ok := provedCallers[f.path]; ok && len(provedUses(f.ast, "password")) > 0 {
			found[f.path] = true
		}
	}
	for path, why := range provedCallers {
		if !found[path] {
			t.Errorf("%s is listed as a caller of password.Proved (%s) and does not call it: remove the entry", path, why)
		}
	}
}

func TestGatePriorityLintCanFail(t *testing.T) {
	const pkg = `import "github.com/Kup1ng/CtrlZ-Panel/internal/auth/password"`
	cases := map[string]struct {
		path, src string
		want      int
	}{
		"a route marks its requests":   {"internal/adminapi/routes_users.go", "package x\n" + pkg + "\nfunc f() { _ = password.Proved(nil) }\n", 1},
		"a tenant route":               {"internal/api/routes_account.go", "package x\n" + pkg + "\nvar _ = password.Proved\n", 1},
		"the tenant resolver":          {"internal/api/resolver.go", "package x\n" + pkg + "\nvar _ = password.ProvedAs\n", 0},
		"the tenant resolver, plain":   {"internal/api/resolver.go", "package x\n" + pkg + "\nvar _ = password.Proved\n", 1},
		"the tenant login, plain":      {"internal/api/routes_login.go", "package x\n" + pkg + "\nfunc f() { _ = password.Proved(nil) }\n", 1},
		"a route with ProvedAs":        {"internal/api/routes_account.go", "package x\n" + pkg + "\nfunc f() { _ = password.ProvedAs(nil, \"u\") }\n", 1},
		"a route that runs a Spec":     {"internal/api/routes_reset.go", "package x\n" + pkg + "\nfunc f() { _ = password.Proved(nil) }\n", 1},
		"the proof runner":             {"internal/auth/proof/proof.go", "package x\n" + pkg + "\nfunc f() { _ = password.Proved(nil) }\n", 0},
		"an alias":                     {"internal/api/a.go", "package x\nimport pw \"github.com/Kup1ng/CtrlZ-Panel/internal/auth/password\"\nfunc f() { _ = pw.Proved(nil) }\n", 1},
		"a dot import":                 {"internal/api/a.go", "package x\nimport . \"github.com/Kup1ng/CtrlZ-Panel/internal/auth/password\"\nfunc f() { _ = Proved(nil) }\n", 1},
		"the listed caller":            {"internal/adminapi/server.go", "package x\n" + pkg + "\nfunc f() { _ = password.Proved(nil) }\n", 0},
		"a test":                       {"internal/api/a_test.go", "package x\n" + pkg + "\nfunc f() { _ = password.Proved(nil) }\n", 0},
		"another selector named alike": {"internal/api/a.go", "package x\n" + pkg + "\nfunc f(s struct{ Proved int }) { _ = s.Proved }\n", 0},
	}
	for name, c := range cases {
		f, err := parser.ParseFile(token.NewFileSet(), c.path, c.src, 0)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := len(provedProblems(c.path, f)); got != c.want {
			t.Errorf("%s: %d findings, want %d", name, got, c.want)
		}
	}
}
