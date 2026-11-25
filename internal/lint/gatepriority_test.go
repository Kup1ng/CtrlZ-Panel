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
// So the callers are one reviewed list, and a call anywhere else fails. Since round 18
// (primitives-r18-8) the list is keyed by declaration ("file::Func", sites_test.go) and not by file:
// the reason of each entry is a claim about one function (the resolver of a session that passed its
// gate, the login whose marker holds), and a file such as routes_login.go holds the other login and
// reset handlers too, which the file-keyed list let take the lane.
//
//   - internal/adminapi/server.go, resolver.Resolve: an admin session that passed its gate;
//
//   - internal/adminapi/routes_auth.go, Server.loginHolding: the login whose device marker opened
//     under its seal and holds for the account found;
//
//   - internal/api/resolver.go, resolver.Resolve: a tenant session that passed its gate (tenant-r6-1);
//
//   - internal/api/routes_login.go, Server.loginPassword: the tenant login whose device marker holds
//     for the account;
//
//   - internal/auth/proof/proof.go, Run: the Work step of a Spec whose Check passed (a code, a ticket,
//     an invite, a sealed ceremony): the one place a route's own proof becomes the lane. A
//     first-factor password is not given it there.
var provedSites = map[string]string{
	"internal/adminapi/server.go::resolver.Resolve":         "an admin session that passed its gate is a proof",
	"internal/adminapi/routes_auth.go::Server.loginHolding": "a device marker that opened under its seal and holds for the account found is a proof",
	"internal/api/resolver.go::resolver.Resolve":            "a tenant session that passed its gate is a proof",
	"internal/api/routes_login.go::Server.loginPassword":    "a device marker that opened under its seal and holds for the account found is a proof",
	"internal/auth/proof/proof.go::Run":                     "the Work step of a Spec whose Check passed is a request with a proof; a first-factor password is not",
}

// subjectBoundSites lists the callers whose proof can be used again and again (a session, a device
// marker). They must ask for the lane with password.ProvedAs, which bounds an account to one hash in it
// at a time, and not with the plain Proved, which would hand one account holder the whole lane through
// any number of sessions (round 7, tenant-r7-6). The admin callers are not listed: admin accounts are
// made at the console by the owner, and the admin gate has one slot.
var subjectBoundSites = map[string]bool{
	"internal/api/resolver.go::resolver.Resolve":         true,
	"internal/api/routes_login.go::Server.loginPassword": true,
}

const (
	passwordPkgDir  = "internal/auth/password/"
	passwordPkgPath = "github.com/Kup1ng/CtrlZ-Panel/internal/auth/password"
)

// provedUse is one selector local.Proved or local.ProvedAs, with the declaration that holds it.
type provedUse struct {
	member, site string
	sel          *ast.SelectorExpr
}

// provedUses lists the selectors Proved and ProvedAs of the password package in a file, through every
// name the file gives the package (localNames), each with its site.
func provedUses(path string, f *ast.File) []provedUse {
	names := usableNames(localNames(f, passwordPkgPath))
	var out []provedUse
	walkSites(path, f, func(site string, n ast.Node) {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok || (sel.Sel.Name != "Proved" && sel.Sel.Name != "ProvedAs") {
			return
		}
		if x, ok := sel.X.(*ast.Ident); ok {
			for _, nm := range names {
				if x.Name == nm {
					out = append(out, provedUse{member: sel.Sel.Name, site: site, sel: sel})
				}
			}
		}
	})
	return out
}

// provedProblems returns every use of password.Proved or ProvedAs in a declaration that is not on the
// list, and a plain Proved in a subject-bound one. Test files and the package itself are free.
func provedProblems(path string, f *ast.File) []string {
	if strings.HasSuffix(path, "_test.go") || strings.HasPrefix(path, passwordPkgDir) {
		return nil
	}
	var out []string
	if hasDot(localNames(f, passwordPkgPath)) {
		out = append(out, path+" imports the password package with a dot, which hides its calls from this lint")
	}
	for _, u := range provedUses(path, f) {
		if _, ok := provedSites[u.site]; !ok {
			out = append(out, path+": "+u.site+" uses password."+u.member+", the priority lane of the Argon2 gate, and only the declarations listed in provedSites may ask for it")
			continue
		}
		if subjectBoundSites[u.site] && u.member == "Proved" {
			out = append(out, path+": "+u.site+" asks for the gate lane with a proof that can be used again (a session, a device marker); it uses password.ProvedAs, so that one account holds one hash in it at a time")
		}
	}
	return out
}

func TestGatePriorityIsGivenOnlyByProofs(t *testing.T) {
	_, files := parseRepo(t)
	found := map[string]bool{}
	for _, f := range files {
		for _, p := range provedProblems(f.path, f.ast) {
			t.Error(p)
		}
		if f.test || strings.HasPrefix(f.path, passwordPkgDir) {
			continue
		}
		for _, u := range provedUses(f.path, f.ast) {
			found[u.site] = true
		}
	}
	for site, why := range provedSites {
		if !found[site] {
			t.Errorf("%s is listed as a caller of password.Proved (%s) and does not call it: remove the entry", site, why)
		}
	}
	for site := range subjectBoundSites {
		if _, ok := provedSites[site]; !ok {
			t.Errorf("subjectBoundSites lists %s, which is not in provedSites", site)
		}
	}
}

func TestGatePriorityLintCanFail(t *testing.T) {
	const pkg = `import "github.com/Kup1ng/CtrlZ-Panel/internal/auth/password"`
	cases := map[string]struct {
		path, src string
		want      int
	}{
		"a route marks its requests":                 {"internal/adminapi/routes_users.go", "package x\n" + pkg + "\nfunc f() { _ = password.Proved(nil) }\n", 1},
		"a tenant route":                             {"internal/api/routes_account.go", "package x\n" + pkg + "\nvar _ = password.Proved\n", 1},
		"the tenant resolver":                        {"internal/api/resolver.go", "package x\n" + pkg + "\ntype resolver struct{}\nfunc (r resolver) Resolve() { _ = password.ProvedAs(nil, \"u\") }\n", 0},
		"the tenant resolver, plain":                 {"internal/api/resolver.go", "package x\n" + pkg + "\ntype resolver struct{}\nfunc (r resolver) Resolve() { _ = password.Proved(nil) }\n", 1},
		"a closure of the tenant resolver":           {"internal/api/resolver.go", "package x\n" + pkg + "\ntype resolver struct{}\nfunc (r resolver) Resolve() { _ = func() { _ = password.ProvedAs(nil, \"u\") } }\n", 0},
		"another method of the tenant resolver file": {"internal/api/resolver.go", "package x\n" + pkg + "\ntype resolver struct{}\nfunc (r resolver) Other() { _ = password.ProvedAs(nil, \"u\") }\n", 1},
		"the tenant login, plain":                    {"internal/api/routes_login.go", "package x\n" + pkg + "\ntype Server struct{}\nfunc (s *Server) loginPassword() { _ = password.Proved(nil) }\n", 1},
		"the tenant login":                           {"internal/api/routes_login.go", "package x\n" + pkg + "\ntype Server struct{}\nfunc (s *Server) loginPassword() { _ = password.ProvedAs(nil, \"u\") }\n", 0},
		"another handler of the login file":          {"internal/api/routes_login.go", "package x\n" + pkg + "\ntype Server struct{}\nfunc (s *Server) loginOTP() { _ = password.ProvedAs(nil, \"u\") }\n", 1},
		"a function of the admin login file":         {"internal/adminapi/routes_auth.go", "package x\n" + pkg + "\nfunc resetStep() { _ = password.Proved(nil) }\n", 1},
		"the admin login":                            {"internal/adminapi/routes_auth.go", "package x\n" + pkg + "\ntype Server struct{}\nfunc (s *Server) loginHolding() { _ = password.Proved(nil) }\n", 0},
		"a route with ProvedAs":                      {"internal/api/routes_account.go", "package x\n" + pkg + "\nfunc f() { _ = password.ProvedAs(nil, \"u\") }\n", 1},
		"a route that runs a Spec":                   {"internal/api/routes_reset.go", "package x\n" + pkg + "\nfunc f() { _ = password.Proved(nil) }\n", 1},
		"the proof runner":                           {"internal/auth/proof/proof.go", "package x\n" + pkg + "\nfunc Run() { _ = password.Proved(nil) }\n", 0},
		"another function of the proof file":         {"internal/auth/proof/proof.go", "package x\n" + pkg + "\nfunc other() { _ = password.Proved(nil) }\n", 1},
		"a method value":                             {"internal/api/routes_account.go", "package x\n" + pkg + "\nfunc f() { v := password.Proved; _ = v }\n", 1},
		"an alias":                                   {"internal/api/a.go", "package x\nimport pw \"github.com/Kup1ng/CtrlZ-Panel/internal/auth/password\"\nfunc f() { _ = pw.Proved(nil) }\n", 1},
		"two imports of the package":                 {"internal/api/a.go", "package x\nimport a \"github.com/Kup1ng/CtrlZ-Panel/internal/auth/password\"\nimport b \"github.com/Kup1ng/CtrlZ-Panel/internal/auth/password\"\nfunc f() { _ = a.Proved(nil); _ = b.Proved(nil) }\n", 2},
		"a dot import":                               {"internal/api/a.go", "package x\nimport . \"github.com/Kup1ng/CtrlZ-Panel/internal/auth/password\"\nfunc f() { _ = Proved(nil) }\n", 1},
		"the listed caller":                          {"internal/adminapi/server.go", "package x\n" + pkg + "\ntype resolver struct{}\nfunc (r resolver) Resolve() { _ = password.Proved(nil) }\n", 0},
		"a test":                                     {"internal/api/a_test.go", "package x\n" + pkg + "\nfunc f() { _ = password.Proved(nil) }\n", 0},
		"another selector named alike":               {"internal/api/a.go", "package x\n" + pkg + "\nfunc f(s struct{ Proved int }) { _ = s.Proved }\n", 0},
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
