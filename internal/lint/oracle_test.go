package lint_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"sort"
	"strings"
	"testing"
)

// The known-or-unknown rule (P1 auth review round 5, rules.md topic 4, spec 18.5)
// is enforced by the oracle tests of internal/api and internal/adminapi, which
// compare a phone or username with an account against one without. This lint
// closes the one door those tests walk through by name: the only place the answer
// to "did this request reach the Argon2 gate" may depend on the account is the
// admin login's one-time password (spec 10.2 step 2, admin-r4-6), and the method
// that does it is used by two declarations of the admin service and nowhere
// else. A tenant route that reached for it would open the gate difference again in
// a way no fault state of the oracle test sees until somebody wrote its variant.
//
// Round 18 (primitives-r18-7). The lint matched a call whose function was a selector named
// VerifyGateFree and keyed its allow list by file. A method value (`vf := s.hasher.VerifyGateFree;
// vf(...)`) is not a call of that selector and was never judged in any package, and any other function
// of routes_auth.go or routes_me.go could call it. Now the method is found by the type checker
// (Hasher.VerifyGateFree, however it is reached: a call, a method value, a method expression), an
// interface anywhere that has the method with its signature is refused (a value of it reaches the
// method with no selector of the Hasher), a selector of that name on a value the checker could not
// type fails closed, and the allow list is two declarations ("file::Type.Method", sites_test.go) with a
// stale-entry check.

const passwordPkg = module + "/internal/auth/password"

// gateFreeSites are the only declarations that may use Hasher.VerifyGateFree, the two the doc comment
// of the method names.
var gateFreeSites = map[string]string{
	"internal/adminapi/routes_auth.go::Server.loginHolding": "AdminLogin step 2, the declared exception",
	"internal/adminapi/routes_me.go::Server.changePassword": "POST /me/password, the current password of a first login",
}

// gateFreeProblems judges every non-test file outside the password package and reports which listed
// sites used the method.
func gateFreeProblems(fset *token.FileSet, files []file, info *types.Info, allowed map[string]string) (problems []string, used map[string]bool, uses int) {
	used = map[string]bool{}
	isMethod := func(fn *types.Func) bool {
		if fn.Name() != "VerifyGateFree" || fn.Pkg() == nil || fn.Pkg().Path() != passwordPkg {
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
		return ok && n.Obj().Name() == "Hasher"
	}
	var hasherSig types.Type
	for _, o := range info.Defs {
		if tn, ok := o.(*types.TypeName); ok && tn.Pkg() != nil && tn.Pkg().Path() == passwordPkg && tn.Name() == "Hasher" {
			ms := types.NewMethodSet(types.NewPointer(tn.Type()))
			for i := range ms.Len() {
				if fn, ok := ms.At(i).Obj().(*types.Func); ok && fn.Name() == "VerifyGateFree" {
					hasherSig = fn.Type()
				}
			}
		}
	}
	for _, f := range files {
		if f.test || strings.HasPrefix(f.path, "internal/auth/password/") {
			continue
		}
		walkSites(f.path, f.ast, func(site string, n ast.Node) {
			switch x := n.(type) {
			case *ast.SelectorExpr:
				if x.Sel.Name != "VerifyGateFree" {
					return
				}
				if s := info.Selections[x]; s != nil {
					if fn, ok := s.Obj().(*types.Func); ok && isMethod(fn) {
						uses++
						if _, ok := allowed[site]; ok {
							used[site] = true
						} else {
							problems = append(problems, fset.Position(x.Pos()).String()+": "+site+" uses VerifyGateFree; only the admin service's login and password change may (spec 10.2 step 2), and each by its own declaration (gateFreeSites)")
						}
					}
					return
				}
				if info.Uses[x.Sel] == nil && !isPackageName(info, x.X) {
					problems = append(problems, fset.Position(x.Pos()).String()+": VerifyGateFree is selected on a value whose type the lint could not resolve, so it cannot tell whether it is the Hasher's; give the value a type the repository declares")
				}
			case *ast.InterfaceType:
				tv, ok := info.Types[x]
				if !ok || tv.Type == nil || hasherSig == nil {
					return
				}
				it, ok := tv.Type.Underlying().(*types.Interface)
				if !ok {
					return
				}
				for i := range it.NumMethods() {
					if m := it.Method(i); m.Name() == "VerifyGateFree" && types.Identical(m.Type(), hasherSig) {
						problems = append(problems, fset.Position(x.Pos()).String()+": an interface has VerifyGateFree with the Hasher's signature, so a *password.Hasher can reach the gate-free check through it where no lint reads the call")
					}
				}
			}
		})
	}
	sort.Strings(problems)
	return problems, used, uses
}

func TestGateFreeVerifyOnlyInTheAdminService(t *testing.T) {
	fset, files := parseRepo(t)
	info, ok := typeInfo(fset, files)
	if !ok {
		t.Fatal("type information unavailable")
	}
	problems, used, uses := gateFreeProblems(fset, files, info, gateFreeSites)
	for _, p := range problems {
		t.Error(p)
	}
	if uses == 0 {
		t.Error("no use of VerifyGateFree found: the lint looks at the wrong files, or the exception is gone and the method should be deleted")
	}
	// Each entry must still use it: a caller that is gone leaves a stale entry that would let a new one
	// in under the same declaration (round 9, admin-r9-1).
	for site := range gateFreeSites {
		if !used[site] {
			t.Errorf("%s is on the VerifyGateFree allow list and no longer uses it: remove the entry, and the sentence that names it in the method's comment", site)
		}
	}
}

// TestGateFreeLintCanFail plants every way ordinary Go reaches the method: a call, a method value, a
// method expression, an alias of the receiver, an interface value, a wrapper in the same package, a
// closure, another declaration of a listed file, and the listed declarations themselves.
func TestGateFreeLintCanFail(t *testing.T) {
	const stub = "type Hasher struct{}\nfunc (h *Hasher) VerifyGateFree(a, b string) (bool, error) { return false, nil }\n"
	const imp = "import \"" + passwordPkg + "\"\n"
	cases := []struct {
		name, path, src string
		want            int
	}{
		{"a tenant route calls it", "internal/api/routes_login.go", imp + "func f(h *password.Hasher) { _, _ = h.VerifyGateFree(\"a\", \"b\") }", 1},
		{"a method value", "internal/api/routes_login.go", imp + "func f(h *password.Hasher) { vf := h.VerifyGateFree; _, _ = vf(\"a\", \"b\") }", 1},
		{"a method expression", "internal/api/routes_login.go", imp + "var vf = (*password.Hasher).VerifyGateFree", 1},
		{"a value of a struct that embeds the hasher", "internal/api/routes_login.go", imp + "type S struct{ *password.Hasher }\nfunc f(s S) { _, _ = s.VerifyGateFree(\"a\", \"b\") }", 1},
		{"a wrapper in the same package", "internal/api/routes_login.go", imp + "func g(h *password.Hasher) (bool, error) { return h.VerifyGateFree(\"a\", \"b\") }\nfunc f(h *password.Hasher) { _, _ = g(h) }", 1},
		{"a closure", "internal/api/routes_login.go", imp + "func f(h *password.Hasher) { _ = func() { _, _ = h.VerifyGateFree(\"a\", \"b\") } }", 1},
		{"an interface value", "internal/api/routes_login.go", imp + "type gf interface{ VerifyGateFree(a, b string) (bool, error) }\nfunc f(h *password.Hasher) { var g gf = h; _ = g }", 1},
		{"an interface literal", "internal/api/routes_login.go", imp + "func f(g interface{ VerifyGateFree(a, b string) (bool, error) }) {}", 1},
		{"a value of a library type", "internal/api/routes_login.go", "import \"example.com/lib\"\nfunc f(v lib.T) { v.VerifyGateFree() }", 1},
		{"another declaration of a listed file", "internal/adminapi/routes_auth.go", imp + "func resetStep(h *password.Hasher) { _, _ = h.VerifyGateFree(\"a\", \"b\") }", 1},
		{"the listed login", "internal/adminapi/routes_auth.go", imp + "type Server struct{ hasher *password.Hasher }\nfunc (s *Server) loginHolding() { _, _ = s.hasher.VerifyGateFree(\"a\", \"b\") }", 0},
		{"the listed password change", "internal/adminapi/routes_me.go", imp + "type Server struct{ hasher *password.Hasher }\nfunc (s *Server) changePassword() { _, _ = s.hasher.VerifyGateFree(\"a\", \"b\") }", 0},
		{"a method of another type with the name", "internal/api/routes_login.go", "type T struct{}\nfunc (T) VerifyGateFree() {}\nfunc f(t T) { t.VerifyGateFree() }", 0},
		{"a test file", "internal/api/routes_login_test.go", imp + "func f(h *password.Hasher) { _, _ = h.VerifyGateFree(\"a\", \"b\") }", 0},
	}
	for _, c := range cases {
		fset := token.NewFileSet()
		var fs []file
		for p, s := range map[string]string{"internal/auth/password/p.go": "package password\n" + stub, c.path: "package x\n" + c.src} {
			af, err := parser.ParseFile(fset, p, s, parser.ParseComments)
			if err != nil {
				t.Fatalf("%s: %v", c.name, err)
			}
			fs = append(fs, file{path: p, test: strings.HasSuffix(p, "_test.go"), ast: af})
		}
		info, ok := typeInfo(fset, fs)
		if !ok {
			t.Fatalf("%s: no type information", c.name)
		}
		got, _, _ := gateFreeProblems(fset, fs, info, gateFreeSites)
		if len(got) != c.want {
			t.Errorf("%s: %d problems %v, want %d", c.name, len(got), got, c.want)
		}
	}
}
