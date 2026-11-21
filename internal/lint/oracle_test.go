package lint_test

import (
	"go/ast"
	"strings"
	"testing"
)

// The known-or-unknown rule (P1 auth review round 5, rules.md topic 4, spec 18.5)
// is enforced by the oracle tests of internal/api and internal/adminapi, which
// compare a phone or username with an account against one without. This lint
// closes the one door those tests walk through by name: the only place the answer
// to "did this request reach the Argon2 gate" may depend on the account is the
// admin login's one-time password (spec 10.2 step 2, admin-r4-6), and the method
// that does it is called from the admin service's two password checks and nowhere
// else. A tenant route that reached for it would open the gate difference again in
// a way no fault state of the oracle test sees until somebody wrote its variant.
func TestGateFreeVerifyOnlyInTheAdminService(t *testing.T) {
	// The allow list is the two callers the doc comment of Hasher.VerifyGateFree names, and each must
	// still call it: a caller that is gone leaves a stale entry that would let a new one in under the
	// same file (round 9, admin-r9-1).
	allowed := map[string]bool{
		"internal/adminapi/routes_auth.go": true, // AdminLogin step 2, the declared exception
		"internal/adminapi/routes_me.go":   true, // POST /me/password, the current password of a first login
	}
	_, files := parseRepo(t)
	calls := 0
	calledIn := map[string]int{}
	for _, f := range files {
		if f.test || strings.HasPrefix(f.path, "internal/auth/password/") {
			continue
		}
		ast.Inspect(f.ast, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "VerifyGateFree" {
				calls++
				calledIn[f.path]++
				if !allowed[f.path] {
					t.Errorf("%s calls VerifyGateFree; only the admin service's login and password change may (spec 10.2 step 2)", f.path)
				}
			}
			return true
		})
	}
	if calls == 0 {
		t.Error("no caller of VerifyGateFree found: the lint looks at the wrong files, or the exception is gone and the method should be deleted")
	}
	for path := range allowed {
		if calledIn[path] == 0 {
			t.Errorf("%s is on the VerifyGateFree allow list and no longer calls it: remove the entry, and the sentence that names it in the method's comment", path)
		}
	}
}
