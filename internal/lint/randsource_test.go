package lint_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"slices"
	"strings"
	"testing"
)

// This is the "crypto/rand everywhere" convention of the primitives (review round 5,
// primitives-r5-4): every token,
// nonce, salt, code and id that an attacker must not predict comes from crypto/rand. It was
// held by reading only, so a helper that reached for math/rand/v2 `rand.N` for a code would
// have failed no test. math/rand is allowed in the one place below, and only because its
// value is not a secret.
//
// The exception is a declaration and not a file (round 18, primitives-r18-23): another function of the
// listed file that drew a code from math/rand used to pass because the file was listed. The lint reads
// every selector written through a local name of either package (localNames) and refuses one whose
// enclosing declaration is not listed; a file that imports the package and has no listed declaration
// is refused at the import, so a blank import (which uses nothing) is not a way in.

// mathRandAllowed lists the declarations ("file::Func", sites_test.go) of non-test files that may use
// math/rand or math/rand/v2, each with the reason. A new entry is a reviewed decision; a stale one fails.
func mathRandAllowed() map[string]string {
	return map[string]string{
		"internal/auth/password/floor.go::RealTiming": "the jitter of the response-time floor of a login; it blurs a timing, it protects no value",
	}
}

func isMathRand(p string) bool { return p == "math/rand" || p == "math/rand/v2" }

// mathRandViolations judges one non-test source file given as text (so the self-test can plant cases)
// and reports a message per import of math/rand in a file with no listed declaration and per use outside
// a listed one. It also returns the listed sites that the file really uses.
func mathRandViolations(name, src string, allowed map[string]string) (out []string, used map[string]bool) {
	f, err := parser.ParseFile(token.NewFileSet(), name, src, 0)
	if err != nil {
		return []string{name + ": " + err.Error()}, map[string]bool{}
	}
	return mathRandViolationsOf(name, f, allowed)
}

// mathRandViolationsOf is mathRandViolations for a parsed file.
func mathRandViolationsOf(name string, f *ast.File, allowed map[string]string) (out []string, used map[string]bool) {
	used = map[string]bool{}
	names := localNamesWhere(f, isMathRand)
	if len(names) == 0 {
		return nil, used
	}
	hasListed := false
	for site := range allowed {
		if strings.HasPrefix(site, name+"::") {
			hasListed = true
		}
	}
	if !hasListed {
		return []string{name + " imports math/rand; secrets, tokens, salts, codes and ids come from crypto/rand"}, used
	}
	if hasDot(names) {
		out = append(out, name+" dot-imports math/rand, which hides its members from this lint")
	}
	usable := usableNames(names)
	walkSites(name, f, func(site string, n ast.Node) {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return
		}
		id, ok := sel.X.(*ast.Ident)
		if !ok || id.Obj != nil || !slices.Contains(usable, id.Name) {
			return
		}
		if _, ok := allowed[site]; ok {
			used[site] = true
			return
		}
		out = append(out, name+": "+id.Name+"."+sel.Sel.Name+" in "+site+"; math/rand is allowed only in the listed declarations of mathRandAllowed, and secrets, tokens, salts, codes and ids come from crypto/rand")
	})
	return out, used
}

func TestSecurityValuesUseCryptoRand(t *testing.T) {
	_, files := parseRepo(t)
	allowed := mathRandAllowed()
	used := map[string]bool{}
	for _, f := range files {
		if f.test {
			continue
		}
		out, u := mathRandViolationsOf(f.path, f.ast, allowed)
		for _, p := range out {
			t.Error(p)
		}
		for s := range u {
			used[s] = true
		}
	}
	for site := range allowed {
		if !used[site] {
			t.Errorf("%s is on the math/rand allow list and no longer uses it; remove the entry", site)
		}
	}
}

func TestMathRandLintCanFail(t *testing.T) {
	allowed := map[string]string{"internal/ok/jitter.go::jitter": "a reason"}
	for name, tc := range map[string]struct {
		file, src string
		want      int
	}{
		"v1":                            {"internal/x/a.go", "package x\nimport \"math/rand\"\n", 1},
		"v2":                            {"internal/x/a.go", "package x\nimport \"math/rand/v2\"\n", 1},
		"aliased":                       {"internal/x/a.go", "package x\nimport r \"math/rand/v2\"\n", 1},
		"blank":                         {"internal/x/a.go", "package x\nimport _ \"math/rand\"\n", 1},
		"crypto is fine":                {"internal/x/a.go", "package x\nimport \"crypto/rand\"\n", 0},
		"the allowed site":              {"internal/ok/jitter.go", "package x\nimport \"math/rand/v2\"\nfunc jitter() int { return rand.N(5) }\n", 0},
		"the allowed site in a literal": {"internal/ok/jitter.go", "package x\nimport \"math/rand/v2\"\nfunc jitter() func() int { return func() int { return rand.N(5) } }\n", 0},
		"same name elsewhere":           {"internal/other/jitter.go", "package x\nimport \"math/rand/v2\"\nfunc jitter() int { return rand.N(5) }\n", 1},
		// primitives-r18-23: the file is listed and the declaration is not.
		"another function of the allowed file":            {"internal/ok/jitter.go", "package x\nimport \"math/rand/v2\"\nfunc jitter() int { return rand.N(5) }\nfunc code() int { return rand.N(1000000) }\n", 1},
		"a method of the allowed file":                    {"internal/ok/jitter.go", "package x\nimport \"math/rand/v2\"\ntype T struct{}\nfunc (T) jitter() int { return rand.N(5) }\n", 1},
		"a package-level use in the allowed file":         {"internal/ok/jitter.go", "package x\nimport \"math/rand/v2\"\nvar seed = rand.N(9)\n", 1},
		"the second alias in the allowed file":            {"internal/ok/jitter.go", "package x\nimport \"math/rand/v2\"\nimport r \"math/rand/v2\"\nfunc code() int { return r.N(9) }\n", 1},
		"another function through the first of two names": {"internal/ok/jitter.go", "package x\nimport \"math/rand/v2\"\nimport r \"math/rand/v2\"\nfunc jitter() int { return r.N(5) }\nfunc code() int { return rand.N(9) }\n", 1},
		"a dot import in the allowed file":                {"internal/ok/jitter.go", "package x\nimport . \"math/rand/v2\"\nfunc jitter() int { return N(5) }\n", 1},
		"a blank import in the allowed file":              {"internal/ok/jitter.go", "package x\nimport _ \"math/rand\"\nimport \"math/rand/v2\"\nfunc jitter() int { return rand.N(5) }\n", 0},
		"a local called rand is not the package":          {"internal/ok/jitter.go", "package x\nimport \"math/rand/v2\"\nfunc jitter() int { return rand.N(5) }\nfunc code(rand struct{ N func(int) int }) int { return rand.N(9) }\n", 0},
	} {
		got, _ := mathRandViolations(tc.file, tc.src, allowed)
		if len(got) != tc.want {
			t.Errorf("%s: %d violations %v, want %d", name, len(got), got, tc.want)
		}
	}
}
