package lint_test

import (
	"go/parser"
	"go/token"
	"strconv"
	"testing"
)

// This is the "crypto/rand everywhere" convention of the primitives (review round 5,
// primitives-r5-4): every token,
// nonce, salt, code and id that an attacker must not predict comes from crypto/rand. It was
// held by reading only, so a helper that reached for math/rand/v2 `rand.N` for a code would
// have failed no test. math/rand is allowed in the one place below, and only because its
// value is not a secret.

// mathRandAllowed lists the non-test files that may import math/rand or math/rand/v2, each
// with the reason. A new entry is a reviewed decision; a stale one fails.
func mathRandAllowed() map[string]string {
	return map[string]string{
		"internal/auth/password/floor.go": "the jitter of the response-time floor of a login; it blurs a timing, it protects no value",
	}
}

func isMathRand(p string) bool { return p == "math/rand" || p == "math/rand/v2" }

// mathRandViolations judges one non-test source file given as text (so the self-test can
// plant cases) and reports a message per import of math/rand outside the allow list.
func mathRandViolations(name, src string, allowed map[string]string) []string {
	f, err := parser.ParseFile(token.NewFileSet(), name, src, parser.ImportsOnly)
	if err != nil {
		return []string{name + ": " + err.Error()}
	}
	var out []string
	for _, imp := range f.Imports {
		p, _ := strconv.Unquote(imp.Path.Value)
		if !isMathRand(p) {
			continue
		}
		if _, ok := allowed[name]; !ok {
			out = append(out, name+" imports "+p+"; secrets, tokens, salts, codes and ids come from crypto/rand")
		}
	}
	return out
}

func TestSecurityValuesUseCryptoRand(t *testing.T) {
	_, files := parseRepo(t)
	allowed := mathRandAllowed()
	used := map[string]bool{}
	for _, f := range files {
		if f.test {
			continue
		}
		for _, imp := range f.ast.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			if !isMathRand(p) {
				continue
			}
			if _, ok := allowed[f.path]; !ok {
				t.Errorf("%s imports %s; secrets, tokens, salts, codes and ids come from crypto/rand", f.path, p)
			}
			used[f.path] = true
		}
	}
	for name := range allowed {
		if !used[name] {
			t.Errorf("%s is on the math/rand allow list and no longer imports it; remove the entry", name)
		}
	}
}

func TestMathRandLintCanFail(t *testing.T) {
	allowed := map[string]string{"internal/ok/jitter.go": "a reason"}
	for name, tc := range map[string]struct {
		file, src string
		want      int
	}{
		"v1":                  {"internal/x/a.go", "package x\nimport \"math/rand\"\n", 1},
		"v2":                  {"internal/x/a.go", "package x\nimport \"math/rand/v2\"\n", 1},
		"aliased":             {"internal/x/a.go", "package x\nimport r \"math/rand/v2\"\n", 1},
		"blank":               {"internal/x/a.go", "package x\nimport _ \"math/rand\"\n", 1},
		"crypto is fine":      {"internal/x/a.go", "package x\nimport \"crypto/rand\"\n", 0},
		"the allowed file":    {"internal/ok/jitter.go", "package x\nimport \"math/rand/v2\"\n", 0},
		"same name elsewhere": {"internal/other/jitter.go", "package x\nimport \"math/rand/v2\"\n", 1},
	} {
		if got := len(mathRandViolations(tc.file, tc.src, allowed)); got != tc.want {
			t.Errorf("%s: %d violations, want %d", name, got, tc.want)
		}
	}
}
