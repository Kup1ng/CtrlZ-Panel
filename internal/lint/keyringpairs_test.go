package lint_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
)

// Rule one-primitive-per-key, third half (review round 7, primitives-r7-3; typed in round 13,
// primitives-r13-5). The keyring refuses a (domain, label) pair that keyring.Uses does not list, at
// run time. A pair on a path no test reaches would be found only in production (MAC panics), so
// this lint reads every use of the four labelled operations in non-test code through the type
// checker (keyringuse_test.go) and compares the constant values of the arguments with Uses. The
// value is the constant's own, not the name of an identifier, so an alias, a local constant or a
// dot import is read as what it is. A call whose domain or label is not a constant cannot be judged
// from the text; those are the files of variablePairFiles, each with the reason its values are
// held elsewhere, and any other file that passes a variable is a failure. A method value or
// expression of any of them is a failure of its own (keyringContextProblems has the same rule for
// the sealing four).

// variablePairSites are the only declarations of non-test files that pass a domain or a label that is
// not a keyring constant, each with where the value is fixed (round 18, primitives-r18-8: the list was
// keyed by file, so any other function of tag.go could MAC under a label chosen at run time and a
// mismatch between an issue and a check was invisible; now a reviewer reads each function that holds
// the right, and an entry whose function no longer does is stale).
var variablePairSites = map[string]string{
	"internal/auth/marker/marker.go::Service.Issue":         "seals a marker under the domain and label of its Kind, constants of the package (params); the marker tests issue and read both kinds",
	"internal/auth/marker/marker.go::Service.Open":          "opens a marker under the domain and label of its Kind, the same constants as Issue",
	"internal/auth/session/tag.go::Manager.newSessionToken": "tags a session token under the manager's domain (auth_mac for the tenant, admin_mac for the admin, a constructor argument) and the constant LabelSession",
	"internal/auth/session/tag.go::Manager.Screen":          "verifies the tag under the same domain and the same constant LabelSession as newSessionToken: the two places that must agree",
	"internal/authtest/boundary/boundary.go::CookieFor":     "a test fixture that forges a session tag for either service's domain, with the constant LabelSession",
}

func pairedOps() map[string]bool {
	return map[string]bool{"MAC": true, "VerifyMAC": true, "SealLabeled": true, "OpenLabeled": true}
}

// keyringConstants reads the Domain and Label constants from the keyring source itself, so the
// lint knows no list that can go stale. The planted sources of the tests are built from them.
func keyringConstants(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	fset := token.NewFileSet()
	pkg := filepath.Join(repoRoot(t), "internal", "keyring")
	files, err := filepath.Glob(filepath.Join(pkg, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range files {
		if strings.HasSuffix(p, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, p, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, s := range gd.Specs {
				vs := s.(*ast.ValueSpec)
				for i, n := range vs.Names {
					if !strings.HasPrefix(n.Name, "Domain") && !strings.HasPrefix(n.Name, "Label") || i >= len(vs.Values) {
						continue
					}
					if lit, ok := vs.Values[i].(*ast.BasicLit); ok && lit.Kind == token.STRING {
						v, _ := strconv.Unquote(lit.Value)
						out[n.Name] = v
					}
				}
			}
		}
	}
	if len(out) < 8 {
		t.Fatalf("read %d keyring constants; the source layout changed", len(out))
	}
	return out
}

// pairArgs reads the domain and the label of a direct call of a labelled operation.
func (w *keyringWorld) pairArgs(u ringUse) (dom, lab string, domConst, labConst, ok bool) {
	if u.call == nil || len(u.call.Args) < 2 {
		return "", "", false, false, false
	}
	dom, domConst = w.stringConst(u.call.Args[0])
	lab, labConst = w.stringConst(u.call.Args[1])
	return dom, lab, domConst, labConst, true
}

// keyringPairProblems judges the files; listed says which (domain, label) pairs Uses has.
func keyringPairProblems(w *keyringWorld, listed func(domain, label string) bool) []string {
	labelUnderSomeDomain := func(label string) bool {
		for _, u := range keyring.Uses() {
			if u.Label == label {
				return true
			}
		}
		return false
	}
	out := w.shapeProblems(pairedOps())
	for _, u := range w.uses {
		if !pairedOps()[u.name] || u.call == nil {
			continue
		}
		dom, lab, domConst, labConst, ok := w.pairArgs(u)
		if !ok {
			out = append(out, w.at(u.call)+": "+u.name+" is called with too few arguments to read its pair")
			continue
		}
		at := w.at(u.call)
		if domConst && labConst {
			if !listed(dom, lab) {
				out = append(out, at+": "+u.name+" uses label "+lab+" under domain "+dom+", which keyring.Uses does not list")
			}
			continue
		}
		if labConst && !labelUnderSomeDomain(lab) {
			out = append(out, at+": "+u.name+" uses label "+lab+", which keyring.Uses lists under no domain")
		}
		if _, ok := variablePairSites[u.site]; !ok {
			out = append(out, at+": "+u.name+" takes a domain or a label that is not a constant, in "+u.site+", which is not in variablePairSites")
		}
	}
	sort.Strings(out)
	return out
}

func TestEveryKeyringCallUsesAListedPair(t *testing.T) {
	fset, files := parseRepo(t)
	w, ok := newKeyringWorld(fset, files)
	if !ok {
		t.Fatal("type information unavailable")
	}
	if got := keyringPairProblems(w, keyring.PairListed); len(got) > 0 {
		t.Errorf("%d keyring calls break the (domain, label) registry:\n%s", len(got), strings.Join(got, "\n"))
	}
	// The scan found the calls it is about, and read their constants through the checker.
	pairs, constant := 0, 0
	for _, u := range w.uses {
		if !pairedOps()[u.name] || u.call == nil {
			continue
		}
		pairs++
		if _, _, d, l, _ := w.pairArgs(u); d && l {
			constant++
		}
	}
	if pairs < 8 || constant < 5 {
		t.Errorf("the lint saw %d labelled calls and read the constants of %d; the type information is incomplete", pairs, constant)
	}
	// The allow list can only shrink: a declaration that no longer passes a variable is removed from it.
	used := map[string]bool{}
	for _, u := range w.uses {
		if _, listed := variablePairSites[u.site]; !listed || !pairedOps()[u.name] || u.call == nil {
			continue
		}
		if _, _, d, l, _ := w.pairArgs(u); !d || !l {
			used[u.site] = true
		}
	}
	for p := range variablePairSites {
		if !used[p] {
			t.Errorf("variablePairSites lists %s, which passes no variable domain or label any more", p)
		}
	}
}

// TestKeyringPairLintCanFail plants the shapes the rule is about.
func TestKeyringPairLintCanFail(t *testing.T) {
	cases := []struct {
		name, path, src string
		want            int
	}{
		{"a listed pair", "internal/api/x.go", `func f(r *keyring.Ring) { r.MAC(keyring.DomainAuthMAC, keyring.LabelOTP, nil) }`, 0},
		{"the admin device label under auth_mac", "internal/api/x.go", `func f(r *keyring.Ring) { r.SealLabeled(keyring.DomainAuthMAC, keyring.LabelAdminDevice, nil, nil) }`, 1},
		{"a ceremony tag under admin_mac", "internal/adminapi/x.go", `func f(r *keyring.Ring) { r.VerifyMAC(keyring.DomainAdminMAC, keyring.LabelCeremony, nil, nil) }`, 1},
		{"the device label under admin_mac", "internal/adminapi/x.go", `func f(r *keyring.Ring) { r.OpenLabeled(keyring.DomainAdminMAC, keyring.LabelDevice, nil, nil) }`, 1},
		{"a sealed domain as a MAC root", "internal/api/x.go", `func f(r *keyring.Ring) { r.MAC(keyring.DomainUserTOTP, keyring.LabelThrottle, nil) }`, 1},
		{"a variable domain outside the list", "internal/api/x.go", `func f(r *keyring.Ring, d string) { r.MAC(d, keyring.LabelSession, nil) }`, 1},
		{"a variable label outside the list", "internal/api/x.go", `func f(r *keyring.Ring, l string) { r.MAC(keyring.DomainAuthMAC, l, nil) }`, 1},
		{"a variable domain in a listed declaration", "internal/auth/session/tag.go", `type Manager struct{}
func (m *Manager) newSessionToken(r *keyring.Ring, d string) { r.MAC(d, keyring.LabelSession, nil) }`, 0},
		{"a variable domain in another declaration of the listed file", "internal/auth/session/tag.go", `func g(r *keyring.Ring, d string) { r.MAC(d, keyring.LabelSession, nil) }`, 1},
		{"a test file is not judged", "internal/api/x_test.go", `func f(r *keyring.Ring) { r.MAC(keyring.DomainAuthMAC, keyring.LabelAdminDevice, nil) }`, 0},
		{"the keyring itself is not judged", "internal/keyring/x.go", `func f(r *Ring) { r.MAC(DomainAuthMAC, LabelAdminDevice, nil) }`, 0},
		{"a call of another method is not judged", "internal/api/x.go", `type H struct{}
func (H) Sum(a, b string) {}
func f(h H) { h.Sum(keyring.DomainAuthMAC, keyring.LabelAdminDevice) }`, 0},
		// The value is read, not the spelling (round 13, primitives-r13-5).
		{"a pair behind a local constant", "internal/api/x.go", `const d = keyring.DomainAuthMAC
const l = keyring.LabelAdminDevice
func f(r *keyring.Ring) { r.MAC(d, l, nil) }`, 1},
		{"a pair spelled as string literals", "internal/api/x.go", `func f(r *keyring.Ring) { r.MAC("auth_mac", "admin_device", nil) }`, 1},
		{"a listed pair spelled as string literals", "internal/api/x.go", `func f(r *keyring.Ring) { r.MAC("auth_mac", "otp", nil) }`, 0},
		{"a pair behind an aliased import", "internal/api/x.go", `func f(r *kr.Ring) { r.MAC(kr.DomainAuthMAC, kr.LabelAdminDevice, nil) }
type _ = kr.Ring`, 1},
		// Not a call: the arguments are not where the lint reads them.
		{"a method value", "internal/api/x.go", `func f(r *keyring.Ring) { mac := r.MAC; mac(keyring.DomainAuthMAC, keyring.LabelAdminDevice, nil) }`, 1},
		{"a method value handed on", "internal/api/x.go", `func use(v func(string, string, ...[]byte) []byte) {}
func f(r *keyring.Ring) { use(r.MAC) }`, 1},
		{"a method expression", "internal/api/x.go", `func f(r *keyring.Ring) { _ = (*keyring.Ring).VerifyMAC }`, 1},
		{"a labelled open as a value", "internal/api/x.go", `func f(r *keyring.Ring) { open := r.OpenLabeled; _ = open }`, 1},
	}
	for _, c := range cases {
		src := plantHeader + c.src
		if strings.Contains(c.src, "kr.") {
			src = strings.Replace(src, "\t\""+keyringPkg+"\"", "\tkr \""+keyringPkg+"\"", 1)
		}
		if c.path == "internal/keyring/x.go" {
			src = "package keyring\n" + c.src
		}
		w := plantedWorld(t, c.name, c.path, src)
		if got := keyringPairProblems(w, keyring.PairListed); len(got) != c.want {
			t.Errorf("%s: %d problems %v, want %d", c.name, len(got), got, c.want)
		}
	}
}
