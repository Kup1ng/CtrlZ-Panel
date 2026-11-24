package lint_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strings"
	"testing"
)

// Rule budget-keying, round 6 (tenant-r6-8): a count made before the work is given back when the
// gate turned the request away. Round 5 (tenant-r5-1) made that a property of proof.Spec (a Spec
// with a Charge needs a Refund, which TestProofBeforeWorkRule checks), and it held only for the
// routes that use proof.Run: reauth charged reauth_user, verified a password and returned
// password.ErrBusy with the charge kept, so five busy answers locked a signed-in owner out of
// reauth for the whole window once the load had gone.
//
// The rule here is the same sentence for every function that is not a Spec: in internal/api and
// internal/adminapi, a function that charges a budget and, later in its text, takes a slot of a
// gate (a hasher verify or hash, the strength check through preparePassword) must also give a
// charge back (Refund, or a method named refund). A function that runs a Spec
// is judged by the Spec. The check is by name and by position, which is crude and fails closed: a
// new function that charges and hashes has to say what it does when the gate is full.

var (
	refundCharges = map[string]bool{"Charge": true, "ChargeProof": true, "chargeFactor": true}
	refundGates   = map[string]bool{"preparePassword": true, "preparePasswordOn": true}
	refundGives   = map[string]bool{"Refund": true, "refund": true}
)

// gateCall says a call takes a slot of the Argon2 or scoring gate: a function named in gates, or a
// Verify or Hash called on a value named like the hasher. gates is refundGates plus every
// function of the two API packages that reaches a gate call (gateNames), so a wrapper such as
// verifyStored is a gate as well. A list of names alone went blind the day reauth moved its
// password check into a wrapper: the mutant that removed the refund survived (CI, round 7).
func gateCall(call *ast.CallExpr, gates map[string]bool) bool {
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		return gates[fn.Name]
	case *ast.SelectorExpr:
		if gates[fn.Sel.Name] {
			return true
		}
		if fn.Sel.Name == "Verify" || fn.Sel.Name == "Hash" {
			switch x := fn.X.(type) {
			case *ast.Ident:
				return strings.EqualFold(x.Name, "hasher")
			case *ast.SelectorExpr:
				return strings.EqualFold(x.Sel.Name, "hasher")
			}
		}
	}
	return false
}

func inAPIPackages(path string) bool {
	return !strings.HasSuffix(path, "_test.go") && (strings.HasPrefix(path, "internal/api/") || strings.HasPrefix(path, "internal/adminapi/"))
}

// gateNames is the closure of refundGates over the functions of internal/api and
// internal/adminapi: a function whose body calls a gate is a gate. It goes by name and ignores the
// receiver, which over-approximates (two functions of one name are one) and so fails closed: a
// charge followed by a call to either has to say what it does when the gate is full.
func gateNames(files map[string]*ast.File) map[string]bool {
	gates := map[string]bool{}
	for n := range refundGates {
		gates[n] = true
	}
	for changed := true; changed; {
		changed = false
		for path, f := range files {
			if !inAPIPackages(path) {
				continue
			}
			for _, d := range f.Decls {
				fd, ok := d.(*ast.FuncDecl)
				if !ok || fd.Body == nil || gates[fd.Name.Name] {
					continue
				}
				reaches := false
				ast.Inspect(fd.Body, func(n ast.Node) bool {
					if c, ok := n.(*ast.CallExpr); ok && gateCall(c, gates) {
						reaches = true
					}
					return !reaches
				})
				if reaches {
					gates[fd.Name.Name], changed = true, true
				}
			}
		}
	}
	return gates
}

func refundProblems(path string, f *ast.File, gates map[string]bool) []string {
	if !inAPIPackages(path) {
		return nil
	}
	var out []string
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Body == nil {
			continue
		}
		var firstCharge token.Pos
		var gateAfter, gives, runsSpec bool
		var gatePos token.Pos
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.CallExpr:
				name := ""
				switch fn := n.Fun.(type) {
				case *ast.Ident:
					name = fn.Name
				case *ast.SelectorExpr:
					name = fn.Sel.Name
					if x, ok := fn.X.(*ast.Ident); ok && x.Name == "proof" && name == "Run" {
						runsSpec = true
					}
				}
				if refundCharges[name] && (firstCharge == 0 || n.Pos() < firstCharge) {
					firstCharge = n.Pos()
				}
				if refundGives[name] {
					gives = true
				}
			}
			return true
		})
		if firstCharge == 0 || runsSpec || gives {
			continue
		}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if c, ok := n.(*ast.CallExpr); ok && gateCall(c, gates) && c.Pos() > firstCharge && !gateAfter {
				gateAfter, gatePos = true, c.Pos()
			}
			return true
		})
		if gateAfter {
			out = append(out, path+": "+fd.Name.Name+" charges a budget and then takes a slot of a gate, and never gives the charge back when the gate is full (call Refund when proof.Busy(err), or run it as a proof.Spec)")
			_ = gatePos
		}
	}
	return out
}

func TestAChargeBeforeAGateIsGivenBackWhenTheGateIsFull(t *testing.T) {
	_, files := parseRepo(t)
	byPath := map[string]*ast.File{}
	for _, f := range files {
		byPath[f.path] = f.ast
	}
	gates := gateNames(byPath)
	if !gates["verifyStored"] {
		t.Error("verifyStored is not a gate by closure: the closure is not following wrappers, so the rule is as blind as it was")
	}
	var all []string
	for _, f := range files {
		all = append(all, refundProblems(f.path, f.ast, gates)...)
	}
	sort.Strings(all)
	for _, p := range all {
		t.Error(p)
	}
}

func TestGiveBackLintCanFail(t *testing.T) {
	cases := map[string]struct {
		src  string
		want int
	}{
		"reauth as it was": {`package x
func (s *S) reauth() error {
	c, err := s.throttle.ChargeProof(ctx, a, b)
	ok, err := s.hasher.Verify(ctx, pw, stored)
	return err
}`, 1},
		"a charge then a preparePassword": {`package x
func (s *S) f() error { s.throttle.Charge(ctx, a, b); _, err := s.preparePassword(ctx); return err }`, 1},
		"with a refund on busy": {`package x
func (s *S) f() error {
	s.throttle.Charge(ctx, a, b)
	ok, err := s.hasher.Verify(ctx, pw, stored)
	if proof.Busy(err) { s.throttle.Refund(ctx, a, b) }
	return err
}`, 0},
		"the hash comes first": {`package x
func (s *S) f() error { s.preparePassword(ctx); s.throttle.Charge(ctx, a, b); return nil }`, 0},
		"a Spec is judged by its Spec": {`package x
func (s *S) f() error { s.throttle.Charge(ctx, a, b); s.hasher.Hash(ctx, p); proof.Run(ctx, spec); return nil }`, 0},
		"no gate": {`package x
func (s *S) f() error { s.throttle.Charge(ctx, a, b); return nil }`, 0},
		"a wrapper of the hasher is a gate": {`package x
func (s *S) verifyStored() error { _, err := s.hasher.Verify(ctx, pw, stored); return err }
func (s *S) reauth() error {
	s.throttle.ChargeProof(ctx, a, b)
	return s.verifyStored()
}`, 1},
		"a wrapper of a wrapper is a gate": {`package x
func (s *S) inner() error { return s.preparePassword(ctx) }
func (s *S) outer() error { return s.inner() }
func (s *S) f() error { s.throttle.Charge(ctx, a, b); return s.outer() }`, 1},
		"a wrapper with the refund": {`package x
func (s *S) verifyStored() error { _, err := s.hasher.Verify(ctx, pw, stored); return err }
func (s *S) reauth() error {
	s.throttle.ChargeProof(ctx, a, b)
	err := s.verifyStored()
	if proof.Busy(err) { s.throttle.Refund(ctx, a, b) }
	return err
}`, 0},
	}
	for name, c := range cases {
		f, err := parser.ParseFile(token.NewFileSet(), "internal/api/x.go", c.src, 0)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		gates := gateNames(map[string]*ast.File{"internal/api/x.go": f})
		if got := len(refundProblems("internal/api/x.go", f, gates)); got != c.want {
			t.Errorf("%s: %d findings, want %d", name, got, c.want)
		}
	}
}
