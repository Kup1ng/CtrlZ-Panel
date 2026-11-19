package lint_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const totpImportSuffix = "/internal/auth/totp"

// totpCheckers are the only non-test files that may call totp.Check or totp.CheckAt (review round
// 6, primitives-r6-3 and -6). Each of them takes its guard from throttle.Counted, which needs the
// throttle.Charged proof that only Service.ChargeProof makes, so a code is never checked without
// the attempt having been counted first. A new route that needs a code goes through one of these
// two functions or adds itself here, in a diff a reviewer reads.
func totpCheckers() map[string]bool {
	return map[string]bool{
		"internal/adminapi/helpers.go": true,
		"internal/api/routes_totp.go":  true,
	}
}

// totpViolations is the RFC 6238 rule of spec 6.3 for one non-test file in dir:
// totp.Check is the only way to verify a code, because it throttles first and
// spends the matched step after. The code generator is exported for tests only.
// What an HMAC, or an HOTP built on SHA-1, or somebody else's code library
// would be imported as is judged by importViolations against the allow list
// internal/lint/imports.yaml (round 11, primitives-r11-2 and -3), not here: a
// name list in this function failed open for every name nobody had thought of.
//
// The import is followed by its path, not by the name "totp", so an alias or a
// dot import does not get past it (review round 1, primitives-r1-6 and -13).
func totpViolations(dir, name string, f *ast.File) []string {
	var out []string
	inTOTP := dir == "internal/auth/totp"
	local, dot := "", false
	for _, imp := range f.Imports {
		p, _ := strconv.Unquote(imp.Path.Value)
		switch {
		case strings.HasSuffix(p, totpImportSuffix):
			switch {
			case imp.Name == nil:
				local = path.Base(p)
			case imp.Name.Name == ".":
				dot = true
			case imp.Name.Name != "_":
				local = imp.Name.Name
			}
		}
	}
	if inTOTP || (local == "" && !dot) {
		return out
	}
	allowedChecker := totpCheckers()[name]
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.SelectorExpr:
			if id, ok := x.X.(*ast.Ident); ok && local != "" && id.Name == local && (x.Sel.Name == "Check" || x.Sel.Name == "CheckAt") && !allowedChecker {
				out = append(out, name+" calls "+id.Name+"."+x.Sel.Name+" outside the two files that build a throttle.Counted guard ("+strings.Join(sortedKeys(totpCheckers()), ", ")+")")
			}
			if id, ok := x.X.(*ast.Ident); ok && local != "" && id.Name == local && strings.EqualFold(x.Sel.Name, "generate") {
				out = append(out, name+" calls "+id.Name+"."+x.Sel.Name+" outside internal/auth/totp; verify codes with totp.Check")
			}
			// Plausible looks at a code and spends nothing, so it is no verification; the one route that
			// needs a look before heavy work is peekSecondFactor, and only the file that holds it may call it
			// (round 12, primitives-r12-1): a directory is wide enough for any new route to look first.
			if id, ok := x.X.(*ast.Ident); ok && local != "" && id.Name == local && strings.EqualFold(x.Sel.Name, "plausible") && !plausibleCallers()[name] {
				out = append(out, name+" calls "+id.Name+"."+x.Sel.Name+" outside the file of peekSecondFactor ("+strings.Join(sortedKeys(plausibleCallers()), ", ")+"); it spends no step and is no verification")
			}
		case *ast.Ident:
			// Under a dot import the generator is a bare identifier. A local
			// function of the same name in a file that dot-imports totp would not
			// compile, so there are no false hits.
			if dot && strings.EqualFold(x.Name, "generate") {
				out = append(out, name+" uses a dot-imported Generate from internal/auth/totp; verify codes with totp.Check")
			}
			if dot && (x.Name == "Check" || x.Name == "CheckAt") && !allowedChecker {
				out = append(out, name+" uses a dot-imported "+x.Name+" outside the two files that build a throttle.Counted guard")
			}
			if dot && strings.EqualFold(x.Name, "plausible") && !plausibleCallers()[name] {
				out = append(out, name+" uses a dot-imported Plausible outside the file of peekSecondFactor ("+strings.Join(sortedKeys(plausibleCallers()), ", ")+"); it spends no step and is no verification")
			}
		}
		return true
	})
	return out
}

func receiverTypeName(e ast.Expr) string {
	if st, ok := e.(*ast.StarExpr); ok {
		e = st.X
	}
	if ix, ok := e.(*ast.IndexExpr); ok {
		e = ix.X
	}
	if id, ok := e.(*ast.Ident); ok {
		return id.Name
	}
	return ""
}

func TestRFC6238StaysInsideTheTOTPPackage(t *testing.T) {
	_, files := parseRepo(t)
	// The one guard: types of non-test files, package by package.
	byDir := map[string]map[string]*ast.File{}
	for _, f := range files {
		if f.test {
			continue
		}
		d := filepath.ToSlash(filepath.Dir(f.path))
		if byDir[d] == nil {
			byDir[d] = map[string]*ast.File{}
		}
		byDir[d][filepath.ToSlash(f.path)] = f.ast
	}
	// shared/ is read in full (round 13, primitives-r13-3): parseRepo leaves it out, but a type
	// declared there with Hit, Spend and Reset reaches totp.Check as well as a Panel one.
	sharedFiles := parseSharedTreeMode(t, 0)
	if len(sharedFiles) < 10 {
		t.Fatalf("read %d files of shared/; the layout changed", len(sharedFiles))
	}
	for _, f := range sharedFiles {
		d := filepath.ToSlash(filepath.Dir(f.path))
		if byDir[d] == nil {
			byDir[d] = map[string]*ast.File{}
		}
		byDir[d][f.path] = f.ast
	}
	for _, v := range guardImplementorsOf(byDir) {
		t.Error(v)
	}
	// The callers must exist, or the allow list protects nothing.
	for name := range totpCheckers() {
		found := false
		for _, fs := range byDir {
			if _, ok := fs[name]; ok {
				found = true
			}
		}
		if !found {
			t.Errorf("%s is on the list of totp.Check callers and does not exist", name)
		}
	}
	for _, f := range files {
		if f.test {
			continue // test files may use both
		}
		for _, v := range totpViolations(filepath.ToSlash(filepath.Dir(f.path)), filepath.ToSlash(f.path), f.ast) {
			t.Error(v)
		}
	}
}

// TestRFC6238RuleFires checks the checker: a rule that never fires, or that an
// alias walks around, would pass for ever.
func TestRFC6238RuleFires(t *testing.T) {
	const mod = `"github.com/Kup1ng/CtrlZ-Panel/internal/auth/totp"`
	for name, tc := range map[string]struct {
		dir, src string
		want     int
	}{
		"plain call": {"internal/api", `package x
import "github.com/Kup1ng/CtrlZ-Panel/internal/auth/totp"
func f() { _ = totp.Generate(nil, time.Now()) }`, 1},
		"lower case": {"internal/api", `package x
import ` + mod + `
func f() { _ = totp.generate }`, 1},
		"aliased import": {"internal/api", `package x
import otp6238 ` + mod + `
func f() { _ = otp6238.Generate(nil, time.Now()) }`, 1},
		"dot import": {"internal/api", `package x
import . ` + mod + `
func f() { _ = Generate(nil, time.Now()) }`, 1},
		"plausible in the file of peekSecondFactor": {"internal/api", `package x
import ` + mod + `
func f() { _ = totp.Plausible(nil, nil) }`, 0},
		"plausible in another file of the api": {"internal/api", `package x
import ` + mod + `
func f() { _ = totp.Plausible(nil, nil) }`, 1},
		"plausible elsewhere": {"internal/adminapi", `package x
import ` + mod + `
func f() { _ = totp.Plausible(nil, nil) }`, 1},
		"Check in a file that builds the guard": {"internal/api", `package x
import ` + mod + `
func f() { _ = totp.Check(nil, nil, nil, nil) }`, 0},
		"Check in any other file": {"internal/api", `package x
import ` + mod + `
func f() { _ = totp.Check(nil, nil, nil, nil) }`, 1},
		"CheckAt in any other file": {"internal/adminapi", `package x
import ` + mod + `
func f() { _ = totp.CheckAt(nil, nil, nil, nil, time.Now()) }`, 1},
		"alias of Check elsewhere": {"internal/api", `package x
import t ` + mod + `
func f() { _ = t.Check(nil, nil, nil, nil) }`, 1},
		"dot import of Check elsewhere": {"internal/adminapi", `package x
import . ` + mod + `
func f() { _ = Check(nil, nil, nil, nil) }`, 1},
		"dot import of Plausible elsewhere": {"internal/adminapi", `package x
import . ` + mod + `
func f() { _ = Plausible(nil, nil) }`, 1},
		"dot import of Plausible in the file of peekSecondFactor": {"internal/api", `package x
import . ` + mod + `
func f() { _ = Plausible(nil, nil) }`, 0},
		"inside the package": {"internal/auth/totp", `package totp
func f() { _ = Generate(nil, time.Now()) }`, 0},
	} {
		f, err := parser.ParseFile(token.NewFileSet(), "x.go", tc.src, 0)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		file := "x.go"
		if name == "Check in a file that builds the guard" || strings.HasSuffix(name, "in the file of peekSecondFactor") {
			file = "internal/api/routes_totp.go"
		}
		if got := totpViolations(tc.dir, file, f); len(got) != tc.want {
			t.Errorf("%s: %d violations %v, want %d", name, len(got), got, tc.want)
		}
	}
}

// TestTOTPGuardLintFires plants the guards the rule is there to stop: a type with its own Hit,
// Spend and Reset, one that embeds the interface to override a single method, and the right one in
// the throttle package.
func TestTOTPGuardLintFires(t *testing.T) {
	const mod = `"github.com/Kup1ng/CtrlZ-Panel/internal/auth/totp"`
	for name, tc := range map[string]struct {
		dir, src string
		want     int
	}{
		"a free guard": {"internal/api", `package x
type freeGuard struct{}
func (freeGuard) Hit() bool { return true }
func (freeGuard) Spend() bool { return true }
func (freeGuard) Reset() {}`, 1},
		"a pointer receiver guard": {"internal/adminapi", `package x
type g struct{}
func (*g) Hit() bool { return true }
func (*g) Spend() bool { return true }
func (*g) Reset() {}`, 1},
		"a guard that embeds the interface": {"internal/api", `package x
import ` + mod + `
type g struct{ totp.Guard }`, 1},
		"an aliased embed": {"internal/api", `package x
import tt ` + mod + `
type g struct{ tt.Guard }`, 1},
		"methods promoted from a local helper": {"internal/api", `package x
type base struct{}
func (base) Spend() bool { return true }
func (base) Reset() {}
type evil struct{ base }
func (evil) Hit() bool { return true }`, 1},
		"methods promoted through a pointer embed": {"internal/api", `package x
type base struct{}
func (*base) Spend() bool { return true }
func (*base) Reset() {}
type evil struct{ *base }
func (evil) Hit() bool { return true }`, 1},
		"two levels of embedding": {"internal/api", `package x
type a struct{}
func (a) Spend() bool { return true }
func (a) Reset() {}
type b struct{ a }
type c struct{ b }
func (c) Hit() bool { return true }`, 1},
		"an alias of totp.Guard embedded": {"internal/api", `package x
import tt ` + mod + `
type G = tt.Guard
type evil struct{ G }`, 1},
		"a defined type of totp.Guard embedded": {"internal/api", `package x
import tt ` + mod + `
type G tt.Guard
type evil struct{ G }`, 1},
		"a local interface embedded": {"internal/api", `package x
type I interface{ Hit() bool; Spend() bool; Reset() }
type evil struct{ I }`, 1},
		"an inline struct that embeds the guard": {"internal/api", `package x
import tt ` + mod + `
func f() any { return struct{ tt.Guard }{} }`, 1},
		"a function-local type that embeds the guard": {"internal/api", `package x
import tt ` + mod + `
func f() { type g struct{ tt.Guard }; _ = g{} }`, 1},
		"a named field is only a holder": {"internal/api", `package x
import tt ` + mod + `
type holder struct{ g tt.Guard }`, 0},
		"an alias of a free guard": {"internal/api", `package x
type free struct{}
func (free) Hit() bool { return true }
func (free) Spend() bool { return true }
func (free) Reset() {}
type A = free
type evil struct{ A }`, 3},
		"two of the three methods are not a guard": {"internal/api", `package x
type c struct{}
func (c) Hit() bool { return true }
func (c) Reset() {}`, 0},
		"the throttle package builds the one guard": {"internal/auth/throttle", `package x
type counted struct{}
func (counted) Hit() bool { return true }
func (counted) Spend() bool { return true }
func (counted) Reset() {}`, 0},
	} {
		f, err := parser.ParseFile(token.NewFileSet(), "x.go", tc.src, 0)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := guardImplementors(tc.dir, map[string]*ast.File{"x.go": f}); len(got) != tc.want {
			t.Errorf("%s: %d findings %v, want %d", name, len(got), got, tc.want)
		}
	}
}

// TestTOTPGuardLintFollowsAnotherPackage plants a helper in one package and an implementer in
// another: the guard methods arrive by promotion across a package boundary, and so does the
// throttle package's own guard type, which a free type must not wrap to override one method.
func TestTOTPGuardLintFollowsAnotherPackage(t *testing.T) {
	parse := func(src string) *ast.File {
		f, err := parser.ParseFile(token.NewFileSet(), "x.go", src, 0)
		if err != nil {
			t.Fatal(err)
		}
		return f
	}
	helper := parse(`package helper
type Base struct{}
func (Base) Spend() bool { return true }
func (Base) Reset() {}`)
	user := parse(`package api
import "` + module + `/internal/helper"
type evil struct{ helper.Base }
func (evil) Hit() bool { return true }`)
	got := guardImplementorsOf(map[string]map[string]*ast.File{
		"internal/helper": {"internal/helper/h.go": helper},
		"internal/api":    {"internal/api/x.go": user},
	})
	if len(got) != 1 {
		t.Errorf("%d findings %v, want 1 (evil); Base alone has no Hit", len(got), got)
	}
	throttle := parse(`package throttle
type Counted struct{}
func (Counted) Hit() bool { return true }
func (Counted) Spend() bool { return true }
func (Counted) Reset() {}`)
	wrap := parse(`package api
import "` + module + `/internal/auth/throttle"
type wrapped struct{ throttle.Counted }
func (wrapped) Hit() bool { return true }`)
	got = guardImplementorsOf(map[string]map[string]*ast.File{
		"internal/auth/throttle": {"internal/auth/throttle/t.go": throttle},
		"internal/api":           {"internal/api/x.go": wrap},
	})
	if len(got) != 1 {
		t.Errorf("%d findings %v, want 1 (wrapped)", len(got), got)
	}
	// A type of the shared module with the three methods, and a Panel struct that embeds one
	// (round 13, primitives-r13-3). The shared type is a guard by itself, so both are found; a
	// shared type with two of the three is not.
	sharedCounter := parse(`package counter
type Counter struct{}
func (Counter) Hit() bool { return true }
func (Counter) Spend() bool { return true }
func (Counter) Reset() {}
type Half struct{}
func (Half) Hit() bool { return true }
func (Half) Reset() {}`)
	embeds := parse(`package api
import "github.com/Kup1ng/CtrlZ-Shared/counter"
type local struct{ counter.Counter }
type holder struct{ c counter.Counter }
type half struct{ counter.Half }`)
	got = guardImplementorsOf(map[string]map[string]*ast.File{
		"shared/counter": {"shared/counter/c.go": sharedCounter},
		"internal/api":   {"internal/api/x.go": embeds},
	})
	if len(got) != 2 {
		t.Errorf("%d findings %v, want 2 (shared Counter, and local that embeds it)", len(got), got)
	}
}
