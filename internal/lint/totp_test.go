package lint_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const totpImportSuffix = "/internal/auth/totp"

// totpCheckers are the only functions that may call totp.Check (review round 6, primitives-r6-3 and
// -6; by function since round 17, primitives-r17-10). Each of them takes its guard from
// throttle.Counted, which needs the throttle.Charged proof that only Service.ChargeProof makes, so a
// code is never checked without the attempt having been counted first. A site is "file::Func" or
// "file::Type.Method": the enclosing declaration, not the file, because a file list let any new
// function of routes_totp.go (which holds every TOTP and recovery handler) call a verifier with no
// charge. A function literal belongs to the declaration it is written in; a use outside every
// function (a package-level variable) has no site and is refused. A new route that needs a code goes
// through one of these functions or adds itself here, in a diff a reviewer reads.
func totpCheckers() map[string]bool {
	return map[string]bool{
		"internal/adminapi/helpers.go::Server.checkTOTPUnder": true,
		"internal/api/routes_totp.go::Server.checkTOTP":       true,
	}
}

// totpOpen are the members of internal/auth/totp that a file outside it may use freely: the ones
// that verify nothing (the sealing contexts, the seed maker and its two renderings, the constants,
// the errors and the interface a guard implements). Everything else a file reaches in the package is
// judged by totpGated, and a member in neither list is refused.
//
// The rule is an allow list over the package's whole exported surface (round 16, primitives-r16-3),
// where the rule of rounds 1 to 12 was four forbidden spellings (Check, CheckAt, Generate,
// Plausible): an exported verifier added tomorrow under another name (Match, Verify) was in neither
// block list and reached a handler with no throttle charge and no step spent. Now the same function
// is refused by the caller rule because nobody named it here, and TestTOTPExportsAreTheReviewedSet
// refuses the package that grows a member nobody classified.
func totpOpen() map[string]bool {
	return map[string]bool{
		"UserAAD": true, "AdminAAD": true, "NewSecret": true, "Base32": true, "URI": true,
		"Digits": true, "PeriodSecs": true, "SecretSize": true, "Window": true,
		"ErrInvalid": true, "ErrStepReused": true, "ErrTooMany": true, "TooManyError": true, "Guard": true,
	}
}

// totpGated are the members that verify or look at a code, with the functions that may use each:
// Check in the two functions that build a throttle.Counted guard, Plausible in peekSecondFactor.
// CheckAt takes the time from the caller, so a stale or chosen time would get past the machine-clock
// lint; nothing in production calls it (Check passes the application clock), so it is test only and in
// neither list until a reviewed caller needs it (primitives-r17-10).
func totpGated() map[string]map[string]bool {
	return map[string]map[string]bool{
		"Check": totpCheckers(), "Plausible": plausibleCallers(),
	}
}

// totpUse is one use of a member of the totp package by a file outside it: the member, the
// "file::Func" site that holds it ("" outside every function) and the local name it was reached by.
type totpUse struct{ member, site, local string }

// totpSite names the declaration that encloses a node: "file::Func", or "file::Type.Method".
func totpSite(file string, d *ast.FuncDecl) string {
	if d.Recv != nil && len(d.Recv.List) == 1 {
		return file + "::" + receiverTypeName(d.Recv.List[0].Type) + "." + d.Name.Name
	}
	return file + "::" + d.Name.Name
}

// totpViolations is the RFC 6238 rule of spec 6.3 for one non-test file in dir: totp.Check is the
// only way to verify a code, because it throttles first and spends the matched step after. A file
// outside internal/auth/totp may use a member of the package only if it is in totpOpen, or in
// totpGated and the file is one that entry names; anything else (the code generator, which is
// exported for tests only, and any verifier a later change adds) fails closed. A dot import is
// refused, because under it a member is a bare identifier that the package's name no longer
// leads to. What an HMAC, or an HOTP built on SHA-1, or somebody else's code library would be
// imported as is judged by importViolations against the allow list internal/lint/imports.yaml
// (round 11, primitives-r11-2 and -3), not here.
//
// The import is followed by its path, not by the name "totp", so an alias does not get past it
// (review round 1, primitives-r1-6 and -13). A selector is judged whatever surrounds it (a call, a
// method value, an assignment to a variable, an argument), so a function value made from a member
// is judged where it is made.
func totpViolations(dir, name string, f *ast.File) []string {
	var out []string
	inTOTP := dir == "internal/auth/totp"
	// Every name the file gives the package is judged (localNames, round 18, primitives-r18-6 and -10):
	// the loop kept the last import's name, so a second import under another name hid the selectors
	// written through the first from the rule.
	names := localNamesWhere(f, func(p string) bool { return strings.HasSuffix(p, totpImportSuffix) })
	if inTOTP || len(names) == 0 {
		return out
	}
	if hasDot(names) {
		return append(out, name+" dot-imports internal/auth/totp; use its members by the package name so each one is judged")
	}
	open, gated := totpOpen(), totpGated()
	for _, local := range usableNames(names) {
		for _, u := range totpUses(name, f, local) {
			switch sites, isGated := gated[u.member]; {
			case open[u.member]:
			case isGated && sites[u.site]:
			case isGated:
				out = append(out, name+" uses "+u.local+"."+u.member+" in "+u.site+", outside "+strings.Join(sortedKeys(sites), ", ")+"; a code is verified only after the attempt was counted (spec 6.3)")
			default:
				out = append(out, name+" uses "+u.local+"."+u.member+", which is neither open nor gated in internal/lint totpOpen and totpGated; verify codes with totp.Check")
			}
		}
	}
	return out
}

// totpUses lists every selector of the totp package in f, each with the declaration that encloses it.
// Every declaration of the file is walked, so a use in a method, a function, a closure or a
// package-level initialiser is found; the last has no site.
func totpUses(name string, f *ast.File, local string) []totpUse {
	var out []totpUse
	walk := func(site string, n ast.Node) {
		ast.Inspect(n, func(n ast.Node) bool {
			x, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if id, ok := x.X.(*ast.Ident); ok && id.Name == local {
				out = append(out, totpUse{member: x.Sel.Name, site: site, local: local})
			}
			return true
		})
	}
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok {
			walk(totpSite(name, fd), fd)
			continue
		}
		walk("", d)
	}
	return out
}

// totpStaleSites lists the allowed (member, site) pairs that no file uses any more.
func totpStaleSites(gated map[string]map[string]bool, seen map[string]bool) []string {
	var out []string
	for member, sites := range gated {
		for site := range sites {
			if !seen[member+" "+site] {
				out = append(out, site+" is allowed to use totp."+member+" and does not: the function was renamed or the call removed; update internal/lint totpGated")
			}
		}
	}
	sort.Strings(out)
	return out
}

// TestTOTPStaleSiteCheckCanFail plants an allowed site nobody uses (a renamed function) and an
// allowed site that is used.
func TestTOTPStaleSiteCheckCanFail(t *testing.T) {
	gated := map[string]map[string]bool{"Check": {"a.go::F": true, "a.go::G": true}}
	if got := totpStaleSites(gated, map[string]bool{"Check a.go::F": true, "Check a.go::G": true}); len(got) != 0 {
		t.Errorf("every site used: %v", got)
	}
	if got := totpStaleSites(gated, map[string]bool{"Check a.go::F": true}); len(got) != 1 || !strings.Contains(got[0], "a.go::G") {
		t.Errorf("a site nobody uses: %v", got)
	}
	// The real lists: every site names a declaration of the form file::Func or file::Type.Method.
	for member, sites := range totpGated() {
		for site := range sites {
			if file, fn, ok := strings.Cut(site, "::"); !ok || !strings.HasSuffix(file, ".go") || fn == "" {
				t.Errorf("totp.%s: the site %q is not file::Func", member, site)
			}
		}
	}
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
	// Every site on the lists must still use its member, or the allow list protects nothing: a
	// renamed function would leave an entry that lets nobody in and a new name that is refused,
	// and a deleted call would leave an entry that lets a later call in unseen.
	seen := map[string]bool{}
	for _, f := range files {
		if f.test {
			continue
		}
		name := filepath.ToSlash(f.path)
		local := ""
		for _, imp := range f.ast.Imports {
			if p, _ := strconv.Unquote(imp.Path.Value); strings.HasSuffix(p, totpImportSuffix) && imp.Name == nil {
				local = path.Base(p)
			}
		}
		if local == "" || filepath.ToSlash(filepath.Dir(f.path)) == "internal/auth/totp" {
			continue
		}
		for _, u := range totpUses(name, f.ast, local) {
			seen[u.member+" "+u.site] = true
		}
	}
	for _, p := range totpStaleSites(totpGated(), seen) {
		t.Error(p)
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
		// Round 18, primitives-r18-6 and -10: one path under two names, every name judged.
		"two aliases of the package": {"internal/api", `package x
import a ` + mod + `
import b ` + mod + `
func f() { _ = a.Generate(nil, time.Now()) }
func g() { _ = b.Plausible(nil, nil) }`, 2},
		"the name and an alias": {"internal/api", `package x
import ` + mod + `
import t2 ` + mod + `
func f() { _ = t2.Generate(nil, time.Now()) }
func g() { _ = totp.Check(nil, nil, nil, nil) }`, 2},
		"a blank import beside the name": {"internal/api", `package x
import ` + mod + `
import _ ` + mod + `
func f() { _ = totp.Generate(nil, time.Now()) }`, 1},
		"plausible in peekSecondFactor": {"internal/api", `package x
import ` + mod + `
func (s *Server) peekSecondFactor() { _ = totp.Plausible(nil, nil) }`, 0},
		"plausible in a closure of peekSecondFactor": {"internal/api", `package x
import ` + mod + `
func (s *Server) peekSecondFactor() { f := func() { _ = totp.Plausible(nil, nil) }; f() }`, 0},
		// Round 17, primitives-r17-10: the allow list is a function, not a file, so a new function in
		// the file that holds every TOTP handler is refused.
		"plausible in another function of the same file": {"internal/api", `package x
import ` + mod + `
func (s *Server) preCheck() { _ = totp.Plausible(nil, nil) }`, 1},
		"plausible in a function of the same name in another type": {"internal/api", `package x
import ` + mod + `
func (s *Other) peekSecondFactor() { _ = totp.Plausible(nil, nil) }`, 1},
		"plausible in a package-level variable of the same file": {"internal/api", `package x
import ` + mod + `
var look = totp.Plausible`, 1},
		"plausible in another file of the api": {"internal/api", `package x
import ` + mod + `
func f() { _ = totp.Plausible(nil, nil) }`, 1},
		"plausible elsewhere": {"internal/adminapi", `package x
import ` + mod + `
func f() { _ = totp.Plausible(nil, nil) }`, 1},
		"Check in the function that builds the guard": {"internal/api", `package x
import ` + mod + `
func (s *Server) checkTOTP() { _ = totp.Check(nil, nil, nil, nil) }`, 0},
		"Check in another function of the same file": {"internal/api", `package x
import ` + mod + `
func (s *Server) checkRecovery() { _ = totp.Check(nil, nil, nil, nil) }`, 1},
		"Check in the admin checker": {"internal/adminapi", `package x
import ` + mod + `
func (s *Server) checkTOTPUnder() { _ = totp.Check(nil, nil, nil, nil) }`, 0},
		"Check in another function of the admin file": {"internal/adminapi", `package x
import ` + mod + `
func (s *Server) other() { _ = totp.Check(nil, nil, nil, nil) }`, 1},
		"CheckAt in the function that checks": {"internal/api", `package x
import ` + mod + `
func (s *Server) checkTOTP() { _ = totp.CheckAt(nil, nil, nil, nil, time.Unix(0, 0)) }`, 1},
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
func f() { _ = Plausible(nil, nil) }`, 1},
		// Round 16, primitives-r16-3: a verifier added later under another name is judged by the
		// rule, not by a list of the names somebody thought of.
		"a new exported verifier called in a handler": {"internal/api", `package x
import ` + mod + `
func f() { _, _ = totp.Match(nil, nil, time.Now()) }`, 1},
		"a new verifier as a method value": {"internal/api", `package x
import ` + mod + `
var verify = totp.Verify`, 1},
		"a new verifier behind an alias import": {"internal/adminapi", `package x
import t6238 ` + mod + `
func f() { g := t6238.Verify; _ = g }`, 1},
		"a new verifier passed as an argument": {"internal/api", `package x
import ` + mod + `
func f() { use(totp.Match) }`, 1},
		"a new verifier in a file of the api": {"internal/api", `package x
import ` + mod + `
func f() { _ = totp.Match }`, 1},
		"the open members": {"internal/api", `package x
import ` + mod + `
func f() { _ = totp.UserAAD; _ = totp.NewSecret; _ = totp.ErrInvalid; var _ totp.Guard; _ = totp.SecretSize }`, 0},
		"an unrelated package that shares a member name": {"internal/api", `package x
import "other/verifier"
func f() { _ = verifier.Match }`, 0},
		"inside the package": {"internal/auth/totp", `package totp
func f() { _ = Generate(nil, time.Now()) }`, 0},
	} {
		f, err := parser.ParseFile(token.NewFileSet(), "x.go", tc.src, 0)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		file := "x.go"
		switch {
		case strings.Contains(name, "admin"):
			file = "internal/adminapi/helpers.go"
		case strings.Contains(name, "peekSecondFactor"), strings.Contains(name, "same file"), strings.Contains(name, "Check in the function"), strings.Contains(name, "function that checks"):
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

// totpExportSurface lists every exported member of package totp: its top-level functions, types,
// variables and constants, and the exported methods of its types as Type.Method. It reads the
// declarations of the non-test files, so a member added tomorrow is in the result without a line here.
func totpExportSurface(files []*ast.File) map[string]bool {
	out := map[string]bool{}
	for _, f := range files {
		for _, d := range f.Decls {
			switch d := d.(type) {
			case *ast.FuncDecl:
				if !d.Name.IsExported() {
					continue
				}
				if d.Recv != nil && len(d.Recv.List) == 1 {
					if tn := receiverTypeName(d.Recv.List[0].Type); ast.IsExported(tn) {
						out[tn+"."+d.Name.Name] = true
					}
					continue
				}
				out[d.Name.Name] = true
			case *ast.GenDecl:
				for _, s := range d.Specs {
					switch s := s.(type) {
					case *ast.TypeSpec:
						if s.Name.IsExported() {
							out[s.Name.Name] = true
						}
					case *ast.ValueSpec:
						for _, n := range s.Names {
							if n.IsExported() {
								out[n.Name] = true
							}
						}
					}
				}
			}
		}
	}
	return out
}

// totpReviewedSurface is every exported member of package totp with the reason it is safe to be
// exported. A member that verifies a code is in totpGated (Check, CheckAt, Plausible) and a member
// that makes a code (Generate) is exported for the tests of other packages and is in neither
// totpOpen nor totpGated, so a non-test file that uses it fails totpViolations. The methods are
// the error text and matching of TooManyError. Adding a member to the package fails the test below
// until it is classified here and, if it is open, in totpOpen.
func totpReviewedSurface() map[string]string {
	return map[string]string{
		"Check": "gated: verify a code after the guard counted the attempt", "CheckAt": "test only: Check at a time the caller chooses; no production caller, and the machine-clock lint cannot see the time it is given",
		"Plausible": "gated: a look that spends no step and verifies nothing", "Generate": "test only: makes a code, refused in non-test files outside the package",
		"NewSecret": "open: draws a seed", "Base32": "open: renders a seed", "URI": "open: renders a seed",
		"UserAAD": "open: sealing context", "AdminAAD": "open: sealing context",
		"Guard": "open: the interface a guard implements", "TooManyError": "open: the refusal of a spent window",
		"TooManyError.Error": "open", "TooManyError.Is": "open",
		"ErrInvalid": "open", "ErrStepReused": "open", "ErrTooMany": "open",
		"Digits": "open", "PeriodSecs": "open", "SecretSize": "open", "Window": "open",
	}
}

// TestTOTPExportsAreTheReviewedSet is the other half of the RFC 6238 rule (primitives-r16-3). The
// caller rule (totpViolations) is an allow list, so an exported verifier nobody classified is
// refused wherever it is used; this test is what makes the package's own growth visible: the
// exported surface read from the declarations must equal the reviewed list, member for member, and
// every open or gated member must be one the caller rule knows (and every one it knows must exist).
func TestTOTPExportsAreTheReviewedSet(t *testing.T) {
	_, files := parseRepo(t)
	var asts []*ast.File
	for _, f := range files {
		if !f.test && filepath.ToSlash(filepath.Dir(f.path)) == "internal/auth/totp" {
			asts = append(asts, f.ast)
		}
	}
	if len(asts) == 0 {
		t.Fatal("no file of internal/auth/totp was read")
	}
	if problems := totpSurfaceProblems(totpExportSurface(asts), totpReviewedSurface(), totpOpen(), totpGated()); len(problems) > 0 {
		for _, p := range problems {
			t.Error(p)
		}
	}
}

// totpSurfaceProblems compares the declared surface with the reviewed list and the caller rule's two
// lists, both ways.
func totpSurfaceProblems(declared map[string]bool, reviewed map[string]string, open map[string]bool, gated map[string]map[string]bool) []string {
	var out []string
	for m := range declared {
		if _, ok := reviewed[m]; !ok {
			out = append(out, "internal/auth/totp exports "+m+", which is not in totpReviewedSurface: classify it (open, gated or test only) in a reviewed change")
		}
	}
	for m := range reviewed {
		if !declared[m] {
			out = append(out, "totpReviewedSurface lists "+m+", which the package no longer exports")
		}
	}
	for m := range open {
		if !declared[m] {
			out = append(out, "totpOpen lists "+m+", which the package does not export")
		}
	}
	for m := range gated {
		if !declared[m] {
			out = append(out, "totpGated lists "+m+", which the package does not export")
		}
	}
	for m, why := range reviewed {
		if strings.Contains(m, ".") {
			continue
		}
		_, isGated := gated[m]
		switch {
		case strings.HasPrefix(why, "open") && !open[m]:
			out = append(out, m+" is reviewed as open and is not in totpOpen")
		case strings.HasPrefix(why, "gated") && !isGated:
			out = append(out, m+" is reviewed as gated and is not in totpGated")
		case strings.HasPrefix(why, "test only") && (open[m] || isGated):
			out = append(out, m+" is reviewed as test only and the caller rule lets non-test code use it")
		}
	}
	sort.Strings(out)
	return out
}

// TestTOTPSurfaceLintCanFail plants the shapes of the finding: a verifier added under a new name, a
// method, a variable, a constant and a type, a reviewed member that disappeared, and a member that
// the caller rule opens although it was reviewed as test only.
func TestTOTPSurfaceLintCanFail(t *testing.T) {
	parse := func(src string) []*ast.File {
		f, err := parser.ParseFile(token.NewFileSet(), "x.go", "package totp\n"+src, 0)
		if err != nil {
			t.Fatal(err)
		}
		return []*ast.File{f}
	}
	reviewed := map[string]string{"Check": "gated: x", "Generate": "test only: x", "NewSecret": "open: x", "T": "open", "T.M": "open"}
	open := map[string]bool{"NewSecret": true, "T": true}
	gated := map[string]map[string]bool{"Check": {"a.go": true}}
	base := "func Check() {}\nfunc Generate() {}\nfunc NewSecret() {}\ntype T struct{}\nfunc (T) M() {}\n"
	for name, tc := range map[string]struct {
		src  string
		want int
	}{
		"the reviewed package":      {base, 0},
		"a new verifier":            {base + "func Match() {}\n", 1},
		"a new verifier method":     {base + "func (T) Verify() {}\n", 1},
		"a new variable":            {base + "var Matcher = Check\n", 1},
		"a new constant":            {base + "const Max = 3\n", 1},
		"a new type":                {base + "type Verifier interface{}\n", 1},
		"an unexported helper":      {base + "func match() {}\n", 0},
		"an unexported method":      {base + "func (T) verify() {}\n", 0},
		"a reviewed member removed": {"func Check() {}\nfunc Generate() {}\nfunc NewSecret() {}\ntype T struct{}\n", 1},
	} {
		got := totpSurfaceProblems(totpExportSurface(parse(tc.src)), reviewed, open, gated)
		if len(got) != tc.want {
			t.Errorf("%s: %d problems %v, want %d", name, len(got), got, tc.want)
		}
	}
	// The caller rule and the reviewed list disagree.
	got := totpSurfaceProblems(totpExportSurface(parse(base)), reviewed, map[string]bool{"NewSecret": true, "T": true, "Generate": true}, gated)
	if len(got) != 1 {
		t.Errorf("Generate opened to non-test code: %d problems %v, want 1", len(got), got)
	}
}

// TestTOTPSurfaceCrossChecksCanFail plants each disagreement between the reviewed list, the open
// list and the gated list that totpSurfaceProblems judges, one at a time, and requires its own
// message, so a clause deleted from the function is noticed even where another clause would still
// report something (round 16 fix gate, primitives-r16-19).
func TestTOTPSurfaceCrossChecksCanFail(t *testing.T) {
	declared := map[string]bool{"Check": true, "Generate": true, "NewSecret": true}
	reviewed := func() map[string]string {
		return map[string]string{"Check": "gated: x", "Generate": "test only: x", "NewSecret": "open: x"}
	}
	open := func() map[string]bool { return map[string]bool{"NewSecret": true} }
	gated := func() map[string]map[string]bool { return map[string]map[string]bool{"Check": {"a.go": true}} }
	if got := totpSurfaceProblems(declared, reviewed(), open(), gated()); len(got) != 0 {
		t.Fatalf("the consistent lists: %v", got)
	}
	type in struct {
		declared map[string]bool
		reviewed map[string]string
		open     map[string]bool
		gated    map[string]map[string]bool
	}
	mk := func(mod func(*in)) in {
		x := in{declared, reviewed(), open(), gated()}
		mod(&x)
		return x
	}
	for name, c := range map[string]struct {
		x    in
		want string
	}{
		"an exported member nobody reviewed": {mk(func(x *in) {
			x.declared = map[string]bool{"Check": true, "Generate": true, "NewSecret": true, "Match": true}
		}), "which is not in totpReviewedSurface"},
		"a reviewed member that is gone":           {mk(func(x *in) { x.reviewed["Old"] = "removed" }), "which the package no longer exports"},
		"an open entry that is not exported":       {mk(func(x *in) { x.open["Ghost"] = true }), "totpOpen lists Ghost"},
		"a gated entry that is not exported":       {mk(func(x *in) { x.gated["Ghost"] = map[string]bool{"a.go": true} }), "totpGated lists Ghost"},
		"reviewed open but not in the open list":   {mk(func(x *in) { delete(x.open, "NewSecret") }), "reviewed as open and is not in totpOpen"},
		"reviewed gated but not in the gated list": {mk(func(x *in) { delete(x.gated, "Check") }), "reviewed as gated and is not in totpGated"},
		"reviewed test only but opened":            {mk(func(x *in) { x.open["Generate"] = true }), "reviewed as test only and the caller rule lets"},
	} {
		got := totpSurfaceProblems(c.x.declared, c.x.reviewed, c.x.open, c.x.gated)
		if len(got) != 1 || !strings.Contains(got[0], c.want) {
			t.Errorf("%s: %v, want one problem containing %q", name, got, c.want)
		}
	}
}
