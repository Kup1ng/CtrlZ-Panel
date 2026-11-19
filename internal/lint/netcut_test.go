package lint_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// The network-cut rule (P1 auth review, rule 6 budget-keying; tenant-r10-3, tenant-r11-4, tenant-r12-1 and -3).
//
// A bucket that counts on the network of a client is declared in the registry (internal/budget) and built by one
// implementation (internal/netpool, internal/throttle, internal/ratelimit). Round 11 enforced that with an AST walk
// that looked for four spellings: a call to netkey.Net, netkey.Wide, netip.PrefixFrom or netip.ParsePrefix. Round 12
// found three ways round that walk, all of one kind: it matched names, not the thing the name stands for. An import
// under another name, a function taken as a value, the method Addr.Prefix, a wrapper that returns the key
// ready-made (httpx.Subject) and net.CIDRMask each cut a network and passed.
//
// The rule is now judged by types, in four parts:
//
//  1. Roots. Every reference (not only a call: a function value, a method value, an alias, a dot import) to a
//     function that cuts an address into a network, or that takes an address apart into bytes to cut it by hand, is
//     a cut. The roots are resolved through go/types, so the spelling of the import does not matter.
//  2. Wrappers. A function in an allowed file that returns a string, a netip.Prefix or a netip.Addr and reaches a
//     root (directly or through another wrapper) hands a network key to its caller, and a reference to it from a
//     file that is not allowed is a cut of the same kind (httpx.Subject is one). The wrappers are found by a fixed
//     point over the allowed files, so a new wrapper needs no entry anywhere.
//  3. Unresolved names fail closed. A selector with the name of a root whose type did not resolve (a third-party
//     package the checker stubs) is reported, because the lint cannot show it is not a cut.
//  4. The allow list is files, each with its reason, and a listed file that no longer cuts is an error, so the list
//     cannot outlive its reason. A key stored in a map, a struct or an array is built by a call, and a call is a
//     reference, so there is no separate rule for where the key goes.
//
// Not covered, and declared: a cut by hand from a string (strings.Split of ip.String()), which no function of the
// roots does. The registry's abuse tests (internal/budget) are the net for what a source lint cannot see.

const netkeyPkg = module + "/internal/netkey"

// netCutRoots are the functions whose use is a cut. The value is the reason, for the failure message.
var netCutRoots = map[string]string{
	netkeyPkg + ".Net":  "the /24 or /64 of an address",
	netkeyPkg + ".Wide": "the IPv6 /48 of an address",

	"net/netip.PrefixFrom":      "makes a prefix of an address",
	"net/netip.ParsePrefix":     "parses a prefix",
	"net/netip.MustParsePrefix": "parses a prefix",
	"(net/netip.Addr).Prefix":   "cuts an address to a prefix",
	"(net/netip.Prefix).Masked": "zeroes the host bits of a prefix",
	"(net/netip.Addr).As4":      "takes an address apart into bytes, to cut it by hand",
	"(net/netip.Addr).As16":     "takes an address apart into bytes, to cut it by hand",
	"(net/netip.Addr).AsSlice":  "takes an address apart into bytes, to cut it by hand",
	"net/netip.AddrFrom4":       "builds an address from bytes that were cut by hand",
	"net/netip.AddrFrom16":      "builds an address from bytes that were cut by hand",
	"net/netip.AddrFromSlice":   "builds an address from bytes that were cut by hand",

	"net.CIDRMask":  "makes a network mask",
	"net.ParseCIDR": "parses a network",
	"(net.IP).Mask": "cuts an address with a mask",
}

// netCutNames are the selector names that, when the type checker could not resolve them (the receiver or the
// package is a stub), still count as a cut. A resolved selector of the same name is judged by netCutRoots instead,
// so phone.Mask is not one.
var netCutNames = map[string]bool{
	"Prefix": true, "Masked": true, "PrefixFrom": true, "ParsePrefix": true, "MustParsePrefix": true,
	"CIDRMask": true, "ParseCIDR": true, "As4": true, "As16": true, "AsSlice": true,
	"AddrFrom4": true, "AddrFrom16": true, "AddrFromSlice": true,
}

// netCutAllowed are the files that may, each with the reason. A listed file that no longer cuts is an error.
var netCutAllowed = map[string]string{
	"internal/netkey/netkey.go":          "the definition of the network of an address",
	"internal/httpx/middleware.go":       "the pipeline derives the network and the /48 once per request, for the rate classes of the registry (Subject), and reads the trusted-proxy prefixes",
	"internal/httpx/pipeline.go":         "charges the rate classes of the registry with the network keys httpx.Subject hands it; it makes no key of its own and keeps no bucket",
	"internal/auth/throttle/throttle.go": "the one choke point of the throttle scopes: Who.part builds the network and /48 key parts the registry names",
	"internal/netpool/netpool.go":        "the one implementation of a registered NetPool",
	"internal/sms/counterkeys.go":        "the daily SMS counters key their network by the same function and are stored counters, bounded by the SMS caps of spec 5.1, not a pool",
}

type netCutResult struct {
	problems []string
	used     map[string]bool // allowed file -> it cut
	seen     int             // non-test files examined
}

func isKeyLike(t types.Type) bool {
	if b, ok := t.Underlying().(*types.Basic); ok && b.Kind() == types.String {
		return true
	}
	n, ok := t.(*types.Named)
	if !ok || n.Obj().Pkg() == nil || n.Obj().Pkg().Path() != "net/netip" {
		return false
	}
	return n.Obj().Name() == "Prefix" || n.Obj().Name() == "Addr"
}

func returnsKey(fn *types.Func) bool {
	sig, ok := fn.Type().(*types.Signature)
	if !ok {
		return false
	}
	for i := 0; i < sig.Results().Len(); i++ {
		if isKeyLike(sig.Results().At(i).Type()) {
			return true
		}
	}
	return false
}

func funcName(fn *types.Func) string { return fn.Origin().FullName() }

// netCutProblems judges every non-test file. allowed is netCutAllowed, a parameter so the can-fail test can pass
// its own paths.
func netCutProblems(fset *token.FileSet, files []file, info *types.Info, allowed map[string]string) netCutResult {
	res := netCutResult{used: map[string]bool{}}

	// Part 2: the wrappers, by a fixed point over the functions declared in allowed files.
	type decl struct {
		fn   *types.Func
		body *ast.BlockStmt
	}
	var decls []decl
	for _, f := range files {
		if f.test {
			continue
		}
		if _, ok := allowed[f.path]; !ok {
			continue
		}
		for _, d := range f.ast.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			if fn, ok := info.Defs[fd.Name].(*types.Func); ok && returnsKey(fn) {
				decls = append(decls, decl{fn, fd.Body})
			}
		}
	}
	wrappers := map[*types.Func]bool{}
	refsCut := func(n ast.Node) bool {
		hit := false
		ast.Inspect(n, func(x ast.Node) bool {
			id, ok := x.(*ast.Ident)
			if !ok || hit {
				return !hit
			}
			if fn, ok := info.Uses[id].(*types.Func); ok {
				if _, root := netCutRoots[funcName(fn)]; root || wrappers[fn.Origin()] {
					hit = true
				}
			}
			return !hit
		})
		return hit
	}
	for changed := true; changed; {
		changed = false
		for _, d := range decls {
			if !wrappers[d.fn.Origin()] && refsCut(d.body) {
				wrappers[d.fn.Origin()] = true
				changed = true
			}
		}
	}

	// Parts 1 and 3: every reference in every file.
	for _, f := range files {
		if f.test {
			continue
		}
		res.seen++
		_, isAllowed := allowed[f.path]
		report := func(pos token.Pos, what string) {
			if isAllowed {
				res.used[f.path] = true
				return
			}
			res.problems = append(res.problems, fmt.Sprintf("%s: %s", fset.Position(pos), what))
		}
		ast.Inspect(f.ast, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.Ident:
				fn, ok := info.Uses[n].(*types.Func)
				if !ok {
					return true
				}
				if why, root := netCutRoots[funcName(fn)]; root {
					report(n.Pos(), "refers to "+funcName(fn)+", which "+why)
				} else if wrappers[fn.Origin()] {
					report(n.Pos(), "refers to "+funcName(fn)+", which returns a network key made by a cut")
				}
			case *ast.SelectorExpr:
				if netCutNames[n.Sel.Name] && info.Uses[n.Sel] == nil && info.Selections[n] == nil {
					report(n.Sel.Pos(), "uses ."+n.Sel.Name+" and the checker could not resolve it, so it may cut a network")
				}
			}
			return true
		})
	}
	sort.Strings(res.problems)
	return res
}

func TestNoCodeKeysAnythingOnTheNetworkOutsideTheRegistry(t *testing.T) {
	fset, files := parseRepo(t)
	info, ok := typeInfoReal(fset, files, "net/netip")
	if !ok {
		t.Fatal("type information unavailable")
	}
	res := netCutProblems(fset, files, info, netCutAllowed)
	for _, p := range res.problems {
		t.Errorf("%s; a bucket keyed on the network is declared in internal/budget (a counter or NetPools) and built by internal/netpool; add a file to netCutAllowed only with a reason that is not a bucket", p)
	}
	var stale []string
	for file := range netCutAllowed {
		if !res.used[file] {
			stale = append(stale, file)
		}
	}
	sort.Strings(stale)
	for _, file := range stale {
		t.Errorf("%s is allowed to cut a network and no longer does", file)
	}
	// A rename of netkey or netip that stopped the lint resolving them would pass for ever.
	if res.seen < 100 || len(res.used) < 4 {
		t.Fatalf("%d files examined and %d allowed files seen cutting; the lint is not resolving the roots", res.seen, len(res.used))
	}
}

// netCutCorpus is the planted program: the real netkey, a stub of httpx that wraps it the way the real one does,
// and one file under test.
func netCutCorpus(t *testing.T, fset *token.FileSet, src string) []file {
	t.Helper()
	root := repoRoot(t)
	real, err := os.ReadFile(filepath.Join(root, "internal", "netkey", "netkey.go"))
	if err != nil {
		t.Fatal(err)
	}
	const httpxStub = `package httpx
import (
	"context"
	"net/netip"
	"github.com/Kup1ng/CtrlZ-Panel/internal/netkey"
)
func ClientIPFrom(ctx context.Context) netip.Addr { return netip.Addr{} }
func Subject(ctx context.Context) (network, wide string) {
	a := ClientIPFrom(ctx)
	network = netkey.Net(a)
	wide, _ = netkey.Wide(a)
	return network, wide
}
`
	parse := func(path, text string) file {
		f, err := parser.ParseFile(fset, path, text, parser.ParseComments)
		if err != nil {
			t.Fatalf("%s: %v\n%s", path, err, text)
		}
		return file{path: path, ast: f}
	}
	return []file{
		parse("internal/netkey/netkey.go", string(real)),
		parse("internal/httpx/middleware.go", httpxStub),
		parse("internal/api/x.go", src),
	}
}

// TestNetworkCutLintCanFail plants each way round the round 11 walk, in a file that is not allowed, and requires
// the lint to report it; the clean programs must pass. Each case names the finding or the shape it stands for.
func TestNetworkCutLintCanFail(t *testing.T) {
	const pre = "package api\nimport (\n\t\"context\"\n\t\"net\"\n\t\"net/netip\"\n\tnk \"github.com/Kup1ng/CtrlZ-Panel/internal/netkey\"\n\t\"github.com/Kup1ng/CtrlZ-Panel/internal/httpx\"\n)\n" +
		"var _ context.Context\nvar _ net.IP\nvar _ netip.Addr\nvar _ = httpx.ClientIPFrom\nvar _ = nk.Net\n"
	// pre holds one reference of its own (nk.Net), counted in every want.
	cases := []struct {
		name string
		src  string // the file body; pre is added unless own is set
		own  bool
		want int
	}{
		{name: "an aliased import of netkey (tenant-r12-1)", src: `func f(a netip.Addr) string { return nk.Net(a) }`, want: 2},
		{name: "netkey.Wide through the alias", src: `func f(a netip.Addr) { w, _ := nk.Wide(a); _ = w }`, want: 2},
		{name: "a function value of PrefixFrom (tenant-r12-1)", src: `func f(a netip.Addr) { g := netip.PrefixFrom; _ = g(a, 64) }`, want: 2},
		{name: "Addr.Prefix (tenant-r12-1, -3)", src: `func f(a netip.Addr) { p, _ := a.Prefix(64); _ = p }`, want: 2},
		{name: "a method value of Addr.Prefix", src: `func f(a netip.Addr) { g := a.Prefix; _, _ = g(24) }`, want: 2},
		{name: "Prefix.Masked (tenant-r12-1)", src: `func f(p netip.Prefix) { _ = p.Masked() }`, want: 2},
		{name: "net.CIDRMask (tenant-r12-1)", src: `func f() { _ = net.CIDRMask(64, 128) }`, want: 2},
		{name: "net.ParseCIDR", src: `func f() { _, _, _ = net.ParseCIDR("2001:db8::/48") }`, want: 2},
		{name: "httpx.Subject, the wrapper that returns the key (tenant-r12-3)", src: `func f(ctx context.Context) { n, w := httpx.Subject(ctx); _, _ = n, w }`, want: 2},
		{name: "a function value of the wrapper", src: `var sub = httpx.Subject`, want: 2},
		{name: "a map keyed on the wrapper's result (tenant-r12-3)", src: `var slots = map[string]int{}
func f(ctx context.Context) { n, _ := httpx.Subject(ctx); slots[n]++ }`, want: 2},
		{name: "the address taken apart by hand", src: `func f(a netip.Addr) []byte { b := a.As16(); return b[:6] }`, want: 2},
		{name: "an address rebuilt from bytes", src: `func f(b []byte) { _, _ = netip.AddrFromSlice(b[:3]) }`, want: 2},
		{name: "a dot import of netip", own: true, want: 1, src: `package api
import . "net/netip"
func f(a Addr) { _ = MustParsePrefix("10.0.0.0/8") }`},
		{name: "a type the checker cannot resolve still fails closed", own: true, want: 1, src: `package api
import "example.com/stub"
func f(c stub.Ctx) { _ = c.Addr().Prefix(24) }`},

		{name: "only the client address is read", src: `func f(ctx context.Context) netip.Addr { return httpx.ClientIPFrom(ctx) }`, want: 1},
		{name: "parsing an address is not a cut", src: `func f(s string) { _, _ = netip.ParseAddr(s) }`, want: 1},
		{name: "a resolved Mask that is not net.IP.Mask", src: `type phone struct{}
func (phone) Mask(string) string { return "" }
func f(p phone) { _ = p.Mask("0912") }`, want: 1},
	}
	allowed := map[string]string{
		"internal/netkey/netkey.go":    "the definition",
		"internal/httpx/middleware.go": "Subject",
	}
	for _, c := range cases {
		fset := token.NewFileSet()
		src := c.src
		if !c.own {
			src = pre + src
		}
		files := netCutCorpus(t, fset, src)
		info, ok := typeInfoReal(fset, files, "net/netip")
		if !ok {
			t.Fatalf("%s: no type information", c.name)
		}
		res := netCutProblems(fset, files, info, allowed)
		if got := len(res.problems); got != c.want {
			t.Errorf("%s: %d findings %v, want %d", c.name, got, res.problems, c.want)
		}
	}
	// A clean file with no header reference is clean: the count above is not a lint that reports everything.
	fset := token.NewFileSet()
	files := netCutCorpus(t, fset, "package api\nimport \"net/netip\"\nfunc f(s string) { _, _ = netip.ParseAddr(s) }\n")
	info, _ := typeInfoReal(fset, files, "net/netip")
	if res := netCutProblems(fset, files, info, allowed); len(res.problems) != 0 {
		t.Errorf("a clean file reported %v", res.problems)
	}
}
