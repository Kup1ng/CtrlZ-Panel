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
//  5. The string of an address (round 16, tenant-r16-14 and -17). A cut by hand starts from the string form, so every
//     way to get it is a root: the String, StringExpanded, MarshalText, AppendTo and AppendText methods of
//     netip.Addr, the String of a Prefix, an AddrPort and a net.IP. The other way to get it is to hand the address
//     to code that renders it, so addrFlows judges every expression whose type carries an address (an address type,
//     or a struct, slice, map, pointer or channel built from one) by where it goes, as a closed allow list: it may be
//     a receiver, an operand or a value of a typed place, and it fails when it becomes a value of interface type or
//     of a type parameter by ANY route (an argument, an assignment, a declaration, a conversion, a return, a send, a
//     composite literal, a comparison, a generic instantiation), when a callee the checker cannot resolve is handed
//     one, and in any context the lint does not list. A statement parameter is bound by one function in a listed file.
//
// Not covered, and declared: an address kept in an interface-typed field (it is not an address type until a type
// assertion) and rendered later, a reflection walk, and a string made from a string that was handed over. shared/ is a
// separate module and is not read, but it is reached through an unresolved import, so an address handed to one of
// its functions fails. The registry's abuse tests (internal/budget) are the net.

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

	"net.CIDRMask":                    "makes a network mask",
	"net.ParseCIDR":                   "parses a network",
	"(net.IP).Mask":                   "cuts an address with a mask",
	"(net/netip.Addr).String":         "the string form of an address, which can be cut by hand",
	"(net/netip.Addr).StringExpanded": "the string form of an address, which can be cut by hand",
	"(net/netip.Addr).MarshalText":    "the string form of an address, which can be cut by hand",
	"(net/netip.Addr).AppendTo":       "the string form of an address, which can be cut by hand",
	"(net/netip.Addr).AppendText":     "the string form of an address, which can be cut by hand",
	"(net/netip.Prefix).String":       "the string form of a prefix, which can be cut by hand",
	"(net/netip.AddrPort).String":     "the string form of an address and port, which can be cut by hand",
	"(net.IP).String":                 "the string form of an address, which can be cut by hand",
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
	"internal/api/routes_reauth.go":      "shows the address a session was opened from, in the owner's own session list (an answer, not a key)",
	"internal/adminapi/routes_audit.go":  "shows the address of an audit row to the admin who reads it (an answer, not a key)",
	"internal/auth/audit/canonical.go":   "the canonical text of the ip field of an audit event, whose bytes are the MAC input; it keys nothing",
	"internal/logattr/logattr.go":        "the one log attribute for a peer address; a log line is not a bucket",
	"internal/store/fn.go":               "the one place the store hands an address or prefix to the driver, as a statement parameter or a scan target (addrArg, scanAddr, scanPrefixes and the registered claim functions); the driver encodes it as inet",
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
		// Part 5: a value that carries an address, and where it goes (round 16, tenant-r16-14 and -17).
		for _, fl := range addrFlows(info, f.ast) {
			report(fl.pos, fl.what)
		}
	}
	sort.Strings(res.problems)
	return res
}

func TestNoCodeKeysAnythingOnTheNetworkOutsideTheRegistry(t *testing.T) {
	fset, files := parseRepo(t)
	info, ok := typeInfoReal(fset, files, "net/netip", "net", "fmt", "log/slog", "encoding/json", "errors", "strings", "strconv", "context", "time")
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
	const addrHead = "package api\nimport (\n\t\"fmt\"\n\t\"net/netip\"\n)\nvar _ = fmt.Sprint\nvar _ netip.Addr\n"
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

		// Round 16, tenant-r16-14: a cut by hand from the STRING of an address. The string form is a root, and an
		// address handed to a parameter of interface type is rendered as one by code this file does not show.
		{name: "the string of an address, cut by hand (tenant-r16-14)", src: `func f(a netip.Addr) string { s := a.String(); return s[:len(s)-2] }`, want: 2},
		{name: "a method value of Addr.String", src: `func f(a netip.Addr) { g := a.String; _ = g() }`, want: 2},
		{name: "a method expression of Addr.String", src: `var g = netip.Addr.String`, want: 2},
		{name: "the string of a prefix", src: `func f(p netip.Prefix) string { return p.String() }`, want: 2},
		{name: "the string of a net.IP", src: `func f(ip net.IP) string { return ip.String() }`, want: 2},
		{name: "a wrapper in the same package that returns the string", src: `func key(a netip.Addr) string { return a.String() }
func f(ctx context.Context) string { return key(httpx.ClientIPFrom(ctx)) }`, want: 2},
		{name: "an address handed to fmt", own: true, want: 1, src: `package api
import (
	"fmt"
	"net/netip"
)
func f(a netip.Addr) string { return fmt.Sprint(a) }`},
		{name: "an address handed to a logger", own: true, want: 1, src: `package api
import (
	"log/slog"
	"net/netip"
)
func f(a netip.Addr) slog.Attr { return slog.Any("ip", a) }`},
		{name: "an address handed to a callee the checker cannot resolve", own: true, want: 1, src: `package api
import (
	"net/netip"
	"example.com/stub"
)
func f(a netip.Addr) { stub.Use(a) }`},
		{name: "an address handed to a typed parameter is not a cut", src: `func g(a netip.Addr) bool { return a.Is4() }
func f(ctx context.Context) bool { return g(httpx.ClientIPFrom(ctx)) }`, want: 1},

		// Round 16, tenant-r16-17: the value, not the call shape. An address that carries into a value of interface
		// type by any route is a cut (own: the file has its own header, with fmt; want counts the findings).
		{name: "an address in an any variable, then rendered (tenant-r16-17)", own: true, want: 1, src: addrHead + `
func f(a netip.Addr) string { var v any = a; return fmt.Sprint(v) }`},
		{name: "an address converted to any in the call (tenant-r16-17)", own: true, want: 1, src: addrHead + `
func f(a netip.Addr) string { return fmt.Sprint(any(a)) }`},
		{name: "an address inside an anonymous struct (tenant-r16-17)", own: true, want: 1, src: addrHead + `
func f(a netip.Addr) string { return fmt.Sprint(struct{ A netip.Addr }{a}) }`},
		{name: "an address inside a named wrapper rendered with a verb", own: true, want: 1, src: addrHead + `
type wrapper struct{ ip netip.Addr }
func f(a netip.Addr) string { return fmt.Sprintf("%v", wrapper{a}) }`},
		{name: "a pointer to a wrapper", own: true, want: 1, src: addrHead + `
type wrapper struct{ ip netip.Addr }
func f(a netip.Addr) string { return fmt.Sprint(&wrapper{a}) }`},
		{name: "a slice of addresses", own: true, want: 1, src: addrHead + `
func f(a []netip.Addr) string { return fmt.Sprint(a) }`},
		{name: "an address returned as any", own: true, want: 1, src: addrHead + `
func f(a netip.Addr) any { return a }`},
		{name: "an address returned beside an error", own: true, want: 1, src: addrHead + `
func f(a netip.Addr) (any, error) { return a, nil }`},
		{name: "a call that returns an address and an error, assigned to any", own: true, want: 1, src: addrHead + `
func g() (netip.Addr, error) { return netip.Addr{}, nil }
func f() { var v any; v, _ = g(); _ = v }`},
		{name: "an address in a slice of any", own: true, want: 1, src: addrHead + `
func f(a netip.Addr) []any { return []any{a} }`},
		{name: "an address in a map of any", own: true, want: 1, src: addrHead + `
func f(a netip.Addr) map[string]any { return map[string]any{"ip": a} }`},
		{name: "an address sent on a channel of any", own: true, want: 1, src: addrHead + `
func f(a netip.Addr, c chan any) { c <- a }`},
		{name: "an address assigned to a field of type any", own: true, want: 1, src: addrHead + `
type box struct{ v any }
func f(a netip.Addr, b *box) { b.v = a }`},
		{name: "an address appended to a slice of any", own: true, want: 1, src: addrHead + `
func f(a netip.Addr) []any { return append([]any{}, a) }`},
		{name: "an address ranged over and rendered", own: true, want: 1, src: addrHead + `
func f(as []netip.Addr) { for _, a := range as { _ = fmt.Sprint(a) } }`},
		{name: "a method value of fmt.Sprint", own: true, want: 1, src: addrHead + `
func f(a netip.Addr) string { p := fmt.Sprint; return p(a) }`},
		{name: "a wrapper in the same package that takes any", own: true, want: 1, src: addrHead + `
func show(v any) string { return "" }
func f(a netip.Addr) string { return show(a) }`},
		{name: "an address in an error text", own: true, want: 1, src: addrHead + `
func f(a netip.Addr) error { return fmt.Errorf("from %v", a) }`},
		{name: "an address as a non-empty interface (Addr is a Stringer)", own: true, want: 1, src: addrHead + `
func f(a netip.Addr) fmt.Stringer { return a }`},
		{name: "a generic function instantiated with an address", own: true, want: 1, src: addrHead + `
func id[T any](v T) T { return v }
func f(a netip.Addr) netip.Addr { return id(a) }`},
		{name: "a generic body that renders its type parameter", own: true, want: 1, src: addrHead + `
func show[T any](v T) string { return fmt.Sprint(v) }
func f() string { return show("x") }`},
		{name: "a generic that renders, called with a wrapper", own: true, want: 1, src: addrHead + `
type wrapper struct{ ip netip.Addr }
func show[T any](v T) string { return fmt.Sprint(v) }
func f(a netip.Addr) string { return show(wrapper{a}) }`},
		{name: "a function of shared/ handed an address", own: true, want: 1, src: `package api
import (
	"net/netip"
	"github.com/Kup1ng/CtrlZ-Shared/netclass"
)
func f(a netip.Addr) bool { return netclass.IsPublic(a) }`},

		// The clean forms of the same values: typed places, comparisons, a method set of our own type.
		{name: "typed places only", own: true, want: 0, src: addrHead + `
type wrapper struct{ ip netip.Addr }
func g(a netip.Addr) bool { return a.Is4() }
func f(a, b netip.Addr, w *wrapper) (netip.Addr, bool) {
	s := []netip.Addr{a, b}
	m := map[netip.Addr]int{a: 1}
	w.ip = a
	_ = m[b]
	_ = wrapper{ip: a}
	return s[0], a == b && g(a)
}`},
		{name: "a holder in a non-empty interface of our own", own: true, want: 0, src: addrHead + `
type wrapper struct{ ip netip.Addr }
func (wrapper) String() string { return "w" }
func f(a netip.Addr) fmt.Stringer { return wrapper{a} }`},
		{name: "a generic with no address", own: true, want: 0, src: addrHead + `
func id[T any](v T) T { return v }
func f() string { return id("x") }`},

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
		info, ok := typeInfoReal(fset, files, "net/netip", "net", "fmt", "log/slog", "encoding/json", "errors", "strings", "strconv", "context", "time")
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

// isAddrType says a type is an address or a prefix of the standard library: the types whose string form is a
// network key made by hand.
func isAddrType(t types.Type) bool {
	n, ok := types.Unalias(t).(*types.Named)
	if !ok || n.Obj().Pkg() == nil {
		return false
	}
	switch n.Obj().Pkg().Path() + "." + n.Obj().Name() {
	case "net/netip.Addr", "net/netip.Prefix", "net/netip.AddrPort", "net.IP", "net.IPNet", "net.IPAddr", "net.TCPAddr", "net.UDPAddr":
		return true
	}
	return false
}

// addrLevel says how a value of type t holds an address. 2: it is one (an address type, a pointer to one, or a
// struct that embeds one, whose promoted String and MarshalText methods make any interface a way to render it).
// 1: it holds one (a slice, array, channel, map or struct built from one, or a value of a type parameter, whose
// body the lint cannot read for every type argument), which is rendered only through an empty interface such as the
// `any` of fmt, a logger, an encoder or a driver, since a non-empty interface shows the methods of OUR type, and those
// are judged where they are written. 0: neither. An interface type is 0, the declared limit (an address kept in an
// interface-typed field). A holder is a value that would be rendered whole (round 16, tenant-r16-17).
func addrLevel(t types.Type) int { return level(t, map[types.Type]bool{}) }

func level(t types.Type, seen map[types.Type]bool) int {
	if t == nil || seen[t] {
		return 0
	}
	seen[t] = true
	t = types.Unalias(t)
	if isAddrType(t) {
		return 2
	}
	hold := func(l int) int {
		if l > 0 {
			return 1
		}
		return 0
	}
	switch t := t.(type) {
	case *types.Named:
		return level(t.Underlying(), seen)
	case *types.TypeParam:
		return 1
	case *types.Pointer:
		return level(t.Elem(), seen)
	case *types.Slice:
		return hold(level(t.Elem(), seen))
	case *types.Array:
		return hold(level(t.Elem(), seen))
	case *types.Chan:
		return hold(level(t.Elem(), seen))
	case *types.Map:
		return hold(max(level(t.Key(), seen), level(t.Elem(), seen)))
	case *types.Struct:
		l := 0
		for i := 0; i < t.NumFields(); i++ {
			fl := level(t.Field(i).Type(), seen)
			if t.Field(i).Embedded() && fl == 2 {
				return 2
			}
			l = max(l, hold(fl))
		}
		return l
	case *types.Tuple:
		l := 0
		for i := 0; i < t.Len(); i++ {
			l = max(l, level(t.At(i).Type(), seen))
		}
		return l
	}
	return 0
}

func carriesAddr(t types.Type) bool { return addrLevel(t) > 0 }

// rendersAs says whether a value of level l handed to a place of type t can be rendered as a string.
func rendersAs(l int, t types.Type) bool {
	if _, tp := types.Unalias(t).(*types.TypeParam); tp {
		// A value going into a type parameter is judged at the instantiation (a bare address) and in the generic
		// body, where a value of the parameter type that is rendered is level 1; a T to T move is not a conversion.
		return false
	}
	if l == 0 || t == nil || !types.IsInterface(t) {
		return false
	}
	if l == 2 {
		return true
	}
	i, ok := t.Underlying().(*types.Interface)
	return ok && i.NumMethods() == 0
}

// addrFlow is a place where a value that carries an address goes somewhere the lint cannot follow it.
type addrFlow struct {
	pos  token.Pos
	what string
}

// addrFlows is part 5 of the network-cut rule, as a closed allow list over the CONTEXT of every expression whose
// type carries an address. Round 16 first judged one shape (an address as the argument of a call whose parameter is
// an interface), and tenant-r16-17 showed the next edit goes round it: `var v any = a`, `fmt.Sprint(any(a))`, an
// address inside a struct or slice, a return into `any`, a send, a generic function. They are one thing, a value
// that carries an address becoming a value of interface type (or of a type parameter, which a generic body can
// convert), so the guard judges that and not a shape:
//
//   - the value is the receiver of a selector (a method call or a field read: the roots above judge the methods),
//     the operand of a unary, star, paren, slice or index expression, a range or switch operand, a comparison with a
//     value that is not of interface type, a statement's expression, or a type assertion's operand;
//   - the value is converted, passed, assigned, returned, sent, put into a composite literal or declared into a place
//     of a type that is not an interface and not a type parameter;
//   - a generic function or type is instantiated with a type argument that carries an address;
//   - a callee the checker cannot resolve (a package it stubs, such as shared/) is handed one;
//   - ANY OTHER context fails: the allow list is closed, so a syntax the lint does not know is a failure.
//
// It judges every non-test file by go/types; the files that bind an address as a statement parameter or show one are
// in netCutAllowed with their reason. It does not judge an address kept in an interface-typed field and rendered
// later, a reflection walk, or a string built by another party from a string it was given.
func addrFlows(info *types.Info, f *ast.File) []addrFlow {
	var out []addrFlow
	var stack []ast.Node
	add := func(n ast.Node, what string) { out = append(out, addrFlow{n.Pos(), what}) }
	lvl := 0 // the level of the value being judged
	sink := func(e ast.Node, t types.Type, what string) {
		if rendersAs(lvl, t) {
			add(e, "hands an address to "+what+" of interface type, where it is rendered as a string that can be cut by hand")
		}
	}
	// The signature of the function a return belongs to.
	sigOf := func() *types.Signature {
		for i := len(stack) - 1; i >= 0; i-- {
			switch fn := stack[i].(type) {
			case *ast.FuncDecl:
				if o, ok := info.Defs[fn.Name].(*types.Func); ok {
					s, _ := o.Type().(*types.Signature)
					return s
				}
				return nil
			case *ast.FuncLit:
				s, _ := info.TypeOf(fn).(*types.Signature)
				return s
			}
		}
		return nil
	}
	index := func(list []ast.Expr, e ast.Expr) int {
		for i, x := range list {
			if x == e {
				return i
			}
		}
		return -1
	}
	// tupleTo judges every component of a call that returns several values against the places they go to.
	tupleTo := func(e ast.Expr, places []types.Type, what string) {
		tup, ok := info.TypeOf(e).(*types.Tuple)
		if !ok {
			return
		}
		for i := 0; i < tup.Len() && i < len(places); i++ {
			lvl = addrLevel(tup.At(i).Type())
			sink(e, places[i], what)
		}
	}
	judge := func(e ast.Expr) {
		parent := stack[len(stack)-2]
		lvl = addrLevel(info.TypeOf(e))
		switch p := parent.(type) {
		case *ast.CallExpr:
			if p.Fun == e {
				return
			}
			ftv, ok := info.Types[p.Fun]
			if !ok || ftv.Type == nil || ftv.Type == types.Typ[types.Invalid] {
				add(e, "hands an address to a callee the checker could not resolve (a package it stubs, such as shared/), which may render it as a string")
				return
			}
			if ftv.IsType() { // a conversion T(x)
				sink(e, ftv.Type, "a conversion")
				return
			}
			sig, ok := ftv.Type.Underlying().(*types.Signature)
			if !ok {
				add(e, "hands an address to a call whose signature the lint cannot read")
				return
			}
			params := sig.Params()
			if _, tuple := info.TypeOf(e).(*types.Tuple); tuple { // f(g()) with g returning several values
				for j := 0; j < params.Len(); j++ {
					sink(e, params.At(j).Type(), "a parameter")
				}
				return
			}
			i := index(p.Args, e)
			switch {
			case sig.Variadic() && i >= params.Len()-1:
				last := params.At(params.Len() - 1).Type()
				if s, ok := last.(*types.Slice); ok && !p.Ellipsis.IsValid() {
					sink(e, s.Elem(), "a parameter")
				} else {
					sink(e, last, "a parameter")
				}
			case i >= 0 && i < params.Len():
				sink(e, params.At(i).Type(), "a parameter")
			}
		case *ast.AssignStmt:
			i := index(p.Rhs, e)
			if i < 0 {
				return // the target of the assignment
			}
			if len(p.Lhs) == len(p.Rhs) {
				sink(e, info.TypeOf(p.Lhs[i]), "a variable")
				return
			}
			places := make([]types.Type, len(p.Lhs))
			for k, l := range p.Lhs {
				places[k] = info.TypeOf(l)
			}
			tupleTo(e, places, "a variable")
		case *ast.ValueSpec:
			i := index(p.Values, e)
			if i < 0 {
				return
			}
			places := make([]types.Type, len(p.Names))
			for k, n := range p.Names {
				if o := info.Defs[n]; o != nil {
					places[k] = o.Type()
				}
			}
			if len(p.Names) == len(p.Values) {
				sink(e, places[i], "a variable")
				return
			}
			tupleTo(e, places, "a variable")
		case *ast.ReturnStmt:
			sig := sigOf()
			if sig == nil {
				add(e, "returns an address from a function the lint cannot read")
				return
			}
			places := make([]types.Type, sig.Results().Len())
			for k := range places {
				places[k] = sig.Results().At(k).Type()
			}
			if len(p.Results) == len(places) {
				if i := index(p.Results, e); i >= 0 {
					sink(e, places[i], "a result")
				}
				return
			}
			tupleTo(e, places, "a result")
		case *ast.CompositeLit:
			sinkElem(info, e, p, nil, sink)
		case *ast.KeyValueExpr:
			var lit *ast.CompositeLit
			if len(stack) >= 3 {
				lit, _ = stack[len(stack)-3].(*ast.CompositeLit)
			}
			if lit == nil {
				add(e, "an address in a position the lint does not recognise")
				return
			}
			if p.Key == e {
				if m, ok := info.TypeOf(lit).Underlying().(*types.Map); ok {
					sink(e, m.Key(), "a map key")
				}
				return
			}
			sinkElem(info, e, lit, p, sink)
		case *ast.SendStmt:
			if p.Value == e {
				if c, ok := info.TypeOf(p.Chan).Underlying().(*types.Chan); ok {
					sink(e, c.Elem(), "a channel")
				}
			}
		case *ast.BinaryExpr:
			other := p.X
			if p.X == e {
				other = p.Y
			}
			sink(e, info.TypeOf(other), "a comparison")
		case *ast.IndexExpr:
			if p.Index == e {
				if m, ok := info.TypeOf(p.X).Underlying().(*types.Map); ok {
					sink(e, m.Key(), "a map key")
				}
			}
		case *ast.SelectorExpr, *ast.ParenExpr, *ast.StarExpr, *ast.UnaryExpr, *ast.SliceExpr, *ast.IndexListExpr,
			*ast.TypeAssertExpr, *ast.ExprStmt, *ast.IncDecStmt, *ast.RangeStmt, *ast.SwitchStmt, *ast.CaseClause,
			*ast.IfStmt, *ast.ForStmt, *ast.TypeSwitchStmt, *ast.DeferStmt, *ast.GoStmt:
			// a field read or method call, an operand, or a statement that only looks at the value.
		default:
			add(e, "an address in a position the lint does not recognise, so it cannot show the value stays typed")
		}
	}
	ast.Inspect(f, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		stack = append(stack, n)
		if id, ok := n.(*ast.Ident); ok {
			if inst, ok := info.Instances[id]; ok {
				for i := 0; i < inst.TypeArgs.Len(); i++ {
					if addrLevel(inst.TypeArgs.At(i)) == 2 {
						add(n, "instantiates a generic with an address, which its body sees as a type parameter and can render")
						break
					}
				}
			}
		}
		if e, ok := n.(ast.Expr); ok && len(stack) >= 2 {
			if tv, ok := info.Types[e]; ok && !tv.IsType() && tv.Type != nil && carriesAddr(tv.Type) {
				judge(e)
			}
		}
		return true
	})
	return out
}

// sinkElem judges an element of a composite literal against the type the literal gives it.
func sinkElem(info *types.Info, e ast.Expr, lit *ast.CompositeLit, kv *ast.KeyValueExpr, sink func(ast.Node, types.Type, string)) {
	t := info.TypeOf(lit)
	if t == nil {
		return
	}
	u := t.Underlying()
	if p, ok := u.(*types.Pointer); ok { // an elided &T{} inside a slice of pointers
		u = p.Elem().Underlying()
	}
	switch u := u.(type) {
	case *types.Struct:
		if kv != nil {
			if id, ok := kv.Key.(*ast.Ident); ok {
				for i := 0; i < u.NumFields(); i++ {
					if u.Field(i).Name() == id.Name {
						sink(e, u.Field(i).Type(), "a field")
					}
				}
			}
			return
		}
		for i, x := range lit.Elts {
			if x == e && i < u.NumFields() {
				sink(e, u.Field(i).Type(), "a field")
			}
		}
	case *types.Slice:
		sink(e, u.Elem(), "an element")
	case *types.Array:
		sink(e, u.Elem(), "an element")
	case *types.Map:
		sink(e, u.Elem(), "an element")
	}
}
