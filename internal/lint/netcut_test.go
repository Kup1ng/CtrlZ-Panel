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
	"strings"
	"testing"
)

// The network-cut rule (P1 auth review, rule 6 budget-keying; tenant-r10-3, tenant-r11-4, tenant-r12-1 and -3).
//
// A bucket that counts on the network of a client is declared in the registry (internal/budget) and built by one
// implementation (internal/throttle, internal/ratelimit; internal/netpool was removed with the invite pool by D67). Round 11 enforced that with an AST walk
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
//  6. The text of the address (round 17, tenant-r17-7, -9 and -10). A string made from a string that was handed
//     over is not an address-typed expression, so the lint cannot follow it; it refuses to let the text in. The
//     peer of a connection (the RemoteAddr field of a request, net.Conn.RemoteAddr and the String of the net
//     address types) and the reads of the header map (Get, Values, Clone, Write, an index, a range) are roots
//     that only a listed function may use, and the header map itself is judged like a value that holds an
//     address (it may not become a value of interface type, which is how the context of Outbox carries it, nor
//     go to a callee the checker cannot read). A wrapper over such a read is not a cut for its callers: the
//     definition is the one that has to be listed. Generated code (a .gen.go under gen/) binds the parameters
//     the OpenAPI document declares and is not read for part 6. An address kept in an interface-typed field can
//     only come from a flow that part 5 judges (a value becomes interface-typed through a place it names), or
//     from a listed function. A reflection walk (or any other escape hatch) is judged once, by the escape-hatch
//     ban (capabilities_test.go).
//
//  7. The members of the address types (round 18, tenant-r18-7). Part 1 named the methods that take an address apart
//     (As4, String, MarshalText, ...), and six ordinary members it had not named (MarshalBinary, AppendBinary,
//     AddrPort.MarshalText, Prefix.MarshalText, the bytes of net.IP.To4, an index of a net.IP) cut a /24 by hand and
//     passed. netip.Addr, netip.Prefix, netip.AddrPort and net.IP are sources like a request, judged by the same
//     machinery as part 6: EVERY selection whose owner is one of them must name a member of its safe list
//     (sourceSafeMembers: the members that answer a question about the address or give back an address), so any member
//     not listed, a later release's among them, is a cut; a net.IP, which is a byte slice, may not be indexed, sliced
//     or ranged over, and may not move into a place of another type (a conversion to string or []byte, a parameter of
//     type []byte, an assignment to one), which is how its bytes are reached. The list of part 1 stays, for the
//     functions that make or cut a network (netkey.Net, PrefixFrom, ParsePrefix, ...) and for finding wrappers.
//
// The unit of the allow list is a FUNCTION, "path#Func" (round 17, tenant-r17-9): a file that shows an address in
// one function used to hide a key cut by hand in the next.
//
// shared/ is a separate module and is not read, but it is reached through an unresolved import, so an address
// handed to one of its functions fails. The registry's abuse tests (internal/budget) are the net.

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

// Part 6 (round 17, tenant-r17-7, -9, -10 and -15): where the address of a client COMES FROM as text. A string made
// from a string that was handed over is not an address-typed expression, so the lint cannot follow it; it refuses
// to let the text in. Round 17 first listed the spellings of the readers (Header.Get, Header.Values, the RemoteAddr
// field, the String of the address types), and the fix gate planted six ways round the list (the concrete
// RemoteAddr of a *net.TCPConn handed to fmt, a header converted to a plain map, textproto.MIMEHeader, Request.Write
// into a buffer, the Request rendered with %+v, a Request returned as any): a list of names again. It is now judged
// by the TYPE of the thing that holds the text, as a fail-closed allow list.
//
// A value is a SOURCE when its type is one of three kinds, found by go/types and not by a name of a method:
//
//   - "request": net/http.Request, the struct a server is handed, which holds the peer (RemoteAddr), the headers
//     and a copy of both in its Write text;
//   - "headers": a header map, any type whose underlying type is map[string][]string except net/url.Values (the
//     query string is a value of its own, and a key made from it is the boundary rule's business). net/http.Header,
//     textproto.MIMEHeader and a plain map made by converting one are all this kind, because the conversion
//     keeps the underlying type;
//   - "peer": any type that implements net.Addr (the interface itself and every concrete address a connection or a
//     packet gives: *net.TCPAddr, *net.UDPAddr, a type of our own with Network and String).
//
// Four contexts judge a source, each a closed allow list:
//
//  1. Members. EVERY selection whose owner is a source (a field read, a method call, a method value, a method
//     expression, one promoted through an embedded field) must name a member on the safe list of its kind
//     (sourceSafeMembers). Anything not listed is a read of the text: Header.Get, Values, Clone, Write, Request.
//     RemoteAddr, Request.Write, net.Addr.String, and every member a later Go release adds.
//  2. The map itself. A header map may not be indexed or ranged over, with a write too (use Set, Add and Del).
//  3. Flows. A source becomes a value of interface type, or goes to a callee the checker cannot read, or is
//     converted to a type that is not a source, or instantiates a generic, only in a function listed in
//     netCutAllowed (the flow judgement of part 5 carries them: a request is level 1, a header map is level 1, a
//     peer address is level 2). A peer address may become a net.Addr, which is the same kind.
//  4. Listing. A function that reads the text is listed with its reason, so the definition is the one a reviewer
//     reads; a wrapper over a read is not a cut for its callers.
//
// Generated code (a .gen.go under gen/) binds the parameters the OpenAPI document declares and is not read for
// part 6. A connection (net.Conn) is not a source: it hands out its peer only as a net.Addr, which is. An address
// kept in an interface-typed field, and a reflection walk, need a source to become interface-typed first.
var sourceSafeMembers = map[string]map[string]bool{
	// The members of a request that hold nothing of the client's address. RemoteAddr, Write and WriteProxy are
	// the ones that do, and are left out with every member a later release adds.
	"request": setOf([]string{"Method", "URL", "Proto", "ProtoMajor", "ProtoMinor", "ProtoAtLeast", "Body", "GetBody",
		"ContentLength", "TransferEncoding", "Close", "Host", "Form", "PostForm", "MultipartForm", "Pattern",
		"Response", "Context", "WithContext", "Clone", "Cookie", "Cookies", "CookiesNamed", "AddCookie",
		"BasicAuth", "SetBasicAuth", "UserAgent", "Referer", "FormValue", "PostFormValue", "ParseForm",
		"ParseMultipartForm", "FormFile", "MultipartReader", "PathValue", "SetPathValue", "Header", "Trailer",
		"Cancel", "TLS", "RequestURI"}),
	// A header map is written, never read.
	"headers": setOf([]string{"Set", "Add", "Del"}),
	// What a peer address shows without being text: its kind, its parts as typed values.
	"peer": setOf([]string{"Network", "AddrPort", "IP", "Port", "Zone"}),
	// The address types themselves (round 18, tenant-r18-7). Round 16 forbade a list of method names (As4, String,
	// MarshalText, ...) and a member that was not on it (MarshalBinary, AppendBinary, AddrPort.MarshalText,
	// Prefix.MarshalText, an index of net.IP) cut the address by hand and passed. Each type now has the list of
	// what is SAFE, the members that answer a question about the address or give back a value of a type that is
	// itself judged; every other member, and any member a later release adds, takes the address apart and fails.
	"addr": setOf([]string{"Is4", "Is4In6", "Is6", "IsValid", "IsLoopback", "IsMulticast", "IsPrivate", "IsUnspecified",
		"IsGlobalUnicast", "IsLinkLocalMulticast", "IsLinkLocalUnicast", "IsInterfaceLocalMulticast", "Unmap", "Zone",
		"WithZone", "BitLen", "Compare", "Less", "Next", "Prev"}),
	"prefix":   setOf([]string{"Addr", "Bits", "IsValid", "Contains", "Overlaps", "IsSingleIP"}),
	"addrport": setOf([]string{"Addr", "Port", "IsValid", "Compare"}),
	// A net.IP is a byte slice: it may be asked about, never indexed, sliced, ranged over or converted (see below).
	"ip": setOf([]string{"Equal", "IsLoopback", "IsMulticast", "IsPrivate", "IsUnspecified", "IsGlobalUnicast",
		"IsLinkLocalMulticast", "IsLinkLocalUnicast", "IsInterfaceLocalMulticast", "To4", "To16"}),
}

// addrKind says which of the standard library's address types a type is (a pointer to one counts): "addr",
// "prefix", "addrport" or "ip" (net.IP, a byte slice), and "" for any other type. They are sources of part 7.
func addrKind(t types.Type) string {
	t = types.Unalias(t)
	if p, ok := t.(*types.Pointer); ok {
		t = types.Unalias(p.Elem())
	}
	n, ok := t.(*types.Named)
	if !ok || n.Obj().Pkg() == nil {
		return ""
	}
	switch n.Obj().Pkg().Path() + "." + n.Obj().Name() {
	case "net/netip.Addr":
		return "addr"
	case "net/netip.Prefix":
		return "prefix"
	case "net/netip.AddrPort":
		return "addrport"
	case "net.IP":
		return "ip"
	}
	return ""
}

// netAddrIface is net.Addr, built from its two methods so a type implements it structurally and the lint does not
// depend on which package declares the type.
var netAddrIface = func() *types.Interface {
	sig := types.NewSignatureType(nil, nil, nil, nil, types.NewTuple(types.NewVar(token.NoPos, nil, "", types.Typ[types.String])), false)
	return types.NewInterfaceType([]*types.Func{
		types.NewFunc(token.NoPos, nil, "Network", sig),
		types.NewFunc(token.NoPos, nil, "String", sig),
	}, nil).Complete()
}()

// isHeaderMap says a type is a header map: net/http.Header or net/textproto.MIMEHeader, the two types the standard
// library gives the headers of a message. A header map that lost its name (a conversion to map[string][]string,
// to url.Values or to a type of our own, or an assignment to a variable of one of those) is not found here, so
// the move itself is judged: a source leaving its kind is a problem (see addrFlows). A plain map[string][]string
// is NOT a header map, since the repository holds many that have nothing to do with a request.
func isHeaderMap(t types.Type) bool {
	n, ok := types.Unalias(t).(*types.Named)
	if !ok || n.Obj().Pkg() == nil {
		return false
	}
	switch n.Obj().Pkg().Path() + "." + n.Obj().Name() {
	case "net/http.Header", "net/textproto.MIMEHeader":
		return true
	}
	return false
}

// isPeerAddr says a type implements net.Addr (a pointer to a non-interface type counts: the methods of an address
// type are usually declared on the pointer).
func isPeerAddr(t types.Type) bool {
	// types.Implements answers true for an invalid type (a package the checker stubs), so that one error does not
	// make a hundred; here it would make every value of a stubbed type a peer address.
	if t == nil || t.Underlying() == types.Typ[types.Invalid] {
		return false
	}
	if p, ok := types.Unalias(t).(*types.Pointer); ok && p.Elem().Underlying() == types.Typ[types.Invalid] {
		return false
	}
	if types.Implements(t, netAddrIface) {
		return true
	}
	if _, isPtr := types.Unalias(t).(*types.Pointer); !isPtr && !types.IsInterface(t) {
		return types.Implements(types.NewPointer(t), netAddrIface)
	}
	return false
}

func isTypeParam(t types.Type) bool {
	_, ok := types.Unalias(t).(*types.TypeParam)
	return ok
}

// sourceKind says which kind of source a type is: "request", "headers", "peer", or "" when it is none. A pointer
// to a source is a source of the same kind.
func sourceKind(t types.Type) string {
	if t == nil {
		return ""
	}
	t = types.Unalias(t)
	if p, ok := t.(*types.Pointer); ok {
		if n, ok := types.Unalias(p.Elem()).(*types.Named); ok && n.Obj().Pkg() != nil && n.Obj().Pkg().Path() == "net/http" && n.Obj().Name() == "Request" {
			return "request"
		}
	}
	if n, ok := t.(*types.Named); ok && n.Obj().Pkg() != nil && n.Obj().Pkg().Path() == "net/http" && n.Obj().Name() == "Request" {
		return "request"
	}
	if isHeaderMap(t) {
		return "headers"
	}
	if k := addrKind(t); k != "" {
		return k
	}
	if isPeerAddr(t) {
		return "peer"
	}
	return ""
}

// sourceOwner follows a selection to the type that DECLARES the member it names, through the embedded fields a
// promoted member goes by, and says which kind of source that type is. A member promoted from an embedded
// *http.Request is judged as a member of the request.
func sourceOwner(s *types.Selection) string {
	t := s.Recv()
	idx := s.Index()
	for _, i := range idx[:len(idx)-1] {
		if p, ok := types.Unalias(t).(*types.Pointer); ok {
			t = p.Elem()
		}
		st, ok := t.Underlying().(*types.Struct)
		if !ok || i >= st.NumFields() {
			return ""
		}
		t = st.Field(i).Type()
	}
	return sourceKind(t)
}

// netCutNames are the selector names that, when the type checker could not resolve them (the receiver or the
// package is a stub), still count as a cut. A resolved selector of the same name is judged by netCutRoots instead,
// so phone.Mask is not one.
var netCutNames = map[string]bool{
	"Prefix": true, "Masked": true, "PrefixFrom": true, "ParsePrefix": true, "MustParsePrefix": true,
	"CIDRMask": true, "ParseCIDR": true, "As4": true, "As16": true, "AsSlice": true,
	"AddrFrom4": true, "AddrFrom16": true, "AddrFromSlice": true,
}

// netCutAllowed are the FUNCTIONS that may cut a network, each with the reason, keyed "path#Func" or
// "path#(Recv).Func" (see enclosing). The unit is a function and not a file, because a file that shows an address
// in one function hid a key cut by hand in the next: any cut in routes_reauth.go passed the lint while the same
// line in routes_login.go failed it (round 17, tenant-r17-9). A function that is listed and no longer cuts is an
// error, and a cut in a sibling function of a listed one is a problem, so the list cannot grow by being near.
var netCutAllowed = map[string]string{
	"internal/netkey/netkey.go#Net":  "the definition of the network of an address",
	"internal/netkey/netkey.go#Wide": "the definition of the IPv6 /48 of an address",

	"internal/httpx/middleware.go#ClientIP":            "derives the client address once per request, and compares it with the trusted-proxy prefixes",
	"internal/httpx/middleware.go#ParseTrustedProxies": "reads the trusted-proxy prefixes of the configuration; they are prefixes of proxies, not keys",
	"internal/httpx/middleware.go#Subject":             "the pipeline derives the network and the /48 once per request, for the rate classes of the registry",
	"internal/httpx/pipeline.go#(API).perOp":           "charges the rate classes of the registry with the network keys httpx.Subject hands it; it makes no key of its own and keeps no bucket",

	// Part 6, the readers of the peer and of header text (round 17, tenant-r17-7 and -10). Each reads one header by a
	// name that is not the client address, or the peer of a connection to judge it and keep nothing.
	"internal/httpx/middleware.go#CSRF":          "reads the Origin header of a request, which is a host and not a client address",
	"internal/httpx/middleware.go#Recover":       "reads the request id from the RESPONSE header the previous step set",
	"internal/httpx/middleware.go#UserAgentFrom": "reads the User-Agent header, which is a label and not a client address",
	"internal/httpx/middleware.go#Outbox":        "puts the request and response headers in the context under keys of its own that no other package can name; httpx.UserAgentFrom is the one reader of the request's, and the lint judges it",
	"internal/httpx/middleware.go#loopbackOnly":  "judges the peer of the connection against loopback to answer 404; it keeps the text of nothing",
	"internal/httpx/errors.go#Write":             "reads the request id from the RESPONSE header",
	"internal/auth/ticket/ticket.go#FromRequest": "reads the ticket header, a name of its own",
	"internal/authtest/oracle/oracle.go#Observe": "reduces a RESPONSE the harness received to its parts; no client address is in it",
	"internal/app/app.go#Run":                    "hands the server's OWN listen address to the Ready hook of a test; it is not a client",

	"internal/auth/throttle/throttle.go#(Who).part":                  "the one choke point of the throttle scopes: it builds the network and /48 key parts the registry names",
	"internal/auth/throttle/throttle.go#(Service).AdminLoginHits":    "the admin login throttle reads the network part through the registry's scope (Who.part)",
	"internal/auth/throttle/throttle.go#(Service).AdminLoginSuccess": "the admin login throttle clears the network part through the registry's scope",
	"internal/auth/throttle/throttle.go#(Service).InviteHit":         "the invite throttle only checks that the client address cuts to a network; its scope is keyed on the invite id (D67)",
	"internal/auth/throttle/throttle.go#(Service).LoginSuccess":      "the login throttle clears the network part of the registry's scope",
	"internal/auth/throttle/throttle.go#(Service).keyLabelled":       "builds the key of a registered scope from the parts Who.part makes; it keeps no bucket of its own",

	"internal/sms/counterkeys.go#OTPCounterKeys": "the daily SMS counters key their network by the same function; they are stored counters bounded by the SMS caps of spec 5.1, not a pool",
	"internal/sms/counterkeys.go#netPrefix":      "the daily SMS counters key their network by the same function; they are stored counters bounded by the SMS caps of spec 5.1, not a pool",

	"internal/api/routes_reauth.go#(Server).ListSessions":  "shows the address a session was opened from, in the owner's own session list (an answer, not a key)",
	"internal/admincli/sms.go#runSMSPending":               "shows the address of the audit row that staged a pending credential pair to the owner at the console, so they can tell their own PUT from a stolen session's (an answer, not a key)",
	"internal/adminapi/routes_audit.go#(Server).ListAudit": "shows the address of an audit row to the admin who reads it (an answer, not a key)",
	"internal/auth/audit/canonical.go#Canonical":           "the canonical text of the ip field of an audit event, whose bytes are the MAC input; it keys nothing",
	"internal/logattr/logattr.go#Addr":                     "the one log attribute for a peer address; a log line is not a bucket",

	"internal/store/fn.go#addrArg":              "the one place the store hands an address to the driver, as a statement parameter; the driver encodes it as inet",
	"internal/store/fn.go#scanAddr":             "the scan target of an address read back from inet",
	"internal/store/fn.go#scanPrefixes":         "the scan target of prefixes read back from cidr",
	"internal/store/fn.go#(Tx).EndpointPairIPs": "a registered claim function: it hands the addresses of an endpoint pair to the driver",
	"internal/store/fn.go#(Tx).IPClaimCheck":    "a registered claim function: it hands an address to the driver as a statement parameter",
	"internal/store/fn.go#(Tx).IPClaimRequest":  "a registered claim function: it hands an address to the driver as a statement parameter",
}

type netCutResult struct {
	problems []string
	used     map[string]bool // allowed function (path#Func) -> it cut
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

// generatedFile says a path is the output of the code generator: a .gen.go file under a gen directory.
func generatedFile(path string) bool {
	return strings.HasSuffix(path, ".gen.go") && strings.Contains("/"+path, "/gen/")
}

func funcName(fn *types.Func) string { return fn.Origin().FullName() }

// enclosing names the top-level declaration that holds pos: "Func", "(Recv).Func" (a pointer receiver is written
// without the star), or "(package)" for a package-level variable, constant or type. It is the unit of
// netCutAllowed. A literal inside a function belongs to that function.
func enclosing(f *ast.File, pos token.Pos) string {
	for _, d := range f.Decls {
		if pos < d.Pos() || pos > d.End() {
			continue
		}
		fd, ok := d.(*ast.FuncDecl)
		if !ok {
			return "(package)"
		}
		if fd.Recv == nil || len(fd.Recv.List) == 0 {
			return fd.Name.Name
		}
		t := fd.Recv.List[0].Type
		if st, ok := t.(*ast.StarExpr); ok {
			t = st.X
		}
		if ix, ok := t.(*ast.IndexExpr); ok {
			t = ix.X
		}
		if id, ok := t.(*ast.Ident); ok {
			return "(" + id.Name + ")." + fd.Name.Name
		}
		return "(?)." + fd.Name.Name
	}
	return "(package)"
}

// netCutProblems judges every non-test file. allowed is netCutAllowed, a parameter so the can-fail test can pass
// its own paths.
func netCutProblems(fset *token.FileSet, files []file, info *types.Info, allowed map[string]string) netCutResult {
	res := netCutResult{used: map[string]bool{}}

	// An allowed unit is a function, "path#Func" or "path#(Recv).Func" (see enclosing), and not a file: a file that
	// shows an address in one function must not hide a key cut by hand in the next (round 17, tenant-r17-9).
	allowedFiles := map[string]bool{}
	for k := range allowed {
		if i := strings.LastIndex(k, "#"); i > 0 {
			allowedFiles[k[:i]] = true
		}
	}

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
		if !allowedFiles[f.path] {
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
		report := func(pos token.Pos, what string) {
			if key := f.path + "#" + enclosing(f.ast, pos); allowed[key] != "" {
				res.used[key] = true
				return
			}
			res.problems = append(res.problems, fmt.Sprintf("%s: %s", fset.Position(pos), what))
		}
		// A generated file reads the headers and the request the OpenAPI document declares, to bind parameters; it
		// is written by the generator from the document the boundary lint judges, so part 6 does not read it.
		reportSource := func(pos token.Pos, what string) {
			if !generatedFile(f.path) {
				report(pos, what)
			}
		}
		ast.Inspect(f.ast, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.Ident:
				fn, ok := info.Uses[n].(*types.Func)
				if !ok {
					return true
				}
				if why, root := netCutRoots[funcName(fn)]; root {
					// A member of an address type is judged once, by the safe list of part 7 below; the root entry
					// stays so that a function that reaches it is found as a wrapper, but it is not a second finding.
					if sig, isSig := fn.Type().(*types.Signature); !isSig || sig.Recv() == nil || addrKind(sig.Recv().Type()) == "" {
						report(n.Pos(), "refers to "+funcName(fn)+", which "+why)
					}
				} else if wrappers[fn.Origin()] {
					report(n.Pos(), "refers to "+funcName(fn)+", which returns a network key made by a cut")
				}
			case *ast.IndexExpr:
				if tv, ok := info.Types[n.X]; ok && sourceKind(tv.Type) == "headers" {
					reportSource(n.Pos(), "indexes the headers of a request, X-Forwarded-For among them: the address of a client as text")
				} else if ok && sourceKind(tv.Type) == "ip" {
					reportSource(n.Pos(), "indexes a net.IP, which takes the address apart into bytes to cut it by hand")
				}
			case *ast.SliceExpr:
				if tv, ok := info.Types[n.X]; ok && sourceKind(tv.Type) == "ip" {
					reportSource(n.Pos(), "slices a net.IP, which takes the address apart into bytes to cut it by hand")
				}
			case *ast.RangeStmt:
				if rv, ok := info.Types[n.X]; ok && sourceKind(rv.Type) == "headers" {
					reportSource(n.Pos(), "ranges over the headers of a request, X-Forwarded-For among them: the address of a client as text")
				} else if ok && sourceKind(rv.Type) == "ip" {
					reportSource(n.Pos(), "ranges over a net.IP, which takes the address apart into bytes to cut it by hand")
				}
			case *ast.SelectorExpr:
				if s := info.Selections[n]; s != nil {
					if kind := sourceOwner(s); kind != "" && !sourceSafeMembers[kind][s.Obj().Name()] {
						reportSource(n.Sel.Pos(), "uses "+s.Obj().Name()+" of a "+kind+", which can show the address of a client as text; only "+
							strings.Join(sortedKeys(sourceSafeMembers[kind]), ", ")+" are safe")
					}
				}
				if netCutNames[n.Sel.Name] && info.Uses[n.Sel] == nil && info.Selections[n] == nil {
					report(n.Sel.Pos(), "uses ."+n.Sel.Name+" and the checker could not resolve it, so it may cut a network")
				}
			}
			return true
		})
		// Part 5: a value that carries an address, and where it goes (round 16, tenant-r16-14 and -17).
		for _, fl := range addrFlows(info, f.ast) {
			if fl.source {
				reportSource(fl.pos, fl.what)
			} else {
				report(fl.pos, fl.what)
			}
		}
	}
	sort.Strings(res.problems)
	return res
}

func TestNoCodeKeysAnythingOnTheNetworkOutsideTheRegistry(t *testing.T) {
	fset, files := parseRepo(t)
	info, ok := typeInfoReal(fset, files, "net/http", "net/netip", "net", "fmt", "log/slog", "encoding/json", "errors", "strings", "strconv", "context", "time")
	if !ok {
		t.Fatal("type information unavailable")
	}
	res := netCutProblems(fset, files, info, netCutAllowed)
	for _, p := range res.problems {
		t.Errorf("%s; a bucket keyed on the network is declared in internal/budget (a counter) and built by internal/throttle or internal/ratelimit; add a file to netCutAllowed only with a reason that is not a bucket", p)
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
	const httpHead = "package api\nimport (\n\t\"net\"\n\t\"net/http\"\n)\nvar _ net.IP\nvar _ http.Header\n"
	const fmtHead = "package api\nimport (\n\t\"fmt\"\n\t\"net\"\n\t\"net/http\"\n)\nvar _ net.IP\nvar _ http.Header\nvar _ = fmt.Sprint\n"
	const ipHead = "package api\nimport (\n\t\"net\"\n\t\"net/netip\"\n)\nvar _ net.IP\nvar _ netip.Addr\n"
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

		// Round 17, tenant-r17-7 and -10: a string made from a string that was handed over. The text of the peer and
		// of the headers is a root, so only a listed function ever holds it. Resolved against the real net/http.
		{name: "the peer of the connection as text (tenant-r17-10)", own: true, want: 1, src: httpHead + `
func f(r *http.Request) string { return r.RemoteAddr }`},
		{name: "the forwarded header, read by Get", own: true, want: 1, src: httpHead + `
func f(r *http.Request) string { return r.Header.Get("X-Forwarded-For") }`},
		{name: "the forwarded header, read by Values", own: true, want: 1, src: httpHead + `
func f(r *http.Request) []string { return r.Header.Values("X-Forwarded-For") }`},
		{name: "a method value of Header.Get", own: true, want: 1, src: httpHead + `
func f(r *http.Request) string { g := r.Header.Get; return g("X-Real-Ip") }`},
		{name: "a method expression of Header.Get", own: true, want: 1, src: httpHead + `
var g = http.Header.Get`},
		{name: "the forwarded header, read by index", own: true, want: 1, src: httpHead + `
func f(h http.Header) []string { return h["X-Forwarded-For"] }`},
		{name: "the headers, ranged over", own: true, want: 1, src: httpHead + `
func f(h http.Header) (n int) { for range h { n++ }; return }`},
		{name: "the peer of a connection (tenant-r17-10)", own: true, want: 1, src: httpHead + `
func f(c net.Conn) string { return c.RemoteAddr().String() }`},
		{name: "a wrapper that returns the peer: the definition fails, its caller does not", own: true, want: 1, src: httpHead + `
func peer(r *http.Request) string { return r.RemoteAddr }
func f(r *http.Request) string { return peer(r) }`},
		{name: "a request handed to a function is not a cut", own: true, want: 0, src: httpHead + `
func g(r *http.Request) bool { return r.Method == "GET" }
func f(r *http.Request) bool { return g(r) }`},
		{name: "headers written, not read", own: true, want: 0, src: httpHead + `
func f(r *http.Request) { r.Header.Set("X-A", "b"); r.Header.Del("X-A") }`},

		// Round 17, tenant-r17-15: the six shapes the fix gate planted round the list of spellings, and their siblings.
		// Each is judged by the TYPE of the value (a request, a header map, a peer address) and not by a name.
		{name: "the concrete peer of a *net.TCPConn handed to fmt (tenant-r17-15, 1)", own: true, want: 1, src: fmtHead + `
func f(c *net.TCPConn) string { return fmt.Sprint(c.RemoteAddr()) }`},
		{name: "a header converted to a plain map (tenant-r17-15, 2)", own: true, want: 1, src: httpHead + `
func f(h http.Header) []string { m := map[string][]string(h); return m["X-Forwarded-For"] }`},
		{name: "a header converted to textproto.MIMEHeader (tenant-r17-15, 3)", own: true, want: 1, src: "package api\nimport (\n\t\"net/http\"\n\t\"net/textproto\"\n)\nfunc f(h http.Header) string { return textproto.MIMEHeader(h).Get(\"X-Forwarded-For\") }"},
		{name: "the request written into a buffer (tenant-r17-15, 4)", own: true, want: 1, src: "package api\nimport (\n\t\"net/http\"\n\t\"strings\"\n)\nfunc f(r *http.Request) string { var sb strings.Builder; _ = r.Write(&sb); return sb.String() }"},
		{name: "the request rendered with %+v (tenant-r17-15, 5)", own: true, want: 1, src: fmtHead + `
func f(r *http.Request) string { return fmt.Sprintf("%+v", *r) }`},
		{name: "a request returned as any (tenant-r17-15, 6)", own: true, want: 1, src: httpHead + `
func f(r *http.Request) any { return r }`},
		{name: "the peer address as text, by the concrete method", own: true, want: 1, src: httpHead + `
func f(a *net.TCPAddr) string { return a.String() }`},
		{name: "the peer address of a packet, by the interface", own: true, want: 1, src: httpHead + `
func f(c net.PacketConn) string { _, a, _ := c.ReadFrom(nil); return a.String() }`},
		{name: "a member promoted from an embedded request", own: true, want: 1, src: httpHead + `
type wrapped struct{ *http.Request }
func f(w wrapped) string { return w.RemoteAddr }`},
		{name: "a header map moved into a plain map", own: true, want: 1, src: httpHead + `
func f(h http.Header) map[string][]string { return h }`},
		{name: "a header map converted to a type of our own", own: true, want: 1, src: httpHead + `
type vals map[string][]string
func f(h http.Header) vals { return vals(h) }`},
		{name: "a request converted to a type of our own", own: true, want: 1, src: httpHead + `
type mine http.Request
func f(r http.Request) mine { return mine(r) }`},
		{name: "a header map handed to a generic", own: true, want: 1, src: httpHead + `
func id[T any](v T) T { return v }
func f(h http.Header) http.Header { return id(h) }`},
		{name: "a net.Addr stays a net.Addr", own: true, want: 0, src: httpHead + `
func f(c net.Conn) (string, bool) { var a net.Addr = c.RemoteAddr(); return a.Network(), a != nil }`},
		{name: "the safe members of a request", own: true, want: 0, src: httpHead + `
func f(r *http.Request) (string, bool) { return r.Method + r.URL.Path, r.Context() != nil && r.Header != nil }`},
		{name: "a plain map[string][]string is not a source", own: true, want: 0, src: httpHead + `
func f(m map[string][]string) []string { return m["a"] }`},

		{name: "the headers handed to an interface (the context of Outbox)", own: true, want: 1, src: httpHead + `
func f(h http.Header) any { return h }`},
		{name: "the headers handed to a callee the checker cannot resolve", own: true, want: 1, src: "package api\nimport (\n\t\"net/http\"\n\t\"example.com/stub\"\n)\nfunc f(h http.Header) { stub.Use(h) }"},
		{name: "the headers handed to a typed parameter are not a cut", own: true, want: 0, src: httpHead + `
func g(h http.Header) int { return len(h) }
func f(h http.Header) int { return g(h) }`},
		{name: "only the client address is read", src: `func f(ctx context.Context) netip.Addr { return httpx.ClientIPFrom(ctx) }`, want: 1},
		{name: "parsing an address is not a cut", src: `func f(s string) { _, _ = netip.ParseAddr(s) }`, want: 1},
		// Round 18, tenant-r18-7: six ordinary-Go hand cuts that the list of forbidden method names let through. The
		// address types are sources of part 7 now: a closed list of the members that are safe, and no index, slice,
		// range or conversion of a net.IP.
		{name: "Addr.MarshalBinary then a cut of the bytes (tenant-r18-7, 1)", own: true, want: 1, src: ipHead + `
func f(a netip.Addr) string { b, _ := a.MarshalBinary(); return string(b[:3]) }`},
		{name: "Addr.AppendBinary (tenant-r18-7, 2)", own: true, want: 1, src: ipHead + `
func f(a netip.Addr) []byte { b, _ := a.AppendBinary(nil); return b }`},
		{name: "AddrPort.MarshalText (tenant-r18-7, 3)", own: true, want: 1, src: ipHead + `
func f(a netip.AddrPort) []byte { b, _ := a.MarshalText(); return b }`},
		{name: "Prefix.MarshalText (tenant-r18-7, 4)", own: true, want: 1, src: ipHead + `
func f(p netip.Prefix) []byte { b, _ := p.MarshalText(); return b }`},
		{name: "a slice of net.IP.To4 converted to a string (tenant-r18-7, 5)", own: true, want: 2, src: ipHead + `
func f(ip net.IP) string { return string(ip.To4()[:3]) }`},
		{name: "an index of a net.IP (tenant-r18-7, 6)", own: true, want: 1, src: ipHead + `
func f(ip net.IP) byte { return ip[0] }`},
		{name: "a net.IP ranged over", own: true, want: 1, src: ipHead + `
func f(ip net.IP) (n int) { for range ip { n++ }; return }`},
		{name: "a net.IP moved into a byte slice", own: true, want: 1, src: ipHead + `
func g(b []byte) int { return len(b) }
func f(ip net.IP) int { return g(ip) }`},
		{name: "a method value of a member that is not safe", own: true, want: 1, src: ipHead + `
func f(a netip.Addr) { g := a.MarshalText; _, _ = g() }`},
		{name: "a method expression of a member that is not safe", own: true, want: 1, src: ipHead + `
var g = netip.Prefix.MarshalBinary`},
		{name: "the safe members of the address types", own: true, want: 0, src: ipHead + `
func f(a netip.Addr, p netip.Prefix, ap netip.AddrPort, ip net.IP) bool {
	return a.Is4() && a.Unmap().IsValid() && p.Contains(a) && p.Addr().IsLoopback() && ap.Addr().IsValid() && ap.Port() > 0 && ip.IsLoopback() && ip.Equal(ip.To16()) && len(ip) == 4
}`},
		// Round 18 fix gate, tenant-r18-17: a place whose type the checker could not resolve (here encoding, which the
		// importer of this test does not read, and a library it stubs) may be an interface with MarshalText or
		// MarshalBinary. A value that carries an address going there fails closed, whatever the package.
		{name: "an address in an encoding.TextMarshaler (tenant-r18-17)", own: true, want: 1, src: "package api\nimport (\n\t\"encoding\"\n\t\"net/netip\"\n)\n" + `
func f(a netip.Addr) []byte { var m encoding.TextMarshaler = a; b, _ := m.MarshalText(); return b[:3] }`},
		{name: "an address handed to an encoding.BinaryMarshaler parameter", own: true, want: 1, src: "package api\nimport (\n\t\"encoding\"\n\t\"net/netip\"\n)\nfunc g(m encoding.BinaryMarshaler) {}\nfunc f(a netip.Addr) { g(a) }"},
		{name: "an address returned as an encoding.TextMarshaler", own: true, want: 1, src: "package api\nimport (\n\t\"encoding\"\n\t\"net/netip\"\n)\nfunc f(p netip.Prefix) encoding.TextMarshaler { return p }"},
		{name: "an address in a field of an unresolved interface type", own: true, want: 1, src: "package api\nimport (\n\t\"example.com/stub\"\n\t\"net/netip\"\n)\ntype box struct{ m stub.Marshaler }\nfunc f(a netip.AddrPort) box { return box{m: a} }"},
		{name: "a typed place of the resolved kind is still no cut", own: true, want: 0, src: "package api\nimport (\n\t\"encoding\"\n\t\"net/netip\"\n)\nvar _ encoding.TextMarshaler\nfunc f(a netip.Addr) bool { return a.Is4() }"},
		{name: "a resolved Mask that is not net.IP.Mask", src: `type phone struct{}
func (phone) Mask(string) string { return "" }
func f(p phone) { _ = p.Mask("0912") }`, want: 1},
	}
	allowed := map[string]string{
		"internal/netkey/netkey.go#Net":        "the definition",
		"internal/netkey/netkey.go#Wide":       "the definition",
		"internal/httpx/middleware.go#Subject": "Subject",
	}
	for _, c := range cases {
		fset := token.NewFileSet()
		src := c.src
		if !c.own {
			src = pre + src
		}
		files := netCutCorpus(t, fset, src)
		info, ok := typeInfoReal(fset, files, "net/http", "net/netip", "net", "fmt", "log/slog", "encoding/json", "errors", "strings", "strconv", "context", "time")
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
	if isAddrType(t) || isPeerAddr(t) {
		return 2
	}
	if isHeaderMap(t) {
		// A header map holds X-Forwarded-For, the address of the client as text, whatever it is called: a Header, a
		// MIMEHeader, a plain map made by converting one (round 17, tenant-r17-15).
		return 1
	}
	hold := func(l int) int {
		if l > 0 {
			return 1
		}
		return 0
	}
	switch t := t.(type) {
	case *types.Named:
		if t.Obj().Pkg() != nil && t.Obj().Pkg().Path() == "net/http" {
			// A response or a server reaches an address only through a member part 6 judges, and its certificates and
			// its TLS state hold addresses nobody keys on, so these are not judged by value. A REQUEST is: it holds
			// the peer and the headers, and %+v of it prints both, so it is judged like a struct that holds an
			// address and may not become a value of interface type, or go to a callee the checker cannot read.
			if t.Obj().Name() == "Request" {
				return 1
			}
			return 0
		}
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
	pos    token.Pos
	what   string
	source bool // the value is a source of the client address as text (part 6), not an address
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
// later, or a string built by another party from a string it was given. Escape hatches (a reflection walk
// among them) are judged once, by the escape-hatch ban (capabilities_test.go).
func addrFlows(info *types.Info, f *ast.File) []addrFlow {
	var out []addrFlow
	var stack []ast.Node
	lvl := 0  // the level of the value being judged
	src := "" // its source kind (part 6), "" when it is not one
	add := func(n ast.Node, what string) { out = append(out, addrFlow{n.Pos(), what, src != ""}) }
	sink := func(e ast.Node, t types.Type, what string) {
		// A peer address that becomes a net.Addr stays what it is: every member of it is judged where it is used.
		if src == "peer" && sourceKind(t) == "peer" {
			return
		}
		// A source that moves into a place of a type that is not a source of its kind (a header map into a plain
		// map[string][]string, a url.Values or a type of our own, a request into a struct) loses the member
		// allow list: the place has a method set the lint does not judge. Comparisons and map keys move nothing.
		if src != "" && t != nil && what != "a comparison" && what != "a map key" && sourceKind(t) != src &&
			!types.IsInterface(t) && !isTypeParam(t) && t.Underlying() != types.Typ[types.Invalid] {
			add(e, "moves a "+src+", which can show the address of a client as text, into "+what+" of a type that is not one, so its members are no longer judged")
		}
		// A place whose type did not resolve (a standard package the checker stubs, such as encoding, or shared/) may be an
		// interface with MarshalText or MarshalBinary, which is how the text of an address is reached through it. The
		// lint cannot show it is not one, so a value that carries an address going there fails closed, whatever the
		// package is (tenant-r18-17: the first form judged only the interfaces it could see).
		if lvl > 0 && t != nil && t.Underlying() == types.Typ[types.Invalid] {
			add(e, "hands an address to "+what+" whose type the checker could not resolve (a package it stubs), which may be an interface that renders it as text")
		}
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
			lvl, src = addrLevel(tup.At(i).Type()), sourceKind(tup.At(i).Type())
			sink(e, places[i], what)
		}
	}
	judge := func(e ast.Expr) {
		parent := stack[len(stack)-2]
		lvl, src = addrLevel(info.TypeOf(e)), sourceKind(info.TypeOf(e))
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
					src = sourceKind(inst.TypeArgs.At(i))
					if addrLevel(inst.TypeArgs.At(i)) == 2 || src != "" {
						add(n, "instantiates a generic with an address or a source of one, which its body sees as a type parameter and can render or read")
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

// TestNetworkCutAllowListIsByFunction is tenant-r17-9. The unit of the allow list is a function: a cut in a
// sibling function of a listed one, in the same file, is a problem; a listed function that no longer cuts is not
// marked used (the real test turns that into an error); a literal inside a listed function belongs to it; and
// a package-level initialiser is its own unit.
func TestNetworkCutAllowListIsByFunction(t *testing.T) {
	root := repoRoot(t)
	real, err := os.ReadFile(filepath.Join(root, "internal", "netkey", "netkey.go"))
	if err != nil {
		t.Fatal(err)
	}
	run := func(httpxSrc string, allowed map[string]string) netCutResult {
		fset := token.NewFileSet()
		var files []file
		for path, text := range map[string]string{"internal/netkey/netkey.go": string(real), "internal/httpx/middleware.go": httpxSrc} {
			f, err := parser.ParseFile(fset, path, text, parser.ParseComments)
			if err != nil {
				t.Fatalf("%s: %v", path, err)
			}
			files = append(files, file{path: path, ast: f})
		}
		info, ok := typeInfoReal(fset, files, "net/http", "net/netip", "net", "fmt", "context", "errors", "strings", "strconv", "time", "log/slog", "encoding/json")
		if !ok {
			t.Fatal("no type information")
		}
		return netCutProblems(fset, files, info, allowed)
	}
	const head = "package httpx\nimport (\n\t\"net/netip\"\n\t\"github.com/Kup1ng/CtrlZ-Panel/internal/netkey\"\n)\n"
	base := map[string]string{
		"internal/netkey/netkey.go#Net":        "the definition",
		"internal/netkey/netkey.go#Wide":       "the definition",
		"internal/httpx/middleware.go#Subject": "listed",
	}
	listed := head + "func Subject(a netip.Addr) string { f := func() string { return netkey.Net(a) }; return f() }\n"
	if res := run(listed, base); len(res.problems) != 0 || !res.used["internal/httpx/middleware.go#Subject"] {
		t.Errorf("the listed function, with a literal that cuts, = %v used %v, want clean and used", res.problems, res.used)
	}
	if res := run(listed+"func Other(a netip.Addr) string { return netkey.Net(a) }\n", base); len(res.problems) == 0 {
		t.Error("a cut in a sibling function of a listed one, in the same file, passed")
	}
	if res := run(listed+"var key = netkey.Net\n", base); len(res.problems) == 0 {
		t.Error("a cut in a package-level initialiser of a file with a listed function passed")
	}
	if res := run(head+"func Subject(a netip.Addr) bool { return a.IsValid() }\n", base); res.used["internal/httpx/middleware.go#Subject"] {
		t.Error("a listed function that does not cut was marked used, so the stale entry would not be reported")
	}
}
