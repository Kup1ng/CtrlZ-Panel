package lint_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"sort"
	"strings"
	"testing"
)

// Rule sms-failure-classification, round 12 (sms-r12-1): a reply body reaches a driver only
// through smshttp.Do, because that is where Normalize removes the byte order mark, the line
// breaks and the UTF-16 dress of a body. A driver that made its own request, or read a body
// itself, would read a BOM-prefixed accepted reply as a failure and the router would send the
// code again through the other gateway.
//
// Round 14 (sms-r14-1, sms-r14-3) changed WHAT IS SCANNED and WHAT A DRIVER MAY NAME. Until then
// the lint judged net/http objects in the files under internal/sms except five named
// directories, so a driver that dialled with net or crypto/tls, a driver kept in senders or
// noop, and a driver placed outside internal/sms were not read at all, and every rule below was
// about spellings of net/http. Now:
//
//   - the scope is every package that can reach a gateway: everything under internal/sms except
//     the one HTTP layer, the package of every type that has the Provider, Send and Balance
//     methods of sms.Sender wherever it is declared, and everything those import inside this
//     module, transitively;
//   - a scoped package reaches the network only through smshttp: no import of net, crypto/tls or
//     any other net/ or crypto/tls/ package except the ones that only describe a request, no
//     os/exec, syscall, unsafe, plugin or cgo, no third-party package in a driver except the ones
//     listed with a reason (an allow list: a new one is a diff a reviewer reads), and no
//     go:linkname;
//   - the client is *smshttp.Client, which is opaque (it has no field or method to set, and a
//     test in smshttp keeps it so), so the net/http types behind it are not named at all: no
//     http.Client, http.Transport or http.RoundTripper in any form, with no exception for a
//     pointer.
//
// The round 13 rules stay, judged by types and not by spelling: no http.DefaultClient or
// http.DefaultTransport, no http.Get, Post, PostForm or Head, no method of a client, a transport
// or a round tripper whatever its receiver is called, no value or type that holds an
// *http.Response (so an interface of a driver's own with a Do that returns one is refused where it
// is declared), and no read of the Body of an http.Response. The round 12 call named ReadAll
// stays as a second net.
const httpPkg = "net/http"

// smsHTTPLayer is the one package that builds a client, dials and reads a body.
const smsHTTPLayer = "internal/sms/smshttp"

// smsNetAllowed are the net family packages a scoped package may import: they describe a
// request, a URL or an address and cannot open a connection.
var smsNetAllowed = map[string]string{
	"net/http":  "builds a request, sets a header and reads a status; never a client (the lint refuses that)",
	"net/url":   "a form body and an escaped query",
	"net/netip": "parsing an address without the network",
}

// smsThirdParty are the third-party packages a gateway package may import, each with the reason.
// An allow list that fails closed: a library that dials, or one that wraps a client, is a package
// nobody listed here.
var smsThirdParty = map[string]string{
	"github.com/google/uuid": "identifiers of a gateway and of a message; no I/O",
}

// smsAlwaysForbidden are the packages no scoped package imports at all.
var smsAlwaysForbidden = map[string]string{
	"os/exec":     "starts a process that could carry a request",
	"syscall":     "opens a socket without the dial guard",
	"unsafe":      "reaches the unexported client behind smshttp.Client",
	"plugin":      "loads code the lint has not read",
	"C":           "cgo links code the lint has not read",
	"runtime/cgo": "cgo",
}

// smsNetFamily says whether an import path is one that can open a connection or wrap one.
func smsNetFamily(p string) bool {
	return p == "net" || strings.HasPrefix(p, "net/") || p == "crypto/tls" || strings.HasPrefix(p, "crypto/tls/") ||
		strings.HasPrefix(p, "golang.org/x/net") || strings.HasPrefix(p, "golang.org/x/sys")
}

// httpObj returns the net/http object an identifier uses, or nil.
func httpObj(info *types.Info, id *ast.Ident) types.Object {
	obj := info.Uses[id]
	if obj == nil || obj.Pkg() == nil || obj.Pkg().Path() != httpPkg {
		return nil
	}
	return obj
}

// httpNamed returns the name of the net/http type t is, through pointers and aliases, or "".
func httpNamed(t types.Type) string {
	for {
		t = types.Unalias(t)
		p, ok := t.(*types.Pointer)
		if !ok {
			break
		}
		t = p.Elem()
	}
	n, ok := t.(*types.Named)
	if !ok || n.Obj().Pkg() == nil || n.Obj().Pkg().Path() != httpPkg {
		return ""
	}
	return n.Obj().Name()
}

// holdsHTTPResponse reports whether t is, or has as a result, a net/http Response.
func holdsHTTPResponse(t types.Type) bool {
	switch x := types.Unalias(t).(type) {
	case *types.Tuple:
		for i := 0; i < x.Len(); i++ {
			if holdsHTTPResponse(x.At(i).Type()) {
				return true
			}
		}
		return false
	case *types.Signature:
		return holdsHTTPResponse(x.Results())
	}
	return httpNamed(t) == "Response"
}

// smsSenderMethods are the methods that make a type an sms.Sender. They are judged by name and not
// by types.Implements, so a signature that did not resolve (a fake third-party package under the
// loose type checker) cannot hide an implementer.
var smsSenderMethods = []string{"Provider", "Send", "Balance"}

// reflectPkg is the one standard package that can reach the unexported client behind
// smshttp.Client without unsafe, syscall or linkname (sms-r15-2): reflect.Value.UnsafePointer works
// on an unexported pointer field, and reflect.NewAt turns that pointer into a writable value, from
// which Transport, TLSClientConfig.InsecureSkipVerify, DialContext, Proxy and CheckRedirect can all
// be set. The opaque type of round 14 is only as closed as every way around it, and this was the
// way nobody had judged.
const reflectPkg = "reflect"

// reflectEscapes are the members of reflect that give a value its memory back after the type system
// took it away: a function that builds a writable value over a raw pointer, and the methods that
// hand out a raw pointer or address of a value, whatever its visibility. A scoped package uses none
// of them, with no exception for a reviewed package (internal/closed reads kinds and elements and
// needs none).
func reflectEscape(o types.Object) (string, bool) {
	if o == nil || o.Pkg() == nil || o.Pkg().Path() != reflectPkg {
		return "", false
	}
	fn, ok := o.(*types.Func)
	if !ok {
		return "", false
	}
	sig, _ := fn.Type().(*types.Signature)
	if sig == nil {
		return "", false
	}
	switch {
	case sig.Recv() == nil && fn.Name() == "NewAt":
		return "reflect.NewAt", true
	case sig.Recv() != nil && (fn.Name() == "UnsafePointer" || fn.Name() == "UnsafeAddr" || fn.Name() == "Pointer"):
		return "reflect.Value." + fn.Name(), true
	}
	return "", false
}

// holdsSMSClient reports whether a value of type t is, points to or contains (in any field, element
// or key, to a bounded depth) a smshttp.Client. A reflect call over such a value is a way to walk
// into the client, and no scoped package has a reason to hand one to reflect.
func holdsSMSClient(t types.Type, seen map[types.Type]bool, depth int) bool {
	if t == nil || depth > 6 || seen[t] {
		return false
	}
	seen[t] = true
	switch x := types.Unalias(t).(type) {
	case *types.Pointer:
		return holdsSMSClient(x.Elem(), seen, depth+1)
	case *types.Slice:
		return holdsSMSClient(x.Elem(), seen, depth+1)
	case *types.Array:
		return holdsSMSClient(x.Elem(), seen, depth+1)
	case *types.Map:
		return holdsSMSClient(x.Key(), seen, depth+1) || holdsSMSClient(x.Elem(), seen, depth+1)
	case *types.Chan:
		return holdsSMSClient(x.Elem(), seen, depth+1)
	case *types.Named:
		if x.Obj().Name() == "Client" && x.Obj().Pkg() != nil && strings.HasSuffix(x.Obj().Pkg().Path(), "/"+smsHTTPLayer) {
			return true
		}
		return holdsSMSClient(x.Underlying(), seen, depth+1)
	case *types.Struct:
		for i := 0; i < x.NumFields(); i++ {
			if holdsSMSClient(x.Field(i).Type(), seen, depth+1) {
				return true
			}
		}
	}
	return false
}

// callee returns the function a call expression names, through a selector, or nil.
func callee(info *types.Info, call *ast.CallExpr) *types.Func {
	var id *ast.Ident
	switch f := call.Fun.(type) {
	case *ast.Ident:
		id = f
	case *ast.SelectorExpr:
		id = f.Sel
	default:
		return nil
	}
	fn, _ := info.Uses[id].(*types.Func)
	return fn
}

// smsScope returns the directories the rule reads, with why each is in. The HTTP layer never is.
func smsScope(files []file, info *types.Info) map[string]string {
	scope := map[string]string{}
	imports := map[string][]string{} // directory to the module directories it imports, non-test code
	for _, f := range files {
		if f.test {
			continue
		}
		dir := f.path[:strings.LastIndex(f.path, "/")]
		for _, im := range f.ast.Imports {
			if p := strings.Trim(im.Path.Value, `"`); strings.HasPrefix(p, module+"/") {
				imports[dir] = append(imports[dir], strings.TrimPrefix(p, module+"/"))
			}
		}
		if (dir == "internal/sms" || strings.HasPrefix(dir, "internal/sms/")) && dir != smsHTTPLayer {
			scope[dir] = "under internal/sms"
		}
	}
	// Every type that has the Sender methods, wherever it is declared.
	for _, o := range info.Defs {
		tn, ok := o.(*types.TypeName)
		if !ok || tn.Pkg() == nil || tn.IsAlias() || !strings.HasPrefix(tn.Pkg().Path(), module+"/") {
			continue
		}
		if _, isIface := tn.Type().Underlying().(*types.Interface); isIface {
			continue
		}
		ms := types.NewMethodSet(types.NewPointer(tn.Type()))
		all := true
		for _, m := range smsSenderMethods {
			if ms.Lookup(tn.Pkg(), m) == nil {
				all = false
			}
		}
		dir := strings.TrimPrefix(tn.Pkg().Path(), module+"/")
		if _, in := scope[dir]; all && !in && dir != smsHTTPLayer {
			scope[dir] = "declares " + tn.Name() + ", which has the methods of sms.Sender"
		}
	}
	// What a scoped package imports inside the module, transitively, runs in a gateway call too.
	queue := make([]string, 0, len(scope))
	for d := range scope {
		queue = append(queue, d)
	}
	sort.Strings(queue)
	for len(queue) > 0 {
		d := queue[0]
		queue = queue[1:]
		for _, im := range imports[d] {
			if _, in := scope[im]; !in && im != smsHTTPLayer {
				scope[im] = "imported by " + d + ", so reachable from a gateway call"
				queue = append(queue, im)
			}
		}
	}
	return scope
}

func smsBodyProblems(fset *token.FileSet, files []file, info *types.Info) (problems []string, scanned map[string]bool) {
	scope := smsScope(files, info)
	scanned = map[string]bool{}
	for _, f := range files {
		if f.test {
			continue
		}
		dir := f.path[:strings.LastIndex(f.path, "/")]
		why, in := scope[dir]
		if !in {
			continue
		}
		scanned[dir] = true
		// The third-party allow list holds for a package that is a gateway by itself (under
		// internal/sms or declaring a sender). A package that is only reachable from one is held
		// to the net rules, and its other libraries are judged by imports.yaml.
		strictThird := strings.HasPrefix(why, "under internal/sms") || strings.HasPrefix(why, "declares ")
		add := func(pos token.Pos, msg string) {
			problems = append(problems, fmt.Sprintf("%s: %s (rule sms-failure-classification, sms-r13-1, sms-r14-1, sms-r14-3, sms-r15-2)", fset.Position(pos), msg))
		}
		for _, im := range f.ast.Imports {
			p := strings.Trim(im.Path.Value, `"`)
			switch {
			case p == reflectPkg && strictThird:
				add(im.Pos(), "a gateway package imports reflect, which reaches the unexported client behind smshttp.Client (UnsafePointer and NewAt give a writable *http.Client) and can switch off TLS verification, the dial guard or the redirect refusal; a gateway has no use for it")
			case smsAlwaysForbidden[p] != "":
				add(im.Pos(), "a package a gateway call can reach imports "+p+" ("+smsAlwaysForbidden[p]+"); the network is smshttp's")
			case smsNetFamily(p):
				if _, ok := smsNetAllowed[p]; !ok {
					add(im.Pos(), "a package a gateway call can reach imports "+p+", which can open a connection of its own and skip the fixed-host dial guard, TLS verification, no redirect, no proxy and smshttp.Normalize; use smshttp")
				}
			case !strings.HasPrefix(p, module+"/") && strings.Contains(strings.SplitN(p, "/", 2)[0], "."):
				if _, ok := smsThirdParty[p]; !ok && strictThird {
					add(im.Pos(), "a gateway package imports "+p+", which is not in smsThirdParty; a library here may dial, so list it with the reason")
				}
			}
		}
		for _, cg := range f.ast.Comments {
			for _, c := range cg.List {
				if strings.HasPrefix(c.Text, "//go:linkname") {
					add(c.Pos(), "a package a gateway call can reach uses go:linkname, which reaches what the type system hides")
				}
			}
		}
		ast.Inspect(f.ast, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok {
				if what, bad := reflectEscape(info.Uses[id]); bad {
					add(id.Pos(), "a package a gateway call can reach uses "+what+", which gives back the memory of a value the type system hid (the opaque smshttp.Client included); no scoped package needs it")
				}
			}
			if call, ok := n.(*ast.CallExpr); ok {
				if fn := callee(info, call); fn != nil && fn.Pkg() != nil && fn.Pkg().Path() == reflectPkg {
					for _, a := range call.Args {
						if tv, ok := info.Types[a]; ok && holdsSMSClient(tv.Type, map[types.Type]bool{}, 0) {
							add(a.Pos(), "a value that holds an smshttp.Client is handed to reflect; the client is opaque so that nothing can set what is behind it")
						}
					}
				}
			}
			switch x := n.(type) {
			case *ast.Ident:
				switch o := httpObj(info, x).(type) {
				case *types.Func:
					if sig, _ := o.Type().(*types.Signature); sig != nil && sig.Recv() == nil {
						switch o.Name() {
						case "Get", "Post", "PostForm", "Head":
							add(x.Pos(), "a driver sends with http."+o.Name()+" on the default client; send with smshttp.Do on a client from smshttp.NewClient")
						}
					}
				case *types.Var:
					if !o.IsField() && (o.Name() == "DefaultClient" || o.Name() == "DefaultTransport") {
						add(x.Pos(), "a driver uses http."+o.Name()+", which has no dial guard and follows redirects; hold a *smshttp.Client")
					}
				case *types.TypeName:
					switch o.Name() {
					case "Client", "Transport", "RoundTripper":
						add(x.Pos(), "a driver names http."+o.Name()+"; the client is *smshttp.Client, which is opaque so that its fixed-host dial guard, TLS verification, no redirect and no proxy cannot be changed")
					}
				}
			case *ast.SelectorExpr:
				if sel := info.Selections[x]; sel != nil {
					switch sel.Kind() {
					case types.MethodVal, types.MethodExpr:
						if fn, ok := sel.Obj().(*types.Func); ok {
							if sig, _ := fn.Type().(*types.Signature); sig != nil && sig.Recv() != nil {
								switch httpNamed(sig.Recv().Type()) {
								case "Client", "Transport", "RoundTripper":
									add(x.Pos(), "a driver calls "+fn.Name()+" of an http client or transport; the request goes through smshttp.Do, which normalises the reply")
								}
							}
						}
					case types.FieldVal:
						if v, ok := sel.Obj().(*types.Var); ok && v.Name() == "Body" && httpNamed(sel.Recv()) == "Response" {
							add(x.Pos(), "a driver reads the Body of an http.Response; the body of a reply comes from smshttp.Do")
						}
					}
				}
			}
			if e, ok := n.(ast.Expr); ok {
				if tv, ok := info.Types[e]; ok && tv.Type != nil && holdsHTTPResponse(tv.Type) {
					add(e.Pos(), "a driver holds an *http.Response; only smshttp.Do sees one")
				}
			}
			// The round 12 spelling, kept as a second net. Only a package that names net/http can
			// have a reply body to read; a package that never imports it may read what it likes.
			if call, ok := n.(*ast.CallExpr); ok && importsPath(f.ast, httpPkg) {
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "ReadAll" {
					add(call.Pos(), "a driver reads a body itself; the body of a reply comes from smshttp.Do")
				}
			}
			return true
		})
	}
	sort.Strings(problems)
	return dedupe(problems), scanned
}

func importsPath(f *ast.File, path string) bool {
	for _, im := range f.Imports {
		if strings.Trim(im.Path.Value, `"`) == path {
			return true
		}
	}
	return false
}

func TestSMSDriversReadRepliesOnlyThroughSmshttp(t *testing.T) {
	fset, files := parseRepo(t)
	info, ok := typeInfoReal(fset, files, httpPkg, reflectPkg)
	if !ok {
		t.Fatal("type information unavailable")
	}
	problems, scanned := smsBodyProblems(fset, files, info)
	for _, p := range problems {
		t.Error(p)
	}
	for _, want := range []string{"internal/sms/smsir", "internal/sms/melipayamak", "internal/sms/noop", "internal/sms/senders", "internal/sms"} {
		if !scanned[want] {
			t.Errorf("%s was not scanned; the lint is not looking at the gateway packages", want)
		}
	}
	if scanned[smsHTTPLayer] {
		t.Errorf("%s was scanned; it is the one place that may build a client and dial", smsHTTPLayer)
	}
	// The exemption must name a package that exists, or it names nothing.
	found := false
	for _, f := range files {
		if strings.HasPrefix(f.path, smsHTTPLayer+"/") && !f.test {
			found = true
		}
	}
	if !found {
		t.Errorf("%s has no source file; the exemption of the lint names nothing", smsHTTPLayer)
	}
	// An allow list entry no gateway package imports is a free pass kept for later: it fails.
	used := map[string]bool{}
	for _, f := range files {
		if f.test || !scanned[f.path[:strings.LastIndex(f.path, "/")]] {
			continue
		}
		for _, im := range f.ast.Imports {
			used[strings.Trim(im.Path.Value, `"`)] = true
		}
	}
	for p := range smsThirdParty {
		if !used[p] {
			t.Errorf("smsThirdParty lists %s, which no gateway package imports; remove it", p)
		}
	}
	for p := range smsNetAllowed {
		if !used[p] {
			t.Errorf("smsNetAllowed lists %s, which no gateway package imports; remove it", p)
		}
	}
}

const stubSmshttp = `package smshttp
import ("net/http"; "net"; "crypto/tls")
var _ = net.Dial
var _ = tls.Dial
type Options struct{}
type Client struct{ c *http.Client }
type Response struct {
	Status int
	Body   []byte
}
func NewClient(hostPort string, o Options) *Client { return nil }
func Do(c *Client, r *http.Request) (Response, error) { return Response{}, nil }
`

// planted is one more file of a case, in its own directory.
type planted struct{ path, src string }

// TestSMSBodyLintCanFail plants every way a driver can leave smshttp: each spelling of a send on
// a client, a transport or the default client, each way to read a body, a client built by hand in
// every form, an interface of the driver's own, a package that opens its own connection by an
// import, a library nobody listed, and a gateway kept where the lint used to look for none (a
// directory it exempted, one outside internal/sms, a type that only has the Sender methods). The
// clean uses must pass.
//
// What no case can plant is a write to a field of the client smshttp.NewClient returns
// (c.Transport...InsecureSkipVerify, c.CheckRedirect = nil, a DialContext, a Proxy): the type has
// none, so the line does not compile. That half is TestClientHasNothingToSet in smshttp. The same
// writes through a *http.Client are cases below, refused by the name of the type.
func TestSMSBodyLintCanFail(t *testing.T) {
	const d = "internal/sms/newdrv/d.go"
	cases := []struct {
		name, path, src string
		extra           []planted
		want            int // findings, at least; 0 means none
	}{
		{"a driver's own client call", d, `func f(c *http.Client, r *http.Request) { c.Do(r) }`, nil, 1},
		{"a driver's own read", d, `func f(b io.Reader) { io.ReadAll(b) }`, nil, 1},
		{"Post on a client", d, `func f(c *http.Client) { c.Post("u", "t", nil) }`, nil, 1},
		{"PostForm on a client", d, `func f(c *http.Client) { c.PostForm("u", nil) }`, nil, 1},
		{"Get on a client", d, `func f(c *http.Client) { c.Get("u") }`, nil, 1},
		{"Head on a client", d, `func f(c *http.Client) { c.Head("u") }`, nil, 1},
		{"a method value of a client", d, `func f(c *http.Client) { g := c.Post; _ = g }`, nil, 1},
		{"RoundTrip on a transport", d, `func f(t *http.Transport, r *http.Request) { t.RoundTrip(r) }`, nil, 1},
		{"RoundTrip on a round tripper", d, `func f(t http.RoundTripper, r *http.Request) { t.RoundTrip(r) }`, nil, 1},
		{"io.Copy over a response body", d, `func f(resp *http.Response) { io.Copy(nil, resp.Body) }`, nil, 1},
		{"a decoder over a response body", d, `func f(resp *http.Response) { json.NewDecoder(resp.Body) }`, nil, 1},
		{"a Read of a response body", d, `func f(resp *http.Response) { resp.Body.Read(nil) }`, nil, 1},
		{"a client literal", d, `var c = &http.Client{}`, nil, 1},
		{"a client value", d, `var c http.Client`, nil, 1},
		{"new of a client", d, `var c = new(http.Client)`, nil, 1},
		{"a transport literal", d, `var t = &http.Transport{}`, nil, 1},
		{"a client through an alias", d, `type cl = http.Client
var c cl`, nil, 1},
		{"an embedded client value", d, `type d struct{ http.Client }`, nil, 1},
		{"an embedded client pointer, then a call", d, `type d struct{ *http.Client }
func f(x d, r *http.Request) { x.Do(r) }`, nil, 1},
		{"the default client", d, `func f() { _ = http.DefaultClient }`, nil, 1},
		{"the default transport", d, `func f() { _ = http.DefaultTransport }`, nil, 1},
		{"a package level Get", d, `func f() { http.Get("u") }`, nil, 1},
		{"an interface of the driver's own that returns a response", d, `type doer interface{ Do(*http.Request) (*http.Response, error) }
func f(d doer, r *http.Request) { d.Do(r) }`, nil, 1},

		// sms-r14-3: the four field writes of the finding, and a pointer to a client, which was
		// the one use of the type names the lint allowed.
		{"TLS verification turned off through the transport", d, `func f(c *http.Client) { c.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify = true }`, nil, 1},
		{"the dial guard removed", d, `func f(c *http.Client) { c.Transport.(*http.Transport).DialContext = nil }`, nil, 1},
		{"the redirect refusal removed", d, `func f(c *http.Client) { c.CheckRedirect = nil }`, nil, 1},
		{"the environment's proxy put back", d, `func f(c *http.Client) { c.Transport.(*http.Transport).Proxy = http.ProxyFromEnvironment }`, nil, 1},
		{"a type assertion on a client of unwritten type", d, `func f() { c := smshttp.NewClient("h", smshttp.Options{}); _ = c; var a any; a.(*http.Transport).DialContext = nil }`, nil, 1},
		{"a pointer to a client", d, `type D struct{ client *http.Client }`, nil, 1},

		// sms-r14-1: a connection of the package's own.
		{"net", d, `import _ "net"`, nil, 1},
		{"crypto/tls", d, `import _ "crypto/tls"`, nil, 1},
		{"net/http/httptrace", d, `import _ "net/http/httptrace"`, nil, 1},
		{"net/http/httputil", d, `import _ "net/http/httputil"`, nil, 1},
		{"net/rpc", d, `import _ "net/rpc"`, nil, 1},
		{"net/smtp", d, `import _ "net/smtp"`, nil, 1},
		{"os/exec", d, `import _ "os/exec"`, nil, 1},
		{"syscall", d, `import _ "syscall"`, nil, 1},
		{"unsafe", d, `import _ "unsafe"`, nil, 1},
		{"plugin", d, `import _ "plugin"`, nil, 1},
		{"x/net", d, `import _ "golang.org/x/net/proxy"`, nil, 1},
		{"a library nobody listed", d, `import _ "github.com/go-resty/resty/v2"`, nil, 1},
		{"go:linkname", d, "//go:linkname x y\nvar x int", nil, 1},

		// Where the gateway is: directories the lint used to exempt, one outside internal/sms,
		// what a gateway imports, and a type that only has the Sender methods.
		{"a client in senders", "internal/sms/senders/d.go", `var c = &http.Client{}`, nil, 1},
		{"a connection in noop", "internal/sms/noop/d.go", `import _ "net"`, nil, 1},
		{"a connection in the router package", "internal/sms/d.go", `import _ "crypto/tls"`, nil, 1},
		{"a connection in a package a gateway imports", "internal/sms/senders/s.go", `import _ "` + module + `/internal/elsewhere"`,
			[]planted{{"internal/elsewhere/e.go", `import _ "net"`}}, 1},
		{"a connection two imports away", "internal/sms/senders/s.go", `import _ "` + module + `/internal/elsewhere"`,
			[]planted{{"internal/elsewhere/e.go", `import _ "` + module + `/internal/deeper"`}, {"internal/deeper/e.go", `import _ "crypto/tls"`}}, 1},
		{"a gateway outside internal/sms", "internal/elsewhere/g.go", `import _ "net"
type G struct{}
func (G) Provider() string { return "" }
func (G) Send() {}
func (G) Balance() {}`, nil, 1},
		{"a gateway outside internal/sms that makes its own client", "internal/elsewhere/g.go", `var c = &http.Client{}
type G struct{}
func (G) Provider() string { return "" }
func (G) Send() {}
func (G) Balance() {}`, nil, 1},
		{"a gateway that gets its methods from an embedded one", "internal/elsewhere/g.go", `import _ "net"
type base struct{}
func (base) Provider() string { return "" }
func (base) Send() {}
func (base) Balance() {}
type G struct{ base }`, nil, 1},

		// sms-r15-2: reflect reaches the unexported client without unsafe. A gateway package has no
		// use for reflect at all; a package a gateway only imports may read kinds and elements (as
		// internal/closed does) but may not take a raw pointer or build a writable value over one,
		// or hand a client to reflect.
		{"reflect imported by a gateway", d, `import "reflect"
func f(v any) bool { return reflect.TypeOf(v).Kind() == reflect.String }`, nil, 1},
		{"the NewAt sequence of the finding, in a gateway", d, `import "reflect"
type D struct{ client *smshttp.Client }
func f(d *D) {
	f0 := reflect.ValueOf(d.client).Elem().Field(0)
	w := reflect.NewAt(f0.Type().Elem(), f0.UnsafePointer())
	w.Elem().FieldByName("Transport").Elem().Elem().FieldByName("TLSClientConfig").Elem().FieldByName("InsecureSkipVerify").SetBool(true)
}`, nil, 3},
		{"NewAt in a package a gateway imports", "internal/sms/senders/s.go", `import _ "` + module + `/internal/elsewhere"`,
			[]planted{{"internal/elsewhere/e.go", `import "reflect"
func f(t reflect.Type) { _ = reflect.NewAt(t, nil) }`}}, 1},
		{"UnsafePointer in a package a gateway imports", "internal/sms/senders/s.go", `import _ "` + module + `/internal/elsewhere"`,
			[]planted{{"internal/elsewhere/e.go", `import "reflect"
func f(v reflect.Value) { _ = v.UnsafePointer() }`}}, 1},
		{"UnsafeAddr in a package a gateway imports", "internal/sms/senders/s.go", `import _ "` + module + `/internal/elsewhere"`,
			[]planted{{"internal/elsewhere/e.go", `import "reflect"
func f(v reflect.Value) { _ = v.UnsafeAddr() }`}}, 1},
		{"Pointer in a package a gateway imports", "internal/sms/senders/s.go", `import _ "` + module + `/internal/elsewhere"`,
			[]planted{{"internal/elsewhere/e.go", `import "reflect"
func f(v reflect.Value) { _ = v.Pointer() }`}}, 1},
		{"reflect.ValueOf on a client in a package a gateway imports", "internal/sms/senders/s.go", `import _ "` + module + `/internal/elsewhere"`,
			[]planted{{"internal/elsewhere/e.go", `import "reflect"
var c *smshttp.Client
func f() { _ = reflect.ValueOf(c) }`}}, 1},
		{"reflect.ValueOf on a driver that holds a client in a package a gateway imports", "internal/sms/senders/s.go", `import _ "` + module + `/internal/elsewhere"`,
			[]planted{{"internal/elsewhere/e.go", `import "reflect"
type holder struct{ inner struct{ c []*smshttp.Client } }
func f(h holder) { _ = reflect.ValueOf(h) }`}}, 1},

		// The clean uses.
		{"through smshttp", d, `type D struct{ client *smshttp.Client }
func n() *D { return &D{client: smshttp.NewClient("h", smshttp.Options{})} }
func f(d *D, r *http.Request) { resp, _ := smshttp.Do(d.client, r); _ = resp.Body; _ = resp.Status }`, nil, 0},
		{"a request built by hand", d, `func f(ctx context.Context) {
	r, _ := http.NewRequestWithContext(ctx, http.MethodPost, "u", nil)
	r.Header.Set("a", "b")
	_ = http.StatusOK
}`, nil, 0},
		{"a type of the driver's own that is named Client and has Do", d, `type Client struct{}
func (Client) Do() {}
func f(c Client) { c.Do() }`, nil, 0},
		{"the imports that only describe a request", d, `import (_ "net/url"; _ "net/netip"; _ "crypto/x509"; _ "github.com/google/uuid")`, nil, 0},
		{"inside smshttp", "internal/sms/smshttp/x.go", `import _ "net"
import _ "crypto/tls"
func g(c *http.Client, r *http.Request) { c.Do(r) }
var c = &http.Client{}`, nil, 0},
		{"a package that is not a gateway", "internal/elsewhere/g.go", `import _ "net"
var c = &http.Client{}`, nil, 0},
		{"a package a gateway imports, with nothing wrong", "internal/sms/senders/s.go", `import _ "` + module + `/internal/elsewhere"`,
			[]planted{{"internal/elsewhere/e.go", `import _ "github.com/some/lib"
var x = 1`}}, 0},
		{"a type with only some of the Sender methods", "internal/elsewhere/g.go", `import _ "net"
type G struct{}
func (G) Provider() string { return "" }
func (G) Send() {}`, nil, 0},
		{"reading kinds and elements by reflect in a package a gateway imports", "internal/sms/senders/s.go", `import _ "` + module + `/internal/elsewhere"`,
			[]planted{{"internal/elsewhere/e.go", `import "reflect"
func f(v any) bool { rv := reflect.ValueOf(v); return rv.Kind() == reflect.String && reflect.TypeOf(v).Kind() == reflect.String }`}}, 0},
		{"NewAt in a package no gateway reaches", "internal/elsewhere/e.go", `import "reflect"
func f(t reflect.Type, p reflect.Value) { _ = reflect.NewAt(t, p.UnsafePointer()) }`, nil, 0},
	}
	for _, c := range cases {
		fset := token.NewFileSet()
		parse := func(p, src string) file {
			pkg := p[strings.LastIndex(p[:strings.LastIndex(p, "/")], "/")+1 : strings.LastIndex(p, "/")]
			header := "package " + pkg + "\nimport (\"context\"; \"io\"; \"encoding/json\"; \"net/http\"; \"" + module + "/internal/sms/smshttp\")\n"
			// Imports go before the declarations of the body; the body may start with some.
			body := src
			var imports []string
			for body = strings.TrimLeft(body, "\n"); strings.HasPrefix(body, "import "); body = strings.TrimLeft(body, "\n") {
				nl := strings.Index(body, "\n")
				if nl < 0 {
					nl = len(body)
				}
				imports = append(imports, body[:nl])
				body = body[nl:]
				// A parenthesised group spans lines only when written on one; the cases keep it so.
			}
			full := header + strings.Join(imports, "\n") + "\n" + body + "\n"
			if p == "internal/sms/smshttp/stub.go" {
				full = src
			}
			af, err := parser.ParseFile(fset, p, full, parser.ParseComments)
			if err != nil {
				t.Fatalf("%s: %v\n%s", c.name, err, full)
			}
			return file{path: p, ast: af}
		}
		fs := []file{parse("internal/sms/smshttp/stub.go", stubSmshttp), parse(c.path, c.src)}
		for _, e := range c.extra {
			fs = append(fs, parse(e.path, e.src))
		}
		info, ok := typeInfoReal(fset, fs, httpPkg, reflectPkg)
		if !ok {
			t.Fatalf("%s: no type information", c.name)
		}
		got, _ := smsBodyProblems(fset, fs, info)
		if (c.want == 0) != (len(got) == 0) {
			t.Errorf("%s: %d problems, want %d or more: %v", c.name, len(got), c.want, got)
		}
	}
}
