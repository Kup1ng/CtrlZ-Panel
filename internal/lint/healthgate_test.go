package lint_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"strconv"
	"strings"
	"testing"
)

// Rule 28 (exposure-is-declared), admin-r11-4 and admin-r12-2. The unauthenticated health mux
// (/healthz names the role and the release, /readyz takes a pooled database connection) must answer
// loopback peers only. Round 11 made that a lint over the call shapes that mount a handler at "/" or
// "/*", and round 12 found the shapes it did not list: root.Get, root.NotFound, a path in a variable,
// an http.Server whose Handler is the mux, a second listener. A list of shapes is the wrong kind of
// rule, so the rule is now a type and four facts about where things may live:
//
//  1. httpx.Health holds the mux in a private field, has no ServeHTTP, and its one method, Handler,
//     returns the mux behind the peer check. api.New, adminapi.New and app take a Health, so no code
//     can mount the raw mux, whatever call it uses, without the compiler refusing it.
//  2. The health paths are registered in one file, internal/app/health.go. A second registration of
//     /healthz or /readyz anywhere is a second mux, which is the way past (1).
//  3. httpx.NewHealth is called in non-test code only there, so the raw mux is wrapped where it is built.
//  4. A listener is opened only in the files of healthListenerFiles. A new one (the hub's node
//     listener in P4) adds its file there with the reason, so it is a decision somebody reads.

const (
	healthFile      = "internal/app/health.go"
	healthTypeFile  = "internal/httpx/middleware.go"
	healthGateName  = "loopbackOnly"
	healthTypeName  = "Health"
	healthPathLit1  = "/healthz"
	healthPathLit2  = "/readyz"
	healthNewFnName = "NewHealth"
)

// healthStdlib are the packages the listener facts are judged against, type-checked from source.
var healthStdlib = []string{"net", "net/http", "crypto/tls"}

// healthListenerFiles may open a listener or an http.Server. The two test helpers pick a free port
// for a container and serve nothing.
var healthListenerFiles = map[string]string{
	"internal/app/app.go":               "the one listener of a role: the API pipeline, or the health mux alone, always behind Health.Handler",
	"internal/testpg/testpg.go":         "finds a free port for the test Postgres",
	"internal/testtls/testtls.go":       "serves nothing: starts an httptest TLS server for an instant to read the one throw-away certificate every such server presents, so driver tests can trust it (sms-r15-3)",
	"internal/testvalkey/testvalkey.go": "finds a free port for the test Valkey",
}

// healthProblems judges a set of parsed files against the four facts. info is the type information
// of those files with net, net/http and crypto/tls resolved from source (healthStdlib).
func healthProblems(fset *token.FileSet, files []file, info *types.Info) []string {
	var out []string
	add := func(n ast.Node, format string, a ...any) {
		out = append(out, fset.Position(n.Pos()).String()+": "+fmt.Sprintf(format, a...))
	}
	sawType := false
	for _, f := range files {
		if f.test || !(strings.HasPrefix(f.path, "internal/") || strings.HasPrefix(f.path, "cmd/")) {
			continue
		}
		_, mayListen := healthListenerFiles[f.path]
		ast.Inspect(f.ast, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.BasicLit:
				// 2. The health paths, in any string, are registered in one file.
				if x.Kind == token.STRING && f.path != healthFile {
					if s, err := strconv.Unquote(x.Value); err == nil && (strings.Contains(s, healthPathLit1) || strings.Contains(s, healthPathLit2)) {
						add(x, "%s is named outside %s: a second health mux is a way past httpx.Health (rule 28)", x.Value, healthFile)
					}
				}
			case *ast.CallExpr:
				name, pkg := healthCallee(x)
				// 3. NewHealth wraps the mux where it is built and nowhere else.
				if name == healthNewFnName && f.path != healthFile {
					add(x, "httpx.NewHealth is called outside %s (rule 28)", healthFile)
				}
				_ = pkg
				// 4. Listeners, judged by what the callee and the value are, never by how the
				// package was imported (admin-r13-2, admin-r13-4).
				if why := listenerCall(info, x); why != "" && !mayListen {
					add(x, "%s outside healthListenerFiles (rule 28)", why)
				}
			case *ast.CompositeLit:
				if !mayListen && isHTTPServer(info.TypeOf(x), false) {
					add(x, "an http.Server value outside healthListenerFiles (rule 28)")
				}
			case *ast.Ident:
				// `var s http.Server` and a field of that type: a server made without a literal.
				if v, ok := info.Defs[x].(*types.Var); ok && !mayListen && isHTTPServer(v.Type(), false) {
					add(x, "%s is an http.Server value outside healthListenerFiles (rule 28)", x.Name)
				}
			}
			return true
		})
		if f.path == healthTypeFile {
			sawType = true
			out = append(out, healthTypeProblems(fset, f.ast)...)
		}
	}
	if !sawType {
		out = append(out, healthTypeFile+" is missing from the scan: the type the rule rests on was not judged")
	}
	return out
}

// listenerName says whether a name looks like one that opens or serves a listener. It decides only for
// a callee the type checker could not resolve (a package outside the module and the standard library,
// which the lint stubs): a resolved callee is judged by its package and its result type below, so an
// aliased import or a method on a ListenConfig value is judged the same as net.Listen.
//
// It is a shape and not a list of names (admin-r14-6): the exact list passed quic.ListenAddr,
// http3.ListenAndServeQUIC and httptest.NewServer, and the first third-party transport of the hub is
// likely to be one of them. A name that starts with Listen or Serve, or holds ListenAndServe or
// NewServer (NewServer, NewTLSServer, NewUnstartedServer), is refused; the remedy for a false hit is the
// same as for a true one, a place on healthListenerFiles with its reason. ServeHTTP is the one
// exception: it hands a request to a handler and listens on nothing.
func listenerName(name string) bool {
	if name == "ServeHTTP" {
		return false
	}
	return strings.HasPrefix(name, "Listen") || strings.HasPrefix(name, "Serve") ||
		strings.Contains(name, "ListenAndServe") || strings.Contains(name, "NewServer") ||
		strings.Contains(name, "NewTLSServer") || strings.Contains(name, "NewUnstartedServer")
}

// listenerCall says why a call opens a listener or serves on one, or "" when it does not:
//   - a function or method of package net whose name starts with Listen (net.Listen,
//     net.ListenTCP, (*net.ListenConfig).Listen, whichever way net was imported);
//   - crypto/tls Listen and NewListener, and net/http ListenAndServe, ListenAndServeTLS, Serve and
//     ServeTLS as functions and as methods of *http.Server;
//   - any call whose result is a net.Listener or has its method set (a wrapper, a file listener, an
//     activated socket), so a helper that hands one out is judged where it is called;
//   - new(http.Server);
//   - a callee of an unresolved package whose name listenerName refuses.
func listenerCall(info *types.Info, c *ast.CallExpr) string {
	var id *ast.Ident
	sel, isSel := ast.Unparen(c.Fun).(*ast.SelectorExpr)
	switch f := ast.Unparen(c.Fun).(type) {
	case *ast.SelectorExpr:
		id = f.Sel
	case *ast.Ident:
		id = f
	}
	if id != nil {
		switch obj := info.Uses[id].(type) {
		case *types.Func:
			if p := obj.Pkg(); p != nil {
				switch p.Path() {
				case "net":
					if strings.HasPrefix(obj.Name(), "Listen") {
						return "net." + obj.Name() + " opens a listener"
					}
				case "crypto/tls":
					if obj.Name() == "Listen" || obj.Name() == "NewListener" {
						return "tls." + obj.Name() + " opens a listener"
					}
				case "net/http":
					switch obj.Name() {
					case "ListenAndServe", "ListenAndServeTLS", "Serve", "ServeTLS":
						return "http." + obj.Name() + " serves on a listener"
					}
				}
			}
		case nil:
			// A selector with no object is either a method of a value the checker could not type or
			// a function of a stubbed package. A name on the list is refused rather than waved through.
			if isSel && info.Selections[sel] == nil && listenerName(id.Name) {
				return id.Name + " (a package the lint cannot resolve) looks like a listener"
			}
		}
	}
	if t := info.TypeOf(c); t != nil {
		if tup, ok := t.(*types.Tuple); ok {
			if tup.Len() == 0 {
				return ""
			}
			t = tup.At(0).Type()
		}
		if hasListenerMethods(t) {
			return "a call that returns a net.Listener"
		}
		if b, ok := ast.Unparen(c.Fun).(*ast.Ident); ok && b.Name == "new" && isHTTPServer(t, true) {
			return "new(http.Server)"
		}
	}
	return ""
}

// hasListenerMethods is a structural net.Listener test (Accept, Addr, Close), so the lint does not
// need the interface object of a package it may have stubbed.
func hasListenerMethods(t types.Type) bool {
	if t == nil {
		return false
	}
	ms := types.NewMethodSet(t)
	for _, n := range []string{"Accept", "Addr", "Close"} {
		found := false
		for i := 0; i < ms.Len(); i++ {
			if ms.At(i).Obj().Name() == n {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// isHTTPServer reports whether t is net/http.Server, or a pointer to it when ptr is set.
func isHTTPServer(t types.Type, ptr bool) bool {
	if t == nil {
		return false
	}
	if p, ok := t.(*types.Pointer); ok && ptr {
		t = p.Elem()
	}
	n, ok := t.(*types.Named)
	return ok && n.Obj().Pkg() != nil && n.Obj().Pkg().Path() == "net/http" && n.Obj().Name() == "Server"
}

// healthCallee returns the function name and the package identifier of a call such as net.Listen or
// http.ListenAndServe, or the bare name of a method or local call.
func healthCallee(c *ast.CallExpr) (name, pkg string) {
	switch f := c.Fun.(type) {
	case *ast.SelectorExpr:
		if id, ok := f.X.(*ast.Ident); ok {
			return f.Sel.Name, id.Name
		}
		return f.Sel.Name, ""
	case *ast.Ident:
		return f.Name, ""
	}
	return "", ""
}

// healthTypeProblems holds the type to its shape: one unexported field, no method but Handler, and a
// Handler that returns loopbackOnly(...) or the 404 handler and nothing else.
func healthTypeProblems(fset *token.FileSet, f *ast.File) []string {
	var out []string
	add := func(n ast.Node, msg string) { out = append(out, fset.Position(n.Pos()).String()+": "+msg) }
	var decl *ast.TypeSpec
	for _, d := range f.Decls {
		if gd, ok := d.(*ast.GenDecl); ok && gd.Tok == token.TYPE {
			for _, s := range gd.Specs {
				if ts := s.(*ast.TypeSpec); ts.Name.Name == healthTypeName {
					decl = ts
				}
			}
		}
	}
	if decl == nil {
		return []string{"httpx." + healthTypeName + " is not declared in " + healthTypeFile}
	}
	st, ok := decl.Type.(*ast.StructType)
	if !ok {
		add(decl, "Health must be a struct")
		return out
	}
	fields := 0
	for _, fl := range st.Fields.List {
		if len(fl.Names) == 0 {
			add(fl, "Health embeds a type, which would promote its methods (ServeHTTP) and so hand out the raw mux")
			fields++
		}
		for _, n := range fl.Names {
			fields++
			if n.IsExported() {
				add(n, "Health has an exported field, so any package could read the raw mux")
			}
		}
	}
	if fields != 1 {
		add(decl, "Health must hold exactly one field, the mux")
	}
	handler := false
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Recv == nil || len(fd.Recv.List) != 1 {
			continue
		}
		rt := fd.Recv.List[0].Type
		if s, ok := rt.(*ast.StarExpr); ok {
			rt = s.X
		}
		if id, ok := rt.(*ast.Ident); !ok || id.Name != healthTypeName {
			continue
		}
		if fd.Name.Name != "Handler" {
			add(fd, "Health has a method other than Handler ("+fd.Name.Name+"): the only way out of the mux is the gated one")
			continue
		}
		handler = true
		gated := false
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			rs, ok := n.(*ast.ReturnStmt)
			if !ok {
				return true
			}
			for _, r := range rs.Results {
				c, isCall := r.(*ast.CallExpr)
				if !isCall {
					add(r, "Health.Handler returns something that is not a call: the mux must leave through loopbackOnly")
					continue
				}
				switch nm, _ := healthCallee(c); nm {
				case healthGateName:
					gated = true
				case "NotFoundHandler":
				default:
					add(r, "Health.Handler returns "+nm+"(...), which is not loopbackOnly or the 404 handler")
				}
			}
			return true
		})
		if !gated {
			add(fd, "Health.Handler does not return loopbackOnly(...)")
		}
	}
	if !handler {
		add(decl, "Health has no Handler method")
	}
	return out
}

func TestHealthMuxHasOneExposureGate(t *testing.T) {
	fset, files := parseRepo(t)
	info, ok := typeInfoReal(fset, files, healthStdlib...)
	if !ok {
		t.Fatal("type information unavailable")
	}
	for _, p := range healthProblems(fset, files, info) {
		t.Error(p)
	}
	// A scan that found nothing to judge has lost its target.
	seen := map[string]bool{}
	for _, f := range files {
		seen[f.path] = true
	}
	for p := range healthListenerFiles {
		if !seen[p] {
			t.Errorf("healthListenerFiles names %s, which does not exist: remove it", p)
		}
	}
	if !seen[healthFile] {
		t.Errorf("%s does not exist", healthFile)
	}
}

func TestHealthMuxCheckCanFail(t *testing.T) {
	const typeOK = `package httpx
type Health struct{ h http.Handler }
func NewHealth(h http.Handler) Health { return Health{h: h} }
func (h Health) Handler() http.Handler {
	if h.h == nil { return http.NotFoundHandler() }
	return loopbackOnly(h.h)
}
`
	cases := []struct {
		name  string
		files map[string]string
		want  int
	}{
		{"the type as built", map[string]string{healthTypeFile: typeOK}, 0},
		{"Handler returns the field", map[string]string{healthTypeFile: strings.Replace(typeOK, "return loopbackOnly(h.h)", "return h.h", 1)}, 2},
		{"Handler returns another call", map[string]string{healthTypeFile: strings.Replace(typeOK, "return loopbackOnly(h.h)", "return wrap(h.h)", 1)}, 2},
		{"an exported field", map[string]string{healthTypeFile: strings.Replace(typeOK, "struct{ h http.Handler }", "struct{ H http.Handler }", 1)}, 1},
		{"an embedded handler", map[string]string{healthTypeFile: strings.Replace(typeOK, "struct{ h http.Handler }", "struct{ http.Handler }", 1)}, 1},
		{"a ServeHTTP method", map[string]string{healthTypeFile: typeOK + "func (h Health) ServeHTTP(w http.ResponseWriter, r *http.Request) { h.h.ServeHTTP(w, r) }\n"}, 1},
		{"a second field", map[string]string{healthTypeFile: strings.Replace(typeOK, "struct{ h http.Handler }", "struct{ h, raw http.Handler }", 1)}, 1},
		{"the type is missing", map[string]string{healthTypeFile: "package httpx\n"}, 1},
		{"root.Get of the health path (admin-r12-2)", map[string]string{healthTypeFile: typeOK, "internal/api/s.go": `package api
func f(root R) { root.Get("/readyz", nil) }`}, 1},
		{"a path held in a variable", map[string]string{healthTypeFile: typeOK, "internal/api/s.go": `package api
var p = "GET /healthz"`}, 1},
		{"a second mux through NotFound", map[string]string{healthTypeFile: typeOK, "internal/adminapi/s.go": `package adminapi
func f(root R) { m := http.NewServeMux(); m.HandleFunc("/healthz", nil); root.NotFound(m.ServeHTTP) }`}, 1},
		{"the paths in the one file", map[string]string{healthTypeFile: typeOK, healthFile: `package app
func f(m M) { m.HandleFunc("GET /healthz", nil); m.HandleFunc("GET /readyz", nil); _ = httpx.NewHealth(m) }`}, 0},
		{"NewHealth elsewhere", map[string]string{healthTypeFile: typeOK, "internal/api/s.go": `package api
func f(m M) { _ = httpx.NewHealth(m) }`}, 1},
		// Listener shapes. Every one is judged by what the callee and the value are, so none
		// depends on how the package was imported (admin-r13-2, admin-r13-4).
		{"a second listener", map[string]string{healthTypeFile: typeOK, "internal/hub/s.go": `package hub
import "net"
func f() { _, _ = net.Listen("tcp", ":7443") }`}, 1},
		{"net.ListenTCP", map[string]string{healthTypeFile: typeOK, "internal/hub/s.go": `package hub
import "net"
func f() { _, _ = net.ListenTCP("tcp", nil) }`}, 1},
		{"a ListenConfig value", map[string]string{healthTypeFile: typeOK, "internal/hub/s.go": `package hub
import ("context"; "net")
func f(ctx context.Context) { var lc net.ListenConfig; _, _ = lc.Listen(ctx, "tcp", ":7443") }`}, 1},
		{"a ListenConfig literal", map[string]string{healthTypeFile: typeOK, "internal/hub/s.go": `package hub
import ("context"; "net")
func f(ctx context.Context) { _, _ = (&net.ListenConfig{}).Listen(ctx, "tcp", ":7443") }`}, 1},
		{"an aliased net import", map[string]string{healthTypeFile: typeOK, "internal/hub/s.go": `package hub
import nn "net"
func f() { _, _ = nn.Listen("tcp", ":7443") }`}, 1},
		{"tls.Listen", map[string]string{healthTypeFile: typeOK, "internal/hub/s.go": `package hub
import "crypto/tls"
func f(c *tls.Config) { _, _ = tls.Listen("tcp", ":7443", c) }`}, 1},
		{"a wrapper that hands out a listener", map[string]string{healthTypeFile: typeOK, "internal/hub/s.go": `package hub
import "net"
func f(l net.Listener) { _ = wrap(l) }
func wrap(l net.Listener) net.Listener { return l }`}, 1},
		{"a second http.Server", map[string]string{healthTypeFile: typeOK, "internal/hub/s.go": `package hub
import "net/http"
func f(h http.Handler) { _ = &http.Server{Handler: h} }`}, 1},
		{"an aliased net/http import with ListenAndServe", map[string]string{healthTypeFile: typeOK, "internal/hub/s.go": `package hub
import nh "net/http"
func f() { go nh.ListenAndServe(":6060", nil) }`}, 1},
		{"new(http.Server) then Serve", map[string]string{healthTypeFile: typeOK, "internal/hub/s.go": `package hub
import ("net"; "net/http")
func f(l net.Listener) { s := new(http.Server); _ = s.Serve(l) }`}, 2},
		{"var http.Server then Serve", map[string]string{healthTypeFile: typeOK, "internal/hub/s.go": `package hub
import ("net"; "net/http")
func f(l net.Listener) { var s http.Server; _ = s.Serve(l) }`}, 2},
		{"ListenAndServe", map[string]string{healthTypeFile: typeOK, "cmd/x/main.go": `package main
import "net/http"
func main() { _ = http.ListenAndServe(":80", nil) }`}, 1},
		{"a listener of a package the lint cannot resolve", map[string]string{healthTypeFile: typeOK, "internal/hub/s.go": `package hub
import "example.com/quic"
func f() { _, _ = quic.Listen(":7443") }`}, 1},
		// admin-r14-6: the names of a third-party transport are judged by their shape, not by an exact list.
		{"quic.ListenAddr", map[string]string{healthTypeFile: typeOK, "internal/hub/s.go": `package hub
import "example.com/quic"
func f() { _ = quic.ListenAddr(":7443", nil, nil) }`}, 1},
		{"quic.ListenAddrEarly", map[string]string{healthTypeFile: typeOK, "internal/hub/s.go": `package hub
import "example.com/quic"
func f() { _ = quic.ListenAddrEarly(":7443", nil, nil) }`}, 1},
		{"http3.ListenAndServeQUIC", map[string]string{healthTypeFile: typeOK, "internal/hub/s.go": `package hub
import "example.com/http3"
func f() { _ = http3.ListenAndServeQUIC(":7443", "c", "k", nil) }`}, 1},
		{"httptest.NewServer in a non-test file", map[string]string{healthTypeFile: typeOK, "internal/hub/s.go": `package hub
import "net/http/httptest"
func f() { _ = httptest.NewServer(nil) }`}, 1},
		{"httptest.NewTLSServer in a non-test file", map[string]string{healthTypeFile: typeOK, "internal/hub/s.go": `package hub
import "net/http/httptest"
func f() { _ = httptest.NewTLSServer(nil) }`}, 1},
		{"a server of an unresolved package that only serves", map[string]string{healthTypeFile: typeOK, "internal/hub/s.go": `package hub
import "example.com/srv"
func f() { _ = srv.ServeUDP(nil) }`}, 1},
		{"ServeHTTP on a value of an unresolved package hands a request on and listens on nothing", map[string]string{healthTypeFile: typeOK, "internal/hub/s.go": `package hub
import "example.com/router"
func f(r *router.Mux) { r.ServeHTTP(nil, nil) }`}, 0},
		{"a pgx-style Listen of the module is not a socket", map[string]string{healthTypeFile: typeOK, "internal/store/s.go": `package store
type S struct{}
func (S) Listen(ch string) error { return nil }
func f(s S) { _ = s.Listen("x") }`}, 0},
		{"a function that only takes a listener", map[string]string{healthTypeFile: typeOK, "internal/hub/s.go": `package hub
import "net"
func f(l net.Listener) string { return l.Addr().String() }`}, 0},
		{"the app listener is declared", map[string]string{healthTypeFile: typeOK, "internal/app/app.go": `package app
import ("net"; "net/http")
func f(h http.Handler) { _ = &http.Server{Handler: h}; _, _ = net.Listen("tcp", ":0") }`}, 0},
		{"a test file may listen", map[string]string{healthTypeFile: typeOK, "internal/hub/s_test.go": `package hub
import "net"
func f() { _, _ = net.Listen("tcp", ":0") }`}, 0},
	}
	for _, c := range cases {
		fset := token.NewFileSet()
		var files []file
		for path, src := range c.files {
			af, err := parser.ParseFile(fset, path, src, 0)
			if err != nil {
				t.Fatalf("%s: %v", c.name, err)
			}
			files = append(files, file{path: path, test: strings.HasSuffix(path, "_test.go"), ast: af})
		}
		info, ok := typeInfoReal(fset, files, healthStdlib...)
		if !ok {
			t.Fatalf("%s: no type information", c.name)
		}
		if got := healthProblems(fset, files, info); len(got) != c.want {
			t.Errorf("%s: %d findings %v, want %d", c.name, len(got), got, c.want)
		}
	}
}
