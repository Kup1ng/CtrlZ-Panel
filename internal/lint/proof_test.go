package lint_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/api"
	"github.com/Kup1ng/CtrlZ-Panel/internal/apispec"
	"github.com/Kup1ng/CtrlZ-Panel/internal/ratelimit"
)

// The proof-before-work rule (P1 auth review, round 5, topic 8; spec 4.3, 4.4, 5.6, 7.5,
// 10.2, 18.5).
//
// A route that takes a one-time proof (an OTP code, a reset, mfa or passkey ticket, an
// invite token, a console password) runs one shape through one helper,
// internal/auth/proof: O(1) shape checks, a charge to the proof's budget, a
// non-consuming check of the proof, and only then the heavy work, in the Work step.
// Rounds 1 to 4 each flipped the order for one route (reset, register, the admin rehash,
// the one-time exception, the passkey begin rows) between "do not burn the code on a
// weak password" and "do not spend CPU, memory or rows before proof", and the next
// route had the old order. This is the source-level half; the behavioural half is the
// flood test of every x-ctrlz-auth none operation (internal/api and internal/adminapi
// flood_test.go).
//
// What it checks, by types and not by name:
//
//  1. Heavy primitives (zxcvbn scoring, Argon2 hash and verify, the WebAuthn finish
//     calls, the consume of a ticket) may be reached from the handler of an
//     x-ctrlz-auth none operation only through the Work step of a proof.Spec literal.
//     The walk starts at the handler method named after each none operationId of both
//     OpenAPI documents and follows every function the module declares that it names
//     (a call or a method value), in ANY package and not only the two service
//     packages (round 18, tenant-r18-9: the first form followed internal/api and
//     internal/adminapi alone, so a heavy call moved into internal/auth/login or any
//     other package was never entered), without entering a Work literal. A function
//     value that a package-level var holds (a literal, a method expression `(*T).M`, a function of another package, a table of functions: any initialiser, round 18, tenant-r18-15) is a node of the walk too, and a
//     call through an interface method reaches EVERY method of the module that
//     implements it (found by go/types, so a new implementation is followed with no
//     entry anywhere), which over-approximates and so fails closed. What the walk does
//     not follow is a call through a field or a local variable of function type (the
//     callee is a value, not a declaration); the flood test is the net for those.
//     Handlers of session-authenticated operations are not starting points: their
//     caller has a live session, which is the proof.
//  2. A proof.Spec literal names its Kind and its Work, and a Spec that is not a
//     first-factor password names a Check: a route with a proof and no check of it is
//     the shape this rule exists to remove.
//  3. The lint saw what it claims to guard: every primitive is referenced somewhere in
//     the two services, and every none operation has a handler. A rename that stopped
//     the lint seeing a primitive would otherwise pass for ever.

const (
	proofPkg = module + "/internal/auth/proof"
)

// proofServicePkgs are the packages whose handlers start the walk (the handler is a method of Server there).
var proofServicePkgs = []string{"internal/api", "internal/adminapi"}

// heavyPrimitives names the calls that cost a gate slot, CPU, memory or a row before a
// caller has proved anything. The key is types.Func.FullName.
func heavyPrimitives() map[string]string {
	return map[string]string{
		"(*" + module + "/internal/auth/pwstrength.Checker).Check":           "zxcvbn scoring",
		"(*" + module + "/internal/auth/password.Hasher).Hash":               "Argon2 hash",
		"(*" + module + "/internal/auth/password.Hasher).Verify":             "Argon2 verify",
		"(*" + module + "/internal/auth/password.Hasher).VerifyGateFree":     "one-time password verify",
		"(" + module + "/internal/auth/passkey.Instance).FinishLogin":        "WebAuthn assertion",
		"(" + module + "/internal/auth/passkey.Instance).FinishDiscoverable": "WebAuthn assertion",
		"(" + module + "/internal/auth/passkey.Instance).FinishRegistration": "WebAuthn attestation",
		"(*" + module + "/internal/auth/ticket.Service).Take":                "ticket consume",
		"(" + module + "/internal/store.AuthLookups).TicketTake":             "ticket consume",
		"(" + module + "/internal/store.Tx).TicketTake":                      "ticket consume",
		"(*" + module + "/internal/auth/ticket.Service).TakeTx":              "ticket consume",
		"(" + module + "/internal/store.AuthLookups).TicketSpend":            "ticket nonce row",
	}
}

// primitiveViaWrapper are the heavy primitives that no handler names any more because the
// ticket service wraps them (ticket.Service.Take over AuthLookups.TicketTake). They stay on
// the list so that a handler which calls them directly is still caught; the check that the
// lint can see every primitive skips them.
func primitiveViaWrapper() map[string]bool {
	return map[string]bool{"(" + module + "/internal/store.AuthLookups).TicketTake": true}
}

// proofFunc is one function or method of a service package.
type proofFunc struct {
	obj    types.Object // a *types.Func, or the *types.Var of a package-level function literal
	file   string
	recv   string // receiver type name, "" for a function
	name   string
	edges  []types.Object // module functions and function variables it names outside Work literals
	heavy  []proofHeavy   // primitives it names outside Work literals
	litErr []string       // malformed proof.Spec literals
}

type proofHeavy struct {
	name, why, at string
}

// importsProof returns the local name under which a file imports the proof package,
// or "".
func importsProof(f *ast.File) string {
	for _, imp := range f.Imports {
		if strings.Trim(imp.Path.Value, `"`) != proofPkg {
			continue
		}
		if imp.Name != nil {
			return imp.Name.Name
		}
		return "proof"
	}
	return ""
}

// specLit reports whether cl is a composite literal of proof.Spec, with or without an
// explicit type argument.
func specLit(cl *ast.CompositeLit, local string) bool {
	if local == "" || cl.Type == nil {
		return false
	}
	t := cl.Type
	switch x := t.(type) {
	case *ast.IndexExpr:
		t = x.X
	case *ast.IndexListExpr:
		t = x.X
	}
	sel, ok := t.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Spec" {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == local
}

// proofIndex collects the functions of the service packages with what each names.
func proofIndex(fset *token.FileSet, files []file, info *types.Info, prim map[string]string) (map[types.Object]*proofFunc, map[string]map[string]*proofFunc, map[string]int) {
	byObj := map[types.Object]*proofFunc{}
	byMethod := map[string]map[string]*proofFunc{} // package dir -> "Recv.Name" -> func
	refs := map[string]int{}                       // how often each primitive is named in a service package
	for _, f := range files {
		dir := filepath.ToSlash(filepath.Dir(f.path))
		if f.test || generatedFile(f.path) {
			continue
		}
		local := importsProof(f.ast)
		for _, d := range f.ast.Decls {
			if gd, ok := d.(*ast.GenDecl); ok && gd.Tok == token.VAR {
				// A package-level `var x = func...` is a function a handler can call by its name.
				for _, sp := range gd.Specs {
					vs, ok := sp.(*ast.ValueSpec)
					if !ok {
						continue
					}
					for i, name := range vs.Names {
						// Whatever the initialiser is (a literal, a method expression `(*T).M`, a function of
						// another package, a wrapper call, a map of functions), the variable is a node that
						// names what the initialiser names: a call through it then reaches those (round 18,
						// tenant-r18-15). `var a, b = f()` gives both names the one initialiser.
						var init ast.Node
						switch {
						case len(vs.Values) == len(vs.Names):
							init = vs.Values[i]
						case len(vs.Values) == 1:
							init = vs.Values[0]
						}
						obj := info.Defs[name]
						if init == nil || obj == nil {
							continue
						}
						pf := &proofFunc{obj: obj, file: f.path, name: name.Name}
						byObj[obj] = pf
						scanProofBody(fset, f, init, local, info, prim, pf, refs)
					}
				}
				continue
			}
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			obj, _ := info.Defs[fd.Name].(*types.Func)
			if obj == nil {
				continue
			}
			pf := &proofFunc{obj: obj, file: f.path, name: fd.Name.Name}
			if fd.Recv != nil && len(fd.Recv.List) == 1 {
				pf.recv = recvName(fd.Recv.List[0].Type)
			}
			byObj[obj] = pf
			if byMethod[dir] == nil {
				byMethod[dir] = map[string]*proofFunc{}
			}
			byMethod[dir][pf.recv+"."+pf.name] = pf
			scanProofBody(fset, f, fd.Body, local, info, prim, pf, refs)
		}
	}
	// A call through an interface method reaches every method of the module that implements it (go/types, so
	// a new implementation needs no entry). Over-approximating is the safe direction for a guard.
	for _, pf := range byObj {
		var extra []types.Object
		for _, e := range pf.edges {
			fn, ok := e.(*types.Func)
			if !ok {
				continue
			}
			sig, ok := fn.Type().(*types.Signature)
			if !ok || sig.Recv() == nil {
				continue
			}
			iface, ok := sig.Recv().Type().Underlying().(*types.Interface)
			if !ok {
				continue
			}
			for o, cand := range byObj {
				cf, ok := o.(*types.Func)
				if !ok || cf.Name() != fn.Name() {
					continue
				}
				csig, ok := cf.Type().(*types.Signature)
				if !ok || csig.Recv() == nil {
					continue
				}
				rt := csig.Recv().Type()
				if types.Implements(rt, iface) || types.Implements(types.NewPointer(rt), iface) {
					extra = append(extra, cand.obj)
				}
			}
		}
		pf.edges = append(pf.edges, extra...)
	}
	// Edges only to functions that are indexed (the module's own); the rest is the standard library and the
	// libraries, which are not ours to read.
	for _, pf := range byObj {
		kept := pf.edges[:0]
		for _, e := range pf.edges {
			if _, ok := byObj[e]; ok {
				kept = append(kept, e)
			}
		}
		pf.edges = kept
	}
	return byObj, byMethod, refs
}

func recvName(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.StarExpr:
		return recvName(x.X)
	case *ast.Ident:
		return x.Name
	case *ast.IndexExpr:
		return recvName(x.X)
	}
	return ""
}

// scanProofBody records what a function names outside the Work literals of the proof.Spec
// literals it contains, and checks that each literal is well formed.
func scanProofBody(fset *token.FileSet, f file, body ast.Node, local string, info *types.Info, prim map[string]string, pf *proofFunc, refs map[string]int) {
	skip := map[ast.Node]bool{} // Work literals
	at := func(n ast.Node) string { return fmt.Sprintf("%s:%d", f.path, fset.Position(n.Pos()).Line) }
	ast.Inspect(body, func(n ast.Node) bool {
		if skip[n] {
			// The Work step is where heavy work belongs. Its own references still count as
			// "seen" so the lint knows the primitives resolve, but they are not violations
			// and its calls are not followed.
			ast.Inspect(n, func(m ast.Node) bool {
				if id, ok := m.(*ast.Ident); ok {
					if fn, ok := info.Uses[id].(*types.Func); ok {
						if _, heavy := prim[fn.FullName()]; heavy {
							refs[fn.FullName()]++
						}
					}
				}
				return true
			})
			return false
		}
		switch n := n.(type) {
		case *ast.CompositeLit:
			if !specLit(n, local) {
				break
			}
			var kind ast.Expr
			hasCheck, hasWork, hasCharge, hasRefund := false, false, false, false
			for _, el := range n.Elts {
				kv, ok := el.(*ast.KeyValueExpr)
				if !ok {
					pf.litErr = append(pf.litErr, at(n)+": a proof.Spec literal must use field names")
					continue
				}
				key, _ := kv.Key.(*ast.Ident)
				if key == nil {
					continue
				}
				switch key.Name {
				case "Kind":
					kind = kv.Value
				case "Check":
					if id, ok := kv.Value.(*ast.Ident); !ok || id.Name != "nil" {
						hasCheck = true
					}
				case "Charge":
					if id, ok := kv.Value.(*ast.Ident); !ok || id.Name != "nil" {
						hasCharge = true
					}
				case "Refund":
					// A Refund that is a literal with an empty body is a reason in another spelling.
					if id, ok := kv.Value.(*ast.Ident); !ok || id.Name != "nil" {
						hasRefund = true
					}
					if lit, ok := kv.Value.(*ast.FuncLit); ok && len(lit.Body.List) == 0 {
						hasRefund = false
					}
				case "Work":
					hasWork = true
					if lit, ok := kv.Value.(*ast.FuncLit); ok {
						skip[lit] = true
					} else {
						pf.litErr = append(pf.litErr, at(kv)+": proof.Spec.Work must be a function literal, so the lint can see where heavy work is allowed")
					}
				}
			}
			switch {
			case kind == nil:
				pf.litErr = append(pf.litErr, at(n)+": proof.Spec without a Kind")
			case !hasCheck && !isProofPassword(kind, local):
				pf.litErr = append(pf.litErr, at(n)+": proof.Spec of a proof other than a first-factor password without a Check: a proof nobody checks before the work")
			}
			if !hasWork {
				pf.litErr = append(pf.litErr, at(n)+": proof.Spec without a Work step")
			}
			// Every Spec that charges can be turned away by a full gate, whatever its author believes
			// (the admin login claimed "gate-free" while its verify takes a slot), so the attempt it
			// counted must be given back: a Charge needs a Refund that does something (round 6,
			// primitives-r6-9). A reason string was accepted before and proved nothing.
			if hasCharge && !hasRefund {
				pf.litErr = append(pf.litErr, at(n)+": proof.Spec with a Charge and no Refund (or an empty one): a busy server would leave the attempt counted")
			}
		case *ast.Ident:
			switch o := info.Uses[n].(type) {
			case *types.Func:
				if why, heavy := prim[o.FullName()]; heavy {
					refs[o.FullName()]++
					pf.heavy = append(pf.heavy, proofHeavy{o.FullName(), why, at(n)})
					break
				}
				pf.edges = append(pf.edges, o)
			case *types.Var:
				pf.edges = append(pf.edges, o) // kept only when it is a package-level function literal that was indexed
			}
		}
		return true
	})
}

func isProofPassword(e ast.Expr, local string) bool {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Password" {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == local
}

// proofProblems is the whole check. roots maps a service package directory to the handler
// method names of its x-ctrlz-auth none operations.
func proofProblems(fset *token.FileSet, files []file, roots map[string][]string, prim map[string]string) []string {
	info, ok := typeInfo(fset, files)
	if !ok {
		return []string{"type information unavailable"}
	}
	byObj, byMethod, refs := proofIndex(fset, files, info, prim)
	var out []string
	for _, pf := range byObj {
		out = append(out, pf.litErr...)
	}
	var dirs []string
	for d := range roots {
		dirs = append(dirs, d)
	}
	sort.Strings(dirs)
	for _, dir := range dirs {
		for _, h := range roots[dir] {
			root := byMethod[dir]["Server."+h]
			if root == nil {
				out = append(out, fmt.Sprintf("%s: the none operation's handler Server.%s does not exist", dir, h))
				continue
			}
			parent := map[*proofFunc]*proofFunc{root: nil}
			queue := []*proofFunc{root}
			for len(queue) > 0 {
				cur := queue[0]
				queue = queue[1:]
				for _, hv := range cur.heavy {
					out = append(out, fmt.Sprintf("%s: %s (%s) is reached before any proof: %s", hv.at, shortName(hv.name), hv.why, chain(parent, cur)))
				}
				for _, e := range cur.edges {
					next := byObj[e]
					if _, seen := parent[next]; !seen {
						parent[next] = cur
						queue = append(queue, next)
					}
				}
			}
		}
	}
	// The lint must have looked at something real.
	var names []string
	for n := range prim {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if refs[n] == 0 && !primitiveViaWrapper()[n] {
			out = append(out, "primitive "+shortName(n)+" is named nowhere in the module's non-test code; the lint cannot see it any more (renamed or moved?)")
		}
	}
	sort.Strings(out)
	return dedupe(out)
}

func dedupe(s []string) []string {
	var out []string
	for i, v := range s {
		if i == 0 || v != s[i-1] {
			out = append(out, v)
		}
	}
	return out
}

func shortName(full string) string {
	if i := strings.LastIndex(full, "/"); i >= 0 {
		full = full[i+1:]
	}
	return strings.ReplaceAll(full, "pwstrength.", "pwstrength.")
}

// chain renders the path from the handler to a function.
func chain(parent map[*proofFunc]*proofFunc, f *proofFunc) string {
	var names []string
	for ; f != nil; f = parent[f] {
		n := f.name
		if f.recv != "" {
			n = f.recv + "." + n
		}
		names = append([]string{n}, names...)
	}
	return strings.Join(names, " -> ") + " (outside a proof.Spec Work step)"
}

// noneHandlers lists the handler method of every none operation of both documents.
func noneHandlers(t *testing.T) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	for _, c := range []struct {
		dir string
		doc []byte
		svc ratelimit.Service
	}{
		{"internal/api", api.Tenant(), ratelimit.Tenant},
		{"internal/adminapi", api.Admin(), ratelimit.Admin},
	} {
		ops, err := apispec.Parse(c.doc, c.svc)
		if err != nil {
			t.Fatal(err)
		}
		for _, op := range ops {
			if op.Auth == apispec.None {
				out[c.dir] = append(out[c.dir], strings.ToUpper(op.ID[:1])+op.ID[1:])
			}
		}
	}
	if len(out["internal/api"]) < 10 || len(out["internal/adminapi"]) < 1 {
		t.Fatalf("the OpenAPI documents gave only %v none operations", out)
	}
	return out
}

func TestProofBeforeWorkRule(t *testing.T) {
	fset, files := parseRepo(t)
	for _, p := range proofProblems(fset, files, noneHandlers(t), heavyPrimitives()) {
		t.Error(p)
	}
}

// proofFixture is a small module: the primitives under their real import paths, the
// helper, and the service package the case plants code into.
func proofFixture(service string) map[string]string {
	return map[string]string{
		"internal/auth/password/p.go": `package password
type Hasher struct{}
func (h *Hasher) Hash() {}
func (h *Hasher) Verify() {}
func (h *Hasher) VerifyGateFree() {}`,
		"internal/auth/pwstrength/p.go": `package pwstrength
type Checker struct{}
func (c *Checker) Check() {}`,
		"internal/auth/passkey/p.go": `package passkey
type Instance struct{}
func (i Instance) FinishLogin() {}
func (i Instance) FinishDiscoverable() {}
func (i Instance) FinishRegistration() {}`,
		"internal/auth/ticket/p.go": `package ticket
type Service struct{}
func (s *Service) Take() {}
func (s *Service) TakeTx() {}
func (s *Service) Peek() {}`,
		"internal/store/p.go": `package store
type AuthLookups struct{}
func (a AuthLookups) TicketTake() {}
func (a AuthLookups) TicketSpend() {}
type Tx struct{}
func (t Tx) TicketTake() {}`,
		// A package other than the two services, where a heavy call can be moved to (tenant-r18-9): a method, an
		// interface with an implementation, and a function the handler reaches through another package.
		"internal/auth/login/l.go": `package login
import "github.com/Kup1ng/CtrlZ-Panel/internal/auth/password"
type Service struct{ H *password.Hasher }
func (s *Service) PasswordLogin() { s.H.Verify() }
func (s *Service) Light() {}
type Runner interface{ Run() }
type impl struct{ H *password.Hasher }
func (i impl) Run() { i.H.Hash() }
func New() Runner { return impl{} }
func Helper(h *password.Hasher) { h.Hash() }
var Hook = func(h *password.Hasher) { h.Hash() }`,
		"internal/auth/proof/p.go": `package proof
type Kind int
const (
	Password Kind = 1
	Ticket   Kind = 2
)
type Proved struct{}
type Spec[T any] struct {
	Kind   Kind
	Shape  func() error
	Charge func() error
	Check  func() error
	Work   func(Proved) (T, error)
	Refund func()
}
func Run[T any](s Spec[T]) (T, error) { var z T; return z, nil }`,
		"internal/api/x.go": `package api
import (
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/login"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/password"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/passkey"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/proof"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/pwstrength"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/ticket"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)
type Server struct {
	hasher  *password.Hasher
	score   *pwstrength.Checker
	tickets *ticket.Service
	auth    store.AuthLookups
	tx      store.Tx
	inst    passkey.Instance
	login   *login.Service
	runner  login.Runner
}
func (s *Server) prepare() { s.score.Check(); s.hasher.Hash() }
func (s *Server) peek() error { s.tickets.Peek(); return nil }
func (s *Server) light() error { return nil }
` + service,
	}
}

// proofRun type-checks the fixture and returns the problems for the handlers named.
func proofRun(t *testing.T, service string, handlers ...string) []string {
	t.Helper()
	fset := token.NewFileSet()
	var files []file
	for path, src := range proofFixture(service) {
		af, err := parser.ParseFile(fset, path, src, parser.ParseComments)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		files = append(files, file{path: path, ast: af})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].path < files[j].path })
	got := proofProblems(fset, files, map[string][]string{"internal/api": handlers}, heavyPrimitives())
	// The fixture names every primitive once so the "lint cannot see it" check is quiet
	// for it; a case that wants it loud removes the reference.
	return got
}

// everyPrimitive is a session handler that names each primitive once: session handlers are
// not starting points, so it also shows that they are exempt.
const everyPrimitive = `
func (s *Server) Everything() {
	s.hasher.Hash(); s.hasher.Verify(); s.hasher.VerifyGateFree(); s.score.Check()
	s.tickets.Take(); s.tickets.TakeTx(); s.auth.TicketTake(); s.tx.TicketTake(); s.auth.TicketSpend()
	s.inst.FinishLogin(); s.inst.FinishDiscoverable(); s.inst.FinishRegistration()
}
`

// TestProofLintCanFail is the lint's own test: each shape of the mistake is planted and
// must be reported, and each clean shape must pass.
func TestProofLintCanFail(t *testing.T) {
	cases := []struct {
		name     string
		src      string
		handlers []string
		want     int // problems; -1 means "at least one"
	}{
		{"the register shape: check, then work", `
func (s *Server) Register() {
	proof.Run(proof.Spec[int]{Kind: proof.Ticket, Check: s.peek, Work: func(proof.Proved) (int, error) { s.prepare(); return 0, nil }})
}`, []string{"Register"}, 0},
		{"the mutant: scoring in the shape step, ahead of the check", `
func (s *Server) Register() {
	proof.Run(proof.Spec[int]{Kind: proof.Ticket,
		Shape: func() error { s.prepare(); return nil },
		Check: s.peek,
		Work:  func(proof.Proved) (int, error) { return 0, nil }})
}`, []string{"Register"}, -1},
		{"scoring in the handler body", `
func (s *Server) Register() { s.score.Check() }`, []string{"Register"}, 1},
		{"hash in a helper the handler calls", `
func (s *Server) Register() { s.helper() }
func (s *Server) helper()   { s.hasher.Hash() }`, []string{"Register"}, 1},
		{"hash two helpers down", `
func (s *Server) Register() { s.a() }
func (s *Server) a()        { s.b() }
func (s *Server) b()        { s.prepare() }`, []string{"Register"}, 2},
		{"a method value is a reference too", `
func (s *Server) Register() { f := s.hasher.Hash; f() }`, []string{"Register"}, 1},
		{"the ticket consume ahead of the proof", `
func (s *Server) Register() { s.tickets.Take() }`, []string{"Register"}, 1},
		{"the store's consume ahead of the proof", `
func (s *Server) Register() { s.auth.TicketTake() }`, []string{"Register"}, 1},
		{"the nonce row ahead of the proof", `
func (s *Server) Register() { s.auth.TicketSpend() }`, []string{"Register"}, 1},
		{"a WebAuthn finish ahead of the proof", `
func (s *Server) Register() { s.inst.FinishLogin() }`, []string{"Register"}, 1},
		{"the discoverable finish ahead of the proof", `
func (s *Server) Register() { s.inst.FinishDiscoverable() }`, []string{"Register"}, 1},
		{"a heavy call in the Charge step", `
func (s *Server) Register() {
	proof.Run(proof.Spec[int]{Kind: proof.Ticket, Charge: func() error { s.hasher.Verify(); return nil }, Check: s.peek,
		Refund: func() { s.light() }, Work: func(proof.Proved) (int, error) { return 0, nil }})
}`, []string{"Register"}, 1},
		{"a Spec with a Charge and no Refund", `
func (s *Server) Register() {
	proof.Run(proof.Spec[int]{Kind: proof.Password, Charge: func() error { return nil },
		Work: func(proof.Proved) (int, error) { return 0, nil }})
}`, []string{"Register"}, 1},
		{"a Spec with a Charge and an empty Refund", `
func (s *Server) Register() {
	proof.Run(proof.Spec[int]{Kind: proof.Password, Charge: func() error { return nil }, Refund: func() {},
		Work: func(proof.Proved) (int, error) { return 0, nil }})
}`, []string{"Register"}, 1},
		{"a Spec with a Charge and a nil Refund", `
func (s *Server) Register() {
	proof.Run(proof.Spec[int]{Kind: proof.Password, Charge: func() error { return nil }, Refund: nil,
		Work: func(proof.Proved) (int, error) { return 0, nil }})
}`, []string{"Register"}, 1},
		{"a Spec with a Charge and a real Refund", `
func (s *Server) Register() {
	proof.Run(proof.Spec[int]{Kind: proof.Password, Charge: func() error { return nil }, Refund: func() { s.light() },
		Work: func(proof.Proved) (int, error) { return 0, nil }})
}`, []string{"Register"}, 0},
		{"a heavy call in the Check step", `
func (s *Server) Register() {
	proof.Run(proof.Spec[int]{Kind: proof.Ticket, Check: func() error { s.prepare(); return nil },
		Work: func(proof.Proved) (int, error) { return 0, nil }})
}`, []string{"Register"}, -1},
		{"a first-factor verify in the Work step", `
func (s *Server) Register() {
	proof.Run(proof.Spec[int]{Kind: proof.Password, Work: func(proof.Proved) (int, error) { s.hasher.Verify(); return 0, nil }})
}`, []string{"Register"}, 0},
		{"heavy work in a helper reached only from Work", `
func (s *Server) Register() {
	proof.Run(proof.Spec[int]{Kind: proof.Ticket, Check: s.peek, Work: func(proof.Proved) (int, error) { s.deep(); return 0, nil }})
}
func (s *Server) deep() { s.prepare() }`, []string{"Register"}, 0},
		{"the same helper reached from Work and from outside it", `
func (s *Server) Register() {
	s.prepare()
	proof.Run(proof.Spec[int]{Kind: proof.Ticket, Check: s.peek, Work: func(proof.Proved) (int, error) { s.prepare(); return 0, nil }})
}`, []string{"Register"}, 2},
		{"a session-authenticated handler may do heavy work", `
func (s *Server) ChangePassword() { s.prepare() }
func (s *Server) Register() { s.light() }`, []string{"Register"}, 0},
		{"a none handler that never reaches heavy work", `
func (s *Server) Register() { s.light() }`, []string{"Register"}, 0},
		{"a handler named for a none operation that does not exist", ``, []string{"Missing"}, 1},
		{"a Spec without a Kind", `
func (s *Server) Register() {
	proof.Run(proof.Spec[int]{Check: s.peek, Work: func(proof.Proved) (int, error) { return 0, nil }})
}`, []string{"Register"}, 1},
		{"a Spec of a ticket without a Check", `
func (s *Server) Register() {
	proof.Run(proof.Spec[int]{Kind: proof.Ticket, Work: func(proof.Proved) (int, error) { return 0, nil }})
}`, []string{"Register"}, 1},
		{"a Spec with a nil Check is no Check", `
func (s *Server) Register() {
	proof.Run(proof.Spec[int]{Kind: proof.Ticket, Check: nil, Work: func(proof.Proved) (int, error) { return 0, nil }})
}`, []string{"Register"}, 1},
		{"a Spec without a Work step", `
func (s *Server) Register() { proof.Run(proof.Spec[int]{Kind: proof.Ticket, Check: s.peek}) }`, []string{"Register"}, 1},
		{"a Work that is a named function hides what it does", `
func (s *Server) Register() {
	proof.Run(proof.Spec[int]{Kind: proof.Ticket, Check: s.peek, Work: s.work})
}
func (s *Server) work(proof.Proved) (int, error) { s.prepare(); return 0, nil }`, []string{"Register"}, -1},
		{"a positional Spec literal", `
func (s *Server) Register() { proof.Run(proof.Spec[int]{proof.Ticket, nil, nil, s.peek, nil}) }`, []string{"Register"}, -1},
		// Round 18, tenant-r18-9: the walk enters every package of the module, not only the two services.
		{"the verify moved into a method of another package", `
func (s *Server) Register() { s.login.PasswordLogin() }`, []string{"Register"}, 1},
		{"the verify in a function of another package", `
func (s *Server) Register() { login.Helper(s.hasher) }`, []string{"Register"}, 1},
		{"the hash behind an interface value, in another package", `
func (s *Server) Register() { s.runner.Run() }`, []string{"Register"}, 1},
		{"the hash behind an interface value made by a constructor", `
func (s *Server) Register() { login.New().Run() }`, []string{"Register"}, 1},
		{"a package-level function literal of another package", `
func (s *Server) Register() { login.Hook(s.hasher) }`, []string{"Register"}, 1},
		{"a package-level function literal of the service", `
var hook = func(s *Server) { s.prepare() }
func (s *Server) Register() { hook(s) }`, []string{"Register"}, -1},
		// Round 18, tenant-r18-15: a package-level variable of any initialiser is a node of the walk, not only a
		// function literal.
		{"a package-level var holding a method expression", `
var verify = (*password.Hasher).Verify
func (s *Server) Register() { verify(s.hasher) }`, []string{"Register"}, 1},
		{"a package-level var holding a function of another package", `
var viaHelper = login.Helper
func (s *Server) Register() { viaHelper(s.hasher) }`, []string{"Register"}, 1},
		{"a package-level table of functions", `
var table = map[string]func(*password.Hasher){"a": login.Helper}
func (s *Server) Register() { table["a"](s.hasher) }`, []string{"Register"}, 1},
		{"a package-level var of two names with one initialiser each", `
var first, second = (*password.Hasher).Verify, (*login.Service).Light
func (s *Server) Register() { first(s.hasher) }`, []string{"Register"}, 1},
		{"a package-level var holding a function that does no heavy work", `
var light2 = (*login.Service).Light
func (s *Server) Register() { light2(s.login) }`, []string{"Register"}, 0},
		{"a method of another package that does no heavy work", `
func (s *Server) Register() { s.login.Light() }`, []string{"Register"}, 0},
		{"the other package's verify, reached only from Work", `
func (s *Server) Register() {
	proof.Run(proof.Spec[int]{Kind: proof.Ticket, Check: s.peek, Work: func(proof.Proved) (int, error) { s.login.PasswordLogin(); return 0, nil }})
}`, []string{"Register"}, 0},
		{"a primitive nobody names any more", ``, []string{"Light"}, -1},
	}
	for _, c := range cases {
		src := c.src + everyPrimitive
		if c.name == "a primitive nobody names any more" {
			src = `func (s *Server) Light() { s.light() }`
		}
		if c.name == "a handler named for a none operation that does not exist" {
			src = everyPrimitive
		}
		got := proofRun(t, src, c.handlers...)
		mine := got
		if c.want >= 0 && len(mine) != c.want || c.want < 0 && len(mine) == 0 {
			t.Errorf("%s: %d problems, want %d:\n  %s", c.name, len(mine), c.want, strings.Join(mine, "\n  "))
		}
	}
}
