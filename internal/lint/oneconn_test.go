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

// The one-connection-per-request rule (P1 auth review, round 5, topic 14; spec 17.1,
// 17.2, 18.3, 18.6).
//
// A request holds at most one database connection at any moment. Rounds 1 to 3 met the same
// failure in ten shapes: a handler inside WithTenant or WithGlobal called a single-statement
// function (Store.Auth(), Store.Admin()) with the context it was handed from outside the
// callback, so the call asked the pool for a second connection while the first was held, and
// N parallel requests on a pool of N waited for each other. The old answer was a second pool
// for those calls, which doubled every role's connection footprint and needed its own sizing,
// compose arithmetic and fault tests, and a ticket taken on that second pool still committed
// before the transaction's own outcome was known, so a later failure burned it.
//
// The structural answer has two halves, and this is the static one (the runtime one is
// store.ErrNested in store.one, tested in internal/store):
//
//  1. Inside a transaction callback the only context is the one the transaction hands out:
//     tx.Context() (or a context derived from it). A callback is any function, literal or
//     declared, that has a store.Tx or store.GlobalTx parameter. Every expression of type
//     context.Context in its body must be a variable declared inside the body, a
//     Tx.Context() or GlobalTx.Context() call, or a context.With* call on one of those.
//     A captured ctx variable, a struct field, an http.Request's Context() and
//     context.Background() all fail, because each one is a context without the
//     transaction marker, which is the thing that let a second connection be asked for.
//  2. A function that takes a transaction takes no context parameter next to it: the
//     parameter would be the outside context again, one call away from the callback.
//
// A call that needs the database while a transaction is open is a Tx or GlobalTx method, on
// the transaction's own connection. A throttle hit (which must outlive a rollback) is made
// before the transaction and a reset after its commit.

// oneConnStdlib is type-checked from source so that context.Context is the real type.
var oneConnStdlib = []string{"context"}

// contextDerivers are the context package functions that return a child of their first
// argument. A child of the transaction's context keeps its marker.
var contextDerivers = map[string]bool{
	"WithValue": true, "WithCancel": true, "WithTimeout": true, "WithDeadline": true,
	"WithoutCancel": true, "WithCancelCause": true, "WithTimeoutCause": true, "WithDeadlineCause": true,
}

func isContextType(t types.Type) bool {
	n, ok := t.(*types.Named)
	return ok && n.Obj().Pkg() != nil && n.Obj().Pkg().Path() == "context" && n.Obj().Name() == "Context"
}

// isTxType is store.Tx or store.GlobalTx, or a pointer to one.
func isTxType(t types.Type) bool {
	if p, ok := t.(*types.Pointer); ok {
		t = p.Elem()
	}
	n, ok := t.(*types.Named)
	if !ok || n.Obj().Pkg() == nil || n.Obj().Pkg().Path() != storePkg {
		return false
	}
	return n.Obj().Name() == "Tx" || n.Obj().Name() == "GlobalTx"
}

// oneConnProblems checks every function that has a transaction parameter. It returns the
// problems and the number of such functions it examined.
func oneConnProblems(fset *token.FileSet, files []file, info *types.Info) ([]string, int) {
	var problems []string
	examined := 0
	for _, f := range files {
		if f.test {
			continue
		}
		check := func(name string, ft *ast.FuncType, body *ast.BlockStmt) {
			if body == nil || ft.Params == nil {
				return
			}
			hasTx, hasCtx := false, false
			for _, fld := range ft.Params.List {
				t := info.TypeOf(fld.Type)
				if t == nil {
					continue
				}
				if isTxType(t) {
					hasTx = true
				}
				if isContextType(t) {
					hasCtx = true
				}
			}
			if !hasTx {
				return
			}
			examined++
			at := func(p token.Pos) string { return fset.Position(p).String() }
			if hasCtx {
				problems = append(problems, fmt.Sprintf("%s: %s takes a transaction and a context.Context; use tx.Context() so the call cannot reach for a second connection", at(ft.Pos()), name))
			}
			inside := func(p token.Pos) bool { return p >= body.Pos() && p <= body.End() }
			var ok func(e ast.Expr) bool
			ok = func(e ast.Expr) bool {
				switch e := e.(type) {
				case *ast.ParenExpr:
					return ok(e.X)
				case *ast.Ident:
					obj := info.ObjectOf(e)
					return obj != nil && inside(obj.Pos())
				case *ast.SelectorExpr:
					// The store's own helpers read the transaction's private ctx field.
					if e.Sel.Name == "ctx" {
						if t := info.TypeOf(e.X); t != nil && isTxType(t) {
							return true
						}
					}
					return false
				case *ast.CallExpr:
					sel, isSel := e.Fun.(*ast.SelectorExpr)
					if !isSel {
						return false
					}
					if s := info.Selections[sel]; s != nil && sel.Sel.Name == "Context" && len(e.Args) == 0 && isTxType(s.Recv()) {
						return true
					}
					if x, isIdent := sel.X.(*ast.Ident); isIdent && contextDerivers[sel.Sel.Name] && len(e.Args) > 0 {
						if pn, isPkg := info.ObjectOf(x).(*types.PkgName); isPkg && pn.Imported().Path() == "context" {
							return ok(e.Args[0])
						}
					}
					return false
				}
				return false
			}
			ast.Inspect(body, func(n ast.Node) bool {
				e, isExpr := n.(ast.Expr)
				if !isExpr {
					return true
				}
				if tv, known := info.Types[e]; known && tv.IsType() {
					return false // the type context.Context written in a signature (and its parts) is not a context
				}
				ctxTyped := false
				if t := info.TypeOf(e); t != nil && isContextType(t) {
					ctxTyped = true
				}
				// A stubbed package (net/http) gives its methods no type, so the call that
				// would hand back the request's context is told by its name instead.
				if c, isCall := e.(*ast.CallExpr); isCall && !ctxTyped {
					if s, isSel := c.Fun.(*ast.SelectorExpr); isSel && s.Sel.Name == "Context" && len(c.Args) == 0 {
						ctxTyped = true
					}
				}
				if !ctxTyped {
					return true
				}
				if ok(e) {
					// An accepted selector (the store's tx.ctx) must not have its field name
					// judged again as an identifier declared outside.
					_, isSel := e.(*ast.SelectorExpr)
					return !isSel
				}
				problems = append(problems, fmt.Sprintf("%s: %s uses a context that is not the transaction's (%s); use tx.Context()", at(e.Pos()), name, exprText(e)))
				return false
			})
		}
		ast.Inspect(f.ast, func(n ast.Node) bool {
			switch fn := n.(type) {
			case *ast.FuncLit:
				check("a transaction callback", fn.Type, fn.Body)
			case *ast.FuncDecl:
				check(fn.Name.Name, fn.Type, fn.Body)
			}
			return true
		})
	}
	sort.Strings(problems)
	return dedupe(problems), examined
}

func TestOneConnectionPerRequest(t *testing.T) {
	fset, files := parseRepo(t)
	info, ok := typeInfoReal(fset, files, oneConnStdlib...)
	if !ok {
		t.Fatal("type information unavailable")
	}
	problems, examined := oneConnProblems(fset, files, info)
	for _, p := range problems {
		t.Error(p)
	}
	// The lint must be looking at the callbacks: the tenant and admin services have well
	// over this many. A rename of store.Tx that stopped it seeing them would pass for ever.
	if examined < 60 {
		t.Fatalf("only %d functions with a transaction parameter were examined; the lint is not seeing store.Tx", examined)
	}
}

const stubStoreTx = `package store
import "context"
type Tx struct{ ctx context.Context }
func (t Tx) Context() context.Context { return t.ctx }
type GlobalTx struct{ ctx context.Context }
func (t GlobalTx) Context() context.Context { return t.ctx }
type Store struct{}
func (*Store) WithTenant(ctx context.Context, fn func(Tx) error) error { return nil }
func (*Store) WithGlobal(ctx context.Context, fn func(GlobalTx) error) error { return nil }
type AuthLookups struct{}
func (AuthLookups) TicketPut(ctx context.Context) {}
func MarkDirty(tx Tx) { _ = tx.ctx }
`

// TestOneConnectionLintCanFail plants each way a callback could reach for a context that is
// not the transaction's, and the uses that must stay allowed.
func TestOneConnectionLintCanFail(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want int
	}{
		{"the transaction's own context", `func f(ctx context.Context, s *store.Store, a store.AuthLookups) {
	_ = s.WithTenant(ctx, func(tx store.Tx) error { a.TicketPut(tx.Context()); return nil })
}`, 0},
		{"a derived context", `func f(ctx context.Context, s *store.Store, a store.AuthLookups) {
	_ = s.WithTenant(ctx, func(tx store.Tx) error {
		c, cancel := context.WithTimeout(tx.Context(), 1)
		defer cancel()
		a.TicketPut(context.WithValue(c, "k", 1))
		return nil
	})
}`, 0},
		{"a variable declared inside from the transaction", `func f(ctx context.Context, s *store.Store, a store.AuthLookups) {
	_ = s.WithGlobal(ctx, func(g store.GlobalTx) error { c := g.Context(); a.TicketPut(c); return nil })
}`, 0},
		{"the outer context (the mutant: a ticket put inside the callback)", `func f(ctx context.Context, s *store.Store, a store.AuthLookups) {
	_ = s.WithTenant(ctx, func(tx store.Tx) error { a.TicketPut(ctx); return nil })
}`, 1},
		{"the outer context in a global transaction", `func f(ctx context.Context, s *store.Store, a store.AuthLookups) {
	_ = s.WithGlobal(ctx, func(g store.GlobalTx) error { a.TicketPut(ctx); return nil })
}`, 1},
		{"a context struct field", `type svc struct{ ctx context.Context; s *store.Store; a store.AuthLookups }
func (x *svc) f() {
	_ = x.s.WithTenant(x.ctx, func(tx store.Tx) error { x.a.TicketPut(x.ctx); return nil })
}`, 1},
		{"a context copied into a local inside the callback", `func f(ctx context.Context, s *store.Store, a store.AuthLookups) {
	_ = s.WithTenant(ctx, func(tx store.Tx) error { c := ctx; a.TicketPut(c); return nil })
}`, 1},
		{"a request's context", `func f(r *http.Request, s *store.Store, a store.AuthLookups) {
	_ = s.WithTenant(r.Context(), func(tx store.Tx) error { a.TicketPut(r.Context()); return nil })
}`, 1},
		{"a fresh background context", `func f(ctx context.Context, s *store.Store, a store.AuthLookups) {
	_ = s.WithTenant(ctx, func(tx store.Tx) error { a.TicketPut(context.Background()); return nil })
}`, 1},
		{"a child of the outer context", `func f(ctx context.Context, s *store.Store, a store.AuthLookups) {
	_ = s.WithTenant(ctx, func(tx store.Tx) error {
		c, cancel := context.WithTimeout(ctx, 1)
		defer cancel()
		a.TicketPut(c)
		return nil
	})
}`, 1},
		{"a callback built before the call", `func f(ctx context.Context, s *store.Store, a store.AuthLookups) {
	fn := func(tx store.Tx) error { a.TicketPut(ctx); return nil }
	_ = s.WithTenant(ctx, fn)
}`, 1},
		{"a nested closure in the callback", `func f(ctx context.Context, s *store.Store, a store.AuthLookups) {
	_ = s.WithTenant(ctx, func(tx store.Tx) error {
		g := func() { a.TicketPut(ctx) }
		g()
		return nil
	})
}`, 1},
		{"a helper that takes the transaction and a context", `func helper(ctx context.Context, tx store.Tx, a store.AuthLookups) { a.TicketPut(tx.Context()) }`, 1},
		{"a helper that takes the transaction and uses a captured field", `type h struct{ ctx context.Context }
func (x h) helper(tx store.Tx, a store.AuthLookups) { a.TicketPut(x.ctx) }`, 1},
		{"a helper that takes only the transaction", `func helper(tx store.Tx, a store.AuthLookups) { a.TicketPut(tx.Context()) }`, 0},
		{"a function without a transaction is not examined", `func plain(ctx context.Context, a store.AuthLookups) { a.TicketPut(ctx) }`, 0},
		{"the store's own helper reading the private field", `func other(tx store.Tx) { store.MarkDirty(tx) }`, 0},
	}
	for _, c := range cases {
		fset := token.NewFileSet()
		parse := func(path, src string) file {
			f, err := parser.ParseFile(fset, path, src, parser.ParseComments)
			if err != nil {
				t.Fatalf("%s: %v\n%s", c.name, err, src)
			}
			return file{path: path, ast: f}
		}
		src := "package x\nimport (\n\t\"context\"\n\t\"net/http\"\n\t\"" + storePkg + "\"\n)\nvar _ context.Context\nvar _ *http.Request\nvar _ store.Tx\n" + c.src + "\n"
		fs := []file{parse("internal/store/tx.go", stubStoreTx), parse("internal/api/x.go", src)}
		info, ok := typeInfoReal(fset, fs, oneConnStdlib...)
		if !ok {
			t.Fatalf("%s: no type information", c.name)
		}
		got, _ := oneConnProblems(fset, fs, info)
		if len(got) != c.want {
			t.Errorf("%s: %d findings %s, want %d", c.name, len(got), strings.Join(got, "; "), c.want)
		}
	}
}
