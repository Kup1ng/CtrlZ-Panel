package lint_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"sort"
	"testing"
)

// The rule caps-and-endings and the rule closed-values-in-logs both end at one call site
// (P1 auth review round 9, sms-r9-9). "A call is started only when the time left can finish
// it" (round 8) and "every accepted Result passes Scrubbed" (round 5) are both enforced by
// Router.try and by nothing that stops a second site: a worker probe of the breaker (named as
// the way out in rules.md topic 4, round 6) or a balance check on the SMS page calling
// Sender.Send or Sender.Balance directly would start a call with 2 seconds left, which the
// budget then cuts with an accepted message unrecorded, or would store a reply holding the
// recipient's number. The mutants of those rules proved only that THIS site checks.
//
// The rule is about the call, not the receiver (round 10, sms-r10-1 and sms-r10-6). Round 9 judged
// the receiver: a value whose method set held Provider, Send and Balance. A value that is only
// "something with Send" or "something with Balance" is not that: a one-method interface of the
// caller's own (type balancer interface{ Balance(ctx) (sms.Field, error) }), an embedded narrow
// interface or a type parameter constrained by one is assigned a Sender without a visible
// conversion, and its call started a provider call outside the router while the lint stayed
// green. What every such value has in common is the method it calls: whatever holds a Sender and
// is called must carry the Sender's own signature for that method, because assignability
// requires it. So the rule judges the selected method, by name and by signature (the
// sms.Message, sms.ProviderTemplate, sms.Result and sms.Field it names), and not the type it is
// selected from:
//
//   - Send(context.Context, sms.Message, sms.ProviderTemplate) (sms.Result, error)
//   - Balance(context.Context) (sms.Field, error)
//
// A selection of either, on any receiver (an interface, a narrower interface, a struct that
// embeds one, a type parameter, a concrete driver, a pointer to one), is refused in non-test
// code outside Router.try. A method value (f := s.Send), a method expression (sms.Sender.Send)
// and a call through an interface conversion are selections too and are caught the same way.
// A method of the same name with another signature (the router's own Send) is not a provider
// call. Test files may call a driver: they test it.
//
// A call by reflection (MethodByName) is not judged here; it is closed one level up (sms-r16-5):
// only the directories of reflectImporters (internal/closed, internal/logattr) may import reflect at
// all, and a new one is a reviewed entry (TestReflectAndTheTestHarnessesAreImportedOnlyWhereListed).

// providerCallSites are the functions that may call a provider, with the reason.
var providerCallSites = map[string]string{
	"internal/sms/router.go:(*Router).try": "the one site that holds a call to the time left and scrubs what the provider answered",
}

var providerCallMethods = map[string]bool{"Send": true, "Balance": true}

// smsValue reports the named type sms.<name> itself: not a pointer to it, which is another type
// and so another signature.
func smsValue(t types.Type, name string) bool {
	n, ok := types.Unalias(t).(*types.Named)
	return ok && n.Obj().Pkg() != nil && n.Obj().Pkg().Path() == smsPkg && n.Obj().Name() == name
}

func isContext(t types.Type) bool {
	n, ok := types.Unalias(t).(*types.Named)
	return ok && n.Obj().Pkg() != nil && n.Obj().Pkg().Path() == "context" && n.Obj().Name() == "Context"
}

func isErrorType(t types.Type) bool {
	return types.Identical(t, types.Universe.Lookup("error").Type())
}

// providerCallMethod reports whether fn is a provider call: a method named Send or Balance whose
// signature is the Sender's. The receiver is not looked at.
func providerCallMethod(fn *types.Func) bool {
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Variadic() {
		return false
	}
	p, r := sig.Params(), sig.Results()
	switch fn.Name() {
	case "Send":
		return p.Len() == 3 && isContext(p.At(0).Type()) && smsValue(p.At(1).Type(), "Message") && smsValue(p.At(2).Type(), "ProviderTemplate") &&
			r.Len() == 2 && smsValue(r.At(0).Type(), "Result") && isErrorType(r.At(1).Type())
	case "Balance":
		return p.Len() == 1 && isContext(p.At(0).Type()) &&
			r.Len() == 2 && smsValue(r.At(0).Type(), "Field") && isErrorType(r.At(1).Type())
	}
	return false
}

func providerCallProblems(fset *token.FileSet, files []file, info *types.Info) (problems []string, used map[string]bool, scanned int) {
	used = map[string]bool{}
	for _, f := range files {
		if f.test {
			continue
		}
		scanned++
		for _, decl := range f.ast.Decls {
			key := ""
			if fd, ok := decl.(*ast.FuncDecl); ok {
				key = funcKey(f.path, fd)
			}
			ast.Inspect(decl, func(n ast.Node) bool {
				x, ok := n.(*ast.SelectorExpr)
				if !ok || !providerCallMethods[x.Sel.Name] {
					return true
				}
				sel := info.Selections[x]
				if sel == nil || (sel.Kind() != types.MethodVal && sel.Kind() != types.MethodExpr) {
					return true
				}
				if fn, ok := sel.Obj().(*types.Func); !ok || !providerCallMethod(fn) {
					return true
				}
				if _, ok := providerCallSites[key]; ok {
					used[key] = true
					return true
				}
				problems = append(problems, fmt.Sprintf("%s: %s of a sender outside Router.try; every provider call goes through the router, which holds it to the time left and scrubs the answer (rule caps-and-endings, closed-values-in-logs)", fset.Position(x.Pos()), x.Sel.Name))
				return true
			})
		}
	}
	sort.Strings(problems)
	return dedupe(problems), used, scanned
}

func TestProviderCallsComeOnlyFromTheRouter(t *testing.T) {
	fset, files := parseRepo(t)
	info, ok := typeInfoReal(fset, files, "context", "time")
	if !ok {
		t.Fatal("type information unavailable")
	}
	problems, used, scanned := providerCallProblems(fset, files, info)
	for _, p := range problems {
		t.Error(p)
	}
	if scanned < 100 {
		t.Fatalf("only %d files scanned; the lint is not looking at the module", scanned)
	}
	for key := range providerCallSites {
		if !used[key] {
			t.Errorf("%s no longer calls a provider (or does not exist); remove it from providerCallSites", key)
		}
	}
}

const stubSender = `package sms
import "context"
type Message struct{}
type ProviderTemplate struct{}
type Result struct{}
type Field struct{}
type Sender interface {
	Provider() string
	Send(ctx context.Context, m Message, t ProviderTemplate) (Result, error)
	Balance(ctx context.Context) (Field, error)
}
type Router struct{ gw Sender }
func (r *Router) Send(ctx context.Context) error { return nil }
func (r *Router) try(ctx context.Context) { _, _ = r.gw.Send(ctx, Message{}, ProviderTemplate{}) }
func (r *Router) other(ctx context.Context) { _, _ = r.gw.Send(ctx, Message{}, ProviderTemplate{}) }
`

const stubDriver = `package drv
import ("context"; "` + smsPkg + `")
type D struct{}
func (D) Provider() string { return "x" }
func (D) Send(ctx context.Context, m sms.Message, t sms.ProviderTemplate) (sms.Result, error) { return sms.Result{}, nil }
func (D) Balance(ctx context.Context) (sms.Field, error) { return sms.Field{}, nil }
type Other struct{}
func (Other) Send() {}
func (Other) Balance() {}
`

// TestProviderCallLintCanFail plants every way to reach a provider outside the router: a direct
// call, a method value, a method expression, a call through an interface conversion, a call on
// a concrete driver, and the clean uses that must pass. Router.other in the stub is a violation
// planted in every case, so each case expects one finding more than its own.
func TestProviderCallLintCanFail(t *testing.T) {
	cases := []struct {
		name     string
		src      string
		want     int
		testFile bool
	}{
		{"a direct call on the interface", `func f(s sms.Sender, ctx context.Context) { _, _ = s.Send(ctx, sms.Message{}, sms.ProviderTemplate{}) }`, 1, false},
		{"a balance call on the interface", `func f(s sms.Sender, ctx context.Context) { _, _ = s.Balance(ctx) }`, 1, false},
		{"a method value", `func f(s sms.Sender) { g := s.Send; _ = g }`, 1, false},
		{"a method value of Balance handed on", `func f(s sms.Sender) { h(s.Balance) }; func h(func(context.Context) (sms.Field, error)) {}`, 1, false},
		{"a method expression", `var g = sms.Sender.Send`, 1, false},
		{"a call through an interface conversion", `func f(d drv.D, ctx context.Context) { _, _ = sms.Sender(d).Send(ctx, sms.Message{}, sms.ProviderTemplate{}) }`, 1, false},
		{"a call on a concrete driver", `func f(d drv.D, ctx context.Context) { _, _ = d.Send(ctx, sms.Message{}, sms.ProviderTemplate{}) }`, 1, false},
		{"a call on a pointer to a driver", `func f(d *drv.D, ctx context.Context) { _, _ = d.Balance(ctx) }`, 1, false},
		// Round 10 (sms-r10-1, sms-r10-6): the receiver is not what makes a call a provider call.
		{"a call through a one-method interface of Balance", `type balancer interface{ Balance(context.Context) (sms.Field, error) }
func f(b balancer, ctx context.Context) { _, _ = b.Balance(ctx) }`, 1, false},
		{"a call through a one-method interface of Send", `type sendOnly interface {
	Send(context.Context, sms.Message, sms.ProviderTemplate) (sms.Result, error)
}
func f(d drv.D, ctx context.Context) { var s sendOnly = d; _, _ = s.Send(ctx, sms.Message{}, sms.ProviderTemplate{}) }`, 1, false},
		{"a call through a narrow interface embedded in a struct", `type balancer interface{ Balance(context.Context) (sms.Field, error) }
type probe struct{ balancer }
func f(p probe, ctx context.Context) { _, _ = p.Balance(ctx) }`, 1, false},
		{"a call through a narrow interface embedded in another interface", `type balancer interface{ Balance(context.Context) (sms.Field, error) }
type probe interface{ balancer; Name() string }
func f(p probe, ctx context.Context) { _, _ = p.Balance(ctx) }`, 1, false},
		{"a call on a type parameter constrained by a narrow interface", `func f[T interface{ Balance(context.Context) (sms.Field, error) }](t T, ctx context.Context) { _, _ = t.Balance(ctx) }`, 1, false},
		{"a call on a type parameter constrained by a narrow Send", `type sendOnly interface {
	Send(context.Context, sms.Message, sms.ProviderTemplate) (sms.Result, error)
}
func f[T sendOnly](t T, ctx context.Context) { _, _ = t.Send(ctx, sms.Message{}, sms.ProviderTemplate{}) }`, 1, false},
		{"a method value of a narrow interface handed on", `type balancer interface{ Balance(context.Context) (sms.Field, error) }
func f(b balancer) { h(b.Balance) }; func h(func(context.Context) (sms.Field, error)) {}`, 1, false},
		{"a concrete type that has only Send", `type onlySend struct{}
func (onlySend) Send(context.Context, sms.Message, sms.ProviderTemplate) (sms.Result, error) { return sms.Result{}, nil }
func f(o onlySend, ctx context.Context) { _, _ = o.Send(ctx, sms.Message{}, sms.ProviderTemplate{}) }`, 1, false},
		{"a narrow interface spelled through type aliases", `type m = sms.Message
type tpl = sms.ProviderTemplate
type sendOnly interface{ Send(context.Context, m, tpl) (sms.Result, error) }
func f(s sendOnly, ctx context.Context) { _, _ = s.Send(ctx, sms.Message{}, sms.ProviderTemplate{}) }`, 1, false},
		{"a Balance with another result is not a provider call", `type balancer interface{ Balance(context.Context) (int, error) }
func f(b balancer, ctx context.Context) { _, _ = b.Balance(ctx) }`, 0, false},
		{"a Send with another parameter list is not a provider call", `type sender interface{ Send(context.Context, string) error }
func f(s sender, ctx context.Context) { _ = s.Send(ctx, "x") }`, 0, false},
		{"a Send with a pointer message is another signature", `type sender interface {
	Send(context.Context, *sms.Message, sms.ProviderTemplate) (sms.Result, error)
}
func f(s sender, ctx context.Context) { _, _ = s.Send(ctx, nil, sms.ProviderTemplate{}) }`, 0, false},
		{"a narrow interface in a test file", `type balancer interface{ Balance(context.Context) (sms.Field, error) }
func f(b balancer, ctx context.Context) { _, _ = b.Balance(ctx) }`, 0, true},
		{"the router's own Send", `func f(r *sms.Router, ctx context.Context) { _ = r.Send(ctx) }`, 0, false},
		{"an unrelated type with a Send method", `func f(o drv.Other) { o.Send(); o.Balance() }`, 0, false},
		{"a field read, not a method", `type T struct{ Send int }; func f(t T) int { return t.Send }`, 0, false},
		{"a test file may call a driver", `func f(d drv.D, ctx context.Context) { _, _ = d.Send(ctx, sms.Message{}, sms.ProviderTemplate{}) }`, 0, true},
	}
	for _, c := range cases {
		fset := token.NewFileSet()
		parse := func(p, src string, test bool) file {
			f, err := parser.ParseFile(fset, p, src, parser.ParseComments)
			if err != nil {
				t.Fatalf("%s: %v\n%s", c.name, err, src)
			}
			return file{path: p, ast: f, test: test}
		}
		planted := "internal/worker/smssend/x.go"
		if c.testFile {
			planted = "internal/worker/smssend/x_test.go"
		}
		header := "package smssend\nimport (\"context\"; \"" + smsPkg + "\"; \"" + module + "/internal/sms/drv\")\nvar _ context.Context\nvar _ sms.Sender\nvar _ drv.D\n"
		fs := []file{
			parse("internal/sms/router.go", stubSender, false),
			parse("internal/sms/drv/d.go", stubDriver, false),
			parse(planted, header+c.src+"\n", c.testFile),
		}
		// A test file is not type-checked by typeInfoReal; the planted case is judged without it
		// because providerCallProblems skips it before it asks for a selection.
		info, ok := typeInfoReal(fset, fs, "context")
		if !ok {
			t.Fatalf("%s: no type information", c.name)
		}
		got, used, _ := providerCallProblems(fset, fs, info)
		if len(got) != c.want+1 {
			t.Errorf("%s: %d findings %v, want %d", c.name, len(got), got, c.want+1)
		}
		if !used["internal/sms/router.go:(*Router).try"] {
			t.Errorf("%s: the allowed site was not recognised", c.name)
		}
	}
}
