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

// The sms-failure-classification rule (P1 auth review, round 5, topic 17; spec 9.1, 9.5,
// 9.7, 9.8).
//
// The breaker count, sms_available, the number-refused ending, the refund keys, the
// delivery outcome and the alert severity and key each used to look at the error class
// in their own way, so every new failure mode (Auth, Credit, an unreadable key, a missing
// mapping, a blacklist, a skipped gateway) was classified case by case and some left OTP
// offered while nothing could be sent. Now one closed table, internal/sms/classify, maps
// every failure to a scope (gateway, template, message, number, ambiguous) and every one
// of those decisions is a function of the scopes, defined there once.
//
// What this file enforces, over the non-test files of the module:
//
//  1. The class of a failure is read only in internal/sms/classify. Outside it no code
//     may read the Class field of an sms.Error, call a method on an sms.Class, compare an
//     sms.Class (==, !=, <, >, a switch), or mention GatewayWide, which no longer exists.
//     Code that wants to know what a failure means asks classify. The exceptions are the
//     few functions of package sms that render or validate the closed word itself
//     (smsClassRenderers), each with the reason it decides nothing.
//  2. The allow list may not rot: every renderer named must still exist and must still
//     need the exception.
//
// The exhaustive half (every sms.Code has a scope) and the truth-table half (scope per
// gateway, gateway count, breaker open or skipped) are in internal/sms/classify.

const smsPkg = module + "/internal/sms"

// smsClassScope is the one place the class may be read.
const smsClassScope = "internal/sms/classify/"

// smsClassRenderers are the functions outside classify that read an sms.Class only to
// print it as its closed word or to say that it is one of the six. They decide nothing
// about routing, counting, refunds or alerts.
var smsClassRenderers = map[string]string{
	"internal/sms/sms.go:(*Error).Status":   "stores the class beside the code for a status column",
	"internal/sms/sms.go:Class.String":      "the word of a class",
	"internal/sms/sms.go:Class.MarshalText": "the word of a class in encoded params",
	"internal/sms/sms.go:Status.String":     "\"class:code\", or the bare code when there is no class",
	"internal/sms/sms.go:Status.Valid":      "membership of the stored class",
	"internal/sms/alerts.go:Class.Valid":    "membership of the six classes for closed.Check",
	"internal/sms/vocab.go:Class.Name":      "the word of a class as a closed string for a log attribute",
}

func smsNamed(t types.Type, name string) bool {
	for {
		p, ok := t.(*types.Pointer)
		if !ok {
			break
		}
		t = p.Elem()
	}
	n, ok := t.(*types.Named)
	return ok && n.Obj().Pkg() != nil && n.Obj().Pkg().Path() == smsPkg && n.Obj().Name() == name
}

// funcKey names a declaration the way smsClassRenderers does: path:Name, or
// path:Type.Name and path:(*Type).Name for a method.
func funcKey(path string, d *ast.FuncDecl) string {
	if d.Recv == nil || len(d.Recv.List) == 0 {
		return path + ":" + d.Name.Name
	}
	switch rt := d.Recv.List[0].Type.(type) {
	case *ast.StarExpr:
		if id, ok := rt.X.(*ast.Ident); ok {
			return path + ":(*" + id.Name + ")." + d.Name.Name
		}
	case *ast.Ident:
		return path + ":" + rt.Name + "." + d.Name.Name
	}
	return path + ":" + d.Name.Name
}

// smsClassProblems returns the reads of a failure class outside classify, and the
// renderer keys that an exception was actually needed for.
func smsClassProblems(fset *token.FileSet, files []file, info *types.Info) (problems []string, used map[string]bool, scanned int) {
	used = map[string]bool{}
	isClass := func(e ast.Expr) bool {
		tv, ok := info.Types[e]
		return ok && tv.Type != nil && smsNamed(tv.Type, "Class")
	}
	for _, f := range files {
		if f.test || strings.HasPrefix(f.path, smsClassScope) {
			continue
		}
		scanned++
		for _, decl := range f.ast.Decls {
			key := ""
			if fd, ok := decl.(*ast.FuncDecl); ok {
				key = funcKey(f.path, fd)
			}
			report := func(n ast.Node, format string, args ...any) {
				if _, ok := smsClassRenderers[key]; ok {
					used[key] = true
					return
				}
				problems = append(problems, fmt.Sprintf("%s: %s", fset.Position(n.Pos()), fmt.Sprintf(format, args...)))
			}
			ast.Inspect(decl, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.Ident:
					if x.Name == "GatewayWide" {
						report(x, "GatewayWide is a class decision; ask internal/sms/classify (rule sms-failure-classification)")
					}
				case *ast.SelectorExpr:
					if sel := info.Selections[x]; sel != nil && sel.Kind() == types.FieldVal && x.Sel.Name == "Class" && smsNamed(sel.Recv(), "Error") {
						report(x, "reads the Class of an sms.Error; ask internal/sms/classify for the scope (rule sms-failure-classification)")
					} else if key, ok := classMethod(sel); ok && !smsClassMethods[key] {
						report(x, "uses %s, a method of a type that carries a failure class that is not in smsClassMethods; its text or value holds the class, which is read only in internal/sms/classify (rule sms-failure-classification)", key)
					} else if isClass(x.X) {
						report(x, "calls %s on an sms.Class; the class is read only in internal/sms/classify (rule sms-failure-classification)", x.Sel.Name)
					}
				case *ast.BinaryExpr:
					switch x.Op {
					case token.EQL, token.NEQ, token.LSS, token.LEQ, token.GTR, token.GEQ:
						if isClass(x.X) || isClass(x.Y) {
							report(x, "compares an sms.Class; decide on the scope in internal/sms/classify (rule sms-failure-classification)")
						}
					}
				case *ast.SwitchStmt:
					if x.Tag != nil && isClass(x.Tag) {
						report(x, "switches on an sms.Class; decide on the scope in internal/sms/classify (rule sms-failure-classification)")
					}
				}
				return true
			})
			smsClassFlows(info, decl, func(n ast.Node, msg string) { report(n, "%s", msg) })
		}
	}
	sort.Strings(problems)
	return dedupe(problems), used, scanned
}

func TestSMSFailureClassIsReadOnlyInClassify(t *testing.T) {
	fset, files := parseRepo(t)
	info, ok := typeInfoReal(fset, files, "fmt", "strings", "regexp", "bytes")
	if !ok {
		t.Fatal("type information unavailable")
	}
	problems, used, scanned := smsClassProblems(fset, files, info)
	for _, p := range problems {
		t.Error(p)
	}
	if scanned < 100 {
		t.Fatalf("only %d files scanned; the lint is not looking at the module", scanned)
	}
	for key := range smsClassRenderers {
		if !used[key] {
			t.Errorf("renderer %s no longer reads a class (or does not exist); remove it from smsClassRenderers", key)
		}
	}
	// The scope has to exist, or the rule would pass on a tree that has no classifier.
	have := false
	for _, f := range files {
		if strings.HasPrefix(f.path, smsClassScope) && !f.test {
			have = true
		}
	}
	if !have {
		t.Error("internal/sms/classify does not exist")
	}
}

const stubSMSClass = `package sms
type Class int
const (Transient Class = iota + 1; Auth)
func (c Class) String() string { return "" }
type Error struct{ Class Class; Code string }
func (e *Error) Error() string { return "" }
func (e *Error) Describe() string { return "" }
func (s Status) Describe() string { return "" }
type Status struct{ class Class }
func (s Status) String() string { return "" }
func (e *Error) Status() Status { return Status{} }
type Attempt struct{ Err *Error; Local bool }
`

// TestSMSFailureClassLintCanFail plants each way to read a class outside classify, and
// the clean uses that must stay allowed, so the rule is shown to fail and to pass.
func TestSMSFailureClassLintCanFail(t *testing.T) {
	cases := []struct {
		name string
		path string
		src  string
		want int
	}{
		{"the Class field of an error", "", `func f(a sms.Attempt) bool { return a.Err.Class == sms.Auth }`, 2},
		{"a Class stored in a variable", "", `func f(a sms.Attempt) { c := a.Err.Class; _ = c }`, 1},
		{"a method on a class", "", `func f(a sms.Attempt) string { return a.Err.Class.String() }`, 2},
		{"a switch on a class", "", `func f(c sms.Class) int { switch c { case sms.Auth: return 1 }; return 0 }`, 1},
		{"an ordered comparison", "", `func f(c sms.Class) bool { return c >= sms.Transient }`, 1},
		{"GatewayWide", "", `func f(a sms.Attempt) bool { return a.Err == nil && a.Local && a.GatewayWide() }`, 1},
		{"a class passed on without a look", "", `func f(c sms.Class) *sms.Error { return &sms.Error{Class: c, Code: "x"} }`, 0},
		{"an error handed on", "", `func f(a sms.Attempt) *sms.Error { return a.Err }`, 0},
		{"inside classify", "internal/sms/classify/x.go", `func f(a sms.Attempt) bool { return a.Err.Class == sms.Auth }`, 0},
		{"a renderer of package sms", "internal/sms/sms.go", `func (s Status) Valid() bool { return s.class.String() != "" }`, 0},
		{"another method of package sms", "internal/sms/sms.go", `func (e *Error) Retry() bool { return e.Class == Auth }`, 2},

		// sms-r16-19: the text of an Error holds no class (a construction, TestAnErrorTextCarriesNoClass),
		// so a decision on it, in whatever shape, reads nothing of the class and is not this rule's.
		{"Error() of an sms.Error", "", `func f(a sms.Attempt) string { return a.Err.Error() }`, 0},
		{"a method value of Error", "", `func f(a sms.Attempt) func() string { return a.Err.Error }`, 0},
		{"a method expression of Error", "", `func f(a sms.Attempt) string { return (*sms.Error).Error(a.Err) }`, 0},
		{"the text of an error put in a variable and searched", "", `import "strings"
func f(err error) bool { s := err.Error(); return strings.Contains(s, "auth") }`, 0},
		{"a switch on the text of an error", "", `func f(err error) int { switch err.Error() { case "sms: x auth": return 1 }; return 0 }`, 0},
		{"fmt over an error compared", "", `import "fmt"
func f(err error) bool { return fmt.Sprint(err) == "sms: x auth" }`, 0},
		{"fmt over an sms.Error", "", `import "fmt"
func f(a sms.Attempt) string { return fmt.Sprint(a.Err) }`, 0},
		{"an error formatted with fmt is only an error", "", `import "fmt"
func f(err error) error { return fmt.Errorf("send: %w", err) }`, 0},
		{"the text of an error concatenated into a message", "", `func f(err error) string { return "failed: " + err.Error() }`, 0},
		{"the status handed on", "", `func f(a sms.Attempt) sms.Status { return a.Err.Status() }`, 0},
		{"a generic function keeps the static type", "", `func g[T any](v T) {}
func f(a sms.Attempt) { g(a.Err.Status()) }`, 0},

		// The Status and the Class are the carriers: no method of theirs outside the closed list, and
		// no way into an interface value, which is how a value becomes a string or an any.
		{"String of a status", "", `func f(a sms.Attempt) string { return a.Err.Status().String() }`, 1},
		{"String of a status held in a variable", "", `func f(a sms.Attempt) string { s := a.Err.Status(); return s.String() }`, 1},
		{"a method of a status nobody listed", "", `func f(a sms.Attempt) string { return a.Err.Status().Describe() }`, 1},
		{"a method of an error nobody listed", "", `func f(a sms.Attempt) string { return a.Err.Describe() }`, 1},
		{"a method value of a status", "", `func f(a sms.Attempt) func() string { return a.Err.Status().String }`, 1},
		{"a method expression of a status", "", `func f(a sms.Attempt) string { return sms.Status.String(a.Err.Status()) }`, 1},
		{"String promoted through an embedding", "", `type w struct{ sms.Status }
func f(x w) string { return x.String() }`, 1},
		{"fmt over a status", "", `import "fmt"
func f(a sms.Attempt) string { return fmt.Sprintf("%v", a.Err.Status()) }`, 1},
		{"fmt over a status compared", "", `import "fmt"
func f(a sms.Attempt) bool { return fmt.Sprint(a.Err.Status()) == "auth:x" }`, 1},
		{"fmt over a class", "", `import "fmt"
func f(c sms.Class) string { return fmt.Sprintf("%d", c) }`, 1},
		{"a status in a variable of type any", "", `func f(a sms.Attempt) any { var x any = a.Err.Status(); return x }`, 1},
		{"a status assigned to an any", "", `func f(a sms.Attempt) { var x any; x = a.Err.Status(); _ = x }`, 1},
		{"a status in a Stringer", "", `import "fmt"
func f(a sms.Attempt) fmt.Stringer { var s fmt.Stringer = a.Err.Status(); return s }`, 1},
		{"a status converted to any", "", `func f(a sms.Attempt) any { return any(a.Err.Status()) }`, 1},
		{"a status returned as any", "", `func f(a sms.Attempt) any { return a.Err.Status() }`, 1},
		{"a status in a map of any", "", `func f(a sms.Attempt) map[string]any { return map[string]any{"s": a.Err.Status()} }`, 1},
		{"a status in a slice of any", "", `func f(a sms.Attempt) []any { return []any{a.Err.Status()} }`, 1},
		{"a status in a field of type any", "", `type h struct{ V any }
func f(a sms.Attempt) h { return h{V: a.Err.Status()} }`, 1},
		{"a status sent on a channel of any", "", `func f(a sms.Attempt, c chan any) { c <- a.Err.Status() }`, 1},
		{"a status compared with an any", "", `func f(a sms.Attempt, x any) bool { return x == a.Err.Status() }`, 1},
		{"a struct that holds a status converted to any", "", `type h struct{ S sms.Status }
func f(x h) any { return x }`, 1},
		{"a slice of statuses converted to any", "", `func f(x []sms.Status) any { return x }`, 1},
		{"a class in a func literal that returns any", "", `func f(c sms.Class) func() any { return func() any { return c } }`, 1},
	}
	for _, c := range cases {
		fset := token.NewFileSet()
		parse := func(p, src string) file {
			f, err := parser.ParseFile(fset, p, src, parser.ParseComments)
			if err != nil {
				t.Fatalf("%s: %v", c.name, err)
			}
			return file{path: p, ast: f}
		}
		p := c.path
		if p == "" {
			p = "internal/worker/smssend/x.go"
		}
		var fs []file
		if strings.HasPrefix(p, "internal/sms/") && !strings.HasPrefix(p, "internal/sms/classify/") {
			// The planted file is part of package sms itself.
			fs = []file{parse(p, strings.Replace(stubSMSClass, "type Error struct", "type Error struct", 1)+c.src+"\n")}
		} else {
			pkg := "smssend"
			if strings.HasPrefix(p, "internal/sms/classify/") {
				pkg = "classify"
			}
			fs = []file{
				parse("internal/sms/sms.go", stubSMSClass),
				parse(p, "package "+pkg+"\nimport \""+smsPkg+"\"\n"+importsOf(c.src)+"var _ sms.Class\n"+withoutImports(c.src)+"\n"),
			}
		}
		info, ok := typeInfoReal(fset, fs, "fmt", "strings", "regexp", "bytes")
		if !ok {
			t.Fatalf("%s: no type information", c.name)
		}
		got, _, _ := smsClassProblems(fset, fs, info)
		// The key of the planted renderer is looked up in smsClassRenderers, so a
		// real renderer name is exempt only in the real file.
		if len(got) != c.want {
			t.Errorf("%s: %d findings %v, want %d", c.name, len(got), got, c.want)
		}
	}
}

// carriesClass reports the types whose text, or whose fields, hold a failure class.
func carriesClass(t types.Type) bool {
	return smsNamed(t, "Error") || smsNamed(t, "Status") || smsNamed(t, "Class")
}

// importsOf and withoutImports split the leading import lines of a planted body, which must come
// before the declarations the harness adds.
func importsOf(src string) string {
	var out []string
	for _, l := range strings.Split(src, "\n") {
		if strings.HasPrefix(l, "import ") {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n") + "\n"
}

func withoutImports(src string) string {
	var out []string
	for _, l := range strings.Split(src, "\n") {
		if !strings.HasPrefix(l, "import ") {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}

// smsClassMethods are the methods of the types that carry a failure class that code outside classify
// may use, keyed "Type.Method". The list is closed (sms-r16-19): a method of Class, Status or Error
// that is not here fails, whatever it is called, so a method added tomorrow (a Name, a Format, a
// GoString, a MarshalText) starts refused and is a diff a reviewer reads. Error is on it because the
// text of an Error holds no class (TestAnErrorTextCarriesNoClass, a construction: there is nothing
// in it to read), and Status because it hands the status on to the column that stores it.
var smsClassMethods = map[string]bool{
	"Error.Error":  true,
	"Error.Status": true,
}

// classMethod names the method a selector uses, when the method belongs to a type that carries a
// failure class. It reads the object the selector names, so a method promoted through an embedding
// and a method value or expression are the same method.
func classMethod(sel *types.Selection) (string, bool) {
	if sel == nil || (sel.Kind() != types.MethodVal && sel.Kind() != types.MethodExpr) {
		return "", false
	}
	fn, ok := sel.Obj().(*types.Func)
	if !ok {
		return "", false
	}
	sig, _ := fn.Type().(*types.Signature)
	if sig == nil || sig.Recv() == nil {
		return "", false
	}
	rt := sig.Recv().Type()
	if !carriesClass(rt) {
		return "", false
	}
	if p, ok := types.Unalias(rt).(*types.Pointer); ok {
		rt = p.Elem()
	}
	n, ok := types.Unalias(rt).(*types.Named)
	if !ok {
		return "", false
	}
	return n.Obj().Name() + "." + fn.Name(), true
}

// holdsClass reports whether a value of type t is, or holds in a field, element or key (to a
// bounded depth), an sms.Class or sms.Status. An *sms.Error is opaque on purpose: its text and every
// fmt verb print it without the class (Error and Format), so the value reaching an interface says
// nothing a decision could read.
func holdsClass(t types.Type, seen map[types.Type]bool, depth int) bool {
	if t == nil || depth > 6 || seen[t] {
		return false
	}
	seen[t] = true
	t = types.Unalias(t)
	if smsNamed(t, "Error") {
		return false
	}
	if smsNamed(t, "Class") || smsNamed(t, "Status") {
		return true
	}
	switch x := t.(type) {
	case *types.Pointer:
		return holdsClass(x.Elem(), seen, depth+1)
	case *types.Slice:
		return holdsClass(x.Elem(), seen, depth+1)
	case *types.Array:
		return holdsClass(x.Elem(), seen, depth+1)
	case *types.Map:
		return holdsClass(x.Key(), seen, depth+1) || holdsClass(x.Elem(), seen, depth+1)
	case *types.Chan:
		return holdsClass(x.Elem(), seen, depth+1)
	case *types.Named:
		return holdsClass(x.Underlying(), seen, depth+1)
	case *types.Struct:
		for i := 0; i < x.NumFields(); i++ {
			if holdsClass(x.Field(i).Type(), seen, depth+1) {
				return true
			}
		}
	}
	return false
}

// smsClassSinks are the packages whose functions may be handed a status as an interface value: the
// store writes it into the status column that stores it (closed.Text, checked there) and decides
// nothing on it. Only an argument of a call to one of their functions is exempt, never a variable
// of the interface type, a return or a field, which are the places a string gets read.
var smsClassSinks = map[string]string{
	"internal/store": "writes a status into last_error_code and last_error; the bytes stored are the same",
}

// isIfaceTarget reports an interface type a value is converted to (not a type parameter, which keeps
// the static type of what it is instantiated with).
func isIfaceTarget(t types.Type) bool {
	if t == nil {
		return false
	}
	if _, tp := types.Unalias(t).(*types.TypeParam); tp {
		return false
	}
	return types.IsInterface(t)
}

// smsClassFlows reports every place under root where a value that holds a failure class meets an
// interface type: a call argument, a conversion, an assignment, a variable declaration, a return, a
// composite literal element, a send, a comparison with an interface. This is the one way a class
// becomes text or an any that a lint cannot follow (fmt, json, a Stringer, a map of any), and it is
// judged by the static types go/types records, so it does not matter which function the value goes
// to or what it is called. The contract: it judges the flow into an interface in the non-test files
// it is given, outside classify; it does not follow a value after it is an interface (the conversion
// is already refused), and it does not judge reflection, which reflectImporters keeps out of every
// package but two.
func smsClassFlows(info *types.Info, root ast.Node, report func(ast.Node, string)) {
	var stack []ast.Node
	check := func(e ast.Expr, target types.Type) {
		if !isIfaceTarget(target) {
			return
		}
		tv, ok := info.Types[e]
		if !ok || tv.Type == nil || tv.IsType() || isIfaceTarget(tv.Type) {
			return
		}
		if holdsClass(tv.Type, map[types.Type]bool{}, 0) {
			report(e, "a value that holds a failure class (an sms.Class or sms.Status) becomes an interface value, which is how it turns into text or an any that no lint follows; the class is read only in internal/sms/classify (rule sms-failure-classification)")
		}
	}
	results := func() *types.Tuple {
		for i := len(stack) - 1; i >= 0; i-- {
			switch f := stack[i].(type) {
			case *ast.FuncLit:
				if sig, ok := info.Types[f].Type.(*types.Signature); ok {
					return sig.Results()
				}
			case *ast.FuncDecl:
				if obj, ok := info.Defs[f.Name].(*types.Func); ok {
					return obj.Type().(*types.Signature).Results()
				}
			}
		}
		return nil
	}
	ast.Inspect(root, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		stack = append(stack, n)
		switch x := n.(type) {
		case *ast.CallExpr:
			ft, ok := info.Types[x.Fun]
			if !ok {
				break
			}
			if ft.IsType() { // a conversion
				if len(x.Args) == 1 {
					check(x.Args[0], ft.Type)
				}
				break
			}
			sig, _ := ft.Type.Underlying().(*types.Signature)
			if sig == nil {
				break
			}
			if fn := callee(info, x); fn != nil && fn.Pkg() != nil {
				if _, sink := smsClassSinks[strings.TrimPrefix(fn.Pkg().Path(), module+"/")]; sink {
					break
				}
			}
			ps := sig.Params()
			for i, a := range x.Args {
				var pt types.Type
				switch {
				case sig.Variadic() && i >= ps.Len()-1:
					last := ps.At(ps.Len() - 1).Type()
					if x.Ellipsis.IsValid() {
						pt = last
					} else if s, ok := last.(*types.Slice); ok {
						pt = s.Elem()
					}
				case i < ps.Len():
					pt = ps.At(i).Type()
				}
				check(a, pt)
			}
		case *ast.AssignStmt:
			if x.Tok == token.ASSIGN && len(x.Lhs) == len(x.Rhs) {
				for i, r := range x.Rhs {
					check(r, info.TypeOf(x.Lhs[i]))
				}
			}
		case *ast.ValueSpec:
			if x.Type != nil {
				for _, v := range x.Values {
					check(v, info.TypeOf(x.Type))
				}
			}
		case *ast.ReturnStmt:
			if rs := results(); rs != nil && rs.Len() == len(x.Results) {
				for i, r := range x.Results {
					check(r, rs.At(i).Type())
				}
			}
		case *ast.SendStmt:
			if ct, ok := info.TypeOf(x.Chan).Underlying().(*types.Chan); ok {
				check(x.Value, ct.Elem())
			}
		case *ast.BinaryExpr:
			switch x.Op {
			case token.EQL, token.NEQ:
				check(x.X, info.TypeOf(x.Y))
				check(x.Y, info.TypeOf(x.X))
			}
		case *ast.CompositeLit:
			t := info.TypeOf(x)
			if t == nil {
				break
			}
			switch u := t.Underlying().(type) {
			case *types.Struct:
				for i, el := range x.Elts {
					if kv, ok := el.(*ast.KeyValueExpr); ok {
						if id, ok := kv.Key.(*ast.Ident); ok {
							if f, ok := info.Uses[id].(*types.Var); ok {
								check(kv.Value, f.Type())
							}
						}
					} else if i < u.NumFields() {
						check(el, u.Field(i).Type())
					}
				}
			case *types.Slice:
				for _, el := range x.Elts {
					check(valueOf(el), u.Elem())
				}
			case *types.Array:
				for _, el := range x.Elts {
					check(valueOf(el), u.Elem())
				}
			case *types.Map:
				for _, el := range x.Elts {
					if kv, ok := el.(*ast.KeyValueExpr); ok {
						check(kv.Key, u.Key())
						check(kv.Value, u.Elem())
					}
				}
			}
		}
		return true
	})
}

func valueOf(e ast.Expr) ast.Expr {
	if kv, ok := e.(*ast.KeyValueExpr); ok {
		return kv.Value
	}
	return e
}

// TestSMSFailureClassSinkCanFail shows the one exemption of the flow rule is only the argument of a
// call to a function of a sink package, and that it is not a way to keep a status as text.
func TestSMSFailureClassSinkCanFail(t *testing.T) {
	const storeSrc = "package store\ntype Text interface{ String() string }\ntype G struct{}\nfunc (G) Fail(c Text) {}\nfunc Keep(c Text) Text { return c }\n"
	cases := []struct {
		name, src string
		want      int
	}{
		{"a status handed to a store function", `func f(g store.G, a sms.Attempt) { g.Fail(a.Err.Status()) }`, 0},
		{"a status kept in a variable of the store's interface", `func f(a sms.Attempt) store.Text { var t store.Text = a.Err.Status(); return t }`, 1},
		{"a status returned through a store function", `func f(a sms.Attempt) string { return store.Keep(a.Err.Status()).String() }`, 0},
		{"a status assigned to the interface and then passed", `func f(g store.G, a sms.Attempt) { var t store.Text; t = a.Err.Status(); g.Fail(t) }`, 1},
	}
	for _, c := range cases {
		fset := token.NewFileSet()
		parse := func(p, src string) file {
			f, err := parser.ParseFile(fset, p, src, parser.ParseComments)
			if err != nil {
				t.Fatalf("%s: %v", c.name, err)
			}
			return file{path: p, ast: f}
		}
		fs := []file{
			parse("internal/sms/sms.go", stubSMSClass),
			parse("internal/store/s.go", storeSrc),
			parse("internal/worker/smssend/x.go", "package smssend\nimport \""+smsPkg+"\"\nimport \""+module+"/internal/store\"\nvar _ sms.Class\n"+c.src+"\n"),
		}
		info, ok := typeInfoReal(fset, fs)
		if !ok {
			t.Fatalf("%s: no type information", c.name)
		}
		got, _, _ := smsClassProblems(fset, fs, info)
		if len(got) != c.want {
			t.Errorf("%s: %d findings %v, want %d", c.name, len(got), got, c.want)
		}
	}
}
