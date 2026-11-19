package lint_test

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/parser"
	"go/token"
	"go/types"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// The closed-values-in-logs rule (P1 auth review, round 5, topic 10; spec 8.6, 13.3).
//
// A log line, an audit row, an alert and a provider status column hold only values
// from closed sets, opaque ids and masked phones. The old guard was a deny list (a
// scan for runs of digits) applied to the field kinds somebody remembered, and each
// round found a kind (slices), a script (Devanagari) or a driver that escaped it.
// What replaces it is a type rule that cannot be forgotten for new code:
//
//  1. Every call on a *slog.Logger, and every slog function, has a constant message
//     and attributes that are calls into internal/logattr, whose functions take ints,
//     bools, ids, addresses and values of types that declare a closed set. Raw
//     key/value pairs, slog.String and slog.Any do not exist outside that package.
//     The key is a constant too. logattr's own signatures are judged by this file:
//     no function takes a plain string value (three named grammar helpers excepted).
//  2. An sms.Code is made in internal/sms/codes.go and nowhere else: no conversion
//     sms.Code(x) and no string literal that becomes one. A driver can say only what
//     the table says, and a reply it did not expect is the one fixed unknown code.
//  3. A closed type (a string type with a Valid method) is converted from a variable
//     string only inside its own package, where its Parse function lives.
//
// The audit and alert halves are reflection tests, because the field kinds of a
// struct are a type fact: internal/auth/audit (TestEveryEventFieldIsClosed) and
// internal/sms (TestAlertParamsAreClosed) walk the registered events and params with
// internal/closed.Check; a new event is covered because the test also parses the
// package for every type that carries the event marker method.

const (
	logattrPath = module + "/internal/logattr"
	smsPath     = module + "/internal/sms"
	codesFile   = "internal/sms/codes.go"
)

// slogAfterMessage is how many arguments precede the message, per slog method, or
// -1 for a method that has none.
var slogMessageAt = map[string]int{
	"Debug": 0, "Info": 0, "Warn": 0, "Error": 0,
	"DebugContext": 1, "InfoContext": 1, "WarnContext": 1, "ErrorContext": 1,
	"Log": 2, "LogAttrs": 2,
	"With": -1,
}

// slogConstructors build attributes. Outside internal/logattr none may be called.
var slogConstructors = map[string]bool{
	"String": true, "Int": true, "Int64": true, "Uint64": true, "Float64": true, "Bool": true,
	"Time": true, "Duration": true, "Any": true, "Group": true, "GroupAttrs": true,
}

// grammarHelpers are the logattr functions that take a plain string or an any. Each
// one checks its argument against a fixed grammar and reduces it to a fixed word when
// it does not fit; a new one needs a reviewer to add its name here.
var grammarHelpers = map[string]bool{"RequestID": true, "Release": true, "TypeName": true}

func isSlogPkg(p *types.Package) bool { return p != nil && p.Path() == "log/slog" }

// slogFunc says whether call is a method of *slog.Logger or a function of package
// slog, and which.
func slogFunc(info *types.Info, call *ast.CallExpr) (name string, ok bool) {
	return slogSelector(info, callSelector(call))
}

func callSelector(call *ast.CallExpr) *ast.SelectorExpr {
	fun := call.Fun
	for {
		switch f := fun.(type) {
		case *ast.ParenExpr:
			fun = f.X
			continue
		case *ast.IndexExpr:
			fun = f.X
			continue
		case *ast.IndexListExpr:
			fun = f.X
			continue
		case *ast.SelectorExpr:
			return f
		}
		return nil
	}
}

func slogSelector(info *types.Info, sel *ast.SelectorExpr) (string, bool) {
	if sel == nil {
		return "", false
	}
	if s, found := info.Selections[sel]; found {
		fn, isFn := s.Obj().(*types.Func)
		if !isFn || !isSlogPkg(fn.Pkg()) {
			return "", false
		}
		sig, _ := fn.Type().(*types.Signature)
		if sig == nil || sig.Recv() == nil {
			return "", false
		}
		rt := sig.Recv().Type()
		if p, isPtr := rt.(*types.Pointer); isPtr {
			rt = p.Elem()
		}
		if n, isNamed := rt.(*types.Named); isNamed && n.Obj().Name() == "Logger" {
			return fn.Name(), true
		}
		return "", false
	}
	if fn, isFn := info.Uses[sel.Sel].(*types.Func); isFn && isSlogPkg(fn.Pkg()) {
		if sig, _ := fn.Type().(*types.Signature); sig != nil && sig.Recv() == nil {
			return fn.Name(), true
		}
	}
	return "", false
}

func unparen(e ast.Expr) ast.Expr {
	for {
		p, ok := e.(*ast.ParenExpr)
		if !ok {
			return e
		}
		e = p.X
	}
}

// logattrCall returns the logattr function a call invokes, or nil.
func logattrCall(info *types.Info, e ast.Expr) (*ast.CallExpr, *types.Func) {
	call, ok := unparen(e).(*ast.CallExpr)
	if !ok {
		return nil, nil
	}
	sel := callSelector(call)
	if sel == nil {
		return nil, nil
	}
	if fn, isFn := info.Uses[sel.Sel].(*types.Func); isFn && fn.Pkg() != nil && fn.Pkg().Path() == logattrPath {
		return call, fn
	}
	return nil, nil
}

func isConstString(info *types.Info, e ast.Expr) bool {
	tv, ok := info.Types[e]
	return ok && tv.Value != nil && tv.Value.Kind() == constant.String
}

// slogProblems judges rule 1 over the non-test files.
func slogProblems(fset *token.FileSet, files []file, info *types.Info) (problems []string, sinks int) {
	add := func(n ast.Node, format string, args ...any) {
		problems = append(problems, fmt.Sprintf("%s: %s", fset.Position(n.Pos()), fmt.Sprintf(format, args...)))
	}
	for _, f := range files {
		if f.test {
			continue
		}
		inLogattr := strings.HasPrefix(f.path, "internal/logattr/")
		called := map[*ast.SelectorExpr]bool{}
		ast.Inspect(f.ast, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if sel := callSelector(call); sel != nil {
				called[sel] = true
			}
			// A call into logattr: the key is a constant.
			if lc, fn := logattrCall(info, call); lc != nil && !inLogattr {
				if sig, _ := fn.Type().(*types.Signature); sig != nil && sig.Params().Len() > 0 && sig.Params().At(0).Name() == "key" {
					if len(lc.Args) == 0 || !isConstString(info, lc.Args[0]) {
						add(lc, "logattr.%s is given a key that is not a constant", fn.Name())
					}
				}
			}
			name, isSlog := slogFunc(info, call)
			if !isSlog || inLogattr {
				return true
			}
			switch {
			case name == "WithGroup":
				sinks++
				if len(call.Args) != 1 || !isConstString(info, call.Args[0]) {
					add(call, "slog %s with a group name that is not a constant", name)
				}
				return true
			case slogConstructors[name]:
				add(call, "slog.%s builds an attribute outside internal/logattr", name)
				return true
			}
			at, isSink := slogMessageAt[name]
			if !isSink {
				return true
			}
			sinks++
			first := at + 1
			if at >= 0 {
				if len(call.Args) <= at || !isConstString(info, call.Args[at]) {
					add(call, "slog %s with a message that is not a constant string", name)
				}
			} else {
				first = 0
			}
			for i := first; i < len(call.Args); i++ {
				if call.Ellipsis.IsValid() && i == len(call.Args)-1 {
					add(call.Args[i], "slog %s with a spread attribute list; every attribute must be a visible logattr call", name)
					continue
				}
				if lc, _ := logattrCall(info, call.Args[i]); lc == nil {
					add(call.Args[i], "slog %s argument is not a logattr call (a raw key or value)", name)
				}
			}
			return true
		})
		// A Logger method or slog function taken as a value escapes the call check.
		ast.Inspect(f.ast, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.SelectorExpr:
				if inLogattr || called[x] {
					return true
				}
				if name, ok := slogSelector(info, x); ok && (slogConstructors[name] || slogMessageAt[name] != 0 || name == "Debug" || name == "Info" || name == "Warn" || name == "Error") {
					add(x, "slog %s used as a value, which hides its arguments", name)
				}
			case *ast.CompositeLit:
				if inLogattr {
					return true
				}
				if t, ok := info.Types[x]; ok {
					if nt, isNamed := t.Type.(*types.Named); isNamed && isSlogPkg(nt.Obj().Pkg()) && nt.Obj().Name() == "Attr" {
						add(x, "slog.Attr literal outside internal/logattr")
					}
				}
			}
			return true
		})
	}
	sort.Strings(problems)
	return problems, sinks
}

// apiProblems judges the signatures of internal/logattr: a function that takes a
// plain string value would be the hole the package exists to close.
func apiProblems(fset *token.FileSet, files []file) (problems []string, funcs int) {
	for _, f := range files {
		if f.test || !strings.HasPrefix(f.path, "internal/logattr/") {
			continue
		}
		for _, d := range f.ast.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Recv != nil || !fd.Name.IsExported() {
				continue
			}
			funcs++
			closedParams := map[string]bool{}
			if fd.Type.TypeParams != nil {
				for _, tp := range fd.Type.TypeParams.List {
					if sel, isSel := tp.Type.(*ast.SelectorExpr); isSel && sel.Sel.Name == "Closed" {
						for _, n := range tp.Names {
							closedParams[n.Name] = true
						}
					}
				}
			}
			for _, p := range fd.Type.Params.List {
				for _, n := range p.Names {
					if !paramAllowed(p.Type, n.Name, fd.Name.Name, closedParams) {
						problems = append(problems, fmt.Sprintf("%s: logattr.%s takes %s as %s, which is not a closed kind",
							fset.Position(p.Pos()), fd.Name.Name, n.Name, exprString(p.Type)))
					}
				}
			}
		}
	}
	return problems, funcs
}

func exprString(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.SelectorExpr:
		return exprString(x.X) + "." + x.Sel.Name
	case *ast.ArrayType:
		return "[]" + exprString(x.Elt)
	case *ast.InterfaceType:
		return "interface"
	}
	return fmt.Sprintf("%T", e)
}

func paramAllowed(t ast.Expr, name, fn string, closedParams map[string]bool) bool {
	if name == "key" {
		id, ok := t.(*ast.Ident)
		return ok && id.Name == "string"
	}
	switch x := t.(type) {
	case *ast.Ident:
		switch x.Name {
		case "int", "bool", "error":
			return true
		case "string", "any":
			return grammarHelpers[fn]
		}
		return closedParams[x.Name]
	case *ast.SelectorExpr:
		s := exprString(x)
		return s == "uuid.UUID" || s == "netip.AddrPort" || s == "time.Duration"
	case *ast.ArrayType:
		if id, ok := x.Elt.(*ast.Ident); ok {
			return closedParams[id.Name]
		}
	}
	return false
}

// codeProblems judges rules 2 and 3.
func codeProblems(fset *token.FileSet, files []file, info *types.Info) []string {
	var problems []string
	add := func(n ast.Node, format string, args ...any) {
		problems = append(problems, fmt.Sprintf("%s: %s", fset.Position(n.Pos()), fmt.Sprintf(format, args...)))
	}
	isCode := func(t types.Type) bool {
		n, ok := t.(*types.Named)
		return ok && n.Obj().Name() == "Code" && n.Obj().Pkg() != nil && n.Obj().Pkg().Path() == smsPath
	}
	paths := map[string]string{} // filename on disk -> repo path
	for _, f := range files {
		paths[fset.Position(f.ast.Pos()).Filename] = f.path
	}
	repoPath := func(n ast.Node) string { return paths[fset.Position(n.Pos()).Filename] }

	// Rule 2a: a conversion to sms.Code.
	for _, f := range files {
		if f.test || f.path == codesFile {
			continue
		}
		ast.Inspect(f.ast, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) != 1 {
				return true
			}
			if tv, known := info.Types[call.Fun]; known && tv.IsType() && isCode(tv.Type) {
				add(call, "conversion to sms.Code outside %s", codesFile)
			}
			return true
		})
	}
	// Rule 2b: a constant that becomes an sms.Code without naming a table entry.
	for e, tv := range info.Types {
		if tv.Value == nil || !isCode(tv.Type) {
			continue
		}
		path := repoPath(e)
		if path == "" || path == codesFile || strings.HasSuffix(path, "_test.go") {
			continue
		}
		var id *ast.Ident
		switch x := unparen(e).(type) {
		case *ast.Ident:
			id = x
		case *ast.SelectorExpr:
			id = x.Sel
		}
		if id != nil {
			if obj := info.Uses[id]; obj != nil && fset.Position(obj.Pos()).Filename != "" && paths[fset.Position(obj.Pos()).Filename] == codesFile {
				continue
			}
		}
		add(e, "a literal or constant expression becomes an sms.Code outside %s; name an entry of the table", codesFile)
	}
	// Rule 3: a variable string converted to a closed type outside its package.
	for _, f := range files {
		if f.test {
			continue
		}
		here := module + "/" + filepath.ToSlash(filepath.Dir(f.path))
		ast.Inspect(f.ast, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) != 1 {
				return true
			}
			tv, known := info.Types[call.Fun]
			if !known || !tv.IsType() {
				return true
			}
			named, isNamed := tv.Type.(*types.Named)
			// The generated OpenAPI enums (…/gen) are closed strings too, but they describe the
			// API's own vocabulary and are filled from database columns by design; the rule is
			// about what reaches a log, an audit row or a status column.
			if isNamed && isCode(named) {
				return true // rule 2 judges it
			}
			if !isNamed || named.Obj().Pkg() == nil || named.Obj().Pkg().Path() == here || strings.HasSuffix(named.Obj().Pkg().Path(), "/gen") {
				return true
			}
			if b, isBasic := named.Underlying().(*types.Basic); !isBasic || b.Kind() != types.String {
				return true
			}
			if m, _, _ := types.LookupFieldOrMethod(named, false, named.Obj().Pkg(), "Valid"); m == nil {
				return true
			}
			if arg := info.Types[call.Args[0]]; arg.Value == nil {
				add(call, "%s.%s is built from a variable string outside its package; use its Parse function", named.Obj().Pkg().Name(), named.Obj().Name())
			}
			return true
		})
	}
	sort.Strings(problems)
	return dedupe(problems)
}

func TestClosedValuesInLogs(t *testing.T) {
	fset, files := parseRepo(t)
	info, ok := typeInfoReal(fset, files, "log/slog")
	if !ok {
		t.Fatal("type information unavailable")
	}
	problems, sinks := slogProblems(fset, files, info)
	for _, p := range problems {
		t.Error(p)
	}
	if sinks < 20 {
		t.Fatalf("only %d slog calls were examined; the lint is not seeing the logger", sinks)
	}
	api, funcs := apiProblems(fset, files)
	for _, p := range api {
		t.Error(p)
	}
	if funcs < 5 {
		t.Fatalf("only %d logattr functions found", funcs)
	}
	for _, p := range codeProblems(fset, files, info) {
		t.Error(p)
	}
}

// in-memory packages for the can-fail test.
const (
	stubLogattr = `package logattr
import "log/slog"
func Int(key string, n int) slog.Attr { return slog.Attr{} }
func Mask(key string) slog.Attr { return slog.Attr{} }
`
	stubSMS = `package sms
type Code string
const CodeTimeout Code = "timeout"
func (c Code) Valid() bool { return true }
type Tag string
func (t Tag) Valid() bool { return true }
func ParseTag(s string) Tag { return Tag(s) }
func NewError(code Code) {}
`
)

func TestClosedValuesLintCanFail(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want int
	}{
		{"constant message and a logattr attribute", `func f(l *slog.Logger) { l.Info("x", logattr.Int("n", 1)) }`, 0},
		{"a raw key and value pair", `func f(l *slog.Logger, v string) { l.Info("x", "k", v) }`, 2},
		{"slog.String", `func f(l *slog.Logger, v string) { l.Info("x", slog.String("k", v)) }`, 2},
		{"slog.Any", `func f(l *slog.Logger, v any) { l.Warn("x", slog.Any("k", v)) }`, 2},
		{"a message built at run time", `func f(l *slog.Logger, v string) { l.Error("bad " + v) }`, 1},
		{"a message from a constant", `const m = "x"
func f(l *slog.Logger) { l.Error(m) }`, 0},
		{"the package function", `func f(v string) { slog.Info(v) }`, 1},
		{"with context", `func f(l *slog.Logger, c context.Context, v string) { l.WarnContext(c, "x", "k", v) }`, 2},
		{"Log with a level", `func f(l *slog.Logger, c context.Context, v string) { l.Log(c, slog.LevelInfo, "x", "k", v) }`, 2},
		{"With", `func f(l *slog.Logger, v string) *slog.Logger { return l.With("k", v) }`, 2},
		{"With and a logattr call", `func f(l *slog.Logger) *slog.Logger { return l.With(logattr.Int("k", 1)) }`, 0},
		{"a spread list", `func f(l *slog.Logger, a ...any) { l.Info("x", a...) }`, 1},
		{"a key that is a variable", `func f(l *slog.Logger, k string) { l.Info("x", logattr.Int(k, 1)) }`, 1},
		{"an Attr literal", `func f(l *slog.Logger) { l.Info("x", slog.Attr{}) }`, 2},
		{"a method taken as a value", `func f(l *slog.Logger) { g := l.Info; g("x", "k", "v") }`, 1},
		{"a struct field logger", `type s struct{ log *slog.Logger }
func (x *s) f(v string) { x.log.Warn("x", "k", v) }`, 2},
		{"an embedded logger", `type s struct{ *slog.Logger }
func (x *s) f(v string) { x.Warn("x", "k", v) }`, 2},
		{"another type with an Info method", `type o struct{}
func (o) Info(string, ...any) {}
func f(x o, v string) { x.Info("x", "k", v) }`, 0},
		{"a code conversion", `func f(v string) { sms.NewError(sms.Code("value_" + v)) }`, 1},
		{"a code from a literal", `func f() { sms.NewError("timeout") }`, 1},
		{"a code from the table", `func f() { sms.NewError(sms.CodeTimeout) }`, 0},
		{"a code compared with a literal", `func f(c sms.Code) bool { return c == "x" }`, 1},
		{"a closed type from a variable", `func f(v string) sms.Tag { return sms.Tag(v) }`, 1},
		{"a closed type from a constant", `func f() sms.Tag { return sms.Tag("fixed") }`, 0},
		{"a closed type through its Parse function", `func f(v string) sms.Tag { return sms.ParseTag(v) }`, 0},
	}
	for _, c := range cases {
		fset := token.NewFileSet()
		parse := func(path, src string) file {
			f, err := parser.ParseFile(fset, path, src, parser.ParseComments)
			if err != nil {
				t.Fatalf("%s: %v", c.name, err)
			}
			return file{path: path, ast: f}
		}
		src := "package x\nimport (\n\t\"context\"\n\t\"log/slog\"\n\t\"" + logattrPath + "\"\n\t\"" + smsPath + "\"\n)\nvar _ context.Context\nvar _ slog.Level\nvar _ = logattr.Mask\nvar _ sms.Code\n" + c.src + "\n"
		fs := []file{
			parse("internal/logattr/logattr.go", stubLogattr),
			parse(codesFile, stubSMS),
			parse("internal/worker/x/x.go", src),
		}
		info, ok := typeInfoReal(fset, fs, "log/slog")
		if !ok {
			t.Fatalf("%s: no type information", c.name)
		}
		got, _ := slogProblems(fset, fs, info)
		got = append(got, codeProblems(fset, fs, info)...)
		if len(got) != c.want {
			t.Errorf("%s: %d findings %v, want %d", c.name, len(got), got, c.want)
		}
	}
}

func TestLogattrAPILintCanFail(t *testing.T) {
	cases := []struct {
		src  string
		want int
	}{
		{`func Int(key string, n int) slog.Attr { return slog.Attr{} }`, 0},
		{`func Str(key string, v string) slog.Attr { return slog.Attr{} }`, 1},
		{`func Note(key string, v any) slog.Attr { return slog.Attr{} }`, 1},
		{`func Err(key string, err error) slog.Attr { return slog.Attr{} }`, 0},
		{`func Enum[T closed.Closed](key string, v T) slog.Attr { return slog.Attr{} }`, 0},
		{`func Enum[T fmt.Stringer](key string, v T) slog.Attr { return slog.Attr{} }`, 1},
		{`func Many[T closed.Closed](key string, v []T) slog.Attr { return slog.Attr{} }`, 0},
		{`func ID(key string, id uuid.UUID) slog.Attr { return slog.Attr{} }`, 0},
		{`func Bytes(key string, b []byte) slog.Attr { return slog.Attr{} }`, 1},
		{`func RequestID(id string) slog.Attr { return slog.Attr{} }`, 0},
		{`func Key(k string) slog.Attr { return slog.Attr{} }`, 1}, // the one string parameter is named key
		{`func unexported(key string, v string) {}`, 0},
	}
	for _, c := range cases {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, "internal/logattr/x.go", "package logattr\n"+c.src, 0)
		if err != nil {
			t.Fatal(err)
		}
		got, _ := apiProblems(fset, []file{{path: "internal/logattr/x.go", ast: f}})
		if len(got) != c.want {
			t.Errorf("%s: %d findings %v, want %d", c.src, len(got), got, c.want)
		}
	}
}
