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
	"internal/sms/sms.go:(*Error).Error":    "formats \"sms: <provider> <class> <code>\"",
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
		}
	}
	sort.Strings(problems)
	return dedupe(problems), used, scanned
}

func TestSMSFailureClassIsReadOnlyInClassify(t *testing.T) {
	fset, files := parseRepo(t)
	info, ok := typeInfoReal(fset, files)
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
		{"a renderer of package sms", "internal/sms/sms.go", `func (e *Error) Error() string { return e.Class.String() }`, 0},
		{"another method of package sms", "internal/sms/sms.go", `func (e *Error) Retry() bool { return e.Class == Auth }`, 2},
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
				parse(p, "package "+pkg+"\nimport \""+smsPkg+"\"\nvar _ sms.Class\n"+c.src+"\n"),
			}
		}
		info, ok := typeInfoReal(fset, fs)
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
