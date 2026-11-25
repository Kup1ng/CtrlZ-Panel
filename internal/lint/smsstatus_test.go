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

// The store decides nothing on a status (P1 auth review round 17, sms-r17-11; rule
// sms-failure-classification).
//
// The flow rule (smsClassFlows) lets a status, which holds a failure class, meet an interface only as the
// closed.Text parameter of a function of internal/store, because the store writes the status column and
// decides nothing on it. That was a premise with no check: inside the store the value is a closed.Text
// interface, and neither the selector clauses nor the flow clause can see store code that calls String() on
// it and branches on "auth:" or "transient:". The class would then be decided in a second place, which is
// the drift the rule exists to stop.
//
// The premise is now enforced by one fail-closed shape. In every non-test file of internal/store, a value
// of type closed.Text:
//
//  1. is used only as the argument of textArg, or inside textArg (the one function that turns it into a
//     query argument: nil, ErrConstraint for a word off its list, or its text);
//  2. in textArg, which is exactly three statements (the nil check, the Valid check that returns
//     ErrConstraint, and the return of emptyNull(t.String())), meets its parameter only there: the shape
//     of the whole body is matched, so any other use of the parameter fails (sms-r17-18); and
//  3. every caller of textArg uses the first value it returns only as an argument of a database call.
//
// So no other expression of the store holds one: not a variable, a field, a return, a comparison, a method
// call. A new store method that takes a status hands it to textArg or fails.
//
// Contract. It judges the non-test files of internal/store by the static types go/types records. It does
// not judge a status that arrives as a value of another type (a string), which holds no class by
// construction (closed.Text is the only way a status enters the store), nor the SQL a status is written
// with.

const (
	storeDir      = "internal/store"
	statusFunc    = "textArg"
	statusCarrier = "emptyNull"
)

func storeStatusProblems(fset *token.FileSet, files []file, info *types.Info) []string {
	var out []string
	for _, f := range files {
		if f.test || dirOf(f.path) != storeDir {
			continue
		}
		isStatusCall := func(c *ast.CallExpr) bool {
			fn := callee(info, c)
			return fn != nil && fn.Name() == statusFunc && fn.Pkg() != nil && strings.TrimPrefix(fn.Pkg().Path(), module+"/") == storeDir
		}
		var stack []ast.Node
		inTextArg := func() bool {
			for i := len(stack) - 1; i >= 0; i-- {
				if fd, ok := stack[i].(*ast.FuncDecl); ok {
					return fd.Name.Name == statusFunc && fd.Recv == nil
				}
			}
			return false
		}
		ast.Inspect(f.ast, func(n ast.Node) bool {
			if n == nil {
				stack = stack[:len(stack)-1]
				return true
			}
			stack = append(stack, n)
			e, ok := n.(ast.Expr)
			if !ok {
				return true
			}
			tv, known := info.Types[e]
			if !known || tv.IsType() || tv.Type == nil || !isClosedText(tv.Type) {
				return true
			}
			if inTextArg() {
				return true
			}
			if len(stack) >= 2 {
				if c, ok := stack[len(stack)-2].(*ast.CallExpr); ok && isStatusCall(c) {
					for _, a := range c.Args {
						if a == e {
							return true
						}
					}
				}
			}
			out = append(out, fmt.Sprintf("%s: a closed.Text (a status, which holds a failure class) is used in internal/store other than as the argument of %s; the store writes the status column and decides nothing on it (rule sms-failure-classification)", fset.Position(e.Pos()), statusFunc))
			return true
		})
		// Parts 2 and 3: the shape of textArg itself, and what its callers do with the result.
		ast.Inspect(f.ast, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.FuncDecl:
				if x.Name.Name == statusFunc && x.Recv == nil && x.Body != nil {
					out = append(out, textArgShape(fset, x, info)...)
				}
			case *ast.AssignStmt:
				if len(x.Rhs) == 1 {
					if c, ok := x.Rhs[0].(*ast.CallExpr); ok && isStatusCall(c) && len(x.Lhs) >= 1 {
						out = append(out, textArgResultUses(fset, f.ast, x, info)...)
					}
				}
			case *ast.CallExpr:
				if isStatusCall(x) && !callIsAssigned(f.ast, x) {
					out = append(out, fmt.Sprintf("%s: the result of %s must be assigned and used only as an argument of a database call", fset.Position(x.Pos()), statusFunc))
				}
			}
			return true
		})
	}
	sort.Strings(out)
	return dedupe(out)
}

func callIsAssigned(root *ast.File, c *ast.CallExpr) bool {
	found := false
	ast.Inspect(root, func(n ast.Node) bool {
		if as, ok := n.(*ast.AssignStmt); ok && len(as.Rhs) == 1 && as.Rhs[0] == c {
			found = true
		}
		return !found
	})
	return found
}

// textArgShape checks part 2: textArg is exactly the three statements of its contract, and so every use of
// its parameter is one of three, which are the only ones that cannot decide on a class:
//
//	if t == nil { return nil, nil }              // no status was given
//	if !t.Valid() { return nil, ErrConstraint }  // a word off its list is refused, never stored
//	return emptyNull(t.String()), nil            // the text goes to the query and nowhere else
//
// It is a match of the whole body and not a search for bad uses (sms-r17-18): a type switch on the status,
// fmt.Sprint(t), a second branch on Valid, a field read, a helper handed t, or a fourth statement is not on
// the list of what to refuse, it is simply not one of the three, so it fails.
func textArgShape(fset *token.FileSet, fd *ast.FuncDecl, info *types.Info) []string {
	bad := func(what string) []string {
		return []string{fmt.Sprintf("%s: %s %s; its body must be exactly the three statements of its contract (rule sms-failure-classification)", fset.Position(fd.Pos()), statusFunc, what)}
	}
	p := textArgParam(fd, info)
	if p == nil {
		return bad("must take one closed.Text parameter and nothing else")
	}
	if len(fd.Body.List) != 3 {
		return bad("must have exactly three statements")
	}
	var out []string
	for i, ok := range []bool{
		isNilGuard(fd.Body.List[0], p, info),
		isValidGuard(fd.Body.List[1], p, info),
		isTextReturn(fd.Body.List[2], p, info),
	} {
		if !ok {
			out = append(out, bad(fmt.Sprintf("has a statement %d that is not the one of its contract", i+1))...)
		}
	}
	return out
}

// textArgParam is the one parameter of textArg, else nil. Its type is not judged: only a closed.Text has the
// methods the three statements call, and the type checker has already refused any other.
func textArgParam(fd *ast.FuncDecl, info *types.Info) types.Object {
	ps := fd.Type.Params
	if ps == nil || len(ps.List) != 1 || len(ps.List[0].Names) != 1 {
		return nil
	}
	return info.Defs[ps.List[0].Names[0]]
}

func isParam(e ast.Expr, p types.Object, info *types.Info) bool {
	id, ok := e.(*ast.Ident)
	return ok && info.Uses[id] == p
}

func isNilExpr(e ast.Expr, info *types.Info) bool {
	tv, ok := info.Types[e]
	return ok && tv.IsNil()
}

// isNamed reports an identifier that resolves to an object of that name. textArg has no scope of its own to
// shadow it in (its body is three fixed statements), so the name is the store function or variable.
func isNamed(e ast.Expr, name string, info *types.Info) bool {
	id, ok := e.(*ast.Ident)
	if !ok {
		return false
	}
	obj := info.Uses[id]
	return obj != nil && obj.Name() == name
}

// returnsOnly reports a block of one statement, a return of two values the given tests accept.
func returnsOnly(b *ast.BlockStmt, first, second func(ast.Expr) bool) bool {
	if b == nil || len(b.List) != 1 {
		return false
	}
	r, ok := b.List[0].(*ast.ReturnStmt)
	return ok && len(r.Results) == 2 && first(r.Results[0]) && second(r.Results[1])
}

func isNilGuard(s ast.Stmt, p types.Object, info *types.Info) bool {
	ifs, ok := s.(*ast.IfStmt)
	if !ok || ifs.Init != nil || ifs.Else != nil {
		return false
	}
	b, ok := ifs.Cond.(*ast.BinaryExpr)
	if !ok || b.Op != token.EQL || !isParam(b.X, p, info) || !isNilExpr(b.Y, info) {
		return false
	}
	isNil := func(e ast.Expr) bool { return isNilExpr(e, info) }
	return returnsOnly(ifs.Body, isNil, isNil)
}

func isValidGuard(s ast.Stmt, p types.Object, info *types.Info) bool {
	ifs, ok := s.(*ast.IfStmt)
	if !ok || ifs.Init != nil || ifs.Else != nil {
		return false
	}
	u, ok := ifs.Cond.(*ast.UnaryExpr)
	if !ok || u.Op != token.NOT {
		return false
	}
	call, ok := u.X.(*ast.CallExpr)
	if !ok || len(call.Args) != 0 {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Valid" || !isParam(sel.X, p, info) {
		return false
	}
	return returnsOnly(ifs.Body, func(e ast.Expr) bool { return isNilExpr(e, info) }, func(e ast.Expr) bool { return isNamed(e, "ErrConstraint", info) })
}

func isTextReturn(s ast.Stmt, p types.Object, info *types.Info) bool {
	r, ok := s.(*ast.ReturnStmt)
	if !ok || len(r.Results) != 2 || !isNilExpr(r.Results[1], info) {
		return false
	}
	outer, ok := r.Results[0].(*ast.CallExpr)
	if !ok || len(outer.Args) != 1 || !isNamed(outer.Fun, statusCarrier, info) {
		return false
	}
	inner, ok := outer.Args[0].(*ast.CallExpr)
	if !ok || len(inner.Args) != 0 {
		return false
	}
	sel, ok := inner.Fun.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "String" && isParam(sel.X, p, info)
}

// textArgResultUses checks part 3 for one assignment of the result of textArg: the first variable it
// assigns is used only as an argument of a call of a database sink.
func textArgResultUses(fset *token.FileSet, root *ast.File, as *ast.AssignStmt, info *types.Info) []string {
	id, ok := as.Lhs[0].(*ast.Ident)
	if !ok {
		return []string{fmt.Sprintf("%s: the result of %s must be assigned to a variable", fset.Position(as.Pos()), statusFunc)}
	}
	if id.Name == "_" {
		return nil
	}
	obj := info.ObjectOf(id)
	var out []string
	var stack []ast.Node
	ast.Inspect(root, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		stack = append(stack, n)
		use, ok := n.(*ast.Ident)
		if !ok || use == id || obj == nil || info.Uses[use] != obj {
			return true
		}
		allowed := false
		if len(stack) >= 2 {
			// A comparison with nil says only that no status was given; it reads nothing of the text.
			if b, ok := stack[len(stack)-2].(*ast.BinaryExpr); ok && (b.Op == token.EQL || b.Op == token.NEQ) {
				other := b.X
				if other == ast.Expr(use) {
					other = b.Y
				}
				if tv, ok := info.Types[other]; ok && tv.IsNil() {
					allowed = true
				}
			}
			if c, ok := stack[len(stack)-2].(*ast.CallExpr); ok {
				if _, isSink := sqlSinks()[calleeName(c.Fun)]; isSink {
					for _, a := range c.Args {
						if a == use {
							allowed = true
						}
					}
				}
			}
		}
		if !allowed {
			out = append(out, fmt.Sprintf("%s: the text of a status is used other than as an argument of a database call (rule sms-failure-classification)", fset.Position(use.Pos())))
		}
		return true
	})
	return out
}

func TestTheStoreDecidesNothingOnAStatus(t *testing.T) {
	fset, files := parseRepo(t)
	info, ok := typeInfoReal(fset, files, "fmt", "strings", "regexp", "bytes")
	if !ok {
		t.Fatal("type information unavailable")
	}
	for _, p := range storeStatusProblems(fset, files, info) {
		t.Error(p)
	}
	// The rule must have looked at the function it is about.
	seen := false
	for _, f := range files {
		if f.test || dirOf(f.path) != storeDir {
			continue
		}
		for _, d := range f.ast.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Name.Name == statusFunc && fd.Recv == nil {
				seen = true
			}
		}
	}
	if !seen {
		t.Errorf("internal/store has no %s; the rule is looking in the wrong place", statusFunc)
	}
}

// TestStoreStatusLintCanFail plants each way a store function could decide on a status, and the clean
// shape that must stay allowed.
func TestStoreStatusLintCanFail(t *testing.T) {
	const closedSrc = "package closed\ntype Text interface{ String() string; Valid() bool }\n"
	const head = "package store\nimport \"strings\"\nimport \"" + module + "/internal/closed\"\nvar _ = strings.HasPrefix\ntype D struct{ State closed.Text }\ntype DB struct{}\nfunc (DB) Exec(ctx any, sql string, args ...any) {}\nfunc emptyNull(s string) any { return s }\nvar ErrConstraint error\n"
	const good = "func textArg(t closed.Text) (any, error) {\n\tif t == nil { return nil, nil }\n\tif !t.Valid() { return nil, ErrConstraint }\n\treturn emptyNull(t.String()), nil\n}\n"
	cases := []struct {
		name, src string
		want      int
	}{
		{"the clean shape", good + `func (db DB) Fail(ctx any, code closed.Text) error { arg, err := textArg(code); if err != nil { return err }; db.Exec(ctx, "q", arg); return nil }`, 0},
		{"a field handed to textArg", good + `func (db DB) Rec(ctx any, d D) error { arg, err := textArg(d.State); if err != nil { return err }; db.Exec(ctx, "q", arg); return nil }`, 0},
		{"a branch on the text of the status", good + `func (db DB) Fail(ctx any, code closed.Text) error { if strings.HasPrefix(code.String(), "auth:") { return nil }; arg, _ := textArg(code); db.Exec(ctx, "q", arg); return nil }`, -1},
		{"a helper that is handed the status", good + "func note(v closed.Text) bool { return v != nil }\nfunc (db DB) Fail(ctx any, code closed.Text) error { note(code); arg, _ := textArg(code); db.Exec(ctx, \"q\", arg); return nil }", -1},
		// A helper that never reads its parameter: only the call that hands it the status is the evidence.
		{"a helper that is handed the status and reads nothing", good + "func note(closed.Text) {}\nfunc (db DB) Fail(ctx any, code closed.Text) error { note(code); arg, _ := textArg(code); db.Exec(ctx, \"q\", arg); return nil }", -1},
		{"the status kept in a variable", good + `func (db DB) Fail(ctx any, code closed.Text) error { c := code; arg, _ := textArg(c); db.Exec(ctx, "q", arg); return nil }`, -1},
		{"the status handed back", good + `func Keep(code closed.Text) closed.Text { return code }`, -1},
		{"the status stored in a struct", good + `func Put(code closed.Text) D { return D{State: code} }`, -1},
		{"the text of the argument inspected", good + `func (db DB) Fail(ctx any, code closed.Text) error { arg, _ := textArg(code); if s, ok := arg.(string); ok && strings.HasPrefix(s, "auth") { return nil }; db.Exec(ctx, "q", arg); return nil }`, -1},
		{"the result compared with nil", good + `func (db DB) Fail(ctx any, code closed.Text) error { arg, _ := textArg(code); if arg == nil { return nil }; db.Exec(ctx, "q", arg); return nil }`, 0},
		{"the result compared with a word", good + `func (db DB) Fail(ctx any, code closed.Text) error { arg, _ := textArg(code); if arg == "auth:x" { return nil }; db.Exec(ctx, "q", arg); return nil }`, -1},
		{"the result of textArg thrown into a decision", good + "func (db DB) Fail(ctx any, code closed.Text) error { arg, _ := textArg(code); return check(arg) }\nfunc check(any) error { return nil }", -1},
		{"the result of textArg not assigned", good + "func (db DB) Fail(ctx any, code closed.Text) { use(textArg(code)) }\nfunc use(any, error) {}", -1},
		{"textArg that branches on the text", "func textArg(t closed.Text) (any, error) {\n\tif strings.HasPrefix(t.String(), \"auth:\") { return nil, nil }\n\treturn emptyNull(t.String()), nil\n}\n", -1},
		{"textArg that keeps the text", "func textArg(t closed.Text) (any, error) {\n\ts := t.String()\n\treturn emptyNull(s), nil\n}\n", -1},
		// Every other use of the parameter inside textArg (sms-r17-18): none is on a list of spellings, the body
		// is matched whole.
		{"textArg with a type switch on the status", "func textArg(t closed.Text) (any, error) {\n\tswitch t.(type) {\n\tcase interface{ Class() int }:\n\t\treturn nil, nil\n\t}\n\tif t == nil { return nil, nil }\n\tif !t.Valid() { return nil, ErrConstraint }\n\treturn emptyNull(t.String()), nil\n}\n", -1},
		{"textArg that prints the status", "func textArg(t closed.Text) (any, error) {\n\tif fmt.Sprint(t) == \"auth:x\" { return nil, nil }\n\tif t == nil { return nil, nil }\n\tif !t.Valid() { return nil, ErrConstraint }\n\treturn emptyNull(t.String()), nil\n}\n", -1},
		{"textArg with an extra statement after the contract", "func textArg(t closed.Text) (any, error) {\n\tif t == nil { return nil, nil }\n\tif !t.Valid() { return nil, ErrConstraint }\n\treturn emptyNull(t.String()), nil\n\tprintln(t.String())\n}\n", -1},
		{"textArg without the nil check", "func textArg(t closed.Text) (any, error) {\n\tif t != nil { return nil, nil }\n\tif !t.Valid() { return nil, ErrConstraint }\n\treturn emptyNull(t.String()), nil\n}\n", -1},
		{"textArg whose nil check returns a value", "func textArg(t closed.Text) (any, error) {\n\tif t == nil { return \"x\", nil }\n\tif !t.Valid() { return nil, ErrConstraint }\n\treturn emptyNull(t.String()), nil\n}\n", -1},
		{"textArg that lets a word off its list through", "func textArg(t closed.Text) (any, error) {\n\tif t == nil { return nil, nil }\n\tif !t.Valid() { return nil, nil }\n\treturn emptyNull(t.String()), nil\n}\n", -1},
		{"textArg whose Valid check is not a negation", "func textArg(t closed.Text) (any, error) {\n\tif t == nil { return nil, nil }\n\tif t.Valid() { return nil, ErrConstraint }\n\treturn emptyNull(t.String()), nil\n}\n", -1},
		{"textArg that returns the text without emptyNull", "func textArg(t closed.Text) (any, error) {\n\tif t == nil { return nil, nil }\n\tif !t.Valid() { return nil, ErrConstraint }\n\treturn t.String(), nil\n}\n", -1},
		{"textArg that returns an error beside the text", "func textArg(t closed.Text) (any, error) {\n\tif t == nil { return nil, nil }\n\tif !t.Valid() { return nil, ErrConstraint }\n\treturn emptyNull(t.String()), ErrConstraint\n}\n", -1},
		{"textArg that returns another error for a word off its list", "var errOther error\nfunc textArg(t closed.Text) (any, error) {\n\tif t == nil { return nil, nil }\n\tif !t.Valid() { return nil, errOther }\n\treturn emptyNull(t.String()), nil\n}\n", -1},
		{"textArg that hands the text to another function", "func other(s string) any { return s }\nfunc textArg(t closed.Text) (any, error) {\n\tif t == nil { return nil, nil }\n\tif !t.Valid() { return nil, ErrConstraint }\n\treturn other(t.String()), nil\n}\n", -1},
		{"textArg that takes a second parameter", "func textArg(t closed.Text, u closed.Text) (any, error) {\n\tif t == nil { return nil, nil }\n\tif !t.Valid() { return nil, ErrConstraint }\n\treturn emptyNull(t.String()), nil\n}\n", -1},
		{"textArg that takes a string", "func textArg(t string) (any, error) {\n\treturn emptyNull(t), nil\n}\n", -1},
	}
	for _, c := range cases {
		fset := token.NewFileSet()
		parse := func(p, src string) file {
			f, err := parser.ParseFile(fset, p, src, parser.ParseComments)
			if err != nil {
				t.Fatalf("%s: %v\n%s", c.name, err, src)
			}
			return file{path: p, ast: f}
		}
		fs := []file{parse("internal/closed/closed.go", closedSrc), parse("internal/store/s.go", head+c.src+"\n")}
		info, ok := typeInfoReal(fset, fs, "strings", "fmt")
		if !ok {
			t.Fatalf("%s: no type information", c.name)
		}
		got := storeStatusProblems(fset, fs, info)
		// want -1 means "at least one": the exact count depends on how many expressions of the status a
		// planted shape has, and the property is that it is refused.
		if (c.want == 0 && len(got) != 0) || (c.want < 0 && len(got) == 0) {
			t.Errorf("%s: %d problems %v, want %s", c.name, len(got), got, map[bool]string{true: "none", false: "some"}[c.want == 0])
		}
	}
}
