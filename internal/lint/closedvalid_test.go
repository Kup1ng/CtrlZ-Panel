package lint_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Rule closed-values-in-logs, round 6 (primitives-r6-7): "a string may be stored only as a type
// whose Valid is a switch over its members" was enforced by checking that the method EXISTS.
// `type Note string; func (Note) Valid() bool { return true }` therefore passed closed.CheckType,
// closed.Marshal and logattr, and the lint's own rule 3 let its package convert any variable string
// into it, so an event could carry the text of an error that quotes a phone number.
//
// The rule now looks inside the method. For every named string type of the module that has
// `Valid() bool`, the method must be a test of MEMBERSHIP and nothing else:
//
//   - the receiver is named and read only as the tag of a switch, as one side of `==` whose other
//     side is a constant (a literal, a package constant, a qualified name) or a value of a range
//     over a registered helper, or as the argument of a registered grammar helper, each possibly
//     wrapped in string(...). Anything else (len, an index, a slice, strings.*, <, >, !=, a call
//     of an unregistered function) is a way to accept a value that is not in a list;
//   - a `return` of anything but the literal false is dominated by such a test (a case of a
//     switch on the receiver, an if whose condition holds one, or an expression made of them);
//   - a switch on the receiver has no default clause that returns true.
//
// The registered helpers are the grammars and registries a closed type may defer to. Each is a
// reviewed entry below, and a helper no Valid method calls fails the test as stale.
func registeredGrammarHelpers() map[string]string {
	return map[string]string{
		"ValidDomain":     "keyring: the domain list of the key ring (8.1)",
		"hostGrammar":     "audit: the grammar of a relying-party id, which cannot spell a phone number or a code",
		"nodeNameGrammar": "audit: the grammar of a node name (ASCII letters, digits and a few marks, few digits), which cannot spell a phone number",
		"nodeAddrGrammar": "audit: an IP address with no zone, which a phone number or a token does not parse as",
		"ValidTemplate":   "sms: the five template keys",
		"ValidLocale":     "sms: fa and en",
		"httpStatusOf":    "sms: an HTTP status written as a code, 100 to 599",
		"numericCode":     "sms: the status values the two providers' pages document, a switch over literals",
		"Lookup":          "ratelimit: the class table of the budget registry, which is code",
		"Roles":           "app: the process roles",
	}
}

// validProblems judges every named string type of files that has a Valid method. dir groups the
// package, so a package-level constant of the same package counts as a constant.
func validProblems(files []file) (problems []string, judged int, used map[string]bool) {
	used = map[string]bool{}
	byDir := map[string][]file{}
	for _, f := range files {
		if f.test || strings.Contains(f.path, "/gen/") || strings.HasPrefix(f.path, "shared/") {
			continue
		}
		byDir[path.Dir(f.path)] = append(byDir[path.Dir(f.path)], f)
	}
	for _, fs := range byDir {
		consts := map[string]bool{}
		stringTypes := map[string]bool{}
		for _, f := range fs {
			for _, d := range f.ast.Decls {
				gd, ok := d.(*ast.GenDecl)
				if !ok {
					continue
				}
				for _, sp := range gd.Specs {
					switch x := sp.(type) {
					case *ast.ValueSpec:
						if gd.Tok == token.CONST {
							for _, n := range x.Names {
								consts[n.Name] = true
							}
						}
					case *ast.TypeSpec:
						if id, ok := x.Type.(*ast.Ident); ok && id.Name == "string" && !x.Assign.IsValid() {
							stringTypes[x.Name.Name] = true
						}
					}
				}
			}
		}
		for _, f := range fs {
			for _, d := range f.ast.Decls {
				fd, ok := d.(*ast.FuncDecl)
				if !ok || fd.Recv == nil || fd.Name.Name != "Valid" || fd.Body == nil || len(fd.Recv.List) != 1 {
					continue
				}
				tn := receiverTypeName(fd.Recv.List[0].Type)
				if !stringTypes[tn] {
					continue
				}
				judged++
				at := fmt.Sprintf("%s: %s.Valid", f.path, tn)
				recv := ""
				if names := fd.Recv.List[0].Names; len(names) == 1 {
					recv = names[0].Name
				}
				for _, p := range judgeValid(fd, recv, consts, used) {
					problems = append(problems, at+": "+p)
				}
			}
		}
	}
	sort.Strings(problems)
	return problems, judged, used
}

// judgeValid applies the rule to one method.
func judgeValid(fd *ast.FuncDecl, recv string, consts map[string]bool, used map[string]bool) []string {
	if recv == "" || recv == "_" {
		return []string{"the receiver is unnamed, so the method cannot test membership of anything"}
	}
	var out []string
	rangeVars := map[string]bool{}
	helper := func(call *ast.CallExpr) (string, bool) {
		var name string
		switch fn := call.Fun.(type) {
		case *ast.Ident:
			name = fn.Name
		case *ast.SelectorExpr:
			name = fn.Sel.Name
		}
		_, ok := registeredGrammarHelpers()[name]
		return name, ok
	}
	isString := func(e ast.Expr) (ast.Expr, bool) { // string(x) -> x
		if c, ok := e.(*ast.CallExpr); ok && len(c.Args) == 1 {
			if id, ok := c.Fun.(*ast.Ident); ok && id.Name == "string" {
				return c.Args[0], true
			}
		}
		return e, false
	}
	var constLike func(e ast.Expr) bool
	constLike = func(e ast.Expr) bool {
		if inner, ok := isString(e); ok {
			return constLike(inner)
		}
		switch x := e.(type) {
		case *ast.BasicLit:
			return true
		case *ast.Ident:
			return consts[x.Name] || rangeVars[x.Name]
		case *ast.SelectorExpr:
			return true // pkg.Const; a field of a value would not be a bare selector on an identifier
		case *ast.ParenExpr:
			return constLike(x.X)
		}
		return false
	}
	// isRecv: the receiver, or string(receiver).
	isRecv := func(e ast.Expr) bool {
		if inner, ok := isString(e); ok {
			e = inner
		}
		id, ok := e.(*ast.Ident)
		return ok && id.Name == recv
	}
	// testVars are the names a registered helper's answer was kept in (v, ok := helper(string(r))):
	// returning one of them returns the helper's verdict, which is a test of the receiver.
	testVars := map[string]bool{}
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok || len(as.Rhs) != 1 {
			return true
		}
		call, ok := as.Rhs[0].(*ast.CallExpr)
		if !ok {
			return true
		}
		if _, ok := helper(call); !ok {
			return true
		}
		for _, a := range call.Args {
			if isRecv(a) {
				for _, l := range as.Lhs {
					if id, ok := l.(*ast.Ident); ok && id.Name != "_" {
						testVars[id.Name] = true
					}
				}
			}
		}
		return true
	})
	// recvTest says whether e is, or holds, an allowed test of the receiver.
	var recvTest func(e ast.Expr) bool
	recvTest = func(e ast.Expr) bool {
		switch x := e.(type) {
		case *ast.Ident:
			return testVars[x.Name]
		case *ast.ParenExpr:
			return recvTest(x.X)
		case *ast.BinaryExpr:
			switch x.Op {
			case token.LOR, token.LAND:
				return recvTest(x.X) || recvTest(x.Y)
			case token.EQL:
				return (isRecv(x.X) && constLike(x.Y)) || (isRecv(x.Y) && constLike(x.X))
			}
		case *ast.CallExpr:
			if _, ok := helper(x); ok {
				for _, a := range x.Args {
					if isRecv(a) {
						return true
					}
				}
			}
		}
		return false
	}
	// holdsTest: some part of a condition, or a statement list, is an allowed test.
	holdsTest := func(n ast.Node) bool {
		found := false
		ast.Inspect(n, func(m ast.Node) bool {
			if e, ok := m.(ast.Expr); ok && recvTest(e) {
				found = true
			}
			return !found
		})
		return found
	}

	// 1. Every occurrence of the receiver is an allowed one.
	var walk func(n ast.Node, parents []ast.Node)
	walk = func(n ast.Node, parents []ast.Node) {
		if n == nil {
			return
		}
		if rs, ok := n.(*ast.RangeStmt); ok {
			if call, ok := rs.X.(*ast.CallExpr); ok {
				if name, ok := helper(call); ok {
					used[name] = true
					if v, ok := rs.Value.(*ast.Ident); ok {
						rangeVars[v.Name] = true
					}
				}
			}
		}
		if id, ok := n.(*ast.Ident); ok && id.Name == recv && len(parents) > 0 {
			// The value is the receiver, or string(receiver).
			value, up := ast.Node(id), parents
			if c, ok := parents[len(parents)-1].(*ast.CallExpr); ok && len(c.Args) == 1 && c.Args[0] == ast.Expr(id) {
				if f, ok := c.Fun.(*ast.Ident); ok && f.Name == "string" {
					value, up = c, parents[:len(parents)-1]
				}
			}
			ok := false
			if len(up) > 0 {
				switch p := up[len(up)-1].(type) {
				case *ast.SwitchStmt:
					ok = p.Tag == value
				case *ast.BinaryExpr:
					other := p.Y
					if ast.Node(p.Y) == value {
						other = p.X
					}
					ok = p.Op == token.EQL && constLike(other)
				case *ast.CallExpr:
					if name, isHelper := helper(p); isHelper {
						ok = true
						used[name] = true
					}
				}
			}
			if !ok {
				out = append(out, "the receiver is used other than as a switch tag, an == against a constant or the argument of a registered helper; such a test accepts values that are in no list")
			}
		}
		parents = append(parents, n)
		ast.Inspect(n, func(m ast.Node) bool {
			if m == n || m == nil {
				return true
			}
			walk(m, parents)
			return false
		})
	}
	walk(fd.Body, nil)

	// 2. A switch on the receiver has no default clause that returns true, and every case that
	// returns true holds constants.
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		sw, ok := n.(*ast.SwitchStmt)
		if !ok {
			return true
		}
		tagged := sw.Tag != nil && isRecv(sw.Tag)
		for _, c := range sw.Body.List {
			cc := c.(*ast.CaseClause)
			if cc.List == nil && tagged && returnsNotFalse(cc.Body) {
				out = append(out, "a default clause of a switch on the receiver returns true: every other value is accepted")
			}
			if tagged {
				for _, e := range cc.List {
					if !constLike(e) {
						out = append(out, "a case of the switch on the receiver is not a constant")
					}
				}
			}
		}
		return true
	})

	// 3. Every return that is not the literal false is dominated by a test of the receiver.
	var dominated func(stmts []ast.Stmt, guarded bool)
	dominated = func(stmts []ast.Stmt, guarded bool) {
		for _, s := range stmts {
			switch x := s.(type) {
			case *ast.ReturnStmt:
				if !isFalseReturn(x) && !guarded && !holdsTest(x) {
					out = append(out, "a return that is not false is not behind any test of the receiver")
				}
			case *ast.IfStmt:
				g := guarded || (x.Init != nil && holdsTest(x.Init)) || holdsTest(x.Cond)
				dominated(x.Body.List, g)
				if x.Else != nil {
					dominated([]ast.Stmt{x.Else}, guarded)
				}
			case *ast.SwitchStmt:
				tagged := (x.Tag != nil && isRecv(x.Tag)) || (x.Init != nil && holdsTest(x.Init))
				for _, c := range x.Body.List {
					cc := c.(*ast.CaseClause)
					g := guarded || (tagged && cc.List != nil)
					for _, e := range cc.List {
						if recvTest(e) {
							g = true
						}
					}
					dominated(cc.Body, g)
				}
			case *ast.RangeStmt:
				dominated(x.Body.List, guarded)
			case *ast.ForStmt:
				dominated(x.Body.List, guarded)
			case *ast.BlockStmt:
				dominated(x.List, guarded)
			}
		}
	}
	dominated(fd.Body.List, false)
	return dedupeStrings(out)
}

func returnsNotFalse(stmts []ast.Stmt) bool {
	for _, s := range stmts {
		if r, ok := s.(*ast.ReturnStmt); ok && !isFalseReturn(r) {
			return true
		}
	}
	return false
}

func isFalseReturn(r *ast.ReturnStmt) bool {
	if len(r.Results) != 1 {
		return false
	}
	id, ok := r.Results[0].(*ast.Ident)
	return ok && id.Name == "false"
}

func dedupeStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func TestEveryClosedStringTypeHasAClosedValid(t *testing.T) {
	_, files := parseRepo(t)
	problems, judged, used := validProblems(files)
	for _, p := range problems {
		t.Error(p)
	}
	if judged < 25 {
		t.Fatalf("only %d named string types with a Valid method were judged; the lint is not seeing the module", judged)
	}
	for name, why := range registeredGrammarHelpers() {
		if !used[name] {
			t.Errorf("the grammar helper %s (%s) is registered and no Valid method calls it: remove it from the list", name, why)
		}
	}
}

// TestClosedValidLintCanFail plants the shapes the rule exists to refuse, and the shapes it must
// accept, so that neither a lint that never fires nor one that fires on every method passes.
func TestClosedValidLintCanFail(t *testing.T) {
	cases := []struct {
		name, src string
		want      int
	}{
		{"always true, receiver unnamed", `type Note string
func (Note) Valid() bool { return true }`, 1},
		{"always true, receiver named", `type Note string
func (n Note) Valid() bool { return true }`, 1},
		{"a length bound", `type Note string
func (n Note) Valid() bool { return len(n) < 100 }`, 1},
		{"a prefix", `type Note string
func (n Note) Valid() bool { return strings.HasPrefix(string(n), "x") }`, 1},
		{"not empty", `type Note string
func (n Note) Valid() bool { return n != "" }`, 1},
		{"a default that returns true", `type Note string
const A Note = "a"
func (n Note) Valid() bool {
	switch n {
	case A:
		return true
	default:
		return true
	}
}`, 1},
		{"a switch then return true", `type Note string
const A Note = "a"
func (n Note) Valid() bool {
	switch n {
	case A:
		return false
	}
	return true
}`, 1},
		{"a case that is a variable", `type Note string
func (n Note) Valid() bool {
	switch n {
	case Note(os.Getenv("X")):
		return true
	}
	return false
}`, 2},
		{"a helper nobody registered", `type Note string
func (n Note) Valid() bool { return looksFine(string(n)) }`, 1},
		{"a comparison with a variable", `type Note string
func (n Note) Valid() bool { return n == Note(other) }`, 1},
		{"the verdict of a helper nobody registered", `type Note string
func (n Note) Valid() bool {
	_, ok := looksFine(string(n))
	return ok
}`, 1},
		{"the verdict of a registered helper", `type Note string
func (n Note) Valid() bool {
	_, ok := numericCode(string(n))
	return ok
}`, 0},
		{"the switch of the module", `type Note string
const (
	A Note = "a"
	B Note = "b"
)
func (n Note) Valid() bool {
	switch n {
	case A, B:
		return true
	}
	return false
}`, 0},
		{"a switch on string(n) with literals", `type Note string
func (n Note) Valid() bool {
	switch string(n) {
	case "a", "b":
		return true
	}
	return false
}`, 0},
		{"comparisons", `type Note string
const (
	A Note = "a"
	B Note = "b"
)
func (n Note) Valid() bool { return n == A || n == B }`, 0},
		{"a registered grammar helper", `type Note string
func (n Note) Valid() bool { return ValidDomain(string(n)) }`, 0},
		{"a registered helper and a range of a registry", `type Note string
func (n Note) Valid() bool {
	for _, k := range Roles() {
		if n == k {
			return true
		}
	}
	return false
}`, 0},
		{"a helper then a numeric test of its own result", `type Note string
func (n Note) Valid() bool {
	if v, ok := httpStatusOf(n); ok {
		return v >= 100 && v <= 599
	}
	return false
}`, 0},
		{"a type that is not a string is not judged", `type N int
func (n N) Valid() bool { return n > 0 }`, 0},
	}
	for _, c := range cases {
		af, err := parser.ParseFile(token.NewFileSet(), "internal/x/x.go", "package x\n"+c.src+"\n", 0)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		got, _, _ := validProblems([]file{{path: filepath.ToSlash("internal/x/x.go"), ast: af}})
		// want is 0 for a method the rule must accept and anything else for one it must refuse.
		if (len(got) == 0) != (c.want == 0) {
			t.Errorf("%s: %d problems %v, want %d", c.name, len(got), got, c.want)
		}
	}
}
