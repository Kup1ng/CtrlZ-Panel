package lint_test

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/caps"
)

// The caps-and-endings rule (P1 auth review, round 5, topic caps-and-endings; spec 9.5,
// 9.6, 14.2, 18.3).
//
// A cap, a single use or the end of a row is decided by ONE conditional SQL statement,
// and the row it returns is the only permission to act. The store hands that answer out
// as a store.Won. Five things keep that true for code nobody has written yet:
//
//  1. A call that returns a Won may not drop it, put it in a blank, or keep it anywhere
//     but a local variable or a parameter, and every such variable must reach a condition
//     (or be passed on, or returned). Won.Yes may be called only in a condition or a
//     return, so the answer cannot be turned into a bool that is then forgotten.
//  2. Every method of internal/caps (Wins and Rows) exists in the store, and every Win
//     returns a Won. Every store method that returns a Won is in the registry,
//     which the race harness (internal/store/caps_race_test.go) drives.
//  3. Every Go constant named max* is a cap in the registry or a bound with a reason,
//     and every column named *_cap* in the migrations is a cap in the registry.
//  4. Every SQL text that reaches a database call compares a *_cap* value only through
//     ctrlz.cap_reached.
//  5. Ending a row is one statement: a store method that returns a Won is never followed
//     by a second statement that decides the same thing (this is the race harness's
//     business, not the lint's; see the registry).

const storePkg = module + "/internal/store"

func isWon(t types.Type) bool {
	n, ok := t.(*types.Named)
	if !ok || n.Obj().Pkg() == nil {
		return false
	}
	return n.Obj().Name() == "Won" && n.Obj().Pkg().Path() == storePkg
}

// wonIndex returns the position of the Won in a result type: -1 when there is none.
func wonIndex(t types.Type) int {
	if tup, ok := t.(*types.Tuple); ok {
		for i := 0; i < tup.Len(); i++ {
			if isWon(tup.At(i).Type()) {
				return i
			}
		}
		return -1
	}
	if t != nil && isWon(t) {
		return 0
	}
	return -1
}

// parentsOf maps every node of a file to its parent.
func parentsOf(f *ast.File) map[ast.Node]ast.Node {
	parents := map[ast.Node]ast.Node{}
	var stack []ast.Node
	ast.Inspect(f, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		if len(stack) > 0 {
			parents[n] = stack[len(stack)-1]
		}
		stack = append(stack, n)
		return true
	})
	return parents
}

// up climbs over parentheses.
func up(parents map[ast.Node]ast.Node, n ast.Node) (child, parent ast.Node) {
	child, parent = n, parents[n]
	for {
		if p, ok := parent.(*ast.ParenExpr); ok {
			child, parent = p, parents[p]
			continue
		}
		return child, parent
	}
}

// inDecision reports whether a Yes() call stands where its answer decides something: in
// the condition of an if, a for or a switch, in a case, or in a return, reached through
// nothing but !, && , || and comparisons.
func inDecision(parents map[ast.Node]ast.Node, n ast.Node) bool {
	child, parent := up(parents, n)
	for {
		switch p := parent.(type) {
		case *ast.UnaryExpr:
			if p.Op != token.NOT {
				return false
			}
		case *ast.BinaryExpr:
			switch p.Op {
			case token.LAND, token.LOR, token.EQL, token.NEQ:
			default:
				return false
			}
		case *ast.IfStmt:
			return p.Cond == child
		case *ast.ForStmt:
			return p.Cond == child
		case *ast.SwitchStmt:
			return p.Tag == child
		case *ast.CaseClause:
			for _, e := range p.List {
				if e == child {
					return true
				}
			}
			return false
		case *ast.ReturnStmt:
			return true
		default:
			return false
		}
		child, parent = up(parents, parent)
	}
}

// passedOn reports whether a Won expression is handed to someone who must use it: a
// return, an argument, a composite literal element.
func passedOn(parents map[ast.Node]ast.Node, n ast.Node) bool {
	child, parent := up(parents, n)
	switch p := parent.(type) {
	case *ast.ReturnStmt:
		return true
	case *ast.CallExpr:
		for _, a := range p.Args {
			if a == child {
				return true
			}
		}
	case *ast.CompositeLit:
		return true
	case *ast.KeyValueExpr:
		return p.Value == child
	}
	return false
}

// wonProblems applies rule 1 to every non-test file of the module.
func wonProblems(fset *token.FileSet, files []file) []string {
	info, ok := typeInfo(fset, files)
	if !ok {
		return []string{"type information unavailable"}
	}
	var out []string
	for _, f := range files {
		if f.test {
			continue
		}
		parents := parentsOf(f.ast)
		where := func(n ast.Node) string { return fmt.Sprintf("%s:%d", f.path, fset.Position(n.Pos()).Line) }
		// The variables and parameters that hold a Won, with the first node that made
		// them. Each must be used.
		var duties []wonDuty
		addDuty := func(id *ast.Ident, def bool) {
			var obj types.Object
			if def {
				obj = info.Defs[id]
			}
			if obj == nil {
				obj = info.Uses[id]
			}
			if obj != nil {
				duties = append(duties, wonDuty{obj, id})
			}
		}
		ast.Inspect(f.ast, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.CallExpr:
				if sel, ok := n.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Yes" && len(n.Args) == 0 {
					if tv, known := info.Types[sel.X]; known && isWon(tv.Type) && !inDecision(parents, n) {
						out = append(out, where(n)+": Won.Yes outside a condition or a return; the answer must decide, not be stored")
					}
					return true
				}
				tv, known := info.Types[n]
				if !known {
					return true
				}
				idx := wonIndex(tv.Type)
				if idx < 0 {
					return true
				}
				child, parent := up(parents, n)
				switch p := parent.(type) {
				case *ast.ExprStmt, *ast.GoStmt, *ast.DeferStmt:
					out = append(out, where(n)+": the Won returned by this call is dropped")
				case *ast.AssignStmt:
					pos := idx
					if len(p.Rhs) > 1 {
						for i, r := range p.Rhs {
							if r == child {
								pos = i
							}
						}
					}
					if pos >= len(p.Lhs) {
						out = append(out, where(n)+": the Won returned by this call is not assigned")
						break
					}
					switch l := p.Lhs[pos].(type) {
					case *ast.Ident:
						if l.Name == "_" {
							out = append(out, where(n)+": the Won returned by this call is assigned to _")
						} else {
							addDuty(l, p.Tok == token.DEFINE)
						}
					default:
						out = append(out, where(n)+": the Won returned by this call is kept in a field or an element; hold it in a variable and decide")
					}
				case *ast.ValueSpec:
					pos := idx
					if len(p.Values) > 1 {
						for i, r := range p.Values {
							if r == child {
								pos = i
							}
						}
					}
					if pos < len(p.Names) && p.Names[pos].Name != "_" {
						addDuty(p.Names[pos], true)
					} else {
						out = append(out, where(n)+": the Won returned by this call is assigned to _")
					}
				case *ast.SelectorExpr:
					// x.Yes() on the result: the check above has judged where it stands.
				case *ast.ReturnStmt, *ast.CallExpr, *ast.CompositeLit, *ast.KeyValueExpr:
					if !passedOn(parents, n) {
						out = append(out, where(n)+": the Won returned by this call is used in an expression")
					}
				default:
					out = append(out, where(n)+": the Won returned by this call is used in an expression")
				}
			case *ast.FuncDecl:
				duties = append(duties, wonParams(n.Type, info)...)
			case *ast.FuncLit:
				duties = append(duties, wonParams(n.Type, info)...)
			}
			return true
		})
		// A variable that holds a Won must reach a decision, or be passed on.
		seen := map[types.Object]bool{}
		for _, d := range duties {
			if seen[d.obj] {
				continue
			}
			seen[d.obj] = true
			used := false
			ast.Inspect(f.ast, func(n ast.Node) bool {
				id, ok := n.(*ast.Ident)
				if !ok || info.Uses[id] != d.obj {
					return true
				}
				child, parent := up(parents, id)
				if sel, ok := parent.(*ast.SelectorExpr); ok && sel.X == child && sel.Sel.Name == "Yes" {
					if call, ok := parents[sel].(*ast.CallExpr); ok && inDecision(parents, call) {
						used = true
					}
					return true
				}
				if passedOn(parents, id) {
					used = true
				}
				return true
			})
			if !used {
				out = append(out, where(d.node)+": "+d.obj.Name()+" holds a Won that never reaches a condition and is not passed on")
			}
		}
	}
	sort.Strings(out)
	return out
}

// wonDuty is a variable or parameter that holds a Won, with the node that made it.
type wonDuty struct {
	obj  types.Object
	node ast.Node
}

// wonParams lists the parameters of a function that are a Won.
func wonParams(ft *ast.FuncType, info *types.Info) []wonDuty {
	var out []wonDuty
	if ft.Params == nil {
		return nil
	}
	for _, fld := range ft.Params.List {
		for _, name := range fld.Names {
			if obj := info.Defs[name]; obj != nil && isWon(obj.Type()) && name.Name != "_" {
				out = append(out, wonDuty{obj, name})
			}
		}
	}
	return out
}

// storeMethods lists the methods of internal/store with whether they return a Won.
func storeMethods(files []file) map[string]bool {
	out := map[string]bool{}
	for _, f := range files {
		if f.test || !strings.HasPrefix(f.path, "internal/store/") || strings.Count(strings.TrimPrefix(f.path, "internal/store/"), "/") > 0 {
			continue
		}
		for _, d := range f.ast.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Recv == nil || len(fd.Recv.List) == 0 || !fd.Name.IsExported() {
				continue
			}
			recv := ""
			switch t := fd.Recv.List[0].Type.(type) {
			case *ast.Ident:
				recv = t.Name
			case *ast.StarExpr:
				if id, ok := t.X.(*ast.Ident); ok {
					recv = id.Name
				}
			}
			isW := false
			if fd.Type.Results != nil {
				for _, r := range fd.Type.Results.List {
					if id, ok := r.Type.(*ast.Ident); ok && id.Name == "Won" {
						isW = true
					}
				}
			}
			out[recv+"."+fd.Name.Name] = isW
		}
	}
	return out
}

// maxName finds a name that sets a limit: max or Max followed by a capital or a digit,
// at the start of an identifier or after a lower-case letter.
var maxName = regexp.MustCompile(`(^|[a-z0-9])[mM]ax([A-Z0-9_]|$)`)

// maxConsts lists every constant or package variable named max*, with its place.
func maxConsts(fset *token.FileSet, files []file) map[string]string {
	out := map[string]string{}
	for _, f := range files {
		if f.test || strings.HasPrefix(f.path, "internal/lint/") {
			continue
		}
		ast.Inspect(f.ast, func(n ast.Node) bool {
			vs, ok := n.(*ast.ValueSpec)
			if !ok {
				return true
			}
			for _, id := range vs.Names {
				if maxName.MatchString(id.Name) {
					out[id.Name] = fmt.Sprintf("%s:%d", f.path, fset.Position(id.Pos()).Line)
				}
			}
			return true
		})
	}
	return out
}

// capColumn finds a column named *_cap* in a CREATE TABLE or ADD COLUMN of a migration.
var capColumn = regexp.MustCompile(`(?m)^\s*(?:ADD COLUMN\s+)?([a-z][a-z0-9_]*_cap[a-z0-9_]*)\s+(?:integer|numeric|bigint|smallint|int)\b`)

func capColumns(t *testing.T, root string) []string {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(root, "migrations", "postgres", "src", "*.sql"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("no migration sources found: %v", err)
	}
	set := map[string]bool{}
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range capColumn.FindAllStringSubmatch(string(b), -1) {
			if !strings.HasPrefix(m[1], "v_") && !strings.HasPrefix(m[1], "p_") { // plpgsql variables
				set[m[1]] = true
			}
		}
	}
	var out []string
	for c := range set {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// registryProblems applies rules 2 and 3 to a registry, the store's methods, the
// constants of the code and the cap columns of the migrations.
func registryProblems(entries []caps.Entry, bounds []caps.Bound, methods map[string]bool, consts map[string]string, columns []string) []string {
	var out []string
	names := map[string]bool{}
	inWins := map[string]bool{}
	covered := map[string]bool{}
	for _, e := range entries {
		if names[e.Name] {
			out = append(out, "caps: entry "+e.Name+" is listed twice")
		}
		names[e.Name] = true
		if len(e.Settings)+len(e.Consts)+len(e.Wins)+len(e.Rows) == 0 && e.SQL == "" {
			out = append(out, "caps: entry "+e.Name+" names nothing that decides it")
		}
		for _, w := range e.Wins {
			inWins[w] = true
			isW, ok := methods[w]
			switch {
			case !ok:
				out = append(out, fmt.Sprintf("caps: entry %s names %s, which is not a method of internal/store", e.Name, w))
			case !isW:
				out = append(out, fmt.Sprintf("caps: entry %s names %s as a Win, but it returns no store.Won", e.Name, w))
			}
		}
		for _, r := range e.Rows {
			if _, ok := methods[r]; !ok {
				out = append(out, fmt.Sprintf("caps: entry %s names %s, which is not a method of internal/store", e.Name, r))
			}
		}
		for _, c := range e.Consts {
			covered[c] = true
			if _, ok := consts[c]; !ok {
				out = append(out, fmt.Sprintf("caps: entry %s names constant %s, which does not exist", e.Name, c))
			}
		}
	}
	var wonMethods []string
	for m, isW := range methods {
		if isW && !inWins[m] {
			wonMethods = append(wonMethods, m)
		}
	}
	sort.Strings(wonMethods)
	for _, m := range wonMethods {
		out = append(out, fmt.Sprintf("internal/store: %s returns a store.Won and is not in internal/caps; register it so the race harness drives it", m))
	}
	for _, b := range bounds {
		if strings.TrimSpace(b.Reason) == "" {
			out = append(out, "caps: bound "+b.Const+" has no reason")
		}
		if covered[b.Const] {
			out = append(out, "caps: "+b.Const+" is both a cap and a bound")
		}
		covered[b.Const] = true
		if _, ok := consts[b.Const]; !ok {
			out = append(out, fmt.Sprintf("caps: bound %s names a constant that does not exist", b.Const))
		}
	}
	var unreg []string
	for c := range consts {
		if !covered[c] {
			unreg = append(unreg, c)
		}
	}
	sort.Strings(unreg)
	for _, c := range unreg {
		out = append(out, fmt.Sprintf("%s: constant %s sets a limit and is in neither Entries nor Bounds of internal/caps; decide whether racing actors can spend it", consts[c], c))
	}
	registered := map[string]bool{}
	for _, e := range entries {
		for _, s := range e.Settings {
			registered[s] = true
		}
	}
	for _, c := range columns {
		if !registered[c] {
			out = append(out, "migrations: column "+c+" is a cap and is not in internal/caps")
		}
		delete(registered, c)
	}
	var stale []string
	for s := range registered {
		stale = append(stale, s)
	}
	sort.Strings(stale)
	for _, s := range stale {
		out = append(out, "caps: setting "+s+" is not a column named *_cap* in any migration")
	}
	return out
}

// sharedCompareProblems applies rule 4 to every constant SQL text that reaches a
// database call.
func sharedCompareProblems(fset *token.FileSet, files []file) []string {
	info, ok := typeInfo(fset, files)
	if !ok {
		return []string{"type information unavailable"}
	}
	var out []string
	for _, f := range files {
		if f.test || sqlExempt(f.path) {
			continue
		}
		ast.Inspect(f.ast, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			idx, isSink := sqlSinks()[calleeName(call.Fun)]
			if !isSink || idx < 0 || len(call.Args) <= idx {
				return true
			}
			tv, known := info.Types[call.Args[idx]]
			if !known || tv.Value == nil || tv.Value.Kind() != constant.String {
				return true
			}
			if bad := caps.UnsharedCompare(constant.StringVal(tv.Value)); bad != "" {
				out = append(out, fmt.Sprintf("%s:%d: SQL compares a cap with %q; use %s", f.path, fset.Position(call.Pos()).Line, bad, caps.Shared+"spent, cap)"))
			}
			return true
		})
	}
	sort.Strings(out)
	return out
}

func TestCapsAndEndingsRule(t *testing.T) {
	fset, files := parseRepo(t)
	for _, p := range wonProblems(fset, files) {
		t.Error(p)
	}
	methods := storeMethods(files)
	if len(methods) < 20 {
		t.Fatalf("only %d store methods found; the check is looking in the wrong place", len(methods))
	}
	for _, p := range registryProblems(caps.Entries(), caps.Bounds(), methods, maxConsts(fset, files), capColumns(t, repoRoot(t))) {
		t.Error(p)
	}
	for _, p := range sharedCompareProblems(fset, files) {
		t.Error(p)
	}
	// The Won rule must have looked at something.
	wonCalls := 0
	for _, isW := range methods {
		if isW {
			wonCalls++
		}
	}
	if wonCalls < 10 {
		t.Errorf("only %d store methods return a Won", wonCalls)
	}
}

// TestCapsAndEndingsRuleCanFail plants code that breaks each part of the rule and expects
// the lint to say so. A lint that cannot fail proves nothing.
func TestCapsAndEndingsRuleCanFail(t *testing.T) {
	const storeSrc = `package store
type Won struct{ y bool }
func (w Won) Yes() bool { return w.y }
type GlobalTx struct{}
func (GlobalTx) Clear() (Won, error) { return Won{}, nil }
func (GlobalTx) Take() Won { return Won{} }
func (GlobalTx) Ping() error { return nil }
`
	cases := []struct {
		name string
		src  string
		want int
	}{
		{"the Won is dropped", `func f(g store.GlobalTx) { g.Clear() }`, 1},
		{"a one-value Won is dropped", `func f(g store.GlobalTx) { g.Take() }`, 1},
		{"deferred", `func f(g store.GlobalTx) { defer g.Take() }`, 1},
		{"assigned to a blank", `func f(g store.GlobalTx) error { _, err := g.Clear(); return err }`, 1},
		{"kept and never decided", `func f(g store.GlobalTx) error { w, err := g.Clear(); _ = w; return err }`, 1},
		{"checked outside a condition", `func f(g store.GlobalTx) bool { w, _ := g.Clear(); ok := w.Yes(); return !ok }`, 2},
		{"stored in a struct field", `type h struct{ w store.Won }
func f(g store.GlobalTx, x *h) error { var err error; x.w, err = g.Clear(); return err }`, 1},
		{"decided in an if", `func f(g store.GlobalTx) error { w, err := g.Clear(); if err != nil { return err }; if !w.Yes() { return nil }; return nil }`, 0},
		{"decided by a one-value call in an if", `func f(g store.GlobalTx) { if g.Take().Yes() { return } }`, 0},
		{"returned", `func f(g store.GlobalTx) (store.Won, error) { return g.Clear() }`, 0},
		{"passed to a function that decides", `func f(g store.GlobalTx) error { w, err := g.Clear(); use(w); return err }
func use(w store.Won) { if w.Yes() { return } }`, 0},
		{"passed to a function that ignores it", `func f(g store.GlobalTx) error { w, err := g.Clear(); use(w); return err }
func use(w store.Won) {}`, 1},
		{"a switch case", `func f(g store.GlobalTx) { w := g.Take(); switch { case w.Yes(): } }`, 0},
		{"another error is not a Won", `func f(g store.GlobalTx) { g.Ping() }`, 0},
	}
	for _, c := range cases {
		fset := token.NewFileSet()
		st, err := parser.ParseFile(fset, "internal/store/won.go", storeSrc, parser.ParseComments)
		if err != nil {
			t.Fatal(err)
		}
		src := "package x\nimport \"" + storePkg + "\"\n" + c.src + "\n"
		cf, err := parser.ParseFile(fset, "internal/worker/x/x.go", src, parser.ParseComments)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		fs := []file{{path: "internal/store/won.go", ast: st}, {path: "internal/worker/x/x.go", ast: cf}}
		if got := wonProblems(fset, fs); len(got) != c.want {
			t.Errorf("%s: %d problems %v, want %d", c.name, len(got), got, c.want)
		}
	}
}

func TestCapsRegistryCanFail(t *testing.T) {
	entries := []caps.Entry{
		{Name: "a", Kind: caps.Cap, Settings: []string{"x_cap"}, Consts: []string{"maxA"}, Wins: []string{"T.Win"}},
		{Name: "b", Kind: caps.Ending, Rows: []string{"T.Rows"}},
	}
	bounds := []caps.Bound{{Const: "maxB", Reason: "a page size"}}
	methods := map[string]bool{"T.Win": true, "T.Rows": false}
	consts := map[string]string{"maxA": "a.go:1", "maxB": "b.go:1"}
	cols := []string{"x_cap"}
	if got := registryProblems(entries, bounds, methods, consts, cols); len(got) != 0 {
		t.Fatalf("a clean registry has problems: %v", got)
	}
	cases := []struct {
		name    string
		entries []caps.Entry
		bounds  []caps.Bound
		methods map[string]bool
		consts  map[string]string
		cols    []string
	}{
		{"a Won method nobody registered", entries, bounds, map[string]bool{"T.Win": true, "T.Rows": false, "T.New": true}, consts, cols},
		{"a Win that returns no Won", entries, bounds, map[string]bool{"T.Win": false, "T.Rows": false}, consts, cols},
		{"a method that does not exist", entries, bounds, map[string]bool{"T.Rows": false}, consts, cols},
		{"a new max constant", entries, bounds, methods, map[string]string{"maxA": "a.go:1", "maxB": "b.go:1", "maxNew": "c.go:3"}, cols},
		{"a bound with no reason", entries, []caps.Bound{{Const: "maxB"}}, methods, consts, cols},
		{"a stale constant", entries, bounds, methods, map[string]string{"maxA": "a.go:1"}, cols},
		{"a new cap column", entries, bounds, methods, consts, []string{"x_cap", "y_cap_daily"}},
		{"a stale setting", entries, bounds, methods, consts, nil},
	}
	for _, c := range cases {
		if got := registryProblems(c.entries, c.bounds, c.methods, c.consts, c.cols); len(got) == 0 {
			t.Errorf("%s: no problem reported", c.name)
		}
	}
}

func TestSharedCapCompareCanFail(t *testing.T) {
	const header = "package pkg\nimport \"context\"\ntype DB struct{}\nfunc (DB) Exec(context.Context, string, ...any) {}\nvar ctx = context.Background()\nvar db DB\n"
	cases := []struct {
		name, src string
		bad       int
	}{
		{"the shared expression", `const q = "UPDATE t SET c = c + 1 WHERE NOT ctrlz.cap_reached(c, (SELECT s.x_cap FROM s))"; func f() { db.Exec(ctx, q) }`, 0},
		{"a count compared with a cap", `const q = "UPDATE t SET c = c + 1 WHERE c < (SELECT s.sms_outbox_cap_daily FROM s)"; func f() { db.Exec(ctx, q) }`, 1},
		{"a cost compared with a cap", `const q = "SELECT cost >= s.sms_cost_cap_daily FROM s"; func f() { db.Exec(ctx, q) }`, 1},
		{"the cap on the left", `const q = "SELECT 1 FROM s WHERE s.otp_cap_ip <= 3"; func f() { db.Exec(ctx, q) }`, 1},
		{"a text with no cap", `const q = "SELECT 1 WHERE a < b"; func f() { db.Exec(ctx, q) }`, 0},
		{"a constant built from parts", `const part = "(SELECT s.x_cap FROM s)"; const q = "SELECT 1 WHERE c >= " + part; func f() { db.Exec(ctx, q) }`, 1},
	}
	for _, c := range cases {
		fset := token.NewFileSet()
		af, err := parser.ParseFile(fset, "internal/store/x.go", header+c.src, parser.ParseComments)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		fs := []file{{path: "internal/store/x.go", ast: af}, filler(t, fset)}
		if got := sharedCompareProblems(fset, fs); len(got) != c.bad {
			t.Errorf("%s: %d problems %v, want %d", c.name, len(got), got, c.bad)
		}
	}
}
