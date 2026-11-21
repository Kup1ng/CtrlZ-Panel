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
			// The *_cap* net asks about the columns it can name; a limit called anything else is found by
			// the catalog's discovery by type (internal/store/catalogtest, check 26), not by this spelling.
			if strings.Contains(s, "_cap") {
				registered[s] = true
			}
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
// limitStatementAllowed and limitStatementUsed are the allow list of caps.LimitStatements and the
// entries a run met; an entry nothing met is a free pass kept for later and fails (sms-r16-4).
var limitStatementAllowed, limitStatementUsed = map[string]caps.LimitStatement{}, map[string]bool{}

func sharedCompareProblems(fset *token.FileSet, files []file) []string {
	limitStatementAllowed, limitStatementUsed = map[string]caps.LimitStatement{}, map[string]bool{}
	for _, s := range limitStatementsSource() {
		limitStatementAllowed[s.Pkg+"."+s.Const] = s
	}
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
			if col := limitRead(constant.StringVal(tv.Value)); col != "" {
				name, key := constName(info, call.Args[idx]), constKey(info, call.Args[idx])
				if s, ok := limitStatementAllowed[key]; ok && key != "" && s.Digest == limitDigest(constant.StringVal(tv.Value)) {
					limitStatementUsed[key] = true
				} else if ok && key != "" {
					out = append(out, fmt.Sprintf("%s:%d: constant %s is listed in caps.LimitStatements but its text is not the one that was reviewed; read it again, and if it still only reads or writes the limit set its Digest to %s", f.path, fset.Position(call.Pos()).Line, name, limitDigest(constant.StringVal(tv.Value))))
				} else {
					out = append(out, fmt.Sprintf("%s:%d: SQL (%s) reads %s outside every call of %s; call it, or list the constant in caps.LimitStatements with the reason it only reads or writes the value", f.path, fset.Position(call.Pos()).Line, orLiteral(name), col, caps.Shared+"spent, cap)"))
				}
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
	if info, ok := typeInfo(fset, files); ok {
		for _, p := range registryGateProblems(files, info, caps.Entries()) {
			t.Error(p)
		}
	} else {
		t.Error("type information unavailable")
	}
	for _, s := range caps.LimitStatements() {
		if strings.TrimSpace(s.Reason) == "" {
			t.Errorf("caps.LimitStatements: %s has no reason", s.Const)
		}
		if !limitStatementUsed[s.Pkg+"."+s.Const] {
			t.Errorf("caps.LimitStatements lists %s of %s, which no SQL constant of the module is, or whose digest is wrong: remove the entry", s.Const, s.Pkg)
		}
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
		{"a count compared with a cap", `const q = "UPDATE t SET c = c + 1 WHERE c < (SELECT s.sms_outbox_cap_daily FROM s)"; func f() { db.Exec(ctx, q) }`, 2},
		{"a cost compared with a cap", `const q = "SELECT cost >= s.sms_cost_cap_daily FROM s"; func f() { db.Exec(ctx, q) }`, 2},
		{"the cap on the left", `const q = "SELECT 1 FROM s WHERE s.otp_cap_ip <= 3"; func f() { db.Exec(ctx, q) }`, 2},
		{"a text with no cap", `const q = "SELECT 1 WHERE a < b"; func f() { db.Exec(ctx, q) }`, 0},
		// sms-r17-10: judged limit by limit, and a whole row of a limit table names none.
		{"cap_reached for one limit, another compared by hand", `const q = "SELECT 1 WHERE ctrlz.cap_reached(n, (SELECT otp_cap_ip FROM t)) AND m < (SELECT sms_outbox_cap_daily FROM t)"; func f() { db.Exec(ctx, q) }`, 2},
		{"one limit, only inside the shared call", `const q = "SELECT 1 WHERE ctrlz.cap_reached(n, (SELECT otp_cap_ip FROM t))"; func f() { db.Exec(ctx, q) }`, 0},
		{"a star over a limit table", `const q = "SELECT * FROM ctrlz.system_settings"; func f() { db.Exec(ctx, q) }`, 1},
		{"a row function over a limit table", `const q = "SELECT to_jsonb(s) FROM ctrlz.system_settings s"; func f() { db.Exec(ctx, q) }`, 1},
		{"a returning star on an entitlement table", `const q = "UPDATE ctrlz.tenant_entitlements SET x = 1 RETURNING *"; func f() { db.Exec(ctx, q) }`, 1},
		{"a qualified star over a limit table", `const q = "SELECT s.* FROM ctrlz.entitlement_defaults s"; func f() { db.Exec(ctx, q) }`, 1},
		{"a count star is no row", `const q = "SELECT count(*) FROM ctrlz.system_settings"; func f() { db.Exec(ctx, q) }`, 0},
		{"a bare alias is the row", `const q = "SELECT s FROM ctrlz.system_settings s"; func f() { db.Exec(ctx, q) }`, 1},
		{"a cast of the alias", `const q = "SELECT s::text FROM ctrlz.system_settings s"; func f() { db.Exec(ctx, q) }`, 1},
		{"TABLE of a limit table", `const q = "TABLE ctrlz.system_settings"; func f() { db.Exec(ctx, q) }`, 1},
		{"a non-limit column of a limit table", `const q = "SELECT registration_mode FROM ctrlz.system_settings"; func f() { db.Exec(ctx, q) }`, 0},
		{"a star over another table", `const q = "SELECT * FROM ctrlz.users"; func f() { db.Exec(ctx, q) }`, 0},
		{"a constant built from parts", `const part = "(SELECT s.x_cap FROM s)"; const q = "SELECT 1 WHERE c >= " + part; func f() { db.Exec(ctx, q) }`, 1},
		// sms-r16-4: no spelling of a comparison is looked for; any text that names a limit and does not call
		// the shared expression is refused unless its constant is on caps.LimitStatements.
		{"a limit compared through a CTE alias", `const q = "WITH s AS (SELECT sms_outbox_cap_daily AS c FROM t) SELECT 1 WHERE n < (SELECT c FROM s)"; func f() { db.Exec(ctx, q) }`, 1},
		{"a limit under BETWEEN", `const q = "SELECT 1 WHERE n BETWEEN 0 AND (SELECT otp_cap_ip FROM t)"; func f() { db.Exec(ctx, q) }`, 1},
		{"a limit in a GREATEST", `const q = "SELECT GREATEST(otp_cap_net24, 0) - n FROM t"; func f() { db.Exec(ctx, q) }`, 1},
		{"a text written at the call", `func f() { db.Exec(ctx, "SELECT sms_outbox_cap_daily FROM t") }`, 1},
		{"a constant nobody listed", `const qUnlisted = "SELECT sms_outbox_cap_daily FROM t"; func f() { db.Exec(ctx, qUnlisted) }`, 1},
		{"a column that is not a limit", `const q = "SELECT open_grace_days FROM t"; func f() { db.Exec(ctx, q) }`, 0},
		// sms-r16-29: a listed statement is the declared object with the reviewed text, not a name.
		{"a constant on the list with its reviewed text", `const qListed = "SELECT sms_outbox_cap_daily FROM t"; func f() { db.Exec(ctx, qListed) }`, 0},
		{"a listed constant edited to compare by hand", `const qListed = "SELECT 1 FROM t WHERE n < (SELECT sms_outbox_cap_daily FROM t)"; func f() { db.Exec(ctx, qListed) }`, 2},
		{"a listed constant re-indented is the same statement", `const qListed = "SELECT   sms_outbox_cap_daily    FROM t"; func f() { db.Exec(ctx, qListed) }`, 0},
	}
	defer func(f func() []caps.LimitStatement) { limitStatementsSource = f }(limitStatementsSource)
	limitStatementsSource = func() []caps.LimitStatement {
		return []caps.LimitStatement{{Const: "qListed", Pkg: "internal/store", Digest: limitDigest("SELECT sms_outbox_cap_daily FROM t"), Reason: "planted"}}
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

// constName is the name of the constant an argument is, or "" for a literal or any other
// expression: the allow list names a statement by its declaration, so a text written at the call
// can never be on it.
func constName(info *types.Info, e ast.Expr) string {
	var id *ast.Ident
	switch x := e.(type) {
	case *ast.Ident:
		id = x
	case *ast.SelectorExpr:
		id = x.Sel
	case *ast.ParenExpr:
		return constName(info, x.X)
	default:
		return ""
	}
	if c, ok := info.Uses[id].(*types.Const); ok {
		return c.Name()
	}
	return ""
}

func orLiteral(name string) string {
	if name == "" {
		return "a text written at the call"
	}
	return "constant " + name
}

// constKey is "<package path under the module>.<name>" of the constant an argument is, or "": the
// allow list names a statement by the object it is declared as, so a constant of another package
// with the same name is another statement (sms-r16-29).
func constKey(info *types.Info, e ast.Expr) string {
	var id *ast.Ident
	switch x := e.(type) {
	case *ast.Ident:
		id = x
	case *ast.SelectorExpr:
		id = x.Sel
	case *ast.ParenExpr:
		return constKey(info, x.X)
	default:
		return ""
	}
	c, ok := info.Uses[id].(*types.Const)
	if !ok || c.Pkg() == nil {
		return ""
	}
	return strings.TrimPrefix(c.Pkg().Path(), module+"/") + "." + c.Name()
}

// limitDigest is the digest a caps.LimitStatement pins: the SHA-256 of the statement with its white
// space collapsed, so a re-indented statement is the same and an edited one is not.
func limitDigest(sql string) string { return caps.Digest(sql) }

// registryGateProblems asks of every store method a registry entry names as the decision of a cap
// that it reaches a statement calling ctrlz.cap_reached (sms-r16-26). The registry named the gates of
// a cap, but nothing read them: a gate that stopped calling the shared expression (the money gate of
// the OTP claim, once) was reported by the race harness and a mutant only. Now the statement the
// method runs is found from the method's own body, by the constants it references (go/types objects),
// and one of them must call the shared expression. Entries that set a limit through a Settings column
// are judged; a Consts entry (a Go constant) and a single-use entry have no column to compare.
func registryGateProblems(files []file, info *types.Info, entries []caps.Entry) []string {
	bodies := map[string]*ast.FuncDecl{}
	for _, f := range files {
		if f.test || !strings.HasPrefix(f.path, "internal/store/") || strings.Count(strings.TrimPrefix(f.path, "internal/store/"), "/") > 0 {
			continue
		}
		for _, d := range f.ast.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Recv == nil || len(fd.Recv.List) == 0 || fd.Body == nil {
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
			bodies[recv+"."+fd.Name.Name] = fd
		}
	}
	var out []string
	for _, e := range entries {
		if e.Kind != caps.Cap || len(e.Settings) == 0 {
			continue
		}
		for _, m := range append(append([]string(nil), e.Wins...), e.Rows...) {
			fd := bodies[m]
			if fd == nil {
				continue // a method that does not exist is registryProblems' to say
			}
			calls := false
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				id, ok := n.(*ast.Ident)
				if !ok {
					return true
				}
				if c, ok := info.Uses[id].(*types.Const); ok && c.Val().Kind() == constant.String && strings.Contains(constant.StringVal(c.Val()), caps.Shared) {
					calls = true
				}
				return !calls
			})
			if !calls {
				out = append(out, fmt.Sprintf("caps: entry %s names %s as a gate of %s, and no SQL constant the method uses calls %s", e.Name, m, strings.Join(e.Settings, ", "), caps.Shared+"spent, cap)"))
			}
		}
	}
	sort.Strings(out)
	return out
}

// limitStatementsSource is the registry the lint reads; a can-fail test swaps it to plant an entry
// whose digest it can compute, and puts it back.
var limitStatementsSource = caps.LimitStatements

// TestListedLimitStatementIsOfItsPackage: the same name and the same text in another package is
// another statement (sms-r16-29).
func TestListedLimitStatementIsOfItsPackage(t *testing.T) {
	defer func(f func() []caps.LimitStatement) { limitStatementsSource = f }(limitStatementsSource)
	text := "SELECT sms_outbox_cap_daily FROM t"
	limitStatementsSource = func() []caps.LimitStatement {
		return []caps.LimitStatement{{Const: "qListed", Pkg: "internal/store", Digest: limitDigest(text), Reason: "planted"}}
	}
	const header = "package pkg\nimport \"context\"\ntype DB struct{}\nfunc (DB) Exec(context.Context, string, ...any) {}\nvar ctx = context.Background()\nvar db DB\n"
	for path, want := range map[string]int{"internal/store/x.go": 0, "internal/admin/x.go": 1} {
		fset := token.NewFileSet()
		af, err := parser.ParseFile(fset, path, header+`const qListed = "`+text+`"; func f() { db.Exec(ctx, qListed) }`, parser.ParseComments)
		if err != nil {
			t.Fatal(err)
		}
		if got := sharedCompareProblems(fset, []file{{path: path, ast: af}, filler(t, fset)}); len(got) != want {
			t.Errorf("%s: %d problems %v, want %d", path, len(got), got, want)
		}
	}
}

// TestRegistryGateCheckCanFail: a method a Cap entry names as its gate whose statement does not call
// the shared expression is reported, and one that does is not (sms-r16-26).
func TestRegistryGateCheckCanFail(t *testing.T) {
	const store = "package store\ntype GlobalTx struct{}\ntype Won struct{}\n"
	cases := []struct {
		name, src string
		want      int
	}{
		{"a gate that calls the shared expression", "const qGate = `SELECT 1 WHERE NOT ctrlz.cap_reached(0, 1)`\nfunc (GlobalTx) Gate() Won { _ = qGate; return Won{} }", 0},
		{"a gate that compares by hand", "const qGate = `SELECT 1 WHERE 0 < 1`\nfunc (GlobalTx) Gate() Won { _ = qGate; return Won{} }", 1},
		{"a gate that runs no statement of its own", "func (GlobalTx) Gate() Won { return Won{} }", 1},
	}
	entries := []caps.Entry{{Name: "x", Kind: caps.Cap, Settings: []string{"x_cap"}, Wins: []string{"GlobalTx.Gate"}}}
	for _, c := range cases {
		fset := token.NewFileSet()
		af, err := parser.ParseFile(fset, "internal/store/x.go", store+c.src, 0)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		fs := []file{{path: "internal/store/x.go", ast: af}}
		info, ok := typeInfo(fset, fs)
		if !ok {
			t.Fatalf("%s: no type information", c.name)
		}
		if got := registryGateProblems(fs, info, entries); len(got) != c.want {
			t.Errorf("%s: %d problems %v, want %d", c.name, len(got), got, c.want)
		}
	}
}

// limitRead is what a Go statement reads of the limits outside ctrlz.cap_reached: a limit column named
// beside the call, or a whole row of a limit table (sms-r17-10; caps.ReadsLimit and WholeRowOfLimitTable).
func limitRead(sql string) string {
	if col := caps.ReadsLimit(sql); col != "" {
		return "the limit " + col
	}
	if row := caps.WholeRowOfLimitTable(sql); row != "" {
		return row
	}
	return ""
}
