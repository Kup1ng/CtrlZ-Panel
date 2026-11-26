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

// Rule clock-source, round 18 (primitives-r18-11). The machine-clock lint (clock_test.go) refuses a
// member of package time that is not on timeSafe, and its list called the timers safe because they
// "count a length and compare no stamp". They do hand one over in effect: time.After, time.Tick and
// the C channel of a Timer or a Ticker SEND the current machine time, and context's Deadline() returns
// the machine's now plus the timeout, through a package the lint never looked at. So a worker could
// decide a security window on `now := <-time.After(0)`, or on ctx.Deadline(), and nothing failed.
//
// The guard judges the value and not the name of the member, through the type checker: in every
// non-test file of the module and of shared/ (outside internal/appclock) it counts
//
//   - a receive from a channel whose element is time.Time whose value is used (anything but a
//     statement that drops it: `<-time.After(d)` waits and reads nothing),
//   - a range over such a channel that binds its value, and
//   - a call, method value or method expression of a method named Deadline whose results are
//     (time.Time, bool), which is context.Context's and anything that mirrors it,
//
// and holds the count of each file to an exact entry of wallClockValueAllowed with a reason, like the
// reads of time.Now (wallClockAllowed). A new package starts refused, a new read in a listed file is a
// new judgement, and an entry with no read left is stale.

// wallClockValueAllowed is every declaration of a non-test file that takes a time.Time off a channel or a
// context deadline, by exact count, with the reason it decides no window on a stored security stamp. The
// key is a site ("file::Func", sites_test.go), not a file (primitives-r18-23): another function of a listed
// file that takes the deadline as a stamp keeps the count of the file and used to pass.
func wallClockValueAllowed() map[string]wallUse {
	return map[string]wallUse{
		"internal/sms/router.go::Router.try":        {1, "a length: the time left of the send's context deadline, to refuse a call the deadline cannot finish (sms-r8-5); it is compared with a duration and never with a stored stamp"},
		"internal/worker/periodic/ddns.go::hasRoom": {1, "a length: the time left of the pass's context deadline, to refuse beginning a tenant the deadline cannot finish (J12-r3-5); it is compared with a duration and never with a stored stamp"},
		// The generic waits of the test support package (primitives-r18-20). The element type is the caller's
		// (a struct, an error, a signal), never a stamp the package reads; the package is imported by test
		// files only, which TestTestwaitIsImportedByTestFilesOnly holds.
		"internal/testwait/testwait.go::Receive":    {1, "a generic wait for a value of the caller's type, in test support: it hands the value on and compares no stamp"},
		"internal/testwait/testwait.go::TryReceive": {1, "a generic wait for a value of the caller's type, in test support: it hands the value on and compares no stamp"},
		"internal/testwait/testwait.go::Bound":      {1, "a generic wait whose answer is dropped, in test support: it compares no stamp"},
	}
}

func isTimeTime(t types.Type) bool {
	n, ok := types.Unalias(t).(*types.Named)
	return ok && n.Obj().Pkg() != nil && n.Obj().Pkg().Path() == "time" && n.Obj().Name() == "Time"
}

// timeChan says whether t is a channel (of either direction) whose element is time.Time, or a type
// parameter. A generic helper `func recv[T any](c <-chan T) T { return <-c }` receives an element of
// type T, never time.Time, so a check of the element type alone never saw it (primitives-r18-20). A
// type parameter is counted as a time.Time because it can be one, whatever the helper is instantiated
// with at a place this lint does not read; a helper with a real need is listed with its reason.
func timeChan(t types.Type) bool {
	if t == nil {
		return false
	}
	ch, ok := t.Underlying().(*types.Chan)
	if !ok {
		return false
	}
	_, param := types.Unalias(ch.Elem()).(*types.TypeParam)
	return param || isTimeTime(ch.Elem())
}

// calleeIdent is the identifier a call names its function by, through a selector, a parenthesis or an
// explicit instantiation; nil for any other callee.
func calleeIdent(fun ast.Expr) *ast.Ident {
	switch f := fun.(type) {
	case *ast.Ident:
		return f
	case *ast.SelectorExpr:
		return f.Sel
	case *ast.IndexExpr:
		return calleeIdent(f.X)
	case *ast.IndexListExpr:
		return calleeIdent(f.X)
	case *ast.ParenExpr:
		return calleeIdent(f.X)
	}
	return nil
}

// wallClockValueReads counts, per site, the values of the machine clock that arrive through a channel
// or a deadline, and the position of the first. A read outside every function is the site "file::"...
func wallClockValueReads(files []file, info *types.Info) (map[string]int, map[string]token.Pos) {
	counts, first := map[string]int{}, map[string]token.Pos{}
	hit := func(site string, pos token.Pos) {
		if counts[site] == 0 {
			first[site] = pos
		}
		counts[site]++
	}
	isDeadline := func(sx *ast.SelectorExpr) bool {
		if sx.Sel.Name != "Deadline" {
			return false
		}
		sig, ok := info.TypeOf(sx).(*types.Signature)
		if !ok || sig.Results().Len() != 2 {
			return false
		}
		b, isBasic := sig.Results().At(1).Type().Underlying().(*types.Basic)
		return isTimeTime(sig.Results().At(0).Type()) && isBasic && b.Kind() == types.Bool
	}
	for _, f := range files {
		if f.test || strings.HasPrefix(f.path, "internal/appclock/") {
			continue
		}
		var stack []ast.Node
		ast.Inspect(f.ast, func(n ast.Node) bool {
			if n == nil {
				stack = stack[:len(stack)-1]
				return true
			}
			site := enclosingSite(f.path, stack)
			if site == "" {
				site = f.path + "::"
			}
			switch x := n.(type) {
			case *ast.UnaryExpr:
				if x.Op == token.ARROW && timeChan(info.TypeOf(x.X)) {
					dropped := false
					if len(stack) > 0 {
						// A bare `<-ch` statement (a wait, also a select case) reads nothing.
						_, dropped = stack[len(stack)-1].(*ast.ExprStmt)
					}
					if !dropped {
						hit(site, x.Pos())
					}
				}
			case *ast.RangeStmt:
				if timeChan(info.TypeOf(x.X)) && x.Key != nil {
					if id, ok := x.Key.(*ast.Ident); !ok || id.Name != "_" {
						hit(site, x.Pos())
					}
				}
			case *ast.CallExpr:
				// A generic function of another package (a library) that is handed a time channel
				// receives from it where this lint cannot read the body (primitives-r18-20): counted at
				// the call. The helper of this module is counted where it receives, through timeChan.
				if id := calleeIdent(x.Fun); id != nil {
					if _, generic := info.Instances[id]; generic {
						for _, a := range x.Args {
							if timeChan(info.TypeOf(a)) {
								hit(site, x.Pos())
							}
						}
					}
				}
			case *ast.SelectorExpr:
				if isDeadline(x) {
					hit(site, x.Pos())
				}
			}
			stack = append(stack, n)
			return true
		})
	}
	return counts, first
}

// wallClockValueProblems judges the counts against the allow list.
func wallClockValueProblems(fset *token.FileSet, files []file, info *types.Info, allowed map[string]wallUse) []string {
	counts, first := wallClockValueReads(files, info)
	var out []string
	for p, n := range counts {
		switch want, listed := allowed[p]; {
		case !listed:
			out = append(out, fmt.Sprintf("%s:%d: a time.Time of the machine clock arrives through a channel or a context deadline (%d times); use internal/appclock, or list the file in wallClockValueAllowed with the reason it decides no window on a stored stamp", p, fset.Position(first[p]).Line, n))
		case want.n != n:
			out = append(out, fmt.Sprintf("%s takes the machine clock off a channel or a deadline %d times and wallClockValueAllowed lists %d; a new read is a new judgement", p, n, want.n))
		}
	}
	for p, u := range allowed {
		if u.why == "" || u.n < 1 {
			out = append(out, fmt.Sprintf("wallClockValueAllowed lists %s with no reason or no count", p))
		}
		if counts[p] == 0 {
			out = append(out, fmt.Sprintf("wallClockValueAllowed lists %s, which takes no time off a channel or a deadline any more; take it off", p))
		}
	}
	sort.Strings(out)
	return out
}

func TestMachineClockValuesAreOnlyReadWhereListed(t *testing.T) {
	fset, files := clockFiles(t)
	info, ok := typeInfoReal(fset, files, "time", "context")
	if !ok {
		t.Fatal("type information unavailable")
	}
	for _, p := range wallClockValueProblems(fset, files, info, wallClockValueAllowed()) {
		t.Error(p)
	}
}

// TestMachineClockValueLintCanFail plants each form Go allows: a receive from time.After, a Timer, a
// Ticker, a Tick; a receive bound in a select case, in a := with and without ok, passed on as an
// argument; a range over a ticker; Deadline called, taken as a method value, as a method expression and
// through an interface; and the clean forms (a wait, a select with a dropped receive, a channel of
// another type, a method of that name with other results, a listed file with its count).
func TestMachineClockValueLintCanFail(t *testing.T) {
	cases := []struct {
		name, path, src string
		want            int
	}{
		{"a receive from time.After", "internal/worker/x.go", "import \"time\"\nfunc f(s time.Time) bool { now := <-time.After(0); return now.After(s) }", 1},
		{"a receive from a timer", "internal/worker/x.go", "import \"time\"\nfunc f(s time.Time) bool { t := time.NewTimer(0); return (<-t.C).After(s) }", 1},
		{"a receive from a ticker bound in a select", "internal/worker/x.go", "import \"time\"\nfunc f(s time.Time, c chan int) bool { t := time.NewTicker(1); select { case now := <-t.C: return now.After(s); case <-c: return false } }", 1},
		{"a receive with ok", "internal/worker/x.go", "import \"time\"\nfunc f() { now, ok := <-time.Tick(1); _, _ = now, ok }", 1},
		{"a receive handed on", "internal/worker/x.go", "import \"time\"\nfunc use(time.Time) {}\nfunc f() { use(<-time.After(1)) }", 1},
		{"a range over a ticker", "internal/worker/x.go", "import \"time\"\nfunc f() { for now := range time.NewTicker(1).C { _ = now } }", 1},
		{"a receive of a channel handed in and dropped", "internal/worker/x.go", "import \"time\"\nfunc f(c <-chan time.Time) { <-c }", 0},
		{"a receive of a channel handed in and used", "internal/worker/x.go", "import \"time\"\nfunc f(c <-chan time.Time) time.Time { return <-c }", 1},
		{"a deadline", "internal/worker/x.go", "import \"context\"\nfunc f(ctx context.Context) { d, _ := ctx.Deadline(); _ = d }", 1},
		{"a deadline method value", "internal/worker/x.go", "import \"context\"\nfunc f(ctx context.Context) { dl := ctx.Deadline; _, _ = dl() }", 1},
		{"a deadline method expression", "internal/worker/x.go", "import \"context\"\nvar dl = context.Context.Deadline", 1},
		{"a deadline through an interface", "internal/worker/x.go", "import \"time\"\ntype dler interface{ Deadline() (time.Time, bool) }\nfunc f(d dler) { _, _ = d.Deadline() }", 1},
		{"a deadline of the timeout just made", "internal/worker/x.go", "import (\n\t\"context\"\n\t\"time\"\n)\nfunc f() { ctx, cancel := context.WithTimeout(context.Background(), time.Second); defer cancel(); d, _ := ctx.Deadline(); _ = d }", 1},
		{"a wait", "internal/worker/x.go", "import \"time\"\nfunc f() { <-time.After(time.Second) }", 0},
		{"a select that drops the value", "internal/worker/x.go", "import \"time\"\nfunc f(c chan int) { select { case <-c: case <-time.After(1): } }", 0},
		{"a range that binds nothing", "internal/worker/x.go", "import \"time\"\nfunc f() { for range time.NewTicker(1).C { return } }", 0},
		{"a channel of another type", "internal/worker/x.go", "func f(c chan int) int { return <-c }", 0},
		{"a method of that name with other results", "internal/worker/x.go", "type T struct{}\nfunc (T) Deadline() int { return 0 }\nfunc f(t T) int { return t.Deadline() }", 0},
		{"the application clock package", "internal/appclock/x.go", "import \"time\"\nfunc f() time.Time { return <-time.After(0) }", 0},
		{"a test file", "internal/worker/x_test.go", "import \"time\"\nfunc f() time.Time { return <-time.After(0) }", 0},
		{"a file of shared/", "shared/quarantine/x.go", "import \"time\"\nfunc f() time.Time { return <-time.After(0) }", 1},
		// primitives-r18-20: a type parameter stands for any element, time.Time included.
		{"a generic helper that receives", "internal/worker/x.go", "func recv[T any](c <-chan T) T { return <-c }", 1},
		{"a generic helper that receives, called with a timer channel", "internal/worker/x.go", "import \"time\"\nfunc recv[T any](c <-chan T) T { return <-c }\nfunc f() { now := recv(time.After(0)); _ = now }", 2},
		{"a generic helper that ranges over its channel", "internal/worker/x.go", "func each[T any](c <-chan T) { for v := range c { _ = v } }", 1},
		{"a generic function handed a time channel and receiving nothing here", "internal/worker/x.go", "import \"time\"\nfunc hold[T any](c <-chan T) {}\nfunc f() { hold(time.After(0)) }", 1},
		{"a generic function handed a time channel through an explicit instantiation", "internal/worker/x.go", "import \"time\"\nfunc hold[T any](c <-chan T) {}\nfunc f() { hold[time.Time](time.After(0)) }", 1},
		{"a generic helper that only waits", "internal/worker/x.go", "func wait[T any](c <-chan T) { <-c }", 0},
		{"a generic function handed a channel of another type", "internal/worker/x.go", "func hold[T any](c <-chan T) {}\nfunc f(c chan int) { hold(c) }", 0},
	}
	for _, c := range cases {
		fset := token.NewFileSet()
		dir := c.path[:strings.LastIndex(c.path, "/")]
		src := "package " + dir[strings.LastIndex(dir, "/")+1:] + "\n" + c.src
		af, err := parser.ParseFile(fset, c.path, src, parser.ParseComments)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		fs := []file{{path: c.path, test: strings.HasSuffix(c.path, "_test.go"), ast: af}}
		info, ok := typeInfoReal(fset, fs, "time", "context")
		if !ok {
			if c.want == 0 && strings.HasSuffix(c.path, "_test.go") {
				continue // a file of tests only has no package the checker reads: nothing is judged
			}
			t.Fatalf("%s: no type information", c.name)
		}
		got := wallClockValueProblems(fset, fs, info, nil)
		if len(got) != c.want {
			t.Errorf("%s: %d problems %v, want %d", c.name, len(got), got, c.want)
		}
	}
	// A listed site with its count passes; with one read fewer, or a ghost entry, it does not; another
	// function of the same file is not excused by it (primitives-r18-23).
	fset := token.NewFileSet()
	af, _ := parser.ParseFile(fset, "internal/worker/x.go", "package worker\nimport \"time\"\nfunc f() time.Time { return <-time.After(0) }", 0)
	fs := []file{{path: "internal/worker/x.go", ast: af}}
	info, _ := typeInfoReal(fset, fs, "time", "context")
	if got := wallClockValueProblems(fset, fs, info, map[string]wallUse{"internal/worker/x.go::f": {1, "a length"}}); len(got) != 0 {
		t.Errorf("a listed file with its count: %v", got)
	}
	if got := wallClockValueProblems(fset, fs, info, map[string]wallUse{"internal/worker/x.go::f": {2, "a length"}}); len(got) != 1 {
		t.Errorf("a listed file with one read fewer: %v", got)
	}
	if got := wallClockValueProblems(fset, fs, info, map[string]wallUse{"internal/worker/x.go::f": {1, "a length"}, "internal/ghost/x.go": {1, "a length"}}); len(got) != 1 {
		t.Errorf("a stale entry: %v", got)
	}
	af2, _ := parser.ParseFile(fset, "internal/worker/x.go", "package worker\nimport \"time\"\nfunc f() time.Time { return <-time.After(0) }\nfunc g() time.Time { return <-time.After(0) }", 0)
	fs2 := []file{{path: "internal/worker/x.go", ast: af2}}
	info2, _ := typeInfoReal(fset, fs2, "time", "context")
	if got := wallClockValueProblems(fset, fs2, info2, map[string]wallUse{"internal/worker/x.go::f": {1, "a length"}}); len(got) != 1 {
		t.Errorf("another function of a listed file: %v", got)
	}
}

// TestTestwaitIsImportedByTestFilesOnly holds the reason of the testwait entries of
// wallClockValueAllowed: the generic waits take a value of the caller's type off a channel, which the
// lint cannot tell from a stamp, so they are excused only while no non-test file can reach them.
func TestTestwaitIsImportedByTestFilesOnly(t *testing.T) {
	_, files := parseRepo(t)
	seen := false
	for _, f := range files {
		if len(localNames(f.ast, "github.com/Kup1ng/CtrlZ-Panel/internal/testwait")) == 0 {
			continue
		}
		if f.test {
			seen = true
			continue
		}
		if !strings.HasPrefix(f.path, "internal/testwait/") {
			t.Errorf("%s imports internal/testwait, whose generic waits are excused by wallClockValueAllowed for test files only", f.path)
		}
	}
	if !seen {
		t.Error("no test file imports internal/testwait: the lint looks at the wrong files, or the package moved")
	}
}
