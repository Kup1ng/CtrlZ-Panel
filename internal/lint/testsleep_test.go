package lint_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// Rule tests-wait-on-conditions (round 16, admin-r16-10 and -20). A test that sleeps for a fixed time to stand
// for "the other side has done it by now" passes vacuously on a slow runner whenever what it asserts is an
// ABSENCE (no canary in the log, no marker file): the sleep ends before the thing could have happened, and the
// absence proves nothing. The first fix (admin-r16-10) changed the tests it had found and left the same shape in
// the Caddy log tests and the Valkey loop test (admin-r16-20), found only by a grep.
//
// The invariant: a wait in a test is on a condition. What it judges, as an allow list over the test files of
// the admin area (internal/lint, internal/adminapi, internal/admincli, internal/app, internal/testvalkey,
// internal/adminname, internal/auth/adminnotice and cmd): a call of time.Sleep (the package, however it is
// imported) is allowed only inside a for or range statement, where the loop's own condition ends the wait and
// the sleep is the pause between two looks; anywhere else it is a problem unless the file and function are on
// testSleepExempt with the reason. What it does not judge: a wait written with time.After, a timer or a ticker,
// a loop whose condition is itself a clock (`for time.Now().Before(end)` with no look at the state), and the
// test files of the other areas, which the other fixers own.
var testSleepDirs = []string{"internal/lint", "internal/adminapi", "internal/admincli", "internal/app", "internal/testvalkey", "internal/adminname", "internal/auth/adminnotice", "cmd"}

// testSleepExempt is empty: no test of this area needs a bare sleep. An entry is "path:function" with its reason.
var testSleepExempt = map[string]string{}

// testSleepProblems reports each time.Sleep of one Go file that is outside a loop and not exempt.
func testSleepProblems(path, src string) []string {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, 0)
	if err != nil {
		return []string{path + ": " + err.Error()}
	}
	timeName := ""
	for _, im := range f.Imports {
		if p, _ := strconv.Unquote(im.Path.Value); p == "time" {
			timeName = "time"
			if im.Name != nil {
				timeName = im.Name.Name
			}
		}
	}
	if timeName == "" {
		return nil
	}
	var out []string
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Body == nil {
			continue
		}
		var stack []ast.Node
		ast.Inspect(fd, func(n ast.Node) bool {
			if n == nil {
				stack = stack[:len(stack)-1]
				return true
			}
			stack = append(stack, n)
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Sleep" {
				return true
			}
			if id, ok := sel.X.(*ast.Ident); !ok || id.Name != timeName {
				return true
			}
			inLoop := false
			for _, a := range stack {
				switch a.(type) {
				case *ast.ForStmt, *ast.RangeStmt:
					inLoop = true
				}
			}
			if !inLoop {
				if _, exempt := testSleepExempt[path+":"+fd.Name.Name]; !exempt {
					out = append(out, path+":"+strconv.Itoa(fset.Position(call.Pos()).Line)+": time.Sleep in "+fd.Name.Name+" stands for a condition; wait on the condition")
				}
			}
			return true
		})
	}
	return out
}

func TestTestsWaitOnConditionsNotOnClocks(t *testing.T) {
	root := repoRoot(t)
	var problems []string
	n := 0
	for _, dir := range testSleepDirs {
		err := filepath.WalkDir(filepath.Join(root, dir), func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(p, "_test.go") {
				return err
			}
			b, rerr := os.ReadFile(p)
			if rerr != nil {
				return rerr
			}
			rel, _ := filepath.Rel(root, p)
			n++
			problems = append(problems, testSleepProblems(filepath.ToSlash(rel), string(b))...)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if n < 20 {
		t.Fatalf("only %d test files were read: the lint would judge nothing", n)
	}
	for key, why := range testSleepExempt {
		if strings.TrimSpace(why) == "" {
			t.Errorf("the exemption %s has no reason", key)
		}
	}
	sort.Strings(problems)
	if len(problems) != 0 {
		t.Fatalf("%s", strings.Join(problems, "\n"))
	}
}

// TestTestSleepLintCanFail plants each form Go allows for the construct: a bare call, an aliased import, a
// sleep in a closure, a method, a sleep after a loop, and the allowed shapes.
func TestTestSleepLintCanFail(t *testing.T) {
	for _, tc := range []struct {
		name, src string
		bad       bool
	}{
		{"a bare sleep", "package x\nimport \"time\"\nfunc f() { time.Sleep(time.Second) }\n", true},
		{"an aliased import", "package x\nimport tm \"time\"\nfunc f() { tm.Sleep(1) }\n", true},
		{"in a closure", "package x\nimport \"time\"\nfunc f() { go func() { time.Sleep(1) }() }\n", true},
		{"in a method", "package x\nimport \"time\"\ntype a struct{}\nfunc (a) g() { time.Sleep(1) }\n", true},
		{"after a loop", "package x\nimport \"time\"\nfunc f() { for i := 0; i < 3; i++ {}\n time.Sleep(1) }\n", true},
		{"after the body of an if", "package x\nimport \"time\"\nfunc f(b bool) { if b { time.Sleep(1) } }\n", true},
		{"in a for body", "package x\nimport \"time\"\nfunc f() { for !done() { time.Sleep(1) } }\nfunc done() bool { return true }\n", false},
		{"in the post statement of a for", "package x\nimport \"time\"\nfunc f() { for end := time.Now(); time.Now().Before(end); time.Sleep(1) {} }\n", false},
		{"in a range", "package x\nimport \"time\"\nfunc f(c chan int) { for range c { time.Sleep(1) } }\n", false},
		{"in a closure inside a loop", "package x\nimport \"time\"\nfunc f() { for { func() { time.Sleep(1) }() } }\n", false},
		{"a sleep of another package", "package x\nimport \"time\"\ntype s struct{}\nfunc (s) Sleep(int) {}\nfunc f() { var z s; z.Sleep(1); _ = time.Second }\n", false},
	} {
		got := testSleepProblems("x/x_test.go", tc.src)
		if (len(got) > 0) != tc.bad {
			t.Errorf("%s: problems %v, want a problem: %v", tc.name, got, tc.bad)
		}
	}
}
