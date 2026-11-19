package lint_test

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/parser"
	"go/token"
	"sort"
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/clockrule"
)

// The clock rule (P1 auth review, round 5, topic clock-source; spec 3.3, 3.5, 4.5,
// 10.2, 10.5, 16.1).
//
// Every security timestamp column has one clock, declared in
// migrations/catalog/clocks.yaml. Two things keep that true for code nobody has
// written yet:
//
//  1. Every SQL constant that reaches a database call is judged by clockrule: a
//     statement that names an application-clock column and reads a database clock
//     fails, and so does one that hands a database-clock column to Go as a time or
//     writes or compares it with a Go value. The live bodies of the definer
//     functions and the column defaults are judged by catalog check 24.
//  2. Go reads the time from one place. time.Now, time.Since and time.Until are
//     called in internal/appclock and nowhere else under internal/auth, internal/api,
//     internal/adminapi and internal/store, so a test that moves the application
//     clock moves every window, and a window cannot be decided by a clock the test
//     did not move.
//
// The boundary test (internal/store, TestClockWindows) moves the application clock
// three hours either way for every app and db column of the registry.

// clockProblems judges every constant SQL text that reaches a database call.
func clockProblems(fset *token.FileSet, files []file, reg *clockrule.Registry) []string {
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
				return true // the sql-const rule reports it
			}
			for _, fd := range reg.Analyze(constant.StringVal(tv.Value), clockrule.Options{GoBound: true}) {
				out = append(out, fmt.Sprintf("%s:%d: %s", f.path, fset.Position(call.Pos()).Line, fd))
			}
			return true
		})
	}
	sort.Strings(out)
	return out
}

// clockPackages are the directories where the application clock must come from
// internal/clock.
var clockPackages = []string{"internal/auth/", "internal/api/", "internal/adminapi/", "internal/store/"}

// clockCalls are the time package functions that read the machine's clock.
var clockCallNames = map[string]bool{"Now": true, "Since": true, "Until": true}

// wallClockProblems reports reads of the machine's clock outside internal/clock.
func wallClockProblems(fset *token.FileSet, files []file) []string {
	var out []string
	for _, f := range files {
		if f.test || strings.HasPrefix(f.path, "internal/appclock/") {
			continue
		}
		in := false
		for _, p := range clockPackages {
			in = in || strings.HasPrefix(f.path, p)
		}
		if !in || strings.HasPrefix(f.path, "internal/store/catalogtest/") {
			continue
		}
		timeName := ""
		for _, imp := range f.ast.Imports {
			if imp.Path.Value == `"time"` {
				timeName = "time"
				if imp.Name != nil {
					timeName = imp.Name.Name
				}
			}
		}
		if timeName == "" {
			continue
		}
		ast.Inspect(f.ast, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok || !clockCallNames[sel.Sel.Name] {
				return true
			}
			if id, ok := sel.X.(*ast.Ident); ok && id.Name == timeName {
				out = append(out, fmt.Sprintf("%s:%d: time.%s reads the machine's clock; use internal/appclock", f.path, fset.Position(sel.Pos()).Line, sel.Sel.Name))
			}
			return true
		})
	}
	sort.Strings(out)
	return out
}

func TestClockRule(t *testing.T) {
	reg, err := clockrule.Load()
	if err != nil {
		t.Fatal(err)
	}
	fset, files := parseRepo(t)
	for _, p := range clockProblems(fset, files, reg) {
		t.Error(p)
	}
	for _, p := range wallClockProblems(fset, files) {
		t.Error(p)
	}
}

// TestClockRuleCanFail plants code that breaks each part of the rule and expects
// the lint to say so. A lint that cannot fail proves nothing.
func TestClockRuleCanFail(t *testing.T) {
	reg, err := clockrule.Parse([]byte(`
tables:
  sessions: {idle_expires_at: app, reauth_at: app, last_seen_at: app, revoked_at: stamp}
  admin_sessions: {totp_verified_at: app, revoked_at: stamp}
  users: {password_expires_at: db, enforce_lift_at: app, last_login_at: stamp, totp_pending_at: db}
  invites: {expires_at: db}
read: {}
`))
	if err != nil {
		t.Fatal(err)
	}
	const header = "package p\n"
	sql := []struct {
		name, src string
		want      int
	}{
		{"app column stamped by now()", "func f() { db.Exec(ctx, `UPDATE ctrlz.admin_sessions SET totp_verified_at = now() WHERE id = $1`) }", 1},
		{"app column compared with now() in a join", "func f() { db.Exec(ctx, `SELECT 1 FROM ctrlz.sessions s WHERE s.idle_expires_at > pg_catalog.now()`) }", 1},
		{"app column next to a clock keyword", "func f() { db.Exec(ctx, `UPDATE ctrlz.sessions SET idle_expires_at = $2, last_seen_at = CURRENT_TIMESTAMP WHERE id = $1`) }", 2},
		{"app column by a clock string", "func f() { db.Exec(ctx, `UPDATE ctrlz.sessions SET reauth_at = 'now'::timestamptz WHERE id = $1`) }", 1},
		{"app column set from a parameter is the rule", "func f() { db.Exec(ctx, `UPDATE ctrlz.admin_sessions SET totp_verified_at = $2::timestamptz WHERE id = $1`) }", 0},
		{"a stamp column with now() is fine", "func f() { db.Exec(ctx, `UPDATE ctrlz.sessions SET revoked_at = now() WHERE id = $1`) }", 0},
		{"db column selected", "func f() { db.QueryRow(ctx, `SELECT password_expires_at FROM ctrlz.users WHERE id = $1`) }", 1},
		{"db column selected through RETURNING", "func f() { db.QueryRow(ctx, `UPDATE ctrlz.users SET totp_pending_at = now() WHERE id = $1 RETURNING totp_pending_at`) }", 1},
		{"db column selected through a star", "func f() { db.QueryRow(ctx, `SELECT * FROM ctrlz.invites WHERE id = $1`) }", 1},
		{"db column decided in SQL is fine", "func f() { db.QueryRow(ctx, `SELECT COALESCE(password_expires_at <= now(), false) FROM ctrlz.users WHERE id = $1`) }", 0},
		{"db column in a CTE returning is not Go-bound", "func f() { db.QueryRow(ctx, `WITH r AS (UPDATE ctrlz.users SET last_login_at = now() RETURNING password_expires_at) SELECT count(*) FROM r`) }", 0},
		{"db column compared with a parameter", "func f() { db.Exec(ctx, `SELECT 1 FROM ctrlz.invites WHERE expires_at > $1`) }", 1},
		{"db column compared with a cast parameter on the left", "func f() { db.Exec(ctx, `SELECT 1 FROM ctrlz.invites WHERE $1::timestamptz < expires_at`) }", 1},
		{"db column written from a parameter", "func f() { db.Exec(ctx, `UPDATE ctrlz.invites SET expires_at = $2 WHERE id = $1`) }", 1},
		{"db column inserted from a parameter", "func f() { db.Exec(ctx, `INSERT INTO ctrlz.invites (token_hash, expires_at) VALUES ($1, $2)`) }", 1},
		{"db column written from the clock and a parameter is fine", "func f() { db.Exec(ctx, `INSERT INTO ctrlz.invites (token_hash, expires_at) VALUES ($1, now() + make_interval(secs => $2))`) }", 0},
	}
	for _, c := range sql {
		fset := token.NewFileSet()
		af, err := parser.ParseFile(fset, "internal/store/x.go", header+c.src, parser.ParseComments)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		got := clockProblems(fset, []file{{path: "internal/store/x.go", ast: af}, filler(t, fset)}, reg)
		if len(got) != c.want {
			t.Errorf("%s: %d problems %v, want %d", c.name, len(got), got, c.want)
		}
	}

	wall := []struct {
		name, path, src string
		want            int
	}{
		{"time.Now in the api", "internal/api/x.go", "import \"time\"\nfunc f() time.Time { return time.Now() }", 1},
		{"time.Since in the store", "internal/store/x.go", "import \"time\"\nfunc f(t time.Time) time.Duration { return time.Since(t) }", 1},
		{"time.Now as a value", "internal/auth/login/x.go", "import \"time\"\nvar now = time.Now", 1},
		{"an aliased import", "internal/adminapi/x.go", "import tm \"time\"\nfunc f() tm.Time { return tm.Now() }", 1},
		{"internal/clock is the place for it", "internal/appclock/x.go", "import \"time\"\nfunc f() time.Time { return time.Now() }", 0},
		{"another package is outside this rule", "internal/worker/x.go", "import \"time\"\nfunc f() time.Time { return time.Now() }", 0},
		{"time.Unix is not a read of the clock", "internal/api/y.go", "import \"time\"\nfunc f() time.Time { return time.Unix(0, 0) }", 0},
	}
	for _, c := range wall {
		fset := token.NewFileSet()
		af, err := parser.ParseFile(fset, c.path, header+c.src, parser.ParseComments)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		got := wallClockProblems(fset, []file{{path: c.path, ast: af}})
		if len(got) != c.want {
			t.Errorf("%s: %d problems %v, want %d", c.name, len(got), got, c.want)
		}
	}
}
