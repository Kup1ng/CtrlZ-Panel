package lint_test

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/parser"
	"go/token"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/lockrank"
)

// The lock order rule (P1 auth review, round 5, topic lock-order; spec 4.4).
//
// Every write transaction takes row locks in the one order of package
// lockrank. Three things keep that true for code nobody has written yet:
//
//  1. Lock clauses (FOR UPDATE and its relatives, pg_advisory_xact_lock) are
//     spelled in one file, internal/store/locks.go, as named constants. A
//     literal anywhere else is a lock that no one declared an order for.
//  2. Every SQL constant that reaches a database call is classified by
//     lockrank.Analyze. One that cannot be (an unranked table, an unknown
//     function or advisory key) fails here, so a new table or function has to
//     be given a place in the order before it can be used.
//  3. users and admin_users are locked only with FOR NO KEY UPDATE or FOR KEY
//     SHARE: FOR UPDATE and FOR SHARE conflict with the key share that every
//     insert into a child table takes on them, which is how Refresh and a
//     credential writer deadlocked (db-r4-1).
//
// The runtime half (a transaction that asks for a lock below one it holds
// gets ErrLockOrder) is in internal/store/locks_test.go.

const locksFile = "internal/store/locks.go"

// lockWords finds a lock clause or an advisory lock call in a string literal.
var lockWords = regexp.MustCompile(`(?i)\bfor\s+(no\s+key\s+update|key\s+share|update|share)\b|\bpg_(try_)?advisory_(xact_)?lock`)

// lockLiteralProblems reports lock clauses spelled outside locks.go.
func lockLiteralProblems(fset *token.FileSet, files []file) []string {
	var out []string
	for _, f := range files {
		if f.test || sqlExempt(f.path) || f.path == locksFile || strings.HasPrefix(f.path, "internal/lockrank/") {
			continue
		}
		ast.Inspect(f.ast, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			s, err := strconv.Unquote(lit.Value)
			if err != nil {
				return true
			}
			if m := lockWords.FindString(s); m != "" {
				out = append(out, fmt.Sprintf("%s:%d: lock clause %q spelled outside %s; use the constant defined there", f.path, fset.Position(lit.Pos()).Line, m, locksFile))
			}
			return true
		})
	}
	sort.Strings(out)
	return out
}

// lockProblems classifies every constant SQL text that reaches a database call.
func lockProblems(fset *token.FileSet, files []file) []string {
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
			text := constant.StringVal(tv.Value)
			where := fmt.Sprintf("%s:%d", f.path, fset.Position(call.Pos()).Line)
			touches, err := lockrank.Analyze(text)
			if err != nil {
				out = append(out, fmt.Sprintf("%s: %v", where, err))
				return true
			}
			for _, t := range touches {
				switch {
				case t.Clause == "update" || t.Clause == "share":
					if t.Table == "users" || t.Table == "admin_users" || lockrank.Inert(t.Table) {
						out = append(out, fmt.Sprintf("%s: FOR %s on %s; use FOR NO KEY UPDATE or FOR KEY SHARE (it conflicts with the key share of every insert into a child table)", where, strings.ToUpper(t.Clause), t.Table))
					}
				}
			}
			return true
		})
	}
	sort.Strings(out)
	return out
}

func TestLockOrderRule(t *testing.T) {
	fset, files := parseRepo(t)
	for _, p := range lockLiteralProblems(fset, files) {
		t.Error(p)
	}
	for _, p := range lockProblems(fset, files) {
		t.Error(p)
	}
	found := false
	for _, f := range files {
		if f.path == locksFile {
			found = true
		}
	}
	if !found {
		t.Errorf("%s does not exist", locksFile)
	}
}

// TestLockOrderRuleCanFail plants code that breaks each part of the rule and
// expects the lint to say so. A lint that cannot fail proves nothing.
func TestLockOrderRuleCanFail(t *testing.T) {
	const header = "package p\n"
	cases := []struct {
		name, path, src string
		literal, class  int
	}{
		{"a FOR UPDATE literal outside locks.go", "internal/store/x.go", `const q = "SELECT 1 FROM ctrlz.sessions FOR UPDATE"`, 1, 0},
		{"a lower-case clause", "internal/api/x.go", `var q = "select 1 from t for no key update"`, 1, 0},
		{"an advisory lock literal", "internal/store/y.go", `const q = "SELECT pg_catalog.pg_advisory_xact_lock(1)"`, 1, 0},
		{"the same text in locks.go is the place for it", locksFile, `const q = "SELECT 1 FROM ctrlz.sessions FOR UPDATE"`, 0, 0},
		{"prose without a clause", "internal/store/z.go", `const q = "wait for updates to finish"`, 0, 0},
		{"FOR UPDATE on users", "internal/store/u.go", `func f() { db.Exec(ctx, "SELECT 1 FROM ctrlz.users WHERE id = $1 FOR UPDATE") }`, 1, 1},
		{"FOR SHARE on admin_users", "internal/store/u2.go", `func f() { db.Exec(ctx, "SELECT 1 FROM ctrlz.admin_users WHERE id = $1 FOR SHARE") }`, 1, 1},
		{"FOR NO KEY UPDATE on users is the rule", "internal/store/u3.go", `func f() { db.Exec(ctx, "SELECT 1 FROM ctrlz.users WHERE id = $1 FOR NO KEY UPDATE") }`, 1, 0},
		{"FOR UPDATE OF u on a join with users", "internal/store/u4.go", `func f() { db.Exec(ctx, "SELECT 1 FROM ctrlz.users u JOIN ctrlz.tenants t ON t.id = u.tenant_id FOR UPDATE OF u") }`, 1, 1},
		{"a table that has no rank", "internal/store/n.go", `func f() { db.Exec(ctx, "UPDATE ctrlz.brand_new SET a = 1") }`, 0, 1},
		{"a function that has no declared ranks", "internal/store/n2.go", `func f() { db.Exec(ctx, "SELECT * FROM ctrlz_fn.brand_new_fn($1)") }`, 0, 1},
		{"an advisory key that has no rank", "internal/store/n3.go", `func f() { db.Exec(ctx, "SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('somewhere.else', 0))") }`, 1, 1},
		{"an update without the schema", "internal/store/q1.go", `func f() { db.Exec(ctx, "UPDATE refresh_tokens SET revoked_at = now() WHERE id = $1") }`, 0, 1},
		{"a delete without the schema", "internal/store/q2.go", `func f() { db.Exec(ctx, "DELETE FROM sessions WHERE id = $1") }`, 0, 1},
		{"a quoted insert without the schema", "internal/store/q3.go", `func f() { db.Exec(ctx, "INSERT INTO \"refresh_tokens\" (id) VALUES ($1)") }`, 0, 1},
	}
	for _, c := range cases {
		fset := token.NewFileSet()
		af, err := parser.ParseFile(fset, c.path, header+c.src, parser.ParseComments)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		fs := []file{{path: c.path, ast: af}, filler(t, fset)}
		if got := lockLiteralProblems(fset, fs); len(got) != c.literal {
			t.Errorf("%s: %d literal problems %v, want %d", c.name, len(got), got, c.literal)
		}
		if got := lockProblems(fset, fs); len(got) != c.class {
			t.Errorf("%s: %d classification problems %v, want %d", c.name, len(got), got, c.class)
		}
	}
}
