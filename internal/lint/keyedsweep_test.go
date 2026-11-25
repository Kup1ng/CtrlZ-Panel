package lint_test

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/parser"
	"go/token"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// A keyed sweep reads its ids with a plain SELECT and deletes each row with its own statement (sweepKeyed in
// internal/store/worker_sms.go, rule bounded-sweeps and lock-order). The DELETE must repeat every condition of
// the read, because the read locks nothing: a row refreshed between the two (an invite whose expiry was
// extended, a session used again) must be left alone, and only the repeated predicate does that. The
// bounded-sweeps lint accepts a keyed statement as it stands (`id = $n` names one row), so nothing judged this,
// and a mutant that dropped the predicate of the invites sweep survived in run 44855288724.
//
// One rule, read from the call sites of sweepKeyed and not from the names of the statements: the conjuncts of
// the DELETE, less its one `id = $n`, are the conjuncts of the read, as sets. A statement the rule cannot read
// (a SQL text that is not a constant, a closure with no database call or with two, an OR outside parentheses)
// is a problem and not a pass.

var keyConjunct = regexp.MustCompile(`(?i)^id\s*=\s*\$\d+$`)

// keyedWhere returns the conjuncts of the WHERE clause of a statement, up to its ORDER BY, LIMIT or RETURNING.
func keyedWhere(sql string) ([]string, string) {
	s := strings.Join(strings.Fields(sql), " ")
	w := atDepth0(s, "WHERE")
	if len(w) != 1 {
		return nil, "it has no single WHERE clause"
	}
	cond := s[w[0]+len("WHERE"):]
	for _, end := range []string{"ORDER", "LIMIT", "RETURNING", "FOR"} {
		if p := atDepth0(cond, end); len(p) > 0 {
			cond = cond[:p[0]]
		}
	}
	if len(atDepth0(cond, "OR")) > 0 {
		return nil, "an OR outside parentheses"
	}
	parts := splitAt(cond, atDepth0(cond, "AND"), "AND")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts, ""
}

// keyedSweepPairProblem judges one pair of statements: the read of the ids and the delete of one row.
func keyedSweepPairProblem(read, del string) string {
	if !strings.HasPrefix(strings.ToUpper(strings.TrimSpace(read)), "SELECT") {
		return "the read is not a SELECT"
	}
	if !strings.HasPrefix(strings.ToUpper(strings.TrimSpace(del)), "DELETE") {
		return "the write is not a DELETE"
	}
	want, why := keyedWhere(read)
	if why != "" {
		return "the read: " + why
	}
	got, why := keyedWhere(del)
	if why != "" {
		return "the delete: " + why
	}
	var rest []string
	keys := 0
	for _, c := range got {
		if keyConjunct.MatchString(c) {
			keys++
			continue
		}
		rest = append(rest, c)
	}
	if keys != 1 {
		return fmt.Sprintf("the delete names its row %d times (want one `id = $n`)", keys)
	}
	sort.Strings(rest)
	sort.Strings(want)
	if strings.Join(rest, "\x00") != strings.Join(want, "\x00") {
		return fmt.Sprintf("the delete does not repeat the predicate of the read: it checks %q, the read selected by %q", rest, want)
	}
	return ""
}

// keyedSweepProblems reads every call of sweepKeyed in the non-test files.
func keyedSweepProblems(fset *token.FileSet, files []file) (problems []string, calls int) {
	info, ok := typeInfo(fset, files)
	if !ok {
		return []string{"type information unavailable"}, 0
	}
	sinks := sqlSinks()
	// sqlOf returns the one SQL constant a closure sends to the database.
	sqlOf := func(arg ast.Expr) (string, string) {
		lit, ok := arg.(*ast.FuncLit)
		if !ok {
			return "", "an argument that is not a function literal"
		}
		var texts []string
		var bad string
		ast.Inspect(lit.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			idx, isSink := sinks[calleeName(call.Fun)]
			if !isSink {
				return true
			}
			if idx < 0 || len(call.Args) <= idx {
				bad = "a database call that carries no SQL text"
				return true
			}
			tv, known := info.Types[call.Args[idx]]
			if !known || tv.Value == nil || tv.Value.Kind() != constant.String {
				bad = "a SQL text that is not a constant"
				return true
			}
			texts = append(texts, constant.StringVal(tv.Value))
			return true
		})
		if bad != "" {
			return "", bad
		}
		if len(texts) != 1 {
			return "", fmt.Sprintf("%d database calls (want one)", len(texts))
		}
		return texts[0], ""
	}
	for _, f := range files {
		if f.test {
			continue
		}
		ast.Inspect(f.ast, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || calleeName(call.Fun) != "sweepKeyed" {
				return true
			}
			calls++
			at := fmt.Sprintf("%s:%d", f.path, fset.Position(call.Pos()).Line)
			if len(call.Args) != 2 {
				problems = append(problems, at+": sweepKeyed takes the read and the delete")
				return true
			}
			read, why := sqlOf(call.Args[0])
			if why != "" {
				problems = append(problems, at+": the read: "+why)
				return true
			}
			del, why := sqlOf(call.Args[1])
			if why != "" {
				problems = append(problems, at+": the delete: "+why)
				return true
			}
			if p := keyedSweepPairProblem(read, del); p != "" {
				problems = append(problems, at+": "+p)
			}
			return true
		})
	}
	sort.Strings(problems)
	return problems, calls
}

func TestAKeyedSweepRepeatsThePredicateOfItsRead(t *testing.T) {
	fset, files := parseRepo(t)
	problems, calls := keyedSweepProblems(fset, files)
	for _, p := range problems {
		t.Error(p)
	}
	// The module has five keyed sweeps (the invites and four tenant ones). None found means the rule read
	// nothing, which is a failure and not a pass.
	if calls < 5 {
		t.Fatalf("%d calls of sweepKeyed were read, want at least 5: the rule would judge nothing", calls)
	}
}

// TestAKeyedSweepRuleCanFail plants each way a keyed delete can lose or change the predicate of its read.
func TestAKeyedSweepRuleCanFail(t *testing.T) {
	const read = "SELECT id FROM ctrlz.invites WHERE expires_at < now() - interval '90 days' ORDER BY id LIMIT $1"
	const tenantRead = "SELECT id FROM ctrlz.sessions WHERE tenant_id = $1 AND absolute_expires_at < $3::timestamptz - interval '1 day' ORDER BY id LIMIT $2"
	cases := []struct {
		name, read, del string
		bad             bool
	}{
		{"the predicate repeated", read, "DELETE FROM ctrlz.invites WHERE id = $1 AND expires_at < now() - interval '90 days'", false},
		{"a tenant read and delete", tenantRead, "DELETE FROM ctrlz.sessions WHERE tenant_id = $1 AND id = $2 AND absolute_expires_at < $3::timestamptz - interval '1 day'", false},
		{"the key in another place and lines", tenantRead, "DELETE FROM ctrlz.sessions\n WHERE id = $2\n  AND absolute_expires_at < $3::timestamptz - interval '1 day'\n  AND tenant_id = $1", false},
		{"the predicate dropped", read, "DELETE FROM ctrlz.invites WHERE id = $1 AND true", true},
		{"no predicate at all", read, "DELETE FROM ctrlz.invites WHERE id = $1", true},
		{"a longer interval", read, "DELETE FROM ctrlz.invites WHERE id = $1 AND expires_at < now() - interval '1 day'", true},
		{"the tenant dropped", tenantRead, "DELETE FROM ctrlz.sessions WHERE id = $2 AND absolute_expires_at < $3::timestamptz - interval '1 day'", true},
		{"no key", read, "DELETE FROM ctrlz.invites WHERE expires_at < now() - interval '90 days'", true},
		{"the key twice", read, "DELETE FROM ctrlz.invites WHERE id = $1 AND id = $2 AND expires_at < now() - interval '90 days'", true},
		{"an OR in the delete", read, "DELETE FROM ctrlz.invites WHERE id = $1 AND expires_at < now() - interval '90 days' OR true", true},
		{"no WHERE", read, "DELETE FROM ctrlz.invites", true},
		{"an update for a delete", read, "UPDATE ctrlz.invites SET expires_at = now() WHERE id = $1 AND expires_at < now() - interval '90 days'", true},
		{"a read that is not a select", "DELETE FROM ctrlz.invites WHERE true", "DELETE FROM ctrlz.invites WHERE id = $1", true},
	}
	for _, c := range cases {
		if got := keyedSweepPairProblem(c.read, c.del); (got != "") != c.bad {
			t.Errorf("%s: problem %q, want a problem: %v", c.name, got, c.bad)
		}
	}

	// The shapes of the call sites.
	const hdr = "package p\ntype tx struct{}\nfunc (tx) Query(ctx any, sql string, a ...any) any { return nil }\nfunc (tx) Exec(ctx any, sql string, a ...any) any { return nil }\nfunc sweepKeyed(f func() any, d func(id int) any) {}\nvar t tx\nvar dyn string\n"
	const qRead = "const qIDs = `" + read + "`\n"
	const qDel = "const qDel = `DELETE FROM ctrlz.invites WHERE id = $1 AND expires_at < now() - interval '90 days'`\n"
	const qBadDel = "const qBadDel = `DELETE FROM ctrlz.invites WHERE id = $1`\n"
	siteCases := []struct {
		name, src string
		want      int
	}{
		{"a pair that repeats", hdr + qRead + qDel + "func f() { sweepKeyed(func() any { return t.Query(nil, qIDs, 1) }, func(id int) any { return t.Exec(nil, qDel, id) }) }\n", 0},
		{"a pair that drops the predicate", hdr + qRead + qBadDel + "func f() { sweepKeyed(func() any { return t.Query(nil, qIDs, 1) }, func(id int) any { return t.Exec(nil, qBadDel, id) }) }\n", 1},
		{"a delete whose text is not a constant", hdr + qRead + "func f() { sweepKeyed(func() any { return t.Query(nil, qIDs, 1) }, func(id int) any { return t.Exec(nil, dyn, id) }) }\n", 1},
		{"a delete passed as a named function", hdr + qRead + "func g(id int) any { return nil }\nfunc f() { sweepKeyed(func() any { return t.Query(nil, qIDs, 1) }, g) }\n", 1},
		{"a delete closure with two calls", hdr + qRead + qDel + "func f() { sweepKeyed(func() any { return t.Query(nil, qIDs, 1) }, func(id int) any { t.Exec(nil, qDel, id); return t.Exec(nil, qDel, id) }) }\n", 1},
		{"a delete closure with no call", hdr + qRead + "func f() { sweepKeyed(func() any { return nil }, func(id int) any { return nil }) }\n", 1},
	}
	for _, c := range siteCases {
		fset := token.NewFileSet()
		af, err := parser.ParseFile(fset, "internal/store/x.go", c.src, 0)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		got, n := keyedSweepProblems(fset, []file{{path: "internal/store/x.go", ast: af}, filler(t, fset)})
		if len(got) != c.want || n != 1 {
			t.Errorf("%s: %d problems %v over %d calls, want %d over 1", c.name, len(got), got, n, c.want)
		}
	}
}
