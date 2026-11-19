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
)

// The bounded-sweeps rule (P1 auth review, round 5, topic 16; spec 9.5, 10.4, 18.3).
//
// Retention and expiry sweeps were written as unbounded statements in one transaction,
// first for the global tables, then for the tenant tables and the fast OTP sweep. One
// statement_timeout rolled the whole transaction back, and the slow sweep shared a
// goroutine with the fast one. The rule has three parts, each enforced here for code
// nobody has written yet:
//
//  1. Every DELETE or UPDATE that can retire many rows is a batch bounded by primary key:
//     `WHERE <pk> IN (SELECT <pk> FROM <same table> ... LIMIT <parameter>)`. A statement
//     may instead be keyed (`id = $n`, one row), or be named in sweepNotASweep with the
//     reason it is neither. The scope is every statement of internal/store/worker_*.go,
//     every DELETE of the module's SQL constants, and the bodies of the definer functions
//     the worker runs (a name that says sweep, purge, expire, cleanup, retention, prune or
//     starts with worker_). A new statement that is none of the three fails, and so does a
//     registry entry that no longer matches one.
//  2. Every call of a store batch method (a GlobalTx or Tx method named ...Batch) from
//     outside the store sits inside a transaction callback (WithGlobal or WithTenant), and
//     that sits inside a sweepbatch.Drain callback. Drain is the one loop: it bounds the
//     batches of a run, and each batch is its own transaction because the callback opens
//     it.
//  3. The fast and the slow sweep run on separate goroutines: Sweeper.Run has two go
//     statements, each reaching exactly one of Fast and Slow, and nothing else calls them
//     outside tests.

// sweepNotASweep names the statements that are in scope and are neither bounded nor keyed,
// with the reason each is not a retention sweep. The key is the Go constant or the SQL
// function.
var sweepNotASweep = map[string]string{
	"qCountersRefund": "gives one message's count back to one counter row named by its whole primary key (day, scope, key)",
	"qRecoveryDelete": "replaces the recovery codes of one user on regeneration: at most the ten of a set, not a retention sweep",
	"worker_passkeys_mark_stale": "the RP ID change job: one tenant's credentials of another RP ID, in the one transaction that makes the change and its notices atomic (7.4); " +
		"run by an admin action, not by a timer",
	"worker_enforce_clear_without_live": "the second half of the RP ID change job, atomic with the first so nobody is locked out (7.4); run by an admin action, not by a timer",
}

// sweepPrimaryKeys are the primary keys that are not just id. A bounded batch names the
// whole key.
var sweepPrimaryKeys = map[string]string{
	"sms_counters":  "day,scope,key",
	"auth_throttle": "scope,key",
}

// sweepFunctionName is the name of a definer function the rule reads.
var sweepFunctionName = regexp.MustCompile(`(?i)^worker_|sweep|purge|expire|expiry|cleanup|retention|prune`)

// ---------------------------------------------------------------------------
// SQL reading

type dmlStatement struct {
	kind  string // DELETE or UPDATE
	table string
	text  string // from the keyword to the end of the statement
}

var dmlStart = regexp.MustCompile(`(?i)\b(DELETE\s+FROM|UPDATE)\s+ctrlz\.(\w+)`)

// dmlStatements finds the DELETE and UPDATE statements of a SQL text, a CTE or a function
// body included. A statement ends at a semicolon, or at the parenthesis that closes the
// one it is inside (a WITH ... AS (UPDATE ...)).
func dmlStatements(sql string) []dmlStatement {
	s := stripSQLComments(sql)
	var out []dmlStatement
	for _, m := range dmlStart.FindAllStringSubmatchIndex(s, -1) {
		end := len(s)
		depth := 0
		inQuote := false
	scan:
		for i := m[0]; i < len(s); i++ {
			switch c := s[i]; {
			case c == '\'':
				inQuote = !inQuote
			case inQuote:
			case c == '(':
				depth++
			case c == ')':
				depth--
				if depth < 0 {
					end = i
					break scan
				}
			case c == ';' && depth == 0:
				end = i
				break scan
			}
		}
		kind := "UPDATE"
		if strings.HasPrefix(strings.ToUpper(s[m[2]:m[3]]), "DELETE") {
			kind = "DELETE"
		}
		out = append(out, dmlStatement{kind: kind, table: s[m[4]:m[5]], text: s[m[0]:end]})
	}
	return out
}

func wordByte(c byte) bool {
	return c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// atDepth0 returns the positions of the word w that stand outside every parenthesis and
// quote of s.
func atDepth0(s, w string) []int {
	var out []int
	depth := 0
	inQuote := false
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '\'':
			inQuote = !inQuote
		case inQuote:
		case c == '(':
			depth++
		case c == ')':
			depth--
		case depth == 0 && i+len(w) <= len(s) && strings.EqualFold(s[i:i+len(w)], w) &&
			(i == 0 || !wordByte(s[i-1])) && (i+len(w) == len(s) || !wordByte(s[i+len(w)])):
			out = append(out, i)
		}
	}
	return out
}

// splitAt cuts s at the given word positions.
func splitAt(s string, pos []int, w string) []string {
	var parts []string
	last := 0
	for _, p := range pos {
		parts = append(parts, strings.TrimSpace(s[last:p]))
		last = p + len(w)
	}
	return append(parts, strings.TrimSpace(s[last:]))
}

var (
	keyedConjunct  = regexp.MustCompile(`(?i)^(?:\w+\.)?id\s*=\s*\$\d+(?:::\w+)?$`)
	inConjunct     = regexp.MustCompile(`(?is)^(.+?)\s+IN\s*\(`)
	dollarParam    = regexp.MustCompile(`\$\d+`)
	aliasPrefix    = regexp.MustCompile(`\b\w+\.`)
	spaceAndParens = strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "", "(", "", ")", "")
)

// judge says why a statement is neither keyed nor a batch bounded by its primary key, or
// "" when it is one of the two. params are the names a limit may be drawn from: nothing for
// a Go constant (its parameters are $n), the function's own parameters for a function body.
func judge(st dmlStatement, params []string) string {
	where := atDepth0(st.text, "WHERE")
	if len(where) == 0 {
		return "no WHERE clause: it touches every row"
	}
	cond := st.text[where[0]+len("WHERE"):]
	if r := atDepth0(cond, "RETURNING"); len(r) > 0 {
		cond = cond[:r[0]]
	}
	if len(atDepth0(cond, "OR")) > 0 {
		return "an OR outside parentheses widens the key or the bound"
	}
	pk := sweepPrimaryKeys[st.table]
	if pk == "" {
		pk = "id"
	}
	for _, c := range splitAt(cond, atDepth0(cond, "AND"), "AND") {
		if keyedConjunct.MatchString(c) && pk == "id" {
			return ""
		}
		m := inConjunct.FindStringSubmatchIndex(c)
		if m == nil {
			continue
		}
		left := strings.ToLower(spaceAndParens.Replace(aliasPrefix.ReplaceAllString(c[m[2]:m[3]], "")))
		if left != pk {
			continue
		}
		open := m[1] - 1 // the "(" after IN
		depth := 0
		closeAt := -1
		for i := open; i < len(c); i++ {
			if c[i] == '(' {
				depth++
			} else if c[i] == ')' {
				depth--
				if depth == 0 {
					closeAt = i
					break
				}
			}
		}
		if closeAt != len(c)-1 {
			continue // something follows the subselect: it is not the whole condition
		}
		inner := strings.TrimSpace(c[open+1 : closeAt])
		if !strings.HasPrefix(strings.ToUpper(inner), "SELECT") {
			continue
		}
		if !regexp.MustCompile(`(?i)\bFROM\s+ctrlz\.` + st.table + `\b`).MatchString(inner) {
			continue // the bound must come from the table being swept
		}
		lim := atDepth0(inner, "LIMIT")
		if len(lim) == 0 {
			continue
		}
		expr := inner[lim[0]+len("LIMIT"):]
		for _, w := range []string{"FOR", "OFFSET"} {
			if p := atDepth0(expr, w); len(p) > 0 {
				expr = expr[:p[0]]
			}
		}
		bounded := dollarParam.MatchString(expr)
		for _, p := range params {
			if regexp.MustCompile(`\b` + regexp.QuoteMeta(p) + `\b`).MatchString(expr) {
				bounded = true
			}
		}
		if bounded {
			return recheck(splitAt(cond, atDepth0(cond, "AND"), "AND"), c, inner)
		}
	}
	return fmt.Sprintf("%s ctrlz.%s is neither keyed (id = $n) nor bounded (%s IN (SELECT %s FROM ctrlz.%s ... LIMIT <parameter>))",
		st.kind, st.table, pk, pk, st.table)
}

// ---------------------------------------------------------------------------
// Go constants

// sweepScope says whether a statement of this file is read by the rule.
func sweepScope(path string, st dmlStatement) bool {
	if strings.HasPrefix(path, "internal/store/worker_") {
		return true
	}
	return st.kind == "DELETE"
}

// goSweepProblems judges the SQL constants of the module and the SQL literals that reach a
// database call. It returns the problems and the registry names it used.
func goSweepProblems(fset *token.FileSet, files []file) (problems []string, used map[string]bool) {
	used = map[string]bool{}
	info, ok := typeInfo(fset, files)
	if !ok {
		return []string{"type information unavailable"}, used
	}
	judgeText := func(path, name string, pos token.Pos, sql string) {
		for _, st := range dmlStatements(sql) {
			if !sweepScope(path, st) {
				continue
			}
			why := judge(st, nil)
			if why == "" {
				continue
			}
			if _, ok := sweepNotASweep[name]; ok && name != "" {
				used[name] = true
				continue
			}
			problems = append(problems, fmt.Sprintf("%s:%d: %s: %s", path, fset.Position(pos).Line, name, why))
		}
	}
	for _, f := range files {
		if f.test || sqlExempt(f.path) {
			continue
		}
		ast.Inspect(f.ast, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.ValueSpec:
				for _, id := range n.Names {
					if c, ok := info.Defs[id].(*types.Const); ok && c.Val().Kind() == constant.String {
						judgeText(f.path, id.Name, id.Pos(), constant.StringVal(c.Val()))
					}
				}
			case *ast.CallExpr:
				idx, isSink := sqlSinks()[calleeName(n.Fun)]
				if !isSink || idx < 0 || len(n.Args) <= idx {
					return true
				}
				if _, named := n.Args[idx].(*ast.Ident); named {
					return true // a constant, judged by name above
				}
				if tv, known := info.Types[n.Args[idx]]; known && tv.Value != nil && tv.Value.Kind() == constant.String {
					// A literal cannot be named in the registry: it has to be bounded or keyed.
					judgeText(f.path, "", n.Pos(), constant.StringVal(tv.Value))
				}
			}
			return true
		})
	}
	sort.Strings(problems)
	return problems, used
}

// ---------------------------------------------------------------------------
// Definer functions

type sqlFunction struct {
	name   string
	params []string
	body   string
	file   string
}

var (
	createFunction = regexp.MustCompile(`(?is)\bCREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+(?:\w+\.)?(\w+)\s*\(([^)]*)\)`)
	dropFunction   = regexp.MustCompile(`(?is)\bDROP\s+FUNCTION\s+(?:IF\s+EXISTS\s+)?(?:\w+\.)?(\w+)\s*\(([^)]*)\)`)
)

func splitArgs(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return strings.Split(s, ",")
}

// liveFunctions reads migration files in order and returns the definer functions as the last
// migration leaves them: a later CREATE replaces an earlier one of the same name and
// number of arguments, and a DROP removes it.
func liveFunctions(files map[string]string) []sqlFunction {
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	live := map[string]sqlFunction{}
	for _, fn := range names {
		s := stripSQLComments(files[fn])
		type ev struct {
			at   int
			drop bool
			m    []int
		}
		var evs []ev
		for _, m := range createFunction.FindAllStringSubmatchIndex(s, -1) {
			evs = append(evs, ev{at: m[0], m: m})
		}
		for _, m := range dropFunction.FindAllStringSubmatchIndex(s, -1) {
			evs = append(evs, ev{at: m[0], drop: true, m: m})
		}
		sort.Slice(evs, func(i, j int) bool { return evs[i].at < evs[j].at })
		for _, e := range evs {
			name := s[e.m[2]:e.m[3]]
			args := splitArgs(s[e.m[4]:e.m[5]])
			key := fmt.Sprintf("%s/%d", name, len(args))
			if e.drop {
				delete(live, key)
				continue
			}
			var params []string
			for _, a := range args {
				f := strings.Fields(a)
				if len(f) >= 2 {
					params = append(params, f[0])
				}
			}
			rest := s[e.m[1]:]
			tag := regexp.MustCompile(`\$\w*\$`).FindStringIndex(rest)
			body := ""
			if tag != nil {
				open := rest[tag[0]:tag[1]]
				if end := strings.Index(rest[tag[1]:], open); end >= 0 {
					body = rest[tag[1] : tag[1]+end]
				}
			}
			live[key] = sqlFunction{name: name, params: params, body: body, file: fn}
		}
	}
	out := make([]sqlFunction, 0, len(live))
	for _, f := range live {
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}

func functionSweepProblems(fns []sqlFunction) (problems []string, used map[string]bool) {
	used = map[string]bool{}
	for _, f := range fns {
		if !sweepFunctionName.MatchString(f.name) {
			continue
		}
		for _, st := range dmlStatements(f.body) {
			why := judge(st, f.params)
			if why == "" {
				continue
			}
			if _, ok := sweepNotASweep[f.name]; ok {
				used[f.name] = true
				continue
			}
			problems = append(problems, fmt.Sprintf("%s: function %s: %s", f.file, f.name, why))
		}
	}
	sort.Strings(problems)
	return problems, used
}

func readMigrations(t *testing.T) map[string]string {
	t.Helper()
	dir := filepath.Join(repoRoot(t), "migrations", "postgres")
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") || e.Name()[0] < '0' || e.Name()[0] > '9' {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		out[e.Name()] = string(b)
	}
	if len(out) < 20 {
		t.Fatalf("only %d migrations found in %s", len(out), dir)
	}
	return out
}

// ---------------------------------------------------------------------------
// Callers

// batchMethods are the store methods the loop helper drives: a GlobalTx or Tx method
// named ...Batch.
func batchMethods(files []file) map[string]bool {
	out := map[string]bool{}
	for _, f := range files {
		if f.test || !strings.HasPrefix(f.path, "internal/store/") || sqlExempt(f.path) {
			continue
		}
		for _, d := range f.ast.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Recv == nil || !strings.HasSuffix(fd.Name.Name, "Batch") {
				continue
			}
			t := fd.Recv.List[0].Type
			if s, ok := t.(*ast.StarExpr); ok {
				t = s.X
			}
			if id, ok := t.(*ast.Ident); ok && (id.Name == "GlobalTx" || id.Name == "Tx") {
				out[fd.Name.Name] = true
			}
		}
	}
	return out
}

// calledAs reports whether n is a call of a function or method with this name.
func calledAs(n ast.Node, names ...string) bool {
	call, ok := n.(*ast.CallExpr)
	if !ok {
		return false
	}
	got := calleeName(call.Fun)
	if i := strings.LastIndex(got, "."); i >= 0 {
		got = got[i+1:]
	}
	for _, w := range names {
		if got == w {
			return true
		}
	}
	return false
}

// batchCallProblems finds a batch method called outside a transaction callback that sits
// inside a Drain callback.
func batchCallProblems(fset *token.FileSet, files []file, batch map[string]bool) []string {
	var out []string
	for _, f := range files {
		if f.test || strings.HasPrefix(f.path, "internal/store/") || strings.HasPrefix(f.path, "internal/sweepbatch/") || sqlExempt(f.path) {
			continue
		}
		var stack []ast.Node
		ast.Inspect(f.ast, func(n ast.Node) bool {
			if n == nil {
				stack = stack[:len(stack)-1]
				return true
			}
			stack = append(stack, n)
			sel, ok := n.(*ast.SelectorExpr)
			if !ok || !batch[sel.Sel.Name] {
				return true
			}
			// Climb: the nearest function literal that is an argument of WithGlobal or
			// WithTenant, then the nearest one above it that is an argument of Drain.
			stage := 0
			for i := len(stack) - 2; i > 0 && stage < 2; i-- {
				lit, isLit := stack[i].(*ast.FuncLit)
				if !isLit {
					continue
				}
				if call, isCall := stack[i-1].(*ast.CallExpr); isCall {
					if stage == 0 && calledAs(call, "WithGlobal", "WithTenant") {
						stage = 1
					} else if stage == 1 && calledAs(call, "Drain") {
						stage = 2
					}
				}
				_ = lit
			}
			if stage < 2 {
				out = append(out, fmt.Sprintf("%s:%d: %s must be called inside WithGlobal or WithTenant inside a sweepbatch.Drain callback", f.path, fset.Position(sel.Pos()).Line, sel.Sel.Name))
			}
			return true
		})
	}
	sort.Strings(out)
	return out
}

// goroutineProblems checks that Run starts the fast and the slow sweep on goroutines of
// their own and that nothing else calls them.
func goroutineProblems(fset *token.FileSet, files []file) []string {
	var out []string
	found := false
	for _, f := range files {
		if f.test || sqlExempt(f.path) {
			continue
		}
		for _, d := range f.ast.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil || f.path != "internal/worker/sweep/sweep.go" {
				continue
			}
			switch fd.Name.Name {
			case "Run":
				found = true
				seen := map[string]int{}
				gos := 0
				ast.Inspect(fd.Body, func(n ast.Node) bool {
					g, ok := n.(*ast.GoStmt)
					if !ok {
						return true
					}
					gos++
					reach := map[string]bool{}
					ast.Inspect(g, func(m ast.Node) bool {
						if s, ok := m.(*ast.SelectorExpr); ok && (s.Sel.Name == "Fast" || s.Sel.Name == "Slow") {
							reach[s.Sel.Name] = true
						}
						return true
					})
					if len(reach) != 1 {
						out = append(out, fmt.Sprintf("%s:%d: a goroutine of Run must reach exactly one of Fast and Slow", f.path, fset.Position(g.Pos()).Line))
					}
					for k := range reach {
						seen[k]++
					}
					return true
				})
				if gos != 2 || seen["Fast"] != 1 || seen["Slow"] != 1 {
					out = append(out, fmt.Sprintf("%s: Run must start the fast and the slow sweep on one goroutine each (go statements %d, fast %d, slow %d)", f.path, gos, seen["Fast"], seen["Slow"]))
				}
			case "Fast", "Slow":
				ast.Inspect(fd.Body, func(n ast.Node) bool {
					if s, ok := n.(*ast.SelectorExpr); ok && (s.Sel.Name == "Fast" || s.Sel.Name == "Slow") {
						out = append(out, fmt.Sprintf("%s:%d: %s must not call the other cadence", f.path, fset.Position(s.Pos()).Line, fd.Name.Name))
					}
					return true
				})
			}
		}
	}
	if !found {
		out = append(out, "Sweeper.Run not found in internal/worker/sweep/sweep.go")
	}
	sort.Strings(out)
	return out
}

func TestBoundedSweeps(t *testing.T) {
	fset, files := parseRepo(t)
	problems, usedGo := goSweepProblems(fset, files)
	for _, p := range problems {
		t.Error(p)
	}
	fp, usedFn := functionSweepProblems(liveFunctions(readMigrations(t)))
	for _, p := range fp {
		t.Error(p)
	}
	// A registry entry that nothing needs any more is a hole in the rule: delete it.
	for name := range sweepNotASweep {
		if !usedGo[name] && !usedFn[name] {
			t.Errorf("sweepNotASweep[%q] matches no statement that needs it; remove it", name)
		}
	}
	for _, p := range batchCallProblems(fset, files, batchMethods(files)) {
		t.Error(p)
	}
	for _, p := range goroutineProblems(fset, files) {
		t.Error(p)
	}
}

// TestBoundedSweepsCanFail plants code that breaks each part and expects the lint to say so.
func TestBoundedSweepsCanFail(t *testing.T) {
	goCases := []struct {
		name, path, src string
		want            int
	}{
		{"the mutant: an unbounded delete of sessions in the worker file", "internal/store/worker_sms.go",
			"const qBad = `DELETE FROM ctrlz.sessions WHERE absolute_expires_at < now()`", 1},
		{"an unbounded delete outside the worker file", "internal/store/other.go",
			"const qBad = `DELETE FROM ctrlz.invites WHERE expires_at < now()`", 1},
		{"a bulk update in the worker file", "internal/store/worker_x.go",
			"const qBad = `UPDATE ctrlz.sms_outbox SET state = 'failed' WHERE created_at < now() - interval '1 hour'`", 1},
		{"a bulk update elsewhere is not read", "internal/store/other.go",
			"const qFine = `UPDATE ctrlz.sms_outbox SET state = 'failed' WHERE created_at < now()`", 0},
		{"a delete of every row", "internal/store/other.go",
			"const qBad = `DELETE FROM ctrlz.sessions`", 1},
		{"a limit on the wrong side of an OR", "internal/store/other.go",
			"const qBad = `DELETE FROM ctrlz.sessions WHERE id IN (SELECT id FROM ctrlz.sessions LIMIT $1) OR expires_at < now()`", 1},
		{"a limit that is a literal", "internal/store/other.go",
			"const qBad = `DELETE FROM ctrlz.sessions WHERE id IN (SELECT id FROM ctrlz.sessions WHERE expires_at < now() LIMIT 5000)`", 1},
		{"a limit on a different table", "internal/store/other.go",
			"const qBad = `DELETE FROM ctrlz.sessions WHERE id IN (SELECT id FROM ctrlz.invites LIMIT $1)`", 1},
		{"a limit inside a condition that is not the key", "internal/store/other.go",
			"const qBad = `DELETE FROM ctrlz.sessions WHERE expires_at < now() AND user_id IN (SELECT user_id FROM ctrlz.sessions LIMIT $1)`", 1},
		{"a bound that names a part of a composite key", "internal/store/other.go",
			"const qBad = `DELETE FROM ctrlz.sms_counters WHERE key IN (SELECT key FROM ctrlz.sms_counters LIMIT $1)`", 1},
		{"a subselect with something after it", "internal/store/other.go",
			"const qBad = `DELETE FROM ctrlz.sessions WHERE id IN (SELECT id FROM ctrlz.sessions LIMIT $1) OR true`", 1},
		{"a literal that reaches the database", "internal/store/other.go",
			"func f() { db.Exec(ctx, `DELETE FROM ctrlz.sessions WHERE expires_at < now()`) }", 1},
		{"a constant concatenated into the statement", "internal/store/other.go",
			"const lock = \" FOR UPDATE SKIP LOCKED\"\nconst qBad = `DELETE FROM ctrlz.sessions WHERE expires_at < now()` + lock", 1},
		{"a bounded batch", "internal/store/other.go",
			"const qOK = `DELETE FROM ctrlz.sessions WHERE tenant_id = $1 AND id IN (SELECT id FROM ctrlz.sessions WHERE tenant_id = $1 LIMIT $2)`", 0},
		{"a bounded batch with a lock clause", "internal/store/other.go",
			"const lock = \" FOR UPDATE SKIP LOCKED\"\nconst qOK = `WITH e AS (UPDATE ctrlz.otp_challenges SET delivery_ct = NULL WHERE id IN (SELECT id FROM ctrlz.otp_challenges ORDER BY created_at LIMIT $1` + lock + `) RETURNING id) SELECT id FROM e`", 0},
		{"a composite key batch", "internal/store/other.go",
			"const qOK = `DELETE FROM ctrlz.sms_counters WHERE (day, scope, key) IN (SELECT day, scope, key FROM ctrlz.sms_counters WHERE day < $1 LIMIT $2) AND day < $1`", 0},
		// db-r5-7: the predicate that only the subselect carries is not asked again on a row
		// another transaction updated after the snapshot.
		{"a batch whose outer statement forgets the predicate", "internal/store/other.go",
			"const qBad = `DELETE FROM ctrlz.invites WHERE id IN (SELECT id FROM ctrlz.invites WHERE expires_at < now() LIMIT $1)`", 1},
		{"a batch that repeats the predicate with another alias", "internal/store/other.go",
			"const qOK = `DELETE FROM ctrlz.invites i WHERE i.id IN (SELECT s.id FROM ctrlz.invites s WHERE s.expires_at < now() LIMIT $1) AND i.expires_at < now()`", 0},
		{"a batch that repeats only one of two predicates", "internal/store/other.go",
			"const qBad = `DELETE FROM ctrlz.invites WHERE id IN (SELECT id FROM ctrlz.invites WHERE expires_at < now() AND used_at IS NULL LIMIT $1) AND expires_at < now()`", 1},
		{"a batch that locks the rows it picks needs no repeat", "internal/store/other.go",
			"const lock = \" FOR UPDATE SKIP LOCKED\"\nconst qOK = `DELETE FROM ctrlz.invites WHERE id IN (SELECT id FROM ctrlz.invites WHERE expires_at < now() LIMIT $1` + lock + `)`", 0},
		{"a keyed delete", "internal/store/other.go",
			"const qOK = `DELETE FROM ctrlz.webauthn_credentials WHERE tenant_id = $1 AND user_id = $2 AND id = $3`", 0},
		{"a keyed update in the worker file", "internal/store/worker_x.go",
			"const qOK = `UPDATE ctrlz.admin_jobs SET state = $2 WHERE id = $1 AND state IN ('queued', 'running')`", 0},
		{"an id equality that an OR makes meaningless", "internal/store/other.go",
			"const qBad = `DELETE FROM ctrlz.sessions WHERE id = $1 OR expires_at < now()`", 1},
		{"an id compared with something other than a parameter", "internal/store/other.go",
			"const qBad = `DELETE FROM ctrlz.sessions WHERE id = id`", 1},
		{"the registry names a constant that is unbounded", "internal/store/worker_sms.go",
			"const qCountersRefund = `UPDATE ctrlz.sms_counters SET count = count - 1 WHERE scope = $1`", 0},
		{"a test file may delete as it likes", "internal/store/other_test.go",
			"const qFine = `DELETE FROM ctrlz.sessions`", 0},
		{"the fixtures may delete as they like", "internal/authtest/x.go",
			"const qFine = `DELETE FROM ctrlz.sessions`", 0},
	}
	for _, c := range goCases {
		fset := token.NewFileSet()
		af, err := parser.ParseFile(fset, c.path, "package p\nvar db interface{ Exec(ctx any, sql string) }\nvar ctx any\n"+c.src, parser.ParseComments)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		got, _ := goSweepProblems(fset, []file{{path: c.path, test: strings.HasSuffix(c.path, "_test.go"), ast: af}, filler(t, fset)})
		if len(got) != c.want {
			t.Errorf("%s: %d problems %v, want %d", c.name, len(got), got, c.want)
		}
	}

	fnSrc := func(name, args, body string) map[string]string {
		return map[string]string{"0001_x.sql": "CREATE FUNCTION ctrlz_fn." + name + "(" + args + ") RETURNS integer LANGUAGE plpgsql AS $$ BEGIN " + body + " END $$;"}
	}
	fnCases := []struct {
		name string
		src  map[string]string
		want int
	}{
		{"an unbounded delete in a worker function", fnSrc("worker_sweep_x", "p_limit integer",
			"DELETE FROM ctrlz.auth_tickets WHERE expires_at < now();"), 1},
		{"an unbounded update in a sweep function", fnSrc("auth_sweep_x", "",
			"UPDATE ctrlz.users u SET totp_secret_ct = NULL WHERE u.totp_pending_at < now();"), 1},
		{"a limit that is not the parameter", fnSrc("worker_sweep_x", "p_limit integer",
			"DELETE FROM ctrlz.auth_tickets t WHERE t.id IN (SELECT s.id FROM ctrlz.auth_tickets s WHERE s.expires_at < now() LIMIT 100);"), 1},
		{"a limit drawn from the parameter", fnSrc("worker_sweep_x", "p_limit integer",
			"DELETE FROM ctrlz.auth_tickets t WHERE t.id IN (SELECT s.id FROM ctrlz.auth_tickets s WHERE s.expires_at < now() LIMIT LEAST(p_limit, 10000)) AND t.expires_at < now();"), 0},
		// The body of migration 0025 before 0026: the outer statement repeated the tenant and the
		// enrolment test and not the 15 minute test.
		{"the pending TOTP sweep of 0025", fnSrc("worker_sweep_pending_totp", "p_limit integer",
			"UPDATE ctrlz.users u SET totp_secret_ct = NULL, totp_pending_at = NULL WHERE u.id IN (SELECT s.id FROM ctrlz.users s WHERE s.tenant_id = v_tenant AND s.totp_enabled_at IS NULL AND s.totp_pending_at < pg_catalog.now() - interval '15 minutes' LIMIT LEAST(p_limit, 10000)) AND u.tenant_id = v_tenant AND u.totp_enabled_at IS NULL;"), 1},
		{"the pending TOTP sweep of 0026", fnSrc("worker_sweep_pending_totp", "p_limit integer",
			"UPDATE ctrlz.users u SET totp_secret_ct = NULL, totp_pending_at = NULL WHERE u.id IN (SELECT s.id FROM ctrlz.users s WHERE s.tenant_id = v_tenant AND s.totp_enabled_at IS NULL AND s.totp_pending_at < pg_catalog.now() - interval '15 minutes' LIMIT LEAST(p_limit, 10000)) AND u.tenant_id = v_tenant AND u.totp_enabled_at IS NULL AND u.totp_pending_at < pg_catalog.now() - interval '15 minutes';"), 0},
		{"a composite key", fnSrc("worker_sweep_x", "p_limit integer",
			"DELETE FROM ctrlz.auth_throttle t WHERE (t.scope, t.key) IN (SELECT s.scope, s.key FROM ctrlz.auth_throttle s WHERE s.window_start < now() LIMIT p_limit) AND t.window_start < now();"), 0},
		{"a function that is not a worker or sweep function is not read", fnSrc("auth_x", "",
			"DELETE FROM ctrlz.auth_tickets WHERE expires_at < now();"), 0},
		{"for update is not an update", fnSrc("worker_x", "",
			"PERFORM 1 FROM ctrlz.users WHERE id = $1 FOR UPDATE; INSERT INTO ctrlz.t VALUES (1) ON CONFLICT DO UPDATE SET a = 1;"), 0},
		{"a later migration replaces the function", map[string]string{
			"0001_x.sql": "CREATE FUNCTION ctrlz_fn.worker_sweep_x() RETURNS integer LANGUAGE sql AS $$ DELETE FROM ctrlz.auth_tickets WHERE expires_at < now() $$;",
			"0002_y.sql": "DROP FUNCTION ctrlz_fn.worker_sweep_x();\nCREATE FUNCTION ctrlz_fn.worker_sweep_x(p_limit integer) RETURNS integer LANGUAGE sql AS $$ DELETE FROM ctrlz.auth_tickets t WHERE t.id IN (SELECT s.id FROM ctrlz.auth_tickets s LIMIT p_limit) $$;"}, 0},
		{"a later migration brings the unbounded one back", map[string]string{
			"0001_x.sql": "CREATE FUNCTION ctrlz_fn.worker_sweep_x(p_limit integer) RETURNS integer LANGUAGE sql AS $$ DELETE FROM ctrlz.auth_tickets t WHERE t.id IN (SELECT s.id FROM ctrlz.auth_tickets s LIMIT p_limit) $$;",
			"0002_y.sql": "CREATE OR REPLACE FUNCTION ctrlz_fn.worker_sweep_x(p_limit integer) RETURNS integer LANGUAGE sql AS $$ DELETE FROM ctrlz.auth_tickets WHERE expires_at < now() $$;"}, 1},
	}
	for _, c := range fnCases {
		got, _ := functionSweepProblems(liveFunctions(c.src))
		if len(got) != c.want {
			t.Errorf("%s: %d problems %v, want %d", c.name, len(got), got, c.want)
		}
	}

	// The callers.
	storeFile := "package store\ntype GlobalTx struct{}\ntype Tx struct{}\nfunc (GlobalTx) SweepXBatch(a int) (int, error) { return 0, nil }\nfunc (Tx) Plain() {}\n"
	callCases := []struct {
		name, src string
		want      int
	}{
		{"a batch call in a Drain callback in its own transaction", `func f() {
	sweepbatch.Drain(ctx, p, func(ctx C, n int) (int, bool, error) {
		return 0, false, st.WithGlobal(ctx, o, func(g store.GlobalTx) error { _, err := g.SweepXBatch(n); return err })
	})
}`, 0},
		{"a batch call in a hand-written loop", `func f() {
	for i := 0; i < 9; i++ {
		st.WithGlobal(ctx, o, func(g store.GlobalTx) error { _, err := g.SweepXBatch(5); return err })
	}
}`, 1},
		{"a batch call in a Drain callback but in the callers transaction", `func f() {
	st.WithGlobal(ctx, o, func(g store.GlobalTx) error {
		sweepbatch.Drain(ctx, p, func(ctx C, n int) (int, bool, error) { _, err := g.SweepXBatch(n); return 0, false, err })
		return nil
	})
}`, 1},
		{"a batch call with no transaction callback", `func f(g store.GlobalTx) {
	sweepbatch.Drain(ctx, p, func(ctx C, n int) (int, bool, error) { _, err := g.SweepXBatch(n); return 0, false, err })
}`, 1},
		{"a batch call straight in a function", `func f(g store.GlobalTx) { g.SweepXBatch(1) }`, 1},
		{"a method that is not a batch is free", `func f(g store.Tx) { g.Plain() }`, 0},
	}
	for _, c := range callCases {
		fset := token.NewFileSet()
		sf, err := parser.ParseFile(fset, "internal/store/x.go", storeFile, 0)
		if err != nil {
			t.Fatal(err)
		}
		af, err := parser.ParseFile(fset, "internal/worker/y/y.go", "package y\n"+c.src, 0)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		files := []file{{path: "internal/store/x.go", ast: sf}, {path: "internal/worker/y/y.go", ast: af}}
		got := batchCallProblems(fset, files, batchMethods(files))
		if len(got) != c.want {
			t.Errorf("%s: %d problems %v, want %d", c.name, len(got), got, c.want)
		}
	}

	// The goroutines.
	goroutineCases := []struct {
		name, src string
		want      int
	}{
		{"two goroutines, one each", `func (s *S) Run() { go func() { s.Fast() }(); go func() { s.Slow() }() }
func (s *S) Fast() {}
func (s *S) Slow() {}`, 0},
		{"one goroutine runs both", `func (s *S) Run() { go func() { s.Fast(); s.Slow() }() }
func (s *S) Fast() {}
func (s *S) Slow() {}`, 2},
		{"slow runs in the callers goroutine", `func (s *S) Run() { go func() { s.Fast() }(); s.Slow() }
func (s *S) Fast() {}
func (s *S) Slow() {}`, 1},
		{"the slow sweep calls the fast one", `func (s *S) Run() { go func() { s.Fast() }(); go func() { s.Slow() }() }
func (s *S) Fast() {}
func (s *S) Slow() { s.Fast() }`, 1},
	}
	for _, c := range goroutineCases {
		fset := token.NewFileSet()
		af, err := parser.ParseFile(fset, "internal/worker/sweep/sweep.go", "package sweep\ntype S struct{}\n"+c.src, 0)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		got := goroutineProblems(fset, []file{{path: "internal/worker/sweep/sweep.go", ast: af}})
		if len(got) != c.want {
			t.Errorf("%s: %d problems %v, want %d", c.name, len(got), got, c.want)
		}
	}
}

// ---------------------------------------------------------------------------
// The predicate re-check (P1 auth review round 5, finding db-r5-7)

var conjunctEnd = []string{"GROUP", "ORDER", "LIMIT", "OFFSET", "HAVING", "FOR", "UNION", "WINDOW"}

// normalizeConjunct makes two spellings of one condition equal: no case, no white space, no
// table alias, no parentheses around the whole.
func normalizeConjunct(c string) string {
	return strings.ToLower(spaceAndParens.Replace(aliasPrefix.ReplaceAllString(c, "")))
}

// subselectConjuncts returns the AND-separated conditions of the subselect's own WHERE.
func subselectConjuncts(inner string) []string {
	where := atDepth0(inner, "WHERE")
	if len(where) == 0 {
		return nil
	}
	cond := inner[where[0]+len("WHERE"):]
	for _, w := range conjunctEnd {
		if p := atDepth0(cond, w); len(p) > 0 {
			cond = cond[:p[0]]
		}
	}
	return splitAt(cond, atDepth0(cond, "AND"), "AND")
}

// locksItsRows reports whether the subselect locks the rows it picks (FOR UPDATE and its
// relatives). The server then waits for a row and re-reads it against the subselect's own
// predicate, so the outer statement can only see rows that still qualify.
func locksItsRows(inner string) bool {
	for _, p := range atDepth0(inner, "FOR") {
		rest := strings.ToUpper(strings.TrimSpace(inner[p+len("FOR"):]))
		if strings.HasPrefix(rest, "UPDATE") || strings.HasPrefix(rest, "NO KEY UPDATE") {
			return true
		}
	}
	return false
}

// recheck is the second half of the batch shape. `<pk> IN (SELECT <pk> ... WHERE p LIMIT n)`
// bounds the batch, but under READ COMMITTED a row that another transaction updated after
// the statement's snapshot is re-read for the outer statement and judged against the OUTER
// WHERE only; the subselect's row is reused, not evaluated again. So a predicate that lives
// only in the subselect (a pending TOTP setup older than 15 minutes, a window that is over)
// is not re-checked on the new version of the row, and the sweep clears a setup the user
// just restarted. Every condition of the subselect's WHERE is therefore repeated in the
// outer WHERE, unless the subselect locks its rows.
func recheck(outer []string, inConjunct, inner string) string {
	if locksItsRows(inner) {
		return ""
	}
	have := map[string]bool{}
	for _, c := range outer {
		if c != inConjunct {
			have[normalizeConjunct(c)] = true
		}
	}
	for _, c := range subselectConjuncts(inner) {
		if !have[normalizeConjunct(c)] {
			return fmt.Sprintf("the outer WHERE does not repeat %q of the subselect: a row updated after the snapshot is re-checked against the outer WHERE only (repeat it, or lock the rows with FOR UPDATE in the subselect)", strings.TrimSpace(c))
		}
	}
	return ""
}
