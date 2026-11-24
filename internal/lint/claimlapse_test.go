package lint_test

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/parser"
	"go/token"
	"go/types"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The lapse of a claim and who may act on it (P1 auth review round 10, sms-r10-5; rule
// caps-and-endings).
//
// A claim keeps other workers away from an OTP or an outbox row for the lease, and a record of an
// accepted send may run past it: a record that meets a lock timeout rolls back, pauses and runs
// again, and for the pause it holds no lock on its row. A statement that ends a row "because its
// claim lapsed" (the exhausted pass, the expiry of unsent codes, the stale-outbox sweep) would take
// the row in that pause, refund the global slot of a code the provider had accepted, or fail an
// invite that was delivered. Round 9 made the record retry and so made the window.
//
// The rule is one source of truth for how long "lapsed" is: a statement may compare a claim column
// with the clock only by `claimed_until < now() - make_interval(secs => $n)`, where the parameter is
// store.RecordBudget; the only statements that compare it at the lapse itself are the two claim
// statements, which exist to replace a worker that died.
//
// Round 11 (sms-r11-1, sms-r11-3) turned the first form of this lint, a deny regex for the bare
// `claimed_until < now()`, into an allow list: a deny list names the spellings of one author (the
// other operand order, another clock function, a bare parameter and a literal grace all got past
// it), an allow list names the one shape that is right and fails closed for any other. So:
//
//  1. every mention of a claim column outside the two claim statements must be one of four shapes:
//     IS [NOT] NULL, the ending shape above, the target of an assignment in a SET list, or (only
//     in a registered reader) a plain read in a select list. Any other mention, whatever it does
//     with the column, is a problem;
//  2. the parameter of the ending shape is checked at its call site: the statement is passed to a
//     call whose argument for $n is `store.RecordBudget.Seconds()`, so a literal, a zero or another
//     duration is refused although the SQL text is the same;
//  3. a column that looks like a claim (a timestamp named for a claim or a lease) must be in
//     claimColumns, so a new claim column cannot sit outside the lint; a migration statement that
//     is not a declaration or a grant may not name a claim column; and a SQL string that is not a
//     constant is refused.

// claimColumnMention finds a claim column in SQL text, with the qualifier it carries: every
// identifier that ends in claimed_until, so a new column named like the two is judged too.
var claimColumnMention = regexp.MustCompile(`(?i)(?:\b[a-z_][a-z0-9_]*\.)?\b[a-z0-9_]*claimed_until\b`)

// claimColumns are the claim columns that exist. claimMigrationProblems fails for a timestamp
// column of a migration that is named like a claim and is not listed.
var claimColumns = map[string]bool{"claimed_until": true, "delivery_claimed_until": true}

// claimColumnDeclaration finds a timestamptz column whose name is a claim or a lease.
var claimColumnDeclaration = regexp.MustCompile(`(?i)\b([a-z0-9_]*(?:claim|lease)[a-z0-9_]*)\s+timestamptz\b`)

var (
	claimIsNull   = regexp.MustCompile(`(?i)^\s+IS\s+(?:NOT\s+)?NULL\b`)
	claimEnding   = regexp.MustCompile(`(?i)^\s*<\s*now\(\)\s*-\s*make_interval\(\s*secs\s*=>\s*\$(\d+)\s*\)`)
	claimAssign   = regexp.MustCompile(`^\s*=[^=>]`)
	claimRead     = regexp.MustCompile(`(?i)^\s+(?:AS\s+[a-z_][a-z0-9_]*\s+)?FROM\b`)
	claimAfterSet = regexp.MustCompile(`(?is)\bSET\b(.*)$`)
	claimNotList  = regexp.MustCompile(`(?i)\b(?:WHERE|FROM|SELECT|AND|OR|ON|HAVING|RETURNING)\b`)
	claimSelectOf = regexp.MustCompile(`(?i)\bSELECT\s*$`)
	claimDollar   = regexp.MustCompile(`^\$[a-zA-Z_]*\$`)
)

// claimStatements are the statements that may compare a claim at the lapse, with the reason.
var claimStatements = map[string]string{
	"qOTPClaim":    "takes an OTP whose lease lapsed, so a worker that died is replaced after the lease",
	"qOutboxClaim": "takes an outbox message whose lease lapsed, for the same reason",
}

// claimReaders are the statements that may read a claim column in a select list: the lease the
// claim still has is measured in the database, and nothing compares it with a clock in SQL.
var claimReaders = map[string]string{
	"qClaimLeaseLeft": "reports how much of its lease a claimed row still has, for the send budget",
}

// claimLapseFinding is what one statement leaves: its problems, and the parameter numbers its
// ending shapes pass the grace through (each is checked at the call site).
type claimLapseFinding struct {
	problems []string
	graceArg []int
}

// claimLapseJudge judges every mention of a claim column in a SQL text. claim says the statement
// is one of the registered claims, reader that it may read the column in a select list.
func claimLapseJudge(text string, claim, reader bool) claimLapseFinding {
	var out claimLapseFinding
	if claim {
		return out
	}
	text = stripSQLComments(text)
	for _, loc := range claimColumnMention.FindAllStringIndex(text, -1) {
		before, after := text[:loc[0]], text[loc[1]:]
		mention := text[loc[0]:loc[1]]
		switch {
		case claimIsNull.MatchString(after):
		case claimEnding.MatchString(after):
			m := claimEnding.FindStringSubmatch(after)
			n, _ := strconv.Atoi(m[1])
			out.graceArg = append(out.graceArg, n)
		case claimAssign.MatchString(after) && claimIsSetTarget(before):
		case reader && claimRead.MatchString(after) && claimSelectOf.MatchString(before):
		default:
			near := strings.Join(strings.Fields(text[max(0, loc[0]-24):min(len(text), loc[1]+32)]), " ")
			out.problems = append(out.problems, fmt.Sprintf("%q is used in a way the claim-lapse rule does not allow (near %q): outside the claim statements a claim column may only be tested IS [NOT] NULL, compared as `%s < now() - make_interval(secs => $n)` with $n bound to store.RecordBudget, or assigned in a SET list (rule caps-and-endings, sms-r10-5, sms-r11-1); a statement that must see a lapse itself is a claim and is registered in claimStatements", mention, near, mention))
		}
	}
	return out
}

// claimIsSetTarget says the text before a mention puts it in the target position of a SET list:
// right after SET or after a comma, with no clause that ends the list between the last SET and
// the mention.
func claimIsSetTarget(before string) bool {
	t := strings.TrimRight(before, " \t\r\n")
	up := strings.ToUpper(t)
	if !(strings.HasSuffix(t, ",") || strings.HasSuffix(up, " SET") || up == "SET") {
		return false
	}
	m := claimAfterSet.FindStringSubmatch(t)
	return m != nil && !claimNotList.MatchString(m[1])
}

// claimGraceIsRecordBudget says the argument of a call is `RecordBudget.Seconds()` of the store
// package, by the object the identifier resolves to and not by the spelling.
func claimGraceIsRecordBudget(info *types.Info, arg ast.Expr) bool {
	call, ok := arg.(*ast.CallExpr)
	if !ok || len(call.Args) != 0 {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Seconds" {
		return false
	}
	var id *ast.Ident
	switch x := sel.X.(type) {
	case *ast.Ident:
		id = x
	case *ast.SelectorExpr:
		id = x.Sel
	default:
		return false
	}
	c, ok := info.Uses[id].(*types.Const)
	return ok && c.Name() == "RecordBudget" && c.Pkg() != nil && c.Pkg().Name() == "store"
}

// claimLapseGoProblems judges every string of the module's non-test code.
func claimLapseGoProblems(fset *token.FileSet, files []file) (problems []string, used map[string]bool) {
	used = map[string]bool{}
	info, ok := typeInfo(fset, files)
	if !ok {
		return []string{"type information unavailable"}, used
	}
	graced := map[string][]int{} // constant name -> parameter numbers that carry the grace
	graceSeen := map[string]bool{}
	inConst := map[*ast.BasicLit]bool{}
	for _, f := range files {
		if f.test || sqlExempt(f.path) {
			continue
		}
		ast.Inspect(f.ast, func(n ast.Node) bool {
			vs, ok := n.(*ast.ValueSpec)
			if !ok {
				return true
			}
			for _, v := range vs.Values {
				ast.Inspect(v, func(m ast.Node) bool {
					if bl, ok := m.(*ast.BasicLit); ok {
						inConst[bl] = true
					}
					return true
				})
			}
			for _, id := range vs.Names {
				c, ok := info.Defs[id].(*types.Const)
				if !ok || c.Val().Kind() != constant.String {
					continue
				}
				text := constant.StringVal(c.Val())
				_, claim := claimStatements[id.Name]
				_, reader := claimReaders[id.Name]
				if (claim || reader) && claimColumnMention.MatchString(text) {
					used[id.Name] = true
				}
				fnd := claimLapseJudge(text, claim, reader)
				for _, p := range fnd.problems {
					problems = append(problems, fmt.Sprintf("%s:%d: %s: %s", f.path, fset.Position(id.Pos()).Line, id.Name, p))
				}
				if len(fnd.graceArg) > 0 {
					graced[id.Name] = fnd.graceArg
				}
			}
			return true
		})
	}
	for _, f := range files {
		if f.test || sqlExempt(f.path) {
			continue
		}
		ast.Inspect(f.ast, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.BasicLit:
				// A SQL string outside a constant is not judged by name, so it is refused
				// outright: the SQL lint already wants every statement to be a constant.
				if x.Kind == token.STRING && !inConst[x] && claimColumnMention.MatchString(x.Value) {
					problems = append(problems, fmt.Sprintf("%s:%d: a string outside a constant names a claim column; the claim-lapse rule judges constants only", f.path, fset.Position(x.Pos()).Line))
				}
			case *ast.CallExpr:
				for i, a := range x.Args {
					id, ok := a.(*ast.Ident)
					if !ok {
						continue
					}
					c, ok := info.Uses[id].(*types.Const)
					if !ok {
						continue
					}
					ns, ok := graced[c.Name()]
					if !ok {
						continue
					}
					graceSeen[c.Name()] = true
					for _, k := range ns {
						if i+k >= len(x.Args) || x.Ellipsis.IsValid() || !claimGraceIsRecordBudget(info, x.Args[i+k]) {
							problems = append(problems, fmt.Sprintf("%s:%d: %s passes its claim-lapse grace as $%d, and that argument is not store.RecordBudget.Seconds(): a literal or another duration lets the statement take a row inside the pause of a record (rule caps-and-endings, sms-r11-3)", f.path, fset.Position(x.Pos()).Line, c.Name(), k))
						}
					}
				}
			}
			return true
		})
	}
	for name := range graced {
		if !graceSeen[name] {
			problems = append(problems, fmt.Sprintf("%s compares a claim with the grace but is never passed to a call whose grace argument can be checked", name))
		}
	}
	sort.Strings(problems)
	return problems, used
}

// claimMigrationStatements splits a migration into statements at the semicolons that are outside a
// dollar-quoted body and a string.
func claimMigrationStatements(sql string) []string {
	var out []string
	var cur strings.Builder
	for i := 0; i < len(sql); {
		switch {
		case sql[i] == '\'':
			j := i + 1
			for j < len(sql) {
				if sql[j] == '\'' {
					if j+1 < len(sql) && sql[j+1] == '\'' {
						j += 2
						continue
					}
					break
				}
				j++
			}
			j = min(j+1, len(sql))
			cur.WriteString(sql[i:j])
			i = j
		case sql[i] == '$':
			m := claimDollar.FindString(sql[i:])
			if m == "" {
				cur.WriteByte(sql[i])
				i++
				continue
			}
			j := len(sql)
			if end := strings.Index(sql[i+len(m):], m); end >= 0 {
				j = i + len(m) + end + len(m)
			}
			cur.WriteString(sql[i:j])
			i = j
		case sql[i] == ';':
			out = append(out, cur.String())
			cur.Reset()
			i++
		default:
			cur.WriteByte(sql[i])
			i++
		}
	}
	if strings.TrimSpace(cur.String()) != "" {
		out = append(out, cur.String())
	}
	return out
}

// claimMigrationDeclares are the statements of a migration that may name a claim column: the ones
// that declare it, constrain it or grant on it. Everything else (a function, a view, a trigger, an
// index with a predicate, a DO block, a DML statement) may not, so a definer function that ends a
// row on a lapse is a problem here whatever it compares.
var claimMigrationDeclares = regexp.MustCompile(`(?i)^\s*(?:CREATE\s+TABLE|ALTER\s+TABLE|GRANT|REVOKE|COMMENT\s+ON)\b`)

// claimMigrationProblems judges one migration (comments are stripped first).
func claimMigrationProblems(sql string) []string {
	var problems []string
	sql = stripSQLComments(sql)
	for _, st := range claimMigrationStatements(sql) {
		if !claimColumnMention.MatchString(st) || claimMigrationDeclares.MatchString(st) {
			continue
		}
		head := strings.Join(strings.Fields(st), " ")
		head = head[:min(len(head), 60)]
		problems = append(problems, fmt.Sprintf("a statement that is not a declaration or a grant names a claim column (%q...): a migration may not end a row on a lapse (rule caps-and-endings, sms-r10-5, sms-r11-3)", head))
	}
	for _, m := range claimColumnDeclaration.FindAllStringSubmatch(sql, -1) {
		if !claimColumns[strings.ToLower(m[1])] {
			problems = append(problems, fmt.Sprintf("column %q looks like a claim or a lease and is not in claimColumns: register it so the lapse rule judges it", m[1]))
		}
	}
	return problems
}

func TestAClaimLapsesForAnEndingOnlyAfterTheRecordBudget(t *testing.T) {
	fset, files := parseRepo(t)
	problems, used := claimLapseGoProblems(fset, files)
	for _, p := range problems {
		t.Error(p)
	}
	for name := range claimStatements {
		if !used[name] {
			t.Errorf("claimStatements[%q] matches no statement that names a claim column; remove it", name)
		}
	}
	for name := range claimReaders {
		if !used[name] {
			t.Errorf("claimReaders[%q] matches no statement that names a claim column; remove it", name)
		}
	}
	mig := readMigrations(t)
	names := make([]string, 0, len(mig))
	for n := range mig {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		for _, p := range claimMigrationProblems(mig[n]) {
			t.Errorf("migrations/postgres/%s: %s", n, p)
		}
	}
}

func TestAClaimLapseLintCanFail(t *testing.T) {
	for _, c := range []struct {
		name, text    string
		claim, reader bool
		want          bool // a problem is expected
	}{
		// The first form of the lint (round 10) and the spellings of its own author.
		{"the mutant: the exhausted pass at the lapse itself", "AND (delivery_claimed_until IS NULL OR delivery_claimed_until < now())", false, false, true},
		{"the stale sweep at the lapse itself", "AND (claimed_until IS NULL OR claimed_until < now())", false, false, true},
		{"the clock spelled another way", "claimed_until <= clock_timestamp()", false, false, true},
		{"with a literal interval, not the budget parameter", "claimed_until < now() - interval '40 seconds'", false, false, true},
		{"one of two comparisons without the grace", "claimed_until < now() - make_interval(secs => $3) OR delivery_claimed_until < now()", false, false, true},
		// The spellings of round 11 (sms-r11-1, sms-r11-3).
		{"the operands reversed", "state = 'pending' AND now() > claimed_until", false, false, true},
		{"the operands reversed, or equal", "now() >= delivery_claimed_until", false, false, true},
		{"statement_timestamp", "claimed_until < statement_timestamp()", false, false, true},
		{"transaction_timestamp", "claimed_until < transaction_timestamp()", false, false, true},
		{"LEAST of the clock", "claimed_until < LEAST(now(), $2)", false, false, true},
		{"the column plus a zero interval", "claimed_until + interval '0' < now()", false, false, true},
		{"the age of the claim", "now() - claimed_until > interval '1 second'", false, false, true},
		{"a bare parameter the caller fills", "claimed_until < $4", false, false, true},
		{"a qualified column against current_timestamp", "c.claimed_until < current_timestamp", false, false, true},
		{"a schema qualified clock", "claimed_until < pg_catalog.now()", false, false, true},
		{"the column inside a function", "COALESCE(claimed_until, now()) < now()", false, false, true},
		{"a read outside a reader", "SELECT claimed_until FROM ctrlz.sms_outbox", false, false, true},
		{"an assignment spelled in a WHERE", "WHERE x = 1 AND claimed_until = $2", false, false, true},
		{"a new column named like a claim", "WHERE retry_claimed_until < now()", false, false, true},
		{"a live claim test is the other direction", "claimed_until > now()", false, false, true},
		{"a reader that compares it", "SELECT 1 FROM t WHERE claimed_until < now()", false, true, true},
		// What is right.
		{"the grace", "(claimed_until IS NULL OR claimed_until < now() - make_interval(secs => $3))", false, false, false},
		{"the grace, qualified and spaced", "c.delivery_claimed_until  <  now()-make_interval( secs=>$2 )", false, false, false},
		{"a claim at the lapse", "AND (c.claimed_until IS NULL OR c.claimed_until < now())", true, false, false},
		{"an assignment after SET", "SET claimed_until = now() + make_interval(secs => $2)", false, false, false},
		{"an assignment after a comma", "SET state = $2, last_error = $3, claimed_until = NULL, sent_at = now()", false, false, false},
		{"a reader selects it", "SELECT claimed_until FROM ctrlz.sms_outbox", false, true, false},
		{"a reader selects it with an alias", "SELECT delivery_claimed_until AS until FROM t UNION ALL SELECT claimed_until FROM u", false, true, false},
		{"IS NOT NULL", "WHERE claimed_until IS NOT NULL", false, false, false},
		{"a comment is not a use", "-- claimed_until < now() is the claim\nSELECT 1", false, false, false},
	} {
		if got := len(claimLapseJudge(c.text, c.claim, c.reader).problems) > 0; got != c.want {
			t.Errorf("%s: problem %v, want %v", c.name, got, c.want)
		}
	}

	// The migration side: a function body or a view that names the column is refused, a
	// declaration and a grant are not, and a new claim-like column is found.
	for _, c := range []struct {
		name, sql string
		want      bool
	}{
		{"a definer function that ends a row", "CREATE FUNCTION f() RETURNS void LANGUAGE sql AS $$ UPDATE ctrlz.sms_outbox SET state = 'failed' WHERE now() > claimed_until; $$;", true},
		{"a view", "CREATE VIEW v AS SELECT 1 FROM ctrlz.sms_outbox WHERE claimed_until < now();", true},
		{"a DO block", "DO $$ BEGIN DELETE FROM ctrlz.otp_challenges WHERE delivery_claimed_until < now(); END $$;", true},
		{"a plain UPDATE", "UPDATE ctrlz.sms_outbox SET state = 'failed' WHERE claimed_until < now();", true},
		{"a new claim column", "ALTER TABLE ctrlz.x ADD COLUMN retry_lease_until timestamptz;", true},
		{"a semicolon inside a body does not end the statement", "CREATE FUNCTION f() RETURNS void LANGUAGE plpgsql AS $$ BEGIN PERFORM 1; PERFORM 2 WHERE claimed_until < now(); END $$;", true},
		{"the declaration", "ALTER TABLE ctrlz.otp_challenges ADD COLUMN delivery_claimed_until timestamptz;", false},
		{"the grant", "GRANT SELECT (claimed_until), UPDATE (claimed_until) ON ctrlz.sms_outbox TO ctrlz_worker;", false},
	} {
		if got := len(claimMigrationProblems(c.sql)) > 0; got != c.want {
			t.Errorf("migration, %s: problem %v, want %v", c.name, got, c.want)
		}
	}

	// The Go side: a constant nobody registered is found, a registered claim that stopped naming
	// the claim is reported as unused, and the grace is checked where the statement is run.
	run := func(src string) ([]string, map[string]bool) {
		t.Helper()
		fset := token.NewFileSet()
		af, err := parser.ParseFile(fset, "internal/store/worker_x.go", src, 0)
		if err != nil {
			t.Fatal(err)
		}
		return claimLapseGoProblems(fset, []file{{path: "internal/store/worker_x.go", ast: af}})
	}
	problems, used := run("package store\nconst qNewEnding = `UPDATE ctrlz.sms_outbox SET state = 'failed' WHERE claimed_until < now()`\nconst qOTPClaim = `SELECT 1`\n")
	if len(problems) != 1 || !strings.Contains(problems[0], "qNewEnding") {
		t.Errorf("a new ending with a bare lapse: %v", problems)
	}
	if used["qOTPClaim"] {
		t.Error("a claim constant that compares nothing counted as used")
	}
	const prelude = "package store\nimport \"time\"\nconst RecordBudget = 40 * time.Second\nconst qEnd = `UPDATE t SET x = 1 WHERE claimed_until < now() - make_interval(secs => $2)`\ntype tx struct{}\nfunc (tx) Exec(a, b any, c ...any) {}\nvar g tx\n"
	for _, c := range []struct {
		name, call string
		want       bool
	}{
		{"the record budget", "func f() { g.Exec(nil, qEnd, 1, RecordBudget.Seconds()) }", false},
		{"a literal grace", "func f() { g.Exec(nil, qEnd, 1, 0.0) }", true},
		{"another duration", "func f() { g.Exec(nil, qEnd, 1, (20 * time.Second).Seconds()) }", true},
		{"the grace in the wrong place", "func f() { g.Exec(nil, qEnd, RecordBudget.Seconds(), 1) }", true},
		{"no grace at all", "func f() { g.Exec(nil, qEnd, 1) }", true},
		{"a spread argument list", "func f(a []any) { g.Exec(nil, qEnd, a...) }", true},
		{"never run", "func f() {}", true},
	} {
		problems, _ := run(prelude + c.call)
		if got := len(problems) > 0; got != c.want {
			t.Errorf("call site, %s: problem %v (%v), want %v", c.name, got, problems, c.want)
		}
	}
	// A claim string outside a constant is refused outright.
	problems, _ = run("package store\nfunc f() string { return \"SELECT claimed_until FROM t\" }\n")
	if len(problems) != 1 {
		t.Errorf("a string outside a constant that names a claim column: %v", problems)
	}
}
