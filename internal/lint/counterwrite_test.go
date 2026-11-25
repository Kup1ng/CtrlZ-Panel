package lint_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The refund half of the known-or-unknown rule (rules.md topic 4, spec 5.3): an OTP row that
// ends without a message reaching the user gives back the world-wide counter and no other key,
// because auth_otp_issue bumps the per-phone and per-network keys for a decoy too and a decoy is
// never ended, so any other refund tells a phone with an account from one without by the 429
// of the next request.
//
// What decides it. The DATABASE does (migration 0034: a trigger on sms_counters judges every row
// the worker role writes, whatever the text of the statement says; the catalog test
// TestTheWorkerRoleCannotWriteAPerPhoneCounterRow runs the spellings that get past a lint of
// text). This lint is the early warning that points at the line, and it reads what a statement
// IS, not how it is spelled (sms-r7-6, sms-r7-7): every string expression is folded through the
// constants of its package (so `"UPDATE ctrlz.sms_" + "counters"` and a refund widened by a
// constant of another file read as the statement they build), every migration is split into its
// real statements by dollar quoting (so what follows the issue function in the same file is not
// taken for part of it), and the shapes that hide a table name from a reader of text (a
// unicode-escaped identifier, EXECUTE, DO, CREATE PROCEDURE) are refused outright.

// counterWrite finds a statement that writes sms_counters in a text that has been through
// normSQL: the verb, an optional ONLY, an optional schema, the table. The whole word is
// matched, so sms_counters_x is not.
var counterWrite = regexp.MustCompile(`\b(update|insert into|delete from|merge into|truncate table|truncate)\s+(?:only\s+)?(?:ctrlz\.)?sms_counters\b`)

var (
	blockComment = regexp.MustCompile(`(?s)/\*.*?\*/`)
	lineComment  = regexp.MustCompile(`--[^\n]*`)
	// A unicode-escaped identifier names a table by code points, so no search for the plain
	// word finds it. Nothing in the module has a use for one.
	unicodeIdent = regexp.MustCompile(`\bu&\s*["']`)
	// The word after EXECUTE; see runsDynamicSQL. EXECUTE FUNCTION
	// and EXECUTE PROCEDURE (a trigger) and GRANT EXECUTE ON are not dynamic SQL.
	executeWord = regexp.MustCompile(`\bexecute\s+([a-z_]\w*|'|\()`)
)

// normSQL lower-cases a SQL text, drops identifier quotes and comments and collapses white
// space, so `UPDATE  "ctrlz"."sms_counters"` and a statement split over lines read as the
// one thing.
func normSQL(s string) string {
	s = blockComment.ReplaceAllString(s, " ")
	s = lineComment.ReplaceAllString(s, " ")
	s = strings.ReplaceAll(strings.ToLower(s), `"`, "")
	return strings.Join(strings.Fields(s), " ")
}

// counterWriters are the only statements of the module that may write sms_counters, each by
// the file and constant that hold it and the one verb it may use. The issue function is the
// one writer in SQL (counterWriterFunctions). What an unsent OTP gives back is
// qCountersRefund, whose scope and key are literals: the world-wide row and nothing else.
// reviewedRefund is the one refund the lint accepts, compared as normalised text (the statement's whole
// text, so a widened condition, a second parameter or another key pattern is a different statement and
// fails). Since 0055 (db-r18-2) the global count is sixteen shard rows, and the refund takes one back from the
// first shard that has something to give and that nobody is writing: the ordered locking subselect that
// skips locked rows, which never waits.
const reviewedRefund = `UPDATE ctrlz.sms_counters SET count = count - 1
WHERE ctid = ANY (ARRAY(SELECT k.ctid FROM ctrlz.sms_counters k
  WHERE k.day = ($1::timestamptz AT TIME ZONE 'Asia/Tehran')::date AND k.scope = 'global'
    AND (k.key = 'all' OR k.key LIKE 'all:%') AND k.count > 0
  ORDER BY k.key LIMIT 1 FOR UPDATE SKIP LOCKED))`

var counterWriters = map[string]string{
	"internal/store/worker_sms.go:qCountersRefund":  "update",      // an unsent code gives the global slot back
	"internal/store/worker_sms.go:qCountersAddCost": "insert into", // the price of an accepted message, on the global row
	"internal/store/worker_sms.go:qOutboxFirstGate": "insert into", // the daily outbox count, on the global outbox row
	// The retention sweep of the raw rows is a function now (counterWriterFunctions), and the Go
	// constant that calls it holds no verb: the worker cannot see those rows (sms-r8-3, sms-r8-7).
}

// counterWriterFunctions are the SQL functions that may write sms_counters.
var counterWriterFunctions = map[string][]string{
	"auth_otp_issue":            {"insert into", "update"}, // bumps the per-phone, per-network, per-address and global keys of a request
	"worker_sweep_sms_counters": {"delete from"},           // the retention sweep of the raw per-subject rows (sms-r8-3); the worker holds no DELETE
}

// counterCleanupMigrations are the migrations whose own top-level statements (never a function
// body) may delete or update sms_counters rows once, with the verbs each may use. A migration
// that adds a constraint has to clean the rows that already break it first, and the guard trigger
// is switched off for that statement alone (0040, db-r10-1). A new file is not added without a
// reviewer deciding it: it is the one door through which a migration writes the counters.
var counterCleanupMigrations = map[string][]string{
	"0040_review_round10_db.sql": {"delete from", "update"}, // rows planted for a future day and negative values, before the CHECKs
	"0044_review_round12_db.sql": {"update"},                // a NaN spend becomes zero, before the NaN CHECK (db-r12-1)
}

// dynamicSQLMigrations are the migrations that already used EXECUTE or DO when the rule was
// written, each with what it does. A new file is not added without a reviewer deciding it: a
// migration that needs dynamic SQL is a migration that can name any table. Their dynamic statements
// may not mention the counters at all.
var dynamicSQLMigrations = map[string]string{
	"0007_grants.sql":       "the grant helper of the roles: EXECUTE format('GRANT ...') for a table and a role it is given",
	"0017_worker_reach.sql": "a DO block that raises when the key tool role is missing",
}

// counterTestSupport are packages of test helpers that hold no production statement; they are
// imported from test files only.
func counterTestSupport(p string) bool {
	return strings.HasPrefix(p, "internal/authtest/") || strings.HasPrefix(p, "internal/store/catalogtest/") ||
		strings.HasPrefix(p, "internal/testpg/")
}

// packageConsts collects the package-level constants and variables of the given files by name,
// so a string expression can be folded through them. A name declared twice (two packages in one
// call) keeps the first; callers pass the files of one package.
func packageConsts(files ...*ast.File) map[string]ast.Expr {
	out := map[string]ast.Expr{}
	for _, f := range files {
		for _, d := range f.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || (gd.Tok != token.CONST && gd.Tok != token.VAR) {
				continue
			}
			for _, sp := range gd.Specs {
				vs := sp.(*ast.ValueSpec)
				for i, n := range vs.Names {
					if i < len(vs.Values) {
						if _, dup := out[n.Name]; !dup {
							out[n.Name] = vs.Values[i]
						}
					}
				}
			}
		}
	}
	return out
}

// foldString evaluates a string expression the way the compiler folds a constant: literals,
// parentheses, +, and names of constants of the package. Anything it cannot know (a call, a
// parameter) becomes a "\x00", which no SQL word contains, so the parts that are known are
// still read and a name can never be completed by something unknown.
func foldString(e ast.Expr, consts map[string]ast.Expr, depth int) string {
	if depth > 32 {
		return "\x00"
	}
	switch e := e.(type) {
	case *ast.BasicLit:
		if e.Kind == token.STRING {
			if s, err := strconv.Unquote(e.Value); err == nil {
				return s
			}
		}
	case *ast.ParenExpr:
		return foldString(e.X, consts, depth+1)
	case *ast.BinaryExpr:
		if e.Op == token.ADD {
			return foldString(e.X, consts, depth+1) + foldString(e.Y, consts, depth+1)
		}
	case *ast.Ident:
		if v, ok := consts[e.Name]; ok {
			return foldString(v, consts, depth+1)
		}
	}
	return "\x00"
}

// stringExprs lists the maximal string expressions of a file: every literal and every chain of
// + that is not itself part of a longer chain, each with the name of the top-level declaration
// that holds it ("" for an inline statement in a call).
type stringExpr struct {
	expr  ast.Expr
	owner string
}

func stringExprs(f *ast.File) []stringExpr {
	inner := map[ast.Expr]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		if b, ok := n.(*ast.BinaryExpr); ok && b.Op == token.ADD {
			for _, side := range []ast.Expr{b.X, b.Y} {
				inner[side] = true
				if p, ok := side.(*ast.ParenExpr); ok {
					inner[p.X] = true
				}
			}
		}
		return true
	})
	owner := map[ast.Node]string{}
	ast.Inspect(f, func(n ast.Node) bool {
		vs, ok := n.(*ast.ValueSpec)
		if !ok {
			return true
		}
		for i, v := range vs.Values {
			if i >= len(vs.Names) {
				break
			}
			ast.Inspect(v, func(m ast.Node) bool {
				if m != nil {
					owner[m] = vs.Names[i].Name
				}
				return true
			})
		}
		return true
	})
	var out []stringExpr
	ast.Inspect(f, func(n ast.Node) bool {
		switch e := n.(type) {
		case *ast.BasicLit:
			if e.Kind == token.STRING && !inner[e] {
				out = append(out, stringExpr{e, owner[e]})
			}
		case *ast.BinaryExpr:
			if e.Op == token.ADD && !inner[e] {
				out = append(out, stringExpr{e, owner[e]})
			}
		}
		return true
	})
	return out
}

// counterWriteViolations lists, for one non-test Go file, every string expression that writes
// sms_counters outside counterWriters, or that spells a table name in a way no text search
// reads. consts are the constants of the file's package.
func counterWriteViolations(p string, f *ast.File, consts map[string]ast.Expr) []string {
	if counterTestSupport(p) {
		return nil
	}
	var out []string
	for _, se := range stringExprs(f) {
		text := foldString(se.expr, consts, 0)
		if unicodeIdent.MatchString(strings.ToLower(text)) {
			out = append(out, fmt.Sprintf("%s: %q holds a unicode-escaped identifier; nothing in the module needs one and a search for a table name cannot read it", p, se.owner))
			continue
		}
		norm := normSQL(text)
		m := counterWrite.FindStringSubmatch(norm)
		if m == nil {
			continue
		}
		verb, name := m[1], se.owner
		want, listed := counterWriters[p+":"+name]
		switch {
		case !listed:
			out = append(out, fmt.Sprintf("%s: a %q statement on sms_counters in %q; the only writers are %s", p, verb, name, counterWriterNames()))
		case verb != want:
			out = append(out, fmt.Sprintf("%s: %s uses %q, want %q", p, name, verb, want))
		case name == "qCountersRefund" && norm != normSQL(reviewedRefund):
			out = append(out, p+": qCountersRefund is not the reviewed statement: it must refund one row of the world-wide counter (scope = 'global', the shard keys 'all' and 'all:%' as literals) and take nothing but the day; change reviewedRefund with it")
		case name == "qOutboxFirstGate" && !strings.Contains(norm, "'global', 'outbox'"):
			out = append(out, p+": qOutboxFirstGate must write the global outbox row and nothing else")
		}
	}
	return out
}

func counterWriterNames() string {
	var names []string
	for k := range counterWriters {
		names = append(names, k)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// sqlStatements splits a SQL text into its top-level statements the way the server reads it: a
// semicolon ends a statement only outside a comment, a quoted string, a quoted identifier and a
// dollar-quoted body. A function is therefore one statement, from CREATE to the `;` after its
// closing $$, and what follows it is another.
func sqlStatements(text string) []string {
	var out []string
	start, i, n := 0, 0, len(text)
	flush := func(end int) {
		if s := strings.TrimSpace(text[start:end]); s != "" {
			out = append(out, s)
		}
		start = end
	}
	for i < n {
		c := text[i]
		switch {
		case c == '-' && i+1 < n && text[i+1] == '-':
			for i < n && text[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < n && text[i+1] == '*':
			depth := 0
			for i < n {
				if strings.HasPrefix(text[i:], "/*") {
					depth++
					i += 2
				} else if strings.HasPrefix(text[i:], "*/") {
					depth--
					i += 2
					if depth == 0 {
						break
					}
				} else {
					i++
				}
			}
		case c == '\'' || c == '"':
			i++
			for i < n {
				if text[i] == c {
					if i+1 < n && text[i+1] == c { // a doubled quote is a quote
						i += 2
						continue
					}
					break
				}
				i++
			}
			i++
		case c == '$':
			j := i + 1
			for j < n && (text[j] == '_' || text[j] >= 'a' && text[j] <= 'z' || text[j] >= 'A' && text[j] <= 'Z' || text[j] >= '0' && text[j] <= '9') {
				j++
			}
			if j < n && text[j] == '$' && (j == i+1 || !(text[i+1] >= '0' && text[i+1] <= '9')) {
				tag := text[i : j+1]
				if end := strings.Index(text[j+1:], tag); end >= 0 {
					i = j + 1 + end + len(tag)
				} else {
					i = n
				}
			} else {
				i++
			}
		case c == ';':
			i++
			flush(i)
		default:
			i++
		}
	}
	flush(n)
	return out
}

var (
	counterCreateFn   = regexp.MustCompile(`^create (?:or replace )?function (?:\w+\.)?(\w+)`)
	counterCreateProc = regexp.MustCompile(`^create (?:or replace )?procedure\b`)
)

// counterWriteViolationsInSQL judges the text of a migration statement by statement. A function
// other than the issue function that writes sms_counters, a DO block or a procedure that does,
// and a statement outside any function that does, are violations; so are dynamic SQL (EXECUTE)
// and a unicode-escaped identifier outside the migrations that already had them, because a text
// that builds a table name at run time is one no search of text reads. file is the base name.
func counterWriteViolationsInSQL(file, text string) []string {
	var out []string
	_, dynamicOK := dynamicSQLMigrations[file]
	for _, stmt := range sqlStatements(text) {
		norm := normSQL(stmt)
		kind, fn := "a statement outside any function", ""
		switch m := counterCreateFn.FindStringSubmatch(norm); {
		case m != nil:
			kind, fn = "function "+m[1], m[1]
		case counterCreateProc.MatchString(norm):
			kind = "a procedure"
		case strings.HasPrefix(norm, "do "), strings.HasPrefix(norm, "do$"):
			kind = "a DO block"
		}
		if unicodeIdent.MatchString(strings.ToLower(lineComment.ReplaceAllString(blockComment.ReplaceAllString(stmt, " "), " "))) {
			out = append(out, fmt.Sprintf("%s: %s holds a unicode-escaped identifier; a search for a table name cannot read it", file, kind))
		}
		for _, m := range counterWrite.FindAllStringSubmatch(norm, -1) {
			if fn == "" && kind == "a statement outside any function" && contains(counterCleanupMigrations[file], m[1]) {
				continue
			}
			if !contains(counterWriterFunctions[fn], m[1]) {
				out = append(out, fmt.Sprintf("%s: %s writes sms_counters (%s); only the functions of counterWriterFunctions may, each with its own verbs", file, kind, m[1]))
			}
		}
		bodies := fn != "" || kind == "a procedure" || kind == "a DO block"
		if bodies && !dynamicOK && counterWriterFunctions[fn] == nil && runsDynamicSQL(norm) {
			out = append(out, fmt.Sprintf("%s: %s runs dynamic SQL (EXECUTE); a table name built at run time is not read by this rule, so it is not allowed (add the migration to dynamicSQLMigrations only with a reviewer's decision)", file, kind))
		}
		if bodies && dynamicOK && (kind == "a DO block" || runsDynamicSQL(norm)) && strings.Contains(norm, "counters") {
			out = append(out, fmt.Sprintf("%s: a migration that may run dynamic SQL names the counters", file))
		}
	}
	return out
}

// TestRefundIsTheGlobalKeyOnly is the lint half of the refund rule (see the comment above, and
// the trigger of migration 0034 that is the other half). Every statement of the module that
// writes sms_counters is named here with its verb; the refund's scope and key are literals of
// its folded text; and no migration function other than the issue function writes the table.
// A new ending, a new store method or a new function that tries to refund another key has no
// statement to do it with and fails here, in any Go it is written in, in any file of the module,
// and the database refuses it when it runs.
func TestRefundIsTheGlobalKeyOnly(t *testing.T) {
	_, files := parseRepo(t)
	byDir := map[string][]*ast.File{}
	for _, f := range files {
		if !f.test {
			byDir[path.Dir(f.path)] = append(byDir[path.Dir(f.path)], f.ast)
		}
	}
	consts := map[string]map[string]ast.Expr{}
	for dir, fs := range byDir {
		consts[dir] = packageConsts(fs...)
	}
	seen := map[string]bool{}
	for _, f := range files {
		if f.test {
			continue
		}
		for _, v := range counterWriteViolations(f.path, f.ast, consts[path.Dir(f.path)]) {
			t.Error(v)
		}
		ast.Inspect(f.ast, func(n ast.Node) bool {
			if vs, ok := n.(*ast.ValueSpec); ok {
				for _, name := range vs.Names {
					if _, ok := counterWriters[f.path+":"+name.Name]; ok {
						seen[f.path+":"+name.Name] = true
					}
				}
			}
			return true
		})
	}
	for k := range counterWriters {
		if !seen[k] {
			t.Errorf("%s is listed as a writer of sms_counters and does not exist: the lint reads the wrong files, or the list is stale", k)
		}
	}

	migrations, err := filepath.Glob(filepath.Join(repoRoot(t), "migrations", "postgres", "src", "*.sql"))
	if err != nil || len(migrations) < 20 {
		t.Fatalf("migrations not found (%d, %v)", len(migrations), err)
	}
	issue := false
	listed := map[string]bool{}
	for _, p := range migrations {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		for _, v := range counterWriteViolationsInSQL(filepath.Base(p), string(b)) {
			t.Error(v)
		}
		if strings.Contains(string(b), "auth_otp_issue") {
			issue = true
		}
		listed[filepath.Base(p)] = true
	}
	for name := range dynamicSQLMigrations {
		if !listed[name] {
			t.Errorf("%s is listed as a migration with dynamic SQL and does not exist", name)
		}
	}
	if !issue {
		t.Error("no migration defines auth_otp_issue: the lint reads the wrong files")
	}
}

func TestRefundLintCanFail(t *testing.T) {
	parse := func(p, src string) *ast.File {
		f, err := parser.ParseFile(token.NewFileSet(), p, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		return f
	}
	goCases := map[string]struct {
		path, src string
		want      int
	}{
		"a per-phone refund in a new store method": {"internal/store/admin_sms.go", "package store\nconst qX = `UPDATE ctrlz.sms_counters SET count = count - 1 WHERE scope = 'phone' AND key = $1`", 1},
		"an inline statement in a call":            {"internal/worker/smssend/x.go", "package x\nfunc f() { db.Exec(`UPDATE ctrlz.sms_counters SET count = count - 1`) }", 1},
		"a quoted, spaced and ONLY form":           {"internal/store/x.go", "package store\nconst qX = `update  ONLY \"ctrlz\".\"sms_counters\" set count = 0`", 1},
		"a second constant in the allowed file":    {"internal/store/worker_sms.go", "package store\nconst qOther = `UPDATE ctrlz.sms_counters SET count = 0 WHERE scope = 'ip'`", 1},
		"an insert on a decoy's keys":              {"internal/api/x.go", "package api\nvar q = `INSERT INTO ctrlz.sms_counters (day, scope, key, count) VALUES ($1, 'phone', $2, 1)`", 1},
		"a delete outside the sweep":               {"internal/store/y.go", "package store\nconst qD = `DELETE FROM ctrlz.sms_counters`", 1},
		"the refund names its row by parameter":    {"internal/store/worker_sms.go", "package store\nconst qCountersRefund = `UPDATE ctrlz.sms_counters SET count = GREATEST(count - 1, 0) WHERE day = $1 AND scope = $2 AND key = $3`", 1},
		"the refund widened with an OR":            {"internal/store/worker_sms.go", "package store\nconst qCountersRefund = `UPDATE ctrlz.sms_counters SET count = count - 1 WHERE scope = 'global' AND key = 'all' OR scope = 'phone'`", 1},
		"the refund as it is":                      {"internal/store/worker_sms.go", "package store\nconst qCountersRefund = `" + reviewedRefund + "`", 0},
		"the refund with another verb":             {"internal/store/worker_sms.go", "package store\nconst qCountersRefund = `DELETE FROM ctrlz.sms_counters WHERE scope = 'global' AND key = 'all'`", 1},
		"a read is not a write":                    {"internal/store/admin_sms.go", "package store\nconst qR = `SELECT count FROM ctrlz.sms_counters WHERE scope = 'phone'`", 0},
		"a name that only contains the table":      {"internal/store/z.go", "package store\nconst qR = `UPDATE ctrlz.sms_counters_archive SET count = 0`", 0},
		"test support may seed rows":               {"internal/authtest/sms.go", "package authtest\nconst q = `DELETE FROM ctrlz.sms_counters`", 0},

		// sms-r7-7: the statement is what the constants fold to, not what one literal says.
		"the table name split over two literals": {"internal/store/worker_sms.go", "package store\nconst qRefundPhone = `UPDATE ctrlz.sms_` + `counters SET count = GREATEST(count - 1, 0) WHERE day = $1::date AND scope = 'phone' AND key = $2`", 1},
		"the refund widened by a constant": {"internal/store/worker_sms.go", "package store\nconst qWiden = ` OR (scope = 'phone' AND key = $2)`\n" +
			"const qCountersRefund = `" + reviewedRefund + "` + qWiden", 1},
		"the verb in one constant, the table in another":   {"internal/store/worker_sms.go", "package store\nconst qVerb = `UPDATE `\nconst qTable = `ctrlz.sms_counters SET count = 0`\nconst qSneaky = qVerb + qTable", 1},
		"a parenthesised concatenation":                    {"internal/store/worker_sms.go", "package store\nconst qSneaky = (`UPDATE ctrlz.sms_` + (`counters SET count = 0`))", 1},
		"a unicode-escaped table name":                     {"internal/store/worker_sms.go", "package store\nconst qSneaky = `UPDATE ctrlz.U&\"sms\\005fcounters\" SET count = 0`", 1},
		"a unicode-escaped name split over literals":       {"internal/store/worker_sms.go", "package store\nconst qSneaky = `UPDATE ctrlz.U&` + `\"sms\\005fcounters\" SET count = 0`", 1},
		"a statement built from a name that is unknown":    {"internal/store/worker_sms.go", "package store\nfunc f(n string) string { return `UPDATE ctrlz.sms_` + n }", 0},
		"a constant named like the refund in another file": {"internal/api/x.go", "package api\nconst qCountersRefund = `UPDATE ctrlz.sms_counters SET count = count - 1 WHERE scope = 'global' AND key = 'all'`", 1},
		"a statement in a module outside internal":         {"cmd/ctrlz-tool/main.go", "package main\nconst q = `UPDATE ctrlz.sms_counters SET count = count - 1 WHERE scope = 'phone'`", 1},
	}
	for name, c := range goCases {
		f := parse(c.path, c.src)
		if got := len(counterWriteViolations(c.path, f, packageConsts(f))); got != c.want {
			t.Errorf("%s: %d violations, want %d", name, got, c.want)
		}
	}
	// A constant of another file of the package widens the refund: the fold goes through the
	// package, not the file.
	{
		a := parse("internal/store/widen.go", "package store\nconst qTail = ` OR scope = 'phone'`")
		b := parse("internal/store/worker_sms.go", "package store\nconst qCountersRefund = `"+reviewedRefund+"` + qTail")
		if got := len(counterWriteViolations("internal/store/worker_sms.go", b, packageConsts(a, b))); got != 1 {
			t.Errorf("a refund widened by a constant of another file: %d violations, want 1", got)
		}
		if got := len(counterWriteViolations("internal/store/worker_sms.go", b, packageConsts(b))); got != 1 {
			t.Errorf("the same file without the other one: %d violations, want 1 (the refund is pinned as a whole, so a part the lint cannot read is not the reviewed statement)", got)
		}
	}
	sqlCases := map[string]struct {
		src  string
		want int
	}{
		"another function refunds the phone": {"CREATE FUNCTION ctrlz_fn.worker_refund(p text) RETURNS void AS $$ UPDATE ctrlz.sms_counters SET count = count - 1 WHERE key = p $$", 1},
		"the issue function":                 {"CREATE OR REPLACE FUNCTION ctrlz_fn.auth_otp_issue(p text) RETURNS void AS $$ INSERT INTO ctrlz.sms_counters AS c (day) VALUES (1) $$", 0},
		"a later function after the issue":   {"CREATE FUNCTION ctrlz_fn.auth_otp_issue() AS $$ SELECT 1 $$;\nCREATE FUNCTION ctrlz_fn.sneaky() AS $$ DELETE FROM ctrlz.sms_counters $$", 1},
		"a statement outside any function":   {"-- fix\nUPDATE ctrlz.sms_counters SET count = 0;", 1},
		"a comment that says it":             {"-- UPDATE ctrlz.sms_counters is the refund\nCREATE FUNCTION ctrlz_fn.other() AS $$ SELECT 1 $$", 0},
		"a read":                             {"CREATE FUNCTION ctrlz_fn.r() AS $$ SELECT count FROM ctrlz.sms_counters $$", 0},

		// sms-r8-3: the sweep is the one other writer, and it may only delete; the issue function may not.
		"the sweep function deletes":            {"CREATE FUNCTION ctrlz_fn.worker_sweep_sms_counters(p integer) AS $$ DELETE FROM ctrlz.sms_counters d WHERE true $$", 0},
		"the sweep function updates":            {"CREATE OR REPLACE FUNCTION ctrlz_fn.worker_sweep_sms_counters(p integer) AS $$ UPDATE ctrlz.sms_counters SET count = count - 1 $$", 1},
		"the sweep function refunds and sweeps": {"CREATE FUNCTION ctrlz_fn.worker_sweep_sms_counters(p integer) AS $$ DELETE FROM ctrlz.sms_counters d WHERE true; UPDATE ctrlz.sms_counters SET count = 0 $$", 1},
		"the issue function deletes":            {"CREATE FUNCTION ctrlz_fn.auth_otp_issue() AS $$ DELETE FROM ctrlz.sms_counters WHERE scope = 'phone' $$", 1},

		// sms-r7-6: the end of a function is its closing quote, not the next CREATE.
		"a statement after the issue function in the same file": {"CREATE FUNCTION ctrlz_fn.auth_otp_issue() AS $$ SELECT 1 $$;\nUPDATE ctrlz.sms_counters SET count = count - 1 WHERE scope = 'phone';", 1},
		"a statement after a tagged body":                       {"CREATE FUNCTION ctrlz_fn.f() AS $body$ SELECT ';' $body$;\nUPDATE ctrlz.sms_counters SET count = 0;", 1},
		"semicolons inside the issue function stay inside it":   {"CREATE FUNCTION ctrlz_fn.auth_otp_issue() AS $$ BEGIN INSERT INTO ctrlz.sms_counters AS c (day) VALUES (1); UPDATE ctrlz.sms_counters SET count = 1; END $$;", 0},
		"a DO block":                                    {"DO $$ BEGIN UPDATE ctrlz.sms_counters SET count = 0 WHERE scope = 'phone'; END $$;", 1},
		"a procedure":                                   {"CREATE PROCEDURE ctrlz_fn.p() LANGUAGE sql AS $$ UPDATE ctrlz.sms_counters SET count = 0 $$;", 1},
		"a procedure after the issue function":          {"CREATE FUNCTION ctrlz_fn.auth_otp_issue() AS $$ SELECT 1 $$;\nCREATE OR REPLACE PROCEDURE ctrlz_fn.p() LANGUAGE sql AS $$ DELETE FROM ctrlz.sms_counters $$;", 1},
		"EXECUTE builds the name":                       {"CREATE FUNCTION ctrlz_fn.q() RETURNS void LANGUAGE plpgsql AS $$ BEGIN EXECUTE 'UPDATE ctrlz.sms_' || 'counters SET count = 0'; END $$;", 1},
		"EXECUTE format with an identifier":             {"CREATE FUNCTION ctrlz_fn.q() RETURNS void LANGUAGE plpgsql AS $$ BEGIN EXECUTE format('UPDATE ctrlz.%I SET count = 0', 'sms_counters'); END $$;", 1},
		"EXECUTE of a variable":                         {"DO $$ DECLARE s text := 'x'; BEGIN EXECUTE s; END $$;", 1},
		"a unicode-escaped table name":                  {"UPDATE ctrlz.U&\"sms\\005fcounters\" SET count = 0;", 1},
		"GRANT EXECUTE is not dynamic SQL":              {"GRANT EXECUTE ON FUNCTION ctrlz_fn.f() TO ctrlz_admin;", 0},
		"a trigger EXECUTE FUNCTION is not dynamic SQL": {"CREATE TRIGGER t BEFORE UPDATE ON ctrlz.sms_counters FOR EACH ROW EXECUTE FUNCTION ctrlz.g();", 0},
		"a function that only reads, with plain SQL":    {"CREATE FUNCTION ctrlz_fn.r() RETURNS int LANGUAGE plpgsql AS $$ BEGIN RETURN (SELECT count(*) FROM ctrlz.sms_counters); END $$;", 0},
	}
	for name, c := range sqlCases {
		if got := len(counterWriteViolationsInSQL("x.sql", c.src)); got != c.want {
			t.Errorf("%s: %d violations, want %d", name, got, c.want)
		}
	}
	// The cleanup door of a constraint migration is one file, top-level statements only, and only
	// the verbs it lists.
	for name, c := range map[string]struct {
		file, src string
		want      int
	}{
		"a cleanup in the listed migration":     {"0040_review_round10_db.sql", "DELETE FROM ctrlz.sms_counters WHERE day > 1; UPDATE ctrlz.sms_counters SET count = 0 WHERE count < 0;", 0},
		"the same cleanup in another migration": {"0041_other.sql", "DELETE FROM ctrlz.sms_counters WHERE day > 1;", 1},
		"an insert in the listed migration":     {"0040_review_round10_db.sql", "INSERT INTO ctrlz.sms_counters (day) VALUES (1);", 1},
		"a function of the listed migration":    {"0040_review_round10_db.sql", "CREATE FUNCTION ctrlz_fn.f() AS $$ UPDATE ctrlz.sms_counters SET count = 0 $$;", 1},
		"a DO block of the listed migration":    {"0040_review_round10_db.sql", "DO $$ BEGIN DELETE FROM ctrlz.sms_counters; END $$;", 1},
	} {
		if got := len(counterWriteViolationsInSQL(c.file, c.src)); got != c.want {
			t.Errorf("%s: %d violations, want %d", name, got, c.want)
		}
	}
	// A migration that is allowed dynamic SQL may not mention the counters.
	if got := len(counterWriteViolationsInSQL("0007_grants.sql", "CREATE FUNCTION f() AS $$ BEGIN EXECUTE format('GRANT SELECT ON ctrlz.%I TO x', 'sms_counters'); END $$;")); got != 1 {
		t.Errorf("an allowed dynamic migration that names the counters: %d violations, want 1", got)
	}
	if got := len(counterWriteViolationsInSQL("0007_grants.sql", "CREATE FUNCTION f() AS $$ BEGIN EXECUTE format('GRANT SELECT ON ctrlz.%I TO x', 'tenants'); END $$;")); got != 0 {
		t.Errorf("an allowed dynamic migration: %d violations, want 0", got)
	}
}

// runsDynamicSQL says a normalised body runs a text as a statement: EXECUTE followed by anything
// but FUNCTION or PROCEDURE (a trigger) or ON (GRANT EXECUTE ON).
func runsDynamicSQL(norm string) bool {
	for _, m := range executeWord.FindAllStringSubmatch(norm, -1) {
		switch m[1] {
		case "function", "procedure", "on":
		default:
			return true
		}
	}
	return false
}
