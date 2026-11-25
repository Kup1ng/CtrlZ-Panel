package lint_test

import (
	"crypto/sha256"
	"encoding/hex"
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

	"github.com/Kup1ng/CtrlZ-Panel/internal/lockrank"
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
//     reason it is neither. The scope is EVERY DELETE and EVERY UPDATE of every SQL
//     constant of the module and of every live definer function, whatever its file and its
//     name (sms-r16-15: until round 16 it was the files worker_*.go and the functions whose
//     name said sweep, purge, expire, cleanup, retention or prune, so a retention statement
//     written under another name was never read). A new statement that is none of the
//     three fails, and so does a registry entry that no longer matches one.
//  2. Every call of a store batch method (a GlobalTx or Tx method named ...Batch) from
//     outside the store sits inside a transaction callback (WithGlobal or WithTenant), and
//     that sits inside a sweepbatch.Drain callback. Drain is the one loop: it bounds the
//     batches of a run, and each batch is its own transaction because the callback opens
//     it.
//  3. The fast and the slow sweep run on separate goroutines: Sweeper.Run has two go
//     statements, each reaching exactly one of Fast and Slow, and nothing else calls them
//     outside tests.

// The reasons of the statements that are neither keyed nor a bounded batch (sms-r16-15). The rule reads
// EVERY DELETE and UPDATE of every SQL constant and every live function, whatever its file or its name,
// so a retention statement written under a name with none of the old keywords fails like any other; each
// entry below is addressed to a set its own parameters name, which no timer drives.
const (
	sweepSubject      = "addressed to the rows of one subject (a user, a session, a token family, a ticket, a phone change, an IP claim, a throttle scope) named by the statement's own parameters, and bounded by what that subject holds; nothing drives it by a timer, so there is no backlog to batch"
	sweepEndpointRows = "addressed to the rows of one Endpoint, or of the ids one request names, picked once by the ordered locking subselect and bounded by what the request may hold (500 ids, 64 windows, the clients of one Endpoint, 10 share links); a request of a tenant drives it, nothing drives it by a timer, so there is no backlog to batch"
	sweepSingle       = "writes the one row of a singleton settings table, or the few rows of a table that holds one per provider or template; there is nothing to batch"
)

// sweepNotASweep names the statements that are in scope and are neither bounded nor keyed,
// with the reason each is not a retention sweep. The key is the Go constant or the SQL
// function.
var sweepNotASweep = map[string]string{
	"qOutboxFirstGate": "the day's outbox counter: an upsert from a one-row CTE whose conflict update touches the one counter row (day, 'global', 'outbox'), compared and written in the one statement (9.5, 9.6)",
	"qCountersRefund":  "gives one message's count back to one shard of the day's global counter, picked by an ordered locking subselect that skips locked rows (LIMIT 1, never waits)",
	"qRecoveryDelete":  "replaces the recovery codes of one user on regeneration: at most the ten of a set, not a retention sweep",
	"worker_passkeys_mark_stale": "the RP ID change job: one tenant's credentials of another RP ID, in the one transaction that makes the change and its notices atomic (7.4); " +
		"run by an admin action, not by a timer",
	"worker_enforce_clear_without_live": "the second half of the RP ID change job, atomic with the first so nobody is locked out (7.4); run by an admin action, not by a timer",
	"qAdminSessionsRevokeOthers":        sweepSubject,
	"qAdminJobsSupersede":               sweepSubject,
	"qRecoveryUse":                      sweepSubject,
	"qSessionRotateRefresh":             sweepSubject,
	"qSessionRevokeRefresh":             sweepSubject,
	"qSessionsRevokeOthers":             sweepSubject,
	"qSessionsTrim":                     sweepSubject,
	"qSessionsTrimRefresh":              sweepSubject,
	"qRefreshRevokeOthers":              sweepSubject,
	"qAPITokensRevoke":                  sweepSubject,
	"qRefreshRevokeFamily":              sweepSubject,
	"qRefreshRevokeFamilySession":       sweepSubject,
	"ip_claim_take":                     sweepSubject,
	"promote_profile2":                  sweepSubject,
	"auth_tickets_revoke":               sweepSubject,
	"admin_revoke_user_sessions":        sweepSubject,
	"auth_ticket_peek":                  sweepSubject,
	"auth_ticket_take":                  sweepSubject,
	"admin_throttle_refund":             sweepSubject,
	"admin_throttle_reset":              sweepSubject,
	"auth_throttle_refund":              sweepSubject,
	"auth_throttle_reset":               sweepSubject,
	"keytool_totp_declare_lost":         sweepSubject,
	"qRegistrationSet":                  sweepSingle,
	"qRegistrationGraceSet":             sweepSingle,
	"qWebauthnConfigSet":                sweepSingle,
	"qSMSRoutingAssign":                 sweepSingle,
	"qSMSRoutingClear":                  sweepSingle,
	"qSMSTemplateSet":                   sweepSingle,
	"qSMSLimitsSet":                     sweepSingle,
	"qServiceDelete":                    "keyed by its whole primary key (tenant, profile, service_slug): one row, named by the statement's own parameters",
	"qClientsDelete":                    sweepEndpointRows,
	"qShareLinkDownloadsDelete":         sweepEndpointRows,
	"qWindowsDelete":                    sweepEndpointRows,
	"qEndpointsSetGroup":                sweepEndpointRows,
	"qEndpointsDelete":                  sweepEndpointRows,
	"qAuthorizedDelete":                 sweepEndpointRows,
	"qShareLinksRevoke":                 sweepEndpointRows,
	"qDownloadLinksDelete":              sweepEndpointRows,
	"qFixtureDemote":                    "keyed by its whole primary key (version): one row, named by the statement's own parameter; the table has no id column",
	"qCompilerSnapshotDelete":           "keyed by its whole primary key (seq): one row, named by the statement's own parameter; the table has no id column",
	"qCompilerArtifactGC":               "keyed by its whole primary key (hash): one row, named by the statement's own parameter; the table has no id column",
	"qCompilerOutboxDelete":             "the rows an entry stands for, named by the ids of the marks the compiler read: its own statement, bounded by the 5,000 marks of a pass, deleted in the same transaction as the entry",
	"qIdempotencyFinish":                "keyed by its whole primary key (tenant, key): the one row the request inserted, named by the statement's own parameters",
}

// sweepPrimaryKeys are the primary keys that are not just id. A bounded batch names the
// whole key.
var sweepPrimaryKeys = map[string]string{
	"sms_counters":     "day,scope,key",
	"auth_throttle":    "scope,key",
	"idempotency_keys": "tenant_id,key",
}

// ---------------------------------------------------------------------------
// SQL reading

type dmlStatement struct {
	kind  string // DELETE or UPDATE
	table string
	text  string // from the keyword to the end of the statement
	// canon is the same text with the target spelled ctrlz.<table> (ONLY, quotes and a missing schema dropped),
	// which is the form lockrank reads (db-r17-14: one grammar of the WHERE clause, not a second one here).
	canon string
}

// dmlWord finds every word that starts a statement that writes rows other than an INSERT. The rule
// asks about every occurrence of one of these words and not about one spelling of a statement
// (sms-r16-23): `UPDATE ONLY ctrlz.t`, `DELETE FROM ONLY ctrlz.t`, a quoted `"ctrlz"."t"`, an
// unqualified table, MERGE and TRUNCATE were never read by the regular expression this replaced, so
// a bulk statement written in any of them passed. Now an occurrence is either READ (dmlShape: the
// optional ONLY, an optional schema, an optional quoted table, which are then judged like any other
// statement), or a context that is not a statement (dmlNotAStatement), or it is reported as a form
// the rule cannot read, which fails with no registry exemption.
var (
	dmlWord  = regexp.MustCompile(`(?i)\b(UPDATE|DELETE|MERGE|TRUNCATE)\b`)
	dmlShape = regexp.MustCompile(`(?is)^(DELETE\s+FROM|UPDATE)\s+(?:ONLY\s+)?(?:"?ctrlz"?\s*\.\s*)?"?(\w+)"?`)
	prevWord = regexp.MustCompile(`(\w+)\s*$`)
)

// dmlNotAStatement are the words that, standing before UPDATE or DELETE, make it part of something
// else: a row lock (FOR UPDATE, FOR NO KEY UPDATE), an upsert (DO UPDATE, whose rows are the INSERT's
// own), a foreign key action or trigger event (ON/AFTER/BEFORE/OR UPDATE).
var dmlNotAStatement = map[string]bool{"FOR": true, "KEY": true, "DO": true, "ON": true, "AFTER": true, "BEFORE": true, "OR": true, "OF": true}

// blankStrings replaces the inside of every string literal with spaces, keeping the length, so a
// keyword in a message is not read and a position in the result is a position in the input.
func blankStrings(s string) string {
	b := []byte(s)
	in := false
	for i := 0; i < len(b); i++ {
		switch {
		case b[i] == '\'':
			in = !in
		case in && b[i] != '\n':
			b[i] = ' '
		}
	}
	return string(b)
}

// stmtEnd is where the statement that starts at from ends: a semicolon at its own depth, or the
// parenthesis that closes the one it is inside.
func stmtEnd(s string, from int) int {
	depth := 0
	inQuote := false
	for i := from; i < len(s); i++ {
		switch c := s[i]; {
		case c == '\'':
			inQuote = !inQuote
		case inQuote:
		case c == '(':
			depth++
		case c == ')':
			depth--
			if depth < 0 {
				return i
			}
		case c == ';' && depth == 0:
			return i
		}
	}
	return len(s)
}

var insertInto = regexp.MustCompile(`(?is)^INSERT\s+INTO\s+(?:"?ctrlz"?\s*\.\s*)?"?(\w+)"?`)

// dmlStatements finds the statements of a SQL text that write rows other than an INSERT, a CTE or a
// function body included, and the occurrences it cannot read. A statement ends at a semicolon, or
// at the parenthesis that closes the one it is inside (a WITH ... AS (UPDATE ...)).
func dmlStatements(sql string) (stmts []dmlStatement, unread []string) {
	s := blankStrings(stripSQLComments(sql))
	for _, m := range dmlWord.FindAllStringIndex(s, -1) {
		word := strings.ToUpper(s[m[0]:m[1]])
		if pw := prevWord.FindStringSubmatch(s[:m[0]]); pw != nil && dmlNotAStatement[strings.ToUpper(pw[1])] && (word == "UPDATE" || word == "DELETE") {
			if strings.ToUpper(pw[1]) == "DO" {
				// An upsert writes the rows its INSERT names, which is bounded unless the INSERT
				// reads them from a SELECT (a bulk update by another name).
				// It is read as an UPDATE of the INSERT's table, judged like any other: keyed, bounded,
				// or listed with the reason and pinned to its text.
				head := s[:m[0]]
				if i := strings.LastIndex(strings.ToUpper(head), "INSERT"); i >= 0 && len(atDepth0(head[i:], "SELECT")) > 0 {
					if im := insertInto.FindStringSubmatch(s[i:]); im != nil {
						stmts = append(stmts, dmlStatement{kind: "UPDATE", table: im[1], text: s[i:stmtEnd(s, i)]})
					} else {
						unread = append(unread, "an INSERT ... SELECT ... ON CONFLICT DO UPDATE whose table the rule cannot read")
					}
				}
			}
			continue
		}
		sm := dmlShape.FindStringSubmatchIndex(s[m[0]:])
		if sm == nil {
			if strings.TrimSpace(s) == strings.TrimSpace(s[m[0]:m[1]]) {
				continue // the whole text is the word: a name or a verb, not a statement
			}
			unread = append(unread, fmt.Sprintf("%s is a write the rule cannot read (%.40q); write it as DELETE FROM ctrlz.<table> or UPDATE ctrlz.<table>", word, strings.Join(strings.Fields(s[m[0]:]), " ")))
			continue
		}
		end := stmtEnd(s, m[0])
		kind := "UPDATE"
		if strings.HasPrefix(strings.ToUpper(s[m[0]+sm[2]:m[0]+sm[3]]), "DELETE") {
			kind = "DELETE"
		}
		table := s[m[0]+sm[4] : m[0]+sm[5]]
		stmts = append(stmts, dmlStatement{kind: kind, table: table, text: s[m[0]:end], canon: strings.Replace(kind, "DELETE", "DELETE FROM", 1) + " ctrlz." + table + s[m[0]+sm[1]:end]})
	}
	return stmts, unread
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
	inConjunct     = regexp.MustCompile(`(?is)^(.+?)\s+IN\s*\(`)
	dollarParam    = regexp.MustCompile(`\$\d+`)
	aliasPrefix    = regexp.MustCompile(`\b\w+\.`)
	spaceAndParens = strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "", "(", "", ")", "")
)

// judge says why a statement is neither keyed nor a batch bounded by its primary key, or
// "" when it is one of the two. params are the names a limit may be drawn from: nothing for
// a Go constant (its parameters are $n), the function's own parameters for a function body.
//
// Contract (db-r17-14). Which conjunct names one row, which conjunct is a batch, and whether the columns of
// either belong to the written table are read by lockrank.Writes, the one grammar of the WHERE clause that
// the lock-order rules share: an `id` of a joined table, or of an alias that is not the target's, is neither
// keyed nor a bound. What this function adds is what that grammar does not judge: that the key is the table's
// primary key (sweepPrimaryKeys), that the LIMIT is a parameter, and that the outer statement repeats the
// subselect's predicate (recheck). A statement lockrank cannot read as a write of the table is neither keyed
// nor bounded, so it fails closed.
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
	var w lockrank.RowWrite
	if ws, err := lockrank.Writes(st.canon); err == nil && len(ws) > 0 && ws[0].Table == st.table {
		w = ws[0]
	}
	if w.Keyed && pk == "id" {
		return ""
	}
	for _, c := range splitAt(cond, atDepth0(cond, "AND"), "AND") {
		c = anyArrayAsIn(c)
		m := inConjunct.FindStringSubmatchIndex(c)
		if m == nil {
			continue
		}
		left := strings.ToLower(spaceAndParens.Replace(aliasPrefix.ReplaceAllString(c[m[2]:m[3]], "")))
		// The physical address of a row the subselect locks names one row of any table as well as its
		// key does (db-r17-1: a row comparison of a composite key cannot use an index, ctid can).
		if left != pk && left != "ctid" {
			continue
		}
		var limit string
		for _, b := range w.Batches {
			if strings.Join(b.Key, ",") == left {
				limit = strings.Join(b.Limit, " ")
			}
		}
		if limit == "" {
			continue // not a batch of the written table's own rows with a LIMIT
		}
		bounded := dollarParam.MatchString(limit)
		for _, p := range params {
			if regexp.MustCompile(`\b` + regexp.QuoteMeta(p) + `\b`).MatchString(limit) {
				bounded = true
			}
		}
		if !bounded {
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
			continue
		}
		inner := strings.TrimSpace(c[open+1 : closeAt])
		if !strings.HasPrefix(strings.ToUpper(inner), "SELECT") {
			continue
		}
		return recheck(splitAt(cond, atDepth0(cond, "AND"), "AND"), c, inner)
	}
	return fmt.Sprintf("%s ctrlz.%s is neither keyed (id = $n) nor bounded (%s IN (SELECT %s FROM ctrlz.%s ... LIMIT <parameter>))",
		st.kind, st.table, pk, pk, st.table)
}

// ---------------------------------------------------------------------------
// Go constants

// goSweepProblems judges the SQL constants of the module and the SQL literals that reach a
// database call. It returns the problems and the registry names it used.
func goSweepProblems(fset *token.FileSet, files []file) (problems []string, used map[string][]string) {
	used = map[string][]string{}
	info, ok := typeInfo(fset, files)
	if !ok {
		return []string{"type information unavailable"}, used
	}
	judgeText := func(path, name string, pos token.Pos, sql string) {
		stmts, unread := dmlStatements(sql)
		for _, u := range unread {
			problems = append(problems, fmt.Sprintf("%s:%d: %s: %s", path, fset.Position(pos).Line, name, u))
		}
		for _, st := range stmts {
			why := judge(st, nil)
			if why == "" {
				continue
			}
			if _, ok := sweepNotASweep[name]; ok && name != "" {
				used[name] = append(used[name], strings.Join(strings.Fields(st.text), " "))
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

func functionSweepProblems(fns []sqlFunction) (problems []string, used map[string][]string) {
	used = map[string][]string{}
	for _, f := range fns {
		stmts, unread := dmlStatements(f.body)
		for _, u := range unread {
			problems = append(problems, fmt.Sprintf("%s: function %s: %s", f.file, f.name, u))
		}
		for _, st := range stmts {
			why := judge(st, f.params)
			if why == "" {
				continue
			}
			if _, ok := sweepNotASweep[f.name]; ok {
				used[f.name] = append(used[f.name], strings.Join(strings.Fields(st.text), " "))
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
					// A goroutine is a go statement or, since round 18 (rule goroutine-recover), a call of safego.Go,
					// the one place that starts one; its function literal is the goroutine.
					var g ast.Node
					switch x := n.(type) {
					case *ast.GoStmt:
						g = x
					case *ast.CallExpr:
						if sel, ok := x.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Go" {
							if id, ok := sel.X.(*ast.Ident); !ok || id.Name != "safego" {
								return true
							}
							g = x
						}
					}
					if g == nil {
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
	// A registry entry that nothing needs any more is a hole in the rule: delete it. One that still
	// needs it is pinned to the TEXT it was reviewed for (sms-r16-23): the entry used to be found by
	// the name of a constant or a function alone, so a listed statement rewritten into a bulk one
	// stayed listed. The golden holds the digest of the exempted statements of each name; a change
	// fails until somebody reads the new text and records the new digest.
	for _, p := range sweepPinProblems(sweepNotASweep, usedGo, usedFn, readSweepPins(t)) {
		t.Error(p)
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
		// sms-r16-15: no file and no name decides what is read. A retention UPDATE outside worker_*.go, and one in
		// a function whose name has no keyword, are judged like any other; a listed name is the one way out.
		{"a bulk update outside the worker files", "internal/store/other.go",
			"const qBad = `UPDATE ctrlz.sms_outbox SET state = 'failed' WHERE created_at < now()`", 1},
		{"a bulk update in a store file nobody listed", "internal/store/admin_sms.go",
			"const qFinalise = `UPDATE ctrlz.otp_challenges SET delivery_ct = NULL WHERE created_at < now() - interval '1 day'`", 1},
		{"a keyed update outside the worker files", "internal/store/other.go",
			"const qFine = `UPDATE ctrlz.sms_outbox SET state = 'failed' WHERE id = $1`", 0},
		{"a bulk update that is listed", "internal/store/other.go",
			"const qRecoveryUse = `UPDATE ctrlz.recovery_codes SET used_at = now() WHERE user_id = $1`", 0},
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
		// db-r16-21: the composite key in the ARRAY form that locks and skips (worker_sweep_throttle).
		{"a composite key batch taken as an array of rows", "internal/store/other.go",
			"const qOK = `DELETE FROM ctrlz.sms_counters WHERE (day, scope, key) = ANY (ARRAY(SELECT (day, scope, key) FROM ctrlz.sms_counters WHERE day < $1 LIMIT $2 FOR UPDATE SKIP LOCKED)) AND day < $1`", 0},
		{"the same with no limit", "internal/store/other.go",
			"const qBad = `DELETE FROM ctrlz.sms_counters WHERE (day, scope, key) = ANY (ARRAY(SELECT (day, scope, key) FROM ctrlz.sms_counters WHERE day < $1 FOR UPDATE SKIP LOCKED)) AND day < $1`", 1},
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
		// db-r17-14: the key is read by the one grammar of lockrank.Writes, so the id of a joined table is not it.
		{"the id of a joined table pins nothing of the written one", "internal/store/other.go",
			"const qBad = `UPDATE ctrlz.refresh_tokens r SET revoked_at = now() FROM ctrlz.sessions s WHERE s.id = $2 AND r.session_id = s.id`", 1},
		{"a bare id beside a joined table", "internal/store/other.go",
			"const qBad = `UPDATE ctrlz.refresh_tokens r SET revoked_at = now() FROM ctrlz.sessions s WHERE id = $2 AND r.session_id = s.id`", 1},
		{"the target's own id beside a join", "internal/store/other.go",
			"const qOK = `UPDATE ctrlz.refresh_tokens r SET revoked_at = now() FROM ctrlz.sessions s WHERE r.id = $2 AND r.session_id = s.id`", 0},
		{"a batch keyed by the id of a joined table", "internal/store/other.go",
			"const qBad = `UPDATE ctrlz.refresh_tokens r SET revoked_at = now() FROM ctrlz.sessions s WHERE s.id IN (SELECT id FROM ctrlz.refresh_tokens LIMIT $1) AND r.session_id = s.id AND r.revoked_at IS NULL`", 1},
		{"a cast of the parameter is one row", "internal/store/other.go",
			"const qOK = `UPDATE ctrlz.sessions SET revoked_at = now() WHERE id = $2::uuid`", 0},
		{"the registry names a constant that is unbounded", "internal/store/worker_sms.go",
			"const qCountersRefund = `UPDATE ctrlz.sms_counters SET count = count - 1 WHERE scope = $1`", 0},
		// sms-r16-23: every occurrence of a write word is read, whatever the spelling around it.
		{"UPDATE ONLY", "internal/store/other.go",
			"const qBad = `UPDATE ONLY ctrlz.otp_challenges SET delivery_ct = NULL WHERE created_at < now()`", 1},
		{"UPDATE ONLY as a bounded batch is read and passes", "internal/store/other.go",
			"const qOK = `UPDATE ONLY ctrlz.otp_challenges SET delivery_ct = NULL WHERE id IN (SELECT id FROM ctrlz.otp_challenges WHERE created_at < now() LIMIT $1) AND created_at < now()`", 0},
		{"a quoted schema and table as a bounded batch is read and passes", "internal/store/other.go",
			"const qOK = `UPDATE \"ctrlz\".\"otp_challenges\" SET delivery_ct = NULL WHERE id IN (SELECT id FROM ctrlz.otp_challenges WHERE created_at < now() LIMIT $1) AND created_at < now()`", 0},
		{"DELETE FROM ONLY", "internal/store/other.go",
			"const qBad = `DELETE FROM ONLY ctrlz.sessions WHERE expires_at < now()`", 1},
		{"a quoted schema and table", "internal/store/other.go",
			"const qBad = `DELETE FROM \"ctrlz\".\"sessions\" WHERE expires_at < now()`", 1},
		{"an unqualified table", "internal/store/other.go",
			"const qBad = `UPDATE sessions SET revoked_at = now() WHERE expires_at < now()`", 1},
		{"an unqualified keyed update", "internal/store/other.go",
			"const qOK = `UPDATE sessions SET revoked_at = now() WHERE id = $1`", 0},
		{"MERGE", "internal/store/other.go",
			"const qBad = `MERGE INTO ctrlz.sessions s USING ctrlz.invites i ON s.id = i.id WHEN MATCHED THEN DELETE`", 2},
		{"TRUNCATE", "internal/store/other.go",
			"const qBad = `TRUNCATE ctrlz.sessions`", 1},
		{"an insert from a select that updates on conflict", "internal/store/other.go",
			"const qBad = `INSERT INTO ctrlz.sms_counters AS c (day, scope, key, count) SELECT day, scope, key, 1 FROM ctrlz.sessions ON CONFLICT (day, scope, key) DO UPDATE SET count = c.count + 1`", 1},
		{"an insert of values that updates on conflict is one row per tuple", "internal/store/other.go",
			"const qOK = `INSERT INTO ctrlz.sms_counters AS c (day, scope, key, count) VALUES ($1, $2, $3, 1) ON CONFLICT (day, scope, key) DO UPDATE SET count = c.count + 1`", 0},
		{"a row lock is not an update", "internal/store/other.go",
			"const qOK = `SELECT id FROM ctrlz.sessions WHERE id = $1 FOR NO KEY UPDATE`", 0},
		{"the word in a string literal", "internal/store/other.go",
			"const qOK = `SELECT 'delete from ctrlz.sessions; truncate x' FROM ctrlz.sessions WHERE id = $1`", 0},
		{"a bare word that is a name, not SQL", "internal/store/other.go", "const verbUpdate = `update`", 0},
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
		{"a batch by ctid", fnSrc("worker_sweep_x", "p_limit integer",
			"DELETE FROM ctrlz.auth_throttle t WHERE t.ctid = ANY (ARRAY(SELECT s.ctid FROM ctrlz.auth_throttle s WHERE s.window_start < now() LIMIT LEAST(p_limit, 10000) FOR UPDATE SKIP LOCKED)) AND t.window_start < now();"), 0},
		{"a batch by ctid with no limit", fnSrc("worker_sweep_x", "p_limit integer",
			"DELETE FROM ctrlz.auth_throttle t WHERE t.ctid = ANY (ARRAY(SELECT s.ctid FROM ctrlz.auth_throttle s WHERE s.window_start < now() FOR UPDATE SKIP LOCKED)) AND t.window_start < now();"), 1},
		{"a batch by ctid that selects another column", fnSrc("worker_sweep_x", "p_limit integer",
			"DELETE FROM ctrlz.auth_throttle t WHERE t.ctid = ANY (ARRAY(SELECT s.scope FROM ctrlz.auth_throttle s WHERE s.window_start < now() LIMIT p_limit)) AND t.window_start < now();"), 1},
		{"a function whose name has no sweep keyword is read too", fnSrc("auth_x", "",
			"DELETE FROM ctrlz.auth_tickets WHERE expires_at < now();"), 1},
		{"an update in a function named finalise", fnSrc("otp_finalize", "",
			"UPDATE ctrlz.otp_challenges SET delivery_ct = NULL WHERE created_at < now() - interval '1 day';"), 1},
		{"a listed function", fnSrc("auth_ticket_take", "",
			"UPDATE ctrlz.auth_tickets SET taken_at = now() WHERE hash = $1;"), 0},
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
		// The same cases through safego.Go, which is how Run starts them since round 18.
		{"safego: two goroutines, one each", `func (s *S) Run() { safego.Go(nil, 0, func() { s.Fast() }); safego.Go(nil, 0, func() { s.Slow() }) }
func (s *S) Fast() {}
func (s *S) Slow() {}`, 0},
		{"safego: one goroutine runs both", `func (s *S) Run() { safego.Go(nil, 0, func() { s.Fast(); s.Slow() }) }
func (s *S) Fast() {}
func (s *S) Slow() {}`, 2},
		{"safego: slow runs in the callers goroutine", `func (s *S) Run() { safego.Go(nil, 0, func() { s.Fast() }); s.Slow() }
func (s *S) Fast() {}
func (s *S) Slow() {}`, 1},
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

// sweepDigest is the digest of the exempted statements of one name, in a normal form (white space
// collapsed, sorted), so a re-indented statement is the same and an edited one is not.
func sweepDigest(stmts []string) string {
	s := append([]string(nil), stmts...)
	sort.Strings(s)
	sum := sha256.Sum256([]byte(strings.Join(s, "\n")))
	return hex.EncodeToString(sum[:])
}

func readSweepPins(t *testing.T) map[string]string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot(t), "internal", "lint", "testdata", "sweep_pins.golden"))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Fields(l)
		if len(f) == 2 && !strings.HasPrefix(l, "#") {
			out[f[0]] = f[1]
		}
	}
	return out
}

// TestSweepPinsCanFail shows what the pin is: the same statement written with other white space has
// the same digest, and a listed statement edited into something else does not, so it can no longer
// hide behind its name.
func TestSweepPinsCanFail(t *testing.T) {
	norm := func(sql string) []string {
		st, _ := dmlStatements(sql)
		var out []string
		for _, s := range st {
			out = append(out, strings.Join(strings.Fields(s.text), " "))
		}
		return out
	}
	listed := "UPDATE ctrlz.recovery_codes SET used_at = now() WHERE user_id = $1"
	if sweepDigest(norm(listed)) != sweepDigest(norm("UPDATE  ctrlz.recovery_codes\n  SET used_at = now()\n  WHERE user_id = $1")) {
		t.Error("re-indenting a pinned statement changed its digest")
	}
	if sweepDigest(norm(listed)) == sweepDigest(norm("UPDATE ctrlz.recovery_codes SET used_at = now() WHERE created_at < now()")) {
		t.Error("a pinned statement rewritten into a bulk one kept its digest")
	}
}

// sweepPinProblems judges the registry against the statements that needed it and the pinned digests:
// an entry nothing needs, an entry whose statement is not the reviewed one, a pin of a name that is no
// entry, and an entry with no pin (sms-r16-23).
func sweepPinProblems(registry map[string]string, usedGo, usedFn map[string][]string, pins map[string]string) []string {
	var out []string
	for name := range registry {
		stmts := append(append([]string(nil), usedGo[name]...), usedFn[name]...)
		if len(stmts) == 0 {
			out = append(out, fmt.Sprintf("sweepNotASweep[%q] matches no statement that needs it; remove it", name))
			continue
		}
		if got := sweepDigest(stmts); pins[name] != got {
			out = append(out, fmt.Sprintf("the statement of sweepNotASweep[%q] is not the one that was reviewed (pinned %q); read it again, and if it is still not a sweep set the line in testdata/sweep_pins.golden to: %s %s", name, pins[name], name, got))
		}
	}
	for name := range pins {
		if _, ok := registry[name]; !ok {
			out = append(out, fmt.Sprintf("testdata/sweep_pins.golden pins %q, which is not in sweepNotASweep; remove the line", name))
		}
	}
	sort.Strings(out)
	return out
}

func TestSweepPinProblemsCanFail(t *testing.T) {
	stmt := []string{"UPDATE ctrlz.recovery_codes SET used_at = now() WHERE user_id = $1"}
	good := sweepDigest(stmt)
	reg := map[string]string{"qRecoveryUse": "r"}
	cases := []struct {
		name string
		used map[string][]string
		pins map[string]string
		want int
	}{
		{"the reviewed statement", map[string][]string{"qRecoveryUse": stmt}, map[string]string{"qRecoveryUse": good}, 0},
		{"an edited statement", map[string][]string{"qRecoveryUse": {"UPDATE ctrlz.recovery_codes SET used_at = now()"}}, map[string]string{"qRecoveryUse": good}, 1},
		{"an entry nothing needs", map[string][]string{}, map[string]string{"qRecoveryUse": sweepDigest(nil)}, 1},
		{"an entry with no pin", map[string][]string{"qRecoveryUse": stmt}, map[string]string{}, 1},
		{"a pin of nothing", map[string][]string{"qRecoveryUse": stmt}, map[string]string{"qRecoveryUse": good, "qGone": "x"}, 1},
	}
	for _, c := range cases {
		if got := sweepPinProblems(reg, c.used, nil, c.pins); len(got) != c.want {
			t.Errorf("%s: %d problems %v, want %d", c.name, len(got), got, c.want)
		}
	}
	if got := sweepPinProblems(reg, nil, map[string][]string{"qRecoveryUse": stmt}, map[string]string{"qRecoveryUse": good}); len(got) != 0 {
		t.Errorf("a function statement is read like a constant: %v", got)
	}
}
