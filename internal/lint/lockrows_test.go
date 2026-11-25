package lint_test

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"go/ast"
	"go/constant"
	"go/parser"
	"go/token"
	"sort"
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/lockrank"
)

// The rows of one table (P1 auth review round 16, db-r16-19; rule lock-order, "inside a rank").
//
// The rank orders the tables a transaction locks, and TestLockOrderRule makes every statement readable
// by it. Inside one table the rows of a multi-row UPDATE or DELETE were locked in whatever order the
// statement scanned them: the worker's sweep of expired sessions (an IN-subselect, heap order) and a
// user's "log out all" (its own predicate, index order) lock the same two rows in opposite orders and
// one of them fails with a deadlock (40P01, a 503). Every round found one more pair. The rule is a
// shape, and the lint is a fail-closed allow list over every constant SQL text that reaches a database
// call:
//
//	a write that can touch several rows must hold, in its WHERE, a subquery that selects its rows
//	ORDER BY id and locks them FOR UPDATE (internal/store/locks.go, the constant orderedRows), so that
//	two such statements meet in the same order;
//	a write that names its row (id = $n) is one row and needs nothing;
//	a write that never waits (SKIP LOCKED) cannot be the waiting side of a cycle;
//	anything else is a finding, unless the table is on rowOrderExempt with the reason.
//
// Contract. It judges the statement texts of the store and of every package that sends SQL (the sinks of
// sqlSinks), by the value of the constant as go/types computes it, with the reading of lockrank.Writes.
// It does not judge the plpgsql bodies of definer functions (their own writes are read from the live
// catalog by catalogtest check 21's sibling TestDefinerWritesLockInKeyOrder), nor the rows a DELETE
// cascades to.

// stmtExempt is one reviewed statement that the rule cannot read as ordered, with the table it writes and the
// reason and the digest of its text. It is keyed by the NAME of the constant that holds the statement
// (db-r18-7): the first form excused a whole table, so a second, different statement of that table (an
// unordered UPDATE of the counters, an unsorted INSERT of many rows) passed on the strength of a reason
// written for the first. The name alone is not the statement (db-r18-14): a constant keeps its name when its
// text is edited into another shape, and a selector of another package can carry the same name, so the entry
// also pins the text the reviewer read (stmtDigest, white space collapsed), as sweep_pins.golden and
// reviewedRefund do. A statement that reaches a database call through anything but a named constant cannot
// be excused, and an edited statement is excused again only when a person reads it and sets the new digest.
type stmtExempt struct{ table, reason, digest string }

// stmtDigest is the digest of the text a reviewer read: white space collapsed, so a re-indented statement is
// the same one and an edited statement is not.
func stmtDigest(sql string) string {
	sum := sha256.Sum256([]byte(strings.Join(strings.Fields(sql), " ")))
	return hex.EncodeToString(sum[:])
}

// covers says whether the entry excuses this statement: the table it was reviewed for and the text it was
// reviewed as.
func (e stmtExempt) covers(table, text string) bool {
	return e.table == table && e.digest == stmtDigest(text)
}

// exemptFor looks the entry of a statement's constant up. The name finds the entry; covers decides.
func exemptFor(m map[string]stmtExempt, arg ast.Expr, table, text string) bool {
	e, ok := m[stmtName(arg)]
	return ok && e.covers(table, text)
}

// rowOrderExempt are the statements whose multi-row write needs no order, each with the reason. A statement
// that is not here and is not keyed, ordered or skipping fails the lint, and so does an entry whose statement
// no longer needs it.
var rowOrderExempt = map[string]stmtExempt{
	"qRegistrationSet":      {"system_settings", "one row by construction (a singleton table with a CHECK on its id)", "fc0f117409e94867d8df35b89f75aa33afd4bf008344e713566dbff76844c367"},
	"qRegistrationGraceSet": {"system_settings", "one row by construction (a singleton table with a CHECK on its id)", "4a6b074bf6fcbdc83f1231d708f5775c9484ca044c3d12f1d1417f9f8ea8324c"},
	"qSMSLimitsSet":         {"system_settings", "one row by construction (a singleton table with a CHECK on its id)", "c4f7bd28e36a53b15dec7e61d331d1443d865f842898ecbef7818e47d4062a1e"},
	"qWebauthnConfigSet":    {"webauthn_config", "one row by construction (a singleton table with a CHECK on its id)", "c353620f4df3517df420cb2dbd20964c56079b36794f3b22bfd3410a93927786"},
	"qSMSTemplateSet":       {"sms_templates", "keyed by its whole primary key (key, locale), which names one row", "cb959f5e871e5a8e7cc1e5071342b2f82c97842544fec3d94e4a1f90a80e2258"},
	"qServiceDelete":        {"profile_services", "keyed by its whole primary key (tenant, profile, service_slug), which names one row", "d28330c71b280809f2eca548feaede93f4b50b8038b149c1b47db8baf09b3da1"},
	"qIdempotencyFinish":    {"idempotency_keys", "keyed by its whole primary key (tenant, key), which names one row", "3284fcd1c37012ca3c2bddf46f821f9e901d2cc6cf0023330e41042f75b4f6c6"},
	"qIdempotencyPurge":     {"idempotency_keys", "the purge of expired keys deletes a bounded batch by the whole key, which the worker cannot lock first (it holds no UPDATE on the table) and no other statement writes many rows of", "d4a554c2261bfa3225d6c9a61bddf7074cb52457e8a34ee474a415a534897cb4"},
	"qJobOutboxTake":        {"job_outbox", "the drain takes a bounded batch with one DELETE, which the worker cannot lock first (it holds S and D only); every other writer inserts one row of a tenant at a time (JobQueue)", "7571c87eecf72d01045de2e758888762cf8ab3bd65d47b2ca27895e8d76f9c3f"},
}

// insertOrderExempt are the statements whose INSERT ... SELECT adds exactly one row, each with the reason. The
// rule cannot tell a one-row SELECT from a many-row one (that is semantics, not shape), so each is read by a
// person, and one that no longer matches a statement fails.
var insertOrderExempt = map[string]stmtExempt{
	"qPasskeyAdd":         {"webauthn_credentials", "one row: the source is the one-row aggregate count(*) (no GROUP BY) of the user's credentials (PasskeyAdd)", "89ea5b25e13ffb72181076efdc50e7c8ef3f4bf3d1a27c55983c9f8a440b8ec0"},
	"qOutboxFirstGate":    {"sms_counters", "one row: the source is a CTE over the singleton system_settings table, filtered by a WHERE", "b7fb77ebfc7657d71ffed74affaf3274be892ff5743d68d8bd7a4601bb7f880e"},
	"qFolderInsert":       {"rule_folders", "one row: the source is a SELECT of the parameters with a WHERE on the folder cap, no FROM", "cb801ae1930a9371f0ebc690e66c6b3bb86c2aae25cc1e2d92ac17dcae924d18"},
	"qClientInsert":       {"clients", "one row: the source is a SELECT of the parameters with a WHERE on max_clients_per_endpoint, no FROM; the WITH only supplies the tenant's one row of limits (none: the cap reads 0)", "b7454b801e5da267470643a8ecc06887cec45facf541a7e6a22574a52b03cb2f"},
	"qDDNSHostInsert":     {"endpoint_ddns_hosts", "one row: the source is a SELECT of the parameters with a WHERE on the host cap of the Endpoint, no FROM", "a79bf6e1c3a3e9f0fceb56ae130fb90cbc79debaebcf7fd312b10cfe76c7d4f7"},
	"qGroupInsert":        {"endpoint_groups", "one row: the source is a SELECT of the parameters with a WHERE on the group cap, no FROM", "50082951cc9a7ad465cd81a78b41337592588f925a69cf2b310364e93a9e9080"},
	"qProfileCreate":      {"profiles", "one row: the source is a SELECT of the parameters with a WHERE on max_profiles, no FROM; the WITH only supplies the tenant's one row of limits (none: the cap reads 0)", "017e323d70e5916c5d6c553b8c575b9c0b408cdd616c598a05ad01de772184ee"},
	"qShareLinkInsert":    {"setup_share_tokens", "one row: the source is a SELECT of the parameters with a WHERE on the live count of the Endpoint's links against the cap, no FROM", "add6ee23824409a091240755288fae6516eb3c9ed137df8ff17c9bfa58f6b13c"},
	"qDownloadLinkInsert": {"profile_download_tokens", "one row: the source is a SELECT of the parameters with a WHERE on the live count of the tenant's own links against the cap, no FROM", "9c6d02aad24b7bdcb22ea9734eba993f309459d9aca45b7f48ffcf23e622909f"},
}

// stmtName is the name of the constant a statement is passed as ("" for a literal or any other expression),
// the key of the two exemption tables.
func stmtName(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.SelectorExpr:
		return x.Sel.Name
	case *ast.ParenExpr:
		return stmtName(x.X)
	}
	return ""
}

func rowOrderProblems(fset *token.FileSet, files []file) []string {
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
			ws, err := lockrank.Writes(constant.StringVal(tv.Value))
			if err != nil {
				return true // the lock-order rule reports it
			}
			// The INSERT half of the class (db-r17-17): a statement that can add several rows waits for another
			// transaction's uncommitted row of the same key in the order its plan produces them, so it is sorted
			// or listed with the reason it adds one row.
			if is, err := lockrank.Inserts(constant.StringVal(tv.Value)); err == nil {
				for _, in := range is {
					problem := lockrank.InsertOrderProblem(in)
					if problem == "" {
						continue
					}
					if exemptFor(insertOrderExempt, call.Args[idx], in.Table, constant.StringVal(tv.Value)) {
						continue
					}
					out = append(out, fmt.Sprintf("%s:%d: %s (statement %q, digest %s): sort by ORDER BY, or list the statement's constant in insertOrderExempt with the reason it adds one row and this digest",
						f.path, fset.Position(call.Pos()).Line, problem, stmtName(call.Args[idx]), stmtDigest(constant.StringVal(tv.Value))))
				}
			}
			// The shape of every locking subselect, whatever the write skips or orders by (sms-r17-4).
			if nested, lerr := lockingSubselectsOutsideArray(constant.StringVal(tv.Value)); lerr != nil {
				out = append(out, fmt.Sprintf("%s:%d: the lock shape of this statement cannot be read (%v); the check fails closed", f.path, fset.Position(call.Pos()).Line, lerr))
			} else if len(ws) > 0 && nested > 0 {
				out = append(out, fmt.Sprintf("%s:%d: a write has a row-locking subselect that is not the body of ARRAY(...): pick the rows once with id = ANY (ARRAY(SELECT id FROM ... FOR UPDATE ...)) (internal/store/locks.go), because an IN over a locking, limited subselect may be rescanned and then picks more rows",
					f.path, fset.Position(call.Pos()).Line))
			}
			for _, w := range ws {
				if w.Keyed || w.Ordered || w.NoWait {
					continue
				}
				if exemptFor(rowOrderExempt, call.Args[idx], w.Table, constant.StringVal(tv.Value)) {
					continue
				}
				out = append(out, fmt.Sprintf("%s:%d: a %s of ctrlz.%s (statement %q, digest %s) that can touch several rows does not lock them in key order: take them through the ordered locking subselect of internal/store/locks.go (id = ANY (ARRAY(SELECT id FROM ... ORDER BY id FOR UPDATE))), name the row (id = $n), or list the statement's constant in rowOrderExempt with the reason and this digest",
					f.path, fset.Position(call.Pos()).Line, w.Kind, w.Table, stmtName(call.Args[idx]), stmtDigest(constant.StringVal(tv.Value))))
			}
			return true
		})
	}
	sort.Strings(out)
	return out
}

func TestMultiRowWritesLockInKeyOrder(t *testing.T) {
	fset, files := parseRepo(t)
	for _, p := range rowOrderProblems(fset, files) {
		t.Error(p)
	}
	// Every exemption is still needed: a table that no multi-row statement writes has no business here.
	used, usedInsert := map[string]bool{}, map[string]bool{}
	info, _ := typeInfo(fset, files)
	for _, f := range files {
		if f.test || sqlExempt(f.path) {
			continue
		}
		ast.Inspect(f.ast, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				if idx, isSink := sqlSinks()[calleeName(call.Fun)]; isSink && idx >= 0 && len(call.Args) > idx {
					if tv, known := info.Types[call.Args[idx]]; known && tv.Value != nil && tv.Value.Kind() == constant.String {
						if is, err := lockrank.Inserts(constant.StringVal(tv.Value)); err == nil {
							for _, in := range is {
								if lockrank.InsertOrderProblem(in) != "" {
									markNeeded(insertOrderExempt, stmtName(call.Args[idx]), in.Table, constant.StringVal(tv.Value), usedInsert)
								}
							}
						}
						if ws, err := lockrank.Writes(constant.StringVal(tv.Value)); err == nil {
							for _, w := range ws {
								if !w.Keyed && !w.Ordered && !w.NoWait {
									markNeeded(rowOrderExempt, stmtName(call.Args[idx]), w.Table, constant.StringVal(tv.Value), used)
								}
							}
						}
					}
				}
			}
			return true
		})
	}
	for name := range rowOrderExempt {
		if !used[name] {
			t.Errorf("rowOrderExempt names %s, which no unordered multi-row write needs: remove the entry", name)
		}
	}
	for name := range insertOrderExempt {
		if !usedInsert[name] {
			t.Errorf("insertOrderExempt names %s, which no unsorted multi-row INSERT needs: remove the entry", name)
		}
	}
}

// markNeeded records that the entry of name is still needed: a statement that carries its name, is unordered for
// its table and has the text that was reviewed. An entry whose digest no statement has any more is stale as well
// (db-r18-14).
func markNeeded(m map[string]stmtExempt, name, table, text string, into map[string]bool) {
	if e, ok := m[name]; ok && e.covers(table, text) {
		into[name] = true
	}
}

// TestMultiRowWriteLintCanFail plants each shape and requires the verdict.
func TestMultiRowWriteLintCanFail(t *testing.T) {
	cases := []struct {
		name, sql string
		want      int
	}{
		{"a user's sessions in scan order", `UPDATE ctrlz.sessions SET revoked_at = now() WHERE tenant_id = $1 AND user_id = $2`, 1},
		{"the sweep in heap order", `DELETE FROM ctrlz.sessions WHERE tenant_id = $1 AND id IN (SELECT id FROM ctrlz.sessions WHERE tenant_id = $1 LIMIT $2)`, 1},
		{"the same, ordered and locked, as an IN (rescannable)", `DELETE FROM ctrlz.sessions WHERE tenant_id = $1 AND id IN (SELECT id FROM ctrlz.sessions WHERE tenant_id = $1 ORDER BY id LIMIT $2 FOR UPDATE)`, 1},
		{"the same, ordered and locked, as an array", `DELETE FROM ctrlz.sessions WHERE tenant_id = $1 AND id = ANY (ARRAY(SELECT id FROM ctrlz.sessions WHERE tenant_id = $1 ORDER BY id LIMIT $2 FOR UPDATE))`, 0},
		{"a claim that skips locked rows, as an IN (rescannable)", `UPDATE ctrlz.sms_outbox o SET claimed_until = now() WHERE o.id IN (SELECT id FROM ctrlz.sms_outbox LIMIT 1 FOR UPDATE SKIP LOCKED)`, 1},
		{"a claim that skips locked rows, as an array", `UPDATE ctrlz.sms_outbox o SET claimed_until = now() WHERE o.id = ANY (ARRAY(SELECT id FROM ctrlz.sms_outbox LIMIT 1 FOR UPDATE SKIP LOCKED))`, 0},
		{"a CTE body that locks and skips", `WITH x AS (SELECT id FROM ctrlz.sms_outbox LIMIT 1 FOR UPDATE SKIP LOCKED) UPDATE ctrlz.sms_outbox SET claimed_until = now() WHERE id IN (SELECT id FROM x)`, 2},
		{"a lock word inside a string is not a lock", `UPDATE ctrlz.sessions SET revoked_at = now() WHERE tenant_id = $1 AND id = $2 AND note = '(FOR UPDATE'`, 0},
		{"one row", `UPDATE ctrlz.sessions SET revoked_at = now() WHERE tenant_id = $1 AND id = $2`, 0},
		{"a singleton table is excused by its statement's name, never as a literal (db-r18-7)", `UPDATE ctrlz.system_settings SET registration_mode = $1`, 1},
		{"a closing parenthesis with no opening one", `UPDATE ctrlz.sessions SET revoked_at = now() WHERE tenant_id = $1 AND id = $2)`, 1},
		{"a table nobody listed, no where", `UPDATE ctrlz.api_tokens SET revoked_at = now()`, 1},
		{"an ORDER BY with no lock", `DELETE FROM ctrlz.sessions WHERE id IN (SELECT id FROM ctrlz.sessions ORDER BY id LIMIT 5)`, 1},
		{"a read is not judged", `SELECT id FROM ctrlz.sessions WHERE user_id = $1`, 0},
		{"an id and an OR branch (db-r17-2)", `UPDATE ctrlz.sessions SET revoked_at = now() WHERE id = $1 AND tenant_id = $2 OR revoked_at IS NULL`, 1},
		{"the id of a joined table (db-r17-10)", `UPDATE ctrlz.refresh_tokens r SET revoked_at = now() FROM ctrlz.sessions s WHERE s.id = $2 AND r.session_id = s.id AND r.tenant_id = $1`, 1},
		{"the ordered subselect, descending (db-r17-3)", `UPDATE ctrlz.sessions SET revoked_at = now() WHERE tenant_id = $1 AND id = ANY (ARRAY(SELECT id FROM ctrlz.sessions WHERE user_id = $2 ORDER BY id DESC FOR NO KEY UPDATE))`, 1},
		{"the ordered subselect, by a cast", `UPDATE ctrlz.sessions SET revoked_at = now() WHERE id = ANY (ARRAY(SELECT id FROM ctrlz.sessions WHERE user_id = $2 ORDER BY id::text FOR NO KEY UPDATE))`, 1},
		{"the ordered subselect, USING", `UPDATE ctrlz.sessions SET revoked_at = now() WHERE id = ANY (ARRAY(SELECT id FROM ctrlz.sessions WHERE user_id = $2 ORDER BY id USING > FOR NO KEY UPDATE))`, 1},
		{"the ordered subselect, ascending", `UPDATE ctrlz.sessions SET revoked_at = now() WHERE id = ANY (ARRAY(SELECT id FROM ctrlz.sessions WHERE user_id = $2 ORDER BY id ASC FOR NO KEY UPDATE))`, 0},
		// db-r17-17: the INSERT half of the class.
		{"an insert of rows from a select, unsorted", `INSERT INTO ctrlz.policy_outbox (tenant_id, aggregate_type, aggregate_id, batch_id) SELECT t.id, 'x', t.id, $1 FROM ctrlz.tenants t ON CONFLICT DO NOTHING`, 1},
		{"the same, sorted", `INSERT INTO ctrlz.policy_outbox (tenant_id, aggregate_type, aggregate_id, batch_id) SELECT t.id, 'x', t.id, $1 FROM ctrlz.tenants t ORDER BY t.id ON CONFLICT DO NOTHING`, 0},
		{"several tuples, unsorted", `INSERT INTO ctrlz.notifications (tenant_id, kind) VALUES ($1, 'a'), ($1, 'b')`, 1},
		{"one tuple", `INSERT INTO ctrlz.notifications (tenant_id, kind) VALUES ($1, 'a')`, 0},
		{"an insert through a CTE", `WITH x AS (INSERT INTO ctrlz.notifications (tenant_id, kind) SELECT id, 'a' FROM ctrlz.tenants RETURNING 1) SELECT count(*) FROM x`, 1},
		// db-r18-6: the order of an insert is the table's one order, read to the columns the sort feeds.
		{"an insert sorted descending", `INSERT INTO ctrlz.policy_outbox (tenant_id, aggregate_type, aggregate_id, batch_id) SELECT t.id, 'x', t.id, $1 FROM ctrlz.tenants t ORDER BY t.id DESC ON CONFLICT DO NOTHING`, 1},
		{"an insert sorted by a random order", `INSERT INTO ctrlz.policy_outbox (tenant_id, aggregate_type, aggregate_id, batch_id) SELECT t.id, 'x', t.id, $1 FROM ctrlz.tenants t ORDER BY random() ON CONFLICT DO NOTHING`, 1},
		{"an insert sorted by an expression", `INSERT INTO ctrlz.policy_outbox (tenant_id, aggregate_type, aggregate_id, batch_id) SELECT t.id, 'x', t.id, $1 FROM ctrlz.tenants t ORDER BY t.id::text ON CONFLICT DO NOTHING`, 1},
		{"an insert sorted by a column that feeds another target column", `INSERT INTO ctrlz.policy_outbox (tenant_id, aggregate_type, aggregate_id, batch_id) SELECT t.id, 'x', t.org AS o, $1 FROM ctrlz.tenants t ORDER BY o ON CONFLICT DO NOTHING`, 1},
		{"an insert sorted by a position", `INSERT INTO ctrlz.policy_outbox (tenant_id, aggregate_type, aggregate_id, batch_id) SELECT t.id, 'x', t.id, $1 FROM ctrlz.tenants t ORDER BY 1 ON CONFLICT DO NOTHING`, 1},
		{"the recovery codes, sorted by the hash", `INSERT INTO ctrlz.recovery_codes (tenant_id, user_id, code_hash) SELECT $1, $2, h FROM unnest($3::bytea[]) AS h ORDER BY h`, 0},
		{"the recovery codes, sorted by the hash descending", `INSERT INTO ctrlz.recovery_codes (tenant_id, user_id, code_hash) SELECT $1, $2, h FROM unnest($3::bytea[]) AS h ORDER BY h DESC`, 1},
		{"a table with no declared insert order, sorted", `INSERT INTO ctrlz.notifications (tenant_id) SELECT id FROM ctrlz.tenants ORDER BY id`, 1},
		{"another statement of a table that has an exempt one", `UPDATE ctrlz.webauthn_config SET rp_id = $1`, 1},
		{"a throttle batch by ctid that skips locked rows", `DELETE FROM ctrlz.auth_throttle t WHERE t.ctid = ANY (ARRAY(SELECT s.ctid FROM ctrlz.auth_throttle s WHERE s.window_start < $2 LIMIT $1 FOR UPDATE SKIP LOCKED)) AND t.window_start < $2`, 0},
	}
	for _, c := range cases {
		fs := token.NewFileSet()
		src := "package p\nfunc f() { db.Exec(ctx, `" + c.sql + "`) }\n"
		af, err := parser.ParseFile(fs, "internal/store/x.go", src, 0)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		got := rowOrderProblems(fs, []file{{path: "internal/store/x.go", ast: af}})
		if len(got) != c.want {
			t.Errorf("%s: %d problems %v, want %d", c.name, len(got), strings.Join(got, "; "), c.want)
		}
	}
}

// TestAStatementExemptionBelongsToTheStatement is db-r18-7 and db-r18-14: the exemption names the constant
// that holds the reviewed statement, the table it writes and the text that was read. The same text under
// another name, an edited text under the reviewed name,
// a different statement of the same table, and a text that reaches the call as a literal are all judged on
// their own.
func TestAStatementExemptionBelongsToTheStatement(t *testing.T) {
	run := func(lines ...string) []string {
		t.Helper()
		fs := token.NewFileSet()
		af, err := parser.ParseFile(fs, "internal/store/x.go", strings.Join(lines, "\n")+"\n", 0)
		if err != nil {
			t.Fatal(err)
		}
		return rowOrderProblems(fs, []file{{path: "internal/store/x.go", ast: af}})
	}
	// The text of the reviewed statement as internal/store/admin_auth.go writes it.
	reviewed := "UPDATE ctrlz.webauthn_config SET rp_id = $1, allowed_origins = $2, enabled = $3"
	if got := run("package p", "const qWebauthnConfigSet = `"+reviewed+"`", "func f() { db.Exec(ctx, qWebauthnConfigSet) }"); len(got) != 0 {
		t.Errorf("the reviewed statement under its own name: %v", got)
	}
	reindented := "UPDATE  ctrlz.webauthn_config\n\tSET rp_id = $1, allowed_origins = $2, enabled = $3"
	if got := run("package p", "const qWebauthnConfigSet = `"+reindented+"`", "func f() { db.Exec(ctx, qWebauthnConfigSet) }"); len(got) != 0 {
		t.Errorf("the reviewed statement, re-indented: %v", got)
	}
	if got := run("package p", "const qSomethingElse = `"+reviewed+"`", "func f() { db.Exec(ctx, qSomethingElse) }"); len(got) != 1 {
		t.Errorf("the same text under another name must be judged on its own: %v", got)
	}
	if got := run("package p", "const qWebauthnConfigSet = `UPDATE ctrlz.webauthn_config SET enabled = $1`", "func f() { db.Exec(ctx, qWebauthnConfigSet) }"); len(got) != 1 {
		t.Errorf("an edited statement under the reviewed name must be judged again: %v", got)
	}
	if got := run("package p", "const qWebauthnConfigSet = `UPDATE ctrlz.webauthn_config SET enabled = $1`", "type s struct{}", "func (s) f() { db.Exec(ctx, qWebauthnConfigSet) }"); len(got) != 1 {
		t.Errorf("an edited statement called from a method must be judged again: %v", got)
	}
	if got := run("package p", "func f() { db.Exec(ctx, `"+reviewed+"`) }"); len(got) != 1 {
		t.Errorf("a literal has no name and cannot be excused: %v", got)
	}
}

// TestAnExemptionCoversOneTableAndOneText judges the entry itself, each clause apart: a statement that writes
// two tables is excused for the table it was reviewed for only, and an edited text is not the reviewed one.
func TestAnExemptionCoversOneTableAndOneText(t *testing.T) {
	e := stmtExempt{table: "sessions", reason: "test", digest: stmtDigest("UPDATE ctrlz.sessions SET a = 1")}
	if !e.covers("sessions", "UPDATE  ctrlz.sessions\n SET a = 1") {
		t.Error("the reviewed text, re-indented, is not covered")
	}
	if e.covers("refresh_tokens", "UPDATE ctrlz.sessions SET a = 1") {
		t.Error("another table of the same statement is covered")
	}
	if e.covers("sessions", "UPDATE ctrlz.sessions SET a = 2") {
		t.Error("an edited text is covered")
	}
}

// TestAnEntryWhoseTextIsGoneIsStale is the stale check of the two tables, judged on planted statements.
func TestAnEntryWhoseTextIsGoneIsStale(t *testing.T) {
	m := map[string]stmtExempt{"qX": {table: "sessions", reason: "test", digest: stmtDigest("UPDATE ctrlz.sessions SET a = 1")}}
	used := map[string]bool{}
	markNeeded(m, "qX", "sessions", "UPDATE ctrlz.sessions SET a = 2", used)
	if used["qX"] {
		t.Error("a statement with another text than the reviewed one keeps the entry alive")
	}
	markNeeded(m, "qOther", "sessions", "UPDATE ctrlz.sessions SET a = 1", used)
	if used["qX"] || used["qOther"] {
		t.Error("a statement under another name keeps the entry alive")
	}
	markNeeded(m, "qX", "sessions", "UPDATE ctrlz.sessions SET a = 1", used)
	if !used["qX"] {
		t.Error("the reviewed statement does not keep its entry alive")
	}
}
