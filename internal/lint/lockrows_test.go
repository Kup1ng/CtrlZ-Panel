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

// rowOrderExempt are the tables whose multi-row writes need no order, each with the reason. A table that
// is not here and whose statement is not keyed, ordered or skipping fails the lint.
var rowOrderExempt = map[string]string{
	"system_settings": "one row by construction (a singleton table with a CHECK on its id)",
	"webauthn_config": "one row by construction (a singleton table with a CHECK on its id)",
	"sms_templates":   "keyed by its whole primary key (key, locale), which names one row",
	"sms_counters":    "the refund names the whole primary key (day, scope, key): one row per statement, days in order (CountersRefundAll sorts them)",
}

// insertOrderExempt are the tables whose INSERT ... SELECT adds exactly one row, each with the reason. The rule
// cannot tell a one-row SELECT from a many-row one (that is semantics, not shape), so each is read by a person,
// and one that no longer matches a statement fails.
var insertOrderExempt = map[string]string{
	"webauthn_credentials": "one row: the source is the one-row aggregate count(*) (no GROUP BY) of the user's credentials (PasskeyAdd)",
	"sms_counters":         "one row: the source is a CTE over the singleton system_settings table, filtered by a WHERE (qOutboxFirstGate)",
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
					if !in.Multi || in.Sorted {
						continue
					}
					if _, exempt := insertOrderExempt[in.Table]; exempt {
						continue
					}
					out = append(out, fmt.Sprintf("%s:%d: an INSERT into ctrlz.%s that can add several rows does not sort them: add ORDER BY, or list the table in insertOrderExempt with the reason it adds one row",
						f.path, fset.Position(call.Pos()).Line, in.Table))
				}
			}
			// The shape of every locking subselect, whatever the write skips or orders by (sms-r17-4).
			if len(ws) > 0 && len(lockingSubselectsOutsideArray(constant.StringVal(tv.Value))) > 0 {
				out = append(out, fmt.Sprintf("%s:%d: a write has a row-locking subselect that is not the body of ARRAY(...): pick the rows once with id = ANY (ARRAY(SELECT id FROM ... FOR UPDATE ...)) (internal/store/locks.go), because an IN over a locking, limited subselect may be rescanned and then picks more rows",
					f.path, fset.Position(call.Pos()).Line))
			}
			for _, w := range ws {
				if w.Keyed || w.Ordered || w.NoWait {
					continue
				}
				if _, exempt := rowOrderExempt[w.Table]; exempt {
					continue
				}
				out = append(out, fmt.Sprintf("%s:%d: a %s of ctrlz.%s that can touch several rows does not lock them in key order: take them through the ordered locking subselect of internal/store/locks.go (id = ANY (ARRAY(SELECT id FROM ... ORDER BY id FOR UPDATE))), name the row (id = $n), or list the table in rowOrderExempt with the reason",
					f.path, fset.Position(call.Pos()).Line, w.Kind, w.Table))
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
								if in.Multi && !in.Sorted {
									usedInsert[in.Table] = true
								}
							}
						}
						if ws, err := lockrank.Writes(constant.StringVal(tv.Value)); err == nil {
							for _, w := range ws {
								if !w.Keyed && !w.Ordered && !w.NoWait {
									used[w.Table] = true
								}
							}
						}
					}
				}
			}
			return true
		})
	}
	for table := range rowOrderExempt {
		if !used[table] {
			t.Errorf("rowOrderExempt names %s, which no unordered multi-row write needs: remove the entry", table)
		}
	}
	for table := range insertOrderExempt {
		if !usedInsert[table] {
			t.Errorf("insertOrderExempt names %s, which no unsorted multi-row INSERT needs: remove the entry", table)
		}
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
		{"a singleton table", `UPDATE ctrlz.system_settings SET registration_mode = $1`, 0},
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
