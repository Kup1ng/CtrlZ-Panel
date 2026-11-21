package lockrank_test

import (
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/lockrank"
)

func shape(ws []lockrank.RowWrite) string {
	var out []string
	for _, w := range ws {
		s := w.Kind + ":" + w.Table
		if w.Keyed {
			s += ":keyed"
		}
		if w.Ordered {
			s += ":ordered"
		}
		if w.NoWait {
			s += ":skip"
		}
		out = append(out, s)
	}
	return strings.Join(out, " ")
}

// TestWrites is the reading of db-r16-19: which writes can lock several rows of a table, and which of
// those lock them in key order.
func TestWrites(t *testing.T) {
	cases := []struct{ name, sql, want string }{
		{"one row by id", `UPDATE ctrlz.sessions SET revoked_at = now() WHERE tenant_id = $1 AND id = $2`, "update:sessions:keyed"},
		{"a PL/pgSQL parameter names one row", `UPDATE ctrlz.phone_change_requests p SET completed_at = pg_catalog.now() WHERE p.tenant_id = v_tenant AND p.id = p_request_id`, "update:phone_change_requests:keyed"},
		{"a column on the right is a join, not a key", `UPDATE ctrlz.sessions s SET x = 1 WHERE s.id = r.session_id`, "update:sessions"},
		{"an aliased key", `UPDATE ctrlz.sessions s SET revoked_at = now() WHERE s.tenant_id = $1 AND s.id = $2`, "update:sessions:keyed"},
		{"a user's rows", `UPDATE ctrlz.sessions SET revoked_at = now() WHERE tenant_id = $1 AND user_id = $2 AND revoked_at IS NULL`, "update:sessions"},
		{"an id list is several rows", `UPDATE ctrlz.sessions SET revoked_at = now() WHERE tenant_id = $1 AND id IN (SELECT id FROM ctrlz.sessions WHERE user_id = $2)`, "update:sessions"},
		{"locked in key order", `UPDATE ctrlz.sessions SET revoked_at = now() WHERE tenant_id = $1 AND id IN (SELECT id FROM ctrlz.sessions WHERE user_id = $2 ORDER BY id FOR UPDATE)`, "update:sessions:ordered"},
		{"locked for no key update, which is what an UPDATE takes", `UPDATE ctrlz.sessions SET revoked_at = now() WHERE id IN (SELECT id FROM ctrlz.sessions WHERE user_id = $1 ORDER BY id FOR NO KEY UPDATE)`, "update:sessions:ordered"},
		{"FOR SHARE is not a write lock", `UPDATE ctrlz.sessions SET revoked_at = now() WHERE id IN (SELECT id FROM ctrlz.sessions WHERE user_id = $1 ORDER BY id FOR SHARE)`, "update:sessions"},
		{"a batch in key order", `DELETE FROM ctrlz.sessions WHERE tenant_id = $1 AND id IN (SELECT id FROM ctrlz.sessions WHERE tenant_id = $1 AND x < $3 ORDER BY id LIMIT $2 FOR UPDATE)`, "delete:sessions:ordered"},
		{"a batch in heap order is not ordered", `DELETE FROM ctrlz.sessions WHERE tenant_id = $1 AND id IN (SELECT id FROM ctrlz.sessions WHERE tenant_id = $1 LIMIT $2)`, "delete:sessions"},
		{"ordered by something else", `DELETE FROM ctrlz.sessions WHERE id IN (SELECT id FROM ctrlz.sessions ORDER BY created_at FOR UPDATE)`, "delete:sessions"},
		{"ordered by id and more", `DELETE FROM ctrlz.sessions WHERE id IN (SELECT id FROM ctrlz.sessions ORDER BY id, created_at FOR UPDATE)`, "delete:sessions"},
		{"the order without the lock", `DELETE FROM ctrlz.sessions WHERE id IN (SELECT id FROM ctrlz.sessions ORDER BY id LIMIT 5)`, "delete:sessions"},
		{"the lock of another level", `DELETE FROM ctrlz.sessions WHERE id IN (SELECT id FROM (SELECT id FROM ctrlz.sessions ORDER BY id) x) AND EXISTS (SELECT 1 FROM ctrlz.users FOR UPDATE)`, "delete:sessions"},
		{"skip locked never waits", `UPDATE ctrlz.sms_outbox o SET claimed_until = now() WHERE o.id IN (SELECT id FROM ctrlz.sms_outbox WHERE state = 'queued' FOR UPDATE SKIP LOCKED LIMIT 5)`, "update:sms_outbox:skip"},
		{"FOR UPDATE is a clause, not a write", `SELECT id FROM ctrlz.sessions WHERE id = $1 FOR UPDATE`, ""},
		{"FOR NO KEY UPDATE is a clause, not a write", `SELECT id FROM ctrlz.users WHERE id = $1 FOR NO KEY UPDATE`, ""},
		{"DO UPDATE of an upsert is not an UPDATE statement", `INSERT INTO ctrlz.sms_counters (k) VALUES ($1) ON CONFLICT (k) DO UPDATE SET count = 1`, ""},
		{"a write in a CTE", `WITH r AS (UPDATE ctrlz.sessions SET revoked_at = now() WHERE user_id = $1 RETURNING id) SELECT count(*) FROM r`, "update:sessions"},
		{"RETURNING ends the clause", `UPDATE ctrlz.alerts SET resolved_at = now() WHERE id = $1 AND resolved_at IS NULL RETURNING kind`, "update:alerts:keyed"},
		{"a key in a SET subselect is not the key of the write", `UPDATE ctrlz.sessions SET revoked_at = (SELECT now() FROM ctrlz.users WHERE id = $1) WHERE user_id = $2`, "update:sessions"},
		{"no WHERE is every row", `UPDATE ctrlz.system_settings SET registration_mode = $1`, "update:system_settings"},
		// db-r16-22: the shape is the grammar of the WHERE, not the presence of its tokens.
		{"a locking subselect of another table decorates the statement", `UPDATE ctrlz.sessions SET revoked_at = now() WHERE tenant_id = $1 AND user_id = $2 AND EXISTS (SELECT 1 FROM ctrlz.tenants x WHERE x.id = $1 ORDER BY x.id FOR UPDATE)`, "update:sessions"},
		{"skip locked of another table", `UPDATE ctrlz.sessions SET revoked_at = now() WHERE tenant_id = $1 AND user_id = $2 AND EXISTS (SELECT 1 FROM ctrlz.tenants x FOR UPDATE SKIP LOCKED)`, "update:sessions"},
		{"the ordered subselect in an OR branch", `UPDATE ctrlz.sessions SET revoked_at = now() WHERE tenant_id = $1 AND (user_id = $2 OR id = ANY (ARRAY(SELECT id FROM ctrlz.sessions WHERE user_id = $2 ORDER BY id FOR NO KEY UPDATE)))`, "update:sessions"},
		{"an OR at the top level", `UPDATE ctrlz.sessions SET revoked_at = now() WHERE id = ANY (ARRAY(SELECT id FROM ctrlz.sessions WHERE user_id = $2 ORDER BY id FOR NO KEY UPDATE)) OR user_id = $3`, "update:sessions"},
		{"a composite key that skips locked rows never waits", `DELETE FROM ctrlz.auth_throttle t WHERE (t.scope, t.key) = ANY (ARRAY(SELECT (s.scope, s.key) FROM ctrlz.auth_throttle s WHERE s.window_start < now() LIMIT $1 FOR UPDATE SKIP LOCKED)) AND t.window_start < now()`, "delete:auth_throttle:skip"},
		{"a composite key in IN", `DELETE FROM ctrlz.auth_throttle t WHERE (t.scope, t.key) IN (SELECT s.scope, s.key FROM ctrlz.auth_throttle s FOR UPDATE SKIP LOCKED)`, "delete:auth_throttle:skip"},
		{"a composite key without skip is not ordered", `DELETE FROM ctrlz.auth_throttle t WHERE (t.scope, t.key) IN (SELECT s.scope, s.key FROM ctrlz.auth_throttle s ORDER BY s.scope FOR UPDATE)`, "delete:auth_throttle"},
		{"a composite key with fewer columns selected", `DELETE FROM ctrlz.auth_throttle t WHERE (t.scope, t.key) IN (SELECT s.scope FROM ctrlz.auth_throttle s FOR UPDATE SKIP LOCKED)`, "delete:auth_throttle"},
		{"the ordered conjunct, and an OR after it", `UPDATE ctrlz.sessions SET revoked_at = now() WHERE id = ANY (ARRAY(SELECT id FROM ctrlz.sessions WHERE user_id = $2 ORDER BY id FOR NO KEY UPDATE)) AND tenant_id = $1 OR user_id = $3`, "update:sessions"},
		{"the ordered subselect selects the table of another write", `UPDATE ctrlz.sessions SET revoked_at = now() WHERE id = ANY (ARRAY(SELECT id FROM ctrlz.refresh_tokens WHERE user_id = $2 ORDER BY id FOR NO KEY UPDATE))`, "update:sessions"},
		{"the ordered subselect selects another column", `UPDATE ctrlz.sessions SET revoked_at = now() WHERE id = ANY (ARRAY(SELECT session_id FROM ctrlz.sessions WHERE user_id = $2 ORDER BY id FOR NO KEY UPDATE))`, "update:sessions"},
		{"the subselect is only a part of the condition", `UPDATE ctrlz.sessions SET revoked_at = now() WHERE id = ANY (ARRAY(SELECT id FROM ctrlz.sessions WHERE user_id = $2 ORDER BY id FOR NO KEY UPDATE) || ARRAY[$3]::uuid[])`, "update:sessions"},
		{"the lock clause of a nested level", `UPDATE ctrlz.sessions SET revoked_at = now() WHERE id = ANY (ARRAY(SELECT id FROM ctrlz.sessions WHERE user_id = $2 AND x IN (SELECT 1 FROM ctrlz.users ORDER BY id FOR UPDATE) ORDER BY id))`, "update:sessions"},
		{"skip locked of the nested subselect", `UPDATE ctrlz.sms_outbox SET x = 1 WHERE id IN (SELECT id FROM ctrlz.sms_outbox WHERE y IN (SELECT 1 FROM ctrlz.users FOR UPDATE SKIP LOCKED) FOR UPDATE)`, "update:sms_outbox"},
		{"a skip locked subselect of the table, ordered", `UPDATE ctrlz.sms_outbox SET x = 1 WHERE id = ANY (ARRAY(SELECT id FROM ctrlz.sms_outbox WHERE y = 1 ORDER BY id LIMIT $1 FOR UPDATE SKIP LOCKED))`, "update:sms_outbox:ordered:skip"},
		{"a set operation", `UPDATE ctrlz.sessions SET x = 1 WHERE id IN (SELECT id FROM ctrlz.sessions ORDER BY id FOR UPDATE UNION SELECT id FROM ctrlz.sessions)`, "update:sessions"},
		{"a quoted table", `UPDATE "ctrlz"."sessions" SET revoked_at = now() WHERE user_id = $1`, "update:sessions"},
		// db-r17-2, -3 and -10: Keyed, Ordered and Pinned are read from the same grammar as the shape.
		{"an id and an OR branch is not one row", "UPDATE ctrlz.sessions SET revoked_at = now() WHERE id = $1 AND tenant_id = $2 OR revoked_at IS NULL", "update:sessions"},
		{"an OR before the id is not one row either", "UPDATE ctrlz.sessions SET revoked_at = now() WHERE revoked_at IS NULL OR tenant_id = $2 AND id = $1", "update:sessions"},
		{"an OR in a parenthesis does not break the conjunct", "UPDATE ctrlz.sessions SET revoked_at = now() WHERE id = $1 AND (tenant_id = $2 OR tenant_id = $3)", "update:sessions:keyed"},
		{"the id of a joined table is not the key of the write", "UPDATE ctrlz.refresh_tokens r SET revoked_at = now() FROM ctrlz.sessions s WHERE s.id = $2 AND r.session_id = s.id AND r.tenant_id = $1", "update:refresh_tokens"},
		{"a bare id beside a joined table is not read as the written table's", "UPDATE ctrlz.refresh_tokens r SET revoked_at = now() FROM ctrlz.sessions s WHERE id = $2 AND r.session_id = s.id", "update:refresh_tokens"},
		{"the id of the USING table of a DELETE", "DELETE FROM ctrlz.refresh_tokens r USING ctrlz.sessions s WHERE s.id = $2 AND r.session_id = s.id", "delete:refresh_tokens"},
		{"the alias of the target is its own id", "UPDATE ctrlz.refresh_tokens r SET revoked_at = now() FROM ctrlz.sessions s WHERE r.id = $2 AND r.session_id = s.id", "update:refresh_tokens:keyed"},
		{"the table name cannot qualify a column of an aliased target", "UPDATE ctrlz.sessions s SET revoked_at = now() WHERE ctrlz.sessions.id = $1", "update:sessions"},
		{"the table name qualifies a column of an unaliased target", "UPDATE ctrlz.sessions SET revoked_at = now() WHERE ctrlz.sessions.id = $1", "update:sessions:keyed"},
		{"ordered descending", "UPDATE ctrlz.sessions SET revoked_at = now() WHERE tenant_id = $1 AND id = ANY (ARRAY(SELECT id FROM ctrlz.sessions WHERE user_id = $2 ORDER BY id DESC FOR NO KEY UPDATE))", "update:sessions"},
		{"ordered by a cast of the id", "UPDATE ctrlz.sessions SET revoked_at = now() WHERE id = ANY (ARRAY(SELECT id FROM ctrlz.sessions WHERE user_id = $2 ORDER BY id::text FOR NO KEY UPDATE))", "update:sessions"},
		{"ordered by id USING >", "UPDATE ctrlz.sessions SET revoked_at = now() WHERE id = ANY (ARRAY(SELECT id FROM ctrlz.sessions WHERE user_id = $2 ORDER BY id USING > FOR NO KEY UPDATE))", "update:sessions"},
		{"ordered by id NULLS LAST", "UPDATE ctrlz.sessions SET revoked_at = now() WHERE id = ANY (ARRAY(SELECT id FROM ctrlz.sessions WHERE user_id = $2 ORDER BY id NULLS LAST FOR NO KEY UPDATE))", "update:sessions"},
		{"ordered ascending, spelled out, with limit and offset", "UPDATE ctrlz.sessions SET revoked_at = now() WHERE id = ANY (ARRAY(SELECT id FROM ctrlz.sessions WHERE user_id = $2 ORDER BY id ASC OFFSET 0 LIMIT $3 FOR NO KEY UPDATE))", "update:sessions:ordered"},
		{"ordered by the id of another table of the subselect", "UPDATE ctrlz.sessions SET revoked_at = now() WHERE id = ANY (ARRAY(SELECT s.id FROM ctrlz.sessions s JOIN ctrlz.users u ON u.id = s.user_id ORDER BY u.id FOR NO KEY UPDATE))", "update:sessions"},
		{"a join in the subselect", "UPDATE ctrlz.sessions SET revoked_at = now() WHERE id = ANY (ARRAY(SELECT s.id FROM ctrlz.sessions s JOIN ctrlz.users u ON u.id = s.user_id ORDER BY s.id FOR NO KEY UPDATE))", "update:sessions"},
		{"a comma item in the subselect", "UPDATE ctrlz.sessions SET revoked_at = now() WHERE id = ANY (ARRAY(SELECT s.id FROM ctrlz.sessions s, ctrlz.users u ORDER BY s.id FOR NO KEY UPDATE))", "update:sessions"},
		{"the outer key is the id of another alias", "UPDATE ctrlz.sessions s SET revoked_at = now() FROM ctrlz.users u WHERE u.id = ANY (ARRAY(SELECT id FROM ctrlz.sessions ORDER BY id FOR NO KEY UPDATE)) AND s.user_id = u.id", "update:sessions"},
		// The physical address of a locked row: an index (TID scan) finds it where a row comparison cannot.
		{"ctid of rows locked without waiting", "DELETE FROM ctrlz.auth_throttle t WHERE t.ctid = ANY (ARRAY(SELECT s.ctid FROM ctrlz.auth_throttle s WHERE s.window_start < now() LIMIT $1 FOR UPDATE SKIP LOCKED)) AND t.window_start < now()", "delete:auth_throttle:skip"},
		{"ctid of rows locked with waiting is neither", "DELETE FROM ctrlz.auth_throttle t WHERE t.ctid = ANY (ARRAY(SELECT s.ctid FROM ctrlz.auth_throttle s WHERE s.window_start < now() LIMIT $1 FOR UPDATE))", "delete:auth_throttle"},
		{"ctid is never ordered", "DELETE FROM ctrlz.sessions t WHERE t.ctid = ANY (ARRAY(SELECT s.ctid FROM ctrlz.sessions s ORDER BY s.id FOR UPDATE))", "delete:sessions"},
		{"ctid selected, id compared", "DELETE FROM ctrlz.sessions t WHERE t.id = ANY (ARRAY(SELECT s.ctid FROM ctrlz.sessions s FOR UPDATE SKIP LOCKED))", "delete:sessions"},
		{"a composite key with other names selected", "DELETE FROM ctrlz.auth_throttle t WHERE (t.scope, t.key) IN (SELECT s.key, s.scope FROM ctrlz.auth_throttle s FOR UPDATE SKIP LOCKED)", "delete:auth_throttle"},
	}
	for _, c := range cases {
		ws, err := lockrank.Writes(c.sql)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if got := shape(ws); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
	if _, err := lockrank.Writes(`SELECT $$x$$`); err == nil {
		t.Error("a text the lexer refuses was read")
	}
}

// TestWritesPinnedColumns: the columns a write equates to one parameter, which a caller that knows the unique
// keys of a table uses to tell one row from several (db-r16-21).
func TestWritesPinnedColumns(t *testing.T) {
	cases := []struct {
		name, sql string
		want      string
	}{
		{"a token hash and a kind", `UPDATE ctrlz.auth_tickets t SET consumed_at = now() WHERE t.token_hash = p_token_hash AND t.kind = p_kind AND t.consumed_at IS NULL`, "token_hash,kind"},
		{"a composite key", `UPDATE ctrlz.auth_throttle t SET count = 0 WHERE t.scope = p_scope AND t.key = p_key`, "scope,key"},
		{"a parameter on the left", `UPDATE ctrlz.sessions SET x = 1 WHERE $1 = tenant_id`, "tenant_id"},
		{"a join is not a pin", `UPDATE ctrlz.users u SET x = 1 FROM unnest($1::uuid[]) AS l(id) WHERE u.id = l.id`, ""},
		{"a literal is not a pin", `UPDATE ctrlz.auth_tickets t SET x = 1 WHERE t.kind = 'mfa'`, ""},
		{"an OR pins nothing", `UPDATE ctrlz.auth_tickets t SET x = 1 WHERE t.token_hash = p_a OR t.kind = p_b`, ""},
	}
	for _, c := range cases {
		ws, err := lockrank.Writes(c.sql)
		if err != nil || len(ws) != 1 {
			t.Fatalf("%s: %v %v", c.name, ws, err)
		}
		if got := strings.Join(ws[0].Pinned, ","); got != c.want {
			t.Errorf("%s: pinned %q, want %q", c.name, got, c.want)
		}
	}
}

// TestWritesPinnedColumnsOfTheWrittenTableOnly: a pin counts only for a column of the written table (db-r17-10).
func TestWritesPinnedColumnsOfTheWrittenTableOnly(t *testing.T) {
	cases := []struct{ name, sql, want string }{
		{"a joined table's column", "UPDATE ctrlz.refresh_tokens r SET x = 1 FROM ctrlz.sessions s WHERE s.id = $1 AND r.session_id = s.id", ""},
		{"the target's own column beside a join", "UPDATE ctrlz.refresh_tokens r SET x = 1 FROM ctrlz.sessions s WHERE r.id = $1 AND r.session_id = s.id", "id"},
		{"a bare column beside a join", "UPDATE ctrlz.refresh_tokens r SET x = 1 FROM ctrlz.sessions s WHERE tenant_id = $1 AND r.session_id = s.id", ""},
		{"an OR makes every pin empty", "UPDATE ctrlz.sessions SET x = 1 WHERE id = $1 AND tenant_id = $2 OR revoked_at IS NULL", ""},
	}
	for _, c := range cases {
		ws, err := lockrank.Writes(c.sql)
		if err != nil || len(ws) != 1 {
			t.Fatalf("%s: %v %v", c.name, ws, err)
		}
		if got := strings.Join(ws[0].Pinned, ","); got != c.want {
			t.Errorf("%s: pinned %q, want %q", c.name, got, c.want)
		}
	}
}

// TestWritesOrderedBy: the sort of the locking subselect, for a table whose key is not id (db-r17-4).
func TestWritesOrderedBy(t *testing.T) {
	cases := []struct{ name, sql, want string }{
		{"a composite key by ctid", "DELETE FROM ctrlz.auth_throttle t WHERE t.ctid = ANY (ARRAY(SELECT s.ctid FROM ctrlz.auth_throttle s WHERE s.scope = $1 ORDER BY s.scope, s.key FOR UPDATE))", "scope,key"},
		{"ascending spelled out", "DELETE FROM ctrlz.auth_throttle t WHERE t.ctid = ANY (ARRAY(SELECT s.ctid FROM ctrlz.auth_throttle s ORDER BY s.scope ASC, s.key ASC LIMIT 5 FOR UPDATE))", "scope,key"},
		{"the id", "DELETE FROM ctrlz.sessions WHERE id = ANY (ARRAY(SELECT id FROM ctrlz.sessions ORDER BY id FOR UPDATE))", "id"},
		{"a descending column", "DELETE FROM ctrlz.auth_throttle t WHERE t.ctid = ANY (ARRAY(SELECT s.ctid FROM ctrlz.auth_throttle s ORDER BY s.scope DESC, s.key FOR UPDATE))", ""},
		{"a nulls clause", "DELETE FROM ctrlz.auth_throttle t WHERE t.ctid = ANY (ARRAY(SELECT s.ctid FROM ctrlz.auth_throttle s ORDER BY s.scope NULLS LAST, s.key FOR UPDATE))", ""},
		{"a column of another table", "DELETE FROM ctrlz.auth_throttle t WHERE t.ctid = ANY (ARRAY(SELECT s.ctid FROM ctrlz.auth_throttle s ORDER BY x.scope FOR UPDATE))", ""},
		{"an expression", "DELETE FROM ctrlz.auth_throttle t WHERE t.ctid = ANY (ARRAY(SELECT s.ctid FROM ctrlz.auth_throttle s ORDER BY s.scope::text FOR UPDATE))", ""},
		{"no lock after the sort", "DELETE FROM ctrlz.auth_throttle t WHERE t.ctid = ANY (ARRAY(SELECT s.ctid FROM ctrlz.auth_throttle s ORDER BY s.scope, s.key))", ""},
		{"the sort after the lock", "DELETE FROM ctrlz.auth_throttle t WHERE t.ctid = ANY (ARRAY(SELECT s.ctid FROM ctrlz.auth_throttle s FOR UPDATE ORDER BY s.scope, s.key))", ""},
		{"an OR makes it nothing", "DELETE FROM ctrlz.auth_throttle t WHERE t.ctid = ANY (ARRAY(SELECT s.ctid FROM ctrlz.auth_throttle s ORDER BY s.scope, s.key FOR UPDATE)) OR t.count > 5", ""},
	}
	for _, c := range cases {
		ws, err := lockrank.Writes(c.sql)
		if err != nil || len(ws) != 1 {
			t.Fatalf("%s: %v %v", c.name, ws, err)
		}
		if got := strings.Join(ws[0].OrderedBy, ","); got != c.want {
			t.Errorf("%s: ordered by %q, want %q", c.name, got, c.want)
		}
	}
}

// TestWritesBatches: a bounded batch is read by the grammar of the lock shape, so the id of a joined table
// is not the key of the write (db-r17-14), and a cast of the parameter is still one row.
func TestWritesBatches(t *testing.T) {
	cases := []struct{ name, sql, want string }{
		{"a bounded batch", "DELETE FROM ctrlz.sessions WHERE id IN (SELECT id FROM ctrlz.sessions WHERE x < now() LIMIT $1)", "id:$1"},
		{"the limit is the subselect's own, up to FOR", "DELETE FROM ctrlz.sessions t WHERE t.id = ANY (ARRAY(SELECT s.id FROM ctrlz.sessions s ORDER BY s.id LIMIT LEAST(p_limit, 10) FOR UPDATE))", "id:least ( p_limit , 10 )"},
		{"a composite key", "DELETE FROM ctrlz.sms_counters WHERE (day, scope, key) IN (SELECT day, scope, key FROM ctrlz.sms_counters LIMIT $2)", "day,scope,key:$2"},
		{"no limit is no batch", "DELETE FROM ctrlz.sessions WHERE id IN (SELECT id FROM ctrlz.sessions WHERE x < now())", ""},
		{"a limit of a nested level is not the batch's", "DELETE FROM ctrlz.sessions WHERE id IN (SELECT id FROM ctrlz.sessions WHERE y IN (SELECT y FROM ctrlz.users LIMIT $1))", ""},
		{"the id of a joined table is not the key of the write", "UPDATE ctrlz.refresh_tokens r SET x = 1 FROM ctrlz.sessions s WHERE s.id IN (SELECT id FROM ctrlz.sessions LIMIT $1) AND r.session_id = s.id", ""},
		{"the written table's own alias", "UPDATE ctrlz.refresh_tokens r SET x = 1 FROM ctrlz.sessions s WHERE r.id IN (SELECT id FROM ctrlz.refresh_tokens LIMIT $1) AND r.session_id = s.id", "id:$1"},
		{"another table in the subselect", "DELETE FROM ctrlz.sessions WHERE id IN (SELECT id FROM ctrlz.invites LIMIT $1)", ""},
		{"an OR", "DELETE FROM ctrlz.sessions WHERE id IN (SELECT id FROM ctrlz.sessions LIMIT $1) OR x < now()", ""},
	}
	for _, c := range cases {
		ws, err := lockrank.Writes(c.sql)
		if err != nil || len(ws) != 1 {
			t.Fatalf("%s: %v %v", c.name, ws, err)
		}
		got := ""
		for _, b := range ws[0].Batches {
			got = strings.Join(b.Key, ",") + ":" + strings.Join(b.Limit, " ")
		}
		if got != c.want {
			t.Errorf("%s: batch %q, want %q", c.name, got, c.want)
		}
	}
	ws, _ := lockrank.Writes("UPDATE ctrlz.sessions SET x = 1 WHERE id = $2::uuid")
	if len(ws) != 1 || !ws[0].Keyed {
		t.Error("a cast of the parameter is not one row")
	}
	ws, _ = lockrank.Writes("UPDATE ctrlz.sessions SET x = 1 WHERE id = $2::uuid OR y = 1")
	if len(ws) != 1 || ws[0].Keyed {
		t.Error("a cast does not defeat the OR rule")
	}
}

// TestInserts: which INSERTs can add several rows, and which of those are sorted (db-r17-17).
func TestInserts(t *testing.T) {
	cases := []struct{ name, sql, want string }{
		{"one tuple", `INSERT INTO ctrlz.notifications (tenant_id, kind) VALUES ($1, $2)`, "notifications"},
		{"several tuples", `INSERT INTO ctrlz.sms_counters AS c (day, scope, key, count) VALUES (1, 'a', 'b', 1), (1, 'c', 'd', 1) ON CONFLICT (day, scope, key) DO UPDATE SET count = c.count + 1`, "sms_counters:multi"},
		{"default values", `INSERT INTO ctrlz.system_settings DEFAULT VALUES`, "system_settings"},
		{"a select", `INSERT INTO ctrlz.recovery_codes (tenant_id, user_id, code_hash) SELECT $1, $2, h FROM unnest($3::bytea[]) AS h`, "recovery_codes:multi"},
		{"a sorted select", `INSERT INTO ctrlz.recovery_codes (tenant_id, user_id, code_hash) SELECT $1, $2, h FROM unnest($3::bytea[]) AS h ORDER BY h`, "recovery_codes:multi:sorted"},
		{"sorted, then a conflict clause", `INSERT INTO ctrlz.policy_outbox (tenant_id, aggregate_type, aggregate_id, batch_id) SELECT t.id, 'x', t.id, $1 FROM (SELECT DISTINCT x AS id FROM unnest($2::uuid[]) AS x) t ORDER BY t.id ON CONFLICT DO NOTHING`, "policy_outbox:multi:sorted"},
		{"an ORDER BY of a nested level does not sort the insert", `INSERT INTO ctrlz.policy_outbox (tenant_id) SELECT t.id FROM (SELECT x AS id FROM unnest($2::uuid[]) AS x ORDER BY x) t ON CONFLICT DO NOTHING`, "policy_outbox:multi"},
		{"an ORDER BY after the conflict clause is not the insert's", `INSERT INTO ctrlz.policy_outbox (tenant_id) SELECT t.id FROM t ON CONFLICT DO UPDATE SET a = (SELECT 1 ORDER BY 1)`, "policy_outbox:multi"},
		{"a parenthesised query", `INSERT INTO ctrlz.notifications (tenant_id) (SELECT id FROM ctrlz.tenants)`, "notifications:multi"},
		{"a WITH source", `INSERT INTO ctrlz.notifications (tenant_id) WITH x AS (SELECT 1) SELECT * FROM x`, "notifications:multi"},
		{"an insert in a CTE and a function body", `WITH d AS (INSERT INTO ctrlz.notifications (tenant_id) SELECT id FROM ctrlz.tenants RETURNING 1) SELECT 1`, "notifications:multi"},
		{"two inserts", "INSERT INTO ctrlz.tenants (id) VALUES ($1); INSERT INTO ctrlz.users (tenant_id) SELECT id FROM ctrlz.tenants", "tenants users:multi"},
	}
	for _, c := range cases {
		is, err := lockrank.Inserts(c.sql)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		var parts []string
		for _, i := range is {
			s := i.Table
			if i.Multi {
				s += ":multi"
			}
			if i.Sorted {
				s += ":sorted"
			}
			parts = append(parts, s)
		}
		if got := strings.Join(parts, " "); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

// TestInsertsOfOneRowFromASelect: a SELECT with no FROM item adds one row, unless a function in it can return
// a set, which only a caller with the catalog can tell (db-r17-17).
func TestInsertsOfOneRowFromASelect(t *testing.T) {
	multi := func(is []lockrank.RowInsert, err error) bool {
		t.Helper()
		if err != nil || len(is) != 1 {
			t.Fatalf("%v %v", is, err)
		}
		return is[0].Multi
	}
	first := `INSERT INTO ctrlz.admin_users (username, password_hash) SELECT $1, $2 WHERE NOT EXISTS (SELECT 1 FROM ctrlz.admin_users) RETURNING id`
	if multi(lockrank.InsertsWith(first, func(string) bool { return false })) {
		t.Error("a SELECT of parameters with no FROM item is several rows")
	}
	withCall := `INSERT INTO ctrlz.admin_users (username, expires) SELECT p_username, pg_catalog.now() + interval '24 hours' WHERE NOT EXISTS (SELECT 1 FROM ctrlz.admin_users)`
	if !multi(lockrank.Inserts(withCall)) {
		t.Error("without the catalog, a call in the list is a possible set-returning function and must fail closed")
	}
	if multi(lockrank.InsertsWith(withCall, func(string) bool { return false })) {
		t.Error("the catalog says now() returns one row")
	}
	srf := `INSERT INTO ctrlz.notifications (tenant_id) SELECT pg_catalog.unnest($1::uuid[])`
	if !multi(lockrank.InsertsWith(srf, func(n string) bool { return n == "unnest" })) {
		t.Error("unnest in the list adds several rows")
	}
	if !multi(lockrank.Inserts(`INSERT INTO ctrlz.notifications (tenant_id) SELECT $1 UNION ALL SELECT $2`)) {
		t.Error("a set operation adds several rows")
	}
	if !multi(lockrank.Inserts(`INSERT INTO ctrlz.notifications (tenant_id) SELECT id FROM ctrlz.tenants`)) {
		t.Error("a FROM item adds several rows")
	}
}
