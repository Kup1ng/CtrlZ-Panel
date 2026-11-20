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
