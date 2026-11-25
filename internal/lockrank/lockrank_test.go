package lockrank_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/lockrank"
)

func tables(ts []lockrank.Touch) string {
	var out []string
	for _, t := range ts {
		s := t.Table
		switch t.Mode {
		case lockrank.KeyShare:
			s += ":ks"
		case lockrank.Insert:
			s += ":ins"
		}
		if t.NoWait {
			s += ":skip"
		}
		out = append(out, s)
	}
	return strings.Join(out, " ")
}

func TestAnalyze(t *testing.T) {
	for _, c := range []struct {
		name, sql, want string
	}{
		{"a plain read takes nothing", `SELECT id FROM ctrlz.sessions WHERE id = $1`, ""},
		{"an update", `UPDATE ctrlz.sessions SET revoked_at = now() WHERE id = $1`, "sessions"},
		{"an insert takes key shares on its parents first", `INSERT INTO ctrlz.refresh_tokens (tenant_id, session_id, user_id) VALUES ($1, $2, $3)`, "users:ks sessions:ks refresh_tokens:ins"},
		{"FOR NO KEY UPDATE", `SELECT 1 FROM ctrlz.users WHERE id = $1 FOR NO KEY UPDATE`, "users"},
		{"FOR KEY SHARE", `SELECT 1 FROM ctrlz.users WHERE id = $1 FOR KEY SHARE`, "users:ks"},
		{"OF names the table that is locked", `SELECT 1 FROM ctrlz.users u JOIN ctrlz.tenants t ON t.id = u.tenant_id WHERE u.id = $1 FOR NO KEY UPDATE OF u`, "users"},
		{"without OF every table of the query is locked", `SELECT 1 FROM ctrlz.sessions s JOIN ctrlz.refresh_tokens r ON r.session_id = s.id FOR UPDATE`, "sessions refresh_tokens"},
		{"SKIP LOCKED never waits", `UPDATE ctrlz.otp_challenges o SET delivery_attempts = 1 WHERE o.id IN (SELECT c.id FROM ctrlz.otp_challenges c ORDER BY c.created_at LIMIT 5 FOR UPDATE SKIP LOCKED)`, "otp_challenges:skip otp_challenges:skip"},
		{"a lock in a subquery does not reach the outer tables", `SELECT 1 FROM ctrlz.sessions s WHERE s.id IN (SELECT r.session_id FROM ctrlz.refresh_tokens r FOR UPDATE)`, "refresh_tokens"},
		{"an upsert is a write on the conflicting row", `INSERT INTO ctrlz.sms_counters AS c (day, scope, key, count) VALUES ($1, $2, $3, 1) ON CONFLICT (day, scope, key) DO UPDATE SET count = c.count + 1`, "sms_counters"},
		{"DO NOTHING is an insert", `INSERT INTO ctrlz.alerts (severity, kind, params) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`, "alerts:ins"},
		{"the audit advisory lock", `SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('ctrlz.audit_log', 0))`, "audit_log"},
		{"the config log advisory lock", `SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('ctrlz.config_log', 0))`, "config_log"},
		{"a comment hides nothing and shows nothing", "-- FOR UPDATE ctrlz.users\nSELECT 1 /* UPDATE ctrlz.sessions */", ""},
		{"a string hides its words", `SELECT 'FOR UPDATE' FROM ctrlz.sessions`, ""},
		{"a function call applies the declared ranks", `SELECT * FROM ctrlz_fn.admin_reissue_one_time_password($1, $2)`, "users"},
		{"a plpgsql loop is not a lock", `FOR r IN SELECT 1 FROM ctrlz.sessions LOOP END LOOP`, ""},
		{"delete reaches the cascade", `DELETE FROM ctrlz.sessions WHERE id = $1`, "sessions refresh_tokens"},
		// db-r5-2: the same table written in the other ways Postgres accepts.
		{"a quoted schema and table", `UPDATE "ctrlz"."sessions" SET revoked_at = now() WHERE id = $1`, "sessions"},
		{"spaces around the dot", `UPDATE ctrlz . sessions SET revoked_at = now() WHERE id = $1`, "sessions"},
		{"a CTE name is a from-list item", `WITH s AS (SELECT id FROM ctrlz.sessions) UPDATE ctrlz.refresh_tokens SET revoked_at = now() WHERE session_id IN (SELECT id FROM s)`, "refresh_tokens"},
		{"functions and catalogs are from-list items", `SELECT x FROM unnest($1::uuid[]) AS x, pg_catalog.pg_class c`, ""},
		{"FROM inside EXTRACT and TRIM is syntax", `SELECT EXTRACT(EPOCH FROM now() - created_at), TRIM(BOTH ' ' FROM name) FROM ctrlz.sessions`, ""},
		{"IS DISTINCT FROM is an operator", `SELECT 1 FROM ctrlz.sessions WHERE a IS DISTINCT FROM b`, ""},
		{"INTO of a plpgsql select is a variable", `SELECT id INTO v_id FROM ctrlz.sessions WHERE id = $1`, ""},
		{"DELETE USING a ctrlz table", `DELETE FROM ctrlz.sessions s USING ctrlz.users u WHERE u.id = s.user_id`, "sessions refresh_tokens"},
		// db-r6-2: ONLY names the same table, and the readers looked at the word before it.
		{"UPDATE ONLY", `UPDATE ONLY ctrlz.sessions SET revoked_at = now() WHERE id = $1`, "sessions"},
		{"DELETE FROM ONLY reaches the cascade", `DELETE FROM ONLY ctrlz.sessions WHERE id = $1`, "sessions refresh_tokens"},
		{"an update followed by a comment", "UPDATE ctrlz.sessions /* why */ SET revoked_at = now() WHERE id = $1", "sessions"},
	} {
		got, err := lockrank.Analyze(c.sql)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if g := tables(got); g != c.want {
			t.Errorf("%s: got %q, want %q", c.name, g, c.want)
		}
	}
}

func TestAnalyzeRefuses(t *testing.T) {
	for _, c := range []struct{ name, sql string }{
		{"an unranked table", `UPDATE ctrlz.brand_new SET a = 1`},
		{"an unranked table in a lock clause", `SELECT 1 FROM ctrlz.brand_new FOR UPDATE`},
		{"a function with no declared ranks", `SELECT * FROM ctrlz_fn.brand_new($1)`},
		{"an advisory lock on an unranked key", `SELECT pg_advisory_xact_lock(42)`},
		{"a session-level advisory lock", `SELECT pg_advisory_lock(1)`},
		{"a lock clause with no table", `SELECT 1 FOR UPDATE`},
		{"dollar quoting", `SELECT $$x$$ FROM ctrlz.sessions`},
		// db-r5-2: the search_path finds a table written without its schema, the
		// lock order did not. Each shape below ran in the database and was classified
		// as touching nothing.
		{"an update without the schema", `UPDATE sessions SET revoked_at = now() WHERE id = $1`},
		{"an insert without the schema", `INSERT INTO refresh_tokens (tenant_id, session_id, user_id) VALUES ($1, $2, $3)`},
		{"a delete without the schema", `DELETE FROM users WHERE id = $1`},
		{"a delete using a table without the schema", `DELETE FROM ctrlz.sessions s USING users u WHERE u.id = s.user_id`},
		{"a lock on a table without the schema", `SELECT 1 FROM sessions WHERE id = $1 FOR UPDATE`},
		{"a join without the schema", `SELECT 1 FROM ctrlz.sessions s JOIN users u ON u.id = s.user_id`},
		{"a second from-list item without the schema", `SELECT 1 FROM ctrlz.sessions s, users u WHERE u.id = s.user_id`},
		{"a subquery table without the schema", `SELECT 1 FROM ctrlz.sessions WHERE user_id IN (SELECT id FROM users)`},
		{"an update from a table without the schema", `UPDATE ctrlz.sessions s SET revoked_at = now() FROM users u WHERE u.id = s.user_id`},
		{"another schema", `UPDATE other.sessions SET a = 1`},
		{"a quoted table without the schema", `UPDATE "sessions" SET a = 1`},
		{"a quoted name that is not the table", `UPDATE "ctrlz"."Sessions" SET a = 1`},
		{"a merge target", `MERGE INTO sessions USING ctrlz.users ON true WHEN MATCHED THEN DO NOTHING`},
		{"a merge into a ranked table", `MERGE INTO ctrlz.users u USING ctrlz.sessions s ON true WHEN MATCHED THEN DELETE`},
		{"a merge into a quoted table", `MERGE INTO "ctrlz"."users" USING ctrlz.sessions s ON true WHEN MATCHED THEN DELETE`},
		{"truncate", `TRUNCATE ctrlz.sessions`},
		{"lock table", `LOCK TABLE ctrlz.sessions IN ACCESS EXCLUSIVE MODE`},
		{"a write whose target is a subquery", `UPDATE (SELECT 1) SET a = 1`},
	} {
		if _, err := lockrank.Analyze(c.sql); err == nil {
			t.Errorf("%s: no error", c.name)
		}
	}
}

func apply(t *testing.T, st *lockrank.State, sql string) error {
	t.Helper()
	ts, err := lockrank.Analyze(sql)
	if err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
	return st.Acquire(ts)
}

func TestStateOrder(t *testing.T) {
	const (
		lockUser    = `SELECT 1 FROM ctrlz.users WHERE id = $1 FOR NO KEY UPDATE`
		keyShare    = `SELECT 1 FROM ctrlz.users WHERE id = $1 FOR KEY SHARE`
		lockSession = `SELECT 1 FROM ctrlz.sessions WHERE id = $1 FOR UPDATE`
		rotate      = `UPDATE ctrlz.refresh_tokens SET rotated_at = now() WHERE id = $1`
		touchSess   = `UPDATE ctrlz.sessions SET idle_expires_at = $2 WHERE id = $1`
		newRefresh  = `INSERT INTO ctrlz.refresh_tokens (tenant_id, session_id, user_id) VALUES ($1, $2, $3)`
		audit       = `SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('ctrlz.audit_log', 0))`
		setNotice   = `UPDATE ctrlz.admin_users SET pending_notice = $2 WHERE id = $1`
		setGateway  = `UPDATE ctrlz.sms_gateways SET credentials_ct = $2 WHERE id = $1`
	)
	t.Run("the order of spec 4.4 passes", func(t *testing.T) {
		var st lockrank.State
		for _, q := range []string{lockUser, lockSession, rotate, newRefresh} {
			if err := apply(t, &st, q); err != nil {
				t.Fatalf("%s: %v", q, err)
			}
		}
	})
	t.Run("a lock already held can be asked for again", func(t *testing.T) {
		// Refresh: the user's key share first, so the key share its new refresh row
		// takes later is one it already holds.
		var st lockrank.State
		for _, q := range []string{keyShare, lockSession, rotate, touchSess, newRefresh} {
			if err := apply(t, &st, q); err != nil {
				t.Fatalf("%s: %v", q, err)
			}
		}
	})
	t.Run("the refresh insert without the user first is refused", func(t *testing.T) {
		// The db-r4-1 shape: the session is held and the insert wants the user.
		var st lockrank.State
		if err := apply(t, &st, lockSession); err != nil {
			t.Fatal(err)
		}
		err := apply(t, &st, newRefresh)
		var oe *lockrank.OrderError
		if !errors.As(err, &oe) || oe.Table != "users" {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("a key share is not an upgrade path", func(t *testing.T) {
		var st lockrank.State
		for _, q := range []string{keyShare, lockSession} {
			if err := apply(t, &st, q); err != nil {
				t.Fatal(err)
			}
		}
		if err := apply(t, &st, lockUser); err == nil {
			t.Fatal("NO KEY UPDATE after a key share and a session lock was allowed")
		}
	})
	t.Run("the audit lock is last", func(t *testing.T) {
		var st lockrank.State
		for _, q := range []string{setNotice, setGateway, audit} {
			if err := apply(t, &st, q); err != nil {
				t.Fatalf("%s: %v", q, err)
			}
		}
		var late lockrank.State
		if err := apply(t, &late, audit); err != nil {
			t.Fatal(err)
		}
		if err := apply(t, &late, setNotice); err == nil {
			t.Fatal("an admin row after the audit lock was allowed (admin-r3-3)")
		}
	})
	t.Run("a gateway after the audit lock is refused", func(t *testing.T) {
		var st lockrank.State
		if err := apply(t, &st, audit); err != nil {
			t.Fatal(err)
		}
		if err := apply(t, &st, setGateway); err == nil {
			t.Fatal("sms_gateways after the audit lock was allowed")
		}
	})
	t.Run("a statement that never waits is not refused", func(t *testing.T) {
		var st lockrank.State
		if err := apply(t, &st, setGateway); err != nil {
			t.Fatal(err)
		}
		const claim = `UPDATE ctrlz.otp_challenges o SET delivery_attempts = 1 WHERE o.id IN (SELECT c.id FROM ctrlz.otp_challenges c LIMIT 5 FOR UPDATE SKIP LOCKED)`
		ts, err := lockrank.Analyze(claim)
		if err != nil {
			t.Fatal(err)
		}
		var skip []lockrank.Touch
		for _, x := range ts {
			if x.NoWait {
				skip = append(skip, x)
			}
		}
		if len(skip) == 0 {
			t.Fatal("the claim has no SKIP LOCKED touch")
		}
		if err := st.Acquire(skip); err != nil {
			t.Fatalf("SKIP LOCKED was refused: %v", err)
		}
	})
	t.Run("inserts are trusted", func(t *testing.T) {
		var st lockrank.State
		if err := apply(t, &st, audit); err != nil {
			t.Fatal(err)
		}
		if err := apply(t, &st, `INSERT INTO ctrlz.alerts (severity, kind, params) VALUES ($1, $2, $3)`); err != nil {
			t.Fatalf("an insert after the audit lock: %v", err)
		}
	})
}

func TestDeclareRoundTrip(t *testing.T) {
	ts, err := lockrank.Analyze(`SELECT 1 FROM ctrlz.users u WHERE u.id = $1 FOR NO KEY UPDATE; INSERT INTO ctrlz.notifications (tenant_id) VALUES ($1); UPDATE ctrlz.users SET locale = 'fa'`)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(lockrank.Declare(ts), ",")
	if got != "users,notifications:ins" {
		t.Fatalf("got %q", got)
	}
	back, err := lockrank.ParseDeclared(lockrank.Declare(ts))
	if err != nil || tables(back) != "users notifications:ins" {
		t.Fatalf("parsed %q %v", tables(back), err)
	}
}

func mustRank(t *testing.T, table string) lockrank.Rank {
	t.Helper()
	r, ok := lockrank.Of(table)
	if !ok {
		t.Fatalf("%s has no rank", table)
	}
	return r
}

// TestTheOrderOfSpec44 pins the ladder the spec states in prose: users, tickets, sessions,
// refresh tokens, other per-user rows, gateways, counters, the audit log.
func TestTheOrderOfSpec44(t *testing.T) {
	ladder := []string{"users", "recovery_codes", "auth_tickets", "sessions", "refresh_tokens", "api_tokens", "sms_gateways", "sms_counters", "audit_log"}
	for i := 1; i < len(ladder); i++ {
		if mustRank(t, ladder[i-1]) >= mustRank(t, ladder[i]) {
			t.Errorf("%s must rank before %s", ladder[i-1], ladder[i])
		}
	}
	for _, name := range lockrank.Tables() {
		if _, ok := lockrank.Of(name); !ok {
			t.Errorf("%s is listed but has no rank", name)
		}
	}
}

func targetList(ts []lockrank.Target) string {
	var out []string
	for _, t := range ts {
		out = append(out, string(t.Verb)+":"+t.Table)
	}
	return strings.Join(out, " ")
}

// TestTargets is the reader behind catalog check 23: every legal way to write a table is read
// as the table and the verb, and a write it cannot read is an error, never "writes nothing"
// (db-r6-2).
func TestTargets(t *testing.T) {
	for _, c := range []struct{ name, sql, want string }{
		{"plain", `INSERT INTO ctrlz.sessions (a) VALUES (1); UPDATE ctrlz.users SET a = 1; DELETE FROM ctrlz.recovery_codes`, "insert:sessions update:users delete:recovery_codes"},
		{"upper case and ONLY", `UPDATE ONLY ctrlz.sessions SET a = 1; DELETE FROM ONLY CTRLZ.USERS`, "update:sessions delete:users"},
		{"quoted lower case", `UPDATE "ctrlz"."sessions" SET a = 1`, "update:sessions"},
		{"spaces around the dot", `UPDATE ctrlz . sessions SET a = 1`, "update:sessions"},
		{"a block comment between the verb and the table", "UPDATE /* why */ ctrlz.sessions SET a = 1", "update:sessions"},
		{"a block comment after the table", "UPDATE ctrlz.sessions /* why */ SET a = 1", "update:sessions"},
		{"a line comment hides a write", "-- UPDATE ctrlz.sessions\nSELECT 1", ""},
		{"a string hides a write", `SELECT 'UPDATE ctrlz.sessions'`, ""},
		{"a lock clause is not a write", `SELECT 1 FROM ctrlz.users FOR UPDATE; SELECT 1 FROM ctrlz.users FOR NO KEY UPDATE`, ""},
		{"DO UPDATE is the write of its insert", `INSERT INTO ctrlz.sms_counters (a) VALUES (1) ON CONFLICT (a) DO UPDATE SET b = 1`, "insert:sms_counters"},
		{"a write in a CTE", `WITH x AS (UPDATE ctrlz.sessions SET a = 1 RETURNING id) SELECT * FROM x`, "update:sessions"},
	} {
		got, err := lockrank.Targets(c.sql)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if g := targetList(got); g != c.want {
			t.Errorf("%s: got %q, want %q", c.name, g, c.want)
		}
	}
	for _, c := range []struct{ name, sql string }{
		{"merge", `MERGE INTO ctrlz.users u USING ctrlz.sessions s ON true WHEN MATCHED THEN DELETE`},
		{"a quoted capitalised table", `INSERT INTO ctrlz."Users" (a) VALUES (1)`},
		{"an unqualified table", `UPDATE sessions SET a = 1`},
		{"another schema", `DELETE FROM other.sessions`},
		{"dynamic SQL", `EXECUTE format('UPDATE ctrlz.%I SET a = 1', 'sessions')`},
		{"truncate", `TRUNCATE ctrlz.sessions`},
		{"a parenthesis as a target", `UPDATE (SELECT 1) SET a = 1`},
	} {
		if _, err := lockrank.Targets(c.sql); err == nil {
			t.Errorf("%s: no error; a write that cannot be read must be refused", c.name)
		}
	}
}

// TestSetColumns is the reader behind the body half of catalog check 21 (db-r9-5): the columns a
// SET list assigns, on the lexer of Analyze and Targets.
func TestSetColumns(t *testing.T) {
	render := func(ws []lockrank.SetWrite) string {
		var out []string
		for _, w := range ws {
			out = append(out, w.Table+":"+strings.Join(w.Cols, "+"))
		}
		return strings.Join(out, " ")
	}
	for _, c := range []struct{ name, sql, want string }{
		{"one column", `UPDATE ctrlz.admin_users SET username = 'x' WHERE id = 1`, "admin_users:username"},
		{"several, with function calls and commas inside them", `UPDATE ctrlz.admin_users SET a = coalesce(b, c), d = 1, e = (SELECT x, y FROM ctrlz.t) WHERE true`, "admin_users:a+d+e"},
		{"a qualified column and an alias", `UPDATE ctrlz.admin_users AS u SET u.username = 'x'`, "admin_users:username"},
		{"an alias with no AS", `UPDATE ctrlz.admin_users u SET username = 'x' RETURNING id`, "admin_users:username"},
		{"a column list", `UPDATE ctrlz.tenants SET (id, name) = (1, 'x')`, "tenants:id+name"},
		{"quoted, upper case and ONLY", `UPDATE ONLY CTRLZ."admin_users" SET "username" = 'x'`, "admin_users:username"},
		{"the DO UPDATE arm of an insert", `INSERT INTO ctrlz.admin_users (id) VALUES (1) ON CONFLICT (id) DO UPDATE SET username = excluded.username, a = 1`, "admin_users:username+a"},
		{"IS DISTINCT FROM is an operator", `UPDATE ctrlz.t SET a = b IS DISTINCT FROM c, d = 1 WHERE true`, "t:a+d"},
		{"an array literal", `UPDATE ctrlz.t SET a = ARRAY[1, 2], b = 3`, "t:a+b"},
		{"a lock clause is not an update", `SELECT 1 FROM ctrlz.admin_users FOR UPDATE; SELECT 1 FROM ctrlz.admin_users FOR NO KEY UPDATE`, ""},
		{"a string and a comment hide nothing and add nothing", "-- UPDATE ctrlz.t SET a = 1\nSELECT 'UPDATE ctrlz.t SET a = 1'", ""},
		{"an update in a CTE ends at the parenthesis", `WITH x AS (UPDATE ctrlz.t SET a = 1 RETURNING id) SELECT * FROM x`, "t:a"},
	} {
		got, err := lockrank.SetColumns(c.sql)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if g := render(got); g != c.want {
			t.Errorf("%s: got %q, want %q", c.name, g, c.want)
		}
	}
	for _, c := range []struct{ name, sql string }{
		{"an unqualified table", `UPDATE admin_users SET username = 'x'`},
		{"no SET", `UPDATE ctrlz.admin_users WHERE true`},
		{"DO UPDATE with no insert", `ON CONFLICT DO UPDATE SET a = 1`},
		{"dynamic SQL", `EXECUTE format('UPDATE ctrlz.%I SET a = 1', 'admin_users')`},
		{"merge", `MERGE INTO ctrlz.users u USING ctrlz.sessions s ON true WHEN MATCHED THEN DELETE`},
		{"a parenthesis as a target", `UPDATE (SELECT 1) SET a = 1`},
	} {
		if got, err := lockrank.SetColumns(c.sql); err == nil {
			t.Errorf("%s: read as %v instead of refused", c.name, got)
		}
	}
}
