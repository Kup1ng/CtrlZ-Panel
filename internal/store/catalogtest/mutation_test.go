package catalogtest_test

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store/catalogtest"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

// mutation breaks the database in one way. want names the catalog check that
// must notice (the spec's number), so that a mutation caught only by an
// unrelated check still fails the meta-test.
type mutation struct {
	name string
	sql  []string
	want string
}

// firstViolation runs the catalog checks in order and stops at the first one
// that reports anything.
func firstViolation(ctx context.Context, q catalogtest.Querier, fx *catalogtest.Fixtures) (id string, violations []string, err error) {
	for _, ck := range catalogtest.Checks() {
		v, err := ck.Run(ctx, q, fx)
		if err != nil {
			return ck.ID, nil, fmt.Errorf("check %s could not run: %w", ck.ID, err)
		}
		if len(v) > 0 {
			return ck.ID, v, nil
		}
	}
	return "", nil, nil
}

// TestMutations is spec test 26, the proof that the catalog test can fail.
// Each mutation drops or loosens one thing the isolation depends on, inside a
// transaction that is rolled back, and the checks must notice. A mutation that
// nothing catches fails the build: it means a guard can be removed unseen.
func TestMutations(t *testing.T) {
	c := testpg.Need(t, cluster)
	h := newHarness(t, c)
	ctx := h.ctx
	fx := h.fx
	conn := h.super
	if _, err := conn.Exec(ctx, "SET search_path = pg_catalog"); err != nil {
		t.Fatal(err)
	}

	// Baseline: the unmutated database is clean, or nothing below means anything.
	if id, v, err := firstViolation(ctx, conn, fx); err != nil || len(v) > 0 {
		t.Fatalf("baseline is not clean (check %s): %v %v", id, v, err)
	}

	var muts []mutation
	// reAdd drops a constraint and adds it back with its own deparsed text and one more word, so the
	// constraint is what it was except for the one property under test.
	reAdd := func(tbl, name, suffix string) string {
		return fmt.Sprintf(`DO $m$ DECLARE d text; BEGIN
  SELECT pg_catalog.pg_get_constraintdef(c.oid) INTO d FROM pg_catalog.pg_constraint c
   WHERE c.conname = %s AND c.conrelid = %s::regclass;
  EXECUTE pg_catalog.format('ALTER TABLE ctrlz.%%I DROP CONSTRAINT %%I', %s, %s);
  EXECUTE pg_catalog.format('ALTER TABLE ctrlz.%%I ADD CONSTRAINT %%I %%s %s', %s, %s, d);
END $m$`, quoteLit(name), quoteLit("ctrlz."+pgx.Identifier{tbl}.Sanitize()), quoteLit(tbl), quoteLit(name), suffix, quoteLit(tbl), quoteLit(name))
	}
	add := func(name, want string, sql ...string) { muts = append(muts, mutation{name, sql, want}) }

	// Row level security.
	for _, tbl := range fx.Tables.Tenant {
		q := ident(tbl)
		add("drop tenant_isolation on "+tbl, "03", "DROP POLICY tenant_isolation ON "+q)
		add("remove FORCE from "+tbl, "02", "ALTER TABLE "+q+" NO FORCE ROW LEVEL SECURITY")
		add("disable RLS on "+tbl, "02", "ALTER TABLE "+q+" DISABLE ROW LEVEL SECURITY")
		add("USING (true) on "+tbl, "03", "ALTER POLICY tenant_isolation ON "+q+" USING (true)")
		add("WITH CHECK (true) on "+tbl, "03", "ALTER POLICY tenant_isolation ON "+q+" WITH CHECK (true)")
	}
	for _, p := range fx.Policies.Named {
		q := ident(p.Table)
		add("drop policy "+p.Table+"."+p.Name, "05", "DROP POLICY "+pgx.Identifier{p.Name}.Sanitize()+" ON "+q)
	}
	add("a policy USING (true) TO PUBLIC", "05", "CREATE POLICY leak ON ctrlz.users USING (true)")
	add("a new named policy for a role", "05", "CREATE POLICY extra ON ctrlz.sessions FOR SELECT TO ctrlz_hub USING (true)")

	// Composite foreign keys, read from the live catalog.
	rows, err := conn.Query(ctx, `
SELECT cl.relname, c.conname FROM pg_constraint c JOIN pg_class cl ON cl.oid = c.conrelid JOIN pg_class pl ON pl.oid = c.confrelid
WHERE c.contype = 'f' AND c.connamespace = 'ctrlz'::regnamespace AND cl.relname <> 'tenants' AND pl.relname <> 'tenants'
ORDER BY 1, 2`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var tbl, name string
		if err := rows.Scan(&tbl, &name); err != nil {
			t.Fatal(err)
		}
		add("drop foreign key "+name, "07", "ALTER TABLE "+ident(tbl)+" DROP CONSTRAINT "+pgx.Identifier{name}.Sanitize())
		// PG18 stores a row the key would refuse when the key is NOT ENFORCED, or NOT VALID for the rows that
		// exist (db-r13-3). The first is one ALTER; the second re-adds the key with its own text.
		add("foreign key "+name+" becomes NOT ENFORCED", "07", "ALTER TABLE "+ident(tbl)+" ALTER CONSTRAINT "+pgx.Identifier{name}.Sanitize()+" NOT ENFORCED")
		add("foreign key "+name+" is re-added NOT VALID", "07", reAdd(tbl, name, "NOT VALID"))
	}
	rows.Close()

	// Grants: take away every entry of grants.yaml, one at a time.
	for _, tbl := range sortedTables(fx) {
		for _, short := range sortedRoles(fx.Grants.Tables[tbl]) {
			add(fmt.Sprintf("revoke %s on %s", short, tbl), "12", fmt.Sprintf("REVOKE ALL ON %s FROM ctrlz_%s", ident(tbl), short))
		}
	}
	add("grant SELECT on users to PUBLIC", "12", "GRANT SELECT ON ctrlz.users TO PUBLIC")
	add("grant SELECT on users to the hub", "12", "GRANT SELECT ON ctrlz.users TO ctrlz_hub")
	add("grant SELECT (password_hash) to the tenant", "12", "GRANT SELECT (password_hash) ON ctrlz.users TO ctrlz_tenant")
	add("grant UPDATE (admin_hold) to the tenant", "12", "GRANT UPDATE (admin_hold) ON ctrlz.endpoints TO ctrlz_tenant")
	add("grant TRUNCATE to the tenant", "12", "GRANT TRUNCATE ON ctrlz.rules TO ctrlz_tenant")
	add("grant on a sequence", "12", "CREATE SEQUENCE ctrlz.s1", "GRANT USAGE ON SEQUENCE ctrlz.s1 TO PUBLIC")
	add("grant CREATE on ctrlz", "12", "GRANT CREATE ON SCHEMA ctrlz TO ctrlz_tenant")
	add("grant USAGE on ctrlz_ext", "12", "GRANT USAGE ON SCHEMA ctrlz_ext TO ctrlz_tenant")
	add("grant EXECUTE on current_tenant_id to PUBLIC", "12", "GRANT EXECUTE ON FUNCTION ctrlz.current_tenant_id() TO PUBLIC")
	add("grant TEMP on the database to PUBLIC", "12", "GRANT TEMPORARY ON DATABASE "+pgx.Identifier{h.db.Name}.Sanitize()+" TO PUBLIC")
	add("tenant writes first_query_at", "12", "GRANT UPDATE (first_query_at) ON ctrlz.endpoints TO ctrlz_tenant")

	// Views.
	for _, v := range fx.Views.Views {
		add("view "+v+" loses security_invoker", "14", "ALTER VIEW "+ident(v)+" SET (security_invoker = false)")
	}
	add("a materialized view", "14", "CREATE MATERIALIZED VIEW ctrlz.mv AS SELECT 1 AS x")
	add("an unlisted view", "14", "CREATE VIEW ctrlz.v2 WITH (security_invoker = true) AS SELECT 1 AS x")

	// SECURITY DEFINER.
	for _, f := range fx.Functions.SecurityDefiner {
		sig := fmt.Sprintf("ctrlz_fn.%s(%s)", f.Name, f.Args)
		add("function "+f.Name+" loses its search_path", "10", "ALTER FUNCTION "+sig+" RESET search_path")
		add("function "+f.Name+" is executable by PUBLIC", "10", "GRANT EXECUTE ON FUNCTION "+sig+" TO PUBLIC")
		add("function "+f.Name+" is executable by the hub", "10", "GRANT EXECUTE ON FUNCTION "+sig+" TO ctrlz_hub")
		add("function "+f.Name+" loses SECURITY DEFINER", "10", "ALTER FUNCTION "+sig+" SECURITY INVOKER")
		add("function "+f.Name+" changes owner", "09", "ALTER FUNCTION "+sig+" OWNER TO ctrlz_migrator")
	}
	// Lock order (check 21). Each rewrites a body with its own definition, so the
	// function stays what it was except for the one change.
	rewrite := func(sig, from, to string) string {
		return fmt.Sprintf(`DO $m$ DECLARE d text; BEGIN
  d := pg_catalog.pg_get_functiondef('%s'::regprocedure);
  IF pg_catalog.strpos(d, '%s') = 0 THEN RAISE EXCEPTION 'mutation does not apply'; END IF;
  EXECUTE pg_catalog.replace(d, '%s', '%s');
END $m$`, sig, from, from, to)
	}
	add("a one-time password lock back to FOR UPDATE", "21",
		rewrite("ctrlz_fn.admin_reissue_one_time_password(uuid, text)", "FOR NO KEY UPDATE OF u", "FOR UPDATE OF u"))
	add("a phone verification locks the user FOR UPDATE", "21",
		rewrite("ctrlz_fn.auth_phone_mark_verified(uuid, uuid)", "FOR NO KEY UPDATE;", "FOR UPDATE;"))
	add("a function locks a row its ranks do not declare", "21",
		rewrite("ctrlz_fn.auth_phone_mark_verified(uuid, uuid)", "WHERE u.tenant_id = v_tenant AND u.id = p_user_id AND u.phone_verified_at IS NULL;",
			"WHERE u.tenant_id = v_tenant AND u.id = p_user_id AND u.phone_verified_at IS NULL; UPDATE ctrlz.sessions SET revoked_at = revoked_at WHERE tenant_id = v_tenant;"))
	add("a function locks the request before the user", "21",
		rewrite("ctrlz_fn.auth_phone_change_complete(uuid)", "SELECT p.user_id INTO v_user\n  FROM ctrlz.phone_change_requests p\n  WHERE p.tenant_id = v_tenant AND p.id = p_request_id;",
			"SELECT p.user_id INTO v_user\n  FROM ctrlz.phone_change_requests p\n  WHERE p.tenant_id = v_tenant AND p.id = p_request_id FOR UPDATE;"))
	add("an extra SECURITY DEFINER function", "10",
		"CREATE FUNCTION ctrlz.evil() RETURNS int LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog AS 'SELECT 1'")
	add("an extra function in ctrlz_fn", "10",
		"SET LOCAL ROLE ctrlz_auth", "CREATE FUNCTION ctrlz_fn.helper() RETURNS int LANGUAGE sql AS 'SELECT 1'", "RESET ROLE")
	add("an unlisted helper in ctrlz", "11", "CREATE FUNCTION ctrlz.sneaky() RETURNS int LANGUAGE sql AS 'SELECT 1'")
	// The delete guards are triggers, and check 11 reads them: one that is gone
	// or switched off must be noticed.
	add("the guard of suspended claims is disabled", "11", "ALTER TABLE ctrlz.ip_claims DISABLE TRIGGER suspended_claim_stays")
	add("the promotion of Profile 2 is dropped", "11", "DROP TRIGGER promote_profile2 ON ctrlz.profiles")
	add("revocation of sessions can be undone again", "11", "ALTER TABLE ctrlz.sessions DISABLE TRIGGER revocation_stays")
	add("revocation of refresh tokens can be undone again", "11", "DROP TRIGGER revocation_stays ON ctrlz.refresh_tokens")
	add("revocation of API tokens can be undone again", "11", "ALTER TABLE ctrlz.api_tokens DISABLE TRIGGER revocation_stays")
	add("the admin role may declare a user key lost", "10", "GRANT EXECUTE ON FUNCTION ctrlz_fn.keytool_totp_declare_lost(integer, uuid[], bytea[]) TO ctrlz_admin")
	add("the worker may declare a user key lost", "10", "GRANT EXECUTE ON FUNCTION ctrlz_fn.keytool_totp_declare_lost(integer, uuid[], bytea[]) TO ctrlz_worker")
	// What a login role reaches in pg_catalog (check 30, db-r14-3 and db-r14-4): the advisory locks, the
	// statistics, the lock views, the sizes and the WAL position. Each plants one privilege the bootstrap took
	// away, or takes away the one it gave back.
	for _, g := range []struct{ name, sql string }{
		{"PUBLIC may call pg_advisory_lock", "GRANT EXECUTE ON FUNCTION pg_catalog.pg_advisory_lock(bigint) TO PUBLIC"},
		{"the tenant role may hold a session advisory lock", "GRANT EXECUTE ON FUNCTION pg_catalog.pg_advisory_lock(bigint) TO ctrlz_tenant"},
		{"the hub may take a transaction advisory lock", "GRANT EXECUTE ON FUNCTION pg_catalog.pg_advisory_xact_lock(bigint) TO ctrlz_hub"},
		{"the admin role may take a transaction advisory lock", "GRANT EXECUTE ON FUNCTION pg_catalog.pg_advisory_xact_lock(bigint) TO ctrlz_admin"},
		{"PUBLIC may try an advisory lock on two integers", "GRANT EXECUTE ON FUNCTION pg_catalog.pg_try_advisory_xact_lock(integer, integer) TO PUBLIC"},
		{"the worker may release every advisory lock", "GRANT EXECUTE ON FUNCTION pg_catalog.pg_advisory_unlock_all() TO ctrlz_worker"},
		{"the definer owner loses the transaction lock", "REVOKE EXECUTE ON FUNCTION pg_catalog.pg_advisory_xact_lock(bigint) FROM ctrlz_auth"},
		{"the migrator loses the session locker", "REVOKE EXECUTE ON FUNCTION pg_catalog.pg_try_advisory_lock(bigint) FROM ctrlz_migrator"},
		{"PUBLIC may read the statistics of every table", "GRANT SELECT ON pg_catalog.pg_stat_all_tables TO PUBLIC"},
		{"the hub may read the database statistics", "GRANT SELECT ON pg_catalog.pg_stat_database TO ctrlz_hub"},
		{"the compiler may read the session list", "GRANT SELECT ON pg_catalog.pg_stat_activity TO ctrlz_compiler"},
		{"the worker may read the lock table", "GRANT SELECT ON pg_catalog.pg_locks TO ctrlz_worker"},
		{"PUBLIC may read the rows inserted into a table", "GRANT EXECUTE ON FUNCTION pg_catalog.pg_stat_get_tuples_inserted(oid) TO PUBLIC"},
		{"the compiler may call a statistics function", "GRANT EXECUTE ON FUNCTION pg_catalog.pg_stat_get_db_tuples_inserted(oid) TO ctrlz_compiler"},
		{"the tenant role may read the lock status", "GRANT EXECUTE ON FUNCTION pg_catalog.pg_lock_status() TO ctrlz_tenant"},
		{"PUBLIC may ask the size of a relation", "GRANT EXECUTE ON FUNCTION pg_catalog.pg_relation_size(regclass) TO PUBLIC"},
		{"the hub may read the WAL position", "GRANT EXECUTE ON FUNCTION pg_catalog.pg_current_wal_lsn() TO ctrlz_hub"},
	} {
		add(g.name, "30", g.sql)
	}
	// db-r15-9: what no family names is judged by check 31, and the two families added with it by 30.
	add("PUBLIC may ask which session blocks which", "30", "GRANT EXECUTE ON FUNCTION pg_catalog.pg_blocking_pids(integer) TO PUBLIC")
	add("the hub may read the last checkpoint's position", "30", "GRANT EXECUTE ON FUNCTION pg_catalog.pg_control_checkpoint() TO ctrlz_hub")
	add("PUBLIC may list the directory of the server", "31", "GRANT EXECUTE ON FUNCTION pg_catalog.pg_ls_dir(text) TO PUBLIC")
	add("PUBLIC may read the role passwords", "31", "GRANT SELECT ON pg_catalog.pg_shadow TO PUBLIC")
	add("a function the reviewed list holds is closed to PUBLIC", "31", "REVOKE EXECUTE ON FUNCTION pg_catalog.pg_sleep(double precision) FROM PUBLIC")
	// Round 16: the families added for db-r16-1, -15, -16 and -17.
	add("PUBLIC may store large objects", "30", "GRANT EXECUTE ON FUNCTION pg_catalog.lo_from_bytea(oid, bytea) TO PUBLIC")
	add("the worker may store large objects", "30", "GRANT EXECUTE ON FUNCTION pg_catalog.lo_create(oid) TO ctrlz_worker")
	add("PUBLIC may call a pg_upgrade helper", "30", "GRANT EXECUTE ON FUNCTION pg_catalog.binary_upgrade_set_record_init_privs(boolean) TO PUBLIC")
	add("PUBLIC may read the snapshot of running transactions", "30", "GRANT EXECUTE ON FUNCTION pg_catalog.pg_current_snapshot() TO PUBLIC")
	add("PUBLIC may ask whether a transaction committed", "30", "GRANT EXECUTE ON FUNCTION pg_catalog.txid_status(bigint) TO PUBLIC")
	add("PUBLIC may notify", "30", "GRANT EXECUTE ON FUNCTION pg_catalog.pg_notify(text, text) TO PUBLIC")
	add("the hub may write a WAL message", "30", "GRANT EXECUTE ON FUNCTION pg_catalog.pg_logical_emit_message(boolean, text, text, boolean) TO ctrlz_hub")
	add("a function that notifies for one kind of request", "32", "CREATE FUNCTION ctrlz_fn.zz_notify(p_known boolean) RETURNS void LANGUAGE plpgsql AS $$ BEGIN IF p_known THEN NOTIFY ctrlz_sms; END IF; END $$")
	add("a column default that notifies", "32", "CREATE TABLE ctrlz.zz_notify (n text DEFAULT pg_catalog.pg_notify('ctrlz_sms', '')::text)")

	// Roles and ownership.
	// Role defaults and connection limits (A4): each one is removed alone.
	for _, r := range sortedRolesOf(fx) {
		spec := fx.Roles.Roles[r]
		if spec.ConnLimit >= 0 {
			add("role "+r+" loses its connection limit", "08", "ALTER ROLE "+r+" CONNECTION LIMIT -1")
			add("role "+r+" gets a different connection limit", "08", fmt.Sprintf("ALTER ROLE %s CONNECTION LIMIT %d", r, spec.ConnLimit+1))
		}
		for k := range spec.Settings {
			add("role "+r+" loses "+k, "08", "ALTER ROLE "+r+" RESET "+k)
			other := "7s"
			if k == "search_path" {
				other = "pg_catalog"
			}
			add("role "+r+" gets another "+k, "08", "ALTER ROLE "+r+" SET "+k+" = '"+other+"'")
		}
	}
	add("the auth role gets a default setting", "08", "ALTER ROLE ctrlz_auth SET statement_timeout = '1s'")
	// A restrictive policy is a guard of its own: dropping it is the loop above,
	// and these two keep it present but useless.
	for _, p := range fx.Policies.Named {
		if !p.Restrictive {
			continue
		}
		q := ident(p.Table)
		pn := pgx.Identifier{p.Name}.Sanitize()
		add("restrictive policy "+p.Table+"."+p.Name+" is weakened", "05", "ALTER POLICY "+pn+" ON "+q+" USING (true)")
		add("restrictive policy "+p.Table+"."+p.Name+" becomes permissive", "05",
			"DROP POLICY "+pn+" ON "+q,
			"CREATE POLICY "+pn+" ON "+q+" FOR "+p.Cmd+" TO "+p.Role+" USING (true)")
	}
	add("the tenant role bypasses RLS", "08", "ALTER ROLE ctrlz_tenant BYPASSRLS")
	add("the hub becomes a superuser", "08", "ALTER ROLE ctrlz_hub SUPERUSER")
	add("the worker may create roles", "08", "ALTER ROLE ctrlz_worker CREATEROLE")
	add("the auth role can log in", "08", "ALTER ROLE ctrlz_auth LOGIN")
	add("a role joins the tenant role", "08", "GRANT pg_read_all_data TO ctrlz_tenant")
	add("the migrator inherits ctrlz_auth", "08", "GRANT ctrlz_auth TO ctrlz_migrator WITH INHERIT TRUE")
	add("an extra ctrlz role", "08", "CREATE ROLE ctrlz_rogue")
	// What pg_roles hides (db-r11-3): a per-database role setting, a database-wide one, and a parameter
	// privilege that lets a login role switch the trigger guards off.
	add("a per-database timeout of zero for the tenant role", "08", "ALTER ROLE ctrlz_tenant IN DATABASE "+pgx.Identifier{h.db.Name}.Sanitize()+" SET statement_timeout = 0")
	add("a database-wide replica mode", "08", "ALTER DATABASE "+pgx.Identifier{h.db.Name}.Sanitize()+" SET session_replication_role = replica")
	add("SET on session_replication_role for the worker", "08", "GRANT SET ON PARAMETER session_replication_role TO ctrlz_worker")
	add("SET on session_replication_role for PUBLIC", "08", "GRANT SET ON PARAMETER session_replication_role TO PUBLIC")
	add("a table owned by another role", "09", "ALTER TABLE ctrlz.rules OWNER TO ctrlz_worker")
	add("backfill owns a table", "09", "ALTER TABLE ctrlz.job_outbox OWNER TO ctrlz_backfill")

	// Schema shape.
	add("an unlisted table", "01", "CREATE TABLE ctrlz.rogue (id int)")
	add("a tenant table without RLS", "01", "CREATE TABLE ctrlz.rogue2 (tenant_id uuid NOT NULL, id uuid)")
	add("a tenant_id column on a global table", "04", "ALTER TABLE ctrlz.alerts ADD COLUMN tenant_id uuid")
	add("RLS on a global table", "04", "ALTER TABLE ctrlz.alerts ENABLE ROW LEVEL SECURITY")
	add("RLS off on the global table that needs it", "04", "ALTER TABLE ctrlz.sms_counters DISABLE ROW LEVEL SECURITY")
	add("a tenant key that is nullable", "02", "ALTER TABLE ctrlz.rules DROP CONSTRAINT rules_pkey CASCADE", "ALTER TABLE ctrlz.rules ALTER COLUMN tenant_id DROP NOT NULL")
	add("an index that does not lead with tenant_id", "06", "CREATE INDEX bad_idx ON ctrlz.rules (comment)")
	add("an unlisted unique index on a tenant table", "06", "CREATE UNIQUE INDEX bad_uq ON ctrlz.users (locale, tenant_id)")
	add("an email column", "18", "ALTER TABLE ctrlz.users ADD COLUMN email text")
	add("an ai_malware column", "18", "ALTER TABLE ctrlz.profile_options ADD COLUMN ai_malware_level text")
	add("public gets USAGE", "15", "GRANT USAGE ON SCHEMA public TO PUBLIC")
	add("an object in public", "15", "CREATE TABLE public.oops (id int)")
	add("an extension", "16", "CREATE EXTENSION pg_trgm SCHEMA ctrlz_ext")
	add("a named constraint is dropped", "17", "ALTER TABLE ctrlz.node_pairs DROP CONSTRAINT node_pairs_distinct")
	add("the slot limit is dropped", "17", "ALTER TABLE ctrlz.nodes DROP CONSTRAINT nodes_slot_range")
	add("the claim exclusion is dropped", "17", "ALTER TABLE ctrlz.ip_claims DROP CONSTRAINT ip_claims_no_overlap")
	add("the schedule exclusion is dropped", "17", "ALTER TABLE ctrlz.schedule_windows DROP CONSTRAINT schedule_windows_no_overlap")
	// A named CHECK that is switched off keeps its expression in its text (db-r13-3), and a CHECK that
	// is NOT ENFORCED or NOT VALID holds nothing, whoever listed it.
	for _, nc := range fx.Tables.NamedConstraints {
		var kind string
		if err := conn.QueryRow(ctx, "SELECT contype::text FROM pg_constraint WHERE conname = $1 AND conrelid = ('ctrlz.' || quote_ident($2))::regclass", nc.Name, nc.Table).Scan(&kind); err != nil {
			t.Fatalf("named constraint %s: %v", nc.Name, err)
		}
		if kind == "c" {
			add("named CHECK "+nc.Name+" is re-added NOT ENFORCED", "17", reAdd(nc.Table, nc.Name, "NOT ENFORCED"))
			add("named CHECK "+nc.Name+" is re-added NOT VALID", "17", reAdd(nc.Table, nc.Name, "NOT VALID"))
		}
	}
	add("the cap's NaN line is re-added NOT ENFORCED", "27", reAdd("system_settings", "system_settings_sms_cost_cap_not_nan", "NOT ENFORCED"))
	add("the spend's NaN line is re-added NOT VALID", "27", reAdd("sms_counters", "sms_counters_cost_not_nan", "NOT VALID"))
	add("a constraint nobody listed is NOT ENFORCED", "28", "ALTER TABLE ctrlz.alerts ADD CONSTRAINT zz_free CHECK (true) NOT ENFORCED")
	add("a constraint nobody listed is NOT VALID", "28", "ALTER TABLE ctrlz.alerts ADD CONSTRAINT zz_free CHECK (true) NOT VALID")
	// Rewrite rules run as the table's owner (db-r13-4).
	add("a rule writes a guarded column on every login", "29",
		"CREATE RULE plant AS ON INSERT TO ctrlz.sessions DO ALSO UPDATE ctrlz.users SET enforce_passkey = false WHERE tenant_id = NEW.tenant_id AND id = NEW.user_id")
	add("a rule makes revocation of a session a no-op", "29",
		"CREATE RULE keep AS ON UPDATE TO ctrlz.sessions WHERE NEW.revoked_at IS NOT NULL DO INSTEAD NOTHING")
	add("a rule on a listed view", "29", "CREATE RULE hide AS ON INSERT TO ctrlz.tenant_profile_counts DO INSTEAD NOTHING")
	add("a rule on a table of another schema", "29", "CREATE SCHEMA zz_other", "CREATE TABLE zz_other.t (id int)", "CREATE RULE r AS ON INSERT TO zz_other.t DO INSTEAD NOTHING")
	// A numeric column that accepts NaN (db-r12-1, db-r12-3): the lower bound alone passes it.
	// An unbounded numeric or a float with a NaN line alone still holds an infinity (db-r13-2).
	add("an unbounded money column with only a NaN line", "27", "ALTER TABLE ctrlz.alerts ADD COLUMN zz_money numeric CHECK (zz_money >= 0 AND zz_money <> 'NaN'::numeric)")
	add("a float money column with only a NaN line", "27", "ALTER TABLE ctrlz.alerts ADD COLUMN zz_money double precision CHECK (zz_money >= 0 AND zz_money <> 'NaN')")
	add("a money column with only a lower bound", "27", "ALTER TABLE ctrlz.alerts ADD COLUMN zz_money numeric(14,4) CHECK (zz_money >= 0)")
	add("the cap loses its NaN line", "27", "ALTER TABLE ctrlz.system_settings DROP CONSTRAINT system_settings_sms_cost_cap_not_nan")
	add("the default privilege on functions is gone", "13", "ALTER DEFAULT PRIVILEGES FOR ROLE ctrlz_migrator GRANT EXECUTE ON FUNCTIONS TO PUBLIC")
	add("a default grant to a service role", "13", "ALTER DEFAULT PRIVILEGES FOR ROLE ctrlz_migrator IN SCHEMA ctrlz GRANT SELECT ON TABLES TO ctrlz_tenant")
	add("the hub reaches river", "20", "GRANT USAGE ON SCHEMA river TO ctrlz_hub")
	add("a river table open to PUBLIC", "20", "CREATE TABLE river.job (id int)", "GRANT SELECT ON river.job TO PUBLIC")

	caught := map[string]int{}
	var uncaught []string
	for _, m := range muts {
		tx, err := conn.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var mutErr error
		for _, stmt := range m.sql {
			if _, err := tx.Exec(ctx, stmt); err != nil {
				mutErr = fmt.Errorf("%s: %w", stmt, err)
				break
			}
		}
		if mutErr != nil {
			tx.Rollback(ctx)
			t.Errorf("mutation %q could not be applied: %v", m.name, mutErr)
			continue
		}
		// The check the mutation is aimed at must notice it. Only when it does
		// not is the rest of the suite consulted, to say who did.
		var hit bool
		for _, ck := range catalogtest.Checks() {
			if ck.ID != m.want {
				continue
			}
			v, err := ck.Run(ctx, tx, fx)
			if err != nil {
				t.Errorf("mutation %q: check %s: %v", m.name, ck.ID, err)
			}
			hit = len(v) > 0
		}
		if hit {
			tx.Rollback(ctx)
			caught[m.want]++
			continue
		}
		id, v, err := firstViolation(ctx, tx, fx)
		tx.Rollback(ctx)
		switch {
		case err != nil:
			t.Errorf("mutation %q: %v", m.name, err)
		case len(v) == 0:
			uncaught = append(uncaught, m.name)
		default:
			t.Errorf("mutation %q was caught by check %s but not by the check aimed at it, %s", m.name, id, m.want)
		}
	}
	for _, u := range uncaught {
		t.Errorf("NOT CAUGHT by any catalog check: %s", u)
	}
	ids := make([]string, 0, len(caught))
	for id := range caught {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var summary []string
	for _, id := range ids {
		summary = append(summary, fmt.Sprintf("%s:%d", id, caught[id]))
	}
	t.Logf("%d mutations, all caught; catching check: count %s", len(muts), strings.Join(summary, " "))
}

func sortedRolesOf(fx *catalogtest.Fixtures) []string {
	out := make([]string, 0, len(fx.Roles.Roles))
	for r := range fx.Roles.Roles {
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}

func sortedTables(fx *catalogtest.Fixtures) []string {
	out := make([]string, 0, len(fx.Grants.Tables))
	for t := range fx.Grants.Tables {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

func sortedRoles(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for r := range m {
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}

// TestMutationsBreakIsolation shows that the two-tenant behaviour tests have
// teeth too. Each mutation that would let one tenant read another's rows, or
// lock a tenant out of its own, is applied and the same probe the isolation
// test uses (count the rows visible to ctrlz_tenant with the setting at A) must
// give the wrong answer.
func TestMutationsBreakIsolation(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	a := h.A.Tenant.String()

	// probe returns what ctrlz_tenant sees in a table with the setting at A.
	probe := func(tx pgx.Tx, tbl string) (int, error) {
		if _, err := tx.Exec(h.ctx, "SAVEPOINT probe"); err != nil {
			return 0, err
		}
		if _, err := tx.Exec(h.ctx, "SET LOCAL ROLE ctrlz_tenant"); err != nil {
			return 0, err
		}
		if _, err := tx.Exec(h.ctx, "SELECT pg_catalog.set_config('ctrlz.tenant_id', $1, true)", a); err != nil {
			return 0, err
		}
		n, err := count(h.ctx, tx, "SELECT count(*) FROM "+ident(tbl))
		if _, rerr := tx.Exec(h.ctx, "RESET ROLE"); rerr != nil {
			return 0, rerr
		}
		return n, err
	}

	tested := 0
	for _, tbl := range h.fx.Tables.Tenant {
		if !h.has(tbl, "tenant", "SELECT") || h.namedAll(tbl, "tenant", "SELECT") {
			continue
		}
		q := ident(tbl)
		own := rowsPer(tbl)
		for name, sql := range map[string][]string{
			"USING (true)":             {"ALTER POLICY tenant_isolation ON " + q + " USING (true)"},
			"drop the policy":          {"DROP POLICY tenant_isolation ON " + q},
			"policy on a wrong column": {"ALTER POLICY tenant_isolation ON " + q + " USING (true) WITH CHECK (true)"},
			"disable RLS":              {"ALTER TABLE " + q + " DISABLE ROW LEVEL SECURITY"},
			"bypass for tenant":        {"ALTER ROLE ctrlz_tenant BYPASSRLS"},
		} {
			tx, err := h.super.Begin(h.ctx)
			if err != nil {
				t.Fatal(err)
			}
			// Unmutated: the probe sees exactly the tenant's own rows.
			if n, err := probe(tx, tbl); err != nil || n != own {
				tx.Rollback(h.ctx)
				t.Fatalf("%s: baseline probe sees %d rows (err %v), want %d", tbl, n, err, own)
			}
			for _, s := range sql {
				if _, err := tx.Exec(h.ctx, s); err != nil {
					tx.Rollback(h.ctx)
					t.Fatalf("%s %s: %v", tbl, name, err)
				}
			}
			n, err := probe(tx, tbl)
			tx.Rollback(h.ctx)
			if err == nil && n == own {
				t.Errorf("%s: mutation %q is invisible to the two-tenant probe", tbl, name)
			}
			tested++
		}
	}
	t.Logf("%d isolation mutations, each seen by the two-tenant probe", tested)
	if tested < 100 {
		t.Errorf("only %d isolation mutations ran", tested)
	}
}

// quoteLit is a SQL string literal for the names of the mutations above, which are our own.
func quoteLit(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
