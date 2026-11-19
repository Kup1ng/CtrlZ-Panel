package catalogtest_test

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store/catalogtest"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

// loginRoleNames are the roles of roles.yaml that can log in.
func loginRoleNames(h *harness) []string {
	var out []string
	for n, r := range h.fx.Roles.Roles {
		if r.Login {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

// TestCatalogReachCheckCanFail is the proof for check 30: every way a ctrlz role can come to hold a
// privilege of a family that the file does not name is reported, the migrated database is clean, and an
// entry that names nothing, or a role that does not exist, is reported too.
func TestCatalogReachCheckCanFail(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	if v := runCheck(t, h, catalogtest.CheckCatalogReach, h.fx); len(v) != 0 {
		t.Fatalf("the migrated database is not clean for check 30: %v", v)
	}
	for _, m := range []struct {
		name, want string
		sql        []string
	}{
		{"PUBLIC holds a lock function", "PUBLIC holds EXECUTE on pg_catalog function pg_advisory_lock(bigint)",
			[]string{`GRANT EXECUTE ON FUNCTION pg_catalog.pg_advisory_lock(bigint) TO PUBLIC`}},
		// A membership is a route has_function_privilege follows and a list of direct grants does not.
		{"a login role is a member of a group that holds one", "ctrlz_hub holds EXECUTE on pg_catalog function pg_advisory_lock(bigint)",
			[]string{`CREATE ROLE zz_group NOLOGIN`, `GRANT EXECUTE ON FUNCTION pg_catalog.pg_advisory_lock(bigint) TO zz_group`, `GRANT zz_group TO ctrlz_hub`}},
		{"the admin role holds the transaction lock", "ctrlz_admin holds EXECUTE on pg_catalog function pg_advisory_xact_lock(bigint)",
			[]string{`GRANT EXECUTE ON FUNCTION pg_catalog.pg_advisory_xact_lock(bigint) TO ctrlz_admin`}},
		{"a statistics view for the tenant role", "ctrlz_tenant holds SELECT on pg_catalog relation pg_stat_user_tables",
			[]string{`GRANT SELECT ON pg_catalog.pg_stat_user_tables TO ctrlz_tenant`}},
		{"the lock table for PUBLIC", "PUBLIC holds SELECT on pg_catalog relation pg_locks",
			[]string{`GRANT SELECT ON pg_catalog.pg_locks TO PUBLIC`}},
		{"a size function for the worker", "ctrlz_worker holds EXECUTE on pg_catalog function pg_total_relation_size(regclass)",
			[]string{`GRANT EXECUTE ON FUNCTION pg_catalog.pg_total_relation_size(regclass) TO ctrlz_worker`}},
		{"the migrator loses what goose needs", "ctrlz_migrator is named for EXECUTE on pg_catalog function pg_advisory_unlock(bigint) and does not hold it",
			[]string{`REVOKE EXECUTE ON FUNCTION pg_catalog.pg_advisory_unlock(bigint) FROM ctrlz_migrator`}},
	} {
		t.Run(m.name, func(t *testing.T) {
			v := strings.Join(runCheck(t, h, catalogtest.CheckCatalogReach, h.fx, m.sql...), "\n")
			if !strings.Contains(v, m.want) {
				t.Errorf("check 30 did not report %q; it said %q", m.want, v)
			}
		})
	}
	// The file itself: an entry for a function Postgres does not have, and a role it does not know.
	bad := *h.fx
	bad.Reach.Functions = append([]catalogtest.ReachFamily(nil), h.fx.Reach.Functions...)
	adv := bad.Reach.Functions[0]
	adv.Execute = map[string][]string{}
	for k, v := range h.fx.Reach.Functions[0].Execute {
		adv.Execute[k] = v
	}
	adv.Execute["pg_advisory_gone(bigint)"] = []string{"auth"}
	adv.Execute["pg_advisory_xact_lock(bigint)"] = []string{"auth", "nobody"}
	bad.Reach.Functions[0] = adv
	v := strings.Join(runCheck(t, h, catalogtest.CheckCatalogReach, &bad), "\n")
	for _, w := range []string{"pg_advisory_gone(bigint) is named in catalog_reach.yaml and matches no object", `names "nobody", which is not a role`} {
		if !strings.Contains(v, w) {
			t.Errorf("check 30 did not report %q for a bad file; it said %q", w, v)
		}
	}
}

// refused runs sql on the connection and says whether Postgres refused it for lack of privilege.
func refused(ctx context.Context, conn *pgx.Conn, sql string) (bool, error) {
	_, err := conn.Exec(ctx, sql)
	if err == nil {
		return false, nil
	}
	var pe *pgconn.PgError
	if errors.As(err, &pe) && pe.Code == "42501" {
		return true, nil
	}
	return false, err
}

// TestNoLoginRoleHoldsTheAuditChainOrWatchesOthers is the probe of db-r14-3 and db-r14-4 as the real
// roles over real connections. Before the fix every one of them could call pg_advisory_lock with the
// key of the audit chain and keep it until it disconnected (so every audited admin write waited
// lock_timeout and failed), and every one could read the per-table counters of tables it has no grant
// on. Now the lock functions are refused for every service login, the audit lock is the one function
// only the admin role may call (and it takes that key and no other), and the statistics, the lock
// views, the sizes and the WAL position are refused.
func TestNoLoginRoleHoldsTheAuditChainOrWatchesOthers(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	const key = `pg_catalog.hashtextextended('ctrlz.audit_log', 0)`
	const tenantKey = `pg_catalog.hashtextextended('ctrlz.ip_claim_request:00000000-0000-0000-0000-000000000001', 0)`
	probes := []string{
		`SELECT pg_catalog.pg_advisory_lock(` + key + `)`,
		`SELECT pg_catalog.pg_advisory_lock_shared(` + key + `)`,
		`SELECT pg_catalog.pg_try_advisory_lock(` + key + `)`,
		`SELECT pg_catalog.pg_advisory_xact_lock(` + key + `)`,
		`SELECT pg_catalog.pg_advisory_xact_lock(` + tenantKey + `)`,
		`SELECT pg_catalog.pg_try_advisory_xact_lock(` + key + `)`,
		`SELECT pg_catalog.pg_advisory_lock(1, 2)`,
		`SELECT pg_catalog.pg_advisory_xact_lock(1, 2)`,
		`SELECT pg_catalog.pg_advisory_unlock_all()`,
		`SELECT count(*) FROM pg_catalog.pg_stat_all_tables`,
		`SELECT count(*) FROM pg_catalog.pg_stat_user_tables`,
		`SELECT count(*) FROM pg_catalog.pg_statio_user_tables`,
		`SELECT count(*) FROM pg_catalog.pg_stat_database`,
		`SELECT count(*) FROM pg_catalog.pg_stat_activity`,
		`SELECT count(*) FROM pg_catalog.pg_locks`,
		`SELECT pg_catalog.pg_stat_get_tuples_inserted('ctrlz.sms_counters'::regclass)`,
		`SELECT pg_catalog.pg_relation_size('ctrlz.sms_counters'::regclass)`,
		`SELECT pg_catalog.pg_total_relation_size('ctrlz.sms_deliveries'::regclass)`,
		`SELECT pg_catalog.pg_current_wal_lsn()`,
	}
	for _, role := range loginRoleNames(h) {
		if role == "ctrlz_migrator" {
			continue // goose's session locker, declared in catalog_reach.yaml and checked there
		}
		t.Run(role, func(t *testing.T) {
			conn, err := h.db.Conn(h.ctx, role)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close(context.Background())
			for _, sql := range probes {
				ok, err := refused(h.ctx, conn, sql)
				if err != nil {
					t.Errorf("%s: %v", sql, err)
				} else if !ok {
					t.Errorf("%s was not refused for %s", sql, role)
				}
			}
			// The one audit lock function: the admin role's alone.
			ok, err := refused(h.ctx, conn, `SELECT ctrlz_fn.audit_lock()`)
			if err != nil {
				t.Fatal(err)
			}
			if wantRefused := role != "ctrlz_admin"; ok != wantRefused {
				t.Errorf("ctrlz_fn.audit_lock() refused for %s: %v, want %v", role, ok, wantRefused)
			}
		})
	}
	// The admin role still takes the lock, inside a transaction, and the lock goes at commit.
	admin, err := h.db.Conn(h.ctx, "ctrlz_admin")
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(context.Background())
	tx, err := admin.Begin(h.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(h.ctx, `SELECT ctrlz_fn.audit_lock()`); err != nil {
		t.Fatalf("the admin role could not take the audit lock: %v", err)
	}
	held := func() bool {
		var n int
		if err := h.super.QueryRow(h.ctx, `SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND granted AND pid = $1`, admin.PgConn().PID()).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n > 0
	}
	if !held() {
		t.Error("ctrlz_fn.audit_lock() did not take an advisory lock")
	}
	if err := tx.Commit(h.ctx); err != nil {
		t.Fatal(err)
	}
	if held() {
		t.Error("the audit lock outlived the transaction")
	}
}

// TestNoFunctionNotifies is the proof for check 32 and the probe of db-r15-1 and db-r15-6. The migrated
// database is clean; each way a notification could come back is reported (a plpgsql PERFORM pg_notify,
// a NOTIFY and a LISTEN statement in a schema the first version of this test never looked in, a column
// default, a view, a rewritten auth_otp_issue); a word in a comment is not. Then the behaviour: a
// listener of every login role that can listen sees nothing at all while a real and a decoy OTP are
// issued, and the issue still commits when the cluster's notification queue cannot take one more
// message (TestAFullNotifyQueueDoesNotStopACommit, which needs a cluster of its own).
func TestNoFunctionNotifies(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	if v := runCheck(t, h, catalogtest.CheckNoNotify, h.fx); len(v) != 0 {
		t.Fatalf("the migrated database notifies: %v", v)
	}
	for _, m := range []struct {
		name, want string
		sql        []string
	}{
		{"a PERFORM pg_notify in a ctrlz_fn function", "zz_a()", []string{
			`CREATE FUNCTION ctrlz_fn.zz_a() RETURNS void LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_catalog.pg_notify('ctrlz_sms', ''); END $$`}},
		{"a NOTIFY statement only for one kind of request", "zz_b(", []string{
			`CREATE FUNCTION ctrlz_fn.zz_b(p_known boolean) RETURNS void LANGUAGE plpgsql AS $$ BEGIN IF p_known THEN NOTIFY ctrlz_sms; END IF; END $$`}},
		{"a NOTIFY in a trigger function of another schema", "zz_other.zz_c()", []string{
			`CREATE SCHEMA zz_other`,
			`CREATE FUNCTION zz_other.zz_c() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN NOTIFY ctrlz_sms; RETURN NEW; END $$`}},
		{"a LISTEN in a procedure", "zz_d()", []string{
			`CREATE PROCEDURE ctrlz.zz_d() LANGUAGE plpgsql AS $$ BEGIN LISTEN ctrlz_sms; END $$`}},
		{"a NOTIFY built into an SQL-standard body", "zz_e()", []string{
			`CREATE FUNCTION ctrlz.zz_e() RETURNS void LANGUAGE sql BEGIN ATOMIC SELECT pg_catalog.pg_notify('x', ''); END`}},
		{"a column default", "calls pg_notify", []string{
			`CREATE TABLE ctrlz.zz_t (id int, n text DEFAULT pg_catalog.pg_notify('ctrlz_sms', '')::text)`}},
		{"a view", "calls pg_notify", []string{
			`CREATE VIEW ctrlz.zz_v AS SELECT pg_catalog.pg_notify('ctrlz_sms', '')::text AS n`}},
	} {
		t.Run(m.name, func(t *testing.T) {
			v := strings.Join(runCheck(t, h, catalogtest.CheckNoNotify, h.fx, m.sql...), "\n")
			if !strings.Contains(v, m.want) {
				t.Errorf("check 32 did not report %q; it said %q", m.want, v)
			}
		})
	}
	t.Run("a word in a comment is not a notification", func(t *testing.T) {
		if v := runCheck(t, h, catalogtest.CheckNoNotify, h.fx,
			`CREATE FUNCTION ctrlz_fn.zz_f() RETURNS void LANGUAGE plpgsql AS $$ BEGIN -- never pg_notify, never NOTIFY
  /* LISTEN is not used either */ NULL; END $$`); len(v) != 0 {
			t.Errorf("a comment was reported: %v", v)
		}
	})

	// Behaviour: every role that can listen sees nothing for a real and for a decoy request.
	var ls []*pgx.Conn
	for _, role := range loginRoleNames(h) {
		if role == "ctrlz_tenant" || role == "ctrlz_migrator" {
			continue
		}
		c, err := h.db.Conn(h.ctx, role)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close(context.Background())
		if _, err := c.Exec(h.ctx, "LISTEN ctrlz_sms"); err != nil {
			t.Fatalf("%s cannot listen (the premise of the oracle): %v", role, err)
		}
		ls = append(ls, c)
	}
	issuer, err := h.db.Conn(h.ctx, "ctrlz_tenant")
	if err != nil {
		t.Fatal(err)
	}
	defer issuer.Close(context.Background())
	for i, ct := range [][]byte{{9}, nil, {9}, nil} {
		var id *string
		var allowed bool
		if err := issuer.QueryRow(h.ctx, `SELECT id::text, allowed FROM ctrlz_fn.auth_otp_issue($1, 'login', '\x01'::bytea, $2, '203.0.113.7'::inet, false)`,
			fmt.Sprintf("+98912333%04d", i+1), ct).Scan(&id, &allowed); err != nil || !allowed {
			t.Fatalf("issue %d (real=%v): allowed=%v %v", i, ct != nil, allowed, err)
		}
	}
	for i, c := range ls {
		wctx, cancel := context.WithTimeout(h.ctx, 700*time.Millisecond)
		n, err := c.WaitForNotification(wctx)
		cancel()
		if err == nil {
			t.Errorf("listener %d was sent %q: an OTP request notifies again", i, n.Channel)
		}
	}
}
