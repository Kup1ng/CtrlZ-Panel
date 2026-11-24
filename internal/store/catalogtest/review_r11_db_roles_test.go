package catalogtest_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/migrate"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store/catalogtest"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

// Round 11, database area (db-r11-1, db-r11-2, db-r11-3).

// TestGatewayPriceRefusesANegativeOrNaNValueForEveryWriter is db-r11-1. The price that the sender
// adds to sms_counters.cost is judged where it is stored: before 0042 only the admin route's regex
// kept it non-negative, ctrlz_admin holds a direct UPDATE, and a negative price made the counter's
// own guard (0040) refuse every accepted-send record. The CHECK holds for the admin role and for
// the superuser with the triggers off, and a price of zero or a plain positive one still goes in.
func TestGatewayPriceRefusesANegativeOrNaNValueForEveryWriter(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	for _, who := range []struct{ name, role string }{{"the admin role", "ctrlz_admin"}, {"the owner with the triggers off", ""}} {
		for _, c := range []struct {
			name, price string
			refused     bool
		}{
			{"a negative price", "-1", true},
			{"the smallest negative price", "-0.0001", true},
			{"NaN", "'NaN'", true},
			{"zero", "0", false},
			{"a plain price", "120.5", false},
		} {
			t.Run(who.name+"/"+c.name, func(t *testing.T) {
				tx, err := h.super.Begin(h.ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback(context.Background())
				if _, err := tx.Exec(h.ctx, `INSERT INTO ctrlz.sms_gateways (provider, role) VALUES ('sms_ir', 'disabled')`); err != nil {
					t.Fatal(err)
				}
				if who.role != "" {
					if _, err := tx.Exec(h.ctx, `SET LOCAL ROLE `+who.role); err != nil {
						t.Fatal(err)
					}
				} else if _, err := tx.Exec(h.ctx, `SET LOCAL session_replication_role = replica`); err != nil {
					t.Fatal(err)
				}
				_, err = tx.Exec(h.ctx, `UPDATE ctrlz.sms_gateways SET cost_per_message = `+c.price+`::numeric WHERE provider = 'sms_ir'`)
				if c.refused {
					if pe := pgErr(err); pe == nil || pe.Code != "23514" {
						t.Fatalf("want SQLSTATE 23514 (check_violation), got %v", err)
					}
					return
				}
				if err != nil {
					t.Fatalf("a price of %s must be accepted: %v", c.price, err)
				}
			})
		}
	}
}

// TestMigrationsCleanWhatAnInstalledDatabaseHolds is db-r11-2. Every other test migrates an empty
// database, where the cleanup statements of a migration never touch a row, so a migration that
// dropped its DELETE or UPDATE, or ran it after the ADD CONSTRAINT, passed on a clean install and
// aborted on a deployed one. Here a database is taken to the migration before, the rows a real one
// could hold are planted (the guard of the day does not exist yet, and the triggers are off for the
// plant as a restored backup would be), and the one migration runs on them. The same shape covers
// 0042: a price below zero or NaN becomes NULL and a plain price stays.
func TestMigrationsCleanWhatAnInstalledDatabaseHolds(t *testing.T) {
	c := testpg.Need(t, cluster)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	d := c.NewEmptyDB(ctx, t)
	db, err := d.MigratorDB()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	super, err := d.Super(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer super.Close(context.Background())

	if _, err := migrate.UpTo(ctx, db, 39); err != nil {
		t.Fatal(err)
	}
	const today = `(now() AT TIME ZONE 'Asia/Tehran')::date`
	for _, s := range []string{
		`INSERT INTO ctrlz.sms_counters (day, scope, key, count, cost) VALUES
		  (` + today + ` + 1, 'global', 'all', -2000000000, -9999999999),
		  (` + today + ` + 1, 'phone', 'p-future', 1, 1),
		  (` + today + `, 'phone', 'p-negcount', -3, 5),
		  (` + today + ` - 1, 'phone', 'p-negcost', 4, -7),
		  (` + today + `, 'ip', 'n-healthy', 2, 3)`,
		`INSERT INTO ctrlz.auth_throttle (scope, key, window_start, count) VALUES
		  ('login_phone', sha256('neg'::bytea), now(), -5),
		  ('login_phone', sha256('ok'::bytea), now(), 3)`,
	} {
		if _, err := super.Exec(ctx, testpg.PlantCounters(s)); err != nil {
			t.Fatalf("plant at 0039: %v", err)
		}
	}
	if n, err := migrate.UpTo(ctx, db, 40); err != nil || n != 1 {
		t.Fatalf("0040 applied %d migration(s) on the planted rows: %v", n, err)
	}
	type row struct {
		day            string
		scope, key     string
		count          int
		cost           string
		wantCount      int
		wantCost       string
		wantRowPresent bool
	}
	for _, w := range []row{
		{scope: "global", key: "all", wantRowPresent: false},
		{scope: "phone", key: "p-future", wantRowPresent: false},
		{scope: "phone", key: "p-negcount", wantRowPresent: true, wantCount: 0, wantCost: "5.0000"},
		{scope: "phone", key: "p-negcost", wantRowPresent: true, wantCount: 4, wantCost: "0.0000"},
		{scope: "ip", key: "n-healthy", wantRowPresent: true, wantCount: 2, wantCost: "3.0000"},
	} {
		var count int
		var cost string
		err := super.QueryRow(ctx, `SELECT count, cost::text FROM ctrlz.sms_counters WHERE scope = $1 AND key = $2`, w.scope, w.key).Scan(&count, &cost)
		if !w.wantRowPresent {
			if err == nil {
				t.Errorf("%s/%s: a row of a day that has not begun survived the cleanup", w.scope, w.key)
			}
			continue
		}
		if err != nil || count != w.wantCount || cost != w.wantCost {
			t.Errorf("%s/%s: count %d cost %s (err %v), want %d and %s", w.scope, w.key, count, cost, err, w.wantCount, w.wantCost)
		}
	}
	for key, want := range map[string]int{"neg": 0, "ok": 3} {
		var n int
		if err := super.QueryRow(ctx, `SELECT count FROM ctrlz.auth_throttle WHERE key = sha256($1::bytea)`, key).Scan(&n); err != nil || n != want {
			t.Errorf("auth_throttle %q: count %d (err %v), want %d", key, n, err, want)
		}
	}
	var constraints int
	if err := super.QueryRow(ctx, `SELECT count(*) FROM pg_constraint WHERE conname IN ('sms_counters_count_not_negative', 'sms_counters_cost_not_negative', 'auth_throttle_count_not_negative')`).Scan(&constraints); err != nil || constraints != 3 {
		t.Errorf("after 0040 there are %d of the three CHECKs (err %v)", constraints, err)
	}

	// 0042 (db-r11-1): the prices at 0041, a database where nothing refuses them yet.
	if _, err := migrate.UpTo(ctx, db, 41); err != nil {
		t.Fatal(err)
	}
	if _, err := super.Exec(ctx, `INSERT INTO ctrlz.sms_gateways (provider, role, cost_per_message) VALUES
	  ('sms_ir', 'disabled', -5), ('melipayamak', 'disabled', 'NaN'), ('noop', 'disabled', 12.5)`); err != nil {
		t.Fatalf("plant prices at 0041: %v", err)
	}
	// 0044 (db-r12-1, db-r12-3): a NaN spend and a NaN cap at 0043, where only ">= 0" stands
	// guard (the triggers are off for the plant, as a restored backup would be).
	if _, err := migrate.UpTo(ctx, db, 43); err != nil {
		t.Fatal(err)
	}
	if _, err := super.Exec(ctx, testpg.PlantCounters(`INSERT INTO ctrlz.sms_counters (day, scope, key, count, cost) VALUES
	  (`+today+`, 'global', 'all', 1, 'NaN'), (`+today+`, 'phone', 'p-nan', 1, 'NaN'), (`+today+`, 'ip', 'i-ok', 2, 4.5)`)); err != nil {
		t.Fatalf("plant NaN spends at 0043: %v", err)
	}
	if tag, err := super.Exec(ctx, `UPDATE ctrlz.system_settings SET sms_cost_cap_daily = 'NaN'`); err != nil || tag.RowsAffected() != 1 {
		t.Fatalf("plant a NaN cap at 0043: %v", err)
	}
	if n, err := migrate.Up(ctx, db); err != nil || n < 1 {
		t.Fatalf("the migrations after 0043 applied %d on the planted prices, spends and cap: %v", n, err)
	}
	for _, w := range []struct{ scope, key, cost string }{
		{"global", "all", "0.0000"}, {"phone", "p-nan", "0.0000"}, {"ip", "i-ok", "4.5000"},
	} {
		var cost string
		if err := super.QueryRow(ctx, `SELECT cost::text FROM ctrlz.sms_counters WHERE scope = $1 AND key = $2`, w.scope, w.key).Scan(&cost); err != nil || cost != w.cost {
			t.Errorf("%s/%s: spend %s (err %v), want %s", w.scope, w.key, cost, err, w.cost)
		}
	}
	var cap *string
	if err := super.QueryRow(ctx, `SELECT sms_cost_cap_daily::text FROM ctrlz.system_settings`).Scan(&cap); err != nil || cap != nil {
		t.Errorf("a NaN cap became %v (err %v), want NULL", cap, err)
	}
	for provider, want := range map[string]string{"sms_ir": "", "melipayamak": "", "noop": "12.5000"} {
		var got *string
		if err := super.QueryRow(ctx, `SELECT cost_per_message::text FROM ctrlz.sms_gateways WHERE provider = $1`, provider).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if (want == "") != (got == nil) || (got != nil && *got != want) {
			t.Errorf("%s: price %v, want %q (empty is NULL)", provider, got, want)
		}
	}
}

// breakRoleDefaults applies statements in a transaction that is rolled back, and returns what the
// role check (08) says about the broken database.
func breakRoleDefaults(t *testing.T, h *harness, sql ...string) []string {
	t.Helper()
	tx, err := h.super.Begin(h.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	for _, s := range sql {
		if _, err := tx.Exec(h.ctx, s); err != nil {
			t.Fatalf("mutation %.80q does not apply: %v", s, err)
		}
	}
	for _, ck := range catalogtest.Checks() {
		if ck.ID != "08" {
			continue
		}
		v, err := ck.Run(h.ctx, tx, h.fx)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	t.Fatal("check 08 is gone")
	return nil
}

// TestRoleCheckReadsWhatPgRolesHides is db-r11-3. pg_roles.rolconfig shows only ALTER ROLE r SET,
// and Postgres also applies a per-database role setting (before it), a database-wide setting and an
// all-roles one, and a parameter privilege lets a login role run SET LOCAL session_replication_role
// = replica, which skips every ordinary trigger. Each of these is planted, one at a time, and check
// 08 must name it (not merely fail: a membership or a role made for the plant fails the same check
// for another reason, so the text is read).
func TestRoleCheckReadsWhatPgRolesHides(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	if v := breakRoleDefaults(t, h); len(v) != 0 {
		t.Fatalf("the migrated database is not clean for check 08: %v", v)
	}
	db := `"` + h.db.Name + `"`
	for _, m := range []struct {
		name, want string
		sql        []string
	}{
		{"a per-database timeout of zero beside the role-wide one", "ctrlz_tenant has a setting for one database",
			[]string{"ALTER ROLE ctrlz_tenant IN DATABASE " + db + " SET statement_timeout = 0"}},
		{"a per-database idle timeout of zero", "ctrlz_worker has a setting for one database",
			[]string{"ALTER ROLE ctrlz_worker IN DATABASE " + db + " SET idle_in_transaction_session_timeout = 0"}},
		{"a per-database setting of a NOLOGIN role", "ctrlz_auth has a setting for one database",
			[]string{"ALTER ROLE ctrlz_auth IN DATABASE " + db + " SET session_replication_role = replica"}},
		{"a database-wide setting", "ALTER DATABASE SET (database_defaults): unexpected session_replication_role=replica",
			[]string{"ALTER DATABASE " + db + " SET session_replication_role = replica"}},
		{"an all-roles setting", "ALTER ROLE ALL SET (cluster_defaults): unexpected row_security=off",
			[]string{"ALTER ROLE ALL SET row_security = off"}},
		{"SET on session_replication_role to the tenant role", "ctrlz_tenant holds SET on parameter session_replication_role",
			[]string{"GRANT SET ON PARAMETER session_replication_role TO ctrlz_tenant"}},
		{"ALTER SYSTEM on a parameter to the worker", "ctrlz_worker holds ALTER SYSTEM on parameter session_replication_role",
			[]string{"GRANT ALTER SYSTEM ON PARAMETER session_replication_role TO ctrlz_worker"}},
		{"SET to the worker through a group role", "ctrlz_worker holds SET on parameter session_replication_role through grp_not_ctrlz",
			[]string{"CREATE ROLE grp_not_ctrlz NOLOGIN", "GRANT SET ON PARAMETER session_replication_role TO grp_not_ctrlz",
				"GRANT grp_not_ctrlz TO ctrlz_worker WITH INHERIT FALSE, SET TRUE"}},
		{"SET to PUBLIC", "holds SET on parameter session_replication_role through PUBLIC",
			[]string{"GRANT SET ON PARAMETER session_replication_role TO PUBLIC"}},
	} {
		t.Run(m.name, func(t *testing.T) {
			v := breakRoleDefaults(t, h, m.sql...)
			if !strings.Contains(strings.Join(v, "\n"), m.want) {
				t.Fatalf("check 08 did not report %q for the planted database; it said: %v", m.want, v)
			}
		})
	}
	// A parameter privilege held by a role that no ctrlz role belongs to is nobody's reach.
	if v := breakRoleDefaults(t, h, "CREATE ROLE other_not_ctrlz NOLOGIN", "GRANT SET ON PARAMETER session_replication_role TO other_not_ctrlz"); len(v) != 0 {
		t.Fatalf("a privilege of an unrelated role is reported: %v", v)
	}
}

// TestParameterPrivilegeLetsALoginRoleSwitchTheGuardsOff shows what the check is protecting: with
// the privilege the tenant role skips credential_gen_bump, and without it the same statement is
// refused. This is the reason the check exists, so a PostgreSQL release that stops the privilege
// doing so would show here (db-r12-2: the first version asserted only the refusal without the
// privilege, which is Postgres' default and cannot fail, so it proved nothing about the premise).
// Both halves run: refused without the grant; with it, the role switches to replica, writes a
// credential column and credential_gen does not move, while the same write in origin mode moves it
// (the control that the trigger is live and that the write is one it watches).
func TestParameterPrivilegeLetsALoginRoleSwitchTheGuardsOff(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	tx, err := h.super.Begin(h.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if _, err := tx.Exec(h.ctx, `SET LOCAL ROLE ctrlz_tenant`); err != nil {
		t.Fatal(err)
	}
	// Half one: no privilege, refused. A savepoint keeps the transaction usable after the error.
	if _, err := tx.Exec(h.ctx, `SAVEPOINT s1`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(h.ctx, `SET LOCAL session_replication_role = replica`); pgErr(err) == nil || pgErr(err).Code != "42501" {
		t.Fatalf("a login role without the privilege must be refused (42501), got %v", err)
	}
	if _, err := tx.Exec(h.ctx, `ROLLBACK TO SAVEPOINT s1`); err != nil {
		t.Fatal(err)
	}
	// Half two: the privilege (granted as the owner of the cluster, undone with the transaction).
	if _, err := tx.Exec(h.ctx, `RESET ROLE`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(h.ctx, `GRANT SET ON PARAMETER session_replication_role TO ctrlz_tenant`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(h.ctx, `SET LOCAL ROLE ctrlz_tenant`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(h.ctx, `SELECT pg_catalog.set_config('ctrlz.tenant_id', $1, true)`, h.A.Tenant.String()); err != nil {
		t.Fatal(err)
	}
	gen := func() int64 {
		t.Helper()
		var g int64
		if err := tx.QueryRow(h.ctx, `SELECT credential_gen FROM ctrlz.users WHERE id = $1`, h.A.User.String()).Scan(&g); err != nil {
			t.Fatal(err)
		}
		return g
	}
	write := func(secret string) {
		t.Helper()
		if _, err := tx.Exec(h.ctx, `UPDATE ctrlz.users SET totp_secret_ct = $2::bytea, totp_enabled_at = now() WHERE id = $1`, h.A.User.String(), secret); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := tx.Exec(h.ctx, `SET LOCAL session_replication_role = replica`); err != nil {
		t.Fatalf("with the privilege the role may switch to replica: %v", err)
	}
	before := gen()
	write(`\x01`)
	if got := gen(); got != before {
		t.Fatalf("with the privilege and replica mode credential_gen moved from %d to %d: the premise of check 08 is gone", before, got)
	}
	if _, err := tx.Exec(h.ctx, `SET LOCAL session_replication_role = origin`); err != nil {
		t.Fatal(err)
	}
	write(`\x02`)
	if got := gen(); got != before+1 {
		t.Fatalf("in origin mode the same kind of write must move credential_gen from %d to %d, got %d", before, before+1, got)
	}
}
