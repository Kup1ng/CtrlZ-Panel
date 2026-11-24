package catalogtest_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store/catalogtest"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

// Rule role-reach (P1 auth review round 5; migrations/catalog/guarded.yaml).
//
// The enforcement is catalog check 22 (who can write a guarded column, read a
// secret, or change a trail row) and check 23 (a guarded write is a function that
// leaves its trail), both run by TestCatalog on the migrated database. This file
// proves they can fail, and holds the behaviour tests of what 0020 turned into
// functions.

// breakIn runs the mutation statements in a transaction that is rolled back and
// returns what check 22 and 23 say about the broken database.
func breakIn(t *testing.T, h *harness, fx *catalogtest.Fixtures, sql ...string) []string {
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
	var out []string
	for _, run := range []func(context.Context, catalogtest.Querier, *catalogtest.Fixtures) ([]string, error){catalogtest.CheckRoleReach, catalogtest.CheckGuardedFunctions} {
		v, err := run(h.ctx, tx, fx)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, v...)
	}
	return out
}

// TestRoleReachCheckCanFail applies, one at a time, the grants the rule exists to
// stop. Each must be reported by the role-reach check on its own, whatever grants.yaml
// says: check 12 would notice most of them too, but it compares with the author's
// intent, and a grant added to both files in one commit passes it.
func TestRoleReachCheckCanFail(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	if v := breakIn(t, h, h.fx); len(v) != 0 {
		t.Fatalf("the migrated database is not clean for checks 22 and 23: %v", v)
	}
	for _, m := range []struct {
		name, want string
		sql        []string
	}{
		// The three mutants of the rule.
		{"the worker may switch Enforce Passkey off", "ctrlz_worker can UPDATE users.enforce_passkey",
			[]string{"GRANT UPDATE (enforce_passkey) ON ctrlz.users TO ctrlz_worker"}},
		{"the worker may delete notices", "ctrlz_worker can DELETE from trail table notifications",
			[]string{"GRANT DELETE ON ctrlz.notifications TO ctrlz_worker"}},
		{"the admin may insert any outbox column", "ctrlz_admin can INSERT sms_outbox.attempts",
			[]string{"GRANT INSERT ON ctrlz.sms_outbox TO ctrlz_admin"}},
		// The same class, other roles, other kinds.
		{"the admin may read a seed", "ctrlz_admin can SELECT users.totp_secret_ct",
			[]string{"GRANT SELECT (totp_secret_ct) ON ctrlz.users TO ctrlz_admin"}},
		{"the hub may read raw counters", "ctrlz_hub can SELECT sms_counters.key",
			[]string{"GRANT SELECT ON ctrlz.sms_counters TO ctrlz_hub"}},
		// Round 8, sms-r8-3 and sms-r8-7: the worker's SELECT on the raw keys is bounded by a row
		// policy that a privilege check cannot see, so the declared predicate is compared with it.
		{"the worker's row policy on the counters turns into USING (true)", "row_bound.sms_counters.worker says",
			[]string{"DROP POLICY worker_global_rows ON ctrlz.sms_counters",
				"CREATE POLICY worker_global_rows ON ctrlz.sms_counters FOR ALL TO ctrlz_worker USING (true) WITH CHECK (true)"}},
		{"the worker's row policy on the counters is dropped", "row_bound.sms_counters.worker says",
			[]string{"DROP POLICY worker_global_rows ON ctrlz.sms_counters"}},
		{"a second permissive policy shows the worker every row", "row_bound.sms_counters.worker says",
			[]string{"CREATE POLICY worker_all ON ctrlz.sms_counters FOR SELECT TO ctrlz_worker USING (true)"}},
		// Round 9, sms-r9-8: Postgres also applies a policy with no TO clause (PUBLIC) and the
		// policies of every role the reader is a member of, and ORs the permissive ones. The row
		// half of the rule read only the policies that named the reader.
		{"a PUBLIC policy shows the worker every row", "row_bound.sms_counters.worker says",
			[]string{"CREATE POLICY stats_read ON ctrlz.sms_counters FOR SELECT USING (true)"}},
		{"a PUBLIC policy for ALL shows the worker every row", "row_bound.sms_counters.worker says",
			[]string{"CREATE POLICY stats_all ON ctrlz.sms_counters FOR ALL USING (true) WITH CHECK (true)"}},
		{"a membership brings the policy of another role", "row_bound.sms_counters.worker says",
			[]string{"GRANT ctrlz_auth TO ctrlz_worker"}},
		{"a membership with no inherit still counts", "row_bound.sms_counters.worker says",
			[]string{"GRANT ctrlz_auth TO ctrlz_worker WITH INHERIT FALSE"}},
		// Round 9, db-r9-3: the decoy challenges. The sender's SELECT on phone_e164 reaches the
		// rows its policy shows, which must be the ones that carry a sealed code and no other.
		{"the sender's row policy on the challenges turns into USING (true)", "row_bound.otp_challenges.worker says",
			[]string{"DROP POLICY worker_deliverable_rows ON ctrlz.otp_challenges",
				"CREATE POLICY worker_deliverable_rows ON ctrlz.otp_challenges FOR ALL TO ctrlz_worker USING (true) WITH CHECK (true)"}},
		{"the sender's row policy on the challenges is dropped", "row_bound.otp_challenges.worker says",
			[]string{"DROP POLICY worker_deliverable_rows ON ctrlz.otp_challenges"}},
		{"a PUBLIC policy shows the sender every challenge", "row_bound.otp_challenges.worker says",
			[]string{"CREATE POLICY stats_read ON ctrlz.otp_challenges FOR SELECT USING (true)"}},
		{"the worker may delete the raw counters again", "ctrlz_worker can DELETE from sms_counters",
			[]string{"GRANT DELETE ON ctrlz.sms_counters TO ctrlz_worker"}},
		{"the key tool may write a seed", "ctrlz_keytool can UPDATE users.totp_secret_ct",
			[]string{"GRANT UPDATE (totp_secret_ct) ON ctrlz.users TO ctrlz_keytool"}},
		{"the compiler may truncate the audit log", "ctrlz_compiler can TRUNCATE trail table tenant_audit_log",
			[]string{"GRANT TRUNCATE ON ctrlz.tenant_audit_log TO ctrlz_compiler"}},
		{"the key tool may delete audit rows", "ctrlz_keytool can DELETE from trail table tenant_audit_log",
			[]string{"GRANT DELETE ON ctrlz.tenant_audit_log TO ctrlz_keytool"}},
		{"the tenant may rewrite a notice", "ctrlz_tenant can UPDATE trail table notifications",
			[]string{"GRANT UPDATE (params) ON ctrlz.notifications TO ctrlz_tenant"}},
		{"the worker may delete the delivery record", "ctrlz_worker can DELETE from trail table sms_deliveries",
			[]string{"GRANT DELETE ON ctrlz.sms_deliveries TO ctrlz_worker"}},
		{"the worker's retention policy is dropped", "no RESTRICTIVE DELETE policy",
			[]string{"DROP POLICY worker_retention ON ctrlz.tenant_audit_log"}},
		{"the worker's retention policy turns permissive", "no RESTRICTIVE DELETE policy",
			[]string{"DROP POLICY worker_retention ON ctrlz.tenant_audit_log",
				"CREATE POLICY worker_retention ON ctrlz.tenant_audit_log FOR DELETE TO ctrlz_worker USING (true)"}},
		// Round 5, db-r5-1 and db-r5-6: DELETE is judged on every guarded table, and a
		// DELETE on a parent counts as a DELETE of what its ON DELETE CASCADE reaches.
		{"the worker may delete a tenant (again)", "ctrlz_worker can DELETE from tenants",
			[]string{"GRANT DELETE ON ctrlz.tenants TO ctrlz_worker"}},
		{"the tenant delete cascades into the trail", "ctrlz_worker can DELETE trail table tenant_audit_log through the ON DELETE CASCADE of tenants",
			[]string{"GRANT DELETE ON ctrlz.tenants TO ctrlz_worker"}},
		{"the tenant delete cascades into the credentials", "ctrlz_worker can DELETE from users through the ON DELETE CASCADE of tenants",
			[]string{"GRANT DELETE ON ctrlz.tenants TO ctrlz_worker"}},
		{"a tenant delete cascades into the notices", "ctrlz_compiler can DELETE trail table notifications through the ON DELETE CASCADE of tenants",
			[]string{"GRANT DELETE ON ctrlz.tenants TO ctrlz_compiler"}},
		{"the worker may undo a suspension", "ctrlz_worker can UPDATE tenants.status",
			[]string{"GRANT UPDATE (status) ON ctrlz.tenants TO ctrlz_worker"}},
		{"the admin may delete admin accounts", "ctrlz_admin can DELETE from admin_users",
			[]string{"GRANT DELETE ON ctrlz.admin_users TO ctrlz_admin"}},
		{"the admin may delete recovery codes", "ctrlz_admin can DELETE from recovery_codes",
			[]string{"GRANT DELETE ON ctrlz.recovery_codes TO ctrlz_admin"}},
		// admin-r5-10 named this one: deleting an enforcing user's passkeys lets the RP job lift
		// the enforcement, so DELETE on a factor table is second-factor removal.
		{"the admin may delete passkeys", "ctrlz_admin can DELETE from webauthn_credentials",
			[]string{"GRANT DELETE ON ctrlz.webauthn_credentials TO ctrlz_admin"}},
		{"the worker may delete users", "ctrlz_worker can DELETE from users",
			[]string{"GRANT DELETE ON ctrlz.users TO ctrlz_worker"}},
		{"the tenant may truncate sessions", "ctrlz_tenant can TRUNCATE sessions",
			[]string{"GRANT TRUNCATE ON ctrlz.sessions TO ctrlz_tenant"}},
		{"a table outside the guarded set may be truncated", "ctrlz_hub can TRUNCATE endpoints",
			[]string{"GRANT TRUNCATE ON ctrlz.endpoints TO ctrlz_hub"}},
		{"a declared delete is no longer held", "delete.sessions declares worker",
			[]string{"REVOKE DELETE ON ctrlz.sessions FROM ctrlz_worker"}},
		// Round 5, db-r5-8: a column that looks secret is judged by its name.
		{"the hub may read the sealed SMS credentials", "ctrlz_hub can SELECT sms_gateways.credentials_ct",
			[]string{"GRANT SELECT (credentials_ct) ON ctrlz.sms_gateways TO ctrlz_hub"}},
		{"the admin may read the sealed outbox parameters", "ctrlz_admin can SELECT sms_outbox.params_ct",
			[]string{"GRANT SELECT (params_ct) ON ctrlz.sms_outbox TO ctrlz_admin"}},
		{"the hub may read the DoH token", "ctrlz_hub can SELECT endpoints.doh_token_ct",
			[]string{"GRANT SELECT (doh_token_ct) ON ctrlz.endpoints TO ctrlz_hub"}},
		{"a secret-looking column added tomorrow", "endpoints.api_secret_ct (bytea) has a secret-looking name",
			[]string{"ALTER TABLE ctrlz.endpoints ADD COLUMN api_secret_ct bytea"}},
		{"a hash column added to a table nobody listed", "nodes.enroll_code_hash (bytea) has a secret-looking name",
			[]string{"ALTER TABLE ctrlz.nodes ADD COLUMN enroll_code_hash bytea"}},
		// Round 6, db-r6-3 and db-r6-10: the secret test is on the name AND on the type, so a
		// credential called by a name nobody listed is still judged.
		{"an accept_token added tomorrow", "invites.accept_token (text) has a secret-looking name",
			[]string{"ALTER TABLE ctrlz.invites ADD COLUMN accept_token text"}},
		{"a private_key on nodes", "nodes.private_key (bytea) has a secret-looking name",
			[]string{"ALTER TABLE ctrlz.nodes ADD COLUMN private_key bytea"}},
		{"a bare key column", "endpoints.key (text) has a secret-looking name",
			[]string{"ALTER TABLE ctrlz.endpoints ADD COLUMN key text"}},
		{"a txt_code", "ip_proof_challenges.txt_code (text) has a secret-looking name",
			[]string{"ALTER TABLE ctrlz.ip_proof_challenges ADD COLUMN txt_code text"}},
		{"an otp_seed", "users.otp_seed (text) has a secret-looking name",
			[]string{"ALTER TABLE ctrlz.users ADD COLUMN otp_seed text"}},
		{"a free-form column called something harmless", "endpoints.notes_blob (bytea) is a free-form column with no decision",
			[]string{"ALTER TABLE ctrlz.endpoints ADD COLUMN notes_blob bytea"}},
		{"a jsonb column nobody decided", "profiles.extra (jsonb) is a free-form column with no decision",
			[]string{"ALTER TABLE ctrlz.profiles ADD COLUMN extra jsonb"}},
		{"an open entry whose column is gone", "open.endpoints.comment is not a column",
			[]string{"ALTER TABLE ctrlz.endpoints DROP COLUMN comment CASCADE"}},
		// Round 7, db-r7-5: the secret test also judges the types that can hold a code, and the
		// personal-data class is decided by name across every type, so the record of which
		// address asked a code for which phone is not guarded by the grants golden alone.
		{"a numeric PIN added tomorrow", "users.otp_pin (integer) has a secret-looking name",
			[]string{"ALTER TABLE ctrlz.users ADD COLUMN otp_pin integer"}},
		{"a bigint login code added tomorrow", "users.login_code (bigint) has a secret-looking name",
			[]string{"ALTER TABLE ctrlz.users ADD COLUMN login_code bigint"}},
		{"a numeric recovery code", "users.recovery_code (numeric(8,0)) has a secret-looking name",
			[]string{"ALTER TABLE ctrlz.users ADD COLUMN recovery_code numeric(8,0)"}},
		{"the hub reads the address that asked a code", "ctrlz_hub can SELECT otp_challenges.ip",
			[]string{"GRANT SELECT (ip, trusted, phone_e164) ON ctrlz.otp_challenges TO ctrlz_hub"}},
		{"the hub reads how the address was judged", "ctrlz_hub can SELECT otp_challenges.trusted",
			[]string{"GRANT SELECT (ip, trusted, phone_e164) ON ctrlz.otp_challenges TO ctrlz_hub"}},
		{"the hub reads the phone a code was asked for", "ctrlz_hub can SELECT otp_challenges.phone_e164",
			[]string{"GRANT SELECT (ip, trusted, phone_e164) ON ctrlz.otp_challenges TO ctrlz_hub"}},
		{"the worker gets the OTP address back", "ctrlz_worker can SELECT otp_challenges.ip",
			[]string{"GRANT SELECT (ip) ON ctrlz.otp_challenges TO ctrlz_worker"}},
		{"the compiler reads every phone number", "ctrlz_compiler can SELECT users.phone_e164",
			[]string{"GRANT SELECT (phone_e164) ON ctrlz.users TO ctrlz_compiler"}},
		{"a phone column added tomorrow", "endpoints.contact_phone (text) looks like personal data",
			[]string{"ALTER TABLE ctrlz.endpoints ADD COLUMN contact_phone text"}},
		{"an address column added tomorrow", "endpoints.last_client_ip (inet) looks like personal data",
			[]string{"ALTER TABLE ctrlz.endpoints ADD COLUMN last_client_ip inet"}},
		{"a user agent added tomorrow", "api_tokens.user_agent (text) looks like personal data",
			[]string{"ALTER TABLE ctrlz.api_tokens ADD COLUMN user_agent text"}},
		{"a personal_open entry whose column is gone", "personal_open.nodes.dns_bind_ip is not a column",
			[]string{"ALTER TABLE ctrlz.nodes DROP COLUMN dns_bind_ip CASCADE"}},
		// Round 6, db-r6-8: a referential action rewrites the child as its owner.
		{"a gateway delete rewrites the delivery trail", "ctrlz_admin can rewrite trail table sms_deliveries (gateway_id) through the ON DELETE SET NULL of sms_gateways",
			[]string{"GRANT DELETE ON ctrlz.sms_gateways TO ctrlz_admin"}},
		{"an admin delete rewrites the guarded invites", "ctrlz_worker can rewrite invites.created_by through the ON DELETE SET NULL of admin_users",
			[]string{"GRANT DELETE ON ctrlz.admin_users TO ctrlz_worker"}},
		{"a key update cascades into the trail", "ctrlz_hub can rewrite trail table tenant_audit_log (tenant_id) through the ON UPDATE CASCADE of tenants",
			[]string{"ALTER TABLE ctrlz.tenant_audit_log ADD CONSTRAINT zz_upd_fk FOREIGN KEY (tenant_id) REFERENCES ctrlz.tenants (id) ON UPDATE CASCADE", "GRANT UPDATE (id) ON ctrlz.tenants TO ctrlz_hub"}},
		// PUBLIC, inheritance and a role made tomorrow are all counted.
		{"PUBLIC may write a hash", "ctrlz_hub can UPDATE users.password_hash",
			[]string{"GRANT UPDATE (password_hash) ON ctrlz.users TO PUBLIC"}},
		{"a role inherits ctrlz_auth", "ctrlz_compiler can",
			[]string{"GRANT ctrlz_auth TO ctrlz_compiler WITH INHERIT TRUE"}},
		{"a login role made tomorrow", "ctrlz_tomorrow can",
			[]string{"CREATE ROLE ctrlz_tomorrow LOGIN", "GRANT UPDATE ON ctrlz.sessions TO ctrlz_tomorrow"}},
		// A column added tomorrow to a guarded table is guarded from the start.
		{"a column added to users and granted to the worker", "ctrlz_worker can UPDATE users.recovery_flag",
			[]string{"ALTER TABLE ctrlz.users ADD COLUMN recovery_flag boolean", "GRANT UPDATE (recovery_flag) ON ctrlz.users TO ctrlz_worker"}},
		// The list can only shrink without a diff: a declared reach that is gone is an error.
		{"a declared grant is no longer held", "guarded.yaml declares (read_at)",
			[]string{"REVOKE UPDATE (read_at) ON ctrlz.notifications FROM ctrlz_tenant"}},
	} {
		t.Run(m.name, func(t *testing.T) {
			v := breakIn(t, h, h.fx, m.sql...)
			if !strings.Contains(strings.Join(v, "\n"), m.want) {
				t.Errorf("checks 22 and 23 did not report %q after %v; they said %v", m.want, m.sql, v)
			}
		})
	}
}

// TestGuardedFunctionCheckCanFail breaks functions.yaml in the ways check 23 exists
// for. The fixture is copied and changed, because the database cannot hold a function
// the file does not list (check 10) without failing earlier.
func TestGuardedFunctionCheckCanFail(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	for _, m := range []struct {
		name, fn, want string
		change         func(f *catalogtest.SDFunction)
	}{
		{"a guarded write with no note", "worker_sweep_pending_totp", "says neither trail nor no_trail",
			func(f *catalogtest.SDFunction) { f.NoTrail = "" }},
		{"a trail the body does not write", "worker_sweep_pending_totp", "does not insert into it",
			func(f *catalogtest.SDFunction) { f.NoTrail = ""; f.Trail = []string{"notifications"} }},
		{"a trail that is not a trail table", "keytool_totp_declare_lost", "not a trail table",
			func(f *catalogtest.SDFunction) { f.Trail = []string{"users"} }},
		{"a worker function handed to another role", "worker_sweep_throttle", "executable by that role alone",
			func(f *catalogtest.SDFunction) { f.Execute = []string{"worker", "hub"} }},
		{"a no_trail that is no reason", "keytool_totp_replace", "is not a reason",
			func(f *catalogtest.SDFunction) { f.NoTrail = "n/a" }},
	} {
		t.Run(m.name, func(t *testing.T) {
			fx := *h.fx
			fx.Functions.SecurityDefiner = append([]catalogtest.SDFunction(nil), h.fx.Functions.SecurityDefiner...)
			found := false
			for i := range fx.Functions.SecurityDefiner {
				if fx.Functions.SecurityDefiner[i].Name == m.fn {
					m.change(&fx.Functions.SecurityDefiner[i])
					found = true
				}
			}
			if !found {
				t.Fatalf("no function %s in functions.yaml", m.fn)
			}
			v, err := catalogtest.CheckGuardedFunctions(h.ctx, h.super, &fx)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(strings.Join(v, "\n"), m.want) {
				t.Errorf("check 23 did not report %q; it said %v", m.want, v)
			}
		})
	}
	// A function that writes nothing guarded must not carry a note.
	fx := *h.fx
	fx.Functions.SecurityDefiner = append([]catalogtest.SDFunction(nil), h.fx.Functions.SecurityDefiner...)
	for i := range fx.Functions.SecurityDefiner {
		if fx.Functions.SecurityDefiner[i].Name == "auth_session_by_hash" {
			fx.Functions.SecurityDefiner[i].NoTrail = "a note that has no function behind it"
		}
	}
	if v, err := catalogtest.CheckGuardedFunctions(h.ctx, h.super, &fx); err != nil || !strings.Contains(strings.Join(v, "\n"), "writes no guarded table") {
		t.Errorf("a stale note was not reported: %v %v", v, err)
	}
}

// trailScenarios arrange the data for each function that declares a trail and call
// it as its one role. A function with a `trail` in functions.yaml and no entry here
// fails TestGuardedFunctionsLeaveATrail, so a new one cannot skip the proof.
var trailScenarios = map[string]struct {
	setup []string
	call  string
	args  []any
}{
	"keytool_totp_declare_lost": {
		setup: []string{`UPDATE ctrlz.users SET totp_secret_ct = ` + declaredLostCT(1) + `, totp_enabled_at = now(), totp_last_step = 7 WHERE tenant_id = '{A}'`},
		// The function takes the seeds the tool proved lost (admin-r13-3), so the call lists the ones the setup planted.
		call: `SELECT ctrlz_fn.keytool_totp_declare_lost(1, (SELECT array_agg(id) FROM ctrlz.users WHERE totp_secret_ct IS NOT NULL), (SELECT array_agg(totp_secret_ct) FROM ctrlz.users WHERE totp_secret_ct IS NOT NULL))`,
	},
	"worker_enforce_clear_without_live": {
		setup: []string{
			`UPDATE ctrlz.webauthn_config SET rp_id = 'panel.localhost'`,
			`UPDATE ctrlz.webauthn_credentials SET stale_at = now() WHERE tenant_id = '{A}'`,
			`UPDATE ctrlz.users SET enforce_passkey = true WHERE tenant_id = '{A}'`,
		},
		call: `SELECT ctrlz_fn.worker_enforce_clear_without_live('panel.localhost')`,
	},
}

// TestGuardedFunctionsLeaveATrail is rule role-reach (c), generated from
// functions.yaml: every function that declares a `trail` is called as its one role
// under tenant A's setting, must add a row to each trail table it names (and none
// for tenant B), and the same role must then be unable to take the new row back,
// by DELETE or by UPDATE. This is what makes "a change of a second factor leaves a
// notice and an audit row" a property of the database and not of the caller.
func TestGuardedFunctionsLeaveATrail(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	aGUC := h.A.Tenant.String()
	var have []string
	for _, f := range h.fx.Functions.SecurityDefiner {
		if len(f.Trail) == 0 {
			continue
		}
		have = append(have, f.Name)
		sc, ok := trailScenarios[f.Name]
		if !ok {
			t.Errorf("function %s declares a trail and has no scenario in trailScenarios", f.Name)
			continue
		}
		if len(f.Execute) != 1 {
			t.Errorf("function %s must have exactly one executing role, has %v", f.Name, f.Execute)
			continue
		}
		role := f.Execute[0]
		t.Run(f.Name, func(t *testing.T) {
			for _, s := range sc.setup {
				h.exec(strings.ReplaceAll(s, "{A}", aGUC))
			}
			counts := func(tx pgx.Tx, tenant string) map[string]int {
				out := map[string]int{}
				asSuper(h, tx, role, func() {
					for _, tbl := range f.Trail {
						n, err := count(h.ctx, tx, "SELECT count(*) FROM ctrlz."+tbl+" WHERE tenant_id = $1", tenant)
						if err != nil {
							t.Fatal(err)
						}
						out[tbl] = n
					}
				})
				return out
			}
			h.inTx(h.super, role, &aGUC, func(tx pgx.Tx) {
				beforeA, beforeB := counts(tx, aGUC), counts(tx, h.B.Tenant.String())
				var n int
				if err := tx.QueryRow(h.ctx, sc.call, sc.args...).Scan(&n); err != nil || n == 0 {
					t.Fatalf("%s: %d, %v (the scenario must make the function act)", sc.call, n, err)
				}
				afterA, afterB := counts(tx, aGUC), counts(tx, h.B.Tenant.String())
				for _, tbl := range f.Trail {
					if afterA[tbl] <= beforeA[tbl] {
						t.Errorf("%s left no row in %s for the tenant it acted on", f.Name, tbl)
					}
					if afterB[tbl] != beforeB[tbl] {
						t.Errorf("%s wrote %d rows to %s of the other tenant", f.Name, afterB[tbl]-beforeB[tbl], tbl)
					}
					// The role cannot take the new row back. A privilege error or zero rows
					// deleted (the age policy) both hold it.
					for _, stmt := range []string{"DELETE FROM ctrlz." + tbl, "UPDATE ctrlz." + tbl + " SET tenant_id = tenant_id"} {
						sp, err := tx.Begin(h.ctx)
						if err != nil {
							t.Fatal(err)
						}
						_, err = sp.Exec(h.ctx, stmt)
						_ = sp.Rollback(h.ctx)
						if pe := pgErr(err); err != nil && (pe == nil || pe.Code != "42501") {
							t.Errorf("%s as %s: %v", stmt, role, err)
						}
					}
					if after := counts(tx, aGUC); after[tbl] != afterA[tbl] {
						t.Errorf("%s: %s as %s changed the trail table (%d rows, was %d)", f.Name, tbl, role, after[tbl], afterA[tbl])
					}
				}
			})
		})
	}
	for name := range trailScenarios {
		if !contains(have, name) {
			t.Errorf("trailScenarios has %s, which functions.yaml gives no trail", name)
		}
	}
	if len(have) == 0 {
		t.Fatal("functions.yaml declares no trail at all; the test proves nothing")
	}
}

// TestWorkerPendingSweepClearsOnlyUnconfirmedSetups (0020). The worker reads every
// login code, so it must not clear the seed of a user who has TOTP on. A column
// grant could not say "only unconfirmed", so the sweep is a function that does.
func TestWorkerPendingSweepClearsOnlyUnconfirmedSetups(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	aGUC := h.A.Tenant.String()
	const abandoned = `UPDATE ctrlz.users SET totp_secret_ct = 'C5a010001', totp_pending_at = now() - interval '20 minutes' WHERE tenant_id = $1`
	// sweep arranges A's user with a statement, B's as an abandoned setup, runs the
	// sweep as the worker under guc, and reports how many it cleared and whether each
	// tenant's seed is still there. The transaction is rolled back.
	sweep := func(arrangeA string, guc *string) (cleared int, aLive, bLive bool) {
		h.inTx(h.super, "worker", guc, func(tx pgx.Tx) {
			asSuper(h, tx, "worker", func() {
				for _, a := range []struct{ sql, tenant string }{{"UPDATE ctrlz.users SET totp_secret_ct = NULL, totp_enabled_at = NULL, totp_pending_at = NULL", ""}, {arrangeA, aGUC}, {abandoned, h.B.Tenant.String()}} {
					var err error
					if a.tenant == "" {
						_, err = tx.Exec(h.ctx, a.sql)
					} else {
						_, err = tx.Exec(h.ctx, a.sql, a.tenant)
					}
					if err != nil {
						t.Fatal(err)
					}
				}
			})
			if err := tx.QueryRow(h.ctx, "SELECT ctrlz_fn.worker_sweep_pending_totp(1000)").Scan(&cleared); err != nil {
				t.Fatal(err)
			}
			asSuper(h, tx, "worker", func() {
				for tenant, live := range map[string]*bool{aGUC: &aLive, h.B.Tenant.String(): &bLive} {
					if err := tx.QueryRow(h.ctx, "SELECT totp_secret_ct IS NOT NULL FROM ctrlz.users WHERE tenant_id = $1", tenant).Scan(live); err != nil {
						t.Fatal(err)
					}
				}
			})
		})
		return
	}
	for _, c := range []struct {
		name    string
		sql     string
		cleared int
	}{
		{"an abandoned setup", abandoned, 1},
		{"a setup still inside its 15 minutes", `UPDATE ctrlz.users SET totp_secret_ct = 'C5a010001', totp_pending_at = now() - interval '5 minutes' WHERE tenant_id = $1`, 0},
		{"an enabled factor", `UPDATE ctrlz.users SET totp_secret_ct = 'C5a010001', totp_enabled_at = now() - interval '2 days' WHERE tenant_id = $1`, 0},
		{"an enabled factor with a stale pending time", `UPDATE ctrlz.users SET totp_secret_ct = 'C5a010001', totp_enabled_at = now() - interval '2 days', totp_pending_at = now() - interval '2 days' WHERE tenant_id = $1`, 0},
	} {
		cleared, aLive, bLive := sweep(c.sql, &aGUC)
		if cleared != c.cleared || aLive == (c.cleared == 1) {
			t.Errorf("%s: cleared %d (want %d), A's seed live = %v", c.name, cleared, c.cleared, aLive)
		}
		if !bLive {
			t.Errorf("%s: a sweep under A's setting cleared B's abandoned setup", c.name)
		}
	}
	// No tenant setting, no sweep.
	if cleared, aLive, bLive := sweep(abandoned, nil); cleared != 0 || !aLive || !bLive {
		t.Errorf("without a tenant setting the sweep cleared %d (A live %v, B live %v)", cleared, aLive, bLive)
	}
}

// TestKeytoolReplaceIsACompareAndSwap (0020). The rekey tool re-seals seeds; with a
// plain UPDATE grant it could write NULL and switch a user's second factor off.
func TestKeytoolReplaceIsACompareAndSwap(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	aGUC := h.A.Tenant.String()
	old := []byte{0x43, 0x5a, 0x01, 0x00, 0x01, 0xaa}
	h.exec(`UPDATE ctrlz.users SET totp_secret_ct = $1, totp_enabled_at = now()`, old)
	for _, sql := range []string{
		`UPDATE ctrlz.users SET totp_secret_ct = NULL`,
		`UPDATE ctrlz.users SET totp_secret_ct = '\x00'`,
	} {
		if !h.denied("keytool", &aGUC, sql) {
			t.Errorf("the key tool could run %q", sql)
		}
	}
	try := func(guc *string, user any, o, n []byte) (ok bool) {
		h.inTx(h.super, "keytool", guc, func(tx pgx.Tx) {
			if err := tx.QueryRow(h.ctx, `SELECT ctrlz_fn.keytool_totp_replace($1, $2, $3)`, user, o, n).Scan(&ok); err != nil {
				t.Fatal(err)
			}
		})
		return
	}
	next := []byte{0x43, 0x5a, 0x01, 0x00, 0x02, 0xbb}
	for _, c := range []struct {
		name string
		guc  *string
		user any
		old  []byte
		new  []byte
	}{
		{"a wrong old value", &aGUC, h.A.User, []byte("not the seed"), next},
		{"a NULL replacement", &aGUC, h.A.User, old, nil},
		{"a too short replacement", &aGUC, h.A.User, old, []byte{1}},
		{"B's user under A's setting", &aGUC, h.B.User, old, next},
		{"no tenant setting", nil, h.A.User, old, next},
		{"a NULL user", &aGUC, nil, old, next},
	} {
		if try(c.guc, c.user, c.old, c.new) {
			t.Errorf("%s: the swap went through", c.name)
		}
	}
	var ct []byte
	if err := h.super.QueryRow(h.ctx, `SELECT totp_secret_ct FROM ctrlz.users WHERE id = $1`, h.A.User).Scan(&ct); err != nil || string(ct) != string(old) {
		t.Fatalf("a refused swap changed the seed: %x %v", ct, err)
	}
	if !try(&aGUC, h.A.User, old, next) {
		t.Error("the swap with the right old value and a plausible new one was refused")
	}
}

// TestAdminTOTPReplaceIsACompareAndSwap (0033, db-r7-4): the admin's own rekey swap is a
// definer function like the key tool's, so a re-seal is a writer the trigger can recognise.
// It cannot write NULL or a short value, cannot overwrite a seed the admin changed in the
// meantime, and no other role can call it.
func TestAdminTOTPReplaceIsACompareAndSwap(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	const adminID = "00000000-0000-7000-8000-0000000000e1"
	old := []byte{0x43, 0x5a, 0x01, 0x00, 0x01, 0xaa}
	next := []byte{0x43, 0x5a, 0x01, 0x00, 0x02, 0xbb}
	h.exec(`UPDATE ctrlz.admin_users SET totp_secret_ct = $1, totp_enabled_at = now() WHERE id = $2`, old, adminID)
	try := func(role string, id any, o, n []byte) (ok bool) {
		h.inTx(h.super, role, nil, func(tx pgx.Tx) {
			if err := tx.QueryRow(h.ctx, `SELECT ctrlz_fn.admin_totp_replace($1, $2, $3)`, id, o, n).Scan(&ok); err != nil {
				if pe := pgErr(err); pe != nil && pe.Code == "42501" {
					ok = false
					return
				}
				t.Fatal(err)
			}
		})
		return
	}
	for _, c := range []struct {
		name string
		id   any
		old  []byte
		new  []byte
	}{
		{"a wrong old value", adminID, []byte("not the seed"), next},
		{"a NULL replacement", adminID, old, nil},
		{"a too short replacement", adminID, old, []byte{1}},
		{"a NULL admin", nil, old, next},
	} {
		if try("admin", c.id, c.old, c.new) {
			t.Errorf("%s: the swap went through", c.name)
		}
	}
	for _, role := range []string{"tenant", "worker", "keytool", "hub", "compiler"} {
		if try(role, adminID, old, next) {
			t.Errorf("ctrlz_%s ran the admin's seed swap", role)
		}
	}
	var ct []byte
	if err := h.super.QueryRow(h.ctx, `SELECT totp_secret_ct FROM ctrlz.admin_users WHERE id = $1`, adminID).Scan(&ct); err != nil || string(ct) != string(old) {
		t.Fatalf("a refused swap changed the seed: %x %v", ct, err)
	}
	if !try("admin", adminID, old, next) {
		t.Error("the swap with the right old value and a plausible new one was refused")
	}
}

// TestAdminInviteColumns (0020). The admin queues and revokes invites. It cannot
// read a token hash, and cannot mark an invite used or accepted: that is
// auth_register_user's, so a used invite stays used.
func TestAdminInviteColumns(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	for _, sql := range []string{
		`SELECT token_hash FROM ctrlz.invites`,
		`UPDATE ctrlz.invites SET used_at = NULL`,
		`UPDATE ctrlz.invites SET accepted_tenant_id = NULL`,
		`UPDATE ctrlz.invites SET token_hash = '\x01'`,
		`UPDATE ctrlz.invites SET expires_at = now() + interval '1 year'`,
	} {
		if !h.denied("admin", nil, sql) {
			t.Errorf("the admin role could run %q", sql)
		}
	}
	h.inTx(h.super, "admin", nil, func(tx pgx.Tx) {
		var id string
		if err := tx.QueryRow(h.ctx, `INSERT INTO ctrlz.invites (token_hash, phone_e164, locale, expires_at) VALUES (decode(repeat('cd', 32), 'hex'), '+989121110000', 'fa', now() + interval '1 day') RETURNING id::text`).Scan(&id); err != nil {
			t.Fatalf("the admin's invite insert: %v", err)
		}
		tag, err := tx.Exec(h.ctx, `UPDATE ctrlz.invites SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL AND used_at IS NULL`, id)
		if err != nil || tag.RowsAffected() != 1 {
			t.Errorf("the admin's revoke: %d rows, %v", tag.RowsAffected(), err)
		}
	})
}

// TestWorkerSweepsDeliveriesByFunction (0020). The worker appends to
// sms_deliveries and cannot delete from it; the function removes only rows past 90
// days, in a bounded batch.
func TestWorkerSweepsDeliveriesByFunction(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	if !h.denied("worker", nil, `DELETE FROM ctrlz.sms_deliveries`) {
		t.Error("the worker can delete delivery records")
	}
	h.exec(`DELETE FROM ctrlz.sms_deliveries`)
	for i, age := range []string{"100 days", "91 days", "89 days", "1 hour"} {
		h.exec(fmt.Sprintf(`INSERT INTO ctrlz.sms_deliveries (source, source_id, provider, template_key, outcome, created_at) VALUES ('otp', gen_random_uuid(), 'test', 'otp', 'accepted', now() - interval '%s')`, age))
		_ = i
	}
	h.inTx(h.super, "worker", nil, func(tx pgx.Tx) {
		var n int
		for _, limit := range []any{0, nil, -3} {
			if err := tx.QueryRow(h.ctx, `SELECT ctrlz_fn.worker_sweep_sms_deliveries($1)`, limit).Scan(&n); err != nil || n != 0 {
				t.Errorf("limit %v: deleted %d, %v", limit, n, err)
			}
		}
		if err := tx.QueryRow(h.ctx, `SELECT ctrlz_fn.worker_sweep_sms_deliveries(1)`).Scan(&n); err != nil || n != 1 {
			t.Errorf("a batch of one deleted %d, %v", n, err)
		}
		if err := tx.QueryRow(h.ctx, `SELECT ctrlz_fn.worker_sweep_sms_deliveries(100)`).Scan(&n); err != nil || n != 1 {
			t.Errorf("the rest of the old rows: %d, %v", n, err)
		}
		asSuper(h, tx, "worker", func() {
			if left, err := count(h.ctx, tx, `SELECT count(*) FROM ctrlz.sms_deliveries`); err != nil || left != 2 {
				t.Errorf("%d rows left, want the two young ones (%v)", left, err)
			}
		})
	})
}

// TestGuardedFunctionCheckReadsEveryWayToWrite plants a definer function whose body writes a
// guarded table in a way a pattern would miss, and requires check 23 to see it (db-r6-2): the
// body is read by the lexer of the lock order, so UPDATE ONLY, quoting, spacing, upper case
// and comments are the same write, and a body that cannot be read at all (MERGE, dynamic SQL)
// is refused instead of being read as writing nothing.
func TestGuardedFunctionCheckReadsEveryWayToWrite(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	for _, m := range []struct{ name, body, want string }{
		{"UPDATE ONLY", `UPDATE ONLY ctrlz.sessions SET revoked_at = NULL;`, "writes guarded sessions"},
		{"an upper case schema and table", `UPDATE CTRLZ.USERS SET theme = 'x';`, "writes guarded users"},
		{"quoted names", `UPDATE "ctrlz"."sessions" SET revoked_at = NULL;`, "writes guarded sessions"},
		{"spaces around the dot", `DELETE FROM ctrlz . sessions;`, "writes guarded sessions"},
		{"a comment between the table and SET", `UPDATE ctrlz.sessions /* why */ SET revoked_at = NULL;`, "writes guarded sessions"},
		{"a comment between the verb and the table", `UPDATE /* why */ ctrlz.sessions SET revoked_at = NULL;`, "writes guarded sessions"},
		{"MERGE", `MERGE INTO ctrlz.users u USING ctrlz.sessions s ON true WHEN MATCHED THEN DELETE;`, "cannot be read for its writes"},
		{"dynamic SQL", `EXECUTE 'UPDATE ctrlz.sessions SET revoked_at = NULL';`, "cannot be read for its writes"},
		{"a capitalised quoted name", `UPDATE ctrlz."Sessions" SET revoked_at = NULL;`, "cannot be read for its writes"},
	} {
		t.Run(m.name, func(t *testing.T) {
			tx, err := h.super.Begin(h.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			if _, err := tx.Exec(h.ctx, `CREATE FUNCTION ctrlz_fn.zz_planted() RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $x$ BEGIN `+m.body+` END $x$`); err != nil {
				t.Fatalf("the planted function does not compile: %v", err)
			}
			fx := *h.fx
			fx.Functions.SecurityDefiner = append(append([]catalogtest.SDFunction(nil), h.fx.Functions.SecurityDefiner...), catalogtest.SDFunction{Name: "zz_planted"})
			v, err := catalogtest.CheckGuardedFunctions(h.ctx, tx, &fx)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(strings.Join(v, "\n"), m.want) {
				t.Errorf("check 23 did not report %q for a body that does `%s`; it said %v", m.want, m.body, v)
			}
		})
	}
}

// TestRoleReachIgnoresFixedWidthColumns is the other half of the name test (db-r6-3, narrowed in
// db-r7-5): a time, a flag or an address cannot hold a credential, so a name like
// password_changed_at or password_ok is not asked about, and the check does not drown in false
// findings. An integer is different: a 6 digit code fits one, so max_tokens IS asked, and the
// answer is a line under read_open. The same holds for the personal class since db-r8-2: a phone
// fits a bigint, so an integer named like one is asked (TestPersonalDataIsDecidedByTypeAndNotOnlyByName).
func TestRoleReachIgnoresFixedWidthColumns(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	v := breakIn(t, h, h.fx,
		"ALTER TABLE ctrlz.endpoints ADD COLUMN key_rotated_at timestamptz",
		"ALTER TABLE ctrlz.endpoints ADD COLUMN password_ok boolean",
		"ALTER TABLE ctrlz.endpoints ADD COLUMN phone_checked_at timestamptz",
		"ALTER TABLE ctrlz.endpoints ADD COLUMN show_ip boolean",
		"ALTER TABLE ctrlz.endpoints ADD COLUMN token_window interval",
		"ALTER TABLE ctrlz.endpoints ADD COLUMN code_range int4range")
	if len(v) != 0 {
		t.Errorf("columns that cannot hold a credential or a value were reported: %v", v)
	}
	v = breakIn(t, h, h.fx, "ALTER TABLE ctrlz.endpoints ADD COLUMN max_tokens integer")
	if !strings.Contains(strings.Join(v, "\n"), "endpoints.max_tokens (integer) has a secret-looking name") {
		t.Errorf("an integer named like a token was not asked about: %v", v)
	}
}
