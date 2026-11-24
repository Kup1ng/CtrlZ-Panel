package catalogtest_test

import (
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store/catalogtest"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

// scopedGlobalReach are the global (no row-level security) tables ctrlz_scoped may read, each with the reason.
// Every other table it reaches is a tenant table, where tenant_isolation is the only policy it meets. A global
// table that holds anything of anybody needs a line here, and so a person who decides it.
var scopedGlobalReach = map[string]string{
	"announcements":   "operator announcements, shown to every tenant by audience (announcements_for_tenant)",
	"nodes":           "the operator's node list: only the advertised address, which every endpoint page shows (endpoint_pair_ips)",
	"node_pairs":      "the operator's node pairs, which the endpoint addresses are resolved through",
	"public_settings": "the global pair, one row of operator settings",
	"webauthn_config": "the one RP ID configuration row (rp_id), which the passkey jobs compare a credential with",
}

// TestScopedRoleSeesOneTenantOnEveryTableItReaches is the behaviour half of db-r18-1, read from the LIVE catalog
// and not from a list of ours: for every table of ctrlz on which ctrlz_scoped holds any privilege, as the role,
// with the tenant setting at A it sees A's rows and none of B's, with the setting at B the other way round, and
// with the setting unset, empty or a third tenant's it sees nothing. A definer function owned by ctrlz_scoped
// therefore cannot read another tenant's row even when its body forgets the predicate, on any table it ever
// touches. A table it reaches that is global must be in scopedGlobalReach with the reason.
func TestScopedRoleSeesOneTenantOnEveryTableItReaches(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	rows, err := h.super.Query(h.ctx, `
SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace AND n.nspname = 'ctrlz'
WHERE c.relkind IN ('r', 'p') AND (has_any_column_privilege('ctrlz_scoped', c.oid, 'SELECT') OR has_any_column_privilege('ctrlz_scoped', c.oid, 'UPDATE')
   OR has_any_column_privilege('ctrlz_scoped', c.oid, 'INSERT') OR has_table_privilege('ctrlz_scoped', c.oid, 'DELETE'))
ORDER BY 1`)
	if err != nil {
		t.Fatal(err)
	}
	var reached []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		reached = append(reached, n)
	}
	rows.Close()
	if len(reached) == 0 {
		t.Fatal("ctrlz_scoped reaches no table: the premise of the test is gone")
	}
	tenantTable := map[string]bool{}
	for _, tbl := range h.fx.Tables.Tenant {
		tenantTable[tbl] = true
	}
	a, b := h.A.Tenant.String(), h.B.Tenant.String()
	third := uuid.Must(uuid.NewV7()).String()
	for _, tbl := range reached {
		if !tenantTable[tbl] {
			if _, ok := scopedGlobalReach[tbl]; !ok && tbl != "tenants" {
				t.Errorf("ctrlz_scoped reaches the global table %s, which is not in scopedGlobalReach: say why a function that acts for one tenant needs it", tbl)
			}
			continue
		}
		// A table the role can only write (notifications, tenant_audit_log) has nothing to count; its INSERT and
		// UPDATE across tenants are refused by the WITH CHECK of tenant_isolation, which TestTwoTenantIsolation
		// drives for every role with a grant, this one included.
		var canRead bool
		if err := h.super.QueryRow(h.ctx, "SELECT has_any_column_privilege('ctrlz_scoped', $1::regclass, 'SELECT')", ident(tbl)).Scan(&canRead); err != nil {
			t.Fatal(err)
		}
		if !canRead {
			continue
		}
		key := h.fx.KeyColumn(tbl)
		var own [2]int
		for i, id := range []uuid.UUID{h.A.Tenant, h.B.Tenant} {
			if err := h.super.QueryRow(h.ctx, "SELECT count(*) FROM "+ident(tbl)+" WHERE "+key+" = $1", id).Scan(&own[i]); err != nil {
				t.Fatal(err)
			}
		}
		if own[0] == 0 || own[1] == 0 {
			t.Fatalf("%s has no seed row for a tenant: the test would prove nothing", tbl)
		}
		for _, c := range []struct {
			name string
			guc  *string
			want int
		}{{"tenant A", &a, own[0]}, {"tenant B", &b, own[1]}, {"a third tenant", &third, 0}, {"an empty setting", str(""), 0}, {"no setting", nil, 0}} {
			h.inTx(h.fresh(), "scoped", c.guc, func(tx pgx.Tx) {
				var n int
				if err := tx.QueryRow(h.ctx, "SELECT count(*) FROM "+ident(tbl)).Scan(&n); err != nil {
					t.Errorf("%s as ctrlz_scoped with %s: %v", tbl, c.name, err)
					return
				}
				if n != c.want {
					t.Errorf("%s as ctrlz_scoped with %s sees %d rows, want %d", tbl, c.name, n, c.want)
				}
			})
		}
	}
	// The tenants table is the tenant's own row.
	for _, c := range []struct {
		guc  *string
		want int
	}{{&a, 1}, {&b, 1}, {&third, 0}, {nil, 0}} {
		h.inTx(h.fresh(), "scoped", c.guc, func(tx pgx.Tx) {
			var n int
			if err := tx.QueryRow(h.ctx, "SELECT count(*) FROM ctrlz.tenants").Scan(&n); err != nil {
				t.Error(err)
				return
			}
			if n != c.want {
				t.Errorf("tenants as ctrlz_scoped sees %d rows, want %d", n, c.want)
			}
		})
	}
}

// TestDefinerOwnerListCanFail is the can-fail test of the closed list of db-r18-1. Catalog check 10 judges the
// live owner of every definer function against functions.yaml, and the file against itself: a function owned by
// ctrlz_auth with no reason, one that says scoped while ctrlz_auth owns it, a scoped function whose isolation is
// not a tenant, and an owner that is neither are each reported.
func TestDefinerOwnerListCanFail(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	check := func(mutate func(fx *catalogtest.Fixtures)) string {
		t.Helper()
		fx := mustFixtures(t)
		mutate(fx)
		var ck catalogtest.Check
		for _, c := range catalogtest.Checks() {
			if c.ID == "10" {
				ck = c
			}
		}
		out, err := ck.Run(h.ctx, h.super, fx)
		if err != nil {
			t.Fatal(err)
		}
		return strings.Join(out, "\n")
	}
	find := func(fx *catalogtest.Fixtures, name string) *catalogtest.SDFunction {
		for i := range fx.Functions.SecurityDefiner {
			if fx.Functions.SecurityDefiner[i].Name == name {
				return &fx.Functions.SecurityDefiner[i]
			}
		}
		t.Fatalf("no function %s in functions.yaml", name)
		return nil
	}
	if got := check(func(*catalogtest.Fixtures) {}); got != "" {
		t.Fatalf("check 10 reports on the real files: %s", got)
	}
	for name, c := range map[string]struct {
		mutate func(fx *catalogtest.Fixtures)
		want   string
	}{
		"an auth-owned function with no reason": {func(fx *catalogtest.Fixtures) { find(fx, "auth_session_by_hash").AuthOwnerReason = "" }, "has no auth_owner_reason"},
		"a function that says scoped while ctrlz_auth owns it": {func(fx *catalogtest.Fixtures) {
			f := find(fx, "ip_claim_take")
			f.Owner, f.AuthOwnerReason = "scoped", ""
		}, "owner is ctrlz_auth, functions.yaml says ctrlz_scoped"},
		"a function that says auth while ctrlz_scoped owns it": {func(fx *catalogtest.Fixtures) {
			f := find(fx, "tenant_set_password")
			f.Owner, f.AuthOwnerReason = "auth", "x"
		}, "owner is ctrlz_scoped, functions.yaml says ctrlz_auth"},
		"a scoped function that is not about a tenant": {func(fx *catalogtest.Fixtures) { find(fx, "tenant_set_password").Isolation = "key" }, "a scoped function acts for the tenant of the call"},
		"a reason on a scoped function":                {func(fx *catalogtest.Fixtures) { find(fx, "tenant_set_password").AuthOwnerReason = "x" }, "owner: scoped has an auth_owner_reason"},
		"an owner that is neither":                     {func(fx *catalogtest.Fixtures) { find(fx, "tenant_set_password").Owner = "" }, "want auth or scoped"},
	} {
		if got := check(c.mutate); !strings.Contains(got, c.want) {
			t.Errorf("%s: check 10 did not report %q:\n%s", name, c.want, got)
		}
	}
	// A policy that applies to ctrlz_scoped and is not tenant_isolation, and a role attribute that lets it past
	// row-level security, are reported by the other half of the construction. Each way is planted alone and
	// undone at once (the role is the cluster's, not this database's), because a clause of the check that nothing
	// plants is a clause that can rot unseen (db-r18-22): a policy for the role, one for PUBLIC, a RESTRICTIVE
	// one, and each of the four attributes.
	for _, c := range []struct{ name, plant, undo, want string }{
		{"a policy for the role", `CREATE POLICY planted ON ctrlz.users FOR SELECT TO ctrlz_scoped USING (true)`, `DROP POLICY planted ON ctrlz.users`, "policy planted on users"},
		{"a policy for PUBLIC", `CREATE POLICY planted_public ON ctrlz.sessions FOR SELECT USING (true)`, `DROP POLICY planted_public ON ctrlz.sessions`, "policy planted_public on sessions"},
		{"a RESTRICTIVE policy", `CREATE POLICY planted_restrictive ON ctrlz.sessions AS RESTRICTIVE FOR SELECT TO ctrlz_scoped USING (true)`, `DROP POLICY planted_restrictive ON ctrlz.sessions`, "policy planted_restrictive on sessions"},
		{"BYPASSRLS", `ALTER ROLE ctrlz_scoped BYPASSRLS`, `ALTER ROLE ctrlz_scoped NOBYPASSRLS`, "ctrlz_scoped has BYPASSRLS"},
		{"SUPERUSER", `ALTER ROLE ctrlz_scoped SUPERUSER`, `ALTER ROLE ctrlz_scoped NOSUPERUSER`, "ctrlz_scoped has SUPERUSER"},
		{"LOGIN", `ALTER ROLE ctrlz_scoped LOGIN`, `ALTER ROLE ctrlz_scoped NOLOGIN`, "ctrlz_scoped has LOGIN"},
		{"CREATEROLE", `ALTER ROLE ctrlz_scoped CREATEROLE`, `ALTER ROLE ctrlz_scoped NOCREATEROLE`, "ctrlz_scoped has CREATEROLE"},
	} {
		if got, err := catalogtest.ScopedPolicyFindings(h.ctx, h.super); err != nil || len(got) != 0 {
			t.Fatalf("before %s the check reports %v (%v)", c.name, got, err)
		}
		if _, err := h.super.Exec(h.ctx, c.plant); err != nil {
			t.Fatalf("%s: %v", c.plant, err)
		}
		got, err := catalogtest.ScopedPolicyFindings(h.ctx, h.super)
		if _, uerr := h.super.Exec(h.ctx, c.undo); uerr != nil {
			t.Fatalf("%s: %v", c.undo, uerr)
		}
		if err != nil {
			t.Fatal(err)
		}
		if all := strings.Join(got, "\n"); !strings.Contains(all, c.want) {
			t.Errorf("%s: ScopedPolicyFindings did not report %q:\n%s", c.name, c.want, all)
		}
	}
}
