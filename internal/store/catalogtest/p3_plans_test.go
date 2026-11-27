package catalogtest_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Kup1ng/CtrlZ-Panel/internal/migrate"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

// Tests of the plans model of migration 0074 (D56, T-562, spec P3 2.4). Every test of the cap
// readers uses two tenants on two different plans, so a reader that reads the wrong tenant's plan,
// or the default plan for everybody, fails.

// planCols are the eleven limit columns of a plan, in the order of the migration.
var planCols = []string{"max_profiles", "max_endpoints", "max_clients_per_endpoint", "max_authorized_ips", "max_api_tokens",
	"max_rules_per_request", "max_rules_per_profile", "max_wildcards_per_profile", "max_realtime_sessions",
	"max_publishes_per_hour", "max_ip_claims"}

// insertPlan adds a plan that copies the default plan's limits and returns its id.
func (h *harness) insertPlan(name string) uuid.UUID {
	h.t.Helper()
	var id uuid.UUID
	cols := strings.Join(planCols, ", ")
	if err := h.super.QueryRow(h.ctx, `INSERT INTO ctrlz.plans (name, `+cols+`) SELECT $1, `+cols+
		` FROM ctrlz.plans WHERE is_default RETURNING id`, name).Scan(&id); err != nil {
		h.t.Fatalf("insert plan %s: %v", name, err)
	}
	return id
}

// commit runs the statements in one transaction and commits, and returns the SQLSTATE of the first
// failure ("" for none). The deferred check of plans_one_default_row runs here, at the commit, which
// a rolled-back h.try never reaches.
func (h *harness) commit(sqls ...string) string {
	h.t.Helper()
	tx, err := h.super.Begin(h.ctx)
	if err != nil {
		h.t.Fatal(err)
	}
	defer tx.Rollback(h.ctx)
	for _, s := range sqls {
		if _, err := tx.Exec(h.ctx, s); err != nil {
			if pe := pgErr(err); pe != nil {
				return pe.Code
			}
			h.t.Fatalf("%s: %v", s, err)
		}
	}
	if err := tx.Commit(h.ctx); err != nil {
		if pe := pgErr(err); pe != nil {
			return pe.Code
		}
		h.t.Fatalf("commit: %v", err)
	}
	return ""
}

func (h *harness) str(sql string, args ...any) string {
	h.t.Helper()
	var s string
	if err := h.super.QueryRow(h.ctx, sql, args...).Scan(&s); err != nil {
		h.t.Fatalf("%s: %v", sql, err)
	}
	return s
}

// TestPlansModel: the table the migration made, its CHECKs, the one default, and the rule that a
// plan in use or the default is never deleted.
func TestPlansModel(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))

	// The free plan holds the values entitlement_defaults held (D31 numbers, 10,000 rules per request
	// since P2), and every tenant is on it.
	want := map[string]int{"max_profiles": 20, "max_endpoints": 50, "max_clients_per_endpoint": 1000, "max_authorized_ips": 50,
		"max_api_tokens": 10, "max_rules_per_request": 10000, "max_rules_per_profile": 10000, "max_wildcards_per_profile": 1000,
		"max_realtime_sessions": 3, "max_publishes_per_hour": 120, "max_ip_claims": 50}
	if len(want) != len(planCols) {
		t.Fatalf("the test knows %d limits, the plans table %d", len(want), len(planCols))
	}
	for col, n := range want {
		if got := h.one(`SELECT ` + col + ` FROM ctrlz.plans WHERE is_default`); got != n {
			t.Errorf("the free plan's %s is %d, want %d", col, got, n)
		}
	}
	if n := h.one(`SELECT count(*) FROM ctrlz.plans`); n != 1 {
		t.Errorf("%d plans, want only the free one", n)
	}
	if name := h.str(`SELECT name FROM ctrlz.plans WHERE is_default`); name != "Free" {
		t.Errorf("the default plan is %q", name)
	}
	if n := h.one(`SELECT count(*) FROM ctrlz.tenants WHERE plan_id = (SELECT id FROM ctrlz.plans WHERE is_default)`); n != 2 {
		t.Errorf("%d seeded tenants on the free plan, want 2", n)
	}

	// The CHECKs, NOT NULLs and the unique name are those of the table it replaces.
	for _, c := range []struct{ what, sql, code string }{
		{"a negative limit", `UPDATE ctrlz.plans SET max_profiles = -1`, "23514"},
		{"a NULL limit", `UPDATE ctrlz.plans SET max_endpoints = NULL`, "23502"},
		{"a limit of zero", `UPDATE ctrlz.plans SET max_ip_claims = 0`, ""},
		{"rules per profile above the document bound", `UPDATE ctrlz.plans SET max_rules_per_profile = 10001`, "23514"},
		{"rules per profile at the document bound", `UPDATE ctrlz.plans SET max_rules_per_profile = 10000`, ""},
		{"an empty name", `UPDATE ctrlz.plans SET name = ''`, "23514"},
		{"a name of 65 characters", `UPDATE ctrlz.plans SET name = repeat('x', 65)`, "23514"},
		{"a limit-less plan", `INSERT INTO ctrlz.plans (name) VALUES ('Empty')`, "23502"},
		{"a second plan of the same name", `INSERT INTO ctrlz.plans (name, ` + strings.Join(planCols, ", ") + `) SELECT name, ` +
			strings.Join(planCols, ", ") + ` FROM ctrlz.plans`, "23505"},
		{"a second default", `INSERT INTO ctrlz.plans (name, is_default, ` + strings.Join(planCols, ", ") + `) SELECT 'Other', true, ` +
			strings.Join(planCols, ", ") + ` FROM ctrlz.plans`, "23505"},
		{"a tenant on no plan", `UPDATE ctrlz.tenants SET plan_id = NULL`, "23502"},
		{"a tenant on a plan that does not exist", `UPDATE ctrlz.tenants SET plan_id = gen_random_uuid()`, "23503"},
	} {
		if got := h.try("", nil, c.sql); got != c.code {
			t.Errorf("%s: SQLSTATE %q, want %q", c.what, got, c.code)
		}
	}

	free := h.str(`SELECT id::text FROM ctrlz.plans WHERE is_default`)
	small := h.insertPlan("Small")
	spare := h.insertPlan("Spare")
	// A plan nobody uses goes.
	if code := h.commit(fmt.Sprintf(`DELETE FROM ctrlz.plans WHERE id = '%s'`, spare)); code != "" {
		t.Errorf("deleting an unused plan: %q", code)
	}
	// A plan a tenant uses does not, and neither does the default while a tenant is on it.
	b := h.B.Tenant.String()
	h.exec(`UPDATE ctrlz.tenants SET plan_id = $1 WHERE id = $2`, small, b)
	if got := h.try("", nil, `DELETE FROM ctrlz.plans WHERE id = $1`, small); got != "23001" {
		t.Errorf("deleting a plan a tenant uses: %q, want 23001", got)
	}
	if got := h.try("", nil, `DELETE FROM ctrlz.plans WHERE id = $1`, free); got != "23001" {
		t.Errorf("deleting the plan the other tenant is on: %q, want 23001", got)
	}
	// The default cannot be unset, nor deleted when no tenant holds it: the commit finds none.
	if got := h.commit(`UPDATE ctrlz.plans SET is_default = false WHERE is_default`); got != "23514" {
		t.Errorf("unsetting the default: %q, want 23514 at commit", got)
	}
	if got := h.commit(`UPDATE ctrlz.tenants SET plan_id = '`+small.String()+`'`, `DELETE FROM ctrlz.plans WHERE is_default`); got != "23514" {
		t.Errorf("deleting the default plan: %q, want 23514 at commit", got)
	}
	if n := h.one(`SELECT count(*) FROM ctrlz.plans WHERE is_default AND id = $1`, free); n != 1 {
		t.Errorf("the refused changes left the default as %d rows", n)
	}
	// Moving the default is two statements in one transaction, and leaves exactly one.
	if got := h.commit(`UPDATE ctrlz.plans SET is_default = false WHERE is_default`,
		`UPDATE ctrlz.plans SET is_default = true WHERE name = 'Small'`); got != "" {
		t.Errorf("moving the default: %q", got)
	}
	if name := h.str(`SELECT name FROM ctrlz.plans WHERE is_default`); name != "Small" {
		t.Errorf("after the move the default is %q", name)
	}
	// Two defaults in one transaction fail at once (the unique index), not at commit.
	if got := h.commit(`UPDATE ctrlz.plans SET is_default = true WHERE name = 'Free'`); got != "23505" {
		t.Errorf("a second default: %q, want 23505", got)
	}
}

// TestPlansReach: what each role can read of a plan, and that the tenant role reads only its own,
// through ctrlz_fn.tenant_plan().
func TestPlansReach(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	a, b := h.A.Tenant.String(), h.B.Tenant.String()
	small := h.insertPlan("Small")
	h.exec(`UPDATE ctrlz.plans SET max_profiles = 3 WHERE id = $1`, small)
	h.exec(`UPDATE ctrlz.tenants SET plan_id = $1 WHERE id = $2`, small, b)

	// No role that serves a tenant reads the table or the column.
	for _, role := range []string{"tenant", "worker", "hub"} {
		if !h.denied(role, &a, `SELECT name FROM ctrlz.plans`) {
			t.Errorf("%s read plans", role)
		}
		if !h.denied(role, &a, `SELECT plan_id FROM ctrlz.tenants`) {
			t.Errorf("%s read tenants.plan_id", role)
		}
	}
	// The function answers the caller's own plan.
	for _, c := range []struct {
		role, tenant, plan string
		profiles           int
	}{{"tenant", a, "Free", 20}, {"tenant", b, "Small", 3}, {"worker", a, "Free", 20}, {"worker", b, "Small", 3}} {
		tenant := c.tenant
		h.inTx(h.super, c.role, &tenant, func(tx pgx.Tx) {
			var name string
			var profiles, rows int
			r, err := tx.Query(h.ctx, `SELECT name, max_profiles FROM ctrlz_fn.tenant_plan()`)
			if err != nil {
				t.Fatal(err)
			}
			for r.Next() {
				rows++
				if err := r.Scan(&name, &profiles); err != nil {
					t.Fatal(err)
				}
			}
			r.Close()
			if rows != 1 || name != c.plan || profiles != c.profiles {
				t.Errorf("%s of %s: %d rows, plan %q with %d profiles, want %q with %d", c.role, c.plan, rows, name, profiles, c.plan, c.profiles)
			}
		})
	}
	// No tenant setting, no plan.
	h.inTx(h.super, "tenant", nil, func(tx pgx.Tx) {
		if _, err := tx.Exec(h.ctx, `SELECT pg_catalog.set_config('ctrlz.tenant_id', '', true)`); err != nil {
			t.Fatal(err)
		}
		if n, err := count(h.ctx, tx, `SELECT count(*) FROM ctrlz_fn.tenant_plan()`); err != nil || n != 0 {
			t.Errorf("the plan of no tenant: %d rows, %v", n, err)
		}
	})
	// Roles with no business in a tenant's plan cannot call it.
	for _, role := range []string{"hub", "compiler", "admin"} {
		if !h.denied(role, &a, `SELECT * FROM ctrlz_fn.tenant_plan()`) {
			t.Errorf("%s called tenant_plan", role)
		}
	}
	// The admin and the compiler read the table and write nothing of it (the writes are P7).
	for _, role := range []string{"admin", "compiler"} {
		if h.denied(role, nil, `SELECT name, max_profiles FROM ctrlz.plans`) {
			t.Errorf("%s cannot read plans", role)
		}
		for _, w := range []string{`UPDATE ctrlz.plans SET max_profiles = 1`, `DELETE FROM ctrlz.plans`,
			`INSERT INTO ctrlz.plans (name) VALUES ('x')`} {
			if !h.denied(role, nil, w) {
				t.Errorf("%s ran %q", role, w)
			}
		}
	}
	if !h.denied("admin", nil, `UPDATE ctrlz.tenants SET plan_id = plan_id`) {
		t.Error("the admin role changed a tenant's plan with no route and no audit row behind it")
	}
	// ctrlz_auth reads three columns, no name and no limit but max_ip_claims.
	if h.denied("auth", nil, `SELECT id, is_default, max_ip_claims FROM ctrlz.plans`) {
		t.Error("auth cannot read what the creators and the claim functions need")
	}
	if !h.denied("auth", nil, `SELECT max_profiles FROM ctrlz.plans`) {
		t.Error("auth read max_profiles")
	}
}

// TestCapReadersTakeTheTenantsOwnPlan: the limit of the claim function and of the store statements
// is the tenant's override in tenant_entitlements, else the value of the tenant's own plan. A is on
// the free plan, B on a smaller one, so a reader of the wrong tenant's plan, or of the default, fails.
func TestCapReadersTakeTheTenantsOwnPlan(t *testing.T) {
	l := newClaimLab(t)
	h := l.h
	small := h.insertPlan("Small")
	h.exec(`UPDATE ctrlz.plans SET max_ip_claims = 3, max_profiles = 1 WHERE id = $1`, small)
	h.exec(`UPDATE ctrlz.tenants SET plan_id = $1 WHERE id = $2`, small, l.B.Tenant)
	h.exec(`UPDATE ctrlz.tenant_entitlements SET max_ip_claims = NULL, max_profiles = NULL`)
	l.openMode()

	// ip_claim_request. Every tenant starts with its seeded claim, which counts: B has room for two
	// more, then none; A, on the free plan, has plenty.
	outcomes := func(who string, n int) (out []string) {
		w := l.A
		if who == "B" {
			w = l.B
		}
		for i := 0; i < n; i++ {
			out = append(out, l.request(w, fmt.Sprintf("203.0.113.%d/32", 100+i), "manual").Outcome)
		}
		return out
	}
	if got := strings.Join(outcomes("B", 3), ","); got != "pending_proof,pending_proof,quota_exceeded" {
		t.Errorf("B on a plan of 3 claims: %s", got)
	}
	if got := outcomes("A", 4); strings.Contains(strings.Join(got, ","), "quota_exceeded") {
		t.Errorf("A on the free plan: %v", got)
	}
	// B's own override beats the plan in both directions, and a NULL gives the plan back.
	h.exec(`UPDATE ctrlz.tenant_entitlements SET max_ip_claims = 5 WHERE tenant_id = $1`, l.B.Tenant)
	if got := l.request(l.B, "203.0.113.150/32", "manual").Outcome; got != "pending_proof" {
		t.Errorf("B with an override of 5 above its plan: %s", got)
	}
	h.exec(`UPDATE ctrlz.tenant_entitlements SET max_ip_claims = 0 WHERE tenant_id = $1`, l.B.Tenant)
	if got := l.request(l.B, "203.0.113.151/32", "manual").Outcome; got != "quota_exceeded" {
		t.Errorf("B with an override of 0: %s", got)
	}
	h.exec(`UPDATE ctrlz.tenant_entitlements SET max_ip_claims = NULL WHERE tenant_id = $1`, l.B.Tenant)
	if got := l.request(l.B, "203.0.113.152/32", "manual").Outcome; got != "quota_exceeded" {
		t.Errorf("B with the override removed, back on its plan (full): %s", got)
	}
	// Raising B's plan lets B on, which the default plan's value could not.
	h.exec(`UPDATE ctrlz.plans SET max_ip_claims = 100 WHERE id = $1`, small)
	if got := l.request(l.B, "203.0.113.153/32", "manual").Outcome; got != "pending_proof" {
		t.Errorf("B after its plan was raised: %s", got)
	}

	// The Go statement: a profile create (max_profiles). B holds two seeded profiles and its plan allows
	// one, A is on the free plan.
	create := func(who uuid.UUID, name string) bool {
		var yes bool
		err := l.tenant.WithTenant(h.ctx, who, store.TxOpts{}, func(tx store.Tx) error {
			_, w, err := tx.ProfileCreate(name, "custom")
			yes = w.Yes()
			return err
		})
		if err != nil {
			t.Fatalf("profile create: %v", err)
		}
		return yes
	}
	if create(l.B.Tenant, "over") {
		t.Error("B created a profile above its plan's max_profiles")
	}
	if !create(l.A.Tenant, "fine") {
		t.Error("A could not create a profile on the free plan")
	}
	h.exec(`UPDATE ctrlz.tenant_entitlements SET max_profiles = 50 WHERE tenant_id = $1`, l.B.Tenant)
	if !create(l.B.Tenant, "over-with-override") {
		t.Error("B's override of max_profiles did not beat its plan")
	}
}

// tenantCount counts rows of one tenant in a table, as the superuser, so a test can say nothing was removed.
func (h *harness) tenantCount(table string, tenant uuid.UUID) (n int) {
	h.t.Helper()
	if err := h.super.QueryRow(h.ctx, `SELECT count(*) FROM ctrlz.`+table+` WHERE tenant_id = $1`, tenant).Scan(&n); err != nil {
		h.t.Fatalf("count %s: %v", table, err)
	}
	return n
}

// TestCapStatementsRefuseWhenThePlanCannotBeRead: a tenant whose plan tenant_plan() cannot return has
// no limit to compare with, and the statements refuse (spec 2.4, item 7), as the claim functions do.
// A restrictive policy hides tenant B from the function's owner, which is the shape of a later change
// that filters tenants by status; the statements must not read the NULL cap as "no cap".
func TestCapStatementsRefuseWhenThePlanCannotBeRead(t *testing.T) {
	l := newClaimLab(t)
	h := l.h
	h.exec(`UPDATE ctrlz.tenant_entitlements SET max_profiles = 50, max_rules_per_profile = 50, max_wildcards_per_profile = 50 WHERE tenant_id = $1`, l.B.Tenant)

	type result struct{ profile, rule, wildcard, capRules bool }
	run := func(tag string) (r result) {
		t.Helper()
		err := l.tenant.WithTenant(h.ctx, l.B.Tenant, store.TxOpts{}, func(tx store.Tx) error {
			_, w, err := tx.ProfileCreate("cap-"+tag, "custom")
			if err != nil {
				return err
			}
			r.profile = w.Yes()
			pw, g, err := tx.ProfileGuard(l.B.Profile)
			if err != nil || !g.Yes() {
				t.Fatalf("guard: %v %v", err, g.Yes())
			}
			_, w, err = tx.RulesInsert(pw, []store.NewRule{{Key: tag + ".plain.example.com", MatchKind: "domain", Action: "block", Enabled: true}})
			if err != nil {
				return err
			}
			r.rule = w.Yes()
			_, w, err = tx.RulesInsert(pw, []store.NewRule{{Key: "*." + tag + ".wild.example.com", MatchKind: "subdomains", Action: "block", Enabled: true}})
			if err != nil {
				return err
			}
			r.wildcard = w.Yes()
			rules, _, err := tx.RulesCapReached(pw, 1, 0)
			r.capRules = rules
			return err
		})
		if err != nil {
			t.Fatalf("%s: %v", tag, err)
		}
		return r
	}
	if got := run("before"); !got.profile || !got.rule || !got.wildcard || got.capRules {
		t.Fatalf("B with room: %+v", got)
	}
	h.exec(fmt.Sprintf(`CREATE POLICY hide_b ON ctrlz.tenants AS RESTRICTIVE FOR SELECT TO ctrlz_scoped USING (id <> '%s')`, l.B.Tenant))
	if got := run("after"); got.profile || got.rule || got.wildcard || !got.capRules {
		t.Errorf("B with no readable plan: %+v, want every create refused and the cap reported", got)
	}
}

// TestLoweringAPlanDeletesNothing (D56 item 5): a tenant above its plan keeps every profile, rule and
// claim, new creates are refused, and an edit that adds nothing to a count still goes through.
func TestLoweringAPlanDeletesNothing(t *testing.T) {
	l := newClaimLab(t)
	h := l.h
	h.exec(`UPDATE ctrlz.tenant_entitlements SET max_ip_claims = NULL, max_profiles = NULL, max_rules_per_profile = NULL, max_wildcards_per_profile = NULL`)
	small := h.insertPlan("Lowered")
	h.exec(`UPDATE ctrlz.tenants SET plan_id = $1 WHERE id = $2`, small, l.B.Tenant)
	l.openMode()

	// Ids are read back by key: RulesInsert returns them in the database collation order, not the input order.
	var wildcard, plain uuid.UUID
	if err := l.tenant.WithTenant(h.ctx, l.B.Tenant, store.TxOpts{}, func(tx store.Tx) error {
		pw, g, err := tx.ProfileGuard(l.B.Profile)
		if err != nil || !g.Yes() {
			t.Fatalf("guard: %v %v", err, g.Yes())
		}
		_, w, err := tx.RulesInsert(pw, []store.NewRule{
			{Key: "*.one.example.com", MatchKind: "subdomains", Action: "block", Enabled: true},
			{Key: "*.two.example.com", MatchKind: "subdomains", Action: "block", Enabled: true},
			{Key: "plain.example.com", MatchKind: "domain", Action: "block", Enabled: true},
		})
		if err != nil || !w.Yes() {
			t.Fatalf("seed rules: %v %v", err, w.Yes())
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for key, dst := range map[string]*uuid.UUID{"*.one.example.com": &wildcard, "plain.example.com": &plain} {
		if err := h.super.QueryRow(h.ctx, `SELECT id FROM ctrlz.rules WHERE tenant_id = $1 AND profile_id = $2 AND rule_key = $3`, l.B.Tenant, l.B.Profile, key).Scan(dst); err != nil {
			t.Fatalf("rule %s: %v", key, err)
		}
	}
	before := map[string]int{}
	for _, tbl := range []string{"profiles", "rules", "ip_claims"} {
		before[tbl] = h.tenantCount(tbl, l.B.Tenant)
	}

	// Lower every cap below what B holds.
	h.exec(`UPDATE ctrlz.plans SET max_profiles = 1, max_rules_per_profile = 1, max_wildcards_per_profile = 1, max_ip_claims = 0 WHERE id = $1`, small)

	var grew, same, created, inserted bool
	if err := l.tenant.WithTenant(h.ctx, l.B.Tenant, store.TxOpts{}, func(tx store.Tx) error {
		_, w, err := tx.ProfileCreate("above-plan", "custom")
		if err != nil {
			return err
		}
		created = w.Yes()
		pw, g, err := tx.ProfileGuard(l.B.Profile)
		if err != nil || !g.Yes() {
			t.Fatalf("guard: %v %v", err, g.Yes())
		}
		_, w, err = tx.RulesInsert(pw, []store.NewRule{{Key: "more.example.com", MatchKind: "domain", Action: "block", Enabled: true}})
		if err != nil {
			return err
		}
		inserted = w.Yes()
		// A plain rule that becomes a wildcard grows the count; a wildcard that stays one does not.
		w, err = tx.RuleUpdate(pw, store.RuleRow{ID: plain, Key: "*.plain.example.com", MatchKind: "subdomains", Action: "block", Enabled: true})
		if err != nil {
			return err
		}
		grew = w.Yes()
		w, err = tx.RuleUpdate(pw, store.RuleRow{ID: wildcard, Key: "*.one.example.com", MatchKind: "subdomains", Action: "bypass", Enabled: true, Comment: "edited"})
		same = w.Yes()
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if created || inserted || grew {
		t.Errorf("above its plan B created a profile %v, inserted a rule %v, made a wildcard %v", created, inserted, grew)
	}
	if !same {
		t.Error("an edit of a wildcard that stays one was refused while B is over its wildcard cap")
	}
	if got := l.request(l.B, "203.0.113.200/32", "manual").Outcome; got != "quota_exceeded" {
		t.Errorf("a claim above the lowered plan: %s", got)
	}
	for _, tbl := range []string{"profiles", "rules", "ip_claims"} {
		if got := h.tenantCount(tbl, l.B.Tenant); got != before[tbl] {
			t.Errorf("%s: %d rows before the plan was lowered, %d after", tbl, before[tbl], got)
		}
	}
}

// TestLimitFunctionsReadOverrideThenPlan: the two claim functions name the override table and the
// plans table and no table that no longer exists.
func TestLimitFunctionsReadOverrideThenPlan(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	for _, fn := range []string{"ip_claim_request", "ip_claim_open_challenge"} {
		def := h.str(`SELECT pg_get_functiondef(p.oid) FROM pg_proc p WHERE p.pronamespace = 'ctrlz_fn'::regnamespace AND p.proname = $1`, fn)
		for _, want := range []string{"COALESCE(te.max_ip_claims, p.max_ip_claims)", "ctrlz.plans p", "ctrlz.tenant_entitlements te"} {
			if !strings.Contains(def, want) {
				t.Errorf("%s does not contain %q", fn, want)
			}
		}
	}
}

// TestNewTenantsTakeTheDefaultPlan: the two creators of a tenant put it on the plan that is the
// default when they run, so a function that named the free plan by id would fail the second half.
func TestNewTenantsTakeTheDefaultPlan(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	planOf := func(tx pgx.Tx, tenant uuid.UUID) (name string) {
		t.Helper()
		// The creators run as a service role; the superuser reads what they made, in the same transaction.
		if _, err := tx.Exec(h.ctx, `RESET ROLE`); err != nil {
			t.Fatal(err)
		}
		if err := tx.QueryRow(h.ctx, `SELECT p.name FROM ctrlz.tenants t JOIN ctrlz.plans p ON p.id = t.plan_id WHERE t.id = $1`, tenant).Scan(&name); err != nil {
			t.Fatalf("the new tenant has no plan: %v", err)
		}
		return name
	}
	adminCreates := func(phone string) string {
		var plan string
		h.inTx(h.super, "admin", nil, func(tx pgx.Tx) {
			var tenant, user uuid.UUID
			if err := tx.QueryRow(h.ctx, `SELECT tenant_id, user_id FROM ctrlz_fn.admin_create_user($1, 'hash', 'fa')`, phone).Scan(&tenant, &user); err != nil {
				t.Fatalf("admin_create_user: %v", err)
			}
			plan = planOf(tx, tenant)
		})
		return plan
	}
	if got := adminCreates("+989121110001"); got != "Free" {
		t.Errorf("admin_create_user: plan %q, want the default, Free", got)
	}

	// Move the default.
	h.insertPlan("Pro")
	if code := h.commit(`UPDATE ctrlz.plans SET is_default = false WHERE is_default`, `UPDATE ctrlz.plans SET is_default = true WHERE name = 'Pro'`); code != "" {
		t.Fatalf("moving the default: %q", code)
	}
	if got := adminCreates("+989121110002"); got != "Pro" {
		t.Errorf("admin_create_user after the default moved: plan %q, want Pro", got)
	}

	// auth_register_user: open registration, a consumed signup code.
	h.exec(`UPDATE ctrlz.system_settings SET registration_mode = 'open'`)
	ago := time.Minute
	h.inTx(h.super, "tenant", nil, func(tx pgx.Tx) {
		const phone = "+989121110003"
		otp := otpRow(h, tx, phone, "signup", &ago)
		var tenant, user uuid.UUID
		if err := tx.QueryRow(h.ctx, `SELECT tenant_id, user_id FROM ctrlz_fn.auth_register_user($1, 'hash', 'fa', NULL, $2)`, phone, otp).Scan(&tenant, &user); err != nil {
			t.Fatalf("auth_register_user: %v", err)
		}
		if got := planOf(tx, tenant); got != "Pro" {
			t.Errorf("auth_register_user: plan %q, want the default, Pro", got)
		}
	})
}

// TestPlanMigrationOnAnInstalledDatabase: a database at 0073 with tenants and an entitlement_defaults row an
// admin had edited keeps those numbers as the free plan, every tenant ends on it, and the old table is gone.
func TestPlanMigrationOnAnInstalledDatabase(t *testing.T) {
	c := testpg.Need(t, cluster)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
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
	if _, err := migrate.UpTo(ctx, db, 73); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"00000000-0000-7000-8000-0000000000a1", "00000000-0000-7000-8000-0000000000a2"} {
		if _, err := super.Exec(ctx, `INSERT INTO ctrlz.tenants (id) VALUES ($1)`, id); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := super.Exec(ctx, `UPDATE ctrlz.entitlement_defaults SET max_profiles = 33, max_ip_claims = 77`); err != nil {
		t.Fatal(err)
	}
	if _, err := migrate.UpTo(ctx, db, 74); err != nil {
		t.Fatalf("0074: %v", err)
	}
	var name string
	var profiles, claims, onFree, tenants int
	if err := super.QueryRow(ctx, `SELECT name, max_profiles, max_ip_claims FROM ctrlz.plans WHERE is_default`).Scan(&name, &profiles, &claims); err != nil {
		t.Fatal(err)
	}
	if name != "Free" || profiles != 33 || claims != 77 {
		t.Errorf("the free plan: %s with %d profiles and %d claims, want Free with the edited 33 and 77", name, profiles, claims)
	}
	if err := super.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE plan_id = (SELECT id FROM ctrlz.plans WHERE is_default)) FROM ctrlz.tenants`).Scan(&tenants, &onFree); err != nil {
		t.Fatal(err)
	}
	if tenants != 2 || onFree != 2 {
		t.Errorf("%d tenants, %d of them on the free plan, want 2 and 2", tenants, onFree)
	}
	var gone bool
	if err := super.QueryRow(ctx, `SELECT to_regclass('ctrlz.entitlement_defaults') IS NULL`).Scan(&gone); err != nil || !gone {
		t.Errorf("entitlement_defaults is still there (%v): two sources of defaults", err)
	}
}
