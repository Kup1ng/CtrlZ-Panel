package catalogtest_test

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

// Tests of the P2 migrations 0070 (schema) and 0071 (seed), docs/specs/p2-profiles.md 2.2 and 2.3.

// iconSlugs reads the slugs of one icon group from the generated registry, which is the owner of
// the 20 native filter ids and the 12 service category ids (spec finding 10): a seed that drifts
// from it would show a monogram where an icon exists.
func iconSlugs(t *testing.T, group string) []string {
	t.Helper()
	raw, err := os.ReadFile("../../../packages/icons/src/generated/registry.ts")
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	start := strings.Index(s, "export const "+group+"Icons = {")
	if start < 0 {
		t.Fatalf("no %sIcons in the registry", group)
	}
	body := s[start:]
	body = body[:strings.Index(body, "} as const")]
	var out []string
	for _, m := range regexp.MustCompile(`"([a-z0-9-]+)":`).FindAllStringSubmatch(body, -1) {
		out = append(out, m[1])
	}
	return out
}

func (h *harness) column(sql string, args ...any) []string {
	h.t.Helper()
	rows, err := h.super.Query(h.ctx, sql, args...)
	if err != nil {
		h.t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			h.t.Fatal(err)
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		h.t.Fatal(err)
	}
	return out
}

func (h *harness) one(sql string, args ...any) int {
	h.t.Helper()
	var n int
	if err := h.super.QueryRow(h.ctx, sql, args...).Scan(&n); err != nil {
		h.t.Fatalf("%s: %v", sql, err)
	}
	return n
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := map[string]int{}
	for _, x := range a {
		m[x]++
	}
	for _, x := range b {
		m[x]--
	}
	for _, v := range m {
		if v != 0 {
			return false
		}
	}
	return true
}

// TestP2SeedFilters: 20 native filters with the icon slugs, 12 third party lists, the modes of
// Plan "Filters", and a default mode (the lowest wire id) that is Relaxed or Last Week (T-144 to T-149).
func TestP2SeedFilters(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	native := h.column(`SELECT id FROM ctrlz.catalog_filter WHERE kind = 'native'`)
	if want := iconSlugs(t, "filters"); !sameSet(native, want) || len(native) != 20 {
		t.Errorf("native filters %v, want the 20 icon slugs %v", native, want)
	}
	third := h.column(`SELECT id FROM ctrlz.catalog_filter WHERE kind = 'third_party'`)
	if len(third) != 12 {
		t.Errorf("%d third party lists, want 12", len(third))
	}
	for _, id := range third {
		if !regexp.MustCompile(`^[a-z0-9]+-[a-z0-9-]+$`).MatchString(id) {
			t.Errorf("third party id %q is not <source>-<list>", id)
		}
	}
	if n := h.one(`SELECT count(*) FROM ctrlz.catalog_filter WHERE kind = 'third_party' AND wire_id < 1000`); n != 0 {
		t.Errorf("%d third party lists below 1000", n)
	}
	// Every filter has at least one mode; the multi-mode ones are the four of the Plan.
	multi := map[string][]string{
		"ads-trackers": {"relaxed", "balanced", "strict"},
		"malware":      {"relaxed", "balanced", "strict"},
		"adult":        {"relaxed", "strict"},
		"new-domains":  {"last_week", "last_month"},
	}
	for _, id := range append(append([]string{}, native...), third...) {
		modes := h.column(`SELECT mode FROM ctrlz.catalog_filter_mode WHERE filter_id = $1 ORDER BY wire_id`, id)
		want, ok := multi[id]
		if !ok {
			want = []string{"standard"}
		}
		if strings.Join(modes, ",") != strings.Join(want, ",") {
			t.Errorf("filter %s: modes %v in wire order, want %v (the first is the default, T-146)", id, modes, want)
		}
	}
}

// TestP2SeedServices: every column has a live value (spec 2.3), and the Iranian services carry
// redirect_allowed = false with their domains on the D42 list (T-161, T-521, T-525).
func TestP2SeedServices(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	cats := h.column(`SELECT id FROM ctrlz.catalog_service_category`)
	if want := iconSlugs(t, "services"); !sameSet(cats, want) || len(cats) != 12 {
		t.Errorf("categories %v, want the 12 icon slugs %v", cats, want)
	}
	if n := h.one(`SELECT count(*) FROM ctrlz.catalog_service`); n < 100 {
		t.Errorf("%d services, want at least 100", n)
	}
	for _, c := range cats {
		if n := h.one(`SELECT count(*) FROM ctrlz.catalog_service WHERE category_id = $1`, c); n == 0 {
			t.Errorf("category %s has no service", c)
		}
	}
	for what, q := range map[string]string{
		"Iranian (redirect_allowed = false)": `SELECT count(*) FROM ctrlz.catalog_service WHERE NOT redirect_allowed`,
		"with allowed_regions":               `SELECT count(*) FROM ctrlz.catalog_service WHERE allowed_regions IS NOT NULL`,
		"with risk_flag":                     `SELECT count(*) FROM ctrlz.catalog_service WHERE risk_flag`,
	} {
		min := 2
		if strings.HasPrefix(what, "Iranian") {
			min = 5
		}
		if n := h.one(q); n < min {
			t.Errorf("%d services %s, want at least %d", n, what, min)
		}
	}
	if n := h.one(`SELECT count(*) FROM ctrlz.catalog_service WHERE coalesce(source, '') = '' OR coalesce(license, '') = '' OR name_fa = '' OR name_en = ''`); n != 0 {
		t.Errorf("%d services lack a source, a license or a name (T-168)", n)
	}
	if n := h.one(`SELECT count(*) FROM ctrlz.catalog_service s WHERE NOT EXISTS (SELECT 1 FROM ctrlz.catalog_service_domain d WHERE d.slug = s.slug)`); n != 0 {
		t.Errorf("%d services have no domain", n)
	}

	// D42: a domain of a redirect_allowed = false service that is not under .ir or .ایران is on the
	// list, a 'domain' row with scope domain and a 'full' row with scope host; nothing under .ir is.
	isIr := `(d.pattern = 'ir' OR d.pattern LIKE '%.ir' OR d.pattern LIKE '%.ایران' OR d.pattern LIKE '%.xn--mgba3a4f16a')`
	rows, err := h.super.Query(h.ctx, `
SELECT d.slug, d.pattern, d.kind, n.scope
FROM ctrlz.catalog_service s JOIN ctrlz.catalog_service_domain d ON d.slug = s.slug
LEFT JOIN ctrlz.catalog_no_redirect_domain n ON n.pattern = d.pattern
WHERE NOT s.redirect_allowed AND NOT `+isIr)
	if err != nil {
		t.Fatal(err)
	}
	seen, sawHost := 0, false
	for rows.Next() {
		var slug, pattern, kind string
		var scope *string
		if err := rows.Scan(&slug, &pattern, &kind, &scope); err != nil {
			t.Fatal(err)
		}
		want := map[string]string{"domain": "domain", "full": "host"}[kind]
		if scope == nil || *scope != want {
			t.Errorf("%s %s (kind %s): list scope %v, want %s", slug, pattern, kind, scope, want)
		}
		sawHost = sawHost || kind == "full"
		seen++
	}
	rows.Close()
	if seen == 0 || !sawHost {
		t.Errorf("checked %d non-.ir Iranian domains, a full (host) row among them: %v", seen, sawHost)
	}
	if n := h.one(`SELECT count(*) FROM ctrlz.catalog_no_redirect_domain d WHERE ` + isIr); n != 0 {
		t.Errorf("%d .ir or .ایران names on the list, which the built-in TLD rule covers", n)
	}
	// The entry bound of 8 labels and the scope set are the table's own checks.
	if code := h.try("", nil, `INSERT INTO ctrlz.catalog_no_redirect_domain VALUES ('a.b.c.d.e.f.g.h.i.example', 'domain')`); code != "23514" {
		t.Errorf("nine labels: %q, want 23514", code)
	}
	if code := h.try("", nil, `INSERT INTO ctrlz.catalog_no_redirect_domain VALUES ('a.b.c.d.e.f.g.example', 'domain')`); code != "" {
		t.Errorf("eight labels: %q, want accepted", code)
	}
	if code := h.try("", nil, `INSERT INTO ctrlz.catalog_no_redirect_domain VALUES ('x.example', 'suffix')`); code != "23514" {
		t.Errorf("scope suffix: %q, want 23514", code)
	}
}

// TestP2SeedPresets: seven profile types (spec 5), each a document that names only filters and
// modes the catalog has, a mode only on a multi-mode filter, and no service.
func TestP2SeedPresets(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	kinds := h.column(`SELECT kind FROM ctrlz.profile_presets`)
	if !sameSet(kinds, []string{"custom", "developer", "gaming", "kids", "privacy", "productivity", "vpn_replacement"}) {
		t.Fatalf("preset kinds %v", kinds)
	}
	for _, kind := range kinds {
		var raw []byte
		if err := h.super.QueryRow(h.ctx, `SELECT content FROM ctrlz.profile_presets WHERE kind = $1 AND schema_version = 1`, kind).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Format   string                      `json:"format"`
			Version  int                         `json:"version"`
			Kind     string                      `json:"kind"`
			Name     *string                     `json:"name"`
			Filters  []struct{ ID, Mode string } `json:"filters"`
			Services []json.RawMessage           `json:"services"`
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		if doc.Format != "ctrlz-profile" || doc.Version != 1 || doc.Kind != kind || doc.Name != nil || len(doc.Services) != 0 {
			t.Errorf("preset %s: format %q version %d kind %q name %v services %d", kind, doc.Format, doc.Version, doc.Kind, doc.Name, len(doc.Services))
		}
		prev := ""
		for _, f := range doc.Filters {
			if f.ID <= prev {
				t.Errorf("preset %s: filters not sorted by id at %s", kind, f.ID)
			}
			prev = f.ID
			modes := h.column(`SELECT mode FROM ctrlz.catalog_filter_mode WHERE filter_id = $1`, f.ID)
			switch {
			case len(modes) == 0:
				t.Errorf("preset %s: unknown filter %s", kind, f.ID)
			case len(modes) == 1 && f.Mode != "":
				t.Errorf("preset %s: a mode on the one-mode filter %s", kind, f.ID)
			case len(modes) > 1 && !hasString(modes, f.Mode):
				t.Errorf("preset %s: filter %s has no mode %q", kind, f.ID, f.Mode)
			}
		}
	}
}

func hasString(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// TestP2Entitlements: the request limit is 10,000 and no profile limit exceeds the document
// bound, for the defaults and for a tenant override (spec 2.2 item 3, 3.4).
func TestP2Entitlements(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	if n := h.one(`SELECT max_rules_per_request FROM ctrlz.plans`); n != 10000 {
		t.Errorf("default max_rules_per_request %d, want 10000", n)
	}
	if code := h.try("", nil, `UPDATE ctrlz.plans SET max_rules_per_profile = 10001`); code != "23514" {
		t.Errorf("default max_rules_per_profile 10001: %q, want 23514", code)
	}
	if code := h.try("", nil, `UPDATE ctrlz.plans SET max_rules_per_profile = 10000`); code != "" {
		t.Errorf("default max_rules_per_profile 10000: %q", code)
	}
	// Two tenants: an override of A is checked on A's row and leaves B's alone.
	a, b := h.A.Tenant.String(), h.B.Tenant.String()
	if code := h.try("admin", &a, `UPDATE ctrlz.tenant_entitlements SET max_rules_per_profile = 10001`); code != "23514" {
		t.Errorf("tenant override 10001: %q, want 23514", code)
	}
	if code := h.try("admin", &a, `UPDATE ctrlz.tenant_entitlements SET max_rules_per_profile = 5000`); code != "" {
		t.Errorf("tenant override 5000: %q", code)
	}
	h.inTx(h.super, "admin", &b, func(tx pgx.Tx) {
		if _, err := tx.Exec(h.ctx, `UPDATE ctrlz.tenant_entitlements SET max_rules_per_profile = 5000`); err != nil {
			t.Fatal(err)
		}
		// A's override was in a rolled back transaction: B's tenant sees only its own row.
		n, err := count(h.ctx, tx, `SELECT count(*) FROM ctrlz.tenant_entitlements WHERE max_rules_per_profile = 5000`)
		if err != nil || n != 1 {
			t.Errorf("B sees %d rows with its override (%v), want 1", n, err)
		}
	})
}

// TestP2ProfilesLockColumns: the lock hash is read by the tenant role only, the compiler and the
// worker read every other column, and the worker's INSERT cannot set a lock column (spec 2.2 items
// 6, 7, 11). The lock message is bounded.
func TestP2ProfilesLockColumns(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	a := h.A.Tenant.String()
	for _, role := range []string{"compiler", "worker"} {
		if code := h.try(role, &a, `SELECT lock_password_hash FROM ctrlz.profiles`); code != "42501" {
			t.Errorf("%s reads lock_password_hash: %q, want 42501", role, code)
		}
		if code := h.try(role, &a, `SELECT * FROM ctrlz.profiles`); code != "42501" {
			t.Errorf("%s SELECT *: %q, want 42501", role, code)
		}
		if code := h.try(role, &a, `SELECT id, name, kind, version, disabled_until, lock_state, lock_message, locked_by, locked_at, compiled_hash FROM ctrlz.profiles`); code != "" {
			t.Errorf("%s reads the other columns: %q", role, code)
		}
	}
	if code := h.try("tenant", &a, `SELECT lock_password_hash FROM ctrlz.profiles`); code != "" {
		t.Errorf("tenant reads lock_password_hash: %q", code)
	}
	// The job runner creates a profile (Import, Duplicate) and never touches a lock.
	id := "00000000-0000-7000-8000-00000000b2a1"
	if code := h.try("worker", &a, `INSERT INTO ctrlz.profiles (tenant_id, id, name, kind) VALUES ($1, $2, 'from a job', 'kids')`, h.A.Tenant, id); code != "" {
		t.Errorf("worker INSERT of a profile: %q", code)
	}
	for _, col := range []string{"lock_state", "lock_message", "lock_password_hash", "locked_by", "locked_at"} {
		if code := h.try("worker", &a, `INSERT INTO ctrlz.profiles (tenant_id, id, name, `+col+`) VALUES ($1, $2, 'x', NULL)`, h.A.Tenant, id); code != "42501" {
			t.Errorf("worker INSERT naming %s: %q, want 42501", col, code)
		}
		if code := h.try("worker", &a, `UPDATE ctrlz.profiles SET `+col+` = NULL`); code != "42501" {
			t.Errorf("worker UPDATE of %s: %q, want 42501", col, code)
		}
	}
	if code := h.try("worker", &a, `UPDATE ctrlz.profiles SET version = version + 1`); code != "" {
		t.Errorf("worker bumps version: %q", code)
	}
	long := strings.Repeat("x", 257)
	if code := h.try("tenant", &a, `UPDATE ctrlz.profiles SET lock_message = $1`, long); code != "23514" {
		t.Errorf("lock_message of 257 characters: %q, want 23514", code)
	}
	if code := h.try("tenant", &a, `UPDATE ctrlz.profiles SET lock_message = $1`, long[:256]); code != "" {
		t.Errorf("lock_message of 256 characters: %q", code)
	}
}

// TestP2WorkerJobReach: what the job runner and the idempotency sweep were granted (spec 2.2 items
// 3, 5, 6), and what stays out of reach. The rows of another tenant are never seen: the runner
// enters one tenant at a time.
func TestP2WorkerJobReach(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	a, b := h.A.Tenant.String(), h.B.Tenant.String()
	for _, q := range []string{
		`INSERT INTO ctrlz.rule_folders (tenant_id, profile_id, name) VALUES ($1, $2, 'f')`,
		`INSERT INTO ctrlz.profile_filters (tenant_id, profile_id, filter_id) VALUES ($1, $2, 'malware')`,
		`INSERT INTO ctrlz.rules (tenant_id, profile_id, rule_key, match_kind, action) VALUES ($1, $2, 'k.example', 'domain', 'block')`,
		`INSERT INTO ctrlz.profile_services (tenant_id, profile_id, service_slug, action) VALUES ($1, $2, 'netflix', 'block')`,
		`UPDATE ctrlz.rule_folders SET location_unavailable = true WHERE tenant_id = $1 AND profile_id = $2`,
		`DELETE FROM ctrlz.rules WHERE tenant_id = $1 AND profile_id = $2`,
		`DELETE FROM ctrlz.idempotency_keys WHERE tenant_id = $1 AND expires_at < now() AND key <> $2::text`,
	} {
		if code := h.try("worker", &a, q, h.A.Tenant, h.A.Profile.String()); code != "" {
			t.Errorf("worker %q: %q", q, code)
		}
	}
	// Another tenant's row is refused by row security whatever the grants say: the runner
	// enters one tenant at a time and cannot write into a second one.
	if code := h.try("worker", &a, `INSERT INTO ctrlz.rules (tenant_id, profile_id, rule_key, match_kind, action) VALUES ($1, $2, 'b.example', 'domain', 'block')`, h.B.Tenant, h.B.Profile); code != "42501" {
		t.Errorf("worker under tenant A's setting inserts into tenant B: %q, want a row security refusal (42501)", code)
	}
	// The reads allowed(profile) needs, and nothing of the Endpoint's secrets.
	if code := h.try("worker", &a, `SELECT profile_id, profile2_id, pair_override_node_a, pair_override_node_b FROM ctrlz.endpoints`); code != "" {
		t.Errorf("worker reads the Endpoint profile and pair columns: %q", code)
	}
	if code := h.try("worker", &a, `SELECT doh_token_ct FROM ctrlz.endpoints`); code != "42501" {
		t.Errorf("worker reads doh_token_ct: %q, want 42501", code)
	}
	if code := h.try("worker", &a, `SELECT tenant_id, endpoint_id, profile_id, profile2_id FROM ctrlz.schedule_windows`); code != "" {
		t.Errorf("worker reads schedule_windows: %q", code)
	}
	if code := h.try("worker", &a, `SELECT minutes FROM ctrlz.schedule_windows`); code != "42501" {
		t.Errorf("worker reads the minutes of a window: %q, want 42501", code)
	}
	if code := h.try("worker", &a, `SELECT response FROM ctrlz.idempotency_keys`); code != "42501" {
		t.Errorf("worker reads a stored idempotent response: %q, want 42501", code)
	}
	// The D42 list: the tenant role and the compiler read it, the hub does not.
	for role, want := range map[string]string{"tenant": "", "compiler": "", "worker": "", "admin": "", "hub": "42501"} {
		if code := h.try(role, &b, `SELECT pattern, scope FROM ctrlz.catalog_no_redirect_domain`); code != want {
			t.Errorf("%s reads catalog_no_redirect_domain: %q, want %q", role, code, want)
		}
	}
	for _, role := range []string{"tenant", "compiler", "hub"} {
		if code := h.try(role, &b, `INSERT INTO ctrlz.catalog_no_redirect_domain VALUES ('x.example', 'domain')`); code != "42501" {
			t.Errorf("%s writes catalog_no_redirect_domain: %q, want 42501", role, code)
		}
	}
}

// TestP2BatchJobs: one active job per tenant (spec 2.2 item 5), and the row carries the input and
// the error. Two tenants: A's active job does not stop B's.
func TestP2BatchJobs(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	a, b := h.A.Tenant.String(), h.B.Tenant.String()
	// The seed gave each tenant one queued job already.
	ins := `INSERT INTO ctrlz.batch_jobs (tenant_id, kind, profile_id, state, input) VALUES ($1, 'import', $2, $3, '{"items":[]}')`
	if code := h.try("tenant", &a, ins, h.A.Tenant, h.A.Profile, "queued"); code != "23505" {
		t.Errorf("a second queued job of tenant A: %q, want 23505", code)
	}
	if code := h.try("tenant", &a, ins, h.A.Tenant, h.A.Profile, "running"); code != "23505" {
		t.Errorf("a running job beside a queued one: %q, want 23505", code)
	}
	if code := h.try("tenant", &a, ins, h.A.Tenant, h.A.Profile, "done"); code != "" {
		t.Errorf("a finished job beside an active one: %q", code)
	}
	// B's job is independent of A's: end B's seeded job and queue another.
	h.inTx(h.super, "worker", &b, func(tx pgx.Tx) {
		if _, err := tx.Exec(h.ctx, `UPDATE ctrlz.batch_jobs SET state = 'failed', error = '{"code":"validation_failed"}', input = NULL`); err != nil {
			t.Fatal(err)
		}
		// The tenant role queues, the worker runs: switch roles inside the same transaction.
		if _, err := tx.Exec(h.ctx, `RESET ROLE`); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(h.ctx, `SET LOCAL ROLE ctrlz_tenant`); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(h.ctx, `INSERT INTO ctrlz.batch_jobs (tenant_id, kind, profile_id) VALUES ($1, 'import', $2)`, h.B.Tenant, h.B.Profile); err != nil {
			t.Errorf("B queues a job after its own ended: %v", err)
		}
		if n, _ := count(h.ctx, tx, `SELECT count(*) FROM ctrlz.batch_jobs WHERE tenant_id = $1`, h.A.Tenant); n != 0 {
			t.Errorf("tenant B's transaction sees %d jobs of tenant A", n)
		}
	})
	if n := h.one(`SELECT count(*) FROM ctrlz.batch_jobs WHERE state IN ('queued','running') AND tenant_id = $1`, h.A.Tenant); n != 1 {
		t.Errorf("tenant A has %d active jobs, want 1", n)
	}
}

// TestP2OptionUnits: option_count counts units (spec 2.2 item 10), compatibility_mode and the
// location flag not at all, and a tenant counts its own profiles only.
func TestP2OptionUnits(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	a := h.A.Tenant.String()
	h.exec(`INSERT INTO ctrlz.profile_options (tenant_id, profile_id) VALUES ($1, $2)`, h.A.Tenant, h.A.Profile2)
	count := func() int {
		n := -1
		h.inTx(h.super, "tenant", &a, func(tx pgx.Tx) {
			if err := tx.QueryRow(h.ctx, `SELECT option_count FROM ctrlz.tenant_profile_counts WHERE profile_id = $1`, h.A.Profile2).Scan(&n); err != nil {
				t.Fatal(err)
			}
		})
		return n
	}
	if n := count(); n != 0 {
		t.Fatalf("an options row with nothing set counts %d", n)
	}
	h.exec(`UPDATE ctrlz.profile_options SET default_action = 'redirect', default_target_kind = 'auto',
  block_response = 'custom', block_custom_v4 = '203.0.113.1', block_custom_v6 = '2001:db8::1',
  ecs_mode = 'custom', ecs_v4 = '203.0.113.0/24', ecs_v6 = '2001:db8::/48',
  compatibility_mode = true, default_location_unavailable = true
WHERE tenant_id = $1 AND profile_id = $2`, h.A.Tenant, h.A.Profile2)
	if n := count(); n != 3 {
		t.Errorf("Default Rule, Block Response and ECS with all their members count %d, want 3", n)
	}
	h.exec(`UPDATE ctrlz.profile_options SET block_exfiltration = false, rebind_protection = true, disable_dnssec = true,
  block_ttl = 5, redirect_ttl = 6, bypass_ttl = 7, dns64 = false, cname_flattening = true, safe_search = true, restricted_youtube = false
WHERE tenant_id = $1 AND profile_id = $2`, h.A.Tenant, h.A.Profile2)
	if n := count(); n != 13 {
		t.Errorf("every option set counts %d, want 13 (3 units and 10 single options; false is set)", n)
	}
}

// TestP2RuleFolderFlag: a Folder Rule carries the location flag, false by default, and the
// worker may set it (spec 2.2 item 4). The worker holds the job runner's full UPDATE on the table
// (spec 2.2 item 6), so it could rewrite a folder's action too: the guard against that is code
// (spec 3.1), not a grant, and this test does not claim otherwise.
func TestP2RuleFolderFlag(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	a := h.A.Tenant.String()
	if n := h.one(`SELECT count(*) FROM ctrlz.rule_folders WHERE location_unavailable`); n != 0 {
		t.Errorf("%d folders start flagged", n)
	}
	if code := h.try("worker", &a, `UPDATE ctrlz.rule_folders SET location_unavailable = true`); code != "" {
		t.Errorf("worker sets the flag: %q", code)
	}
}

// TestP2NoRedirectPatternIsCanonical: the write path finds a name by exact equality on its
// canonical suffixes (spec 3.6), so the table refuses a pattern that could never be found.
// Accepting one would fail open: the Redirect rule for that domain would be allowed.
func TestP2NoRedirectPatternIsCanonical(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	for _, p := range []string{"Snapp.ir.cab", "digikala.com.", ".digikala.com", "a..b.example", "-a.example", "a-.example",
		"a b.example", "bäume.example", strings.Repeat("a", 64) + ".example"} {
		if code := h.try("", nil, `INSERT INTO ctrlz.catalog_no_redirect_domain VALUES ($$`+p+`$$, 'domain')`); code != "23514" {
			t.Errorf("pattern %q: %q, want 23514", p, code)
		}
	}
	for _, p := range []string{"canon-check.example", "xn--mgba3gch31f.example", "a-b.c1.example", strings.Repeat("a", 63) + ".example"} {
		if code := h.try("", nil, `INSERT INTO ctrlz.catalog_no_redirect_domain VALUES ($$`+p+`$$, 'host')`); code != "" {
			t.Errorf("pattern %q: %q, want accepted", p, code)
		}
	}
}

// TestP2LockBudgetIsNotResettable: no success clears profile_lock_tenant (spec 7.1), so the
// tenant role's reset function must not take that scope, while profile_unlock, which a successful
// unlock clears (7.2), stays resettable.
func TestP2LockBudgetIsNotResettable(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	key := "decode(repeat('9a', 32), 'hex')"
	h.inTx(h.super, "tenant", nil, func(tx pgx.Tx) {
		if _, err := tx.Exec(h.ctx, "SET LOCAL ROLE ctrlz_tenant"); err != nil {
			t.Fatal(err)
		}
		for _, s := range []string{"profile_lock_tenant", "profile_unlock"} {
			for i := 0; i < 3; i++ {
				if _, err := tx.Exec(h.ctx, fmt.Sprintf("SELECT ctrlz_fn.auth_throttle_hit($1, %s, 20, 3600)", key), s); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := tx.Exec(h.ctx, fmt.Sprintf("SELECT ctrlz_fn.auth_throttle_reset($1, %s)", key), s); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := tx.Exec(h.ctx, "RESET ROLE"); err != nil {
			t.Fatal(err)
		}
		count := func(scope string) (n int) {
			if err := tx.QueryRow(h.ctx, "SELECT count FROM ctrlz.auth_throttle WHERE key = "+key+" AND scope = $1", scope).Scan(&n); err != nil {
				t.Fatal(err)
			}
			return
		}
		if n := count("profile_lock_tenant"); n != 3 {
			t.Errorf("the tenant role reset profile_lock_tenant: count %d, want 3", n)
		}
		if n := count("profile_unlock"); n != 0 {
			t.Errorf("profile_unlock not cleared by its reset: count %d, want 0", n)
		}
	})
}
