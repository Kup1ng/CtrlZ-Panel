package catalogtest_test

import (
	"encoding/json"
	"net/netip"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Shared/appleprofile"
	"github.com/Kup1ng/CtrlZ-Shared/identity"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

// Tests of migrations 0075 (schema) and 0076 (seed), docs/specs/p3-endpoints.md 2.2 and 2.3. Two tenants
// everywhere a tenant reads or writes.

// endpointTypes is the list of Plan.md "Endpoint" findings, in the order of the menu (T-219). It is written out
// here and not read from the seed file, so a change of the file that drops or reorders a type fails.
var endpointTypes = []struct{ key, name string }{
	{"windows", "Windows"}, {"mac", "Mac"}, {"linux", "Linux"}, {"ios", "iOS"}, {"android", "Android"},
	{"chrome", "Chrome"}, {"firefox", "Firefox"}, {"edge", "Edge"}, {"brave", "Brave"}, {"other_browser", "Other Browser"},
	{"apple_tv", "Apple TV"}, {"android_tv", "Android TV"}, {"fire_tv", "Fire TV"}, {"samsung_tv", "Samsung TV"}, {"other_tv", "Other TV"},
	{"asus_merlin", "Asus Merlin"}, {"dd_wrt", "DD-WRT"}, {"firewalla", "Firewalla"}, {"fresh_tomato", "Fresh Tomato"},
	{"gl_inet", "GL.iNet"}, {"openwrt", "OpenWRT"}, {"opnsense", "OPNsense"}, {"pfsense", "pfSense"}, {"synology", "Synology"},
	{"ubiquiti", "Ubiquiti"}, {"windows_server", "Windows Server"}, {"generic_linux", "Generic Linux"}, {"tailscale", "Tailscale"},
	{"other_router", "Other Router"}, {"other_endpoint", "Other Endpoint"},
}

// TestEndpointTypesSeed: the 30 types in the order of the menu, each with a generic device icon.
func TestEndpointTypesSeed(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	if len(endpointTypes) != 30 {
		t.Fatalf("the test lists %d types, want 30", len(endpointTypes))
	}
	rows, err := h.super.Query(h.ctx, `SELECT key, name_en, name_fa, position, icon FROM ctrlz.endpoint_types WHERE position < 99 ORDER BY position`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	generic := map[string]bool{"computer": true, "phone": true, "tablet": true, "browser": true, "tv": true, "router": true, "server": true, "network": true}
	i := 0
	for rows.Next() {
		var key, en, fa, icon string
		var pos int
		if err := rows.Scan(&key, &en, &fa, &pos, &icon); err != nil {
			t.Fatal(err)
		}
		if i >= len(endpointTypes) {
			t.Fatalf("an extra type %q", key)
		}
		if w := endpointTypes[i]; key != w.key || en != w.name || pos != i+1 {
			t.Errorf("type %d is %q %q at %d, want %q %q at %d", i+1, key, en, pos, w.key, w.name, i+1)
		}
		if strings.TrimSpace(fa) == "" {
			t.Errorf("type %q has no Persian name", key)
		}
		if !generic[icon] {
			t.Errorf("type %q has icon %q, which is not a generic device icon", key, icon)
		}
		i++
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if i != 30 {
		t.Errorf("%d types seeded, want 30", i)
	}
	// The icon is a slug and is never empty.
	for _, bad := range []string{"", "Computer", "a b", "x/y", strings.Repeat("a", 33)} {
		if code := h.try("", nil, `INSERT INTO ctrlz.endpoint_types (key, name_en, name_fa, position, icon) VALUES ('t_bad', 'x', 'x', 100, $1)`, bad); code != "23514" {
			t.Errorf("icon %q: SQLSTATE %q, want 23514", bad, code)
		}
	}
	if code := h.try("", nil, `INSERT INTO ctrlz.endpoint_types (key, name_en, name_fa, position) VALUES ('t_bad', 'x', 'x', 100)`); code != "23502" {
		t.Errorf("a type with no icon: SQLSTATE %q, want 23502", code)
	}
}

// TestCommonDomainsSeed: version 0 is the seed's, every entry is a name the Apple builder accepts, and the tenant
// reads the list and the state of a catalog version but not its key.
func TestCommonDomainsSeed(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	common := h.column(`SELECT pattern FROM ctrlz.catalog_common_domains WHERE version = 0 ORDER BY pattern`)
	if len(common) == 0 {
		t.Fatal("version 0 of the common domains is empty")
	}
	for _, want := range []string{"local", "lan", "home.arpa", "captive.apple.com", "detectportal.firefox.com", "www.msftconnecttest.com", "connectivitycheck.gstatic.com"} {
		found := false
		for _, c := range common {
			found = found || c == want
		}
		if !found {
			t.Errorf("version 0 lacks %q", want)
		}
	}
	// The Apple builder takes the list as it is: a name it refuses would fail every profile that excludes the common
	// domains, and an expanded list is bounded.
	p, err := appleprofile.Expand(appleprofile.Request{Protocol: "doh", ExcludeCommon: true}, common)
	if err != nil {
		t.Fatalf("the builder refuses the seeded common domains: %v", err)
	}
	if len(p.ExcludedDomains) != len(common) {
		t.Errorf("%d domains expanded from %d seeded", len(p.ExcludedDomains), len(common))
	}
	// No import writes version 0, and none of 0 or less exists.
	if code := h.try("", nil, `INSERT INTO ctrlz.catalog_versions (version, key) VALUES (0, '\x01')`); code != "23514" {
		t.Errorf("catalog version 0: SQLSTATE %q, want 23514", code)
	}
	if code := h.try("", nil, `INSERT INTO ctrlz.catalog_versions (version, key) VALUES (-1, '\x01')`); code != "23514" {
		t.Errorf("catalog version -1: SQLSTATE %q, want 23514", code)
	}
	if _, err := h.super.Exec(h.ctx, `INSERT INTO ctrlz.catalog_versions (version, key, state) VALUES (1, '\x0101', 'current')`); err != nil {
		t.Fatal(err)
	}
	for _, who := range []uuid.UUID{h.A.Tenant, h.B.Tenant} {
		g := who.String()
		if code := h.try("tenant", &g, `SELECT count(*) FROM ctrlz.catalog_common_domains`); code != "" {
			t.Errorf("the tenant cannot read the common domains: %s", code)
		}
		if code := h.try("tenant", &g, `SELECT version, state FROM ctrlz.catalog_versions`); code != "" {
			t.Errorf("the tenant cannot read the state of a catalog version: %s", code)
		}
		if code := h.try("tenant", &g, `SELECT key FROM ctrlz.catalog_versions`); code != "42501" {
			t.Errorf("the tenant reads a catalog version key: %q", code)
		}
		if code := h.try("tenant", &g, `INSERT INTO ctrlz.catalog_common_domains (version, pattern) VALUES (7, 'x.example')`); code != "42501" {
			t.Errorf("the tenant writes a common domain: %q", code)
		}
	}
}

// TestLinkTokenColumns: params and via_share_id of the download links, and the expiry of the three bearer tables.
func TestLinkTokenColumns(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	A, B := h.A, h.B

	if got := h.str(`SELECT column_default FROM information_schema.columns WHERE table_schema = 'ctrlz' AND table_name = 'profile_download_tokens' AND column_name = 'max_uses'`); got != "3" {
		t.Errorf("a download link has %s uses by default, want 3 (D31)", got)
	}
	for _, col := range [][2]string{{"profile_download_tokens", "params"}, {"api_tokens", "expires_at"}} {
		var def *string
		var null string
		if err := h.super.QueryRow(h.ctx, `SELECT column_default, is_nullable FROM information_schema.columns WHERE table_schema = 'ctrlz' AND table_name = $1 AND column_name = $2`, col[0], col[1]).Scan(&def, &null); err != nil {
			t.Fatal(err)
		}
		if def != nil || null != "NO" {
			t.Errorf("%s.%s must be NOT NULL with no default (the writer states it), got default %v nullable %s", col[0], col[1], def, null)
		}
	}

	share := func(who uuid.UUID, endpoint uuid.UUID, tag string) uuid.UUID {
		var id uuid.UUID
		if err := h.super.QueryRow(h.ctx, `INSERT INTO ctrlz.setup_share_tokens (tenant_id, endpoint_id, token_hash, expires_at) VALUES ($1, $2, convert_to($3, 'UTF8'), now() + interval '1 day') RETURNING id`, who, endpoint, tag).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	link := func(who, endpoint uuid.UUID, tag string, via any, params string) error {
		_, err := h.super.Exec(h.ctx, `INSERT INTO ctrlz.profile_download_tokens (tenant_id, endpoint_id, params, params_hash, token_hash, expires_at, via_share_id) VALUES ($1, $2, $3::jsonb, '\x01', convert_to($4, 'UTF8'), now() + interval '15 minutes', $5)`, who, endpoint, params, tag, via)
		return err
	}
	shareA := share(A.Tenant, A.Endpoint, "p3-share-a")
	shareB := share(B.Tenant, B.Endpoint, "p3-share-b")

	if err := link(A.Tenant, A.Endpoint, "p3-link-a1", shareA, `{"protocol":"doh"}`); err != nil {
		t.Fatalf("a link through the tenant's own share link: %v", err)
	}
	if err := link(A.Tenant, A.Endpoint, "p3-link-a2", nil, `{}`); err != nil {
		t.Fatalf("a link with no share link: %v", err)
	}
	// Two tenants: A's link cannot name B's share link, whatever role writes it (the key is composite).
	if err := link(A.Tenant, A.Endpoint, "p3-link-x", shareB, `{}`); err == nil || pgErrCode(err) != "23503" {
		t.Errorf("a link of A through B's share link: %v, want 23503", err)
	}
	// The size bound is on the text of params.
	big := `{"x":"` + strings.Repeat("a", 65536) + `"}`
	if err := link(A.Tenant, A.Endpoint, "p3-link-big", nil, big); err == nil || pgErrCode(err) != "23514" {
		t.Errorf("params over 65,536 bytes: %v, want 23514", err)
	}
	if err := link(A.Tenant, A.Endpoint, "p3-link-ok", nil, `{"x":"`+strings.Repeat("a", 65536-9)+`"}`); err != nil {
		t.Errorf("params of exactly 65,536 bytes: %v", err)
	}

	// Revoking (deleting) a share link deletes the links made through it, and only those.
	if h.one(`SELECT count(*) FROM ctrlz.profile_download_tokens WHERE via_share_id = $1`, shareA) != 1 {
		t.Fatal("the link of A through its share link is missing")
	}
	if _, err := h.super.Exec(h.ctx, `DELETE FROM ctrlz.setup_share_tokens WHERE id = $1`, shareA); err != nil {
		t.Fatal(err)
	}
	if n := h.one(`SELECT count(*) FROM ctrlz.profile_download_tokens WHERE token_hash = convert_to('p3-link-a1', 'UTF8')`); n != 0 {
		t.Errorf("a link outlived its share link: %d", n)
	}
	if n := h.one(`SELECT count(*) FROM ctrlz.profile_download_tokens WHERE token_hash = convert_to('p3-link-a2', 'UTF8')`); n != 1 {
		t.Errorf("a link with no share link was deleted with another: %d", n)
	}

	// The tenant role may write both columns of its own row and sees nothing of the other tenant's.
	a, b := A.Tenant.String(), B.Tenant.String()
	ins := `INSERT INTO ctrlz.profile_download_tokens (tenant_id, endpoint_id, params, params_hash, token_hash, expires_at, via_share_id) VALUES ($1, $2, '{}', '\x01', convert_to($3, 'UTF8'), now() + interval '1 minute', $4)`
	if code := h.try("tenant", &a, ins, A.Tenant, A.Endpoint, "p3-link-t1", nil); code != "" {
		t.Errorf("the tenant inserts its own link: %q", code)
	}
	if code := h.try("tenant", &a, ins, B.Tenant, B.Endpoint, "p3-link-t2", nil); code == "" {
		t.Error("tenant A inserted a link for tenant B")
	}
	if code := h.try("tenant", &a, ins, A.Tenant, A.Endpoint, "p3-link-t3", shareB); code == "" {
		t.Error("tenant A made a link through tenant B's share link")
	}
	if code := h.try("tenant", &b, `INSERT INTO ctrlz.api_tokens (tenant_id, user_id, name, kind, token_hash, token_prefix, expires_at) VALUES ($1, $2, 'p3', 'read', '\x7b01', 'czt_p', now() + interval '1 day')`, B.Tenant, B.User); code != "" {
		t.Errorf("the tenant inserts its own API token: %q", code)
	}
	if code := h.try("tenant", &b, `INSERT INTO ctrlz.api_tokens (tenant_id, user_id, name, kind, token_hash, token_prefix) VALUES ($1, $2, 'p3', 'read', '\x7b02', 'czt_p')`, B.Tenant, B.User); code != "23502" {
		t.Errorf("an API token with no expiry: %q, want 23502", code)
	}
}

func pgErrCode(err error) string {
	if pe := pgErr(err); pe != nil {
		return pe.Code
	}
	return ""
}

// TestLinkLookupsReturnTenantStatus: both lookups say what state the tenant is in, for the tenant of the value and
// no other (7.1).
func TestLinkLookupsReturnTenantStatus(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	A, B := h.A, h.B
	lookup := func(fn, value string) (tenant uuid.UUID, status string, found bool) {
		rows, err := h.super.Query(h.ctx, `SELECT tenant_id, status FROM ctrlz_fn.`+fn+`(convert_to($1, 'UTF8'))`, value)
		if err != nil {
			t.Fatalf("%s: %v", fn, err)
		}
		defer rows.Close()
		for rows.Next() {
			if err := rows.Scan(&tenant, &status); err != nil {
				t.Fatal(err)
			}
			found = true
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return
	}
	for _, c := range []struct {
		fn    string
		value string
		who   uuid.UUID
	}{{"auth_share_by_hash", A.Share, A.Tenant}, {"auth_share_by_hash", B.Share, B.Tenant}, {"auth_download_by_hash", A.Download, A.Tenant}, {"auth_download_by_hash", B.Download, B.Tenant}} {
		got, st, ok := lookup(c.fn, c.value)
		if !ok || got != c.who || st != "active" {
			t.Errorf("%s(%s...) = %v %q %v, want %v active", c.fn, c.value[:5], got, st, ok, c.who)
		}
	}
	if _, err := h.super.Exec(h.ctx, `UPDATE ctrlz.tenants SET status = 'suspended' WHERE id = $1`, A.Tenant); err != nil {
		t.Fatal(err)
	}
	for _, fn := range []string{"auth_share_by_hash", "auth_download_by_hash"} {
		value := map[string]string{"auth_share_by_hash": A.Share, "auth_download_by_hash": A.Download}[fn]
		if _, st, ok := lookup(fn, value); !ok || st != "suspended" {
			t.Errorf("%s of a suspended tenant: %q %v, want suspended", fn, st, ok)
		}
		other := map[string]string{"auth_share_by_hash": B.Share, "auth_download_by_hash": B.Download}[fn]
		if _, st, ok := lookup(fn, other); !ok || st != "active" {
			t.Errorf("%s of tenant B after A was suspended: %q %v, want active", fn, st, ok)
		}
	}
	if _, st, ok := lookup("auth_share_by_hash", "no-such-token"); ok {
		t.Errorf("an unknown value resolved: %q", st)
	}
	// A revoked share link still does not resolve.
	if _, err := h.super.Exec(h.ctx, `UPDATE ctrlz.setup_share_tokens SET revoked_at = now() WHERE tenant_id = $1`, B.Tenant); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := lookup("auth_share_by_hash", B.Share); ok {
		t.Error("a revoked share link resolved")
	}
}

// TestEndpointColumnConstraints: the Apple profile staleness columns, and the length bounds.
func TestEndpointColumnConstraints(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	A, B := h.A, h.B
	a, b := A.Tenant.String(), B.Tenant.String()

	// The tenant writes the three columns together, for its own Endpoint, with a resolver id that has the grammar.
	upd := `UPDATE ctrlz.endpoints SET apple_profile_generated_at = now(), apple_profile_pair_version = 3, apple_profile_resolver_id = $2 WHERE id = $1`
	good := strings.Repeat("b", 26)
	if code := h.try("tenant", &a, upd, A.Endpoint, good); code != "" {
		t.Errorf("the tenant records a download: %q", code)
	}
	for _, bad := range []string{"", "short", strings.Repeat("B", 26), strings.Repeat("1", 26), strings.Repeat("b", 27)} {
		if code := h.try("tenant", &a, upd, A.Endpoint, bad); code != "23514" {
			t.Errorf("resolver id %q: SQLSTATE %q, want 23514", bad, code)
		}
	}
	// B's setting does not reach A's row: the statement changes nothing for another tenant's Endpoint.
	var n int
	if err := h.super.QueryRow(h.ctx, `SELECT count(*) FROM ctrlz.endpoints WHERE id = $1 AND apple_profile_pair_version IS NOT NULL`, A.Endpoint).Scan(&n); err != nil || n != 0 {
		t.Fatalf("the rolled back updates left a value: %d %v", n, err)
	}
	if err := h.tenantExec(B.Tenant, upd, A.Endpoint, good); err != nil {
		t.Fatal(err)
	}
	if err := h.super.QueryRow(h.ctx, `SELECT count(*) FROM ctrlz.endpoints WHERE id = $1 AND apple_profile_pair_version IS NOT NULL`, A.Endpoint).Scan(&n); err != nil || n != 0 {
		t.Errorf("tenant B wrote to tenant A's Endpoint: %d %v", n, err)
	}
	// The compiler does not read them (a resolver id means nothing to a node), the tenant does.
	if code := h.try("compiler", nil, `SELECT apple_profile_resolver_id FROM ctrlz.endpoints`); code != "42501" {
		t.Errorf("the compiler reads the Apple profile resolver id: %q", code)
	}
	if code := h.try("compiler", nil, `SELECT apple_profile_pair_version FROM ctrlz.endpoints`); code != "42501" {
		t.Errorf("the compiler reads the Apple profile pair version: %q", code)
	}
	if code := h.try("tenant", &b, `SELECT apple_profile_resolver_id, apple_profile_pair_version FROM ctrlz.endpoints`); code != "" {
		t.Errorf("the tenant cannot read its Apple profile columns: %q", code)
	}

	// Lengths. 253 is the longest host name, 64 the longest alias and group.
	host := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	if len(host) != 253 {
		t.Fatalf("test host is %d bytes", len(host))
	}
	insHost := `INSERT INTO ctrlz.endpoint_ddns_hosts (tenant_id, endpoint_id, hostname) VALUES ($1, $2, $3)`
	if code := h.try("", nil, insHost, A.Tenant, A.Endpoint, host); code != "" {
		t.Errorf("a 253 byte host name: %q", code)
	}
	for _, bad := range []string{"", host + "x"} {
		if code := h.try("", nil, insHost, A.Tenant, A.Endpoint, bad); code != "23514" {
			t.Errorf("a host name of %d bytes: %q, want 23514", len(bad), code)
		}
	}
	for _, col := range []string{"alias", "group_name"} {
		q := `UPDATE ctrlz.clients SET ` + col + ` = $2 WHERE tenant_id = $1`
		if code := h.try("", nil, q, A.Tenant, strings.Repeat("ا", 64)); code != "" {
			t.Errorf("%s of 64 characters: %q", col, code)
		}
		if code := h.try("", nil, q, A.Tenant, strings.Repeat("ا", 65)); code != "23514" {
			t.Errorf("%s of 65 characters: %q, want 23514", col, code)
		}
	}
}

// tenantExec runs a statement as the tenant role for a tenant and returns its error. A statement that matches no
// row is not an error.
func (h *harness) tenantExec(tenant uuid.UUID, sql string, args ...any) error {
	s := h.db.Store(h.ctx, h.t, store.RoleTenant)
	return s.WithTenant(h.ctx, tenant, store.TxOpts{}, func(tx store.Tx) error {
		_, err := tx.DB().Exec(tx.Context(), sql, args...)
		return err
	})
}

// TestDDNSHostDoesNotCascade: the key from an authorized IP to its DDNS host no longer cascades (5): deleting a host
// that learned rows is refused at commit, an Endpoint or tenant delete still removes both.
func TestDDNSHostDoesNotCascade(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	A, B := h.A, h.B
	host := func(who uuid.UUID) uuid.UUID {
		return uuid.MustParse(strings.Replace("00000000-0000-7000-8000-0000000X0d01", "X", map[uuid.UUID]string{A.Tenant: "1", B.Tenant: "2"}[who], 1))
	}
	// The seed has one host and one authorized IP that names it, for each tenant.
	if n := h.one(`SELECT count(*) FROM ctrlz.authorized_ips WHERE ddns_host_id = $1`, host(A.Tenant)); n != 1 {
		t.Fatalf("seed: %d authorized IPs of A's host", n)
	}
	if code := h.commit(`DELETE FROM ctrlz.endpoint_ddns_hosts WHERE id = '` + host(A.Tenant).String() + `'`); code != "23503" {
		t.Errorf("a host delete with learned rows: SQLSTATE %q at commit, want 23503", code)
	}
	if n := h.one(`SELECT count(*) FROM ctrlz.endpoint_ddns_hosts WHERE tenant_id = $1`, A.Tenant); n != 1 {
		t.Errorf("A's host was deleted anyway")
	}
	// The method of 5 removes the rows first, then the host, in one transaction.
	if code := h.commit(
		`DELETE FROM ctrlz.authorized_ips WHERE ddns_host_id = '`+host(A.Tenant).String()+`'`,
		`DELETE FROM ctrlz.endpoint_ddns_hosts WHERE id = '`+host(A.Tenant).String()+`'`); code != "" {
		t.Errorf("the rows first and then the host: %q", code)
	}
	// B's host and rows are untouched by what was done to A's.
	if n := h.one(`SELECT count(*) FROM ctrlz.authorized_ips WHERE tenant_id = $1 AND ddns_host_id = $2`, B.Tenant, host(B.Tenant)); n != 1 {
		t.Errorf("B's authorized IP: %d", n)
	}
	// An Endpoint delete cascades to the host and to the rows of the host in one go (the deferred check runs at
	// commit, when both cascades have run), and so does the delete of the tenant.
	if code := h.commit(`DELETE FROM ctrlz.endpoints WHERE id = '` + B.Endpoint.String() + `'`); code != "" {
		t.Errorf("an Endpoint delete whose host learned rows: %q", code)
	}
	if n := h.one(`SELECT count(*) FROM ctrlz.authorized_ips WHERE tenant_id = $1`, B.Tenant); n != 0 {
		t.Errorf("B's authorized IPs outlived their Endpoint: %d", n)
	}
	if code := h.commit(`DELETE FROM ctrlz.tenants WHERE id = '` + A.Tenant.String() + `'`); code != "" {
		t.Errorf("a tenant delete: %q", code)
	}
}

// TestEndpointViews: tenant_endpoint_status has no `configured` and no sealed token, and tenant_profile_counts counts an
// Endpoint once wherever it names the profile.
func TestEndpointViews(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	A, B := h.A, h.B
	for _, col := range []string{"configured", "doh_token_ct", "doh_token_hash"} {
		if n := h.one(`SELECT count(*) FROM information_schema.columns WHERE table_schema = 'ctrlz' AND table_name = 'tenant_endpoint_status' AND column_name = $1`, col); n != 0 {
			t.Errorf("tenant_endpoint_status still has %s", col)
		}
	}

	read := func(who uuid.UUID, sql string, args ...any) (out []string) {
		s := h.db.Store(h.ctx, t, store.RoleTenant)
		if err := s.WithTenant(h.ctx, who, store.TxOpts{ReadOnly: true}, func(tx store.Tx) error {
			rows, err := tx.DB().Query(tx.Context(), sql, args...)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var v string
				if err := rows.Scan(&v); err != nil {
					return err
				}
				out = append(out, v)
			}
			return rows.Err()
		}); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
		return out
	}

	// The seeded Endpoint has clients and authorized IPs and no query yet: it is Pending, and so is any Endpoint with no
	// query, configured or not (Plan, Endpoint model).
	for _, who := range []uuid.UUID{A.Tenant, B.Tenant} {
		got := read(who, `SELECT status FROM ctrlz.tenant_endpoint_status`)
		if len(got) != 1 || got[0] != "pending" {
			t.Errorf("status of the seeded Endpoint: %v, want [pending]", got)
		}
	}
	if _, err := h.super.Exec(h.ctx, `UPDATE ctrlz.endpoints SET first_query_at = now() WHERE id = $1`, A.Endpoint); err != nil {
		t.Fatal(err)
	}
	if got := read(A.Tenant, `SELECT status FROM ctrlz.tenant_endpoint_status`); len(got) != 1 || got[0] != "active" {
		t.Errorf("status after the first query: %v, want [active]", got)
	}
	if got := read(B.Tenant, `SELECT status FROM ctrlz.tenant_endpoint_status`); len(got) != 1 || got[0] != "pending" {
		t.Errorf("tenant B's status changed with A's: %v", got)
	}

	// endpoint_count. The seed names Profile and Profile2 in the base stack, in a window and in a client of one Endpoint:
	// that is one Endpoint for each, not four.
	count := func(who uuid.UUID, profile uuid.UUID) string {
		got := read(who, `SELECT endpoint_count::text FROM ctrlz.tenant_profile_counts WHERE profile_id = $1`, profile)
		if len(got) != 1 {
			t.Fatalf("no counters of profile %s for tenant %s", profile, who)
		}
		return got[0]
	}
	if c := count(A.Tenant, A.Profile); c != "1" {
		t.Errorf("an Endpoint that names the profile four times counts %s, want 1", c)
	}
	if c := count(A.Tenant, A.Profile2); c != "1" {
		t.Errorf("Profile 2: %s, want 1", c)
	}

	// A profile used only in a schedule window, or only by a client, or in a second slot, or by nobody.
	newProfile := func(name string) uuid.UUID {
		var id uuid.UUID
		if err := h.super.QueryRow(h.ctx, `INSERT INTO ctrlz.profiles (tenant_id, name) VALUES ($1, $2) RETURNING id`, A.Tenant, name).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	unused, window, client, window2, client2 := newProfile("unused"), newProfile("window"), newProfile("client"), newProfile("window2"), newProfile("client2")
	if c := count(A.Tenant, unused); c != "0" {
		t.Errorf("an unused profile counts %s, want 0", c)
	}
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := h.super.Exec(h.ctx, sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	exec(`INSERT INTO ctrlz.schedule_windows (tenant_id, endpoint_id, minutes, profile_id, profile2_id) VALUES ($1, $2, int4range(120, 180), $3, $4)`, A.Tenant, A.Endpoint, window, window2)
	exec(`INSERT INTO ctrlz.clients (tenant_id, endpoint_id, label, profile_id, profile2_id) VALUES ($1, $2, 'kid', $3, $4)`, A.Tenant, A.Endpoint, client, client2)
	for name, p := range map[string]uuid.UUID{"a window's Profile 1": window, "a window's Profile 2": window2, "a client's Profile 1": client, "a client's Profile 2": client2} {
		if c := count(A.Tenant, p); c != "1" {
			t.Errorf("a profile used only as %s counts %s, want 1", name, c)
		}
	}
	// A second Endpoint using one profile makes two, and B never counts for A.
	var second uuid.UUID
	if err := h.super.QueryRow(h.ctx, `INSERT INTO ctrlz.endpoints (tenant_id, name, type, resolver_id, profile_id) VALUES ($1, 'second', 'doh_client', $2, $3) RETURNING id`, A.Tenant, strings.Repeat("c", 26), A.Profile).Scan(&second); err != nil {
		t.Fatal(err)
	}
	if c := count(A.Tenant, A.Profile); c != "2" {
		t.Errorf("two Endpoints on a profile: %s, want 2", c)
	}
	if c := count(B.Tenant, B.Profile); c != "1" {
		t.Errorf("tenant B's count moved with A's Endpoint: %s", c)
	}
	if got := read(B.Tenant, `SELECT count(*)::text FROM ctrlz.tenant_profile_counts WHERE profile_id = $1`, A.Profile); got[0] != "0" {
		t.Errorf("tenant B sees tenant A's counters: %v", got)
	}
}

// TestProfileCountsCost: a profile read costs a pass over the tenant's rows, not a probe of every client of every
// Endpoint per profile. The tenant has 30 profiles, 20 Endpoints and 10,000 clients that all name one profile; the
// other 29 profiles are named by no client, which is the case where a per-(profile, Endpoint) probe heap-fetches every
// client (about 290,000 tuples). The buffers the read touches are bounded well under that, and the counts are right.
func TestProfileCountsCost(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	A := h.A
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := h.super.Exec(h.ctx, sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	exec(`INSERT INTO ctrlz.profiles (tenant_id, name) SELECT $1, 'bulk' || g FROM generate_series(1, 29) g`, A.Tenant)
	exec(`INSERT INTO ctrlz.endpoints (tenant_id, name, type, resolver_id, profile_id)
	      SELECT $1, 'bulk' || g, 'doh_client', repeat(chr(100 + g), 26), $2 FROM generate_series(1, 19) g`, A.Tenant, A.Profile)
	exec(`INSERT INTO ctrlz.clients (tenant_id, endpoint_id, label, profile_id)
	      SELECT $1, e.id, 'c' || g, $2 FROM ctrlz.endpoints e, generate_series(1, 500) g WHERE e.tenant_id = $1`, A.Tenant, A.Profile)
	exec(`ANALYZE ctrlz.clients`)
	exec(`ANALYZE ctrlz.endpoints`)
	exec(`ANALYZE ctrlz.profiles`)

	s := h.db.Store(h.ctx, t, store.RoleTenant)
	var plan string
	counts := map[uuid.UUID]int{}
	if err := s.WithTenant(h.ctx, A.Tenant, store.TxOpts{ReadOnly: true}, func(tx store.Tx) error {
		if err := tx.DB().QueryRow(tx.Context(), `EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) SELECT profile_id, endpoint_count FROM ctrlz.tenant_profile_counts`).Scan(&plan); err != nil {
			return err
		}
		rows, err := tx.DB().Query(tx.Context(), `SELECT profile_id, endpoint_count FROM ctrlz.tenant_profile_counts`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id uuid.UUID
			var n int
			if err := rows.Scan(&id, &n); err != nil {
				return err
			}
			counts[id] = n
		}
		return rows.Err()
	}); err != nil {
		t.Fatal(err)
	}
	var doc []struct {
		Plan struct {
			Hit  int64 `json:"Shared Hit Blocks"`
			Read int64 `json:"Shared Read Blocks"`
		}
	}
	if err := json.Unmarshal([]byte(plan), &doc); err != nil || len(doc) != 1 {
		t.Fatalf("plan %q: %v", plan, err)
	}
	blocks := doc[0].Plan.Hit + doc[0].Plan.Read
	t.Logf("buffers: %d", blocks)
	if blocks > 3000 {
		t.Errorf("tenant_profile_counts touched %d buffers for 10,000 clients, want a single pass (under 3000)", blocks)
	}
	if len(counts) != 31 {
		t.Fatalf("%d profiles counted, want 31", len(counts))
	}
	if counts[A.Profile] != 20 {
		t.Errorf("the profile every client names counts %d Endpoints, want 20", counts[A.Profile])
	}
	zero := 0
	for id, n := range counts {
		if n == 0 {
			zero++
		}
		if id == A.Profile2 && n != 1 {
			t.Errorf("Profile 2 counts %d, want 1", n)
		}
	}
	if zero != 29 {
		t.Errorf("%d profiles count 0, want the 29 nobody names", zero)
	}
}

// ridCases are the resolver ids of shared/vectors/identity.json (the answers of its parse cases) and of the known
// answer of hash.json, the cases the Go and the SQL hash are compared over.
func ridCases(t *testing.T) []string {
	t.Helper()
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		if regexp.MustCompile(`^[a-z2-7]{26}$`).MatchString(s) && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, file := range []string{"identity", "hash"} {
		raw, err := os.ReadFile("../../../shared/vectors/" + file + ".json")
		if err != nil {
			t.Fatal(err)
		}
		var g struct {
			Cases []struct {
				Op     string          `json:"op"`
				Input  string          `json:"input"`
				Expect json.RawMessage `json:"expect"`
			} `json:"cases"`
		}
		if err := json.Unmarshal(raw, &g); err != nil {
			t.Fatal(err)
		}
		for _, c := range g.Cases {
			if c.Op == "rid_hash" {
				add(c.Input)
			}
			var s string
			if json.Unmarshal(c.Expect, &s) == nil {
				for _, f := range strings.Fields(s) {
					if rid, ok := strings.CutPrefix(f, "rid="); ok {
						add(rid)
					}
				}
			}
		}
	}
	if len(out) == 0 {
		t.Fatal("no resolver id in the vectors")
	}
	// The vectors carry one id; the edges of the alphabet and a mixed one show the whole hash is compared.
	for _, extra := range []string{strings.Repeat("a", 26), strings.Repeat("7", 26), "abcdefghijklmnopqrstuvwxyz"[:26], "z7y6x5w4v3u2tsrqponmlkjihg"} {
		add(extra)
	}
	return out
}

// TestClaimTakeRIDHashMatchesIdentity (P3 2.2 item 10): the SQL hash in ip_claim_take is shared/identity.RIDHash.
// For each resolver id of the vectors, the Endpoint takes it, an observation that carries the Go hash proves the
// claim, and one that carries the hash of any other id does not.
func TestClaimTakeRIDHashMatchesIdentity(t *testing.T) {
	l := newClaimLab(t)
	l.openMode()
	rids := ridCases(t)
	if len(rids) < 4 {
		t.Fatalf("only %d resolver ids in the vectors", len(rids))
	}
	for i, rid := range rids {
		l.exec(`UPDATE ctrlz.endpoints SET resolver_id = $2 WHERE id = $1`, l.A.Endpoint, rid)
		ip := "192.0.2." + strconv.Itoa(10+i)
		claim := l.pendingClaimOf(l.A, ip)
		other := rids[(i+1)%len(rids)]
		oh := identity.RIDHash(other)
		l.hubSeesRID(l.open(l.A, claim).Label, ip, "doh", oh[:])
		if got := l.take(l.A, claim); got != "no_proof" {
			t.Errorf("%s: an observation on the identity of %s proved the claim: %s", rid, other, got)
		}
		h := identity.RIDHash(rid)
		l.hubSeesRID(l.open(l.A, claim).Label, ip, "dot", h[:])
		if got := l.take(l.A, claim); got != "active" {
			t.Errorf("%s: the observation on the Endpoint's own identity: %s, want active (the SQL hash differs from identity.RIDHash)", rid, got)
		}
	}
}

// TestClaimTakeNeedsTheClaimantsOwnIdentity (P3 2.2 item 10, 4.2): a device whose encrypted DNS uses another
// tenant's Endpoint cannot prove the claimant's address, and neither can an observation with no identity.
func TestClaimTakeNeedsTheClaimantsOwnIdentity(t *testing.T) {
	l := newClaimLab(t)
	l.openMode()
	A, B := l.A, l.B
	hashOf := func(rid string) []byte { h := identity.RIDHash(rid); return h[:] }

	claim := l.pendingClaimOf(A, "192.0.2.201")
	observe := func(proto string, rid []byte) {
		t.Helper()
		l.hubSeesRID(l.open(A, claim).Label, "192.0.2.201", proto, rid)
	}

	// The query arrived on B's Endpoint (a page of B made the device resolve A's label), over each encrypted protocol.
	for _, proto := range []string{"doh", "doh3", "dot", "doq"} {
		observe(proto, hashOf(B.ResolveID))
		l.want(proto+" on another tenant's identity", l.take(A, claim), "no_proof")
	}
	// No identity at all, over each encrypted protocol: fail closed.
	for _, proto := range []string{"doh", "doh3", "dot", "doq"} {
		observe(proto, nil)
		l.want(proto+" with no identity", l.take(A, claim), "no_proof")
	}
	// A hash of a resolver id that belongs to nobody.
	observe("doh", hashOf(strings.Repeat("z", 26)))
	l.want("an identity of nobody", l.take(A, claim), "no_proof")
	l.wantState("the claim", claim, "pending_proof")

	// The identity of A's Endpoint as it was before a rotation no longer proves.
	old := hashOf(A.ResolveID)
	l.exec(`UPDATE ctrlz.endpoints SET resolver_id = $2 WHERE id = $1`, A.Endpoint, strings.Repeat("e", 26))
	observe("doh", old)
	l.want("the identity from before a rotation", l.take(A, claim), "no_proof")

	// B takes the same address with B's own identity on B's own Endpoint: tenant isolation of the hash.
	bclaim := l.pendingClaimOf(B, "192.0.2.202")
	l.hubSeesRID(l.open(B, bclaim).Label, "192.0.2.202", "doh", hashOf(strings.Repeat("e", 26)))
	l.want("B with the identity A rotated to", l.take(B, bclaim), "no_proof")
	l.hubSeesRID(l.open(B, bclaim).Label, "192.0.2.202", "doh", hashOf(B.ResolveID))
	l.want("B with its own identity", l.take(B, bclaim), "active")

	// The current identity of A proves, over each protocol, and the method is secure_dns.
	for i, proto := range []string{"doh", "doh3", "dot", "doq"} {
		ip := "192.0.2." + strconv.Itoa(210+i)
		c := l.pendingClaimOf(A, ip)
		l.hubSeesRID(l.open(A, c).Label, ip, proto, hashOf(strings.Repeat("e", 26)))
		l.want(proto+" on the claimant's own identity", l.take(A, c), "active")
		if m := l.method(c); m != "secure_dns" {
			t.Errorf("%s: proof method %q, want secure_dns", proto, m)
		}
	}

	// The hub cannot write an identity for a plain transport, nor one of the wrong length.
	c := l.pendingClaimOf(A, "192.0.2.220")
	label := l.open(A, c).Label
	hubWrite := func(proto string, rid []byte) error {
		return l.hub.WithTenant(l.h.ctx, A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
			_, err := tx.DB().Exec(tx.Context(), `UPDATE ctrlz.ip_proof_challenges SET observed_at = now(), observed_ip = '192.0.2.220', observed_protocol = $2, observed_rid_hash = $3 WHERE label = $1`, label, proto, rid)
			return err
		})
	}
	for _, bad := range []struct {
		proto string
		rid   []byte
	}{{"tcp", make([]byte, 16)}, {"udp", make([]byte, 16)}, {"doh", make([]byte, 15)}, {"doh", make([]byte, 17)}, {"doh", []byte{}}} {
		if err := hubWrite(bad.proto, bad.rid); err == nil {
			t.Errorf("the hub wrote a %d byte identity for %s", len(bad.rid), bad.proto)
		}
	}
	// The tenant reads neither the hash nor the address of the evidence.
	if err := l.tenant.WithTenant(l.h.ctx, A.Tenant, store.TxOpts{ReadOnly: true}, func(tx store.Tx) error {
		_, err := tx.DB().Exec(tx.Context(), `SELECT observed_rid_hash FROM ctrlz.ip_proof_challenges`)
		return err
	}); err == nil {
		t.Error("the tenant reads observed_rid_hash")
	}
}

// claimCount is the number of rows of a tenant's claims, whatever their state.
func (l *claimLab) claimCount(tenant uuid.UUID) int {
	l.t.Helper()
	return l.h.one(`SELECT count(*) FROM ctrlz.ip_claims WHERE tenant_id = $1`, tenant)
}

// TestClaimRequestD35 (P3 2.2 item 11, request side): in every mode an overlap with the caller's own active or grace
// claim is `own` and inserts nothing, and an overlap with another tenant's active or grace claim is a pending_proof row.
func TestClaimRequestD35(t *testing.T) {
	for i, mode := range []string{"closed", "invite", "open"} {
		t.Run(mode, func(t *testing.T) {
			l := newClaimLab(t)
			A, B := l.A, l.B
			l.exec("UPDATE ctrlz.system_settings SET registration_mode = $1", mode)
			base := "198.51.100." + strconv.Itoa(16*(i+1))
			// A /28 is the widest a closed or invite request may be: in open mode only a /32 is, so use one prefix that
			// fits the mode.
			own := base + "/32"
			if mode != "open" {
				own = base + "/28"
			}
			a := l.request(A, own, "manual")
			if mode == "open" {
				l.want("A's request in open mode", a.Outcome, "pending_proof")
				l.observe(A, a.ClaimID, base)
				l.want("A proves it", l.take(A, a.ClaimID), "active")
			} else {
				l.want("A's request", a.Outcome, "active")
			}
			before := l.claimCount(A.Tenant)

			// Own overlap: the same prefix, a part of it, and a wider one, and for a wider one the answer is own and not
			// wide_requires_approval. Nothing is inserted.
			for _, p := range []string{own, base + "/32", "198.51.100.0/24"} {
				r := l.request(A, p, "manual")
				l.want("A overlaps its own claim with "+p, r.Outcome, "own")
				if r.ClaimID != uuid.Nil {
					t.Errorf("an own overlap with %s returned claim %s", p, r.ClaimID)
				}
			}
			if n := l.claimCount(A.Tenant); n != before {
				t.Errorf("an own overlap inserted rows: %d claims, had %d", n, before)
			}
			// A claim in grace is as much its own.
			l.workerSets(A, a.ClaimID, "UPDATE ctrlz.ip_claims SET state = 'grace', first_grace_at = now(), grace_until = now() + interval '14 days' WHERE id = $1")
			l.want("A overlaps its own claim in grace", l.request(A, base+"/32", "manual").Outcome, "own")
			l.workerSets(A, a.ClaimID, "UPDATE ctrlz.ip_claims SET state = 'active', grace_until = NULL WHERE id = $1")

			// Another tenant's claim: a row that waits.
			bb := l.request(B, base+"/32", "manual")
			l.want("B overlaps A's claim", bb.Outcome, "pending_proof")
			if bb.ClaimID == uuid.Nil {
				t.Fatal("B's request left no row")
			}
			l.wantState("B's request", bb.ClaimID, "pending_proof")
			l.wantState("A's claim", a.ClaimID, "active")
			// B asking again for the same address is B's own pending row and no active claim: it waits again.
			l.want("B asks twice", l.request(B, base+"/32", "manual").Outcome, "pending_proof")

			// A /28 to /31 that overlaps another tenant's claim leaves a row that waits, and the answer says an admin is
			// needed: ip_claim_take refuses anything wider than /32 without approved_by_admin, so no proof activates it.
			w := l.request(B, base+"/29", "manual")
			l.want("B's /29 overlapping A's claim", w.Outcome, "wide_requires_approval")
			if w.ClaimID == uuid.Nil {
				t.Fatal("B's /29 request left no row")
			}
			l.wantState("B's /29", w.ClaimID, "pending_proof")
		})
	}
}

// TestClaimTakeD35 (item 11, take side): a proof of one address displaces another tenant's claim that contains it and
// is unproven, idle or on a hard disabled Endpoint, also when that claim is wider than the taker's; a proven, fresh
// one holds. One two-tenant run for each reason.
func TestClaimTakeD35(t *testing.T) {
	l := newClaimLab(t)
	A, B := l.A, l.B
	l.closedMode()

	attempt := func(base string, prep func(a uuid.UUID), want string, wantA string) {
		t.Helper()
		a := l.request(A, base+"/28", "manual")
		l.want("A's /28 "+base, a.Outcome, "active")
		if prep != nil {
			prep(a.ClaimID)
		}
		ip := at(base, 5)
		b := l.request(B, ip+"/32", "manual")
		l.want("B's /32 inside A's /28 "+base, b.Outcome, "pending_proof")
		l.observe(B, b.ClaimID, ip)
		l.want("B's proof against "+base, l.take(B, b.ClaimID), want)
		l.wantState("A's /28 "+base, a.ClaimID, wantA)
		if want == "active" {
			l.wantState("B's /32 "+base, b.ClaimID, "active")
		} else {
			l.wantState("B's /32 "+base, b.ClaimID, "pending_proof")
		}
	}

	prove := func(base string) func(uuid.UUID) {
		return func(a uuid.UUID) {
			// A claim wider than a /32 is proven only after an admin approved it (4.1).
			l.approve(a)
			ip := at(base, 9)
			l.observe(A, a, ip)
			l.want("A proves its /28", l.take(A, a), "active")
		}
	}

	// Unproven and wider: displaced.
	attempt("203.0.113.0", nil, "active", "released")
	// Proven and fresh and wider: holds.
	attempt("203.0.113.16", prove("203.0.113.16"), "unavailable", "active")
	// Proven, but idle past takeover_idle_days: displaced.
	attempt("203.0.113.32", func(a uuid.UUID) {
		prove("203.0.113.32")(a)
		l.exec("UPDATE ctrlz.ip_claims SET last_seen_at = now() - interval '400 days' WHERE id = $1", a)
	}, "active", "released")
	// Proven and fresh, on an Endpoint the admin hard disabled: displaced.
	attempt("203.0.113.48", func(a uuid.UUID) {
		prove("203.0.113.48")(a)
		l.exec("UPDATE ctrlz.endpoints SET admin_state = 'hard_disabled' WHERE id = $1", A.Endpoint)
	}, "active", "released")
	l.exec("UPDATE ctrlz.endpoints SET admin_state = 'enabled' WHERE id = $1", A.Endpoint)

	// A claim that overlaps the taker's but does not contain the observed address still blocks: B's /28 proven from an
	// address A's /32 does not hold.
	a32 := l.request(A, "203.0.113.66/32", "manual")
	l.want("A's /32", a32.Outcome, "active")
	l.openMode()
	b28 := l.request(B, "203.0.113.64/28", "manual")
	l.want("B's /28 in open mode", b28.Outcome, "wide_requires_approval")
	l.approve(b28.ClaimID)
	l.observe(B, b28.ClaimID, "203.0.113.70")
	l.want("a /28 proven from an address the overlapping claim does not hold", l.take(B, b28.ClaimID), "unavailable")
	l.wantState("A's /32", a32.ClaimID, "active")
}

// TestClaimQuotaAndOwnOnAPlan: with tenant B on a plan of one claim and tenant A on the default plan, B's own overlap is
// `own` (not a quota refusal), its other prefix is over quota, and A is not limited by B's plan (the max_ip_claims case
// of 11.4 with a plan value that differs from the defaults).
func TestClaimQuotaAndOwnOnAPlan(t *testing.T) {
	l := newClaimLab(t)
	A, B := l.A, l.B
	l.closedMode()
	small := l.h.insertPlan("one claim")
	l.exec(`UPDATE ctrlz.plans SET max_ip_claims = 1 WHERE id = $1`, small)
	l.exec(`UPDATE ctrlz.tenants SET plan_id = $2 WHERE id = $1`, B.Tenant, small)
	// The seeded active claim of each tenant counts: B holds one, so it is at its limit already.
	l.exec(`UPDATE ctrlz.ip_claims SET state = 'released' WHERE tenant_id = $1`, B.Tenant)
	b := l.request(B, "192.0.2.240/32", "manual")
	l.want("B's one claim", b.Outcome, "active")
	l.want("B overlaps its own claim at its limit", l.request(B, "192.0.2.240/32", "manual").Outcome, "own")
	l.want("B's second prefix", l.request(B, "192.0.2.241/32", "manual").Outcome, "quota_exceeded")
	for i := 0; i < 3; i++ {
		l.want("A on the default plan", l.request(A, "192.0.2."+strconv.Itoa(244+i)+"/32", "manual").Outcome, "active")
	}
}

// at is the address off places above a network's first address ("203.0.113.16", 5 is "203.0.113.21").
func at(base string, off int) string {
	a := netip.MustParseAddr(base).As4()
	a[3] += byte(off)
	return netip.AddrFrom4(a).String()
}
