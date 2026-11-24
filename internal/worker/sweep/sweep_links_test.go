package sweep_test

import "testing"

// The purge of share and download links (docs/specs/p3-endpoints.md 7.1): rows past their expiry, and revoked share links
// with the download links made through them, go; what is live stays, for every tenant, and a second run deletes nothing.
func TestSlowDeletesLinksPastTheirExpiryOrRevoked(t *testing.T) {
	r := newRig(t)
	a, b := r.env.A, r.env.B
	ex := func(sql string, args ...any) { r.env.Exec(t, sql, args...) }
	plant := func(tenant, endpoint any, tag string, dead bool) {
		exp, rev := "now() + interval '1 day'", "NULL"
		if dead {
			exp, rev = "now() - interval '1 hour'", "now()"
		}
		// An expired share link, a revoked one that has not expired, a live one, and download links of each kind.
		ex(`INSERT INTO ctrlz.setup_share_tokens (tenant_id, endpoint_id, token_hash, expires_at) VALUES ($1, $2, convert_to($3 || '-expired', 'UTF8'), `+exp+`)`, tenant, endpoint, tag)
		ex(`INSERT INTO ctrlz.setup_share_tokens (tenant_id, endpoint_id, token_hash, expires_at, revoked_at) VALUES ($1, $2, convert_to($3 || '-revoked', 'UTF8'), now() + interval '1 day', `+rev+`)`, tenant, endpoint, tag)
		ex(`INSERT INTO ctrlz.profile_download_tokens (tenant_id, endpoint_id, params, params_hash, token_hash, expires_at, via_share_id)
			VALUES ($1, $2, '{}'::jsonb, '\x01', convert_to($3 || '-down', 'UTF8'), now() + interval '10 minutes',
			(SELECT id FROM ctrlz.setup_share_tokens WHERE tenant_id = $1 AND token_hash = convert_to($3 || '-revoked', 'UTF8')))`, tenant, endpoint, tag)
		ex(`INSERT INTO ctrlz.profile_download_tokens (tenant_id, endpoint_id, params, params_hash, token_hash, expires_at)
			VALUES ($1, $2, '{}'::jsonb, '\x01', convert_to($3 || '-old', 'UTF8'), `+exp+`)`, tenant, endpoint, tag)
	}
	plant(a.Tenant, a.Endpoint, "a", true)
	plant(b.Tenant, b.Endpoint, "b", false)
	shares := func(tenant any) int {
		return r.count(`SELECT count(*) FROM ctrlz.setup_share_tokens WHERE tenant_id = $1`, tenant)
	}
	downloads := func(tenant any) int {
		return r.count(`SELECT count(*) FROM ctrlz.profile_download_tokens WHERE tenant_id = $1`, tenant)
	}
	// Each tenant holds its seeded share link and download link (live) besides what the case planted.
	if shares(a.Tenant) != 3 || downloads(a.Tenant) != 3 || shares(b.Tenant) != 3 || downloads(b.Tenant) != 3 {
		t.Fatalf("planted shares %d/%d downloads %d/%d", shares(a.Tenant), shares(b.Tenant), downloads(a.Tenant), downloads(b.Tenant))
	}
	res, err := r.sweep.Slow(r.env.Ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res.Tenant.ShareLinks != 2 {
		t.Errorf("swept %d share links, want 2", res.Tenant.ShareLinks)
	}
	// A: the seeded live ones stay, the expired and the revoked go, and the download link made through the revoked one with it.
	if n := shares(a.Tenant); n != 1 {
		t.Errorf("A holds %d share links, want its seeded one", n)
	}
	if n := downloads(a.Tenant); n != 1 {
		t.Errorf("A holds %d download links, want its seeded one", n)
	}
	// B's live rows are all still there.
	if shares(b.Tenant) != 3 || downloads(b.Tenant) != 3 {
		t.Errorf("B holds %d share links and %d download links, want 3 and 3", shares(b.Tenant), downloads(b.Tenant))
	}
	res2, err := r.sweep.Slow(r.env.Ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res2.Tenant.ShareLinks != 0 || res2.Tenant.DownloadLinks != 0 {
		t.Errorf("a second sweep deleted again: %+v", res2.Tenant)
	}
}
