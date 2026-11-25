package store_test

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// DownloadLinkRead (p3-D4-r2-2) answers what DownloadLinkConsume would answer, and spends nothing: the same row under the same
// test, for the Endpoint and the tenant that own it and nobody else.
func TestDownloadLinkReadSpendsNothingAndSeesWhatConsumeSees(t *testing.T) {
	e := newRaceEnv(t)
	now := time.Now().UTC()
	var id uuid.UUID
	if err := e.super.QueryRow(e.ctx, `INSERT INTO ctrlz.profile_download_tokens (tenant_id, endpoint_id, params, params_hash, token_hash, expires_at, max_uses)
		VALUES ($1, $2, '{"a":1}'::jsonb, '\x0102', '\x7e01', now() + interval '1 hour', 2) RETURNING id`, e.A.Tenant, e.A.Endpoint).Scan(&id); err != nil {
		t.Fatal(err)
	}
	read := func(tenant, endpoint uuid.UUID, at time.Time) (store.DownloadConsumed, bool) {
		t.Helper()
		var c store.DownloadConsumed
		var ok bool
		if err := e.tenant.WithTenant(e.ctx, tenant, store.TxOpts{}, func(tx store.Tx) (err error) {
			c, ok, err = tx.DownloadLinkRead(id, endpoint, at)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return c, ok
	}
	for i := 0; i < 3; i++ {
		c, ok := read(e.A.Tenant, e.A.Endpoint, now)
		if !ok || len(c.Params) == 0 || len(c.ParamsHash) != 2 {
			t.Fatalf("read %d: %q %x %v", i, c.Params, c.ParamsHash, ok)
		}
	}
	if n := e.count(t, `SELECT uses FROM ctrlz.profile_download_tokens WHERE id = $1`, id); n != 0 {
		t.Errorf("reading spent %d uses", n)
	}
	// Past its expiry, another Endpoint's and another tenant's: nothing, as for the consume.
	if _, ok := read(e.A.Tenant, e.A.Endpoint, now.Add(2*time.Hour)); ok {
		t.Error("an expired link was read")
	}
	if _, ok := read(e.A.Tenant, e.B.Endpoint, now); ok {
		t.Error("a link was read through another Endpoint")
	}
	if _, ok := read(e.B.Tenant, e.B.Endpoint, now); ok {
		t.Error("tenant B read A's link")
	}
	// Used up: nothing.
	e.exec(t, `UPDATE ctrlz.profile_download_tokens SET uses = max_uses WHERE id = $1`, id)
	if _, ok := read(e.A.Tenant, e.A.Endpoint, now); ok {
		t.Error("a used-up link was read")
	}
}

// ShareLinkList (p3-D4-r2-5) puts the live links first, so that the at most ten of an Endpoint are in the page of 100 however many
// used-up rows are newer, and another Endpoint's and another tenant's rows are not in it.
func TestShareLinkListKeepsLiveLinksInThePage(t *testing.T) {
	e := newRaceEnv(t)
	now := time.Now().UTC()
	// One live link, older than 150 used-up ones.
	var live uuid.UUID
	if err := e.super.QueryRow(e.ctx, `INSERT INTO ctrlz.setup_share_tokens (tenant_id, endpoint_id, token_hash, expires_at, created_at)
		VALUES ($1, $2, '\x7f01', now() + interval '1 day', now() - interval '3 hours') RETURNING id`, e.A.Tenant, e.A.Endpoint).Scan(&live); err != nil {
		t.Fatal(err)
	}
	e.exec(t, `INSERT INTO ctrlz.setup_share_tokens (tenant_id, endpoint_id, token_hash, expires_at, uses, created_at)
		SELECT $1, $2, convert_to('spent-' || g, 'UTF8'), now() + interval '1 day', 10, now() - interval '2 hours' + g * interval '1 second'
		FROM generate_series(1, 150) g`, e.A.Tenant, e.A.Endpoint)
	// B has its own, which is nobody else's.
	e.exec(t, `INSERT INTO ctrlz.setup_share_tokens (tenant_id, endpoint_id, token_hash, expires_at) VALUES ($1, $2, '\x7f02', now() + interval '1 day')`, e.B.Tenant, e.B.Endpoint)
	list := func(tenant, endpoint uuid.UUID) []store.ShareLinkRow {
		t.Helper()
		var rows []store.ShareLinkRow
		if err := e.tenant.WithTenant(e.ctx, tenant, store.TxOpts{ReadOnly: true}, func(tx store.Tx) (err error) {
			rows, err = tx.ShareLinkList(endpoint, now)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return rows
	}
	rows := list(e.A.Tenant, e.A.Endpoint)
	if len(rows) != 100 {
		t.Fatalf("%d rows, want the page of 100", len(rows))
	}
	isLive := func(r store.ShareLinkRow) bool { return !r.Revoked && r.Uses < r.MaxUses && r.ExpiresAt.After(now) }
	seenDead, found := false, false
	for i, r := range rows {
		if r.ID == live {
			found = true
			if i >= store.MaxShareLinksPerEndpoint {
				t.Errorf("the live link is at position %d, past the cap of live links", i)
			}
		}
		if !isLive(r) {
			seenDead = true
		} else if seenDead {
			t.Errorf("a live link at position %d follows a link that is not live", i)
		}
	}
	if !found {
		t.Fatal("the live link fell out of the page")
	}
	if got := list(e.B.Tenant, e.A.Endpoint); len(got) != 0 {
		t.Errorf("tenant B listed %d of A's links", len(got))
	}
	for _, r := range list(e.B.Tenant, e.B.Endpoint) {
		if r.ID == live {
			t.Error("B's list holds A's link")
		}
	}
}
