package store_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// The race drivers of the share and download links (docs/specs/p3-endpoints.md 3.5, 7.1). Like the drivers beside them, each runs
// more spenders than the limit allows on a barrier against the real database and checks that exactly the limit got through.

func p3LinkDrivers() map[string]func(*testing.T, *raceEnv) {
	return map[string]func(*testing.T, *raceEnv){
		"share_link.create":    driveShareLinkCap,
		"download_link.create": driveDownloadLinkCap,
		"share_link.use":       driveShareLinkUse,
		"download_link.use":    driveDownloadLinkUse,
	}
}

func driveShareLinkCap(t *testing.T, e *raceEnv) {
	now := time.Now().UTC()
	live := `SELECT count(*) FROM ctrlz.setup_share_tokens WHERE tenant_id = $1 AND endpoint_id = $2 AND revoked_at IS NULL AND uses < max_uses AND expires_at > now()`
	have := e.count(t, live, e.A.Tenant, e.A.Endpoint)
	e.exec(t, `INSERT INTO ctrlz.setup_share_tokens (tenant_id, endpoint_id, token_hash, expires_at)
		SELECT $1, $2, convert_to('fill-' || g, 'UTF8'), now() + interval '1 day' FROM generate_series(1, $3::int) g`,
		e.A.Tenant, e.A.Endpoint, store.MaxShareLinksPerEndpoint-3-have)
	// Dead rows do not count: a revoked one, a used-up one and an expired one beside the live ones.
	e.exec(t, `INSERT INTO ctrlz.setup_share_tokens (tenant_id, endpoint_id, token_hash, expires_at, revoked_at) VALUES ($1, $2, '\x7b01', now() + interval '1 day', now())`, e.A.Tenant, e.A.Endpoint)
	e.exec(t, `INSERT INTO ctrlz.setup_share_tokens (tenant_id, endpoint_id, token_hash, expires_at, uses) VALUES ($1, $2, '\x7b02', now() + interval '1 day', 10)`, e.A.Tenant, e.A.Endpoint)
	e.exec(t, `INSERT INTO ctrlz.setup_share_tokens (tenant_id, endpoint_id, token_hash, expires_at) VALUES ($1, $2, '\x7b03', now() - interval '1 hour')`, e.A.Tenant, e.A.Endpoint)
	settle := newBarrier(spenders, 400*time.Millisecond)
	got := wins(t, spenders, func(i int, hold func()) (bool, error) {
		var w store.Won
		err := e.tenant.WithTenant(e.ctx, e.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
			hold()
			if _, err := tx.EndpointsLock([]uuid.UUID{e.A.Endpoint}); err != nil {
				return err
			}
			id, err := uuid.NewV7()
			if err != nil {
				return err
			}
			w, err = tx.ShareLinkInsert(store.ShareLinkNew{ID: id, Endpoint: e.A.Endpoint, Hash: []byte(fmt.Sprintf("race-share-%d", i)), Expires: now.Add(time.Hour), Now: now})
			settle()
			return err
		})
		return w.Yes(), err
	})
	if got != 3 {
		t.Errorf("%d share links were made into 3 free slots", got)
	}
	if n := e.count(t, live, e.A.Tenant, e.A.Endpoint); n != store.MaxShareLinksPerEndpoint {
		t.Errorf("the Endpoint holds %d live share links, want %d", n, store.MaxShareLinksPerEndpoint)
	}
}

func driveDownloadLinkCap(t *testing.T, e *raceEnv) {
	now := time.Now().UTC()
	live := `SELECT count(*) FROM ctrlz.profile_download_tokens WHERE tenant_id = $1 AND via_share_id IS NULL AND uses < max_uses AND expires_at > now()`
	have := e.count(t, live, e.A.Tenant)
	e.exec(t, `INSERT INTO ctrlz.profile_download_tokens (tenant_id, endpoint_id, params, params_hash, token_hash, expires_at)
		SELECT $1, $2, '{}'::jsonb, '\x01', convert_to('fill-' || g, 'UTF8'), now() + interval '1 hour' FROM generate_series(1, $3::int) g`,
		e.A.Tenant, e.A.Endpoint, store.MaxDownloadLinksPerTenant-3-have)
	settle := newBarrier(spenders, 400*time.Millisecond)
	got := wins(t, spenders, func(i int, hold func()) (bool, error) {
		var w store.Won
		err := e.tenant.WithTenant(e.ctx, e.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
			hold()
			if err := tx.QuotaLock(); err != nil {
				return err
			}
			if _, err := tx.EndpointsLock([]uuid.UUID{e.A.Endpoint}); err != nil {
				return err
			}
			id, err := uuid.NewV7()
			if err != nil {
				return err
			}
			w, err = tx.DownloadLinkInsert(store.DownloadLinkNew{ID: id, Endpoint: e.A.Endpoint, Params: []byte(`{}`), ParamsHash: []byte{1},
				Hash: []byte(fmt.Sprintf("race-download-%d", i)), Expires: now.Add(time.Hour), Now: now})
			settle()
			return err
		})
		return w.Yes(), err
	})
	if got != 3 {
		t.Errorf("%d download links were made into 3 free slots", got)
	}
	if n := e.count(t, live, e.A.Tenant); n != store.MaxDownloadLinksPerTenant {
		t.Errorf("the tenant holds %d live download links, want %d", n, store.MaxDownloadLinksPerTenant)
	}
	// The cap is the tenant's own: B holds none of A's.
	if n := e.count(t, live, e.B.Tenant); n >= store.MaxDownloadLinksPerTenant {
		t.Errorf("B holds %d live download links", n)
	}
}

func driveShareLinkUse(t *testing.T, e *raceEnv) {
	now := time.Now().UTC()
	var id uuid.UUID
	if err := e.super.QueryRow(e.ctx, `INSERT INTO ctrlz.setup_share_tokens (tenant_id, endpoint_id, token_hash, expires_at, max_uses) VALUES ($1, $2, '\x7c01', now() + interval '1 day', 3) RETURNING id`,
		e.A.Tenant, e.A.Endpoint).Scan(&id); err != nil {
		t.Fatal(err)
	}
	settle := newBarrier(spenders, 400*time.Millisecond)
	got := wins(t, spenders, func(i int, hold func()) (bool, error) {
		var w store.Won
		err := e.tenant.WithTenant(e.ctx, e.A.Tenant, store.TxOpts{}, func(tx store.Tx) (err error) {
			hold()
			if _, err = tx.EndpointsLock([]uuid.UUID{e.A.Endpoint}); err != nil {
				return err
			}
			_, w, err = tx.ShareLinkConsume(id, e.A.Endpoint, now)
			settle()
			return err
		})
		return w.Yes(), err
	})
	if got != 3 {
		t.Errorf("%d racing opens took one of the 3 uses", got)
	}
	if n := e.count(t, `SELECT uses FROM ctrlz.setup_share_tokens WHERE id = $1`, id); n != 3 {
		t.Errorf("uses = %d, want 3", n)
	}
	// Past its expiry, revoked, another Endpoint's and another tenant's: no use, whatever the id.
	e.exec(t, `UPDATE ctrlz.setup_share_tokens SET uses = 0 WHERE id = $1`, id)
	for name, c := range map[string]struct {
		tenant, endpoint uuid.UUID
		at               time.Time
	}{
		"after its expiry":   {e.A.Tenant, e.A.Endpoint, now.Add(48 * time.Hour)},
		"another Endpoint":   {e.A.Tenant, e.B.Endpoint, now},
		"another tenant":     {e.B.Tenant, e.B.Endpoint, now},
		"another tenant, id": {e.B.Tenant, e.A.Endpoint, now},
	} {
		var w store.Won
		if err := e.tenant.WithTenant(e.ctx, c.tenant, store.TxOpts{}, func(tx store.Tx) (err error) {
			_, w, err = tx.ShareLinkConsume(id, c.endpoint, c.at)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if w.Yes() {
			t.Errorf("a use was taken %s", name)
		}
	}
	e.exec(t, `UPDATE ctrlz.setup_share_tokens SET revoked_at = now() WHERE id = $1`, id)
	var w store.Won
	if err := e.tenant.WithTenant(e.ctx, e.A.Tenant, store.TxOpts{}, func(tx store.Tx) (err error) {
		_, w, err = tx.ShareLinkConsume(id, e.A.Endpoint, now)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if w.Yes() {
		t.Error("a use of a revoked link was taken")
	}
}

func driveDownloadLinkUse(t *testing.T, e *raceEnv) {
	now := time.Now().UTC()
	var id uuid.UUID
	if err := e.super.QueryRow(e.ctx, `INSERT INTO ctrlz.profile_download_tokens (tenant_id, endpoint_id, params, params_hash, token_hash, expires_at)
		VALUES ($1, $2, '{"a":1}'::jsonb, '\x0102', '\x7d01', now() + interval '1 hour') RETURNING id`, e.A.Tenant, e.A.Endpoint).Scan(&id); err != nil {
		t.Fatal(err)
	}
	settle := newBarrier(spenders, 400*time.Millisecond)
	got := wins(t, spenders, func(i int, hold func()) (bool, error) {
		var w store.Won
		err := e.tenant.WithTenant(e.ctx, e.A.Tenant, store.TxOpts{}, func(tx store.Tx) (err error) {
			hold()
			if _, err = tx.EndpointsLock([]uuid.UUID{e.A.Endpoint}); err != nil {
				return err
			}
			var c store.DownloadConsumed
			c, w, err = tx.DownloadLinkConsume(id, e.A.Endpoint, now)
			if err == nil && w.Yes() && (len(c.ParamsHash) != 2 || len(c.Params) == 0) {
				err = fmt.Errorf("the stored request did not come back: %q %x", c.Params, c.ParamsHash)
			}
			settle()
			return err
		})
		return w.Yes(), err
	})
	if got != 3 {
		t.Errorf("%d racing downloads took one of the 3 uses", got)
	}
	e.exec(t, `UPDATE ctrlz.profile_download_tokens SET uses = 0 WHERE id = $1`, id)
	var w store.Won
	if err := e.tenant.WithTenant(e.ctx, e.A.Tenant, store.TxOpts{}, func(tx store.Tx) (err error) {
		_, w, err = tx.DownloadLinkConsume(id, e.A.Endpoint, now.Add(time.Hour+time.Minute))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if w.Yes() {
		t.Error("a use of a link past its expiry was taken")
	}
	if err := e.tenant.WithTenant(e.ctx, e.B.Tenant, store.TxOpts{}, func(tx store.Tx) (err error) {
		_, w, err = tx.DownloadLinkConsume(id, e.B.Endpoint, now)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if w.Yes() {
		t.Error("tenant B took a use of A's link")
	}
}
