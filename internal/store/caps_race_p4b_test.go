package store_test

import (
	"bytes"
	"errors"
	"image"
	"image/png"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/assets"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// The race drivers of P4b (docs/specs/p4b-proxy.md 10.5). Like the others, a driver runs more spenders than the limit allows
// on a barrier against the real database and checks that exactly the limit got through.

func p4bDrivers() map[string]func(*testing.T, *raceEnv) {
	return map[string]func(*testing.T, *raceEnv){
		"tenant_asset.create": driveAssetCap,
	}
}

// driveAssetCap races assets.Store, the only writer of tenant_assets, for the last three of the tenant's 20 places. A spender
// that loses gets ErrLimit and commits nothing; the logos are the real thing (a PNG that goes through the decoder and back).
func driveAssetCap(t *testing.T, e *raceEnv) {
	have := e.count(t, `SELECT count(*) FROM ctrlz.tenant_assets WHERE tenant_id = $1`, e.A.Tenant)
	fill := store.MaxAssetsPerTenant - 3 - have
	e.exec(t, `INSERT INTO ctrlz.tenant_assets (tenant_id, kind, sha256, mime, size, bytes)
		SELECT $1, 'logo', decode(repeat('ab', 32), 'hex'), 'image/png', 4, '\x89504e47' FROM generate_series(1, $2::int)`, e.A.Tenant, fill)
	img := image.NewNRGBA(image.Rect(0, 0, 16, 16))
	var logo bytes.Buffer
	if err := png.Encode(&logo, img); err != nil {
		t.Fatal(err)
	}
	settle := newBarrier(spenders, 400*time.Millisecond)
	got := wins(t, spenders, func(i int, hold func()) (bool, error) {
		stored := false
		err := e.tenant.WithTenant(e.ctx, e.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
			hold()
			_, err := assets.Store(tx, logo.Bytes())
			settle()
			switch {
			case err == nil:
				stored = true
			case errors.Is(err, assets.ErrLimit):
				// A loss is a normal answer, not a failure of the transaction.
			default:
				return err
			}
			return nil
		})
		return stored, err
	})
	if got != 3 {
		t.Errorf("%d assets were stored into 3 free places", got)
	}
	if n := e.count(t, `SELECT count(*) FROM ctrlz.tenant_assets WHERE tenant_id = $1`, e.A.Tenant); n != store.MaxAssetsPerTenant {
		t.Errorf("the tenant holds %d assets, want %d", n, store.MaxAssetsPerTenant)
	}
	// What is stored is the PNG the package wrote, with its digest and size, and B's room is its own.
	if n := e.count(t, `SELECT count(*) FROM ctrlz.tenant_assets WHERE tenant_id = $1 AND mime = 'image/png' AND size = octet_length(bytes) AND sha256 = sha256(bytes) AND size > 4`, e.A.Tenant); n != 3 {
		t.Errorf("%d stored rows carry their own digest and size, want 3", n)
	}
	if err := e.tenant.WithTenant(e.ctx, e.B.Tenant, store.TxOpts{}, func(tx store.Tx) error {
		_, err := assets.Store(tx, logo.Bytes())
		return err
	}); err != nil {
		t.Errorf("tenant B is refused with A full: %v", err)
	}
}
