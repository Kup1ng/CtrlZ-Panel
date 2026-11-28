package store

import "github.com/google/uuid"

// MaxAssetsPerTenant is how many uploaded images (the logos of block pages) a tenant holds (D31, P4b 10.5). A cap and not
// an input bound: Tx.AssetInsert compares it inside the INSERT, under the tenant quota lock, and the trigger
// tenant_assets_limit of migration 0105 counts again for any other writer.
const MaxAssetsPerTenant = 20

const qAssetInsert = `INSERT INTO ctrlz.tenant_assets (tenant_id, kind, sha256, mime, size, bytes)
SELECT $1::uuid, 'logo', $2::bytea, 'image/png', $3::int, $4::bytea
WHERE NOT ctrlz.cap_reached((SELECT count(*) FROM ctrlz.tenant_assets WHERE tenant_id = $1), $5::int)
RETURNING id`

// AssetInsert adds a PNG logo unless the tenant already holds MaxAssetsPerTenant assets. A loss is that cap. The caller
// holds QuotaLock. It is the statement of assets.Store, which is its only caller: the bytes were decoded and written again
// there, so the row never holds an image the tenant sent as it came.
func (t Tx) AssetInsert(sha256, png []byte) (uuid.UUID, Won, error) {
	var id uuid.UUID
	w, err := wonRow(t.tx.QueryRow(t.ctx, qAssetInsert, t.tenant, sha256, int32(len(png)), png, int32(MaxAssetsPerTenant)).Scan(&id))
	if err != nil || !w.Yes() {
		return uuid.Nil, Won{}, err
	}
	return id, w, nil
}
