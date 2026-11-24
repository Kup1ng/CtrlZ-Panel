package store

import (
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Share links and Apple profile download links (docs/specs/p3-endpoints.md 7). Both tables hold only the SHA-256 of the bearer
// value (internal/auth/bearer) and an expiry that is written from the application clock and compared only with an
// application time passed as a parameter (clocks.yaml, P3 2.2 item 12): no statement here reads now() for an expiry.
//
// The rules of this file, all in statements:
//
//   - A cap counts live rows only (not revoked, not used up, not past its expiry), so a revoke or a rotation gives the slot back
//     at once, and is decided by the statement that adds the row, under the Endpoint's row (share links) or the tenant quota lock
//     (download links): Go never compares a count.
//   - A use is taken by one UPDATE that also checks the limit, the expiry and the revocation (7.1), so two requests with the last
//     use cannot both have it.
//   - Every statement of a link names the tenant, and the Endpoint it must belong to, so a value of Endpoint X never reads
//     Endpoint Y.

// MaxShareLinksPerEndpoint is how many live share links one Endpoint holds (D31, spec 3.5). A cap and not an input bound:
// Tx.ShareLinkInsert compares it inside the INSERT, under the Endpoint's row.
const MaxShareLinksPerEndpoint = 10

// MaxDownloadLinksPerTenant is how many live download links a tenant holds that its users made (via_share_id NULL, D31,
// spec 3.5). A link made through a share link is bounded by that link's uses. A cap: Tx.DownloadLinkInsert compares it inside
// the INSERT, under the tenant quota lock.
const MaxDownloadLinksPerTenant = 20

// ---------------------------------------------------------------------------
// Share links.

// ShareLinkNew is a share link to add.
type ShareLinkNew struct {
	ID       uuid.UUID
	Endpoint uuid.UUID
	Client   string // empty for none
	// Hash is the SHA-256 of the value (bearer.Hash).
	Hash    []byte
	Expires time.Time
	// Now is the application time the live count is taken at.
	Now time.Time
}

const qShareLinkInsert = `INSERT INTO ctrlz.setup_share_tokens (tenant_id, id, endpoint_id, client, token_hash, expires_at)
SELECT $1::uuid, $2::uuid, $3::uuid, $4::text, $5::bytea, $6::timestamptz
WHERE NOT ctrlz.cap_reached((SELECT count(*) FROM ctrlz.setup_share_tokens s WHERE s.tenant_id = $1 AND s.endpoint_id = $3
    AND s.revoked_at IS NULL AND s.uses < s.max_uses AND s.expires_at > $7::timestamptz), $8::int)
RETURNING id`

// ShareLinkInsert adds a share link unless the Endpoint holds MaxShareLinksPerEndpoint live ones. A loss is that cap. The
// caller holds the Endpoint's row (EndpointsLock), which orders every writer of its links.
func (t Tx) ShareLinkInsert(n ShareLinkNew) (Won, error) {
	var id uuid.UUID
	w, err := wonRow(t.tx.QueryRow(t.ctx, qShareLinkInsert, t.tenant, n.ID, n.Endpoint, nullIf(n.Client), n.Hash, n.Expires, n.Now,
		int32(MaxShareLinksPerEndpoint)).Scan(&id))
	if err != nil || !w.Yes() {
		return Won{}, err
	}
	return w, nil
}

// ShareLinkRow is a share link as its owner reads it: never the value or its hash.
type ShareLinkRow struct {
	ID        uuid.UUID
	Client    string
	ExpiresAt time.Time
	Uses      int
	MaxUses   int
	Revoked   bool
	CreatedAt time.Time
}

const qShareLinkList = `SELECT id, client, expires_at, uses, max_uses, revoked_at IS NOT NULL, created_at FROM ctrlz.setup_share_tokens
WHERE tenant_id = $1 AND endpoint_id = $2 ORDER BY created_at DESC, id DESC LIMIT 100`

// ShareLinkList reads the share links of an Endpoint, newest first.
func (t Tx) ShareLinkList(endpoint uuid.UUID) ([]ShareLinkRow, error) {
	rows, err := t.tx.Query(t.ctx, qShareLinkList, t.tenant, endpoint)
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []ShareLinkRow
	for rows.Next() {
		var r ShareLinkRow
		var client *string
		var uses, useLimit int32
		if err := rows.Scan(&r.ID, &client, &r.ExpiresAt, &uses, &useLimit, &r.Revoked, &r.CreatedAt); err != nil {
			return nil, sanitize(err)
		}
		if client != nil {
			r.Client = *client
		}
		r.Uses, r.MaxUses = int(uses), int(useLimit)
		out = append(out, r)
	}
	return out, sanitize(rows.Err())
}

const qShareLinkRevoke = `UPDATE ctrlz.setup_share_tokens SET revoked_at = COALESCE(revoked_at, now())
WHERE tenant_id = $1 AND endpoint_id = $2 AND id = $3 RETURNING id`

// ShareLinkRevoke ends a share link of the Endpoint; found is false for an id that is not one of the Endpoint's. A link that is
// already revoked stays revoked at its first time. The caller holds the Endpoint's row.
func (t Tx) ShareLinkRevoke(endpoint, id uuid.UUID) (bool, error) {
	var got uuid.UUID
	err := t.tx.QueryRow(t.ctx, qShareLinkRevoke, t.tenant, endpoint, id).Scan(&got)
	return notFound(err)
}

const qShareLinkDownloadsDelete = `DELETE FROM ctrlz.profile_download_tokens WHERE tenant_id = $1
  AND id = ANY (ARRAY(SELECT id FROM ctrlz.profile_download_tokens WHERE tenant_id = $1 AND via_share_id = $2` + orderedDelete + `))`

// ShareLinkDownloadsDelete removes the download links made through a share link, which a revoke ends with it (7.1). The caller
// holds the Endpoint's row.
func (t Tx) ShareLinkDownloadsDelete(share uuid.UUID) error {
	_, err := t.tx.Exec(t.ctx, qShareLinkDownloadsDelete, t.tenant, share)
	return sanitize(err)
}

// ShareConsumed is what a spent use of a share link says.
type ShareConsumed struct {
	Client    string
	ExpiresAt time.Time
}

const qShareLinkConsume = `UPDATE ctrlz.setup_share_tokens SET uses = uses + 1
WHERE tenant_id = $1 AND id = $2 AND endpoint_id = $3 AND uses < max_uses AND expires_at > $4::timestamptz AND revoked_at IS NULL
RETURNING client, expires_at`

// ShareLinkConsume spends one use of a share link, in one statement that decides the limit, the expiry and the revocation
// against the application time (7.1). A loss is every refusal: used up, expired, revoked, or not the Endpoint's. The caller holds
// the Endpoint's row.
func (t Tx) ShareLinkConsume(id, endpoint uuid.UUID, now time.Time) (ShareConsumed, Won, error) {
	var c ShareConsumed
	var client *string
	w, err := wonRow(t.tx.QueryRow(t.ctx, qShareLinkConsume, t.tenant, id, endpoint, now).Scan(&client, &c.ExpiresAt))
	if err != nil || !w.Yes() {
		return ShareConsumed{}, Won{}, err
	}
	if client != nil {
		c.Client = *client
	}
	return c, w, nil
}

// ---------------------------------------------------------------------------
// Download links.

// DownloadLinkNew is an Apple profile download link to add.
type DownloadLinkNew struct {
	ID       uuid.UUID
	Endpoint uuid.UUID
	// Params is the canonical JSON of the expanded request (appleprofile.Params.Canonical) and ParamsHash its SHA-256.
	Params     []byte
	ParamsHash []byte
	// Hash is the SHA-256 of the value (bearer.Hash).
	Hash    []byte
	Expires time.Time
	// Now is the application time the live count is taken at.
	Now time.Time
	// Via is the share link the link is made through, or the nil id for a link its owner made.
	Via uuid.UUID
}

const qDownloadLinkInsert = `INSERT INTO ctrlz.profile_download_tokens (tenant_id, id, endpoint_id, params, params_hash, token_hash, expires_at)
SELECT $1::uuid, $2::uuid, $3::uuid, $4::jsonb, $5::bytea, $6::bytea, $7::timestamptz
WHERE NOT ctrlz.cap_reached((SELECT count(*) FROM ctrlz.profile_download_tokens d WHERE d.tenant_id = $1 AND d.via_share_id IS NULL
    AND d.uses < d.max_uses AND d.expires_at > $8::timestamptz), $9::int)
RETURNING id`

// DownloadLinkInsert adds a download link its owner made, unless the tenant holds MaxDownloadLinksPerTenant live ones. A loss is
// that cap. The caller holds the tenant quota lock (QuotaLock) and the Endpoint's row.
func (t Tx) DownloadLinkInsert(n DownloadLinkNew) (Won, error) {
	var id uuid.UUID
	w, err := wonRow(t.tx.QueryRow(t.ctx, qDownloadLinkInsert, t.tenant, n.ID, n.Endpoint, string(n.Params), n.ParamsHash, n.Hash, n.Expires,
		n.Now, int32(MaxDownloadLinksPerTenant)).Scan(&id))
	if err != nil || !w.Yes() {
		return Won{}, err
	}
	return w, nil
}

const qDownloadLinkInsertVia = `INSERT INTO ctrlz.profile_download_tokens (tenant_id, id, endpoint_id, params, params_hash, token_hash, expires_at, via_share_id)
VALUES ($1, $2, $3, $4::jsonb, $5, $6, $7, $8)`

// DownloadLinkInsertVia adds a download link made through a share link. It is bounded by that link's uses and not by the
// tenant's cap (7.2), and its row goes with the share link when that is revoked or deleted. The caller has just spent a use of
// the share link and holds the Endpoint's row.
func (t Tx) DownloadLinkInsertVia(n DownloadLinkNew) error {
	_, err := t.tx.Exec(t.ctx, qDownloadLinkInsertVia, t.tenant, n.ID, n.Endpoint, string(n.Params), n.ParamsHash, n.Hash, n.Expires, n.Via)
	return sanitize(err)
}

// DownloadConsumed is what a spent use of a download link says: the stored request and the hash that covers it.
type DownloadConsumed struct {
	Params     []byte
	ParamsHash []byte
}

const qDownloadLinkConsume = `UPDATE ctrlz.profile_download_tokens SET uses = uses + 1
WHERE tenant_id = $1 AND id = $2 AND endpoint_id = $3 AND uses < max_uses AND expires_at > $4::timestamptz
RETURNING params::text, params_hash`

// DownloadLinkConsume spends one use of a download link (7.1, 7.3). A loss is every refusal: used up, expired, or not the
// Endpoint's. The caller holds the Endpoint's row.
func (t Tx) DownloadLinkConsume(id, endpoint uuid.UUID, now time.Time) (DownloadConsumed, Won, error) {
	var c DownloadConsumed
	var params string
	w, err := wonRow(t.tx.QueryRow(t.ctx, qDownloadLinkConsume, t.tenant, id, endpoint, now).Scan(&params, &c.ParamsHash))
	if err != nil || !w.Yes() {
		return DownloadConsumed{}, Won{}, err
	}
	c.Params = []byte(params)
	return c, w, nil
}

const qAppleProfileDownloaded = `UPDATE ctrlz.endpoints SET apple_profile_generated_at = $3::timestamptz, apple_profile_pair_version = pair_version,
  apple_profile_resolver_id = resolver_id WHERE tenant_id = $1 AND id = $2`

// AppleProfileDownloaded records that a profile was built from the Endpoint's current pair and resolver id, so a change of
// either makes the profile stale (T-248). The caller holds the Endpoint's row. Nothing here is compiled, so no outbox row.
func (t Tx) AppleProfileDownloaded(endpoint uuid.UUID, at time.Time) error {
	_, err := t.tx.Exec(t.ctx, qAppleProfileDownloaded, t.tenant, endpoint, at)
	return sanitize(err)
}

// ---------------------------------------------------------------------------
// What the Apple request reads.

const qCommonDomains = `SELECT pattern FROM ctrlz.catalog_common_domains
WHERE version = COALESCE((SELECT max(version) FROM ctrlz.catalog_versions WHERE state = 'current'), 0) ORDER BY pattern LIMIT 201`

// CommonDomains reads the common domains of the current catalog version, or of version 0, the seed's, while none is current
// (7.3). At most 201: the builder refuses a list over 200, and a version that holds more must not cost more than the bound.
func (t Tx) CommonDomains() ([]string, error) {
	rows, err := t.tx.Query(t.ctx, qCommonDomains)
	if err != nil {
		return nil, sanitize(err)
	}
	return collectStrings(rows)
}

const qFolderKnown = `SELECT 1 FROM ctrlz.rule_folders WHERE tenant_id = $1 AND id = $2`

// FolderKnown says the id is a folder of the tenant, whatever profile it is in.
func (t Tx) FolderKnown(id uuid.UUID) (bool, error) {
	var one int
	err := t.tx.QueryRow(t.ctx, qFolderKnown, t.tenant, id).Scan(&one)
	return notFound(err)
}

const qFolderDomains = `SELECT CASE WHEN match_kind = 'subdomains' THEN substr(rule_key, 3) ELSE rule_key END FROM ctrlz.rules
WHERE tenant_id = $1 AND folder_id = $2 AND match_kind IN ('domain', 'subdomains') ORDER BY rule_key LIMIT 1001`

// FolderDomains reads the domains of the folder's domain and subdomains rules, a subdomains rule as its suffix (a device
// excludes a name and what is under it). Other kinds are skipped (7.3). At most 1,001: the builder refuses more than 100.
func (t Tx) FolderDomains(folder uuid.UUID) ([]string, error) {
	rows, err := t.tx.Query(t.ctx, qFolderDomains, t.tenant, folder)
	if err != nil {
		return nil, sanitize(err)
	}
	return collectStrings(rows)
}

// collectStrings reads the one text column of rows that a constant statement of the caller returned.
func collectStrings(rows pgx.Rows) ([]string, error) {
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, sanitize(err)
		}
		out = append(out, s)
	}
	return out, sanitize(rows.Err())
}

// ---------------------------------------------------------------------------
// The sweep (7.1): rows past their expiry or revoked, in batches.

const (
	qSweepShareIDs = `SELECT id FROM ctrlz.setup_share_tokens WHERE tenant_id = $1 AND (expires_at < $3::timestamptz OR revoked_at IS NOT NULL) ORDER BY id LIMIT $2`
	qSweepShare    = `DELETE FROM ctrlz.setup_share_tokens WHERE tenant_id = $1 AND id = $2 AND (expires_at < $3::timestamptz OR revoked_at IS NOT NULL)`
	qSweepDownIDs  = `SELECT id FROM ctrlz.profile_download_tokens WHERE tenant_id = $1 AND expires_at < $3::timestamptz ORDER BY id LIMIT $2`
	qSweepDown     = `DELETE FROM ctrlz.profile_download_tokens WHERE tenant_id = $1 AND id = $2 AND expires_at < $3::timestamptz`
)

// sweepLinks is the body of the two link steps of SweepTenantBatch.
func (t Tx) sweepLinks(share bool, limit int, now time.Time) (int64, error) {
	if share {
		return sweepKeyed(
			func() (pgx.Rows, error) { return t.tx.Query(t.ctx, qSweepShareIDs, t.tenant, int32(limit), now) },
			func(id uuid.UUID) (pgconn.CommandTag, error) { return t.tx.Exec(t.ctx, qSweepShare, t.tenant, id, now) })
	}
	return sweepKeyed(
		func() (pgx.Rows, error) { return t.tx.Query(t.ctx, qSweepDownIDs, t.tenant, int32(limit), now) },
		func(id uuid.UUID) (pgconn.CommandTag, error) { return t.tx.Exec(t.ctx, qSweepDown, t.tenant, id, now) })
}

const qShareLinkGet = `SELECT id, client, expires_at, uses, max_uses, revoked_at IS NOT NULL, created_at FROM ctrlz.setup_share_tokens
WHERE tenant_id = $1 AND endpoint_id = $2 AND id = $3`

// ShareLinkGet reads one share link of the Endpoint.
func (t Tx) ShareLinkGet(endpoint, id uuid.UUID) (ShareLinkRow, bool, error) {
	var r ShareLinkRow
	var client *string
	var uses, useLimit int32
	err := t.tx.QueryRow(t.ctx, qShareLinkGet, t.tenant, endpoint, id).Scan(&r.ID, &client, &r.ExpiresAt, &uses, &useLimit, &r.Revoked, &r.CreatedAt)
	ok, err := notFound(err)
	if client != nil {
		r.Client = *client
	}
	r.Uses, r.MaxUses = int(uses), int(useLimit)
	return r, ok, err
}
