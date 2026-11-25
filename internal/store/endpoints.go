package store

import (
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
)

// This file is the Endpoint side of the write path (docs/specs/p3-endpoints.md 3). The rules of it, all enforced by
// statements and not by callers:
//
//   - A cap is decided by the statement that adds the row (ctrlz.cap_reached), under the lock that serialises its writers:
//     the tenant quota lock for tenant-wide counts, the Endpoint row for per-Endpoint counts. Go never compares a count.
//   - Every transaction that writes Endpoints locks them first, in id order, by EndpointsLock (spec 3.7 step 5). The
//     update, delete and rotate statements of this file assume the row is already ours.
//   - Nothing here reads doh_token_hash (the tenant role has no SELECT on it); the token itself is sealed by the caller.

// QuotaLock takes the tenant's quota advisory lock, the first lock of every transaction that adds rows against a
// tenant-wide count (spec 3.7 step 1). It is the function P2's profile creation takes, so one tenant's creators of
// profiles, Endpoints and groups are ordered by one lock.
func (t Tx) QuotaLock() error {
	var locked bool
	if err := t.tx.QueryRow(t.ctx, qProfileTenantLock).Scan(&locked); err != nil {
		return sanitize(err)
	}
	if !locked {
		return ErrNilTenant
	}
	return nil
}

// ---------------------------------------------------------------------------
// Endpoint types.

// EndpointTypeRow is a row of ctrlz.endpoint_types.
type EndpointTypeRow struct {
	Key, NameFA, NameEN, Icon string
	Position                  int
}

const qEndpointTypes = `SELECT key, name_fa, name_en, position, icon FROM ctrlz.endpoint_types ORDER BY position, key`

// EndpointTypes lists the 30 types in the order of the seed.
func (t Tx) EndpointTypes() ([]EndpointTypeRow, error) {
	rows, err := t.tx.Query(t.ctx, qEndpointTypes)
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []EndpointTypeRow
	for rows.Next() {
		var r EndpointTypeRow
		var pos int32
		if err := rows.Scan(&r.Key, &r.NameFA, &r.NameEN, &pos, &r.Icon); err != nil {
			return nil, sanitize(err)
		}
		r.Position = int(pos)
		out = append(out, r)
	}
	return out, sanitize(rows.Err())
}

const qEndpointTypeKnown = `SELECT 1 FROM ctrlz.endpoint_types WHERE key = $1`

// EndpointTypeKnown says the key is one of the seeded types.
func (t Tx) EndpointTypeKnown(key string) (bool, error) {
	var one int
	err := t.tx.QueryRow(t.ctx, qEndpointTypeKnown, key).Scan(&one)
	return notFound(err)
}

// ---------------------------------------------------------------------------
// Endpoints.

// EndpointRow is an Endpoint as the tenant reads it. The DoH token is not part of it (its ciphertext has its own read) and
// neither is the hash the node compares.
type EndpointRow struct {
	ID                   uuid.UUID
	Name                 string
	Type                 string
	GroupID              uuid.UUID // Nil for none
	Comment              *string
	ResolverID           string
	ProfileID            uuid.UUID
	Profile2ID           uuid.UUID // Nil for none
	AnalyticsLevel       string
	AdminState           string
	AdminHold            bool
	LegacyDNS            bool
	AuthorizeSecureDNS   bool
	AuthorizeDDNS        bool
	ExposeIP             bool
	PreventDeactivation  bool
	RequireAuthorizedIPs bool
	ScheduleTimezone     string
	FirstQueryAt         *time.Time
	LastQueryAt          *time.Time
	CreatedAt            time.Time
	UpdatedAt            time.Time
	// Derived by the statement.
	AppleStale    bool
	HasSchedule   bool
	Clients       int
	AuthorizedIPs int
	ClaimsWaiting int
}

// endpointColumns is the select list of every Endpoint read; e is the alias of ctrlz.endpoints. The three counters are one
// probe each per returned row, which a page of at most 100 rows bounds. apple_profile_stale is T-248: a profile was made and
// the resolver or the pair moved since.
const endpointColumns = `e.id, e.name, e.type, e.group_id, e.comment, e.resolver_id, e.profile_id, e.profile2_id, e.analytics_level,
  e.admin_state, e.admin_hold, e.legacy_dns, e.authorize_secure_dns, e.authorize_ddns, e.expose_ip, e.prevent_deactivation,
  e.require_authorized_ips, e.schedule_timezone, e.first_query_at, e.last_query_at, e.created_at, e.updated_at,
  (e.apple_profile_generated_at IS NOT NULL AND (e.apple_profile_pair_version IS DISTINCT FROM e.pair_version
     OR e.apple_profile_resolver_id IS DISTINCT FROM e.resolver_id)),
  EXISTS (SELECT 1 FROM ctrlz.schedule_windows w WHERE w.tenant_id = e.tenant_id AND w.endpoint_id = e.id),
  (SELECT count(*) FROM ctrlz.clients c WHERE c.tenant_id = e.tenant_id AND c.endpoint_id = e.id),
  (SELECT count(*) FROM ctrlz.authorized_ips a WHERE a.tenant_id = e.tenant_id AND a.endpoint_id = e.id),
  (SELECT count(*) FROM ctrlz.ip_claims q WHERE q.tenant_id = e.tenant_id AND q.endpoint_id = e.id AND q.state IN ('pending_proof', 'grace'))`

func scanEndpoint(r interface{ Scan(...any) error }) (EndpointRow, error) {
	var e EndpointRow
	var group, p2 *uuid.UUID
	var clients, auth, claims int64
	err := r.Scan(&e.ID, &e.Name, &e.Type, &group, &e.Comment, &e.ResolverID, &e.ProfileID, &p2, &e.AnalyticsLevel,
		&e.AdminState, &e.AdminHold, &e.LegacyDNS, &e.AuthorizeSecureDNS, &e.AuthorizeDDNS, &e.ExposeIP, &e.PreventDeactivation,
		&e.RequireAuthorizedIPs, &e.ScheduleTimezone, &e.FirstQueryAt, &e.LastQueryAt, &e.CreatedAt, &e.UpdatedAt,
		&e.AppleStale, &e.HasSchedule, &clients, &auth, &claims)
	if group != nil {
		e.GroupID = *group
	}
	if p2 != nil {
		e.Profile2ID = *p2
	}
	e.Clients, e.AuthorizedIPs, e.ClaimsWaiting = int(clients), int(auth), int(claims)
	return e, err
}

const qEndpointGet = `SELECT ` + endpointColumns + ` FROM ctrlz.endpoints e WHERE e.tenant_id = $1 AND e.id = $2`

// EndpointGet reads one Endpoint of the tenant; found is false for an id that is not the tenant's.
func (t Tx) EndpointGet(id uuid.UUID) (EndpointRow, bool, error) {
	e, err := scanEndpoint(t.tx.QueryRow(t.ctx, qEndpointGet, t.tenant, id))
	ok, err := notFound(err)
	return e, ok, err
}

const qEndpointsGet = `SELECT ` + endpointColumns + ` FROM ctrlz.endpoints e WHERE e.tenant_id = $1 AND e.id = ANY($2::uuid[]) ORDER BY e.id`

// EndpointsGet reads the Endpoints of the tenant that have one of the ids, in id order. An id that is not the tenant's is
// absent from the answer.
func (t Tx) EndpointsGet(ids []uuid.UUID) ([]EndpointRow, error) {
	rows, err := t.tx.Query(t.ctx, qEndpointsGet, t.tenant, ids)
	if err != nil {
		return nil, sanitize(err)
	}
	return collectEndpoints(rows)
}

func collectEndpoints(rows interface {
	Next() bool
	Scan(...any) error
	Err() error
	Close()
}) ([]EndpointRow, error) {
	defer rows.Close()
	var out []EndpointRow
	for rows.Next() {
		e, err := scanEndpoint(rows)
		if err != nil {
			return nil, sanitize(err)
		}
		out = append(out, e)
	}
	return out, sanitize(rows.Err())
}

// EndpointFilter is the filter and the position of an Endpoint list. Zero members do not filter.
type EndpointFilter struct {
	Group  uuid.UUID
	Type   string
	Status string // "pending" or "active"
	Q      string // a case-insensitive substring of the name
	Limit  int
	// ByName orders by the folded name and then the id, and After is read as (Name, ID); otherwise the order is newest
	// first and After is (At, ID).
	ByName    bool
	AfterAt   time.Time
	AfterName string
	AfterID   uuid.UUID
	HasAfter  bool
}

// The two list orders are two statements (the position is a different key), over the same filter. strpos and not LIKE, so a
// % or an _ in the search text means itself.
const endpointFilterSQL = `e.tenant_id = $1
  AND ($2::uuid IS NULL OR e.group_id = $2)
  AND ($3::text = '' OR e.type = $3)
  AND ($4::text = '' OR (CASE WHEN e.first_query_at IS NULL THEN 'pending' ELSE 'active' END) = $4)
  AND ($5::text = '' OR strpos(lower(e.name), lower($5)) > 0)`

const qEndpointListNewest = `SELECT ` + endpointColumns + ` FROM ctrlz.endpoints e WHERE ` + endpointFilterSQL + `
  AND (NOT $6::boolean OR (e.created_at, e.id) < ($7::timestamptz, $8::uuid))
ORDER BY e.created_at DESC, e.id DESC LIMIT $9`

const qEndpointListByName = `SELECT ` + endpointColumns + ` FROM ctrlz.endpoints e WHERE ` + endpointFilterSQL + `
  AND (NOT $6::boolean OR (lower(e.name), e.id) > (lower($7::text), $8::uuid))
ORDER BY lower(e.name), e.id LIMIT $9`

// EndpointList reads one page, f.Limit rows at most (the caller asks for one more than it shows, to know whether a next page
// exists).
func (t Tx) EndpointList(f EndpointFilter) ([]EndpointRow, error) {
	var group *uuid.UUID
	if f.Group != uuid.Nil {
		group = &f.Group
	}
	var (
		rows interface {
			Next() bool
			Scan(...any) error
			Err() error
			Close()
		}
		err error
	)
	if f.ByName {
		rows, err = t.tx.Query(t.ctx, qEndpointListByName, t.tenant, group, f.Type, f.Status, f.Q, f.HasAfter, f.AfterName, f.AfterID, int32(f.Limit))
	} else {
		rows, err = t.tx.Query(t.ctx, qEndpointListNewest, t.tenant, group, f.Type, f.Status, f.Q, f.HasAfter, f.AfterAt, f.AfterID, int32(f.Limit))
	}
	if err != nil {
		return nil, sanitize(err)
	}
	return collectEndpoints(rows)
}

// EndpointFacets is the counters of the list page: Endpoints by type, and by status.
type EndpointFacets struct {
	ByType          map[string]int
	Pending, Active int
}

const qEndpointFacets = `SELECT e.type, count(*), count(*) FILTER (WHERE e.first_query_at IS NULL) FROM ctrlz.endpoints e
WHERE e.tenant_id = $1 GROUP BY e.type`

// EndpointFacets counts the tenant's Endpoints by type and by status, over all of them (a facet that moved with the filter
// would hide the choices the filter excluded).
func (t Tx) EndpointFacets() (EndpointFacets, error) {
	out := EndpointFacets{ByType: map[string]int{}}
	rows, err := t.tx.Query(t.ctx, qEndpointFacets, t.tenant)
	if err != nil {
		return out, sanitize(err)
	}
	defer rows.Close()
	for rows.Next() {
		var k string
		var n, pending int64
		if err := rows.Scan(&k, &n, &pending); err != nil {
			return out, sanitize(err)
		}
		out.ByType[k] = int(n)
		out.Pending += int(pending)
		out.Active += int(n - pending)
	}
	return out, sanitize(rows.Err())
}

// qEndpointsLock is step 5 of the lock order (spec 3.7): the Endpoints a request writes, in id order, by one statement before
// any statement that writes them (a cascade included).
const qEndpointsLock = `SELECT id FROM ctrlz.endpoints WHERE tenant_id = $1 AND id = ANY($2::uuid[])` + keyOrder + lockNoKeyUpdate

// EndpointsLock locks the Endpoints of the tenant that have one of the ids and returns the ids it found, in id order. A
// request names its Endpoints and compares the answer with the names: an id that is missing is another tenant's or gone.
func (t Tx) EndpointsLock(ids []uuid.UUID) ([]uuid.UUID, error) {
	rows, err := t.tx.Query(t.ctx, qEndpointsLock, t.tenant, ids)
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, sanitize(err)
		}
		out = append(out, id)
	}
	return out, sanitize(rows.Err())
}

const qGroupEndpointsLock = `SELECT id FROM ctrlz.endpoints WHERE tenant_id = $1 AND group_id = $2` + keyOrder + lockNoKeyUpdate

// GroupEndpointsLock locks the Endpoints of a group and returns their ids: the delete of a group sets their group_id to NULL
// through the foreign key, so they are locked first, in id order (spec 3.7 step 5).
func (t Tx) GroupEndpointsLock(group uuid.UUID) ([]uuid.UUID, error) {
	rows, err := t.tx.Query(t.ctx, qGroupEndpointsLock, t.tenant, group)
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, sanitize(err)
		}
		out = append(out, id)
	}
	return out, sanitize(rows.Err())
}

// EndpointNew is the values an Endpoint is created with. The id, the resolver id and the sealed token are made by the caller
// (the id is the AAD of the seal).
type EndpointNew struct {
	ID                  uuid.UUID
	Name                string
	ResolverID          string
	TokenCT             []byte
	TokenHash           []byte
	Type                string
	GroupID             uuid.UUID
	Comment             string
	ProfileID           uuid.UUID
	Profile2ID          uuid.UUID
	AnalyticsLevel      string
	LegacyDNS           bool
	AuthorizeSecureDNS  bool
	AuthorizeDDNS       bool
	ExposeIP            bool
	PreventDeactivation bool
	ScheduleTimezone    string
}

// qEndpointsInsert adds the Endpoints of one request (one row per name) unless the tenant would pass max_endpoints with
// them. The count is of the tenant's Endpoints after the write, compared as the last row would see it, inside the
// statement and under the quota lock that EndpointsInsert's caller holds.
const qEndpointsInsert = `WITH lim AS (SELECT * FROM ctrlz_fn.tenant_plan())
INSERT INTO ctrlz.endpoints (tenant_id, id, name, type, group_id, comment, resolver_id, doh_token_ct, doh_token_hash, profile_id, profile2_id,
  analytics_level, legacy_dns, authorize_secure_dns, authorize_ddns, expose_ip, prevent_deactivation, schedule_timezone)
SELECT $1::uuid, x.id, x.name, $5::text, $6::uuid, $7::text, x.rid, x.ct, x.hash, $8::uuid, $9::uuid,
  $10::text, $11::boolean, $12::boolean, $13::boolean, $14::boolean, $15::boolean, $16::text
FROM unnest($2::uuid[], $3::text[], $4::text[], $17::bytea[], $18::bytea[]) AS x(id, name, rid, ct, hash)
WHERE NOT ctrlz.cap_reached((SELECT count(*) FROM ctrlz.endpoints e WHERE e.tenant_id = $1) + $19::int - 1,
    COALESCE((SELECT lim.max_endpoints FROM lim), 0))
ORDER BY x.rid
RETURNING id`

// EndpointsInsert creates one Endpoint per element of rows, which share every value but the id, the name and the token.
// A loss is max_endpoints: nothing was written. A resolver id that already exists is ErrConflict, which the caller answers
// by drawing again (26 characters of 32 symbols: it does not happen). The caller holds QuotaLock.
func (t Tx) EndpointsInsert(rows []EndpointNew) ([]uuid.UUID, Won, error) {
	if len(rows) == 0 {
		return nil, won(true), nil
	}
	ids := make([]uuid.UUID, len(rows))
	names := make([]string, len(rows))
	rids := make([]string, len(rows))
	cts := make([][]byte, len(rows))
	hashes := make([][]byte, len(rows))
	for i, r := range rows {
		ids[i], names[i], rids[i], cts[i], hashes[i] = r.ID, r.Name, r.ResolverID, r.TokenCT, r.TokenHash
	}
	c := rows[0]
	res, err := t.tx.Query(t.ctx, qEndpointsInsert, t.tenant, ids, names, rids, c.Type, nullUUID(c.GroupID), nullIf(c.Comment),
		c.ProfileID, nullUUID(c.Profile2ID), c.AnalyticsLevel, c.LegacyDNS, c.AuthorizeSecureDNS, c.AuthorizeDDNS, c.ExposeIP,
		c.PreventDeactivation, c.ScheduleTimezone, cts, hashes, int32(len(rows)))
	if err != nil {
		return nil, Won{}, sanitize(err)
	}
	defer res.Close()
	var out []uuid.UUID
	for res.Next() {
		var id uuid.UUID
		if err := res.Scan(&id); err != nil {
			return nil, Won{}, sanitize(err)
		}
		out = append(out, id)
	}
	if err := res.Err(); err != nil {
		return nil, Won{}, sanitize(err)
	}
	return out, won(len(out) == len(rows)), nil
}

const qEndpointUpdate = `UPDATE ctrlz.endpoints SET name = $3, type = $4, group_id = $5, comment = $6, profile_id = $7, profile2_id = $8,
  analytics_level = $9, admin_state = $10, legacy_dns = $11, authorize_secure_dns = $12, authorize_ddns = $13, expose_ip = $14,
  prevent_deactivation = $15, require_authorized_ips = $16, schedule_timezone = $17
WHERE tenant_id = $1 AND id = $2`

// EndpointUpdate writes every value an Endpoint's owner may change, from the row the caller read under EndpointsLock and
// changed. Nothing else of the row moves: not the resolver id, the token, the hold and the times the node writes.
func (t Tx) EndpointUpdate(e EndpointRow) error {
	_, err := t.tx.Exec(t.ctx, qEndpointUpdate, t.tenant, e.ID, e.Name, e.Type, nullUUID(e.GroupID), e.Comment, e.ProfileID,
		nullUUID(e.Profile2ID), e.AnalyticsLevel, e.AdminState, e.LegacyDNS, e.AuthorizeSecureDNS, e.AuthorizeDDNS, e.ExposeIP,
		e.PreventDeactivation, e.RequireAuthorizedIPs, e.ScheduleTimezone)
	return sanitize(err)
}

const qEndpointsSetGroup = `UPDATE ctrlz.endpoints SET group_id = $3 WHERE tenant_id = $1
  AND id = ANY (ARRAY(SELECT id FROM ctrlz.endpoints WHERE tenant_id = $1 AND id = ANY($2::uuid[])` + orderedUpdate + `))`

// EndpointsSetGroup moves the Endpoints into a group, or out of every group with the nil id.
func (t Tx) EndpointsSetGroup(ids []uuid.UUID, group uuid.UUID) error {
	_, err := t.tx.Exec(t.ctx, qEndpointsSetGroup, t.tenant, ids, nullUUID(group))
	return sanitize(err)
}

const qEndpointsHeld = `SELECT e.id FROM ctrlz.endpoints e WHERE e.tenant_id = $1 AND e.id = ANY($2::uuid[])
  AND (e.admin_hold OR EXISTS (SELECT 1 FROM ctrlz.ip_claims c WHERE c.tenant_id = e.tenant_id AND c.endpoint_id = e.id AND c.state = 'suspended'))
ORDER BY e.id`

// EndpointsHeld says which of the Endpoints an admin holds or whose claim is suspended: the delete policy of ctrlz.endpoints
// (hold_blocks_delete) hides those rows from a DELETE, so the zero rows it gives are told apart from a missing id here.
func (t Tx) EndpointsHeld(ids []uuid.UUID) ([]uuid.UUID, error) {
	rows, err := t.tx.Query(t.ctx, qEndpointsHeld, t.tenant, ids)
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, sanitize(err)
		}
		out = append(out, id)
	}
	return out, sanitize(rows.Err())
}

const qEndpointsDelete = `DELETE FROM ctrlz.endpoints WHERE tenant_id = $1
  AND id = ANY (ARRAY(SELECT id FROM ctrlz.endpoints WHERE tenant_id = $1 AND id = ANY($2::uuid[])` + orderedDelete + `))
RETURNING id`

// EndpointsDelete deletes the Endpoints and returns the ids that went. An id that was locked and is not returned is held
// (hold_blocks_delete gives no row for it); CZ001 from the cascade is a claim suspended after the policy looked, and is
// ErrConflict. The caller has locked the clients of the Endpoints first (ClientsLockOf, spec 3.6).
func (t Tx) EndpointsDelete(ids []uuid.UUID) ([]uuid.UUID, Won, error) {
	rows, err := t.tx.Query(t.ctx, qEndpointsDelete, t.tenant, ids)
	if err != nil {
		return nil, Won{}, sanitize(err)
	}
	defer rows.Close()
	var out []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, Won{}, sanitize(err)
		}
		out = append(out, id)
	}
	if err := rows.Err(); err != nil {
		return nil, Won{}, sanitize(err)
	}
	return out, won(len(out) == len(ids)), nil
}

const qEndpointRotate = `UPDATE ctrlz.endpoints SET resolver_id = $3, doh_token_ct = $4, doh_token_hash = $5 WHERE tenant_id = $1 AND id = $2`

// EndpointRotate sets a new resolver id and DoH token (spec 8.1). A resolver id that exists is ErrConflict.
func (t Tx) EndpointRotate(id uuid.UUID, resolverID string, tokenCT, tokenHash []byte) error {
	_, err := t.tx.Exec(t.ctx, qEndpointRotate, t.tenant, id, resolverID, tokenCT, tokenHash)
	return sanitize(err)
}

const qShareLinksRevoke = `UPDATE ctrlz.setup_share_tokens SET revoked_at = now() WHERE tenant_id = $1
  AND id = ANY (ARRAY(SELECT id FROM ctrlz.setup_share_tokens WHERE tenant_id = $1 AND endpoint_id = $2 AND revoked_at IS NULL` + orderedUpdate + `))`

// ShareLinksRevoke ends the Endpoint's live share links: they build from current data, so after a rotation they would hand
// out the new values (spec 8.1).
func (t Tx) ShareLinksRevoke(endpoint uuid.UUID) error {
	_, err := t.tx.Exec(t.ctx, qShareLinksRevoke, t.tenant, endpoint)
	return sanitize(err)
}

const qDownloadLinksDelete = `DELETE FROM ctrlz.profile_download_tokens WHERE tenant_id = $1
  AND id = ANY (ARRAY(SELECT id FROM ctrlz.profile_download_tokens WHERE tenant_id = $1 AND endpoint_id = $2` + orderedDelete + `))`

// DownloadLinksDelete removes the Endpoint's download links, for the reason ShareLinksRevoke gives.
func (t Tx) DownloadLinksDelete(endpoint uuid.UUID) error {
	_, err := t.tx.Exec(t.ctx, qDownloadLinksDelete, t.tenant, endpoint)
	return sanitize(err)
}

const qEndpointTokenCT = `SELECT doh_token_ct FROM ctrlz.endpoints WHERE tenant_id = $1 AND id = $2`

// EndpointTokenCT reads the sealed DoH token of an Endpoint. The one route that shows the token opens it from this.
func (t Tx) EndpointTokenCT(id uuid.UUID) ([]byte, bool, error) {
	var ct []byte
	err := t.tx.QueryRow(t.ctx, qEndpointTokenCT, t.tenant, id).Scan(&ct)
	ok, err := notFound(err)
	return ct, ok, err
}

// ---------------------------------------------------------------------------
// Groups.

// GroupRow is an Endpoint group with the number of Endpoints in it.
type GroupRow struct {
	ID            uuid.UUID
	Name          string
	EndpointCount int
}

const qGroupList = `SELECT g.id, g.name, (SELECT count(*) FROM ctrlz.endpoints e WHERE e.tenant_id = g.tenant_id AND e.group_id = g.id)
FROM ctrlz.endpoint_groups g WHERE g.tenant_id = $1 ORDER BY g.id`

// GroupList reads the tenant's groups, oldest first.
func (t Tx) GroupList() ([]GroupRow, error) {
	rows, err := t.tx.Query(t.ctx, qGroupList, t.tenant)
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []GroupRow
	for rows.Next() {
		var g GroupRow
		var n int64
		if err := rows.Scan(&g.ID, &g.Name, &n); err != nil {
			return nil, sanitize(err)
		}
		g.EndpointCount = int(n)
		out = append(out, g)
	}
	return out, sanitize(rows.Err())
}

const qGroupGet = `SELECT g.id, g.name, (SELECT count(*) FROM ctrlz.endpoints e WHERE e.tenant_id = g.tenant_id AND e.group_id = g.id)
FROM ctrlz.endpoint_groups g WHERE g.tenant_id = $1 AND g.id = $2`

// GroupGet reads one group of the tenant.
func (t Tx) GroupGet(id uuid.UUID) (GroupRow, bool, error) {
	var g GroupRow
	var n int64
	err := t.tx.QueryRow(t.ctx, qGroupGet, t.tenant, id).Scan(&g.ID, &g.Name, &n)
	g.EndpointCount = int(n)
	ok, err := notFound(err)
	return g, ok, err
}

// MaxGroupsPerTenant is how many Endpoint groups a tenant holds (D31, spec 3.5). A cap and not an input bound:
// Tx.GroupInsert compares it inside the INSERT, under the tenant quota lock.
const MaxGroupsPerTenant = 100

const qGroupInsert = `INSERT INTO ctrlz.endpoint_groups (tenant_id, name)
SELECT $1::uuid, $2::text
WHERE NOT ctrlz.cap_reached((SELECT count(*) FROM ctrlz.endpoint_groups g WHERE g.tenant_id = $1), $3::int)
RETURNING id`

// GroupInsert adds a group unless the tenant holds MaxGroupsPerTenant. A loss is that cap. The caller holds QuotaLock.
func (t Tx) GroupInsert(name string) (uuid.UUID, Won, error) {
	var id uuid.UUID
	w, err := wonRow(t.tx.QueryRow(t.ctx, qGroupInsert, t.tenant, name, int32(MaxGroupsPerTenant)).Scan(&id))
	if err != nil || !w.Yes() {
		return uuid.Nil, Won{}, err
	}
	return id, w, nil
}

const qGroupRename = `UPDATE ctrlz.endpoint_groups SET name = $3 WHERE tenant_id = $1 AND id = $2 RETURNING id`

// GroupRename renames a group of the tenant; found is false for an id that is not the tenant's. A group name is not
// compiled.
func (t Tx) GroupRename(id uuid.UUID, name string) (bool, error) {
	var got uuid.UUID
	err := t.tx.QueryRow(t.ctx, qGroupRename, t.tenant, id, name).Scan(&got)
	return notFound(err)
}

const qGroupDelete = `DELETE FROM ctrlz.endpoint_groups WHERE tenant_id = $1 AND id = $2 RETURNING id`

// GroupDelete deletes a group of the tenant; its Endpoints lose the group (ON DELETE SET NULL) and the caller has locked
// them first (GroupEndpointsLock). found is false for an id that is not the tenant's.
func (t Tx) GroupDelete(id uuid.UUID) (bool, error) {
	var got uuid.UUID
	err := t.tx.QueryRow(t.ctx, qGroupDelete, t.tenant, id).Scan(&got)
	return notFound(err)
}

const qGroupKnown = `SELECT 1 FROM ctrlz.endpoint_groups WHERE tenant_id = $1 AND id = $2` + lockKeyShare

// GroupKeyShare takes the group row key-shared (the foreign key of an Endpoint insert or update would) and says whether it is
// the tenant's.
func (t Tx) GroupKeyShare(id uuid.UUID) (bool, error) {
	var one int
	err := t.tx.QueryRow(t.ctx, qGroupKnown, t.tenant, id).Scan(&one)
	return notFound(err)
}

// ---------------------------------------------------------------------------
// Profiles, as the Endpoint write path reads them.

const qProfilesKeyShare = `SELECT id FROM ctrlz.profiles WHERE tenant_id = $1 AND id = ANY($2::uuid[])` + keyOrder + lockKeyShare

// ProfilesKeyShare locks the profiles of the tenant that have one of the ids, key-shared and in id order (spec 3.7 step 4),
// and returns the ids found: an id that is missing is another tenant's or gone, and the caller answers 404.
func (t Tx) ProfilesKeyShare(ids []uuid.UUID) ([]uuid.UUID, error) {
	return collectIDs(t.tx.Query(t.ctx, qProfilesKeyShare, t.tenant, ids))
}

const qProfilesShare = `SELECT id FROM ctrlz.profiles WHERE tenant_id = $1 AND id = ANY($2::uuid[]) AND lock_state = 'locked'` + keyOrder + lockShare

// ProfilesShare locks the locked profiles among the ids FOR SHARE, in id order, so that no unlock, relock or guarded write of
// them can come between the verification of a password and the write (spec 3.3).
func (t Tx) ProfilesShare(ids []uuid.UUID) ([]uuid.UUID, error) {
	return collectIDs(t.tx.Query(t.ctx, qProfilesShare, t.tenant, ids))
}

// collectIDs reads the one uuid column of rows that a constant statement of the caller returned (the SQL is built at no run
// time: a statement is passed to Query only where it is written).
func collectIDs(rows pgx.Rows, err error) ([]uuid.UUID, error) {
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, sanitize(err)
		}
		out = append(out, id)
	}
	return out, sanitize(rows.Err())
}

const qProfilesLockedAmong = `SELECT id FROM ctrlz.profiles WHERE tenant_id = $1 AND id = ANY($2::uuid[]) AND lock_state = 'locked' ORDER BY id`

// ProfilesLockedAmong says which of the profiles are locked now.
func (t Tx) ProfilesLockedAmong(ids []uuid.UUID) ([]uuid.UUID, error) {
	return collectIDs(t.tx.Query(t.ctx, qProfilesLockedAmong, t.tenant, ids))
}

const qAnyProfileLocked = `SELECT EXISTS (SELECT 1 FROM ctrlz.profiles WHERE tenant_id = $1 AND lock_state = 'locked')`

// AnyProfileLocked says the tenant has a locked profile. A request of a tenant that has none can need no password, so the
// pre-check that finds out what a request needs is skipped.
func (t Tx) AnyProfileLocked() (bool, error) {
	var any bool
	err := t.tx.QueryRow(t.ctx, qAnyProfileLocked, t.tenant).Scan(&any)
	return any, sanitize(err)
}

// LockHash is the stored hash of one locked profile, a secret.String so that a formatted value never prints it.
type LockHash struct {
	ID   uuid.UUID
	Hash secret.String
}

const qProfileLockHashes = `SELECT id, lock_password_hash FROM ctrlz.profiles WHERE tenant_id = $1 AND id = ANY($2::uuid[]) AND lock_state = 'locked' ORDER BY id`

// ProfileLockHashes reads the hashes of the locked profiles among the ids. The caller keeps them in a secret.String.
func (t Tx) ProfileLockHashes(ids []uuid.UUID) ([]LockHash, error) {
	rows, err := t.tx.Query(t.ctx, qProfileLockHashes, t.tenant, ids)
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []LockHash
	for rows.Next() {
		var h LockHash
		var hash *string
		if err := rows.Scan(&h.ID, &hash); err != nil {
			return nil, sanitize(err)
		}
		if hash != nil {
			h.Hash = secret.New(*hash)
		}
		out = append(out, h)
	}
	return out, sanitize(rows.Err())
}

const qProfileTargetLocations = `SELECT DISTINCT l FROM (
  SELECT r.target_location_id AS l FROM ctrlz.rules r WHERE r.tenant_id = $1 AND r.profile_id = $2
  UNION ALL SELECT f.target_location_id FROM ctrlz.rule_folders f WHERE f.tenant_id = $1 AND f.profile_id = $2
  UNION ALL SELECT s.target_location_id FROM ctrlz.profile_services s WHERE s.tenant_id = $1 AND s.profile_id = $2
  UNION ALL SELECT o.default_target_location_id FROM ctrlz.profile_options o WHERE o.tenant_id = $1 AND o.profile_id = $2
) x WHERE l IS NOT NULL`

// ProfileTargetLocations lists the locations the profile's rules, folders, services and Default Rule redirect to (spec 3.4).
func (t Tx) ProfileTargetLocations(profile uuid.UUID) ([]uuid.UUID, error) {
	rows, err := t.tx.Query(t.ctx, qProfileTargetLocations, t.tenant, profile)
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, sanitize(err)
		}
		out = append(out, id)
	}
	return out, sanitize(rows.Err())
}

// ProfileEndpointRef is an Endpoint that uses a profile in some role.
type ProfileEndpointRef struct {
	Profile uuid.UUID
	ID      uuid.UUID
	Name    string
}

// qProfileEndpointRefs lists, for every profile of the tenant, the Endpoints that use it in any role: the base stack, a
// schedule window or a client, either slot (the same set tenant_profile_counts counts). One pass over the three tables.
const qProfileEndpointRefs = `SELECT DISTINCT u.profile_id, e.id, e.name FROM (
  SELECT tenant_id, id AS endpoint_id, profile_id FROM ctrlz.endpoints WHERE tenant_id = $1
  UNION ALL SELECT tenant_id, id, profile2_id FROM ctrlz.endpoints WHERE tenant_id = $1 AND profile2_id IS NOT NULL
  UNION ALL SELECT tenant_id, endpoint_id, profile_id FROM ctrlz.schedule_windows WHERE tenant_id = $1
  UNION ALL SELECT tenant_id, endpoint_id, profile2_id FROM ctrlz.schedule_windows WHERE tenant_id = $1 AND profile2_id IS NOT NULL
  UNION ALL SELECT tenant_id, endpoint_id, profile_id FROM ctrlz.clients WHERE tenant_id = $1 AND profile_id IS NOT NULL
  UNION ALL SELECT tenant_id, endpoint_id, profile2_id FROM ctrlz.clients WHERE tenant_id = $1 AND profile2_id IS NOT NULL
) u JOIN ctrlz.endpoints e ON e.tenant_id = u.tenant_id AND e.id = u.endpoint_id
ORDER BY u.profile_id, e.name, e.id`

// ProfileEndpointRefs reads the Endpoints of every profile, for the profile list (spec 9.3 Profile.endpoints).
func (t Tx) ProfileEndpointRefs() (map[uuid.UUID][]ProfileEndpointRef, error) {
	rows, err := t.tx.Query(t.ctx, qProfileEndpointRefs, t.tenant)
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	out := map[uuid.UUID][]ProfileEndpointRef{}
	for rows.Next() {
		var r ProfileEndpointRef
		if err := rows.Scan(&r.Profile, &r.ID, &r.Name); err != nil {
			return nil, sanitize(err)
		}
		out[r.Profile] = append(out[r.Profile], r)
	}
	return out, sanitize(rows.Err())
}

const qDNSZone = `SELECT COALESCE(dns_zone, '') FROM ctrlz.domain_settings`

// DNSZone reads domain_settings.dns_zone ("dns.<domain>"), empty while the admin has set no domain (spec 0, finding 12).
func (t Tx) DNSZone() (string, error) {
	var z string
	err := t.tx.QueryRow(t.ctx, qDNSZone).Scan(&z)
	return z, sanitize(err)
}

const qProfilesExist = `SELECT id FROM ctrlz.profiles WHERE tenant_id = $1 AND id = ANY($2::uuid[]) ORDER BY id`

// ProfilesExist says which of the ids are profiles of the tenant, with no lock: a request that names a profile that is not the
// tenant's is refused before anything is charged, whether or not the profile would have mattered.
func (t Tx) ProfilesExist(ids []uuid.UUID) ([]uuid.UUID, error) {
	return collectIDs(t.tx.Query(t.ctx, qProfilesExist, t.tenant, ids))
}
