package store

import (
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// The access side of an Endpoint: its Authorized IPs, its DDNS hosts and its Plain DNS claims as the tenant reads them
// (docs/specs/p3-endpoints.md 4, 5). Every writer here assumes the caller holds the Endpoint's row (EndpointsLock, spec 3.7
// step 5), which is what orders the writers of one Endpoint's rows; the tenant-wide count of manual addresses is ordered by
// the quota lock besides.

// MaxDDNSHostsPerEndpoint is how many DDNS hosts one Endpoint holds (D31, spec 3.5). A cap and not an input bound:
// Tx.DDNSHostInsert compares it inside the INSERT, under the Endpoint's row.
const MaxDDNSHostsPerEndpoint = 5

// ---------------------------------------------------------------------------
// Authorized IPs.

// AuthorizedRow is an authorized prefix as the tenant reads it.
type AuthorizedRow struct {
	ID           uuid.UUID
	EndpointID   uuid.UUID
	CIDR         netip.Prefix
	Source       string
	DDNSHostID   uuid.UUID // Nil for a row no host made
	CleanupOptIn bool
	City, ISP    *string
	LastSeenAt   *time.Time
	CreatedAt    time.Time
	// IsCurrent says the prefix contains the address the caller passed (spec 5 rule 1); false when none was passed.
	IsCurrent bool
}

// authorizedColumns is the select list of every read of authorized rows; $4 is the caller's address, or NULL.
const authorizedColumns = `a.id, a.endpoint_id, a.cidr, a.source, a.ddns_host_id, a.cleanup_opt_in, a.city, a.isp, a.last_seen_at, a.created_at,
  COALESCE(a.cidr >>= $4::inet, false)`

func scanAuthorized(r interface{ Scan(...any) error }) (AuthorizedRow, error) {
	var a AuthorizedRow
	var host *uuid.UUID
	err := r.Scan(&a.ID, &a.EndpointID, scanPrefix(&a.CIDR), &a.Source, &host, &a.CleanupOptIn, &a.City, &a.ISP, &a.LastSeenAt, &a.CreatedAt, &a.IsCurrent)
	if host != nil {
		a.DDNSHostID = *host
	}
	return a, err
}

// authorizedRows reads the authorized rows of a query. It takes the rows and not the statement: every statement the store runs is a
// constant at the call that runs it (rule no-dynamic-sql).
func authorizedRows(rows pgx.Rows, err error) ([]AuthorizedRow, error) {
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []AuthorizedRow
	for rows.Next() {
		a, err := scanAuthorized(rows)
		if err != nil {
			return nil, sanitize(err)
		}
		out = append(out, a)
	}
	return out, sanitize(rows.Err())
}

// idRows reads one uuid column of a query, with the same rule.
func idRows(rows pgx.Rows, err error) ([]uuid.UUID, error) {
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

// AuthorizedFilter selects one page of an Endpoint's authorized rows, newest first.
type AuthorizedFilter struct {
	Endpoint uuid.UUID
	// Q is a part of the prefix as text; empty matches all.
	Q string
	// Current is the caller's address, for IsCurrent; invalid for none.
	Current  netip.Addr
	Limit    int
	HasAfter bool
	AfterAt  time.Time
	AfterID  uuid.UUID
}

const qAuthorizedList = `SELECT ` + authorizedColumns + ` FROM ctrlz.authorized_ips a
WHERE a.tenant_id = $1 AND a.endpoint_id = $2 AND ($3::text = '' OR strpos(a.cidr::text, $3::text) > 0)
  AND ($5::timestamptz IS NULL OR (a.created_at, a.id) < ($5::timestamptz, $6::uuid))
ORDER BY a.created_at DESC, a.id DESC LIMIT $7::int`

// AuthorizedList reads one page.
func (t Tx) AuthorizedList(f AuthorizedFilter) ([]AuthorizedRow, error) {
	var at *time.Time
	var after *uuid.UUID
	if f.HasAfter {
		at, after = &f.AfterAt, &f.AfterID
	}
	return authorizedRows(t.tx.Query(t.ctx, qAuthorizedList, t.tenant, f.Endpoint, f.Q, addrArg(f.Current), at, after, int32(f.Limit)))
}

const qAuthorizedByIDs = `SELECT ` + authorizedColumns + ` FROM ctrlz.authorized_ips a
WHERE a.tenant_id = $1 AND a.endpoint_id = $2 AND a.id = ANY($3::uuid[]) ORDER BY a.id`

// AuthorizedByIDs reads the rows of the Endpoint that have one of the ids, in id order. An id that is missing is another
// Endpoint's or tenant's, or gone.
func (t Tx) AuthorizedByIDs(endpoint uuid.UUID, ids []uuid.UUID, current netip.Addr) ([]AuthorizedRow, error) {
	return authorizedRows(t.tx.Query(t.ctx, qAuthorizedByIDs, t.tenant, endpoint, ids, addrArg(current)))
}

const qAuthorizedLock = `SELECT ` + authorizedColumns + ` FROM ctrlz.authorized_ips a
WHERE a.tenant_id = $1 AND a.endpoint_id = $2 AND a.id = ANY($3::uuid[]) ORDER BY a.id` + lockUpdate

// AuthorizedLock is AuthorizedByIDs that also locks the rows, for a request that is about to delete them.
func (t Tx) AuthorizedLock(endpoint uuid.UUID, ids []uuid.UUID, current netip.Addr) ([]AuthorizedRow, error) {
	return authorizedRows(t.tx.Query(t.ctx, qAuthorizedLock, t.tenant, endpoint, ids, addrArg(current)))
}

const qAuthorizedOfHost = `SELECT a.id FROM ctrlz.authorized_ips a
WHERE a.tenant_id = $1 AND a.endpoint_id = $2 AND a.ddns_host_id = $3 ORDER BY a.id`

// AuthorizedOfHost lists the ids of the rows a DDNS host made, in id order.
func (t Tx) AuthorizedOfHost(endpoint, host uuid.UUID) ([]uuid.UUID, error) {
	return idRows(t.tx.Query(t.ctx, qAuthorizedOfHost, t.tenant, endpoint, host))
}

const qAuthorizedExisting = `SELECT (x.i - 1)::int FROM unnest($3::cidr[]) WITH ORDINALITY AS x(c, i)
WHERE EXISTS (SELECT 1 FROM ctrlz.authorized_ips a WHERE a.tenant_id = $1 AND a.endpoint_id = $2 AND a.cidr = x.c) ORDER BY x.i`

// AuthorizedExisting says which of the prefixes the Endpoint already holds, by their index in the argument.
func (t Tx) AuthorizedExisting(endpoint uuid.UUID, cidrs []netip.Prefix) ([]int, error) {
	rows, err := t.tx.Query(t.ctx, qAuthorizedExisting, t.tenant, endpoint, prefixesArg(cidrs))
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []int
	for rows.Next() {
		var i int32
		if err := rows.Scan(&i); err != nil {
			return nil, sanitize(err)
		}
		out = append(out, int(i))
	}
	return out, sanitize(rows.Err())
}

const qAuthorizedContaining = `SELECT a.id FROM ctrlz.authorized_ips a
WHERE a.tenant_id = $1 AND a.endpoint_id = $2 AND a.id = ANY($3::uuid[]) AND a.cidr >>= $4::inet ORDER BY a.id`

// AuthorizedContaining says which of the rows hold the address (spec 5 rule 1: a row that holds the caller's own address is
// not deleted). An invalid address holds none.
func (t Tx) AuthorizedContaining(endpoint uuid.UUID, ids []uuid.UUID, ip netip.Addr) ([]uuid.UUID, error) {
	return idRows(t.tx.Query(t.ctx, qAuthorizedContaining, t.tenant, endpoint, ids, addrArg(ip)))
}

// qAuthorizedInsert adds all the prefixes or none: the WHERE does not depend on the row, so the tenant-wide cap of manual
// rows lets the whole request in or stops it. "After the write" is count + n, so the compare is count + n - 1 against
// ctrlz.cap_reached's "spent >= cap". Learned rows (secure_dns, ddns) are not counted: their writers bound them per
// Endpoint, so a party that knows a resolver_id cannot use up the owner's room (spec 3.5). The caller holds the quota lock
// and the Endpoint's row. ORDER BY puts the rows in the table's one insert order.
const qAuthorizedInsert = `WITH lim AS (SELECT * FROM ctrlz_fn.tenant_plan())
INSERT INTO ctrlz.authorized_ips (tenant_id, endpoint_id, cidr, source)
SELECT $1::uuid, $2::uuid, x.c, 'manual'
FROM unnest($3::cidr[]) AS x(c)
WHERE NOT ctrlz.cap_reached((SELECT count(*) FROM ctrlz.authorized_ips a WHERE a.tenant_id = $1 AND a.source = 'manual') + $4::int - 1,
    COALESCE((SELECT lim.max_authorized_ips FROM lim), 0))
ORDER BY x.c
RETURNING id`

// AuthorizedInsert adds manual prefixes to the Endpoint. A loss is max_authorized_ips and nothing was written. A prefix the
// Endpoint already holds is ErrConflict, which a caller that read AuthorizedExisting under the Endpoint's row never meets.
func (t Tx) AuthorizedInsert(endpoint uuid.UUID, cidrs []netip.Prefix) ([]uuid.UUID, Won, error) {
	if len(cidrs) == 0 {
		return nil, won(true), nil
	}
	ids, err := idRows(t.tx.Query(t.ctx, qAuthorizedInsert, t.tenant, endpoint, prefixesArg(cidrs), int32(len(cidrs))))
	if err != nil {
		return nil, Won{}, err
	}
	return ids, won(len(ids) == len(cidrs)), nil
}

// qAuthorizedDelete is the one statement of the module that deletes from authorized_ips (spec 5, check E6): rule 2, "the last
// row of an Endpoint with require_authorized_ips is not deleted", is decided here for every deleter, the owner's routes, a
// DDNS host delete, the P4 DDNS worker and the P5 cleanup alike. The condition does not depend on the row, so it deletes all
// the rows it was given or none. The caller holds the Endpoint's row, which every writer of the Endpoint's authorized rows
// takes first, so the rows the condition reads cannot move under it.
const qAuthorizedDelete = `DELETE FROM ctrlz.authorized_ips WHERE tenant_id = $1 AND endpoint_id = $2
  AND id = ANY (ARRAY(SELECT id FROM ctrlz.authorized_ips WHERE tenant_id = $1 AND endpoint_id = $2 AND id = ANY($3::uuid[])` + orderedDelete + `))
  AND (NOT (SELECT e.require_authorized_ips FROM ctrlz.endpoints e WHERE e.tenant_id = $1 AND e.id = $2)
    OR EXISTS (SELECT 1 FROM ctrlz.authorized_ips k WHERE k.tenant_id = $1 AND k.endpoint_id = $2 AND NOT (k.id = ANY($3::uuid[]))))
RETURNING id`

// AuthorizedDelete deletes authorized rows of the Endpoint. A loss means the Endpoint requires authorized IPs and the rows
// would have been all it has: nothing was deleted. ids must be distinct and the Endpoint's own (the caller has read them
// with AuthorizedLock); any other id deletes nothing and is a loss.
func (t Tx) AuthorizedDelete(endpoint uuid.UUID, ids []uuid.UUID) (Won, error) {
	if len(ids) == 0 {
		return won(true), nil
	}
	gone, err := idRows(t.tx.Query(t.ctx, qAuthorizedDelete, t.tenant, endpoint, ids))
	if err != nil {
		return Won{}, err
	}
	return won(len(gone) == len(ids)), nil
}

const qAuthorizedOptIn = `UPDATE ctrlz.authorized_ips SET cleanup_opt_in = $4 WHERE tenant_id = $1 AND endpoint_id = $2 AND id = $3`

// AuthorizedSetOptIn sets cleanup_opt_in of one row the caller has found.
func (t Tx) AuthorizedSetOptIn(endpoint, id uuid.UUID, on bool) error {
	_, err := t.tx.Exec(t.ctx, qAuthorizedOptIn, t.tenant, endpoint, id, on)
	return sanitize(err)
}

// ---------------------------------------------------------------------------
// DDNS hosts.

// DDNSHostRow is a DDNS host as the tenant reads it. LastIPs are the addresses as text.
type DDNSHostRow struct {
	ID             uuid.UUID
	Hostname       string
	LastResolvedAt *time.Time
	LastIPs        []string
	LastError      *string
}

const ddnsColumns = `h.id, h.hostname, h.last_resolved_at, ARRAY(SELECT host(x) FROM unnest(h.last_ips) AS x), h.last_error`

func scanDDNS(r interface{ Scan(...any) error }) (DDNSHostRow, error) {
	var h DDNSHostRow
	err := r.Scan(&h.ID, &h.Hostname, &h.LastResolvedAt, &h.LastIPs, &h.LastError)
	return h, err
}

const qDDNSHostList = `SELECT ` + ddnsColumns + ` FROM ctrlz.endpoint_ddns_hosts h
WHERE h.tenant_id = $1 AND h.endpoint_id = $2 ORDER BY h.created_at, h.id`

// DDNSHostList lists the Endpoint's hosts, oldest first.
func (t Tx) DDNSHostList(endpoint uuid.UUID) ([]DDNSHostRow, error) {
	rows, err := t.tx.Query(t.ctx, qDDNSHostList, t.tenant, endpoint)
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []DDNSHostRow
	for rows.Next() {
		h, err := scanDDNS(rows)
		if err != nil {
			return nil, sanitize(err)
		}
		out = append(out, h)
	}
	return out, sanitize(rows.Err())
}

const qDDNSHostGet = `SELECT ` + ddnsColumns + ` FROM ctrlz.endpoint_ddns_hosts h WHERE h.tenant_id = $1 AND h.endpoint_id = $2 AND h.id = $3`

// DDNSHostGet reads one host of the Endpoint.
func (t Tx) DDNSHostGet(endpoint, id uuid.UUID) (DDNSHostRow, bool, error) {
	h, err := scanDDNS(t.tx.QueryRow(t.ctx, qDDNSHostGet, t.tenant, endpoint, id))
	ok, err := notFound(err)
	return h, ok, err
}

const qDDNSHostInsert = `INSERT INTO ctrlz.endpoint_ddns_hosts (tenant_id, endpoint_id, hostname)
SELECT $1::uuid, $2::uuid, $3::text
WHERE NOT ctrlz.cap_reached((SELECT count(*) FROM ctrlz.endpoint_ddns_hosts h WHERE h.tenant_id = $1 AND h.endpoint_id = $2), $4::int)
RETURNING id`

// DDNSHostInsert adds a host unless the Endpoint holds MaxDDNSHostsPerEndpoint. A loss is that cap. A hostname the Endpoint
// already has is ErrConflict. The caller holds the Endpoint's row.
func (t Tx) DDNSHostInsert(endpoint uuid.UUID, hostname string) (uuid.UUID, Won, error) {
	var id uuid.UUID
	w, err := wonRow(t.tx.QueryRow(t.ctx, qDDNSHostInsert, t.tenant, endpoint, hostname, int32(MaxDDNSHostsPerEndpoint)).Scan(&id))
	if err != nil || !w.Yes() {
		return uuid.Nil, Won{}, sanitize(err)
	}
	return id, w, nil
}

const qDDNSHostDelete = `DELETE FROM ctrlz.endpoint_ddns_hosts WHERE tenant_id = $1 AND endpoint_id = $2 AND id = $3 RETURNING id`

// DDNSHostDelete deletes a host after its authorized rows went through AuthorizedDelete: the key from authorized_ips is not a
// cascade and is checked at commit (spec 2.2 item 7), so a row left behind fails the commit.
func (t Tx) DDNSHostDelete(endpoint, id uuid.UUID) (bool, error) {
	var got uuid.UUID
	err := t.tx.QueryRow(t.ctx, qDDNSHostDelete, t.tenant, endpoint, id).Scan(&got)
	return notFound(err)
}

// ---------------------------------------------------------------------------
// Plain DNS claims.

// ChallengeRow is the live proof challenge of a claim, as far as the tenant may read it: never the observed address.
type ChallengeRow struct {
	ID        uuid.UUID
	Label     string
	ExpiresAt time.Time
	Observed  bool
	Protocol  *string
}

// ClaimRow is a claim as the tenant reads it.
type ClaimRow struct {
	ID         uuid.UUID
	EndpointID uuid.UUID
	CIDR       netip.Prefix
	State      string
	Method     *string
	ProvenAt   *time.Time
	GraceUntil *time.Time
	Source     string
	LastSeenAt *time.Time
	// NeedsAdmin says the claim is wider than /32, unproven and not approved: nothing proves it before an admin does.
	NeedsAdmin bool
	Challenge  *ChallengeRow
}

const qClaims = `SELECT c.id, c.endpoint_id, c.cidr, c.state, c.proof_method, c.proven_at, c.grace_until, c.source, c.last_seen_at,
  (masklen(c.cidr) < 32 AND NOT c.approved_by_admin AND c.proven_at IS NULL AND c.state IN ('pending_proof', 'grace', 'active')),
  ch.id, ch.label, ch.expires_at, ch.observed_at IS NOT NULL, ch.observed_protocol
FROM ctrlz.ip_claims c
LEFT JOIN LATERAL (SELECT x.id, x.label, x.expires_at, x.observed_at, x.observed_protocol FROM ctrlz.ip_proof_challenges x
  WHERE x.tenant_id = c.tenant_id AND x.claim_id = c.id AND x.consumed_at IS NULL AND x.expires_at > now()
  ORDER BY x.created_at DESC, x.id DESC LIMIT 1) ch ON true
WHERE c.tenant_id = $1 AND c.endpoint_id = $2 AND c.state <> 'released' AND ($3::uuid IS NULL OR c.id = $3::uuid)
ORDER BY c.created_at DESC, c.id DESC`

func scanClaim(r interface{ Scan(...any) error }) (ClaimRow, error) {
	var c ClaimRow
	var chID *uuid.UUID
	var chLabel *string
	var chExp *time.Time
	var chObs *bool
	var chProto *string
	err := r.Scan(&c.ID, &c.EndpointID, scanPrefix(&c.CIDR), &c.State, &c.Method, &c.ProvenAt, &c.GraceUntil, &c.Source, &c.LastSeenAt,
		&c.NeedsAdmin, &chID, &chLabel, &chExp, &chObs, &chProto)
	if err == nil && chID != nil && chLabel != nil && chExp != nil {
		c.Challenge = &ChallengeRow{ID: *chID, Label: *chLabel, ExpiresAt: *chExp, Observed: chObs != nil && *chObs, Protocol: chProto}
	}
	return c, err
}

// ClaimList lists the Endpoint's claims that are not released, newest first, each with its live challenge.
func (t Tx) ClaimList(endpoint uuid.UUID) ([]ClaimRow, error) {
	rows, err := t.tx.Query(t.ctx, qClaims, t.tenant, endpoint, nil)
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []ClaimRow
	for rows.Next() {
		c, err := scanClaim(rows)
		if err != nil {
			return nil, sanitize(err)
		}
		out = append(out, c)
	}
	return out, sanitize(rows.Err())
}

// ClaimGet reads one claim of the Endpoint that is not released.
func (t Tx) ClaimGet(endpoint, id uuid.UUID) (ClaimRow, bool, error) {
	c, err := scanClaim(t.tx.QueryRow(t.ctx, qClaims, t.tenant, endpoint, id))
	ok, err := notFound(err)
	return c, ok, err
}

const qClaimChallengeRetry = `SELECT COALESCE(GREATEST(1, ceil(extract(epoch FROM (min(x.expires_at) - now())))), 60)::int
FROM ctrlz.ip_proof_challenges x WHERE x.tenant_id = $1 AND x.claim_id = $2 AND x.expires_at > now()`

// ClaimChallengeRetry says in how many seconds the oldest live challenge of the claim ends, which is when a refused open can
// succeed again (the caps of PS 8); 60 when the claim has none and the tenant-wide bound is what refused.
func (t Tx) ClaimChallengeRetry(claim uuid.UUID) (int, error) {
	var n int32
	if err := t.tx.QueryRow(t.ctx, qClaimChallengeRetry, t.tenant, claim).Scan(&n); err != nil {
		return 0, sanitize(err)
	}
	return int(n), nil
}
