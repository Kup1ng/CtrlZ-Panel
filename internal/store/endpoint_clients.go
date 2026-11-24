package store

import (
	"time"

	"github.com/google/uuid"
)

// Schedule windows, clients and the inputs of the stack that applies (docs/specs/p3-endpoints.md 3.2, 3.3, 3.7).

// ---------------------------------------------------------------------------
// Schedule windows.

// WindowRow is one schedule window: minutes [Start, End) of the week in the Endpoint's zone, Sunday 00:00 being 0.
type WindowRow struct {
	ID         uuid.UUID
	EndpointID uuid.UUID
	Start, End int
	ProfileID  uuid.UUID
	Profile2ID uuid.UUID // Nil for none
}

const qWindowsOf = `SELECT id, endpoint_id, lower(minutes), upper(minutes), profile_id, profile2_id FROM ctrlz.schedule_windows
WHERE tenant_id = $1 AND endpoint_id = ANY($2::uuid[]) ORDER BY endpoint_id, lower(minutes)`

// WindowsOf reads the windows of the Endpoints, ordered by Endpoint and then by start (the order of the grid, spec 3.2).
func (t Tx) WindowsOf(endpoints []uuid.UUID) ([]WindowRow, error) {
	rows, err := t.tx.Query(t.ctx, qWindowsOf, t.tenant, endpoints)
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []WindowRow
	for rows.Next() {
		var w WindowRow
		var p2 *uuid.UUID
		var s, e int32
		if err := rows.Scan(&w.ID, &w.EndpointID, &s, &e, &w.ProfileID, &p2); err != nil {
			return nil, sanitize(err)
		}
		w.Start, w.End = int(s), int(e)
		if p2 != nil {
			w.Profile2ID = *p2
		}
		out = append(out, w)
	}
	return out, sanitize(rows.Err())
}

const qWindowsDelete = `DELETE FROM ctrlz.schedule_windows WHERE tenant_id = $1
  AND id = ANY (ARRAY(SELECT id FROM ctrlz.schedule_windows WHERE tenant_id = $1 AND endpoint_id = $2` + orderedDelete + `))`

// WindowsDelete removes every window of the Endpoint. The caller holds the Endpoint's row (EndpointsLock), which orders
// every writer of its windows.
func (t Tx) WindowsDelete(endpoint uuid.UUID) error {
	_, err := t.tx.Exec(t.ctx, qWindowsDelete, t.tenant, endpoint)
	return sanitize(err)
}

const qWindowInsert = `INSERT INTO ctrlz.schedule_windows (tenant_id, id, endpoint_id, minutes, profile_id, profile2_id)
VALUES ($1, $2, $3, int4range($4::int, $5::int, '[)'), $6, $7)`

// WindowInsert adds one window. An overlap is ErrConflict (the exclusion constraint backs the validation of the request); a
// grid violation is ErrConstraint.
func (t Tx) WindowInsert(w WindowRow) error {
	_, err := t.tx.Exec(t.ctx, qWindowInsert, t.tenant, w.ID, w.EndpointID, int32(w.Start), int32(w.End), w.ProfileID, nullUUID(w.Profile2ID))
	return sanitize(err)
}

// ---------------------------------------------------------------------------
// Clients.

// ClientRow is a client of an Endpoint. hostname, mac and ip are written only by the app, later (D8); the API returns them
// and accepts none of them.
type ClientRow struct {
	ID             uuid.UUID
	EndpointID     uuid.UUID
	Label          string
	Alias          *string
	GroupName      *string
	ProfileID      uuid.UUID // Nil for none
	Profile2ID     uuid.UUID // Nil for none
	AnalyticsLevel *string
	Source         string
	IsCustom       bool
	Hostname       *string
	MAC            *string
	IP             *string
	FirstSeenAt    time.Time
	LastSeenAt     time.Time
}

const clientColumns = `c.id, c.endpoint_id, c.label, c.alias, c.group_name, c.profile_id, c.profile2_id, c.analytics_level, c.source,
  c.is_custom, c.hostname, c.mac::text, host(c.ip), c.first_seen_at, c.last_seen_at`

func scanClient(r interface{ Scan(...any) error }) (ClientRow, error) {
	var c ClientRow
	var p, p2 *uuid.UUID
	err := r.Scan(&c.ID, &c.EndpointID, &c.Label, &c.Alias, &c.GroupName, &p, &p2, &c.AnalyticsLevel, &c.Source, &c.IsCustom,
		&c.Hostname, &c.MAC, &c.IP, &c.FirstSeenAt, &c.LastSeenAt)
	if p != nil {
		c.ProfileID = *p
	}
	if p2 != nil {
		c.Profile2ID = *p2
	}
	return c, err
}

func collectClients(rows interface {
	Next() bool
	Scan(...any) error
	Err() error
	Close()
}) ([]ClientRow, error) {
	defer rows.Close()
	var out []ClientRow
	for rows.Next() {
		c, err := scanClient(rows)
		if err != nil {
			return nil, sanitize(err)
		}
		out = append(out, c)
	}
	return out, sanitize(rows.Err())
}

const qClientGet = `SELECT ` + clientColumns + ` FROM ctrlz.clients c WHERE c.tenant_id = $1 AND c.endpoint_id = $2 AND c.id = $3`

// ClientGet reads one client of one Endpoint of the tenant.
func (t Tx) ClientGet(endpoint, id uuid.UUID) (ClientRow, bool, error) {
	c, err := scanClient(t.tx.QueryRow(t.ctx, qClientGet, t.tenant, endpoint, id))
	ok, err := notFound(err)
	return c, ok, err
}

// ClientFilter is the filter and the position of a client list. Zero members do not filter.
type ClientFilter struct {
	Endpoint     uuid.UUID
	Q            string // a case-insensitive substring of the alias, the label or the group
	Group        string // the group name, exactly
	InactiveDays int    // last seen at least this many days before Now
	Now          time.Time
	Limit        int
	AfterAt      time.Time
	AfterID      uuid.UUID
	HasAfter     bool
}

// The predicate of a client list and of its count, one text so the count the UI shows before a bulk delete is the set the
// delete acts on. last_seen_at is compared with the application time handed in, never with now() (the hub writes it, the
// panel only reads it as a record).
const clientFilterSQL = `c.tenant_id = $1 AND c.endpoint_id = $2
  AND ($3::text = '' OR strpos(lower(COALESCE(c.alias, '')), lower($3)) > 0 OR strpos(c.label, lower($3)) > 0
       OR strpos(lower(COALESCE(c.group_name, '')), lower($3)) > 0)
  AND ($4::text = '' OR c.group_name = $4)
  AND ($5::int = 0 OR c.last_seen_at < $6::timestamptz - make_interval(days => $5::int))`

// ClientList reads one page of an Endpoint's clients, newest first by (created_at, id). It returns the creation time of each
// row beside it, which is the position the caller's cursor carries.
func (t Tx) ClientList(f ClientFilter) ([]ClientRow, []time.Time, error) {
	rows, err := t.tx.Query(t.ctx, qClientListWithPos, t.tenant, f.Endpoint, f.Q, f.Group, int32(f.InactiveDays), f.Now, f.HasAfter, f.AfterAt, f.AfterID, int32(f.Limit))
	if err != nil {
		return nil, nil, sanitize(err)
	}
	defer rows.Close()
	var out []ClientRow
	var pos []time.Time
	for rows.Next() {
		var c ClientRow
		var p, p2 *uuid.UUID
		var created time.Time
		if err := rows.Scan(&c.ID, &c.EndpointID, &c.Label, &c.Alias, &c.GroupName, &p, &p2, &c.AnalyticsLevel, &c.Source, &c.IsCustom,
			&c.Hostname, &c.MAC, &c.IP, &c.FirstSeenAt, &c.LastSeenAt, &created); err != nil {
			return nil, nil, sanitize(err)
		}
		if p != nil {
			c.ProfileID = *p
		}
		if p2 != nil {
			c.Profile2ID = *p2
		}
		out = append(out, c)
		pos = append(pos, created)
	}
	return out, pos, sanitize(rows.Err())
}

const qClientListWithPos = `SELECT ` + clientColumns + `, c.created_at FROM ctrlz.clients c WHERE ` + clientFilterSQL + `
  AND (NOT $7::boolean OR (c.created_at, c.id) < ($8::timestamptz, $9::uuid))
ORDER BY c.created_at DESC, c.id DESC LIMIT $10`

const qClientCount = `SELECT count(*) FROM ctrlz.clients c WHERE ` + clientFilterSQL

// ClientCount counts the clients the filter matches (the filter's position members are ignored).
func (t Tx) ClientCount(f ClientFilter) (int, error) {
	var n int64
	err := t.tx.QueryRow(t.ctx, qClientCount, t.tenant, f.Endpoint, f.Q, f.Group, int32(f.InactiveDays), f.Now).Scan(&n)
	return int(n), sanitize(err)
}

// qClientsLock is step 3 of the lock order (spec 3.7): the clients a request writes, in id order, before any profile or
// Endpoint lock. The delete of an Endpoint locks all of them, since the cascade writes them.
const qClientsLockIDs = `SELECT ` + clientColumns + ` FROM ctrlz.clients c WHERE c.tenant_id = $1 AND c.endpoint_id = $2 AND c.id = ANY($3::uuid[])
ORDER BY c.id` + lockUpdate

// ClientsLockIDs locks the named clients of one Endpoint and returns them in id order; a client that is missing is another
// Endpoint's or tenant's, or gone.
func (t Tx) ClientsLockIDs(endpoint uuid.UUID, ids []uuid.UUID) ([]ClientRow, error) {
	rows, err := t.tx.Query(t.ctx, qClientsLockIDs, t.tenant, endpoint, ids)
	if err != nil {
		return nil, sanitize(err)
	}
	return collectClients(rows)
}

// MaxClientsPerSelector is how many clients one selector write resolves: the caller repeats while more remain (spec 9.3).
const MaxClientsPerSelector = 500

const qClientsLockSelector = `SELECT ` + clientColumns + ` FROM ctrlz.clients c WHERE c.tenant_id = $1 AND c.endpoint_id = $2
  AND ($3::int = 0 OR c.last_seen_at < $4::timestamptz - make_interval(days => $3::int))
  AND c.id > $6::uuid
ORDER BY c.id LIMIT $5` + lockUpdate

// ClientsLockSelector locks the clients a selector names: the inactive ones (days > 0) or all of them (days = 0) whose id is
// above after (the nil id starts at the first), at most limit of them, in id order. The caller asks for one more than it
// applies, to learn whether matches remain, and pages with after when it skips rows a change would not alter (an edit that
// finds a client already holding the values makes no progress by selecting it again).
func (t Tx) ClientsLockSelector(endpoint uuid.UUID, inactiveDays int, now time.Time, after uuid.UUID, limit int) ([]ClientRow, error) {
	rows, err := t.tx.Query(t.ctx, qClientsLockSelector, t.tenant, endpoint, int32(inactiveDays), now, int32(limit), after)
	if err != nil {
		return nil, sanitize(err)
	}
	return collectClients(rows)
}

const qClientsLockOf = `SELECT c.id FROM ctrlz.clients c WHERE c.tenant_id = $1 AND c.endpoint_id = ANY($2::uuid[]) ORDER BY c.id` + lockUpdate

// ClientsLockOf locks every client of the Endpoints, in id order: the first statement of an Endpoint delete (spec 3.6, D43),
// since the cascade deletes them and a writer of a client that came in another order would deadlock with it.
func (t Tx) ClientsLockOf(endpoints []uuid.UUID) error {
	rows, err := t.tx.Query(t.ctx, qClientsLockOf, t.tenant, endpoints)
	if err != nil {
		return sanitize(err)
	}
	defer rows.Close()
	for rows.Next() {
	}
	return sanitize(rows.Err())
}

// ClientNew is the values of a manual client.
type ClientNew struct {
	Endpoint       uuid.UUID
	Label          string
	Alias          string
	GroupName      string
	ProfileID      uuid.UUID
	Profile2ID     uuid.UUID
	AnalyticsLevel string
}

// qClientInsert adds a manual client unless the Endpoint holds max_clients_per_endpoint of them. Only manual clients count:
// the hub's are bounded by client_cap at the node, so traffic to client labels cannot use up the owner's room (spec 3.5).
// The caller holds the Endpoint's row, which orders the writers of its count.
const qClientInsert = `WITH lim AS (SELECT * FROM ctrlz_fn.tenant_plan())
INSERT INTO ctrlz.clients (tenant_id, endpoint_id, label, alias, group_name, profile_id, profile2_id, analytics_level, source, is_custom)
SELECT $1::uuid, $2::uuid, $3::text, $4::text, $5::text, $6::uuid, $7::uuid, $8::text, 'manual', true
WHERE NOT ctrlz.cap_reached((SELECT count(*) FROM ctrlz.clients c WHERE c.tenant_id = $1 AND c.endpoint_id = $2 AND c.source = 'manual'),
    COALESCE((SELECT lim.max_clients_per_endpoint FROM lim), 0))
RETURNING id`

// ClientInsert adds a manual (custom) client. A loss is max_clients_per_endpoint. A label that exists on the Endpoint is
// ErrConflict.
func (t Tx) ClientInsert(c ClientNew) (uuid.UUID, Won, error) {
	var id uuid.UUID
	w, err := wonRow(t.tx.QueryRow(t.ctx, qClientInsert, t.tenant, c.Endpoint, c.Label, nullIf(c.Alias), nullIf(c.GroupName),
		nullUUID(c.ProfileID), nullUUID(c.Profile2ID), nullIf(c.AnalyticsLevel)).Scan(&id))
	if err != nil || !w.Yes() {
		return uuid.Nil, Won{}, err
	}
	return id, w, nil
}

const qClientUpdate = `UPDATE ctrlz.clients SET alias = $4, group_name = $5, profile_id = $6, profile2_id = $7, analytics_level = $8
WHERE tenant_id = $1 AND endpoint_id = $2 AND id = $3`

// ClientUpdate writes the members of a client its owner may change (the label, the Endpoint and everything the app writes
// stay as they are).
func (t Tx) ClientUpdate(c ClientRow) error {
	_, err := t.tx.Exec(t.ctx, qClientUpdate, t.tenant, c.EndpointID, c.ID, c.Alias, c.GroupName, nullUUID(c.ProfileID),
		nullUUID(c.Profile2ID), c.AnalyticsLevel)
	return sanitize(err)
}

const qClientsDelete = `DELETE FROM ctrlz.clients WHERE tenant_id = $1 AND endpoint_id = $2
  AND id = ANY (ARRAY(SELECT id FROM ctrlz.clients WHERE tenant_id = $1 AND endpoint_id = $2 AND id = ANY($3::uuid[])` + orderedDelete + `))`

// ClientsDelete deletes clients of one Endpoint, already locked by the caller.
func (t Tx) ClientsDelete(endpoint uuid.UUID, ids []uuid.UUID) error {
	_, err := t.tx.Exec(t.ctx, qClientsDelete, t.tenant, endpoint, ids)
	return sanitize(err)
}

// ---------------------------------------------------------------------------
// The inputs of the stack that applies (spec 3.3).

// StackClient is a client that has a stack of its own.
type StackClient struct {
	Endpoint   uuid.UUID
	Label      string
	ProfileID  uuid.UUID
	Profile2ID uuid.UUID
}

// StackClaim is a claim whose devices a Plain DNS identity stands for.
type StackClaim struct {
	Endpoint uuid.UUID
	ID       uuid.UUID
}

const qStackClients = `SELECT endpoint_id, label, profile_id, profile2_id FROM ctrlz.clients
WHERE tenant_id = $1 AND endpoint_id = ANY($2::uuid[]) AND profile_id IS NOT NULL ORDER BY endpoint_id, label`

// StackClients reads the clients of the Endpoints that have a stack of their own.
func (t Tx) StackClients(endpoints []uuid.UUID) ([]StackClient, error) {
	rows, err := t.tx.Query(t.ctx, qStackClients, t.tenant, endpoints)
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []StackClient
	for rows.Next() {
		var c StackClient
		var p2 *uuid.UUID
		if err := rows.Scan(&c.Endpoint, &c.Label, &c.ProfileID, &p2); err != nil {
			return nil, sanitize(err)
		}
		if p2 != nil {
			c.Profile2ID = *p2
		}
		out = append(out, c)
	}
	return out, sanitize(rows.Err())
}

const qStackClaims = `SELECT endpoint_id, id FROM ctrlz.ip_claims WHERE tenant_id = $1 AND endpoint_id = ANY($2::uuid[])
  AND state IN ('active', 'grace') ORDER BY endpoint_id, id`

// StackClaims reads the active and grace claims of the Endpoints: one Plain DNS identity each while Legacy DNS is on.
func (t Tx) StackClaims(endpoints []uuid.UUID) ([]StackClaim, error) {
	rows, err := t.tx.Query(t.ctx, qStackClaims, t.tenant, endpoints)
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []StackClaim
	for rows.Next() {
		var c StackClaim
		if err := rows.Scan(&c.Endpoint, &c.ID); err != nil {
			return nil, sanitize(err)
		}
		out = append(out, c)
	}
	return out, sanitize(rows.Err())
}
