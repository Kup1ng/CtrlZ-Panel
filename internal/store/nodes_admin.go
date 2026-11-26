package store

import (
	"encoding/json"
	"net/netip"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/appclock"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// The admin's half of the node tables (p4-nodes 4.2 steps 1 to 5, 9.2): enrolment records, the nodes
// list and the reports of a node. Every method runs in WithGlobal as ctrlz_admin, so its reach is the
// role's grants and nothing more (migration 0100: the admin inserts a node row without status or
// failover columns, and writes an enrolment through three columns of INSERT and five of UPDATE). A node
// is never tenant data, so nothing here is scoped to a tenant.

// NodeEnrollment is one row of node_enrollments as the admin page shows it (4.2 step 4). It carries no
// token hash, no CSR and no certificate: the admin compares the fingerprint and the addresses with the host's
// console and needs nothing else of the record.
type NodeEnrollment struct {
	ID           uuid.UUID
	State        string
	CreatedAt    time.Time
	ExpiresAt    time.Time
	BoundIP      *netip.Addr
	NodeID       *uuid.UUID
	Fingerprint  string // hex SHA-256 of the key, empty before the first Enroll
	DNSBind      *netip.Addr
	DNSAdv       *netip.Addr
	ProxyBind    *netip.Addr
	ProxyAdv     *netip.Addr
	Hostname     string
	OSRelease    string
	NodeVersion  string
	EnrolledAt   *time.Time
	EnrolledFrom *netip.Addr
	ApprovedAt   *time.Time
	RejectedAt   *time.Time
}

const enrollmentColumns = `id, state, created_at, expires_at, bound_ip, node_id, COALESCE(key_fingerprint, ''),
  dns_bind_ip, dns_advertised_ip, proxy_bind_ip, proxy_advertised_ip,
  COALESCE(hostname, ''), COALESCE(os_release, ''), COALESCE(node_version, ''),
  enrolled_at, enrolled_from, approved_at, rejected_at`

func scanEnrollment(row pgx.Row) (NodeEnrollment, error) {
	var e NodeEnrollment
	err := row.Scan(&e.ID, &e.State, &e.CreatedAt, &e.ExpiresAt, scanAddr(&e.BoundIP), &e.NodeID, &e.Fingerprint,
		scanAddr(&e.DNSBind), scanAddr(&e.DNSAdv), scanAddr(&e.ProxyBind), scanAddr(&e.ProxyAdv),
		&e.Hostname, &e.OSRelease, &e.NodeVersion,
		&e.EnrolledAt, scanAddr(&e.EnrolledFrom), &e.ApprovedAt, &e.RejectedAt)
	return e, err
}

const qNodeEnrollmentCreate = `INSERT INTO ctrlz.node_enrollments (token_hash, expires_at, bound_ip)
VALUES ($1, now() + make_interval(secs => $2), $3) RETURNING id, expires_at`

// NodeEnrollmentCreate stores the hash of a new token with its expiry, which the database adds to its own
// clock (the hub compares expires_at with now() as well, so both sides use one clock), and returns the id
// and the expiry it computed. bound is the address the token is bound to, invalid for none.
func (g GlobalTx) NodeEnrollmentCreate(tokenHash []byte, ttl time.Duration, bound netip.Addr) (uuid.UUID, time.Time, error) {
	var id uuid.UUID
	var exp time.Time
	err := g.tx.QueryRow(g.ctx, qNodeEnrollmentCreate, tokenHash, ttl.Seconds(), addrArg(bound)).Scan(&id, &exp)
	return id, exp, sanitize(err)
}

const qNodeEnrollmentsPage = `SELECT ` + enrollmentColumns + ` FROM ctrlz.node_enrollments
WHERE ($1::uuid IS NULL OR id < $1) ORDER BY id DESC LIMIT $2`

// NodeEnrollmentsPage lists enrolment records newest first. before is the last id of the previous page
// (the nil uuid for the first).
func (g GlobalTx) NodeEnrollmentsPage(before uuid.UUID, limit int) ([]NodeEnrollment, error) {
	rows, err := g.tx.Query(g.ctx, qNodeEnrollmentsPage, nilUUID(before), int32(limit))
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []NodeEnrollment
	for rows.Next() {
		e, err := scanEnrollment(rows)
		if err != nil {
			return nil, sanitize(err)
		}
		out = append(out, e)
	}
	return out, sanitize(rows.Err())
}

const qNodeEnrollmentLock = `SELECT ` + enrollmentColumns + `, spki_sha256 FROM ctrlz.node_enrollments WHERE id = $1` + lockUpdate

// NodeEnrollmentLock reads one record and locks its row, so two admins confirming or rejecting it at once
// are ordered. spki is the SHA-256 of the enrolled key (nil before the first Enroll).
func (g GlobalTx) NodeEnrollmentLock(id uuid.UUID) (e NodeEnrollment, spki []byte, found bool, err error) {
	row := g.tx.QueryRow(g.ctx, qNodeEnrollmentLock, id)
	var e2 NodeEnrollment
	err = row.Scan(&e2.ID, &e2.State, &e2.CreatedAt, &e2.ExpiresAt, scanAddr(&e2.BoundIP), &e2.NodeID, &e2.Fingerprint,
		scanAddr(&e2.DNSBind), scanAddr(&e2.DNSAdv), scanAddr(&e2.ProxyBind), scanAddr(&e2.ProxyAdv),
		&e2.Hostname, &e2.OSRelease, &e2.NodeVersion,
		&e2.EnrolledAt, scanAddr(&e2.EnrolledFrom), &e2.ApprovedAt, &e2.RejectedAt, &spki)
	found, err = notFound(err)
	return e2, spki, found, err
}

const qNodeEnrollmentReject = `UPDATE ctrlz.node_enrollments SET state = 'rejected', rejected_at = now() WHERE id = $1`

// NodeEnrollmentReject moves a locked record to rejected (an issued token withdrawn, or a pending record
// the admin did not recognise). The database refuses any other move of state.
func (g GlobalTx) NodeEnrollmentReject(id uuid.UUID) error {
	_, err := g.tx.Exec(g.ctx, qNodeEnrollmentReject, id)
	return sanitize(err)
}

const qNodeEnrollmentApprove = `UPDATE ctrlz.node_enrollments SET state = 'approved', node_id = $2, approved_by = $3, approved_at = now() WHERE id = $1`

// NodeEnrollmentApprove moves a locked pending_approval record to approved and names its node row. The
// trigger node_enrollments_frozen refuses an approved record without a node.
func (g GlobalTx) NodeEnrollmentApprove(id, node, admin uuid.UUID) error {
	_, err := g.tx.Exec(g.ctx, qNodeEnrollmentApprove, id, node, nilUUID(admin))
	return sanitize(err)
}

const qNodeKeyKnown = `SELECT EXISTS (SELECT 1 FROM ctrlz.nodes WHERE spki_sha256 = $1)
  OR EXISTS (SELECT 1 FROM ctrlz.node_spki_retired WHERE spki_sha256 = $1)`

// NodeKeyKnown says whether a key was ever admitted: it is in nodes (any status) or in node_spki_retired
// (a revoked or removed node's key, kept by a trigger so that a key once admitted is never admitted
// again, 4.2 step 4).
func (g GlobalTx) NodeKeyKnown(spki []byte) (bool, error) {
	var known bool
	err := g.tx.QueryRow(g.ctx, qNodeKeyKnown, spki).Scan(&known)
	return known, sanitize(err)
}

const qNodeSlotsTaken = `SELECT slot FROM ctrlz.nodes ORDER BY slot`

// NodeSlotsTaken lists the slots in use. A revoked node keeps its slot until its row is removed.
func (g GlobalTx) NodeSlotsTaken() ([]int, error) {
	rows, err := g.tx.Query(g.ctx, qNodeSlotsTaken)
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []int
	for rows.Next() {
		var s int16
		if err := rows.Scan(&s); err != nil {
			return nil, sanitize(err)
		}
		out = append(out, int(s))
	}
	return out, sanitize(rows.Err())
}

// NewNode is the insert of a confirmed node: it always starts pending (the admin's INSERT grant has no
// status column) and carries the key of its enrolment record.
type NewNode struct {
	Slot      int
	Name      string
	DNSBind   netip.Addr
	DNSAdv    netip.Addr
	ProxyBind netip.Addr // invalid means none
	ProxyAdv  netip.Addr // invalid means none
	SPKI      []byte
}

const qNodeInsert = `INSERT INTO ctrlz.nodes (slot, name, dns_bind_ip, dns_advertised_ip, proxy_bind_ip, proxy_advertised_ip, spki_sha256)
VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`

// NodeInsert inserts the pending row of a confirmed enrolment. A slot or a key taken by a racing
// transaction is a unique violation, which is ErrConflict.
func (g GlobalTx) NodeInsert(n NewNode) (uuid.UUID, error) {
	var id uuid.UUID
	err := g.tx.QueryRow(g.ctx, qNodeInsert, int16(n.Slot), n.Name, addrArg(n.DNSBind), addrArg(n.DNSAdv), addrArg(n.ProxyBind),
		addrArg(n.ProxyAdv), n.SPKI).Scan(&id)
	return id, sanitize(err)
}

// NodeMembership reads the rows a PairTable is built from: every node, every pair and the global pair (the nil
// uuid when none is set). It is the compiler's own read (CompilerNodes, CompilerPairs, CompilerGlobalPair), so the
// node routes and the compiler judge one reading of the rows and cannot disagree on it (P4 6.1).
func (g GlobalTx) NodeMembership() (nodes []MemberNode, pairs []MemberPair, global uuid.UUID, err error) {
	if nodes, err = g.CompilerNodes(); err != nil {
		return nil, nil, uuid.Nil, err
	}
	if pairs, err = g.CompilerPairs(); err != nil {
		return nil, nil, uuid.Nil, err
	}
	if global, err = g.CompilerGlobalPair(); err != nil {
		return nil, nil, uuid.Nil, err
	}
	return nodes, pairs, global, nil
}

// NodeRow is a node as GET /nodes shows it. version_info is the hub's latest Heartbeat summary, handed on
// as the JSON the hub wrote; the route reads the fields it knows and ignores the rest.
type NodeRow struct {
	ID              uuid.UUID
	Slot            int
	Name            string
	Status          string
	ResolveMode     string
	ProxyBlocked    bool
	DNSBind         *netip.Addr
	DNSAdv          *netip.Addr
	ProxyBind       *netip.Addr
	ProxyAdv        *netip.Addr
	SPKIHex         string
	CreatedAt       time.Time
	LastHeartbeatAt *time.Time
	VersionInfo     []byte
	AppliedSeq      int64
	ConfigHead      int64
	DNSWithdrawn    bool
	DNSHold         bool
	DNSLastFailback *time.Time
	DNSFlapUntil    *time.Time
	PairPeer        *uuid.UUID
	PendingRequests int
	// What the hub wrote of the node's return and drain (node_dns_state, 0103, T-542). DrainState is nil when the hub has written no
	// row for the node (it is pending, or the hub has not run since the migration), and then the page says "not reported yet".
	F3Unmet    []string
	F3DueAt    *time.Time
	DrainState *string
	DrainSince *time.Time
}

const nodeColumns = `n.id, n.slot, n.name, n.status, n.resolve_mode, n.proxy_blocked,
  n.dns_bind_ip, n.dns_advertised_ip, n.proxy_bind_ip, n.proxy_advertised_ip,
  COALESCE(encode(n.spki_sha256, 'hex'), ''), n.created_at, n.last_heartbeat_at, n.version_info, n.applied_seq,
  (SELECT COALESCE(max(l.seq), 0) FROM ctrlz.config_log l),
  n.dns_withdrawn, n.dns_hold, n.dns_last_failback_at, n.dns_flap_until,
  (SELECT CASE WHEN p.primary_node_id = n.id THEN p.fallback_node_id ELSE p.primary_node_id END
     FROM ctrlz.node_pairs p WHERE p.primary_node_id = n.id OR p.fallback_node_id = n.id ORDER BY p.id LIMIT 1),
  (SELECT count(*) FROM ctrlz.node_dns_requests r WHERE r.node_id = n.id AND r.state = 'pending'),
  s.f3_unmet, s.f3_due_at, s.drain_state, s.drain_since`

// nodeFrom joins the hub's state of the node; a node the hub has written no row for has NULLs.
const nodeFrom = `ctrlz.nodes n LEFT JOIN ctrlz.node_dns_state s ON s.node_id = n.id`

func scanNode(row pgx.Row) (NodeRow, error) {
	var n NodeRow
	var slot int16
	var pending int64
	err := row.Scan(&n.ID, &slot, &n.Name, &n.Status, &n.ResolveMode, &n.ProxyBlocked,
		scanAddr(&n.DNSBind), scanAddr(&n.DNSAdv), scanAddr(&n.ProxyBind), scanAddr(&n.ProxyAdv),
		&n.SPKIHex, &n.CreatedAt, &n.LastHeartbeatAt, &n.VersionInfo, &n.AppliedSeq, &n.ConfigHead,
		&n.DNSWithdrawn, &n.DNSHold, &n.DNSLastFailback, &n.DNSFlapUntil, &n.PairPeer, &pending,
		&n.F3Unmet, &n.F3DueAt, &n.DrainState, &n.DrainSince)
	n.Slot, n.PendingRequests = int(slot), int(pending)
	n.DrainState = drainShown(n.DrainState, n.DrainSince, appclock.Now())
	return n, err
}

// drainDoneAfter is zone.Inputs().DrainDone (SC 8a.6: a withdrawn node's drain is done 360 s after it began); a test holds the two
// equal, because the store does not import the zone package for one number.
const drainDoneAfter = 360 * time.Second

// drainShown is the drain state the page shows. A row the hub left as "draining" and no hub has seen since (a restart or a change
// of the lease holder in the middle of the drain: the new hub cannot tell a drain from none and leaves the columns alone, GP-r1-1)
// would otherwise show "draining" for good, though "done" is nothing but the time since drain_since. So the read applies the same
// rule the hub does; a hub that has seen the drain writes "done" itself at the same moment, and a row that is "none" or "done"
// is never touched.
func drainShown(state *string, since *time.Time, now time.Time) *string {
	if state == nil || *state != "draining" || since == nil || now.Sub(*since) < drainDoneAfter {
		return state
	}
	done := "done"
	return &done
}

const qNodesPage = `SELECT ` + nodeColumns + ` FROM ` + nodeFrom + ` WHERE ($1::uuid IS NULL OR n.id > $1) ORDER BY n.id LIMIT $2`

// NodesPage lists nodes oldest first (at most four exist, D25; the page is the list's contract all the same).
func (g GlobalTx) NodesPage(after uuid.UUID, limit int) ([]NodeRow, error) {
	rows, err := g.tx.Query(g.ctx, qNodesPage, nilUUID(after), int32(limit))
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []NodeRow
	for rows.Next() {
		n, err := scanNode(rows)
		if err != nil {
			return nil, sanitize(err)
		}
		out = append(out, n)
	}
	return out, sanitize(rows.Err())
}

const qNodeGet = `SELECT ` + nodeColumns + ` FROM ` + nodeFrom + ` WHERE n.id = $1`

// NodeGet reads one node.
func (g GlobalTx) NodeGet(id uuid.UUID) (NodeRow, bool, error) {
	n, err := scanNode(g.tx.QueryRow(g.ctx, qNodeGet, id))
	ok, err := notFound(err)
	return n, ok, err
}

const qNodeExists = `SELECT EXISTS (SELECT 1 FROM ctrlz.nodes WHERE id = $1)`

// NodeExists says whether a node row exists.
func (g GlobalTx) NodeExists(id uuid.UUID) (bool, error) {
	var ok bool
	err := g.tx.QueryRow(g.ctx, qNodeExists, id).Scan(&ok)
	return ok, sanitize(err)
}

const qNodeRemovedAudited = `SELECT EXISTS (SELECT 1 FROM ctrlz.audit_log WHERE action = 'node.remove' AND target = $1)`

// NodeRemovedAudited says whether the audit log records the removal of a node row. The reports of a node outlive its
// row (4.5), and this is how the route tells a removed node from an id that never existed.
func (g GlobalTx) NodeRemovedAudited(id uuid.UUID) (bool, error) {
	var ok bool
	err := g.tx.QueryRow(g.ctx, qNodeRemovedAudited, "node:"+id.String()).Scan(&ok)
	return ok, sanitize(err)
}

// TakenClaim is a claim that was proven on a challenge a node observed (4.5).
type TakenClaim struct {
	TenantID   uuid.UUID
	EndpointID uuid.UUID
	ClaimID    uuid.UUID
	CIDR       netip.Prefix
	ConsumedAt time.Time
}

const qNodeTakenClaims = `SELECT tenant_id, endpoint_id, claim_id, cidr, consumed_at FROM ctrlz_fn.node_taken_claims($1, $2)
WHERE ($4::timestamptz IS NULL OR consumed_at <= $4) ORDER BY consumed_at DESC, claim_id LIMIT $3`

// NodeTakenClaims lists the claims taken on the observations of a node since a Unix time and, when until is not
// nil, no later than it (inclusive, so a page that ends inside one instant is read again from there), newest first,
// up to limit. The definer function is the only door to another tenant's claim rows that the admin has (it returns
// ids and the claimed prefix, nothing of the tenant's profile or log).
func (g GlobalTx) NodeTakenClaims(node uuid.UUID, sinceUnix int64, until *time.Time, limit int) ([]TakenClaim, error) {
	rows, err := g.tx.Query(g.ctx, qNodeTakenClaims, node, sinceUnix, int32(limit), until)
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []TakenClaim
	for rows.Next() {
		var c TakenClaim
		if err := rows.Scan(&c.TenantID, &c.EndpointID, &c.ClaimID, scanPrefix(&c.CIDR), &c.ConsumedAt); err != nil {
			return nil, sanitize(err)
		}
		out = append(out, c)
	}
	return out, sanitize(rows.Err())
}

const qNodeRevokedProgress = `SELECT progress FROM ctrlz.admin_jobs
WHERE kind = 'node_revoked' AND params->'node_ids' @> to_jsonb($1::text) ORDER BY id DESC LIMIT 20`

// NodeRevokedProgress returns the progress documents of the node_revoked jobs that name a node (8, Revoked
// node): the worker records there the learned rows it could not delete. The documents are the worker's
// JSON, returned as it wrote them.
func (g GlobalTx) NodeRevokedProgress(node uuid.UUID) ([]json.RawMessage, error) {
	rows, err := g.tx.Query(g.ctx, qNodeRevokedProgress, node.String())
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []json.RawMessage
	for rows.Next() {
		var p []byte
		if err := rows.Scan(&p); err != nil {
			return nil, sanitize(err)
		}
		out = append(out, json.RawMessage(p))
	}
	return out, sanitize(rows.Err())
}

// AddressGivenUpRow is an audit row that gave node addresses up (a node removed, or an advertised address
// edited), with the old addresses its params record.
type AddressGivenUpRow struct {
	ID     int64
	At     time.Time
	Action string
	Target string
	Params []byte
}

const qAddressesGivenUp = `SELECT id, at, action, COALESCE(target, ''), params FROM ctrlz.audit_log
WHERE action = ANY($1::text[]) ORDER BY id DESC LIMIT $2`

// AddressesGivenUpRows returns the newest audit rows of the given actions. The window of 30 days is the
// caller's: the clock of audit_log.at is the application's, so it is compared in Go, not here.
func (g GlobalTx) AddressesGivenUpRows(actions []string, limit int) ([]AddressGivenUpRow, error) {
	rows, err := g.tx.Query(g.ctx, qAddressesGivenUp, actions, int32(limit))
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []AddressGivenUpRow
	for rows.Next() {
		var r AddressGivenUpRow
		if err := rows.Scan(&r.ID, &r.At, &r.Action, &r.Target, &r.Params); err != nil {
			return nil, sanitize(err)
		}
		out = append(out, r)
	}
	return out, sanitize(rows.Err())
}

const qNodeAddressesHeld = `SELECT dns_advertised_ip, proxy_advertised_ip FROM ctrlz.nodes`

// NodeAddressesHeld lists the advertised addresses the node rows hold now.
func (g GlobalTx) NodeAddressesHeld() ([]netip.Addr, error) {
	rows, err := g.tx.Query(g.ctx, qNodeAddressesHeld)
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []netip.Addr
	for rows.Next() {
		var a [2]*netip.Addr
		if err := rows.Scan(scanAddr(&a[0]), scanAddr(&a[1])); err != nil {
			return nil, sanitize(err)
		}
		for _, p := range a {
			if p != nil {
				out = append(out, p.Unmap())
			}
		}
	}
	return out, sanitize(rows.Err())
}
