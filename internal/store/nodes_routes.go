package store

import (
	"math"
	"net/netip"
	"time"

	"github.com/google/uuid"
)

// The admin's writes of the node and pair tables (p4-nodes 4.5, 9.2). Every method runs in WithGlobal as
// ctrlz_admin, so its reach is the role's grants: nodes through its column grants (name, resolve_mode,
// proxy_blocked, the two advertised addresses and status, and D), node_pairs S I U D, public_settings U,
// node_dns_requests I of three columns. None of it writes policy_outbox (T-081): a change of membership reaches the
// compiler by the compiler's own comparison of the PairTable (SC 8a.4).

const qNodePairsLock = `SELECT ctrlz_fn.node_pairs_lock()`

// NodePairsLock takes the advisory lock of the pair rule, the one node_pairs_one_peer takes at commit. A route that
// reads the membership, judges the table its change would give and then writes holds it from before its first
// read, so two admins cannot both pass on rows the other is about to change. The constraint triggers take it again
// at commit, which the same transaction may do.
func (g GlobalTx) NodePairsLock() error {
	_, err := g.tx.Exec(g.ctx, qNodePairsLock)
	return sanitize(err)
}

const qNodeUpstreamsLock = `SELECT ctrlz_fn.node_upstreams_lock()`

// NodeUpstreamsLock takes the advisory lock of the upstream loop rule, so that the check of UpstreamLoops and the
// write of an address cannot be interleaved with an upstream that is being added.
func (g GlobalTx) NodeUpstreamsLock() error {
	_, err := g.tx.Exec(g.ctx, qNodeUpstreamsLock)
	return sanitize(err)
}

// NodeForm is the part of a node row the node routes read before they write.
type NodeForm struct {
	ID       uuid.UUID
	Slot     int
	Name     string
	Status   string
	DNSAdv   *netip.Addr
	ProxyAdv *netip.Addr
}

const qNodeFormLock = `SELECT id, slot, name, status, dns_advertised_ip, proxy_advertised_ip FROM ctrlz.nodes WHERE id = $1` + lockNoKeyUpdate

// NodeFormLock reads one node and locks its row, so two admins acting on one node are ordered.
func (g GlobalTx) NodeFormLock(id uuid.UUID) (NodeForm, bool, error) {
	var n NodeForm
	var slot int16
	err := g.tx.QueryRow(g.ctx, qNodeFormLock, id).Scan(&n.ID, &slot, &n.Name, &n.Status, scanAddr(&n.DNSAdv), scanAddr(&n.ProxyAdv))
	n.Slot = int(slot)
	ok, err := notFound(err)
	return n, ok, err
}

const qNodeSetStatus = `UPDATE ctrlz.nodes SET status = $3 WHERE id = $1 AND status = $2`

// NodeSetStatus moves a node from one status to the next. The trigger nodes_revoked_terminal allows only pending to
// active and active to revoked, for any role; false means the row was not in the status the caller read.
func (g GlobalTx) NodeSetStatus(id uuid.UUID, from, to string) (bool, error) {
	tag, err := g.tx.Exec(g.ctx, qNodeSetStatus, id, from, to)
	if err != nil {
		return false, sanitize(err)
	}
	return tag.RowsAffected() == 1, nil
}

const qNodeUpdateForm = `UPDATE ctrlz.nodes SET name = COALESCE($2::text, name), proxy_blocked = COALESCE($3::boolean, proxy_blocked) WHERE id = $1`

// NodeUpdateForm changes the name and proxy_blocked of a node; a nil argument leaves its column as it was.
func (g GlobalTx) NodeUpdateForm(id uuid.UUID, name *string, proxyBlocked *bool) error {
	_, err := g.tx.Exec(g.ctx, qNodeUpdateForm, id, name, proxyBlocked)
	return sanitize(err)
}

const qNodeSetAddresses = `UPDATE ctrlz.nodes SET dns_advertised_ip = $2, proxy_advertised_ip = $3 WHERE id = $1`

// NodeSetAddresses writes the two advertised addresses of a node.
func (g GlobalTx) NodeSetAddresses(id uuid.UUID, dns, proxy netip.Addr) error {
	_, err := g.tx.Exec(g.ctx, qNodeSetAddresses, id, addrArg(dns), addrArg(proxy))
	return sanitize(err)
}

const qNodeDelete = `DELETE FROM ctrlz.nodes WHERE id = $1`

// NodeDelete removes a node row. The foreign keys of node_pairs refuse it for a paired node, and the node's
// certificates, requests and enrolment record go with it by cascade; a trigger keeps its key in node_spki_retired.
func (g GlobalTx) NodeDelete(id uuid.UUID) error {
	_, err := g.tx.Exec(g.ctx, qNodeDelete, id)
	return sanitize(err)
}

const qNodeInPair = `SELECT EXISTS (SELECT 1 FROM ctrlz.node_pairs WHERE primary_node_id = $1 OR fallback_node_id = $1)`

// NodeInPair says whether a node is a member of a row of node_pairs.
func (g GlobalTx) NodeInPair(id uuid.UUID) (bool, error) {
	var in bool
	err := g.tx.QueryRow(g.ctx, qNodeInPair, id).Scan(&in)
	return in, sanitize(err)
}

const qLogTableStep = `SELECT seq, payload FROM ctrlz.config_log WHERE seq < $1 AND seq > $2 ORDER BY seq DESC LIMIT 1`

// LogLastTable walks config_log newest first over the entries above a seq, one row per statement, and returns the
// table the newest entry that carries one holds (found says whether one does: an entry may carry an empty table),
// and the highest seq it saw (above when there is no entry above it).
// Not the newest entry: an entry carries a table only when the membership changed, so a tenant-only entry on top
// would hide the table the log last carried (SC 8a.4 Membership). extract is given by the caller because the store
// does not know what a PairTable is; it must not decode more than it returns.
//
// One row at a time and no cursor, so the walk holds one payload (up to about 15 MiB, p4-nodes 6.1) and stops
// reading at the first table: a query for the whole log would be drained by rows.Close() even after a break. A
// caller that must hold a lock while it reads passes the top of an earlier, unlocked walk as above, and reads
// only what came after it.
func (g GlobalTx) LogLastTable(above int64, extract func(payload []byte) (table []byte, found bool, err error)) (top int64, table []byte, found bool, err error) {
	top = above
	cursor := int64(math.MaxInt64)
	for first := true; ; first = false {
		var seq int64
		var payload []byte
		err := g.tx.QueryRow(g.ctx, qLogTableStep, cursor, above).Scan(&seq, &payload)
		if ok, err2 := notFound(err); err2 != nil {
			return 0, nil, false, err2
		} else if !ok {
			return top, nil, false, nil
		}
		if first {
			top = seq
		}
		t, hit, err := extract(payload)
		if err != nil {
			return 0, nil, false, err
		}
		if hit {
			return top, t, true, nil
		}
		cursor = seq
	}
}

const qLogMinSeq = `SELECT min(seq) FROM ctrlz.config_log`

// LogPruned says whether the log has lost its first entries: the compiler starts at seq 1 and the worker prunes
// from below, so a log whose lowest seq is above 1 has had a table go with them, and one whose lowest is 1 (or
// that is empty) has never lost any.
func (g GlobalTx) LogPruned() (bool, error) {
	var lowest *int64
	if err := g.tx.QueryRow(g.ctx, qLogMinSeq).Scan(&lowest); err != nil {
		return false, sanitize(err)
	}
	return lowest != nil && *lowest > 1, nil
}

const qHubLastTable = `SELECT last_table FROM ctrlz.pair_event_state`

// HubLastTable returns the bytes of the table of the hub's last signing event (pair_event_state.last_table), nil
// before its first event.
func (g GlobalTx) HubLastTable() ([]byte, error) {
	var last []byte
	err := g.tx.QueryRow(g.ctx, qHubLastTable).Scan(&last)
	if ok, err2 := notFound(err); err2 != nil {
		return nil, err2
	} else if !ok {
		return nil, nil
	}
	return last, nil
}

const qUpstreamLoops = `SELECT EXISTS (SELECT 1 FROM ctrlz.node_upstreams u
  WHERE u.bootstrap_ip = $1 OR (u.kind = 'udp' AND ctrlz.upstream_udp_ip(u.address) = $1))`

// UpstreamLoops says whether an upstream of any node names the address as its bootstrap IP or as the IP of a udp
// upstream on any port: the rule of the trigger node_upstreams_no_loop, asked before the write so that the route
// can answer upstream_loop by name.
func (g GlobalTx) UpstreamLoops(a netip.Addr) (bool, error) {
	var loops bool
	err := g.tx.QueryRow(g.ctx, qUpstreamLoops, addrArg(a)).Scan(&loops)
	return loops, sanitize(err)
}

const qNodeDNSRequestInsert = `INSERT INTO ctrlz.node_dns_requests (node_id, kind, requested_by) VALUES ($1, $2, $3) RETURNING id`

// NodeDNSRequestInsert asks the hub for a Hold, Release or Force failback. The database sets requested_at and the
// state, and only the hub writes a decision (SC 8a.4, Requests).
func (g GlobalTx) NodeDNSRequestInsert(node uuid.UUID, kind string, admin uuid.UUID) (uuid.UUID, error) {
	var id uuid.UUID
	err := g.tx.QueryRow(g.ctx, qNodeDNSRequestInsert, node, kind, nilUUID(admin)).Scan(&id)
	return id, sanitize(err)
}

// PairRow is a node_pairs row with whether it is the global pair.
type PairRow struct {
	ID        uuid.UUID
	Primary   uuid.UUID
	Fallback  uuid.UUID
	IsGlobal  bool
	CreatedAt time.Time
}

const pairColumns = `p.id, p.primary_node_id, p.fallback_node_id, COALESCE(p.id = s.global_pair_id, false), p.created_at`

func scanPair(row interface{ Scan(...any) error }) (PairRow, error) {
	var p PairRow
	err := row.Scan(&p.ID, &p.Primary, &p.Fallback, &p.IsGlobal, &p.CreatedAt)
	return p, err
}

const qPairsPage = `SELECT ` + pairColumns + ` FROM ctrlz.node_pairs p CROSS JOIN ctrlz.public_settings s WHERE ($1::uuid IS NULL OR p.id > $1) ORDER BY p.id LIMIT $2`

// PairsPage lists pairs oldest first.
func (g GlobalTx) PairsPage(after uuid.UUID, limit int) ([]PairRow, error) {
	rows, err := g.tx.Query(g.ctx, qPairsPage, nilUUID(after), int32(limit))
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []PairRow
	for rows.Next() {
		p, err := scanPair(rows)
		if err != nil {
			return nil, sanitize(err)
		}
		out = append(out, p)
	}
	return out, sanitize(rows.Err())
}

const qPairGet = `SELECT ` + pairColumns + ` FROM ctrlz.node_pairs p CROSS JOIN ctrlz.public_settings s WHERE p.id = $1`

// PairGet reads one pair.
func (g GlobalTx) PairGet(id uuid.UUID) (PairRow, bool, error) {
	p, err := scanPair(g.tx.QueryRow(g.ctx, qPairGet, id))
	ok, err := notFound(err)
	return p, ok, err
}

const qPairLock = `SELECT id FROM ctrlz.node_pairs WHERE id = $1` + lockNoKeyUpdate

// PairLock locks one pair row and says whether it exists.
func (g GlobalTx) PairLock(id uuid.UUID) (bool, error) {
	var got uuid.UUID
	err := g.tx.QueryRow(g.ctx, qPairLock, id).Scan(&got)
	return notFound(err)
}

const qPairInsert = `INSERT INTO ctrlz.node_pairs (primary_node_id, fallback_node_id) VALUES ($1, $2) RETURNING id`

// PairInsert makes a pair.
func (g GlobalTx) PairInsert(primary, fallback uuid.UUID) (uuid.UUID, error) {
	var id uuid.UUID
	err := g.tx.QueryRow(g.ctx, qPairInsert, primary, fallback).Scan(&id)
	return id, sanitize(err)
}

const qPairUpdate = `UPDATE ctrlz.node_pairs SET primary_node_id = $2, fallback_node_id = $3 WHERE id = $1`

// PairUpdate changes the two members of a pair.
func (g GlobalTx) PairUpdate(id, primary, fallback uuid.UUID) error {
	_, err := g.tx.Exec(g.ctx, qPairUpdate, id, primary, fallback)
	return sanitize(err)
}

const qPairDelete = `DELETE FROM ctrlz.node_pairs WHERE id = $1`

// PairDelete dissolves a pair. The foreign key of public_settings.global_pair_id refuses the global pair.
func (g GlobalTx) PairDelete(id uuid.UUID) error {
	_, err := g.tx.Exec(g.ctx, qPairDelete, id)
	return sanitize(err)
}

const qGlobalPairSet = `UPDATE ctrlz.public_settings SET global_pair_id = $1`

// GlobalPairSet makes a pair the global pair.
func (g GlobalTx) GlobalPairSet(id uuid.UUID) error {
	_, err := g.tx.Exec(g.ctx, qGlobalPairSet, id)
	return sanitize(err)
}

const qAdminJobsSupersedeParams = qAdminJobsSupersede + ` RETURNING params`

// AdminJobsSupersedeParams ends the queued or running job of a kind, as AdminJobsSupersede does, and returns its
// params so the job that replaces it can carry what it had not finished (a node_revoked job names the nodes it is
// for, and the newer one covers the older ones' too). Like AdminJobsSupersede it must be the first statement of the
// transaction that queues the replacement.
func (g GlobalTx) AdminJobsSupersedeParams(kind string) ([][]byte, error) {
	rows, err := g.tx.Query(g.ctx, qAdminJobsSupersedeParams, kind)
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out [][]byte
	for rows.Next() {
		var p []byte
		if err := rows.Scan(&p); err != nil {
			return nil, sanitize(err)
		}
		out = append(out, p)
	}
	return out, sanitize(rows.Err())
}
