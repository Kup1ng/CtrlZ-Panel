package store

import (
	"context"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// The reads and writes of the three P4 admin jobs (docs/specs/p4-nodes.md 8, package J1): pair_change, domain_change and
// node_revoked. The worker runs them as ctrlz_worker, one tenant per transaction. Each statement is the smallest the job
// needs, and none of them decides anything on a clock in Go: a live zone and a certificate's validity are compared inside
// the statement, against the database's own time.

// ---------------------------------------------------------------------------
// Notices with a key.

const qNoticeOnce = `INSERT INTO ctrlz.notifications (tenant_id, kind, severity, params)
VALUES ($1, $2, $3, jsonb_set($5::jsonb, '{key}', to_jsonb($4::text)))
ON CONFLICT DO NOTHING`

// NoticeOnce writes a notification to the tenant of the transaction unless it already holds one of the same kind and key
// (notifications_kind_key_uq, migration 0101). The worker holds INSERT on notifications and no SELECT, so it cannot look for
// an earlier notice; the unique index does it, and holds against two workers at once. It says whether this call wrote the
// notice. key is a hash the caller made of the state the notice announces, so a run that repeats, or that a newer job
// supersedes half way, tells nobody the same thing twice. params is a JSON object with no secret in it; the key is added.
func (t Tx) NoticeOnce(kind, severity, key string, params []byte) (bool, error) {
	if key == "" {
		return false, ErrConstraint // a notice with no key is not deduplicated: the caller must use NotificationAdd
	}
	if params == nil {
		params = []byte("{}")
	}
	tag, err := t.tx.Exec(t.ctx, qNoticeOnce, t.tenant, kind, severity, key, params)
	if err != nil {
		return false, sanitize(err)
	}
	return tag.RowsAffected() == 1, nil
}

// ---------------------------------------------------------------------------
// pair_change.

// qEndpointsBumpPair raises pair_version of every Endpoint of the tenant. v1 has no Endpoint with a pair of its own, so the
// Endpoints whose effective pair is the global pair are all of them (spec 8). The rows are locked in id order by the one shape
// every multi-row write of the store uses, so a request that holds one Endpoint's row and wants another's meets this write in
// the same order.
const qEndpointsBumpPair = `UPDATE ctrlz.endpoints SET pair_version = pair_version + 1 WHERE tenant_id = $1
  AND id = ANY (ARRAY(SELECT id FROM ctrlz.endpoints WHERE tenant_id = $1` + orderedUpdate + `))`

// EndpointsBumpPairVersion raises pair_version of every Endpoint of the tenant and says how many it raised. The compiler writes
// the record again for each (the version is part of the record), which is what makes a node learn the new pair.
func (t Tx) EndpointsBumpPairVersion() (int, error) {
	tag, err := t.tx.Exec(t.ctx, qEndpointsBumpPair, t.tenant)
	if err != nil {
		return 0, sanitize(err)
	}
	return int(tag.RowsAffected()), nil
}

const qHasServingClaim = `SELECT EXISTS (SELECT 1 FROM ctrlz.ip_claims WHERE tenant_id = $1 AND state IN ('active', 'grace'))`

// HasServingClaim says whether the tenant holds a Plain DNS claim the nodes serve (active, or in its grace): the tenant that
// has to learn a new address by hand, because a router or a device holds the old one.
func (t Tx) HasServingClaim() (bool, error) {
	var yes bool
	if err := t.tx.QueryRow(t.ctx, qHasServingClaim, t.tenant).Scan(&yes); err != nil {
		return false, sanitize(err)
	}
	return yes, nil
}

// PairAddresses are the two advertised DNS addresses of the global pair.
type PairAddresses struct {
	Primary, Fallback netip.Addr
}

const qGlobalPairAddresses = `SELECT host(pn.dns_advertised_ip), host(fn.dns_advertised_ip)
FROM ctrlz.public_settings ps
JOIN ctrlz.node_pairs gp ON gp.id = ps.global_pair_id
JOIN ctrlz.nodes pn ON pn.id = gp.primary_node_id
JOIN ctrlz.nodes fn ON fn.id = gp.fallback_node_id
WHERE pn.dns_advertised_ip IS NOT NULL AND fn.dns_advertised_ip IS NOT NULL`

// GlobalPairAddresses reads the advertised addresses of the global pair as they are now. ok is false while there is no global
// pair or a node of it has no advertised address: there is then nothing a tenant could be told.
func (t Tx) GlobalPairAddresses() (PairAddresses, bool, error) { return readGlobalPair(t.tx, t.ctx) }

// GlobalPairAddresses reads the same outside any tenant: the job records the pair it begins with.
func (g GlobalTx) GlobalPairAddresses() (PairAddresses, bool, error) {
	return readGlobalPair(g.tx, g.ctx)
}

// readGlobalPair is the one read, so what a job records at its start is what each tenant reads.
func readGlobalPair(g *guardTx, ctx context.Context) (a PairAddresses, ok bool, err error) {
	var p, f string
	err = g.QueryRow(ctx, qGlobalPairAddresses).Scan(&p, &f)
	if ok, err = notFound(err); err != nil || !ok {
		return PairAddresses{}, false, err
	}
	if a.Primary, err = netip.ParseAddr(p); err != nil {
		return PairAddresses{}, false, ErrConstraint
	}
	if a.Fallback, err = netip.ParseAddr(f); err != nil {
		return PairAddresses{}, false, ErrConstraint
	}
	return a, true, nil
}

// ---------------------------------------------------------------------------
// domain_change.

// ZoneState is what the domain notice of a tenant announces: the zones the nodes serve now, the zone CA in force and whether
// an uploaded certificate covers the zone (the private-CA reinstall line is only for a zone no upload covers, 4.3).
type ZoneState struct {
	// Zone is dns_zone, empty while no domain is set.
	Zone string
	// Prev is the zone being left, while its transition is still running; empty after.
	Prev string
	// CANotBefore is the start of the active zone CA row, zero while there is none.
	CANotBefore time.Time
	// Wildcards are the SAN lists of the uploaded certificates that are active and not expired.
	Wildcards [][]string
}

const qZoneSettings = `SELECT COALESCE(dns_zone, ''), CASE WHEN transition_until > now() THEN COALESCE(prev_dns_zone, '') ELSE '' END
FROM ctrlz.domain_settings`

const qZoneCA = `SELECT not_before FROM ctrlz.certificates WHERE kind = 'zone_ca' AND state = 'active' ORDER BY not_before DESC, id DESC LIMIT 1`

const qZoneWildcards = `SELECT names FROM ctrlz.certificates WHERE kind = 'wildcard' AND state = 'active' AND not_after > now() ORDER BY id`

// readZoneState is the one read of ZoneState; the tenant's transaction and the global one both call it, so the state a
// job compares at the start and the end of a pass is the state each tenant saw.
func readZoneState(g *guardTx, ctx context.Context) (ZoneState, error) {
	var z ZoneState
	if err := g.QueryRow(ctx, qZoneSettings).Scan(&z.Zone, &z.Prev); err != nil {
		return ZoneState{}, sanitize(err)
	}
	var nb time.Time
	ok, err := notFound(g.QueryRow(ctx, qZoneCA).Scan(&nb))
	if err != nil {
		return ZoneState{}, err
	}
	if ok {
		z.CANotBefore = nb
	}
	rows, err := g.Query(ctx, qZoneWildcards)
	if err != nil {
		return ZoneState{}, sanitize(err)
	}
	defer rows.Close()
	for rows.Next() {
		var names []string
		if err := rows.Scan(&names); err != nil {
			return ZoneState{}, sanitize(err)
		}
		z.Wildcards = append(z.Wildcards, names)
	}
	return z, sanitize(rows.Err())
}

// ZoneState reads the live zones, the zone CA and the uploaded certificates as they are now, inside the tenant's
// transaction.
func (t Tx) ZoneState() (ZoneState, error) { return readZoneState(t.tx, t.ctx) }

// ZoneState reads the same state outside any tenant: a pass of the job compares it at its start and its end.
func (g GlobalTx) ZoneState() (ZoneState, error) { return readZoneState(g.tx, g.ctx) }

// ---------------------------------------------------------------------------
// node_revoked.

const qRevokedEndpoints = `SELECT endpoint_id FROM ctrlz.authorized_ips
  WHERE tenant_id = $1 AND source = 'secure_dns' AND learned_by_node_id = ANY($2::uuid[])
UNION
SELECT endpoint_id FROM ctrlz.clients
  WHERE tenant_id = $1 AND source = 'auto' AND created_by_node_id = ANY($2::uuid[])
ORDER BY 1`

// RevokedNodeEndpoints lists the tenant's Endpoints that hold a row a node of the list reported: an address it learned
// from a secure DNS query or a client row it created. It only names the Endpoints; each one is then read and written in a
// transaction of its own under its lock.
func (t Tx) RevokedNodeEndpoints(nodes []uuid.UUID) ([]uuid.UUID, error) {
	return idRows(t.tx.Query(t.ctx, qRevokedEndpoints, t.tenant, nodes))
}

// The client rows a revoked node made: created by a node of the list from what it saw (source auto), with nothing of the
// tenant's own on them (no profile, alias, group, analytics level, not a custom client) and not seen since the revoke, because
// a client that is seen after it is a real device that came back through another node.
//
// They are deleted one by one with the predicate repeated (sweepKeyed) and not locked first: ctrlz_worker holds S and D on
// clients and no UPDATE column, and Postgres refuses FOR UPDATE without one, so a locking read or the ordered DELETE the tenant
// side uses would fail for every revoke. The repeated predicate does what the lock did: a row the tenant named or a device that
// was seen between the read and the delete is left alone. clients is rank 430 and comes before the Endpoint's row (spec 3.7).
const (
	revokedClientsWhere = `tenant_id = $1 AND endpoint_id = $2
  AND source = 'auto' AND NOT is_custom AND created_by_node_id = ANY($3::uuid[])
  AND profile_id IS NULL AND profile2_id IS NULL AND alias IS NULL AND group_name IS NULL AND analytics_level IS NULL
  AND last_seen_at <= $4::timestamptz`
	qRevokedClientIDs    = `SELECT id FROM ctrlz.clients WHERE ` + revokedClientsWhere + ` ORDER BY id LIMIT $5`
	qRevokedClientDelete = `DELETE FROM ctrlz.clients WHERE ` + revokedClientsWhere + ` AND id = $5`
)

// RevokedClientsDelete deletes, in id order, up to limit client rows of the Endpoint that a revoked node made and the tenant
// never touched, and says how many it deleted. since is the time of the revoke; a row seen after it stays. A row that stays
// no longer matches the read either, so the caller asks again until a call deletes none.
func (t Tx) RevokedClientsDelete(endpoint uuid.UUID, nodes []uuid.UUID, since time.Time, limit int) (int, error) {
	n, err := sweepKeyed(
		func() (pgx.Rows, error) {
			return t.tx.Query(t.ctx, qRevokedClientIDs, t.tenant, endpoint, nodes, since, int32(limit))
		},
		func(id uuid.UUID) (pgconn.CommandTag, error) {
			return t.tx.Exec(t.ctx, qRevokedClientDelete, t.tenant, endpoint, nodes, since, id)
		})
	return int(n), err
}

const qRevokedLearned = `SELECT a.id, a.learned_by_node_id FROM ctrlz.authorized_ips a WHERE a.tenant_id = $1 AND a.endpoint_id = $2
  AND a.source = 'secure_dns' AND a.learned_by_node_id = ANY($3::uuid[]) AND a.id > $4::uuid
ORDER BY a.id LIMIT $5` + lockUpdate

// LearnedRow is an authorized address a node learned, and the node.
type LearnedRow struct {
	ID   uuid.UUID
	Node uuid.UUID
}

// RevokedLearnedLock locks, in id order, up to limit addresses of the Endpoint that a node of the list learned from a secure
// DNS query, with an id above after (the nil id starts at the first). The caller deletes them one at a time with
// AuthorizedDelete, which refuses the last row of an Endpoint that requires authorized addresses; a refused row stays, so the
// caller pages by id and does not read it again.
func (t Tx) RevokedLearnedLock(endpoint uuid.UUID, nodes []uuid.UUID, after uuid.UUID, limit int) ([]LearnedRow, error) {
	rows, err := t.tx.Query(t.ctx, qRevokedLearned, t.tenant, endpoint, nodes, after, int32(limit))
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []LearnedRow
	for rows.Next() {
		var r LearnedRow
		if err := rows.Scan(&r.ID, &r.Node); err != nil {
			return nil, sanitize(err)
		}
		out = append(out, r)
	}
	return out, sanitize(rows.Err())
}

const qPairEpochBefore = `SELECT progress ->> 'pair', progress ->> 'epoch' FROM ctrlz.admin_jobs
WHERE kind = 'pair_change' AND id <> $1 AND created_at < $2::timestamptz AND progress ->> 'epoch' IS NOT NULL
ORDER BY created_at DESC, id DESC LIMIT 1`

// PairEpochBefore reads what the latest earlier pair_change job recorded in its progress: the hash of the address pair it
// announced and the epoch of that pair (the job that first announced it). ok is false when no earlier job recorded one. The
// next job reuses the epoch when the pair is the same, so a repeat tells nobody twice, and starts a new one when it is not,
// so a move back to an earlier pair is told again (the key of a notice holds the epoch).
func (g GlobalTx) PairEpochBefore(job uuid.UUID, created time.Time) (pair, epoch string, ok bool, err error) {
	ok, err = notFound(g.tx.QueryRow(g.ctx, qPairEpochBefore, job, created).Scan(&pair, &epoch))
	return pair, epoch, ok, err
}
