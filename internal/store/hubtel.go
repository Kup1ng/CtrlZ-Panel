package store

import (
	"context"
	"crypto/sha256"
	"net/netip"
	"sort"
	"time"

	"github.com/google/uuid"
)

// The hub's writes of what nodes report (p4-nodes 5.3, 5.4). Each method is one transaction of the pool the caller holds. The
// tenant of a write is always one the caller got from the store's own lookup (HubEndpointTenants, HubProofLookup), never a
// value a node sent, and every tenant write goes through WithTenant (R5).

// HubBeat is what a Heartbeat leaves in the nodes row.
type HubBeat struct {
	VersionInfo []byte // JSON object, no address of a client
	AppliedSeq  uint64
	// At is when the hub received the Heartbeat. last_heartbeat_at says when the node last spoke, not when the hub last
	// wrote, so a node that went quiet is not made to look alive by a repeated write. Zero means now.
	At time.Time
}

const qHubBeat = `UPDATE ctrlz.nodes SET last_heartbeat_at = COALESCE($4::timestamptz, pg_catalog.now()), version_info = $2::jsonb, applied_seq = $3 WHERE id = $1 AND status = 'active'`

// HubWriteBeat writes the Heartbeat fields of one active node (5.3). A node that is not active writes nothing.
func (s *Store) HubWriteBeat(ctx context.Context, node uuid.UUID, in HubBeat) error {
	var at any
	if !in.At.IsZero() {
		at = in.At
	}
	return s.WithGlobal(ctx, TxOpts{}, func(g GlobalTx) error {
		_, err := g.tx.Exec(g.ctx, qHubBeat, node, string(in.VersionInfo), int64(in.AppliedSeq), at)
		return sanitize(err)
	})
}

const qHubQuarantineAdd = `INSERT INTO ctrlz.node_quarantine (node_id, seq, item, reason) VALUES ($1, $2, $3, $4)
ON CONFLICT (node_id, seq, item, reason) DO NOTHING RETURNING id`

const qHubQuarantineNodes = `SELECT count(DISTINCT node_id) FROM ctrlz.node_quarantine WHERE seq = $1 AND item = $2 AND reason = $3 AND cleared_at IS NULL`

// HubQuarantineAdd records one quarantined item of a node (5.3), deduplicated on (node, seq, item, reason), and says whether
// the row is new and how many nodes now report the same failure and have not cleared it.
func (s *Store) HubQuarantineAdd(ctx context.Context, node uuid.UUID, seq uint64, item, reason string) (inserted bool, nodes int, err error) {
	err = s.WithGlobal(ctx, TxOpts{}, func(g GlobalTx) error {
		var id uuid.UUID
		ok, err := notFound(g.tx.QueryRow(g.ctx, qHubQuarantineAdd, node, int64(seq), item, reason).Scan(&id))
		if err != nil {
			return err
		}
		inserted = ok
		var n int64
		if err := g.tx.QueryRow(g.ctx, qHubQuarantineNodes, int64(seq), item, reason).Scan(&n); err != nil {
			return sanitize(err)
		}
		nodes = int(n)
		return nil
	})
	return inserted, nodes, err
}

const qHubEndpointTenants = `SELECT id, tenant_id FROM ctrlz.hub_endpoint_index WHERE id = ANY ($1::uuid[])`

// HubEndpointTenants maps Endpoint ids to the tenants that own them, through hub_endpoint_index. An id with no Endpoint is
// missing from the answer.
func (s *Store) HubEndpointTenants(ctx context.Context, ids []uuid.UUID) (map[uuid.UUID]uuid.UUID, error) {
	out := make(map[uuid.UUID]uuid.UUID, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	err := s.WithGlobal(ctx, TxOpts{ReadOnly: true}, func(g GlobalTx) error {
		rows, err := g.tx.Query(g.ctx, qHubEndpointTenants, ids)
		if err != nil {
			return sanitize(err)
		}
		defer rows.Close()
		for rows.Next() {
			var id, tenant uuid.UUID
			if err := rows.Scan(&id, &tenant); err != nil {
				return sanitize(err)
			}
			out[id] = tenant
		}
		return sanitize(rows.Err())
	})
	return out, err
}

// HubActivityItem is one key of the activity the hub holds, due for a write: the latest bucket any node reported for it.
type HubActivityItem struct {
	Endpoint  uuid.UUID
	Label     string
	Claim     uuid.UUID // uuid.Nil when the entry named none
	Hash      []byte    // source_ip_hash, nil when the entry carried none
	First     time.Time
	Last      time.Time
	Node      uuid.UUID // the node that reported it, for created_by_node_id
	ClientCap uint32    // client_cap of the Endpoint's record
}

// HubActivityResult counts what a write did, for the hub's drop counters.
type HubActivityResult struct {
	ClientsAdded int
	OverCap      int
}

// SourceIPHash is the hash of a source's authorized prefix that the node reports and the hub matches (p4-nodes 7.6): the
// first 16 bytes of SHA-256 of the Endpoint id and the masked prefix text.
func SourceIPHash(endpoint uuid.UUID, p netip.Prefix) []byte {
	sum := sha256.Sum256(append(append([]byte(nil), endpoint[:]...), p.Masked().String()...))
	return sum[:16]
}

const (
	qHubClientsByLabel = `SELECT id, label FROM ctrlz.clients WHERE tenant_id = $1 AND endpoint_id = $2 AND label = ANY ($3::text[])`
	qHubClientSeen     = `UPDATE ctrlz.clients SET last_seen_at = GREATEST(last_seen_at, $3) WHERE tenant_id = $1 AND id = $2`
	qHubAutoCount      = `SELECT count(*) FROM ctrlz.clients WHERE tenant_id = $1 AND endpoint_id = $2 AND source = 'auto' AND label <> 'default'`
	qHubClientInsert   = `INSERT INTO ctrlz.clients (tenant_id, endpoint_id, label, source, first_seen_at, last_seen_at, created_by_node_id)
VALUES ($1, $2, $3, 'auto', $4, $5, $6) ON CONFLICT (tenant_id, endpoint_id, label) DO NOTHING`
	qHubEndpointSeen = `UPDATE ctrlz.endpoints SET first_query_at = COALESCE(first_query_at, $3), last_query_at = GREATEST(last_query_at, $4) WHERE tenant_id = $1 AND id = $2`
	qHubClaimSeen    = `UPDATE ctrlz.ip_claims SET last_seen_at = GREATEST(last_seen_at, $4) WHERE tenant_id = $1 AND id = $2 AND endpoint_id = $3`
	qHubAuthorized   = `SELECT id, cidr FROM ctrlz.authorized_ips WHERE tenant_id = $1 AND endpoint_id = $2`
	qHubAuthSeen     = `UPDATE ctrlz.authorized_ips SET last_seen_at = GREATEST(last_seen_at, $3) WHERE tenant_id = $1 AND id = $2`
)

type hubClientSeen struct {
	id uuid.UUID
	at time.Time
}

// HubActivityWrite writes the due keys of one tenant's Endpoints in one transaction (5.4): clients first, in id order, then
// the Endpoints locked in id order, then the rest. The caller took the tenant from HubEndpointTenants for these Endpoints.
//
// A label the Endpoint has no row for gets one with source auto and created_by_node_id the sender, under the Endpoint lock,
// while the Endpoint's auto rows without default are fewer than the record's client_cap. The label default is inserted
// whatever the count and is not counted (p4b-n0-r2-3). A label past the cap loses its client row only: the claim or the
// authorized row of its entry and the Endpoint still move.
func (s *Store) HubActivityWrite(ctx context.Context, tenant uuid.UUID, items []HubActivityItem) (res HubActivityResult, err error) {
	byEp := map[uuid.UUID][]HubActivityItem{}
	for _, it := range items {
		byEp[it.Endpoint] = append(byEp[it.Endpoint], it)
	}
	eps := make([]uuid.UUID, 0, len(byEp))
	for e := range byEp {
		eps = append(eps, e)
	}
	sortUUIDs(eps)
	err = s.WithTenant(ctx, tenant, TxOpts{}, func(tx Tx) error {
		res = HubActivityResult{}
		// 1. The clients that exist, and their last_seen_at, in id order across every Endpoint (lock order 3.7 step 3).
		existing := map[uuid.UUID]map[string]uuid.UUID{}
		var seen []hubClientSeen
		for _, ep := range eps {
			labels := distinctLabels(byEp[ep])
			rows, err := tx.tx.Query(tx.ctx, qHubClientsByLabel, tenant, ep, labels)
			if err != nil {
				return sanitize(err)
			}
			m := map[string]uuid.UUID{}
			for rows.Next() {
				var id uuid.UUID
				var l string
				if err := rows.Scan(&id, &l); err != nil {
					rows.Close()
					return sanitize(err)
				}
				m[l] = id
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				return sanitize(err)
			}
			existing[ep] = m
			latest := map[string]time.Time{}
			for _, it := range byEp[ep] {
				if it.Last.After(latest[it.Label]) {
					latest[it.Label] = it.Last
				}
			}
			for l, id := range m {
				seen = append(seen, hubClientSeen{id: id, at: latest[l]})
			}
		}
		sort.Slice(seen, func(i, j int) bool { return lessUUID(seen[i].id, seen[j].id) })
		for _, c := range seen {
			if _, err := tx.tx.Exec(tx.ctx, qHubClientSeen, tenant, c.id, c.at); err != nil {
				return sanitize(err)
			}
		}
		// 2. The Endpoints, in id order, before any statement that writes them.
		locked, err := tx.EndpointsLock(eps)
		if err != nil {
			return err
		}
		// 3. Per Endpoint: new clients, the Endpoint's times, the claims and the authorized rows. An Endpoint the lock did not
		// find is not this tenant's (or is gone): nothing of it is written, whatever the caller said.
		for _, ep := range locked {
			if err := hubActivityEndpoint(tx, tenant, ep, byEp[ep], existing[ep], &res); err != nil {
				return err
			}
		}
		return nil
	})
	return res, err
}

func hubActivityEndpoint(tx Tx, tenant, ep uuid.UUID, items []HubActivityItem, have map[string]uuid.UUID, res *HubActivityResult) error {
	var first, last time.Time
	autos := -1 // counted when the first new non-default label needs it
	added := map[string]bool{}
	for _, it := range items {
		if first.IsZero() || it.First.Before(first) {
			first = it.First
		}
		if it.Last.After(last) {
			last = it.Last
		}
		if _, ok := have[it.Label]; ok || added[it.Label] {
			continue
		}
		if it.Label != "default" {
			if autos < 0 {
				var n int64
				if err := tx.tx.QueryRow(tx.ctx, qHubAutoCount, tenant, ep).Scan(&n); err != nil {
					return sanitize(err)
				}
				autos = int(n)
			}
			if autos >= int(it.ClientCap) {
				res.OverCap++
				continue
			}
			autos++
		}
		if _, err := tx.tx.Exec(tx.ctx, qHubClientInsert, tenant, ep, it.Label, it.First, it.Last, it.Node); err != nil {
			return sanitize(err)
		}
		added[it.Label] = true
		res.ClientsAdded++
	}
	if _, err := tx.tx.Exec(tx.ctx, qHubEndpointSeen, tenant, ep, first, last); err != nil {
		return sanitize(err)
	}
	var claims []HubActivityItem
	wantHash := map[string]time.Time{}
	for _, it := range items {
		switch {
		case it.Claim != uuid.Nil:
			claims = append(claims, it)
		case len(it.Hash) != 0:
			if it.Last.After(wantHash[string(it.Hash)]) {
				wantHash[string(it.Hash)] = it.Last
			}
		}
	}
	sort.Slice(claims, func(i, j int) bool { return lessUUID(claims[i].Claim, claims[j].Claim) })
	for _, c := range claims {
		if _, err := tx.tx.Exec(tx.ctx, qHubClaimSeen, tenant, c.Claim, ep, c.Last); err != nil {
			return sanitize(err)
		}
	}
	if len(wantHash) == 0 {
		return nil
	}
	rows, err := tx.tx.Query(tx.ctx, qHubAuthorized, tenant, ep)
	if err != nil {
		return sanitize(err)
	}
	type hit struct {
		id uuid.UUID
		at time.Time
	}
	var hits []hit
	for rows.Next() {
		var id uuid.UUID
		var p netip.Prefix
		if err := rows.Scan(&id, &p); err != nil {
			rows.Close()
			return sanitize(err)
		}
		if at, ok := wantHash[string(SourceIPHash(ep, p))]; ok {
			hits = append(hits, hit{id, at})
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return sanitize(err)
	}
	sort.Slice(hits, func(i, j int) bool { return lessUUID(hits[i].id, hits[j].id) })
	for _, h := range hits {
		if _, err := tx.tx.Exec(tx.ctx, qHubAuthSeen, tenant, h.id, h.at); err != nil {
			return sanitize(err)
		}
	}
	return nil
}

func distinctLabels(items []HubActivityItem) []string {
	seen := map[string]bool{}
	var out []string
	for _, it := range items {
		if !seen[it.Label] {
			seen[it.Label] = true
			out = append(out, it.Label)
		}
	}
	return out
}

func lessUUID(a, b uuid.UUID) bool { return string(a[:]) < string(b[:]) }

func sortUUIDs(ids []uuid.UUID) {
	sort.Slice(ids, func(i, j int) bool { return lessUUID(ids[i], ids[j]) })
}

// MaxLearnedPerEndpoint is the bound of secure_dns rows one Endpoint may hold (D31).
const MaxLearnedPerEndpoint = 100

// HubLearn is a LearnedIP the hub accepted into the pair rule and the rate limit.
type HubLearn struct {
	Endpoint uuid.UUID
	Source   netip.Addr
	Node     uuid.UUID
}

// HubLearnOutcome says what a LearnedIP did.
type HubLearnOutcome int

// The outcomes of HubLearnIP.
const (
	LearnWritten   HubLearnOutcome = iota // a new row
	LearnRefreshed                        // the address was already a secure_dns row
	LearnHeld                             // the address is a manual or DDNS row: nothing written
	LearnOff                              // authorize_secure_dns is off, or the Endpoint is gone
	LearnOverCap                          // 100 rows already: nothing written, nothing evicted
)

const (
	qHubLearnEndpoint = `SELECT authorize_secure_dns FROM ctrlz.endpoints WHERE tenant_id = $1 AND id = $2` + lockNoKeyUpdate
	qHubLearnRow      = `SELECT id, source FROM ctrlz.authorized_ips WHERE tenant_id = $1 AND endpoint_id = $2 AND cidr = $3`
	qHubLearnCount    = `SELECT count(*) FROM ctrlz.authorized_ips WHERE tenant_id = $1 AND endpoint_id = $2 AND source = 'secure_dns'`
	qHubLearnInsert   = `INSERT INTO ctrlz.authorized_ips (tenant_id, endpoint_id, cidr, source, last_seen_at, learned_by_node_id)
VALUES ($1, $2, $3, 'secure_dns', pg_catalog.now(), $4)`
	qHubLearnRefresh = `UPDATE ctrlz.authorized_ips SET last_seen_at = pg_catalog.now() WHERE tenant_id = $1 AND id = $2`
)

// HubLearnIP writes a learned secure_dns address (5.4) under the Endpoint lock, with the endpoint_set mark, only while
// authorize_secure_dns, read after the lock, is on. A new address past MaxLearnedPerEndpoint is dropped, nothing evicted.
func (s *Store) HubLearnIP(ctx context.Context, tenant uuid.UUID, in HubLearn) (out HubLearnOutcome, err error) {
	err = s.WithTenant(ctx, tenant, TxOpts{}, func(tx Tx) error {
		var on bool
		ok, err := notFound(tx.tx.QueryRow(tx.ctx, qHubLearnEndpoint, tenant, in.Endpoint).Scan(&on))
		if err != nil {
			return err
		}
		if !ok || !on {
			out = LearnOff
			return nil
		}
		p := netip.PrefixFrom(in.Source.Unmap(), in.Source.Unmap().BitLen())
		var id uuid.UUID
		var src string
		found, err := notFound(tx.tx.QueryRow(tx.ctx, qHubLearnRow, tenant, in.Endpoint, p).Scan(&id, &src))
		if err != nil {
			return err
		}
		if found {
			if src != "secure_dns" {
				out = LearnHeld
				return nil
			}
			if _, err := tx.tx.Exec(tx.ctx, qHubLearnRefresh, tenant, id); err != nil {
				return sanitize(err)
			}
			out = LearnRefreshed
			return nil
		}
		var n int64
		if err := tx.tx.QueryRow(tx.ctx, qHubLearnCount, tenant, in.Endpoint).Scan(&n); err != nil {
			return sanitize(err)
		}
		if n >= MaxLearnedPerEndpoint {
			out = LearnOverCap
			return nil
		}
		if _, err := tx.tx.Exec(tx.ctx, qHubLearnInsert, tenant, in.Endpoint, p, in.Node); err != nil {
			return sanitize(err)
		}
		out = LearnWritten
		return MarkDirty(tx, AggregateEndpointSet, tenant)
	})
	return out, err
}

const qHubProofLookup = `SELECT tenant_id, id, claim_id FROM ctrlz.ip_proof_challenges WHERE label = $1`

// HubProofLookup finds the challenge of a label through the hub_label policy: its tenant, its id and its claim. found is
// false for a label no challenge has.
func (s *Store) HubProofLookup(ctx context.Context, label string) (tenant, challenge, claim uuid.UUID, found bool, err error) {
	err = s.WithGlobal(ctx, TxOpts{ReadOnly: true}, func(g GlobalTx) error {
		var e error
		found, e = notFound(g.tx.QueryRow(g.ctx, qHubProofLookup, label).Scan(&tenant, &challenge, &claim))
		return e
	})
	return tenant, challenge, claim, found, err
}

// HubProof is a ProofObservation after validation. Code is the SHA-256 of the TXT code the hub derived.
type HubProof struct {
	Challenge uuid.UUID
	Claim     uuid.UUID
	Source    netip.Addr
	Protocol  string // udp, tcp, dot, doh, doh3, doq
	RIDHash   []byte // 16 bytes for an encrypted protocol, nil otherwise
	CodeHash  []byte
	Node      uuid.UUID
}

// HubProofOutcome says what an observation did.
type HubProofOutcome int

// The outcomes of HubProofObserve.
const (
	ProofWritten HubProofOutcome = iota
	ProofStale                   // already observed, consumed or expired: nothing written
	ProofDenied                  // the pair rule refused the claim's Endpoint
	ProofGone                    // the claim is gone
)

const (
	qHubProofClaim = `SELECT endpoint_id FROM ctrlz.ip_claims WHERE tenant_id = $1 AND id = $2`
	qHubProofWrite = `UPDATE ctrlz.ip_proof_challenges SET observed_at = pg_catalog.now(), observed_ip = $3, observed_protocol = $4,
  txt_code_hash = $5, observed_rid_hash = $6, observed_by_node_id = $7
WHERE tenant_id = $1 AND id = $2 AND observed_at IS NULL AND consumed_at IS NULL AND expires_at > pg_catalog.now()`
)

// HubProofObserve writes an observation on the challenge in the tenant the lookup gave, once, on a challenge that is not
// observed, consumed or expired. allow is the pair rule, asked with the claim's Endpoint before any write.
func (s *Store) HubProofObserve(ctx context.Context, tenant uuid.UUID, in HubProof, allow func(endpoint uuid.UUID) bool) (out HubProofOutcome, err error) {
	err = s.WithTenant(ctx, tenant, TxOpts{}, func(tx Tx) error {
		var ep uuid.UUID
		ok, err := notFound(tx.tx.QueryRow(tx.ctx, qHubProofClaim, tenant, in.Claim).Scan(&ep))
		if err != nil {
			return err
		}
		if !ok {
			out = ProofGone
			return nil
		}
		if !allow(ep) {
			out = ProofDenied
			return nil
		}
		var rid any
		if len(in.RIDHash) != 0 {
			rid = in.RIDHash
		}
		tag, err := tx.tx.Exec(tx.ctx, qHubProofWrite, tenant, in.Challenge, in.Source.Unmap(), in.Protocol, in.CodeHash, rid, in.Node)
		if err != nil {
			return sanitize(err)
		}
		if tag.RowsAffected() == 0 {
			out = ProofStale
		}
		return nil
	})
	return out, err
}

// HubFreeItem is one free DNS counter of a batch.
type HubFreeItem struct {
	Protocol string // udp or tcp
	Outcome  string // the lower-case name of the outcome
	RCode    int
	Count    uint64
}

const (
	qHubFreeBatch = `INSERT INTO ctrlz.free_dns_counter_batches (node_id, batch_id, bucket_start) VALUES ($1, $2, pg_catalog.to_timestamp(($3::bigint)::double precision))
ON CONFLICT DO NOTHING RETURNING batch_id`
	qHubFreeItem = `INSERT INTO ctrlz.free_dns_counters (node_id, bucket_start, protocol, outcome, rcode, count)
VALUES ($1, pg_catalog.to_timestamp(($2::bigint)::double precision), $3, $4, $5, $6) ON CONFLICT DO NOTHING`
)

// HubFreeCounters records one CountersBatch's free part (5.2a, SC 12): the batch row and its items in one transaction, so a
// batch resent after a lost Ack counts once. applied is false for a batch the node already sent, by id or by bucket.
// batch_id is the node's 64-bit number kept as the bigint with the same bits.
func (s *Store) HubFreeCounters(ctx context.Context, node uuid.UUID, batch uint64, bucket int64, items []HubFreeItem) (applied bool, err error) {
	err = s.WithGlobal(ctx, TxOpts{}, func(g GlobalTx) error {
		var id int64
		ok, err := notFound(g.tx.QueryRow(g.ctx, qHubFreeBatch, node, int64(batch), bucket).Scan(&id))
		if err != nil || !ok {
			return err
		}
		for _, it := range items {
			if _, err := g.tx.Exec(g.ctx, qHubFreeItem, node, bucket, it.Protocol, it.Outcome, int16(it.RCode), int64(it.Count)); err != nil {
				return sanitize(err)
			}
		}
		applied = true
		return nil
	})
	return applied, err
}
