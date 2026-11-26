package store

import (
	"context"
	"net/netip"
	"time"

	"github.com/google/uuid"
)

// The hub's reads for the Control stream and the transfer RPCs (p4-nodes 5.2, 6.4, 6.5). Each is one
// read-only transaction of the pool the caller holds; which pool that is stays the wiring's decision (5.7).
// Nothing here writes, and nothing here is tenant-scoped: the log, the snapshots and the node rows are the
// panel's own state, which the hub role may read and no tenant may.

// HubLogHead is the part of a log row the rollout and the head need: no payload.
type HubLogHead struct {
	Seq   uint64
	Class string
	Hash  []byte
}

const qHubLogHeads = `SELECT seq, class, entry_hash FROM ctrlz.config_log WHERE seq > $1 ORDER BY seq LIMIT $2`

// HubLogHeads reads up to limit rows after seq, oldest first, without their payloads. The 500 ms poll of the log
// uses it, so an entry of 15 MiB costs the poll a hash and not 15 MiB.
func (s *Store) HubLogHeads(ctx context.Context, after uint64, limit int) (out []HubLogHead, err error) {
	err = s.WithGlobal(ctx, TxOpts{ReadOnly: true}, func(g GlobalTx) error {
		rows, err := g.tx.Query(g.ctx, qHubLogHeads, int64(after), int32(limit))
		if err != nil {
			return sanitize(err)
		}
		defer rows.Close()
		for rows.Next() {
			var h HubLogHead
			var seq int64
			if err := rows.Scan(&seq, &h.Class, &h.Hash); err != nil {
				return sanitize(err)
			}
			h.Seq = uint64(seq)
			out = append(out, h)
		}
		return sanitize(rows.Err())
	})
	return out, err
}

const qHubLogHash = `SELECT entry_hash FROM ctrlz.config_log WHERE seq = $1`

// HubLogHash is the hash of one entry, found false when the log has no such seq (pruned or not written).
func (s *Store) HubLogHash(ctx context.Context, seq uint64) (hash []byte, found bool, err error) {
	err = s.WithGlobal(ctx, TxOpts{ReadOnly: true}, func(g GlobalTx) error {
		found, err = notFound(g.tx.QueryRow(g.ctx, qHubLogHash, int64(seq)).Scan(&hash))
		return err
	})
	return hash, found, err
}

// The payload of an entry can be 16 MiB and a LIMIT of 200 entries could make Postgres detoast and send gigabytes that the byte cap
// then discards (H-r1-7). So the range is chosen by size first: qHubLogSizes reads the lengths, which Postgres takes from the
// TOAST pointer without detoasting, and qHubLogEntries reads the payloads of the rows that stay inside the cap.
const (
	qHubLogSizes   = `SELECT seq, octet_length(payload) FROM ctrlz.config_log WHERE seq > $1 AND seq <= $2 ORDER BY seq LIMIT $3`
	qHubLogEntries = `SELECT seq, class, prev_hash, entry_hash, payload FROM ctrlz.config_log WHERE seq > $1 AND seq <= $2 ORDER BY seq LIMIT $3`
)

// HubLogEntries reads entries with seq in (after, upTo], oldest first, at most limit of them and stopping once
// maxBytes of payload were chosen (the entry that crosses the line is kept: one entry may be larger than the cap, and
// a node that got none would never move). Only the payloads of the chosen entries leave the database.
func (s *Store) HubLogEntries(ctx context.Context, after, upTo uint64, limit, maxBytes int) (out []LogRow, err error) {
	if upTo <= after {
		return nil, nil
	}
	err = s.WithGlobal(ctx, TxOpts{ReadOnly: true, Isolation: RepeatableRead}, func(g GlobalTx) error {
		rows, err := g.tx.Query(g.ctx, qHubLogSizes, int64(after), int64(upTo), int32(limit))
		if err != nil {
			return sanitize(err)
		}
		var cut int64
		var n int32
		total := 0
		for rows.Next() {
			var seq int64
			var size int32
			if err := rows.Scan(&seq, &size); err != nil {
				rows.Close()
				return sanitize(err)
			}
			cut = seq
			n++
			if total += int(size); total >= maxBytes {
				break
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return sanitize(err)
		}
		if n == 0 {
			return nil
		}
		rows, err = g.tx.Query(g.ctx, qHubLogEntries, int64(after), cut, n)
		if err != nil {
			return sanitize(err)
		}
		defer rows.Close()
		for rows.Next() {
			var r LogRow
			var seq int64
			if err := rows.Scan(&seq, &r.Class, &r.PrevHash, &r.EntryHash, &r.Payload); err != nil {
				return sanitize(err)
			}
			r.Seq = uint64(seq)
			out = append(out, r)
		}
		return sanitize(rows.Err())
	})
	return out, err
}

// HubSnapshots lists the newest snapshot rows, newest first.
func (s *Store) HubSnapshots(ctx context.Context, limit int) (out []SnapshotRow, err error) {
	err = s.WithGlobal(ctx, TxOpts{ReadOnly: true}, func(g GlobalTx) (err error) {
		out, err = g.CompilerSnapshots(limit)
		return err
	})
	return out, err
}

// HubMembership is what the rollout order is made from: every node row, the pairs and the global pair.
type HubMembership struct {
	Nodes  []MemberNode
	Pairs  []MemberPair
	Global uuid.UUID
}

// HubMembership reads the rows in one snapshot, so a pair that names a node is read with that node.
func (s *Store) HubMembership(ctx context.Context) (m HubMembership, err error) {
	err = s.WithGlobal(ctx, TxOpts{ReadOnly: true, Isolation: RepeatableRead}, func(g GlobalTx) (err error) {
		if m.Nodes, err = g.CompilerNodes(); err != nil {
			return err
		}
		if m.Pairs, err = g.CompilerPairs(); err != nil {
			return err
		}
		m.Global, err = g.CompilerGlobalPair()
		return err
	})
	return m, err
}

const qHubFreeDNS = `SELECT enabled, version FROM ctrlz.free_dns_settings`

// HubFreeDNS reads the switch and its version (5.2a, Turning it off fast).
func (s *Store) HubFreeDNS(ctx context.Context) (enabled bool, version uint64, err error) {
	err = s.WithGlobal(ctx, TxOpts{ReadOnly: true}, func(g GlobalTx) error {
		var v int64
		if err := g.tx.QueryRow(g.ctx, qHubFreeDNS).Scan(&enabled, &v); err != nil {
			return sanitize(err)
		}
		version = uint64(v)
		return nil
	})
	return enabled, version, err
}

// HubUpstream is a node_upstreams row as NodeConfig needs it.
type HubUpstream struct {
	ID        uuid.UUID
	Group     string
	Position  int
	Kind      string
	Address   string
	Bootstrap netip.Addr // invalid when the row has none
	TLSName   string
	TimeoutMS int
	HealthSec int
	Trusted   bool
	ViaWire   int // locations.wire_id of via_location_id, 0 for none
}

// HubRule is a node_resolver_rules row.
type HubRule struct {
	Position  int
	MatchType string
	Value     string
	Group     string
	Final     bool
}

// HubConfigRead is everything one NodeConfig is built from, read in one snapshot together with the row's status and
// key, so a node that was revoked a moment ago is never handed a config built before it (4.4).
type HubConfigRead struct {
	Found       bool
	Status      string
	SPKI        []byte
	DNSBind     netip.Addr
	DNSAdv      netip.Addr
	ProxyBind   netip.Addr
	ProxyAdv    netip.Addr
	ResolveMode string
	Upstreams   []HubUpstream
	Rules       []HubRule
	PanelHost   string
	AdminHost   string
	DNSZone     string
	PrevZone    string
	PrevUntil   time.Time
}

const qHubConfigNode = `SELECT status, spki_sha256, COALESCE(host(dns_bind_ip), ''), COALESCE(host(dns_advertised_ip), ''),
  COALESCE(host(proxy_bind_ip), ''), COALESCE(host(proxy_advertised_ip), ''), resolve_mode FROM ctrlz.nodes WHERE id = $1`

const qHubConfigUpstreams = `SELECT u.id, u.group_name, u.position, u.kind, u.address, COALESCE(host(u.bootstrap_ip), ''), COALESCE(u.tls_name, ''),
  u.timeout_ms, u.health_interval_s, u.trusted, COALESCE(l.wire_id, 0)
FROM ctrlz.node_upstreams u LEFT JOIN ctrlz.locations l ON l.id = u.via_location_id
WHERE u.node_id = $1 ORDER BY u.group_name, u.position`

const qHubConfigRules = `SELECT position, match_type, COALESCE(match_value, ''), target_group, final_default FROM ctrlz.node_resolver_rules WHERE node_id = $1 ORDER BY position`

const qHubConfigDomain = `SELECT COALESCE(panel_host, ''), COALESCE(admin_host, ''), COALESCE(dns_zone, ''), COALESCE(prev_dns_zone, ''), transition_until FROM ctrlz.domain_settings`

func addrOf(s string) netip.Addr {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}
	}
	return a
}

// HubConfigLoad reads the rows of one node's NodeConfig. Found is false for a node that is gone.
func (s *Store) HubConfigLoad(ctx context.Context, id uuid.UUID) (r HubConfigRead, err error) {
	err = s.WithGlobal(ctx, TxOpts{ReadOnly: true, Isolation: RepeatableRead}, func(g GlobalTx) error {
		var a, b, c, d string
		ok, err := notFound(g.tx.QueryRow(g.ctx, qHubConfigNode, id).Scan(&r.Status, &r.SPKI, &a, &b, &c, &d, &r.ResolveMode))
		if err != nil || !ok {
			return err
		}
		r.Found = true
		r.DNSBind, r.DNSAdv, r.ProxyBind, r.ProxyAdv = addrOf(a), addrOf(b), addrOf(c), addrOf(d)
		rows, err := g.tx.Query(g.ctx, qHubConfigUpstreams, id)
		if err != nil {
			return sanitize(err)
		}
		for rows.Next() {
			var u HubUpstream
			var boot string
			var pos, to, hs, via int32
			if err := rows.Scan(&u.ID, &u.Group, &pos, &u.Kind, &u.Address, &boot, &u.TLSName, &to, &hs, &u.Trusted, &via); err != nil {
				rows.Close()
				return sanitize(err)
			}
			u.Position, u.TimeoutMS, u.HealthSec, u.ViaWire, u.Bootstrap = int(pos), int(to), int(hs), int(via), addrOf(boot)
			r.Upstreams = append(r.Upstreams, u)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return sanitize(err)
		}
		rr, err := g.tx.Query(g.ctx, qHubConfigRules, id)
		if err != nil {
			return sanitize(err)
		}
		for rr.Next() {
			var x HubRule
			var pos int32
			if err := rr.Scan(&pos, &x.MatchType, &x.Value, &x.Group, &x.Final); err != nil {
				rr.Close()
				return sanitize(err)
			}
			x.Position = int(pos)
			r.Rules = append(r.Rules, x)
		}
		rr.Close()
		if err := rr.Err(); err != nil {
			return sanitize(err)
		}
		var until *time.Time
		if err := g.tx.QueryRow(g.ctx, qHubConfigDomain).Scan(&r.PanelHost, &r.AdminHost, &r.DNSZone, &r.PrevZone, &until); err != nil {
			return sanitize(err)
		}
		if until != nil {
			r.PrevUntil = *until
		}
		return nil
	})
	return r, err
}

const qHubLease = `INSERT INTO ctrlz.leases AS l (name, holder, expires_at) VALUES ($1, $2, now() + make_interval(secs => $3::int))
ON CONFLICT (name) DO UPDATE SET holder = EXCLUDED.holder, expires_at = EXCLUDED.expires_at
WHERE l.holder = EXCLUDED.holder OR l.expires_at <= now()
RETURNING name`

// HubLeaseTake takes or renews the named lease for holder, secs seconds, and says whether the holder has it now. It is the
// same statement every lease of the panel uses (a lease is only ever taken or renewed through it), and the hub runs it
// on its lease pool alone (5.7).
func (s *Store) HubLeaseTake(ctx context.Context, name, holder string, secs int) (held bool, err error) {
	err = s.WithGlobal(ctx, TxOpts{}, func(g GlobalTx) error {
		var got string
		held, err = notFound(g.tx.QueryRow(g.ctx, qHubLease, name, holder, int32(secs)).Scan(&got))
		return err
	})
	return held, err
}

const qHubLogLatest = `SELECT seq, class, entry_hash FROM ctrlz.config_log ORDER BY seq DESC LIMIT 1`

// HubLogLatest is the newest entry, found false for an empty log. The hub reads it once at start, so its rollout begins at the
// head and only what is written after it is walked node by node (a restart sets every cursor to the release point, 6.4).
func (s *Store) HubLogLatest(ctx context.Context) (h HubLogHead, found bool, err error) {
	err = s.WithGlobal(ctx, TxOpts{ReadOnly: true}, func(g GlobalTx) error {
		var seq int64
		found, err = notFound(g.tx.QueryRow(g.ctx, qHubLogLatest).Scan(&seq, &h.Class, &h.Hash))
		h.Seq = uint64(seq)
		return err
	})
	return h, found, err
}
