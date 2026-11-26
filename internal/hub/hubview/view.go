// Package hubview is the hub's view of the config log (p4-nodes 5.5): in memory, the latest record of each Endpoint and the
// PairTable of every entry that carried one, loaded at start from the older kept snapshot and the entries after it (6.5), and
// moved by each new entry.
//
// What it is for, and why it is not the compiler's View. The compiler keeps every blob and every claim, because it writes the
// next entry from them. The hub needs four things only: the previous record of an Endpoint (to tell which change is a
// revocation), the Endpoint's pair and client cap (the pair rule and the client cap of 5.4), the latest membership (the
// failover evaluator's input) and the tables of the last 24 h (the previous pair of an Endpoint after a change, D31). Holding
// only those keeps the hub's memory to a record of about a hundred bytes per Endpoint.
//
// The view is read by many goroutines (every report of 5.4 asks Allowed) and written by one (the log poll), so it holds one
// RWMutex. Nothing here waits on the database while it holds it.
package hubview

import (
	"context"
	"encoding/hex"
	"errors"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	commonv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/common/v1"
	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	signv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/sign/v1"
	"github.com/Kup1ng/CtrlZ-Shared/wire"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// Memory and read bounds.
const (
	// PairMemory is how long a node stays allowed to report for an Endpoint after a pair change took the Endpoint off it (D31).
	PairMemory = 24 * time.Hour
	// maxCarriers bounds the tables kept. A table is kept for each membership change since the snapshot the view started from,
	// and one change is an admin act, so the bound is never met in practice; it only keeps a runaway log from growing the hub.
	maxCarriers = 4096
	// batch and batchBytes size one read of the tail: an entry may be 15 MiB, so a batch stops once it has read this much.
	batch      = 16
	batchBytes = 8 << 20
)

// Store reads the log on the control pool.
type Store interface {
	HubSnapshots(ctx context.Context, limit int) ([]store.SnapshotRow, error)
	HubLogEntries(ctx context.Context, after, upTo uint64, limit, maxBytes int) ([]store.LogRow, error)
}

// Files reads a snapshot file by the hash its name is made of (compiler.DirArtifacts).
type Files interface {
	Get(hash []byte) ([]byte, error)
}

// ep is what the hub keeps of an Endpoint record. Hashes are strings so a comparison is a comparison and the record holds no
// slice into the entry it came from, which would keep a 15 MiB payload alive for one 16-byte id.
type ep struct {
	rid, doh  string
	admin     commonv1.AdminState
	reqAuth   bool
	pair      string
	clientCap uint32
	// since is when the view first saw the record, the created_at of the entry that put it; zero for a record the view loaded from
	// a snapshot, which is older than anything the view keeps. hist holds the pairs the Endpoint had before the current one, each
	// with the instant a change took it off, for the last 24 h only (H-r1-8, H-r1-12).
	since time.Time
	hist  []pairSpan
}

// pairSpan is a pair an Endpoint had until the instant a later record took it off.
type pairSpan struct {
	pair  string
	until time.Time
}

// pairsAt are the pair ids whose nodes may report for the Endpoint at now: the current one, and each one a change took it off
// less than PairMemory ago.
func (e ep) pairsAt(now time.Time) []string {
	out := []string{e.pair}
	for _, h := range e.hist {
		if now.Sub(h.until) <= PairMemory {
			out = append(out, h.pair)
		}
	}
	return out
}

func epOf(r *policyv1.EndpointRecord) ep {
	return ep{
		rid: string(r.RidHash), doh: string(r.DohTokenHash), admin: r.AdminState, reqAuth: r.RequireAuthorizedIps,
		pair: string(r.PairId), clientCap: r.ClientCap,
	}
}

// carrier is a PairTable and where it came from. peers is the pair peer of each node of the table, which release-point and F0
// both read, computed once.
type carrier struct {
	seq   uint64
	table *policyv1.PairTable
	peers map[string]string
	ids   []string
	// until is when a later table replaced this one (the later entry's created_at), zero for the newest.
	until time.Time
}

func newCarrier(seq uint64, t *policyv1.PairTable) *carrier {
	c := &carrier{seq: seq, table: t, peers: map[string]string{}}
	for _, n := range t.GetNodes() {
		c.ids = append(c.ids, string(n.NodeId))
	}
	for _, p := range t.GetPairs() {
		if len(p.Fallback) == 0 {
			continue
		}
		c.peers[string(p.Primary)] = string(p.Fallback)
		c.peers[string(p.Fallback)] = string(p.Primary)
	}
	return c
}

// nodesOf are the nodes a pair id names in the table: the pair itself, or the global pair for an id the table does not hold
// (8a.2 step 2, which is also how the zero id of D30 reads).
func (c *carrier) nodesOf(pair string) []string {
	var found *policyv1.Pair
	for _, p := range c.table.GetPairs() {
		if string(p.PairId) == pair {
			found = p
			break
		}
	}
	if found == nil {
		for _, p := range c.table.GetPairs() {
			if string(p.PairId) == string(c.table.GlobalPairId) {
				found = p
				break
			}
		}
	}
	if found == nil {
		return nil
	}
	out := []string{string(found.Primary)}
	if len(found.Fallback) != 0 {
		out = append(out, string(found.Fallback))
	}
	return out
}

// View is the hub's log view.
type View struct {
	mu       sync.RWMutex
	seq      uint64
	eps      map[string]ep
	carriers []*carrier

	skipped atomic.Uint64
}

// New makes an empty view, the view of an empty log.
func New() *View { return &View{eps: map[string]ep{}} }

// Seq is the highest entry the view has applied.
func (v *View) Seq() uint64 {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.seq
}

// Skipped counts entries that did not decode and were passed over. The compiler validates what it writes, so a count above zero
// says the log was written by something else.
func (v *View) Skipped() uint64 { return v.skipped.Load() }

// Rev is one Revocation the hub sends for an entry: a kind and the ids of that kind (5.5).
type Rev struct {
	Kind policyv1.RevocationKind
	IDs  [][]byte
}

// Applied is what one entry did to the view that the rest of the hub acts on.
type Applied struct {
	Seq  uint64
	Revs []Rev
	// Emptied are the nodes whose SPKI this entry's table empties and the previous table had not: their streams end at once
	// (G2 of 8a.9, Hub.Streams.Kill).
	Emptied []uuid.UUID
}

// Load reads the older kept snapshot and every entry after it. An empty log gives an empty view. A snapshot that cannot be read
// or does not match its row is passed over for the newer one, and then for the whole log, as the compiler does, so a missing
// file costs a longer read and not a hub that cannot start.
func (v *View) Load(ctx context.Context, st Store, files Files) error {
	snaps, err := st.HubSnapshots(ctx, 2)
	if err != nil {
		return err
	}
	v.mu.Lock()
	v.seq, v.eps, v.carriers = 0, map[string]ep{}, nil
	v.mu.Unlock()
	// Oldest first: the older snapshot is the one the spec names (6.5), and the newer is the fallback.
	for i := len(snaps) - 1; i >= 0; i-- {
		if v.fromSnapshot(snaps[i], files) {
			break
		}
	}
	for {
		before := v.Seq()
		n, err := v.catch(ctx, st, math.MaxInt64, nil)
		if err != nil {
			return err
		}
		if n == 0 || v.Seq() == before {
			return nil
		}
	}
}

func (v *View) fromSnapshot(s store.SnapshotRow, files Files) bool {
	h, err := hex.DecodeString(s.StoreRef)
	if err != nil || len(h) != 32 {
		return false
	}
	data, err := files.Get(h)
	if err != nil {
		return false
	}
	var sn signv1.Snapshot
	if err := proto.Unmarshal(data, &sn); err != nil || sn.Seq != s.Seq || string(sn.EntryHash) != string(s.EntryHash) {
		return false
	}
	eps := make(map[string]ep, len(sn.Endpoints))
	for _, r := range sn.Endpoints {
		eps[string(r.EndpointId)] = epOf(r)
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	v.seq, v.eps, v.carriers = sn.Seq, eps, nil
	if sn.PairTable != nil {
		v.carriers = []*carrier{newCarrier(sn.Seq, sn.PairTable)}
	}
	return true
}

// Catch applies every entry up to upTo that the view has not seen, in order, and returns what each did. A database error leaves
// the view where it got to and is returned: the caller tries again, and nothing past the entry that failed is announced.
func (v *View) Catch(ctx context.Context, st Store, upTo uint64) ([]Applied, error) {
	var out []Applied
	for v.Seq() < upTo {
		n, err := v.catch(ctx, st, upTo, &out)
		if err != nil {
			return out, err
		}
		if n == 0 {
			return out, errors.New("hubview: the log has no entry after the view's seq")
		}
	}
	return out, nil
}

// catch reads one batch after the view's seq and applies it. It returns how many entries it read.
func (v *View) catch(ctx context.Context, st Store, upTo uint64, out *[]Applied) (int, error) {
	after := v.Seq()
	if upTo > math.MaxInt64 {
		upTo = math.MaxInt64
	}
	rows, err := st.HubLogEntries(ctx, after, upTo, batch, batchBytes)
	if err != nil {
		return 0, err
	}
	for _, r := range rows {
		if r.Seq != v.Seq()+1 {
			return 0, errors.New("hubview: the log has a gap")
		}
		e, derr := wire.DecodeEntry(r.Payload)
		if derr != nil {
			// The entry is not applied but the seq moves: a node would quarantine it too, and a view that stopped here would
			// stop revoking for every entry after it.
			v.skipped.Add(1)
			v.mu.Lock()
			v.seq = r.Seq
			v.mu.Unlock()
			continue
		}
		a := v.Apply(e)
		if out != nil {
			*out = append(*out, a)
		}
	}
	return len(rows), nil
}

// Apply moves the view by one entry that the caller has validated, in the order a node applies it (deletes of Endpoints, then
// puts), and says what it revokes. The previous record of an Endpoint is the one the view held before this entry.
func (v *View) Apply(e *policyv1.ConfigEntry) Applied {
	v.mu.Lock()
	defer v.mu.Unlock()
	a := Applied{Seq: e.Seq}
	var gone, hard [][]byte
	for _, id := range e.DelEndpoints {
		if _, ok := v.eps[string(id)]; ok {
			delete(v.eps, string(id))
		}
		gone = append(gone, id)
	}
	at := time.Unix(e.CreatedAt, 0)
	for _, r := range e.PutEndpoints {
		next := epOf(r)
		old, had := v.eps[string(r.EndpointId)]
		if had && revokes(old, next) {
			hard = append(hard, r.EndpointId)
		}
		switch {
		case !had:
			next.since = at
		case old.pair != next.pair:
			next.since, next.hist = old.since, append(keepSpans(old.hist, at), pairSpan{pair: old.pair, until: at})
		default:
			next.since, next.hist = old.since, keepSpans(old.hist, at)
		}
		v.eps[string(r.EndpointId)] = next
	}
	if ids := append(gone, hard...); len(ids) > 0 {
		a.Revs = append(a.Revs, Rev{Kind: policyv1.RevocationKind_REVOCATION_KIND_ENDPOINT, IDs: ids})
	}
	if len(e.DelClaims) > 0 {
		a.Revs = append(a.Revs, Rev{Kind: policyv1.RevocationKind_REVOCATION_KIND_CLAIM, IDs: e.DelClaims})
	}
	if e.PairTable != nil {
		a.Emptied = v.carry(e.Seq, e.CreatedAt, e.PairTable)
	}
	v.seq = e.Seq
	return a
}

// keepSpans copies the spans that a change at the instant at can still matter for: the ones that ended less than PairMemory before.
func keepSpans(h []pairSpan, at time.Time) []pairSpan {
	var out []pairSpan
	for _, s := range h {
		if at.Sub(s.until) <= PairMemory {
			out = append(out, s)
		}
	}
	return out
}

// revokes says whether a change of an Endpoint record is one the hub does not leave to the rollout (5.5): the Endpoint turns
// hard-disabled, its resolver id or DoH token is rotated, or it starts to require authorized addresses. A lost authorized prefix
// derives none, since DDNS replacement and learned-row expiry make it routine.
func revokes(old, next ep) bool {
	return (next.admin == commonv1.AdminState_ADMIN_STATE_HARD_DISABLED && old.admin != commonv1.AdminState_ADMIN_STATE_HARD_DISABLED) ||
		old.rid != next.rid || old.doh != next.doh || (next.reqAuth && !old.reqAuth)
}

// carry adds a table to the history and returns the nodes it empties the SPKI of. The caller holds the lock.
func (v *View) carry(seq uint64, createdAt int64, t *policyv1.PairTable) []uuid.UUID {
	c := newCarrier(seq, t)
	var prev *carrier
	if n := len(v.carriers); n > 0 {
		prev = v.carriers[n-1]
		prev.until = time.Unix(createdAt, 0)
	}
	was := map[string]bool{}
	if prev != nil {
		for _, n := range prev.table.Nodes {
			was[string(n.NodeId)] = len(n.SpkiSha256) == 0
		}
	}
	var emptied []uuid.UUID
	for _, n := range t.Nodes {
		if len(n.SpkiSha256) != 0 || len(n.NodeId) != 16 {
			continue
		}
		if empty, known := was[string(n.NodeId)]; known && empty {
			continue // already empty in the table before: nothing new to end
		}
		id, err := uuid.FromBytes(n.NodeId)
		if err == nil {
			emptied = append(emptied, id)
		}
	}
	v.carriers = append(v.carriers, c)
	if len(v.carriers) > maxCarriers {
		v.carriers = append([]*carrier(nil), v.carriers[len(v.carriers)-maxCarriers:]...)
	}
	return emptied
}

// Membership is the PairTable of the latest entry that carried one: the hub's latest membership (8a.4). found is false while no
// entry has carried one. The table is shared and must not be changed.
func (v *View) Membership() (t *policyv1.PairTable, seq uint64, found bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if n := len(v.carriers); n > 0 {
		return v.carriers[n-1].table, v.carriers[n-1].seq, true
	}
	return nil, 0, false
}

// Allowed is the pair rule of 5.4: node may report for the Endpoint when it is in the Endpoint's current pair, or in a pair the
// Endpoint had that a change took it off less than 24 h ago. An Endpoint the view does not know is not allowed.
func (v *View) Allowed(endpoint, node uuid.UUID, now time.Time) bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	e, ok := v.eps[string(endpoint[:])]
	if !ok {
		return false
	}
	want := string(node[:])
	pairs := e.pairsAt(now)
	for i := len(v.carriers) - 1; i >= 0; i-- {
		c := v.carriers[i]
		if !c.until.IsZero() && now.Sub(c.until) > PairMemory {
			break // older ones were replaced even earlier
		}
		// A table that was replaced before the Endpoint existed says nothing of it: its fallback to the global pair is for a pair
		// id the table lacks while a record named it, not for a record that was not there yet.
		if !e.since.IsZero() && !c.until.IsZero() && !c.until.After(e.since) {
			continue
		}
		for _, p := range pairs {
			for _, id := range c.nodesOf(p) {
				if id == want {
					return true
				}
			}
		}
	}
	return false
}

// ClientCap is client_cap of the Endpoint's latest record; ok is false when the view has none.
func (v *View) ClientCap(endpoint uuid.UUID) (uint32, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	e, ok := v.eps[string(endpoint[:])]
	return e.clientCap, ok
}

// ReleasePoint is the release point of L12: the highest seq such that the membership in force after that entry leaves row F0 not
// due against last (the pair peer of each node of last_table, by node id). Everything at or below it may be announced and
// served; an entry above it waits for the event that makes F0 not due. latest is the log's head, which is the answer whenever the
// newest table is not due, and also when no entry ever carried one.
//
// Why "highest such seq" and not "up to the first entry that is due": a pair change that is reverted before its F0 event has
// committed leaves F0 not due again, and the entries in between are then safe, which the second reading would hold back for ever
// (8a.11 L12, the revert case).
func (v *View) ReleasePoint(last map[string]string, latest uint64) uint64 {
	v.mu.RLock()
	defer v.mu.RUnlock()
	n := len(v.carriers)
	for i := n - 1; i >= 0; i-- {
		if due(v.carriers[i], last) {
			continue
		}
		if i == n-1 {
			return latest
		}
		return v.carriers[i+1].seq - 1
	}
	if n == 0 {
		return latest
	}
	if s := v.carriers[0].seq; s > 0 {
		return s - 1
	}
	return 0
}

// due is row F0's State: some node of the table has a pair peer that differs from its peer in last, none counting as a value.
func due(c *carrier, last map[string]string) bool {
	for _, id := range c.ids {
		a, aok := c.peers[id]
		b, bok := last[id]
		if aok != bok || a != b {
			return true
		}
	}
	return false
}

// PeersOf is the pair peer of each node a table's pairs name, by node id: what row F0 compares against last_table.
func PeersOf(t *policyv1.PairTable) map[string]string { return newCarrier(0, t).peers }
