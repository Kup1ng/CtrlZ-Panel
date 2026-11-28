// Package hubroll is the hub's side of the rollout of p4-nodes 6.4: it holds the rollout.Queue the compiler's package
// provides, feeds it what the hub hears (the log, the streams, the acks and the heartbeats of the nodes), and says how
// far each node may read.
//
// Two bounds meet here and no other code decides either. The release point (SC 8a.11 L12) says how far the log may go
// at all while a pair change waits for its F0 event; the cursor (6.4) says how far this node may go while an entry is
// walked node by node. A node may read up to the lower of the two, and the same number bounds HeadNotice, GetHead,
// FetchEntries and GetSnapshot, so a node cannot learn of an entry by one door that another door withholds.
//
// The Queue is not safe for concurrent use, and its answers depend on the clock, so every call here takes one mutex.
// Nothing here waits on the database or on a stream: the callers hand in plain values.
package hubroll

import (
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/compiler/rollout"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// Release gives the release point of L12 for a log whose latest entry is latest. known is false before the hub has
// read what the point depends on (pair_event_state), and then the hub serves nothing.
type Release interface {
	Point(latest uint64) (seq uint64, known bool)
}

// HeadRelease is the release point of a log with no pair change held back: the latest entry. It is what the hub uses
// until the evaluator of 5.6 exists; the evaluator's own Release replaces it, and the node count of the lab (one
// node, no pair) cannot have an F0 due.
type HeadRelease struct{}

// Point is the latest entry.
func (HeadRelease) Point(latest uint64) (uint64, bool) { return latest, true }

// Config is what Roll needs.
type Config struct {
	Rollout rollout.Config
	Release Release
}

// Roll is the rollout state of one hub.
type Roll struct {
	mu     sync.Mutex
	q      queue
	rel    Release
	latest uint64
	ids    map[uuid.UUID]string
	// classes remembers the class of the latest entries, so a HeadNotice can name the class of the seq it announces.
	classes map[uint64]string
}

// New makes a Roll. A hub restart makes a new one, and every cursor then starts at the release point (6.4).
func New(cfg Config) *Roll {
	if cfg.Release == nil {
		cfg.Release = HeadRelease{}
	}
	return &Roll{q: rollout.New(cfg.Rollout), rel: cfg.Release, ids: make(map[uuid.UUID]string), classes: make(map[uint64]string)}
}

func (r *Roll) key(id uuid.UUID) string {
	k, ok := r.ids[id]
	if !ok {
		k = id.String()
		r.ids[id] = k
	}
	return k
}

// Order is the order of the rollout from the rows: the global pair's fallback, its primary, then the other active nodes by
// slot (6.4). A node that is not active takes no place, so a pending or revoked node holds nobody.
func Order(m store.HubMembership) []uuid.UUID {
	active := map[uuid.UUID]store.MemberNode{}
	for _, n := range m.Nodes {
		if n.Status == "active" {
			active[n.ID] = n
		}
	}
	var out []uuid.UUID
	seen := map[uuid.UUID]bool{}
	add := func(id uuid.UUID) {
		if _, ok := active[id]; ok && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	for _, p := range m.Pairs {
		if p.ID == m.Global {
			add(p.Fallback)
			add(p.Primary)
		}
	}
	rest := make([]store.MemberNode, 0, len(active))
	for _, n := range active {
		if !seen[n.ID] {
			rest = append(rest, n)
		}
	}
	sort.Slice(rest, func(i, j int) bool { return rest[i].Slot < rest[j].Slot })
	for _, n := range rest {
		add(n.ID)
	}
	return out
}

// SetOrder replaces the order. The streams that are open stay open: the queue keeps what it knows of a node that is still named.
func (r *Roll) SetOrder(ids []uuid.UUID) {
	r.mu.Lock()
	defer r.mu.Unlock()
	keys := make([]string, len(ids))
	for i, id := range ids {
		keys[i] = r.key(id)
	}
	r.q.SetOrder(keys)
}

// Stream records that a node's Control stream opened or closed.
func (r *Roll) Stream(id uuid.UUID, open bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.q.Stream(r.key(id), open)
}

// Written tells the queue about a log entry, by the class the log row holds. An unknown class counts as policy: it
// holds nothing back, which is the side a bad row cannot use to stall the fleet.
func (r *Roll) Written(seq uint64, class string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if seq > r.latest {
		r.latest = seq
	}
	r.classes[seq] = class
	delete(r.classes, seq-classKeep)
	c := rollout.Policy
	if class == "catalog" {
		c = rollout.Catalog
	}
	r.q.Written(seq, c)
}

// Ack records an ApplyResult and says whether the queue believed it (false is a protocol fault the caller counts).
func (r *Roll) Ack(id uuid.UUID, seq uint64, ok bool) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.q.Ack(r.key(id), seq, ok)
}

// Heartbeat records what a heartbeat said of the node's health.
func (r *Roll) Heartbeat(id uuid.UUID, h rollout.Health) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.q.Heartbeat(r.key(id), h)
}

// Latest is the highest seq written, 0 before the first.
func (r *Roll) Latest() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.latest
}

// Bound is how far the node may read now: the lower of the release point and its cursor. known is false while the
// release point is not known, and then nothing may be served (L12: before the read of pair_event_state the hub serves
// no entry and returns no head).
func (r *Roll) Bound(id uuid.UUID) (seq uint64, known bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	point, ok := r.rel.Point(r.latest)
	if !ok {
		return 0, false
	}
	return min(point, r.q.Cursor(r.key(id))), true
}

// Held lists the catalog entries the rollout still holds, for the page and the alert of a failed canary.
func (r *Roll) Held() []uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.q.Held()
}

// Tick is how often the hub looks at the queue again for a node whose cursor moves with time (the stagger of 5 s and the
// cap of 120 s are measured on the clock, not on a message).
const Tick = time.Second

// classKeep is how many of the latest entries have their class remembered.
const classKeep = 1024

// ClassAt is the class of an entry the roll heard of lately, "policy" for one it did not.
func (r *Roll) ClassAt(seq uint64) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if c, ok := r.classes[seq]; ok {
		return c
	}
	return "policy"
}

// queue is what Roll uses of the rollout queue of the compiler's package: the whole of its surface here, named so a test can
// put a recording one in its place.
type queue interface {
	SetOrder(ids []string)
	Stream(id string, open bool)
	Written(seq uint64, class rollout.Class)
	Ack(id string, seq uint64, ok bool) bool
	Heartbeat(id string, h rollout.Health)
	Cursor(id string) uint64
	Held() []uint64
}

// SetRelease replaces the release point. The failover loop (5.6) needs the lease and the log view, which are built after the
// roll, so the hub gives it here once they exist; until then the point is the one New was given.
func (r *Roll) SetRelease(rel Release) {
	if rel == nil {
		return
	}
	r.mu.Lock()
	r.rel = rel
	r.mu.Unlock()
}
