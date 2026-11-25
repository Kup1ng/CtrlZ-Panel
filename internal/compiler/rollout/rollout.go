// Package rollout is the rollout cursor of P4 6.4: how far each node may read the log while an entry is going out.
//
// The compiler writes entries at once; the hub decides when a node may read them, so a bad entry meets one node (or
// one canary) before it meets the fleet. The hub keeps a Queue in memory, feeds it what it hears (streams, acks,
// heartbeats) and serves `HeadNotice`, `GetHead` and `FetchEntries` up to Cursor(node). A restart starts a new Queue,
// whose cursors are the release point: nothing the bound of 120 s does not already allow is held back or given early.
//
// The package has no database and no clock of its own, so the rules are tested to the second.
package rollout

import (
	"sort"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/appclock"
)

// Class is the class of a log entry (SC 9.6).
type Class uint8

// The classes.
const (
	Policy Class = iota + 1
	Catalog
)

// Config holds the numbers of 6.4 (D31, measured by the load test).
type Config struct {
	// Stagger is how long a node's cursor waits behind the previous node of the order for its ack (5 s).
	Stagger time.Duration
	// Soak is how long the canary must report healthy after it applied a catalog entry (60 s).
	Soak time.Duration
	// Cap is the longest a catalog entry holds what is behind it (120 s from the moment it was written).
	Cap time.Duration
	// Now is the clock; the application clock in the hub.
	Now func() time.Time
}

func (c *Config) defaults() {
	if c.Stagger <= 0 {
		c.Stagger = 5 * time.Second
	}
	if c.Soak <= 0 {
		c.Soak = 60 * time.Second
	}
	if c.Cap <= 0 {
		c.Cap = 120 * time.Second
	}
	if c.Now == nil {
		c.Now = appclock.Now
	}
}

// Health is what one heartbeat says that the canary check needs.
type Health struct {
	// ResolveHealthy is true when the node's resolve path is healthy.
	ResolveHealthy bool
	// Quarantined is the node's count of quarantined items; a rise since the node applied the entry is a new quarantine.
	Quarantined int
}

type node struct {
	id     string
	stream bool
	acked  uint64
	// cursor is how far the node may read now, and steps say when it reached each value, so the next node can wait
	// Stagger behind it.
	cursor uint64
	steps  []step
	health Health
}

type step struct {
	seq uint64
	at  time.Time
}

// held is a catalog entry that is not released yet.
type held struct {
	seq     uint64
	written time.Time
	// canary is the node chosen when the entry was written, "" for none (the entry was then released at once).
	canary  string
	applied time.Time // when the canary acked it ok, zero before
	// beat is set by the first Heartbeat of the canary after it applied the entry: a soak is of heartbeats, and a canary that
	// went quiet after its ack has shown nothing.
	beat bool
	// base is the canary's quarantine count when it applied the entry.
	base int
	// bad is set by a new quarantine or an unhealthy heartbeat after the apply: the soak cannot end early, and the cap
	// is what releases the entry.
	bad bool
}

// Queue is the state of one hub. It is not safe for concurrent use; the hub guards it.
type Queue struct {
	cfg     Config
	order   []string
	nodes   map[string]*node
	latest  uint64
	holds   []*held
	release uint64
}

// New makes a Queue. The first nodes and entries come from SetOrder and Written.
func New(cfg Config) *Queue {
	cfg.defaults()
	return &Queue{cfg: cfg, nodes: map[string]*node{}}
}

// SetOrder gives the order of the rollout: the global pair's fallback, its primary, then the other nodes by slot (6.4).
// A node not named is dropped. A node new to the order starts at the release point, as after a restart.
func (q *Queue) SetOrder(ids []string) {
	q.order = append(q.order[:0], ids...)
	keep := map[string]bool{}
	for _, id := range ids {
		keep[id] = true
		if q.nodes[id] == nil {
			q.nodes[id] = &node{id: id, cursor: q.release}
		}
	}
	for id := range q.nodes {
		if !keep[id] {
			delete(q.nodes, id)
		}
	}
	q.recompute()
}

// Stream records that a node's Control stream opened or closed. A node without a stream holds nobody behind it.
func (q *Queue) Stream(id string, open bool) {
	if n := q.nodes[id]; n != nil {
		n.stream = open
	}
	q.recompute()
}

// Written tells the queue about a new entry. A catalog entry is held behind its canary: the first node of the order that
// has a stream now. With none, it is released at once (6.4).
func (q *Queue) Written(seq uint64, class Class) {
	if seq <= q.latest {
		return
	}
	q.latest = seq
	if class == Catalog {
		h := &held{seq: seq, written: q.cfg.Now()}
		for _, id := range q.order {
			if n := q.nodes[id]; n != nil && n.stream {
				h.canary = id
				break
			}
		}
		if h.canary != "" {
			q.holds = append(q.holds, h)
		}
	}
	q.recompute()
}

// Ack records an ApplyResult: the node has applied seq, ok says without a refusal of the entry itself. A seq above what was
// written, or above what the node was allowed to read, cannot be true: it is ignored and false is returned, so the hub can
// count a protocol fault. Believing it would let one node send 2^64-1 and take the stagger away from every later entry
// (W4-r3-11).
func (q *Queue) Ack(id string, seq uint64, ok bool) bool {
	n := q.nodes[id]
	if n == nil {
		return false
	}
	if seq > q.latest || seq > q.Cursor(id) {
		return false
	}
	if seq > n.acked {
		n.acked = seq
	}
	for _, h := range q.holds {
		if h.canary == id && h.applied.IsZero() && seq >= h.seq {
			if ok {
				h.applied, h.base = q.cfg.Now(), n.health.Quarantined
			} else {
				h.bad = true
			}
		}
	}
	q.recompute()
	return true
}

// Heartbeat records what a heartbeat said. A new quarantine or an unhealthy resolve path of the canary after it applied a
// catalog entry ends the chance of an early release; the cap releases it (a canary failure only alerts, R18).
func (q *Queue) Heartbeat(id string, hl Health) {
	n := q.nodes[id]
	if n == nil {
		return
	}
	n.health = hl
	for _, h := range q.holds {
		if h.canary != id || h.applied.IsZero() {
			continue
		}
		h.beat = true
		if !hl.ResolveHealthy || hl.Quarantined > h.base {
			h.bad = true
		}
	}
	q.recompute()
}

// Release is the highest seq every node may read, once the stagger is over.
func (q *Queue) Release() uint64 { q.recompute(); return q.release }

// Cursor is how far the node may read: the lower of the release point and its place in the order. The canary of a held
// catalog entry may read up to it and no further.
func (q *Queue) Cursor(id string) uint64 {
	q.recompute()
	n := q.nodes[id]
	if n == nil {
		return q.release
	}
	limit := n.cursor
	for _, h := range q.holds {
		if h.canary == id {
			limit = max(limit, min(h.seq, q.canaryTop(h)))
			break
		}
	}
	return limit
}

// canaryTop is the highest seq the canary may read: the held entry itself and nothing behind it.
func (q *Queue) canaryTop(h *held) uint64 { return h.seq }

// Held lists the catalog entries still held, for the admin page and the alert of a failed canary.
func (q *Queue) Held() []uint64 {
	q.recompute()
	out := make([]uint64, len(q.holds))
	for i, h := range q.holds {
		out[i] = h.seq
	}
	return out
}

// recompute releases what is due and moves the cursors. It is a function of the state and the clock.
func (q *Queue) recompute() {
	now := q.cfg.Now()
	kept := q.holds[:0]
	for _, h := range q.holds {
		// The soak ends early only for a canary that heartbeat after it applied and still has its stream: one that applied the
		// entry and stopped (a crash on the first lookup, a closed stream) is released by the cap like any silent canary.
		c := q.nodes[h.canary]
		soaked := !h.applied.IsZero() && !h.bad && h.beat && c != nil && c.stream && now.Sub(h.applied) >= q.cfg.Soak
		if soaked || now.Sub(h.written) >= q.cfg.Cap {
			continue
		}
		kept = append(kept, h)
	}
	q.holds = kept
	sort.Slice(q.holds, func(i, j int) bool { return q.holds[i].seq < q.holds[j].seq })
	q.release = q.latest
	if len(q.holds) > 0 {
		q.release = q.holds[0].seq - 1
	}
	// The cursors: the first node reads up to the release point; each next one waits for the one before to ack the seq
	// or Stagger to pass since that one's cursor reached it, and a node without a stream does not hold the queue.
	prev := q.release
	for i, id := range q.order {
		n := q.nodes[id]
		if n == nil {
			continue
		}
		target := prev
		if i > 0 {
			p := q.nodes[q.order[i-1]]
			if p != nil && p.stream {
				ok := p.acked
				for _, s := range p.steps {
					if now.Sub(s.at) >= q.cfg.Stagger && s.seq > ok {
						ok = s.seq
					}
				}
				target = min(target, ok)
			}
		}
		target = max(target, min(n.acked, q.release))
		if target > n.cursor {
			n.cursor = target
			n.steps = append(n.steps, step{seq: target, at: now})
			if len(n.steps) > 64 {
				n.steps = n.steps[len(n.steps)-64:]
			}
		}
		prev = n.cursor
		if !n.stream {
			// Its own place in the order is still kept, but the next node is gated by what this node's cursor was
			// allowed to reach, not by an ack that cannot come.
			prev = max(prev, target)
		}
	}
}
