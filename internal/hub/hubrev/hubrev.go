// Package hubrev sends the Revocations of p4-nodes 5.5 and keeps them until every node has caught up.
//
// A Revocation is the priority channel for the changes that must not wait for the node-by-node rollout (an Endpoint turned
// hard-disabled, a rotated resolver id or token, a deleted Endpoint or claim). The log stays the one source of what changed, so
// no table holds a Revocation: they live here, in memory, and a hub restart loses them (the recorded limitation of SC 10.4).
//
// The rules, each from 5.5:
//   - it goes to every connected node when the entry is read, before any node's rollout reaches that entry;
//   - it goes to every stream that opens meanwhile, after the first ServerTime;
//   - it is kept until every non-revoked node has reported an applied_seq at or above its rev_seq, and sent again with a fresh
//     expiry every 5 minutes to each connected node whose latest Heartbeat is still below it (a node whose transfers fail while
//     Control lives stays revoked);
//   - once a node is 60 s behind a rev_seq the hub alerts, and Pending says so for the node's page.
package hubrev

import (
	"log/slog"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"

	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubview"
	"github.com/Kup1ng/CtrlZ-Panel/internal/logattr"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// The numbers of 5.5.
const (
	// Life is how long a sent Revocation stays valid on a node (D31).
	Life = 15 * time.Minute
	// Resend is how often a lagging connected node is sent it again.
	Resend = 5 * time.Minute
	// Behind is how late a node may be before the hub alerts.
	Behind = 60 * time.Second
	// Keep bounds the Revocations held. A node that never comes back would hold its revocations for ever, so the oldest are let
	// go past this many, and counted.
	Keep = 4096
	// KeepBytes bounds the ids held as well: one Revocation can carry 100,000 ids, so the count alone does not bound memory.
	KeepBytes = 64 << 20
	// SendBudget is the most one send pass (a stream opening, a Tick) puts on one node's queue. The queue is 4 MiB and a put that
	// does not fit ends the stream, so a node that is behind by many large Revocations would end its stream on every open and meet
	// the same burst again. What a pass leaves out is sent by the next Tick, which has no stream to end for it.
	SendBudget = 1 << 20
)

// Sender puts a message on a node's stream. Send says whether the node has one; Broadcast reaches every stream.
type Sender interface {
	Send(node uuid.UUID, m *hubv1.HubMessage) bool
	Broadcast(m *hubv1.HubMessage)
}

// Nodes says which nodes have to catch up and how far each has: the non-revoked nodes of the latest membership, and the
// applied_seq of the latest Heartbeat of each (0 for a node that sent none).
type Nodes interface {
	// Pending lists the non-revoked nodes of the hub's latest membership.
	Pending() []uuid.UUID
	// Applied is the applied_seq of the node's latest Heartbeat, false for a node not heard from.
	Applied(node uuid.UUID) (uint64, bool)
}

type item struct {
	size    int // the ids' bytes, for KeepBytes and SendBudget
	seq     uint64
	kind    policyv1.RevocationKind
	ids     [][]byte
	at      time.Time
	sent    map[uuid.UUID]time.Time
	alerted map[uuid.UUID]bool
}

// Keeper holds the outstanding Revocations.
type Keeper struct {
	send  Sender
	nodes Nodes
	now   func() time.Time
	alert func(sev string, kind store.HubAlertKind, params map[string]string)
	log   *slog.Logger

	mu      sync.Mutex
	items   []*item
	dropped uint64
}

// New makes a Keeper. alert may be nil.
func New(send Sender, nodes Nodes, now func() time.Time, alert func(string, store.HubAlertKind, map[string]string), log *slog.Logger) *Keeper {
	return &Keeper{send: send, nodes: nodes, now: now, alert: alert, log: log}
}

func (k *Keeper) message(it *item, now time.Time) *hubv1.HubMessage {
	return &hubv1.HubMessage{Body: &hubv1.HubMessage_Revocation{Revocation: &policyv1.Revocation{
		RevSeq: it.seq, Kind: it.kind, Ids: it.ids, IssuedAt: now.Unix(), ExpiresAt: now.Add(Life).Unix(),
	}}}
}

// Add keeps the Revocations an entry derived and sends them to every connected node. It is called by the log poll before the
// entry reaches the rollout, so each stream's writer has the Revocation ahead of any HeadNotice for that entry.
func (k *Keeper) Add(a hubview.Applied) {
	now := k.now()
	for _, r := range a.Revs {
		it := &item{seq: a.Seq, kind: r.Kind, ids: r.IDs, at: now, sent: map[uuid.UUID]time.Time{}, alerted: map[uuid.UUID]bool{}}
		for _, id := range r.IDs {
			it.size += len(id) + 4
		}
		k.mu.Lock()
		k.items = append(k.items, it)
		k.evict()
		k.mu.Unlock()
		k.send.Broadcast(k.message(it, now))
		// A node with a stream has it queued now; one without gets it when it opens (Opened). Recording the time here is what
		// makes the 5-minute resend count from the send and not from the first Tick.
		for _, n := range k.nodes.Pending() {
			if _, ok := k.nodes.Applied(n); ok {
				k.mu.Lock()
				it.sent[n] = now
				k.mu.Unlock()
			}
		}
	}
}

// evict lets the oldest Revocations go past Keep items or KeepBytes, always keeping the newest, and says so: a node that comes back
// after that is told only by the rollout. The caller holds the lock.
func (k *Keeper) evict() {
	total := 0
	for _, it := range k.items {
		total += it.size
	}
	n := 0
	for len(k.items)-n > Keep || (total > KeepBytes && len(k.items)-n > 1) {
		total -= k.items[n].size
		n++
	}
	if n == 0 {
		return
	}
	k.items = append([]*item(nil), k.items[n:]...)
	k.dropped += uint64(n)
	if k.log != nil {
		k.log.Warn("revocations let go: more are held than the bound allows", logattr.Int("dropped", n))
	}
}

// Opened sends a node that has just opened its stream the Revocations it has not applied, as the first thing after the first
// ServerTime, up to SendBudget; the next Tick sends the rest.
func (k *Keeper) Opened(node uuid.UUID) {
	now := k.now()
	applied, _ := k.nodes.Applied(node)
	k.mu.Lock()
	var out []*hubv1.HubMessage
	spent := 0
	for _, it := range k.items {
		if it.seq > applied {
			if spent > 0 && spent+it.size > SendBudget {
				// Add stamped it as sent to every node it heard; this node has not been sent it, so the next Tick does.
				delete(it.sent, node)
				continue
			}
			spent += it.size
			it.sent[node] = now
			out = append(out, k.message(it, now))
		}
	}
	k.mu.Unlock()
	for _, m := range out {
		k.send.Send(node, m)
	}
}

// Tick drops what every node has applied, sends again to the nodes that lag, and alerts for the ones 60 s behind.
func (k *Keeper) Tick() {
	now := k.now()
	nodes := k.nodes.Pending()
	k.mu.Lock()
	defer k.mu.Unlock()
	kept := k.items[:0]
	spent := map[uuid.UUID]int{}
	for _, it := range k.items {
		behind := false
		for _, n := range nodes {
			applied, heard := k.nodes.Applied(n)
			if heard && applied >= it.seq {
				continue
			}
			behind = true
			if heard && now.Sub(it.sent[n]) >= Resend {
				// A node is sent it again only while it has a stream: Send says so, and a node with none gets it when it opens.
				if spent[n] == 0 || spent[n]+it.size <= SendBudget {
					if k.send.Send(n, k.message(it, now)) {
						it.sent[n] = now
						spent[n] += it.size
					}
				}
			}
			if now.Sub(it.at) >= Behind && !it.alerted[n] {
				it.alerted[n] = true
				if k.alert != nil {
					k.alert("warning", store.HubAlertRevocationPending, map[string]string{"node": n.String(), "rev_seq": strconv.FormatUint(it.seq, 10)})
				}
			}
		}
		if behind {
			kept = append(kept, it)
		}
	}
	for i := len(kept); i < len(k.items); i++ {
		k.items[i] = nil
	}
	k.items = kept
}

// PendingFor is the highest rev_seq the node is 60 s or more behind, 0 when none: the node page shows "revocation pending" (R34).
func (k *Keeper) PendingFor(node uuid.UUID) uint64 {
	now := k.now()
	applied, _ := k.nodes.Applied(node)
	k.mu.Lock()
	defer k.mu.Unlock()
	var top uint64
	for _, it := range k.items {
		if it.seq > applied && now.Sub(it.at) >= Behind && it.seq > top {
			top = it.seq
		}
	}
	return top
}

// Held lists the rev_seqs still kept, for tests and the page.
func (k *Keeper) Held() []uint64 {
	k.mu.Lock()
	defer k.mu.Unlock()
	out := make([]uint64, 0, len(k.items))
	for _, it := range k.items {
		out = append(out, it.seq)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Dropped counts Revocations let go because more than Keep were held.
func (k *Keeper) Dropped() uint64 {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.dropped
}
