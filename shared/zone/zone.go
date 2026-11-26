// Package zone is the pure core of the Endpoint hostname zone and of pair
// failover (contract section 8a): which address an Endpoint hostname answers
// (Target), which nodes are name servers (NameServers), and the whole failover
// decision as data (Rows, Inputs) with the evaluator that runs it.
//
// It is pure like the rest of the module: no clock, no I/O, no goroutines.
// Every function takes the time and the reported values as arguments. It
// imports only netclass and the standard library, never gen or wire, so the
// hub and the node's local mode share one implementation and a node can run
// the same vectors (section 1).
package zone

import (
	"net/netip"
	"sort"
)

// MaxNodes is the number of node slots of a zone (D25). It equals
// wire.MaxNodes; zone cannot import wire, and TestZoneLimitsMatchWire in wire
// keeps them equal.
const MaxNodes = 4

// MaxPairs bounds the pairs of a table: every ordered pair of nodes, which is
// the most that "each node has at most one peer" lets a four-node table hold
// (wire.ValidatePairTable uses the same bound).
const MaxPairs = MaxNodes * MaxNodes

// HostTTL is the TTL of an Endpoint hostname answer, in seconds (8a.3).
const HostTTL = 30

// NSTTL is the TTL of the apex NS and of the ns1 to ns4 addresses, in seconds.
const NSTTL = 3600

// NodeID is NodeEntry.node_id.
type NodeID [16]byte

// PairID is Pair.pair_id.
type PairID [16]byte

// Node is one node of a table.
type Node struct {
	ID        NodeID
	DNSIP     netip.Addr
	Slot      uint8 // 1 to MaxNodes, names the node's name server ns<Slot> (8a.3)
	Revoked   bool  // NodeEntry.spki_sha256 is empty (8a.4, Versions)
	Withdrawn bool  // this node's flag for ID, by 8a.4 Node apply, step 3
}

// Pair is one pair of a table.
type Pair struct {
	ID          PairID
	Primary     NodeID
	Fallback    NodeID
	HasFallback bool
}

// Table is what Target reads. Build is the only way to make one that has
// passed the checks of 8a.7, and a Table is never changed after it is built:
// the node swaps a new one in, so a reader needs no lock.
type Table struct {
	Version uint64 // the push version the withdrawal flags came from, 0 before any push
	Nodes   map[NodeID]Node
	Pairs   map[PairID]Pair
	Global  PairID
}

// Local is a node's own view, used while the panel is unreachable (8a.5).
type Local struct {
	Self       NodeID
	PanelStale bool            // 8a.5
	PeerDown   map[NodeID]bool // 8a.5, this node's own view after hysteresis
}

// Target returns the node whose address an Endpoint hostname of pair answers
// with (8a.2), or false when the node must answer REFUSED for the name.
//
// Steps 1 and 2 are the callers' contract: a nil table is "no table in use".
// Step 2's rule, an unknown pair is the global pair, exists so the zone is not
// an existence oracle for resolver ids (R29): the caller passes whatever
// pair_id it has, or the zero PairID, and gets the same shape of answer.
func Target(t *Table, pair PairID, l Local) (Node, bool) {
	if t == nil {
		return Node{}, false
	}
	p, ok := t.Pairs[pair]
	if !ok {
		p, ok = t.Pairs[t.Global]
		if !ok {
			return Node{}, false
		}
	}
	primary, ok := t.Nodes[p.Primary]
	if !ok {
		// Build never makes such a table. A hand-made one is refused here
		// rather than answered with a zero address.
		return Node{}, false
	}
	var fallback Node
	hasFallback := false
	if p.HasFallback {
		fallback, hasFallback = t.Nodes[p.Fallback]
	}

	// A local view only moves an answer between two nodes that the hub left
	// both advertisable, and never undoes a hub withdrawal (8a.5): it applies
	// to a node other than this one, and only while the panel is stale.
	down := func(n Node) bool {
		return n.Revoked || n.Withdrawn || (l.PanelStale && n.ID != l.Self && l.PeerDown[n.ID])
	}
	if !down(primary) {
		return primary, true
	}
	if hasFallback && !down(fallback) {
		return fallback, true
	}
	// Both are down. Invariant 2 still wants an address of the pair, and G1 of
	// 8a.9 wants it not to be a revoked node, whatever flags this node holds.
	// A hub withdrawal comes next, and then only both-withdrawn is left: that
	// state exists on a node still behind a membership rollout, and it answers
	// the primary.
	if hasFallback {
		switch {
		case primary.Revoked != fallback.Revoked:
			if primary.Revoked {
				return fallback, true
			}
			return primary, true
		case primary.Withdrawn != fallback.Withdrawn:
			if primary.Withdrawn {
				return fallback, true
			}
			return primary, true
		}
	}
	return primary, true
}

// NameServers returns the nodes that are not revoked, in slot order (8a.3).
// The apex NS RRset and the ns1 to ns4 addresses are exactly this list and do
// not change with failover.
func NameServers(t *Table) []Node {
	if t == nil {
		return nil
	}
	out := make([]Node, 0, len(t.Nodes))
	for _, n := range t.Nodes {
		if !n.Revoked {
			out = append(out, n)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Slot < out[j].Slot })
	return out
}

// PeerOf returns the pair peer of a node: the other node of the pair it is in.
// A node has at most one peer (8a.7), and a pair without a fallback gives none.
func (t *Table) PeerOf(id NodeID) (NodeID, bool) {
	if t == nil {
		return NodeID{}, false
	}
	for _, p := range t.Pairs {
		if !p.HasFallback {
			continue
		}
		switch id {
		case p.Primary:
			return p.Fallback, true
		case p.Fallback:
			return p.Primary, true
		}
	}
	return NodeID{}, false
}
