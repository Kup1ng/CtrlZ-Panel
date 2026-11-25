package zone

import (
	"fmt"
	"net/netip"

	"github.com/Kup1ng/CtrlZ-Shared/netclass"
)

// BuildNode is the plain form of a NodeEntry. Lengths and address classes are
// checked by Build.
type BuildNode struct {
	ID        []byte // NodeEntry.node_id, 16 bytes
	DNSIP     []byte // NodeEntry.dns_ip, 4 or 16 bytes
	Slot      uint32 // NodeEntry.slot, 1 to 4, unique
	Revoked   bool   // NodeEntry.spki_sha256 is empty
	Withdrawn bool   // the flag for this node_id (8a.4 Node apply, step 3), false when none
}

// BuildPair is the plain form of a Pair.
type BuildPair struct {
	ID, Primary, Fallback []byte // Fallback empty when the pair has none
}

// BuildInput is what wire.ZoneInput copies out of a PairTable. It carries
// neither proxy_ip nor the SPKI bytes: Target never reads them.
type BuildInput struct {
	Version uint64
	Nodes   []BuildNode
	Pairs   []BuildPair
	Global  []byte
}

// BuildError says which field of the input broke which rule. Msg is a stable
// phrase: the pair-table-validate vectors name it in error_contains, and
// wire.ValidatePairTable uses the same phrases, so one vector runs through
// both validators.
type BuildError struct {
	Field string
	Msg   string
}

func (e *BuildError) Error() string { return "zone: " + e.Field + ": " + e.Msg }

func bad(field, format string, a ...any) error {
	return &BuildError{Field: field, Msg: fmt.Sprintf(format, a...)}
}

// Build makes a Table from plain input. It repeats on the fields it carries
// the checks of wire.ValidatePairTable (8a.7), so no Table reaches Target with
// an address or a pair the validator would have refused. It never panics, on
// any input (FuzzZoneBuild).
func Build(in BuildInput) (*Table, error) {
	if len(in.Nodes) > MaxNodes || len(in.Pairs) > MaxPairs {
		return nil, bad("pair_table", "too many nodes or pairs")
	}
	t := &Table{Version: in.Version, Nodes: make(map[NodeID]Node, len(in.Nodes)), Pairs: make(map[PairID]Pair, len(in.Pairs))}
	slots := map[uint8]bool{}
	addrs := map[netip.Addr]bool{}
	for _, n := range in.Nodes {
		id, ok := id16(n.ID)
		if !ok {
			return nil, bad("node_id", "must be 16 bytes")
		}
		if _, dup := t.Nodes[NodeID(id)]; dup {
			return nil, bad("node_id", "duplicate node_id")
		}
		addr, err := PairAddr("dns_ip", n.DNSIP)
		if err != nil {
			return nil, err
		}
		if n.Slot < 1 || n.Slot > MaxNodes {
			return nil, bad("slot", "must be 1 to %d", MaxNodes)
		}
		if slots[uint8(n.Slot)] {
			return nil, bad("slot", "duplicate slot")
		}
		if addrs[addr] {
			return nil, bad("dns_ip", "duplicate dns_ip")
		}
		slots[uint8(n.Slot)] = true
		addrs[addr] = true
		t.Nodes[NodeID(id)] = Node{ID: NodeID(id), DNSIP: addr, Slot: uint8(n.Slot), Revoked: n.Revoked, Withdrawn: n.Withdrawn}
	}

	peers := map[NodeID]NodeID{}
	// pair adds a peer relation and refuses a second, different peer.
	pair := func(a, b NodeID) error {
		for _, x := range [][2]NodeID{{a, b}, {b, a}} {
			if old, ok := peers[x[0]]; ok && old != x[1] {
				return bad("pairs", "node has two pair peers")
			}
			peers[x[0]] = x[1]
		}
		return nil
	}
	for _, p := range in.Pairs {
		id, ok := id16(p.ID)
		if !ok {
			return nil, bad("pair_id", "must be 16 bytes")
		}
		if _, dup := t.Pairs[PairID(id)]; dup {
			return nil, bad("pair_id", "duplicate pair_id")
		}
		prim, ok := id16(p.Primary)
		if !ok {
			return nil, bad("primary", "must be 16 bytes")
		}
		pn, ok := t.Nodes[NodeID(prim)]
		if !ok {
			return nil, bad("pairs", "pair names a node that is not in the table")
		}
		pr := Pair{ID: PairID(id), Primary: NodeID(prim)}
		if len(p.Fallback) != 0 {
			fb, ok := id16(p.Fallback)
			if !ok {
				return nil, bad("fallback", "must be 16 bytes or empty")
			}
			fn, ok := t.Nodes[NodeID(fb)]
			if !ok {
				return nil, bad("pairs", "pair names a node that is not in the table")
			}
			if prim == fb {
				return nil, bad("pairs", "primary equals fallback")
			}
			// Invariant 2: the answer for an A or AAAA query is always an
			// address of the pair's one family.
			if pn.DNSIP.Is4() != fn.DNSIP.Is4() {
				return nil, bad("dns_ip", "primary and fallback of a pair have different address families")
			}
			if err := pair(NodeID(prim), NodeID(fb)); err != nil {
				return nil, err
			}
			pr.Fallback, pr.HasFallback = NodeID(fb), true
		}
		t.Pairs[PairID(id)] = pr
	}

	// A table with no pair has an empty global pair; a table with a pair has
	// one that names it (8a.4 Valid table).
	switch {
	case len(in.Global) == 0 && len(in.Pairs) == 0:
	case len(in.Global) != 16:
		return nil, bad("global_pair_id", "must name a pair of the table")
	default:
		g := PairID(in.Global)
		if _, ok := t.Pairs[g]; !ok {
			return nil, bad("global_pair_id", "must name a pair of the table")
		}
		t.Global = g
	}
	return t, nil
}

func id16(b []byte) ([16]byte, bool) {
	var id [16]byte
	if len(b) != 16 {
		return id, false
	}
	copy(id[:], b)
	return id, true
}

// PairAddr checks the address field of a node (field is "dns_ip" or "proxy_ip", the
// name an error carries): 4 bytes for IPv4 (an IPv4-mapped 16-byte form is
// refused, so one address has one encoding), 16 for IPv6, and a Public class.
// Private is accepted only in a lab build (netclass.AllowPrivatePairAddrs).
// wire.ValidatePairTable calls it for proxy_ip too, so one rule serves both.
func PairAddr(field string, b []byte) (netip.Addr, error) {
	var a netip.Addr
	switch len(b) {
	case 4:
		a = netip.AddrFrom4([4]byte(b))
	case 16:
		a = netip.AddrFrom16([16]byte(b))
		if a.Is4In6() {
			return netip.Addr{}, bad(field, "IPv4-mapped address")
		}
	default:
		return netip.Addr{}, bad(field, "must be 4 or 16 bytes")
	}
	switch c := netclass.ClassOf(a); {
	case c == netclass.Public:
	case c == netclass.Private && netclass.AllowPrivatePairAddrs:
	default:
		return netip.Addr{}, bad(field, "address class %s is not allowed", c)
	}
	return a, nil
}
