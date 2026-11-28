package zone

import (
	"net/netip"
	"testing"

	"github.com/Kup1ng/CtrlZ-Shared/netclass"
)

// fuzzAddrs are the addresses the fuzz input picks from: one of each class, an
// IPv4-mapped form and a bad length, so the mutator reaches every refusal.
func fuzzAddrs() [][]byte {
	a := func(s string) []byte { return netip.MustParseAddr(s).AsSlice() }
	return [][]byte{
		a("93.184.216.10"), a("93.184.216.11"), a("8.8.8.8"), a("2606:2800:220:1::1"), a("2606:2800:220:1::2"),
		a("10.0.0.1"), a("127.0.0.1"), a("169.254.0.1"), a("100.64.0.1"), a("224.0.0.1"), a("0.0.0.0"), a("10.10.34.1"),
		a("::ffff:93.184.216.10"), a("fd00::1"), a("::1"), {1, 2, 3}, nil,
	}
}

// decodeBuildInput turns bytes into a BuildInput: a structured decoder, so a
// mutation changes one field and the fuzzer explores the refusals instead of
// failing every input on a length byte.
func decodeBuildInput(data []byte) BuildInput {
	pos := 0
	next := func() byte {
		if pos >= len(data) {
			return 0
		}
		b := data[pos]
		pos++
		return b
	}
	id := func(sel byte) []byte {
		switch {
		case sel%16 == 15:
			return nil
		case sel%16 == 14:
			return []byte{1, 2}
		}
		b := make([]byte, 16)
		b[0] = sel%16 + 1
		return b
	}
	addrs := fuzzAddrs()
	var in BuildInput
	in.Version = uint64(next())
	for i, n := 0, int(next()%7); i < n; i++ {
		fl := next()
		in.Nodes = append(in.Nodes, BuildNode{
			ID: id(next()), DNSIP: addrs[int(next())%len(addrs)], Slot: uint32(next() % 7),
			Revoked: fl&1 != 0, Withdrawn: fl&2 != 0,
		})
	}
	for i, n := 0, int(next()%20); i < n; i++ {
		in.Pairs = append(in.Pairs, BuildPair{ID: id(next()), Primary: id(next()), Fallback: id(next())})
	}
	in.Global = id(next())
	return in
}

// FuzzZoneBuild: Build refuses an input or turns it into a table that passes
// the checks 8a.2 says it repeats, and Target never panics or leaves the pair.
func FuzzZoneBuild(f *testing.F) {
	f.Add([]byte{})
	// Two nodes, one pair, the pair is the global pair.
	f.Add([]byte{1, 2, 0, 0, 0, 1, 0, 1, 0, 1, 2, 1, 0, 1, 0, 1, 1, 0})
	f.Add([]byte{1, 3, 0, 0, 0, 1, 0, 1, 0, 1, 2, 1, 0, 1, 0, 2, 0, 3, 0, 2, 1, 1, 0, 1, 1, 0})
	f.Add([]byte{9, 2, 3, 5, 5, 3, 3, 4, 4, 2, 2, 2, 1, 5, 6, 7, 8, 9, 1, 2, 3})
	f.Fuzz(func(t *testing.T, data []byte) {
		in := decodeBuildInput(data)
		tb, err := Build(in)
		if err != nil {
			return
		}
		slots := map[uint8]bool{}
		addrs := map[netip.Addr]bool{}
		for id, n := range tb.Nodes {
			if n.ID != id || n.Slot < 1 || n.Slot > MaxNodes || slots[n.Slot] || addrs[n.DNSIP] {
				t.Fatalf("node %v breaks the slot or address rules", id)
			}
			slots[n.Slot], addrs[n.DNSIP] = true, true
			c := netclass.ClassOf(n.DNSIP)
			if n.DNSIP.Is4In6() || !(c == netclass.Public || (c == netclass.Private && netclass.AllowPrivatePairAddrs)) {
				t.Fatalf("node %v has the address %v of class %v", id, n.DNSIP, c)
			}
		}
		peer := map[NodeID]NodeID{}
		for _, p := range tb.Pairs {
			pn, ok := tb.Nodes[p.Primary]
			if !ok || (p.HasFallback && p.Primary == p.Fallback) {
				t.Fatalf("pair %v names a bad primary", p.ID)
			}
			if !p.HasFallback {
				continue
			}
			fn, ok := tb.Nodes[p.Fallback]
			if !ok || pn.DNSIP.Is4() != fn.DNSIP.Is4() {
				t.Fatalf("pair %v mixes families or names a bad fallback", p.ID)
			}
			for _, x := range [][2]NodeID{{p.Primary, p.Fallback}, {p.Fallback, p.Primary}} {
				if old, ok := peer[x[0]]; ok && old != x[1] {
					t.Fatalf("node %v has two peers", x[0])
				}
				peer[x[0]] = x[1]
			}
		}
		if len(tb.Pairs) == 0 {
			if tb.Global != (PairID{}) {
				t.Fatal("a global pair with no pairs")
			}
		} else if _, ok := tb.Pairs[tb.Global]; !ok {
			t.Fatal("the global pair is not a pair of the table")
		}
		// Target answers a node of the pair, whatever the local view.
		for pairID, p := range tb.Pairs {
			for _, stale := range []bool{false, true} {
				down := map[NodeID]bool{p.Primary: true, p.Fallback: true}
				for _, self := range []NodeID{p.Primary, p.Fallback, {}} {
					n, ok := Target(tb, pairID, Local{Self: self, PanelStale: stale, PeerDown: down})
					if !ok || (n.ID != p.Primary && !(p.HasFallback && n.ID == p.Fallback)) {
						t.Fatalf("Target left the pair: %v ok=%v", n.ID, ok)
					}
				}
			}
		}
		_ = NameServers(tb)
	})
}
