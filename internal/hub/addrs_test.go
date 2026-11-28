package hub

import (
	"net/netip"
	"testing"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// The reserved handshake set holds the last source of each node and forgets a node that is revoked or
// removed (5.1, W3-r1-8): without that, one address of a revoked node kept a place for as long as the
// hub ran.
func TestAddrSetKeepsOneSourcePerNodeAndForgetsRevokedNodes(t *testing.T) {
	s := newAddrSet()
	a, b := uuid.New(), uuid.New()
	one, two, three := netip.MustParseAddr("203.0.113.1"), netip.MustParseAddr("203.0.113.2"), netip.MustParseAddr("2001:db8::1")
	s.add(a, one)
	s.add(a, two)
	s.add(b, three)
	if s.has(one) || !s.has(two) || !s.has(three) {
		t.Fatalf("the last source of a node is the one kept: %v %v %v", s.has(one), s.has(two), s.has(three))
	}
	// Node a is revoked: the next pass lists only b, and a's source is gone with it.
	s.replace(store.HubAddrs{Nodes: []uuid.UUID{b}, Addrs: []netip.Addr{netip.MustParseAddr("198.51.100.4")}})
	if s.has(two) || !s.has(three) || !s.has(netip.MustParseAddr("198.51.100.4")) {
		t.Fatalf("after a revocation: %v %v", s.has(two), s.has(three))
	}
	// Many sources of one node never grow the set.
	for i := 0; i < 10_000; i++ {
		s.add(b, netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 1}))
	}
	if len(s.seen) != 1 {
		t.Fatalf("%d learned sources for one node", len(s.seen))
	}
}
