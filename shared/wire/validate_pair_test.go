package wire

import (
	"bytes"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	commonv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/common/v1"
	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	"github.com/Kup1ng/CtrlZ-Shared/reason"
	"github.com/Kup1ng/CtrlZ-Shared/zone"
)

// goodTable is a valid two-node table with one pair, the base the cases mutate.
func goodTable() *policyv1.PairTable {
	return &policyv1.PairTable{
		Version: 0, GlobalPairId: b(16, 0xA1),
		Nodes: []*policyv1.NodeEntry{
			{NodeId: b(16, 1), DnsIp: []byte{5, 160, 0, 1}, ProxyIp: []byte{5, 160, 0, 2}, SpkiSha256: b(32, 1), Slot: 1},
			{NodeId: b(16, 2), DnsIp: []byte{5, 160, 1, 1}, ProxyIp: []byte{5, 160, 1, 2}, SpkiSha256: b(32, 2), Slot: 2},
		},
		Pairs: []*policyv1.Pair{{PairId: b(16, 0xA1), Primary: b(16, 1), Fallback: b(16, 2)}},
	}
}

func TestZoneInputIsAFieldCopy(t *testing.T) {
	pt := goodTable()
	pt.Version = 9
	pt.Nodes[1].SpkiSha256 = nil
	pt.Nodes[0].DnsWithdrawn = true
	in := ZoneInput(pt)
	if in.Version != 9 || !bytes.Equal(in.Global, pt.GlobalPairId) || len(in.Nodes) != 2 || len(in.Pairs) != 1 {
		t.Fatalf("copy: %+v", in)
	}
	if !in.Nodes[0].Withdrawn || in.Nodes[0].Revoked || !in.Nodes[1].Revoked || in.Nodes[1].Withdrawn {
		t.Errorf("flags: %+v", in.Nodes)
	}
	if in.Nodes[1].Slot != 2 || !bytes.Equal(in.Nodes[1].DNSIP, []byte{5, 160, 1, 1}) {
		t.Errorf("node 2: %+v", in.Nodes[1])
	}
	// No checks of its own: a bad node is copied, Build and the validator judge it.
	bad := &policyv1.PairTable{Nodes: []*policyv1.NodeEntry{{NodeId: []byte{1}}}}
	if got := ZoneInput(bad); len(got.Nodes) != 1 || len(got.Nodes[0].ID) != 1 {
		t.Errorf("a bad node was changed: %+v", got)
	}
	if got := ZoneInput(nil); len(got.Nodes) != 0 || got.Version != 0 {
		t.Errorf("nil: %+v", got)
	}
}

// What ValidatePairTable accepts, zone.Build builds, and the other way round for
// the fields Build carries (8a.4, Valid table). One phrase runs through both.
func TestValidatePairTableAndBuildAgree(t *testing.T) {
	v6 := []byte{0x2a, 0x00, 0x14, 0x50, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	mapped := func(last2 ...byte) []byte {
		return append([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 5, 160}, last2...)
	}
	node3 := func(p *policyv1.PairTable, i byte) {
		p.Nodes = append(p.Nodes, &policyv1.NodeEntry{NodeId: b(16, i), DnsIp: []byte{5, 160, i, 1}, ProxyIp: []byte{5, 160, i, 2}, SpkiSha256: b(32, i), Slot: uint32(i)})
	}
	cases := []struct {
		name  string
		m     func(*policyv1.PairTable)
		ok    bool
		build bool // false for the fields BuildInput does not carry
		text  string
	}{
		{"good", nil, true, true, ""},
		{"no pair, empty global", func(p *policyv1.PairTable) { p.Pairs, p.GlobalPairId = nil, nil }, true, true, ""},
		{"no node at all", func(p *policyv1.PairTable) { *p = policyv1.PairTable{} }, true, true, ""},
		{"global absent from pairs", func(p *policyv1.PairTable) { p.GlobalPairId = b(16, 0xEE) }, false, true, "global_pair_id: must name a pair of the table"},
		{"empty global beside a pair", func(p *policyv1.PairTable) { p.GlobalPairId = nil }, false, true, "global_pair_id: must name a pair of the table"},
		{"primary equals fallback", func(p *policyv1.PairTable) { p.Pairs[0].Fallback = b(16, 1) }, false, true, "primary equals fallback"},
		{"no fallback", func(p *policyv1.PairTable) { p.Pairs[0].Fallback = nil }, true, true, ""},
		{"two peers", func(p *policyv1.PairTable) {
			node3(p, 3)
			p.Pairs = append(p.Pairs, &policyv1.Pair{PairId: b(16, 0xA2), Primary: b(16, 1), Fallback: b(16, 3)})
		}, false, true, "node has two pair peers"},
		{"pairs (A,B) and (B,A)", func(p *policyv1.PairTable) {
			p.Pairs = append(p.Pairs, &policyv1.Pair{PairId: b(16, 0xA2), Primary: b(16, 2), Fallback: b(16, 1)})
		}, true, true, ""},
		{"loopback dns_ip", func(p *policyv1.PairTable) { p.Nodes[0].DnsIp = []byte{127, 0, 0, 1} }, false, true, "dns_ip: address class"},
		{"multicast dns_ip", func(p *policyv1.PairTable) { p.Nodes[0].DnsIp = []byte{224, 0, 0, 1} }, false, true, "dns_ip: address class"},
		{"link-local dns_ip", func(p *policyv1.PairTable) { p.Nodes[0].DnsIp = []byte{169, 254, 1, 1} }, false, true, "dns_ip: address class"},
		{"CGNAT dns_ip", func(p *policyv1.PairTable) { p.Nodes[0].DnsIp = []byte{100, 64, 0, 1} }, false, true, "dns_ip: address class"},
		{"unspecified dns_ip", func(p *policyv1.PairTable) { p.Nodes[0].DnsIp = []byte{0, 0, 0, 0} }, false, true, "dns_ip: address class"},
		{"reserved dns_ip", func(p *policyv1.PairTable) { p.Nodes[0].DnsIp = []byte{240, 0, 0, 1} }, false, true, "dns_ip: address class"},
		{"injected dns_ip", func(p *policyv1.PairTable) { p.Nodes[0].DnsIp = []byte{10, 10, 34, 5} }, false, true, "dns_ip: address class"},
		{"IPv4-mapped dns_ip", func(p *policyv1.PairTable) { p.Nodes[0].DnsIp = mapped(0, 1) }, false, true, "dns_ip: IPv4-mapped address"},
		{"3-byte dns_ip", func(p *policyv1.PairTable) { p.Nodes[0].DnsIp = []byte{5, 160, 0} }, false, true, "dns_ip: must be 4 or 16 bytes"},
		{"loopback proxy_ip", func(p *policyv1.PairTable) { p.Nodes[0].ProxyIp = []byte{127, 0, 0, 1} }, false, false, "proxy_ip: address class"},
		{"IPv4-mapped proxy_ip", func(p *policyv1.PairTable) { p.Nodes[0].ProxyIp = mapped(0, 2) }, false, false, "proxy_ip: IPv4-mapped address"},
		{"shared dns_ip", func(p *policyv1.PairTable) { p.Nodes[1].DnsIp = p.Nodes[0].DnsIp }, false, true, "dns_ip: duplicate dns_ip"},
		{"shared proxy_ip is allowed", func(p *policyv1.PairTable) { p.Nodes[1].ProxyIp = p.Nodes[0].ProxyIp }, true, true, ""},
		{"mixed families", func(p *policyv1.PairTable) { p.Nodes[1].DnsIp = v6 }, false, true, "primary and fallback of a pair have different address families"},
		{"slot 0", func(p *policyv1.PairTable) { p.Nodes[0].Slot = 0 }, false, true, "slot: must be 1 to 4"},
		{"slot 5", func(p *policyv1.PairTable) { p.Nodes[0].Slot = 5 }, false, true, "slot: must be 1 to 4"},
		{"one slot twice", func(p *policyv1.PairTable) { p.Nodes[1].Slot = 1 }, false, true, "slot: duplicate slot"},
		{"spki of 31 bytes", func(p *policyv1.PairTable) { p.Nodes[0].SpkiSha256 = make([]byte, 31) }, false, false, "spki_sha256"},
		{"empty spki is a revoked node", func(p *policyv1.PairTable) { p.Nodes[0].SpkiSha256 = nil }, true, true, ""},
		{"duplicate node_id", func(p *policyv1.PairTable) { p.Nodes[1].NodeId = b(16, 1) }, false, true, "duplicate node_id"},
		{"pair names an unknown node", func(p *policyv1.PairTable) { p.Pairs[0].Primary = b(16, 9) }, false, true, "pair names a node that is not in the table"},
		{"duplicate pair_id", func(p *policyv1.PairTable) {
			p.Pairs = append(p.Pairs, &policyv1.Pair{PairId: b(16, 0xA1), Primary: b(16, 2)})
		}, false, true, "duplicate pair_id"},
		{"five nodes", func(p *policyv1.PairTable) {
			for i := byte(3); i <= 5; i++ {
				node3(p, i)
			}
		}, false, true, "too many nodes or pairs"},
		{"bitmap too large", func(p *policyv1.PairTable) { p.Pairs[0].LocationBitmap = make([]byte, MaxBitmapBytes+1) }, false, false, "location_bitmap too large"},
	}
	for _, c := range cases {
		pt := goodTable()
		if c.m != nil {
			c.m(pt)
		}
		err := ValidatePairTable(pt)
		if (err == nil) != c.ok {
			t.Errorf("%s: ValidatePairTable = %v, want ok=%v", c.name, err, c.ok)
			continue
		}
		if err != nil && !strings.Contains(err.Error(), c.text) {
			t.Errorf("%s: error %q does not contain %q", c.name, err, c.text)
		}
		if c.build {
			_, berr := zone.Build(ZoneInput(pt))
			if (berr == nil) != c.ok {
				t.Errorf("%s: zone.Build = %v, want ok=%v", c.name, berr, c.ok)
			} else if berr != nil && !strings.Contains(berr.Error(), c.text) {
				t.Errorf("%s: Build error %q does not contain %q", c.name, berr, c.text)
			}
		}
	}
}

func TestValidatePairTablePushRefusesNil(t *testing.T) {
	if err := ValidatePairTable(nil); err != nil {
		t.Errorf("an entry without a table: %v", err)
	}
	if err := ValidatePairTablePush(nil); err == nil {
		t.Error("a push of nil was accepted")
	}
	if err := ValidatePairTablePush(goodTable()); err != nil {
		t.Errorf("good push: %v", err)
	}
	pt := goodTable()
	pt.Pairs[0].Primary = b(16, 9)
	if c := reason.CodeOf(ValidatePairTable(pt)); c != reason.IndexRange {
		t.Errorf("code %v, want index_range", c)
	}
}

func marshalView(t testing.TB, v *hubv1.PeerView) []byte {
	t.Helper()
	raw, err := proto.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestValidatePeerView(t *testing.T) {
	v, err := ValidatePeerView(nil)
	if err != nil || v == nil || len(v.Peers) != 0 {
		t.Fatalf("empty bytes: %v %v", v, err)
	}
	peer := func(i byte, known, down bool) *hubv1.PeerProbe {
		return &hubv1.PeerProbe{NodeId: b(16, i), Known: known, Down: down}
	}
	ok := marshalView(t, &hubv1.PeerView{PairTableVersion: 7, Peers: []*hubv1.PeerProbe{peer(1, true, true), peer(2, false, false)}, LastRefusal: hubv1.PushRefusal_PUSH_REFUSAL_BUILD, Refusals: 3})
	got, err := ValidatePeerView(ok)
	if err != nil || got.PairTableVersion != 7 || got.Refusals != 3 || len(got.Peers) != 2 {
		t.Fatalf("good view: %v %v", got, err)
	}
	cases := map[string][]byte{
		"repeated node_id":      marshalView(t, &hubv1.PeerView{Peers: []*hubv1.PeerProbe{peer(1, true, false), peer(1, true, true)}}),
		"down with known false": marshalView(t, &hubv1.PeerView{Peers: []*hubv1.PeerProbe{peer(1, false, true)}}),
		"undefined refusal":     marshalView(t, &hubv1.PeerView{LastRefusal: hubv1.PushRefusal(7)}),
		"short node_id":         marshalView(t, &hubv1.PeerView{Peers: []*hubv1.PeerProbe{{NodeId: []byte{1}}}}),
		"five peers": marshalView(t, &hubv1.PeerView{Peers: []*hubv1.PeerProbe{
			peer(1, true, false), peer(2, true, false), peer(3, true, false), peer(4, true, false), peer(5, true, false)}}),
		"not protobuf": {0xff, 0xff, 0xff},
		"too large":    make([]byte, MaxPeerView+1),
	}
	for name, raw := range cases {
		if _, err := ValidatePeerView(raw); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestHeartbeatCarriesAPeerViewAndTheLocalUnbound(t *testing.T) {
	hb := func(mut func(*hubv1.Heartbeat)) *hubv1.Heartbeat {
		h := &hubv1.Heartbeat{BlobMajorMax: 1}
		if mut != nil {
			mut(h)
		}
		return h
	}
	local := LocalUnboundID()
	if err := ValidateHeartbeat(hb(func(h *hubv1.Heartbeat) {
		h.Upstreams = []*hubv1.UpstreamHealth{{Id: local[:], Healthy: true}, {Id: b(16, 5)}}
		h.PeerView = marshalView(t, &hubv1.PeerView{PairTableVersion: 1})
	})); err != nil {
		t.Errorf("good heartbeat: %v", err)
	}
	if err := ValidateHeartbeat(hb(nil)); err != nil {
		t.Errorf("a P0 node's empty peer_view: %v", err)
	}
	if ValidateHeartbeat(hb(func(h *hubv1.Heartbeat) {
		h.Upstreams = []*hubv1.UpstreamHealth{{Id: local[:]}, {Id: local[:]}}
	})) == nil {
		t.Error("two local Unbound entries accepted")
	}
	if ValidateHeartbeat(hb(func(h *hubv1.Heartbeat) { h.PeerView = []byte{0xff, 0xff} })) == nil {
		t.Error("a peer_view that is not a PeerView accepted")
	}
}

func TestNodeConfigRefusesTheReservedUpstreamID(t *testing.T) {
	local := LocalUnboundID()
	if local != [16]byte(bytes.Repeat([]byte{0xff}, 16)) {
		t.Fatal("LocalUnboundID is not the Max UUID")
	}
	c := &hubv1.NodeConfig{
		DnsBindIp: []byte{198, 51, 100, 1}, DnsAdvertisedIp: []byte{198, 51, 100, 1}, ProxyBindIp: []byte{198, 51, 100, 2}, ProxyAdvertisedIp: []byte{198, 51, 100, 2},
		Zones: []string{"dns.example.com"}, Mode: commonv1.ResolveMode_RESOLVE_MODE_UPSTREAM, ProofKey: b(32, 1),
		Upstreams: []*hubv1.Upstream{{Id: b(16, 1), Kind: commonv1.UpstreamKind_UPSTREAM_KIND_UDP, Address: "192.0.2.1:53", TimeoutMs: 1000}},
	}
	if err := ValidateNodeConfig(c); err != nil {
		t.Fatalf("good config: %v", err)
	}
	c.Upstreams = append(c.Upstreams, &hubv1.Upstream{Id: local[:], Kind: commonv1.UpstreamKind_UPSTREAM_KIND_UDP, Address: "192.0.2.2:53", TimeoutMs: 1000})
	if ValidateNodeConfig(c) == nil {
		t.Error("an Upstream with the local Unbound id was accepted")
	}
}

func TestFreeDnsValidators(t *testing.T) {
	for name, f := range map[string]*policyv1.FreeDns{
		"qps 0": {Enabled: true, Qps: 0, Version: 1}, "qps over": {Qps: MaxFreeQPS + 1, Version: 1}, "version 0": {Qps: 1000},
	} {
		if ValidateFreeDns(f) == nil {
			t.Errorf("%s accepted", name)
		}
		e := &policyv1.ConfigEntry{Seq: 1, Class: commonv1.EntryClass_ENTRY_CLASS_POLICY, PrevHash: make([]byte, 32), FreeDns: f}
		if ValidateEntry(e) == nil {
			t.Errorf("%s: an entry carrying it was accepted", name)
		}
	}
	for _, f := range []*policyv1.FreeDns{nil, {Enabled: false, Qps: 1, Version: 1}, {Enabled: true, Qps: MaxFreeQPS, Version: 1 << 60}} {
		if err := ValidateFreeDns(f); err != nil {
			t.Errorf("%v: %v", f, err)
		}
	}
	if ValidateFreeDnsOff(&hubv1.FreeDnsOff{}) == nil || ValidateFreeDnsOff(nil) == nil || ValidateFreeDnsOff(&hubv1.FreeDnsOff{Version: 1}) != nil {
		t.Error("FreeDnsOff version rule")
	}
}

// FuzzPeerView: any bytes either validate into a bounded, well-formed view that
// survives a round trip, or are refused; nothing panics (the bytes come from a node).
func FuzzPeerView(f *testing.F) {
	f.Add([]byte{})
	f.Add(marshalView(f, &hubv1.PeerView{PairTableVersion: 3, Peers: []*hubv1.PeerProbe{{NodeId: b(16, 1), Known: true, Down: true}}, LastRefusal: hubv1.PushRefusal_PUSH_REFUSAL_EXPIRED, Refusals: 1}))
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, data []byte) {
		v, err := ValidatePeerView(data)
		if err != nil {
			return
		}
		// What it accepts is bounded and well-formed, and survives a round trip.
		if len(v.Peers) > MaxNodes {
			t.Fatalf("%d peers", len(v.Peers))
		}
		seen := map[string]bool{}
		for _, p := range v.Peers {
			if len(p.NodeId) != 16 || seen[string(p.NodeId)] || (p.Down && !p.Known) {
				t.Fatalf("accepted a bad peer: %v", p)
			}
			seen[string(p.NodeId)] = true
		}
		raw, err := proto.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ValidatePeerView(raw); err != nil {
			t.Fatalf("an accepted view is refused after a round trip: %v", err)
		}
	})
}

// fixedMembership is the node's own membership from its applied log entry in
// FuzzPairTablePush: valid, with a pair, and a node outside every pair.
func fixedMembership() zone.BuildInput {
	return ZoneInput(&policyv1.PairTable{
		GlobalPairId: b(16, 0xA1),
		Nodes: []*policyv1.NodeEntry{
			{NodeId: b(16, 1), DnsIp: []byte{5, 160, 0, 1}, ProxyIp: []byte{5, 160, 0, 2}, SpkiSha256: b(32, 1), Slot: 1},
			{NodeId: b(16, 2), DnsIp: []byte{5, 160, 1, 1}, ProxyIp: []byte{5, 160, 1, 2}, SpkiSha256: b(32, 2), Slot: 2},
			{NodeId: b(16, 3), DnsIp: []byte{5, 160, 2, 1}, ProxyIp: []byte{5, 160, 2, 2}, SpkiSha256: nil, Slot: 3},
		},
		Pairs: []*policyv1.Pair{{PairId: b(16, 0xA1), Primary: b(16, 1), Fallback: b(16, 2)}},
	})
}

// FuzzPairTablePush: any envelope payload that decodes as a PairTable is judged by
// ValidatePairTablePush, and an accepted one has its version and withdrawal flags
// laid on a fixed log membership as 8a.4 Node apply, steps 3 and 4, do. zone.Build
// must not panic and must accept the result, because the membership is valid and
// only flags change. The node swaps the table in only after this succeeds.
func FuzzPairTablePush(f *testing.F) {
	pt := goodTable()
	pt.Version = 5
	pt.Nodes[0].DnsWithdrawn = true
	for _, p := range []*policyv1.PairTable{pt, goodTable(), {}} {
		raw, err := proto.Marshal(p)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(raw)
	}
	f.Add([]byte{0x08, 0xff})
	member := fixedMembership()
	var ids []zone.NodeID
	for _, n := range member.Nodes {
		ids = append(ids, zone.NodeID(n.ID))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var p policyv1.PairTable
		if proto.Unmarshal(data, &p) != nil {
			return
		}
		if ValidatePairTablePush(&p) != nil {
			return
		}
		flags := PushFlags(&p)
		fm := zone.FlagMap{}.Take(flags, ids)
		for id := range fm {
			if _, inPush := flags[id]; !inPush && id != ids[0] && id != ids[1] && id != ids[2] {
				t.Fatalf("a flag of %x is in neither the membership nor the push", id)
			}
		}
		tbl, err := zone.Build(zone.WithFlags(member, p.Version, fm))
		if err != nil {
			t.Fatalf("a valid membership with flags did not build: %v", err)
		}
		if tbl.Version != p.Version {
			t.Fatalf("version %d, want %d", tbl.Version, p.Version)
		}
		// Membership stays the log's: the push cannot add a node or revoke one.
		if len(tbl.Nodes) != len(ids) || !tbl.Nodes[zone.NodeID(b(16, 3))].Revoked || tbl.Nodes[zone.NodeID(b(16, 1))].Revoked {
			t.Fatal("the push changed the membership")
		}
	})
}

// A hostile node fills peer_view with the largest run of empty peer entries that
// fits under MaxPeerView. The refusal must come from the wire count, before
// proto.Unmarshal allocates a PeerProbe for each entry.
func TestValidatePeerViewRefusesManyPeersWithoutDecodingThem(t *testing.T) {
	flood := bytes.Repeat([]byte{0x12, 0x00}, MaxPeerView/2) // 32768 empty field-2 entries
	if _, err := ValidatePeerView(flood); err == nil {
		t.Fatal("a flood of empty peers accepted")
	}
	// Four entries stay valid as far as the count goes; the fifth is the refusal.
	four := bytes.Repeat([]byte{0x12, 0x00}, MaxNodes)
	if got := peerEntries(four); got != MaxNodes {
		t.Fatalf("peerEntries(four) = %d", got)
	}
	if got := peerEntries(append(four, 0x12, 0x00)); got != MaxNodes+1 {
		t.Fatalf("peerEntries(five) = %d", got)
	}
	// Other fields are not peers, and a buffer the walker cannot read is left to
	// Unmarshal, which refuses it.
	if peerEntries([]byte{0x08, 0x07}) != 0 || peerEntries([]byte{0xff}) != 0 {
		t.Error("peerEntries counted a field that is not a peer")
	}
	// The walk agrees with the decoder on a real view, other fields included.
	real := marshalView(t, &hubv1.PeerView{PairTableVersion: 300, Peers: []*hubv1.PeerProbe{{NodeId: b(16, 1), Known: true, Down: true}, {NodeId: b(16, 2)}, {NodeId: b(16, 3), Known: true}}, LastRefusal: hubv1.PushRefusal_PUSH_REFUSAL_BUILD, Refusals: 1 << 40})
	if got := peerEntries(real); got != 3 {
		t.Errorf("peerEntries(real) = %d, want 3", got)
	}
	if got := peerEntries([]byte{0x10, 0x01}); got != 0 { // field 2 as a varint is not a peer
		t.Errorf("a varint field 2 counted: %d", got)
	}
	// Few allocations: the old path made one per entry (about 32k).
	if a := testing.AllocsPerRun(5, func() { _, _ = ValidatePeerView(flood) }); a > 20 {
		t.Errorf("a refused flood cost %.0f allocations", a)
	}
}
