package zone

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Shared/netclass"
)

func nid(c byte) NodeID { return NodeID{c} }
func pid(c byte) PairID { return PairID{c} }

func idb(c byte) []byte {
	if c == 0 {
		return nil
	}
	b := make([]byte, 16)
	b[0] = c
	return b
}

func bp(p, a, b byte) BuildPair { return BuildPair{ID: idb(p), Primary: idb(a), Fallback: idb(b)} }

// tbl builds a table with nodes A, B, C (ids 'A', 'B', 'C', slots 1 to 3, public
// addresses) and the given pairs; the global pair is the first.
func tbl(t *testing.T, flags map[byte]string, pairs ...BuildPair) *Table {
	t.Helper()
	in := BuildInput{Global: pairs[0].ID, Pairs: pairs}
	for i, c := range []byte("ABC") {
		n := BuildNode{ID: idb(c), DNSIP: []byte{93, 184, 216, byte(10 + i)}, Slot: uint32(i + 1)}
		n.Revoked = strings.Contains(flags[c], "r")
		n.Withdrawn = strings.Contains(flags[c], "w")
		in.Nodes = append(in.Nodes, n)
	}
	tb, err := Build(in)
	if err != nil {
		t.Fatal(err)
	}
	return tb
}

func TestTarget(t *testing.T) {
	down := func(c byte) map[NodeID]bool { return map[NodeID]bool{nid(c): true} }
	cases := []struct {
		name  string
		flags map[byte]string
		local Local
		want  byte
	}{
		{"primary healthy", nil, Local{}, 'A'},
		{"primary withdrawn", map[byte]string{'A': "w"}, Local{}, 'B'},
		{"fallback withdrawn", map[byte]string{'B': "w"}, Local{}, 'A'},
		{"both withdrawn", map[byte]string{'A': "w", 'B': "w"}, Local{}, 'A'},
		{"local mode primary down seen from fallback", nil, Local{Self: nid('B'), PanelStale: true, PeerDown: down('A')}, 'B'},
		{"local mode from a third node", nil, Local{Self: nid('C'), PanelStale: true, PeerDown: down('A')}, 'B'},
		{"local mode primary sees itself down", nil, Local{Self: nid('A'), PanelStale: true, PeerDown: down('A')}, 'A'},
		{"peer down ignored while the panel is fresh", nil, Local{Self: nid('B'), PeerDown: down('A')}, 'A'},
		{"a local view never undoes a hub withdrawal", map[byte]string{'A': "w"}, Local{Self: nid('C'), PanelStale: true, PeerDown: down('B')}, 'B'},
		{"fallback withdrawn, primary peer down", map[byte]string{'B': "w"}, Local{Self: nid('C'), PanelStale: true, PeerDown: down('A')}, 'A'},
		{"revoked primary, no flags", map[byte]string{'A': "r"}, Local{}, 'B'},
		{"revoked primary, fallback peer down", map[byte]string{'A': "r"}, Local{Self: nid('C'), PanelStale: true, PeerDown: down('B')}, 'B'},
		{"revoked fallback, primary peer down", map[byte]string{'B': "r"}, Local{Self: nid('C'), PanelStale: true, PeerDown: down('A')}, 'A'},
		{"revoked primary beside withdrawn fallback", map[byte]string{'A': "r", 'B': "w"}, Local{}, 'B'},
		{"withdrawn primary beside revoked fallback", map[byte]string{'A': "w", 'B': "r"}, Local{}, 'A'},
		{"both revoked", map[byte]string{'A': "r", 'B': "r"}, Local{}, 'A'},
	}
	for _, c := range cases {
		tb := tbl(t, c.flags, bp('p', 'A', 'B'))
		got, ok := Target(tb, pid('p'), c.local)
		if !ok || got.ID != nid(c.want) {
			t.Errorf("%s: got %q ok=%v, want %q", c.name, got.ID[0], ok, c.want)
		}
	}
	// No fallback: the primary, even when revoked.
	tb := tbl(t, map[byte]string{'A': "r"}, bp('p', 'A', 0))
	if n, ok := Target(tb, pid('p'), Local{}); !ok || n.ID != nid('A') {
		t.Errorf("pair with no fallback: %v %v", n.ID[0], ok)
	}
	// Unknown pair: the global pair. No table, or no global pair: false.
	tb = tbl(t, nil, bp('p', 'A', 'B'))
	if n, ok := Target(tb, pid('x'), Local{}); !ok || n.ID != nid('A') {
		t.Errorf("unknown pair: %v %v", n.ID[0], ok)
	}
	if _, ok := Target(nil, pid('p'), Local{}); ok {
		t.Error("nil table answered")
	}
	if _, ok := Target(&Table{}, pid('p'), Local{}); ok {
		t.Error("table with no pair answered")
	}
}

func TestNameServers(t *testing.T) {
	tb := tbl(t, map[byte]string{'B': "r"}, bp('p', 'A', 'B'))
	ns := NameServers(tb)
	if len(ns) != 2 || ns[0].Slot != 1 || ns[1].Slot != 3 {
		t.Fatalf("name servers: %+v", ns)
	}
	if NameServers(nil) != nil {
		t.Error("nil table has name servers")
	}
}

func TestPeerOf(t *testing.T) {
	tb := tbl(t, nil, bp('p', 'A', 'B'), bp('q', 'B', 'A'), bp('r', 'C', 0))
	if p, ok := tb.PeerOf(nid('A')); !ok || p != nid('B') {
		t.Error("A's peer")
	}
	if _, ok := tb.PeerOf(nid('C')); ok {
		t.Error("C has no peer")
	}
}

func TestBuildRefusals(t *testing.T) {
	good := func() BuildInput {
		return BuildInput{
			Nodes: []BuildNode{
				{ID: idb('A'), DNSIP: []byte{93, 184, 216, 10}, Slot: 1},
				{ID: idb('B'), DNSIP: []byte{93, 184, 216, 11}, Slot: 2},
				{ID: idb('C'), DNSIP: []byte{93, 184, 216, 12}, Slot: 3},
			},
			Pairs:  []BuildPair{bp('p', 'A', 'B')},
			Global: idb('p'),
		}
	}
	if _, err := Build(good()); err != nil {
		t.Fatalf("good input: %v", err)
	}
	v6 := netip.MustParseAddr("2606:2800:220:1::1").AsSlice()
	v6b := netip.MustParseAddr("2606:2800:220:1::2").AsSlice()
	mapped := netip.MustParseAddr("::ffff:93.184.216.10").AsSlice()
	ip := func(in *BuildInput, b ...byte) { in.Nodes[0].DNSIP = b }
	for name, c := range map[string]struct {
		mut  func(*BuildInput)
		want string
	}{
		"empty global beside a pair": {func(in *BuildInput) { in.Global = nil }, "global_pair_id"},
		"global not in pairs":        {func(in *BuildInput) { in.Global = idb('x') }, "global_pair_id"},
		"global of the wrong length": {func(in *BuildInput) { in.Global = []byte{1} }, "global_pair_id"},
		"primary equals fallback":    {func(in *BuildInput) { in.Pairs[0].Fallback = idb('A') }, "primary equals fallback"},
		"unknown fallback":           {func(in *BuildInput) { in.Pairs[0].Fallback = idb('z') }, "not in the table"},
		"two peers":                  {func(in *BuildInput) { in.Pairs = append(in.Pairs, bp('q', 'A', 'C')) }, "two pair peers"},
		"duplicate pair":             {func(in *BuildInput) { in.Pairs = append(in.Pairs, in.Pairs[0]) }, "duplicate pair_id"},
		"loopback":                   {func(in *BuildInput) { ip(in, 127, 0, 0, 1) }, "not allowed"},
		"multicast":                  {func(in *BuildInput) { ip(in, 224, 0, 0, 1) }, "not allowed"},
		"link local":                 {func(in *BuildInput) { ip(in, 169, 254, 1, 1) }, "not allowed"},
		"cgnat":                      {func(in *BuildInput) { ip(in, 100, 64, 0, 1) }, "not allowed"},
		"reserved":                   {func(in *BuildInput) { ip(in, 0, 0, 0, 0) }, "not allowed"},
		"injected":                   {func(in *BuildInput) { ip(in, 10, 10, 34, 1) }, "not allowed"},
		"ipv4 mapped":                {func(in *BuildInput) { in.Nodes[0].DNSIP = mapped }, "IPv4-mapped"},
		"address length":             {func(in *BuildInput) { ip(in, 1, 2, 3) }, "4 or 16 bytes"},
		"shared dns_ip":              {func(in *BuildInput) { in.Nodes[1].DNSIP = in.Nodes[0].DNSIP }, "duplicate dns_ip"},
		"mixed families":             {func(in *BuildInput) { in.Nodes[1].DNSIP = v6 }, "different address families"},
		"slot 0":                     {func(in *BuildInput) { in.Nodes[0].Slot = 0 }, "slot"},
		"slot above the max":         {func(in *BuildInput) { in.Nodes[0].Slot = 5 }, "slot"},
		"shared slot":                {func(in *BuildInput) { in.Nodes[1].Slot = 1 }, "duplicate slot"},
		"duplicate node":             {func(in *BuildInput) { in.Nodes[1].ID = in.Nodes[0].ID }, "duplicate node_id"},
		"node id length":             {func(in *BuildInput) { in.Nodes[0].ID = []byte{1} }, "node_id"},
		"too many nodes":             {func(in *BuildInput) { in.Nodes = append(in.Nodes, in.Nodes...) }, "too many"},
	} {
		in := good()
		c.mut(&in)
		_, err := Build(in)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want text %q", name, err, c.want)
		}
	}
	// A Private dns_ip is refused in a release build and accepted in a lab build.
	{
		in := good()
		ip(&in, 10, 0, 0, 1)
		_, err := Build(in)
		if netclass.AllowPrivatePairAddrs != (err == nil) {
			t.Errorf("Private dns_ip: AllowPrivatePairAddrs=%v err=%v", netclass.AllowPrivatePairAddrs, err)
		}
	}
	// Accepted: pairs (A, B) and (B, A); an IPv6 pair; no pair with no global.
	in := good()
	in.Pairs = append(in.Pairs, bp('q', 'B', 'A'))
	if _, err := Build(in); err != nil {
		t.Errorf("(A,B) and (B,A): %v", err)
	}
	in = good()
	in.Nodes[0].DNSIP, in.Nodes[1].DNSIP = v6, v6b
	if _, err := Build(in); err != nil {
		t.Errorf("ipv6 pair: %v", err)
	}
	if _, err := Build(BuildInput{Nodes: good().Nodes}); err != nil {
		t.Errorf("no pair, empty global: %v", err)
	}
	if _, err := Build(BuildInput{Global: idb('p')}); err == nil {
		t.Error("a global pair with no pairs")
	}
}

func TestProbe(t *testing.T) {
	t0 := time.Unix(1000, 0)
	at := func(s int) time.Time { return t0.Add(time.Duration(s) * time.Second) }
	var p Probe
	if p.State(at(0)) != ProbeUnknown {
		t.Fatal("fresh tracker is unknown")
	}
	p.Round(at(5), true)
	p.Round(at(10), true)
	if p.State(at(10)) != ProbeUnknown {
		t.Fatal("two passes are not up")
	}
	p.Round(at(15), true)
	if p.State(at(15)) != ProbeUp {
		t.Fatal("three passes are up")
	}
	p.Round(at(20), false)
	p.Round(at(25), false)
	if p.State(at(25)) != ProbeUp {
		t.Fatal("two failures change nothing")
	}
	p.Round(at(30), true)
	p.Round(at(35), false)
	p.Round(at(40), false)
	p.Round(at(45), false)
	if p.State(at(45)) != ProbeDown {
		t.Fatal("three failures are down")
	}
	if p.State(at(59)) != ProbeDown || p.State(at(60)) != ProbeUnknown {
		t.Fatal("no round for 15 s is unknown, 14 s is not")
	}
	// A stall also restarts the count.
	p.Round(at(65), true)
	p.Round(at(70), true)
	if p.State(at(70)) != ProbeUnknown {
		t.Fatal("two passes after a stall are not up")
	}
}

func TestPeerDownTracker(t *testing.T) {
	t0 := time.Unix(0, 0)
	at := func(s int) time.Time { return t0.Add(time.Duration(s) * time.Second) }
	var d PeerDownTracker
	for s := 0; s <= 85; s += 5 {
		if d.Round(at(s), false) {
			t.Fatalf("down at %d s", s)
		}
	}
	if !d.Round(at(90), false) {
		t.Fatal("not down after 90 s of failures")
	}
	d.Round(at(95), true)
	for s := 100; s < 395; s += 5 {
		if !d.Round(at(s), true) {
			t.Fatalf("cleared at %d s", s)
		}
	}
	if d.Round(at(395), true) {
		t.Fatal("not cleared after 300 s of passes")
	}
	var s PeerDownSet
	s.Round(at(0), nid('A'), false)
	if len(s.Snapshot()) != 0 {
		t.Fatal("snapshot has a node that is up")
	}
	for i := 5; i <= 90; i += 5 {
		s.Round(at(i), nid('A'), false)
	}
	if !s.Snapshot()[nid('A')] {
		t.Fatal("snapshot lacks a node that is down")
	}
}

func TestFlapAndStable(t *testing.T) {
	now := time.Unix(100000, 0)
	c := Columns{LastFailbackAt: now.Add(-3599 * time.Second)}
	c2, flapped := Flap(c, now)
	if !flapped || !c2.FlapUntil.Equal(now.Add(24*time.Hour)) {
		t.Fatal("3599 s after a failback flaps")
	}
	if StablePeriod(c2, now) != 1800*time.Second {
		t.Fatal("S while flapping")
	}
	if StablePeriod(c2, now.Add(24*time.Hour)) != 300*time.Second {
		t.Fatal("S after the flap window")
	}
	c.LastFailbackAt = now.Add(-3600 * time.Second)
	if _, flapped := Flap(c, now); flapped {
		t.Fatal("3600 s after a failback is no flap")
	}
	if _, flapped := Flap(Columns{}, now); flapped {
		t.Fatal("no failback yet is no flap")
	}
}

func TestNextVersion(t *testing.T) {
	now := time.UnixMilli(5000)
	if NextVersion(10, now) != 5000 || NextVersion(5000, now) != 5001 || NextVersion(9000, now) != 9001 {
		t.Fatal("NextVersion is max(last+1, now_ms)")
	}
}

func TestDrain(t *testing.T) {
	ab := tbl(t, nil, bp('p', 'A', 'B'))
	aw := tbl(t, map[byte]string{'A': "w"}, bp('p', 'A', 'B'))
	t0 := time.Unix(0, 0)
	var d Drain
	// B starts as the fallback: never advertised, so no drain.
	d.Applied(t0, ab, nil, nid('B'))
	if d.Draining() {
		t.Fatal("a fallback that starts does not drain")
	}
	d.Applied(t0.Add(time.Second), aw, nil, nid('B')) // B advertised
	d.Applied(t0.Add(100*time.Second), ab, nil, nid('B'))
	if !d.Draining() || d.MayClose(t0.Add(159*time.Second)) || !d.MayClose(t0.Add(160*time.Second)) {
		t.Fatal("drain starts at the apply, closes from 60 s")
	}
	if d.Done(t0.Add(459*time.Second)) || !d.Done(t0.Add(460*time.Second)) {
		t.Fatal("drain done at 360 s")
	}
	d.Applied(t0.Add(200*time.Second), aw, nil, nid('B'))
	if d.Draining() {
		t.Fatal("re-advertised: drain cancelled")
	}
	// A switch of the global pair makes A stop being advertised although the
	// old pair still exists.
	two := tbl(t, nil, bp('p', 'A', 'B'), bp('q', 'C', 0))
	two.Global = pid('q')
	var da Drain
	da.Applied(t0, ab, nil, nid('A'))
	da.Applied(t0.Add(time.Second), two, nil, nid('A'))
	if !da.Draining() {
		t.Fatal("A drains after a global pair switch")
	}
	// Still the advertised node of a pair in use: no drain.
	var db Drain
	db.Applied(t0, ab, nil, nid('A'))
	db.Applied(t0.Add(time.Second), two, []PairID{pid('p')}, nid('A'))
	if db.Draining() {
		t.Fatal("A is still advertised by a pair in use")
	}
}

// A silence of ProbeUnknown or more breaks a run (8a.5 counts rounds without a
// break), so a stalled prober's gap is not part of a failed or passing run.
func TestPeerDownTrackerStallBreaksTheRun(t *testing.T) {
	t0 := time.Unix(0, 0)
	at := func(s int) time.Time { return t0.Add(time.Duration(s) * time.Second) }
	var d PeerDownTracker
	d.Round(at(0), false)
	if d.Round(at(95), false) {
		t.Fatal("two failed rounds around a 95 s stall are down")
	}
	// The run restarted at 95 s, so 90 s later it is down.
	for s := 100; s < 185; s += 5 {
		if d.Round(at(s), false) {
			t.Fatalf("down at %d s, before 90 s of rounds", s)
		}
	}
	if !d.Round(at(185), false) {
		t.Fatal("not down after 90 s of rounds without a break")
	}
	// Down stays down until 300 s of passing rounds: a pass, a stall, a pass.
	d.Round(at(190), true)
	if !d.Round(at(500), true) {
		t.Fatal("two passes around a 310 s stall cleared the view")
	}
	for s := 505; s < 800; s += 5 {
		if !d.Round(at(s), true) {
			t.Fatalf("cleared at %d s", s)
		}
	}
	if d.Round(at(800), true) {
		t.Fatal("300 s of passes after the stall did not clear it")
	}
}
