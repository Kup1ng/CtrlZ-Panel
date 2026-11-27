package hublimit

import (
	"fmt"
	"net/netip"
	"testing"
	"time"
)

type fakeClock struct{ t time.Time }

func (c *fakeClock) Now() time.Time          { return c.t }
func (c *fakeClock) Advance(d time.Duration) { c.t = c.t.Add(d) }

func newClock() *fakeClock { return &fakeClock{t: time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)} }

func TestKeyedBucket(t *testing.T) {
	c := newClock()
	k := NewKeyed(30.0/60, 30, c.Now) // 30 a minute
	for i := 0; i < 30; i++ {
		if !k.Allow("a") {
			t.Fatalf("call %d refused inside the burst", i)
		}
	}
	if k.Allow("a") {
		t.Fatal("31st call allowed")
	}
	if !k.Allow("b") {
		t.Fatal("another key shares the bucket")
	}
	c.Advance(2 * time.Second) // one token a 2 s
	if !k.Allow("a") || k.Allow("a") {
		t.Fatal("refill is one token in two seconds")
	}
	if w := k.Wait("a", 1); w <= 0 || w > 3*time.Second {
		t.Fatalf("wait %v", w)
	}
	// Keys at rest are dropped by the sweep, so the table does not keep every source it ever saw.
	c.Advance(10 * time.Minute)
	k.Allow("c")
	if k.Len() != 1 {
		t.Fatalf("table holds %d keys after rest", k.Len())
	}
}

func TestKeyedRefusesMoreThanBurst(t *testing.T) {
	k := NewKeyed(1, 10, newClock().Now)
	if k.AllowN("x", 11) {
		t.Fatal("a request above the burst was allowed")
	}
}

func TestSlots(t *testing.T) {
	s := NewSlots(2)
	r1, ok1 := s.Try()
	_, ok2 := s.Try()
	if !ok1 || !ok2 {
		t.Fatal("two slots refused")
	}
	if _, ok := s.Try(); ok {
		t.Fatal("third slot given")
	}
	r1()
	r1() // twice is once
	if s.InUse() != 1 {
		t.Fatalf("in use %d", s.InUse())
	}
	if _, ok := s.Try(); !ok {
		t.Fatal("a released slot is not free")
	}
}

func TestConnLevels(t *testing.T) {
	v4 := ConnLevels(netip.MustParseAddr("203.0.113.9"))
	if len(v4) != 1 || v4[0].Mult != 1 {
		t.Fatalf("v4 levels: %v", v4)
	}
	a := netip.MustParseAddr("2001:db8:1:2:3:4:5:6")
	b := netip.MustParseAddr("2001:db8:1:2:ffff::1")
	la, lb := ConnLevels(a), ConnLevels(b)
	if la[0] != lb[0] || la[1] != lb[1] || la[2] != lb[2] {
		t.Fatalf("one /64 gives different keys: %v %v", la, lb)
	}
	// Mapped IPv4 is IPv4.
	if got := ConnLevels(netip.MustParseAddr("::ffff:203.0.113.9")); got[0] != v4[0] {
		t.Fatal("a mapped address is a different source")
	}
}

func TestConnsOpenCapPerAddress(t *testing.T) {
	c := newClock()
	l := NewConns(16, 1000, c.Now)
	a := netip.MustParseAddr("203.0.113.9")
	var rel []func()
	for i := 0; i < 16; i++ {
		r, ok := l.Admit(a)
		if !ok {
			t.Fatalf("connection %d refused", i)
		}
		rel = append(rel, r)
	}
	if _, ok := l.Admit(a); ok {
		t.Fatal("17th open connection admitted")
	}
	if _, ok := l.Admit(netip.MustParseAddr("203.0.113.10")); !ok {
		t.Fatal("a neighbour address shares the IPv4 cap")
	}
	rel[0]()
	if _, ok := l.Admit(a); !ok {
		t.Fatal("a closed connection did not free its place")
	}
}

func TestConnsRate(t *testing.T) {
	c := newClock()
	l := NewConns(1000, 10, c.Now)
	a := netip.MustParseAddr("203.0.113.9")
	n := 0
	for i := 0; i < 50; i++ {
		if r, ok := l.Admit(a); ok {
			n++
			r()
		}
	}
	if n != 10 {
		t.Fatalf("%d new connections in one instant, want the burst of 10", n)
	}
	c.Advance(time.Second)
	if _, ok := l.Admit(a); !ok {
		t.Fatal("no refill after a second")
	}
}

// One allocation rotating through its /64s is stopped by the /56 and /48 levels (4 and 16 times the base).
func TestConnsIPv6Aggregates(t *testing.T) {
	c := newClock()
	l := NewConns(16, 1_000_000, c.Now)
	admitted := 0
	for i := 0; i < 100; i++ {
		a := netip.MustParseAddr(fmt.Sprintf("2001:db8:1:%x::1", i)) // 100 different /64s, one /56 (i < 256)
		if _, ok := l.Admit(a); ok {
			admitted++
		}
	}
	if admitted != 64 {
		t.Fatalf("a /56 admitted %d open connections, want 4 times 16", admitted)
	}
	admitted = 0
	for i := 0; i < 40; i++ { // 40 /56s of one /48, 8 /64s each: 320 attempts
		for j := 0; j < 8; j++ {
			a := netip.MustParseAddr(fmt.Sprintf("2001:db8:2:%x::1", i<<8|j))
			if _, ok := l.Admit(a); ok {
				admitted++
			}
		}
	}
	if admitted != 256 {
		t.Fatalf("a /48 admitted %d open connections, want 16 times 16", admitted)
	}
}

func TestConnsSweepKeepsTableBounded(t *testing.T) {
	c := newClock()
	l := NewConns(16, 10, c.Now)
	for i := 0; i < 500; i++ {
		r, ok := l.Admit(netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 1}))
		if !ok {
			t.Fatal("refused")
		}
		r()
	}
	c.Advance(time.Minute)
	l.Admit(netip.MustParseAddr("192.0.2.1"))
	if l.Len() > 2 {
		t.Fatalf("idle sources are still held: %d", l.Len())
	}
}

func TestHandshakes(t *testing.T) {
	h := NewHandshakes(256, 64, 32)
	one := netip.MustParseAddr("203.0.113.9")
	var rel []func()
	for i := 0; i < 32; i++ {
		r, ok := h.Begin(netip.AddrFrom4([4]byte{203, 0, 113, byte(i)}), false)
		if !ok {
			t.Fatalf("handshake %d refused", i)
		}
		rel = append(rel, r)
	}
	if _, ok := h.Begin(one, false); ok {
		t.Fatal("33rd handshake of one /24 admitted")
	}
	if _, ok := h.Begin(netip.MustParseAddr("198.51.100.1"), false); !ok {
		t.Fatal("another /24 was refused by the first one's cap")
	}
	rel[0]()
	if _, ok := h.Begin(one, false); !ok {
		t.Fatal("a finished handshake did not free its place")
	}
}

func TestHandshakesTotalAndReserved(t *testing.T) {
	h := NewHandshakes(256, 64, 32)
	n := 0
	for i := 0; i < 400; i++ {
		// Distinct /24s, so only the total binds.
		if _, ok := h.Begin(netip.AddrFrom4([4]byte{byte(10 + i/200), byte(i % 200), 1, 1}), false); ok {
			n++
		}
	}
	if n != 256 {
		t.Fatalf("%d strangers in progress, want 256", n)
	}
	// Strangers are all in; a node address still gets in, up to its own 64, outside every share.
	m := 0
	for i := 0; i < 100; i++ {
		// Eight node addresses: one address holds at most ReservedPerSource of the 64.
		if _, ok := h.Begin(netip.AddrFrom4([4]byte{203, 0, 113, byte(i % 8)}), true); ok {
			m++
		}
	}
	if m != 64 {
		t.Fatalf("%d node handshakes, want the reserved 64", m)
	}
	if h.InProgress() != 320 {
		t.Fatalf("in progress %d", h.InProgress())
	}
}

func TestHandshakesIPv6Prefixes(t *testing.T) {
	h := NewHandshakes(256, 64, 32)
	n := 0
	for i := 0; i < 100; i++ { // one /48, many /64s: stopped by the /48 share
		if _, ok := h.Begin(netip.MustParseAddr(fmt.Sprintf("2001:db8:1:%x::1", i)), false); ok {
			n++
		}
	}
	if n != 32 {
		t.Fatalf("a /48 had %d handshakes, want 32", n)
	}
	m := 0
	for i := 0; i < 100; i++ { // many /48s of one /32: stopped by the /32 aggregate
		if _, ok := h.Begin(netip.MustParseAddr(fmt.Sprintf("2001:db9:%x::1", i)), false); ok {
			m++
		}
	}
	if m != 32 {
		t.Fatalf("a /32 had %d handshakes, want 32", m)
	}
}

func TestCounts(t *testing.T) {
	c := NewCounts(6)
	var rel []func()
	for i := 0; i < 6; i++ {
		r, ok := c.Take("node")
		if !ok {
			t.Fatal("refused inside the cap")
		}
		rel = append(rel, r)
	}
	if _, ok := c.Take("node"); ok {
		t.Fatal("7th taken")
	}
	if _, ok := c.Take("other"); !ok {
		t.Fatal("another key shares the cap")
	}
	for _, r := range rel {
		r()
	}
	if c.Of("node") != 0 {
		t.Fatal("count did not return to zero")
	}
}

// A node's address whose reserved share is spent is not turned away while general slots are free, and one
// address cannot hold more than its share of the reserved ones (a revoked node's host, say).
func TestHandshakesReservedFallsBackToGeneral(t *testing.T) {
	h := NewHandshakes(256, 64, 32)
	a := netip.MustParseAddr("203.0.113.9")
	var rel []func()
	for i := 0; i < ReservedPerSource+10; i++ {
		r, ok := h.Begin(a, true)
		if !ok {
			t.Fatalf("handshake %d of a node address refused with general slots free", i)
		}
		rel = append(rel, r)
	}
	if h.nRes != ReservedPerSource || h.nTotal != 10 {
		t.Fatalf("reserved %d, general %d: want %d and 10", h.nRes, h.nTotal, ReservedPerSource)
	}
	for _, r := range rel {
		r()
	}
	if h.InProgress() != 0 || len(h.resBySrc) != 0 {
		t.Fatalf("slots leaked: %d in progress, %d sources", h.InProgress(), len(h.resBySrc))
	}
}

// A full table makes room instead of refusing (W3-r2-1): a flood from many networks fills it, and a new
// source, a node's included, is still counted. The flood's own oldest keys are what go.
func TestKeyedFullTableDropsTheOldestKey(t *testing.T) {
	c := newClock()
	k := NewKeyed(0.5, 30, c.Now)
	k.max = 100
	for i := 0; i < 1000; i++ {
		if !k.Allow(fmt.Sprintf("flood-%d", i)) {
			t.Fatalf("a new key was refused at the table's bound (key %d)", i)
		}
		c.Advance(time.Microsecond)
	}
	if k.Len() > 100 {
		t.Fatalf("table holds %d keys, bound 100", k.Len())
	}
	if !k.Allow("a-real-network") {
		t.Fatal("a source outside the flood was refused by a full table")
	}
	// A key that is used stays: recency decides, not age.
	for i := 0; i < 500; i++ {
		k.Allow("kept")
		k.Allow(fmt.Sprintf("more-%d", i))
	}
	if _, ok := k.m["kept"]; !ok {
		t.Fatal("a key in use was dropped")
	}
}

func TestConnsFullTableAdmitsANode(t *testing.T) {
	c := newClock()
	cs := NewConns(16, 10, c.Now)
	cs.max = 30
	// Every entry is held by an open connection: nothing can be dropped.
	var rel []func()
	for i := 0; i < 30; i++ {
		r, ok := cs.Admit(netip.MustParseAddr(fmt.Sprintf("10.0.%d.1", i)))
		if !ok {
			t.Fatalf("connection %d refused below the bound", i)
		}
		rel = append(rel, r)
	}
	stranger := netip.MustParseAddr("198.51.100.9")
	if _, ok := cs.Admit(stranger); ok {
		t.Fatal("a stranger was admitted into a table full of open connections")
	}
	r, ok := cs.AdmitFor(netip.MustParseAddr("203.0.113.7"), true)
	if !ok {
		t.Fatal("a node address was refused by a full table")
	}
	r() // an uncounted admission releases nothing and does not panic
	if cs.Len() != 30 {
		t.Fatalf("table grew to %d", cs.Len())
	}
	// Closed connections free their entries once they are idle: the table makes room for strangers.
	for _, r := range rel {
		r()
	}
	c.Advance(3 * time.Second)
	if _, ok := cs.Admit(stranger); !ok {
		t.Fatal("a stranger was refused after the entries went idle")
	}
}

// A flood of closed connections from many IPv6 /64s fills the table with entries that hold nothing; a
// new source takes the place of the oldest of them at once, without waiting for the sweep (W3-r2-1).
func TestConnsFullTableWithIdleEntriesDropsTheOldest(t *testing.T) {
	c := newClock()
	cs := NewConns(16, 10, c.Now)
	cs.max = 60
	for i := 0; i < 500; i++ {
		a := netip.MustParseAddr(fmt.Sprintf("2001:db8:%x::1", i+1))
		r, ok := cs.Admit(a)
		if !ok {
			t.Fatalf("connection %d refused although every entry is idle", i)
		}
		r()
	}
	if cs.Len() > 60 {
		t.Fatalf("table holds %d keys, bound 60", cs.Len())
	}
	if _, ok := cs.Admit(netip.MustParseAddr("192.0.2.1")); !ok {
		t.Fatal("a new source was refused by a table full of idle entries")
	}
}
