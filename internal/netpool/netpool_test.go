package netpool_test

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/budget"
	"github.com/Kup1ng/CtrlZ-Panel/internal/netpool"
)

func registered(t *testing.T) budget.NetPool {
	t.Helper()
	p, ok := budget.FindNetPool(budget.Tenant, "invite-read")
	if !ok {
		t.Fatal("the invite-read pool is not registered")
	}
	return p
}

func v4(i int) netip.Addr { return netip.MustParseAddr(fmt.Sprintf("10.%d.%d.1", i/250, i%250)) }

// v6 is the first address of the i-th /64 of one /48.
func v6(i int) netip.Addr { return netip.MustParseAddr(fmt.Sprintf("2001:db8:1:%x::1", i)) }

// apart returns n IPv4 networks that hash to places of p that differ from each other and from every address in
// avoid: the seed is random, and two networks that meet share a place by design, which is not what these tests
// are about.
func apart(t *testing.T, p *netpool.Pool, n int, avoid ...netip.Addr) []netip.Addr {
	t.Helper()
	used := map[int]bool{}
	for _, a := range avoid {
		nr, _ := p.Place(a)
		used[nr] = true
	}
	var out []netip.Addr
	for i := 0; len(out) < n && i < 5000; i++ {
		a := v4(i)
		if nr, _ := p.Place(a); !used[nr] {
			used[nr] = true
			out = append(out, a)
		}
	}
	if len(out) < n {
		t.Fatalf("found %d networks that do not meet, want %d", len(out), n)
	}
	return out
}

// drain takes reads from a source at one instant until it is refused and returns how many it got, releasing each
// at once so that only the token bucket and not the concurrency bound ends it.
func drain(p *netpool.Pool, from func(i int) netip.Addr) int {
	got := 0
	for i := 0; i < 100_000; i++ {
		rel, ok := p.Try(from(i))
		if !ok {
			return got
		}
		rel()
		got++
	}
	return got
}

func same(a netip.Addr) func(int) netip.Addr { return func(int) netip.Addr { return a } }

// TestNetReadsAreBoundedPerNetworkAndForTheProcess holds the arithmetic of the bound without a database: one
// network holds one read at a time and spends its burst, another network is untouched by it, and the process bound
// is shared.
func TestNetReadsAreBoundedPerNetworkAndForTheProcess(t *testing.T) {
	c := registered(t)
	now := time.Unix(1_800_000_000, 0)
	p := netpool.New(c, func() time.Time { return now })
	nets := apart(t, p, 2)
	a, b := nets[0], nets[1]
	sameNet := netip.PrefixFrom(a, 24).Masked().Addr().Next().Next() // another host of a's /24

	rel, ok := p.Try(a)
	if !ok {
		t.Fatal("the first read of a network was refused")
	}
	if _, ok := p.Try(sameNet); ok {
		t.Fatal("a second read at once from the same /24 was let through")
	}
	if r2, ok := p.Try(b); !ok {
		t.Fatal("another network was refused by the first one's read")
	} else {
		r2()
	}
	rel()
	rel() // a second release is harmless
	for i := 1; i < c.Burst; i++ {
		r, ok := p.Try(a)
		if !ok {
			t.Fatalf("read %d of the burst was refused", i+1)
		}
		r()
	}
	if _, ok := p.Try(a); ok {
		t.Fatal("a read past the burst was let through")
	}
	now = now.Add(time.Second)
	if r, ok := p.Try(a); !ok {
		t.Fatal("the bucket did not refill with time")
	} else {
		r()
	}
	// The process bound: more networks than slots, all holding a read.
	var held []func()
	for _, n := range apart(t, p, c.Slots+4, a, b) {
		if r, ok := p.Try(n); ok {
			held = append(held, r)
		}
	}
	if len(held) != c.Slots {
		t.Fatalf("%d reads at once, the process bound is %d", len(held), c.Slots)
	}
	for _, r := range held {
		r()
	}
	if r, ok := p.Try(apart(t, p, 1, a, b)[0]); !ok {
		t.Fatal("a slot was not given back")
	} else {
		r()
	}
}

// TestARefusedTryGivesBackEverythingItTook is tenant-r11-1 and -5: a request that the process bound refuses used to
// keep the token of its network, so an invitee who retried while other networks held the slots emptied his own share
// and stayed refused after the slots were free. Every step of the chain is driven: the process step for an IPv4
// network and for an IPv6 one, and the /48 step for the /64.
func TestARefusedTryGivesBackEverythingItTook(t *testing.T) {
	c := registered(t)
	now := time.Unix(1_800_000_000, 0)
	p := netpool.New(c, func() time.Time { return now })
	probes := []netip.Addr{netip.MustParseAddr("203.0.113.9"), v6(0x40)}

	// Other networks hold every process slot.
	var held []func()
	for _, n := range apart(t, p, c.Slots, probes...) {
		r, ok := p.Try(n)
		if !ok {
			t.Fatalf("slot of %s was refused", n)
		}
		held = append(held, r)
	}
	for _, from := range probes {
		// More tries than the burst, every one refused by the process step.
		for i := 0; i < 3*c.Burst; i++ {
			if r, ok := p.Try(from); ok {
				r()
				t.Fatalf("%s: a read was granted while every process slot was held", from)
			}
		}
	}
	for _, r := range held {
		r()
	}
	// The slots are free and the networks have all their tokens: each gets the whole burst at this instant.
	for _, from := range probes {
		if got := drain(p, same(from)); got != c.Burst {
			t.Errorf("%s: %d reads after the slots were free, want its whole burst of %d (a refused try kept a token)", from, got, c.Burst)
		}
	}

	// The /48 step: the narrow token and place a /64 took before the /48 refused it come back.
	q := netpool.New(c, func() time.Time { return now })
	hold, ok := q.Try(v6(1)) // the /48's one place
	if !ok {
		t.Fatal("the first read of the /48 was refused")
	}
	n1, _ := q.Place(v6(1))
	if n2, _ := q.Place(v6(2)); n1 == n2 {
		t.Skip("the two /64s meet in this process's seed, which is the shared place by design")
	}
	for i := 0; i < 3*c.Burst; i++ {
		if r, ok := q.Try(v6(2)); ok {
			r()
			t.Fatal("a second read of one /48 was let through")
		}
	}
	hold()
	if got := drain(q, same(v6(2))); got != c.Burst {
		t.Errorf("a /64 refused by its /48 got %d reads afterwards, want its whole burst of %d", got, c.Burst)
	}
}

// TestOneIPv6AllocationIsOneSource is tenant-r11-4: a /48 holds 65,536 /64s, and the pool used to give each its own
// place, burst and process slot, so one subscriber held every slot of the process and was granted thousands of reads at
// one instant. It now holds one read at a time and WideFactor times the burst of one network, however it rotates.
func TestOneIPv6AllocationIsOneSource(t *testing.T) {
	c := registered(t)
	now := time.Unix(1_800_000_000, 0)
	p := netpool.New(c, func() time.Time { return now })

	// At one instant, rotating the /64, the allocation holds one read, not eight. The /64s are picked apart: two
	// that met would be refused by their shared place, which would hide a missing /48 bound.
	seen := map[int]bool{}
	var held []func()
	tried := 0
	for i := 0; tried < 4*c.Slots; i++ {
		a := v6(i)
		if n, _ := p.Place(a); seen[n] {
			continue
		} else {
			seen[n] = true
		}
		tried++
		if r, ok := p.Try(a); ok {
			held = append(held, r)
		}
	}
	if len(held) != c.Concurrency {
		t.Fatalf("one /48 held %d reads at once through %d /64s, want %d", len(held), tried, c.Concurrency)
	}
	for _, r := range held {
		r()
	}
	// The process still has its other slots for other networks.
	var others []func()
	for _, n := range apart(t, p, c.Slots) {
		if r, ok := p.Try(n); ok {
			others = append(others, r)
		}
	}
	if len(others) != c.Slots {
		t.Errorf("the other networks got %d of the %d slots after the /48 had its read and let it go", len(others), c.Slots)
	}
	for _, r := range others {
		r()
	}

	// Reads in total at one instant: the /48's share, not one burst per /64.
	q := netpool.New(c, func() time.Time { return now })
	if got, want := drain(q, v6), c.Burst*c.WideFactor; got != want {
		t.Errorf("one /48 was granted %d reads at one instant by rotating its /64s, want %d", got, want)
	}
}

// TestTheBucketRefillsAfterTheClockStepsBack is tenant-r11-2: the application clock carries no monotonic reading, so
// an NTP step back used to leave the mark of the last refill in the future and froze every bucket until the clock
// caught up. The rate must survive a step in both kinds of bucket.
func TestTheBucketRefillsAfterTheClockStepsBack(t *testing.T) {
	c := registered(t)
	for _, from := range []struct {
		name  string
		at    func(i int) netip.Addr
		burst int
	}{
		{"an IPv4 network", same(netip.MustParseAddr("203.0.113.9")), c.Burst},
		{"an IPv6 /48", v6, c.Burst * c.WideFactor},
	} {
		t.Run(from.name, func(t *testing.T) {
			now := time.Unix(1_800_000_000, 0)
			p := netpool.New(c, func() time.Time { return now })
			if got := drain(p, from.at); got != from.burst {
				t.Fatalf("drained %d, want %d", got, from.burst)
			}
			now = now.Add(-time.Hour) // the host clock is corrected an hour back
			if got := drain(p, from.at); got != 0 {
				t.Fatalf("%d reads at the instant of the step, the bucket had no time to refill", got)
			}
			now = now.Add(2 * time.Second)
			if got := drain(p, from.at); got < 2 {
				t.Errorf("%d reads two seconds after the step back, want the refill of about 2 a second to resume", got)
			}
		})
	}
}
