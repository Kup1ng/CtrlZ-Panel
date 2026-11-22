package budget_test

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/budget"
	"github.com/Kup1ng/CtrlZ-Panel/internal/netpool"
	"github.com/Kup1ng/CtrlZ-Panel/internal/ratelimit"
)

// Round 11, tenant-r11-4 (rule budget-keying): a bucket that counts on the network and is not a counter in a
// store (a pool of reads in flight) was written by hand in internal/api in round 10, bounded the /64 and nothing
// wider, and none of the registry's generated abuse tests drove it, so one IPv6 /48 held every slot of the process.
// A pool is a registry row now (budget.NetPool, built only by internal/netpool), these tests drive every row the way
// a stranger would, and the lint named below fails for any other file that cuts a client address into a network.

func TestNetworkPoolRowsAreWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, p := range budget.NetPools() {
		key := string(p.Service) + "/" + p.Name
		if seen[key] {
			t.Errorf("the pool %s is declared twice", key)
		}
		seen[key] = true
		if p.Slots < 1 || p.Concurrency < 1 || p.Burst < 1 || p.Refill <= 0 || p.Why == "" {
			t.Errorf("%s: a pool needs slots, a concurrency, a burst, a refill and a reason: %+v", key, p)
		}
		// A /48 is one source: more than a /64 gets, never less, and the factor is the one of the rate classes.
		if p.WideFactor != ratelimit.WideFactor {
			t.Errorf("%s: WideFactor is %d, the /48 factor of every other bucket is %d", key, p.WideFactor, ratelimit.WideFactor)
		}
		// The process keeps more slots than one network can hold, or one network could take them all.
		if p.Slots <= p.Concurrency {
			t.Errorf("%s: %d slots for the process and %d for one network: one network could hold the process", key, p.Slots, p.Concurrency)
		}
		if got, ok := budget.FindNetPool(p.Service, p.Name); !ok || got.Name != p.Name {
			t.Errorf("%s: FindNetPool does not find it", key)
		}
	}
	if len(seen) == 0 {
		t.Error("no network pool is registered")
	}
}

// poolDrain takes work from a source at one instant until refused, releasing each unit at once, and returns the
// grants, so that only the token buckets end it.
func poolDrain(p *netpool.Pool, from func(i int) netip.Addr) int {
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

func TestAbuseANetworkPoolIsBoundedPerNetworkPer48AndForTheProcess(t *testing.T) {
	for _, row := range budget.NetPools() {
		t.Run(string(row.Service)+"/"+row.Name, func(t *testing.T) {
			now := time.Unix(1_800_000_000, 0)
			clock := func() time.Time { return now }
			fresh := func() *netpool.Pool { return netpool.New(row, clock) }

			// apart picks n networks whose places differ from each other and from avoid: two that meet share a
			// place by design, and a test that did not look would fail one run in a thousand.
			apart := func(p *netpool.Pool, n int, avoid ...netip.Addr) []netip.Addr {
				used := map[int]bool{}
				for _, a := range avoid {
					nr, _ := p.Place(a)
					used[nr] = true
				}
				var out []netip.Addr
				for i := 0; len(out) < n && i < 5000; i++ {
					a := netip.MustParseAddr(fmt.Sprintf("10.%d.%d.1", i/250, i%250))
					if nr, _ := p.Place(a); !used[nr] {
						used[nr] = true
						out = append(out, a)
					}
				}
				if len(out) < n {
					t.Fatalf("no %d networks that do not meet", n)
				}
				return out
			}

			// 1. Strangers of one /24 (many hosts) and of one /64 (many hosts) get one network's share.
			p := fresh()
			if got := poolDrain(p, func(i int) netip.Addr { return netip.MustParseAddr(fmt.Sprintf("203.0.113.%d", i%250+1)) }); got != row.Burst {
				t.Errorf("one /24 was granted %d at one instant, want its burst of %d", got, row.Burst)
			}
			if got := poolDrain(p, func(i int) netip.Addr { return netip.MustParseAddr(fmt.Sprintf("2001:db8:5:5::%x", i+1)) }); got != row.Burst {
				t.Errorf("one /64 was granted %d at one instant, want its burst of %d", got, row.Burst)
			}

			// 2. One IPv6 /48 rotating its /64s is ONE source: it holds Concurrency units at a time and is granted
			// WideFactor bursts in all, and the process keeps its slots for everybody else.
			p = fresh()
			var held []func()
			seen := map[int]bool{}
			for i, tried := 0, 0; tried < 4*row.Slots; i++ {
				a := netip.MustParseAddr(fmt.Sprintf("2001:db8:1:%x::1", i))
				nr, _ := p.Place(a)
				if seen[nr] {
					continue
				}
				tried++
				if r, ok := p.Try(a); ok {
					held = append(held, r)
				}
			}
			if len(held) != row.Concurrency {
				t.Errorf("one /48 held %d at once by rotating its /64s, want %d", len(held), row.Concurrency)
			}
			var served []func()
			for _, a := range apart(p, row.Slots) {
				if r, ok := p.Try(a); ok {
					served = append(served, r)
				}
			}
			if want := row.Slots - len(held); len(served) < want {
				t.Errorf("with a /48 flooding, %d other networks were served of %d slots, want at least %d", len(served), row.Slots, want)
			}
			for _, r := range append(held, served...) {
				r()
			}
			p = fresh()
			if got := poolDrain(p, func(i int) netip.Addr { return netip.MustParseAddr(fmt.Sprintf("2001:db8:1:%x::1", i)) }); got != row.Burst*row.WideFactor {
				t.Errorf("one /48 was granted %d at one instant by rotating, want %d", got, row.Burst*row.WideFactor)
			}

			// 3. The process bound: more networks than slots, all holding a unit, and a refusal costs nothing: the
			// refused networks have their whole burst when the slots are free.
			p = fresh()
			probes := []netip.Addr{netip.MustParseAddr("198.51.100.9"), netip.MustParseAddr("2001:db8:9:9::9")}
			var all []func()
			for _, a := range apart(p, row.Slots+4, probes...) {
				if r, ok := p.Try(a); ok {
					all = append(all, r)
				}
			}
			if len(all) != row.Slots {
				t.Errorf("%d units at once from separate networks, the process bound is %d", len(all), row.Slots)
			}
			for _, a := range probes {
				for i := 0; i < 3*row.Burst; i++ {
					if r, ok := p.Try(a); ok {
						r()
						t.Fatalf("%s was granted a unit with every slot held", a)
					}
				}
			}
			for _, r := range all {
				r()
			}
			for _, a := range probes {
				if got := poolDrain(p, func(int) netip.Addr { return a }); got != row.Burst {
					t.Errorf("%s: %d units after the slots were free, want its burst of %d (a refused try kept a token)", a, got, row.Burst)
				}
			}

			// 4. The clock steps back: the share refills at its rate afterwards.
			p = fresh()
			addr := netip.MustParseAddr("203.0.113.77")
			poolDrain(p, func(int) netip.Addr { return addr })
			now = now.Add(-time.Hour)
			if got := poolDrain(p, func(int) netip.Addr { return addr }); got != 0 {
				t.Errorf("%d units at the instant of the step back", got)
			}
			now = now.Add(time.Duration(3/row.Refill*float64(time.Second)) + time.Second)
			if got := poolDrain(p, func(int) netip.Addr { return addr }); got < 3 {
				t.Errorf("%d units after the step back and the time for three tokens: the refill froze", got)
			}
		})
	}
}

// The lint that keeps every other file from cutting a client address into a network (the walk that lived here
// matched four spellings and was passed by an alias, a function value, Addr.Prefix and httpx.Subject, round 12)
// is internal/lint TestNoCodeKeysAnythingOnTheNetworkOutsideTheRegistry; it judges by types and needs the type
// checker that package already has.
