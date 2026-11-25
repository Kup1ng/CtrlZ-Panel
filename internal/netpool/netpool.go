// Package netpool bounds work that a request with no proof causes, per source network, per IPv6 /48 and for the
// process (P1 auth review round 11, tenant-r11-1, -2, -4, -5; rule budget-keying).
//
// It is the one implementation of a registered budget.NetPool. Round 10 wrote the first one by hand inside the api
// package, and it had four defects that were one defect in four places: it knew a /64 and not the /48 that holds
// 65,536 of them, a refusal at the process step kept the token the network had paid, a step back of the clock froze
// the refill, and none of it was visible to the registry's tests. Here the arithmetic is written once, the registry
// row says the numbers, and internal/budget drives every row the way a stranger would.
//
// Nothing here does I/O, never waits and never queues: a refused request costs one hash and a few locks. The
// decision depends on no account, so it is no oracle.
package netpool

import (
	"hash/maphash"
	"net/netip"
	"sync"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/budget"
	"github.com/Kup1ng/CtrlZ-Panel/internal/netkey"
)

// places is how many places the networks are spread over, for each of the two kinds. A network is hashed under a
// seed made when the process starts, so a sender cannot choose a network that lands on the place of another; two
// networks that do meet share one place, which costs them a little of their share and nothing else, and the
// memory stays fixed whatever the senders do.
const places = 1024

// group is the share of the networks that hash to one place: a token bucket and a count of reads in flight.
type group struct {
	mu     sync.Mutex
	tokens float64
	last   int64 // unix nanoseconds of the last refill; 0 before the first use
	busy   int
}

// take spends one token and one place, if both are there.
func (g *group) take(now int64, burst int, refill float64, concurrency int) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.last == 0 {
		g.tokens, g.last = float64(burst), now
	}
	switch dt := float64(now-g.last) / float64(time.Second); {
	case dt > 0:
		g.tokens = min(float64(burst), g.tokens+dt*refill)
		g.last = now
	case dt < 0:
		// The clock stepped back (an NTP correction; the application clock carries no monotonic reading). Starting
		// from the corrected time keeps the bucket refilling at its rate; keeping the old mark would freeze it
		// until the clock caught up, a window of a limit that does not survive a step (rule clock-source).
		g.last = now
	}
	if g.busy >= concurrency || g.tokens < 1 {
		return false
	}
	g.tokens--
	g.busy++
	return true
}

// release gives the place back after the work. The token stays spent: the work was done.
func (g *group) release() {
	g.mu.Lock()
	g.busy--
	g.mu.Unlock()
}

// refund gives back everything take took, for a request that was refused further on and did nothing.
func (g *group) refund(burst int) {
	g.mu.Lock()
	g.busy--
	g.tokens = min(float64(burst), g.tokens+1)
	g.mu.Unlock()
}

// Pool is one registered network pool.
type Pool struct {
	cfg    budget.NetPool
	seed   maphash.Seed
	narrow [places]group
	wide   [places]group
	slots  chan struct{}
	now    func() time.Time
}

// New builds the pool of a registry row. now is the application clock.
func New(cfg budget.NetPool, now func() time.Time) *Pool {
	return &Pool{cfg: cfg, seed: maphash.MakeSeed(), slots: make(chan struct{}, cfg.Slots), now: now}
}

// Try asks for one unit of work for a request from addr, and returns the function that ends it (once). A request
// with no usable address shares one place, so it is bounded like a network and no address is a way round.
func (p *Pool) Try(addr netip.Addr) (release func(), ok bool) {
	now := p.now().UnixNano()
	c := p.cfg

	n := &p.narrow[maphash.String(p.seed, netkey.Net(addr))%places]
	if !n.take(now, c.Burst, c.Refill, c.Concurrency) {
		return nil, false
	}
	// The /48 holds as many places as a /64 does and WideFactor times its tokens: the whole allocation of one
	// subscriber is one source, and rotating through its /64s buys no second place.
	var w *group
	wideBurst, wideRefill := c.Burst*c.WideFactor, c.Refill*float64(c.WideFactor)
	if key, has := netkey.Wide(addr); has {
		w = &p.wide[maphash.String(p.seed, key)%places]
		if !w.take(now, wideBurst, wideRefill, c.Concurrency) {
			n.refund(c.Burst)
			return nil, false
		}
	}
	select {
	case p.slots <- struct{}{}:
	default:
		if w != nil {
			w.refund(wideBurst)
		}
		n.refund(c.Burst)
		return nil, false
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			<-p.slots
			if w != nil {
				w.release()
			}
			n.release()
		})
	}, true
}

// Place says which place of the narrow set and of the /48 set an address hashes to (-1 for the /48 set of an
// IPv4 address). It exists so that a test can choose networks that do not meet: the seed is random per process,
// two networks meet with a probability of about one in a thousand, and a test that did not look would fail on
// that day. It tells nothing a caller without the pool could use.
func (p *Pool) Place(addr netip.Addr) (narrow, wide int) {
	narrow, wide = int(maphash.String(p.seed, netkey.Net(addr))%places), -1
	if key, has := netkey.Wide(addr); has {
		wide = int(maphash.String(p.seed, key) % places)
	}
	return narrow, wide
}
