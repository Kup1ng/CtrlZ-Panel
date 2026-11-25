// Package hublimit holds the in-memory limiters of the hub's node port (p4-nodes 5.1, 5.7, D31).
//
// Why they are here and not in front of the hub: the port is open to the internet, a node's handshake
// looks like anyone's until its certificate arrives, and gRPC under http.Server.ServeHTTP has no flow
// control of its own. Every limiter is a bound on memory and on database work that holds before the
// first database read, and none of them reads a database. The numbers are the provisional ones of D31;
// the P4 load test measures them.
//
// Every table here is bounded: a key that is idle and back at rest is dropped on the next sweep, and
// a table that is full refuses a new key rather than growing, so a flood from many addresses cannot
// turn a limiter into the memory it was written to protect.
package hublimit

import (
	"net/netip"
	"sync"
	"time"
)

// Clock is time.Now, replaceable in tests.
type Clock func() time.Time

// maxKeys bounds each keyed table. A /24 or /64 key is one of a bounded number of networks that can
// reach the port at once (the connection and handshake caps below bound the open ones), so the bound
// is never the working set of a healthy hub.
const maxKeys = 200_000

// ---------------------------------------------------------------------------------------------------
// Keyed token buckets.

type bucket struct {
	tokens float64
	last   time.Time
}

// Keyed is a set of token buckets with one rate and burst, one bucket per key.
type Keyed struct {
	mu      sync.Mutex
	rate    float64 // tokens a second
	burst   float64
	now     Clock
	m       map[string]*bucket
	sweepAt time.Time
}

// NewKeyed makes a limiter that refills rate tokens a second up to burst.
func NewKeyed(rate, burst float64, now Clock) *Keyed {
	return &Keyed{rate: rate, burst: burst, now: now, m: make(map[string]*bucket)}
}

// Allow takes one token from key's bucket, and says whether there was one.
func (k *Keyed) Allow(key string) bool { return k.AllowN(key, 1) }

// AllowN takes n tokens at once (the byte-rate reader asks for bytes). A request larger than the burst
// is never allowed.
func (k *Keyed) AllowN(key string, n float64) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	now := k.now()
	k.sweep(now)
	b, ok := k.m[key]
	if !ok {
		if len(k.m) >= maxKeys {
			return false
		}
		b = &bucket{tokens: k.burst, last: now}
		k.m[key] = b
	}
	if d := now.Sub(b.last).Seconds(); d > 0 {
		b.tokens = min(k.burst, b.tokens+d*k.rate)
		b.last = now
	}
	if b.tokens < n {
		return false
	}
	b.tokens -= n
	return true
}

// Wait is how long until n tokens are there, zero if they are. It takes nothing.
func (k *Keyed) Wait(key string, n float64) time.Duration {
	k.mu.Lock()
	defer k.mu.Unlock()
	b, ok := k.m[key]
	if !ok {
		return 0
	}
	have := min(k.burst, b.tokens+k.now().Sub(b.last).Seconds()*k.rate)
	if have >= n || k.rate <= 0 {
		return 0
	}
	return time.Duration((n - have) / k.rate * float64(time.Second))
}

// sweep drops buckets that have refilled completely: a key at rest holds nothing a new bucket would
// not give it. It runs at most once a second.
func (k *Keyed) sweep(now time.Time) {
	if now.Before(k.sweepAt) {
		return
	}
	k.sweepAt = now.Add(time.Second)
	for key, b := range k.m {
		if k.rate > 0 && b.tokens+now.Sub(b.last).Seconds()*k.rate >= k.burst {
			delete(k.m, key)
		}
	}
}

// Len is the number of live keys.
func (k *Keyed) Len() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return len(k.m)
}

// ---------------------------------------------------------------------------------------------------
// Counted slots.

// Slots is a cap on how many of something are in progress at once.
type Slots struct {
	mu  sync.Mutex
	max int
	n   int
}

// NewSlots makes a cap of max.
func NewSlots(max int) *Slots { return &Slots{max: max} }

// Try takes a slot. The release function is safe to call more than once.
func (s *Slots) Try() (release func(), ok bool) {
	s.mu.Lock()
	if s.n >= s.max {
		s.mu.Unlock()
		return nil, false
	}
	s.n++
	s.mu.Unlock()
	var once sync.Once
	return func() { once.Do(func() { s.mu.Lock(); s.n--; s.mu.Unlock() }) }, true
}

// InUse is how many slots are taken.
func (s *Slots) InUse() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.n
}

// ---------------------------------------------------------------------------------------------------
// Source keys.

// Level is one prefix a source is counted under, and the multiple of the base limit that prefix gets.
type Level struct {
	Key  string
	Mult int
}

// ConnLevels are the prefixes a connection is counted under before TLS (5.1): an IPv4 address by
// itself; an IPv6 address by its /64, and by its /56 and /48 at four times the level below, so one
// allocation cannot rotate through its /64s.
func ConnLevels(a netip.Addr) []Level {
	a = a.Unmap()
	if !a.IsValid() {
		return nil
	}
	if a.Is4() {
		return []Level{{"4:" + a.String(), 1}}
	}
	return []Level{
		{"6/64:" + prefix(a, 64), 1},
		{"6/56:" + prefix(a, 56), 4},
		{"6/48:" + prefix(a, 48), 16},
	}
}

func prefix(a netip.Addr, bits int) string { return netip.PrefixFrom(a, bits).Masked().String() }

// NetKey is the /24 of an IPv4 address and the /56 of an IPv6 one: the unit of the Enrollment and
// install limits (5.1, 5.7).
func NetKey(a netip.Addr) string {
	a = a.Unmap()
	if !a.IsValid() {
		return ""
	}
	if a.Is4() {
		return prefix(a, 24)
	}
	return prefix(a, 56)
}

// ---------------------------------------------------------------------------------------------------
// Connections before TLS.

type connEntry struct {
	open   int
	tokens float64
	last   time.Time
}

// Conns caps open connections and new connections a second per source, before TLS starts (5.1: 16
// open and 10 new a second at the base level).
type Conns struct {
	mu      sync.Mutex
	maxOpen int
	rate    float64
	now     Clock
	m       map[string]*connEntry
	sweepAt time.Time
}

// NewConns makes the limiter; maxOpen and rate are the base level.
func NewConns(maxOpen int, rate float64, now Clock) *Conns {
	return &Conns{maxOpen: maxOpen, rate: rate, now: now, m: make(map[string]*connEntry)}
}

// Admit counts a new connection from a under every level, all or nothing. The release function ends
// the count when the connection closes.
func (c *Conns) Admit(a netip.Addr) (release func(), ok bool) {
	levels := ConnLevels(a)
	if len(levels) == 0 {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	c.sweep(now)
	ents := make([]*connEntry, len(levels))
	for i, l := range levels {
		e, found := c.m[l.Key]
		if !found {
			if len(c.m) >= maxKeys {
				return nil, false
			}
			e = &connEntry{tokens: c.rate * float64(l.Mult), last: now}
			c.m[l.Key] = e
		}
		burst := c.rate * float64(l.Mult)
		if d := now.Sub(e.last).Seconds(); d > 0 {
			e.tokens = min(burst, e.tokens+d*burst)
			e.last = now
		}
		ents[i] = e
		if e.open >= c.maxOpen*l.Mult || e.tokens < 1 {
			return nil, false
		}
	}
	for _, e := range ents {
		e.open++
		e.tokens--
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			c.mu.Lock()
			for _, e := range ents {
				e.open--
			}
			c.mu.Unlock()
		})
	}, true
}

func (c *Conns) sweep(now time.Time) {
	if now.Before(c.sweepAt) {
		return
	}
	c.sweepAt = now.Add(time.Second)
	for k, e := range c.m {
		if e.open == 0 && now.Sub(e.last) > 2*time.Second {
			delete(c.m, k)
		}
	}
}

// Len is the number of live keys.
func (c *Conns) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.m)
}

// ---------------------------------------------------------------------------------------------------
// Handshakes.

// Handshakes caps TLS handshakes in progress (5.1): 256 hub-wide, 32 per IPv4 /24, per IPv6 /48 and per
// IPv6 /32, and, outside every share, 64 slots that only a source in the node address set may use, so a
// flood of strangers cannot keep a node from reconnecting.
type Handshakes struct {
	mu       sync.Mutex
	total    int
	reserved int
	perPref  int
	nTotal   int
	nRes     int
	byPrefix map[string]int
	resBySrc map[netip.Addr]int
}

// NewHandshakes makes the limiter with the numbers of D31.
func NewHandshakes(total, reserved, perPrefix int) *Handshakes {
	return &Handshakes{total: total, reserved: reserved, perPref: perPrefix, byPrefix: make(map[string]int), resBySrc: make(map[netip.Addr]int)}
}

func handshakeKeys(a netip.Addr) []string {
	a = a.Unmap()
	if a.Is4() {
		return []string{prefix(a, 24)}
	}
	return []string{prefix(a, 48), prefix(a, 32)}
}

// ReservedPerSource is how many reserved slots one address may hold at once: a node opens at most six
// connections (5.1), so more than that from one address is not a node reconnecting.
const ReservedPerSource = 8

// Begin takes a handshake slot for a source. node says the source is in the node address set: such a
// source takes a reserved slot while its own share of them and the reserved pool have room, and
// otherwise goes through the general path like any source, so a full reserved pool never costs a node
// the general slots that are free.
func (h *Handshakes) Begin(a netip.Addr, node bool) (release func(), ok bool) {
	if !a.IsValid() {
		return nil, false
	}
	a = a.Unmap()
	keys := handshakeKeys(a)
	h.mu.Lock()
	defer h.mu.Unlock()
	if node && h.nRes < h.reserved && h.resBySrc[a] < ReservedPerSource {
		h.nRes++
		h.resBySrc[a]++
		var once sync.Once
		return func() {
			once.Do(func() {
				h.mu.Lock()
				h.nRes--
				if h.resBySrc[a]--; h.resBySrc[a] <= 0 {
					delete(h.resBySrc, a)
				}
				h.mu.Unlock()
			})
		}, true
	}
	if h.nTotal >= h.total {
		return nil, false
	}
	for _, k := range keys {
		if h.byPrefix[k] >= h.perPref {
			return nil, false
		}
	}
	h.nTotal++
	for _, k := range keys {
		h.byPrefix[k]++
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			h.mu.Lock()
			h.nTotal--
			for _, k := range keys {
				if h.byPrefix[k]--; h.byPrefix[k] <= 0 {
					delete(h.byPrefix, k)
				}
			}
			h.mu.Unlock()
		})
	}, true
}

// InProgress is the number of handshakes in progress, reserved ones included.
func (h *Handshakes) InProgress() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.nTotal + h.nRes
}

// ---------------------------------------------------------------------------------------------------
// Per node.

// Counts holds a count per key under one cap: open connections per node_id, open transfer RPCs per node.
type Counts struct {
	mu  sync.Mutex
	max int
	m   map[string]int
}

// NewCounts makes a per-key cap.
func NewCounts(max int) *Counts { return &Counts{max: max, m: make(map[string]int)} }

// Take counts one more for key, unless key is at its cap.
func (c *Counts) Take(key string) (release func(), ok bool) {
	c.mu.Lock()
	if c.m[key] >= c.max {
		c.mu.Unlock()
		return nil, false
	}
	c.m[key]++
	c.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			c.mu.Lock()
			if c.m[key]--; c.m[key] <= 0 {
				delete(c.m, key)
			}
			c.mu.Unlock()
		})
	}, true
}

// Of is the current count of key.
func (c *Counts) Of(key string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.m[key]
}
