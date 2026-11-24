package httpx

import "sync"

// deadCapacity is how many dead cookies one process remembers. A cookie is a 22-byte key, so the
// set is a few megabytes at most; a full set forgets the oldest first, which costs one lookup of
// that cookie again and nothing else.
const deadCapacity = 1 << 16

// deadSet remembers the lookup keys of cookies whose session is gone for good (review round 6,
// primitives-r6-5). A revoked, rotated or expired session never comes back to life, and its cookie
// keeps a valid tag for as long as its own expiry says (a day, or ninety days with "remember me"),
// so after one lookup that missed, the cookie is refused here for the price of a map read.
//
// The rule it serves is that nothing which is not proof of a live session may refuse one that is.
// Round 5 charged a network bucket (session-miss) before every lookup and gave it back for a live
// one, so any account holder who kept the cookies of his ended sessions could empty the bucket of
// the /24 he shares with every tenant behind a carrier and have the live cookies of strangers
// refused before their lookup (primitives-r6-5). The cost a dead cookie can now impose is one
// lookup, ever, per process; the number of distinct dead cookies is the number of requests the
// holder spent minting them.
//
// It holds a map and a first-in-first-out ring and no clock: a mark never expires by time (the
// token carries its own expiry, Screen refuses it past that), so there is nothing to age.
type deadSet struct {
	mu   sync.Mutex
	seen map[string]struct{}
	ring []string
	next int
	// capacity is how many marks the set holds before it forgets the oldest.
	capacity int
}

func newDeadSet(capacity int) *deadSet {
	if capacity <= 0 {
		capacity = deadCapacity
	}
	return &deadSet{seen: make(map[string]struct{}, 1024), ring: make([]string, 0, min(capacity, 1024)), capacity: capacity}
}

// has reports whether key was marked dead and not yet forgotten.
func (d *deadSet) has(key string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, ok := d.seen[key]
	return ok
}

// add marks key dead, forgetting the oldest mark when the set is full.
func (d *deadSet) add(key string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.seen[key]; ok {
		return
	}
	if len(d.ring) < d.capacity {
		d.ring = append(d.ring, key)
	} else {
		delete(d.seen, d.ring[d.next])
		d.ring[d.next] = key
		d.next = (d.next + 1) % d.capacity
	}
	d.seen[key] = struct{}{}
}
