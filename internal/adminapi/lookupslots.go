package adminapi

import "sync"

// deferredLookupSlots is how many logins of the deferred class admin-login may be reading the
// account at once (round 8, admin-r8-1, -4).
//
// The class is the cheap cut in front of the database only for a request that cannot be the one it
// lets through (a password that has no console one-time shape, answered before anything is read).
// A request that has the shape must read the account to be told from the owner's, and the admin pool
// is small (CTRLZ_ADMIN_DB_MAX_CONNS, 5 by default) and shared with the owner's session lookups. Two
// slots leave the other connections to them: a flood of well-shaped junk is refused at once beyond the
// slots, and costs the owner's pool at most two short reads at a time. The price is declared in spec
// 10.2: while such a flood runs at line rate, the owner's own first login (no device marker) can be
// refused like the rest and has to be retried; the class's refusal is a plain 429 with Retry-After.
const deferredLookupSlots = 2

// lookupSlots is a non-blocking counting semaphore. A busy request is not queued: queueing is the
// cost the slots exist to refuse, and the decision does not depend on any account, so no oracle.
type lookupSlots chan struct{}

func newLookupSlots(n int) lookupSlots { return make(lookupSlots, n) }

// try takes a slot if one is free and returns the function that gives it back (once: it may be
// called from the lookup and again from a deferred cleanup).
func (l lookupSlots) try() (release func(), ok bool) {
	select {
	case l <- struct{}{}:
		var once sync.Once
		return func() { once.Do(func() { <-l }) }, true
	default:
		return nil, false
	}
}
