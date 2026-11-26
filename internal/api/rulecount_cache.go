package api

import (
	"sync"

	"github.com/google/uuid"
)

// ruleCountCacheMax bounds the entries of one process: a tenant has at most a few dozen profiles, so this holds the
// profiles of several thousand tenants. At the bound the map is emptied, which costs one recount per profile, never a wrong
// answer.
const ruleCountCacheMax = 100_000

// ruleCountCache remembers the number of rules of a profile at a version of it, so GET /profiles does not count the rules
// of every profile on every request (p2-B3-r14-1: 20 profiles of 10,000 rules is 200,000 index tuples a request, and a tenant
// with many sessions sends hundreds a second).
//
// The version is what makes it correct. Every statement that adds, changes or removes a rule of a profile runs after
// Tx.ProfileGuard, which steps profiles.version in the same transaction (spec 3.1), and a deleted folder or profile is
// guarded the same way; so a reader that sees version V sees the same rules as every other reader of version V, on any
// instance of the API. The cache never decides freshness: the caller reads the version from the database in the snapshot of
// its own request and the cache only answers for that exact version. A new writer of rules that skipped the guard would break
// this, which is why the guard is the only way to write one (S9).
//
// The zero value is ready to use.
type ruleCountCache struct {
	mu sync.Mutex
	m  map[ruleCountKey]ruleCountEntry
}

type ruleCountKey struct{ tenant, profile uuid.UUID }

type ruleCountEntry struct {
	version int64
	rules   int
}

// get returns the count remembered for the profile at exactly this version.
func (c *ruleCountCache) get(tenant, profile uuid.UUID, version int64) (int, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[ruleCountKey{tenant, profile}]
	if !ok || e.version != version {
		return 0, false
	}
	return e.rules, true
}

// put remembers a count that was read in a snapshot that saw this version. An older version never replaces a newer one: two
// requests that raced, one with an older snapshot, leave the newer answer in place.
func (c *ruleCountCache) put(tenant, profile uuid.UUID, version int64, rules int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	k := ruleCountKey{tenant, profile}
	if old, ok := c.m[k]; ok {
		if old.version > version {
			return
		}
	} else if len(c.m) >= ruleCountCacheMax {
		c.m = nil
	}
	if c.m == nil {
		c.m = map[ruleCountKey]ruleCountEntry{}
	}
	c.m[k] = ruleCountEntry{version: version, rules: rules}
}
