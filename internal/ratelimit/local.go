package ratelimit

import (
	"container/list"
	"sync"
	"time"
)

// slot is one bucket the limiter must take from: a storage key and its shape.
type slot struct {
	key string
	max int
	per time.Duration
}

// DefaultLocalKeys is the size of the in-process fallback (spec 14.1).
const DefaultLocalKeys = 10000

// local is the in-process bucket set used while Valkey is down. It is a fixed
// size LRU, so an attacker spraying keys can evict others' state but cannot grow
// memory: a bucket that is forgotten starts full, which only ever favours the
// client, and that is the right side to err on for a speed bump.
type local struct {
	mu    sync.Mutex
	cap   int
	order *list.List // front = most recently used
	items map[string]*list.Element
}

type bucket struct {
	key    string
	tokens float64
	at     time.Time
}

func newLocal(capacity int) *local {
	if capacity < 1 {
		capacity = DefaultLocalKeys
	}
	return &local{cap: capacity, order: list.New(), items: make(map[string]*list.Element, capacity)}
}

// state returns the bucket of a slot refilled up to now, creating a full one.
// The caller holds mu.
func (l *local) state(s slot, now time.Time) *bucket {
	if el, ok := l.items[s.key]; ok {
		l.order.MoveToFront(el)
		b := el.Value.(*bucket)
		if dt := now.Sub(b.at); dt > 0 {
			b.tokens += float64(s.max) * float64(dt) / float64(s.per)
			if b.tokens > float64(s.max) {
				b.tokens = float64(s.max)
			}
		}
		b.at = now
		return b
	}
	b := &bucket{key: s.key, tokens: float64(s.max), at: now}
	l.items[s.key] = l.order.PushFront(b)
	for l.order.Len() > l.cap {
		last := l.order.Back()
		l.order.Remove(last)
		delete(l.items, last.Value.(*bucket).key)
	}
	return b
}

// take removes one token from every slot, or from none. When it refuses it
// returns how long until every refused slot has a token.
func (l *local) take(slots []slot, now time.Time) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	bs := make([]*bucket, len(slots))
	var wait time.Duration
	for i, s := range slots {
		bs[i] = l.state(s, now)
		if bs[i].tokens < 1 {
			rate := float64(s.max) / float64(s.per) // tokens per nanosecond
			if w := time.Duration((1 - bs[i].tokens) / rate); w > wait {
				wait = w
			}
		}
	}
	if wait > 0 {
		return false, wait
	}
	for _, b := range bs {
		b.tokens--
	}
	return true, 0
}

// give returns one token to every slot, up to its capacity.
func (l *local) give(slots []slot, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, s := range slots {
		b := l.state(s, now)
		b.tokens++
		if b.tokens > float64(s.max) {
			b.tokens = float64(s.max)
		}
	}
}

func (l *local) size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.order.Len()
}
