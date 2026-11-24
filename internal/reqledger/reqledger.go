// Package reqledger is a small notebook that lives for one request. The throttle writes into it
// when a hit is counted and reads from it when the same request gives the hit back, so a refund
// can name the window the attempt was counted in (review round 6, primitives-r6-2).
//
// It is a package of its own, and not part of the throttle, because the HTTP spine installs it
// (httpx.Outbox) and must not import the throttle, the store and the key ring to do so.
//
// The book holds numbers under string keys and nothing else: nothing a client sent, and nothing
// secret (the throttle keys are HMACs, and they are hex-encoded by the writer).
package reqledger

import (
	"context"
	"sync"
)

// maxEntries bounds the book. A request counts a handful of scopes; a request that wrote more
// would be a defect, and the entries past the bound are dropped, which only means a refund of
// them finds nothing and is not made (fail closed: the attempt stays counted).
const maxEntries = 64

type ctxKey struct{}

// Book is the notebook of one request. It is safe for concurrent use, since a handler may
// charge from more than one goroutine.
type Book struct {
	mu sync.Mutex
	m  map[string]entry
}

// entry is a value and how many times it was written: a request that counts the same key twice
// may give it back twice, and each give-back uses one.
type entry struct {
	v int64
	n int
}

// With returns ctx with a book in it. A context that already has one is returned as it is, so
// two layers that both install a book share one.
func With(ctx context.Context) context.Context {
	if _, ok := ctx.Value(ctxKey{}).(*Book); ok {
		return ctx
	}
	return context.WithValue(ctx, ctxKey{}, &Book{m: make(map[string]entry)})
}

// From returns the book of the request, or false when none was installed.
func From(ctx context.Context) (*Book, bool) {
	b, ok := ctx.Value(ctxKey{}).(*Book)
	return b, ok
}

// Put records a value under key. The latest value wins and the count of writes goes up.
func (b *Book) Put(key string, v int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	e, ok := b.m[key]
	if !ok && len(b.m) >= maxEntries {
		return
	}
	b.m[key] = entry{v: v, n: e.n + 1}
}

// Take uses one write of key: it returns the value, and removes the entry when no write is
// left, so a hit is given back as many times as it was counted and no more.
func (b *Book) Take(key string) (int64, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	e, ok := b.m[key]
	if !ok {
		return 0, false
	}
	if e.n <= 1 {
		delete(b.m, key)
	} else {
		e.n--
		b.m[key] = e
	}
	return e.v, true
}
