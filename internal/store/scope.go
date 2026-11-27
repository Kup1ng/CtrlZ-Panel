package store

import (
	"context"
	"sync/atomic"
)

// A request scope is the second half of the one-connection-per-request rule (rule 14; tenant-r18-8).
//
// The first half is txMarker: the context a transaction hands its callback carries a marker, and a call
// made with THAT context is refused (ErrNested) before it asks the pool for a second connection. It sees only
// the context chain. A closure built before the transaction that captured the outer context, a method of a
// struct that holds one, or a method value taken outside the callback, all reach the pool with a context that
// has no marker while the transaction holds its connection, and the lint (oneconn_test.go) reads only functions
// that have a Tx parameter, so it could not see them either. N such requests on a pool of N wait for each
// other, which is the wave of 503s the rule exists to remove.
//
// The scope removes the dependence on the chain. The request pipeline puts one counter into the context of the
// request (WithRequestScope, in httpx.Outbox); every context derived from it, the outer one included, shares the
// counter. A transaction raises it for as long as it holds its connection, and a call that asks the pool for
// another connection while it is raised is refused, whatever context it was given. This is a construction and
// not a list of shapes: the one place that hands out a connection (one, and run for WithTenant and WithGlobal)
// judges it, so no caller can reach the pool around it.
//
// It judges only a context that carries a scope, which is the context of a request. Workers and the console
// have none, and need none: they run no handler, and a job that wants two connections at once says so with
// two transactions of its own. Two transactions of ONE request that overlap in time (parallel goroutines
// holding one connection each) are refused too, since each can be the waiter of the other on a small pool; a
// handler that needs two runs them one after the other.
type scopeKey struct{}

type requestScope struct {
	// open is how many transactions of this request hold a connection right now.
	open atomic.Int32
}

// WithRequestScope returns ctx marked as the context of one request. It is idempotent: a context that
// already has a scope keeps it, so a second call does not reset a count that a transaction holds.
func WithRequestScope(ctx context.Context) context.Context {
	if ctx.Value(scopeKey{}) != nil {
		return ctx
	}
	return context.WithValue(ctx, scopeKey{}, &requestScope{})
}

// InRequestScope reports whether ctx belongs to a request scope.
func InRequestScope(ctx context.Context) bool { return ctx.Value(scopeKey{}) != nil }

// scopeBusy says the request that ctx belongs to already holds a connection, so asking for another is the
// self-wait of the rule. A context with no scope is never busy.
func scopeBusy(ctx context.Context) bool {
	sc, _ := ctx.Value(scopeKey{}).(*requestScope)
	return sc != nil && sc.open.Load() > 0
}

// scopeHold raises the count of the request for the length of a transaction and returns what lowers it. It is
// called only after the pool has handed the connection out, and the release runs after the commit or the
// rollback has returned it, so the count never reads zero while the connection is still held.
func scopeHold(ctx context.Context) (release func()) {
	sc, _ := ctx.Value(scopeKey{}).(*requestScope)
	if sc == nil {
		return func() {}
	}
	sc.open.Add(1)
	return func() { sc.open.Add(-1) }
}

// DetachRequestScope gives ctx a request scope of its own when it has one, for work that is owed after the answer and runs on
// a goroutine of its own (internal/afterwork; tenant-r19-2 and -5). That work must keep the request's values (the client
// address, the request id) and not its count of connections: sharing the counter made a task that held a connection refuse the
// transaction the request opens next with ErrNested (a valid login answering 500), and made a request that was in a transaction
// refuse the task's write silently, and two tasks of one request refuse each other. The task is a one-connection unit of its
// own, so it gets a fresh counter and the rule still holds inside it. A context with no scope is returned as it is.
func DetachRequestScope(ctx context.Context) context.Context {
	if ctx.Value(scopeKey{}) == nil {
		return ctx
	}
	return context.WithValue(ctx, scopeKey{}, &requestScope{})
}
