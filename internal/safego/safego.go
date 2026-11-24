// Package safego is the one place that starts a goroutine, and the one place that keeps a panic
// with the unit of work that raised it (P1 auth review round 18, sms-r18-1, D64 goroutine-panic;
// rule goroutine-recover).
//
// Why one package. Go ends the whole process on a panic in any goroutine, and the request recover
// of the pipeline covers only the request's own. Rounds 14, 15 and 17 each found a goroutine that
// had no recover, and the lint that looked for one could follow only the callees it could resolve:
// `go fn()` through a function value or an interface method passed. The lint now forbids every `go`
// statement outside this package (internal/lint TestEveryGoroutineKeepsItsPanic), a check with no
// resolution in it, so the class is closed by construction: a goroutine that is not started here is
// not started, and the one `go` statement below is the one the lint reads for its guard.
//
// The library calls that start a goroutine with no `go` statement are the same class, and the lint
// reads them as one (sms-r18-14): a call outside this module that is handed a function of no
// arguments (time.AfterFunc, context.AfterFunc, sync.WaitGroup.Go, errgroup's Go, a hook of a
// server) is a finding unless it is listed as synchronous, so the timer and the context callback
// are made here (After, OnDone) and a group of goroutines is Go with a WaitGroup counted down first.
//
// What a kept panic costs. The unit that raised it is left as a crash would leave it (its work is
// not undone, retried or compensated here), and the process goes on. That is right for a unit that
// is written to be run again from a crash: a claim lapses, a sweep is idempotent, a job resumes,
// and a task owed after an answer costs one trail row. It is wrong for a top-level loop whose end
// would leave a process that looks healthy and does nothing (the serve loop, the admin role's
// session sweep): those keep their `go` statement on the short list of the lint and crash, so
// Compose restarts the process.
//
// What a kept panic says: the name of the unit (a closed value), the type of the panic value and a
// bounded stack, never the value, which can hold anything the code was handling (a phone number, a
// reply of a provider). The line is the count: an operator searches for Msg, and the metrics registry of a
// later phase counts there. There is no counter in this package because the workspace rule forbids
// package-level mutable state except registered metrics, and no registry exists yet (D64 asked for a count;
// the log line is it until then).
package safego

import (
	"context"
	"log/slog"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/closed"
	"github.com/Kup1ng/CtrlZ-Panel/internal/logattr"
)

// Msg is the one log message of a kept panic, so an operator can search for it.
const Msg = "unit panicked"

// note says one kept panic. rec is the value recover returned: only its type is logged.
// A nil log says nothing, so a unit built with no logger cannot turn a kept panic into a crash.
func note[K closed.Closed](log *slog.Logger, what K, rec any) {
	if log == nil {
		return
	}
	log.Error(Msg, logattr.Enum("unit", what), logattr.TypeName("panic_type", rec), logattr.Stack())
}

// Keep is deferred directly (`defer safego.Keep(log, unit)`) at the top of one pass of a loop, so a
// panic in the pass costs that pass and the loop goes on at its next tick: recover only stops a
// panic when the deferred function itself calls it, so a wrapper around Keep would stop nothing.
// what is the closed value that says which unit it was.
func Keep[K closed.Closed](log *slog.Logger, what K) {
	if rec := recover(); rec != nil {
		note(log, what, rec)
	}
}

// Run runs fn and keeps its panic, and reports whether fn panicked. It is for a caller that must
// act on the failure of its unit after the unit has unwound (the SMS worker ends a row that
// panicked): by the time Run returns, every deferred function of fn has run, a transaction that
// fn held open has rolled back, and nothing of fn is still on the stack.
func Run[K closed.Closed](log *slog.Logger, what K, fn func()) (panicked bool) {
	defer func() {
		if rec := recover(); rec != nil {
			panicked = true
			note(log, what, rec)
		}
	}()
	fn()
	return false
}

// Go starts fn in a goroutine that keeps its panic. It is the only `go` statement outside the
// short list of top-level loops (internal/lint goroutineTopLevel). A caller that counts its
// goroutines down puts `defer wg.Done()` first in fn: it runs while the panic unwinds, before the
// recover below, so a unit that panicked is still counted down.
func Go[K closed.Closed](log *slog.Logger, what K, fn func()) {
	go func() {
		defer Keep(log, what)
		fn()
	}()
}

// After runs fn once, in a goroutine of the runtime, after d, and keeps its panic. It is the one
// timer callback of the module (P1 auth review round 18, sms-r18-14): time.AfterFunc starts a
// goroutine with no `go` statement, so a panic in its function would end the process exactly like
// an unguarded `go`, and the lint of rule goroutine-recover refuses the original outside this
// package. The caller stops the timer as it would a time.Timer.
func After[K closed.Closed](log *slog.Logger, what K, d time.Duration, fn func()) *time.Timer {
	return time.AfterFunc(d, func() {
		defer Keep(log, what)
		fn()
	})
}

// OnDone runs fn once in a goroutine of the runtime when ctx is done, and keeps its panic: the
// guarded form of context.AfterFunc, refused outside this package for the reason given at After.
// The returned function has the meaning it has there (it stops the call and reports whether it
// did).
func OnDone[K closed.Closed](ctx context.Context, log *slog.Logger, what K, fn func()) (stop func() bool) {
	return context.AfterFunc(ctx, func() {
		defer Keep(log, what)
		fn()
	})
}
