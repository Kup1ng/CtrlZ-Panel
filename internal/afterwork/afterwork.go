// Package afterwork runs what a handler owes after its answer is decided and its floor
// has passed (P1 auth review round 13, tenant-r13-2, rules.md topic 4).
//
// Why it exists: a handler that answers inside a timing floor must not do I/O that the
// existence of an account chooses inside that floor. A wrong password for a phone with an
// account writes a `login.failed` row, which asks the pool for a second connection; an
// unknown phone asks for none. Under a busy pool that second wait is added to the floor and
// a known phone answers late, so the answer's time tells the two apart. The row is still
// wanted, so it is not dropped: the handler hands it to this queue, which runs it after
// the floor, off the request, on a bounded footprint.
//
// The queue is bounded twice and drops what does not fit. Pending tasks are limited (each
// is a parked goroutine), and so is how many run at once (each holds a pool connection), so
// a flood of failed logins cannot hold the pool or grow memory. A dropped task is a trail
// row not written, never an answer changed: the callers write rows that are bounded by the
// throttle and are not counters or gates. The count is not left to a test: the queue says, at
// most once a minute, how many it dropped, and a task that panics costs one trail row and not
// the process (P1 auth review round 14, tenant-r14-2, tenant-r14-3).
package afterwork

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/logattr"
	"github.com/Kup1ng/CtrlZ-Panel/internal/safego"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// Runner is what a handler needs: run fn after the request, or drop it. Tests supply their
// own to hold the work until they have looked at what the request itself did.
type Runner interface {
	// Go reports whether fn was accepted. fn gets a context that keeps the values of ctx and
	// not its cancellation, and that ends after a deadline.
	Go(ctx context.Context, fn func(context.Context)) bool
}

// Defaults of the queue the api builds.
const (
	DefaultPending = 64              // tasks waiting or running
	DefaultWorkers = 4               // tasks running at once
	DefaultBudget  = 5 * time.Second // the longest one task may take
)

// Queue is the production Runner.
type Queue struct {
	slots    chan struct{} // one token per accepted task, until it finishes
	run      chan struct{} // one token per task that is running
	budget   time.Duration
	wg       sync.WaitGroup
	dropped  atomic.Uint64
	reported atomic.Uint64 // the part of dropped a log line has already said
	lastWarn atomic.Int64  // unix nanoseconds of the last drop warning
	log      *slog.Logger
	now      func() time.Time
}

// warnEvery is the least time between two drop warnings: a flood that keeps the queue full
// must not also fill the log (the same suppression as the limiter's Valkey warning).
const warnEvery = time.Minute

// New builds a queue; a value of zero or less takes the default.
func New(pending, workers int, budget time.Duration) *Queue {
	if pending <= 0 {
		pending = DefaultPending
	}
	if workers <= 0 {
		workers = DefaultWorkers
	}
	if budget <= 0 {
		budget = DefaultBudget
	}
	return &Queue{
		slots: make(chan struct{}, pending), run: make(chan struct{}, workers), budget: budget,
		log: slog.New(slog.DiscardHandler), now: time.Now,
	}
}

// WithLog sets where the queue reports a panic in a task and the tasks it dropped. The api
// and the tests that read the report set it; a queue without one stays silent.
func (q *Queue) WithLog(l *slog.Logger) *Queue {
	if l != nil {
		q.log = l
	}
	return q
}

// WithClock replaces the wall clock of the warning's suppression window, for a test.
func (q *Queue) WithClock(now func() time.Time) *Queue {
	if now != nil {
		q.now = now
	}
	return q
}

// Go implements Runner. It never blocks the caller.
func (q *Queue) Go(ctx context.Context, fn func(context.Context)) bool {
	select {
	case q.slots <- struct{}{}:
	default:
		q.dropped.Add(1)
		q.warnDropped(false)
		return false
	}
	// The values (the client address, the request id) are kept for the log lines of the work;
	// the cancellation is not, or the end of the request would end the write.
	// The request's connection count is not kept either: the task is a one-connection unit of its own (tenant-r19-2, -5).
	base := store.DetachRequestScope(context.WithoutCancel(ctx))
	q.wg.Add(1)
	safego.Go(q.log, unitTask, func() { q.runTask(base, fn) })
	return true
}

// runTask is the goroutine of one accepted task. Its first statement keeps a panic from any line
// after it: the request goroutine is covered by the pipeline's recover and this one is not, and Go
// ends the whole process on a panic in any goroutine, so one bad task would cost every tenant the
// service where it should cost one trail row (the goroutine-recover lint holds this shape, round 15,
// tenant-r15-3: it used to guard only the call of fn, not the rest).
func (q *Queue) runTask(base context.Context, fn func(context.Context)) {
	defer q.endTask(base)
	defer func() { <-q.slots }()
	q.run <- struct{}{}
	defer func() { <-q.run }()
	c, cancel := context.WithTimeout(base, q.budget)
	defer cancel()
	fn(c)
}

// endTask is the deferred function that keeps a panic of the task and then counts the task done.
// It runs last, after the slots are given back, and it counts the task done even when it logs a
// panic, so Drain never waits for a task that has already failed. Only the type of the panic value
// is logged, as the pipeline does: the value can carry request data.
func (q *Queue) endTask(ctx context.Context) {
	defer q.wg.Done()
	if rec := recover(); rec != nil {
		q.log.ErrorContext(ctx, "work owed after an answer panicked", logattr.TypeName("panic_type", rec), logattr.Stack())
	}
}

// warnDropped says, at most once a minute (always when force is set), how many tasks were
// dropped since the last line. Before this a drop was counted and never read, so an attacker who
// kept the queue full made failed-login rows vanish with no trace for the operator.
func (q *Queue) warnDropped(force bool) {
	if !force {
		now := q.now().UnixNano()
		last := q.lastWarn.Load()
		if now-last <= int64(warnEvery) || !q.lastWarn.CompareAndSwap(last, now) {
			return
		}
	}
	total := q.dropped.Load()
	prev := q.reported.Swap(total)
	if total > prev {
		q.log.Warn("work owed after an answer was dropped because the queue is full", logattr.Int("dropped", int(total-prev)), logattr.Int("dropped_total", int(total)))
	}
}

// Dropped is how many tasks were refused because the queue was full.
func (q *Queue) Dropped() uint64 { return q.dropped.Load() }

// Wait returns when every accepted task has finished. A test uses it before it reads the
// rows; a shutdown uses Drain.
func (q *Queue) Wait() { q.wg.Wait() }

// Drain is what a shutdown calls after the server has stopped taking requests and before the
// pool closes: it waits for the accepted tasks for at most d (a task past its own budget ends
// by itself), reports the drops no line has said yet, and says whether every task finished.
// A task still running when it returns fails on a closed pool and its row is lost, so the
// caller gives d the budget of a task.
func (q *Queue) Drain(d time.Duration) bool {
	done := make(chan struct{})
	safego.Go(q.log, unitDrain, func() { q.wg.Wait(); close(done) })
	t := time.NewTimer(d)
	defer t.Stop()
	ok := false
	select {
	case <-done:
		ok = true
	case <-t.C:
	}
	q.warnDropped(true)
	return ok
}

// Owed collects what one request owes after its floor. A handler passes the pointer into
// the floored body, so the body can add work without doing it, and calls Run when the floor
// has returned. The zero value is ready.
type Owed struct{ fns []func(context.Context) }

// Add records work for after the floor.
func (o *Owed) Add(fn func(context.Context)) { o.fns = append(o.fns, fn) }

// Run hands every recorded task to r. A nil Runner drops them, which a caller may not want:
// the api always builds one.
func (o *Owed) Run(ctx context.Context, r Runner) {
	for _, fn := range o.fns {
		if r != nil {
			r.Go(ctx, fn)
		}
	}
	o.fns = nil
}

// unit names a goroutine of the queue for the log line safego writes: a closed type, so a line can carry it.
type unit string

const (
	unitTask  unit = "task"  // one accepted task
	unitDrain unit = "drain" // the waiter of a shutdown Drain
)

// Valid reports membership.
func (u unit) Valid() bool { return u == unitTask || u == unitDrain }
