// Package cachex is the one in-process cache of database or network state (P1 auth
// review, round 5, rule cache-loader).
//
// Three hand-written caches (the public configuration, the Valkey client and the SMS
// router snapshot) each wrote their own lock, reload, retry and invalidation, and between
// them held a mutex across I/O, retried on every request after a failure, lost an
// Invalidate that arrived during a reload, and served a stale snapshot to a send that
// needed what had just been saved. A Loader does these things once:
//
//   - The load runs outside the mutex, on a context the Loader owns (a caller that gives
//     up does not fail the load the others wait for), one at a time (single flight).
//   - A value past its TTL is served stale while one load revalidates it; only the caller
//     that starts the load waits, and for at most StaleWait.
//   - After a failed load nobody loads again for RetryAfter, so an outage costs one query
//     per interval and not one per request. The last good value keeps being served.
//   - Invalidate counts a generation. A load remembers the generation it started under, and
//     its result counts as current only if no Invalidate came meanwhile: the value is
//     served, but the next Get loads again, so an Invalidate during a load is never lost.
//   - Fresh is for a caller that needs what was saved a moment ago: it returns a value from
//     a load that started after the call, or the error of that load. It never answers
//     from the old value.
//
// No mutex is held across a wait or a call that takes a context: internal/lint
// TestNoMutexAcrossIO fails any function that does, and TestNoHandRolledCache fails a
// struct elsewhere that pairs a mutex with a clock value or a channel.
package cachex

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/logattr"
)

// Name is which cache a log line is about. It is a closed set, so a line can say it without a
// string that could carry data (rule closed-values-in-logs); a new cache adds its name here.
type Name string

// The caches.
const (
	NameAuthConfig  Name = "auth_config"
	NameValkey      Name = "valkey_client"
	NameSMSSnapshot Name = "sms_router"
)

// Valid reports membership.
func (n Name) Valid() bool {
	switch n {
	case NameAuthConfig, NameValkey, NameSMSSnapshot:
		return true
	}
	return false
}

// logEvery is the quietest a kind of line is: a source that keeps failing is retried every
// RetryAfter, and a line per try would flood the log without telling the operator more. The line
// says how many events it stands for.
const logEvery = time.Minute

// ErrStale is what Get returns when the last good value is older than Config.MaxStale and no load
// has replaced it: the cache would rather answer with an error than with a value it cannot vouch
// for any more (round 15, tenant-r15-4).
var ErrStale = errors.New("cachex: the last good value is too old to serve")

// ErrReset is what a caller waiting for a load gets when Reset ran during the load: the
// value was handed to Release and nobody sees it.
var ErrReset = errors.New("cachex: reset during the load")

// ErrLoadPanicked is what a load that panicked is turned into. The load runs on a goroutine of
// its own, which no request recover covers, and Go ends the whole process on a panic there, so
// one bad row in a source would take every tenant down with it (round 14, tenant-r14-2). The
// panic value is dropped: it can carry what was loaded.
var ErrLoadPanicked = errors.New("cachex: the load panicked")

const (
	defaultRetryAfter  = 5 * time.Second
	defaultLoadTimeout = 5 * time.Second
)

// Config describes one cached value.
type Config[T any] struct {
	// Load reads the value. It gets a context of the Loader's own, bounded by
	// LoadTimeout, never a caller's. It should return a fixed error: the first caller
	// of a cold Loader sees it.
	Load func(ctx context.Context) (T, error)
	// TTL is how long a loaded value is current. Zero means it never expires on its own
	// (a client that reconnects by itself); Invalidate and Fresh still apply.
	TTL time.Duration
	// RetryAfter is the pause after a failed load (default 5 s). It is never zero, so a
	// failing source cannot be loaded in a loop.
	RetryAfter time.Duration
	// LoadTimeout bounds one load (default 5 s).
	LoadTimeout time.Duration
	// StaleWait is the longest the caller that starts a revalidation waits for it while a
	// stale value exists. Zero serves the stale value at once.
	StaleWait time.Duration
	// MaxStale bounds how long the last good value is served while every reload fails. Past it
	// Get returns ErrStale (or the error of the load that is run) and not the old value. Every
	// cache must choose: either MaxStale above zero, or ServeStaleForever with the reason. Both
	// absent is refused by New, because the default used to be "for ever", and two of the three
	// caches took it by leaving the field out (round 16, tenant-r16-12: the SMS router kept the
	// gateway roles and credentials of its last good load, a gateway the operator had just
	// disabled included, with nobody told). A value that gates a security decision (the public
	// configuration: is registration open, is Passkey on) is bounded, because a source that keeps
	// failing would otherwise keep an old decision in force (round 15, tenant-r15-4).
	MaxStale time.Duration
	// ServeStaleForever is the reason a value may be served for ever when every reload fails: what it
	// is (a client that reconnects by itself, a snapshot whose staleness is harmless). It is the explicit
	// form of the old zero MaxStale, so the choice is written down and read in review.
	ServeStaleForever string
	// Now is the clock for the TTL, the pause and the log pacing (default time.Now). It must not
	// panic: the goroutine that loads reads it after a panic of the source too.
	Now func() time.Time
	// Name and Log say which cache a line is about and where it goes, and both are required: a cache
	// that fails or panics without a line is a cache nobody can see fail (round 16, tenant-r16-12: the
	// Valkey client and the SMS router had a name and no logger, so sayPanic, sayFailed and sayStale
	// wrote nothing for them). A load that panics, a refresh that fails and a value refused as too old
	// are each said at most once a minute. Only the cache's name, the type of a panic value, the
	// class of a failure and a count are logged, never the value or the error text.
	Name Name
	Log  *slog.Logger
	// Release is called with a value that Reset drops, and with the result of a load that
	// Reset overtook. It is not called for a value that a newer load replaces: callers
	// may still hold that one.
	Release func(T)
}

// Loader caches one value of type T.
type Loader[T any] struct {
	cfg Config[T]

	mu      sync.Mutex
	val     T
	have    bool
	at      time.Time
	valGen  uint64 // the generation the load of val started under
	gen     uint64 // bumped by Invalidate and Fresh
	epoch   uint64 // bumped by Reset
	flight  *flight[T]
	retryAt time.Time
	lastErr error

	log                         *slog.Logger
	panicSay, failSay, staleSay said
}

// flight is one load in progress. val and err are written before done is closed.
type flight[T any] struct {
	done  chan struct{}
	gen   uint64
	epoch uint64
	val   T
	err   error
	// once makes finish idempotent: the load closes done on its own path, and the deferred guard
	// closes it when a panic skipped that.
	once sync.Once
}

// New returns a Loader. It loads nothing until the first Get.
func New[T any](cfg Config[T]) *Loader[T] {
	if cfg.Load == nil {
		panic("cachex: Config.Load is required")
	}
	// The choices a cache must make are refused here, at construction, and not left to a default: a
	// cache with no logger or no staleness decision cannot be built, so no call site can leave them out
	// (the construction form of rule cache-loader; TestNewRefusesAConfigThatLeavesAChoiceOut).
	if !cfg.Name.Valid() {
		panic("cachex: Config.Name must be a member of the closed set of cache names")
	}
	if cfg.Log == nil {
		panic("cachex: Config.Log is required")
	}
	if cfg.MaxStale < 0 || (cfg.MaxStale == 0) == (cfg.ServeStaleForever == "") {
		panic("cachex: Config needs exactly one of MaxStale and ServeStaleForever")
	}
	if cfg.RetryAfter <= 0 {
		cfg.RetryAfter = defaultRetryAfter
	}
	if cfg.LoadTimeout <= 0 {
		cfg.LoadTimeout = defaultLoadTimeout
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Loader[T]{cfg: cfg, log: cfg.Log}
}

// expired says a current value is past its TTL. The caller holds mu.
func (l *Loader[T]) expired(now time.Time) bool {
	return l.cfg.TTL > 0 && now.Sub(l.at) >= l.cfg.TTL
}

// lastGood answers from what is stored, for a pause after a failure. The caller holds mu;
// this releases it.
func (l *Loader[T]) lastGood() (T, error) {
	v, have, err := l.val, l.have, l.lastErr
	l.mu.Unlock()
	if have {
		return v, nil
	}
	var zero T
	return zero, err
}

// start begins a load. The caller holds mu.
func (l *Loader[T]) start() *flight[T] {
	f := &flight[T]{done: make(chan struct{}), gen: l.gen, epoch: l.epoch}
	l.flight = f
	go l.run(f)
	return f
}

// run is the one load. It holds no lock while the source works. Its first statement keeps a panic
// of any line below it (the source, the clock, the Release callback) and turns it into a failed
// load, because this goroutine has no request recover above it and Go ends the process on a panic
// in any goroutine (rule goroutine-recover, round 15, tenant-r15-3 and -4).
func (l *Loader[T]) run(f *flight[T]) {
	defer l.endRun(f)
	ctx, cancel := context.WithTimeout(context.Background(), l.cfg.LoadTimeout)
	defer cancel()
	v, err := l.load(ctx)

	var dropped T
	var drop bool
	// The clock is read before the lock: a panic in it must not leave mu held for endRun.
	now := l.cfg.Now()
	l.mu.Lock()
	l.flight = nil
	switch {
	case f.epoch != l.epoch:
		dropped, drop = v, err == nil
		var zero T
		v, err = zero, ErrReset
	case err != nil:
		l.retryAt, l.lastErr = now.Add(l.cfg.RetryAfter), err
	default:
		l.val, l.have, l.at, l.valGen = v, true, now, f.gen
		l.retryAt, l.lastErr = time.Time{}, nil
	}
	f.val, f.err = v, err
	l.mu.Unlock()
	if err != nil && !errors.Is(err, ErrReset) && !errors.Is(err, ErrLoadPanicked) {
		l.sayFailed(err)
	}
	if drop && l.cfg.Release != nil {
		l.cfg.Release(dropped)
	}
	f.finish()
}

// finish wakes the callers that wait for the flight, once.
func (f *flight[T]) finish() { f.once.Do(func() { close(f.done) }) }

// endRun is run's deferred guard. A panic that reached it is said (its type, never its value) and,
// if the flight had not been settled yet, becomes a failed load with the usual pause, so callers
// are never left waiting on a flight nobody finishes.
func (l *Loader[T]) endRun(f *flight[T]) {
	rec := recover()
	if rec == nil {
		return
	}
	l.sayPanic(rec)
	l.mu.Lock()
	if l.flight == f {
		l.flight = nil
		l.retryAt, l.lastErr = l.cfg.Now().Add(l.cfg.RetryAfter), ErrLoadPanicked
		f.err = ErrLoadPanicked
	}
	l.mu.Unlock()
	f.finish()
}

// said paces one kind of log line: at most one a minute, carrying how many events it stands for.
type said struct {
	last  atomic.Int64
	count atomic.Uint64
}

// every runs emit with the number of events since the last line, unless a line was written less
// than logEvery ago.
func (l *Loader[T]) every(s *said, emit func(events int)) {
	s.count.Add(1)
	now := l.cfg.Now().UnixNano()
	last := s.last.Load()
	if last != 0 && now-last < int64(logEvery) {
		return
	}
	if !s.last.CompareAndSwap(last, now) {
		return
	}
	emit(int(s.count.Swap(0)))
}

// sayPanic says a load panicked: the cache, the type of the panic value and how many panics the
// line stands for. The value is not logged; it can carry what was loaded.
func (l *Loader[T]) sayPanic(rec any) {
	l.every(&l.panicSay, func(n int) {
		l.log.Error("cache load panicked", logattr.Enum("cache", l.cfg.Name), logattr.TypeName("panic_type", rec), logattr.Int("events", n))
	})
}

// sayFailed says a refresh failed, by class only: the error text can name a host or a row.
func (l *Loader[T]) sayFailed(err error) {
	class := logattr.ErrOther
	if errors.Is(err, context.DeadlineExceeded) {
		class = logattr.ErrTimeout
	}
	l.every(&l.failSay, func(n int) {
		l.log.Warn("cache refresh failed", logattr.Enum("cache", l.cfg.Name), logattr.Enum("class", class), logattr.Int("events", n))
	})
}

// sayStale says a value was refused as too old, with its age.
func (l *Loader[T]) sayStale(age time.Duration) {
	l.every(&l.staleSay, func(n int) {
		l.log.Error("cache value is too old and is no longer served", logattr.Enum("cache", l.cfg.Name), logattr.Duration("age", age), logattr.Int("events", n))
	})
}

// wait waits for a flight, for at most limit when limit is positive, and for ctx. It
// reports whether the flight finished.
func wait[T any](ctx context.Context, f *flight[T], limit time.Duration) (finished bool, err error) {
	var timeout <-chan time.Time
	if limit > 0 {
		t := time.NewTimer(limit)
		defer t.Stop()
		timeout = t.C
	}
	select {
	case <-f.done:
		return true, nil
	case <-timeout:
		return false, nil
	case <-ctx.Done():
		return false, ctx.Err()
	}
}

// Get returns the value.
//
//   - A current value is returned at once.
//   - A value past its TTL is returned stale while one load revalidates it; the caller that
//     starts the load waits for it for at most StaleWait.
//   - After an Invalidate the next Get waits for a load that started after the Invalidate
//     (or, when the last one failed and RetryAfter has not passed, returns the last good
//     value); a caller's context ends the wait with its error.
//   - A Loader that never loaded has nothing to serve: callers wait for the single load
//     (bounded by their context) and get its error, and a failed first load is remembered
//     for RetryAfter.
func (l *Loader[T]) Get(ctx context.Context) (T, error) {
	var zero T
	for {
		l.mu.Lock()
		now := l.cfg.Now()
		if l.have && l.cfg.MaxStale > 0 && now.Sub(l.at) >= l.cfg.MaxStale {
			// Every reload since the value was good has failed (or none ran), and the value is
			// older than the caller of this cache can vouch for: it is not served. A caller gets
			// the answer of a load that runs now, or ErrStale during the pause after a failure.
			age := now.Sub(l.at)
			if now.Before(l.retryAt) {
				l.mu.Unlock()
				l.sayStale(age)
				return zero, ErrStale
			}
			f := l.flight
			if f == nil {
				f = l.start()
			}
			l.mu.Unlock()
			// The wait is bounded like the one of a stale value (StaleWait): every request of the process,
			// the Host check of an anonymous one included, comes through here while the source is down, and
			// each used to wait out the whole flight (LoadTimeout) with nothing to serve (round 16,
			// tenant-r16-5). Zero StaleWait means no wait: the refusal is the answer.
			var finished bool
			if l.cfg.StaleWait > 0 {
				var err error
				if finished, err = wait(ctx, f, l.cfg.StaleWait); err != nil {
					return zero, err
				}
			}
			if !finished {
				l.sayStale(age)
				return zero, ErrStale
			}
			if f.err != nil {
				if !errors.Is(f.err, ErrReset) {
					l.sayStale(age)
					return zero, ErrStale
				}
				return zero, f.err
			}
			return f.val, nil
		}
		current := l.have && l.valGen == l.gen
		if current && !l.expired(now) {
			v := l.val
			l.mu.Unlock()
			return v, nil
		}
		if now.Before(l.retryAt) {
			return l.lastGood()
		}
		f := l.flight
		if current {
			// Past the TTL only: a stale value is good enough to answer with.
			stale := l.val
			if f != nil {
				l.mu.Unlock()
				return stale, nil
			}
			f = l.start()
			l.mu.Unlock()
			if finished, _ := wait(ctx, f, l.cfg.StaleWait); finished && f.err == nil {
				return f.val, nil
			}
			return stale, nil // the wait ran out, the caller left, or the load failed
		}
		if f == nil {
			f = l.start()
		}
		have := l.have
		l.mu.Unlock()
		if _, err := wait(ctx, f, 0); err != nil {
			return zero, err
		}
		if !have {
			return f.val, f.err // a cold caller takes the load's own answer
		}
		// Invalidated: look again. The load either made the value current or failed and
		// set the pause, so this loops at most once per Invalidate.
	}
}

// Fresh returns a value read by a load that started after the call, or that load's
// error. It is for the caller that has just caused the change it needs to see: the test
// send that follows saving a gateway's credentials in another process. It does not answer
// from the old value, and it honours RetryAfter: during the pause after a failed load it
// returns that load's error, so a source that is down is not asked once per call.
// Concurrent Fresh calls share loads; none waits for more than two.
func (l *Loader[T]) Fresh(ctx context.Context) (T, error) {
	var zero T
	l.mu.Lock()
	l.gen++
	want := l.gen
	l.mu.Unlock()
	for {
		l.mu.Lock()
		if l.have && l.valGen >= want {
			v := l.val
			l.mu.Unlock()
			return v, nil
		}
		f := l.flight
		if f == nil {
			if l.cfg.Now().Before(l.retryAt) {
				err := l.lastErr
				l.mu.Unlock()
				return zero, err
			}
			f = l.start()
		}
		l.mu.Unlock()
		if _, err := wait(ctx, f, 0); err != nil {
			return zero, err
		}
		if f.gen >= want {
			return f.val, f.err
		}
		// The load in flight began before the call and may have read old rows: wait for
		// it to end and load again.
	}
}

// Invalidate marks the value out of date. The next Get loads again, and a load already
// in flight does not clear the mark.
func (l *Loader[T]) Invalidate() {
	l.mu.Lock()
	l.gen++
	l.mu.Unlock()
}

// Reset drops the value and forgets any failure, as a Close does. A load in flight is not
// cancelled; when it ends its result goes to Release and its waiters get ErrReset. The
// Loader stays usable: the next Get loads again.
func (l *Loader[T]) Reset() {
	l.mu.Lock()
	l.epoch++
	l.gen++
	v, had := l.val, l.have
	var zero T
	l.val, l.have, l.retryAt, l.lastErr = zero, false, time.Time{}, nil
	l.mu.Unlock()
	if had && l.cfg.Release != nil {
		l.cfg.Release(v)
	}
}

// Loading reports whether a load is in flight, for tests.
func (l *Loader[T]) Loading() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.flight != nil
}

// load calls the source and keeps a panic inside it as an error, which the loader then treats
// like any failed load (last good value, retry after a pause).
func (l *Loader[T]) load(ctx context.Context) (v T, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			l.sayPanic(rec)
			var zero T
			v, err = zero, ErrLoadPanicked
		}
	}()
	return l.cfg.Load(ctx)
}
