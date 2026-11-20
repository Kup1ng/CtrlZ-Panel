package cachex_test

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/cachex"
)

// This is the conformance suite of the loader (rule cache-loader). The three users (the
// public configuration, the Valkey client, the SMS router snapshot) are built on it and
// keep one test each for what they add; the behaviours below are the ones the findings of
// rounds 1 to 4 were about, stated once.

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// source is a database whose answers a test controls.
type source struct {
	calls atomic.Int32
	mu    sync.Mutex
	val   int
	err   error
	hang  bool          // wait for the context
	gate  chan struct{} // when set, a load reports it started and waits to be released
	start chan struct{}
}

func (s *source) set(val int, err error, hang bool) {
	s.mu.Lock()
	s.val, s.err, s.hang = val, err, hang
	s.mu.Unlock()
}

func (s *source) load(ctx context.Context) (int, error) {
	s.calls.Add(1)
	s.mu.Lock()
	val, err, hang, gate, start := s.val, s.err, s.hang, s.gate, s.start
	s.mu.Unlock()
	if gate != nil {
		start <- struct{}{} // read the rows, then wait: the rows change after this point
		<-gate
	}
	if hang {
		<-ctx.Done()
		return 0, errors.New("load timed out")
	}
	return val, err
}

func newLoader(s *source, ck *clock, mod func(*cachex.Config[int])) *cachex.Loader[int] {
	cfg := cachex.Config[int]{Load: s.load, TTL: 30 * time.Second, RetryAfter: 5 * time.Second, StaleWait: 100 * time.Millisecond, Now: ck.now, Name: cachex.NameAuthConfig, Log: slog.New(slog.DiscardHandler), ServeStaleForever: "a test"}
	if mod != nil {
		mod(&cfg)
	}
	return cachex.New(cfg)
}

func mustGet(t *testing.T, l *cachex.Loader[int]) int {
	t.Helper()
	v, err := l.Get(context.Background())
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	return v
}

func settle(t *testing.T, l *cachex.Loader[int]) {
	t.Helper()
	for i := 0; i < 500 && l.Loading(); i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if l.Loading() {
		t.Fatal("a load never ended")
	}
}

func TestColdCallersShareOneLoad(t *testing.T) {
	s := &source{val: 7}
	s.gate, s.start = make(chan struct{}), make(chan struct{}, 8)
	l := newLoader(s, &clock{t: time.Now()}, nil)
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if v, err := l.Get(context.Background()); err != nil || v != 7 {
				t.Errorf("Get = %d, %v", v, err)
			}
		}()
	}
	<-s.start
	time.Sleep(50 * time.Millisecond) // let the others queue behind the one load
	close(s.gate)
	wg.Wait()
	if n := s.calls.Load(); n != 1 {
		t.Errorf("%d loads for six cold callers, want 1", n)
	}
}

// A hanging load: a stale value is served at once to every caller, the starter waits for
// StaleWait only, one load runs, and a cold caller leaves on its own context while the load
// goes on.
func TestHangingLoadNeverQueuesCallers(t *testing.T) {
	s := &source{val: 1}
	ck := &clock{t: time.Now()}
	l := newLoader(s, ck, nil)
	mustGet(t, l)

	ck.add(time.Minute)
	s.set(2, nil, true)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			start := time.Now()
			v, err := l.Get(context.Background())
			if err != nil || v != 1 {
				t.Errorf("Get = %d, %v; want the stale value", v, err)
			}
			if d := time.Since(start); d > time.Second {
				t.Errorf("a caller waited %v for a load that does not answer", d)
			}
		}()
	}
	wg.Wait()
	if n := s.calls.Load(); n != 2 {
		t.Errorf("%d loads for one burst, want 2 (the first and one revalidation)", n)
	}

	// Cold: nothing to serve, so callers wait, but only as long as their own context.
	cold := newLoader(&source{hang: true}, ck, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	if _, err := cold.Get(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("cold Get = %v, want the caller's deadline", err)
	}
	if !cold.Loading() {
		t.Error("the caller leaving ended the load the others wait for")
	}
}

// The load runs on the loader's own context, bounded by LoadTimeout, so a source that
// honours its context frees the flight.
func TestLoadTimeoutEndsTheFlight(t *testing.T) {
	s := &source{hang: true}
	l := newLoader(s, &clock{t: time.Now()}, func(c *cachex.Config[int]) { c.LoadTimeout = 50 * time.Millisecond })
	if _, err := l.Get(context.Background()); err == nil {
		t.Fatal("a load that timed out returned a value")
	}
	if l.Loading() {
		t.Error("the flight outlived its timeout")
	}
}

// A failing load: the last good value is served, the source is not asked again inside
// RetryAfter, and it is asked again after it.
func TestFailingLoadBacksOffAndKeepsTheLastGoodValue(t *testing.T) {
	s := &source{val: 1}
	ck := &clock{t: time.Now()}
	l := newLoader(s, ck, nil)
	mustGet(t, l)

	ck.add(time.Minute)
	s.set(0, errors.New("db down"), false)
	if v := mustGet(t, l); v != 1 {
		t.Errorf("after a failed reload Get = %d, want the last good value", v)
	}
	settle(t, l)
	calls := s.calls.Load()
	for i := 0; i < 20; i++ {
		if v := mustGet(t, l); v != 1 {
			t.Fatalf("Get = %d inside the pause", v)
		}
	}
	if s.calls.Load() != calls {
		t.Errorf("%d loads inside the retry pause", s.calls.Load()-calls)
	}

	ck.add(6 * time.Second)
	s.set(3, nil, false)
	if v := mustGet(t, l); v != 3 {
		t.Errorf("after the pause Get = %d, want 3", v)
	}
}

// A cold failure is remembered too: the next callers get the same error without a query.
func TestColdFailureIsRemembered(t *testing.T) {
	boom := errors.New("db down")
	s := &source{err: boom}
	ck := &clock{t: time.Now()}
	l := newLoader(s, ck, nil)
	for i := 0; i < 5; i++ {
		if _, err := l.Get(context.Background()); !errors.Is(err, boom) {
			t.Fatalf("Get %d = %v", i, err)
		}
	}
	if n := s.calls.Load(); n != 1 {
		t.Errorf("%d loads for five calls inside the pause, want 1", n)
	}
	ck.add(6 * time.Second)
	s.set(4, nil, false)
	if v := mustGet(t, l); v != 4 {
		t.Errorf("after the pause Get = %d", v)
	}
}

// Invalidate during a load is kept: the value that load read is served, and the next Get
// loads again instead of treating it as current (sms-r3-2).
func TestInvalidateDuringALoadIsNotLost(t *testing.T) {
	s := &source{val: 1}
	ck := &clock{t: time.Now()}
	l := newLoader(s, ck, nil)
	mustGet(t, l)

	ck.add(time.Minute)
	gate := make(chan struct{})
	s.gate, s.start = gate, make(chan struct{}, 1)
	done := make(chan struct{})
	go func() { defer close(done); mustGet(t, l) }()
	<-s.start // the revalidation has read the old rows
	l.Invalidate()
	s.mu.Lock()
	s.gate, s.val = nil, 2 // later loads see the new rows
	s.mu.Unlock()
	<-done // the starter gives up waiting after StaleWait and serves the stale value
	close(gate)
	settle(t, l)
	before := s.calls.Load()
	if v := mustGet(t, l); v != 2 {
		t.Errorf("Get after an Invalidate that came during a load = %d, want the new rows", v)
	}
	if s.calls.Load() != before+1 {
		t.Errorf("loads %d -> %d: the Invalidate was dropped", before, s.calls.Load())
	}
}

// After an Invalidate (no load in flight) the very next Get waits for a new load and
// returns what it read, not the old value.
func TestInvalidateMakesTheNextGetLoad(t *testing.T) {
	s := &source{val: 1}
	l := newLoader(s, &clock{t: time.Now()}, nil)
	mustGet(t, l)
	s.set(2, nil, false)
	if v := mustGet(t, l); v != 1 {
		t.Fatalf("a current value changed without an Invalidate: %d", v)
	}
	l.Invalidate()
	if v := mustGet(t, l); v != 2 {
		t.Errorf("Get after Invalidate = %d, want 2", v)
	}
}

// The pinned read: Fresh does not answer from a current value, and does not take the
// answer of a load that started before the call (it may have read the old rows).
func TestFreshNeverAnswersFromAnOlderLoad(t *testing.T) {
	s := &source{val: 1}
	l := newLoader(s, &clock{t: time.Now()}, nil)
	mustGet(t, l)

	// A current value is not good enough.
	s.set(2, nil, false)
	if v, err := l.Fresh(context.Background()); err != nil || v != 2 {
		t.Fatalf("Fresh = %d, %v; want a new read", v, err)
	}

	// A load already in flight when Fresh is called read the rows before the change.
	l.Invalidate()
	s.gate, s.start = make(chan struct{}), make(chan struct{}, 2)
	gate := s.gate
	go func() { _, _ = l.Get(context.Background()) }()
	<-s.start // in flight, has read value 2
	s.mu.Lock()
	s.val = 3 // the change Fresh's caller made
	s.mu.Unlock()
	got := make(chan int, 1)
	go func() {
		v, _ := l.Fresh(context.Background())
		got <- v
	}()
	time.Sleep(50 * time.Millisecond)
	s.mu.Lock()
	s.gate = nil
	s.mu.Unlock()
	close(gate)
	select {
	case v := <-got:
		if v != 3 {
			t.Errorf("Fresh = %d: it took the answer of a load that began before the call", v)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Fresh never returned")
	}
}

// Fresh reports the failure, honours RetryAfter, and parallel calls share loads.
func TestFreshFailureAndSharing(t *testing.T) {
	boom := errors.New("db down")
	s := &source{val: 1}
	ck := &clock{t: time.Now()}
	l := newLoader(s, ck, nil)
	mustGet(t, l)

	s.set(0, boom, false)
	if _, err := l.Fresh(context.Background()); !errors.Is(err, boom) {
		t.Fatalf("Fresh = %v, want the load's error and not the old value", err)
	}
	calls := s.calls.Load()
	for i := 0; i < 3; i++ {
		if _, err := l.Fresh(context.Background()); !errors.Is(err, boom) {
			t.Fatalf("Fresh inside the pause = %v", err)
		}
	}
	if s.calls.Load() != calls {
		t.Errorf("Fresh asked a failing source %d more times inside the pause", s.calls.Load()-calls)
	}

	ck.add(6 * time.Second)
	s.set(5, nil, false)
	s.gate, s.start = make(chan struct{}), make(chan struct{}, 16)
	gate := s.gate
	before := s.calls.Load()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if v, err := l.Fresh(context.Background()); err != nil || v != 5 {
				t.Errorf("Fresh = %d, %v", v, err)
			}
		}()
	}
	<-s.start
	time.Sleep(50 * time.Millisecond)
	s.mu.Lock()
	s.gate = nil
	s.mu.Unlock()
	close(gate)
	wg.Wait()
	if n := s.calls.Load() - before; n > 2 {
		t.Errorf("eight parallel Fresh calls made %d loads, want at most 2", n)
	}
}

// A caller whose context ends stops waiting for Fresh, and the load goes on.
func TestFreshHonoursTheCallersContext(t *testing.T) {
	s := &source{val: 1}
	l := newLoader(s, &clock{t: time.Now()}, nil)
	mustGet(t, l)
	s.set(0, nil, true)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := l.Fresh(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Fresh = %v", err)
	}
}

// Reset drops the value, hands it to Release, and a load that it overtook is released
// instead of stored; the loader then works again.
func TestResetReleasesAndReloads(t *testing.T) {
	var released atomic.Int32
	s := &source{val: 1}
	l := newLoader(s, &clock{t: time.Now()}, func(c *cachex.Config[int]) {
		c.Release = func(int) { released.Add(1) }
	})
	mustGet(t, l)
	l.Reset()
	if released.Load() != 1 {
		t.Fatalf("Reset released %d values, want 1", released.Load())
	}
	s.set(2, nil, false)
	if v := mustGet(t, l); v != 2 {
		t.Errorf("Get after Reset = %d, want a new load", v)
	}

	// Reset during a load: the waiter gets ErrReset and the result is released.
	s2 := &source{val: 9}
	s2.gate, s2.start = make(chan struct{}), make(chan struct{}, 1)
	l2 := newLoader(s2, &clock{t: time.Now()}, func(c *cachex.Config[int]) {
		c.Release = func(int) { released.Add(1) }
	})
	errc := make(chan error, 1)
	go func() { _, err := l2.Get(context.Background()); errc <- err }()
	<-s2.start
	l2.Reset()
	close(s2.gate)
	if err := <-errc; !errors.Is(err, cachex.ErrReset) {
		t.Errorf("a Get that Reset overtook = %v, want ErrReset", err)
	}
	settle(t, l2)
	if released.Load() != 2 {
		t.Errorf("released = %d, the overtaken load was kept", released.Load())
	}
	s2.set(10, nil, false)
	s2.mu.Lock()
	s2.gate = nil
	s2.mu.Unlock()
	if v := mustGet(t, l2); v != 10 {
		t.Errorf("Get after Reset = %d", v)
	}
}

// A TTL of zero never expires on its own; a replaced value is not released.
func TestZeroTTLNeverExpires(t *testing.T) {
	var released atomic.Int32
	s := &source{val: 1}
	ck := &clock{t: time.Now()}
	l := newLoader(s, ck, func(c *cachex.Config[int]) {
		c.TTL = 0
		c.Release = func(int) { released.Add(1) }
	})
	mustGet(t, l)
	ck.add(100 * 24 * time.Hour)
	s.set(2, nil, false)
	if v := mustGet(t, l); v != 1 || s.calls.Load() != 1 {
		t.Errorf("a client with no TTL reloaded: %d after %d loads", v, s.calls.Load())
	}
	l.Invalidate()
	if v := mustGet(t, l); v != 2 {
		t.Errorf("Get after Invalidate = %d", v)
	}
	if released.Load() != 0 {
		t.Error("a value that a newer load replaced was released while callers may hold it")
	}
}

// A load that panics is a failed load, not the end of the process: the load runs on a goroutine
// no request recover covers (tenant-r14-2). The panic value is not kept.
func TestAPanickingLoadIsAFailedLoad(t *testing.T) {
	var boom atomic.Bool
	ck := &clock{t: time.Now()}
	cfg := cachex.Config[int]{
		Load: func(context.Context) (int, error) {
			if boom.Load() {
				panic("row 0912 is bad")
			}
			return 7, nil
		},
		TTL: 30 * time.Second, RetryAfter: 5 * time.Second, StaleWait: 100 * time.Millisecond, Now: ck.now, Name: cachex.NameAuthConfig, Log: slog.New(slog.DiscardHandler), ServeStaleForever: "a test",
	}
	l := cachex.New(cfg)
	if v, err := l.Get(context.Background()); err != nil || v != 7 {
		t.Fatalf("first Get = %d, %v", v, err)
	}
	boom.Store(true)
	ck.add(time.Minute)
	if v, err := l.Get(context.Background()); err != nil || v != 7 {
		t.Fatalf("after a panicking reload Get = %d, %v, want the last good value", v, err)
	}
	// A cold loader reports the panic as an error that does not carry the value.
	cold := cachex.New(cfg)
	_, err := cold.Get(context.Background())
	if !errors.Is(err, cachex.ErrLoadPanicked) || strings.Contains(err.Error(), "0912") {
		t.Fatalf("cold Get error = %v", err)
	}
}

// lines is a log handler's output, one record per line.
type lines struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (l *lines) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *lines) text() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

// A load that panics is said, once, and the line holds the cache and the type of the panic value and
// nothing of the value (round 15, tenant-r15-4). Before this a panicking config load was a silent
// failed load, so a cache that had stopped refreshing kept an old security decision in force with no
// line to show for it.
func TestAPanickingLoadIsSaidOnceAndWithoutItsValue(t *testing.T) {
	var out lines
	var boom atomic.Bool
	ck := &clock{t: time.Now()}
	l := cachex.New(cachex.Config[int]{
		Load: func(context.Context) (int, error) {
			if boom.Load() {
				panic(errors.New("row 0912-555-0101 is bad"))
			}
			return 7, nil
		},
		TTL: 30 * time.Second, RetryAfter: 5 * time.Second, StaleWait: 100 * time.Millisecond, Now: ck.now, ServeStaleForever: "a test",
		Name: cachex.NameAuthConfig, Log: slog.New(slog.NewTextHandler(&out, nil)),
	})
	if _, err := l.Get(context.Background()); err != nil {
		t.Fatal(err)
	}
	boom.Store(true)
	// Six refreshes in under a minute, each panicking: one line.
	ck.add(31 * time.Second) // past the TTL
	for i := 0; i < 6; i++ {
		if i > 0 {
			ck.add(5100 * time.Millisecond) // past the pause, inside the minute the first line opened
		}
		if _, err := l.Get(context.Background()); err != nil {
			t.Fatalf("a stale value must still be served: %v", err)
		}
		waitFor(t, func() bool { return !l.Loading() })
	}
	got := out.text()
	if n := strings.Count(got, "cache load panicked"); n != 1 {
		t.Fatalf("%d panic lines, want exactly one:\n%s", n, got)
	}
	for _, want := range []string{"cache=auth_config", "panic_type="} {
		if !strings.Contains(got, want) {
			t.Errorf("the line lacks %q:\n%s", want, got)
		}
	}
	for _, leak := range []string{"0912", "555", "row", "is bad"} {
		if strings.Contains(got, leak) {
			t.Errorf("the line carries %q of the panic value:\n%s", leak, got)
		}
	}
	// A minute later the next panic is said again, with the count it stands for.
	ck.add(2 * time.Minute)
	l.Get(context.Background())
	waitFor(t, func() bool { return !l.Loading() })
	if n := strings.Count(out.text(), "cache load panicked"); n != 2 {
		t.Fatalf("%d panic lines after the minute, want two:\n%s", n, out.text())
	}
}

func waitFor(t *testing.T, ok func() bool) {
	t.Helper()
	for i := 0; i < 500; i++ {
		if ok() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("condition did not hold in time")
}

// MaxStale is a bound on how long a failing source can keep an old value in force: past it Get
// refuses the value, says so, and serves again when a load works.
func TestAValueOlderThanMaxStaleIsRefused(t *testing.T) {
	var out lines
	var fail atomic.Bool
	ck := &clock{t: time.Now()}
	l := cachex.New(cachex.Config[int]{
		Load: func(context.Context) (int, error) {
			if fail.Load() {
				return 0, errors.New("down")
			}
			return 7, nil
		},
		TTL: 30 * time.Second, RetryAfter: 5 * time.Second, StaleWait: 100 * time.Millisecond, MaxStale: 10 * time.Minute, Now: ck.now,
		Name: cachex.NameAuthConfig, Log: slog.New(slog.NewTextHandler(&out, nil)),
	})
	if v, err := l.Get(context.Background()); err != nil || v != 7 {
		t.Fatalf("first Get = %d, %v", v, err)
	}
	fail.Store(true)
	for _, step := range []time.Duration{time.Minute, 4 * time.Minute, 4 * time.Minute} {
		ck.add(step)
		if v, err := l.Get(context.Background()); err != nil || v != 7 {
			t.Fatalf("inside MaxStale: Get = %d, %v, want the last good value", v, err)
		}
		waitFor(t, func() bool { return !l.Loading() })
	}
	ck.add(2 * time.Minute) // 11 minutes since the value was good
	if _, err := l.Get(context.Background()); !errors.Is(err, cachex.ErrStale) {
		t.Fatalf("past MaxStale: Get error = %v, want ErrStale", err)
	}
	ck.add(10 * time.Second)
	if _, err := l.Get(context.Background()); !errors.Is(err, cachex.ErrStale) {
		t.Fatalf("during the pause past MaxStale: Get error = %v, want ErrStale", err)
	}
	if !strings.Contains(out.text(), "cache value is too old") || strings.Contains(out.text(), "down") {
		t.Fatalf("the refusal is not said, or the error text leaked:\n%s", out.text())
	}
	fail.Store(false)
	ck.add(10 * time.Second)
	if v, err := l.Get(context.Background()); err != nil || v != 7 {
		t.Fatalf("after the source came back: Get = %d, %v", v, err)
	}
}

// A panic outside the source (here the Release callback, which runs after the result is settled) is
// kept by the guard of the load goroutine, and the callers that wait are woken, not left hanging.
func TestAPanicOutsideTheSourceDoesNotEndTheProcessOrHangCallers(t *testing.T) {
	gate, started := make(chan struct{}), make(chan struct{}, 1)
	l := cachex.New(cachex.Config[int]{
		Load: func(context.Context) (int, error) {
			started <- struct{}{}
			<-gate
			return 7, nil
		},
		Release: func(int) { panic("release") }, Name: cachex.NameAuthConfig, Log: slog.New(slog.DiscardHandler), ServeStaleForever: "a test",
	})
	got := make(chan error, 1)
	go func() {
		_, err := l.Get(context.Background())
		got <- err
	}()
	<-started
	l.Reset() // the load is overtaken, so its result goes to the panicking Release
	close(gate)
	select {
	case err := <-got:
		if !errors.Is(err, cachex.ErrReset) {
			t.Fatalf("Get error = %v, want ErrReset", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a caller was left waiting after the load goroutine panicked")
	}
	waitFor(t, func() bool { return !l.Loading() })
}

// TestNewRefusesAConfigThatLeavesAChoiceOut: a cache has a logger and a decision about serving an old
// value, and neither has a default (round 16, tenant-r16-12). The Valkey client and the SMS router
// snapshot were built without a logger, so a panicking or failing load said nothing, and without a bound,
// so the router kept the gateways of its last good load for ever.
func TestNewRefusesAConfigThatLeavesAChoiceOut(t *testing.T) {
	load := func(context.Context) (int, error) { return 1, nil }
	log := slog.New(slog.DiscardHandler)
	full := func() cachex.Config[int] {
		return cachex.Config[int]{Load: load, Name: cachex.NameAuthConfig, Log: log, MaxStale: time.Minute}
	}
	mustNotPanic := func(name string, c cachex.Config[int]) {
		t.Helper()
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("%s: New panicked: %v", name, r)
			}
		}()
		cachex.New(c)
	}
	mustPanic := func(name string, c cachex.Config[int]) {
		t.Helper()
		defer func() {
			if recover() == nil {
				t.Errorf("%s: New accepted the config", name)
			}
		}()
		cachex.New(c)
	}
	mustNotPanic("bounded", full())
	forever := full()
	forever.MaxStale, forever.ServeStaleForever = 0, "a handle and not a decision"
	mustNotPanic("explicitly unbounded", forever)

	noLog := full()
	noLog.Log = nil
	mustPanic("no logger", noLog)
	noName := full()
	noName.Name = ""
	mustPanic("no name", noName)
	noChoice := full()
	noChoice.MaxStale = 0
	mustPanic("neither MaxStale nor a reason", noChoice)
	both := full()
	both.ServeStaleForever = "x"
	mustPanic("both MaxStale and a reason", both)
	negative := full()
	negative.MaxStale = -time.Second
	mustPanic("a negative bound", negative)
}

// Past MaxStale every caller used to wait out the whole flight (LoadTimeout) with nothing to serve, the
// Host check of an anonymous request among them (round 16, tenant-r16-5). The wait is StaleWait, and the
// answer when it runs out is ErrStale.
func TestARefusedStaleValueDoesNotMakeCallersWaitOutTheLoad(t *testing.T) {
	var hang atomic.Bool
	ck := &clock{t: time.Now()}
	l := cachex.New(cachex.Config[int]{
		Load: func(ctx context.Context) (int, error) {
			if hang.Load() {
				<-ctx.Done()
				return 0, ctx.Err()
			}
			return 7, nil
		},
		TTL: 30 * time.Second, RetryAfter: 5 * time.Second, LoadTimeout: 30 * time.Second, StaleWait: 50 * time.Millisecond, MaxStale: time.Minute, Now: ck.now,
		Name: cachex.NameAuthConfig, Log: slog.New(slog.DiscardHandler),
	})
	if _, err := l.Get(context.Background()); err != nil {
		t.Fatal(err)
	}
	hang.Store(true)
	ck.add(2 * time.Minute)
	done := make(chan error, 1)
	go func() { _, err := l.Get(context.Background()); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, cachex.ErrStale) {
			t.Fatalf("Get past MaxStale with a hanging source = %v, want ErrStale", err)
		}
	case <-time.After(10 * time.Second): // far under LoadTimeout; only a Get that waits out the flight is slower
		t.Fatal("Get past MaxStale waited for the whole load")
	}
}

// A zero StaleWait with a MaxStale is the other half of the refusal (round 16, tenant-r16-22): no wait at all,
// the refusal is the answer. wait() reads a limit of zero as "no limit", so a loader that passed its zero on
// would hold every caller for the whole load, which is the wait the refusal exists to remove. The caller that
// starts the load is refused at once, a caller that comes while it runs is refused too and starts no second
// load, and the caller after the load finished (the source has recovered, even during the refusal) gets the
// new value, not a second refusal.
func TestAZeroStaleWaitRefusesAtOnceAndTheNextCallerSeesTheRecovery(t *testing.T) {
	var loads atomic.Int32
	started := make(chan struct{}, 4)
	release := make(chan struct{})
	var blocked atomic.Bool
	ck := &clock{t: time.Now()}
	l := cachex.New(cachex.Config[int]{
		Load: func(ctx context.Context) (int, error) {
			loads.Add(1)
			if !blocked.Load() {
				return 7, nil
			}
			started <- struct{}{}
			select {
			case <-release:
				return 9, nil
			case <-ctx.Done():
				return 0, ctx.Err()
			}
		},
		TTL: 30 * time.Second, RetryAfter: 5 * time.Second, LoadTimeout: 30 * time.Second, StaleWait: 0, MaxStale: time.Minute, Now: ck.now,
		Name: cachex.NameAuthConfig, Log: slog.New(slog.DiscardHandler),
	})
	if v, err := l.Get(context.Background()); err != nil || v != 7 {
		t.Fatalf("first Get = %d, %v", v, err)
	}
	blocked.Store(true)
	ck.add(2 * time.Minute)
	get := func() error {
		done := make(chan error, 1)
		go func() { _, err := l.Get(context.Background()); done <- err }()
		select {
		case err := <-done:
			return err
		case <-time.After(10 * time.Second): // far under LoadTimeout; only a Get that waits out the load is slower
			t.Fatal("Get with StaleWait 0 past MaxStale waited for the load")
			return nil
		}
	}
	if err := get(); !errors.Is(err, cachex.ErrStale) {
		t.Fatalf("the caller that starts the load = %v, want ErrStale at once", err)
	}
	<-started // the load runs, and the source has not answered
	if err := get(); !errors.Is(err, cachex.ErrStale) {
		t.Fatalf("a caller while the load runs = %v, want ErrStale at once", err)
	}
	if n := loads.Load(); n != 2 {
		t.Fatalf("%d loads ran (the first and one refresh), want 2: a refused caller must not start another", n)
	}
	close(release) // the source recovers while the refusal is in force
	deadline := time.Now().Add(10 * time.Second)
	for {
		v, err := l.Get(context.Background())
		if err == nil {
			if v != 9 {
				t.Fatalf("after the recovery Get = %d, want 9", v)
			}
			return
		}
		if !errors.Is(err, cachex.ErrStale) {
			t.Fatalf("after the recovery Get error = %v", err)
		}
		if time.Now().After(deadline) {
			t.Fatal("the loader kept refusing after the source recovered")
		}
		time.Sleep(time.Millisecond)
	}
}
