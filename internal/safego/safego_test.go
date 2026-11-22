package safego_test

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/safego"
)

type unit string

const (
	unitA unit = "a"
)

func (u unit) Valid() bool { return u == unitA }

// escapes runs f and reports whether a panic got out of it. The outer recover is the test's own, so
// a Keep or Run that stops nothing makes the test FAIL cleanly instead of ending the test binary,
// which the mutant registry could not tell from a test that did not run (sms-r17-14). A goroutine
// started by Go is the one case no test can cover this way, because nothing outside the goroutine
// can recover its panic: that clause is held by internal/lint TestEveryGoroutineKeepsItsPanic.
func escapes(f func()) (out bool) {
	defer func() { out = recover() != nil }()
	f()
	return false
}

func newLog() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return slog.New(slog.NewJSONHandler(&buf, nil)), &buf
}

// TestKeepStopsThePanicAndSaysItsUnitNotItsValue is the property of the package for a pass of a loop:
// a panic inside the pass does not leave it, the log holds the unit and the type and the stack, and
// never the value, and the count moves.
func TestKeepStopsThePanicAndSaysItsUnitNotItsValue(t *testing.T) {
	log, buf := newLog()
	if escapes(func() {
		defer safego.Keep(log, unitA)
		panic("canary-panic-value 123456")
	}) {
		t.Fatal("the panic left the guarded unit")
	}
	got := buf.String()
	if strings.Count(got, safego.Msg) != 1 || !strings.Contains(got, `"unit":"a"`) || !strings.Contains(got, `"panic_type":"string"`) {
		t.Errorf("the panic was not logged once with its unit and type: %s", got)
	}
	if strings.Contains(got, "canary-panic-value") || strings.Contains(got, "123456") {
		t.Errorf("the value of the panic reached the log: %s", got)
	}
}

// TestKeepAroundAPassLetsTheLoopGoOn covers the second use: a pass of a loop.
func TestKeepAroundAPassLetsTheLoopGoOn(t *testing.T) {
	log, buf := newLog()
	ran := 0
	pass := func(boom bool) {
		defer safego.Keep(log, unitA)
		ran++
		if boom {
			panic("x")
		}
	}
	if escapes(func() { pass(true) }) {
		t.Fatal("the panic left the pass")
	}
	pass(false) // the loop goes on
	if ran != 2 {
		t.Errorf("ran %d passes, want 2", ran)
	}
	if strings.Count(buf.String(), safego.Msg) != 1 {
		t.Errorf("a pass that did not panic logged, or the one that did did not: %s", buf.String())
	}
}

// TestKeepIsQuietWhenNothingPanicked is the quiet path: no log line.
func TestKeepIsQuietWhenNothingPanicked(t *testing.T) {
	log, buf := newLog()
	func() { defer safego.Keep(log, unitA) }()
	if buf.Len() != 0 {
		t.Errorf("a clean unit logged or counted: %s", buf.String())
	}
}

// TestRunReportsAPanicAfterTheUnitHasUnwound is what the SMS worker leans on: when Run returns true
// the deferred functions of the unit have all run (a transaction would have rolled back), and a
// unit that did not panic returns false.
func TestRunReportsAPanicAfterTheUnitHasUnwound(t *testing.T) {
	log, buf := newLog()
	unwound := false
	var panicked bool
	if escapes(func() {
		panicked = safego.Run(log, unitA, func() {
			defer func() { unwound = true }()
			panic("canary-run-value")
		})
	}) {
		t.Fatal("the panic left Run")
	}
	if !panicked || !unwound {
		t.Errorf("panicked=%v unwound=%v, want both true", panicked, unwound)
	}
	if strings.Contains(buf.String(), "canary-run-value") || strings.Count(buf.String(), safego.Msg) != 1 {
		t.Errorf("Run did not log once without the value: %s", buf.String())
	}
	if safego.Run(log, unitA, func() {}) {
		t.Error("a unit that did not panic was reported as panicked")
	}
}

// TestRunWithANilLogStillKeepsThePanic: a unit built with no logger must not turn a panic into a crash.
func TestRunWithANilLogStillKeepsThePanic(t *testing.T) {
	var panicked bool
	if escapes(func() { panicked = safego.Run(nil, unitA, func() { panic("x") }) }) {
		t.Fatal("the panic left Run")
	}
	if !panicked {
		t.Error("Run did not report the panic of a unit built with no log")
	}
}

// signalWriter is a log sink that is safe to read while a goroutine writes, and tells the test the
// moment the first line arrives, so the test waits on that line and not on a clock (rule 33).
type signalWriter struct {
	mu   sync.Mutex
	buf  bytes.Buffer
	once sync.Once
	got  chan struct{}
}

func (w *signalWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	n, err := w.buf.Write(p)
	w.mu.Unlock()
	w.once.Do(func() { close(w.got) })
	return n, err
}

func (w *signalWriter) text() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}

// TestGoCountsDownAUnitThatPanickedAndTheProcessLives runs the goroutine form. The recover of the
// goroutine is the code under test, so a Go that kept nothing would end this binary: the lint holds
// that clause (a mutant of it names TestEveryGoroutineKeepsItsPanic), and this test holds the rest:
// the count-down put first in fn runs while the panic unwinds, and the log has the unit once.
func TestGoCountsDownAUnitThatPanickedAndTheProcessLives(t *testing.T) {
	w := &signalWriter{got: make(chan struct{})}
	log := slog.New(slog.NewJSONHandler(w, nil))
	var wg sync.WaitGroup
	wg.Add(1)
	safego.Go(log, unitA, func() {
		defer wg.Done()
		panic("canary-go-value")
	})
	wg.Wait() // a count-down that did not run would hang here until the test timeout
	<-w.got
	got := w.text()
	if strings.Count(got, safego.Msg) != 1 || !strings.Contains(got, `"unit":"a"`) {
		t.Errorf("the panic was not logged once with its unit: %s", got)
	}
	if strings.Contains(got, "canary-go-value") {
		t.Errorf("the value of the panic reached the log: %s", got)
	}
}

// TestAfterAndOnDoneKeepThePanicOfTheirCallback runs the two library-started forms (sms-r18-14). As for
// Go, the recover is the code under test and nothing outside the goroutine can recover for it: a form
// that kept nothing would end this binary, and the lint holds that clause (the callback rule of
// TestEveryGoroutineKeepsItsPanic reads the guard of both). This test holds the rest: each callback
// runs once, its panic is logged once with the unit and never the value, and a stopped one never runs.
func TestAfterAndOnDoneKeepThePanicOfTheirCallback(t *testing.T) {
	for name, start := range map[string]func(log *slog.Logger, fn func()){
		"After": func(log *slog.Logger, fn func()) { safego.After(log, unitA, 0, fn) },
		"OnDone": func(log *slog.Logger, fn func()) {
			ctx, cancel := context.WithCancel(context.Background())
			safego.OnDone(ctx, log, unitA, fn)
			cancel()
		},
	} {
		w := &signalWriter{got: make(chan struct{})}
		log := slog.New(slog.NewJSONHandler(w, nil))
		ran := make(chan struct{}, 2)
		start(log, func() {
			ran <- struct{}{}
			panic("canary-callback-value")
		})
		<-ran
		<-w.got
		got := w.text()
		if strings.Count(got, safego.Msg) != 1 || !strings.Contains(got, `"unit":"a"`) {
			t.Errorf("%s: the panic was not logged once with its unit: %s", name, got)
		}
		if strings.Contains(got, "canary-callback-value") {
			t.Errorf("%s: the value of the panic reached the log: %s", name, got)
		}
	}
	// A callback that is stopped before it fires never runs.
	ran := false
	tm := safego.After(slog.New(slog.NewJSONHandler(&bytes.Buffer{}, nil)), unitA, time.Hour, func() { ran = true })
	if !tm.Stop() || ran {
		t.Errorf("a stopped timer fired or could not be stopped")
	}
	ctx, cancel := context.WithCancel(context.Background())
	stop := safego.OnDone(ctx, slog.New(slog.NewJSONHandler(&bytes.Buffer{}, nil)), unitA, func() { ran = true })
	if !stop() {
		t.Errorf("a callback of a live context could not be stopped")
	}
	cancel()
	if ran {
		t.Errorf("a stopped callback ran")
	}
}
