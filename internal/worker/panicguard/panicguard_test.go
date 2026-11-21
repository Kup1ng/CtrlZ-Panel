package panicguard_test

import (
	"bytes"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/worker/panicguard"
)

type unit string

const (
	unitA unit = "a"
)

func (u unit) Valid() bool { return u == unitA }

// escapes runs f and reports whether a panic got out of it. The outer recover is the test's own, so
// a Keep that stops nothing makes the test FAIL cleanly instead of ending the test binary, which the
// mutant registry could not tell from a test that did not run (sms-r17-14).
func escapes(f func()) (out bool) {
	defer func() { out = recover() != nil }()
	f()
	return false
}

// countedDown fails the test when the counter of wg is not zero. Taking one more off a counter that is
// already zero is the panic of sync, and one that is not zero is taken to zero without one, so the check
// needs no wait and no clock, and a skipped count-down fails here and does not hang the binary.
func countedDown(t *testing.T, wg *sync.WaitGroup) {
	t.Helper()
	if !escapes(func() { wg.Add(-1) }) {
		t.Error("the count-down of the goroutine was skipped")
	}
}

// TestKeepStopsThePanicAndCountsDown is the property of the package: a panic inside a unit does not
// leave it, the goroutine's count-down still happens, and the log holds the unit and not the value.
func TestKeepStopsThePanicAndCountsDown(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	var wg sync.WaitGroup
	wg.Add(1)
	if escapes(func() {
		defer panicguard.Keep(log, unitA, &wg)
		panic("canary-panic-value 123456")
	}) {
		t.Fatal("the panic left the guarded unit")
	}
	countedDown(t, &wg)
	got := buf.String()
	if strings.Count(got, panicguard.Msg) != 1 || !strings.Contains(got, `"unit":"a"`) {
		t.Errorf("the panic was not logged once with its unit: %s", got)
	}
	if strings.Contains(got, "canary-panic-value") || strings.Contains(got, "123456") {
		t.Errorf("the value of the panic reached the log: %s", got)
	}
}

// TestKeepAroundAPassNeedsNoWaitGroup covers the second use: a pass of a loop, with no count-down.
func TestKeepAroundAPassNeedsNoWaitGroup(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	ran := 0
	pass := func(boom bool) {
		defer panicguard.Keep(log, unitA, nil)
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
	if strings.Count(buf.String(), panicguard.Msg) != 1 {
		t.Errorf("a pass that did not panic logged, or the one that did did not: %s", buf.String())
	}
}

// TestKeepCountsDownWhenNothingPanicked is the quiet path: no log line, one count-down.
func TestKeepCountsDownWhenNothingPanicked(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	var wg sync.WaitGroup
	wg.Add(1)
	func() { defer panicguard.Keep(log, unitA, &wg) }()
	countedDown(t, &wg)
	if buf.Len() != 0 {
		t.Errorf("a clean unit logged: %s", buf.String())
	}
}
