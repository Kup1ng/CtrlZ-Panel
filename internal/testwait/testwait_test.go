package testwait

import (
	"sync/atomic"
	"testing"
	"time"
)

// fakeT records a Fatalf without stopping the goroutine, so a failing wait can be asserted.
type fakeT struct {
	testing.TB
	failed atomic.Bool
}

func (f *fakeT) Helper()               {}
func (f *fakeT) Fatalf(string, ...any) { f.failed.Store(true) }

func TestUntilReturnsWhenTheConditionHolds(t *testing.T) {
	var n atomic.Int32
	Until(t, 5*time.Second, "three looks", func() bool { return n.Add(1) >= 3 })
	if n.Load() != 3 {
		t.Errorf("looked %d times, want 3", n.Load())
	}
}

func TestUntilLooksOnceMoreAtTheEnd(t *testing.T) {
	var n atomic.Int32
	// The condition is false until the limit has passed; the last look is the one that finds it true.
	start := time.Now()
	ok := Holds(60*time.Millisecond, 20*time.Millisecond, func() bool {
		n.Add(1)
		return time.Since(start) >= 60*time.Millisecond
	})
	if !ok {
		t.Errorf("a condition that held at the limit was missed after %d looks", n.Load())
	}
}

func TestUntilFailsWithWhatItWaitedFor(t *testing.T) {
	f := &fakeT{}
	UntilEvery(f, 40*time.Millisecond, 10*time.Millisecond, "a thing that never happens", func() bool { return false })
	if !f.failed.Load() {
		t.Error("a wait that never held did not fail the test")
	}
}

func TestAWaitWithNoConditionIsRefused(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("a nil condition was accepted")
		}
	}()
	Holds(time.Millisecond, time.Millisecond, nil)
}

func TestReceive(t *testing.T) {
	ch := make(chan int, 1)
	ch <- 7
	if got := Receive(t, ch, time.Second, "a value"); got != 7 {
		t.Errorf("got %d", got)
	}
	if _, ok := TryReceive(make(chan int), 20*time.Millisecond); ok {
		t.Error("a channel nobody wrote to delivered a value")
	}
	closed := make(chan struct{})
	close(closed)
	if _, ok := TryReceive(closed, time.Second); !ok {
		t.Error("a closed channel is the event, and was not delivered")
	}
	f := &fakeT{}
	Receive(f, make(chan int), 20*time.Millisecond, "nothing")
	if !f.failed.Load() {
		t.Error("a receive that timed out did not fail the test")
	}
}
