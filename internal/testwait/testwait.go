// Package testwait is the one place a test waits (rule tests-wait-on-conditions, round 17, admin-r17-11).
//
// The invariant: a wait in a test is on a CONDITION, never on a clock that stands for one. A sleep that ends
// before the thing could have happened makes an assertion of absence (no canary in a log, no marker file) prove
// nothing on a loaded runner. Round 16 allowed `time.Sleep` inside any for or range statement, which is a shape
// and not a rule: `for range 1 { time.Sleep(time.Second) }` passed, and so did `<-time.After(time.Second)`
// before the assertion. The rule is now a construction. The admin area's tests do not call time.Sleep, After,
// AfterFunc, NewTimer, NewTicker or Tick at all (internal/lint TestTestsWaitOnConditionsNotOnClocks refuses
// every reference); they wait through the functions here, each of which takes the predicate or the channel
// that ends the wait, so the clock is only the limit after which the wait gives up and says what it waited for.
package testwait

import (
	"testing"
	"time"
)

// poll is the pause between two looks at a condition.
const poll = 50 * time.Millisecond

// Until calls cond until it returns true and fails the test with what, after limit, when it never did.
func Until(t testing.TB, limit time.Duration, what string, cond func() bool) {
	t.Helper()
	UntilEvery(t, limit, poll, what, cond)
}

// UntilEvery is Until with the pause between two looks, for a condition that costs a process or a round trip to
// ask (a `docker exec`, a SQL query).
func UntilEvery(t testing.TB, limit, every time.Duration, what string, cond func() bool) {
	t.Helper()
	if !Holds(limit, every, cond) {
		t.Fatalf("timed out after %v waiting for %s", limit, what)
	}
}

// Holds reports whether cond became true within limit, looking at it every `every`. It looks once more at the
// end, so a condition that became true during the last pause is not missed. A caller that has more to say than
// "timed out" (a log to print) fails itself.
func Holds(limit, every time.Duration, cond func() bool) bool {
	if cond == nil {
		panic("testwait: a wait with no condition")
	}
	// The limit is a timer and the pause a ticker: a length is counted and no stamp is compared, which is what
	// the clock rule allows (a wait decides nothing about a stored time).
	limitTimer := time.NewTimer(limit)
	defer limitTimer.Stop()
	pause := time.NewTicker(every)
	defer pause.Stop()
	for {
		if cond() {
			return true
		}
		select {
		case <-limitTimer.C:
			return cond()
		case <-pause.C:
		}
	}
}

// Receive returns the value of ch, and fails the test with what when none arrives within limit.
func Receive[T any](t testing.TB, ch <-chan T, limit time.Duration, what string) T {
	t.Helper()
	v, ok := TryReceive(ch, limit)
	if !ok {
		t.Fatalf("timed out after %v waiting for %s", limit, what)
	}
	return v
}

// TryReceive returns the value of ch and true, or the zero value and false when none arrives within limit. A
// closed channel counts as a value: it is the event the caller waited for.
func TryReceive[T any](ch <-chan T, limit time.Duration) (T, bool) {
	timer := time.NewTimer(limit)
	defer timer.Stop()
	select {
	case v := <-ch:
		return v, true
	case <-timer.C:
		var zero T
		return zero, false
	}
}

// Bound gives another goroutine up to limit to signal ch and goes on either way. It is the one wait whose
// answer is not read, and it is named so that the lint can list where it is used (testBoundFiles of
// internal/lint/testsleep_test.go): the callers give a writer that may be queued behind a lock a bounded
// chance to act, or hold a resource for a bounded time, which is a bound on the other side and proves nothing
// by its end. A test that asserts an ABSENCE after it must wait for a condition instead (Until, Holds,
// Receive); every other wait in a test uses its result, which the lint requires (round 17 fix gate, admin-r17-21).
func Bound[T any](ch <-chan T, limit time.Duration) {
	_, _ = TryReceive(ch, limit)
}
