// Package appclock is the one place under internal/auth, internal/api,
// internal/adminapi and internal/store that reads the machine's clock (P1 auth
// review round 5, rule clock-source). A lint fails for time.Now, time.Since or
// time.Until anywhere else there.
//
// Why: a security window is only as testable as its clock. When every service
// takes its time from this package, a test that replaces Func moves every window at
// once, and a window cannot be decided by a clock the test did not move. The
// database has its own clock (clocks.yaml says which column uses which), and the two
// are never mixed in one decision.
package appclock

import "time"

// Func is a source of the application time. A service holds one and tests replace it.
type Func func() time.Time

// Now is the application clock.
func Now() time.Time { return time.Now() }

// Or returns f, or Now when f is nil, so a service whose clock was not set reads the
// real one.
func Or(f Func) Func {
	if f == nil {
		return Now
	}
	return f
}
