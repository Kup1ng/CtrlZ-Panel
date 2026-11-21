//go:build timing

package api

import (
	"fmt"
	"os"
	"slices"
	"strconv"
	"testing"
	"time"
)

// TestTimingKnownAndUnknownPhone is the "Timing" row of 18.5, run by the nightly
// job with `go test -tags timing -run TestTiming ./internal/api`. It is not in
// normal CI because wall-clock medians are noisy. Each sample is a password
// login that fails, for a phone that has an account and for one that has not;
// the medians of 500 samples each must differ by less than 20 ms. Both calls
// run one Argon2 hash and wait for the same 500 ms floor with random jitter, so
// a difference means the floor or the hash path leaks the case.
//
// TIMING_SAMPLES overrides the count for a quick local check.
func TestTimingKnownAndUnknownPhone(t *testing.T) {
	n := 500
	if v := os.Getenv("TIMING_SAMPLES"); v != "" {
		n, _ = strconv.Atoi(v)
	}
	f := newFrig(t, frigOpts{})
	A := f.env.A

	var known, unknown []time.Duration
	// Alternate, so slow drift on the machine hits both sides alike.
	for i := 0; i < n; i++ {
		f.clearThrottle() // a fresh throttle each time: this test is about timing, not limits
		c := f.client()
		known = append(known, c.loginPassword(A.Phone, "Wrong-Guess-Heron-4412-x", false).Dur)
		f.clearThrottle()
		c = f.client()
		unknown = append(unknown, c.loginPassword(fmt.Sprintf("0912555%04d", i%10000), "Wrong-Guess-Heron-4412-x", false).Dur)
	}
	med := func(d []time.Duration) time.Duration {
		s := slices.Clone(d)
		slices.Sort(s)
		return s[len(s)/2]
	}
	mk, mu := med(known), med(unknown)
	diff := mk - mu
	if diff < 0 {
		diff = -diff
	}
	t.Logf("median known %v, unknown %v, difference %v over %d samples each", mk, mu, diff, n)
	if diff >= 20*time.Millisecond {
		t.Fatalf("the medians differ by %v; a known phone is distinguishable by timing", diff)
	}
}
