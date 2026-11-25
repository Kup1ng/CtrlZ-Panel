//go:build timing

package api

import (
	"fmt"
	"net/http"
	"os"
	"slices"
	"strconv"
	"sync"
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

// timingRoutes are the public routes where the existence of an account chooses the code path (the table of the oracle
// registry, internal/api oracle_test.go): a real code is issued or a decoy is, a challenge is real or a decoy. Each
// returns the duration of the one request that is measured, for a phone with an account (known) or without one. The
// password login above stays its own test; these are the rest (tenant-r18-12, D64 oracle-coverage-limits, which
// accepts a heavier statement for a known phone with the same number of asks ONLY because a nightly timing check
// would show it, so the check has to reach every route and not one).
func timingRoutes() map[string]func(f *frig, phone string, i int) time.Duration {
	otpRequest := func(purpose string) func(f *frig, phone string, i int) time.Duration {
		return func(f *frig, phone string, _ int) time.Duration {
			f.clearThrottle()
			f.resetTimingSample()
			return f.client().post("/auth/otp/request", map[string]any{"phone": phone, "purpose": purpose}).Dur
		}
	}
	// verify requests a code and then sends a wrong one against the challenge the answer named: for a known phone the
	// challenge is real and takes a try, for an unknown one it is a decoy, and the two must cost the same.
	verify := func(purpose, path string, extra map[string]any) func(f *frig, phone string, i int) time.Duration {
		return func(f *frig, phone string, _ int) time.Duration {
			f.clearThrottle()
			f.resetTimingSample()
			c := f.client()
			var iss issued
			c.post("/auth/otp/request", map[string]any{"phone": phone, "purpose": purpose}).json(&iss)
			f.clearThrottle()
			body := map[string]any{"phone": phone, "challenge_id": iss.ID, "code": "000000"}
			for k, v := range extra {
				body[k] = v
			}
			return c.post(path, body).Dur
		}
	}
	return map[string]func(f *frig, phone string, i int) time.Duration{
		"POST /auth/otp/request (login)":   otpRequest("login"),
		"POST /auth/otp/request (reset)":   otpRequest("reset"),
		"POST /auth/login/otp":             verify("login", "/auth/login/otp", nil),
		"POST /auth/password/reset/verify": verify("reset", "/auth/password/reset/verify", nil),
		// Registration is closed by default, so the test opens it (f.setMode): the oracle exists once an owner does,
		// and an untimed route is the gap tenant-r18-22 names. The code is wrong, as in the routes above, so the
		// password is never scored and the two cases differ only by what the phone is.
		"POST /auth/register": verify("signup", "/auth/register", map[string]any{"password": "Marble-Island-Copper-6620"}),
	}
}

// resetTimingSample gives the next measured request a fresh start without touching what the load makes it queue on
// (tenant-r18-22). The helper the other tests use (requestOTP, clearOTP) truncates the whole counter table, which
// removes the contention the loaded variant exists to create. Here only the challenges of the measured phones go
// (the cooldown reads them; the phones the load uses, 09130 to 09137, are left alone), and the counters are not
// touched at all: their caps are raised out of reach once, by raiseTimingCaps, so that no request is turned away by
// a cap and every measured request takes the path whose cost is measured, while the load keeps writing the very
// rows it reads.
func (f *frig) resetTimingSample() {
	f.t.Helper()
	f.env.Exec(f.t, `DELETE FROM ctrlz.otp_challenges WHERE phone_e164 NOT LIKE '+98913%'`)
}

// raiseTimingCaps lifts every daily cap of the code requests out of reach for the run (the counters themselves
// stay and stay contended); the cooldown is left as it is and is cleared per sample by resetTimingSample.
func (f *frig) raiseTimingCaps() {
	f.t.Helper()
	f.env.Exec(f.t, `UPDATE ctrlz.system_settings SET otp_cap_phone = 1000000000, otp_cap_phone_net = 1000000000, otp_cap_ip = 1000000000,
		otp_cap_net24 = 1000000000, otp_cap_phone_trusted = 1000000000, otp_cap_net48 = 1000000000, otp_cap_global = 2000000000`)
	f.ck.add(31 * time.Second)
}

// medianOf is the median of a sample.
func medianOf(d []time.Duration) time.Duration {
	s := slices.Clone(d)
	slices.Sort(s)
	return s[len(s)/2]
}

// TestTimingKnownAndUnknownPhoneOnEveryOracleRoute is tenant-r18-12: the comparison of TestTimingKnownAndUnknownPhone
// on every route above, with interleaved samples and the same fixed bound, once on an idle machine and once while other
// clients keep the database busy with code requests (which queue on the shared counter rows, so the work of a request
// can overrun its floor, the one case in which a heavier statement for a known phone would show). The first run
// cannot see a difference hidden inside the floor; the second can. TIMING_SAMPLES overrides the count for a quick
// local check.
func TestTimingKnownAndUnknownPhoneOnEveryOracleRoute(t *testing.T) {
	n := 100
	if v := os.Getenv("TIMING_SAMPLES"); v != "" {
		n, _ = strconv.Atoi(v)
	}
	f := newFrig(t, frigOpts{})
	A := f.env.A
	f.setMode("open")
	f.raiseTimingCaps()
	for _, loaded := range []bool{false, true} {
		stop := func() {}
		if loaded {
			done := make(chan struct{})
			var wg sync.WaitGroup
			for w := 0; w < 8; w++ {
				wg.Add(1)
				go func(w int) {
					defer wg.Done()
					for i := 0; ; i++ {
						select {
						case <-done:
							return
						default:
						}
						// An unknown phone of its own and a fresh network: the load is code requests, which write the
						// counters every other request of the kind reads.
						c := &client{f: f, ip: fmt.Sprintf("203.0.%d.%d", 100+w, i%250+1), jar: map[string]*http.Cookie{}, hdr: map[string]string{}}
						c.post("/auth/otp/request", map[string]any{"phone": fmt.Sprintf("0913%d%05d", w, i%100000), "purpose": "login"})
					}
				}(w)
			}
			stop = func() { close(done); wg.Wait() }
		}
		for name, route := range timingRoutes() {
			var known, unknown []time.Duration
			for i := 0; i < n; i++ { // alternate, so drift of the machine hits both sides alike
				known = append(known, route(f, A.Phone, i))
				unknown = append(unknown, route(f, fmt.Sprintf("0912555%04d", i%10000), i))
			}
			mk, mu := medianOf(known), medianOf(unknown)
			diff := mk - mu
			if diff < 0 {
				diff = -diff
			}
			t.Logf("%s (loaded %v): median known %v, unknown %v, difference %v over %d samples each", name, loaded, mk, mu, diff, n)
			if diff >= 20*time.Millisecond {
				t.Errorf("%s (loaded %v): the medians differ by %v; a known phone is distinguishable by timing", name, loaded, diff)
			}
		}
		stop()
	}
}
