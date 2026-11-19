package api

import (
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/password"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/session"
)

// Tests of the P1 auth review, round 6, area "HTTP spine and tenant API".

// TestUnprovedLoginsCannotStarveTheTenantsWhoHoldAProof is tenant-r6-1 and -7. The tenant Argon2
// gate has two slots and every unproved login runs a hash in one of them (an unknown phone runs
// the dummy), so a flood of them from a few dozen networks refused a signed-in owner's reauth, a
// returning browser's login and a reset whose code was right with 503 server_busy, for as long as
// it lasted. The gate now serves a request with a proof first (password.Proved: a session that
// passed its gate, a device marker that holds for the account, a Spec whose proof was looked at),
// and refuses a stranger at once while one waits. The flood runs the whole time; each proved
// request must be answered, and the flood must have been turned away at least once, or the test
// proved nothing.
func TestUnprovedLoginsCannotStarveTheTenantsWhoHoldAProof(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A := f.env.A
	// A hash big enough that a gate of two slots is the bottleneck, and a wait shorter than the
	// time the forty strangers need to get through it, so the strangers are refused.
	heavy, err := password.NewHasher(password.Params{MemoryKiB: 32 * 1024, Time: 3, Threads: 1}, password.NewGate(2, 400*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	f.hasher, f.deps.Hasher = heavy, heavy
	f.setLimiter(f.deps.Limiter)
	f.setPassword(A.Tenant, A.User, pwA)
	f.clearThrottle()

	// A returning browser: a device marker that holds for A, and the sessions that will reauth.
	first := f.client()
	first.mustLogin(A.Phone, pwA)
	marker := first.jar[session.CookieDevice]
	if marker == nil {
		t.Fatal("the login gave no device marker")
	}
	const n = 6
	owners := make([]*client, n)
	returning := make([]*client, n)
	for i := range owners {
		owners[i] = f.makeSession(A.Tenant, A.User)
		returning[i] = f.client()
		returning[i].jar[session.CookieDevice] = &http.Cookie{Name: session.CookieDevice, Value: marker.Value}
	}
	// 250 networks, one request each in turn, so no network-keyed bucket is what refuses.
	strangers := make([]*client, 250)
	for i := range strangers {
		strangers[i] = f.client()
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	var busy, served atomic.Int64
	for g := 0; g < 40; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				r := strangers[(g*6+i)%len(strangers)].loginPassword(fmt.Sprintf("0912777%04d", (g*1000+i)%10000), pwA, false)
				if r.Code == http.StatusServiceUnavailable {
					busy.Add(1)
				} else {
					served.Add(1)
				}
			}
		}()
	}
	time.Sleep(150 * time.Millisecond) // the gate is full and the queue is long

	for i := range owners {
		if r := owners[i].reauthPassword(pwA); r.Code != http.StatusNoContent {
			t.Errorf("reauth %d of a signed-in owner, with the flood running: %d %s", i, r.Code, r.Body)
		}
	}
	for i := range returning {
		// Distinct networks keep the throttle scopes of one address out of it; the marker is what
		// makes the verify a proof.
		if r := returning[i].loginPassword(A.Phone, pwA, false); r.Code != http.StatusOK {
			t.Errorf("login %d with a device marker that holds, with the flood running: %d %s", i, r.Code, r.Body)
		}
	}
	close(stop)
	wg.Wait()
	if busy.Load() == 0 || served.Load() == 0 {
		t.Fatalf("the flood was turned away %d times and served %d times; it must have done both", busy.Load(), served.Load())
	}
	t.Logf("flood: %d turned away, %d served; %d reauths and %d marker logins all answered", busy.Load(), served.Load(), n, n)
}

// TestBusyReauthGivesBackTheCharge is tenant-r6-8. Reauth charges reauth_user and then verifies the
// password outside proof.Run, so the refund that every Spec has (tenant-r5-1) did not cover it:
// five 503 server_busy answers spent the five tries and the right password was a 429 for the rest
// of the window once the load had gone. The lint in internal/lint (TestAChargeBeforeAGateIsGivenBack
// WhenTheGateIsFull) holds every function of this shape to the same rule.
func TestBusyReauthGivesBackTheCharge(t *testing.T) {
	f, release := busyFrig(t, frigOpts{})
	f.clearThrottle()
	A := f.env.A
	owner := f.makeSession(A.Tenant, A.User)
	for i := 0; i < 8; i++ {
		owner.reauthPassword(pwA).want(503, "server_busy")
	}
	if n := f.scopeCount("reauth_user"); n != 0 {
		t.Fatalf("eight busy reauths left reauth_user at %d, want 0", n)
	}
	release()
	owner.reauthPassword(pwA).want(204, "")
}

// TestRotatingTheCookieDoesNotResetTheSessionClass is tenant-r6-5, on the real routes. Reauth
// rotates the cookie on success, and the route's own class (sensitive, 10 a minute) was keyed on the
// cookie, so every new cookie was a new bucket: 25 of 25 reauths in a minute, each an Argon2 run.
// The class is also charged on the session id, which a rotation keeps. A second session of the same
// user keeps its own budget.
func TestRotatingTheCookieDoesNotResetTheSessionClass(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A := f.env.A
	f.clearThrottle()
	loop := f.makeSession(A.Tenant, A.User)
	other := f.makeSession(A.Tenant, A.User)
	ok, limited := 0, 0
	started := time.Now()
	for i := 0; i < 25; i++ {
		before := loop.jar[session.CookieSession].Value
		switch r := loop.reauthPassword(pwA); r.Code {
		case http.StatusNoContent:
			ok++
			if loop.jar[session.CookieSession].Value == before {
				t.Fatal("the reauth did not rotate the cookie, so this test proves nothing")
			}
		case http.StatusTooManyRequests:
			limited++
		default:
			t.Fatalf("reauth %d: %d %s", i, r.Code, r.Body)
		}
	}
	// The class is a token bucket in Valkey that refills on the server's clock (10 a minute, one token every
	// 6 s), not on the fake clock of this test. On a loaded host the 25 sequential reauths, each an Argon2 run
	// behind a floor, can take long enough for a token to come back, so the count is bounded by the tokens
	// the bucket could have held plus what it refilled in the time the loop really took (tenant-r7-3). A
	// bucket keyed on the cookie answers all 25, which is far above any bound that a loop that fast can reach.
	elapsed := time.Since(started)
	maxOK := 10 + int(elapsed/(6*time.Second)) + 1
	if maxOK >= 25 {
		t.Skipf("the loop took %v, long enough for the bucket to refill the whole difference: this host is too slow to measure the class", elapsed)
	}
	if ok < 10 || ok > maxOK || ok+limited != 25 {
		t.Fatalf("a session that rotated its cookie on every request was answered %d times and refused %d in %v, want between 10 and %d answered", ok, limited, elapsed, maxOK)
	}
	other.reauthPassword(pwA).want(204, "")
}
