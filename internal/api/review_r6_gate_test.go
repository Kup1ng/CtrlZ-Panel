package api

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/password"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/session"
)

// Tests of the P1 auth review, round 6, area "HTTP spine and tenant API".

// gateLine builds the pressure of a full Argon2 gate BY CONSTRUCTION (round 16, tenant-r16-1 and -4). The
// earlier tests got their pressure from a slow hash and a sleep, so on a fast runner the gate was never
// full and the test passed with the code under test removed (the mutant of the marker lane survived two
// GitHub runs). Here the test takes the slots itself with Gate.Acquire, starts each request in its own
// goroutine, and waits until the request has either taken its place in the gate's queues (Gate.Waiting) or
// been answered. Nothing depends on the host's speed: every wait is on a condition, and a request that
// is not where the property says it must be fails the test at once.
type gateLine struct {
	t        *testing.T
	gate     *password.Gate
	launched int
	answered map[string]*resp
	ch       chan namedResp
}

type namedResp struct {
	name string
	r    *resp
}

func newGateLine(t *testing.T, g *password.Gate) *gateLine {
	return &gateLine{t: t, gate: g, answered: map[string]*resp{}, ch: make(chan namedResp, 64)}
}

// start runs one request. do must only call the client, never the test's Fatal.
func (l *gateLine) start(name string, do func() *resp) {
	l.launched++
	go func() { l.ch <- namedResp{name, do()} }()
}

func (l *gateLine) drain() {
	for {
		select {
		case a := <-l.ch:
			l.answered[a.name] = a.r
		default:
			return
		}
	}
}

// settle waits until every started request waits in a queue or has been answered. It is a condition and
// a generous bound that only a hung test reaches.
func (l *gateLine) settle() (proved, plain int) {
	l.t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		l.drain()
		proved, plain = l.gate.Waiting()
		if proved+plain+len(l.answered) >= l.launched {
			return proved, plain
		}
		if time.Now().After(deadline) {
			l.t.Fatalf("%d requests started, %d queued, %d answered: some never reached the gate", l.launched, proved+plain, len(l.answered))
		}
		time.Sleep(time.Millisecond)
	}
}

// await waits for the named requests to be answered.
func (l *gateLine) await(names ...string) {
	l.t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		l.drain()
		done := true
		for _, n := range names {
			if l.answered[n] == nil {
				done = false
			}
		}
		if done {
			return
		}
		if time.Now().After(deadline) {
			l.t.Fatalf("no answer for %v after the slots were given back (answered: %d)", names, len(l.answered))
		}
		time.Sleep(time.Millisecond)
	}
}

// TestUnprovedLoginsCannotStarveTheTenantsWhoHoldAProof is tenant-r6-1 and -7. The tenant Argon2
// gate has two slots and every unproved login runs a hash in one of them (an unknown phone runs
// the dummy), so a flood of them from a few dozen networks refused a signed-in owner's reauth, a
// returning browser's login and a reset whose code was right with 503 server_busy, for as long as
// it lasted. The gate now serves a request with a proof first (password.Proved: a session that
// passed its gate, a device marker that holds for the account, a Spec whose proof was looked at),
// and refuses a stranger at once while one waits.
//
// The test holds both slots and queues two strangers, then asks for the proofs one by one: each must
// take its place in the proved lane and be left waiting there (a request that is answered 503 at once was
// treated as a stranger: the plain queue was full, which is what the lane exists to prevent). Strangers
// after that must be turned away at once, which is the pressure and is asserted. Giving the slots back must
// serve the proofs, and the strangers that queued, and nothing is left waiting. Removing the lane from the
// marker login (budget-keying-marker-login-is-not-in-the-gate-lane) or the session (budget-keying-tenant-
// session-is-not-in-the-gate-lane) fails the step that asks for that proof, on any host.
func TestUnprovedLoginsCannotStarveTheTenantsWhoHoldAProof(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A, B := f.env.A, f.env.B
	// A cheap hash: the slots are held by the test, so the cost of a run decides nothing. The wait is long
	// because the test ends every wait itself by giving a slot back.
	h, err := password.NewHasher(password.Params{MemoryKiB: 64, Time: 1, Threads: 1}, password.NewGate(2, 60*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	f.hasher, f.deps.Hasher = h, h
	f.setLimiter(f.deps.Limiter)
	f.setPassword(A.Tenant, A.User, pwA)
	f.setPassword(B.Tenant, B.User, pwB)
	f.clearThrottle()

	// A returning browser of A (a device marker that holds) and a signed-in session of B. They are two
	// accounts because the lane takes one hash per account at a time (password.ProvedAs).
	first := f.client()
	first.mustLogin(A.Phone, pwA)
	marker := first.jar[session.CookieDevice]
	if marker == nil {
		t.Fatal("the login gave no device marker")
	}
	returning := f.client()
	returning.jar[session.CookieDevice] = &http.Cookie{Name: session.CookieDevice, Value: marker.Value}
	owner := f.makeSession(B.Tenant, B.User)
	s1, s2 := f.client(), f.client()
	extra := []*client{f.client(), f.client(), f.client()}

	hold1, err := h.Gate().Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	hold2, err := h.Gate().Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	released := false
	release := func() {
		if !released {
			released = true
			hold1()
			hold2()
		}
	}
	defer release()

	line := newGateLine(t, h.Gate())
	line.start("stranger1", func() *resp { return s1.loginPassword("09127770001", pwA, false) })
	line.start("stranger2", func() *resp { return s2.loginPassword("09127770002", pwA, false) })
	if proved, plain := line.settle(); proved != 0 || plain != 2 {
		t.Fatalf("two strangers against a full gate: %d proved and %d plain waiting, want 0 and 2", proved, plain)
	}

	line.start("marker-login", func() *resp { return returning.loginPassword(A.Phone, pwA, false) })
	proved, plain := line.settle()
	if r := line.answered["marker-login"]; r != nil {
		t.Fatalf("a login with a device marker that holds was answered %d %s while the gate was full: it was not put in the proved lane", r.Code, r.Body)
	}
	if proved != 1 || plain != 2 {
		t.Fatalf("after the marker login: %d proved and %d plain waiting, want 1 and 2", proved, plain)
	}

	line.start("reauth", func() *resp { return owner.reauthPassword(pwB) })
	proved, plain = line.settle()
	if r := line.answered["reauth"]; r != nil {
		t.Fatalf("the reauth of a signed-in owner was answered %d %s while the gate was full: it was not put in the proved lane", r.Code, r.Body)
	}
	if proved != 2 || plain != 2 {
		t.Fatalf("after the reauth: %d proved and %d plain waiting, want 2 and 2", proved, plain)
	}

	// The pressure, asserted: with the lane in use and the plain queue full, every further stranger is
	// turned away at once. A run that could not build this fails here and is not a pass.
	for i, c := range extra {
		c.loginPassword("0912777100"+string(rune('1'+i)), pwA, false).want(503, "server_busy")
	}

	release()
	line.await("marker-login", "reauth", "stranger1", "stranger2")
	if r := line.answered["marker-login"]; r.Code != http.StatusOK {
		t.Errorf("the marker login, once a slot was free: %d %s", r.Code, r.Body)
	}
	if r := line.answered["reauth"]; r.Code != http.StatusNoContent {
		t.Errorf("the owner's reauth, once a slot was free: %d %s", r.Code, r.Body)
	}
	for _, n := range []string{"stranger1", "stranger2"} {
		if r := line.answered[n]; r.Code == http.StatusServiceUnavailable {
			t.Errorf("%s queued behind the proofs and was still turned away: %d %s", n, r.Code, r.Body)
		}
	}
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
