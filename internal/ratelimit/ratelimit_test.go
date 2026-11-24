package ratelimit

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

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

func newClock() *clock { return &clock{t: time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)} }

// fakeBackend is a Backend that can be told to fail, and counts calls.
type fakeBackend struct {
	mu    sync.Mutex
	fail  bool
	calls int
	inner *local
	now   func() time.Time
}

func (f *fakeBackend) Take(_ context.Context, s []slot) (bool, time.Duration, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.fail {
		return false, 0, errors.New("down")
	}
	ok, d := f.inner.take(s, f.now())
	return ok, d, nil
}
func (f *fakeBackend) Give(_ context.Context, s []slot) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.fail {
		return errors.New("down")
	}
	f.inner.give(s, f.now())
	return nil
}

func cls(t *testing.T, name string) Class {
	t.Helper()
	c, ok := Lookup(Tenant, name)
	if !ok {
		t.Fatalf("no class %s", name)
	}
	return c
}

func TestBurstThenRefill(t *testing.T) {
	ck := newClock()
	l := New(Config{Service: Tenant, LocalOnly: true, Now: ck.now})
	c := cls(t, "auth") // 20 a minute
	s := Subject{Network: "203.0.113.0/24"}
	for i := 0; i < 20; i++ {
		d, err := l.Allow(context.Background(), c, s)
		if err != nil || !d.Allowed {
			t.Fatalf("request %d refused: %+v %v", i, d, err)
		}
	}
	d, _ := l.Allow(context.Background(), c, s)
	if d.Allowed {
		t.Fatal("the 21st request must be refused")
	}
	if d.RetryAfter <= 0 || d.RetryAfter > 4*time.Second {
		t.Fatalf("retry after = %v, want about 3 s (one token at 20/min)", d.RetryAfter)
	}
	ck.add(3100 * time.Millisecond)
	if d, _ := l.Allow(context.Background(), c, s); !d.Allowed {
		t.Fatal("one token must have refilled after 3.1 s")
	}
	if d, _ := l.Allow(context.Background(), c, s); d.Allowed {
		t.Fatal("only one token refilled")
	}
}

func TestNetworksAreSeparate(t *testing.T) {
	l := New(Config{Service: Tenant, LocalOnly: true, Now: newClock().now})
	c := cls(t, "auth")
	for i := 0; i < 20; i++ {
		l.Allow(context.Background(), c, Subject{Network: "a"})
	}
	if d, _ := l.Allow(context.Background(), c, Subject{Network: "a"}); d.Allowed {
		t.Fatal("network a must be exhausted")
	}
	if d, _ := l.Allow(context.Background(), c, Subject{Network: "b"}); !d.Allowed {
		t.Fatal("network b must be untouched")
	}
}

func TestWideBucketStopsRotatingSlash64s(t *testing.T) {
	// One /48, many /64s: each /64 is far under its own limit, the /48 is not.
	l := New(Config{Service: Tenant, LocalOnly: true, Now: newClock().now})
	c := cls(t, "auth") // /48 gets 80
	allowed := 0
	for i := 0; i < 200; i++ {
		d, _ := l.Allow(context.Background(), c, Subject{Network: "net-" + string(rune('A'+i%100)) + "/64", Wide: "2001:db8:1::/48"})
		if d.Allowed {
			allowed++
		}
	}
	if allowed != 20*WideFactor {
		t.Fatalf("the /48 allowed %d requests, want %d", allowed, 20*WideFactor)
	}
}

func TestTwoLimitsAreAllOrNothing(t *testing.T) {
	ck := newClock()
	l := New(Config{Service: Tenant, LocalOnly: true, Now: ck.now})
	c := cls(t, "otp-send") // 5 a minute and 30 an hour
	s := Subject{Network: "n"}
	sent := 0
	for minute := 0; minute < 8; minute++ {
		for i := 0; i < 5; i++ {
			if d, _ := l.Allow(context.Background(), c, s); d.Allowed {
				sent++
			}
		}
		if d, _ := l.Allow(context.Background(), c, s); d.Allowed {
			t.Fatal("a sixth request in one minute must be refused")
		}
		ck.add(time.Minute)
	}
	// 8 minutes at 5 each would be 40; the hourly bucket caps it at 30 (plus the
	// fraction that refilled), and a refused request must not have spent a token.
	if sent < 30 || sent > 34 {
		t.Fatalf("sent %d in 8 minutes, want about 30", sent)
	}
}

func TestRefundRestoresAToken(t *testing.T) {
	l := New(Config{Service: Tenant, LocalOnly: true, Now: newClock().now})
	c := cls(t, SessionLookup)
	s := Subject{Session: "cookie-hash"}
	for i := 0; i < 120; i++ {
		l.Allow(context.Background(), c, s)
	}
	if d, _ := l.Allow(context.Background(), c, s); d.Allowed {
		t.Fatal("exhausted")
	}
	l.Refund(context.Background(), c, s)
	if d, _ := l.Allow(context.Background(), c, s); !d.Allowed {
		t.Fatal("a refunded token must be usable")
	}
	// Refunds never push a bucket past its capacity.
	for i := 0; i < 500; i++ {
		l.Refund(context.Background(), c, s)
	}
	n := 0
	for i := 0; i < 500; i++ {
		if d, _ := l.Allow(context.Background(), c, s); d.Allowed {
			n++
		}
	}
	if n != 120 {
		t.Fatalf("after many refunds the burst is %d, want 120", n)
	}
}

func TestLocalIsBoundedLRU(t *testing.T) {
	l := New(Config{Service: Tenant, LocalOnly: true, LocalKeys: 50, Now: newClock().now})
	c := cls(t, "auth")
	for i := 0; i < 1000; i++ {
		l.Allow(context.Background(), c, Subject{Network: string(rune(0x100 + i))})
	}
	if n := l.LocalSize(); n > 50 {
		t.Fatalf("the fallback holds %d buckets, cap is 50", n)
	}
}

func TestOpenClassFallsBackAndClosedClassRefuses(t *testing.T) {
	ck := newClock()
	fb := &fakeBackend{inner: newLocal(100), now: ck.now, fail: true}
	l := New(Config{Service: Tenant, Backend: fb, Now: ck.now})

	open := cls(t, "auth")
	for i := 0; i < 20; i++ {
		d, err := l.Allow(context.Background(), open, Subject{Network: "n"})
		if err != nil || !d.Allowed {
			t.Fatalf("open class must fall back, got %+v %v", d, err)
		}
	}
	if d, _ := l.Allow(context.Background(), open, Subject{Network: "n"}); d.Allowed {
		t.Fatal("the fallback has the same numbers")
	}

	closed := cls(t, "otp-send")
	if _, err := l.Allow(context.Background(), closed, Subject{Network: "n"}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("closed class with the backend down: %v", err)
	}
}

func TestBackendCooldownAndRecovery(t *testing.T) {
	ck := newClock()
	fb := &fakeBackend{inner: newLocal(100), now: ck.now, fail: true}
	l := New(Config{Service: Tenant, Backend: fb, Now: ck.now, Cooldown: 3 * time.Second})
	c := cls(t, "auth")
	for i := 0; i < 10; i++ {
		l.Allow(context.Background(), c, Subject{Network: "n"})
	}
	if fb.calls != 1 {
		t.Fatalf("during the cooldown the backend was called %d times, want 1", fb.calls)
	}
	fb.mu.Lock()
	fb.fail = false
	fb.mu.Unlock()
	ck.add(4 * time.Second)
	l.Allow(context.Background(), c, Subject{Network: "n"})
	if fb.calls != 2 {
		t.Fatalf("after the cooldown the backend must be tried again, calls = %d", fb.calls)
	}
	// And the closed class works again.
	if d, err := l.Allow(context.Background(), cls(t, "otp-send"), Subject{Network: "m"}); err != nil || !d.Allowed {
		t.Fatalf("closed class after recovery: %+v %v", d, err)
	}
}

func TestNoBackendIsTreatedAsDown(t *testing.T) {
	l := New(Config{Service: Tenant, Now: newClock().now})
	if _, err := l.Allow(context.Background(), cls(t, "otp-send"), Subject{Network: "n"}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("no backend and not local-only must fail a closed class closed: %v", err)
	}
	if d, err := l.Allow(context.Background(), cls(t, "auth"), Subject{Network: "n"}); err != nil || !d.Allowed {
		t.Fatalf("open class without a backend: %+v %v", d, err)
	}
}

func TestEmptySubjectIsRefusedLoudly(t *testing.T) {
	l := New(Config{Service: Tenant, LocalOnly: true})
	if _, err := l.Allow(context.Background(), cls(t, "user-read"), Subject{}); !errors.Is(err, ErrNoSubject) {
		t.Fatalf("a session class with no session: %v", err)
	}
}

func TestClassTablesMatchTheSpec(t *testing.T) {
	// The lookup of a session cookie is counted per cookie hash, so that junk and
	// dead cookies cannot spend a budget the live sessions behind one NAT share
	// (round 4, tenant-r4-4).
	for _, svc := range []Service{Tenant, Admin} {
		if c, _ := Lookup(svc, SessionLookup); c.Key != BySession {
			t.Errorf("%s session-lookup is keyed %v, want BySession", svc, c.Key)
		}
	}
	want := map[string]struct {
		n   int
		per time.Duration
	}{
		"public-read": {60, time.Minute}, "auth": {20, time.Minute}, "user-read": {300, time.Minute},
		"user-write": {60, time.Minute}, "sensitive": {10, time.Minute}, SessionLookup: {120, time.Minute},
	}
	for name, w := range want {
		c := cls(t, name)
		if len(c.Limits) != 1 || c.Limits[0].Max != w.n || c.Limits[0].Per != w.per {
			t.Errorf("%s = %+v", name, c.Limits)
		}
	}
	o := cls(t, "otp-send")
	if len(o.Limits) != 2 || !o.FailClosed {
		t.Errorf("otp-send = %+v", o)
	}
	for _, c := range Classes(Tenant) {
		// The SMS classes and the link budget of a tenant are closed on purpose (P3 9.1): a bound on how many ids can ever pass the
		// check of a link value that fails open is no bound.
		if c.Name != "otp-send" && c.Name != "otp-send-user" && c.Name != LinkCreate && c.FailClosed {
			t.Errorf("%s must be open", c.Name)
		}
	}
	if !cls(t, LinkCreate).FailClosed {
		t.Error("link-create must be closed")
	}
	for name, n := range map[string]int{"admin-login": 5, "admin-read": 300, "admin-write": 60, SessionLookup: 120} {
		c, ok := Lookup(Admin, name)
		if !ok || c.Limits[0].Max != n {
			t.Errorf("admin %s = %+v", name, c)
		}
	}
}

// A request with a proof is charged to the proof, with the class's limits, and not to the
// network; a class without ProofAlt ignores the proof; a missing address is refused whatever
// else the request carries (rule budget-keying).
func TestProofReplacesTheNetworkOnlyForAClassThatTakesOne(t *testing.T) {
	ck := newClock()
	l := New(Config{Service: Tenant, LocalOnly: true, Now: ck.now})
	auth := cls(t, "auth")
	if !auth.ProofAlt {
		t.Fatal("the auth class takes a proof")
	}
	sub := Subject{Network: "203.0.113.0/24", Proof: "marker-1", ProofSubject: "account-1"}
	for i := 0; i < auth.Limits[0].Max; i++ {
		if d, err := l.Allow(context.Background(), auth, sub); err != nil || !d.Allowed {
			t.Fatalf("proof request %d: %+v %v", i, d, err)
		}
	}
	if d, _ := l.Allow(context.Background(), auth, sub); d.Allowed {
		t.Fatal("the proof's own budget never ended")
	}
	// The network bucket was never touched by those.
	if d, err := l.Allow(context.Background(), auth, Subject{Network: "203.0.113.0/24"}); err != nil || !d.Allowed {
		t.Fatalf("a request with no proof, same network: %+v %v", d, err)
	}
	// A proof that names no account is no proof of anything the bucket can be keyed on (the seal
	// always names one, so this is a wiring slip): it falls back to the plain network bucket
	// instead of a proof-network bucket shared by every account (primitives-r6-5).
	l2 := New(Config{Service: Tenant, LocalOnly: true, Now: ck.now})
	for i := 0; i < auth.Limits[0].Max; i++ {
		_, _ = l2.Allow(context.Background(), auth, Subject{Network: "192.0.2.0/24", Proof: "marker-x"})
	}
	if d, _ := l2.Allow(context.Background(), auth, Subject{Network: "192.0.2.0/24"}); d.Allowed {
		t.Fatal("a proof with no account was not charged to the plain network bucket")
	}
	// A class that takes no proof counts the network whatever is carried.
	pub := cls(t, "public-read")
	if pub.ProofAlt {
		t.Fatal("public-read takes no proof")
	}
	for i := 0; i < pub.Limits[0].Max; i++ {
		_, _ = l.Allow(context.Background(), pub, Subject{Network: "198.51.100.0/24", Proof: "marker-1", ProofSubject: "account-1"})
	}
	if d, _ := l.Allow(context.Background(), pub, Subject{Network: "198.51.100.0/24"}); d.Allowed {
		t.Fatal("a proof was honoured by a class that takes none")
	}
	if _, err := l.Allow(context.Background(), auth, Subject{Proof: "marker-1", ProofSubject: "account-1"}); !errors.Is(err, ErrNoSubject) {
		t.Fatalf("a proof with no address: %v", err)
	}
}
