package ratelimit

import (
	"context"
	"errors"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/valkey-io/valkey-go"

	"github.com/Kup1ng/CtrlZ-Panel/internal/testvalkey"
)

var server *testvalkey.Server

func TestMain(m *testing.M) {
	os.Exit(testvalkey.RunMain(m, func(s *testvalkey.Server) { server = s }))
}

func needValkey(t *testing.T) *Valkey {
	t.Helper()
	if server == nil {
		t.Skip("-short: no Valkey container")
	}
	v := NewValkey(ValkeyConfig{Addr: server.Addr})
	t.Cleanup(v.Close)
	return v
}

// uniq keeps tests from sharing buckets in the one container.
var seq atomic.Int64

func uniq(t *testing.T) Subject {
	return Subject{Network: t.Name() + "-" + time.Now().Format("150405.000000") + "-" + string(rune('a'+seq.Add(1)%26))}
}

func TestValkeyBucketBurstAndRetryAfter(t *testing.T) {
	v := needValkey(t)
	l := New(Config{Service: Tenant, Backend: v, Timeout: callTimeout})
	c := cls(t, "auth")
	s := uniq(t)
	for i := 0; i < 20; i++ {
		d, err := l.Allow(context.Background(), c, s)
		if err != nil || !d.Allowed {
			t.Fatalf("request %d: %+v %v", i, d, err)
		}
	}
	d, err := l.Allow(context.Background(), c, s)
	if err != nil || d.Allowed {
		t.Fatalf("21st: %+v %v", d, err)
	}
	if d.RetryAfter <= 0 || d.RetryAfter > 4*time.Second {
		t.Fatalf("retry after %v", d.RetryAfter)
	}
	if l.LocalSize() != 0 {
		t.Fatal("with Valkey up nothing may be counted in process")
	}
}

func TestValkeyParallelCallersNeverOverspend(t *testing.T) {
	v := needValkey(t)
	// Two limiters stand for two instances sharing one Valkey.
	a := New(Config{Service: Tenant, Backend: v, Timeout: callTimeout})
	b := New(Config{Service: Tenant, Backend: v, Timeout: callTimeout})
	// Warm the connection and the script cache first: a cold dial can outlast the
	// 250 ms call timeout under 200 goroutines, and then the limiter, by design,
	// falls back to its in-process bucket, which is not what this test measures.
	if d, err := a.Allow(context.Background(), cls(t, "user-read"), Subject{Session: "warm-" + uniq(t).Network}); err != nil || !d.Allowed {
		t.Fatalf("warm-up: %+v %v", d, err)
	}
	if a.LocalSize() != 0 {
		t.Fatal("the warm-up must have gone through Valkey")
	}
	c := cls(t, "user-write") // 60
	s := Subject{Session: uniq(t).Network}
	var wg sync.WaitGroup
	var ok atomic.Int64
	started := time.Now()
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			l := a
			if i%2 == 1 {
				l = b
			}
			if d, err := l.Allow(context.Background(), c, s); err == nil && d.Allowed {
				ok.Add(1)
			}
		}()
	}
	wg.Wait()
	// 60 is the burst; a few extra tokens may refill during the run.
	if n, max := ok.Load(), 62+int(time.Since(started).Seconds()*2); n < 60 || n > int64(max) {
		t.Fatalf("allowed %d of 200 parallel requests, want 60 (at most %d with refill)", n, max)
	}
}

func TestValkeyTwoLimitsAreAllOrNothing(t *testing.T) {
	v := needValkey(t)
	l := New(Config{Service: Tenant, Backend: v, Timeout: callTimeout})
	c := cls(t, "otp-send")
	s := uniq(t)
	n := 0
	for i := 0; i < 12; i++ {
		if d, err := l.Allow(context.Background(), c, s); err == nil && d.Allowed {
			n++
		}
	}
	if n != 5 {
		t.Fatalf("allowed %d, want 5 (the minute bucket)", n)
	}
}

func TestValkeyWideBucketAndRefund(t *testing.T) {
	v := needValkey(t)
	l := New(Config{Service: Tenant, Backend: v, Timeout: callTimeout})
	c := cls(t, "auth")
	wide := uniq(t).Network + "/48"
	n := 0
	started := time.Now()
	for i := 0; i < 150; i++ {
		d, err := l.Allow(context.Background(), c, Subject{Network: wide + "-" + string(rune('a'+i%26)) + string(rune('a'+i/26)), Wide: wide})
		if err == nil && d.Allowed {
			n++
		}
	}
	// The bucket refills while the loop runs, so the ceiling grows with the time
	// it took: on a loaded machine 150 calls to a container take seconds. The
	// refill is under 2 tokens a second; 80 is the floor either way.
	if max := 82 + int(time.Since(started).Seconds()*2); n < 80 || n > max {
		t.Fatalf("the /48 bucket allowed %d, want 80 (at most %d with refill)", n, max)
	}

	lc := cls(t, SessionLookup)
	// Counted per cookie hash, not per network (round 4, tenant-r4-4).
	s := Subject{Session: uniq(t).Network}
	for i := 0; i < 130; i++ {
		l.Allow(context.Background(), lc, s)
	}
	for i := 0; i < 5; i++ {
		l.Refund(context.Background(), lc, s)
	}
	// Without the refunds at most one token would have refilled by now.
	got := 0
	for i := 0; i < 10; i++ {
		if d, _ := l.Allow(context.Background(), lc, s); d.Allowed {
			got++
		}
	}
	if got < 5 {
		t.Fatalf("after 5 refunds only %d requests passed", got)
	}
}

func TestValkeyDownThenBackWithoutRestart(t *testing.T) {
	// A backend that cannot be reached at all: the client is created lazily, so
	// constructing and using it must not panic or hang, and the limiter falls back.
	dead := NewValkey(ValkeyConfig{Addr: "127.0.0.1:1", DialTimeout: 200 * time.Millisecond})
	defer dead.Close()
	ck := newClock()
	l := New(Config{Service: Tenant, Backend: dead, Now: ck.now, Cooldown: time.Second})
	start := time.Now()
	d, err := l.Allow(context.Background(), cls(t, "auth"), Subject{Network: "n"})
	if err != nil || !d.Allowed {
		t.Fatalf("open class with Valkey unreachable: %+v %v", d, err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("an unreachable Valkey must cost one short timeout, not a hang")
	}
	if _, err := l.Allow(context.Background(), cls(t, "otp-send"), Subject{Network: "n"}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("otp-send with Valkey unreachable: %v", err)
	}

	// Now the same limiter against a real server: after the cooldown it recovers.
	if server == nil {
		return
	}
	good := NewValkey(ValkeyConfig{Addr: server.Addr})
	defer good.Close()
	l2 := New(Config{Service: Tenant, Backend: good, Now: ck.now, Timeout: callTimeout})
	if d, err := l2.Allow(context.Background(), cls(t, "otp-send"), uniq(t)); err != nil || !d.Allowed {
		t.Fatalf("otp-send with Valkey up: %+v %v", d, err)
	}
}

// callTimeout is the per-call timeout of the limiters in the tests that need
// Valkey to answer. The production default is 250 ms, which a cold dial to a
// container that has just started can exceed on a loaded machine; the limiter
// then falls back to its in-process bucket by design, and these tests measure
// the Valkey bucket, not the fallback. Spec 18.3 tests the fallback on its own.
const callTimeout = 5 * time.Second

// A Valkey that is blackholed when the service starts: the dial takes its full
// timeout and fails. Round 2 (tenant-r2-1): the dial used to run under the
// client mutex, so k concurrent requests waited 1, 2, ... k seconds in series.
// The seam makes the hang exact; a loopback address either refuses at once or
// is not portable.
func TestValkeyColdDialOfABlackholeDoesNotStallInSeries(t *testing.T) {
	const dialHang = time.Second
	var dials atomic.Int64
	dead := NewValkey(ValkeyConfig{Addr: "203.0.113.1:6379"})
	dead.newClient = func(valkey.ClientOption) (valkey.Client, error) {
		dials.Add(1)
		time.Sleep(dialHang)
		return nil, errors.New("i/o timeout")
	}
	defer dead.Close()
	l := New(Config{Service: Tenant, Backend: dead, Timeout: 250 * time.Millisecond, Cooldown: 3 * time.Second})

	const n = 8
	var wg sync.WaitGroup
	start := time.Now()
	results := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// An open class answers from the in-process bucket.
			d, err := l.Allow(context.Background(), cls(t, "auth"), Subject{Network: "cold-" + strconv.Itoa(i)})
			if err == nil && !d.Allowed {
				err = errors.New("refused")
			}
			results[i] = err
		}()
	}
	wg.Wait()
	if took := time.Since(start); took > 1500*time.Millisecond {
		t.Fatalf("%d parallel Allow calls against a blackholed Valkey took %v; the dial must not run under a lock", n, took)
	}
	for i, err := range results {
		if err != nil {
			t.Fatalf("open class, call %d: %v", i, err)
		}
	}
	// One shared dial, not one per caller.
	if got := dials.Load(); got != 1 {
		t.Fatalf("%d dials for %d callers; waiters must share the dial in flight", got, n)
	}
	// A fail-closed class refuses at once while the cooldown runs.
	t0 := time.Now()
	if _, err := l.Allow(context.Background(), cls(t, "otp-send"), Subject{Network: "cold"}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("otp-send: %v", err)
	}
	if time.Since(t0) > 100*time.Millisecond {
		t.Fatal("a call during the cooldown must not wait for the dial")
	}
}

// A request whose context is already cancelled does not wait for a dial.
func TestValkeyCancelledCallerDoesNotWaitForTheDial(t *testing.T) {
	release := make(chan struct{})
	v := NewValkey(ValkeyConfig{Addr: "203.0.113.1:6379"})
	v.newClient = func(valkey.ClientOption) (valkey.Client, error) {
		<-release
		return nil, errors.New("i/o timeout")
	}
	defer func() { close(release); v.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	if _, _, err := v.Take(ctx, []slot{{key: "k", max: 1, per: time.Second}}); !errors.Is(err, errDial) {
		t.Fatalf("Take: %v", err)
	}
	if time.Since(start) > 200*time.Millisecond {
		t.Fatal("a cancelled caller waited for the dial")
	}
}

// fakeClient is a connection that only counts its Close.
type fakeClient struct {
	valkey.Client
	closed atomic.Bool
}

func (f *fakeClient) Close() { f.closed.Store(true) }

// A Close that arrives while a dial is in flight must not leave the new connection
// behind (the generation check the hand-written code had, now the loader's reset), and
// the Valkey dials again afterwards.
func TestValkeyCloseDuringADialDiscardsTheClient(t *testing.T) {
	release := make(chan struct{})
	var dials atomic.Int64
	first, second := &fakeClient{}, &fakeClient{}
	v := NewValkey(ValkeyConfig{Addr: "203.0.113.1:6379"})
	v.newClient = func(valkey.ClientOption) (valkey.Client, error) {
		if dials.Add(1) == 1 {
			<-release
			return first, nil
		}
		return second, nil
	}
	got := make(chan error, 1)
	go func() {
		_, err := v.conn(context.Background())
		got <- err
	}()
	for dials.Load() == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	v.Close()
	close(release)
	if err := <-got; !errors.Is(err, errDial) {
		t.Fatalf("a caller whose dial Close overtook got %v", err)
	}
	for i := 0; i < 200 && !first.closed.Load(); i++ {
		time.Sleep(5 * time.Millisecond)
	}
	if !first.closed.Load() {
		t.Fatal("the connection dialled across a Close was kept")
	}
	c, err := v.conn(context.Background())
	if err != nil || c != valkey.Client(second) {
		t.Fatalf("after Close the next call must dial again: %v", err)
	}
	v.Close()
	if !second.closed.Load() {
		t.Error("Close did not close the live client")
	}
}

// TestValkeyIndexListsTheKeysAServiceWritesAndUnlockDeletesThem is admin-r7-6: `ctrlz-admin unlock`
// must clear the admin's buckets without SCAN, which an ACL user cannot be kept from using on other
// services' keys. The scripts keep a sorted set of the keys they write, ResetIndexed deletes exactly
// those keys, and a service with no index (the api) writes none.
func TestValkeyIndexListsTheKeysAServiceWritesAndUnlockDeletesThem(t *testing.T) {
	needValkey(t)
	ctx := context.Background()
	idx := "ctrlz:rl:admin:index-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	v := NewValkey(ValkeyConfig{Addr: server.Addr, IndexKey: idx})
	t.Cleanup(v.Close)
	l := New(Config{Service: Admin, Backend: v, Timeout: callTimeout})
	c, ok := Lookup(Admin, "admin-login")
	if !ok {
		t.Fatal("no class admin-login")
	}
	s := uniq(t)
	for i := 0; i < 6; i++ {
		if _, err := l.Allow(ctx, c, s); err != nil {
			t.Fatal(err)
		}
	}
	l.Refund(ctx, c, s)

	raw, err := valkey.NewClient(valkey.ClientOption{InitAddress: []string{server.Addr}, DisableCache: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(raw.Close)
	members, err := raw.Do(ctx, raw.B().Zrange().Key(idx).Min("0").Max("-1").Build()).AsStrSlice()
	if err != nil || len(members) != 1 { // an IPv4-style subject has the network bucket alone
		t.Fatalf("the index holds %v (%v), want the one key the limiter wrote", members, err)
	}
	for _, k := range members {
		if n, err := raw.Do(ctx, raw.B().Exists().Key(k).Build()).AsInt64(); err != nil || n != 1 {
			t.Fatalf("the index names %q and the key is not there", k)
		}
	}

	n, err := v.ResetIndexed(ctx)
	if err != nil || n != len(members) {
		t.Fatalf("ResetIndexed removed %d (%v), want %d", n, err, len(members))
	}
	for _, k := range members {
		if e, _ := raw.Do(ctx, raw.B().Exists().Key(k).Build()).AsInt64(); e != 0 {
			t.Errorf("%q survived the reset", k)
		}
	}
	if left, _ := raw.Do(ctx, raw.B().Zcard().Key(idx).Build()).AsInt64(); left != 0 {
		t.Errorf("%d members left in the index", left)
	}
	// The bucket is fresh again.
	for i := 0; i < 5; i++ {
		if d, err := l.Allow(ctx, c, s); err != nil || !d.Allowed {
			t.Fatalf("request %d after the reset: %+v %v", i, d, err)
		}
	}

	// A service with no index keeps none, and cannot reset one it does not have.
	plain := NewValkey(ValkeyConfig{Addr: server.Addr})
	t.Cleanup(plain.Close)
	if _, err := plain.ResetIndexed(ctx); err == nil {
		t.Error("ResetIndexed with no IndexKey did not fail")
	}
}

// An index entry follows its key: once the key has expired the next write trims the member, so the
// index holds the live keys and does not grow with every network that ever sent a request.
func TestValkeyIndexTrimsExpiredKeys(t *testing.T) {
	needValkey(t)
	ctx := context.Background()
	idx := "ctrlz:rl:admin:index-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	v := NewValkey(ValkeyConfig{Addr: server.Addr, IndexKey: idx})
	t.Cleanup(v.Close)
	short := []slot{{key: "ctrlz:rl:admin:trim-a-" + idx, max: 5, per: 50 * time.Millisecond}}
	if _, _, err := v.Take(ctx, short); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond) // the key lives 2 x 50 ms
	other := []slot{{key: "ctrlz:rl:admin:trim-b-" + idx, max: 5, per: time.Minute}}
	if _, _, err := v.Take(ctx, other); err != nil {
		t.Fatal(err)
	}
	raw, err := valkey.NewClient(valkey.ClientOption{InitAddress: []string{server.Addr}, DisableCache: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(raw.Close)
	members, err := raw.Do(ctx, raw.B().Zrange().Key(idx).Min("0").Max("-1").Build()).AsStrSlice()
	if err != nil || len(members) != 1 || members[0] != other[0].key {
		t.Fatalf("the index holds %v (%v), want only the live key", members, err)
	}
	if ttl, _ := raw.Do(ctx, raw.B().Pttl().Key(idx).Build()).AsInt64(); ttl <= 0 {
		t.Errorf("the index has no expiry (%d): an idle service would keep it for ever", ttl)
	}
}

// TestValkeyScriptsRefuseACallTheLimiterWouldNeverSend is admin-r14-4: both service users may EVALSHA, so
// the scripts themselves bound a call. Each shape below is answered with an error and leaves no key
// behind, for take.lua and give.lua alike: too many keys, arguments that do not match the keys, a
// capacity or a period outside the range of the Go classes, a value that is not an integer, and a call
// with no slot.
func TestValkeyScriptsRefuseACallTheLimiterWouldNeverSend(t *testing.T) {
	v := needValkey(t)
	ctx := context.Background()
	c, err := v.conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	pre := "ctrlz:rl:probe:" + strconv.FormatInt(time.Now().UnixNano(), 10) + ":"
	keysOf := func(n int) (keys, argv []string) {
		for i := 0; i < n; i++ {
			keys = append(keys, pre+strconv.Itoa(i))
			argv = append(argv, "5", "60000")
		}
		return keys, argv
	}
	many, manyArgs := keysOf(1000)
	one, oneArgs := keysOf(1)
	nine, nineArgs := keysOf(scriptMaxSlots + 1)
	cases := []struct {
		name       string
		keys, argv []string
	}{
		{"a thousand keys", many, manyArgs},
		{"one key over the bound", nine, nineArgs},
		{"a huge period", one, []string{"5", strconv.FormatInt(scriptMaxPerMs+1, 10)}},
		{"a period that never ends", one, []string{"5", "99999999999999999"}},
		{"a huge capacity", one, []string{strconv.Itoa(scriptMaxCap + 1), "60000"}},
		{"a zero period", one, []string{"5", "0"}},
		{"a zero capacity", one, []string{"0", "60000"}},
		{"a fraction", one, []string{"2.5", "60000"}},
		{"not a number", one, []string{"five", "60000"}},
		{"not a finite number", one, []string{"5", "inf"}},
		{"nan", one, []string{"nan", "60000"}},
		{"too few arguments", nine[:3], nineArgs[:2]},
		{"too many arguments", one, append(append([]string{}, oneArgs...), "5", "60000")},
		{"no keys", nil, nil},
		{"only an index", []string{pre + "index"}, nil},
	}
	for _, sc := range []script{v.take, v.give} {
		for _, tc := range cases {
			err := sc.run(ctx, c, tc.keys, tc.argv).Error()
			if err == nil {
				t.Errorf("%s: %.8s accepted the call", tc.name, sc.sha)
			}
		}
	}
	for _, k := range append(append([]string{}, many...), pre+"index") {
		if n, _ := c.Do(ctx, c.B().Exists().Key(k).Build()).AsInt64(); n != 0 {
			t.Fatalf("a refused call left the key %q behind", k)
		}
	}
	// The bound is the limit and not one below it: a call with every slot the bound allows, an index, and the
	// largest capacity and period goes through.
	full, fullArgs := keysOf(scriptMaxSlots)
	for i := range fullArgs {
		if i%2 == 0 {
			fullArgs[i] = strconv.Itoa(scriptMaxCap)
		} else {
			fullArgs[i] = strconv.FormatInt(scriptMaxPerMs, 10)
		}
	}
	if err := v.take.run(ctx, c, append(append([]string{}, full...), pre+"index"), fullArgs).Error(); err != nil {
		t.Errorf("a call at the bound was refused: %v", err)
	}
	c.Do(ctx, c.B().Del().Key(append(full, pre+"index")...).Build())
}
