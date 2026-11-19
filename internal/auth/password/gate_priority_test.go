package password

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Round 5, admin-r5-9: the gate serves a request that carries a proof before any stranger.

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

func queued(g *Gate) (proved, plain int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.proved), len(g.plain)
}

func TestGateServesAProvedWaiterBeforeAStranger(t *testing.T) {
	g := NewGate(1, 5*time.Second)
	hold, err := g.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	order := make(chan string, 2)
	var wg sync.WaitGroup
	acquire := func(name string, ctx context.Context) {
		defer wg.Done()
		rel, err := g.Acquire(ctx)
		if err != nil {
			order <- name + ":" + err.Error()
			return
		}
		order <- name
		rel()
	}
	// The stranger queues first, the proved request second.
	wg.Add(1)
	go acquire("stranger", context.Background())
	waitFor(t, "the stranger to queue", func() bool { _, p := queued(g); return p == 1 })
	wg.Add(1)
	go acquire("proved", Proved(context.Background()))
	waitFor(t, "the proved request to queue", func() bool { v, _ := queued(g); return v == 1 })

	hold()
	wg.Wait()
	if first, second := <-order, <-order; first != "proved" || second != "stranger" {
		t.Fatalf("served %s then %s, want the proved request first", first, second)
	}
	if g.free != g.size {
		t.Errorf("%d slots free of %d after everyone was served", g.free, g.size)
	}
}

// TestGateQueuesOneStrangerPerSlotWhileAProvedRequestWaits: while a proved request waits, the
// plain queue holds at most one waiter per slot (it is served on every plainEvery-th grant, so it
// is not a dead line) and the strangers beyond it are refused at once, without waiting out the
// gate's time.
func TestGateQueuesOneStrangerPerSlotWhileAProvedRequestWaits(t *testing.T) {
	g := NewGate(1, 5*time.Second)
	hold, _ := g.Acquire(context.Background())
	defer hold()
	ctx, cancel := context.WithCancel(Proved(context.Background()))
	done := make(chan error, 1)
	go func() {
		_, err := g.Acquire(ctx)
		done <- err
	}()
	waitFor(t, "the proved request to queue", func() bool { v, _ := queued(g); return v == 1 })
	sctx, scancel := context.WithCancel(context.Background())
	sdone := make(chan error, 1)
	go func() {
		_, err := g.Acquire(sctx)
		sdone <- err
	}()
	waitFor(t, "the first stranger to queue", func() bool { _, p := queued(g); return p == 1 })

	start := time.Now()
	if _, err := g.Acquire(context.Background()); !errors.Is(err, ErrBusy) {
		t.Fatalf("a second stranger while a proved request waits and the plain queue is full: %v, want ErrBusy", err)
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("the refusal took %v: it must not wait out the gate's time", d)
	}
	scancel()
	if err := <-sdone; !errors.Is(err, context.Canceled) {
		t.Fatalf("the stranger that left: %v", err)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("the proved waiter that left: %v", err)
	}
	if v, p := queued(g); v != 0 || p != 0 {
		t.Fatalf("waiters that left are still queued (%d proved, %d plain)", v, p)
	}
	// Without a proved request in the queue a stranger waits as before (the gate's own wait).
	short := NewGate(1, 30*time.Millisecond)
	rel, _ := short.Acquire(context.Background())
	defer rel()
	start = time.Now()
	if _, err := short.Acquire(context.Background()); !errors.Is(err, ErrBusy) || time.Since(start) < 20*time.Millisecond {
		t.Errorf("a stranger with no proved waiter did not wait its time: %v after %v", err, time.Since(start))
	}
}

// TestAFewAccountsCannotKeepEveryStrangerOut is primitives-r7-4. ProvedAs bounds one account to one
// hash in the lane, but accounts are not scarce either: as many accounts as the gate has slots keep
// the proved queue non-empty for ever, and a strict lane then refuses every request without a
// proof, in every tenant, for as long as they keep it up. Four accounts loop proved hashes against
// a gate of two; strangers must still be served (the lane yields on every plainEvery-th grant),
// and the proofs must still be served too.
func TestAFewAccountsCannotKeepEveryStrangerOut(t *testing.T) {
	g := NewGate(2, 2*time.Second)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	var provedServed atomic.Int64
	for i := 0; i < 4; i++ {
		account := string(rune('a' + i))
		for s := 0; s < 20; s++ { // many sessions of one account: ProvedAs keeps one hash in flight
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					select {
					case <-stop:
						return
					default:
					}
					rel, err := g.Acquire(ProvedAs(context.Background(), account))
					if err != nil {
						time.Sleep(time.Millisecond)
						continue
					}
					provedServed.Add(1)
					time.Sleep(3 * time.Millisecond) // an Argon2 run
					rel()
				}
			}()
		}
	}
	time.Sleep(50 * time.Millisecond)
	served, refused := 0, 0
	for i := 0; i < 30; i++ {
		if rel, err := g.Acquire(context.Background()); err == nil {
			served++
			rel()
		} else {
			refused++
		}
		time.Sleep(5 * time.Millisecond)
	}
	close(stop)
	wg.Wait()
	if served < 20 {
		t.Errorf("strangers were served %d of 30 times (refused %d) with four accounts holding the lane: it starves them", served, refused)
	}
	if provedServed.Load() < 50 {
		t.Errorf("the proofs were served %d times: the strangers must not push them out", provedServed.Load())
	}
}

// TestTheLaneYieldsOnEveryPlainEveryGrant fixes the arithmetic at the queue: with a proved lane that
// never empties, the plain waiter gets the slot after exactly plainEvery proved grants.
func TestTheLaneYieldsOnEveryPlainEveryGrant(t *testing.T) {
	g := NewGate(1, 5*time.Second)
	hold, _ := g.Acquire(context.Background())
	order := make(chan string, 16)
	var wg sync.WaitGroup
	enqueue := func(name string, ctx context.Context, wantProved, wantPlain int) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rel, err := g.Acquire(ctx)
			if err != nil {
				order <- name + ":" + err.Error()
				return
			}
			order <- name
			rel()
		}()
		waitFor(t, name+" to queue", func() bool { v, p := queued(g); return v == wantProved && p == wantPlain })
	}
	enqueue("stranger", context.Background(), 0, 1)
	for i := 0; i < plainEvery+2; i++ {
		enqueue("proved"+string(rune('0'+i)), Proved(context.Background()), i+1, 1)
	}
	hold()
	wg.Wait()
	close(order)
	var got []string
	for s := range order {
		got = append(got, s)
	}
	// plainEvery proved grants, then the stranger, then the rest of the proofs.
	for i, s := range got {
		want := "proved" + string(rune('0'+i))
		if i == plainEvery {
			want = "stranger"
		} else if i > plainEvery {
			want = "proved" + string(rune('0'+i-1))
		}
		if s != want {
			t.Fatalf("grant %d went to %s, want %s (order %v)", i, s, want, got)
		}
	}
}

// TestGateStaysConsistentWhenWaitersGiveUpAsTheSlotArrives races the timeout against the grant
// for both kinds of waiter: whatever happens, every slot is back in the pool at the end and the
// queues are empty.
func TestGateStaysConsistentWhenWaitersGiveUpAsTheSlotArrives(t *testing.T) {
	g := NewGate(2, 2*time.Millisecond)
	var wg sync.WaitGroup
	var got, refused atomic.Int64
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx := context.Background()
			if i%3 == 0 {
				ctx = Proved(ctx)
			}
			for j := 0; j < 40; j++ {
				rel, err := g.Acquire(ctx)
				if err != nil {
					refused.Add(1)
					continue
				}
				got.Add(1)
				time.Sleep(200 * time.Microsecond)
				rel()
			}
		}()
	}
	wg.Wait()
	if v, p := queued(g); v != 0 || p != 0 {
		t.Errorf("queues not empty at the end: %d proved, %d plain", v, p)
	}
	if g.free != g.size {
		t.Errorf("%d slots free of %d: a slot was lost or made twice (%d granted, %d refused)", g.free, g.size, got.Load(), refused.Load())
	}
	if got.Load() == 0 || refused.Load() == 0 {
		t.Errorf("the race did not run both ways (%d granted, %d refused)", got.Load(), refused.Load())
	}
}

// TestGateAProofIsServedWhileStrangersHammerIt is the scenario of the finding: strangers keep
// the one slot busy with unproved requests, and the owner's proved request still gets in.
func TestGateAProofIsServedWhileStrangersHammerIt(t *testing.T) {
	g := NewGate(1, 2*time.Second)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	var strangers atomic.Int64 // slots the strangers were handed
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if rel, err := g.Acquire(context.Background()); err == nil {
					strangers.Add(1)
					time.Sleep(5 * time.Millisecond) // a hash
					rel()
				}
			}
		}()
	}
	time.Sleep(20 * time.Millisecond)
	for i := 0; i < 20; i++ {
		before := strangers.Load()
		rel, err := g.Acquire(Proved(context.Background()))
		if err != nil {
			t.Fatalf("proved request %d refused with the gate hammered: %v", i, err)
		}
		// Counted in strangers served, not in time, so a loaded machine cannot flip it: a request
		// that waits its turn behind sixteen strangers lets about sixteen of them go first, and a
		// request with the lane lets none go first, or one that was handed the slot as it queued.
		if over := strangers.Load() - before; over > 3 {
			t.Errorf("proved request %d was served after %d strangers: it queued behind them", i, over)
		}
		time.Sleep(5 * time.Millisecond)
		rel()
	}
	close(stop)
	wg.Wait()
}
