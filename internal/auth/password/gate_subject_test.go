package password

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// Round 7, tenant-r7-6: one account holds one hash in the proved lane at a time, whatever number of
// sessions it has, so a proved flood from one account cannot keep strangers out.

func TestAnAccountHasOneHashInTheLaneAtATime(t *testing.T) {
	g := NewGate(2, 5*time.Second)
	ctx := ProvedAs(context.Background(), "user-a")
	first, err := g.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// A second hash of the same account is refused at once, with a free slot to spare.
	start := time.Now()
	if _, err := g.Acquire(ProvedAs(context.Background(), "user-a")); !errors.Is(err, ErrBusy) {
		t.Fatalf("a second hash of one account: %v, want ErrBusy", err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("the refusal waited instead of coming at once")
	}
	// Another account and a stranger are served by the slot that is left.
	other, err := g.Acquire(ProvedAs(context.Background(), "user-b"))
	if err != nil {
		t.Fatalf("another account: %v", err)
	}
	other()
	stranger, err := g.Acquire(context.Background())
	if err != nil {
		t.Fatalf("a stranger with a slot free: %v", err)
	}
	stranger()
	first()
	// Released: the account may hash again.
	again, err := g.Acquire(ProvedAs(context.Background(), "user-a"))
	if err != nil {
		t.Fatalf("after the release: %v", err)
	}
	again()
	if len(g.inflight) != 0 || g.free != g.size {
		t.Errorf("%d subjects marked and %d of %d slots free after everyone left", len(g.inflight), g.free, g.size)
	}
}

// A request that gives up while it waits must not keep its account marked, or one timeout would lock the
// account out of the lane for ever.
func TestAGivenUpWaitReleasesTheSubject(t *testing.T) {
	g := NewGate(1, 30*time.Millisecond)
	hold, _ := g.Acquire(context.Background())
	if _, err := g.Acquire(ProvedAs(context.Background(), "user-a")); !errors.Is(err, ErrBusy) {
		t.Fatalf("a wait that ran out: %v, want ErrBusy", err)
	}
	ctx, cancel := context.WithCancel(ProvedAs(context.Background(), "user-a"))
	cancel()
	if _, err := g.Acquire(ctx); err == nil {
		t.Fatal("a cancelled request got a slot")
	}
	hold()
	rel, err := g.Acquire(ProvedAs(context.Background(), "user-a"))
	if err != nil {
		t.Fatalf("the account is still marked after its waits ended: %v", err)
	}
	rel()
	if len(g.inflight) != 0 {
		t.Errorf("%d subjects still marked", len(g.inflight))
	}
}

// The flood the finding describes, at the gate: three hundred sessions of one account hash in a loop
// and each is proved. A stranger who arrives meanwhile must be served within the wait, and the flood
// never holds more than one slot.
func TestAProvedFloodFromOneAccountCannotKeepStrangersOut(t *testing.T) {
	g := NewGate(2, 2*time.Second)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	var most, running int
	var mu sync.Mutex
	for i := 0; i < 300; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				rel, err := g.Acquire(ProvedAs(context.Background(), "the-flooder"))
				if err != nil {
					time.Sleep(time.Millisecond)
					continue
				}
				mu.Lock()
				running++
				most = max(most, running)
				mu.Unlock()
				time.Sleep(2 * time.Millisecond) // an Argon2 run
				mu.Lock()
				running--
				mu.Unlock()
				rel()
			}
		}()
	}
	time.Sleep(50 * time.Millisecond)
	for i := 0; i < 20; i++ {
		start := time.Now()
		rel, err := g.Acquire(context.Background())
		if err != nil {
			t.Errorf("stranger %d: %v after %v, with a flood of one account running", i, err, time.Since(start))
			continue
		}
		rel()
	}
	close(stop)
	wg.Wait()
	if most != 1 {
		t.Errorf("one account held %d slots at once, want 1", most)
	}
}
