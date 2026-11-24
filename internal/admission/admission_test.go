package admission_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/admission"
)

func newAdm(t *testing.T, c admission.Config) *admission.Admission {
	t.Helper()
	if c.Dir == "" {
		c.Dir = t.TempDir()
	}
	a, err := admission.New(c)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// A tenant holds at most one place, and the process holds Places of them (6.5 property 1).
func TestAPlaceIsOnePerTenantAndTheProcessHasAFixedNumber(t *testing.T) {
	a := newAdm(t, admission.Config{Places: 3})
	rel, err := a.Place("t1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Place("t1"); !errors.Is(err, admission.ErrBusy) {
		t.Fatalf("a second place of one tenant: %v", err)
	}
	var rels []func()
	for _, n := range []string{"t2", "t3"} {
		r, err := a.Place(n)
		if err != nil {
			t.Fatal(err)
		}
		rels = append(rels, r)
	}
	if _, err := a.Place("t4"); !errors.Is(err, admission.ErrBusy) {
		t.Fatalf("a fourth place in a process of three: %v", err)
	}
	rel()
	rel() // twice is safe and frees nothing more
	if _, err := a.Place("t4"); err != nil {
		t.Fatalf("the place that was given back was not free: %v", err)
	}
	if places, _ := a.Held(); places != 3 {
		t.Fatalf("%d places held, want 3", places)
	}
	for _, r := range rels {
		r()
	}
}

func waitFor(t *testing.T, ok func() bool) {
	t.Helper()
	for i := 0; i < 400; i++ {
		if ok() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("the condition never held")
}

// The queue is first in first out and a large waiter is not passed by a small one that comes later (6.5 property 4).
func TestTheQueueIsFirstInFirstOutAndALargeWaiterIsNotPassed(t *testing.T) {
	a := newAdm(t, admission.Config{Pool: 48 << 20})
	ctx := context.Background()
	first, err := a.Acquire(ctx, 40<<20)
	if err != nil {
		t.Fatal(err)
	}
	type grant struct {
		name string
		rel  func()
	}
	got := make(chan grant, 2)
	var wg sync.WaitGroup
	start := func(name string, n int64) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rel, err := a.Acquire(ctx, n)
			if err != nil {
				t.Errorf("%s: %v", name, err)
				return
			}
			got <- grant{name, rel}
		}()
	}
	start("big", 48<<20)
	// The big one is queued before the small one is asked for, whatever the scheduler does with the goroutines.
	time.Sleep(50 * time.Millisecond)
	start("small", 1<<20)
	time.Sleep(50 * time.Millisecond)
	select {
	case g := <-got:
		t.Fatalf("%s was granted while the big waiter was still ahead of it", g.name)
	default:
	}
	first()
	g := <-got
	if g.name != "big" {
		t.Fatalf("%s went first", g.name)
	}
	g.rel()
	g = <-got
	if g.name != "small" {
		t.Fatalf("%s went second", g.name)
	}
	g.rel()
	wg.Wait()
	waitFor(t, func() bool { return a.Free() == 48<<20 })
}

// A request waits at most QueueWait and then is refused; a client that leaves leaves the queue and holds nothing (6.5
// property 4).
func TestTheQueueWaitEndsAndAClientThatLeavesLeavesTheQueue(t *testing.T) {
	a := newAdm(t, admission.Config{Pool: 1 << 20, QueueWait: 60 * time.Millisecond})
	hold, err := a.Acquire(context.Background(), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Acquire(context.Background(), 1<<20); !errors.Is(err, admission.ErrQueueWait) {
		t.Fatalf("a request that waited out the queue: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := a.Acquire(ctx, 1<<20); done <- err }()
	time.Sleep(10 * time.Millisecond)
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("a client that left: %v, want context.Canceled and not the queue wait", err)
	}
	hold()
	rel, err := a.Acquire(context.Background(), 1<<20)
	if err != nil {
		t.Fatalf("the weight of the request that left was not given back: %v", err)
	}
	rel()
	if _, err := a.Acquire(context.Background(), 2<<20); !errors.Is(err, admission.ErrWeight) {
		t.Fatalf("a weight above the pool: %v", err)
	}
}

// The api empties its spool directory when it starts, and keeps what it did not make (6.5 property 11).
func TestTheSpoolDirectoryIsEmptiedAtStart(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"spool-1234", "probe-77", "keep.txt"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := admission.New(admission.Config{Dir: dir}); err != nil {
		t.Fatal(err)
	}
	es, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(es) != 1 || es[0].Name() != "keep.txt" {
		t.Fatalf("the directory holds %v after the start, want keep.txt alone", es)
	}
}

// A directory that cannot be used stops the service at start and not at the first import.
func TestADirectoryThatCannotBeUsedStopsTheStart(t *testing.T) {
	file := filepath.Join(t.TempDir(), "afile")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := admission.New(admission.Config{Dir: file}); err == nil {
		t.Fatal("a file was taken for the spool directory")
	}
	if _, err := admission.New(admission.Config{Dir: filepath.Join(t.TempDir(), "missing")}); err == nil {
		t.Fatal("a directory that does not exist was taken for the spool directory")
	}
}
