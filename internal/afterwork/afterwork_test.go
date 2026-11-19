package afterwork_test

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/afterwork"
)

type ctxKey struct{}

// The work outlives the request: its context keeps the request's values and not its cancellation,
// and it still has a deadline of its own.
func TestWorkKeepsTheValuesAndLosesTheCancellation(t *testing.T) {
	q := afterwork.New(4, 2, time.Minute)
	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), ctxKey{}, "kept"))
	var got struct {
		val      any
		err      error
		deadline bool
	}
	ok := q.Go(ctx, func(c context.Context) {
		time.Sleep(20 * time.Millisecond) // the request ends first
		got.val, got.err = c.Value(ctxKey{}), c.Err()
		_, got.deadline = c.Deadline()
	})
	cancel()
	if !ok {
		t.Fatal("a task was refused by an empty queue")
	}
	q.Wait()
	if got.val != "kept" || got.err != nil || !got.deadline {
		t.Fatalf("value=%v err=%v deadline=%v", got.val, got.err, got.deadline)
	}
}

// A flood cannot grow the queue or hold the pool: past the pending bound a task is dropped and
// counted, and no more than the worker count runs at once.
func TestTheQueueIsBoundedAndDropsWhatDoesNotFit(t *testing.T) {
	const pending, workers = 6, 2
	q := afterwork.New(pending, workers, time.Minute)
	release := make(chan struct{})
	var running, peak, done atomic.Int64
	var mu sync.Mutex
	task := func(context.Context) {
		n := running.Add(1)
		mu.Lock()
		if n > peak.Load() {
			peak.Store(n)
		}
		mu.Unlock()
		<-release
		running.Add(-1)
		done.Add(1)
	}
	accepted := 0
	for i := 0; i < pending+10; i++ {
		if q.Go(context.Background(), task) {
			accepted++
		}
	}
	if accepted != pending {
		t.Fatalf("accepted %d tasks, want the bound %d", accepted, pending)
	}
	if q.Dropped() != 10 {
		t.Fatalf("dropped = %d, want 10", q.Dropped())
	}
	close(release)
	q.Wait()
	if done.Load() != pending {
		t.Fatalf("ran %d tasks, want %d", done.Load(), pending)
	}
	if peak.Load() > workers {
		t.Fatalf("%d tasks ran at once, the bound is %d", peak.Load(), workers)
	}
	// A slot is given back when a task ends.
	if !q.Go(context.Background(), func(context.Context) {}) {
		t.Fatal("a drained queue refused a task")
	}
	q.Wait()
}

type recorder struct{ n int }

func (r *recorder) Go(_ context.Context, fn func(context.Context)) bool {
	r.n++
	fn(context.Background())
	return true
}

// Owed hands its work over once, in order, and forgets it; a nil runner drops it instead of
// running it on the request.
func TestOwedRunsOnceAndAnEmptyRunnerDrops(t *testing.T) {
	var o afterwork.Owed
	var order []int
	o.Add(func(context.Context) { order = append(order, 1) })
	o.Add(func(context.Context) { order = append(order, 2) })
	r := &recorder{}
	o.Run(context.Background(), r)
	o.Run(context.Background(), r)
	if r.n != 2 || len(order) != 2 || order[0] != 1 || order[1] != 2 {
		t.Fatalf("runs=%d order=%v", r.n, order)
	}
	var p afterwork.Owed
	p.Add(func(context.Context) { t.Fatal("work ran on a nil runner") })
	p.Run(context.Background(), nil)
}

// A panic in a task costs that task and not the process: the goroutine is not covered by the
// pipeline's recover, and the queue keeps working with its slots given back (tenant-r14-2).
func TestAPanickingTaskLeavesTheQueueWorking(t *testing.T) {
	var buf lockedBuf
	q := afterwork.New(2, 1, time.Minute).WithLog(slog.New(slog.NewJSONHandler(&buf, nil)))
	for i := 0; i < 5; i++ { // more than the pending bound: each slot must come back
		if !q.Go(context.Background(), func(context.Context) { panic("secret-looking value 0912") }) {
			q.Wait()
			if !q.Go(context.Background(), func(context.Context) { panic("again") }) {
				t.Fatalf("slot %d was not given back after a panic", i)
			}
		}
	}
	q.Wait()
	var ran atomic.Bool
	if !q.Go(context.Background(), func(context.Context) { ran.Store(true) }) {
		t.Fatal("the queue refuses work after a panic")
	}
	q.Wait()
	if !ran.Load() {
		t.Fatal("a task after a panic did not run")
	}
	out := buf.String()
	if !strings.Contains(out, "panicked") || !strings.Contains(out, "panic_type") {
		t.Fatalf("no line for the panic: %s", out)
	}
	if strings.Contains(out, "secret-looking") || strings.Contains(out, "0912") {
		t.Fatalf("the panic value reached the log: %s", out)
	}
}

// A drop is said, once a minute, with the count; a shutdown says what is left.
func TestDropsAreReportedOncePerMinuteAndAtDrain(t *testing.T) {
	var buf lockedBuf
	now := time.Unix(1_000_000, 0)
	var mu sync.Mutex
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	q := afterwork.New(1, 1, time.Minute).WithLog(slog.New(slog.NewJSONHandler(&buf, nil))).WithClock(clock)
	release := make(chan struct{})
	if !q.Go(context.Background(), func(context.Context) { <-release }) {
		t.Fatal("first task refused")
	}
	count := func() int { return strings.Count(buf.String(), "dropped because the queue is full") }
	for i := 0; i < 5; i++ {
		q.Go(context.Background(), func(context.Context) {})
	}
	if count() != 1 {
		t.Fatalf("a burst of drops made %d warnings, want 1: %s", count(), buf.String())
	}
	mu.Lock()
	now = now.Add(30 * time.Second)
	mu.Unlock()
	q.Go(context.Background(), func(context.Context) {})
	if count() != 1 {
		t.Fatalf("a second warning inside the minute: %s", buf.String())
	}
	mu.Lock()
	now = now.Add(31 * time.Second)
	mu.Unlock()
	q.Go(context.Background(), func(context.Context) {})
	if count() != 2 || !strings.Contains(buf.String(), `"dropped":6`) {
		t.Fatalf("no second warning with the count of the minute: %s", buf.String())
	}
	// Drops since the last line are said at the drain, whatever the clock says.
	q.Go(context.Background(), func(context.Context) {})
	if q.Drain(20 * time.Millisecond) {
		t.Fatal("Drain reported done while a task still runs")
	}
	if count() != 3 {
		t.Fatalf("the drain did not report the pending drop: %s", buf.String())
	}
	close(release)
	if !q.Drain(time.Second) {
		t.Fatal("Drain did not see the task end")
	}
}

type lockedBuf struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}
func (l *lockedBuf) String() string { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }
