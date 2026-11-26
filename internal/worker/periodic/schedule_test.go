package periodic

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

// leaseLog is the lease table as attempt sees it: every request is kept, and a request can be refused.
type leaseLog struct {
	mu     sync.Mutex
	secs   []int
	refuse bool // the next renewals find another holder
	alerts int
}

func (l *leaseLog) take(_ context.Context, _ string, secs int) (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.secs = append(l.secs, secs)
	return !(l.refuse && len(l.secs) > 1), nil
}

func (l *leaseLog) raise(context.Context, Job) {
	l.mu.Lock()
	l.alerts++
	l.mu.Unlock()
}

func scheduleRunner(l *leaseLog) *Runner {
	return &Runner{log: slog.New(slog.NewJSONHandler(io.Discard, nil)), doneDay: map[Job]string{}, ddnsStart: map[uuid.UUID]int{},
		lease: l.take, alert: l.raise}
}

// J12-r3-1: a daily job holds a lease of twice its period while it runs, renewed, and the lease to the end of the UTC day only
// after it returned cleanly. A worker that dies in the middle of a run therefore leaves a lease of minutes, not of the day.
func TestADailyJobHoldsAShortRenewedLeaseWhileItRunsAndTheDayAfterItSucceeded(t *testing.T) {
	l := &leaseLog{}
	r := scheduleRunner(l)
	var during []int
	s := spec{job: JobRules, every: time.Second, budget: 10 * time.Second, daily: true, run: func(ctx context.Context) error {
		time.Sleep(1300 * time.Millisecond) // two renewals, at half a period
		l.mu.Lock()
		during = append(during, l.secs...)
		l.mu.Unlock()
		return nil
	}}
	r.attempt(context.Background(), s)

	if len(during) < 3 {
		t.Fatalf("lease requests while the job ran: %v, want the first and at least two renewals", during)
	}
	for _, secs := range during {
		if secs != 2 {
			t.Fatalf("a lease of %d s while the job ran, want twice the period (2 s): a crash would lock the job out for that long", secs)
		}
	}
	if len(l.secs) != len(during)+1 || l.secs[len(l.secs)-1] <= 2 {
		t.Fatalf("lease requests %v: the last one, after the clean return, must reach the end of the day", l.secs)
	}
	if r.doneDay[JobRules] == "" {
		t.Error("a job that returned cleanly was not marked done for the day")
	}
}

// A daily job that failed holds nothing but its short lease and is not done for the day, so the next tick or another worker
// runs it again, and the failure alerts.
func TestAFailedDailyJobLeavesOnlyItsShortLeaseAndAlerts(t *testing.T) {
	l := &leaseLog{}
	r := scheduleRunner(l)
	s := spec{job: JobRules, every: time.Second, budget: time.Second, daily: true, run: func(context.Context) error { return errors.New("the run failed") }}
	r.attempt(context.Background(), s)

	if len(l.secs) != 1 || l.secs[0] != 2 {
		t.Fatalf("lease requests %v, want the one short lease of a failed run", l.secs)
	}
	if r.doneDay[JobRules] != "" {
		t.Error("a failed job was marked done for the day")
	}
	if l.alerts != 1 {
		t.Errorf("%d alerts, want 1", l.alerts)
	}
}

// A renewal that finds the lease taken by another worker ends the run.
func TestADailyJobStopsWhenItsLeaseIsTaken(t *testing.T) {
	l := &leaseLog{refuse: true}
	r := scheduleRunner(l)
	stopped := make(chan struct{})
	s := spec{job: JobRules, every: 100 * time.Millisecond, budget: 10 * time.Second, daily: true, run: func(ctx context.Context) error {
		select {
		case <-ctx.Done():
			close(stopped)
			return ctx.Err()
		case <-time.After(5 * time.Second):
			return nil
		}
	}}
	r.attempt(context.Background(), s)
	select {
	case <-stopped:
	default:
		t.Fatal("the run went on after its lease was lost")
	}
}

// J12-r3-5: a walk the pass ran out of time in does not count the tenant it was cut off in as done, and says nothing failed.
func TestAPassOutOfTimeIsNotAFailureAndHasRoomOnlyForAWholeTenant(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if hasRoom(ctx, 6*time.Second) {
		t.Error("a pass with 5 s left has room for a tenant that needs 6")
	}
	if !hasRoom(ctx, time.Second) {
		t.Error("a pass with 5 s left has no room for a tenant that needs 1")
	}
	if !hasRoom(context.Background(), time.Hour) {
		t.Error("a context with no deadline has no room")
	}
}
