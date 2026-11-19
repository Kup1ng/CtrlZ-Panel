package smssend_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
	"github.com/Kup1ng/CtrlZ-Panel/internal/worker/smssend"
)

// Review round 10 of the SMS layer and the worker loops (sms-r10-2).

// The loop of recordTx, run without a database. Round 9 tested it only by killing the worker's
// connections (ErrConnection), so removing the ErrRetry test, changing the number of runs or
// dropping the stop on the context passed the whole suite.

func TestRetryRecordRepeatsWhatARepeatCanCure(t *testing.T) {
	for name, cure := range map[string]error{
		"a lock timeout or deadlock (ErrRetry)": store.ErrRetry,
		"a lost connection (ErrConnection)":     store.ErrConnection,
		"ErrRetry wrapped":                      fmt.Errorf("record: %w", store.ErrRetry),
		"ErrConnection wrapped":                 fmt.Errorf("record: %w", store.ErrConnection),
	} {
		var runs int
		err := smssend.RetryRecord(context.Background(), time.Millisecond, func() error {
			runs++
			if runs < smssend.RecordTries() {
				return cure // fails on every run but the last allowed one
			}
			return nil
		})
		if err != nil || runs != smssend.RecordTries() {
			t.Errorf("%s: %d runs, err %v; the last allowed run must be reached and succeed", name, runs, err)
		}
	}
}

func TestRetryRecordDoesNotRepeatAnErrorNothingCures(t *testing.T) {
	for name, bad := range map[string]error{
		"a plain error": errors.New("boom"),
		"canceled":      context.Canceled,
		"deadline":      context.DeadlineExceeded,
	} {
		var runs int
		err := smssend.RetryRecord(context.Background(), time.Millisecond, func() error { runs++; return bad })
		if runs != 1 || !errors.Is(err, bad) {
			t.Errorf("%s: %d runs, err %v; want one run and the error as it came", name, runs, err)
		}
	}
}

func TestRetryRecordStopsAtTheNumberOfRunsAndReturnsTheLastError(t *testing.T) {
	var runs int
	err := smssend.RetryRecord(context.Background(), time.Millisecond, func() error {
		runs++
		if runs == smssend.RecordTries() {
			return fmt.Errorf("last: %w", store.ErrRetry)
		}
		return store.ErrConnection
	})
	if runs != smssend.RecordTries() {
		t.Errorf("%d runs, want %d", runs, smssend.RecordTries())
	}
	if !errors.Is(err, store.ErrRetry) || !strings.Contains(err.Error(), "last") {
		t.Errorf("the last run's error was not returned: %v", err)
	}
	// A retryable error followed by a different one ends the loop on the different one.
	runs = 0
	other := errors.New("other")
	err = smssend.RetryRecord(context.Background(), time.Millisecond, func() error {
		if runs++; runs == 2 {
			return other
		}
		return store.ErrRetry
	})
	if runs != 2 || !errors.Is(err, other) {
		t.Errorf("%d runs, err %v", runs, err)
	}
}

func TestRetryRecordPausesDoubleAndEndWithTheContext(t *testing.T) {
	// The pause doubles: 4 runs with a 20 ms first pause wait at least 20+40+80 ms.
	start := time.Now()
	_ = smssend.RetryRecord(context.Background(), 20*time.Millisecond, func() error { return store.ErrRetry })
	if d := time.Since(start); d < 130*time.Millisecond {
		t.Errorf("four runs took %v: the pauses do not double", d)
	}
	// A pause that is an hour long returns when the context ends, with the error of the run.
	ctx, cancel := context.WithCancel(context.Background())
	var runs atomic.Int32
	done := make(chan error, 1)
	go func() {
		done <- smssend.RetryRecord(ctx, time.Hour, func() error { runs.Add(1); return store.ErrRetry })
	}()
	for runs.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if runs.Load() != 1 || !errors.Is(err, store.ErrRetry) {
			t.Errorf("%d runs, err %v; the context ended in the first pause, so the first run's error comes back", runs.Load(), err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the loop kept waiting in its pause after the context ended")
	}
	// A context that is already over lets the first run happen (the record of an accepted send
	// runs on a detached context) and does not wait for a second.
	ctx2, cancel2 := context.WithCancel(context.Background())
	cancel2()
	runs.Store(0)
	start = time.Now()
	err := smssend.RetryRecord(ctx2, time.Hour, func() error { runs.Add(1); return store.ErrConnection })
	if runs.Load() != 1 || !errors.Is(err, store.ErrConnection) || time.Since(start) > 2*time.Second {
		t.Errorf("%d runs in %v, err %v", runs.Load(), time.Since(start), err)
	}
}

// A record that meets a lock timeout is retried and the code goes once. The worker role's lock_timeout
// is lowered for this database only, the global counter row is held by another session while the
// accepted code is recorded (the exact case of sms-r6-6 and sms-r9-5: every issue holds that row), and
// the row is released after the timeout has fired. Without the ErrRetry branch the record is one
// attempt: the code stays sealed, the claim lapses and the code is sent and billed a second time.
func TestARecordThatMeetsALockTimeoutIsRetriedAndTheCodeGoesOnce(t *testing.T) {
	r := newRig(t)
	ctx := r.env.Ctx
	// Per database, so the cluster's other tests keep the role's 10 seconds. New backends read it.
	r.env.Exec(t, `DO $$ BEGIN EXECUTE format('ALTER ROLE ctrlz_worker IN DATABASE %I SET lock_timeout = ''1s''', current_database()); END $$`)
	r.killWorkerConnections()
	for i := 0; ; i++ { // the pool still holds the dead connections: use them up
		err := r.worker.WithGlobal(ctx, store.TxOpts{}, func(store.GlobalTx) error { return nil })
		if err == nil {
			break
		}
		if i > 10 {
			t.Fatalf("the worker's pool did not recover: %v", err)
		}
	}

	holder, err := r.env.DB.Super(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close(ctx)
	released := make(chan struct{})
	var blockedFor atomic.Int64
	hook := func() {
		// After the accept and before the record: take the row, and let go 1.4 seconds after the
		// worker has started to wait for it, which is past the 1 second lock_timeout.
		if _, err := holder.Exec(ctx, `BEGIN`); err != nil {
			t.Errorf("begin: %v", err)
			close(released)
			return
		}
		if _, err := holder.Exec(ctx, `SELECT 1 FROM ctrlz.sms_counters WHERE scope = 'global' AND key = 'all' FOR UPDATE`); err != nil {
			t.Errorf("lock: %v", err)
			close(released)
			return
		}
		go func() {
			defer close(released)
			deadline := time.Now().Add(20 * time.Second)
			for time.Now().Before(deadline) {
				if r.count(`SELECT count(*) FROM pg_stat_activity WHERE usename = 'ctrlz_worker' AND wait_event_type = 'Lock'`) > 0 {
					break
				}
				time.Sleep(20 * time.Millisecond)
			}
			t0 := time.Now()
			time.Sleep(1400 * time.Millisecond)
			blockedFor.Store(int64(time.Since(t0)))
			if _, err := holder.Exec(ctx, `COMMIT`); err != nil {
				t.Errorf("commit: %v", err)
			}
		}()
	}
	w, err := smssend.New(smssend.Config{Store: r.worker, Router: r.router, Keys: r.ring, Log: slog.New(slog.NewJSONHandler(r.logs, &slog.HandlerOptions{Level: slog.LevelDebug})), BeforeRecord: hook, RecordRetryPause: 10 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	ch := r.request(r.env.A.Phone)
	if _, err := w.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	<-released
	if blockedFor.Load() == 0 {
		t.Fatal("the lock was never contended: the test did not reach the record")
	}
	if r.deliveryCT(ch.ID) {
		t.Fatal("the record of an accepted send was lost to one lock timeout: the code is still sealed")
	}
	r.lapse()
	if _, err := w.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	if n := r.pri.count(); n != 1 {
		t.Errorf("the provider got the code %d times", n)
	}
	if r.cost() != 10 {
		t.Errorf("the price of the accepted code is %v on the money counter, want 10", r.cost())
	}
	if n := r.count(`SELECT count(*) FROM ctrlz.sms_deliveries WHERE source = 'otp' AND source_id = $1 AND outcome = 'accepted'`, ch.ID); n != 1 {
		t.Errorf("%d delivery rows for the accepted code, want 1", n)
	}
	if strings.Contains(r.logs.String(), "sms accepted send was not recorded") {
		t.Errorf("the record succeeded on its retry and still logged a failure:\n%s", r.logs.String())
	}
}

// The number of runs is the spec's, not whatever the constant says: four runs, three retries with
// pauses of 100, 200 and 400 ms, which is under a second in all and well inside recordBudget. A test
// that reads the constant back would pass a change of it (sms-r10-2).
func TestARecordHasFourRunsAndItsPausesFitTheBudget(t *testing.T) {
	if smssend.RecordTries() != 4 {
		t.Fatalf("recordTries is %d; spec 9.5 says up to four runs", smssend.RecordTries())
	}
	if smssend.DefaultRecordRetryPause() != 100*time.Millisecond {
		t.Errorf("the first pause is %v, spec 9.5 says 100 ms", smssend.DefaultRecordRetryPause())
	}
	total := smssend.DefaultRecordRetryPause() * (1 + 2 + 4)
	if total >= store.RecordBudget/10 {
		t.Errorf("the pauses add up to %v, which is not small against the record budget %v", total, store.RecordBudget)
	}
}
