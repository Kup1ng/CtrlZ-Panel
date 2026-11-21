package smssend_test

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/sms"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms/classify"
	"github.com/Kup1ng/CtrlZ-Panel/internal/worker/smssend"
)

// Review round 8 of the SMS layer and the worker loops.

// An accepted send whose record ran out of its own budget is logged (sms-r8-1). The record that
// fails by timing out is the failure the detached context exists to prevent, and the log line
// was suppressed by a check of that same context, so a duplicate-send burst after a deploy left
// nothing to trace. The stop arrives while the record waits on the global counter row, which
// shortens the record to the shutdown budget; it fails; the line must be there, with a closed
// class and no code, phone or id of a gateway.
func TestARecordOfAnAcceptedSendThatTimesOutIsLogged(t *testing.T) {
	r := newRig(t)
	log := slog.New(slog.NewJSONHandler(r.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx, stop := context.WithCancel(r.env.Ctx)
	defer stop()
	hctx, release := context.WithCancel(r.env.Ctx)
	defer release()
	held := make(chan error, 1)
	hook := func() {
		go func() {
			held <- r.env.DB.Exec(hctx, `WITH l AS (SELECT 1 FROM ctrlz.sms_counters WHERE scope = 'global' AND key = 'all'
			  AND day = (now() AT TIME ZONE 'Asia/Tehran')::date FOR UPDATE) SELECT pg_sleep(30) FROM l`)
		}()
		if err := r.env.AwaitSleepers(1); err != nil {
			t.Error(err)
		}
		// The stop arrives once the record is parked on the row.
		go func() {
			if err := r.env.AwaitLockWaiters(1); err != nil {
				t.Error(err)
			}
			stop()
		}()
	}
	w, err := smssend.New(smssend.Config{Store: r.worker, Router: r.router, Keys: r.ring, Log: log, BeforeRecord: hook})
	if err != nil {
		t.Fatal(err)
	}
	ch := r.request(r.env.A.Phone)
	if _, err := w.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	release()
	<-held
	if !r.deliveryCT(ch.ID) {
		t.Fatal("the record that was cut left the code cleared: the setup did not make the record fail")
	}
	out := r.logs.String()
	if !strings.Contains(out, "sms accepted send was not recorded") {
		t.Fatalf("an accepted send was not recorded and nothing was logged:\n%s", out)
	}
	if !strings.Contains(out, `"error_class":"timeout"`) && !strings.Contains(out, `"error_class":"connection"`) && !strings.Contains(out, `"error_class":"other"`) {
		t.Errorf("the line holds no closed error class:\n%s", out)
	}
}

// There is no wake-up (db-r15-1, db-r15-6): the worker polls its outbox, at the default interval of
// 500 ms when Config.Poll is left out, and never listens. It replaces the test of the notification
// (sms-r8-4), which proved a LISTEN connection woke a worker whose poll was an hour. The first drain
// at start is the poll-independent path and has its own test (TestRunDrainsWhatWaitedBeforeItStarted).
func TestRunPollsTheOutboxAndNeverListens(t *testing.T) {
	r := newRig(t)
	log := slog.New(slog.NewJSONHandler(r.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	w, err := smssend.New(smssend.Config{Store: r.worker, Router: r.router, Keys: r.ring, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(r.env.Ctx)
	// The worker has done its first drain and is waiting for the next tick; a request now can only
	// be found by the poll.
	done := r.startAndAwaitFirstDrain(ctx, w.Run)
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("Run did not stop")
		}
	}()

	ch := r.request(r.env.A.Phone)
	deadline := time.Now().Add(4 * time.Second)
	for r.deliveryCT(ch.ID) && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if r.deliveryCT(ch.ID) {
		t.Fatal("the worker did not find a new code within 4 seconds: the default poll is 500 ms")
	}
	if n := r.count(`SELECT count(*) FROM pg_stat_activity WHERE pid <> pg_backend_pid() AND (query ILIKE 'LISTEN%' OR query ILIKE '%pg_notify%')`); n != 0 {
		t.Errorf("%d sessions listen or notify: a stalled listener can fill the cluster's notification queue and fail every commit", n)
	}
}

// A claim that cannot give the send the time of one provider call sends nothing (sms-r8-5): the
// worker leaves the row, no gateway is asked, no gateway is blamed, and the log says the lease
// was spent. The router's call timeout is set above the budget to stand for a claim that waited
// long in its transaction.
func TestASendBudgetBelowOneCallSendsNothing(t *testing.T) {
	r := newRig(t)
	log := slog.New(slog.NewJSONHandler(r.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	router := sms.NewRouter(r.src, classify.Routing{}, sms.WithCallTimeout(smssend.DefaultSendBudget))
	w, err := smssend.New(smssend.Config{Store: r.worker, Router: router, Keys: r.ring, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	ch := r.request(r.env.A.Phone)
	if _, err := w.Drain(r.env.Ctx); err != nil {
		t.Fatal(err)
	}
	if r.pri.count()+r.fb.count() != 0 {
		t.Error("a gateway was called with a budget that cannot finish a call")
	}
	if !r.deliveryCT(ch.ID) {
		t.Error("the row was ended: a claim with no time to send leaves it for the next claim")
	}
	if n := r.count(`SELECT COALESCE(sum(consecutive_failures), 0) FROM ctrlz.sms_gateways`); n != 0 {
		t.Errorf("%d failures counted against a gateway that was not asked", n)
	}
	if !strings.Contains(r.logs.String(), "sms claim lease spent before the send") {
		t.Errorf("the worker did not say the lease was spent:\n%s", r.logs.String())
	}
}
