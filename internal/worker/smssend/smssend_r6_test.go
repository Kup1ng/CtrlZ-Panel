package smssend_test

import (
	"io"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/sms"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms/classify"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
	"github.com/Kup1ng/CtrlZ-Panel/internal/worker/smssend"
)

// Review round 6 of the SMS layer and the worker loops.

// A gateway that accepted a code is recorded even when the counter row every issue locks is
// busy for longer than the old 3 second deadline of the record. The record that timed out left
// the code sealed, the claim lapsed and the next claim sent the same code again: billed twice
// and never added to the money counter, and the third claim then refunded a delivered code
// (sms-r6-6).
func TestAnAcceptedSendIsRecordedThroughALongWaitOnTheGlobalCounterRow(t *testing.T) {
	r := newRig(t)
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))
	const hold = 4 * time.Second
	held := make(chan error, 1)
	r.ensureGlobalRow() // the row the holder locks (a shard of the count is not necessarily this one)
	// The hook runs after the accept and before the record. It starts a transaction that
	// locks the global row for longer than the old budget, and waits until it has it.
	hook := func() {
		go func() {
			held <- r.env.DB.Exec(r.env.Ctx, `WITH l AS (SELECT 1 FROM ctrlz.sms_counters WHERE scope = 'global' AND key = 'all'
			  AND day = (now() AT TIME ZONE 'Asia/Tehran')::date FOR UPDATE) SELECT pg_sleep($1) FROM l`, hold.Seconds())
		}()
		// The holder has the row once its statement is inside pg_sleep, which is the condition, not a time.
		if err := r.env.AwaitSleepers(1); err != nil {
			t.Error(err)
		}
	}
	w, err := smssend.New(smssend.Config{Store: r.worker, Router: r.router, Keys: r.ring, Log: log, BeforeRecord: hook})
	if err != nil {
		t.Fatal(err)
	}
	ch := r.request(r.env.A.Phone)
	start := time.Now()
	if _, err := w.Drain(r.env.Ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-held; err != nil {
		t.Fatal(err)
	}
	if waited := time.Since(start); waited < 3500*time.Millisecond {
		t.Fatalf("the drain took %v: the record never waited for the counter row", waited)
	}
	if r.deliveryCT(ch.ID) {
		t.Error("the accepted code stayed sealed: the next claim would send it again")
	}
	if n := r.count(`SELECT count(*) FROM ctrlz.sms_deliveries WHERE source_id = $1 AND outcome = 'accepted'`, ch.ID); n != 1 {
		t.Errorf("%d delivery rows for the accepted code, want 1", n)
	}
	if r.cost() != 10 {
		t.Errorf("cost %v, want the one message charged", r.cost())
	}
	r.lapse()
	r.drain()
	if r.pri.count() != 1 {
		t.Errorf("%d provider calls, want 1: the code was sent again", r.pri.count())
	}
}

// A send has a budget of its own that is shorter than the lease of the claim, wait for the
// gateway snapshot included, so the claim outlasts the send it was taken for (sms-r6-7). A
// gateway that hangs is cut at the budget: what was attempted is recorded, the one cut off is
// a call it could not finish is not started, and nothing is sent after the budget (sms-r8-5).
func TestASendThatHangsIsCutBeforeItsClaimLapses(t *testing.T) {
	r := newRig(t)
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	r.pri.reply = func(_ int, w http.ResponseWriter) {
		select {
		case <-release:
		case <-time.After(10 * time.Second):
		}
		http500(w)
	}
	// A call timeout of 2 s stands for the drivers' 6 s: the send budget of 3.5 s fits one call
	// and not two, as 14 s fits two calls of 6 s plus a second of slack and not three. The figures were
	// 450 ms and 700 ms until round 13: that left 150 ms for the snapshot load and the claim before the
	// first call, and on a loaded machine the call was not started (it needs its timeout plus the
	// router's slack), so 0 failures were counted. Now the first call has 1.4 s to start in.
	router := sms.NewRouter(r.src, classify.Routing{}, sms.WithCallTimeout(2*time.Second))
	w, err := smssend.New(smssend.Config{Store: r.worker, Router: router, Keys: r.ring, Log: log, SendBudget: 3500 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	ch := r.request(r.env.A.Phone)
	start := time.Now()
	if _, err := w.Drain(r.env.Ctx); err != nil {
		t.Fatal(err)
	}
	if took := time.Since(start); took > 10*time.Second {
		t.Errorf("the send took %v with a budget of 3.5 s", took)
	}
	if r.fb.count() != 0 {
		t.Errorf("the fallback was called %d times after the budget could not finish another call", r.fb.count())
	}
	if !r.deliveryCT(ch.ID) {
		t.Error("the row was ended: a send the budget stopped must leave it for the next claim")
	}
	// The primary was asked, hung for its whole call and timed out: that is the gateway's verdict
	// and counts toward its breaker, as it would with the 6 second client timeout. Before sms-r8-5
	// a hanging primary cut by the budget was dropped and never counted, so a gateway that hung on
	// every send never opened its breaker.
	if n := r.count(`SELECT COALESCE(sum(consecutive_failures), 0) FROM ctrlz.sms_gateways WHERE id = $1`, r.priID); n != 1 {
		t.Errorf("a primary that hung for its whole call counted %d failures, want 1", n)
	}
	if n := r.count(`SELECT COALESCE(sum(consecutive_failures), 0) FROM ctrlz.sms_gateways WHERE id <> $1`, r.priID); n != 0 {
		t.Errorf("the fallback, which was not asked, counted %d failures", n)
	}
	if n := r.count(`SELECT delivery_attempts FROM ctrlz.otp_challenges WHERE id = $1`, ch.ID); n != 1 {
		t.Errorf("attempts %d, want the one claim", n)
	}
}

// The budget is checked against the claim: a worker whose send could outlast its lease is not
// built (sms-r6-7).
func TestTheSendBudgetMustBeShorterThanTheClaim(t *testing.T) {
	r := newRig(t)
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))
	_, err := smssend.New(smssend.Config{Store: r.worker, Router: r.router, Keys: r.ring, Log: log, SendBudget: store.OTPClaimLease})
	if err == nil {
		t.Error("a send budget as long as the claim lease was accepted")
	}
	if smssend.DefaultSendBudget >= store.OTPClaimLease {
		t.Errorf("the default budget %v is not below the lease %v", smssend.DefaultSendBudget, store.OTPClaimLease)
	}
}
