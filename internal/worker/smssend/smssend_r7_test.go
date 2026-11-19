package smssend_test

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/sms"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms/classify"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
	"github.com/Kup1ng/CtrlZ-Panel/internal/worker/smssend"
)

// Review round 7 of the SMS layer and the worker loops.

// The budget of a send is cut to what the claim has left when its transaction ends: the gate
// of an outbox message waits on the counter row another worker's claim holds, the lease the two
// claim statements stamped runs meanwhile, and a send that kept its full budget could end after
// another worker may claim the row and send the same code again (sms-r7-3, sms-r7-8).
func TestASendIsBoundedByWhatTheClaimHasLeftAfterAWaitInTheClaimTransaction(t *testing.T) {
	r := newRig(t)
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))
	var mu sync.Mutex
	var budgets []time.Duration
	w, err := smssend.New(smssend.Config{Store: r.worker, Router: r.router, Keys: r.ring, Log: log,
		OnSendBudget: func(d time.Duration) { mu.Lock(); budgets = append(budgets, d); mu.Unlock() }})
	if err != nil {
		t.Fatal(err)
	}
	ch := r.request(r.env.A.Phone)
	id := r.queue("invite", "invite", "+989121112233", uuid.Nil, "ABCDEFGHJKMNPQRSTVWX")

	// Another worker's claim transaction holds the outbox counter row for a while: the gate of
	// this claim waits on it after both leases were stamped.
	const hold = 3 * time.Second
	hctx, stop := context.WithCancel(r.env.Ctx)
	defer stop()
	held := make(chan error, 1)
	go func() {
		held <- r.env.DB.Exec(hctx, `WITH l AS (INSERT INTO ctrlz.sms_counters AS c (day, scope, key, count)
		  VALUES ((now() AT TIME ZONE 'Asia/Tehran')::date, 'global', 'outbox', 0)
		  ON CONFLICT (day, scope, key) DO UPDATE SET count = c.count RETURNING 1) SELECT pg_sleep($1) FROM l`, hold.Seconds())
	}()
	time.Sleep(500 * time.Millisecond)
	start := time.Now()
	if _, err := w.Drain(r.env.Ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-held; err != nil {
		t.Fatal(err)
	}
	if waited := time.Since(start); waited < 2*time.Second {
		t.Fatalf("the drain took %v: the claim never waited on the counter row", waited)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(budgets) != 2 {
		t.Fatalf("%d sends, want the code and the invite", len(budgets))
	}
	// The wait came out of the lease: whatever the budget was, it left the record its margin.
	most := smssend.DefaultSendBudget - 2*time.Second
	for _, b := range budgets {
		if b <= 0 || b > most {
			t.Errorf("a send got a budget of %v after a wait of about %v in the claim, want 0 < budget <= %v", b, hold, most)
		}
	}
	if r.deliveryCT(ch.ID) {
		t.Error("the code was not sent")
	}
	if state, _, _ := r.outbox(id); state != "sent" {
		t.Errorf("invite state %s", state)
	}
}

// A claim with less lease left than the margin sends nothing: the row waits for the next claim,
// and a send is never started that could run past the lease (sms-r7-8).
func TestNoSendStartsWhenTheClaimHasNoLeaseToSpare(t *testing.T) {
	for _, tc := range []struct {
		name         string
		budget, left time.Duration
		want         time.Duration
	}{
		{"a fresh claim keeps the configured budget", 14 * time.Second, 19900 * time.Millisecond, 13900 * time.Millisecond},
		{"a claim that waited keeps less", 14 * time.Second, 12 * time.Second, 6 * time.Second},
		{"exactly the margin is nothing", 14 * time.Second, smssend.LeaseMargin(), 0},
		{"less than the margin is nothing", 14 * time.Second, time.Second, 0},
		{"a short budget stays short", 700 * time.Millisecond, 19 * time.Second, 700 * time.Millisecond},
	} {
		if got := smssend.SendBudgetWithin(tc.budget, tc.left); tc.want > 0 && got != tc.want || tc.want <= 0 && got > 0 {
			t.Errorf("%s: budget %v with %v left gave %v, want %v", tc.name, tc.budget, tc.left, got, tc.want)
		}
	}
	if smssend.LeaseMargin() <= 0 || smssend.LeaseMargin() >= store.OTPClaimLease {
		t.Errorf("margin %v is not inside the lease %v", smssend.LeaseMargin(), store.OTPClaimLease)
	}
}

// The snapshot wait is inside the budget (spec 9.5): a source that never answers cuts the send
// at the budget, sends nothing and leaves the row for the next claim. A change that loads the
// snapshot before the budget starts would hold the send for the loader's own timeout and the
// claim would lapse under it (sms-r7-5).
func TestASendIsCutWhileItWaitsForTheGatewaySnapshot(t *testing.T) {
	r := newRig(t)
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	router := sms.NewRouter(blockingSource{release: release}, classify.Routing{}, sms.WithCallTimeout(450*time.Millisecond))
	w, err := smssend.New(smssend.Config{Store: r.worker, Router: router, Keys: r.ring, Log: log, SendBudget: 700 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	ch := r.request(r.env.A.Phone)
	start := time.Now()
	if _, err := w.Drain(r.env.Ctx); err != nil {
		t.Fatal(err)
	}
	if took := time.Since(start); took > 4*time.Second {
		t.Errorf("the drain took %v with a budget of 700 ms: the wait for the snapshot is outside the budget", took)
	}
	if !r.deliveryCT(ch.ID) {
		t.Error("the row was ended: a send cut off while it waited for the gateways must leave it for the next claim")
	}
	if r.pri.count()+r.fb.count() != 0 {
		t.Error("a gateway was called without a snapshot")
	}
	if n := r.count(`SELECT COALESCE(sum(consecutive_failures), 0) FROM ctrlz.sms_gateways`); n != 0 {
		t.Errorf("a wait for the snapshot counted %d failures against a gateway", n)
	}
}

// blockingSource is a gateway source whose load never answers until released.
type blockingSource struct{ release chan struct{} }

func (b blockingSource) Load(ctx context.Context) (sms.Snapshot, error) {
	select {
	case <-b.release:
	case <-ctx.Done():
	}
	return sms.Snapshot{}, ctx.Err()
}

// A stop that arrives while the record of an accepted send is already waiting shortens the
// record to the shutdown budget. The budget used to be chosen once, when the record started, so
// the process held the stop for the whole 40 seconds while the container is killed after its
// grace period, and the record (the cleared code, the delivery row, the cost) rolled back with
// it: the next worker sent the same code again (sms-r7-9).
func TestAStopShortensARecordThatIsAlreadyWaiting(t *testing.T) {
	r := newRig(t)
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))
	ctx, stop := context.WithCancel(r.env.Ctx)
	defer stop()
	hctx, release := context.WithCancel(r.env.Ctx)
	defer release()
	held := make(chan error, 1)
	// After the accept and before the record: lock the global row for much longer than the
	// shutdown budget, and tell the worker to stop a second into the record's wait.
	hook := func() {
		go func() {
			held <- r.env.DB.Exec(hctx, `WITH l AS (SELECT 1 FROM ctrlz.sms_counters WHERE scope = 'global' AND key = 'all'
			  AND day = (now() AT TIME ZONE 'Asia/Tehran')::date FOR UPDATE) SELECT pg_sleep(30) FROM l`)
		}()
		time.Sleep(400 * time.Millisecond)
		go func() { time.Sleep(time.Second); stop() }()
	}
	w, err := smssend.New(smssend.Config{Store: r.worker, Router: r.router, Keys: r.ring, Log: log, BeforeRecord: hook})
	if err != nil {
		t.Fatal(err)
	}
	ch := r.request(r.env.A.Phone)
	start := time.Now()
	if _, err := w.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	took := time.Since(start)
	release()
	<-held
	if took < 3*time.Second {
		t.Fatalf("the drain took %v: the record did not wait on the counter row", took)
	}
	if limit := smssend.ShutdownRecordBudget() + 4*time.Second; took > limit {
		t.Errorf("the drain took %v after a stop one second into the record, want about %v at most: the stop did not shorten the record", took, limit)
	}
	if !r.deliveryCT(ch.ID) {
		t.Error("the record that was cut left the code cleared: nothing would send it again")
	}
}
