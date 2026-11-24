package smssend_test

import (
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/worker/smssend"
)

// Review round 9 of the SMS layer and the worker loops.

// killWorkerConnections ends every backend of the worker role, as a Postgres restart or a failover
// does to a pool: the connections the worker holds are dead and its next transaction meets that.
func (r *rig) killWorkerConnections() {
	r.t.Helper()
	r.env.Exec(r.t, `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = 'ctrlz_worker' AND pid <> pg_backend_pid()`)
	for range 100 {
		if r.count(`SELECT count(*) FROM pg_stat_activity WHERE usename = 'ctrlz_worker'`) == 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	r.t.Fatal("the worker's backends did not end")
}

// A connection lost between the provider's accept and the record is retried, and the code is not sent
// again (sms-r9-5). The record used to be one attempt: Store.run runs its function once, so one dead
// pooled connection left the code sealed, the claim lapsed, the next claim sent the same code a second
// time and the price never reached the money counter. The kill happens in BeforeRecord, which runs
// after the accept and before the transaction.
func TestAConnectionLostBetweenAcceptAndRecordIsRetriedAndTheCodeGoesOnce(t *testing.T) {
	r := newRig(t)
	var killed atomic.Int32
	hook := func() {
		if killed.Add(1) == 1 {
			r.killWorkerConnections()
		}
	}
	w, err := smssend.New(smssend.Config{Store: r.worker, Router: r.router, Keys: r.ring, Log: slog.New(slog.NewJSONHandler(r.logs, &slog.HandlerOptions{Level: slog.LevelDebug})), BeforeRecord: hook, RecordRetryPause: 10 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	ch := r.request(r.env.A.Phone)
	if _, err := w.Drain(r.env.Ctx); err != nil {
		t.Fatal(err)
	}
	if killed.Load() != 1 {
		t.Fatalf("the hook ran %d times: the test did not reach the record", killed.Load())
	}
	if r.deliveryCT(ch.ID) {
		t.Fatal("the record of an accepted send was lost to one dead connection: the code is still sealed")
	}
	// Another pass must find nothing to send: a lapsed claim is where the duplicate came from.
	r.lapse()
	if _, err := w.Drain(r.env.Ctx); err != nil {
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

// The same for the outbox: an invite accepted by the gateway whose record meets a dead connection is
// recorded by the retry, so it is not sent again and its price is counted once.
func TestAnInviteAcceptedBeforeALostConnectionIsRecordedByTheRetry(t *testing.T) {
	r := newRig(t)
	var killed atomic.Int32
	hook := func() {
		if killed.Add(1) == 1 {
			r.killWorkerConnections()
		}
	}
	w, err := smssend.New(smssend.Config{Store: r.worker, Router: r.router, Keys: r.ring, Log: slog.New(slog.NewJSONHandler(r.logs, &slog.HandlerOptions{Level: slog.LevelDebug})), BeforeRecord: hook, RecordRetryPause: 10 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	id := r.queue("invite", "invite", "+989121112233", uuid.Nil, "ABCDEFGHJKMNPQRSTVWX")
	if _, err := w.Drain(r.env.Ctx); err != nil {
		t.Fatal(err)
	}
	if state, _, params := r.outbox(id); state != "sent" || params {
		t.Fatalf("state %s, params kept %v: the record was lost", state, params)
	}
	r.lapse()
	if _, err := w.Drain(r.env.Ctx); err != nil {
		t.Fatal(err)
	}
	if n := r.pri.count(); n != 1 {
		t.Errorf("the provider got the invite %d times", n)
	}
	if r.cost() != 10 {
		t.Errorf("money counter %v, want 10", r.cost())
	}
}
