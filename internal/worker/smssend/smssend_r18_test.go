package smssend_test

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/safego"
	"github.com/Kup1ng/CtrlZ-Panel/internal/worker/smssend"
)

// Review round 18 of the SMS layer, fix gate (sms-r18-17): the failure behaviours of Worker.row that the
// first two tests of the round left to reading. Both of those panic in the afterSend hook, which runs
// before the record; these three panic after the record has committed and inside it.

// panicOn is a log handler that panics when a record carries the message, up to a budget of times: a
// panic at a place no hook of the rig reaches, with the log line as its trigger.
type panicOn struct {
	slog.Handler
	msg  string
	left *atomic.Int32
}

func (h panicOn) Handle(ctx context.Context, rec slog.Record) error {
	if rec.Message == h.msg && h.left.Add(-1) >= 0 {
		panic("canary-panic-value " + code)
	}
	return h.Handler.Handle(ctx, rec)
}
func (h panicOn) WithAttrs(a []slog.Attr) slog.Handler {
	return panicOn{Handler: h.Handler.WithAttrs(a), msg: h.msg, left: h.left}
}
func (h panicOn) WithGroup(n string) slog.Handler {
	return panicOn{Handler: h.Handler.WithGroup(n), msg: h.msg, left: h.left}
}

// panicWhenLogging replaces the worker of the rig with one whose logger panics on msg, n times.
func (r *rig) panicWhenLogging(msg string, n int32) {
	r.t.Helper()
	left := &atomic.Int32{}
	left.Store(n)
	h := panicOn{Handler: slog.NewJSONHandler(r.logs, &slog.HandlerOptions{Level: slog.LevelDebug}), msg: msg, left: left}
	w, err := smssend.New(smssend.Config{Store: r.worker, Router: r.router, Keys: r.ring, Log: slog.New(h)})
	if err != nil {
		r.t.Fatal(err)
	}
	r.w = w
}

// A panic after an accepted message was recorded as sent (the log line of afterRecord) must not end the
// row a second time or put it back: the ending of a panicked row is Won-gated, and an outbox message that
// is already `sent` stays so. Before the gate a revive (state back to pending) sent it again.
func TestAPanicAfterTheRecordOfAnOutboxRowDoesNotReviveIt(t *testing.T) {
	r := newRig(t)
	id := r.queue("test", "otp", "+989121112233", uuid.Nil, "ABCDEFGHJKMNPQRSTVWX")
	r.panicWhenLogging("sms sent", 1)
	if n := r.drain(); n != 1 {
		t.Fatalf("drained %d rows, want 1", n)
	}
	if state, _, params := r.outbox(id); state != "sent" || params {
		t.Fatalf("the row is %s with params kept %v: the message was recorded as sent before the panic and stays so", state, params)
	}
	if got := strings.Count(r.logs.String(), safego.Msg); got != 1 {
		t.Errorf("the panic was logged %d times, want once", got)
	}
	r.lapse()
	r.drain()
	if n := r.pri.count() + r.fb.count(); n != 1 {
		t.Errorf("the provider took %d requests, want the one accepted send and no second", n)
	}
	if strings.Contains(r.logs.String(), "canary-panic-value") {
		t.Error("the value of the panic reached the log")
	}
	r.assertLogsClean()
}

// The same for a code on its last claim: the record cleared it and kept the global slot spent (the
// message was delivered); the ending of the panicked row finds nothing to clear and must not give a slot
// back that the delivered code still uses.
func TestAPanicAfterTheRecordOfAnOTPRowOnItsLastClaimRefundsNothing(t *testing.T) {
	r := newRig(t)
	ch := r.request(r.env.A.Phone)
	r.env.Exec(t, `UPDATE ctrlz.otp_challenges SET delivery_attempts = 2 WHERE id = $1`, ch.ID) // the claim makes the third
	before := r.counter("global", "all")
	r.panicWhenLogging("sms sent", 1)
	if n := r.drain(); n != 1 {
		t.Fatalf("drained %d rows, want 1", n)
	}
	if r.deliveryCT(ch.ID) {
		t.Error("the code of a delivered row is still sealed")
	}
	if got := r.counter("global", "all"); got != before {
		t.Errorf("the global counter is %d after a delivered code, was %d: the panicked row's ending refunded a second time", got, before)
	}
	if n := r.pri.count() + r.fb.count(); n != 1 {
		t.Errorf("the provider took %d requests, want 1", n)
	}
	r.assertLogsClean()
}

// A panic inside the record transaction (the line a breaker step logs while the transaction holds the
// gateway row) rolls the whole record back, and the row is ended as a failed attempt that sent nothing:
// no half of the failure is left in the gateway row, the delivery log or the alerts, and the outbox
// message takes its backoff.
func TestAPanicInsideTheRecordTransactionRollsItAllBack(t *testing.T) {
	r := newRig(t)
	r.pri.reply = func(_ int, w http.ResponseWriter) { http500(w) }
	r.fb.reply = func(_ int, w http.ResponseWriter) { http500(w) }
	id := r.queue("test", "otp", "+989121112233", uuid.Nil, "ABCDEFGHJKMNPQRSTVWX")
	r.panicWhenLogging("sms gateway breaker moved one step", 1)
	if n := r.drain(); n != 1 {
		t.Fatalf("drained %d rows, want 1", n)
	}
	if got := strings.Count(r.logs.String(), safego.Msg); got != 1 {
		t.Fatalf("the panic was logged %d times, want once (it did not happen inside the record):\n%s", got, r.logs.String())
	}
	if n := r.count(`SELECT COALESCE(sum(consecutive_failures), 0) FROM ctrlz.sms_gateways`); n != 0 {
		t.Errorf("the gateways hold %d failures of a record that rolled back", n)
	}
	if n := r.count(`SELECT count(*) FROM ctrlz.sms_deliveries WHERE source_id = $1`, id); n != 0 {
		t.Errorf("%d delivery rows of a record that rolled back", n)
	}
	if state, _, params := r.outbox(id); state != "pending" || !params {
		t.Errorf("the row is %s with params kept %v: a failed attempt is retried", state, params)
	}
	if r.count(`SELECT count(*) FROM ctrlz.sms_outbox WHERE id = $1 AND claimed_until > now() + interval '25 seconds'`, id) != 1 {
		t.Error("the row is claimable again at its lease: the panic took no backoff")
	}
	r.assertLogsClean()
}
