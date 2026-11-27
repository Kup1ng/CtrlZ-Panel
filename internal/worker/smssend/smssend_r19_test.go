package smssend_test

import (
	"log/slog"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/worker/smssend"
)

// Review round 19 of the SMS layer and the worker loops.

// sms-r19-2, sms-r19-4: a panic after a gateway accepted the message and before the record committed
// was ended as a send that never happened. An OTP on its last claim was cleared and refunded to the
// global count and its price never reached the money counter, though the provider had billed it; an
// outbox message was sent and billed again after each backoff. The accepted outcome now travels out of
// the panicked unit and is recorded as it was. The hook panics in BeforeRecord, which runs with the
// accepted outcome in hand.
func TestAPanicAfterTheAcceptIsRecordedAsTheAccept(t *testing.T) {
	newWorker := func(r *rig) *smssend.Worker {
		t.Helper()
		w, err := smssend.New(smssend.Config{Store: r.worker, Router: r.router, Keys: r.ring, Log: slog.New(slog.NewJSONHandler(r.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
			BeforeRecord: func() { panic("canary-panic-value " + code) }})
		if err != nil {
			t.Fatal(err)
		}
		return w
	}

	t.Run("otp on its last claim", func(t *testing.T) {
		r := newRig(t)
		ch := r.request(r.env.A.Phone)
		r.env.Exec(t, `UPDATE ctrlz.otp_challenges SET delivery_attempts = 2 WHERE id = $1`, ch.ID) // the claim makes the third
		if _, err := newWorker(r).Drain(r.env.Ctx); err != nil {
			t.Fatal(err)
		}
		if n := r.pri.count(); n != 1 {
			t.Fatalf("the provider got the code %d times, want 1", n)
		}
		if r.deliveryCT(ch.ID) {
			t.Error("the code the provider accepted is still sealed")
		}
		if got := r.cost(); got != 10 {
			t.Errorf("money counter %v, want the 10 the provider billed", got)
		}
		if got := r.counter("global", "all"); got != 1 {
			t.Errorf("global count %d, want 1: an accepted code gives no slot back", got)
		}
		if n := r.count(`SELECT count(*) FROM ctrlz.sms_deliveries WHERE source = 'otp' AND source_id = $1 AND outcome = 'accepted'`, ch.ID); n != 1 {
			t.Errorf("%d accepted delivery rows, want 1", n)
		}
		if n := r.count(`SELECT count(*) FROM ctrlz.alerts WHERE kind = 'sms_down'`); n != 0 {
			t.Errorf("%d sms_down alerts for a code the provider accepted", n)
		}
		if strings.Contains(r.logs.String(), "canary-panic-value") {
			t.Error("the value of the panic reached the log")
		}
		r.assertLogsClean()
	})

	t.Run("outbox message", func(t *testing.T) {
		r := newRig(t)
		id := r.queue("test", "otp", "+989121112233", uuid.Nil, "ABCDEFGHJKMNPQRSTVWX")
		if _, err := newWorker(r).Drain(r.env.Ctx); err != nil {
			t.Fatal(err)
		}
		if state, _, params := r.outbox(id); state != "sent" || params {
			t.Errorf("the message the provider accepted is %s with params kept %v: it would be sent and billed again", state, params)
		}
		if got := r.cost(); got != 10 {
			t.Errorf("money counter %v, want 10", got)
		}
		r.lapse()
		if _, err := newWorker(r).Drain(r.env.Ctx); err != nil {
			t.Fatal(err)
		}
		if n := r.pri.count(); n != 1 {
			t.Errorf("the provider got the message %d times, want 1", n)
		}
		r.assertLogsClean()
	})
}
