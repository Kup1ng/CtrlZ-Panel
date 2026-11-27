package smssend_test

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/safego"
	"github.com/Kup1ng/CtrlZ-Panel/internal/worker/smssend"
)

// Review round 17 of the SMS layer and the worker loops.

// sms-r17-5: the goroutines of the rows in flight kept no panic of their own, so one row whose work
// panicked (a reply parser, an unexpected sealed payload) ended the process while the other rows'
// messages were accepted by the provider and not yet recorded: a second message, a second bill and a
// price never added to the money counter. A panic now stays with its row. The hook panics after the
// FIRST accepted send; the second row must still be recorded, the worker must survive, and the row that
// panicked is left as a crash would leave it, to be sent again when its claim lapses.
func TestAPanicInOneRowStaysWithThatRow(t *testing.T) {
	r := newRig(t)
	a := r.request(r.env.A.Phone)
	b := r.request(r.env.B.Phone)
	var calls atomic.Int32
	r.afterSend = func() {
		if calls.Add(1) == 1 {
			panic("canary-panic-value " + code)
		}
	}
	if n := r.drain(); n != 2 {
		t.Fatalf("drained %d rows, want both counted as handled", n)
	}
	sealedA, sealedB := r.deliveryCT(a.ID), r.deliveryCT(b.ID)
	if sealedA == sealedB {
		t.Fatalf("rows A sealed=%v and B sealed=%v: exactly the row that did not panic should be recorded", sealedA, sealedB)
	}
	if got := strings.Count(r.logs.String(), safego.Msg); got != 1 {
		t.Errorf("the panic was logged %d times, want once:\n%s", got, r.logs.String())
	}
	// The value of a panic can hold anything the code was handling; the log holds the source only.
	if strings.Contains(r.logs.String(), "canary-panic-value") {
		t.Error("the value of the panic reached the log")
	}
	r.assertLogsClean()
	// The row that panicked is still queued: a crash leaves it so, and its claim lapses.
	r.afterSend = nil
	r.lapse()
	if n := r.drain(); n != 1 {
		t.Errorf("after the lapse drained %d rows, want the one that panicked", n)
	}
	if r.deliveryCT(a.ID) || r.deliveryCT(b.ID) {
		t.Error("a row is still queued after the lapse")
	}
}

// sms-r17-17: the passes of the SMS loop outside the row goroutines (the claim, a gate, an alert, the check
// of the gateways at start) keep their own panic too, so one of them does not end the process under the
// rows that another unit of the worker holds in flight.
func TestAPanicInAPassOfTheSMSLoopStaysWithThatPass(t *testing.T) {
	for name, pass := range map[string]func(context.Context, *slog.Logger){
		"drain": smssend.KeptDrainPass, "start": smssend.KeptStartCheck,
	} {
		var buf bytes.Buffer
		log := slog.New(slog.NewJSONHandler(&buf, nil))
		escaped := func() (out bool) {
			defer func() { out = recover() != nil }() // the test's own: a missing guard fails here
			pass(context.Background(), log)
			return false
		}()
		if escaped {
			t.Fatalf("%s: the panic left the pass", name)
		}
		if got := buf.String(); strings.Count(got, safego.Msg) != 1 || !strings.Contains(got, `"unit":"`+name+`"`) {
			t.Errorf("%s: the panic was not logged once with its pass: %s", name, got)
		}
	}
}

// sms-r18-1, sms-r18-5: a panic in a row is ended as a failed attempt that sent nothing, and not left to
// the lapse of its claim. An outbox message that panicked after the provider took it was sent again every
// 20 seconds, up to OutboxMaxAttempts times, to a phone that may already hold the first; it is held back by
// its backoff now, like every failed attempt.
func TestAPanickingOutboxRowTakesTheBackoffAndIsNotResentAtTheLease(t *testing.T) {
	r := newRig(t)
	id := r.queue("test", "otp", "+989121112233", uuid.Nil, "ABCDEFGHJKMNPQRSTVWX")
	r.afterSend = func() { panic("canary-panic-value " + code) }
	if n := r.drain(); n != 1 {
		t.Fatalf("drained %d rows, want the one that panicked counted as handled", n)
	}
	if state, _, params := r.outbox(id); state != "pending" || !params {
		t.Fatalf("the row is %s with params kept %v: a failed attempt is retried, not ended and not forgotten", state, params)
	}
	// The claim leaves it for 20 seconds; the backoff of the first attempt is 30.
	if r.count(`SELECT count(*) FROM ctrlz.sms_outbox WHERE id = $1 AND claimed_until > now() + interval '25 seconds'`, id) != 1 {
		t.Error("the row is claimable again at the lease: the panic took no backoff, so it is sent again every 20 seconds")
	}
	if strings.Contains(r.logs.String(), "canary-panic-value") {
		t.Error("the value of the panic reached the log")
	}
	r.assertLogsClean()
}

// A code on its last claim whose row panicked is ended, cleared and refunded at once, like a failed last
// attempt; before, it stayed sealed until the exhausted pass of the next claim.
func TestAPanickingOTPRowOnItsLastClaimIsEndedAndRefunded(t *testing.T) {
	r := newRig(t)
	ch := r.request(r.env.A.Phone)
	r.env.Exec(t, `UPDATE ctrlz.otp_challenges SET delivery_attempts = 2 WHERE id = $1`, ch.ID) // the claim makes the third
	r.afterSend = func() { panic("canary-panic-value " + code) }
	if n := r.drain(); n != 1 {
		t.Fatalf("drained %d rows, want 1", n)
	}
	if r.deliveryCT(ch.ID) {
		t.Error("the code of a row that panicked on its last claim is still sealed")
	}
	if got := r.counter("global", "all"); got != 0 {
		t.Errorf("the global slot of a row that ended unsent was not refunded: %d", got)
	}
	r.assertLogsClean()
}
