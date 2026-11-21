package smssend_test

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/worker/panicguard"
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
	if got := strings.Count(r.logs.String(), panicguard.Msg); got != 1 {
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
		if got := buf.String(); strings.Count(got, panicguard.Msg) != 1 || !strings.Contains(got, `"unit":"`+name+`"`) {
			t.Errorf("%s: the panic was not logged once with its pass: %s", name, got)
		}
	}
}
