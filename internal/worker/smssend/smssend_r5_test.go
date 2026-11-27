package smssend_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/worker/smssend"
)

// Review round 5 of the SMS layer and the worker loops.

// counters reads the per-phone and per-network counters of one phone as a request from
// the shared test address wrote them.
func (r *rig) phoneCounters(phone string) [2]int {
	return [2]int{r.counter("phone", phone), r.counter("phone_net", phone+"|198.51.100.0/24")}
}

// A real row that ends while the breakers are open leaves the same per-phone counters as
// a decoy does (sms-r5-1). With the old refund on sms_available the real phone got its
// slots back and the unknown phone, whose decoy is never ended, did not: after the
// outage one answered 202 and the other 429. This is the state the oracle tests call
// breaker_opens_mid_row, run here without the HTTP layer.
func TestARowEndedWhileTheBreakersOpenLeavesTheCountersOfADecoy(t *testing.T) {
	r := newRig(t)
	known, unknown := r.env.A.Phone, "+989129990001"
	ch := r.request(known)
	r.request(unknown)
	// The request saw an available gateway; the breakers open before the worker ends the
	// row, so the row finishes with sms_available false.
	r.env.Exec(t, `UPDATE ctrlz.sms_gateways SET consecutive_failures = 3, breaker_open_until = now() + interval '1 hour'`)
	r.router.Invalidate()
	for i := 0; i < 3; i++ {
		r.drain()
		r.lapse()
	}
	if r.deliveryCT(ch.ID) {
		t.Fatal("the real row was not ended")
	}
	if k, u := r.phoneCounters(known), r.phoneCounters(unknown); k != u {
		t.Errorf("a phone with an account has per-phone counters %v and one without has %v after the outage", k, u)
	}
	if n := r.counter("global", "all"); n != 0 {
		t.Errorf("global counter %d, want 0", n)
	}
}

// A shutdown that arrives after the check of the context and before the record
// transaction must not lose an accepted send (sms-r5-3). BeforeRecord cancels the
// context at exactly that point.
func TestShutdownBetweenTheAcceptAndTheRecordLosesNothing(t *testing.T) {
	r := newRig(t)
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))
	// stopping builds a worker that cancels its own context after the gateway accepted
	// and before the record transaction. One message per worker keeps the two sends from
	// racing each other's cancellation.
	stopping := func() (*smssend.Worker, context.Context) {
		ctx, cancel := context.WithCancel(r.env.Ctx)
		t.Cleanup(cancel)
		w, err := smssend.New(smssend.Config{Store: r.worker, Router: r.router, Keys: r.ring, Log: log, BeforeRecord: cancel})
		if err != nil {
			t.Fatal(err)
		}
		return w, ctx
	}
	ch := r.request(r.env.A.Phone)
	w1, ctx1 := stopping()
	if _, err := w1.Drain(ctx1); err != nil {
		t.Fatal(err)
	}
	if r.deliveryCT(ch.ID) {
		t.Error("the accepted code stayed sealed: the next worker would send it again")
	}
	if r.count(`SELECT count(*) FROM ctrlz.sms_deliveries WHERE source_id = $1 AND outcome = 'accepted'`, ch.ID) != 1 {
		t.Error("the accepted code has no delivery row")
	}

	id := r.queue("test", "otp", "+989121112233", uuid.Nil, "ABCDEFGHJKMNPQRSTVWX")
	w2, ctx2 := stopping()
	if _, err := w2.Drain(ctx2); err != nil {
		t.Fatal(err)
	}
	if state, _, params := r.outbox(id); state != "sent" || params {
		t.Errorf("invite: %s, params kept %v", state, params)
	}
	if r.cost() != 20 {
		t.Errorf("cost %v, want both messages charged", r.cost())
	}
	r.lapse()
	r.drain()
	if r.pri.count() != 2 {
		t.Errorf("a message was sent again: %d provider calls, want 2", r.pri.count())
	}
}

// A gateway that answers something no provider page documents to every send (a 404 after
// a path change, a firewall's 403, a redirect) delivers nothing, so it must count toward
// its breaker and turn OTP off. It was classed as a problem of one template, which never
// opens a breaker, and the login page offered a code that never came (sms-r5-4).
func TestAGatewayAnsweringNothingDocumentedTurnsSMSOff(t *testing.T) {
	for name, reply := range map[string]func(int, http.ResponseWriter){
		"404":      func(_ int, w http.ResponseWriter) { w.WriteHeader(404) },
		"403":      func(_ int, w http.ResponseWriter) { w.WriteHeader(403) },
		"redirect": func(_ int, w http.ResponseWriter) { w.WriteHeader(302) },
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			r.pri.reply, r.fb.reply = reply, reply
			ch := r.request(r.env.A.Phone)
			for i := 0; i < 3; i++ {
				r.drain()
				r.lapse()
			}
			if r.deliveryCT(ch.ID) {
				t.Fatal("the row was not ended")
			}
			// What an answer nobody documented does is open the breakers (the router stops asking, the
			// operator is alerted); the public flag no longer follows them (sms-r18-2).
			if n := r.count(`SELECT count(*) FROM ctrlz.sms_gateways WHERE breaker_open_until > now()`); n != 2 {
				t.Errorf("%d breakers open after both gateways answered %s to every send, want 2", n, name)
			}
			cfg, err := r.tenant.Auth().PublicConfig(r.env.Ctx)
			if err != nil || !cfg.SMSAvailable {
				t.Errorf("sms_available = %v (%v) with both gateways answering %s to every send: the flag is configuration alone (sms-r18-2)", cfg.SMSAvailable, err, name)
			}
		})
	}
}
