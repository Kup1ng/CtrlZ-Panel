package smssend_test

import (
	"errors"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/otp"
	"github.com/Kup1ng/CtrlZ-Panel/internal/authtest"
)

// Review round 4 of the SMS layer and the worker loops.

// The T-411 setup step: the admin saves a gateway, then clicks Test send. The
// admin runs in another process, so nothing tells this worker's router that the
// database changed, and its snapshot may be 30 seconds old. No test here calls
// Invalidate (sms-r4-1, sms-r4-4).
func TestTestSendRightAfterSavingSeesTheNewGateway(t *testing.T) {
	r := newRig(t)
	// Ordinary traffic loads the snapshot, as it does all day.
	ch := r.request(r.env.A.Phone)
	r.drain()
	if r.deliveryCT(ch.ID) {
		t.Fatal("the warm-up code was not sent")
	}

	// A gateway that has just been given its credentials appears in the database.
	extra := r.env.AddGateway(t, r.ring, authtest.Gateway{Provider: "noop", Role: "disabled"})
	id := r.queue("test", "otp", "+989121112233", extra, "123456")
	r.drain()
	state, last, _ := r.outbox(id)
	if state != "sent" {
		t.Fatalf("the test send of a gateway saved a moment ago ended %s %s", state, last)
	}
	if b, err := os.ReadFile(r.noopFile); err != nil || !strings.Contains(string(b), "123456") {
		t.Errorf("the pinned gateway did not get the message: %q %v", b, err)
	}
	// Nothing was raised about a gateway fault that does not exist.
	if n := r.count(`SELECT count(*) FROM ctrlz.alerts WHERE kind = 'sms_gateway'`); n != 0 {
		t.Errorf("%d gateway alerts after a good test send", n)
	}
}

// A successful pinned send closes the breaker in the database. Routed traffic must
// see that at once and not skip the gateway until the next 30 second reload while
// sms_available already reads true.
func TestPinnedAcceptClosesTheBreakerForRoutedTraffic(t *testing.T) {
	r := newRig(t)
	r.env.Exec(t, `UPDATE ctrlz.sms_gateways SET consecutive_failures = 3, breaker_open_until = now() + interval '10 minutes' WHERE id = $1`, r.priID)
	// The primary is skipped: the fallback carries the code.
	ch := r.request(r.env.A.Phone)
	r.drain()
	if r.deliveryCT(ch.ID) || r.pri.count() != 0 || r.fb.count() != 1 {
		t.Fatalf("setup: pri %d fb %d", r.pri.count(), r.fb.count())
	}

	// The operator tests the primary and it works.
	id := r.queue("test", "otp", "+989121112233", r.priID, "123456")
	r.drain()
	if state, last, _ := r.outbox(id); state != "sent" {
		t.Fatalf("the test send: %s %s", state, last)
	}
	if n := r.count(`SELECT consecutive_failures FROM ctrlz.sms_gateways WHERE id = $1`, r.priID); n != 0 {
		t.Fatalf("the accepted test did not reset the failures: %d", n)
	}

	// The next ordinary code goes to the primary again.
	r.env.Exec(t, `UPDATE ctrlz.otp_challenges SET created_at = created_at - interval '2 minutes'`) // past the cooldown
	before := r.pri.count()
	ch2 := r.request(r.env.A.Phone)
	r.drain()
	if r.deliveryCT(ch2.ID) || r.pri.count() != before+1 {
		t.Errorf("routed traffic still skips the primary after its breaker closed: pri %d (was %d)", r.pri.count(), before)
	}
}

// A failing gateway whose breaker never opens leaves sms_available true, so an
// unsent ending that gave a real phone its per-phone slots back would show, by the
// 429 of the fourth request, that the phone has an account (sms-r4-5, spec 5.3).
// The failures here are real, but another user's success resets the gateway's
// consecutive count between them, as it does for a gateway that flaps.
func TestFlappingGatewayDoesNotRefundPerPhoneSlots(t *testing.T) {
	scenarios := []struct {
		name  string
		setup func(r *rig)
	}{
		{"primary flaps and the fallback has no otp mapping", func(r *rig) {
			r.env.Exec(r.t, `DELETE FROM ctrlz.sms_provider_templates WHERE key = 'otp' AND gateway_id = $1`, r.fbID)
		}},
		{"only one gateway is routed and it flaps", func(r *rig) {
			r.env.Exec(r.t, `UPDATE ctrlz.sms_gateways SET role = 'disabled' WHERE id = $1`, r.fbID)
		}},
	}
	unknown := "+989129990001"
	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			r := newRig(t)
			sc.setup(r)
			r.pri.reply = func(_ int, w http.ResponseWriter) { http500(w) }
			known := r.env.A.Phone
			ask := func(phone string) error {
				_, err := r.otp.Request(r.env.Ctx, otp.Request{Phone: phone, Purpose: otp.Login, Locale: "fa", IP: ip})
				return err
			}
			for i := 0; i < 3; i++ {
				for _, phone := range []string{known, unknown} {
					if err := ask(phone); err != nil {
						t.Fatalf("request %d for %s: %v", i+1, phone, err)
					}
				}
				for a := 0; a < 3; a++ { // the three claims of one row
					r.drain()
					// Somebody else's code went through in between.
					r.env.Exec(t, `UPDATE ctrlz.sms_gateways SET consecutive_failures = 0, breaker_open_until = NULL WHERE id = $1`, r.priID)
					r.router.Invalidate()
					r.lapse()
				}
				if n := r.count(`SELECT count(*) FROM ctrlz.otp_challenges WHERE phone_e164 = $1 AND delivery_ct IS NOT NULL`, known); n != 0 {
					t.Fatalf("request %d: the row was not ended", i+1)
				}
				r.env.Exec(t, `UPDATE ctrlz.otp_challenges SET created_at = created_at - interval '2 minutes'`)
			}
			if cfg, err := r.tenant.Auth().PublicConfig(r.env.Ctx); err != nil || !cfg.SMSAvailable {
				t.Fatalf("sms_available = %v (%v): the scenario is meant to leave it true", cfg.SMSAvailable, err)
			}
			for _, phone := range []string{known, unknown} {
				if err := ask(phone); !errors.Is(err, otp.ErrLimited) {
					t.Errorf("the 4th request for %s: %v, want the same 429 for both", phone, err)
				}
			}
			if n := r.counter("global", "all"); n != 0 {
				t.Errorf("global counter %d, want 0 (unsent codes cost nothing)", n)
			}
		})
	}
}
