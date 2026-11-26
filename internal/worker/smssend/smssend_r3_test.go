package smssend_test

import (
	"errors"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/otp"
	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms"
)

// Review round 3 of the SMS layer and the worker loops.

const meliCreds = `{"username":"canary-user","password":"` + canaryMeliPW + `"}`

// The primary answers Blacklisted (sms.ir 115) while the fallback was not asked:
// its breaker is open, or its credentials do not open. Spec 9.2 says the other
// route is the one that reaches a SIM on the advertising blacklist, so one answer
// proves nothing and the row must be tried again, not ended with its caps spent
// (sms-r3-1).
func TestBlacklistedWhileTheFallbackWasNotAskedIsRetried(t *testing.T) {
	cases := []struct {
		name    string
		break_  func(r *rig)
		restore func(r *rig)
	}{
		{"breaker open", func(r *rig) {
			r.env.Exec(r.t, `UPDATE ctrlz.sms_gateways SET consecutive_failures = 3, breaker_open_until = now() + interval '10 minutes' WHERE id = $1`, r.fbID)
		}, func(r *rig) {
			r.env.Exec(r.t, `UPDATE ctrlz.sms_gateways SET breaker_open_until = NULL, consecutive_failures = 0 WHERE id = $1`, r.fbID)
		}},
		{"credentials unreadable", func(r *rig) {
			other, _ := keyring.NewEphemeral(keyring.DomainSMSCred)
			ct, err := sms.SealCredentials(other, r.fbID, "melipayamak", secret.NewBytes([]byte(meliCreds)))
			if err != nil {
				r.t.Fatal(err)
			}
			r.env.Exec(r.t, `UPDATE ctrlz.sms_gateways SET credentials_ct = $2 WHERE id = $1`, r.fbID, ct)
		}, func(r *rig) {
			ct, err := sms.SealCredentials(r.ring, r.fbID, "melipayamak", secret.NewBytes([]byte(meliCreds)))
			if err != nil {
				r.t.Fatal(err)
			}
			r.env.Exec(r.t, `UPDATE ctrlz.sms_gateways SET credentials_ct = $2, breaker_open_until = NULL, consecutive_failures = 0 WHERE id = $1`, r.fbID, ct)
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newRig(t)
			c.break_(r)
			r.pri.reply = func(_ int, w http.ResponseWriter) { irStatus(115)(w) }
			phone := r.env.A.Phone
			ch := r.request(phone)
			inv := r.queue("test", "otp", "+989121112233", uuid.Nil, "ABCDEFGHJKMNPQRSTVWX")
			r.drain()
			if r.fb.count() != 0 {
				t.Fatal("the fallback was called")
			}
			if !r.deliveryCT(ch.ID) {
				t.Error("the code was ended after one Blacklisted answer while the fallback was never asked")
			}
			if state, _, params := r.outbox(inv); state != "pending" || !params {
				t.Errorf("the invite was ended (state %s, params kept %v) on one Blacklisted answer", state, params)
			}

			// The fallback comes back: the retry reaches the number through it.
			c.restore(r)
			r.router.Invalidate()
			r.lapse()
			r.env.Exec(r.t, `UPDATE ctrlz.sms_outbox SET claimed_until = NULL`)
			r.drain()
			if r.deliveryCT(ch.ID) {
				t.Error("the code was not sent through the fallback once it was back")
			}
			if state, _, _ := r.outbox(inv); state != "sent" {
				t.Errorf("the invite is %s, want sent", state)
			}
		})
	}
}

// A row that ends unsent without anything the public could see must leave the
// same slots whether the phone has an account or not. A decoy is never delivered
// and so never refunded; a real code refunded in full would let four requests from
// one /24 tell the two apart (sms-r3-6, spec 5.3 and 18.5).
func TestUnsentEndingsLeaveTheSameCapsForKnownAndUnknownPhones(t *testing.T) {
	unknown := "+989129990001"
	scenarios := []struct {
		name  string
		setup func(r *rig)
		// afterRequest runs on every real challenge (a decoy has nothing to damage).
		afterRequest func(r *rig, id uuid.UUID)
	}{
		{name: "otp unmapped on both gateways", setup: func(r *rig) {
			r.env.Exec(r.t, `DELETE FROM ctrlz.sms_provider_templates WHERE key = 'otp'`)
		}},
		{name: "provider answers a documented template status for every message", setup: func(r *rig) {
			// sms.ir 113 and Melipayamak -2 are statuses the providers document as about
			// the template. An answer no page documents (a 404) is not this scenario: it
			// opens the breaker, see TestAGatewayAnsweringNothingDocumentedTurnsSMSOff.
			r.pri.reply = func(_ int, w http.ResponseWriter) { irStatus(113)(w) }
			r.fb.reply = func(_ int, w http.ResponseWriter) { meliStatus("-2")(w) }
		}},
		{name: "delivery sealed under a key the worker lacks", afterRequest: func(r *rig, id uuid.UUID) {
			r.env.Exec(r.t, `UPDATE ctrlz.otp_challenges SET delivery_ct = '\x00112233' WHERE id = $1`, id)
		}},
	}
	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			r := newRig(t)
			if sc.setup != nil {
				sc.setup(r)
			}
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
				var id uuid.UUID
				r.env.Scan(t, `SELECT id FROM ctrlz.otp_challenges WHERE phone_e164 = $1 AND delivery_ct IS NOT NULL ORDER BY created_at DESC LIMIT 1`, []any{known}, &id)
				if sc.afterRequest != nil {
					sc.afterRequest(r, id)
				}
				for a := 0; a < 3; a++ { // the three claims of one row
					r.drain()
					r.lapse()
				}
				if r.deliveryCT(id) {
					t.Fatalf("request %d: the row was not ended", i+1)
				}
				r.env.Exec(t, `UPDATE ctrlz.otp_challenges SET created_at = created_at - interval '2 minutes'`) // past the cooldown
			}
			// The public state did not move: no breaker opened, so sms_available is
			// still true and nothing tells the requester that codes are not arriving.
			if cfg, err := r.tenant.Auth().PublicConfig(r.env.Ctx); err != nil || !cfg.SMSAvailable {
				t.Fatalf("sms_available = %v (%v): the scenario is meant to leave it true", cfg.SMSAvailable, err)
			}
			// The fourth request from the same network: the cap of 3 per phone and
			// network refuses a known and an unknown phone alike.
			for _, phone := range []string{known, unknown} {
				if err := ask(phone); !errors.Is(err, otp.ErrLimited) {
					t.Errorf("the 4th request for %s: %v, want the same 429 for both", phone, err)
				}
			}
			// The world-wide counter is the one that went back.
			if n := r.counter("global", "all"); n != 0 {
				t.Errorf("global counter %d, want 0 (unsent codes cost nothing)", n)
			}
		})
	}
}

// A missing template is about one message type, so it does not open the breaker
// and sms_available stays true. The alert is what an operator gets, so it is
// critical when no routed gateway can send the template (sms-r3-5).
func TestUnmappedTemplateOnEveryGatewayRaisesACriticalAlert(t *testing.T) {
	r := newRig(t)
	r.env.Exec(t, `DELETE FROM ctrlz.sms_provider_templates WHERE key = 'otp'`)
	r.request(r.env.A.Phone)
	r.drain()
	for _, id := range []uuid.UUID{r.priID, r.fbID} {
		if r.count(`SELECT count(*) FROM ctrlz.alerts WHERE kind = 'sms_gateway' AND severity = 'critical' AND params ->> 'key' = $1 AND params ->> 'template' = 'otp'`,
			id.String()+":config:otp:none") != 1 {
			t.Errorf("no critical alert for the unmapped otp template on gateway %s", id)
		}
	}
	if r.count(`SELECT count(*) FROM ctrlz.alerts WHERE severity = 'warning'`) != 0 {
		t.Error("a warning was raised where nothing can send the template")
	}
}

// With one gateway missing the mapping the other still sends: a warning on its own
// key. A later gateway-wide failure of the same gateway raises its own critical
// alert although the warning was never acknowledged (the two used to share
// "<gateway>:config", and ON CONFLICT DO NOTHING hid the second).
func TestTemplateWarningDoesNotHideALaterGatewayWideAlert(t *testing.T) {
	r := newRig(t)
	r.env.Exec(t, `DELETE FROM ctrlz.sms_provider_templates WHERE gateway_id = $1 AND key = 'otp'`, r.priID)
	r.request(r.env.A.Phone)
	r.drain()
	if r.count(`SELECT count(*) FROM ctrlz.alerts WHERE severity = 'warning' AND params ->> 'key' = $1`, r.priID.String()+":config:otp") != 1 {
		t.Fatal("no template warning for the primary")
	}
	if r.fb.count() != 1 {
		t.Fatal("the fallback did not send")
	}
	// Now the primary's credentials stop opening.
	other, _ := keyring.NewEphemeral(keyring.DomainSMSCred)
	ct, err := sms.SealCredentials(other, r.priID, "sms_ir", secret.NewBytes([]byte(`{"api_key":"`+canaryIRKey+`"}`)))
	if err != nil {
		t.Fatal(err)
	}
	r.env.Exec(t, `UPDATE ctrlz.sms_gateways SET credentials_ct = $2 WHERE id = $1`, r.priID, ct)
	r.router.Invalidate()
	r.env.Exec(t, `UPDATE ctrlz.otp_challenges SET created_at = created_at - interval '2 minutes'`)
	r.request(r.env.B.Phone)
	r.drain()
	if r.count(`SELECT count(*) FROM ctrlz.alerts WHERE severity = 'critical' AND params ->> 'key' = $1`, r.priID.String()+":config") != 1 {
		t.Error("the unacknowledged template warning hid the gateway-wide critical alert")
	}
}
