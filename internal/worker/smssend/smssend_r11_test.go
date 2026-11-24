package smssend_test

import (
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms"
)

// Review round 11 of the SMS layer and the worker loops (sms-r11-9).

// reseal saves other credentials for a gateway, as the admin PUT does: a new sealed value, so the
// Source builds a new sender and forgets what it held about the old one.
func (r *rig) reseal(id uuid.UUID, provider, credentials string) {
	r.t.Helper()
	ct, err := sms.SealCredentials(r.ring, id, provider, secret.NewBytes([]byte(credentials)))
	if err != nil {
		r.t.Fatal(err)
	}
	r.env.Exec(r.t, `UPDATE ctrlz.sms_gateways SET credentials_ct = $2 WHERE id = $1`, id, ct)
	r.router.Invalidate()
}

// A refused login is asked once. Without the hold, each of the breaker's probe rounds is another
// failed login with the same credentials, about 96 rounds a day, and Melipayamak answers a run of
// them by blocking the panel's address (-108), which only its support lifts. The held gateway is
// still a Gateway-scope failure to the worker: the breaker steps, the critical alert stays open and
// sms_available is false while no routed gateway can send.
func TestARefusedLoginHoldsTheGatewayUntilItsCredentialsChange(t *testing.T) {
	r := newRig(t)
	r.env.Exec(t, `UPDATE ctrlz.system_settings SET otp_cap_phone = 100, otp_cap_phone_net = 100`)
	r.pri.reply = func(_ int, w http.ResponseWriter) { irStatus(10)(w) } // key refused
	for i := 0; i < 5; i++ {
		ch := r.request(r.env.A.Phone)
		r.drain()
		if r.deliveryCT(ch.ID) {
			t.Fatalf("send %d did not go through the fallback", i)
		}
		r.env.Exec(t, `UPDATE ctrlz.otp_challenges SET created_at = created_at - interval '2 minutes'`)
		// The breaker pauses end (the rig does not wait for them): the held gateway must still not
		// be called when the pause is over.
		r.env.Exec(t, `UPDATE ctrlz.sms_gateways SET breaker_open_until = NULL`)
		r.router.Invalidate()
	}
	if n := r.pri.count(); n != 1 {
		t.Errorf("the refused primary was called %d times, want 1", n)
	}
	if r.fb.count() != 5 {
		t.Errorf("fallback calls: %d, want 5", r.fb.count())
	}
	// The held attempts are steps of the breaker: it opened, and it opens again after a pause
	// instead of staying closed with a gateway nobody asks.
	if r.count(`SELECT consecutive_failures FROM ctrlz.sms_gateways WHERE id = $1`, r.priID) < 3 {
		t.Error("a held gateway did not count toward the breaker")
	}
	if n := r.count(`SELECT count(*) FROM ctrlz.alerts WHERE kind = 'sms_gateway' AND params ->> 'key' = $1 AND resolved_at IS NULL`, r.priID.String()+":auth"); n != 1 {
		t.Errorf("open auth alerts: %d, want 1", n)
	}
	// Saved credentials are the way out: the next send asks the provider again, and this time it
	// answers.
	r.pri.reply = func(_ int, w http.ResponseWriter) { irOK(w) }
	r.reseal(r.priID, "sms_ir", `{"api_key":"`+canaryIRKey+`-2"}`)
	r.env.Exec(t, `UPDATE ctrlz.sms_gateways SET breaker_open_until = NULL, consecutive_failures = 0`)
	r.router.Invalidate()
	r.request(r.env.A.Phone)
	r.drain()
	if n := r.pri.count(); n != 2 {
		t.Errorf("after new credentials the primary was called %d times in all, want 2", n)
	}
}

// The admin's test send is the explicit probe of a held gateway, and an accepted one lifts the
// hold, so a gateway the operator fixed at the provider (an address allow list, a topped-up
// account) is not stuck until a restart.
func TestATestSendProbesAHeldGatewayAndLiftsItWhenAccepted(t *testing.T) {
	r := newRig(t)
	r.env.Exec(t, `UPDATE ctrlz.system_settings SET otp_cap_phone = 100, otp_cap_phone_net = 100`)
	r.pri.reply = func(_ int, w http.ResponseWriter) { irStatus(10)(w) }
	r.request(r.env.A.Phone)
	r.drain()
	if r.pri.count() != 1 {
		t.Fatalf("the first send did not meet the refusal: %d", r.pri.count())
	}
	// Held: a second code does not reach the provider.
	r.env.Exec(t, `UPDATE ctrlz.otp_challenges SET created_at = created_at - interval '2 minutes'`)
	r.env.Exec(t, `UPDATE ctrlz.sms_gateways SET breaker_open_until = NULL`)
	r.router.Invalidate()
	r.request(r.env.A.Phone)
	r.drain()
	if r.pri.count() != 1 {
		t.Fatalf("a held gateway was called: %d", r.pri.count())
	}
	// The test send still goes to the provider, and is refused again.
	id := r.queue("test", "otp", "+989121112233", r.priID, "123456")
	r.drain()
	if r.pri.count() != 2 {
		t.Fatalf("the test send did not probe the held gateway: %d", r.pri.count())
	}
	_ = id
	// The provider now accepts the test send: the hold is lifted.
	r.pri.reply = func(_ int, w http.ResponseWriter) { irOK(w) }
	r.queue("test", "otp", "+989121112233", r.priID, "123456")
	r.drain()
	if r.pri.count() != 3 {
		t.Fatalf("the second test send did not reach the provider: %d", r.pri.count())
	}
	r.env.Exec(t, `UPDATE ctrlz.otp_challenges SET created_at = created_at - interval '2 minutes'`)
	r.env.Exec(t, `UPDATE ctrlz.sms_gateways SET breaker_open_until = NULL, consecutive_failures = 0`)
	r.router.Invalidate()
	r.request(r.env.A.Phone)
	r.drain()
	if r.pri.count() != 4 {
		t.Errorf("after an accepted test send the gateway was not asked again: %d", r.pri.count())
	}
}
