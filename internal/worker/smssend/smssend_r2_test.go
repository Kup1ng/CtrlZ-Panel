package smssend_test

import (
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/otp"
	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms"
)

// Review round 2 of the SMS layer and the worker loops.

func meliStatus(v string) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) { _, _ = io.WriteString(w, `{"Value":"`+v+`"}`) }
}

func (r *rig) breaker(id uuid.UUID) (failures int, pause time.Duration) {
	r.t.Helper()
	var secs *float64
	r.env.Scan(r.t, `SELECT consecutive_failures, extract(epoch FROM breaker_open_until - now())::float8 FROM ctrlz.sms_gateways WHERE id = $1`,
		[]any{id}, &failures, &secs)
	if secs != nil {
		pause = time.Duration(*secs * float64(time.Second))
	}
	return failures, pause
}

// Four rows of one pass reach a gateway whose pause has just ended, and all four
// fail. That is one probe round and one escalation step (120 s after a first
// opening of 60 s), not four (the 15 minute cap): a provider that recovers two
// minutes into an outage must not stay shut for a quarter of an hour (sms-r2-1).
func TestConcurrentProbeFailuresMoveTheBreakerOneStep(t *testing.T) {
	r := newRig(t)
	r.pri.reply = func(_ int, w http.ResponseWriter) { http500(w) }
	r.fb.reply = func(_ int, w http.ResponseWriter) { http500(w) }
	r.request(r.env.A.Phone)
	r.request(r.env.B.Phone)
	r.queue("invite", "invite", "+989121112233", uuid.Nil, "ABCDEFGHJKMNPQRSTVWX")
	r.queue("invite", "invite", "+989121112244", uuid.Nil, "BCDEFGHJKMNPQRSTVWXY")
	// Both gateways were shut for 60 s after three failures, and the pause ended.
	r.env.Exec(t, `UPDATE ctrlz.sms_gateways SET consecutive_failures = 3, breaker_open_until = now() - interval '1 second'`)

	r.drain()
	if r.pri.count() != 4 || r.fb.count() != 4 {
		t.Fatalf("calls: primary %d, fallback %d, want 4 and 4 (one pass of four rows)", r.pri.count(), r.fb.count())
	}
	for name, id := range map[string]uuid.UUID{"primary": r.priID, "fallback": r.fbID} {
		n, pause := r.breaker(id)
		if n != 4 || pause < 100*time.Second || pause > 125*time.Second {
			t.Errorf("%s: %d failures, pause %v, want 4 and about 120 s", name, n, pause)
		}
	}
}

// A pass keeps one of its four slots for the outbox, so a stream of codes cannot
// starve an invite (spec 9.8, sms-r2-8). Six codes and one invite are waiting;
// the first four calls the provider sees are the first pass, and the invite is
// among them.
func TestAStreamOfCodesCannotStarveAnInvite(t *testing.T) {
	r := newRig(t)
	const invite = "ABCDEFGHJKMNPQRSTVWX"
	ch := r.request(r.env.A.Phone)
	// Five more rows with the same sealed code: the payload binds to the phone and
	// the purpose, not to the row.
	r.env.Exec(t, `INSERT INTO ctrlz.otp_challenges (phone_e164, purpose, code_hash, delivery_ct, expires_at, ip)
SELECT phone_e164, purpose, code_hash, delivery_ct, expires_at, ip FROM ctrlz.otp_challenges, generate_series(1, 5) WHERE id = $1`, ch.ID)
	r.queue("invite", "invite", "+989121112233", uuid.Nil, invite)
	// The provider answers slowly, so the rows of one pass overlap and the order of
	// arrival is the order of the passes.
	r.pri.reply = func(_ int, w http.ResponseWriter) { time.Sleep(150 * time.Millisecond); irOK(w) }

	r.drain()
	r.pri.mu.Lock()
	calls := append([]string(nil), r.pri.calls...)
	r.pri.mu.Unlock()
	if len(calls) != 7 {
		t.Fatalf("%d provider calls, want 7", len(calls))
	}
	if !strings.Contains(strings.Join(calls[:4], "\n"), invite) {
		t.Errorf("the invite was not in the first pass of four: it waited behind the codes")
	}
}

// Both gateways have credentials that no longer open (a key rotation that removed
// the old key before rekey ran, or a restore with the wrong key file). Nothing
// can be sent, so the breakers open and the login page stops offering a code that
// would be answered 202 and dropped (sms-r2-2, sms-r2-10).
func TestBothCredentialsUnreadableTurnSMSOff(t *testing.T) {
	r := newRig(t)
	other, _ := keyring.NewEphemeral(keyring.DomainSMSCred)
	for _, g := range []struct {
		id       uuid.UUID
		provider string
		creds    string
	}{{r.priID, "sms_ir", `{"api_key":"` + canaryIRKey + `"}`}, {r.fbID, "melipayamak", `{"username":"canary-user","password":"` + canaryMeliPW + `"}`}} {
		ct, err := sms.SealCredentials(other, g.id, g.provider, secret.NewBytes([]byte(g.creds)))
		if err != nil {
			t.Fatal(err)
		}
		r.env.Exec(t, `UPDATE ctrlz.sms_gateways SET credentials_ct = $2 WHERE id = $1`, g.id, ct)
	}
	phone := r.env.A.Phone
	ch := r.request(phone)
	for i := 0; i < 3; i++ {
		r.drain()
		r.lapse()
	}
	if r.pri.count() != 0 || r.fb.count() != 0 {
		t.Error("a gateway with unreadable credentials was called")
	}
	if r.deliveryCT(ch.ID) || r.counter("global", "all") != 0 || r.counter("phone", phone) != 1 { // only the global key goes back
		t.Error("the unsendable row was not ended with its caps given back")
	}
	cfg, err := r.tenant.Auth().PublicConfig(r.env.Ctx)
	if err != nil || cfg.SMSAvailable {
		t.Fatalf("sms_available = %v (%v) with nothing able to send", cfg.SMSAvailable, err)
	}
	if _, err := r.otp.Request(r.env.Ctx, otp.Request{Phone: phone, Purpose: otp.Login, Locale: "fa", IP: ip}); err == nil {
		t.Error("a request was accepted with both gateways unusable")
	}
	// Critical: nothing can be sent through either of them.
	for _, id := range []uuid.UUID{r.priID, r.fbID} {
		if r.count(`SELECT count(*) FROM ctrlz.alerts WHERE kind = 'sms_gateway' AND severity = 'critical' AND params ->> 'key' = $1`, id.String()+":config") != 1 {
			t.Errorf("no critical alert for gateway %s", id)
		}
	}
}

// A missing template mapping is about one message type, not the gateway, and
// does not count toward the breaker (spec 9.1).
func TestMissingTemplateDoesNotOpenTheBreaker(t *testing.T) {
	r := newRig(t)
	r.env.Exec(t, `DELETE FROM ctrlz.sms_provider_templates WHERE gateway_id = $1`, r.priID)
	for i := 0; i < 3; i++ {
		r.request(r.env.A.Phone)
		r.drain()
		r.env.Exec(t, `UPDATE ctrlz.otp_challenges SET created_at = created_at - interval '2 minutes'`)
	}
	if n, pause := r.breaker(r.priID); n != 0 || pause > 0 {
		t.Errorf("a missing template counted toward the breaker: %d failures, pause %v", n, pause)
	}
	if cfg, err := r.tenant.Auth().PublicConfig(r.env.Ctx); err != nil || !cfg.SMSAvailable {
		t.Errorf("sms_available = %v (%v)", cfg.SMSAvailable, err)
	}
}

// A number every gateway reports as blacklisted is asked once, and the caps it
// spent stay spent, as for a Recipient refusal. Otherwise it could be asked for
// again every cooldown with nothing counted, each time costing provider calls and,
// if the provider throttles, risking both breakers (sms-r2-9).
func TestBlacklistedNumberIsAskedOnceAndKeepsItsCaps(t *testing.T) {
	r := newRig(t)
	r.pri.reply = func(_ int, w http.ResponseWriter) { irStatus(115)(w) }
	r.fb.reply = func(_ int, w http.ResponseWriter) { meliStatus("35")(w) }
	phone := r.env.A.Phone
	ch := r.request(phone)
	r.drain()
	r.lapse()
	r.drain() // nothing is left to claim
	if r.pri.count() != 1 || r.fb.count() != 1 {
		t.Errorf("calls: primary %d, fallback %d, want one each", r.pri.count(), r.fb.count())
	}
	if r.deliveryCT(ch.ID) {
		t.Error("the row was left to be asked again")
	}
	for _, k := range [][2]string{{"phone", phone}, {"ip", ip.String()}} { // the per-phone caps stay spent
		if n := r.counter(k[0], k[1]); n != 1 {
			t.Errorf("counter %s %s = %d, want 1 (not refunded)", k[0], k[1], n)
		}
	}
	// The global key goes back like every unsent ending: the shared counter is the one a
	// decoy never moves (sms-r5-2).
	if n := r.counter("global", "all"); n != 0 {
		t.Errorf("global counter = %d, want 0", n)
	}
	if n := r.count(`SELECT count(*) FROM ctrlz.sms_deliveries WHERE source_id = $1 AND outcome = 'rejected'`, ch.ID); n != 2 {
		t.Errorf("delivery rows: %d, want 2", n)
	}
	if r.count(`SELECT count(*) FROM ctrlz.alerts`) != 0 {
		t.Error("a refused number raised an alert")
	}
	if n, pause := r.breaker(r.priID); n != 0 || pause > 0 {
		t.Errorf("a refused number counted toward the breaker: %d %v", n, pause)
	}
}

// One gateway refusing the number is not enough when the other was unreachable:
// the other might still deliver, so the row is tried again.
func TestBlacklistedByOneAndDownAtTheOtherIsRetried(t *testing.T) {
	r := newRig(t)
	r.pri.reply = func(_ int, w http.ResponseWriter) { http500(w) }
	r.fb.reply = func(_ int, w http.ResponseWriter) { meliStatus("35")(w) }
	ch := r.request(r.env.A.Phone)
	r.drain()
	if !r.deliveryCT(ch.ID) {
		t.Error("the row ended although the primary never answered")
	}
}

// An invite to a number that every gateway refuses is not retried for an hour.
func TestBlacklistedInviteEndsAtOnce(t *testing.T) {
	r := newRig(t)
	r.pri.reply = func(_ int, w http.ResponseWriter) { irStatus(115)(w) }
	r.fb.reply = func(_ int, w http.ResponseWriter) { meliStatus("35")(w) }
	id := r.queue("invite", "invite", "+989121112233", uuid.Nil, "ABCDEFGHJKMNPQRSTVWX")
	r.drain()
	state, lastErr, params := r.outbox(id)
	if state != "failed" || params || !strings.HasPrefix(lastErr, "blacklisted:") {
		t.Errorf("state %s, last error %q, params kept %v", state, lastErr, params)
	}
}

// The user consumed the code (an earlier attempt reached them although the worker
// could not record it) while the third attempt was failing. The sweep never
// refunds such a row, and the worker must not either (sms-r2-8).
func TestAConsumedCodeIsNotRefundedWhenTheLastAttemptFails(t *testing.T) {
	r := newRig(t)
	phone := r.env.A.Phone
	ch := r.request(phone)
	r.env.Exec(t, `UPDATE ctrlz.otp_challenges SET delivery_attempts = 2 WHERE id = $1`, ch.ID) // the next claim is the third
	var once sync.Once
	consume := func() {
		once.Do(func() {
			if err := r.env.DB.Exec(r.env.Ctx, `UPDATE ctrlz.otp_challenges SET consumed_at = now() WHERE id = $1`, ch.ID); err != nil {
				t.Errorf("consume: %v", err)
			}
		})
	}
	r.pri.reply = func(_ int, w http.ResponseWriter) { consume(); http500(w) }
	r.fb.reply = func(_ int, w http.ResponseWriter) { http500(w) }
	r.drain()
	if r.deliveryCT(ch.ID) {
		t.Error("the third failed attempt did not end the row")
	}
	if r.counter("phone", phone) != 1 || r.counter("global", "all") != 1 {
		t.Error("a code the user already consumed was refunded")
	}
	// The failure itself was still recorded and the breakers still count it.
	if r.count(`SELECT count(*) FROM ctrlz.sms_deliveries WHERE source_id = $1`, ch.ID) != 2 {
		t.Error("the attempts were not recorded")
	}
}
