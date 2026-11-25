package smssend_test

import (
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/authtest"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// queueNotice puts the row tenant_notice_sms makes into the outbox: kind notice, the id of the notice, no value, no
// gateway. The table refuses a notice with either (sms_outbox_notice_bare).
func (r *rig) queueNotice(template, phone string) uuid.UUID {
	r.t.Helper()
	id := uuid.Must(uuid.NewV7())
	r.env.Exec(r.t, `INSERT INTO ctrlz.sms_outbox (id, kind, phone_e164, template_key, locale) VALUES ($1, 'notice', $2, $3, 'fa')`, id, phone, template)
	return id
}

// TestANoticeIsSentWithNoValueAndRetriedForAnHour is spec 9.5 and 12.3 for the SMS of a security notice (question 19).
// The worker opens nothing for a row of kind notice and sends it with no value, through either driver and the noop
// one; it is retried like any outbox message and ended at the hour; the daily count of the outbox applies; and a row
// that carries a value, which nothing but a hand on the database can write, ends as unreadable and sends nothing.
func TestANoticeIsSentWithNoValueAndRetriedForAnHour(t *testing.T) {
	t.Run("sent, and nothing sealed is needed", func(t *testing.T) {
		r := newRig(t)
		id := r.queueNotice("notice_passkey", "+989121112233")
		r.drain()
		if state, _, params := r.outbox(id); state != "sent" || params {
			t.Fatalf("state %s, params kept %v", state, params)
		}
		if r.pri.count() != 1 || r.fb.count() != 0 {
			t.Errorf("provider calls: primary %d, fallback %d, want 1 and 0", r.pri.count(), r.fb.count())
		}
		if r.count(`SELECT count(*) FROM ctrlz.sms_deliveries WHERE source = 'outbox' AND source_id = $1 AND outcome = 'accepted' AND template_key = 'notice_passkey'`, id) != 1 {
			t.Error("no delivery row for the notice")
		}
		var dump string
		_ = r.env.DB.Scan(r.env.Ctx, `SELECT string_agg(to_jsonb(d)::text, ' ') FROM ctrlz.sms_deliveries d`, nil, &dump)
		if strings.Contains(dump, "989121112233") {
			t.Errorf("the delivery log holds a number: %s", dump)
		}
	})

	t.Run("the fallback driver sends it too", func(t *testing.T) {
		r := newRig(t)
		r.pri.reply = func(_ int, w http.ResponseWriter) { http500(w) }
		id := r.queueNotice("notice_recovery", "+989121112233")
		r.drain()
		if state, _, _ := r.outbox(id); state != "sent" || r.fb.count() != 1 {
			t.Fatalf("state %s after %d fallback calls, want sent after 1", state, r.fb.count())
		}
	})

	t.Run("the noop driver sends it", func(t *testing.T) {
		r := newRig(t)
		r.env.Exec(t, `DELETE FROM ctrlz.sms_gateways`)
		r.env.AddGateway(t, r.ring, authtest.Gateway{Provider: "noop", Role: "primary"})
		r.router.Invalidate()
		id := r.queueNotice("notice_passkey", "+989121112233")
		r.drain()
		if state, _, _ := r.outbox(id); state != "sent" {
			t.Fatalf("state %s", state)
		}
		line, err := os.ReadFile(r.noopFile)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(line), `"template":"notice_passkey"`) {
			t.Fatalf("noop received %q", line)
		}
	})

	t.Run("retried, then ended at the hour", func(t *testing.T) {
		r := newRig(t)
		r.pri.reply = func(_ int, w http.ResponseWriter) { http500(w) }
		r.fb.reply = func(_ int, w http.ResponseWriter) { http500(w) }
		id := r.queueNotice("notice_passkey", "+989121112233")
		r.drain()
		if state, _, _ := r.outbox(id); state != "pending" {
			t.Fatalf("after one failed pass: %s", state)
		}
		r.lapse()
		r.drain()
		if r.pri.count() != 2 {
			t.Errorf("provider calls after the second pass: %d, want 2", r.pri.count())
		}
		r.env.Exec(t, `UPDATE ctrlz.sms_outbox SET created_at = now() - interval '61 minutes' WHERE id = $1`, id)
		r.lapse()
		if n := r.drain(); n != 0 {
			t.Errorf("a notice past the hour was tried again: %d", n)
		}
		if err := r.worker.WithGlobal(r.env.Ctx, store.TxOpts{}, func(g store.GlobalTx) error {
			n, err := g.OutboxFailStaleBatch(1000)
			if n != 1 {
				t.Errorf("OutboxFailStale ended %d", n)
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if state, last, _ := r.outbox(id); state != "failed" || last != "timeout" {
			t.Errorf("after an hour: %s %s", state, last)
		}
	})

	t.Run("the daily count of the outbox applies", func(t *testing.T) {
		r := newRig(t)
		r.env.Exec(t, `UPDATE ctrlz.system_settings SET sms_outbox_cap_daily = 1`)
		a := r.queueNotice("notice_passkey", "+989121112233")
		r.drain()
		b := r.queueNotice("notice_passkey", "+989121112244")
		r.drain()
		if state, _, _ := r.outbox(a); state != "sent" {
			t.Errorf("first: %s", state)
		}
		if state, last, _ := r.outbox(b); state != "failed" || last != "cap" {
			t.Errorf("over the cap: %s %s", state, last)
		}
		if r.pri.count() != 1 {
			t.Errorf("a capped notice was sent: %d provider calls", r.pri.count())
		}
	})

	t.Run("a notice that carries a value is unreadable", func(t *testing.T) {
		r := newRig(t)
		id := r.queueNotice("notice_passkey", "+989121112233")
		// The CHECK keeps this out of the table for a notice; take it away for the length of the write, as a hand on the
		// database would.
		r.env.Exec(t, `ALTER TABLE ctrlz.sms_outbox DROP CONSTRAINT sms_outbox_notice_bare`)
		r.env.Exec(t, `UPDATE ctrlz.sms_outbox SET params_ct = '\x0102' WHERE id = $1`, id)
		r.drain()
		if state, last, params := r.outbox(id); state != "failed" || last != "unreadable" || params {
			t.Errorf("state %s last %s params kept %v", state, last, params)
		}
		if r.pri.count() != 0 || r.fb.count() != 0 {
			t.Errorf("a notice with a value was sent: %d and %d calls", r.pri.count(), r.fb.count())
		}
	})
}
