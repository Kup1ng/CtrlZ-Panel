package catalogtest_test

import (
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

// Review round 4, sms-r4-7. The worker applies the daily outbox cap on the first
// claim of a message and recognises that claim by attempts = 1, so a row that
// arrives with attempts already above 0 would be sent without being counted.
// ctrlz_admin may insert only the columns the admin code writes; everything that
// carries the queue's own bookkeeping takes its default.
func TestAdminCannotPresetTheOutboxBookkeeping(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	base := `INSERT INTO ctrlz.sms_outbox (kind, phone_e164, template_key, locale, params_ct`
	for _, c := range []struct{ name, sql string }{
		{"attempts", base + `, attempts) VALUES ('invite', '+989121112233', 'invite', 'fa', '\x01', 1)`},
		{"state", base + `, state) VALUES ('invite', '+989121112233', 'invite', 'fa', '\x01', 'sent')`},
		{"claimed_until", base + `, claimed_until) VALUES ('invite', '+989121112233', 'invite', 'fa', '\x01', now())`},
		{"created_at", base + `, created_at) VALUES ('invite', '+989121112233', 'invite', 'fa', '\x01', now() - interval '1 day')`},
		{"last_error", base + `, last_error) VALUES ('invite', '+989121112233', 'invite', 'fa', '\x01', 'x')`},
		{"sent_at", base + `, sent_at) VALUES ('invite', '+989121112233', 'invite', 'fa', '\x01', now())`},
	} {
		if !h.denied("admin", nil, c.sql) {
			t.Errorf("ctrlz_admin could preset sms_outbox.%s", c.name)
		}
	}
	// What the admin code really writes still works, and lands at attempts 0. The
	// transaction rolls back, so the row is read back as the admin (it may select
	// these columns).
	h.inTx(h.super, "admin", nil, func(tx pgx.Tx) {
		var id string
		if err := tx.QueryRow(h.ctx, base+`) VALUES ('invite', '+989121112233', 'invite', 'fa', '\x01') RETURNING id::text`).Scan(&id); err != nil {
			t.Fatalf("the admin insert of an ordinary message: %v", err)
		}
		var attempts int
		var state string
		if err := tx.QueryRow(h.ctx, `SELECT attempts, state FROM ctrlz.sms_outbox WHERE id = $1::uuid`, id).Scan(&attempts, &state); err != nil {
			t.Fatal(err)
		}
		if attempts != 0 || state != "pending" {
			t.Errorf("an admin-queued message started at attempts=%d state=%s", attempts, state)
		}
	})
}
