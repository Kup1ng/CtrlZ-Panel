package catalogtest_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/migrate"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

// TestMigration0062LeavesNoInviteMessage is D67 and question 19 on an installed database: the one migration runs on
// rows a real install could hold. An invite is never sent by SMS, so every outbox row of kind invite goes (the waiting
// ones too: a worker that holds one finds no row to finish), both of its templates go, and nothing else of the
// operator's work is touched: another kind's rows, an edited body of another key and the provider mapping of another
// key stay. The kind column then takes only notice and test, and a notice is bare: no value, no gateway, and one of
// the two templates, so the application cannot make a notice that opens a sealed value.
func TestMigration0062LeavesNoInviteMessage(t *testing.T) {
	c := testpg.Need(t, cluster)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	d := c.NewEmptyDB(ctx, t)
	db, err := d.MigratorDB()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	super, err := d.Super(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer super.Close(context.Background())

	if _, err := migrate.UpTo(ctx, db, 59); err != nil {
		t.Fatal(err)
	}
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := super.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	count := func(sql string, args ...any) int {
		t.Helper()
		var n int
		if err := super.QueryRow(ctx, sql, args...).Scan(&n); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
		return n
	}
	exec(`INSERT INTO ctrlz.sms_gateways (id, provider, role) VALUES ('00000000-0000-7000-8000-0000000000f1', 'noop', 'primary')`)
	exec(`INSERT INTO ctrlz.sms_outbox (kind, phone_e164, template_key, locale, params_ct, state) VALUES
		('invite', '+989121110001', 'invite', 'fa', '\x01', 'pending'),
		('invite', '+989121110002', 'invite', 'fa', NULL, 'sent'),
		('invite', '+989121110003', 'invite', 'en', NULL, 'failed'),
		('test', '+989121110004', 'otp', 'fa', '\x01', 'pending')`)
	exec(`INSERT INTO ctrlz.sms_provider_templates (gateway_id, key, locale, provider_template_id, param_names) VALUES
		('00000000-0000-7000-8000-0000000000f1', 'invite', 'fa', '11', '{CODE}'),
		('00000000-0000-7000-8000-0000000000f1', 'otp', 'fa', '12', '{CODE}')`)
	const custom = "متن ویرایش‌شده توسط اپراتور {code}"
	exec(`UPDATE ctrlz.sms_templates SET body = $1 WHERE key = 'otp' AND locale = 'fa'`, custom)
	exec(`INSERT INTO ctrlz.sms_deliveries (source, source_id, provider, template_key, outcome) VALUES ('outbox', gen_random_uuid(), 'noop', 'invite', 'accepted')`)

	if _, err := migrate.UpTo(ctx, db, 62); err != nil {
		t.Fatalf("0062: %v", err)
	}

	if n := count(`SELECT count(*) FROM ctrlz.sms_outbox WHERE kind = 'invite'`); n != 0 {
		t.Errorf("%d outbox rows of kind invite are left", n)
	}
	if n := count(`SELECT count(*) FROM ctrlz.sms_outbox WHERE kind = 'test' AND phone_e164 = '+989121110004' AND params_ct IS NOT NULL`); n != 1 {
		t.Errorf("the test send of another kind was touched: %d", n)
	}
	if n := count(`SELECT count(*) FROM ctrlz.sms_templates WHERE key = 'invite'`); n != 0 {
		t.Errorf("%d invite templates are left", n)
	}
	if n := count(`SELECT count(*) FROM ctrlz.sms_provider_templates WHERE key = 'invite'`); n != 0 {
		t.Errorf("%d invite provider mappings are left", n)
	}
	if n := count(`SELECT count(*) FROM ctrlz.sms_provider_templates WHERE key = 'otp'`); n != 1 {
		t.Errorf("the provider mapping of another key was touched: %d rows", n)
	}
	var body string
	if err := super.QueryRow(ctx, `SELECT body FROM ctrlz.sms_templates WHERE key = 'otp' AND locale = 'fa'`).Scan(&body); err != nil || body != custom {
		t.Errorf("the edited body of another key was changed: %q %v", body, err)
	}
	if n := count(`SELECT count(*) FROM ctrlz.sms_templates WHERE key IN ('notice_passkey', 'notice_recovery')`); n != 4 {
		t.Errorf("%d notice templates, want the four of spec 9.4", n)
	}
	if n := count(`SELECT count(*) FROM ctrlz.sms_deliveries WHERE template_key = 'invite'`); n != 1 {
		t.Errorf("the delivery history was touched: %d rows", n)
	}
	if n := count(`SELECT count(*) FROM pg_indexes WHERE schemaname = 'ctrlz' AND indexname = 'refresh_tokens_session_idx'`); n != 1 {
		t.Error("the index of the live rule is missing")
	}

	// The table now refuses what the application can no longer make.
	refused := func(what, constraint, sql string, args ...any) {
		t.Helper()
		_, err := super.Exec(ctx, sql, args...)
		if err == nil || !strings.Contains(err.Error(), constraint) {
			t.Errorf("%s: %v, want a refusal by %s", what, err, constraint)
		}
	}
	refused("a message of kind invite", "sms_outbox_kind_check",
		`INSERT INTO ctrlz.sms_outbox (kind, phone_e164, template_key, locale) VALUES ('invite', '+989121110005', 'otp', 'fa')`)
	refused("a notice that carries a value", "sms_outbox_notice_bare",
		`INSERT INTO ctrlz.sms_outbox (kind, phone_e164, template_key, locale, params_ct) VALUES ('notice', '+989121110005', 'notice_passkey', 'fa', '\x01')`)
	refused("a notice pinned to a gateway", "sms_outbox_notice_bare",
		`INSERT INTO ctrlz.sms_outbox (kind, gateway_id, phone_e164, template_key, locale) VALUES ('notice', '00000000-0000-7000-8000-0000000000f1', '+989121110005', 'notice_passkey', 'fa')`)
	refused("a notice with the template of a code", "sms_outbox_notice_bare",
		`INSERT INTO ctrlz.sms_outbox (kind, phone_e164, template_key, locale) VALUES ('notice', '+989121110005', 'otp', 'fa')`)
	exec(`INSERT INTO ctrlz.sms_outbox (kind, phone_e164, template_key, locale) VALUES ('notice', '+989121110005', 'notice_recovery', 'en')`)
}
