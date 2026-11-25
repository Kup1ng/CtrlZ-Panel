package catalogtest_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/migrate"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store/catalogtest"
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

// TestMigration0064AdvisesAnActionThatEvictsAndKeepsAnOperatorsEdit is review dec-c-r2-3 on an installed database: the
// four notice bodies of 0062 are replaced by the ones that name an action that puts a thief out (Forgot password for a
// passkey, new codes for the recovery codes), and only WHILE a row still holds the 0062 text, so a body the operator
// edited on the SMS page is never overwritten. Running the migration's updates again changes nothing.
func TestMigration0064AdvisesAnActionThatEvictsAndKeepsAnOperatorsEdit(t *testing.T) {
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

	if _, err := migrate.UpTo(ctx, db, 63); err != nil {
		t.Fatal(err)
	}
	body := func(key, locale string) string {
		t.Helper()
		var b string
		if err := super.QueryRow(ctx, `SELECT body FROM ctrlz.sms_templates WHERE key = $1 AND locale = $2`, key, locale).Scan(&b); err != nil {
			t.Fatalf("%s/%s: %v", key, locale, err)
		}
		return b
	}
	if !strings.Contains(body("notice_passkey", "en"), "change your password") {
		t.Fatal("the premise is gone: 0062 no longer says change your password")
	}
	const custom = "متن ویرایش‌شده توسط اپراتور"
	if _, err := super.Exec(ctx, `UPDATE ctrlz.sms_templates SET body = $1 WHERE key = 'notice_recovery' AND locale = 'fa'`, custom); err != nil {
		t.Fatal(err)
	}

	if _, err := migrate.UpTo(ctx, db, 64); err != nil {
		t.Fatalf("0064: %v", err)
	}
	if got := body("notice_passkey", "fa"); !strings.Contains(got, "بازیابی") || strings.Contains(got, "عوض") {
		t.Errorf("the Persian passkey notice: %q", got)
	}
	if got := body("notice_passkey", "en"); !strings.Contains(got, "forgot password") || strings.Contains(got, "change your password") {
		t.Errorf("the English passkey notice: %q", got)
	}
	if got := body("notice_recovery", "en"); !strings.Contains(got, "make new codes") {
		t.Errorf("the English recovery notice: %q", got)
	}
	if got := body("notice_recovery", "fa"); got != custom {
		t.Errorf("an operator's edit was overwritten: %q", got)
	}
	var n int
	if err := super.QueryRow(ctx, `SELECT count(*) FROM ctrlz.sms_templates WHERE key IN ('notice_passkey', 'notice_recovery')`).Scan(&n); err != nil || n != 4 {
		t.Errorf("%d notice templates, want 4: %v", n, err)
	}
}

// TestTheNoticeCapIsCountedForTheAccountItTells is review dec-c-r2-5. The message goes to one user's phone and the
// lock that makes the count exact is that user's row lock, so the audit rows counted are that user's: a member who
// added three passkeys of their own has spent nothing of another member's, and the cap still holds for the member who
// reached it. Tenant B has the same activity and none of it counts for A (two tenants). v1 has one user per tenant
// (users_one_owner_uq, D32), so the test lifts that index inside a transaction that is rolled back: the function is
// written for the day members exist, and the day must not find it counting the wrong rows.
func TestTheNoticeCapIsCountedForTheAccountItTells(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	tx, err := h.super.Begin(h.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := tx.Exec(h.ctx, sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	exec(`DROP INDEX ctrlz.users_one_owner_uq`)
	for _, s := range []catalogtest.SeedIDs{h.A, h.B} {
		exec(`UPDATE ctrlz.users SET phone_verified_at = now() WHERE id = $1`, s.User)
	}
	other := uuid.Must(uuid.NewV7()) // a second member of tenant A
	exec(`INSERT INTO ctrlz.users (tenant_id, id, phone_e164, password_hash, phone_verified_at) VALUES ($1, $2, '+989139990001', 'argon2id$seed', now())`, h.A.Tenant, other)
	// The first member added three passkeys today, and so did B's user.
	for _, s := range []catalogtest.SeedIDs{h.A, h.B} {
		for i := 0; i < 3; i++ {
			exec(`INSERT INTO ctrlz.tenant_audit_log (tenant_id, user_id, action) VALUES ($1, $2, 'passkey.add')`, s.Tenant, s.User)
		}
	}
	ask := func(tenant, user uuid.UUID) bool {
		t.Helper()
		exec("SET LOCAL ROLE ctrlz_tenant")
		defer exec("RESET ROLE")
		exec("SELECT pg_catalog.set_config('ctrlz.tenant_id', $1, true)", tenant.String())
		var notice uuid.UUID
		if err := tx.QueryRow(h.ctx, `INSERT INTO ctrlz.notifications (tenant_id, kind, severity) VALUES ($1, 'passkey_added', 'info') RETURNING id`, tenant).Scan(&notice); err != nil {
			t.Fatal(err)
		}
		exec(`INSERT INTO ctrlz.tenant_audit_log (tenant_id, user_id, action) VALUES ($1, $2, 'passkey.add')`, tenant, user)
		var queued bool
		if err := tx.QueryRow(h.ctx, `SELECT ctrlz_fn.tenant_notice_sms($1, $2, 3)`, user, notice).Scan(&queued); err != nil {
			t.Fatal(err)
		}
		return queued
	}
	// The other member's first passkey is told, although the tenant already has three of the first member's today.
	if !ask(h.A.Tenant, other) {
		t.Error("a member's first passkey of the day was not told because another member spent the messages")
	}
	// The first member's fourth is past the cap of three for that account.
	if ask(h.A.Tenant, h.A.User) {
		t.Error("a fourth message to one phone in a day was queued")
	}
	// B's user is in the same state, and A's activity does not touch it.
	if ask(h.B.Tenant, h.B.User) {
		t.Error("B's fourth message was queued")
	}
}
