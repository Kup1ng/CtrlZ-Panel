package api

import (
	"encoding/base32"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
)

// enrolTOTP does the whole set-up of an authenticator app from a session: reauth with the password, setup, confirm.
// It returns the seed and the recovery codes the confirm shows.
func (c *client) enrolTOTP(tenant uuid.UUID, pw string) (secret.Bytes, []string) {
	c.f.t.Helper()
	c.f.ck.add(time.Minute) // the sensitive rate class of the steps below
	c.f.clearThrottle()
	c.reauthPassword(pw).want(204, "")
	var setup struct {
		Secret string `json:"secret"`
	}
	c.post("/account/totp/setup", nil).want(200, "").json(&setup)
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(setup.Secret)
	if err != nil {
		c.f.t.Fatalf("setup secret: %v", err)
	}
	seed := secret.NewBytes(raw)
	c.f.freeStep(tenant)
	var done struct {
		Codes []string `json:"recovery_codes"`
	}
	c.post("/account/totp/confirm", map[string]any{"code": codeAt(seed, time.Now()), "saved": true}).want(200, "").json(&done)
	if len(done.Codes) != 10 {
		c.f.t.Fatalf("the confirm showed %d recovery codes, want 10", len(done.Codes))
	}
	return seed, done.Codes
}

// disableTOTP is the reauth with a code and the disable route, for an account whose authenticator is on.
func (c *client) disableTOTP(tenant uuid.UUID, pw string, seed secret.Bytes) {
	c.f.t.Helper()
	c.f.ck.add(time.Minute)
	c.f.clearThrottle()
	c.f.freeStep(tenant)
	c.post("/auth/reauth", map[string]any{"password": pw, "totp_code": codeAt(seed, time.Now())}).want(204, "")
	c.post("/account/totp/disable", nil).want(200, "")
}

// TestTheConfirmAfterADisableIsARegenerationOfTheCodes is review dec-c-r3-2 and decision D70 (spec 12.3). An account
// that disables its authenticator and sets it up again gets a new set of recovery codes, and a thief with a session
// and the password reaches the same end as through the regeneration route. So the confirm of an account that had
// codes before writes the security notice recovery_codes_regenerated, the audit row recovery.regenerate and one
// notice SMS, in the transaction of the codes, and the session that made the change cannot mark the notice read. The
// first enrolment of an account that never had codes makes none of them. The daily cap counts the confirm once: two
// regenerations are already counted when the confirm comes, it is the third and is sent, and the fourth is capped.
// Tenant B, whose own enrolment and disable are in the log, is not told anything by A's, and B's first enrolment
// beside them is still a first one.
func TestTheConfirmAfterADisableIsARegenerationOfTheCodes(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A, B := f.env.A, f.env.B
	f.env.Exec(t, `DELETE FROM ctrlz.sms_outbox`) // the seed's test row
	f.env.Exec(t, `UPDATE ctrlz.users SET phone_verified_at = now() WHERE id = $1`, A.User)
	f.env.Exec(t, `UPDATE ctrlz.users SET phone_verified_at = now() WHERE id = $1`, B.User)

	notices := func(tenant uuid.UUID) int {
		return f.count(`SELECT count(*) FROM ctrlz.notifications WHERE tenant_id = $1 AND kind = 'recovery_codes_regenerated'`, tenant)
	}
	messages := func(phone string) int {
		return f.count(`SELECT count(*) FROM ctrlz.sms_outbox WHERE kind = 'notice' AND template_key = 'notice_recovery' AND phone_e164 = $1 AND params_ct IS NULL AND gateway_id IS NULL`, phone)
	}
	audits := func(user uuid.UUID, action string) int {
		return f.count(`SELECT count(*) FROM ctrlz.tenant_audit_log WHERE user_id = $1 AND action = $2`, user, action)
	}

	a, b := f.client(), f.client()
	a.mustLogin(A.Phone, pwA)
	b.mustLogin(B.Phone, pwB)

	// Tenant B first: an enrolment and a disable that leave rows in the log. They must not make A's first enrolment
	// a regeneration, and B's own first enrolment, before them, told nobody.
	seedB, _ := b.enrolTOTP(B.Tenant, pwB)
	if notices(B.Tenant) != 0 || messages(B.Phone) != 0 || audits(B.User, "recovery.regenerate") != 0 {
		t.Fatal("the first enrolment of B made a notice, a message or a regeneration row")
	}
	b.disableTOTP(B.Tenant, pwB, seedB)

	// The first enrolment of A: no notice, no message, no regeneration row, ten codes, one totp.enable row.
	seedA, _ := a.enrolTOTP(A.Tenant, pwA)
	if notices(A.Tenant) != 0 || messages(A.Phone) != 0 || audits(A.User, "recovery.regenerate") != 0 {
		t.Fatalf("the first enrolment of A made %d notices, %d messages, %d regeneration rows, want none", notices(A.Tenant), messages(A.Phone), audits(A.User, "recovery.regenerate"))
	}
	if audits(A.User, "totp.enable") != 1 {
		t.Fatalf("%d totp.enable rows after the first enrolment, want 1", audits(A.User, "totp.enable"))
	}

	// Two regenerations of the day are already counted (the cap is three), so a confirm that counted itself twice
	// would be capped and one that counts once is the third and goes out.
	for i := 0; i < 2; i++ {
		f.env.Exec(t, `INSERT INTO ctrlz.tenant_audit_log (tenant_id, user_id, action) VALUES ($1, $2, 'recovery.regenerate')`, A.Tenant, A.User)
	}

	// The thief's path: disable, set up, confirm.
	a.disableTOTP(A.Tenant, pwA, seedA)
	if notices(A.Tenant) != 0 {
		t.Fatal("the disable made a recovery notice")
	}
	seedA, _ = a.enrolTOTP(A.Tenant, pwA)
	if n := notices(A.Tenant); n != 1 {
		t.Fatalf("%d recovery_codes_regenerated notices after a disable and a confirm, want 1", n)
	}
	if n := audits(A.User, "recovery.regenerate"); n != 3 {
		t.Fatalf("%d recovery.regenerate rows, want the 2 of the day and this one", n)
	}
	if n := audits(A.User, "totp.enable"); n != 2 {
		t.Fatalf("%d totp.enable rows, want the first enrolment and this confirm", n)
	}
	n1 := f.noticeID(A.Tenant, "recovery_codes_regenerated")
	var id, tmpl, locale, phone string
	f.env.Scan(t, `SELECT id::text, template_key, locale, phone_e164 FROM ctrlz.sms_outbox WHERE phone_e164 = $1`, []any{A.Phone}, &id, &tmpl, &locale, &phone)
	if id != n1 || tmpl != "notice_recovery" || messages(A.Phone) != 1 {
		t.Fatalf("outbox row %s %s, want the notice %s as notice_recovery, once", id, tmpl, n1)
	}

	// The session that did it cannot hide it, after the rotation the confirm made.
	if got := a.notices("").SecurityItems; len(got) != 1 || got[0].ID != n1 || got[0].Markable {
		t.Fatalf("the session that confirmed sees %+v, want the notice, not markable", got)
	}
	a.post("/notifications/"+n1+"/read", nil).want(409, "conflict")
	if !f.unreadNotice(n1) {
		t.Fatal("the session that confirmed marked its own notice")
	}
	// A session made after the notice, which the owner opens with the new authenticator, can.
	f.ck.add(time.Minute)
	f.clearThrottle()
	owner := f.client()
	owner.mustLoginTOTP(A.Phone, pwA, seedA, f)
	if got := owner.notices("").SecurityItems; len(got) != 1 || got[0].ID != n1 || !got[0].Markable {
		t.Fatalf("the owner's later session sees %+v, want the notice, markable", got)
	}
	owner.post("/notifications/"+n1+"/read", nil).want(204, "")

	// The fourth regeneration of the day: the notice is written and nothing is sent.
	a.disableTOTP(A.Tenant, pwA, seedA)
	a.enrolTOTP(A.Tenant, pwA)
	if n := notices(A.Tenant); n != 2 {
		t.Fatalf("%d notices after the second confirm, want 2", n)
	}
	if n := messages(A.Phone); n != 1 {
		t.Fatalf("%d messages after the capped confirm, want the one of before", n)
	}

	// Tenant B was told nothing, and nothing of A's reached its rows.
	if n := notices(B.Tenant); n != 0 {
		t.Fatalf("B has %d recovery notices", n)
	}
	if n := messages(B.Phone); n != 0 {
		t.Fatalf("B's phone was sent %d messages", n)
	}
	if n := audits(B.User, "recovery.regenerate"); n != 0 {
		t.Fatalf("B has %d regeneration rows", n)
	}
	if got := b.notices("").SecurityItems; len(got) != 0 {
		t.Fatalf("B sees the security notices %+v", got)
	}
}

// TestTheSourceOfWhatTheConfirmReplaces isolates each part of the rule "the account had recovery codes before"
// (review totp-r1-1, totp-r1-2, D70): each case leaves exactly one kind of evidence behind, so removing that part of
// the query, or the user filter, fails it. The evidence is the codes themselves, the totp.disable row, and the
// totp.enable row. The case with none of them is a first enrolment and tells nobody, and the history of another
// account in the same tenant does not make an account's first enrolment a regeneration. The tests set the state with
// the superuser connection, the way the operator path and the retention sweep leave it: the operator's declare-lost
// clears the seed and keeps the codes, and the sweep deletes audit rows past 365 days.
func TestTheSourceOfWhatTheConfirmReplaces(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A := f.env.A
	f.env.Exec(t, `UPDATE ctrlz.users SET phone_verified_at = now() WHERE id = $1`, A.User)
	a := f.client()
	a.mustLogin(A.Phone, pwA)

	notices := func() int {
		return f.count(`SELECT count(*) FROM ctrlz.notifications WHERE tenant_id = $1 AND kind = 'recovery_codes_regenerated'`, A.Tenant)
	}
	// Each case counts its own notice: the unread notice of the one before is not a reason to write or not to write.
	forget := func() { f.env.Exec(t, `DELETE FROM ctrlz.notifications WHERE tenant_id = $1`, A.Tenant) }
	dropAudit := func(actions ...string) {
		for _, act := range actions {
			f.env.Exec(t, `DELETE FROM ctrlz.tenant_audit_log WHERE tenant_id = $1 AND user_id = $2 AND action = $3`, A.Tenant, A.User, act)
		}
	}
	dropCodes := func() {
		f.env.Exec(t, `DELETE FROM ctrlz.recovery_codes WHERE tenant_id = $1 AND user_id = $2`, A.Tenant, A.User)
	}
	// declareLost is what keytool_totp_declare_lost does to the user row: the seed goes, the codes stay.
	declareLost := func() {
		f.env.Exec(t, `UPDATE ctrlz.users SET totp_secret_ct = NULL, totp_enabled_at = NULL, totp_last_step = NULL, totp_pending_at = NULL
			WHERE tenant_id = $1 AND id = $2`, A.Tenant, A.User)
	}
	want := func(name string, n int) {
		t.Helper()
		if got := notices(); got != n {
			t.Fatalf("%s: %d recovery_codes_regenerated notices, want %d", name, got, n)
		}
		forget()
	}

	// The history of another account of the tenant (and of a user id that never existed) is not this account's.
	other := uuid.New()
	for _, act := range []string{"totp.enable", "totp.disable"} {
		f.env.Exec(t, `INSERT INTO ctrlz.tenant_audit_log (tenant_id, user_id, action) VALUES ($1, $2, $3)`, A.Tenant, other, act)
	}
	seed, _ := a.enrolTOTP(A.Tenant, pwA)
	want("a first enrolment beside another account's history", 0)

	// Only the disable row remains: the enrolment it ended is gone from the log (swept, or never recorded), and the
	// codes were deleted by the disable. A thief who disables and confirms is told on this row alone.
	a.disableTOTP(A.Tenant, pwA, seed)
	dropAudit("totp.enable")
	if n := f.count(`SELECT count(*) FROM ctrlz.recovery_codes WHERE user_id = $1`, A.User); n != 0 {
		t.Fatalf("%d recovery codes after the disable, want none", n)
	}
	seed, _ = a.enrolTOTP(A.Tenant, pwA)
	want("only the totp.disable row", 1)

	// Only the totp.enable row remains: no codes, no disable row, the seed cleared.
	dropCodes()
	dropAudit("totp.disable")
	declareLost()
	seed, _ = a.enrolTOTP(A.Tenant, pwA)
	want("only the totp.enable row", 1)

	// Only the codes remain: an operator declared the key lost and the enrolment is older than the retention, so the
	// log holds neither action. The codes still work, and the confirm replaces them.
	dropAudit("totp.enable", "totp.disable")
	declareLost()
	seed, _ = a.enrolTOTP(A.Tenant, pwA)
	want("only the recovery codes", 1)

	// Nothing remains: the account has no codes and the log has no trace of any, which is a first enrolment.
	dropCodes()
	dropAudit("totp.enable", "totp.disable")
	declareLost()
	a.enrolTOTP(A.Tenant, pwA)
	want("nothing left of an earlier set", 0)
}
