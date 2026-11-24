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
