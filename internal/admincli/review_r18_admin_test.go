package admincli_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms"
)

// plantPending plants what PUT /sms/gateways/sms_ir leaves behind for a gateway that has active
// credentials: the owner's in credentials_ct, the new ones, with their hint, in the pending pair.
func plantPending(t *testing.T, r *rig, hint string) (active, pending []byte) {
	t.Helper()
	gw := uuid.New()
	var err error
	if active, err = sms.SealCredentials(r.keys, gw, "sms_ir", secret.NewBytes([]byte(`{"api_key":"owner-key-1111"}`))); err != nil {
		t.Fatal(err)
	}
	if pending, err = sms.SealCredentials(r.keys, gw, "sms_ir", secret.NewBytes([]byte(`{"api_key":"new-key-2222"}`))); err != nil {
		t.Fatal(err)
	}
	r.env.ResetSMS(t)
	r.env.Exec(t, `INSERT INTO ctrlz.sms_gateways (id, provider, role, credentials_ct, hint, credentials_pending_ct, pending_hint)
VALUES ($1, 'sms_ir', 'primary', $2, '1111', $3, $4)`, gw, active, pending, hint)
	return active, pending
}

// TestSMSConfirmIsTheOnlyWayToActivatePendingCredentials is the console half of admin-r18-1: pending
// credentials carry nothing, the console lists them without a secret, refuses a confirmation that does
// not name the pending hint (a PUT that landed after the operator read it), and promotes exactly the
// pair it was shown, with its audit row in the same transaction.
func TestSMSConfirmIsTheOnlyWayToActivatePendingCredentials(t *testing.T) {
	r := newRig(t)
	active, pending := plantPending(t, r, "2222")
	activeNow := func() []byte {
		var ct []byte
		r.env.Scan(t, `SELECT credentials_ct FROM ctrlz.sms_gateways WHERE provider = 'sms_ir'`, nil, &ct)
		return ct
	}

	if code := r.run("sms", "pending"); code != 0 || !strings.Contains(r.out.String(), `hint "2222"`) || !strings.Contains(r.out.String(), "replace the active credentials") {
		t.Fatalf("pending: exit %d, %q", code, r.out.String())
	}
	if strings.Contains(r.out.String()+r.errb.String(), "new-key-2222") || strings.Contains(r.out.String(), string(pending)) {
		t.Fatal("pending shows a credential")
	}

	// A usage error and a wrong hint change nothing and write no row.
	rows := r.count(`SELECT count(*) FROM ctrlz.audit_log`)
	for _, args := range [][]string{
		{"sms", "confirm", "sms_ir"},                        // the hint is required
		{"sms", "confirm", "noop", "--hint", "2222"},        // no credentials to confirm
		{"sms", "confirm", "--hint", "2222"},                // no provider
		{"sms", "confirm", "sms_ir", "--hint", "9999"},      // not the pending pair
		{"sms", "confirm", "melipayamak", "--hint", "2222"}, // nothing pending there
		{"sms", "confirm", "sms_ir", "melipayamak", "--hint", "2222"},
	} {
		if code := r.run(args...); code == 0 {
			t.Fatalf("%v succeeded", args)
		}
		if !bytes.Equal(activeNow(), active) || r.count(`SELECT count(*) FROM ctrlz.audit_log`) != rows {
			t.Fatalf("%v changed the gateway or wrote a row", args)
		}
	}

	if code := r.run("sms", "confirm", "sms_ir", "--hint", "2222"); code != 0 {
		t.Fatalf("confirm: exit %d, %q", code, r.errb.String())
	}
	if !bytes.Equal(activeNow(), pending) {
		t.Fatal("the pending credentials did not become the active ones")
	}
	var left int
	var hint string
	r.env.Scan(t, `SELECT (credentials_pending_ct IS NOT NULL)::int, hint FROM ctrlz.sms_gateways WHERE provider = 'sms_ir'`, nil, &left, &hint)
	if left != 0 || hint != "2222" {
		t.Fatalf("pending left %d, hint %q", left, hint)
	}
	if n := r.count(`SELECT count(*) FROM ctrlz.audit_log WHERE action = 'sms.gateway_change' AND params->'fields' ? 'credentials_confirmed'`); n != 1 {
		t.Fatalf("%d confirmation rows", n)
	}
	// It is once: nothing pends now.
	if code := r.run("sms", "confirm", "sms_ir", "--hint", "2222"); code == 0 {
		t.Fatal("a second confirmation succeeded")
	}
	if code := r.run("sms", "pending"); code != 0 || !strings.Contains(r.out.String(), "no gateway credentials wait") {
		t.Fatalf("pending after: %d %q", code, r.out.String())
	}
}

// TestRekeyAlsoReSealsPendingCredentials: a pending value is sealed under sms_cred like the active one,
// so a rekey that skipped it would strand it when the old key line is removed (admin-r18-1, rule
// key-identity), and `keys status` counts it.
func TestRekeyAlsoReSealsPendingCredentials(t *testing.T) {
	r := newRig(t)
	old := seedRekey(t, r)
	gw := uuid.New()
	for _, c := range []struct{ col, plain string }{{"credentials_ct", `{"api_key":"a-1234567"}`}, {"credentials_pending_ct", `{"api_key":"p-7654321"}`}} {
		ct, err := sms.SealCredentials(old, gw, "sms_ir", secret.NewBytes([]byte(c.plain)))
		if err != nil {
			t.Fatal(err)
		}
		if c.col == "credentials_ct" {
			r.env.ResetSMS(t)
			r.env.Exec(t, `INSERT INTO ctrlz.sms_gateways (id, provider, role, credentials_ct) VALUES ($1, 'sms_ir', 'primary', $2)`, gw, ct)
		} else {
			r.env.Exec(t, `UPDATE ctrlz.sms_gateways SET credentials_pending_ct = $2, pending_hint = '4321' WHERE id = $1`, gw, ct)
		}
	}
	if code := r.run("keys", "status", "sms_cred"); code != 0 || !strings.Contains(r.out.String(), "credentials_pending_ct") {
		t.Fatalf("status: %d %q", code, r.out.String())
	}
	if code := r.run("rekey", "sms_cred"); code != 0 || !strings.Contains(r.out.String(), "2 rewritten") {
		t.Fatalf("rekey: %d %q %q", code, r.out.String(), r.errb.String())
	}
	var active, pending []byte
	r.env.Scan(t, `SELECT credentials_ct, credentials_pending_ct FROM ctrlz.sms_gateways WHERE id = $1`, []any{gw}, &active, &pending)
	for name, ct := range map[string][]byte{"active": active, "pending": pending} {
		if _, err := sms.OpenCredentials(r.keys, gw, "sms_ir", ct); err != nil {
			t.Errorf("the %s credentials do not open under the newest ring after a rekey: %v", name, err)
		}
	}
}

// TestConfirmCommitsWithItsAuditRowOrNotAtAll (round 18 fix gate, admin-r18-22): new_machinery says the
// activation and its audit row are one transaction. The row's insert is made to fail (a trigger that stands for a
// database fault at that statement); the console exits with an error, the pending pair is still pending, the
// active credentials are the owner's byte for byte and no row was written. With the fault gone the same command
// activates, so the refusal was the fault and not the hint.
func TestConfirmCommitsWithItsAuditRowOrNotAtAll(t *testing.T) {
	r := newRig(t)
	active, pending := plantPending(t, r, "2222")
	r.env.Exec(t, `CREATE FUNCTION ctrlz.test_fail_confirm_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
	  IF NEW.action = 'sms.gateway_change' THEN RAISE EXCEPTION 'injected fault'; END IF; RETURN NEW; END $$`)
	r.env.Exec(t, `CREATE TRIGGER test_fail_confirm_audit BEFORE INSERT ON ctrlz.audit_log FOR EACH ROW EXECUTE FUNCTION ctrlz.test_fail_confirm_audit()`)
	rows := r.count(`SELECT count(*) FROM ctrlz.audit_log`)
	if code := r.run("sms", "confirm", "sms_ir", "--hint", "2222"); code == 0 {
		t.Fatal("the confirmation succeeded although its audit row could not be written")
	}
	var ct, pend []byte
	r.env.Scan(t, `SELECT credentials_ct, credentials_pending_ct FROM ctrlz.sms_gateways WHERE provider = 'sms_ir'`, nil, &ct, &pend)
	if !bytes.Equal(ct, active) || !bytes.Equal(pend, pending) {
		t.Fatal("the activation committed without its audit row, or the pending pair was lost")
	}
	if n := r.count(`SELECT count(*) FROM ctrlz.audit_log`); n != rows {
		t.Fatalf("%d audit rows, want %d", n, rows)
	}
	if strings.Contains(r.out.String()+r.errb.String(), "injected") {
		t.Fatal("the database's error text reached the operator's output")
	}
	r.env.Exec(t, `DROP TRIGGER test_fail_confirm_audit ON ctrlz.audit_log`)
	if code := r.run("sms", "confirm", "sms_ir", "--hint", "2222"); code != 0 {
		t.Fatalf("the repeat without the fault: exit %d, %q", code, r.errb.String())
	}
	r.env.Scan(t, `SELECT credentials_ct FROM ctrlz.sms_gateways WHERE provider = 'sms_ir'`, nil, &ct)
	if !bytes.Equal(ct, pending) {
		t.Fatal("the repeat did not activate the pending credentials")
	}
}

// TestSMSDiscardDropsThePendingPairAndKeepsTheActiveOne is the console half of db-r19-2: a PUT refuses a
// second pending pair, so the owner needs a way to free the gateway that a thief (or a typo) filled. It
// drops the pending pair only, writes its row in the same transaction, and a confirmation after it has
// nothing to promote.
func TestSMSDiscardDropsThePendingPairAndKeepsTheActiveOne(t *testing.T) {
	r := newRig(t)
	active, _ := plantPending(t, r, "2222")
	rows := r.count(`SELECT count(*) FROM ctrlz.audit_log`)
	for _, args := range [][]string{
		{"sms", "discard"},
		{"sms", "discard", "noop"},
		{"sms", "discard", "melipayamak"}, // nothing pending there
		{"sms", "discard", "sms_ir", "melipayamak"},
	} {
		if code := r.run(args...); code == 0 {
			t.Fatalf("%v succeeded", args)
		}
	}
	if r.count(`SELECT count(*) FROM ctrlz.audit_log`) != rows {
		t.Fatal("a refused discard wrote a row")
	}
	if code := r.run("sms", "discard", "sms_ir"); code != 0 {
		t.Fatalf("discard: exit %d, %q", code, r.errb.String())
	}
	var now, pend []byte
	r.env.Scan(t, `SELECT credentials_ct, credentials_pending_ct FROM ctrlz.sms_gateways WHERE provider = 'sms_ir'`, nil, &now, &pend)
	if !bytes.Equal(now, active) || pend != nil {
		t.Fatal("discard changed the active credentials or left the pending pair")
	}
	if n := r.count(`SELECT count(*) FROM ctrlz.audit_log WHERE action = 'sms.gateway_change' AND params->'fields' ? 'credentials_discarded'`); n != 1 {
		t.Fatalf("%d discard rows", n)
	}
	if code := r.run("sms", "confirm", "sms_ir", "--hint", "2222"); code == 0 {
		t.Fatal("a confirmation promoted a discarded pair")
	}
}
