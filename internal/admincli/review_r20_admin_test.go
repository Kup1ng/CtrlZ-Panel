package admincli_test

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/audit"
	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

func (r *rig) activeCT() []byte {
	var ct []byte
	r.env.Scan(r.t, `SELECT credentials_ct FROM ctrlz.sms_gateways WHERE provider = 'sms_ir'`, nil, &ct)
	return ct
}

// TestAThiefWhoStagedFirstIsNotConfirmedByTheHint is admin-r20-3 and admin-r20-5 (D64
// sms-gateway-takeover). A stolen session stages a pair under a hint it read from the page; the owner's
// own PUT is refused, and the console is all the owner has. Whatever `sms pending` shows must not be
// enough to confirm the pair: the hint is the thief's to choose, and the fingerprint went to the
// session that staged. `sms pending` also says when, by whom and from where the pair was staged, and
// offers no ready-made confirmation.
func TestAThiefWhoStagedFirstIsNotConfirmedByTheHint(t *testing.T) {
	r := newRig(t)
	r.readyAdmin()
	active, _ := plantPending(t, r, "7731")
	var gw uuid.UUID
	r.env.Scan(t, `SELECT id FROM ctrlz.sms_gateways WHERE provider = 'sms_ir'`, nil, &gw)
	// The row the PUT writes in the transaction that staged: the thief's address, the stolen admin.
	if err := r.st.WithGlobal(r.env.Ctx, store.TxOpts{}, func(g store.GlobalTx) error {
		_, err := audit.Admin(g, time.Now(), seedAdmin, netip.MustParseAddr("203.0.113.9"),
			audit.SMSGatewayChange{Gateway: gw, Fields: []audit.Field{audit.FieldCredentials}})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	fp := r.pendingFP()

	if code := r.run("sms", "pending"); code != 0 {
		t.Fatalf("pending: exit %d, %q", code, r.errb.String())
	}
	out := r.out.String()
	for _, want := range []string{`hint "7731"`, "203.0.113.9", `"root"`, "sms discard sms_ir"} {
		if !strings.Contains(out, want) {
			t.Errorf("sms pending does not show %q: %q", want, out)
		}
	}
	if strings.Contains(out, fp) {
		t.Error("sms pending prints the fingerprint, so a reader of the console could confirm any pair")
	}

	// What the owner can type from that output: the provider and the hint. It changes nothing.
	for _, args := range [][]string{
		{"sms", "confirm", "sms_ir", "--hint", "7731"},
		{"sms", "confirm", "sms_ir", "--hint", "7731", "--fingerprint", "0123456789abcdef"},
	} {
		if code := r.run(args...); code == 0 {
			t.Fatalf("%v confirmed a pair whose fingerprint the owner never held", args)
		}
		if !bytes.Equal(r.activeCT(), active) {
			t.Fatalf("%v changed the active credentials", args)
		}
	}
	// The session that staged holds the fingerprint, in any letter case.
	if code := r.run("sms", "confirm", "sms_ir", "--hint", "7731", "--fingerprint", strings.ToUpper(fp)); code != 0 {
		t.Fatalf("confirm with the fingerprint: exit %d, %q", code, r.errb.String())
	}
	if bytes.Equal(r.activeCT(), active) {
		t.Fatal("the pair was not activated by its own fingerprint")
	}
}

// plantUnopenable plants, for sms_ir, a pending pair sealed under a key 1 that this container does not
// hold (the lost kek_sms_cred), and returns the gateway id.
func plantUnopenable(t *testing.T, r *rig) uuid.UUID {
	t.Helper()
	lost, err := keyring.FromRoot(secret.NewBytes(bytes.Repeat([]byte{9}, 32)), map[string][]uint16{keyring.DomainSMSCred: {1}})
	if err != nil {
		t.Fatal(err)
	}
	gw := uuid.New()
	ct, err := sms.SealCredentials(lost, gw, "sms_ir", secret.NewBytes([]byte(`{"api_key":"stranded-key-3333"}`)))
	if err != nil {
		t.Fatal(err)
	}
	r.env.ResetSMS(t)
	r.env.Exec(t, `INSERT INTO ctrlz.sms_gateways (id, provider, role, credentials_pending_ct, pending_hint) VALUES ($1, 'sms_ir', 'disabled', $2, '3333')`, gw, ct)
	return gw
}

// TestConfirmRefusesAPairTheRingCannotOpen is admin-r20-4: the console holds sms_cred, so it does not
// activate ciphertext that every sender would judge unusable. The message sends the operator to
// discard, and names no value.
func TestConfirmRefusesAPairTheRingCannotOpen(t *testing.T) {
	r := newRig(t)
	r.readyAdmin()
	plantUnopenable(t, r)
	if code := r.run(r.confirmArgs("3333")...); code == 0 {
		t.Fatal("an unopenable pending pair was activated")
	}
	if !strings.Contains(r.errb.String(), "sms discard") || strings.Contains(r.errb.String()+r.out.String(), "stranded-key-3333") {
		t.Fatalf("the refusal does not send the operator to discard, or shows a value: %q", r.errb.String())
	}
	if r.activeCT() != nil || r.count(`SELECT count(*) FROM ctrlz.sms_gateways WHERE credentials_pending_ct IS NOT NULL`) != 1 {
		t.Fatal("the refused confirmation changed the gateway")
	}
}

// TestDeclareLostSMSCredFreesAGatewayWhosePendingPairItStranded is admin-r20-1 and -4: a pending pair
// under the lost key blocks the re-entry the recovery text asks for (a PUT is refused while a pair
// waits). The declaration drops it in its own transaction, with the row of a discard, and the printed
// steps then work.
func TestDeclareLostSMSCredFreesAGatewayWhosePendingPairItStranded(t *testing.T) {
	r := newRig(t)
	r.readyAdmin()
	gw := plantUnopenable(t, r)
	if code := r.run("keys", "declare-lost", "sms_cred", "--key-number", "1", "--yes"); code != 0 {
		t.Fatalf("declare-lost: exit %d, %q", code, r.errb.String())
	}
	for _, want := range []string{"sms discard", "were discarded", "--fingerprint"} {
		if !strings.Contains(r.out.String(), want) {
			t.Errorf("the declaration does not say %q: %q", want, r.out.String())
		}
	}
	if n := r.count(`SELECT count(*) FROM ctrlz.sms_gateways WHERE credentials_pending_ct IS NOT NULL`); n != 0 {
		t.Fatal("the stranded pending pair is still there")
	}
	if n := r.count(`SELECT count(*) FROM ctrlz.audit_log WHERE action = 'sms.gateway_change' AND params->'fields' ? 'credentials_discarded'`); n != 1 {
		t.Fatalf("%d discard rows, want 1", n)
	}
	if n := r.count(`SELECT count(*) FROM ctrlz.audit_log WHERE action = 'key.declared_lost'`); n != 1 {
		t.Fatalf("%d declaration rows, want 1", n)
	}
	// The recovery step the text asks for: the PUT stages again.
	if err := r.st.WithGlobal(r.env.Ctx, store.TxOpts{}, func(g store.GlobalTx) error {
		ok, err := g.SMSGatewayStageCredentials(gw, []byte("new-ciphertext"), "4444")
		if err == nil && !ok {
			t.Error("a PUT after the declaration is still refused with pending_exists")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

// A pending pair that still opens under the ring is not stranded: the declaration leaves it alone.
func TestDeclareLostSMSCredKeepsAPendingPairThatStillOpens(t *testing.T) {
	r := newRig(t)
	r.readyAdmin()
	plantPending(t, r, "2222") // opens: sealed under the ring of the container
	// An active pair under the lost key on the other provider, so the declaration is not refused as
	// "nothing is lost".
	lost, err := keyring.FromRoot(secret.NewBytes(bytes.Repeat([]byte{9}, 32)), map[string][]uint16{keyring.DomainSMSCred: {1}})
	if err != nil {
		t.Fatal(err)
	}
	gw := uuid.New()
	ct, err := sms.SealCredentials(lost, gw, "melipayamak", secret.NewBytes([]byte(`{"username":"u","password":"p"}`)))
	if err != nil {
		t.Fatal(err)
	}
	r.env.Exec(t, `INSERT INTO ctrlz.sms_gateways (id, provider, role, credentials_ct) VALUES ($1, 'melipayamak', 'disabled', $2)`, gw, ct)
	if code := r.run("keys", "declare-lost", "sms_cred", "--key-number", "1", "--yes"); code != 0 {
		t.Fatalf("declare-lost: exit %d, %q", code, r.errb.String())
	}
	if n := r.count(`SELECT count(*) FROM ctrlz.sms_gateways WHERE provider = 'sms_ir' AND credentials_pending_ct IS NOT NULL`); n != 1 {
		t.Fatal("the declaration dropped a pending pair that opens")
	}
}
