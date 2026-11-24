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

// TestSMSPendingNamesTheStagerThroughAFloodOfCostRows is admin-r21-4. Every cost-only PUT writes an
// sms.gateway_change row, and a stolen session has a five-minute window of them, so a fixed number of
// newest rows let it push the row of its own staging out of sight. The console pages back until it
// finds the staging row of the gateway.
func TestSMSPendingNamesTheStagerThroughAFloodOfCostRows(t *testing.T) {
	r := newRig(t)
	r.readyAdmin()
	plantPending(t, r, "7731")
	var gw uuid.UUID
	r.env.Scan(t, `SELECT id FROM ctrlz.sms_gateways WHERE provider = 'sms_ir'`, nil, &gw)
	thief := netip.MustParseAddr("203.0.113.9")
	if err := r.st.WithGlobal(r.env.Ctx, store.TxOpts{}, func(g store.GlobalTx) error {
		now := time.Now()
		if _, err := audit.Admin(g, now, seedAdmin, thief, audit.SMSGatewayChange{Gateway: gw, Fields: []audit.Field{audit.FieldCredentials}}); err != nil {
			return err
		}
		// More than two pages of rows that name the cost, of this gateway and of another one.
		for i := 0; i < 450; i++ {
			target := gw
			if i%2 == 1 {
				target = uuid.New()
			}
			if _, err := audit.Admin(g, now, seedAdmin, netip.MustParseAddr("198.51.100.1"),
				audit.SMSGatewayChange{Gateway: target, Fields: []audit.Field{audit.FieldCostPerMessage}}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if code := r.run("sms", "pending"); code != 0 {
		t.Fatalf("pending: exit %d, %q", code, r.errb.String())
	}
	out := r.out.String()
	if !strings.Contains(out, thief.String()) || !strings.Contains(out, `"root"`) || strings.Contains(out, "no audit row") {
		t.Fatalf("a flood of cost rows hid the staging row: %q", out)
	}
}

// TestARekeyChangesTheFingerprintOfAWaitingPair is admin-r21-2, end to end: a rekey re-seals a pair that
// waits, so the fingerprint its PUT returned no longer confirms it; the owner discards, stages again and
// confirms with the new fingerprint.
func TestARekeyChangesTheFingerprintOfAWaitingPair(t *testing.T) {
	r := newRig(t)
	r.readyAdmin()
	root := secret.NewBytes(bytes.Repeat([]byte{7}, 32))
	doms := func(n ...uint16) map[string][]uint16 {
		return map[string][]uint16{keyring.DomainAdminTOTP: n, keyring.DomainSMSCred: n, keyring.DomainAdminMAC: {1}}
	}
	one, err := keyring.FromRoot(root, doms(1))
	if err != nil {
		t.Fatal(err)
	}
	both, err := keyring.FromRoot(root, doms(1, 2))
	if err != nil {
		t.Fatal(err)
	}
	r.keys = one
	_, pending := plantPending(t, r, "2222")
	stale := store.SMSCredentialsFingerprint(pending)

	r.keys = both
	if code := r.run("rekey", "sms_cred"); code != 0 {
		t.Fatalf("rekey: exit %d, %q", code, r.errb.String())
	}
	if fresh := r.pendingFP(); fresh == stale {
		t.Fatal("a rekey left the fingerprint of the waiting pair unchanged")
	}
	active := r.activeCT()
	if code := r.run("sms", "confirm", "sms_ir", "--hint", "2222", "--fingerprint", stale); code == 0 {
		t.Fatal("the fingerprint from before the rekey confirmed the re-sealed pair")
	}
	if !bytes.Equal(r.activeCT(), active) {
		t.Fatal("the refused confirmation changed the active credentials")
	}
	if code := r.run("sms", "discard", "sms_ir"); code != 0 {
		t.Fatalf("discard: exit %d, %q", code, r.errb.String())
	}
	// The owner's second PUT: a new pair under the current key, and the fingerprint that PUT returned.
	var gw uuid.UUID
	r.env.Scan(t, `SELECT id FROM ctrlz.sms_gateways WHERE provider = 'sms_ir'`, nil, &gw)
	ct := sealPending(t, r, gw, `{"api_key":"third-key-4444"}`)
	r.env.Exec(t, `UPDATE ctrlz.sms_gateways SET credentials_pending_ct = $2, pending_hint = '4444' WHERE id = $1`, gw, ct)
	if code := r.run("sms", "confirm", "sms_ir", "--hint", "4444", "--fingerprint", store.SMSCredentialsFingerprint(ct)); code != 0 {
		t.Fatalf("confirm after the new PUT: exit %d, %q", code, r.errb.String())
	}
	if bytes.Equal(r.activeCT(), active) {
		t.Fatal("the new pair was not activated")
	}
}

func sealPending(t *testing.T, r *rig, gw uuid.UUID, creds string) []byte {
	t.Helper()
	ct, err := sms.SealCredentials(r.keys, gw, "sms_ir", secret.NewBytes([]byte(creds)))
	if err != nil {
		t.Fatal(err)
	}
	return ct
}
