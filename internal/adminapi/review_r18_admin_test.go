package adminapi

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/authtest"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms"
)

// TestAStolenSessionCannotRedirectLoginCodesToItsOwnGateway is the abuse test of admin-r18-1 (D64
// sms-gateway-takeover): with a session and one fresh code, the thief saves credentials of a provider
// account of its own and tries to route to it. The credentials that carry the codes of every tenant do
// not change, the routing refuses the unconfirmed gateway, and only the console makes the change.
func TestAStolenSessionCannotRedirectLoginCodesToItsOwnGateway(t *testing.T) {
	r := newRig(t)
	b, _ := r.admin(t)
	r.env.ResetSMS(t)
	thiefPW := "thief-pw-" + strings.Repeat("9", 10)
	ownerKey, thiefKey := "owner-"+strings.Repeat("7", 14), "thief-"+strings.Repeat("3", 14) // built, so the planted values are not shaped like a key a scanner would flag

	id := r.env.AddGateway(t, r.keys, authtest.Gateway{Provider: "sms_ir", Role: "primary", Credentials: `{"api_key":"` + ownerKey + `"}`, Price: "10", ParamName: "CODE"})
	var before []byte
	r.env.Scan(t, `SELECT credentials_ct FROM ctrlz.sms_gateways WHERE id = $1`, []any{id}, &before)

	// The thief saves its own credentials for the live gateway and for the other provider.
	res := b.put("/sms/gateways/sms_ir", map[string]any{"credentials": map[string]string{"api_key": thiefKey}}).want(200, "")
	if !strings.Contains(string(res.Body), `"pending_confirmation":true`) || !strings.Contains(string(res.Body), `"role":"primary"`) {
		t.Fatalf("the answer must say the credentials wait, and the role is untouched: %s", res.Body)
	}
	b.put("/sms/gateways/melipayamak", map[string]any{"credentials": map[string]string{"username": "thief-user", "password": thiefPW}}).want(200, "")

	// The credentials the sender, the router and the breaker read did not change by a byte, and still open
	// to the owner's key; the thief's sit in the pending column.
	var after, pending []byte
	r.env.Scan(t, `SELECT credentials_ct, credentials_pending_ct FROM ctrlz.sms_gateways WHERE id = $1`, []any{id}, &after, &pending)
	if !bytes.Equal(before, after) {
		t.Fatal("a PUT changed the credentials that carry the codes")
	}
	if plain, err := sms.OpenCredentials(r.keys, id, "sms_ir", after); err != nil || !strings.Contains(string(plain.Reveal()), ownerKey) {
		t.Fatalf("the active credentials are not the owner's: %v", err)
	}
	if plain, err := sms.OpenCredentials(r.keys, id, "sms_ir", pending); err != nil || !strings.Contains(string(plain.Reveal()), thiefKey) {
		t.Fatalf("the pending credentials are not the ones saved: %v", err)
	}

	// The routing cannot name a gateway whose credentials the owner has not confirmed: it has none that
	// can send. The refusal says why, and nothing moves.
	res = b.put("/sms/routing", map[string]any{"primary": "melipayamak"}).want(422, "validation_failed")
	if !strings.Contains(string(res.Body), "pending_confirmation") {
		t.Fatalf("the refusal must name the cause: %s", res.Body)
	}
	if n := r.count(t, `SELECT count(*) FROM ctrlz.sms_gateways WHERE provider = 'sms_ir' AND role = 'primary'`); n != 1 {
		t.Fatal("a refused routing change moved the primary")
	}
	// The test send needs active credentials too: the thief cannot make a gateway of its own send.
	b.post("/sms/gateways/melipayamak/test", map[string]any{"phone": "09125550006", "template": "otp"}).want(422, "validation_failed")

	// The audit row of the PUT says credentials were saved, never that they were confirmed.
	if n := r.count(t, `SELECT count(*) FROM ctrlz.audit_log WHERE action = 'sms.gateway_change' AND params->'fields' ? 'credentials_confirmed'`); n != 0 {
		t.Fatal("a route wrote the confirmation row")
	}
	r.assertQuiet(t, ownerKey, thiefKey, thiefPW)
}
