package adminapi

import (
	"bytes"
	"strings"
	"testing"
)

// TestASecondPutCannotReplaceThePendingCredentials is db-r19-2 (D64 sms-gateway-takeover). The owner
// rotates a Melipayamak password and stages it; the console confirms by a hint the stager chooses, the
// last four characters of the username. A thief with a stolen session PUTs credentials of its own under
// a username that ends alike. The PUT must be refused, with no change and no second banner, so the pair
// the owner confirms at the console is the owner's.
func TestASecondPutCannotReplaceThePendingCredentials(t *testing.T) {
	r := newRig(t)
	b, _ := r.admin(t)
	r.env.ResetSMS(t)
	ownerPW, thiefPW := "owner-pw-"+strings.Repeat("5", 10), "thief-pw-"+strings.Repeat("9", 10)

	b.put("/sms/gateways/melipayamak", map[string]any{"credentials": map[string]string{"username": "ctrlzsms7731", "password": ownerPW}}).want(200, "")
	var owner []byte
	r.env.Scan(t, `SELECT credentials_pending_ct FROM ctrlz.sms_gateways WHERE provider = 'melipayamak'`, nil, &owner)
	const noticeSQL = `SELECT COALESCE(string_agg(pending_notice::text, '|' ORDER BY id), '') FROM ctrlz.admin_users`
	var notices string
	r.env.Scan(t, noticeSQL, nil, &notices)

	b.put("/sms/gateways/melipayamak", map[string]any{"credentials": map[string]string{"username": "evil7731", "password": thiefPW}}).want(422, "validation_failed")

	var now []byte
	var hint string
	r.env.Scan(t, `SELECT credentials_pending_ct, pending_hint FROM ctrlz.sms_gateways WHERE provider = 'melipayamak'`, nil, &now, &hint)
	if !bytes.Equal(now, owner) || hint != "7731" {
		t.Fatal("a second PUT replaced the pending credentials of the owner")
	}
	var noticesNow string
	r.env.Scan(t, noticeSQL, nil, &noticesNow)
	if noticesNow != notices {
		t.Fatal("a refused PUT changed the banners")
	}
	if n := r.count(t, `SELECT count(*) FROM ctrlz.audit_log WHERE action = 'sms.gateway_change'`); n != 1 {
		t.Fatalf("%d gateway_change rows, want only the owner's PUT", n)
	}
	r.assertQuiet(t, ownerPW, thiefPW)
}
