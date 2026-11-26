package adminapi

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// TestOnlyThePutThatStagedACredentialPairReturnsItsFingerprint is the API half of admin-r20-3 and
// admin-r20-5. Whoever stages first holds the slot and the fingerprint the console asks for; the
// session whose PUT is refused with pending_exists, a listing and a PUT of the price alone carry none,
// so an owner who did not stage the pair cannot confirm it. The value is the one the console computes
// from the stored ciphertext, and it holds no part of a credential.
func TestOnlyThePutThatStagedACredentialPairReturnsItsFingerprint(t *testing.T) {
	r := newRig(t)
	b, _ := r.admin(t)
	r.env.ResetSMS(t)
	thiefPW, ownerPW := "thief-pw-"+strings.Repeat("9", 10), "owner-pw-"+strings.Repeat("5", 10)

	// The thief stages first, under a username that ends like the active hint it could read.
	res := b.put("/sms/gateways/melipayamak", map[string]any{"credentials": map[string]string{"username": "evil7731", "password": thiefPW}}).want(200, "")
	var row struct {
		Fingerprint string `json:"pending_fingerprint"`
	}
	if err := json.Unmarshal(res.Body, &row); err != nil {
		t.Fatal(err)
	}
	var stored []byte
	r.env.Scan(t, `SELECT credentials_pending_ct FROM ctrlz.sms_gateways WHERE provider = 'melipayamak'`, nil, &stored)
	if row.Fingerprint == "" || row.Fingerprint != store.SMSCredentialsFingerprint(stored) {
		t.Fatalf("the PUT that staged the pair did not return its fingerprint: %s", res.Body)
	}
	// The same fingerprint is what the confirming statement compares, in SQL, with no Go in between.
	var inSQL string
	r.env.Scan(t, `SELECT encode(substr(sha256(credentials_pending_ct), 1, 8), 'hex') FROM ctrlz.sms_gateways WHERE provider = 'melipayamak'`, nil, &inSQL)
	if inSQL != row.Fingerprint {
		t.Fatalf("Go and SQL name the pair differently: %q and %q", row.Fingerprint, inSQL)
	}

	// The owner's PUT is refused and shows no fingerprint.
	res = b.put("/sms/gateways/melipayamak", map[string]any{"credentials": map[string]string{"username": "owner7731", "password": ownerPW}}).want(422, "validation_failed")
	if strings.Contains(string(res.Body), "pending_fingerprint") || strings.Contains(string(res.Body), row.Fingerprint) {
		t.Fatalf("a refused PUT shows a fingerprint: %s", res.Body)
	}
	// A listing and a price-only PUT do not return it either.
	if res = b.get("/sms/gateways").want(200, ""); strings.Contains(string(res.Body), "pending_fingerprint") {
		t.Fatalf("the listing shows a fingerprint: %s", res.Body)
	}
	res = b.put("/sms/gateways/melipayamak", map[string]any{"cost_per_message": "12"}).want(200, "")
	if strings.Contains(string(res.Body), "pending_fingerprint") {
		t.Fatalf("a PUT that staged nothing returns a fingerprint: %s", res.Body)
	}
	r.assertQuiet(t, thiefPW, ownerPW)
}
