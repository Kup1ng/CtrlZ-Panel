package hubsign_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"google.golang.org/protobuf/proto"

	signv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/sign/v1"
	"github.com/Kup1ng/CtrlZ-Shared/manifest"

	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubsign"
)

func rootOf(pub ed25519.PublicKey) *signv1.Root {
	id := manifest.KeyID(pub)
	return &signv1.Root{
		Version: 1, ExpiresAt: 1 << 40, Threshold: 1,
		Keys:  []*signv1.PublicKey{{KeyId: id, Ed25519: pub}},
		Roles: []*signv1.RoleGrant{{Role: signv1.Role_ROLE_POLICY, KeyIds: [][]byte{id}, Threshold: 1, ExpiresAt: 1 << 40}},
	}
}

// A head the signer made verifies as a head against a root that names the key, and as nothing else.
func TestHeadVerifiesAsAHeadOnly(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	s := hubsign.New(priv)
	env, err := s.Head(7, make([]byte, 32), 100)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := manifest.Verify(env, rootOf(pub), signv1.Role_ROLE_POLICY, manifest.TypeHead, 100)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	var h signv1.SignedHead
	if err := proto.Unmarshal(payload, &h); err != nil || h.Seq != 7 {
		t.Fatalf("payload %v %v", &h, err)
	}
	if _, err := manifest.Verify(env, rootOf(pub), signv1.Role_ROLE_POLICY, manifest.TypePairTable, 100); err == nil {
		t.Fatal("a head verified as a pair table")
	}
	if _, err := s.Head(0, make([]byte, 32), 1); err == nil {
		t.Fatal("a head with seq 0 was signed")
	}
	if _, err := s.Head(1, []byte{1}, 1); err == nil {
		t.Fatal("a head with a short hash was signed")
	}
}

func TestParseReadsPKCS8AndRefusesTheRest(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(priv)
	s, err := hubsign.Parse(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	if err != nil || !s.Public().Equal(priv.Public()) {
		t.Fatalf("parse: %v", err)
	}
	for name, in := range map[string][]byte{"empty": nil, "text": []byte("not pem"), "wrong type": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})} {
		if _, err := hubsign.Parse(in); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
}
