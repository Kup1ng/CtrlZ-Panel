// Package hubsign is the hub's use of the policy key (p4-nodes 3.3): it signs the SignedHead that GetHead
// returns, and later the PairTable pushes of 5.6.
//
// Why the hub and no one else. A head names the highest entry a node may apply, and only the hub knows the
// release point (L12) and the rollout cursor of that node (6.4), so only the hub can say which head is true
// for a given node right now. The compiler writes entries but never signs one: an entry carries no signature
// of its own, the signed head over its hash is what makes it believed.
package hubsign

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"google.golang.org/protobuf/proto"

	signv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/sign/v1"
	"github.com/Kup1ng/CtrlZ-Shared/manifest"
)

// ErrKey is the one answer for a policy key that cannot be read: what is wrong with it is not said, since the
// text a parser gives back can quote the input.
var ErrKey = errors.New("hubsign: the policy key is not an Ed25519 private key in PKCS#8 PEM")

// Signer holds the policy key and signs with it. It has no way to give the key back.
type Signer struct {
	key   ed25519.PrivateKey
	keyID []byte
}

// Parse reads the policy key, as scripts/gen-secrets.sh writes it (an openssl PKCS#8 PEM).
func Parse(pemBytes []byte) (*Signer, error) {
	blk, _ := pem.Decode(pemBytes)
	if blk == nil || blk.Type != "PRIVATE KEY" {
		return nil, ErrKey
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, ErrKey
	}
	ek, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, ErrKey
	}
	return &Signer{key: ek, keyID: manifest.KeyID(ek.Public().(ed25519.PublicKey))}, nil
}

// New wraps a key a test made.
func New(k ed25519.PrivateKey) *Signer {
	return &Signer{key: k, keyID: manifest.KeyID(k.Public().(ed25519.PublicKey))}
}

// Public is the key's public half, which the root's policy grant names.
func (s *Signer) Public() ed25519.PublicKey { return s.key.Public().(ed25519.PublicKey) }

// Sign wraps a payload of the given type in an envelope with one signature over manifest.SigningInput.
func (s *Signer) Sign(payloadType string, payload []byte) *signv1.Envelope {
	sig := ed25519.Sign(s.key, manifest.SigningInput(payloadType, payload))
	return &signv1.Envelope{
		PayloadType: payloadType,
		Payload:     payload,
		Signatures:  []*signv1.Signature{{KeyId: s.keyID, Sig: sig}},
	}
}

// Head signs the head of the log at seq: the entry's hash and the time the head was made.
func (s *Signer) Head(seq uint64, entryHash []byte, createdAt int64) (*signv1.Envelope, error) {
	if seq == 0 || len(entryHash) != 32 {
		return nil, errors.New("hubsign: a head needs a seq and a 32-byte entry hash")
	}
	b, err := proto.Marshal(&signv1.SignedHead{Seq: seq, EntryHash: entryHash, CreatedAt: createdAt})
	if err != nil {
		return nil, err
	}
	return s.Sign(manifest.TypeHead, b), nil
}
