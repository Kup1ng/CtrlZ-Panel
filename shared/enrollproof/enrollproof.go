// Package enrollproof is the proof of possession of a Poll (contract 12, p4-nodes 4.2 step 6): an
// ECDSA signature by the enrolled key over the SHA-256 of "ctrlz-poll-v1\x00" || enrollment_id.
//
// Both sides call this package, the node to sign and the hub to check, so the input they hash
// cannot drift apart. The signature is ASN.1 DER and only DER: an encoding that Go parses but that
// is not what Go itself would write (a padded integer, a long-form length) is refused, so one
// signature has one byte string and a captured Poll cannot be replayed under a second spelling.
package enrollproof

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/asn1"
	"math/big"
)

// Context is the 14-byte prefix of the signed input: the 13 characters of the label and a NUL.
const Context = "ctrlz-poll-v1\x00"

// IDLen is the length of an enrollment id.
const IDLen = 16

// MaxSigLen bounds a signature before it is parsed: an ECDSA P-256 DER signature is at most 72 bytes.
const MaxSigLen = 72

// Input is what the signature covers, before hashing: Context followed by the 16 raw id bytes
// (not their hex text).
func Input(id []byte) []byte {
	out := make([]byte, 0, len(Context)+len(id))
	out = append(out, Context...)
	return append(out, id...)
}

// Digest is the SHA-256 of Input(id), the value that is signed.
func Digest(id []byte) []byte {
	h := sha256.Sum256(Input(id))
	return h[:]
}

type ecSig struct{ R, S *big.Int }

// Verify reports whether sig is a canonical DER ECDSA signature by pub over Digest(id). The key must
// be on P-256, the id exactly IDLen bytes. It never panics on hostile input.
func Verify(pub *ecdsa.PublicKey, id, sig []byte) bool {
	if pub == nil || pub.Curve != elliptic.P256() || len(id) != IDLen || len(sig) == 0 || len(sig) > MaxSigLen {
		return false
	}
	var v ecSig
	rest, err := asn1.Unmarshal(sig, &v)
	if err != nil || len(rest) != 0 || v.R == nil || v.S == nil || v.R.Sign() <= 0 || v.S.Sign() <= 0 {
		return false
	}
	// Re-encode and compare: ecdsa.VerifyASN1 accepts what its parser accepts, and canonical DER is
	// one spelling per (r, s). A signature that reads back as another byte string is refused.
	again, err := asn1.Marshal(v)
	if err != nil || !bytes.Equal(again, sig) {
		return false
	}
	return ecdsa.VerifyASN1(pub, Digest(id), sig)
}
