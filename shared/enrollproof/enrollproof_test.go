package enrollproof

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"encoding/hex"
	"math/big"
	"testing"
)

func id16() []byte {
	id := make([]byte, IDLen)
	for i := range id {
		id[i] = byte(i + 1)
	}
	return id
}

// The golden vector of contract 12 and of the node's internal/enroll: the id 01 02 ... 10.
func TestGoldenDigest(t *testing.T) {
	const want = "ed213f81920fcc9792708e93b04efd440a1feacebf0e3d7dd39ee334074208c8"
	if got := hex.EncodeToString(Digest(id16())); got != want {
		t.Fatalf("digest = %s, want %s", got, want)
	}
	in := Input(id16())
	if len(in) != 14+16 || !bytes.HasPrefix(in, []byte("ctrlz-poll-v1\x00")) || !bytes.Equal(in[14:], id16()) {
		t.Fatalf("input is not the 14-byte prefix and the raw id: %x", in)
	}
}

func sign(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	sig, err := ecdsa.SignASN1(rand.Reader, key, Digest(id16()))
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

func TestVerify(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sig := sign(t, key)
	if !Verify(&key.PublicKey, id16(), sig) {
		t.Fatal("a good proof was refused")
	}
	other := id16()
	other[0] ^= 1
	if Verify(&key.PublicKey, other, sig) {
		t.Fatal("a proof for another id was accepted")
	}
	k2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if Verify(&k2.PublicKey, id16(), sig) {
		t.Fatal("a proof by another key was accepted")
	}
	if Verify(&key.PublicKey, id16()[:15], sig) || Verify(&key.PublicKey, nil, sig) {
		t.Fatal("a short id was accepted")
	}
	if Verify(nil, id16(), sig) || Verify(&key.PublicKey, id16(), nil) || Verify(&key.PublicKey, id16(), sig[:len(sig)-1]) {
		t.Fatal("a nil key, empty or cut signature was accepted")
	}
	k384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if Verify(&k384.PublicKey, id16(), sig) {
		t.Fatal("a P-384 key was accepted")
	}
}

// A signature that a lenient parser takes but that is not canonical DER is one more spelling of the same
// proof. Each of these must be refused although the numbers inside are the real r and s.
func TestVerifyRefusesNonCanonicalDER(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sig := sign(t, key)
	if !Verify(&key.PublicKey, id16(), sig) {
		t.Fatal("setup: the canonical signature must verify")
	}
	if Verify(&key.PublicKey, id16(), append(append([]byte{}, sig...), 0)) {
		t.Fatal("a signature with a trailing byte was accepted")
	}
	// Long-form length for the outer sequence (0x81 LL).
	long := append([]byte{sig[0], 0x81, sig[1]}, sig[2:]...)
	if Verify(&key.PublicKey, id16(), long) {
		t.Fatal("a long-form length was accepted")
	}
	var v ecSig
	if _, err := asn1.Unmarshal(sig, &v); err != nil {
		t.Fatal(err)
	}
	// A padded integer: r written with two extra leading zero bytes.
	rb := v.R.Bytes()
	rInt := append([]byte{0x02, byte(len(rb) + 2), 0, 0}, rb...)
	sInt, _ := asn1.Marshal(v.S)
	body := append(rInt, sInt...)
	padded := append([]byte{0x30, byte(len(body))}, body...)
	if Verify(&key.PublicKey, id16(), padded) {
		t.Fatal("a padded integer was accepted")
	}
	// Raw r || s is not DER.
	raw := append(append([]byte{}, pad32(v.R)...), pad32(v.S)...)
	if Verify(&key.PublicKey, id16(), raw) {
		t.Fatal("a raw r||s signature was accepted")
	}
}

func pad32(n *big.Int) []byte {
	out := make([]byte, 32)
	b := n.Bytes()
	copy(out[32-len(b):], b)
	return out
}
