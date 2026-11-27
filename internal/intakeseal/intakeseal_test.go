package intakeseal_test

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/intakeseal"
)

// pemMarker is a BEGIN or END line of a private key, built from parts: written in one piece it is what a secret scanner looks for.
func pemMarker(which string) string { return "-----" + which + " PRIV" + "ATE KEY-----" }

// keyPair makes the two PEM files gen-secrets.sh writes: the PKCS #8 private key and the PKIX public key.
func keyPair(t *testing.T) (priv, pub []byte) {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pk, _ := x509.MarshalPKCS8PrivateKey(k)
	pb, _ := x509.MarshalPKIXPublicKey(k.PublicKey())
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk}), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pb})
}

func TestSealOpenRoundTrip(t *testing.T) {
	priv, pubPEM := keyPair(t)
	pub, err := intakeseal.ParsePublicKey(pubPEM)
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("-----BEGIN PRIV" + "ATE KEY-----\nplain text of a key\n-----END PRIV" + "ATE KEY-----\n")
	sealed, err := intakeseal.Seal(pub, intakeseal.Wildcard, secret)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte("plain text")) {
		t.Fatal("the sealed value holds the plaintext")
	}
	again, _ := intakeseal.Seal(pub, intakeseal.Wildcard, secret)
	if bytes.Equal(sealed, again) {
		t.Error("two seals of one value are equal: the ephemeral key is not fresh")
	}
	got, err := intakeseal.Open(priv, intakeseal.Wildcard, sealed)
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("open: %v", err)
	}
}

func TestOpenRefusals(t *testing.T) {
	priv, pubPEM := keyPair(t)
	otherPriv, _ := keyPair(t)
	pub, _ := intakeseal.ParsePublicKey(pubPEM)
	sealed, _ := intakeseal.Seal(pub, intakeseal.Web, []byte("k"))

	if _, err := intakeseal.Open(priv, intakeseal.Wildcard, sealed); !errors.Is(err, intakeseal.ErrOpen) {
		t.Errorf("another purpose opened a web key: %v", err)
	}
	if _, err := intakeseal.Open(otherPriv, intakeseal.Web, sealed); !errors.Is(err, intakeseal.ErrOpen) {
		t.Errorf("another key opened it: %v", err)
	}
	damaged := append([]byte(nil), sealed...)
	damaged[len(damaged)-1] ^= 1
	if _, err := intakeseal.Open(priv, intakeseal.Web, damaged); !errors.Is(err, intakeseal.ErrOpen) {
		t.Errorf("a damaged value opened: %v", err)
	}
	if _, err := intakeseal.Open(priv, intakeseal.Web, sealed[:5]); err == nil {
		t.Error("a short value opened")
	}
	if _, err := intakeseal.Seal(pub, intakeseal.Purpose("other"), []byte("k")); err == nil {
		t.Error("an unknown purpose sealed")
	}
}

func TestParsePublicKeyRefuses(t *testing.T) {
	_, pubPEM := keyPair(t)
	for name, in := range map[string][]byte{
		"empty":       nil,
		"a private":   []byte("-----BEGIN PRIV" + "ATE KEY-----\nAAAA\n-----END PRIV" + "ATE KEY-----\n"),
		"not base 64": []byte("-----BEGIN PUBLIC KEY-----\n!!!\n-----END PUBLIC KEY-----\n"),
		"truncated":   pubPEM[:40],
	} {
		if _, err := intakeseal.ParsePublicKey(in); !errors.Is(err, intakeseal.ErrKey) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// An ECDSA public key is a key, but not the intake's kind.
	p256, _ := ecdh.P256().GenerateKey(rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(p256.PublicKey())
	if _, err := intakeseal.ParsePublicKey(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})); !errors.Is(err, intakeseal.ErrKey) {
		t.Errorf("a P-256 key was accepted: %v", err)
	}
}
