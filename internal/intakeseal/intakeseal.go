// Package intakeseal seals an uploaded private key to the intake public key of its kind (p4-nodes 3.3, 4.3).
//
// The admin service holds the two public halves and never a private one, so what it stores it cannot open again: a
// wildcard key is opened only by the hub (to seal it for the nodes) and a panel or admin key only by `ctrlz domain-apply`
// (to give it to Caddy). The info string names the purpose, so a key sealed for the web tier does not open under the
// wildcard key even if the two private keys were ever swapped.
//
// The scheme is HPKE (RFC 9180), DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and AES-256-GCM, single shot: the stored bytes
// are the encapsulated key followed by the ciphertext, as crypto/hpke returns them.
package intakeseal

import (
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

// Purpose is the kind of intake a key is sealed for.
type Purpose string

// The two intakes of 3.3.
const (
	Wildcard Purpose = "wildcard" // opened by the hub
	Web      Purpose = "web"      // opened by domain-apply
)

// ErrKey is returned for a key file that is not an X25519 key in PEM.
var ErrKey = errors.New("intakeseal: not an X25519 key in PEM")

// ErrOpen is returned when a sealed value does not open: the wrong key, the wrong purpose or damaged bytes.
var ErrOpen = errors.New("intakeseal: the sealed value does not open")

func info(p Purpose) []byte { return []byte("ctrlz-intake-v1/" + string(p)) }

func kdf() hpke.KDF   { return hpke.HKDFSHA256() }
func aead() hpke.AEAD { return hpke.AES256GCM() }

// PublicKey is a parsed intake public key.
type PublicKey struct{ pk hpke.PublicKey }

// ParsePublicKey reads the PEM public key file that gen-secrets.sh writes beside each intake key.
func ParsePublicKey(pemBytes []byte) (PublicKey, error) {
	b, _ := pem.Decode(pemBytes)
	if b == nil || b.Type != "PUBLIC KEY" {
		return PublicKey{}, ErrKey
	}
	k, err := x509.ParsePKIXPublicKey(b.Bytes)
	if err != nil {
		return PublicKey{}, ErrKey
	}
	pub, ok := k.(*ecdh.PublicKey)
	if !ok || pub.Curve() != ecdh.X25519() {
		return PublicKey{}, ErrKey
	}
	pk, err := hpke.NewDHKEMPublicKey(pub)
	if err != nil {
		return PublicKey{}, ErrKey
	}
	return PublicKey{pk: pk}, nil
}

// Seal encrypts plaintext to the key for a purpose. Each call uses a fresh ephemeral key.
func Seal(pub PublicKey, p Purpose, plaintext []byte) ([]byte, error) {
	if pub.pk == nil || (p != Wildcard && p != Web) {
		return nil, ErrKey
	}
	return hpke.Seal(pub.pk, kdf(), aead(), info(p), plaintext)
}

// Open decrypts a sealed value with the PEM private key (PKCS #8) of the intake. Only the hub and domain-apply call it.
func Open(privPEM []byte, p Purpose, sealed []byte) ([]byte, error) {
	b, _ := pem.Decode(privPEM)
	if b == nil || b.Type != "PRIVATE KEY" {
		return nil, ErrKey
	}
	k, err := x509.ParsePKCS8PrivateKey(b.Bytes)
	if err != nil {
		return nil, ErrKey
	}
	priv, ok := k.(*ecdh.PrivateKey)
	if !ok || priv.Curve() != ecdh.X25519() {
		return nil, ErrKey
	}
	hk, err := hpke.NewDHKEMPrivateKey(priv)
	if err != nil {
		return nil, ErrKey
	}
	out, err := hpke.Open(hk, kdf(), aead(), info(p), sealed)
	if err != nil {
		return nil, ErrOpen
	}
	return out, nil
}
