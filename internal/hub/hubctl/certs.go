package hubctl

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/hpke"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	signv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/sign/v1"

	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubpki"
)

// SealInfo is the HPKE info string of the seal (p4-nodes 4.3): the node opens with the same string and no other.
const SealInfo = "ctrlz-certbundle-v1"

// ZoneIssuer is the zone CA in force. hubtrust.CAs gives it.
type ZoneIssuer interface {
	Zone() *hubpki.ZoneCA
}

// Wildcards finds the uploaded wildcard certificate that covers a zone (4.3: with an `active` uploaded `wildcard` row whose
// names cover the zone, every node gets that one). It returns the chain and the key already opened from the intake seal;
// the key is sealed again for the one node it is sent to and dropped. A nil Wildcards means no row covers anything, which is
// the state until the admin's upload route exists.
type Wildcards interface {
	Covering(ctx context.Context, zone string) (chainPEM, keyDER []byte, notAfter time.Time, found bool, err error)
}

// Bundle is a CertBundle with the identity the stream uses to decide whether it was already sent: the same identity is the
// same certificate, whatever the seal's randomness did to the wrapped key.
type Bundle struct {
	Msg *hubv1.CertBundle
	// ID is the zone and a hash of the chain, so a renewed leaf, a new zone CA and a new wildcard row each have another one.
	ID string
}

type issued struct {
	b       Bundle
	caKey   string // the zone CA certificate's fingerprint
	pub     []byte
	renewAt time.Time
}

type issuedKey struct {
	node uuid.UUID
	zone string
}

// Certs builds the CertBundles of one node (4.3). In private-CA mode each node gets its own 30-day leaf from the zone CA over a
// key the hub generates per issue and never stores: only the bundle sealed to that node is kept in memory, so a reconnect
// is answered with the same certificate, and the leaf is made again when a third of its life is left, when the zone CA
// changes or when the node's key does.
type Certs struct {
	CAs  ZoneIssuer
	Wild Wildcards
	Now  func() time.Time

	mu    sync.Mutex
	cache map[issuedKey]*issued
}

// NewCerts makes the builder.
func NewCerts(cas ZoneIssuer, wild Wildcards, now func() time.Time) *Certs {
	return &Certs{CAs: cas, Wild: wild, Now: now, cache: make(map[issuedKey]*issued)}
}

// ErrNoZoneCA is returned while the zone CA is not in force; the stream tries again at its next pass.
var ErrNoZoneCA = errors.New("hubctl: no zone CA yet")

// For gives one bundle for each zone, in the order of zones. pub is the public key of the node's certificate, which is the
// enrolled key (the check at open made its SPKI the row's).
//
// A zone that cannot be built (an uploaded wildcard whose key does not open, no zone CA yet, a zone the CA does not permit)
// is left as an empty Bundle (Msg nil) at its place and joined into the returned error; the other zones are still built. One
// bad row must not stop a node's other certificates, or the private-CA leaves of a healthy zone would run out.
func (c *Certs) For(ctx context.Context, node uuid.UUID, pub *ecdsa.PublicKey, zones []string) ([]Bundle, error) {
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, errors.New("hubctl: the node key is not usable")
	}
	pk := sha256.Sum256(spki)
	out := make([]Bundle, len(zones))
	var errs []error
	for i, z := range zones {
		b, err := c.bundleFor(ctx, node, pub, pk[:], z)
		if err != nil {
			errs = append(errs, fmt.Errorf("zone %s: %w", z, err))
			continue
		}
		out[i] = b
	}
	c.forget(node, zones)
	return out, errors.Join(errs...)
}

func (c *Certs) bundleFor(ctx context.Context, node uuid.UUID, pub *ecdsa.PublicKey, pk []byte, zone string) (Bundle, error) {
	if c.Wild != nil {
		chain, keyDER, notAfter, found, err := c.Wild.Covering(ctx, zone)
		if err != nil {
			return Bundle{}, fmt.Errorf("wildcard: %w", err)
		}
		if found {
			sealed, err := Seal(pub, keyDER)
			clear(keyDER)
			if err != nil {
				return Bundle{}, err
			}
			h := sha256.Sum256(chain)
			return Bundle{ID: zone + "/w/" + fmt.Sprintf("%x", h[:8]), Msg: &hubv1.CertBundle{
				Kind: signv1.Kind_KIND_CERTS, WrappedKey: sealed, ChainPem: chain, NotAfter: notAfter.Unix()}}, nil
		}
	}
	ca := c.CAs.Zone()
	if ca == nil {
		return Bundle{}, ErrNoZoneCA
	}
	now := c.Now()
	caID := fmt.Sprintf("%x", sha256.Sum256(ca.CertDER()))
	k := issuedKey{node, zone}
	c.mu.Lock()
	have := c.cache[k]
	c.mu.Unlock()
	if have != nil && have.caKey == caID && bytes.Equal(have.pub, pk) && now.Before(have.renewAt) {
		return have.b, nil
	}
	leaf, err := ca.IssueLeaf(zone, now)
	if err != nil {
		return Bundle{}, fmt.Errorf("zone leaf: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(leaf.Key)
	if err != nil {
		return Bundle{}, errors.New("hubctl: the leaf key cannot be encoded")
	}
	sealed, err := Seal(pub, keyDER)
	clear(keyDER)
	if err != nil {
		return Bundle{}, err
	}
	chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.DER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.CertDER()})...)
	id := fmt.Sprintf("%s/p/%s", zone, leaf.Serial)
	b := Bundle{ID: id, Msg: &hubv1.CertBundle{Kind: signv1.Kind_KIND_CERTS, WrappedKey: sealed, ChainPem: chain, NotAfter: leaf.NotAfter.Unix()}}
	life := leaf.NotAfter.Sub(leaf.NotBefore)
	c.mu.Lock()
	c.cache[k] = &issued{b: b, caKey: caID, pub: pk, renewAt: leaf.NotAfter.Add(-life / 3)}
	c.mu.Unlock()
	return b, nil
}

// forget drops what the node no longer has a zone for, so a finished transition does not keep a sealed key in memory.
func (c *Certs) forget(node uuid.UUID, zones []string) {
	keep := make(map[string]bool, len(zones))
	for _, z := range zones {
		keep[z] = true
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for k := range c.cache {
		if k.node == node && !keep[k.zone] {
			delete(c.cache, k)
		}
	}
}

// Drop forgets everything held for a node, for a node that is revoked or removed.
func (c *Certs) Drop(node uuid.UUID) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k := range c.cache {
		if k.node == node {
			delete(c.cache, k)
		}
	}
}

// Seal seals a PKCS#8 key to a node's public key with HPKE (RFC 9180): DHKEM(P-256), HKDF-SHA256, AES-256-GCM, single
// shot, info SealInfo. Only the node's private key opens it.
func Seal(pub *ecdsa.PublicKey, keyDER []byte) ([]byte, error) {
	ek, err := pub.ECDH()
	if err != nil {
		return nil, errors.New("hubctl: the node key is not usable for HPKE")
	}
	pk, err := hpke.DHKEM(ecdh.P256()).NewPublicKey(ek.Bytes())
	if err != nil {
		return nil, errors.New("hubctl: the node key is not usable for HPKE")
	}
	return hpke.Seal(pk, hpke.HKDFSHA256(), hpke.AES256GCM(), []byte(SealInfo), keyDER)
}
