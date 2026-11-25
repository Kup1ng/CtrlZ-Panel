// Package hubpki is the hub's private PKI (p4-nodes 3.3, 4.3): the node CA that signs the 30-day
// node client certificates and the hub's own server leaf, and the zone CA that signs the per-node
// zone certificates in private-CA mode.
//
// Why the CAs are separate. The node CA authenticates nodes to the hub and the hub to nodes, and
// nothing a user's device is asked to trust. The zone CA is the one a user may install on a phone
// (T-248), so it is bounded by critical name constraints: it can sign a name inside the live zones
// and nothing else, never an IP address, an e-mail address or a URI. A key that leaked from it is
// worth a certificate for the zone and no more.
//
// What is not here: no private key is written to disk or logged, and no function returns a key it
// loaded. A zone leaf's key is generated per issue and handed to the caller to seal for one node.
package hubpki

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Lifetimes (p4-nodes 3.3, 4.2 step 6, 4.3).
const (
	ClientLife   = 30 * 24 * time.Hour
	ServerLife   = 365 * 24 * time.Hour
	ZoneLeafLife = 30 * 24 * time.Hour
	ZoneCALife   = 10 * 365 * 24 * time.Hour
	// backdate keeps a certificate valid for a node whose clock is a little behind. The node tolerates a
	// further day at install (enroll.accept).
	backdate = 5 * time.Minute
)

// RenewalGrace is how long after not_after a node may still renew (D31, 4.3).
const RenewalGrace = 60 * 24 * time.Hour

var (
	ErrKey     = errors.New("hubpki: the key is not an ECDSA P-256 private key in PEM")
	ErrCA      = errors.New("hubpki: the CA certificate is not usable")
	ErrZone    = errors.New("hubpki: zone is not a name the zone CA may sign")
	ErrSAN     = errors.New("hubpki: a server name is neither an address nor a host name")
	ErrExpired = errors.New("hubpki: the CA has expired")
)

// ParseKey reads an ECDSA P-256 private key from PEM (PKCS#8, which openssl genpkey writes, or SEC 1).
func ParseKey(pemBytes []byte) (*ecdsa.PrivateKey, error) {
	blk, _ := pem.Decode(pemBytes)
	if blk == nil {
		return nil, ErrKey
	}
	var k any
	var err error
	switch blk.Type {
	case "PRIVATE KEY":
		k, err = x509.ParsePKCS8PrivateKey(blk.Bytes)
	case "EC PRIVATE KEY":
		k, err = x509.ParseECPrivateKey(blk.Bytes)
	default:
		return nil, ErrKey
	}
	if err != nil {
		return nil, ErrKey
	}
	ec, ok := k.(*ecdsa.PrivateKey)
	if !ok || ec.Curve != elliptic.P256() {
		return nil, ErrKey
	}
	return ec, nil
}

// SPKI is the DER SubjectPublicKeyInfo of a public key.
func SPKI(pub *ecdsa.PublicKey) ([]byte, error) { return x509.MarshalPKIXPublicKey(pub) }

// SPKISHA256 is the SHA-256 of the SubjectPublicKeyInfo: the pin of the hub leaf, the fingerprint of
// a node key and nodes.spki_sha256.
func SPKISHA256(pub *ecdsa.PublicKey) ([]byte, error) {
	der, err := SPKI(pub)
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(der)
	return h[:], nil
}

// CertSPKISHA256 is SPKISHA256 of a certificate's key, from the certificate's own encoding.
func CertSPKISHA256(c *x509.Certificate) []byte {
	h := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return h[:]
}

// SerialText is the text form of a certificate serial the database holds (node_certs.serial,
// nodes.cert_serial): lower-case hexadecimal without leading zeros.
func SerialText(c *x509.Certificate) string { return c.SerialNumber.Text(16) }

// ParseNodeID reads a node id from a certificate CN: 32 hexadecimal digits or the canonical dashed
// UUID, either case. It reads nothing else (no braces, no urn prefix): a CN the hub did not write is
// not a node id.
func ParseNodeID(cn string) (uuid.UUID, bool) {
	switch len(cn) {
	case 32:
		var id uuid.UUID
		if _, err := hex.Decode(id[:], []byte(cn)); err != nil {
			return uuid.Nil, false
		}
		return id, id != uuid.Nil
	case 36:
		id, err := uuid.Parse(cn)
		if err != nil || id == uuid.Nil || cn[8] != '-' || cn[13] != '-' || cn[18] != '-' || cn[23] != '-' {
			return uuid.Nil, false
		}
		return id, true
	}
	return uuid.Nil, false
}

func randSerial(r io.Reader) (*big.Int, error) {
	// 128 random bits and never zero. A set top bit costs one leading zero byte in the DER integer, which
	// x509.CreateCertificate adds itself (it accepts a positive serial up to 160 bits), so no bit is spent
	// on the sign (W3-r4-1).
	for {
		b := make([]byte, 16)
		if _, err := io.ReadFull(r, b); err != nil {
			return nil, err
		}
		n := new(big.Int).SetBytes(b)
		if n.Sign() > 0 {
			return n, nil
		}
	}
}

// NodeCA signs the node client certificates and the server leaves of the hub and of NTS.
type NodeCA struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
	pool *x509.CertPool
	rand io.Reader
}

// LoadNodeCA reads the node CA from its key and certificate PEM. It checks what a start must not
// guess: the certificate is a CA that may sign certificates, is valid at now, and carries this key.
func LoadNodeCA(keyPEM, certPEM []byte, now time.Time) (*NodeCA, error) {
	key, err := ParseKey(keyPEM)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(certPEM)
	if blk == nil || blk.Type != "CERTIFICATE" {
		return nil, ErrCA
	}
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return nil, ErrCA
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&key.PublicKey) {
		return nil, fmt.Errorf("%w: it does not carry the key", ErrCA)
	}
	if !cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, fmt.Errorf("%w: not a CA that signs certificates", ErrCA)
	}
	if now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
		return nil, fmt.Errorf("%w: not valid now", ErrCA)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &NodeCA{key: key, cert: cert, pool: pool, rand: rand.Reader}, nil
}

// Cert, CertDER and Pool give the public side: what nodes get as their chain, and what the hub
// verifies client certificates against.
func (c *NodeCA) Cert() *x509.Certificate { return c.cert }
func (c *NodeCA) CertDER() []byte         { return c.cert.Raw }
func (c *NodeCA) Pool() *x509.CertPool    { return c.pool }

// PEM is the CA certificate as GET /install/node_ca.pem serves it.
func (c *NodeCA) PEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.cert.Raw})
}

// Issued is a certificate the hub signed.
type Issued struct {
	DER       []byte
	Serial    string
	NotBefore time.Time
	NotAfter  time.Time
}

func capLife(now time.Time, life time.Duration, ca *x509.Certificate) (time.Time, error) {
	end := now.Add(life)
	if end.After(ca.NotAfter) {
		// No leaf outlives its CA (4.3). A CA that is gone is an error for the caller to raise, not a
		// certificate that is born expired.
		if !ca.NotAfter.After(now) {
			return time.Time{}, ErrExpired
		}
		end = ca.NotAfter
	}
	return end, nil
}

// IssueClient signs a node client certificate for pub (p4-nodes 4.2 step 6). The hub takes only the
// public key from the node's CSR and builds this template itself: CN the node id, no SAN, digital
// signature, EKU clientAuth only, not a CA, 30 days, a random 128-bit serial.
func (c *NodeCA) IssueClient(pub *ecdsa.PublicKey, nodeID uuid.UUID, now time.Time) (Issued, error) {
	if pub == nil || pub.Curve != elliptic.P256() || nodeID == uuid.Nil {
		return Issued{}, ErrKey
	}
	end, err := capLife(now, ClientLife, c.cert)
	if err != nil {
		return Issued{}, err
	}
	sn, err := randSerial(c.rand)
	if err != nil {
		return Issued{}, err
	}
	t := &x509.Certificate{
		SerialNumber:          sn,
		Subject:               pkix.Name{CommonName: nodeID.String()},
		NotBefore:             now.Add(-backdate).UTC().Truncate(time.Second),
		NotAfter:              end.UTC().Truncate(time.Second),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	return c.sign(t, pub)
}

func (c *NodeCA) sign(t *x509.Certificate, pub *ecdsa.PublicKey) (Issued, error) {
	der, err := x509.CreateCertificate(c.rand, t, c.cert, pub, c.key)
	if err != nil {
		return Issued{}, fmt.Errorf("hubpki: sign: %w", err)
	}
	return Issued{DER: der, Serial: t.SerialNumber.Text(16), NotBefore: t.NotBefore, NotAfter: t.NotAfter}, nil
}

var hostRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)

// Names splits a comma-separated list of server names (CTRLZ_HUB_HOST) into the DNS and IP SANs of a
// certificate. An IPv4-mapped IPv6 literal is refused: it would be a name no client dials.
func Names(list string) (dns []string, ips []net.IP, err error) {
	for _, raw := range strings.Split(list, ",") {
		s := strings.ToLower(strings.TrimSpace(raw))
		if s == "" {
			continue
		}
		if a, perr := netip.ParseAddr(s); perr == nil {
			if a.Is4In6() || a.Zone() != "" || a.IsUnspecified() {
				return nil, nil, ErrSAN
			}
			ips = append(ips, net.IP(a.AsSlice()))
			continue
		}
		if len(s) > 253 || !hostRE.MatchString(s) {
			return nil, nil, ErrSAN
		}
		dns = append(dns, s)
	}
	if len(dns)+len(ips) == 0 {
		return nil, nil, ErrSAN
	}
	return dns, ips, nil
}

// IssueServer signs a serverAuth-only leaf for a key the caller holds: the hub's TLS leaf on 9443 and
// the NTS leaf (7.10). Neither may ever pass as a node client certificate: EKU serverAuth alone, and a
// subject that is not a node id.
func (c *NodeCA) IssueServer(pub *ecdsa.PublicKey, cn string, dns []string, ips []net.IP, life time.Duration, now time.Time) (Issued, error) {
	if pub == nil || pub.Curve != elliptic.P256() {
		return Issued{}, ErrKey
	}
	if _, isNode := ParseNodeID(cn); isNode {
		return Issued{}, errors.New("hubpki: a server leaf is never named like a node")
	}
	end, err := capLife(now, life, c.cert)
	if err != nil {
		return Issued{}, err
	}
	sn, err := randSerial(c.rand)
	if err != nil {
		return Issued{}, err
	}
	t := &x509.Certificate{
		SerialNumber:          sn,
		Subject:               pkix.Name{CommonName: cn},
		DNSNames:              dns,
		IPAddresses:           ips,
		NotBefore:             now.Add(-backdate).UTC().Truncate(time.Second),
		NotAfter:              end.UTC().Truncate(time.Second),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	return c.sign(t, pub)
}

// ClientVerifyTime is the instant a node certificate is verified at: now, or, for a certificate that
// expired while the panel was away, the last second it was valid, when now is within RenewalGrace past
// not_after (D31, 4.3). The caller decides which RPCs may use the grace (RenewCert only).
func ClientVerifyTime(c *x509.Certificate, now time.Time, grace bool) (time.Time, bool) {
	if now.Before(c.NotBefore) {
		return time.Time{}, false
	}
	if now.Before(c.NotAfter) {
		return now, true
	}
	if grace && now.Sub(c.NotAfter) <= RenewalGrace {
		return c.NotAfter.Add(-time.Second), true
	}
	return time.Time{}, false
}

// VerifyClient checks a presented certificate the way every node door does (5.1, 4.4): it chains to
// the node CA, carries EKU clientAuth (and so is no hub or NTS leaf), is no CA, and its CN is a node
// id. It returns the node id. grace allows the 60-day renewal window past not_after.
//
// Why there is no intermediates argument. The node CA signs node leaves directly, so no honest client
// has an intermediate to show. Letting the peer name one would let an anonymous source choose the
// certificates Verify tries (up to 100 signature checks, each over a key it picked, before it has
// proved any key of its own, W3-r4-4). Here the leaf must name the CA as its issuer and carry an ECDSA
// signature, and the chain is the leaf and the CA alone: at most one P-256 verification.
func (c *NodeCA) VerifyClient(leaf *x509.Certificate, now time.Time, grace bool) (uuid.UUID, error) {
	at, ok := ClientVerifyTime(leaf, now, grace)
	if !ok {
		return uuid.Nil, errors.New("hubpki: the certificate is not valid now")
	}
	if leaf.IsCA {
		return uuid.Nil, errors.New("hubpki: a CA certificate is no node certificate")
	}
	if !bytes.Equal(leaf.RawIssuer, c.cert.RawSubject) {
		return uuid.Nil, errors.New("hubpki: the certificate is not issued by the node CA")
	}
	switch leaf.SignatureAlgorithm {
	case x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512:
	default:
		return uuid.Nil, errors.New("hubpki: the certificate is not signed with ECDSA")
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: c.pool, CurrentTime: at, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return uuid.Nil, errors.New("hubpki: the certificate does not chain to the node CA for client use")
	}
	id, ok := ParseNodeID(leaf.Subject.CommonName)
	if !ok {
		return uuid.Nil, errors.New("hubpki: the subject is not a node id")
	}
	return id, nil
}
