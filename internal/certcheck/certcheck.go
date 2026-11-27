// Package certcheck is the one check of a certificate row and the one choice between rows (p4-nodes 4.3, p6-ops 5.5).
//
// The admin upload route calls Check before it stores anything; the hub (for kind wildcard), domain-apply (for panel and
// admin) and the admin's cards call Choose, so one rule decides which uploaded or issued row is in force. Names and the
// end of life come from the leaf itself and never from the columns of a row, because a row that SQL wrote past the
// writer must not be served (p6-ops 5.5).
//
// The chain is verified against the Mozilla roots embedded in the binary (x509roots), never against the host's store and
// never over the network: a public certificate is the test of AUTH 7.2 and keeps a zone under SC 8a.4's public-store
// probe, and nothing at run time may depend on the international internet (rule 9).
package certcheck

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/x509roots/fallback/bundle"
)

// Kind is the kind of an uploaded row (the certificates.kind values the admin may insert).
type Kind string

// The kinds that Check and Choose judge.
const (
	Wildcard Kind = "wildcard"
	Panel    Kind = "panel"
	Admin    Kind = "admin"
)

// Valid reports membership.
func (k Kind) Valid() bool { return k == Wildcard || k == Panel || k == Admin }

// ParseKind is the one way a text from a request becomes a Kind; ok is false for anything that is not a member.
func ParseKind(s string) (Kind, bool) {
	k := Kind(s)
	return k, k.Valid()
}

// The refusals, one for each error code of p4-nodes 9.4. A caller maps them with errors.Is; none carries a name, a
// chain or a key, so the text is safe to log.
var (
	// ErrInvalid is cert_invalid: no parse, not a leaf with its chain, or names outside the rule of 4.3.
	ErrInvalid = errors.New("certcheck: the chain is not a valid leaf with names the kind allows")
	// ErrKeyMismatch is cert_key_mismatch: the key is not the leaf's.
	ErrKeyMismatch = errors.New("certcheck: the key does not belong to the leaf")
	// ErrNotPublic is cert_not_public: the chain does not verify to the embedded public roots.
	ErrNotPublic = errors.New("certcheck: the chain does not verify to a public root")
	// ErrExpiring is cert_expiring: the leaf is expired, or has less life left than the caller asks for.
	ErrExpiring = errors.New("certcheck: the leaf has too little life left")
)

// MinUploadLife is the life an uploaded leaf must still have (p4-nodes 4.3: valid now and for at least 7 days).
const MinUploadLife = 7 * 24 * time.Hour

// maxChain bounds the certificates read from one PEM. A real chain has two to four; the cap keeps a hostile upload from
// making the verifier build a very long path.
const maxChain = 8

// Scope says which names a certificate must cover: the live zones for a wildcard, or one host for panel and admin.
type Scope struct {
	Zones []string
	Host  string
}

// Options tune Check. The zero value is what Choose uses: the embedded roots, no key to compare, valid now.
type Options struct {
	// KeyPublic is the PKIX DER of the public half of the private key the caller holds (ParseKey gives it), compared with
	// the leaf's public key. Nil skips the comparison. It is bytes and not a key type so that this package never names the
	// bare crypto package, which the import allow list keeps for the hash of a code (internal/lint imports.yaml).
	KeyPublic []byte
	// MinLife is how long the leaf must stay valid after now. Zero means valid at now.
	MinLife time.Duration
	// Roots replaces the embedded roots. Only tests set it, with a root of their own.
	Roots *x509.CertPool
}

// Result is what Check read from the leaf.
type Result struct {
	Names     []string // the DNS names of the leaf, lower case, in the leaf's order
	NotBefore time.Time
	NotAfter  time.Time
	Leaf      *x509.Certificate
	// ChainPEM is the chain written again from the parsed certificates, so text between or after the blocks of the upload
	// is never stored.
	ChainPEM string
}

// ZoneNames are the three names a zone certificate covers (4.3): the zone, every name directly under it and every name
// directly under verify.<zone>.
func ZoneNames(zone string) []string {
	return []string{zone, "*." + zone, "*.verify." + zone}
}

// CoversZone says whether one certificate's SAN list covers the three names of a zone (4.3), the way a node is given a
// wildcard: each name of ZoneNames must match a SAN under RFC 6125. It is the one reading of "covers" in the program: Check
// uses it for an upload, and the domain-change job of the worker uses it to choose the notice a tenant reads.
func CoversZone(sans []string, zone string) bool {
	return zone != "" && covers(sans, ZoneNames(zone))
}

// EmbeddedRoots builds the pool of Mozilla roots. A root with a distrust-after date goes in with its constraint, so a
// leaf the program no longer trusts from that date does not verify. It is built on each call and not kept in a variable
// (no package-level state): a caller that judges many rows, as Choose does, builds it once and passes it in Options.
func EmbeddedRoots() *x509.CertPool {
	p := x509.NewCertPool()
	for r := range bundle.Roots() {
		c, err := x509.ParseCertificate(r.Certificate)
		if err != nil {
			continue // the bundle is generated and tested upstream; one unreadable root is not worth refusing every upload for
		}
		if r.Constraint == nil {
			p.AddCert(c)
		} else {
			p.AddCertWithConstraint(c, r.Constraint)
		}
	}
	return p
}

// ParseChain reads a PEM text of certificates, leaf first. Anything but CERTIFICATE blocks, and trailing text that is not
// whitespace, is refused, so a key pasted into the chain field is never accepted as a chain.
func ParseChain(chainPEM []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	rest := chainPEM
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" || len(b.Headers) != 0 {
			return nil, ErrInvalid
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, ErrInvalid
		}
		out = append(out, c)
		if len(out) > maxChain {
			return nil, ErrInvalid
		}
	}
	if len(out) == 0 || strings.TrimSpace(string(rest)) != "" {
		return nil, ErrInvalid
	}
	return out, nil
}

// EncodeChain writes certificates as PEM, in order.
func EncodeChain(chain []*x509.Certificate) string {
	var b strings.Builder
	for _, c := range chain {
		b.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
	}
	return b.String()
}

// ParseKey reads one unencrypted private key in PEM (PKCS #8, PKCS #1 or SEC 1) and returns the PKIX DER of its public half
// (for Options.KeyPublic) and the same key written as PKCS #8 PEM, the one form the hub and domain-apply read after they
// open the seal. An encrypted key, a second block and any other text are ErrInvalid: the route has no password to ask for.
func ParseKey(keyPEM []byte) (publicDER, pkcs8PEM []byte, err error) {
	b, rest := pem.Decode(keyPEM)
	if b == nil || strings.TrimSpace(string(rest)) != "" || len(b.Headers) != 0 {
		return nil, nil, ErrInvalid
	}
	var k any
	switch b.Type {
	case "PRIVATE KEY":
		k, err = x509.ParsePKCS8PrivateKey(b.Bytes)
	case "RSA PRIVATE KEY":
		k, err = x509.ParsePKCS1PrivateKey(b.Bytes)
	case "EC PRIVATE KEY":
		k, err = x509.ParseECPrivateKey(b.Bytes)
	default:
		return nil, nil, ErrInvalid
	}
	if err != nil {
		return nil, nil, ErrInvalid
	}
	var pub any
	switch key := k.(type) {
	case *rsa.PrivateKey:
		pub = &key.PublicKey
	case *ecdsa.PrivateKey:
		pub = &key.PublicKey
	case ed25519.PrivateKey:
		pub = key.Public()
	default:
		return nil, nil, ErrInvalid
	}
	publicDER, err = x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, nil, ErrInvalid
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, nil, ErrInvalid
	}
	return publicDER, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// Check judges a chain for a kind and a scope. The order of the refusals is the order of what an admin can fix first:
// the shape and the names, then the key, then the life, then the chain.
func Check(chainPEM []byte, kind Kind, scope Scope, now time.Time, o Options) (Result, error) {
	if !kind.Valid() {
		return Result{}, ErrInvalid
	}
	chain, err := ParseChain(chainPEM)
	if err != nil {
		return Result{}, err
	}
	leaf := chain[0]
	// A CA certificate is not a leaf, and a leaf with IP, e-mail or URI names would cover things the rule of 4.3 never
	// names. Names come from the DNS SANs alone: the common name is ignored, as every client ignores it.
	if leaf.IsCA || len(leaf.IPAddresses) != 0 || len(leaf.EmailAddresses) != 0 || len(leaf.URIs) != 0 {
		return Result{}, ErrInvalid
	}
	names := make([]string, len(leaf.DNSNames))
	for i, n := range leaf.DNSNames {
		names[i] = strings.ToLower(n)
	}
	if !namesFit(kind, scope, names) {
		return Result{}, ErrInvalid
	}
	if o.KeyPublic != nil && !samePublicKey(leaf.PublicKey, o.KeyPublic) {
		return Result{}, ErrKeyMismatch
	}
	if now.Before(leaf.NotBefore) {
		return Result{}, ErrInvalid
	}
	if !now.Add(o.MinLife).Before(leaf.NotAfter) {
		return Result{}, ErrExpiring
	}
	roots := o.Roots
	if roots == nil {
		roots = EmbeddedRoots()
	}
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	// No DNSName here: the names were judged above by the rule of the kind, which a hostname check of one name cannot say.
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return Result{}, ErrNotPublic
	}
	return Result{Names: names, NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter, Leaf: leaf, ChainPEM: EncodeChain(chain)}, nil
}

// samePublicKey compares the leaf's public key with a PKIX DER by encoding the leaf's the same way.
func samePublicKey(leafPub any, der []byte) bool {
	got, err := x509.MarshalPKIXPublicKey(leafPub)
	return err == nil && bytes.Equal(got, der)
}

// namesFit is the name rule of 4.3. A wildcard leaf's names are exactly the three names of one live zone (they lie
// inside that set and cover it); a panel or admin leaf covers its host.
func namesFit(kind Kind, scope Scope, names []string) bool {
	if len(names) == 0 {
		return false
	}
	if kind == Wildcard {
		return slices.ContainsFunc(scope.Zones, func(z string) bool {
			want := ZoneNames(z)
			return z != "" && covers(names, want) && inside(names, want)
		})
	}
	return scope.Host != "" && coversHost(names, scope.Host)
}

// covers says that every name of want matches a SAN: the same text, or for a concrete name a wildcard SAN under
// RFC 6125 (one label only, and only as the leftmost label). A wanted name that is itself a wildcard is covered only by
// the same text, so `*.zone` does not stand in for `*.verify.zone`.
func covers(sans, want []string) bool {
	for _, w := range want {
		if !coversHost(sans, w) {
			return false
		}
	}
	return true
}

func coversHost(sans []string, host string) bool {
	host = strings.ToLower(host)
	for _, s := range sans {
		if s == host {
			return true
		}
		if strings.HasPrefix(host, "*") || !strings.HasPrefix(s, "*.") {
			continue
		}
		suffix := s[1:] // ".example.com"
		if !strings.HasSuffix(host, suffix) {
			continue
		}
		label := host[:len(host)-len(suffix)]
		if label != "" && !strings.Contains(label, ".") {
			return true
		}
	}
	return false
}

// inside says that every SAN is one of the wanted names, so a leaf that also names a host outside the zone is refused.
func inside(sans, want []string) bool {
	for _, s := range sans {
		if !slices.Contains(want, s) {
			return false
		}
	}
	return true
}

// Row is a row of the certificates table as Choose reads it.
type Row struct {
	ID       uuid.UUID
	State    string // only "active" rows are chosen
	ChainPEM string
	// Revoked is set for a row named in certificate_revocations (p6-ops 5.4); such a row is picked only when no other is.
	Revoked bool
}

// Choose picks the row in force for names (4.3): of the active rows that pass Check and cover names, whatever their
// source, the one whose leaf ends last, ties by the newest id (uuidv7, so the larger bytes). With none, ok is false and
// the zone is in private-CA mode, so devices that installed the zone CA keep working after a public certificate ended.
//
// kind and scope say what a row must cover. They are the same as Check's, so a row whose names changed under it in the
// database is refused here exactly as the upload would have refused it.
func Choose(rows []Row, kind Kind, scope Scope, now time.Time, o Options) (Row, Result, bool) {
	var best, bestRevoked *candidate
	if o.Roots == nil {
		o.Roots = EmbeddedRoots()
	}
	for i := range rows {
		r := rows[i]
		if r.State != "active" {
			continue
		}
		res, err := Check([]byte(r.ChainPEM), kind, scope, now, o)
		if err != nil {
			continue
		}
		c := &candidate{row: r, res: res}
		if r.Revoked {
			bestRevoked = better(bestRevoked, c)
		} else {
			best = better(best, c)
		}
	}
	if best == nil {
		best = bestRevoked
	}
	if best == nil {
		return Row{}, Result{}, false
	}
	return best.row, best.res, true
}

type candidate struct {
	row Row
	res Result
}

// better returns the candidate whose leaf ends later, then the one with the larger id.
func better(cur, c *candidate) *candidate {
	if cur == nil {
		return c
	}
	switch {
	case c.res.NotAfter.After(cur.res.NotAfter):
		return c
	case c.res.NotAfter.Equal(cur.res.NotAfter) && slices.Compare(c.row.ID[:], cur.row.ID[:]) > 0:
		return c
	}
	return cur
}
