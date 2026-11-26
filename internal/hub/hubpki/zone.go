package hubpki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"slices"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"

	"github.com/Kup1ng/CtrlZ-Panel/internal/certcheck"
)

// ZoneCA is the private zone CA of p4-nodes 4.3: self-signed, ten years, pathlen 0, EKU serverAuth,
// critical name constraints that permit the live zones and exclude every address, e-mail and URI.
type ZoneCA struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
	rand io.Reader
}

// ZoneSubject is the subject of the zone CA certificate for a key. It is a function of the key, so
// a reissue over the same key keeps the subject (an installed copy still verifies the new leaves
// until its own not_after) and a new key makes a new one (the notice then says to remove the old CA).
func ZoneSubject(pub *ecdsa.PublicKey) (string, error) {
	h, err := SPKISHA256(pub)
	if err != nil {
		return "", err
	}
	return "Ctrl Z zone CA " + hex.EncodeToString(h[:6]), nil
}

// ValidZone is the rule of domain_invalid (p4-nodes 9.4), applied again by the hub before it signs
// anything: lower-case hostname grammar, the prefix "dns.", and a remainder that is not a public suffix
// and has at least two labels. The database CHECK holds only the prefix and the grammar, and the
// route's check is a separate piece of code, so a wrong or hostile domain_settings row must still not
// become a ten-year CA over names the operator does not own ("dns.com", "dns.co.ir"). The public suffix
// list is the one compiled into golang.org/x/net/publicsuffix, so no network is needed.
func ValidZone(z string) bool {
	if len(z) > 253 || !hostRE.MatchString(z) {
		return false
	}
	rest, ok := strings.CutPrefix(z, "dns.")
	if !ok || strings.Count(rest, ".") < 1 {
		return false
	}
	suffix, _ := publicsuffix.PublicSuffix(rest)
	return suffix != rest
}

func validZone(z string) bool { return ValidZone(z) }

// IssueZoneCA makes the CA certificate for key over zones (at most two: the live zone and the
// previous one during a transition). It refuses a zone outside the grammar before anything is signed.
func IssueZoneCA(key *ecdsa.PrivateKey, zones []string, now time.Time) (*ZoneCA, error) {
	return issueZoneCA(key, zones, now, rand.Reader)
}

func issueZoneCA(key *ecdsa.PrivateKey, zones []string, now time.Time, rnd io.Reader) (*ZoneCA, error) {
	if key == nil || key.Curve != elliptic.P256() {
		return nil, ErrKey
	}
	zs := slices.Clone(zones)
	slices.Sort(zs)
	zs = slices.Compact(zs)
	if len(zs) == 0 || len(zs) > 2 {
		return nil, ErrZone
	}
	var permitted []string
	for _, z := range zs {
		if !validZone(z) {
			return nil, ErrZone
		}
		permitted = append(permitted, z, "."+z)
	}
	cn, err := ZoneSubject(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	sn, err := randSerial(rnd)
	if err != nil {
		return nil, err
	}
	t := &x509.Certificate{
		SerialNumber:                sn,
		Subject:                     pkix.Name{CommonName: cn},
		NotBefore:                   now.Add(-backdate).UTC().Truncate(time.Second),
		NotAfter:                    now.Add(ZoneCALife).UTC().Truncate(time.Second),
		KeyUsage:                    x509.KeyUsageCertSign,
		ExtKeyUsage:                 []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid:       true,
		IsCA:                        true,
		MaxPathLen:                  0,
		MaxPathLenZero:              true,
		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         permitted,
		ExcludedIPRanges: []*net.IPNet{
			{IP: net.IPv4zero.To4(), Mask: net.CIDRMask(0, 32)},
			{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
		},
		// An empty constraint matches every name of its kind (Go follows NSS here), so these exclude
		// all e-mail addresses and all URIs.
		ExcludedEmailAddresses: []string{""},
		ExcludedURIDomains:     []string{""},
	}
	der, err := x509.CreateCertificate(rnd, t, t, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("hubpki: zone CA: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("hubpki: zone CA: %w", err)
	}
	return &ZoneCA{key: key, cert: cert, rand: rnd}, nil
}

// LoadZoneCA wraps an existing CA certificate (the active zone_ca row) over its key, checking that
// the certificate carries the key and is a CA.
func LoadZoneCA(key *ecdsa.PrivateKey, certDER []byte) (*ZoneCA, error) {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, ErrCA
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || key == nil || !pub.Equal(&key.PublicKey) || !cert.IsCA {
		return nil, ErrCA
	}
	return &ZoneCA{key: key, cert: cert, rand: rand.Reader}, nil
}

// Cert and CertDER give the public certificate.
func (z *ZoneCA) Cert() *x509.Certificate { return z.cert }
func (z *ZoneCA) CertDER() []byte         { return z.cert.Raw }

// Zones are the zones the certificate permits, read back from its constraints.
func (z *ZoneCA) Zones() []string {
	var out []string
	for _, d := range z.cert.PermittedDNSDomains {
		if !strings.HasPrefix(d, ".") {
			out = append(out, d)
		}
	}
	slices.Sort(out)
	return out
}

// Reusable says whether this CA certificate may go on being used for zones at now: it carries the
// key, permits exactly these zones, and has more than a third of its life left (4.3).
func (z *ZoneCA) Reusable(key *ecdsa.PrivateKey, zones []string, now time.Time) bool {
	pub, ok := z.cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || key == nil || !pub.Equal(&key.PublicKey) {
		return false
	}
	want := slices.Clone(zones)
	slices.Sort(want)
	want = slices.Compact(want)
	if !slices.Equal(z.Zones(), want) {
		return false
	}
	life := z.cert.NotAfter.Sub(z.cert.NotBefore)
	return z.cert.NotAfter.Sub(now) > life/3 && !now.Before(z.cert.NotBefore)
}

// ZoneNames are the three names a zone certificate covers (4.3): the zone, every name directly under
// it, and every name directly under verify.<zone>. The list is certcheck.ZoneNames, the one the admin's upload check and
// the hub's leaves are both judged by.
func ZoneNames(zone string) []string { return certcheck.ZoneNames(zone) }

// ZoneLeaf is a zone certificate and the key made for it. The key is the caller's to seal for one
// node and drop: it is generated per issue and the hub never stores it.
type ZoneLeaf struct {
	Issued
	Key   *ecdsa.PrivateKey
	Names []string
}

// IssueLeaf signs a 30-day certificate for zone with a new key. It refuses a zone the CA does not
// permit, and caps not_after at the CA's.
func (z *ZoneCA) IssueLeaf(zone string, now time.Time) (ZoneLeaf, error) {
	if !slices.Contains(z.Zones(), zone) || !validZone(zone) {
		return ZoneLeaf{}, ErrZone
	}
	end, err := capLife(now, ZoneLeafLife, z.cert)
	if err != nil {
		return ZoneLeaf{}, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), z.rand)
	if err != nil {
		return ZoneLeaf{}, err
	}
	sn, err := randSerial(z.rand)
	if err != nil {
		return ZoneLeaf{}, err
	}
	names := ZoneNames(zone)
	t := &x509.Certificate{
		SerialNumber:          sn,
		Subject:               pkix.Name{CommonName: zone},
		DNSNames:              names,
		NotBefore:             now.Add(-backdate).UTC().Truncate(time.Second),
		NotAfter:              end.UTC().Truncate(time.Second),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(z.rand, t, z.cert, &key.PublicKey, z.key)
	if err != nil {
		return ZoneLeaf{}, fmt.Errorf("hubpki: zone leaf: %w", err)
	}
	return ZoneLeaf{Issued: Issued{DER: der, Serial: t.SerialNumber.Text(16), NotBefore: t.NotBefore, NotAfter: t.NotAfter}, Key: key, Names: names}, nil
}
