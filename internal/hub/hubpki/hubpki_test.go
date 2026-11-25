package hubpki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/google/uuid"
)

var t0 = time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func keyPEM(t *testing.T, k *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// newNodeCA builds a node CA the way scripts/gen-secrets.sh does (self-signed, ten years).
func newNodeCA(t *testing.T) *NodeCA {
	t.Helper()
	k := newKey(t)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "Ctrl Z node CA"},
		NotBefore: t0.Add(-time.Hour), NotAfter: t0.Add(10 * 365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := LoadNodeCA(keyPEM(t, k), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), t0)
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

func TestLoadNodeCARefusals(t *testing.T) {
	k := newKey(t)
	other := newKey(t)
	mk := func(isCA bool, usage x509.KeyUsage, nb, na time.Time) []byte {
		tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "x"}, NotBefore: nb, NotAfter: na, IsCA: isCA, BasicConstraintsValid: true, KeyUsage: usage}
		der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
		if err != nil {
			t.Fatal(err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	good := mk(true, x509.KeyUsageCertSign, t0.Add(-time.Hour), t0.Add(time.Hour))
	if _, err := LoadNodeCA(keyPEM(t, k), good, t0); err != nil {
		t.Fatalf("good CA refused: %v", err)
	}
	cases := map[string]struct {
		key, cert []byte
	}{
		"other key":   {keyPEM(t, other), good},
		"not a CA":    {keyPEM(t, k), mk(false, x509.KeyUsageDigitalSignature, t0.Add(-time.Hour), t0.Add(time.Hour))},
		"no certsign": {keyPEM(t, k), mk(true, x509.KeyUsageDigitalSignature, t0.Add(-time.Hour), t0.Add(time.Hour))},
		"expired":     {keyPEM(t, k), mk(true, x509.KeyUsageCertSign, t0.Add(-2*time.Hour), t0.Add(-time.Hour))},
		"not yet":     {keyPEM(t, k), mk(true, x509.KeyUsageCertSign, t0.Add(time.Hour), t0.Add(2*time.Hour))},
		"junk key":    {[]byte("nope"), good},
		"junk cert":   {keyPEM(t, k), []byte("nope")},
	}
	for name, c := range cases {
		if _, err := LoadNodeCA(c.key, c.cert, t0); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestIssueClientAndVerify(t *testing.T) {
	ca := newNodeCA(t)
	nk := newKey(t)
	id := uuid.New()
	iss, err := ca.IssueClient(&nk.PublicKey, id, t0)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(iss.DER)
	if err != nil {
		t.Fatal(err)
	}
	if leaf.IsCA || len(leaf.DNSNames)+len(leaf.IPAddresses)+len(leaf.EmailAddresses)+len(leaf.URIs) != 0 {
		t.Fatal("a client certificate carries a SAN or is a CA")
	}
	if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || leaf.KeyUsage != x509.KeyUsageDigitalSignature {
		t.Fatalf("usage: %v %v", leaf.ExtKeyUsage, leaf.KeyUsage)
	}
	if got := leaf.NotAfter.Sub(t0); got < ClientLife-time.Second || got > ClientLife {
		t.Fatalf("life %v", got)
	}
	if SerialText(leaf) != iss.Serial || leaf.SerialNumber.BitLen() > 127 {
		t.Fatalf("serial %s", iss.Serial)
	}
	if got, err := ca.VerifyClient(leaf, nil, t0.Add(time.Hour), false); err != nil || got != id {
		t.Fatalf("verify: %v %v", got, err)
	}
	// The 32-digit form of the CN reads as the same node.
	if got, ok := ParseNodeID(hexOf(id)); !ok || got != id {
		t.Fatal("hex form")
	}

	// Past not_after: refused, except inside the grace of a renewal.
	past1 := leaf.NotAfter.Add(24 * time.Hour)
	if _, err := ca.VerifyClient(leaf, nil, past1, false); err == nil {
		t.Fatal("an expired certificate verified without the grace")
	}
	if got, err := ca.VerifyClient(leaf, nil, past1, true); err != nil || got != id {
		t.Fatalf("one day past with the grace: %v", err)
	}
	if _, err := ca.VerifyClient(leaf, nil, leaf.NotAfter.Add(RenewalGrace+time.Hour), true); err == nil {
		t.Fatal("61 days past verified")
	}
	if _, err := ca.VerifyClient(leaf, nil, t0.Add(-time.Hour), true); err == nil {
		t.Fatal("not yet valid verified")
	}
}

func hexOf(id uuid.UUID) string {
	const d = "0123456789abcdef"
	out := make([]byte, 0, 32)
	for _, b := range id {
		out = append(out, d[b>>4], d[b&15])
	}
	return string(out)
}

func TestParseNodeID(t *testing.T) {
	id := uuid.New()
	for _, ok := range []string{id.String(), hexOf(id)} {
		if got, good := ParseNodeID(ok); !good || got != id {
			t.Errorf("%q refused", ok)
		}
	}
	for _, bad := range []string{"", "ctrlz-node", "{" + id.String() + "}", "urn:uuid:" + id.String(), id.String()[:35], hexOf(id)[:31] + "g",
		"00000000-0000-0000-0000-000000000000", "00000000000000000000000000000000", id.String()[:8] + "x" + id.String()[9:]} {
		if _, good := ParseNodeID(bad); good {
			t.Errorf("%q accepted", bad)
		}
	}
}

// The hub leaf and the NTS leaf must never pass as node clients, whatever their names.
func TestServerLeafIsNotAClient(t *testing.T) {
	ca := newNodeCA(t)
	k := newKey(t)
	dns, ips, err := Names("Hub.Example.ir, 203.0.113.9, 2001:db8::9")
	if err != nil || len(dns) != 1 || dns[0] != "hub.example.ir" || len(ips) != 2 {
		t.Fatalf("names: %v %v %v", dns, ips, err)
	}
	iss, err := ca.IssueServer(&k.PublicKey, "ctrlz-hub", dns, ips, ServerLife, t0)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(iss.DER)
	if _, err := ca.VerifyClient(leaf, nil, t0, false); err == nil {
		t.Fatal("a server leaf verified as a client")
	}
	// Even with a CN that is a node id (which IssueServer refuses to write), EKU alone is enough.
	if _, err := ca.IssueServer(&k.PublicKey, uuid.NewString(), dns, ips, ServerLife, t0); err == nil {
		t.Fatal("a server leaf named like a node was issued")
	}
	// It verifies as a server for its names.
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: ca.Pool(), DNSName: "hub.example.ir", CurrentTime: t0}); err != nil {
		t.Fatalf("server verify: %v", err)
	}
	if got := len(leaf.IPAddresses); got != 2 || !leaf.IPAddresses[0].Equal(net.ParseIP("203.0.113.9")) {
		t.Fatalf("ip sans: %v", leaf.IPAddresses)
	}
}

func TestNamesRefusals(t *testing.T) {
	for _, bad := range []string{"", " , ", "::ffff:203.0.113.9", "0.0.0.0", "has space.example", "a..b", "-x.example", "fe80::1%eth0", "ex_ample.com"} {
		if _, _, err := Names(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestCapLifeAtCA(t *testing.T) {
	ca := newNodeCA(t)
	// Move the clock to a week before the CA ends: a 30-day certificate must end with the CA.
	late := ca.Cert().NotAfter.Add(-7 * 24 * time.Hour)
	iss, err := ca.IssueClient(&newKey(t).PublicKey, uuid.New(), late)
	if err != nil {
		t.Fatal(err)
	}
	if iss.NotAfter.After(ca.Cert().NotAfter) {
		t.Fatal("a leaf outlives its CA")
	}
	if _, err := ca.IssueClient(&newKey(t).PublicKey, uuid.New(), ca.Cert().NotAfter.Add(time.Hour)); err == nil {
		t.Fatal("issued from an expired CA")
	}
}

func TestZoneCA(t *testing.T) {
	key := newKey(t)
	zones := []string{"dns.example.ir", "dns.old.example.ir"}
	z, err := IssueZoneCA(key, zones, t0)
	if err != nil {
		t.Fatal(err)
	}
	c := z.Cert()
	if !c.IsCA || !c.MaxPathLenZero || c.MaxPathLen != 0 || !c.PermittedDNSDomainsCritical {
		t.Fatal("CA constraints")
	}
	if len(c.ExtKeyUsage) != 1 || c.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Fatal("CA EKU")
	}
	if got := z.Zones(); len(got) != 2 || got[0] != "dns.example.ir" {
		t.Fatalf("zones: %v", got)
	}
	subj, _ := ZoneSubject(&key.PublicKey)
	if c.Subject.CommonName != subj {
		t.Fatal("subject is not a function of the key")
	}

	pool := x509.NewCertPool()
	pool.AddCert(c)
	leaf, err := z.IssueLeaf("dns.example.ir", t0)
	if err != nil {
		t.Fatal(err)
	}
	lc, _ := x509.ParseCertificate(leaf.DER)
	if len(leaf.Names) != 3 || lc.NotAfter.Sub(t0) > ZoneLeafLife {
		t.Fatalf("leaf names %v life %v", leaf.Names, lc.NotAfter.Sub(t0))
	}
	// The three names verify under the CA, and a wildcard covers one label only.
	for _, name := range []string{"dns.example.ir", "abc.dns.example.ir", "abc.verify.dns.example.ir"} {
		if _, err := lc.Verify(x509.VerifyOptions{Roots: pool, DNSName: name, CurrentTime: t0.Add(time.Hour)}); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := lc.Verify(x509.VerifyOptions{Roots: pool, DNSName: "a.b.dns.example.ir", CurrentTime: t0.Add(time.Hour)}); err == nil {
		t.Error("a wildcard matched two labels")
	}
	// A zone the CA does not permit is refused by the hub, before it signs.
	if _, err := z.IssueLeaf("dns.other.ir", t0); err == nil {
		t.Fatal("a leaf for a zone outside the CA was issued")
	}

	// Go's verifier refuses what the hub would not sign, under the CA's own constraints (N13): an IP SAN,
	// an out-of-zone name, an e-mail and a URI. The hub's refusal is the first line, this the second.
	probe := func(tpl *x509.Certificate) error {
		pk := newKey(t)
		tpl.SerialNumber = big.NewInt(99)
		tpl.NotBefore, tpl.NotAfter = t0, t0.Add(time.Hour)
		tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		der, err := x509.CreateCertificate(rand.Reader, tpl, c, &pk.PublicKey, key)
		if err != nil {
			return err
		}
		p, _ := x509.ParseCertificate(der)
		_, err = p.Verify(x509.VerifyOptions{Roots: pool, CurrentTime: t0.Add(time.Minute)})
		return err
	}
	if err := probe(&x509.Certificate{Subject: pkix.Name{CommonName: "x"}, DNSNames: []string{"dns.example.ir"}}); err != nil {
		t.Fatalf("control leaf refused: %v", err)
	}
	if err := probe(&x509.Certificate{Subject: pkix.Name{CommonName: "x"}, DNSNames: []string{"dns.example.ir"}, IPAddresses: []net.IP{net.ParseIP("203.0.113.1")}}); err == nil {
		t.Error("an IPv4 SAN verified under the zone CA")
	}
	if err := probe(&x509.Certificate{Subject: pkix.Name{CommonName: "x"}, DNSNames: []string{"dns.example.ir"}, IPAddresses: []net.IP{net.ParseIP("2001:db8::1")}}); err == nil {
		t.Error("an IPv6 SAN verified under the zone CA")
	}
	if err := probe(&x509.Certificate{Subject: pkix.Name{CommonName: "x"}, DNSNames: []string{"www.google.com"}}); err == nil {
		t.Error("an out-of-zone name verified under the zone CA")
	}
	if err := probe(&x509.Certificate{Subject: pkix.Name{CommonName: "x"}, DNSNames: []string{"dns.example.ir"}, EmailAddresses: []string{"a@dns.example.ir"}}); err == nil {
		t.Error("an e-mail SAN verified under the zone CA")
	}
}

func TestZoneCAReuse(t *testing.T) {
	key := newKey(t)
	zones := []string{"dns.example.ir"}
	z, err := IssueZoneCA(key, zones, t0)
	if err != nil {
		t.Fatal(err)
	}
	if !z.Reusable(key, zones, t0.Add(24*time.Hour)) {
		t.Fatal("a fresh CA is not reusable")
	}
	if z.Reusable(newKey(t), zones, t0) {
		t.Fatal("reused over another key")
	}
	if z.Reusable(key, []string{"dns.example.ir", "dns.old.ir"}, t0) || z.Reusable(key, []string{"dns.other.ir"}, t0) {
		t.Fatal("reused for other zones")
	}
	// Past two thirds of its life it is replaced; the same key gives the same subject.
	late := z.Cert().NotBefore.Add(ZoneCALife * 7 / 10)
	if z.Reusable(key, zones, late) {
		t.Fatal("reused with under a third of its life left")
	}
	z2, err := IssueZoneCA(key, zones, late)
	if err != nil {
		t.Fatal(err)
	}
	if z2.Cert().Subject.CommonName != z.Cert().Subject.CommonName || string(z2.Cert().SubjectKeyId) != string(z.Cert().SubjectKeyId) {
		t.Fatal("same key, but the subject or key id changed")
	}
	// A leaf under the new certificate verifies under the old and the new ones (same key, subject).
	leaf, err := z2.IssueLeaf("dns.example.ir", late)
	if err != nil {
		t.Fatal(err)
	}
	lc, _ := x509.ParseCertificate(leaf.DER)
	for _, ca := range []*ZoneCA{z, z2} {
		pool := x509.NewCertPool()
		pool.AddCert(ca.Cert())
		if _, err := lc.Verify(x509.VerifyOptions{Roots: pool, DNSName: "dns.example.ir", CurrentTime: late.Add(time.Hour)}); err != nil {
			t.Errorf("leaf does not verify under a CA of the same key: %v", err)
		}
	}
	// A new key is a new subject.
	z3, _ := IssueZoneCA(newKey(t), zones, t0)
	if z3.Cert().Subject.CommonName == z.Cert().Subject.CommonName {
		t.Fatal("a new key kept the subject")
	}
}

func TestZoneCARefusals(t *testing.T) {
	key := newKey(t)
	for _, zs := range [][]string{nil, {"com"}, {"DNS.Example.ir"}, {"dns.a.ir", "dns.b.ir", "dns.c.ir"}, {"dns..ir"}, {""},
		{"dns.com"}, {"dns.co.ir"}, {"resolver.example.ir"}, {"dns.ir"}, {"dns.example.ir", "dns.com"}} {
		if _, err := IssueZoneCA(key, zs, t0); err == nil {
			t.Errorf("zones %v accepted", zs)
		}
	}
	if _, err := LoadZoneCA(newKey(t), mustZone(t, key).CertDER()); err == nil {
		t.Fatal("loaded over a key that is not the certificate's")
	}
	if _, err := LoadZoneCA(key, mustZone(t, key).CertDER()); err != nil {
		t.Fatal(err)
	}
}

func mustZone(t *testing.T, key *ecdsa.PrivateKey) *ZoneCA {
	z, err := IssueZoneCA(key, []string{"dns.example.ir"}, t0)
	if err != nil {
		t.Fatal(err)
	}
	return z
}

// The hub applies the rule of domain_invalid again before it signs (4.3, N13): the database CHECK holds
// the prefix and the grammar only, so a row written around the route must not become a CA.
func TestValidZoneIsTheDomainInvalidRule(t *testing.T) {
	for _, z := range []string{"dns.example.ir", "dns.a.ir", "dns.old.example.ir", "dns.ctrlz.invalid", "dns.example.co.ir"} {
		if !ValidZone(z) {
			t.Errorf("%q refused", z)
		}
	}
	for _, z := range []string{"", "com", "ir", "example.ir", "resolver.example.ir", "dns.com", "dns.ir", "dns.co.ir", "dns.", "dns.EXAMPLE.ir", "dns..ir", "dns.example.ir."} {
		if ValidZone(z) {
			t.Errorf("%q accepted", z)
		}
	}
	// A CA over a zone that was valid is loaded back, but a leaf is never issued for a zone the rule refuses.
	z := mustZone(t, newKey(t))
	if _, err := z.IssueLeaf("dns.com", t0); err == nil {
		t.Fatal("a leaf for a zone the CA does not permit")
	}
}
