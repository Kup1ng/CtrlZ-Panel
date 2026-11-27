package certcheck_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/certcheck"
)

var now = time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)

// ca is a test root with one intermediate, so the chain tests walk a real path.
type ca struct {
	root  *x509.Certificate
	inter *x509.Certificate
	ikey  *ecdsa.PrivateKey
	pool  *x509.CertPool
}

func newCA(t *testing.T) *ca {
	t.Helper()
	rkey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rt := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test root"}, NotBefore: now.Add(-48 * time.Hour), NotAfter: now.Add(1000 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rder, err := x509.CreateCertificate(rand.Reader, rt, rt, &rkey.PublicKey, rkey)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := x509.ParseCertificate(rder)
	ikey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	it := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "test intermediate"}, NotBefore: now.Add(-48 * time.Hour), NotAfter: now.Add(900 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	ider, err := x509.CreateCertificate(rand.Reader, it, root, &ikey.PublicKey, rkey)
	if err != nil {
		t.Fatal(err)
	}
	inter, _ := x509.ParseCertificate(ider)
	pool := x509.NewCertPool()
	pool.AddCert(root)
	return &ca{root: root, inter: inter, ikey: ikey, pool: pool}
}

type leafSpec struct {
	names []string
	ips   []net.IP
	after time.Duration
	isCA  bool
}

// issue returns the chain PEM (leaf then intermediate) and the leaf's key.
func (c *ca) issue(t *testing.T, s leafSpec) (string, *ecdsa.PrivateKey) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if s.after == 0 {
		s.after = 60 * 24 * time.Hour
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "leaf"}, DNSNames: s.names, IPAddresses: s.ips,
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(s.after), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA: s.isCA, BasicConstraintsValid: s.isCA}
	der, err := x509.CreateCertificate(rand.Reader, tpl, c.inter, &key.PublicKey, c.ikey)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})) + string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.inter.Raw})), key
}

func opts(c *ca, key *ecdsa.PrivateKey) certcheck.Options {
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	return certcheck.Options{Roots: c.pool, KeyPublic: der, MinLife: certcheck.MinUploadLife}
}

var zoneNames = []string{"dns.example.ir", "*.dns.example.ir", "*.verify.dns.example.ir"}

func TestWildcardNamesRule(t *testing.T) {
	c := newCA(t)
	zone := certcheck.Scope{Zones: []string{"dns.example.ir", "dns.old.ir"}}
	cases := []struct {
		name  string
		names []string
		scope certcheck.Scope
		want  error
	}{
		{"the three names of a live zone", zoneNames, zone, nil},
		{"the same names in another order and case", []string{"*.verify.DNS.example.ir", "*.dns.example.ir", "dns.example.ir"}, zone, nil},
		{"the second live zone", certcheck.ZoneNames("dns.old.ir"), zone, nil},
		{"a name missing", []string{"dns.example.ir", "*.dns.example.ir"}, zone, certcheck.ErrInvalid},
		{"a name outside the zone", append([]string{"www.example.ir"}, zoneNames...), zone, certcheck.ErrInvalid},
		{"a zone that is not live", certcheck.ZoneNames("dns.other.ir"), zone, certcheck.ErrInvalid},
		{"a blanket wildcard does not stand in for the verify name", []string{"dns.example.ir", "*.dns.example.ir"}, zone, certcheck.ErrInvalid},
		{"no live zone at all", zoneNames, certcheck.Scope{}, certcheck.ErrInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			chain, key := c.issue(t, leafSpec{names: tc.names})
			_, err := certcheck.Check([]byte(chain), certcheck.Wildcard, tc.scope, now, opts(c, key))
			if !errors.Is(err, tc.want) || (tc.want == nil && err != nil) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestPanelHostRule(t *testing.T) {
	c := newCA(t)
	cases := []struct {
		name  string
		names []string
		host  string
		want  error
	}{
		{"the host itself", []string{"panel.example.ir"}, "panel.example.ir", nil},
		{"a wildcard over one label", []string{"*.example.ir"}, "panel.example.ir", nil},
		{"a wildcard does not span two labels", []string{"*.example.ir"}, "a.panel.example.ir", certcheck.ErrInvalid},
		{"a wildcard does not cover its own apex", []string{"*.example.ir"}, "example.ir", certcheck.ErrInvalid},
		{"another host", []string{"other.example.ir"}, "panel.example.ir", certcheck.ErrInvalid},
		{"no host to cover", []string{"panel.example.ir"}, "", certcheck.ErrInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			chain, key := c.issue(t, leafSpec{names: tc.names})
			_, err := certcheck.Check([]byte(chain), certcheck.Panel, certcheck.Scope{Host: tc.host}, now, opts(c, key))
			if !errors.Is(err, tc.want) || (tc.want == nil && err != nil) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestRefusals(t *testing.T) {
	c := newCA(t)
	other := newCA(t) // a second private root: a chain that verifies to nothing we trust
	host := certcheck.Scope{Host: "panel.example.ir"}
	good, key := c.issue(t, leafSpec{names: []string{"panel.example.ir"}})
	strangerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	if res, err := certcheck.Check([]byte(good), certcheck.Panel, host, now, opts(c, key)); err != nil || len(res.Names) != 1 || res.Names[0] != "panel.example.ir" {
		t.Fatalf("a good chain: %v %v", res.Names, err)
	}
	for name, tc := range map[string]struct {
		chain string
		o     certcheck.Options
		kind  certcheck.Kind
		want  error
	}{
		"the key is another one": {good, opts(c, strangerKey), certcheck.Panel, certcheck.ErrKeyMismatch},
		"a root we do not trust": {good, opts(other, key), certcheck.Panel, certcheck.ErrNotPublic},
		"not a certificate":      {"-----BEGIN PRIV" + "ATE KEY-----\nAAAA\n-----END PRIV" + "ATE KEY-----\n", opts(c, key), certcheck.Panel, certcheck.ErrInvalid},
		"empty":                  {"", opts(c, key), certcheck.Panel, certcheck.ErrInvalid},
		"trailing text":          {good + "junk", opts(c, key), certcheck.Panel, certcheck.ErrInvalid},
		"an unknown kind":        {good, opts(c, key), certcheck.Kind("node_ca"), certcheck.ErrInvalid},
	} {
		if _, err := certcheck.Check([]byte(tc.chain), tc.kind, host, now, tc.o); !errors.Is(err, tc.want) {
			t.Errorf("%s: got %v, want %v", name, err, tc.want)
		}
	}
	// Life: valid now but for 6 days is refused for an upload, accepted where no margin is asked (Choose).
	short, skey := c.issue(t, leafSpec{names: []string{"panel.example.ir"}, after: 6 * 24 * time.Hour})
	if _, err := certcheck.Check([]byte(short), certcheck.Panel, host, now, opts(c, skey)); !errors.Is(err, certcheck.ErrExpiring) {
		t.Errorf("6 days left: got %v, want ErrExpiring", err)
	}
	if _, err := certcheck.Check([]byte(short), certcheck.Panel, host, now, certcheck.Options{Roots: c.pool}); err != nil {
		t.Errorf("6 days left with no margin asked: %v", err)
	}
	if _, err := certcheck.Check([]byte(short), certcheck.Panel, host, now.Add(7*24*time.Hour), certcheck.Options{Roots: c.pool}); !errors.Is(err, certcheck.ErrExpiring) {
		t.Errorf("past its end: got %v, want ErrExpiring", err)
	}
	if _, err := certcheck.Check([]byte(good), certcheck.Panel, host, now.Add(-24*time.Hour), certcheck.Options{Roots: c.pool}); !errors.Is(err, certcheck.ErrInvalid) {
		t.Errorf("before its start: got %v, want ErrInvalid", err)
	}
	// A leaf that names an address or is a CA is not a leaf of ours.
	withIP, ik := c.issue(t, leafSpec{names: []string{"panel.example.ir"}, ips: []net.IP{net.ParseIP("192.0.2.1")}})
	if _, err := certcheck.Check([]byte(withIP), certcheck.Panel, host, now, opts(c, ik)); !errors.Is(err, certcheck.ErrInvalid) {
		t.Errorf("an IP name: got %v", err)
	}
	asCA, ck := c.issue(t, leafSpec{names: []string{"panel.example.ir"}, isCA: true})
	if _, err := certcheck.Check([]byte(asCA), certcheck.Panel, host, now, opts(c, ck)); !errors.Is(err, certcheck.ErrInvalid) {
		t.Errorf("a CA certificate: got %v", err)
	}
}

// TestEmbeddedRootsRefuseAPrivateChain is the "public certificate" test of AUTH 7.2 with the real embedded roots: a chain
// from a private root does not verify, and the pool is not empty.
func TestEmbeddedRootsRefuseAPrivateChain(t *testing.T) {
	if len(certcheck.EmbeddedRoots().Subjects()) < 50 { //nolint:staticcheck // the count is all that is read
		t.Fatal("the embedded root pool is nearly empty")
	}
	c := newCA(t)
	chain, key := c.issue(t, leafSpec{names: []string{"panel.example.ir"}})
	_, err := certcheck.Check([]byte(chain), certcheck.Panel, certcheck.Scope{Host: "panel.example.ir"}, now, optsEmbedded(key))
	if !errors.Is(err, certcheck.ErrNotPublic) {
		t.Fatalf("a private chain against the embedded roots: got %v, want ErrNotPublic", err)
	}
}

func TestChoose(t *testing.T) {
	c := newCA(t)
	host := certcheck.Scope{Host: "panel.example.ir"}
	mk := func(after time.Duration, names ...string) certcheck.Row {
		chain, _ := c.issue(t, leafSpec{names: names, after: after})
		return certcheck.Row{ID: uuid.Must(uuid.NewV7()), State: "active", ChainPEM: chain}
	}
	short := mk(20*24*time.Hour, "panel.example.ir")
	long := mk(80*24*time.Hour, "panel.example.ir")
	wild := mk(50*24*time.Hour, "*.example.ir")
	wrongHost := mk(300*24*time.Hour, "other.example.ir")
	retired := mk(400*24*time.Hour, "panel.example.ir")
	retired.State = "retired"
	junk := certcheck.Row{ID: uuid.Must(uuid.NewV7()), State: "active", ChainPEM: "not a pem"}
	o := certcheck.Options{Roots: c.pool}

	got, _, ok := certcheck.Choose([]certcheck.Row{short, junk, wrongHost, retired, long, wild}, certcheck.Panel, host, now, o)
	if !ok || got.ID != long.ID {
		t.Fatalf("the latest not_after that covers the host: got %v ok %v, want %v", got.ID, ok, long.ID)
	}
	// A tie goes to the newest id (uuidv7 grows with time).
	a := mk(40*24*time.Hour, "panel.example.ir")
	b := a
	b.ID = uuid.Must(uuid.NewV7())
	if got, _, _ := certcheck.Choose([]certcheck.Row{b, a}, certcheck.Panel, host, now, o); got.ID != b.ID {
		t.Errorf("a tie: got %v, want the newer %v", got.ID, b.ID)
	}
	// A revoked row is picked only when nothing else is.
	rev := long
	rev.Revoked = true
	if got, _, _ := certcheck.Choose([]certcheck.Row{rev, short}, certcheck.Panel, host, now, o); got.ID != short.ID {
		t.Errorf("a revoked row beat an unrevoked one")
	}
	if got, _, ok := certcheck.Choose([]certcheck.Row{rev}, certcheck.Panel, host, now, o); !ok || got.ID != rev.ID {
		t.Errorf("a revoked row is the last resort")
	}
	if _, _, ok := certcheck.Choose([]certcheck.Row{retired, junk, wrongHost}, certcheck.Panel, host, now, o); ok {
		t.Errorf("nothing qualifies, so the zone or host is in private-CA mode")
	}
	// Expired by now: the row is not chosen even though it was valid when it was stored.
	if _, _, ok := certcheck.Choose([]certcheck.Row{short}, certcheck.Panel, host, now.Add(30*24*time.Hour), o); ok {
		t.Errorf("an expired row was chosen")
	}
}

func optsEmbedded(key *ecdsa.PrivateKey) certcheck.Options {
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	return certcheck.Options{KeyPublic: der, MinLife: certcheck.MinUploadLife}
}

func TestParseKey(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(k)
	sec1, _ := x509.MarshalECPrivateKey(k)
	wantPub, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	for name, in := range map[string][]byte{
		"pkcs8": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}),
		"sec1":  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1}),
	} {
		pub, out, err := certcheck.ParseKey(in)
		if err != nil || string(pub) != string(wantPub) {
			t.Errorf("%s: %v", name, err)
		}
		// The stored form is always PKCS #8, whatever came in.
		if b, _ := pem.Decode(out); b == nil || b.Type != "PRIVATE KEY" {
			t.Errorf("%s: not written as PKCS #8", name)
		}
	}
	good := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	for name, in := range map[string][]byte{
		"empty": nil, "trailing text": append(append([]byte(nil), good...), "x"...), "two blocks": append(append([]byte(nil), good...), good...),
		"a certificate": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pkcs8}),
		"encrypted":     pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: pkcs8}),
		"a header":      pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Headers: map[string]string{"DEK-Info": "x"}, Bytes: pkcs8}),
	} {
		if _, _, err := certcheck.ParseKey(in); !errors.Is(err, certcheck.ErrInvalid) {
			t.Errorf("%s: got %v, want ErrInvalid", name, err)
		}
	}
}
