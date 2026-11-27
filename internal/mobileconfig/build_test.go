package mobileconfig

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"io"
	"math/big"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Shared/appleprofile"
	"github.com/Kup1ng/CtrlZ-Shared/identity"
)

const (
	endpointID = "0197a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b"
	rid        = "abcdefghijklmnopqrstuvwxy2"
	token      = "abcdefghijklmnopqrstuvwxyz234567"
)

var testNow = time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)

// resolver is what setup.View gives for the fixture Endpoint, for a client or
// without one.
func resolver(client string) Resolver {
	host := rid + ".dns.example.com"
	if client != "" {
		host = rid + "-" + client + ".dns.example.com"
	}
	return Resolver{
		Host:     host,
		DoHURL:   "https://" + host + "/" + token,
		Primary:  netip.MustParseAddr("203.0.113.10"),
		Fallback: netip.MustParseAddr("203.0.113.11"),
	}
}

func input(p appleprofile.Params) Input {
	return Input{EndpointID: endpointID, Name: "Home phone", Params: p, Resolver: resolver(p.Client), Now: testNow}
}

func readTestdata(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// rootCA is an ed25519 test root (seed 1..32, serial 1, valid 2026 to 2046)
// checked in as DER, so the golden file of private CA mode does not depend on
// how a Go release encodes a certificate.
func rootCA(t *testing.T) []byte { return readTestdata(t, "root-ca.der") }

type goldenCase struct {
	file string
	why  string
	in   func(t *testing.T) Input
}

func goldenCases() []goldenCase {
	return []goldenCase{
		{"doh-minimal", "DoH, nothing excluded: no OnDemandRules, no ProhibitDisablement", func(t *testing.T) Input {
			return input(appleprofile.Params{Protocol: "doh"})
		}},
		{"dot-minimal", "DoT uses ServerName and not ServerURL", func(t *testing.T) Input {
			return input(appleprofile.Params{Protocol: "dot"})
		}},
		{"doh-client-full", "a client, two networks, domains, ProhibitDisablement: the rule order", func(t *testing.T) Input {
			return input(appleprofile.Params{
				Client: "kid", Protocol: "doh", ProhibitDisablement: true,
				ExcludedSSIDs:   []string{"Home Wi-Fi", "خانه"},
				ExcludedDomains: []string{"captive.apple.com", "example.com", "local"},
			})
		}},
		{"dot-domains-only", "domains without networks: no Disconnect rule", func(t *testing.T) Input {
			return input(appleprofile.Params{Protocol: "dot", ExcludedDomains: []string{"example.com"}})
		}},
		{"doh-ssid-only", "networks without domains: no EvaluateConnection rule", func(t *testing.T) Input {
			return input(appleprofile.Params{Protocol: "doh", ExcludedSSIDs: []string{"Office"}})
		}},
		{"doh-ssid-markup", "an SSID holding <, & and ]]> is escaped and parses back unchanged (T-246, T-247)", func(t *testing.T) Input {
			return input(appleprofile.Params{Protocol: "doh", ExcludedSSIDs: []string{"<&>]]>", `a"b'c`}})
		}},
		{"doh-ipv6", "an IPv6 pair", func(t *testing.T) Input {
			in := input(appleprofile.Params{Protocol: "doh"})
			in.Resolver.Primary = netip.MustParseAddr("2001:db8::1")
			in.Resolver.Fallback = netip.MustParseAddr("2001:db8::2")
			return in
		}},
		{"doh-private-root", "private CA mode embeds the root as com.apple.security.root and warns", func(t *testing.T) Input {
			in := input(appleprofile.Params{Protocol: "doh"})
			in.Trust = StaticTrust{M: TrustPrivateEmbed, DER: rootCA(t)}
			return in
		}},
		{"doh-no-name", "no Endpoint name: the fixed display name", func(t *testing.T) Input {
			in := input(appleprofile.Params{Protocol: "doh"})
			in.Name = ""
			return in
		}},
	}
}

// The .mobileconfig of each accepted case equals a checked-in file byte for
// byte. To change a file on purpose, delete it, run the test with the new
// output written by hand from the failure message, and review the diff.
func TestGolden(t *testing.T) {
	for _, c := range goldenCases() {
		t.Run(c.file, func(t *testing.T) {
			res, err := Build(c.in(t))
			if err != nil {
				t.Fatalf("%s: %v", c.why, err)
			}
			want := readTestdata(t, c.file+".mobileconfig")
			if !bytes.Equal(res.Data, want) {
				t.Fatalf("%s: output differs from testdata/%s.mobileconfig\n--- got ---\n%s", c.why, c.file, res.Data)
			}
		})
	}
}

func TestEveryGoldenFileHasACase(t *testing.T) {
	have := map[string]bool{}
	for _, c := range goldenCases() {
		have[c.file+".mobileconfig"] = true
	}
	files, err := filepath.Glob("testdata/*.mobileconfig")
	if err != nil || len(files) == 0 {
		t.Fatalf("no golden files: %v", err)
	}
	for _, f := range files {
		if !have[filepath.Base(f)] {
			t.Errorf("%s has no case", f)
		}
	}
}

func build(t *testing.T, in Input) (Result, pDict) {
	t.Helper()
	res, err := Build(in)
	if err != nil {
		t.Fatal(err)
	}
	d, err := parsePlist(res.Data)
	if err != nil {
		t.Fatalf("the profile is not a valid property list: %v\n%s", err, res.Data)
	}
	return res, d
}

// content returns the dnsSettings payload and the other payloads.
func content(t *testing.T, root pDict) (dns pDict, others []pDict) {
	t.Helper()
	for _, v := range root.Array("PayloadContent") {
		d := v.(pDict)
		if d.String("PayloadType") == "com.apple.dnsSettings.managed" {
			if dns.Has("PayloadType") {
				t.Fatal("two dnsSettings payloads")
			}
			dns = d
		} else {
			others = append(others, d)
		}
	}
	if !dns.Has("PayloadType") {
		t.Fatal("no dnsSettings payload")
	}
	return dns, others
}

func TestSSIDsRoundTripWhateverTheyHold(t *testing.T) {
	ssids := []string{"<&>]]>", "]]>", "<![CDATA[x]]>", `"quoted" 'single'`, "a&amp;b", "&#60;", "خانه ۱", "日本語", " lead and trail ", "emoji \U0001F4F6"}
	res, root := build(t, input(appleprofile.Params{Protocol: "doh", ExcludedSSIDs: ssids}))
	dns, _ := content(t, root)
	rules := dns.Array("OnDemandRules")
	got := rules[0].(pDict).Array("SSIDMatch")
	if len(got) != len(ssids) {
		t.Fatalf("got %d SSIDs, want %d", len(got), len(ssids))
	}
	for i, s := range ssids {
		if got[i].(string) != s {
			t.Errorf("SSID %d came back as %q, want %q", i, got[i], s)
		}
	}
	if bytes.Contains(res.Data, []byte("]]>")) || bytes.Contains(res.Data, []byte("<![CDATA[")) {
		t.Error("a CDATA section or a raw ]]> is in the file")
	}
	// Exactly the structure of a profile with no SSID of that kind: the
	// markup in the values added no element.
	_, base := build(t, input(appleprofile.Params{Protocol: "doh", ExcludedSSIDs: []string{"a"}}))
	if root.ElementCount() != base.ElementCount()+len(ssids)-1 {
		t.Errorf("element count %d, want %d: a value changed the structure", root.ElementCount(), base.ElementCount()+len(ssids)-1)
	}
}

func TestDoHAndDoTPayloads(t *testing.T) {
	_, root := build(t, input(appleprofile.Params{Protocol: "doh", Client: "kid"}))
	dns, _ := content(t, root)
	s := dns.Dict("DNSSettings")
	r := resolver("kid")
	if s.String("DNSProtocol") != "HTTPS" || s.String("ServerURL") != r.DoHURL || s.Has("ServerName") {
		t.Errorf("DoH settings %v", s.Keys())
	}
	addrs := s.Array("ServerAddresses")
	if len(addrs) != 2 || addrs[0] != "203.0.113.10" || addrs[1] != "203.0.113.11" {
		t.Errorf("ServerAddresses %v: the primary must come first (SC 8a.8)", addrs)
	}

	_, root = build(t, input(appleprofile.Params{Protocol: "dot"}))
	dns, _ = content(t, root)
	s = dns.Dict("DNSSettings")
	if s.String("DNSProtocol") != "TLS" || s.String("ServerName") != resolver("").Host || s.Has("ServerURL") {
		t.Errorf("DoT settings %v", s.Keys())
	}
	if strings.Contains(string(mustBuild(t, input(appleprofile.Params{Protocol: "dot"})).Data), token) {
		t.Error("a DoT profile carries the DoH token")
	}
}

func mustBuild(t *testing.T, in Input) Result {
	t.Helper()
	res, err := Build(in)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestServerAddressesOrderIsThePairOrder(t *testing.T) {
	in := input(appleprofile.Params{Protocol: "dot"})
	in.Resolver.Primary, in.Resolver.Fallback = netip.MustParseAddr("198.51.100.2"), netip.MustParseAddr("198.51.100.1")
	_, root := build(t, in)
	dns, _ := content(t, root)
	addrs := dns.Dict("DNSSettings").Array("ServerAddresses")
	if addrs[0] != "198.51.100.2" || addrs[1] != "198.51.100.1" {
		t.Errorf("addresses were sorted or swapped: %v", addrs)
	}
}

func TestOnDemandRules(t *testing.T) {
	_, root := build(t, input(appleprofile.Params{Protocol: "doh"}))
	if dns, _ := content(t, root); dns.Has("OnDemandRules") {
		t.Error("rules in a profile that excludes nothing")
	}
	_, root = build(t, input(appleprofile.Params{
		Protocol: "doh", ExcludedSSIDs: []string{"Home"}, ExcludedDomains: []string{"example.com", "local"},
	}))
	dns, _ := content(t, root)
	rules := dns.Array("OnDemandRules")
	if len(rules) != 3 {
		t.Fatalf("%d rules", len(rules))
	}
	r0, r1, r2 := rules[0].(pDict), rules[1].(pDict), rules[2].(pDict)
	if r0.String("Action") != "Disconnect" || r0.Array("SSIDMatch")[0] != "Home" {
		t.Errorf("rule 0: %v", r0.Keys())
	}
	if r1.String("Action") != "EvaluateConnection" {
		t.Errorf("rule 1: %v", r1.Keys())
	}
	ap := r1.Array("ActionParameters")[0].(pDict)
	doms := ap.Array("Domains")
	if ap.String("DomainAction") != "NeverConnect" || len(doms) != 2 || doms[0] != "example.com" || doms[1] != "local" {
		t.Errorf("action parameters: %v %v", ap.Keys(), doms)
	}
	if r2.String("Action") != "Connect" || len(r2.Keys()) != 1 {
		t.Errorf("the last rule must be a plain Connect: %v", r2.Keys())
	}
}

func TestProhibitDisablementIsItsOwnKey(t *testing.T) {
	_, root := build(t, input(appleprofile.Params{Protocol: "doh", ProhibitDisablement: true}))
	dns, others := content(t, root)
	if v, ok := dns.Bool("ProhibitDisablement"); !ok || !v {
		t.Error("ProhibitDisablement is not true on the dnsSettings payload")
	}
	// It is not Prevent Deactivation (D8) and not a removal lock on the profile.
	if root.Has("PayloadRemovalDisallowed") || dns.Has("PayloadRemovalDisallowed") || len(others) != 0 {
		t.Error("the profile locks its own removal")
	}
	_, root = build(t, input(appleprofile.Params{Protocol: "doh"}))
	if dns, _ := content(t, root); dns.Has("ProhibitDisablement") {
		t.Error("ProhibitDisablement written when it was not asked for")
	}
}

// A reinstall replaces the profile (T-247): identifiers depend on the Endpoint
// and the client, and on nothing that rotation or the protocol changes.
func TestIdentifiersAreStable(t *testing.T) {
	ids := func(in Input) (string, string, string, string) {
		_, root := build(t, in)
		dns, _ := content(t, root)
		return root.String("PayloadIdentifier"), root.String("PayloadUUID"), dns.String("PayloadIdentifier"), dns.String("PayloadUUID")
	}
	a1, a2, a3, a4 := ids(input(appleprofile.Params{Protocol: "doh"}))

	rotated := input(appleprofile.Params{Protocol: "dot", ExcludedSSIDs: []string{"x"}})
	rotated.Resolver.Host = "zzzzzzzzzzzzzzzzzzzzzzzzz2.dns.example.com"
	rotated.Resolver.Primary = netip.MustParseAddr("198.51.100.9")
	rotated.Name = "Renamed"
	b1, b2, b3, b4 := ids(rotated)
	if a1 != b1 || a2 != b2 || a3 != b3 || a4 != b4 {
		t.Error("identifiers changed with the resolver, protocol, rules or name")
	}

	c1, c2, _, _ := ids(input(appleprofile.Params{Protocol: "doh", Client: "kid"}))
	if c1 == a1 || c2 == a2 {
		t.Error("a client shares the profile of the Endpoint")
	}
	other := input(appleprofile.Params{Protocol: "doh"})
	other.EndpointID = "0197a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5c"
	d1, d2, _, _ := ids(other)
	if d1 == a1 || d2 == a2 {
		t.Error("two Endpoints share a profile")
	}
	want, err := appleprofile.Identify(endpointID, "")
	if err != nil || a1 != want.PayloadIdentifier || a2 != want.PayloadUUID || a3 != want.ContentIdentifier || a4 != want.ContentUUID {
		t.Error("the profile does not carry the identity shared/appleprofile derives")
	}
	if a2 == a4 {
		t.Error("the two payloads share one UUID")
	}
}

func TestBuildIsDeterministic(t *testing.T) {
	in := input(appleprofile.Params{Protocol: "doh", ExcludedSSIDs: []string{"a", "b"}, ExcludedDomains: []string{"example.com"}})
	if !bytes.Equal(mustBuild(t, in).Data, mustBuild(t, in).Data) {
		t.Fatal("two builds of one input differ")
	}
}

func TestPrivateRoot(t *testing.T) {
	in := input(appleprofile.Params{Protocol: "doh"})
	der := rootCA(t)
	in.Trust = StaticTrust{M: TrustPrivateEmbed, DER: der}
	res, root := build(t, in)
	dns, others := content(t, root)
	if len(others) != 1 || others[0].String("PayloadType") != "com.apple.security.root" {
		t.Fatalf("payloads %v", others)
	}
	got, err := base64.StdEncoding.DecodeString(others[0].String("PayloadContent"))
	if err != nil || !bytes.Equal(got, der) {
		t.Error("the embedded root is not the root given")
	}
	if others[0].String("PayloadUUID") == dns.String("PayloadUUID") || others[0].String("PayloadIdentifier") == dns.String("PayloadIdentifier") {
		t.Error("the root payload shares an identity with the DNS payload")
	}
	if len(res.Warnings) != 2 || res.Warnings[0] != WarnUnsigned || res.Warnings[1] != WarnPrivateRoot {
		t.Errorf("warnings %v", res.Warnings)
	}

	// Public trust, a nil Trust and an explicit public mode carry no root.
	for name, tr := range map[string]Trust{"nil": nil, "public": StaticTrust{M: TrustPublic}, "public with a root given": StaticTrust{M: TrustPublic, DER: der}} {
		in.Trust = tr
		res, root := build(t, in)
		if _, others := content(t, root); len(others) != 0 {
			t.Errorf("%s: a root in a public profile", name)
		}
		if len(res.Warnings) != 1 || res.Warnings[0] != WarnUnsigned {
			t.Errorf("%s: warnings %v", name, res.Warnings)
		}
	}
}

// intermediateCA is a CA certificate signed by another CA: valid, a CA, and
// not a root.
func intermediateCA(t *testing.T) []byte {
	t.Helper()
	mk := func(cn string, parent *x509.Certificate, pkey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: cn},
			NotBefore:             testNow.Add(-time.Hour),
			NotAfter:              testNow.Add(time.Hour),
			IsCA:                  true,
			BasicConstraintsValid: true,
			KeyUsage:              x509.KeyUsageCertSign,
		}
		signer, signKey := tmpl, key
		if parent != nil {
			signer, signKey = parent, pkey
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signKey)
		if err != nil {
			t.Fatal(err)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return c, key, der
	}
	root, rootKey, _ := mk("test root", nil, nil)
	_, _, der := mk("test intermediate", root, rootKey)
	return der
}

func TestPrivateRootRefusals(t *testing.T) {
	in := input(appleprofile.Params{Protocol: "doh"})
	in.Trust = StaticTrust{M: TrustPrivateDisabled, DER: rootCA(t)}
	if _, err := Build(in); !errors.Is(err, ErrDisabled) {
		t.Errorf("disabled: %v", err)
	}
	cases := map[string]struct {
		tr  Trust
		now time.Time
	}{
		"no root":        {StaticTrust{M: TrustPrivateEmbed}, testNow},
		"not DER":        {StaticTrust{M: TrustPrivateEmbed, DER: []byte("not a certificate")}, testNow},
		"not a CA":       {StaticTrust{M: TrustPrivateEmbed, DER: readTestdata(t, "leaf-not-ca.der")}, testNow},
		"not a root":     {StaticTrust{M: TrustPrivateEmbed, DER: intermediateCA(t)}, testNow},
		"before":         {StaticTrust{M: TrustPrivateEmbed, DER: rootCA(t)}, time.Date(2025, 12, 31, 0, 0, 0, 0, time.UTC)},
		"expired":        {StaticTrust{M: TrustPrivateEmbed, DER: rootCA(t)}, time.Date(2046, 1, 2, 0, 0, 0, 0, time.UTC)},
		"no clock given": {StaticTrust{M: TrustPrivateEmbed, DER: rootCA(t)}, time.Time{}},
		"unknown mode":   {StaticTrust{M: 9, DER: rootCA(t)}, testNow},
	}
	for name, c := range cases {
		in.Trust, in.Now = c.tr, c.now
		_, err := Build(in)
		if !errors.Is(err, ErrInput) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestInputsAreValidated(t *testing.T) {
	good := appleprofile.Params{Protocol: "doh", Client: "kid"}
	r := resolver("kid")
	cases := map[string]func(in *Input){
		"endpoint id uppercase":   func(in *Input) { in.EndpointID = strings.ToUpper(endpointID) },
		"endpoint id empty":       func(in *Input) { in.EndpointID = "" },
		"params protocol":         func(in *Input) { in.Params.Protocol = "doq" },
		"params client":           func(in *Input) { in.Params.Client = "Kid" },
		"params ssid":             func(in *Input) { in.Params.ExcludedSSIDs = []string{"a\nb"} },
		"params domain":           func(in *Input) { in.Params.ExcludedDomains = []string{"Example.com"} },
		"name too long":           func(in *Input) { in.Name = strings.Repeat("a", 65) },
		"name control":            func(in *Input) { in.Name = "a\x00b" },
		"name not utf8":           func(in *Input) { in.Name = "\xff" },
		"host empty":              func(in *Input) { in.Resolver.Host = "" },
		"host uppercase":          func(in *Input) { in.Resolver.Host = strings.ToUpper(r.Host) },
		"host no dns label":       func(in *Input) { in.Resolver.Host = rid + "-kid.www.example.com" },
		"host without the client": func(in *Input) { in.Resolver.Host = rid + ".dns.example.com" },
		"host of another client":  func(in *Input) { in.Resolver.Host = rid + "-sis.dns.example.com" },
		"host short id":           func(in *Input) { in.Resolver.Host = "abc-kid.dns.example.com" },
		"host is the apex":        func(in *Input) { in.Resolver.Host = "dns.example.com" },
		"url http":                func(in *Input) { in.Resolver.DoHURL = "http://" + r.Host + "/" + token },
		"url port":                func(in *Input) { in.Resolver.DoHURL = "https://" + r.Host + ":8443/" + token },
		"url other host":          func(in *Input) { in.Resolver.DoHURL = "https://evil.example.net/" + token },
		"url user":                func(in *Input) { in.Resolver.DoHURL = "https://u@" + r.Host + "/" + token },
		"url query":               func(in *Input) { in.Resolver.DoHURL = r.DoHURL + "?x=1" },
		"url fragment":            func(in *Input) { in.Resolver.DoHURL = r.DoHURL + "#x" },
		"url empty query mark":    func(in *Input) { in.Resolver.DoHURL = r.DoHURL + "?" },
		"url trailing slash":      func(in *Input) { in.Resolver.DoHURL = r.DoHURL + "/" },
		"url no token":            func(in *Input) { in.Resolver.DoHURL = "https://" + r.Host + "/" },
		"url short token":         func(in *Input) { in.Resolver.DoHURL = "https://" + r.Host + "/abc" },
		"url dns-query path":      func(in *Input) { in.Resolver.DoHURL = "https://" + r.Host + "/dns-query" },
		"url two segments":        func(in *Input) { in.Resolver.DoHURL = "https://" + r.Host + "/" + rid + "/" + token },
		"url escaped token": func(in *Input) {
			in.Resolver.DoHURL = "https://" + r.Host + "/" + strings.Replace(token, "a", "%61", 1)
		},
		"url empty":                func(in *Input) { in.Resolver.DoHURL = "" },
		"url not a url":            func(in *Input) { in.Resolver.DoHURL = "https://%zz/" + token },
		"primary missing":          func(in *Input) { in.Resolver.Primary = netip.Addr{} },
		"fallback missing":         func(in *Input) { in.Resolver.Fallback = netip.Addr{} },
		"primary unspecified":      func(in *Input) { in.Resolver.Primary = netip.MustParseAddr("0.0.0.0") },
		"primary loopback":         func(in *Input) { in.Resolver.Primary = netip.MustParseAddr("127.0.0.1") },
		"fallback multicast":       func(in *Input) { in.Resolver.Fallback = netip.MustParseAddr("224.0.0.1") },
		"fallback link local":      func(in *Input) { in.Resolver.Fallback = netip.MustParseAddr("169.254.1.1") },
		"fallback with a zone":     func(in *Input) { in.Resolver.Fallback = netip.MustParseAddr("fe80::1%eth0") },
		"fallback 4in6":            func(in *Input) { in.Resolver.Fallback = netip.MustParseAddr("::ffff:203.0.113.11") },
		"same address twice":       func(in *Input) { in.Resolver.Fallback = in.Resolver.Primary },
		"mixed families":           func(in *Input) { in.Resolver.Fallback = netip.MustParseAddr("2001:db8::2") },
		"explicit empty not valid": func(in *Input) { in.Resolver = Resolver{} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			in := input(good)
			mutate(&in)
			res, err := Build(in)
			if !errors.Is(err, ErrInput) {
				t.Fatalf("got %v", err)
			}
			if res.Data != nil {
				t.Error("bytes returned with an error")
			}
			// The DoH URL is a secret: no error quotes it or its token.
			if strings.Contains(err.Error(), token) || strings.Contains(err.Error(), "https://") {
				t.Errorf("the error holds the DoH URL: %v", err)
			}
		})
	}
	// A DoT profile does not read the DoH URL at all.
	in := input(appleprofile.Params{Protocol: "dot"})
	in.Resolver.DoHURL = "junk"
	if _, err := Build(in); err != nil {
		t.Errorf("DoT refused for its unused DoH URL: %v", err)
	}
}

// Every generator obeys SC 8a.8: it never turns certificate validation off and
// never sets a mode that falls back to plaintext. A profile cannot express
// either through the keys this builder writes, and this test holds it to that
// list, so a later key has to be added here by a reviewer.
func TestOnlyReviewedKeysAreWritten(t *testing.T) {
	allowed := map[string]bool{}
	for _, k := range strings.Fields(`PayloadContent PayloadDescription PayloadDisplayName PayloadIdentifier PayloadOrganization
		PayloadType PayloadUUID PayloadVersion DNSSettings DNSProtocol ServerAddresses ServerURL ServerName OnDemandRules
		Action SSIDMatch ActionParameters DomainAction Domains ProhibitDisablement`) {
		allowed[k] = true
	}
	for _, c := range goldenCases() {
		res := mustBuild(t, c.in(t))
		d, err := parsePlist(res.Data)
		if err != nil {
			t.Fatal(err)
		}
		for _, k := range d.AllKeys() {
			if !allowed[k] {
				t.Errorf("%s writes the key %q, which is not on the reviewed list", c.file, k)
			}
		}
		for _, v := range d.AllStrings("DNSProtocol") {
			if v != "HTTPS" && v != "TLS" {
				t.Errorf("%s: DNSProtocol %q", c.file, v)
			}
		}
		for _, v := range d.AllStrings("Action") {
			if v != "Connect" && v != "Disconnect" && v != "EvaluateConnection" {
				t.Errorf("%s: Action %q", c.file, v)
			}
		}
		if bytes.Contains(bytes.ToLower(res.Data), []byte("<key>allow")) || bytes.Contains(bytes.ToLower(res.Data), []byte("insecure")) {
			t.Errorf("%s: a key that relaxes validation", c.file)
		}
	}
}

func TestFileNameIsASCII(t *testing.T) {
	for client, want := range map[string]string{"": "ctrlz-dns.mobileconfig", "kid": "ctrlz-dns-kid.mobileconfig"} {
		res := mustBuild(t, input(appleprofile.Params{Protocol: "doh", Client: client}))
		if res.FileName != want {
			t.Errorf("got %q want %q", res.FileName, want)
		}
	}
	// The Endpoint name never reaches the file name, so a Persian name cannot
	// put non-ASCII bytes in a header.
	in := input(appleprofile.Params{Protocol: "doh"})
	in.Name = "گوشی من"
	res, root := build(t, in)
	if res.FileName != "ctrlz-dns.mobileconfig" {
		t.Errorf("file name %q", res.FileName)
	}
	if root.String("PayloadDisplayName") != "Ctrl Z - گوشی من" {
		t.Errorf("display name %q", root.String("PayloadDisplayName"))
	}
}

func TestWorstCaseParamsBuild(t *testing.T) {
	var doms, ssids []string
	for i := 0; i < appleprofile.MaxExpandedDomains; i++ {
		doms = append(doms, "d"+strconv.Itoa(1000+i)+"."+strings.Repeat("a", 60)+".example.com")
	}
	for i := 0; i < appleprofile.MaxSSIDs; i++ {
		ssids = append(ssids, strings.Repeat("<", 28)+strconv.Itoa(1000+i))
	}
	p, err := appleprofile.Expand(appleprofile.Request{Protocol: "doh", ExcludedSSIDs: ssids, ExcludedDomains: doms[:100], ExcludeCommon: true}, doms[100:])
	if err != nil {
		t.Fatal(err)
	}
	res, root := build(t, input(p))
	dns, _ := content(t, root)
	rules := dns.Array("OnDemandRules")
	if len(rules[0].(pDict).Array("SSIDMatch")) != appleprofile.MaxSSIDs || len(rules[1].(pDict).Array("ActionParameters")[0].(pDict).Array("Domains")) != appleprofile.MaxExpandedDomains {
		t.Error("the worst case lost entries")
	}
	t.Logf("worst case profile: %d bytes", len(res.Data))
}

func TestPlistRefusesWhatXMLCannotCarry(t *testing.T) {
	for _, s := range []string{"a\x00b", "a\x01", "\x7f", "\u0085", "a￿", "a￾", "\xff\xfe", "a\tb", "a\nb", "a\rb"} {
		p := newPlist()
		p.leaf("string", s)
		if _, err := p.finish(); err == nil {
			t.Errorf("%q was written", s)
		}
	}
	// What is allowed is written escaped and read back as it was.
	p := newPlist()
	p.leaf("string", "<>&\"' ]]> é")
	out, err := p.finish()
	if err != nil {
		t.Fatal(err)
	}
	dec := xml.NewDecoder(bytes.NewReader(out))
	var text string
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if cd, ok := tok.(xml.CharData); ok && strings.TrimSpace(string(cd)) != "" {
			text = string(cd)
		}
	}
	if text != "<>&\"' ]]> é" {
		t.Errorf("read back %q", text)
	}
}

func TestGrammarMatchesIdentity(t *testing.T) {
	samples := []string{"", rid, token, rid + "a", rid[:25], token[:31], strings.ToUpper(rid), "abcdefghijklmnopqrstuvwxy1", "abcdefghijklmnopqrstuvwxy8", "abcdefghijklmnopqrstuvwxy-", strings.Repeat("a", 26), strings.Repeat("7", 32), strings.Repeat("2", 31) + "0"}
	for _, s := range samples {
		if b32(s, 26) != identity.ValidResolverID(s) {
			t.Errorf("resolver id grammar differs for %q", s)
		}
		if b32(s, 32) != identity.ValidDoHToken(s) {
			t.Errorf("DoH token grammar differs for %q", s)
		}
	}
}
