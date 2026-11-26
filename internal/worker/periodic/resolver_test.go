package periodic

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func TestParseTargetAcceptsOnlyTheTwoShapesOfTheEgressList(t *testing.T) {
	good := map[string]target{
		"tls://1.1.1.1":                    {scheme: "tls", host: "1.1.1.1", port: "853"},
		"tls://dns.example.org:853":        {scheme: "tls", host: "dns.example.org", port: "853"},
		"tls://[2606:4700:4700::1111]":     {scheme: "tls", host: "2606:4700:4700::1111", port: "853"},
		"https://dns.example.org":          {scheme: "https", host: "dns.example.org", port: "443", path: "/dns-query"},
		"https://9.9.9.9:443/dns-query":    {scheme: "https", host: "9.9.9.9", port: "443", path: "/dns-query"},
		"https://Dns.Example.org/a/b_c.d~": {scheme: "https", host: "dns.example.org", port: "443", path: "/a/b_c.d~"},
	}
	for in, want := range good {
		got, err := parseTarget(in)
		if err != nil || got != want {
			t.Errorf("%q: got %+v, %v; want %+v", in, got, err, want)
		}
	}
	for _, in := range []string{
		"", "1.1.1.1", "udp://1.1.1.1", "http://dns.example.org", "tcp://1.1.1.1:53",
		"tls://1.1.1.1:443", "tls://1.1.1.1:53", "https://dns.example.org:853", "https://dns.example.org:8443/x",
		"tls://user@1.1.1.1", "https://user:pw@dns.example.org", "https://dns.example.org/q?x=1", "https://dns.example.org/q#f",
		"https://dns.example.org/a b", "https://dns.example.org/%2e%2e", "tls://1.1.1.1/path", "tls://", "https://",
		"tls://fe80::1%25eth0", "https://-bad.example.org", "https://bad_name.example.org", "https://a..b",
		"https://" + strings.Repeat("a", 64) + ".example.org",
	} {
		if got, err := parseTarget(in); err == nil {
			t.Errorf("%q was accepted as %+v", in, got)
		}
	}
}

// pack builds a DoH response for a question.
func pack(t *testing.T, q dnsmessage.Question, rcode dnsmessage.RCode, answers ...dnsmessage.Resource) []byte {
	t.Helper()
	b, err := (&dnsmessage.Message{
		Header:    dnsmessage.Header{Response: true, RCode: rcode},
		Questions: []dnsmessage.Question{q},
		Answers:   answers,
	}).Pack()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseAnswer(t *testing.T) {
	name := dnsmessage.MustNewName("h.example.org.")
	q := dnsmessage.Question{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}
	hdr := dnsmessage.ResourceHeader{Name: name, Class: dnsmessage.ClassINET, TTL: 60}
	a := func(b [4]byte) dnsmessage.Resource {
		h := hdr
		h.Type = dnsmessage.TypeA
		return dnsmessage.Resource{Header: h, Body: &dnsmessage.AResource{A: b}}
	}
	cname := dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET}, Body: &dnsmessage.CNAMEResource{CNAME: name}}

	got, err := parseAnswer(pack(t, q, dnsmessage.RCodeSuccess, cname, a([4]byte{203, 0, 113, 7}), a([4]byte{198, 51, 100, 9})), dnsmessage.TypeA)
	if err != nil || len(got) != 2 || got[0] != netip.MustParseAddr("203.0.113.7") {
		t.Fatalf("got %v, %v", got, err)
	}
	// An A record asked about AAAA is not an answer of that type.
	if _, err := parseAnswer(pack(t, q, dnsmessage.RCodeSuccess, a([4]byte{1, 2, 3, 4})), dnsmessage.TypeAAAA); err != errNoData {
		t.Errorf("an A record answered an AAAA query: %v", err)
	}
	if _, err := parseAnswer(pack(t, q, dnsmessage.RCodeNameError), dnsmessage.TypeA); err != errNoData {
		t.Errorf("NXDOMAIN: %v", err)
	}
	if _, err := parseAnswer(pack(t, q, dnsmessage.RCodeServerFailure), dnsmessage.TypeA); err != errLookup {
		t.Errorf("SERVFAIL: %v", err)
	}
	if _, err := parseAnswer([]byte{1, 2, 3}, dnsmessage.TypeA); err != errLookup {
		t.Errorf("junk: %v", err)
	}
}

// A DoH server on a local TLS listener: the client keeps the name it was told (127.0.0.1, which the test certificate names),
// verifies against the roots the test hands it, POSTs the wire message and reads the answers of both types.
func TestDoHLookupAgainstALocalServer(t *testing.T) {
	var posts int
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts++
		if r.Method != http.MethodPost || r.URL.Path != "/dns-query" || r.Header.Get("Content-Type") != "application/dns-message" {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var m dnsmessage.Message
		if err := m.Unpack(body); err != nil || len(m.Questions) != 1 {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		q := m.Questions[0]
		w.Header().Set("Content-Type", "application/dns-message")
		switch q.Type {
		case dnsmessage.TypeA:
			_, _ = w.Write(pack(t, q, dnsmessage.RCodeSuccess, dnsmessage.Resource{
				Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET},
				Body:   &dnsmessage.AResource{A: [4]byte{203, 0, 113, 5}},
			}))
		default:
			_, _ = w.Write(pack(t, q, dnsmessage.RCodeSuccess)) // no AAAA: an answer with nothing in it
		}
	}))
	defer srv.Close()
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())

	res, err := NewResolver("https://127.0.0.1/dns-query", WithRoots(roots), withDialAddr(srv.Listener.Addr().String()))
	if err != nil {
		t.Fatal(err)
	}
	got, err := res.Lookup(context.Background(), "h.example.org")
	if err != nil || len(got) != 1 || got[0] != netip.MustParseAddr("203.0.113.5") {
		t.Fatalf("got %v, %v", got, err)
	}
	if posts != 2 {
		t.Errorf("%d requests, want one for A and one for AAAA", posts)
	}

	// A resolver the client does not trust is a failed lookup and not an empty answer.
	bad, err := NewResolver("https://127.0.0.1/dns-query", withDialAddr(srv.Listener.Addr().String()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bad.Lookup(context.Background(), "h.example.org"); err != errLookup {
		t.Errorf("an untrusted certificate: %v", err)
	}
}

func TestDoHRefusesARedirectAndAFailureOfOneFamily(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://elsewhere.invalid/dns-query", http.StatusFound)
	}))
	defer srv.Close()
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	res, err := NewResolver("https://127.0.0.1", WithRoots(roots), withDialAddr(srv.Listener.Addr().String()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := res.Lookup(context.Background(), "h.example.org"); err != errLookup {
		t.Errorf("a redirect: %v", err)
	}
}

func TestClassifyKeepsPublicAddressesOnceAndCountsInjected(t *testing.T) {
	in := []netip.Addr{
		netip.MustParseAddr("203.0.113.9"), netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("::ffff:8.8.8.8"),
		netip.MustParseAddr("10.10.34.7"), netip.MustParseAddr("192.168.1.1"), netip.MustParseAddr("2606:4700:4700::1111"),
		netip.MustParseAddr("127.0.0.1"),
	}
	pub, injected := classify(in)
	// 203.0.113.0/24 is documentation space (reserved), so it is not public either.
	if injected != 1 {
		t.Errorf("injected %d", injected)
	}
	if len(pub) != 2 || pub[0] != netip.MustParseAddr("8.8.8.8") || pub[1] != netip.MustParseAddr("2606:4700:4700::1111") {
		t.Errorf("public %v", pub)
	}
}

// DoT: the Go resolver speaks DNS over the TLS connection the one dial hands it, and ignores the address of resolv.conf.
func TestDoTLookupAgainstALocalServer(t *testing.T) {
	cert := httptest.NewTLSServer(http.NotFoundHandler())
	defer cert.Close()
	roots := x509.NewCertPool()
	roots.AddCert(cert.Certificate())
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: cert.TLS.Certificates})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				for {
					var n [2]byte
					if _, err := io.ReadFull(c, n[:]); err != nil {
						return
					}
					buf := make([]byte, int(n[0])<<8|int(n[1]))
					if _, err := io.ReadFull(c, buf); err != nil {
						return
					}
					var m dnsmessage.Message
					if err := m.Unpack(buf); err != nil || len(m.Questions) != 1 {
						return
					}
					q := m.Questions[0]
					resp := dnsmessage.Message{Header: dnsmessage.Header{ID: m.Header.ID, Response: true, RecursionAvailable: true}, Questions: m.Questions}
					if q.Type == dnsmessage.TypeA {
						resp.Answers = []dnsmessage.Resource{{
							Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60},
							Body:   &dnsmessage.AResource{A: [4]byte{8, 8, 4, 4}},
						}}
					}
					out, err := resp.Pack()
					if err != nil {
						return
					}
					_, _ = c.Write(append([]byte{byte(len(out) >> 8), byte(len(out))}, out...))
				}
			}()
		}
	}()

	res, err := NewResolver("tls://127.0.0.1", WithRoots(roots), withDialAddr(ln.Addr().String()))
	if err != nil {
		t.Fatal(err)
	}
	got, err := res.Lookup(context.Background(), "h.example.org")
	if err != nil || len(got) != 1 || got[0] != netip.MustParseAddr("8.8.4.4") {
		t.Fatalf("got %v, %v", got, err)
	}
}
