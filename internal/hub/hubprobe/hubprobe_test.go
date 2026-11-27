package hubprobe_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubpki"
	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubprobe"
)

const zoneName = "dns.test.example"

type pki struct {
	ca   *hubpki.ZoneCA
	cert tls.Certificate
	pool *x509.CertPool
}

func newPKI(t *testing.T) pki {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ca, err := hubpki.IssueZoneCA(key, []string{zoneName}, now)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ca.IssueLeaf(zoneName, now)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert())
	return pki{ca: ca, cert: tls.Certificate{Certificate: [][]byte{leaf.DER}, PrivateKey: leaf.Key}, pool: pool}
}

// soaAnswer builds the answer a node gives to `<zone> SOA`, with each field the probe checks open to a fault.
type soaFault struct {
	aa, wrongID, wrongQuestion, wrongMName, wrongOwner, noAnswer bool
}

func name(z string) []byte {
	var b []byte
	for _, l := range strings.Split(strings.TrimSuffix(z, "."), ".") {
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	return append(b, 0)
}

func soaAnswer(q []byte, z string, f soaFault) []byte {
	resp := append([]byte(nil), q...)
	flags := uint16(0x8000)
	if !f.aa {
		flags |= 0x0400
	}
	binary.BigEndian.PutUint16(resp[2:], flags)
	an := uint16(1)
	if f.noAnswer {
		an = 0
	}
	binary.BigEndian.PutUint16(resp[6:], an)
	if f.wrongID {
		resp[0] ^= 0xff
	}
	if f.wrongQuestion {
		resp[13] ^= 0x01 // another name in the question section
	}
	if f.noAnswer {
		return resp
	}
	owner := z
	if f.wrongOwner {
		owner = "other." + z
	}
	m := "ns1." + z
	if f.wrongMName {
		m = "ns9." + z
	}
	resp = append(resp, name(owner)...)
	rdata := append(name(m), name("hostmaster."+z)...)
	rdata = append(rdata, make([]byte, 20)...)
	resp = binary.BigEndian.AppendUint16(resp, 6)
	resp = binary.BigEndian.AppendUint16(resp, 1)
	resp = binary.BigEndian.AppendUint32(resp, 30)
	resp = binary.BigEndian.AppendUint16(resp, uint16(len(rdata)))
	return append(resp, rdata...)
}

// node is a listening DoT and DoH pair with a zone certificate.
type node struct {
	dot    net.Listener
	doh    *httptest.Server
	mu     sync.Mutex
	fault  soaFault
	status int
	body   string
	sni    []string
}

func (n *node) setFault(f soaFault) { n.mu.Lock(); n.fault = f; n.mu.Unlock() }
func (n *node) setDoH(status int, body string) {
	n.mu.Lock()
	n.status, n.body = status, body
	n.mu.Unlock()
}

const goodBody = `{"seen":false,"n":"00000000000000000000000000000001","rid_tag":"00000000000000000000000000000002","client_tag":"00000000000000000000000000000003","proto_tag":"00000000000000000000000000000004"}`

func newNode(t *testing.T, p pki) *node {
	t.Helper()
	n := &node{status: 200, body: goodBody}
	cfg := &tls.Config{Certificates: []tls.Certificate{p.cert}, MinVersion: tls.VersionTLS12}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	n.dot = ln
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				var lb [2]byte
				if _, err := io.ReadFull(c, lb[:]); err != nil {
					return
				}
				q := make([]byte, int(lb[0])<<8|int(lb[1]))
				if _, err := io.ReadFull(c, q); err != nil {
					return
				}
				n.mu.Lock()
				f := n.fault
				n.mu.Unlock()
				a := soaAnswer(q, zoneName, f)
				_, _ = c.Write(append([]byte{byte(len(a) >> 8), byte(len(a))}, a...))
			}()
		}
	}()
	n.doh = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.mu.Lock()
		st, body := n.status, n.body
		n.sni = append(n.sni, r.Host)
		n.mu.Unlock()
		if r.URL.Path != "/v" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(st)
		_, _ = io.WriteString(w, body)
	}))
	n.doh.TLS = &tls.Config{Certificates: []tls.Certificate{p.cert}}
	n.doh.EnableHTTP2 = true
	n.doh.StartTLS()
	t.Cleanup(func() { ln.Close(); n.doh.Close() })
	return n
}

func (n *node) prober(roots *x509.CertPool) *hubprobe.Prober {
	return hubprobe.New(hubprobe.Config{
		Roots: func() *x509.CertPool { return roots },
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			target := n.doh.Listener.Addr().String()
			if strings.HasSuffix(addr, ":853") {
				target = n.dot.Addr().String()
			}
			var d net.Dialer
			return d.DialContext(ctx, network, target)
		},
		Now: time.Now,
	})
}

var addr = netip.MustParseAddr("192.0.2.1")

func probe(t *testing.T, p *hubprobe.Prober, z string) (dot, doh bool) {
	t.Helper()
	dot, doh, _, _ = p.Probe(context.Background(), addr, z)
	return dot, doh
}

// A node that answers as the contract says passes both parts.
func TestAGoodNodePassesBothParts(t *testing.T) {
	p := newPKI(t)
	n := newNode(t, p)
	if dot, doh := probe(t, n.prober(p.pool), zoneName); !dot || !doh {
		t.Fatalf("dot %v doh %v", dot, doh)
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if len(n.sni) != 1 || !regexp.MustCompile(`^[a-z2-7]{26}\.verify\.`+regexp.QuoteMeta(zoneName)+`$`).MatchString(n.sni[0]) {
		t.Fatalf("the DoH part asks for a 26-character label under verify.<zone>: %v", n.sni)
	}
}

// The DoT part fails on each wrong answer the contract lists.
func TestTheDoTPartFailsOnAWrongAnswer(t *testing.T) {
	p := newPKI(t)
	n := newNode(t, p)
	pr := n.prober(p.pool)
	for name, f := range map[string]soaFault{
		"AA=0":           {aa: true},
		"a wrong ID":     {wrongID: true},
		"a changed ques": {wrongQuestion: true},
		"a wrong owner":  {wrongOwner: true},
		"a wrong MNAME":  {wrongMName: true},
		"no answer":      {noAnswer: true},
	} {
		n.setFault(f)
		if dot, doh := probe(t, pr, zoneName); dot || !doh {
			t.Errorf("%s: dot %v doh %v", name, dot, doh)
		}
	}
	n.setFault(soaFault{})
	if dot, _ := probe(t, pr, zoneName); !dot {
		t.Fatal("the fault stayed")
	}
}

// The DoH part passes whatever `seen` says and fails on any other status or a body that is not the /v JSON.
func TestTheDoHPartReadsStatusAndBodyOnly(t *testing.T) {
	p := newPKI(t)
	n := newNode(t, p)
	pr := n.prober(p.pool)
	n.setDoH(200, strings.Replace(goodBody, `"seen":false`, `"seen":true`, 1))
	if _, doh := probe(t, pr, zoneName); !doh {
		t.Error("seen true failed")
	}
	for name, c := range map[string]struct {
		status int
		body   string
	}{
		"a 500":              {500, goodBody},
		"a 404":              {404, goodBody},
		"not JSON":           {200, "hello"},
		"missing fields":     {200, `{"seen":true}`},
		"a short hex field":  {200, strings.Replace(goodBody, `"n":"00000000000000000000000000000001"`, `"n":"01"`, 1)},
		"an empty body":      {200, ""},
		"an array":           {200, `[]`},
		"a field of no type": {200, strings.Replace(goodBody, `"seen":false`, `"seen":"no"`, 1)},
	} {
		n.setDoH(c.status, c.body)
		if dot, doh := probe(t, pr, zoneName); doh || !dot {
			t.Errorf("%s: dot %v doh %v", name, dot, doh)
		}
	}
}

// A certificate that does not chain to the configured CA, or that does not carry the exact name, fails both parts, and no part
// has a way to skip either check.
func TestAWrongChainOrAWrongNameFails(t *testing.T) {
	p := newPKI(t)
	n := newNode(t, p)
	other := newPKI(t)
	if dot, doh := probe(t, n.prober(other.pool), zoneName); dot || doh {
		t.Errorf("a chain to another CA: dot %v doh %v", dot, doh)
	}
	if dot, doh := probe(t, n.prober(x509.NewCertPool()), zoneName); dot || doh {
		t.Errorf("no root at all (the fail-closed pool): dot %v doh %v", dot, doh)
	}
	if dot, doh := probe(t, n.prober(p.pool), "dns.other.example"); dot || doh {
		t.Errorf("a zone the certificate does not cover: dot %v doh %v", dot, doh)
	}
	// A self-signed certificate of the right names is no better than another CA's.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: zoneName}, DNSNames: hubpki.ZoneNames(zoneName),
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ss := newNode(t, pki{cert: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}})
	if dot, doh := probe(t, ss.prober(p.pool), zoneName); dot || doh {
		t.Errorf("a self-signed certificate: dot %v doh %v", dot, doh)
	}
}

func TestLabelsAre26CharactersFromTheAlphabetAndDoNotRepeat(t *testing.T) {
	re := regexp.MustCompile(`^[a-z2-7]{26}$`)
	seen := map[string]bool{}
	for i := 0; i < 200_000; i++ {
		l, err := hubprobe.Label()
		if err != nil || !re.MatchString(l) || seen[l] {
			t.Fatalf("label %q err %v repeated %v", l, err, seen[l])
		}
		seen[l] = true
	}
}

// A round reports each target once, and reports nothing while no zone is known (the state then stays unknown, 8a.4).
func TestARoundReportsEachTargetAndNothingWithoutAZone(t *testing.T) {
	p := newPKI(t)
	n := newNode(t, p)
	var mu sync.Mutex
	var got []hubprobe.Result
	zone := ""
	cfg := hubprobe.Config{
		Targets: func() []hubprobe.Target {
			return []hubprobe.Target{{ID: uuid.MustParse("00000000-0000-4000-8000-000000000001"), Addr: addr}, {ID: uuid.MustParse("00000000-0000-4000-8000-000000000002"), Addr: addr}}
		},
		Zone:  func() string { return zone },
		Roots: func() *x509.CertPool { return p.pool },
		Report: func(r hubprobe.Result) {
			mu.Lock()
			got = append(got, r)
			mu.Unlock()
		},
		Dial: func(ctx context.Context, network, a string) (net.Conn, error) {
			target := n.doh.Listener.Addr().String()
			if strings.HasSuffix(a, ":853") {
				target = n.dot.Addr().String()
			}
			var d net.Dialer
			return d.DialContext(ctx, network, target)
		},
		Now: time.Now,
	}
	pr := hubprobe.New(cfg)
	pr.Round(context.Background())
	if len(got) != 0 {
		t.Fatalf("no zone, yet %d results", len(got))
	}
	zone = zoneName
	pr.Round(context.Background())
	if len(got) != 2 || !got[0].DoT || !got[0].DoH || !got[1].DoT || !got[1].DoH {
		t.Fatalf("results %+v", got)
	}
}

// The probe package never skips the chain or the name check: no identifier of the package turns either off.
func TestNoProbeSkipsAVerification(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "hubprobe.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	ast.Inspect(f, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok {
			switch id.Name {
			case "InsecureSkipVerify", "VerifyPeerCertificate", "VerifyConnection", "GetClientCertificate":
				t.Errorf("%s: %s", fset.Position(id.Pos()), id.Name)
			}
		}
		return true
	})
}

func TestReadNameFollowsAPointerAndRefusesALoop(t *testing.T) {
	// A response whose SOA owner is a pointer back to the question name is read as that name (the usual compressed form).
	q, err := hubprobe.SOAQuery("dns.test.example.")
	if err != nil {
		t.Fatal(err)
	}
	resp := append([]byte(nil), q...)
	binary.BigEndian.PutUint16(resp[2:], 0x8400)
	binary.BigEndian.PutUint16(resp[6:], 1)
	resp = append(resp, 0xc0, 0x0c)
	resp = binary.BigEndian.AppendUint16(resp, 6)
	resp = binary.BigEndian.AppendUint16(resp, 1)
	resp = binary.BigEndian.AppendUint32(resp, 30)
	rdata := append(name("ns1.dns.test.example"), name("hostmaster.dns.test.example")...)
	rdata = append(rdata, make([]byte, 20)...)
	resp = binary.BigEndian.AppendUint16(resp, uint16(len(rdata)))
	resp = append(resp, rdata...)
	if err := hubprobe.CheckSOA(q, resp, "dns.test.example."); err != nil {
		t.Fatalf("a pointer owner: %v", err)
	}
	// A pointer that points at itself ends in an error, not a hang.
	loop := append([]byte(nil), q...)
	binary.BigEndian.PutUint16(loop[2:], 0x8400)
	binary.BigEndian.PutUint16(loop[6:], 1)
	off := len(loop)
	loop = append(loop, 0xc0, byte(off))
	loop = append(loop, make([]byte, 10)...)
	if err := hubprobe.CheckSOA(q, loop, "dns.test.example."); err == nil {
		t.Fatal("a looping name was accepted")
	}
}
