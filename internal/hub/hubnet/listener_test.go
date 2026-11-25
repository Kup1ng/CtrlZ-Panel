package hubnet

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hublimit"
	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubpki"
)

// A certificate is not a secret, so the per-node count of connections is not charged for one that only
// shows it (W3-r1-9): VerifyConnection judges the certificate and counts nothing, and the count is taken
// once the handshake has proved the key.
func TestNodeConnectionIsCountedAfterTheKeyIsProved(t *testing.T) {
	now := time.Now()
	ck, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "Ctrl Z node CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	cder, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &ck.PublicKey, ck)
	if err != nil {
		t.Fatal(err)
	}
	kder, _ := x509.MarshalPKCS8PrivateKey(ck)
	ca, err := hubpki.LoadNodeCA(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cder}), now)
	if err != nil {
		t.Fatal(err)
	}
	nk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	node := uuid.New()
	iss, err := ca.IssueClient(&nk.PublicKey, node, now)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(iss.DER)

	counts := hublimit.NewCounts(MaxConnsPerNode)
	l := &Listener{cfg: ListenerConfig{CA: ca, NodeConns: counts, Now: func() time.Time { return now }}}
	cs := tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}

	// Any number of peers that show the certificate and never prove the key.
	for i := 0; i < 50; i++ {
		if err := l.verify(&rawConn{}, cs); err != nil {
			t.Fatal(err)
		}
	}
	if counts.Of(node.String()) != 0 {
		t.Fatalf("%d connections counted for a certificate that was only shown", counts.Of(node.String()))
	}
	// The ones that finished the handshake are counted, six of them.
	var conns []*rawConn
	for i := 0; i < MaxConnsPerNode+1; i++ {
		rc := &rawConn{}
		if err := l.verify(rc, cs); err != nil {
			t.Fatal(err)
		}
		if ok := l.countNode(rc); ok != (i < MaxConnsPerNode) {
			t.Fatalf("connection %d: counted %v", i, ok)
		}
		conns = append(conns, rc)
	}
	for _, rc := range conns {
		for _, f := range rc.releases {
			f()
		}
	}
	if counts.Of(node.String()) != 0 {
		t.Fatal("a closed connection kept its count")
	}
}

// testNodeCA is a node CA for the listener tests, with the hub's own server leaf for 127.0.0.1.
func testNodeCA(t *testing.T, now time.Time) (*hubpki.NodeCA, tls.Certificate) {
	t.Helper()
	ck, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "Ctrl Z node CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	cder, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &ck.PublicKey, ck)
	if err != nil {
		t.Fatal(err)
	}
	kder, _ := x509.MarshalPKCS8PrivateKey(ck)
	ca, err := hubpki.LoadNodeCA(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cder}), now)
	if err != nil {
		t.Fatal(err)
	}
	sk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	iss, err := ca.IssueServer(&sk.PublicKey, "ctrlz-hub", nil, []net.IP{net.IPv4(127, 0, 0, 1)}, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	return ca, tls.Certificate{Certificate: [][]byte{iss.DER}, PrivateKey: sk}
}

// What a peer may send before its handshake is done is bounded (W3-r4-5): a client that wraps its node
// certificate in a message of many certificates is dropped while Go would still be parsing them, and one
// that sends a few certificates more than a node ever does is refused by verify. A node's own handshake
// goes through, and after it the cap is gone, so a long-lived connection is not cut at 32 KiB.
func TestHandshakeBytesAndCertificatesAreBounded(t *testing.T) {
	now := time.Now()
	ca, hubCert := testNodeCA(t, now)
	nk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	iss, err := ca.IssueClient(&nk.PublicKey, uuid.New(), now)
	if err != nil {
		t.Fatal(err)
	}
	jk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jtpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "j"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	junk, err := x509.CreateCertificate(rand.Reader, jtpl, jtpl, &jk.PublicKey, jk)
	if err != nil {
		t.Fatal(err)
	}

	conns, hs, nc, nodeConns := NewLimits(func() time.Time { return now })
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l, err := NewListener(inner, ListenerConfig{TLS: &tls.Config{Certificates: []tls.Certificate{hubCert}}, CA: ca,
		Now: func() time.Time { return now }, Conns: conns, Handshakes: hs, NoCert: nc, NodeConns: nodeConns,
		HandshakeTimeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	dial := func(extra int) (*tls.Conn, error) {
		chain := [][]byte{iss.DER}
		for i := 0; i < extra; i++ {
			chain = append(chain, junk)
		}
		c, err := tls.Dial("tcp", inner.Addr().String(), &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13,
			Certificates: []tls.Certificate{{Certificate: chain, PrivateKey: nk}}})
		if err != nil {
			return nil, err
		}
		// TLS 1.3 lets the client finish before the server has judged its certificate: the verdict is the
		// connection staying open.
		_ = c.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
		if _, err := c.Read(make([]byte, 1)); err == nil {
			return c, nil
		} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return c, nil
		}
		_ = c.Close()
		return nil, errors.New("closed by the hub")
	}
	accepted := func() bool {
		type res struct{ ok bool }
		ch := make(chan res, 1)
		go func() {
			c, err := l.Accept()
			if err == nil {
				_ = c.Close()
			}
			ch <- res{err == nil}
		}()
		select {
		case r := <-ch:
			return r.ok
		case <-time.After(500 * time.Millisecond):
			return false
		}
	}

	// Control: the node's own handshake is admitted.
	c, err := dial(0)
	if err != nil {
		t.Fatalf("a node: %v", err)
	}
	if !accepted() {
		t.Fatal("a node connection was not delivered")
	}
	_ = c.Close()

	// A message of 150 certificates is over the byte cap whatever they are.
	if c, err := dial(150); err == nil {
		_ = c.Close()
		t.Fatal("a handshake of 150 certificates stayed open")
	}
	// A few more than a node sends is over maxPeerCerts and stays under the cap.
	if c, err := dial(5); err == nil {
		_ = c.Close()
		t.Fatal("a handshake of six certificates stayed open")
	}
	if accepted() {
		t.Fatal("a refused handshake was delivered")
	}
}

// The cap is lifted once the handshake is done, so what a node sends afterwards is not counted.
func TestRawConnCapEndsWithTheHandshake(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	rc := &rawConn{Conn: b}
	go func() { _, _ = a.Write(make([]byte, MaxHandshakeBytes+10)) }()
	buf := make([]byte, 1<<16)
	var got int
	var rerr error
	for rerr == nil {
		var n int
		n, rerr = rc.Read(buf)
		got += n
	}
	if got > MaxHandshakeBytes+1 || rerr != errHandshakeBytes {
		t.Fatalf("read %d bytes, err %v", got, rerr)
	}
	a2, b2 := net.Pipe()
	defer a2.Close()
	rc = &rawConn{Conn: b2, capLifted: true}
	go func() { _, _ = a2.Write(make([]byte, 3*MaxHandshakeBytes)) }()
	got = 0
	for got < 3*MaxHandshakeBytes {
		n, err := rc.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		got += n
	}
}
