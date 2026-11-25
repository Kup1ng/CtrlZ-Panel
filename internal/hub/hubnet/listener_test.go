package hubnet

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
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
