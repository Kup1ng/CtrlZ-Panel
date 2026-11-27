package hub_test

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/google/uuid"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"

	"github.com/Kup1ng/CtrlZ-Panel/internal/hub"
	"github.com/Kup1ng/CtrlZ-Panel/internal/intakeseal"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

type wildSource struct{ rows []store.HubWildcardRow }

func (w wildSource) HubWildcardRows(context.Context) ([]store.HubWildcardRow, error) {
	return w.rows, nil
}

// The two halves of P4 meet here: the admin stores an uploaded wildcard sealed to the intake key, and the hub, given that key and
// the rows, sends the uploaded chain to the node for the live zone instead of a leaf of the zone CA (4.3). Before the hub was
// wired to the rows, startHub gave it no Wildcards and every node got the private-CA leaf while the worker told tenants that no
// reinstall was needed (I-r1-1).
func TestTheHubSendsTheUploadedWildcardForTheLiveZone(t *testing.T) {
	const zone = "dns.example.ir"
	now := time.Now()
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test public root"}, NotBefore: now.Add(-24 * time.Hour),
		NotAfter: now.Add(10 * 365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTpl, rootTpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := x509.ParseCertificate(rootDER)
	roots := x509.NewCertPool()
	roots.AddCert(root)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: zone}, DNSNames: []string{zone, "*." + zone, "*.verify." + zone},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(60 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTpl, root, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	chain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	ik, _ := ecdh.X25519().GenerateKey(rand.Reader)
	ikDER, _ := x509.MarshalPKCS8PrivateKey(ik)
	ikPub, _ := x509.MarshalPKIXPublicKey(ik.PublicKey())
	pub, err := intakeseal.ParsePublicKey(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: ikPub}))
	if err != nil {
		t.Fatal(err)
	}
	leafPKCS8, _ := x509.MarshalPKCS8PrivateKey(leafKey)
	sealed, err := intakeseal.Seal(pub, intakeseal.Wildcard, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: leafPKCS8}))
	if err != nil {
		t.Fatal(err)
	}

	_, polPriv, _ := ed25519.GenerateKey(rand.Reader)
	polDER, _ := x509.MarshalPKCS8PrivateKey(polPriv)
	var fdb *fakeDB
	pre := func(d *fakeDB) {
		fdb = d
		d.zones.DNSZone = zone
	}
	mod := func(d *hub.Deps) {
		d.Next = nil
		d.Stores.Stream, d.Stores.Transfer, d.Stores.Lease = fdb, fdb, fdb
		d.PolicyKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: polDER})
		d.ProofKey = make([]byte, 32)
		d.ArtifactsDir = t.TempDir()
		d.Stores.Wildcards = wildSource{rows: []store.HubWildcardRow{{ID: uuid.New(), ChainPEM: string(chain), SealedKey: sealed}}}
		d.WildcardKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: ikDER})
		d.WildcardRoots = roots
	}
	h := newHarnessMod(t, pre, mod)
	e := h.enrol()
	client := hubv1.NewNodeHubClient(h.dial(e.cert))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	st, err := client.Control(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Send(&hubv1.NodeMessage{Body: &hubv1.NodeMessage_Heartbeat{Heartbeat: &hubv1.Heartbeat{
		NodeTime: h.clk.Now().Unix(), NodeVersion: "1", BlobMajorMax: 1}}}); err != nil {
		t.Fatal(err)
	}
	for {
		m, err := st.Recv()
		if err != nil {
			t.Fatalf("no certificate bundle arrived: %v", err)
		}
		if cb := m.GetCertBundle(); cb != nil {
			if string(cb.ChainPem) != string(chain) {
				t.Fatal("the node was given a leaf of the zone CA, not the uploaded wildcard")
			}
			if len(cb.WrappedKey) == 0 {
				t.Fatal("no key came with the uploaded chain")
			}
			return
		}
	}
}
