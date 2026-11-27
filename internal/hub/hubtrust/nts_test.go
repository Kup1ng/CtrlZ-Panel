package hubtrust_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubpki"
	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubtrust"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

type alerts struct {
	mu    sync.Mutex
	kinds []store.HubAlertKind
	last  map[string]string
}

func (a *alerts) HubAlert(_ context.Context, _ string, k store.HubAlertKind, p map[string]string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.kinds, a.last = append(a.kinds, k), p
	return nil
}

func newCA(t *testing.T, now time.Time) *hubpki.NodeCA {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "Ctrl Z node CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(10 * 365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	kder, _ := x509.MarshalPKCS8PrivateKey(k)
	ca, err := hubpki.LoadNodeCA(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), now)
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

func leafOf(t *testing.T, dir string) *x509.Certificate {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, hubtrust.NTSCertFile))
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(b)
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// T-087 (7.10): the hub writes the five-year NTS leaf into the directory chrony reads, signed by the node CA for the names the
// nodes dial and for server use only, with the key beside it; it leaves a good leaf alone; it writes a new one when a third of
// the life is left, when the names change, when the key file is gone, or when the node CA is another; and each write raises the
// alert that asks the operator to restart chrony (the one thing chrony needs, since it reads the files only at start).
func TestNTSLeafIsWrittenOnceAndRewrittenWhenItMustBe(t *testing.T) {
	now := time.Date(2026, 11, 26, 10, 0, 0, 0, time.UTC)
	clock := now
	ca := newCA(t, now)
	dir := t.TempDir()
	al := &alerts{}
	n := &hubtrust.NTS{CA: ca, Dir: dir, Hosts: "hub.example.net,203.0.113.7", Now: func() time.Time { return clock }, Alerts: al}
	ctx := context.Background()

	wrote, err := n.Ensure(ctx)
	if err != nil || !wrote {
		t.Fatalf("first pass: wrote %v, err %v", wrote, err)
	}
	leaf := leafOf(t, dir)
	if life := leaf.NotAfter.Sub(leaf.NotBefore); life < 5*365*24*time.Hour-time.Hour || life > 5*365*24*time.Hour+time.Hour {
		t.Errorf("life %v, want five years", life)
	}
	if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Errorf("EKU %v, want serverAuth only", leaf.ExtKeyUsage)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: ca.Pool(), DNSName: "hub.example.net", CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Errorf("the node CA does not verify the leaf for the hub name: %v", err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: ca.Pool(), CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err == nil {
		t.Error("the NTS leaf verifies as a client certificate")
	}
	if len(al.kinds) != 1 || al.kinds[0] != store.HubAlertNTSLeafWritten {
		t.Fatalf("alerts %v, want one nts_leaf_written", al.kinds)
	}
	for k, v := range al.last { // names only: no key, path or serial in the alert
		if len(v) > 40 {
			t.Errorf("alert param %s is %d bytes: it looks like more than a name", k, len(v))
		}
	}
	serial := leaf.SerialNumber

	// A good leaf is left alone, and no alert is raised for nothing.
	clock = now.Add(365 * 24 * time.Hour)
	if wrote, err := n.Ensure(ctx); err != nil || wrote || len(al.kinds) != 1 {
		t.Fatalf("a good leaf was rewritten (wrote %v, err %v, alerts %d)", wrote, err, len(al.kinds))
	}

	// A third of the life left: renewed, with an alert.
	clock = now.Add(3 * 365 * 24 * time.Hour) // two of five years left: more than a third
	if wrote, _ := n.Ensure(ctx); wrote {
		t.Fatal("a leaf with more than a third of its life left was rewritten")
	}
	clock = now.Add(4 * 365 * 24 * time.Hour) // a year left of five: under a third
	if wrote, err := n.Ensure(ctx); err != nil || !wrote {
		t.Fatalf("a leaf with under a third left was not renewed (wrote %v, err %v)", wrote, err)
	}
	if leafOf(t, dir).SerialNumber.Cmp(serial) == 0 || len(al.kinds) != 2 {
		t.Fatal("the renewal wrote the same leaf or raised no alert")
	}
	clock = now

	// Another name list, a missing key file, a leaf of another CA: each is a new leaf.
	n.Hosts = "other.example.net"
	if wrote, _ := n.Ensure(ctx); !wrote {
		t.Error("a changed host list did not give a new leaf")
	}
	if err := os.Remove(filepath.Join(dir, hubtrust.NTSKeyFile)); err != nil {
		t.Fatal(err)
	}
	if wrote, _ := n.Ensure(ctx); !wrote {
		t.Error("a missing key file did not give a new leaf")
	}
	if _, err := os.Stat(filepath.Join(dir, hubtrust.NTSKeyFile)); err != nil {
		t.Error("the key was not written again")
	}
	n.CA = newCA(t, now)
	if wrote, _ := n.Ensure(ctx); !wrote {
		t.Error("a leaf of another node CA was kept")
	}
	if len(al.kinds) != 5 {
		t.Errorf("%d alerts, want one per write (5)", len(al.kinds))
	}
}

// A directory that cannot be written is an error, and raises no alert for a file that does not exist.
func TestNTSLeafWriteFailureRaisesNoAlert(t *testing.T) {
	now := time.Now()
	al := &alerts{}
	n := &hubtrust.NTS{CA: newCA(t, now), Dir: filepath.Join(t.TempDir(), "missing", "dir"), Hosts: "hub.example.net", Now: func() time.Time { return now }, Alerts: al}
	if wrote, err := n.Ensure(context.Background()); err == nil || wrote || len(al.kinds) != 0 {
		t.Fatalf("wrote %v, err %v, alerts %d", wrote, err, len(al.kinds))
	}
}
