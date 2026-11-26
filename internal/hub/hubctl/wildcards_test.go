package hubctl_test

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubctl"
	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubpki"
	"github.com/Kup1ng/CtrlZ-Panel/internal/intakeseal"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// wildFixture is an uploaded wildcard as the admin stores it: a leaf of a test root for the three names of a zone, and its key
// sealed to an intake key whose private half is the hub's.
type wildFixture struct {
	roots    *x509.CertPool
	chainPEM string
	leafKey  *ecdsa.PrivateKey
	hubKey   []byte // the hub's intake private key, PKCS #8 PEM
	intake   intakeseal.PublicKey
	row      store.HubWildcardRow
}

func newIntake(t *testing.T) (priv []byte, pub intakeseal.PublicKey) {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pk, _ := x509.MarshalPKCS8PrivateKey(k)
	pb, _ := x509.MarshalPKIXPublicKey(k.PublicKey())
	pub, err = intakeseal.ParsePublicKey(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pb}))
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk}), pub
}

// uploadedWildcard makes the fixture for zone, valid from an hour before now for 60 days.
func uploadedWildcard(t *testing.T, zone string, now time.Time) wildFixture {
	t.Helper()
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
	hubKey, intake := newIntake(t)
	f := wildFixture{roots: roots, leafKey: leafKey, hubKey: hubKey, intake: intake,
		chainPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}))}
	f.row = store.HubWildcardRow{ID: uuid.New(), ChainPEM: f.chainPEM, SealedKey: f.seal(t, leafKey, intakeseal.Wildcard)}
	return f
}

// seal writes key as the admin does: PKCS #8 PEM, sealed to the intake key for a purpose.
func (f wildFixture) seal(t *testing.T, key *ecdsa.PrivateKey, p intakeseal.Purpose) []byte {
	t.Helper()
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	sealed, err := intakeseal.Seal(f.intake, p, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}

type wildRows struct {
	mu    sync.Mutex
	rows  []store.HubWildcardRow
	reads int
	err   error
}

func (w *wildRows) HubWildcardRows(context.Context) ([]store.HubWildcardRow, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.reads++
	return append([]store.HubWildcardRow(nil), w.rows...), w.err
}

func (w *wildRows) count() int { w.mu.Lock(); defer w.mu.Unlock(); return w.reads }

// The hub opens the key of the uploaded wildcard that covers a zone and hands it on in the form the bundle builder seals for a
// node; a zone no row covers is private-CA (found false, no error).
func TestAnUploadedWildcardIsChosenForItsZoneAndItsKeyOpens(t *testing.T) {
	clk := &clock{t: time.Now()}
	f := uploadedWildcard(t, "dns.example.test", clk.now())
	rows := &wildRows{rows: []store.HubWildcardRow{f.row}}
	u := hubctl.NewUploadedWildcards(rows, f.hubKey, clk.now).WithRoots(f.roots)

	chain, keyDER, notAfter, found, err := u.Covering(context.Background(), "dns.example.test")
	if err != nil || !found {
		t.Fatalf("the covering wildcard: found %v, %v", found, err)
	}
	key, err := x509.ParsePKCS8PrivateKey(keyDER)
	if err != nil {
		t.Fatalf("the key handed on is not PKCS #8: %v", err)
	}
	if ec, ok := key.(*ecdsa.PrivateKey); !ok || !f.leafKey.Equal(ec) {
		t.Fatal("the key handed on is not the leaf's")
	}
	if string(chain) != f.chainPEM || notAfter.Before(clk.now().Add(59*24*time.Hour)) {
		t.Fatalf("chain or end of life wrong: %v", notAfter)
	}
	if _, _, _, found, err := u.Covering(context.Background(), "dns.other.test"); found || err != nil {
		t.Fatalf("a zone no row covers: found %v, %v", found, err)
	}
}

// The choice is kept for a few seconds so that the streams of many nodes do not read the table and verify the chains on
// every pass, and is made again after them, so a retired or a newly uploaded wildcard reaches the nodes.
func TestTheChoiceOfAnUploadedWildcardIsKeptForAFewSeconds(t *testing.T) {
	clk := &clock{t: time.Now()}
	f := uploadedWildcard(t, "dns.example.test", clk.now())
	rows := &wildRows{rows: []store.HubWildcardRow{f.row}}
	u := hubctl.NewUploadedWildcards(rows, f.hubKey, clk.now).WithRoots(f.roots)
	for i := 0; i < 3; i++ {
		if _, _, _, found, err := u.Covering(context.Background(), "dns.example.test"); !found || err != nil {
			t.Fatalf("call %d: %v %v", i, found, err)
		}
	}
	if rows.count() != 1 {
		t.Fatalf("%d reads for three calls inside the window", rows.count())
	}
	rows.mu.Lock()
	rows.rows = nil // retired
	rows.mu.Unlock()
	clk.add(6 * time.Second)
	if _, _, _, found, err := u.Covering(context.Background(), "dns.example.test"); found || err != nil {
		t.Fatalf("after the window a retired wildcard was still served: %v %v", found, err)
	}
	if rows.count() != 2 {
		t.Fatalf("%d reads, want the choice made again", rows.count())
	}
}

// A row whose key does not open, or is not the leaf's, is an error and never a reason to serve another certificate: the stream
// sends nothing for the zone and the node keeps its own.
func TestAnUploadedWildcardWhoseKeyIsWrongIsAnErrorAndGivesNoKey(t *testing.T) {
	clk := &clock{t: time.Now()}
	f := uploadedWildcard(t, "dns.example.test", clk.now())
	stranger, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherIntake := uploadedWildcard(t, "dns.example.test", clk.now())
	plain, _ := intakeseal.Seal(f.intake, intakeseal.Wildcard, []byte("plain text"))
	bare, _ := x509.MarshalPKCS8PrivateKey(f.leafKey)
	bareSealed, _ := intakeseal.Seal(f.intake, intakeseal.Wildcard, bare)
	for name, sealed := range map[string][]byte{
		"sealed for the web intake":      f.seal(t, f.leafKey, intakeseal.Web),
		"the key of another certificate": f.seal(t, stranger, intakeseal.Wildcard),
		"bytes that are not a seal":      []byte("not a seal"),
		"sealed to another intake key":   otherIntake.row.SealedKey,
		"no sealed key at all":           nil,
		"a seal of something not a key":  plain,
		"the key written as bare DER":    bareSealed,
	} {
		row := f.row
		row.SealedKey = sealed
		u := hubctl.NewUploadedWildcards(&wildRows{rows: []store.HubWildcardRow{row}}, f.hubKey, clk.now).WithRoots(f.roots)
		_, keyDER, _, found, err := u.Covering(context.Background(), "dns.example.test")
		if err == nil || found || keyDER != nil {
			t.Errorf("%s: found %v, key %d bytes, error %v", name, found, len(keyDER), err)
		}
	}
}

// A chain that does not verify to the roots, or has ended, is not chosen: the zone is private-CA, the mode that keeps devices
// that installed the zone CA working after a public certificate ended (4.3).
func TestAnUploadedWildcardThatHasEndedOrIsNotPublicIsNotChosen(t *testing.T) {
	clk := &clock{t: time.Now()}
	f := uploadedWildcard(t, "dns.example.test", clk.now())
	rows := &wildRows{rows: []store.HubWildcardRow{f.row}}
	other := uploadedWildcard(t, "dns.example.test", clk.now())
	notPublic := hubctl.NewUploadedWildcards(rows, f.hubKey, clk.now).WithRoots(other.roots)
	if _, _, _, found, err := notPublic.Covering(context.Background(), "dns.example.test"); found || err != nil {
		t.Fatalf("a chain of another root: found %v, %v", found, err)
	}
	ended := hubctl.NewUploadedWildcards(rows, f.hubKey, func() time.Time { return clk.now().Add(61 * 24 * time.Hour) }).WithRoots(f.roots)
	if _, _, _, found, err := ended.Covering(context.Background(), "dns.example.test"); found || err != nil {
		t.Fatalf("a chain that has ended: found %v, %v", found, err)
	}
}

// The database failing is an error, so the stream keeps what it has sent and does not fall back to the private CA for a zone an
// upload may cover.
func TestAFailedReadOfTheUploadedRowsIsAnError(t *testing.T) {
	clk := &clock{t: time.Now()}
	f := uploadedWildcard(t, "dns.example.test", clk.now())
	rows := &wildRows{err: context.DeadlineExceeded}
	u := hubctl.NewUploadedWildcards(rows, f.hubKey, clk.now).WithRoots(f.roots)
	if _, _, _, found, err := u.Covering(context.Background(), "dns.example.test"); err == nil || found {
		t.Fatalf("found %v, %v", found, err)
	}
}

// Through the bundle builder, every node gets the covering wildcard in place of a leaf of the zone CA (4.3), sealed to its own key.
func TestEveryNodeGetsTheUploadedWildcardInsteadOfAZoneLeaf(t *testing.T) {
	clk := &clock{t: time.Now()}
	f := uploadedWildcard(t, "dns.example.test", clk.now())
	zkey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca, err := hubpki.IssueZoneCA(zkey, []string{"dns.example.test"}, clk.now())
	if err != nil {
		t.Fatal(err)
	}
	u := hubctl.NewUploadedWildcards(&wildRows{rows: []store.HubWildcardRow{f.row}}, f.hubKey, clk.now).WithRoots(f.roots)
	c := hubctl.NewCerts(zoneOnly{ca}, u, clk.now)
	a, b := newNode(t), newNode(t)
	ba, err := c.For(context.Background(), a.id, &a.key.PublicKey, []string{"dns.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	bb, _ := c.For(context.Background(), b.id, &b.key.PublicKey, []string{"dns.example.test"})
	if string(ba[0].Msg.ChainPem) != f.chainPEM || string(bb[0].Msg.ChainPem) != f.chainPEM {
		t.Fatal("a node was not given the uploaded chain")
	}
	if string(ba[0].Msg.WrappedKey) == string(bb[0].Msg.WrappedKey) || len(ba[0].Msg.WrappedKey) == 0 {
		t.Fatal("the key is not sealed to each node on its own")
	}
	if !strings.HasPrefix(ba[0].ID, "dns.example.test/w/") {
		t.Fatalf("bundle id %q is not a wildcard's", ba[0].ID)
	}
}

type alertLog struct {
	mu   sync.Mutex
	rows []map[string]string
	kind []store.HubAlertKind
	sev  []string
}

func (a *alertLog) HubAlert(_ context.Context, sev string, k store.HubAlertKind, p map[string]string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.rows, a.kind, a.sev = append(a.rows, p), append(a.kind, k), append(a.sev, sev)
	return nil
}

// One uploaded wildcard that does not open stops its own zone and nothing else (I-r2-1, I-r2-3): the other zone of the same
// node, a plain private-CA zone, still gets its leaf, and the bad row raises one critical alert however many passes see it.
func TestABadUploadedWildcardStopsOnlyItsOwnZone(t *testing.T) {
	clk := &clock{t: time.Now()}
	f := uploadedWildcard(t, "dns.example.test", clk.now())
	bad := f.row
	bad.SealedKey = f.seal(t, f.leafKey, intakeseal.Web) // sealed for another purpose: the hub's intake key cannot open it
	zkey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca, err := hubpki.IssueZoneCA(zkey, []string{"dns.example.test", "dns.prev.example.test"}, clk.now())
	if err != nil {
		t.Fatal(err)
	}
	al := &alertLog{}
	u := hubctl.NewUploadedWildcards(&wildRows{rows: []store.HubWildcardRow{bad}}, f.hubKey, clk.now).WithRoots(f.roots).WithAlerts(al)
	c := hubctl.NewCerts(zoneOnly{ca}, u, clk.now)
	n := newNode(t)
	zones := []string{"dns.example.test", "dns.prev.example.test"}
	for range 3 {
		got, err := c.For(context.Background(), n.id, &n.key.PublicKey, zones)
		if err == nil {
			t.Fatal("the bad row raised no error")
		}
		if len(got) != 2 || got[0].Msg != nil {
			t.Fatalf("the failing zone was not left empty: %d bundles", len(got))
		}
		if got[1].Msg == nil || !strings.HasPrefix(got[1].ID, "dns.prev.example.test/p/") {
			t.Fatalf("the healthy zone got no private-CA leaf: %+v", got[1])
		}
	}
	if len(al.kind) != 1 || al.kind[0] != store.HubAlertWildcardUnusable || al.sev[0] != "critical" || al.rows[0]["certificate_id"] != bad.ID.String() {
		t.Fatalf("alerts: %v %v %v", al.kind, al.sev, al.rows)
	}
	// The row works again (the intake seal is made right): the mark is cleared, so a later failure alerts again.
	rows := &wildRows{rows: []store.HubWildcardRow{f.row}}
	u2 := hubctl.NewUploadedWildcards(rows, f.hubKey, clk.now).WithRoots(f.roots).WithAlerts(al)
	if _, _, _, found, err := u2.Covering(context.Background(), "dns.example.test"); !found || err != nil {
		t.Fatalf("the good row: %v %v", found, err)
	}
}
