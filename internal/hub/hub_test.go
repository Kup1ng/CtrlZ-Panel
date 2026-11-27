package hub_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/Kup1ng/CtrlZ-Shared/enrollproof"
	enrollv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/enroll/v1"
	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	signv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/sign/v1"
	telv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/telemetry/v1"
	"github.com/Kup1ng/CtrlZ-Shared/manifest"

	"github.com/Kup1ng/CtrlZ-Panel/internal/hub"
	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubtoken"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testwait"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func pkcs8PEM(t *testing.T, k *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// ctrlStub is the seam of 5.2: Control blocks until the stream's context ends, which is what the
// registry's cancel does; every other method is the Unimplemented of the base type.
type ctrlStub struct {
	hubv1.UnimplementedNodeHubServer
	opened chan struct{}
	// logsOpen and logsEnded are UploadLogs, written the way every upload handler is: a Recv loop that
	// never looks at the context, which is what Registry.Kill has to be able to end (G2).
	logsOpen  chan struct{}
	logsEnded chan error
	logsRecv  atomic.Int64
}

func (s *ctrlStub) UploadLogs(stream grpc.BidiStreamingServer[telv1.LogBatch, telv1.Ack]) error {
	s.logsOpen <- struct{}{}
	for {
		if _, err := stream.Recv(); err != nil {
			s.logsEnded <- err
			return err
		}
		s.logsRecv.Add(1)
	}
}

func (s *ctrlStub) Control(stream hubv1.NodeHub_ControlServer) error {
	s.opened <- struct{}{}
	<-stream.Context().Done()
	return stream.Context().Err()
}

type harness struct {
	t       *testing.T
	db      *fakeDB
	clk     *clock
	hub     *hub.Hub
	addr    string
	caCert  *x509.Certificate
	caKey   *ecdsa.PrivateKey
	roots   *x509.CertPool
	bundles string
	stub    *ctrlStub
	httpc   *http.Client
}

const bundleVersion = 1

var bundleFiles = map[string][]byte{
	"packaging/install/node.sh": []byte("#!/bin/sh\necho node\n"),
	"bin/ctrlz-verify":          []byte("verifier-bytes"),
	"debs/unbound_1_all.deb":    []byte("deb-bytes-0123456789"),
}

// writeBundle writes root.json and node bundle 1 signed by two of three offline keys, the way a release is.
func writeBundle(t *testing.T, dir string, now time.Time) {
	t.Helper()
	var keys []*signv1.PublicKey
	var priv []ed25519.PrivateKey
	var ids [][]byte
	for i := 0; i < 3; i++ {
		pub, pk, _ := ed25519.GenerateKey(rand.Reader)
		id := manifest.KeyID(pub)
		keys = append(keys, &signv1.PublicKey{KeyId: id, Ed25519: pub})
		priv = append(priv, pk)
		ids = append(ids, id)
	}
	exp := now.Add(365 * 24 * time.Hour).Unix()
	root := &signv1.Root{Version: 1, ExpiresAt: exp, Keys: keys, Threshold: 2, RootKeyIds: ids,
		Roles: []*signv1.RoleGrant{{Role: signv1.Role_ROLE_BUNDLE, KeyIds: ids, Threshold: 2, ExpiresAt: exp}}}
	rj, err := protojson.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	mkdir := func(p string) { _ = os.MkdirAll(p, 0o755) }
	mkdir(dir)
	if err := os.WriteFile(filepath.Join(dir, "root.json"), rj, 0o644); err != nil {
		t.Fatal(err)
	}
	m := &signv1.Manifest{Kind: signv1.Kind_KIND_NODE, Version: bundleVersion, CreatedAt: now.Unix(), ExpiresAt: exp, MinVersion: 1}
	bdir := filepath.Join(dir, "node", "1")
	for p, b := range bundleFiles {
		mkdir(filepath.Dir(filepath.Join(bdir, p)))
		if err := os.WriteFile(filepath.Join(bdir, p), b, 0o644); err != nil {
			t.Fatal(err)
		}
		h := sha256sum(b)
		m.Files = append(m.Files, &signv1.FileEntry{Path: p, Sha256: h, Size: uint64(len(b))})
	}
	payload, err := proto.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	typ := manifest.ManifestPayloadType(signv1.Kind_KIND_NODE)
	env := &signv1.Envelope{PayloadType: typ, Payload: payload}
	for i := 0; i < 2; i++ {
		env.Signatures = append(env.Signatures, &signv1.Signature{KeyId: ids[i], Sig: ed25519.Sign(priv[i], manifest.SigningInput(typ, payload))})
	}
	ej, err := protojson.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bdir, "manifest.json"), ej, 0o644); err != nil {
		t.Fatal(err)
	}
	// A file next to the bundle that no manifest lists: it must never be reachable through the install door.
	if err := os.WriteFile(filepath.Join(dir, "node", "secret.txt"), []byte("no"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func newHarness(t *testing.T) *harness { return newHarnessWith(t, nil) }

// newHarnessWith builds the hub after pre has set up the database, for a state that must exist at start.
func newHarnessWith(t *testing.T, pre func(*fakeDB)) *harness { return newHarnessMod(t, pre, nil) }

// newHarnessMod is newHarnessWith with a last say on the hub's dependencies.
func newHarnessMod(t *testing.T, pre func(*fakeDB), mod func(*hub.Deps)) *harness {
	t.Helper()
	clk := &clock{t: time.Now().UTC().Truncate(time.Second)}
	caKey := newKey(t)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Ctrl Z node CA"},
		NotBefore: clk.Now().Add(-time.Hour), NotAfter: clk.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(der)
	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	dir := t.TempDir()
	writeBundle(t, dir, clk.Now())
	pub := t.TempDir()
	db := newFakeDB()
	if pre != nil {
		pre(db)
	}
	stub := &ctrlStub{opened: make(chan struct{}, 8), logsOpen: make(chan struct{}, 8), logsEnded: make(chan error, 8)}
	deps := hub.Deps{
		Stores: hub.Stores{L3: db, Control: db, Telemetry: db, Enrollment: db},
		Now:    clk.Now, NodeCAKeyPEM: pkcs8PEM(t, caKey), NodeCAPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		HubKeyPEM: pkcs8PEM(t, newKey(t)), ZoneKeyPEM: pkcs8PEM(t, newKey(t)), HubHost: "localhost,127.0.0.1",
		PublicDir: pub, BundlesDir: dir, Next: stub,
	}
	if mod != nil {
		mod(&deps)
	}
	h, err := hub.Build(context.Background(), deps)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- h.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			t.Error("the hub did not stop")
		}
	})
	return &harness{t: t, db: db, clk: clk, hub: h, addr: ln.Addr().String(), caCert: caCert, caKey: caKey, roots: roots, bundles: dir, stub: stub}
}

func (h *harness) tlsConfig(cert *tls.Certificate) *tls.Config {
	c := &tls.Config{RootCAs: h.roots, ServerName: "localhost", MinVersion: tls.VersionTLS13}
	if cert != nil {
		c.Certificates = []tls.Certificate{*cert}
	}
	return c
}

func (h *harness) dial(cert *tls.Certificate) *grpc.ClientConn {
	h.t.Helper()
	cc, err := grpc.NewClient("passthrough:///"+h.addr, grpc.WithTransportCredentials(credentials.NewTLS(h.tlsConfig(cert))))
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() { cc.Close() })
	return cc
}

func ctx5(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func code(err error) codes.Code { return status.Code(err) }

// ---------------------------------------------------------------------------------------------------

type enrolled struct {
	key    *ecdsa.PrivateKey
	token  string
	hash   []byte
	id     []byte
	csr    []byte
	enrID  uuid.UUID
	nodeID uuid.UUID
	cert   *tls.Certificate
	leaf   *x509.Certificate
}

func (h *harness) newEnrolment(bound netip.Prefix) *enrolled {
	e := &enrolled{key: newKey(h.t)}
	var err error
	if e.token, e.hash, err = hubtoken.New(nil); err != nil {
		h.t.Fatal(err)
	}
	h.db.issueToken(e.hash, bound)
	e.csr, err = x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "ctrlz-node"}, SignatureAlgorithm: x509.ECDSAWithSHA256}, e.key)
	if err != nil {
		h.t.Fatal(err)
	}
	return e
}

func (e *enrolled) request() *enrollv1.EnrollRequest {
	return &enrollv1.EnrollRequest{Token: e.token, CsrDer: e.csr, Hostname: "node1.example.net", OsRelease: "Ubuntu 24.04.1 LTS", NodeVersion: "0.4.0",
		DnsBindIp: []byte{10, 0, 0, 5}, DnsAdvertisedIp: []byte{203, 0, 113, 5}, ProxyBindIp: []byte{10, 0, 0, 6}, ProxyAdvertisedIp: []byte{203, 0, 113, 6}}
}

func (e *enrolled) poll(h *harness, cc *grpc.ClientConn) (*enrollv1.PollResponse, error) {
	d := enrollproof.Digest(e.id)
	sig, err := ecdsa.SignASN1(rand.Reader, e.key, d)
	if err != nil {
		h.t.Fatal(err)
	}
	return enrollv1.NewEnrollmentClient(cc).Poll(ctx5(h.t), &enrollv1.PollRequest{EnrollmentId: e.id, ProofSig: sig})
}

// enrol runs the whole of 4.2 to an approved node holding a certificate.
func (h *harness) enrol() *enrolled {
	h.t.Helper()
	e := h.newEnrolment(netip.Prefix{})
	cc := h.dial(nil)
	resp, err := enrollv1.NewEnrollmentClient(cc).Enroll(ctx5(h.t), e.request())
	if err != nil {
		h.t.Fatalf("Enroll: %v", err)
	}
	e.id = resp.GetEnrollmentId()
	e.enrID, _ = uuid.FromBytes(e.id)
	e.nodeID = h.db.confirm(e.enrID)
	h.db.setStatus(e.nodeID, "active")
	pr, err := e.poll(h, cc)
	if err != nil || pr.GetState() != enrollv1.EnrollState_ENROLL_STATE_APPROVED {
		h.t.Fatalf("Poll: %v %v", pr.GetState(), err)
	}
	e.leaf, err = x509.ParseCertificate(pr.GetClientCertDer())
	if err != nil {
		h.t.Fatal(err)
	}
	e.cert = &tls.Certificate{Certificate: [][]byte{pr.GetClientCertDer()}, PrivateKey: e.key}
	return e
}

func TestEnrollmentFlow(t *testing.T) {
	h := newHarness(t)
	e := h.newEnrolment(netip.Prefix{})
	cc := h.dial(nil)
	c := enrollv1.NewEnrollmentClient(cc)

	// The format is judged before the database is asked: nothing below reaches the token.
	bad := e.request()
	bad.Hostname = "bad host!"
	if _, err := c.Enroll(ctx5(t), bad); code(err) != codes.InvalidArgument {
		t.Fatalf("bad hostname: %v", err)
	}
	bad = e.request()
	bad.CsrDer = append([]byte{}, e.csr...)
	bad.CsrDer[len(bad.CsrDer)-1] ^= 1 // the CSR's own signature no longer verifies
	if _, err := c.Enroll(ctx5(t), bad); code(err) != codes.InvalidArgument {
		t.Fatalf("bad CSR signature: %v", err)
	}
	bad = e.request()
	bad.Token = "not-a-token"
	if _, err := c.Enroll(ctx5(t), bad); code(err) != codes.InvalidArgument {
		t.Fatalf("bad token form: %v", err)
	}
	bad = e.request()
	bad.DnsBindIp = []byte{0, 0, 0, 0}
	if _, err := c.Enroll(ctx5(t), bad); code(err) != codes.InvalidArgument {
		t.Fatalf("unspecified address: %v", err)
	}

	resp, err := c.Enroll(ctx5(t), e.request())
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	wantFP, _ := hex.DecodeString(resp.GetKeyFingerprint())
	if len(resp.GetEnrollmentId()) != 16 || len(wantFP) != 32 {
		t.Fatalf("response shape: %d %q", len(resp.GetEnrollmentId()), resp.GetKeyFingerprint())
	}
	e.id = resp.GetEnrollmentId()
	e.enrID, _ = uuid.FromBytes(e.id)

	// A second Enroll with the same token: refused, and it cannot overwrite the record.
	if _, err := c.Enroll(ctx5(t), e.request()); code(err) != codes.PermissionDenied {
		t.Fatalf("token reused: %v", err)
	}

	// Pending until the admin confirms, and still pending while the node row is pending.
	pr, err := e.poll(h, cc)
	if err != nil || pr.GetState() != enrollv1.EnrollState_ENROLL_STATE_PENDING || len(pr.GetClientCertDer()) != 0 {
		t.Fatalf("pending: %v %v", pr, err)
	}
	e.nodeID = h.db.confirm(e.enrID)
	if pr, err = e.poll(h, cc); err != nil || pr.GetState() != enrollv1.EnrollState_ENROLL_STATE_PENDING {
		t.Fatalf("approved with a pending row: %v %v", pr, err)
	}

	// A proof by another key, and a signature in raw form, give nothing.
	other := newKey(t)
	badSig, _ := ecdsa.SignASN1(rand.Reader, other, enrollproof.Digest(e.id))
	if _, err := c.Poll(ctx5(t), &enrollv1.PollRequest{EnrollmentId: e.id, ProofSig: badSig}); code(err) != codes.PermissionDenied {
		t.Fatalf("proof by another key: %v", err)
	}
	// An unknown id is answered like a finished enrolment.
	unknown := make([]byte, 16)
	unknown[0] = 9
	sig, _ := ecdsa.SignASN1(rand.Reader, e.key, enrollproof.Digest(unknown))
	if r, err := c.Poll(ctx5(t), &enrollv1.PollRequest{EnrollmentId: unknown, ProofSig: sig}); err != nil || r.GetState() != enrollv1.EnrollState_ENROLL_STATE_REJECTED {
		t.Fatalf("unknown id: %v %v", r, err)
	}

	// Active: the first Poll issues, later ones return the same certificate and change nothing.
	h.db.setStatus(e.nodeID, "active")
	first, err := e.poll(h, cc)
	if err != nil || first.GetState() != enrollv1.EnrollState_ENROLL_STATE_APPROVED {
		t.Fatalf("issue: %v %v", first, err)
	}
	serial := h.db.node(e.nodeID).serial
	second, err := e.poll(h, cc)
	if err != nil || string(second.GetClientCertDer()) != string(first.GetClientCertDer()) || h.db.node(e.nodeID).serial != serial {
		t.Fatalf("a replayed Poll moved the certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(first.GetClientCertDer())
	if err != nil {
		t.Fatal(err)
	}
	id, _ := uuid.FromBytes(first.GetNodeId())
	if id != e.nodeID || leaf.Subject.CommonName != id.String() || leaf.IsCA || len(leaf.DNSNames)+len(leaf.IPAddresses) != 0 ||
		len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Fatalf("certificate: CN %q EKU %v", leaf.Subject.CommonName, leaf.ExtKeyUsage)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: h.roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, CurrentTime: h.clk.Now()}); err != nil {
		t.Fatalf("does not chain to the node CA: %v", err)
	}
	if got := leaf.NotAfter.Sub(h.clk.Now()); got > 30*24*time.Hour || got < 29*24*time.Hour {
		t.Fatalf("life %v", got)
	}
	if len(first.GetCaChainDer()) != 1 || string(first.GetCaChainDer()[0]) != string(h.caCert.Raw) {
		t.Fatal("the chain is not the node CA")
	}

	// A revoked node gets nothing, even with the right proof.
	h.db.setStatus(e.nodeID, "revoked")
	if r, err := e.poll(h, cc); err != nil || r.GetState() != enrollv1.EnrollState_ENROLL_STATE_REJECTED || len(r.GetClientCertDer()) != 0 {
		t.Fatalf("revoked: %v %v", r, err)
	}
}

func TestEnrollBoundAddressAndExpiry(t *testing.T) {
	h := newHarness(t)
	cc := h.dial(nil)
	c := enrollv1.NewEnrollmentClient(cc)
	away := h.newEnrolment(netip.MustParsePrefix("198.51.100.0/24")) // the test connects from 127.0.0.1
	if _, err := c.Enroll(ctx5(t), away.request()); code(err) != codes.PermissionDenied {
		t.Fatalf("a source outside bound_ip: %v", err)
	}
	here := h.newEnrolment(netip.MustParsePrefix("127.0.0.0/8"))
	if _, err := c.Enroll(ctx5(t), here.request()); err != nil {
		t.Fatalf("a source inside bound_ip: %v", err)
	}
	old := h.newEnrolment(netip.Prefix{})
	h.db.expireToken(old.hash)
	if _, err := c.Enroll(ctx5(t), old.request()); code(err) != codes.PermissionDenied {
		t.Fatalf("an expired token: %v", err)
	}
}

// Every method of both services, from the descriptors (N2): with no certificate a NodeHub method is
// refused before gRPC runs, and an Enrollment method refuses a certificate.
func TestEveryMethodHasItsDoor(t *testing.T) {
	h := newHarness(t)
	e := h.enrol()
	anon := h.dial(nil)
	node := h.dial(e.cert)

	for _, m := range hubv1.NodeHub_ServiceDesc.Methods {
		full := "/" + hubv1.NodeHub_ServiceDesc.ServiceName + "/" + m.MethodName
		if err := anon.Invoke(ctx5(t), full, &hubv1.GetHeadRequest{}, &hubv1.GetHeadRequest{}); code(err) != codes.PermissionDenied {
			t.Errorf("%s with no certificate: %v", m.MethodName, err)
		}
	}
	for _, s := range hubv1.NodeHub_ServiceDesc.Streams {
		full := "/" + hubv1.NodeHub_ServiceDesc.ServiceName + "/" + s.StreamName
		st, err := anon.NewStream(ctx5(t), &grpc.StreamDesc{ServerStreams: true, ClientStreams: true}, full)
		if err == nil {
			_ = st.SendMsg(&hubv1.GetHeadRequest{})
			err = st.RecvMsg(&hubv1.GetHeadRequest{})
		}
		if code(err) != codes.PermissionDenied {
			t.Errorf("%s with no certificate: %v", s.StreamName, err)
		}
	}
	// With a good certificate every method but RenewCert and Control reaches the seam, which says
	// Unimplemented: the door let it through.
	for _, m := range hubv1.NodeHub_ServiceDesc.Methods {
		if m.MethodName == "RenewCert" {
			continue
		}
		full := "/" + hubv1.NodeHub_ServiceDesc.ServiceName + "/" + m.MethodName
		if err := node.Invoke(ctx5(t), full, &hubv1.GetHeadRequest{}, &hubv1.GetHeadRequest{}); code(err) != codes.Unimplemented {
			t.Errorf("%s with a good certificate: %v", m.MethodName, err)
		}
	}
	// Enrollment refuses a node certificate on both methods.
	ec := enrollv1.NewEnrollmentClient(node)
	if _, err := ec.Enroll(ctx5(t), e.request()); code(err) != codes.PermissionDenied {
		t.Errorf("Enroll with a certificate: %v", err)
	}
	if _, err := ec.Poll(ctx5(t), &enrollv1.PollRequest{EnrollmentId: e.id, ProofSig: []byte{1}}); code(err) != codes.PermissionDenied {
		t.Errorf("Poll with a certificate: %v", err)
	}
}

func TestCertificateLifecycleAtTheDoor(t *testing.T) {
	h := newHarness(t)
	e := h.enrol()
	head := func(c *grpc.ClientConn) codes.Code {
		return code(c.Invoke(ctx5(t), "/ctrlz.hub.v1.NodeHub/GetHead", &hubv1.GetHeadRequest{}, &hubv1.GetHeadRequest{}))
	}
	if got := head(h.dial(e.cert)); got != codes.Unimplemented {
		t.Fatalf("a good certificate: %v", got)
	}

	// A revoked node is cut off by its next RPC.
	h.db.setStatus(e.nodeID, "revoked")
	if got := head(h.dial(e.cert)); got != codes.Unauthenticated {
		t.Fatalf("a revoked node: %v", got)
	}
	h.db.setStatus(e.nodeID, "active")

	// A certificate for another key under the same serial and node id is no certificate of the row's.
	imp := newKey(t)
	impCert := h.forge(t, imp, e.nodeID)
	if got := head(h.dial(impCert)); got != codes.Unauthenticated {
		t.Fatalf("a certificate whose key is not the row's: %v", got)
	}

	// A database outage is UNAVAILABLE, not a refusal.
	h.db.downErr = context.DeadlineExceeded
	if got := head(h.dial(e.cert)); got != codes.Unavailable {
		t.Fatalf("a database that cannot be read: %v", got)
	}
	h.db.downErr = nil

	// Past not_after by a day: only RenewCert (4.3). 61 days past: the handshake itself fails.
	h.clk.Advance(31 * 24 * time.Hour)
	if got := head(h.dial(e.cert)); got != codes.Unauthenticated {
		t.Fatalf("one day past not_after: %v", got)
	}
	renew := func(c *grpc.ClientConn) (*hubv1.RenewCertResponse, error) {
		csr, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "x"}}, e.key)
		return hubv1.NewNodeHubClient(c).RenewCert(ctx5(t), &hubv1.RenewCertRequest{CsrDer: csr})
	}
	r, err := renew(h.dial(e.cert))
	if err != nil {
		t.Fatalf("RenewCert one day past not_after: %v", err)
	}
	fresh, err := x509.ParseCertificate(r.GetCertDer())
	if err != nil || fresh.SerialNumber.Cmp(e.leaf.SerialNumber) == 0 {
		t.Fatalf("renewed certificate: %v", err)
	}
	h.clk.Advance(61 * 24 * time.Hour)
	if got := head(h.dial(e.cert)); got == codes.Unimplemented || got == codes.OK {
		t.Fatalf("a certificate 91 days past not_after was admitted: %v", got)
	}
	if _, err := renew(h.dial(e.cert)); err == nil {
		t.Fatal("RenewCert with a certificate past the 60-day grace")
	}
}

// forge makes a certificate the node CA signed for imp, with the node's id: what a stolen CA could do,
// and what the row's SPKI check is for.
func (h *harness) forge(t *testing.T, imp *ecdsa.PrivateKey, node uuid.UUID) *tls.Certificate {
	t.Helper()
	tpl := &x509.Certificate{SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: node.String()},
		NotBefore: h.clk.Now().Add(-time.Minute), NotAfter: h.clk.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tpl, h.caCert, &imp.PublicKey, h.caKey)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: imp}
}

func TestRenewCert(t *testing.T) {
	h := newHarness(t)
	e := h.enrol()
	renew := func(cert *tls.Certificate, key *ecdsa.PrivateKey) (*hubv1.RenewCertResponse, error) {
		csr, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "x"}}, key)
		return hubv1.NewNodeHubClient(h.dial(cert)).RenewCert(ctx5(t), &hubv1.RenewCertRequest{CsrDer: csr})
	}
	// Another key's CSR is refused: a new key is a new enrolment (SC 12).
	if _, err := renew(e.cert, newKey(t)); code(err) != codes.PermissionDenied {
		t.Fatalf("a CSR of another key: %v", err)
	}
	// A node renews when a third of its life is left (4.3), so the certificate it was just given has
	// nothing to renew yet: no signature, no row (W3-r1-10).
	if _, err := renew(e.cert, e.key); code(err) != codes.ResourceExhausted {
		t.Fatalf("a fresh certificate renewed: %v", err)
	}
	h.clk.Advance(21 * 24 * time.Hour)
	r1, err := renew(e.cert, e.key)
	if err != nil {
		t.Fatal(err)
	}
	c1, _ := x509.ParseCertificate(r1.GetCertDer())
	n := h.db.node(e.nodeID)
	if n.serial != c1.SerialNumber.Text(16) || n.prev != e.leaf.SerialNumber.Text(16) {
		t.Fatalf("serials after the renewal: %q %q", n.serial, n.prev)
	}
	// The response was lost: the node renews again with its old certificate. The previous serial stays the
	// one the node holds, so it can still renew once more.
	r2, err := renew(e.cert, e.key)
	if err != nil {
		t.Fatalf("a renewal with the previous certificate: %v", err)
	}
	c2, _ := x509.ParseCertificate(r2.GetCertDer())
	n = h.db.node(e.nodeID)
	if n.serial != c2.SerialNumber.Text(16) || n.prev != e.leaf.SerialNumber.Text(16) {
		t.Fatalf("serials after the second renewal: %q %q", n.serial, n.prev)
	}
	// The first use of the newest certificate clears the previous serial, off the check's pool.
	cert2 := &tls.Certificate{Certificate: [][]byte{r2.GetCertDer()}, PrivateKey: e.key}
	cc := h.dial(cert2)
	if err := cc.Invoke(ctx5(t), "/ctrlz.hub.v1.NodeHub/GetHead", &hubv1.GetHeadRequest{}, &hubv1.GetHeadRequest{}); code(err) != codes.Unimplemented {
		t.Fatalf("the new certificate: %v", err)
	}
	waitFor(t, func() bool { return h.db.node(e.nodeID).prev == "" })
	// The old certificate stops working once the new one has been seen.
	if err := h.dial(e.cert).Invoke(ctx5(t), "/ctrlz.hub.v1.NodeHub/GetHead", &hubv1.GetHeadRequest{}, &hubv1.GetHeadRequest{}); code(err) != codes.Unauthenticated {
		t.Fatalf("the old certificate after the new one was used: %v", err)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not reached")
}

// A revoked node's open stream ends at the next check, and a node that is still accepted keeps its own.
func TestOpenStreamsAreCheckedAgain(t *testing.T) {
	h := newHarness(t)
	a, b := h.enrol(), h.enrol()
	open := func(e *enrolled) grpc.ClientStream {
		st, err := h.dial(e.cert).NewStream(context.Background(), &grpc.StreamDesc{ServerStreams: true, ClientStreams: true}, "/ctrlz.hub.v1.NodeHub/Control")
		if err != nil {
			t.Fatal(err)
		}
		_ = st.SendMsg(&hubv1.NodeMessage{})
		<-h.stub.opened
		return st
	}
	sa, sb := open(a), open(b)
	if h.hub.Streams.Count(a.nodeID) != 1 || h.hub.Streams.Count(b.nodeID) != 1 {
		t.Fatalf("registered streams: %d %d", h.hub.Streams.Count(a.nodeID), h.hub.Streams.Count(b.nodeID))
	}
	// A database outage ends nothing (SC 12).
	h.db.downErr = context.DeadlineExceeded
	if n := h.hub.Recheck(context.Background()); n != 0 {
		t.Fatalf("an outage ended %d streams", n)
	}
	h.db.downErr = nil
	if n := h.hub.Recheck(context.Background()); n != 0 {
		t.Fatalf("a healthy pass ended %d streams", n)
	}
	h.db.setStatus(a.nodeID, "revoked")
	if n := h.hub.Recheck(context.Background()); n != 1 {
		t.Fatalf("the recheck ended %d streams, want 1", n)
	}
	if err := sa.RecvMsg(&hubv1.HubMessage{}); err == nil {
		t.Fatal("the revoked node's stream is still open")
	}
	waitFor(t, func() bool { return h.hub.Streams.Count(a.nodeID) == 0 })
	if h.hub.Streams.Count(b.nodeID) != 1 {
		t.Fatal("another node's stream was ended")
	}
	_ = sb
	// Kill is what the 500 ms config_log poll calls on a PairTable that empties an SPKI (G2).
	if h.hub.Streams.Kill(b.nodeID) != 1 {
		t.Fatal("Kill found no stream")
	}
}

func TestNodeConnectionsCap(t *testing.T) {
	h := newHarness(t)
	e := h.enrol()
	var conns []*tls.Conn
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()
	admitted := 0
	for i := 0; i < 9; i++ {
		c, err := tls.Dial("tcp", h.addr, h.tlsConfig(e.cert))
		if err != nil {
			continue
		}
		// TLS 1.3: the server's refusal shows on the first read.
		_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		if _, err := c.Read(make([]byte, 1)); err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				admitted++
				conns = append(conns, c)
				continue
			}
		}
		c.Close()
	}
	if admitted != 6 {
		t.Fatalf("%d connections of one node admitted, want 6", admitted)
	}
}

func TestHubAndNodeCertsDoNotPassAsClients(t *testing.T) {
	h := newHarness(t)
	// A server leaf of the node CA, offered as a client certificate, never completes a handshake.
	k := newKey(t)
	iss, err := h.hub.CA.IssueServer(&k.PublicKey, "ctrlz-nts", []string{"nts.example"}, nil, 24*time.Hour, h.clk.Now())
	if err != nil {
		t.Fatal(err)
	}
	cert := &tls.Certificate{Certificate: [][]byte{iss.DER}, PrivateKey: k}
	c, err := tls.Dial("tcp", h.addr, h.tlsConfig(cert))
	if err == nil {
		_ = c.SetReadDeadline(time.Now().Add(time.Second))
		_, err = c.Read(make([]byte, 1))
		c.Close()
	}
	if err == nil {
		t.Fatal("a serverAuth leaf was admitted as a client")
	}
	// A client certificate of another CA fails the same way.
	otherCA := newKey(t)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "other"}, NotBefore: h.clk.Now().Add(-time.Hour), NotAfter: h.clk.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	oder, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &otherCA.PublicKey, otherCA)
	otherCert, _ := x509.ParseCertificate(oder)
	nk := newKey(t)
	ctpl := &x509.Certificate{SerialNumber: big.NewInt(8), Subject: pkix.Name{CommonName: uuid.NewString()}, NotBefore: h.clk.Now().Add(-time.Minute), NotAfter: h.clk.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	cder, _ := x509.CreateCertificate(rand.Reader, ctpl, otherCert, &nk.PublicKey, otherCA)
	c2, err := tls.Dial("tcp", h.addr, h.tlsConfig(&tls.Certificate{Certificate: [][]byte{cder}, PrivateKey: nk}))
	if err == nil {
		_ = c2.SetReadDeadline(time.Now().Add(time.Second))
		_, err = c2.Read(make([]byte, 1))
		c2.Close()
	}
	if err == nil {
		t.Fatal("a certificate of another CA was admitted")
	}
}

// ---------------------------------------------------------------------------------------------------
// GET /install/*

func (h *harness) get(path string, token string) (int, []byte) {
	h.t.Helper()
	// One transport, so one connection: the listener admits 10 new connections a second from a source.
	if h.httpc == nil {
		tr := &http.Transport{TLSClientConfig: h.tlsConfig(nil), ForceAttemptHTTP2: true}
		h.t.Cleanup(tr.CloseIdleConnections)
		h.httpc = &http.Client{Transport: tr, Timeout: 10 * time.Second}
	}
	// The path is built as given and not resolved, so an encoded or literal dot-dot reaches the server
	// as written.
	dec, err := url.PathUnescape(path)
	if err != nil {
		h.t.Fatal(err)
	}
	req := &http.Request{Method: http.MethodGet, URL: &url.URL{Scheme: "https", Host: h.addr, Path: dec, RawPath: path}, Header: http.Header{}, Host: h.addr}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := h.httpc.Do(req)
	if err != nil {
		h.t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func TestInstallStaticFiles(t *testing.T) {
	h := newHarness(t)
	if code, b := h.get("/install/node_ca.pem", ""); code != 200 || string(b) != string(h.hub.CA.PEM()) {
		t.Fatalf("node_ca.pem: %d", code)
	}
	if code, b := h.get("/install/node.sh", ""); code != 200 || string(b) != string(bundleFiles["packaging/install/node.sh"]) {
		t.Fatalf("node.sh: %d %q", code, b)
	}
	if code, b := h.get("/install/ctrlz-verify", ""); code != 200 || string(b) != "verifier-bytes" {
		t.Fatalf("ctrlz-verify: %d", code)
	}
	rj, _ := os.ReadFile(filepath.Join(h.bundles, "root.json"))
	if code, b := h.get("/install/root.json", ""); code != 200 || string(b) != string(rj) {
		t.Fatalf("root.json: %d", code)
	}
	for _, p := range []string{"/install/", "/install/nothing", "/install/node.sh/x", "/other", "/"} {
		if code, _ := h.get(p, ""); code != 404 {
			t.Errorf("%s: %d, want 404", p, code)
		}
	}
	if code, _ := h.get("/install/bundle/1/debs/unbound_1_all.deb", ""); code != 403 {
		t.Errorf("a bundle file with no token: %d", code)
	}
}

func TestInstallBundleNeedsALiveToken(t *testing.T) {
	h := newHarness(t)
	e := h.newEnrolment(netip.Prefix{})
	want := bundleFiles["debs/unbound_1_all.deb"]
	if code, b := h.get("/install/bundle/1/debs/unbound_1_all.deb", e.token); code != 200 || string(b) != string(want) {
		t.Fatalf("with a live token: %d", code)
	}
	if code, b := h.get("/install/bundle/1/manifest.json", e.token); code != 200 || len(b) == 0 {
		t.Fatalf("manifest.json: %d", code)
	}
	// Not a token, and a token of nobody.
	if code, _ := h.get("/install/bundle/1/debs/unbound_1_all.deb", "short"); code != 403 {
		t.Errorf("a malformed token: %d", code)
	}
	other, _, _ := hubtoken.New(nil)
	if code, _ := h.get("/install/bundle/1/debs/unbound_1_all.deb", other); code != 403 {
		t.Errorf("an unknown token: %d", code)
	}
	// Traversal and unlisted names: 404 whatever they look like, and nothing outside the bundle is read.
	for _, p := range []string{
		"/install/bundle/1/..%2f..%2froot.json", "/install/bundle/1/../../root.json", "/install/bundle/1/%2e%2e/secret.txt",
		"/install/bundle/1//etc/passwd", "/install/bundle/1/debs/../bin/ctrlz-verify", "/install/bundle/1/debs/missing.deb",
		"/install/bundle/1/debs", "/install/bundle/1/", "/install/bundle/2/manifest.json", "/install/bundle/01/manifest.json",
		"/install/bundle/x/manifest.json", "/install/bundle/1/bin\\ctrlz-verify", "/install/bundle/1/C:/x",
	} {
		code, b := h.get(p, e.token)
		if code != 404 && code != 400 {
			t.Errorf("%s: %d %q", p, code, b)
		}
		if string(b) == "no" {
			t.Errorf("%s read outside the bundle", p)
		}
	}
	// Once Enroll has used the token it is spent, and so is the download.
	cc := h.dial(nil)
	if _, err := enrollv1.NewEnrollmentClient(cc).Enroll(ctx5(t), e.request()); err != nil {
		t.Fatal(err)
	}
	if code, _ := h.get("/install/bundle/1/debs/unbound_1_all.deb", e.token); code != 403 {
		t.Errorf("a spent token: %d", code)
	}
	// An expired one too.
	f := h.newEnrolment(netip.Prefix{})
	h.db.expireToken(f.hash)
	if code, _ := h.get("/install/bundle/1/debs/unbound_1_all.deb", f.token); code != 403 {
		t.Errorf("an expired token: %d", code)
	}
}

func TestInstallStaticLimitPerNetwork(t *testing.T) {
	h := newHarness(t)
	limited := 0
	for i := 0; i < 70; i++ {
		if code, _ := h.get("/install/node_ca.pem", ""); code == 429 {
			limited++
		}
	}
	if limited == 0 || limited > 12 {
		t.Fatalf("%d of 70 requests were limited, want a few past the 60-request burst", limited)
	}
}

// ---------------------------------------------------------------------------------------------------
// The hub's certificates.

func TestPinFileAndLeaf(t *testing.T) {
	h := newHarness(t)
	// The pin the install command carries is the SHA-256 of the leaf key's SPKI, and the connection's
	// leaf has that key.
	c, err := tls.Dial("tcp", h.addr, h.tlsConfig(nil))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	leaf := c.ConnectionState().PeerCertificates[0]
	pin, err := h.hub.Leaf.Pin()
	if err != nil {
		t.Fatal(err)
	}
	if string(pin) != string(sha256sum(leaf.RawSubjectPublicKeyInfo)) {
		t.Fatal("the leaf is not over the pinned key")
	}
	if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Fatalf("hub leaf EKU: %v", leaf.ExtKeyUsage)
	}
	// Renewal keeps the key: nothing is due yet, and after two thirds of the year it reissues over the same key.
	if renewed, err := h.hub.Leaf.Renew(); err != nil || renewed {
		t.Fatalf("an early renewal: %v %v", renewed, err)
	}
	h.clk.Advance(250 * 24 * time.Hour)
	if renewed, err := h.hub.Leaf.Renew(); err != nil || !renewed {
		t.Fatalf("renewal at a third left: %v %v", renewed, err)
	}
	pin2, _ := h.hub.Leaf.Pin()
	if string(pin2) != string(pin) {
		t.Fatal("a renewal moved the pin")
	}
}

func TestCARowsAndZoneReissue(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if rows := h.db.cas["node_ca"]; len(rows) != 1 || rows[0].row.ChainPEM != string(h.hub.CA.PEM()) {
		t.Fatalf("node_ca row: %v", rows)
	}
	z := h.db.cas["zone_ca"]
	if len(z) != 1 || len(h.db.jobs) != 0 || h.db.alerts != 0 {
		t.Fatalf("first start: %d rows, %d jobs, %d alerts (a first CA is no change)", len(z), len(h.db.jobs), h.db.alerts)
	}
	if got := z[0].row.Names; len(got) != 1 || got[0] != "dns.ctrlz.invalid" {
		t.Fatalf("placeholder zone: %v", got)
	}
	// Nothing changed: reused, bytes and all.
	if err := h.hub.CAs.EnsureZone(ctx); err != nil || len(h.db.cas["zone_ca"]) != 1 {
		t.Fatalf("an unchanged state replaced the row: %v", err)
	}
	// The domain is set: a new CA over the same key, the old row retired, an alert and a job with the
	// same-key notice.
	h.db.zones.DNSZone = "dns.example.ir"
	if err := h.hub.CAs.EnsureZone(ctx); err != nil {
		t.Fatal(err)
	}
	if rows := h.db.cas["zone_ca"]; len(rows) != 2 || !rows[0].retired || rows[1].retired || len(h.db.jobs) != 1 || h.db.jobs[0] != "same_key" || h.db.alerts != 1 {
		t.Fatalf("after the domain change: %d rows, jobs %v, alerts %d", len(h.db.cas["zone_ca"]), h.db.jobs, h.db.alerts)
	}
	if got := h.hub.CAs.Zone().Zones(); len(got) != 1 || got[0] != "dns.example.ir" {
		t.Fatalf("the CA in force: %v", got)
	}
	leaf, err := h.hub.CAs.Zone().IssueLeaf("dns.example.ir", h.clk.Now())
	if err != nil || len(leaf.Names) != 3 {
		t.Fatalf("a leaf for the new zone: %v", err)
	}
	// A transition holds two zones.
	h.db.zones.PrevDNSZone = "dns.old.ir"
	h.db.zones.TransitionUntil = h.clk.Now().Add(48 * time.Hour)
	if err := h.hub.CAs.EnsureZone(ctx); err != nil {
		t.Fatal(err)
	}
	if got := h.hub.CAs.Zone().Zones(); len(got) != 2 {
		t.Fatalf("zones during a transition: %v", got)
	}
}

func sha256sum(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

// RenewCert is paced per node and refuses a certificate that is not yet due, so a node with a stolen
// or leaked key cannot add a node_certs row and a signature 20 times a second (W3-r1-10).
func TestRenewCertIsPaced(t *testing.T) {
	h := newHarness(t)
	e := h.enrol()
	h.clk.Advance(25 * 24 * time.Hour) // 5 of 30 days left
	cc := h.dial(e.cert)               // one connection: the listener admits 10 new ones a second
	renew := func() error {
		csr, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "x"}}, e.key)
		_, err := hubv1.NewNodeHubClient(cc).RenewCert(ctx5(t), &hubv1.RenewCertRequest{CsrDer: csr})
		return err
	}
	granted := 0
	for i := 0; i < 20; i++ {
		err := renew()
		if err == nil {
			granted++
			continue
		}
		if code(err) != codes.ResourceExhausted {
			t.Fatalf("renewal %d: %v", i, err)
		}
		break
	}
	if granted != 6 {
		t.Fatalf("%d renewals granted in a burst, want 6", granted)
	}
	// An hour later the steady rate has given a few back.
	h.clk.Advance(time.Hour)
	if err := renew(); err != nil {
		t.Fatalf("a renewal an hour later: %v", err)
	}
}

// A handler that sits in Recv ends when its node is revoked, however quiet the node is (G2, W3-r1-1):
// cancelling a derived context alone would leave it there until the node closed the stream itself.
func TestRevokedNodeEndsAStreamBlockedInRecv(t *testing.T) {
	h := newHarness(t)
	e := h.enrol()
	other := h.enrol()
	open := func(n *enrolled) grpc.ClientStream {
		st, err := h.dial(n.cert).NewStream(context.Background(), &grpc.StreamDesc{ServerStreams: true, ClientStreams: true}, "/ctrlz.hub.v1.NodeHub/UploadLogs")
		if err != nil {
			t.Fatal(err)
		}
		if err := st.SendMsg(&telv1.LogBatch{}); err != nil {
			t.Fatal(err)
		}
		select {
		case <-h.stub.logsOpen:
		case <-time.After(5 * time.Second):
			t.Fatal("the handler did not start")
		}
		return st
	}
	st := open(e)
	sto := open(other)
	_ = sto
	// The node says nothing more, and the hub's handler waits in Recv.
	h.db.setStatus(e.nodeID, "revoked")
	if n := h.hub.Recheck(context.Background()); n != 1 {
		t.Fatalf("the recheck ended %d streams, want 1", n)
	}
	select {
	case <-h.stub.logsEnded:
	case <-time.After(5 * time.Second):
		t.Fatal("the handler of a revoked node is still blocked in Recv")
	}
	if err := st.RecvMsg(&telv1.Ack{}); err == nil {
		t.Fatal("the client still sees an open stream")
	}
	// The other node's handler is still running: its stream is registered and its handler has not returned.
	if h.hub.Streams.Count(other.nodeID) != 1 || len(h.stub.logsEnded) != 0 {
		t.Fatalf("another node's stream was ended: %d registered, %d ended", h.hub.Streams.Count(other.nodeID), len(h.stub.logsEnded))
	}
}

// The zone CA follows a domain change on the next minute pass, not the next daily one (W3-r2-3): a zone
// the CA does not list cannot be given a certificate.
func TestZoneCAFollowsTheDomainAtOnce(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.db.zones.DNSZone = "dns.example.ir"
	h.hub.TrustPass(ctx)
	if got := h.hub.CAs.Zone().Zones(); len(got) != 1 || got[0] != "dns.example.ir" {
		t.Fatalf("the CA after one pass: %v", got)
	}
	if _, err := h.hub.CAs.Zone().IssueLeaf("dns.example.ir", h.clk.Now()); err != nil {
		t.Fatalf("a leaf for the new zone: %v", err)
	}
}

// A live zone that fails the hub's own rule is left out and the hub still starts (W3-r2-3): a row that
// the database CHECK accepts must not stop the node port.
func TestInvalidLiveZoneDoesNotStopTheHub(t *testing.T) {
	h := newHarnessWith(t, func(db *fakeDB) {
		db.zones = store.HubZones{DNSZone: "dns.example.ir", PrevDNSZone: "dns.co.ir", TransitionUntil: time.Now().Add(48 * time.Hour)}
	})
	if got := h.hub.CAs.Zone().Zones(); len(got) != 1 || got[0] != "dns.example.ir" {
		t.Fatalf("the zone CA kept an invalid zone or lost the valid one: %v", got)
	}
	if len(h.db.kinds) != 1 || h.db.kinds[0] != store.HubAlertZoneInvalid {
		t.Fatalf("alerts: %v", h.db.kinds)
	}
	// The next passes say nothing more while the state is the same.
	h.hub.TrustPass(context.Background())
	if len(h.db.kinds) != 1 {
		t.Fatalf("a repeated alert: %v", h.db.kinds)
	}
	// Only invalid zones: the placeholder stands.
	h.db.zones = store.HubZones{DNSZone: "dns.com"}
	h.hub.TrustPass(context.Background())
	if got := h.hub.CAs.Zone().Zones(); len(got) != 1 || got[0] != "dns.ctrlz.invalid" {
		t.Fatalf("no valid zone: %v", got)
	}
}

// A reissue whose alert cannot be inserted is not lost (W3-r2-10): the CA is replaced, and the alert is
// raised at the next pass.
func TestZoneCAReissueAlertIsNotLost(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.db.alertErr = context.DeadlineExceeded
	h.db.zones.DNSZone = "dns.example.ir"
	if err := h.hub.CAs.EnsureZone(ctx); err != nil {
		t.Fatal(err)
	}
	if len(h.db.cas["zone_ca"]) != 2 || h.db.alerts != 0 {
		t.Fatalf("rows %d, alerts %d", len(h.db.cas["zone_ca"]), h.db.alerts)
	}
	h.db.alertErr = nil
	h.hub.TrustPass(ctx)
	if h.db.alerts != 1 || h.db.kinds[0] != store.HubAlertZoneCAReissued {
		t.Fatalf("the alert after the database came back: %d %v", h.db.alerts, h.db.kinds)
	}
	h.hub.TrustPass(ctx)
	if h.db.alerts != 1 {
		t.Fatalf("the alert was raised twice: %d", h.db.alerts)
	}
}

// A zone CA row that cannot be written finds the same replacement due at every pass, and the alert is
// raised once for it, not once a minute (W3-r4-2); the row written clears the memory, so a later change
// raises its own.
func TestZoneCAReissueAlertIsNotRepeatedWhileTheRowWriteFails(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.db.replaceErr = context.DeadlineExceeded
	h.db.zones.DNSZone = "dns.example.ir"
	for i := 0; i < 5; i++ {
		if err := h.hub.CAs.EnsureZone(ctx); err == nil {
			t.Fatal("a failed row write was not reported")
		}
	}
	if h.db.alerts != 1 {
		t.Fatalf("%d alerts for one pending replacement", h.db.alerts)
	}
	h.db.replaceErr = nil
	if err := h.hub.CAs.EnsureZone(ctx); err != nil || h.db.alerts != 1 {
		t.Fatalf("the pass that wrote the row: %v, %d alerts", err, h.db.alerts)
	}
	h.db.zones.DNSZone = "dns.other.ir"
	if err := h.hub.CAs.EnsureZone(ctx); err != nil || h.db.alerts != 2 {
		t.Fatalf("a later change: %v, %d alerts", err, h.db.alerts)
	}
}

// A node CA row that is replaced raises an alert (W3-r4-3): every node certificate stops chaining to the
// new CA, and nothing else would tell the admin why. The first start, and a restart with the same CA,
// raise none.
func TestNodeCARowReplacementRaisesAnAlert(t *testing.T) {
	h := newHarness(t)
	if h.db.alerts != 0 {
		t.Fatalf("a first start raised %d alerts", h.db.alerts)
	}
	if err := h.hub.CAs.EnsureNodeRow(context.Background()); err != nil || h.db.alerts != 0 {
		t.Fatalf("the same CA again: %v, %d alerts", err, h.db.alerts)
	}
	h2 := newHarnessWith(t, func(db *fakeDB) {
		db.cas["node_ca"] = []*fCA{{row: store.HubCertRow{ID: uuid.New(), ChainPEM: "an older CA"}}}
	})
	if len(h2.db.kinds) != 1 || h2.db.kinds[0] != store.HubAlertNodeCAChanged {
		t.Fatalf("alerts after a replaced node CA: %v", h2.db.kinds)
	}
	if rows := h2.db.cas["node_ca"]; len(rows) != 2 || !rows[0].retired || rows[1].retired {
		t.Fatalf("node_ca rows: %d", len(rows))
	}
}

// The node CA alert follows the row write (W3-r5-3): a write that fails at every start raises nothing, and
// the start that writes raises one.
func TestNodeCAReplacementAlertWaitsForTheRowWrite(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.db.cas["node_ca"] = []*fCA{{row: store.HubCertRow{ID: uuid.New(), ChainPEM: "an older CA"}}}
	h.db.replaceErr = context.DeadlineExceeded
	for i := 0; i < 3; i++ {
		if err := h.hub.CAs.EnsureNodeRow(ctx); err == nil {
			t.Fatal("a failed row write was not reported")
		}
	}
	if h.db.alerts != 0 {
		t.Fatalf("%d alerts raised for a row that was never written", h.db.alerts)
	}
	h.db.replaceErr = nil
	if err := h.hub.CAs.EnsureNodeRow(ctx); err != nil || h.db.alerts != 1 || h.db.kinds[0] != store.HubAlertNodeCAChanged {
		t.Fatalf("the start that wrote the row: %v, %d alerts %v", err, h.db.alerts, h.db.kinds)
	}
}

// A live upload body is held to an unread budget (W3-r2-6) that the handler's own reads give back: a long
// run of messages of every size, from empty to a megabyte, goes through without the stream stalling, so
// the accounting of what was taken out of the queue matches what the transport read.
func TestUploadStreamOfManyMessagesIsNotStalledByTheUnreadBudget(t *testing.T) {
	h := newHarness(t)
	e := h.enrol()
	st, err := h.dial(e.cert).NewStream(context.Background(), &grpc.StreamDesc{ServerStreams: true, ClientStreams: true}, "/ctrlz.hub.v1.NodeHub/UploadLogs")
	if err != nil {
		t.Fatal(err)
	}
	const messages = 400
	for i := 0; i < messages; i++ {
		m := &telv1.LogBatch{BatchId: uint64(i)}
		switch i % 4 {
		case 1:
			m.Sealed = make([]byte, 100)
		case 2:
			m.Sealed = make([]byte, 20_000)
		case 3:
			if i%200 == 3 {
				m.Sealed = make([]byte, 1<<20)
			}
		}
		if err := st.SendMsg(m); err != nil {
			t.Fatalf("message %d: %v", i, err)
		}
	}
	testwait.Until(t, 20*time.Second, "every message to reach the handler", func() bool { return h.stub.logsRecv.Load() == messages })
}

// T-087 (7.10): with CTRLZ_HUB_NTS_DIR the hub writes the NTS leaf at start and raises the alert that asks for chrony's restart,
// leaves the files alone on the passes that follow, and writes again, with the alert, when a third of the five years is left.
func TestHubWritesTheNTSLeafAtStartAndWhenAThirdIsLeft(t *testing.T) {
	dir := t.TempDir()
	h := newHarnessMod(t, nil, func(d *hub.Deps) { d.NTSDir = dir })
	nts := func() int {
		n := 0
		for _, k := range h.db.kinds {
			if k == store.HubAlertNTSLeafWritten {
				n++
			}
		}
		return n
	}
	first, err := os.ReadFile(filepath.Join(dir, "nts.crt"))
	if err != nil || nts() != 1 {
		t.Fatalf("at start: certificate read error %v, %d alerts", err, nts())
	}
	if _, err := os.Stat(filepath.Join(dir, "nts.key")); err != nil {
		t.Fatal("no key beside the certificate")
	}
	h.hub.TrustPass(context.Background())
	if again, _ := os.ReadFile(filepath.Join(dir, "nts.crt")); !bytes.Equal(first, again) || nts() != 1 {
		t.Fatal("a pass that had nothing to do wrote the leaf or raised an alert")
	}
	h.clk.Advance(4 * 365 * 24 * time.Hour)
	h.hub.TrustPass(context.Background())
	if renewed, _ := os.ReadFile(filepath.Join(dir, "nts.crt")); bytes.Equal(first, renewed) || nts() != 2 {
		t.Fatalf("a third of the life left: leaf unchanged or %d alerts", nts())
	}
}
