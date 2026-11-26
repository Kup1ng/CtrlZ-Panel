package hubnet

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/netip"
	"sync"

	"bytes"
	"fmt"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type fixedClock struct{ t time.Time }

func (c *fixedClock) Now() time.Time { return c.t }

func grpcPost(h http.Handler, path, remote string, body []byte) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/grpc")
	r.RemoteAddr = remote
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func newRoot(clk *fixedClock, enroll, node http.Handler) *Root {
	return &Root{Now: clk.Now, Enrollment: enroll, NodeHub: node, Install: http.NotFoundHandler(), Limits: NewRootLimits(clk.Now)}
}

// A NodeHub path on a connection that did not admit a node certificate is 403 before gRPC sees it.
func TestRootRefusesNodeHubWithoutAnAdmittedNode(t *testing.T) {
	reached := false
	h := newRoot(&fixedClock{time.Now()}, http.NotFoundHandler(), http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))
	w := grpcPost(h, "/ctrlz.hub.v1.NodeHub/Control", "203.0.113.9:4000", nil)
	if w.Code != http.StatusForbidden || reached {
		t.Fatalf("status %d, reached %v", w.Code, reached)
	}
}

// Anything that is neither gRPC nor an install path is a 404, and so is an unknown service.
func TestRootRoutes(t *testing.T) {
	h := newRoot(&fixedClock{time.Now()}, http.NotFoundHandler(), http.NotFoundHandler())
	for _, p := range []string{"/", "/healthz", "/readyz", "/metrics", "/install", "/admin"} {
		r := httptest.NewRequest(http.MethodGet, p, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusNotFound {
			t.Errorf("%s: %d", p, w.Code)
		}
	}
	if w := grpcPost(h, "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo", "203.0.113.9:1", nil); w.Code != http.StatusNotFound {
		t.Errorf("an unknown gRPC service: %d", w.Code)
	}
}

// Enrollment is limited per source network before anything reads the call (5.7): 30 a minute for a /24, and a
// refused call is a gRPC RESOURCE_EXHAUSTED (8) that the node reads as "not read the token".
func TestRootEnrollmentRateAndBody(t *testing.T) {
	clk := &fixedClock{time.Now()}
	var read int
	enroll := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		read = int(n)
	})
	h := newRoot(clk, enroll, http.NotFoundHandler())
	refused := 0
	for i := 0; i < 40; i++ {
		// 40 calls from different hosts of one /24.
		w := grpcPost(h, "/ctrlz.enroll.v1.Enrollment/Poll", fmt.Sprintf("203.0.113.%d:4000", i+1), nil)
		if grpcStatus(w) == "8" {
			refused++
		}
	}
	if refused != 10 {
		t.Fatalf("%d of 40 calls refused, want 10 past the 30 a minute", refused)
	}
	// Another network is not held back by it.
	if w := grpcPost(h, "/ctrlz.enroll.v1.Enrollment/Poll", "198.51.100.7:4000", nil); grpcStatus(w) == "8" {
		t.Fatal("another /24 was limited")
	}
	// The body is read here through a cap of 8 KiB: one over it is refused before the handler is reached,
	// and one inside it reaches the handler whole.
	read = -1
	w := grpcPost(h, "/ctrlz.enroll.v1.Enrollment/Poll", "192.0.2.1:4000", bytes.Repeat([]byte{1}, 64<<10))
	if grpcStatus(w) != "3" || read != -1 {
		t.Fatalf("a 64 KiB body: read %d bytes (status %q)", read, grpcStatus(w))
	}
	w = grpcPost(h, "/ctrlz.enroll.v1.Enrollment/Poll", "192.0.2.2:4000", bytes.Repeat([]byte{1}, EnrollBodyBytes))
	if grpcStatus(w) != "" || read != EnrollBodyBytes {
		t.Fatalf("a body at the cap: read %d bytes (status %q)", read, grpcStatus(w))
	}
}

func TestRootEnrollmentInProgressCap(t *testing.T) {
	clk := &fixedClock{time.Now()}
	block, release := make(chan struct{}), make(chan struct{})
	enroll := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		release <- struct{}{}
		<-block
	})
	h := newRoot(clk, enroll, http.NotFoundHandler())
	done := make(chan struct{}, EnrollInProgress)
	for i := 0; i < EnrollInProgress; i++ {
		go func(i int) {
			grpcPost(h, "/ctrlz.enroll.v1.Enrollment/Poll", fmt.Sprintf("10.%d.0.1:4000", i), nil)
			done <- struct{}{}
		}(i)
		<-release
	}
	// Four are in progress: the fifth, from yet another network, is refused without waiting.
	if w := grpcPost(h, "/ctrlz.enroll.v1.Enrollment/Poll", "172.16.0.1:4000", nil); grpcStatus(w) != "8" {
		t.Fatalf("a fifth call in progress was served: %q", grpcStatus(w))
	}
	close(block)
	for i := 0; i < EnrollInProgress; i++ {
		<-done
	}
}

// nodeReq is a gRPC request on a connection the listener admitted as node: the identity the root handler
// reads, without a TLS handshake.
func nodeReq(path string, node uuid.UUID, body io.Reader) *http.Request {
	r := httptest.NewRequest(http.MethodPost, path, body)
	r.Header.Set("Content-Type", "application/grpc")
	rc := &rawConn{src: netip.MustParseAddr("203.0.113.5"), node: node}
	r = r.WithContext(context.WithValue(r.Context(), connKey{}, rc))
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{NotAfter: time.Now().Add(24 * time.Hour)}}}
	return r
}

type failReader struct{ t *testing.T }

func (f failReader) Read([]byte) (int, error) {
	f.t.Error("the body of a refused node was read")
	return 0, io.EOF
}

// A revoked node's certificate chains to the node CA, so the row check has to run before gRPC decodes a
// byte of the body (W3-r1-5): a refused RPC never reads it.
func TestRootChecksTheNodeBeforeTheBody(t *testing.T) {
	reached := false
	h := newRoot(&fixedClock{time.Now()}, http.NotFoundHandler(), http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))
	h.NodeCheck = func(context.Context, string) (Identity, error) {
		return Identity{}, status.Error(codes.Unauthenticated, "certificate not accepted")
	}
	for _, m := range []string{"RenewCert", "GetHead", "Control", "UploadLogs"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, nodeReq("/ctrlz.hub.v1.NodeHub/"+m, uuid.New(), failReader{t}))
		if grpcStatus(w) != "16" || reached {
			t.Fatalf("%s: status %q, handler reached %v", m, grpcStatus(w), reached)
		}
	}
}

// A unary NodeHub body is capped and read whole; the handler sees the identity the root already checked.
func TestRootUnaryBodyCap(t *testing.T) {
	var read int
	var checked bool
	h := newRoot(&fixedClock{time.Now()}, http.NotFoundHandler(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		read, checked = int(n), IdentityFrom(r.Context()).Checked
	}))
	h.NodeCheck = func(ctx context.Context, _ string) (Identity, error) { return IdentityFrom(ctx), nil }
	node := uuid.New()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, nodeReq("/ctrlz.hub.v1.NodeHub/RenewCert", node, bytes.NewReader(make([]byte, UnaryBodyBytes+1))))
	if grpcStatus(w) != "3" || read != 0 {
		t.Fatalf("an oversized unary body: status %q, read %d", grpcStatus(w), read)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, nodeReq("/ctrlz.hub.v1.NodeHub/RenewCert", node, bytes.NewReader(make([]byte, 4096))))
	if read != 4096 || !checked {
		t.Fatalf("a small unary body: read %d, checked %v", read, checked)
	}
}

// One node holds at most MaxOpenRPCs calls open at once, and another node is not touched by it.
func TestRootOpenRPCsPerNode(t *testing.T) {
	block, started := make(chan struct{}), make(chan struct{}, MaxOpenRPCs)
	h := newRoot(&fixedClock{time.Now()}, http.NotFoundHandler(), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		started <- struct{}{}
		<-block
	}))
	a, b := uuid.New(), uuid.New()
	var wg sync.WaitGroup
	for i := 0; i < MaxOpenRPCs; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h.ServeHTTP(httptest.NewRecorder(), nodeReq("/ctrlz.hub.v1.NodeHub/Control", a, nil))
		}()
		<-started
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, nodeReq("/ctrlz.hub.v1.NodeHub/Control", a, nil))
	if grpcStatus(w) != "8" {
		t.Fatalf("a call past the cap: status %q", grpcStatus(w))
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		h.ServeHTTP(httptest.NewRecorder(), nodeReq("/ctrlz.hub.v1.NodeHub/Control", b, nil))
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("another node was held back by the first one's calls")
	}
	close(block)
	wg.Wait()
}

// The slot of enrolments in progress is given back when the handler starts to answer, so a client that
// never reads the answer holds no slot (W3-r1-4): more than EnrollInProgress answers can be stuck at once
// and a new call is still served.
func TestRootEnrollmentSlotEndsWithTheWork(t *testing.T) {
	block, started := make(chan struct{}), make(chan struct{}, 2*EnrollInProgress)
	enroll := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK) // the first byte of the answer: the work is done
		started <- struct{}{}
		<-block
	})
	h := newRoot(&fixedClock{time.Now()}, enroll, http.NotFoundHandler())
	var wg sync.WaitGroup
	for i := 0; i < 2*EnrollInProgress; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			grpcPost(h, "/ctrlz.enroll.v1.Enrollment/Poll", fmt.Sprintf("10.%d.0.1:4000", i), nil)
		}(i)
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			t.Fatalf("call %d was refused while earlier answers were stuck", i)
		}
	}
	if h.Limits.EnrollSlots.InUse() != 0 {
		t.Fatalf("%d slots held by stuck answers", h.Limits.EnrollSlots.InUse())
	}
	close(block)
	wg.Wait()
}

// grpcStatus is the status a refusal carries. It is a trailer (see grpcRefuse), so it is read from the
// result and not from the header map.
func grpcStatus(w *httptest.ResponseRecorder) string {
	return w.Result().Trailer.Get("Grpc-Status")
}
