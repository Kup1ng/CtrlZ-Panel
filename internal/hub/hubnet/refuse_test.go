package hubnet

import (
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	enrollv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/enroll/v1"
)

// A refusal of the Enrollment door reaches a real gRPC client as the status the hub meant, over HTTP/2
// with the flush that bound() does before the handler returns (W3-r5-4). The recorder tests of the root
// cannot see the difference: a headers-only answer looks right in a header map and is read as INTERNAL on
// the wire.
func TestEnrollmentRefusalsReachARealGRPCClientWithTheirStatus(t *testing.T) {
	clk := &fixedClock{time.Now()}
	root := newRoot(clk, grpc.NewServer(), http.NotFoundHandler())
	ts := httptest.NewUnstartedServer(root)
	ts.EnableHTTP2 = true
	ts.Config.ConnContext = func(ctx context.Context, _ net.Conn) context.Context {
		return context.WithValue(ctx, connKey{}, &rawConn{src: netip.MustParseAddr("127.0.0.1")})
	}
	ts.StartTLS()
	t.Cleanup(ts.Close)

	pool := ts.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	cc, err := grpc.NewClient("passthrough:///"+ts.Listener.Addr().String(),
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{RootCAs: pool, ServerName: "example.com", MinVersion: tls.VersionTLS13})))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cc.Close() })
	cl := enrollv1.NewEnrollmentClient(cc)
	call := func(req *enrollv1.PollRequest) codes.Code {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, err := cl.Poll(ctx, req)
		return status.Code(err)
	}

	// A body over the cap: INVALID_ARGUMENT.
	if c := call(&enrollv1.PollRequest{ProofSig: bytes.Repeat([]byte{1}, EnrollBodyBytes+4096)}); c != codes.InvalidArgument {
		t.Fatalf("an oversized body reached the client as %v, want InvalidArgument", c)
	}
	// Every slot of calls in progress taken: RESOURCE_EXHAUSTED (busy).
	var rels []func()
	for i := 0; i < EnrollInProgress; i++ {
		rel, ok := root.Limits.EnrollSlots.Try()
		if !ok {
			t.Fatal("could not take a slot")
		}
		rels = append(rels, rel)
	}
	if c := call(&enrollv1.PollRequest{}); c != codes.ResourceExhausted {
		t.Fatalf("a busy hub reached the client as %v, want ResourceExhausted", c)
	}
	for _, rel := range rels {
		rel()
	}
	// The per-network rate: the calls up to 30 a minute are served (the empty gRPC server has no such
	// method), the next is RESOURCE_EXHAUSTED.
	last := codes.OK
	for i := 0; i < EnrollPerMinute+5; i++ {
		last = call(&enrollv1.PollRequest{})
	}
	if last != codes.ResourceExhausted {
		t.Fatalf("a call past the rate reached the client as %v, want ResourceExhausted", last)
	}
}
