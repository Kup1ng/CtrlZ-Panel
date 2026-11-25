package hubnodes

import (
	"context"
	"crypto/x509"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubnet"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

func cancelled(c <-chan struct{}) bool {
	select {
	case <-c:
		return true
	default:
		return false
	}
}

// A Kill between a stream's row check and its registration is not missed (W3-r2-2, W3-r2-8): the stream
// carries the mark it took before it read the row, and Add ends it at once when the node was killed since.
func TestKillBetweenCheckAndRegistrationEndsTheStream(t *testing.T) {
	reg := NewRegistry()
	node := uuid.New()
	gen := reg.Gen() // the row check began here and read an active row
	if n := reg.Kill(node); n != 0 {
		t.Fatalf("Kill found %d streams before any was registered", n)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	remove := reg.Add(node, "m", nil, "s", time.Time{}, gen, cancel)
	defer remove()
	if !cancelled(ctx.Done()) {
		t.Fatal("a stream whose node was killed after its check was left running")
	}

	// A stream whose check began after the Kill read the revoked row, so it is not touched; and another
	// node is never touched.
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	defer reg.Add(node, "m", nil, "s", time.Time{}, reg.Gen(), cancel2)()
	ctx3, cancel3 := context.WithCancel(context.Background())
	defer cancel3()
	defer reg.Add(uuid.New(), "m", nil, "s", time.Time{}, gen, cancel3)()
	if cancelled(ctx2.Done()) || cancelled(ctx3.Done()) {
		t.Fatal("a stream was ended without a Kill after its mark")
	}
}

type fakeStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s fakeStream) Context() context.Context { return s.ctx }

type openReader struct{}

func (openReader) HubNodeLoad(context.Context, uuid.UUID) (store.HubNode, bool, error) {
	return store.HubNode{}, false, errors.New("the interceptor must not read the row when the root did")
}

// The interceptor takes the mark the root's check left in the identity, not a new one.
func TestStreamInterceptorUsesTheMarkOfTheRootsCheck(t *testing.T) {
	reg := NewRegistry()
	c := &Checker{Open: openReader{}, Reg: reg}
	node := uuid.New()
	cert := &x509.Certificate{RawSubjectPublicKeyInfo: []byte{2}, SerialNumber: big.NewInt(7), NotAfter: time.Now().Add(time.Hour)}
	id := hubnet.Identity{Node: true, NodeID: node, Cert: cert, Checked: true, KillGen: reg.Gen()}
	reg.Kill(node) // after the root's check, before the interceptor registers
	ctx := hubnet.WithIdentity(context.Background(), id)
	ran := false
	err := c.Stream(reg)(nil, fakeStream{ctx: ctx}, &grpc.StreamServerInfo{FullMethod: "/x/Control"}, func(any, grpc.ServerStream) error {
		ran = true
		return nil
	})
	if err == nil || ran {
		t.Fatalf("a stream killed between the root's check and its registration ran: err %v, ran %v", err, ran)
	}
}

type activeReader struct{ err error }

func (r activeReader) HubNodeLoad(context.Context, uuid.UUID) (store.HubNode, bool, error) {
	return store.HubNode{}, false, r.err
}

// A stream does not outlive the certificate that opened it (W3-r2-9), and the pass that ends it needs no
// database: a stream past not_after is ended while the database is down.
func TestRecheckEndsAStreamPastItsCertificate(t *testing.T) {
	reg := NewRegistry()
	node := uuid.New()
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	ctxA, cancelA := context.WithCancel(context.Background())
	defer cancelA()
	ctxB, cancelB := context.WithCancel(context.Background())
	defer cancelB()
	defer reg.Add(node, "m", nil, "a", now.Add(time.Hour), reg.Gen(), cancelA)()
	defer reg.Add(node, "m", nil, "b", now.Add(-time.Second), reg.Gen(), cancelB)()
	rc := &Rechecker{Reg: reg, Nodes: activeReader{err: errors.New("down")}, Now: func() time.Time { return now }}
	if n := rc.Pass(context.Background()); n != 1 {
		t.Fatalf("the pass ended %d streams, want the one past not_after", n)
	}
	if !cancelled(ctxB.Done()) || cancelled(ctxA.Done()) {
		t.Fatalf("expired ended: %v, current ended: %v", cancelled(ctxB.Done()), cancelled(ctxA.Done()))
	}
}

// The 60-day renewal window is judged at every open and not only at the handshake: a connection kept up
// past it cannot call RenewCert (W3-r5-1, W3-r5-5). The reader errors, so reaching it shows the window
// let the call through, and being denied before it shows the window shut.
func TestRenewCertIsRefusedPastTheWindowOnAnOpenConnection(t *testing.T) {
	notAfter := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	cert := &x509.Certificate{RawSubjectPublicKeyInfo: []byte{2}, SerialNumber: big.NewInt(7), NotBefore: notAfter.Add(-30 * 24 * time.Hour), NotAfter: notAfter}
	ctx := hubnet.WithIdentity(context.Background(), hubnet.Identity{Node: true, NodeID: uuid.New(), Cert: cert})
	now := notAfter.Add(59 * 24 * time.Hour)
	c := &Checker{Open: openReader{}, Now: func() time.Time { return now }}

	// Day 59 past not_after, the id as the handshake saw it: RenewCert gets as far as the row.
	if _, err := c.CheckOpen(ctx, RenewMethod); status.Code(err) != codes.Unavailable {
		t.Fatalf("inside the window RenewCert should reach the row read, got %v", err)
	}
	// Any other method is refused for an expired certificate.
	if _, err := c.CheckOpen(ctx, "/ctrlz.hub.v1.NodeHub/Control"); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("an expired certificate called another method: %v", err)
	}
	// The same connection on day 80: the identity still says what it said at the handshake.
	now = notAfter.Add(80 * 24 * time.Hour)
	if _, err := c.CheckOpen(ctx, RenewMethod); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("RenewCert past the window on an open connection was not refused: %v", err)
	}
}

// A panic in a handler costs the call and not the hub (W3-r5-6): the caller gets INTERNAL.
func TestRecoverInterceptorsTurnAPanicIntoInternal(t *testing.T) {
	_, err := RecoverUnary(nil)(context.Background(), nil, &grpc.UnaryServerInfo{}, func(context.Context, any) (any, error) {
		panic("test")
	})
	if status.Code(err) != codes.Internal {
		t.Fatalf("a unary panic gave %v", err)
	}
	err = RecoverStream(nil)(nil, nil, &grpc.StreamServerInfo{}, func(any, grpc.ServerStream) error { panic("test") })
	if status.Code(err) != codes.Internal {
		t.Fatalf("a stream panic gave %v", err)
	}
	resp, err := RecoverUnary(nil)(context.Background(), nil, &grpc.UnaryServerInfo{}, func(context.Context, any) (any, error) { return 5, nil })
	if err != nil || resp != 5 {
		t.Fatalf("a call that did not panic: %v, %v", resp, err)
	}
}
