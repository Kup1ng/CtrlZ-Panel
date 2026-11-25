// Package hubnodes is what the hub does once a node has a certificate (p4-nodes 4.3, 4.4): the check of
// that certificate against the node's row at the open of every RPC, the registry of open streams that is
// checked again every 60 seconds and cut at once on a revocation, and RenewCert.
//
// What is left as a seam. The Control stream and the transfer, telemetry and head RPCs (5.2 to 5.6) are
// not here: Service delegates every method but RenewCert to the NodeHubServer it was given, which
// is Unimplemented until the next package puts its handlers there. Everything those handlers need
// from this package is already in force when they run: the identity is checked, the stream is
// registered, and Registry.Kill is the call the 500 ms config_log poll makes (G2).
package hubnodes

import (
	"bytes"
	"context"
	"crypto/x509"
	"log/slog"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubnet"
	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubpki"
	"github.com/Kup1ng/CtrlZ-Panel/internal/safego"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

type unit string

const (
	unitRecheck  unit = "hub_recheck"
	unitClear    unit = "hub_clear_prev"
	unitStreamIO unit = "hub_stream_io"
)

func (u unit) Valid() bool { return u == unitRecheck || u == unitClear || u == unitStreamIO }

// OpenTimeout is the time bound of the check at open (SC 8a.11 L3): a check that cannot complete in it
// is refused with UNAVAILABLE, and the node retries as after any error.
const OpenTimeout = 2 * time.Second

// RenewMethod is the one method a certificate past not_after may call (4.3).
const RenewMethod = "/ctrlz.hub.v1.NodeHub/RenewCert"

// NodeReader reads a node row. The hub gives the check at open the L3 pool's store and the later
// checks the control pool's, so one type serves both without either one's queries landing on the
// other's connections (5.7, N12).
type NodeReader interface {
	HubNodeLoad(ctx context.Context, id uuid.UUID) (store.HubNode, bool, error)
}

// PrevClearer drops prev_cert_serial (control pool, best effort).
type PrevClearer interface {
	HubClearPrevSerial(ctx context.Context, node uuid.UUID, current string) error
}

// Checker judges a node's certificate against its row.
type Checker struct {
	Open  NodeReader  // the L3 pool
	Clear PrevClearer // the control pool
	Log   *slog.Logger
	// Seen, if set, is told the node and the source address of every connection that passed the check: the
	// set of node addresses that may use the reserved handshake slots follows the nodes that really
	// connect, one last address per node (5.1).
	Seen func(uuid.UUID, netip.Addr)
	// Reg, if set, is the registry the stream interceptor registers in. The check at open takes its
	// kill mark before it reads the row, so a stream registered after a Kill that the row did not yet
	// show is ended on arrival (G2, W3-r2-2).
	Reg *Registry
}

func errDenied() error { return status.Error(codes.Unauthenticated, "certificate not accepted") }
func errDown() error   { return status.Error(codes.Unavailable, "try again") }

// valid says whether a node row accepts the certificate: active, the certificate's key is the row's,
// and its serial is the current or the previous one (4.3, 4.4).
func valid(n store.HubNode, found bool, cert *x509.Certificate) bool {
	if !found || n.Status != "active" || !bytes.Equal(n.SPKI, hubpki.CertSPKISHA256(cert)) {
		return false
	}
	s := hubpki.SerialText(cert)
	return (n.CertSerial != "" && s == n.CertSerial) || (n.PrevCertSerial != "" && s == n.PrevCertSerial)
}

// CheckOpen is the check at open of 4.4 for the RPC method: a node connection, a certificate that is
// current (past not_after only for RenewCert), and a row that accepts it.
func (c *Checker) CheckOpen(ctx context.Context, method string) (hubnet.Identity, error) {
	id := hubnet.IdentityFrom(ctx)
	if !id.Node || id.Cert == nil {
		return id, errDenied()
	}
	if id.Checked {
		return id, nil
	}
	if c.Reg != nil {
		id.KillGen = c.Reg.Gen()
	}
	if id.Expired && method != RenewMethod {
		return id, errDenied()
	}
	cctx, cancel := context.WithTimeout(ctx, OpenTimeout)
	defer cancel()
	n, found, err := c.Open.HubNodeLoad(cctx, id.NodeID)
	if err != nil {
		return id, errDown()
	}
	if !valid(n, found, id.Cert) {
		return id, errDenied()
	}
	if c.Seen != nil {
		c.Seen(id.NodeID, id.Source)
	}
	if n.PrevCertSerial != "" && hubpki.SerialText(id.Cert) == n.CertSerial && c.Clear != nil {
		// The first RPC with the new serial: the old one is no longer needed (4.3). Best effort, off the
		// pool of the check, so the check stays read-only.
		serial := n.CertSerial
		safego.Go(c.Log, unitClear, func() {
			cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), OpenTimeout)
			defer cancel()
			_ = c.Clear.HubClearPrevSerial(cctx, id.NodeID, serial)
		})
	}
	return id, nil
}

// Unary is the interceptor of unary NodeHub methods.
func (c *Checker) Unary() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
		if _, err := c.CheckOpen(ctx, info.FullMethod); err != nil {
			return nil, err
		}
		return h(ctx, req)
	}
}

// Stream is the interceptor of streaming NodeHub methods. On the served path the root has already run the
// check at open, before it read the body, and left the kill mark it took before reading the row in the
// identity: Registry.Add ends a stream at once when its node was killed after that mark, so a Kill that
// lands between the root's check and the registration is not missed (G2, W3-r2-2). Called without the
// root, the stream is registered before the check runs, which closes the same gap the other way.
func (c *Checker) Stream(reg *Registry) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, h grpc.StreamHandler) error {
		ctx := ss.Context()
		pre := hubnet.IdentityFrom(ctx)
		if !pre.Node || pre.Cert == nil {
			return errDenied()
		}
		sctx, cancel := context.WithCancel(ctx)
		defer cancel()
		gen := reg.Gen()
		if pre.Checked && c.Reg == reg {
			gen = pre.KillGen
		}
		// What the registry calls ends the context and the HTTP stream under it: a handler blocked in a
		// write to a peer that gives no window does not see a context, and only an ended stream frees it
		// and the body it holds (W3-r2-7).
		end := func() {
			cancel()
			hubnet.AbortFrom(ctx)()
		}
		remove := reg.Add(pre.NodeID, info.FullMethod, hubpki.CertSPKISHA256(pre.Cert), hubpki.SerialText(pre.Cert), pre.Cert.NotAfter, gen, end)
		defer remove()
		if _, err := c.CheckOpen(ctx, info.FullMethod); err != nil {
			return err
		}
		if sctx.Err() != nil {
			return errDenied()
		}
		return h(srv, &ctxStream{ServerStream: ss, ctx: sctx, log: c.Log})
	}
}

// ctxStream is the stream a handler sees. Cancelling a derived context does not wake a handler that is
// blocked in RecvMsg or SendMsg on the original stream, and gRPC ends a stream only when its handler
// returns, so a revoked node's UploadLogs loop would run on. RecvMsg and SendMsg therefore return as
// soon as the registry's cancel fires; the abandoned call finishes by itself when the handler returns
// and gRPC closes the stream (G2).
type ctxStream struct {
	grpc.ServerStream
	ctx context.Context
	log *slog.Logger
}

func (s *ctxStream) Context() context.Context { return s.ctx }

func (s *ctxStream) RecvMsg(m any) error {
	err := s.guarded(func() error { return s.ServerStream.RecvMsg(m) })
	if err == nil {
		// The message is out of the transport's queue: its bytes no longer count against the stream's
		// unread budget (W3-r2-6).
		hubnet.Consumed(s.ctx, m)
	}
	return err
}

func (s *ctxStream) SendMsg(m any) error {
	return s.guarded(func() error { return s.ServerStream.SendMsg(m) })
}

func (s *ctxStream) guarded(call func() error) error {
	if s.ctx.Err() != nil {
		return errDenied()
	}
	done := make(chan error, 1)
	safego.Go(s.log, unitStreamIO, func() {
		var err error
		if safego.Run(s.log, unitStreamIO, func() { err = call() }) {
			err = errDown()
		}
		done <- err
	})
	select {
	case err := <-done:
		return err
	case <-s.ctx.Done():
		return errDenied()
	}
}

// EnrollmentGuard refuses an Enrollment call that carries a node certificate: the service is for a host
// that has none yet (5.1).
func EnrollmentGuard() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
		if hubnet.IdentityFrom(ctx).Node {
			return nil, status.Error(codes.PermissionDenied, "not for a node")
		}
		return h(ctx, req)
	}
}
