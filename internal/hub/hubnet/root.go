package hubnet

import (
	"bytes"
	"context"
	"crypto/x509"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	enrollv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/enroll/v1"
	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"

	"github.com/Kup1ng/CtrlZ-Panel/internal/appclock"
	"github.com/Kup1ng/CtrlZ-Panel/internal/httpx"
	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hublimit"
)

// Identity is what a request is known by, decided once by the root handler and read by everything
// below it. A request that did not come over an admitted node connection has Node false, and nothing
// below the root trusts a certificate it finds in the request on its own.
type Identity struct {
	Source  netip.Addr
	Node    bool
	NodeID  uuid.UUID
	Cert    *x509.Certificate
	Expired bool // now is past the certificate's not_after (inside the renewal window)
	// Checked says the root handler already ran the row check of 4.4 for this very RPC before it read a
	// byte of the body, so the interceptors do not pay for it a second time. Only the root sets it.
	Checked bool
	// KillGen is the registry mark taken before the row was read (Checker.CheckOpen), for Registry.Add.
	KillGen uint64
}

type identityKey struct{}
type connKey struct{}
type abortKey struct{}
type bodyKey struct{}

// aborter holds the function that ends a request's HTTP stream, in a type of its own so that the context
// carries a value and not a function that something might run in a goroutine.
type aborter struct{ end func() }

// WithAbort and AbortFrom carry the function that ends the HTTP stream of a NodeHub call: the root
// handler sets it, the stream interceptor hands it to the registry. AbortFrom never returns nil.
func WithAbort(ctx context.Context, f func()) context.Context {
	return context.WithValue(ctx, abortKey{}, &aborter{end: f})
}

// AbortFrom returns the abort function of the request, or one that does nothing.
func AbortFrom(ctx context.Context) func() {
	if a, ok := ctx.Value(abortKey{}).(*aborter); ok && a.end != nil {
		return a.end
	}
	return func() {}
}

// endedKey carries the channel that closes when the HTTP stream of a NodeHub call is over.
type endedKey struct{}

// WithEnded returns a context that carries a channel EndedFrom reads, and the function that closes it (once). The root handler
// closes it when the whole call is done, which for HTTP/2 under gRPC is later than the handler's return: gRPC writes the final
// status after the handler returns, and a peer with no window leaves that write, and everything the call still holds, waiting.
func WithEnded(ctx context.Context) (context.Context, func()) {
	ch := make(chan struct{})
	return context.WithValue(ctx, endedKey{}, ch), sync.OnceFunc(func() { close(ch) })
}

// EndedFrom returns the channel that closes when the call's stream is over; for a context that has none (a call that is not
// served by the root handler) it is a channel that is closed already, so nothing waits for it.
func EndedFrom(ctx context.Context) <-chan struct{} {
	if ch, ok := ctx.Value(endedKey{}).(chan struct{}); ok {
		return ch
	}
	ch := make(chan struct{})
	close(ch)
	return ch
}

// WithIdentity and IdentityFrom carry the identity in a context.
func WithIdentity(ctx context.Context, id Identity) context.Context {
	return context.WithValue(ctx, identityKey{}, id)
}

// IdentityFrom returns the identity the root handler set; the zero Identity (no node) if none.
func IdentityFrom(ctx context.Context) Identity {
	id, _ := ctx.Value(identityKey{}).(Identity)
	return id
}

// ConnContext is http.Server.ConnContext: it remembers the connection of every request.
func ConnContext(ctx context.Context, c net.Conn) context.Context {
	if rc := connOf(c); rc != nil {
		return context.WithValue(ctx, connKey{}, rc)
	}
	return ctx
}

func identityOf(r *http.Request, now time.Time) Identity {
	rc, _ := r.Context().Value(connKey{}).(*rawConn)
	if rc == nil {
		return Identity{Source: sourceOf(r)}
	}
	id := Identity{Source: rc.src}
	if nid, ok := rc.Node(); ok && r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		id.Node, id.NodeID, id.Cert = true, nid, r.TLS.PeerCertificates[0]
		id.Expired = !now.Before(id.Cert.NotAfter)
	}
	return id
}

func sourceOf(r *http.Request) netip.Addr {
	if ap, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
		return ap.Addr().Unmap()
	}
	return netip.Addr{}
}

// Limits of 5.1 and 5.7 held by the root handler (D31).
const (
	EnrollPerMinute   = 30
	EnrollInProgress  = 4
	EnrollBodyBytes   = 8 << 10
	EnrollReadTimeout = 10 * time.Second
	NodeOpensPerSec   = 20
	NodeOpensBurst    = 40
	NodeBytesPerSec   = 2 << 20
	NodeBytesBurst    = 16 << 20
	MaxTransfers      = 8
	// MaxOpenRPCs is the RPCs one node holds open at once: its streams (Control, three uploads, up to
	// MaxTransfers transfers) and the unary calls in flight, with room to spare.
	MaxOpenRPCs = 32
	// A unary NodeHub request is one small message; RenewCert needs about 8 KiB.
	UnaryBodyBytes   = 16 << 10
	UnaryReadTimeout = 10 * time.Second
	// ResponseWriteTimeout bounds how long an answer to an enrolment or a unary call may take to be
	// written: a peer that gives no window must not hold a goroutine for as long as it likes.
	ResponseWriteTimeout = 10 * time.Second
	// AnonymousTimeout is how long a request that is not a node's NodeHub call may take to be read and
	// answered, before a handler that wants longer (a bundle download) sets its own deadlines. Without it
	// a client that sends a window of zero holds the handler, its headers and any unread body for as
	// long as it answers pings (W3-r2-5).
	AnonymousTimeout = 10 * time.Second
	// WriteByteTimeout is how long the HTTP/2 connection may fail to write a single byte before the
	// server closes it (W3-r3-3).
	WriteByteTimeout = 10 * time.Second
	// MaxRequestsPerConn is how many requests of that kind one connection has in progress. One
	// connection may open 100 streams; a client of ours has one, and the rest would each pin the
	// request, its headers and its writer.
	MaxRequestsPerConn = 8
)

// RootLimits are the root handler's limiters; NewRootLimits builds them with the numbers above.
type RootLimits struct {
	EnrollSource *hublimit.Keyed
	EnrollSlots  *hublimit.Slots
	NodeOpens    *hublimit.Keyed
	NodeBytes    *hublimit.Keyed
	Transfers    *hublimit.Counts
	OpenRPCs     *hublimit.Counts
}

// NewRootLimits builds the limiters of the root handler.
func NewRootLimits(now func() time.Time) RootLimits {
	return RootLimits{
		EnrollSource: hublimit.NewKeyed(EnrollPerMinute/60.0, EnrollPerMinute, now),
		EnrollSlots:  hublimit.NewSlots(EnrollInProgress),
		NodeOpens:    hublimit.NewKeyed(NodeOpensPerSec, NodeOpensBurst, now),
		NodeBytes:    hublimit.NewKeyed(NodeBytesPerSec, NodeBytesBurst, now),
		Transfers:    hublimit.NewCounts(MaxTransfers),
		OpenRPCs:     hublimit.NewCounts(MaxOpenRPCs),
	}
}

// Root is the one handler of the port.
type Root struct {
	Now        func() time.Time
	Enrollment http.Handler // the Enrollment grpc.Server's ServeHTTP
	NodeHub    http.Handler // the NodeHub grpc.Server's ServeHTTP
	Install    http.Handler // GET /install/...
	// NodeCheck is the row check of 4.4 for a NodeHub RPC (hubnodes.Checker.CheckOpen). The root runs it
	// before it reads the body; nil skips it, for tests of the other rules.
	NodeCheck func(ctx context.Context, method string) (Identity, error)
	Limits    RootLimits
	Log       *slog.Logger
	// AnonTimeout overrides AnonymousTimeout, for tests.
	AnonTimeout time.Duration
}

// isTransfer says whether a NodeHub method is one of the four transfer RPCs, at most 8 of which a node holds
// open (SC 12).
// isUnary says whether a NodeHub method takes one request message, from the service descriptor.
func isUnary(method string) bool {
	for _, m := range hubv1.NodeHub_ServiceDesc.Methods {
		if m.MethodName == method {
			return true
		}
	}
	return false
}

// oneRequest says whether a NodeHub method takes one request message and nothing more: the unary
// methods and the server-streaming ones (the four transfers). Its body is read whole before gRPC sees it,
// so no live body is left to grow (W3-r2-6).
func oneRequest(method string) bool {
	if isUnary(method) {
		return true
	}
	for _, s := range hubv1.NodeHub_ServiceDesc.Streams {
		if s.StreamName == method {
			return !s.ClientStreams
		}
	}
	return false
}

func isTransfer(method string) bool {
	switch method {
	case "FetchEntries", "FetchBlob", "GetSnapshot", "FetchBundle":
		return true
	}
	return false
}

// trailerPrefix is net/http's TrailerPrefix: a header with it is sent as a trailer. Spelled here because
// the capability lint lists the members of net/http a package may use, and this is one string.
const trailerPrefix = "Trailer:"

// grpcRefuse answers a gRPC call with a status and no message. The status goes out as real trailers and
// not as a headers-only ("trailers-only") answer: bound()'s release flushes the response before the
// handler returns, and over HTTP/2 that sends the HEADERS frame without END_STREAM, which a gRPC client
// then does not read a status from and reports as INTERNAL. With trailers it does not matter whether a
// flush came first (W3-r5-4).
func grpcRefuse(w http.ResponseWriter, code codes.Code, msg string) {
	h := w.Header()
	h.Set("Content-Type", "application/grpc")
	w.WriteHeader(http.StatusOK)
	h.Set(trailerPrefix+"Grpc-Status", strconv.Itoa(int(code)))
	h.Set(trailerPrefix+"Grpc-Message", msg)
}

func (h *Root) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	now := h.Now()
	id := identityOf(r, now)
	r = r.WithContext(WithIdentity(r.Context(), id))

	// Everything but a gRPC call of an admitted node to NodeHub is bounded in time and in number per
	// connection before any branch: even a plain 404 is an answer that a peer with no window can leave
	// unwritten. The exemption is for what serveNodeHub will handle (it counts and checks the call), so a
	// request on a node connection with the NodeHub path and another content type is bounded like any
	// other (W3-r3-1, W3-r3-4).
	if !(id.Node && strings.HasPrefix(r.URL.Path, "/"+hubv1.NodeHub_ServiceDesc.ServiceName+"/") &&
		strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc")) {
		rel, ok := h.bound(w, r)
		if !ok {
			return
		}
		defer rel()
	}

	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc") {
		h.serveGRPC(w, r, id)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/install/") && h.Install != nil {
		h.Install.ServeHTTP(w, r)
		return
	}
	http.NotFound(w, r)
}

// bound takes one of the connection's places for a request and arms its deadlines. When the connection
// holds too many it ends the stream, with no answer to be written: a write would be the very thing a
// peer with no window leaves hanging.
func (h *Root) bound(w http.ResponseWriter, r *http.Request) (release func(), ok bool) {
	release = func() {}
	rc, _ := r.Context().Value(connKey{}).(*rawConn)
	if rc != nil {
		if !rc.enterRequest() {
			endStream(w)
			return nil, false
		}
	}
	// The place is given back after the answer is flushed and not when the handler returns: HTTP/2 writes
	// the buffered answer after the handler's return, and a peer with no window leaves that write
	// hanging, which is exactly the goroutine this place is counting.
	rcw := http.NewResponseController(w)
	h2 := r.ProtoMajor >= 2 // HTTP/1 writes the answer on the handler's goroutine anyway, and a flush would only make it chunked
	release = func() {
		if h2 {
			_ = rcw.Flush()
		}
		if rc != nil {
			rc.leaveRequest()
		}
	}
	within := h.AnonTimeout
	if within <= 0 {
		within = AnonymousTimeout
	}
	deadline := appclock.Now().Add(within)
	_ = rcw.SetWriteDeadline(deadline)
	if r.Body != nil && r.Body != http.NoBody {
		_ = rcw.SetReadDeadline(deadline)
	}
	return release, true
}

// endStream ends the HTTP stream under w at once: a deadline in the past resets an HTTP/2 stream and
// fails the next write of an HTTP/1 connection. It is safe from another goroutine while the handler runs,
// and must not be called after the handler has returned.
func endStream(w http.ResponseWriter) {
	rcw := http.NewResponseController(w)
	past := time.Unix(1, 0)
	_ = rcw.SetReadDeadline(past)
	_ = rcw.SetWriteDeadline(past)
}

func (h *Root) serveGRPC(w http.ResponseWriter, r *http.Request, id Identity) {
	path := r.URL.Path
	switch {
	case strings.HasPrefix(path, "/"+enrollv1.Enrollment_ServiceDesc.ServiceName+"/"):
		h.serveEnrollment(w, r, id)
	case strings.HasPrefix(path, "/"+hubv1.NodeHub_ServiceDesc.ServiceName+"/"):
		h.serveNodeHub(w, r, id)
	default:
		http.NotFound(w, r)
	}
}

// serveEnrollment bounds an anonymous call in rate, bytes, time and work. Before any database read,
// keyed by source: the per-/24 or /56 call rate (5.7). The body is read here, whole, into one buffer of
// at most 8 KiB under a read deadline, and gRPC gets those bytes: handed the live body, grpc-go reads it
// in 16 KiB pooled buffers and keeps each whole however few bytes arrived, so one byte per DATA frame
// would cost 16 KiB a byte. The slot of calls in progress is held only while the handler works and is
// given back when it starts to answer, so a client that never takes the answer (a window of zero) holds
// a goroutine for the write deadline and no slot (5.1, 5.7).
func (h *Root) serveEnrollment(w http.ResponseWriter, r *http.Request, id Identity) {
	if !h.Limits.EnrollSource.Allow(hublimit.NetKey(id.Source)) {
		grpcRefuse(w, codes.ResourceExhausted, "rate limited")
		return
	}
	if err := preread(w, r, EnrollBodyBytes, EnrollReadTimeout); err != nil {
		grpcRefuse(w, codes.InvalidArgument, "bad request")
		return
	}
	// The work that follows waits on one database connection and has no peer to wait for: the answer
	// sets its own deadline when it starts, and the one armed at the top must not end the stream under
	// the work.
	_ = http.NewResponseController(w).SetWriteDeadline(time.Time{})
	rel, ok := h.Limits.EnrollSlots.Try()
	if !ok {
		grpcRefuse(w, codes.ResourceExhausted, "busy")
		return
	}
	defer rel()
	h.Enrollment.ServeHTTP(newStartWriter(w, func() { rel(); setWriteDeadline(w) }), r)
}

func (h *Root) serveNodeHub(w http.ResponseWriter, r *http.Request, id Identity) {
	// A NodeHub path on a connection that did not admit a node certificate gets 403 before gRPC sees
	// it, so an anonymous peer never gets a goroutine that reads into an unbounded buffer.
	if !id.Node {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	key := id.NodeID.String()
	path := r.URL.Path
	method := path[strings.LastIndexByte(path, '/')+1:]
	// Each RPC a node opens counts against its rate, transfers included, and the check that follows
	// is not paid for an RPC refused here (SC 12).
	if !h.Limits.NodeOpens.Allow(key) {
		grpcRefuse(w, codes.ResourceExhausted, "rate limited")
		return
	}
	// The row check of 4.4 runs here, before a byte of the body is read. A revoked or removed node's
	// certificate still chains to the node CA for 30 + 60 days, and a unary message is read and decoded
	// by gRPC before any interceptor runs, so checking later would let that node hold a 4 MiB buffer per
	// stream it opens (G2).
	if h.NodeCheck != nil {
		checked, err := h.NodeCheck(WithIdentity(r.Context(), id), path)
		if err != nil {
			st := status.Convert(err)
			grpcRefuse(w, st.Code(), st.Message())
			return
		}
		checked.Checked = true
		r = r.WithContext(WithIdentity(r.Context(), checked))
	}
	rel, ok := h.Limits.OpenRPCs.Take(key)
	if !ok {
		grpcRefuse(w, codes.ResourceExhausted, "too many calls")
		return
	}
	defer rel()
	if isTransfer(method) {
		relT, ok := h.Limits.Transfers.Take(key)
		if !ok {
			grpcRefuse(w, codes.ResourceExhausted, "too many transfers")
			return
		}
		defer relT()
	}
	rb := &rateBody{rc: r.Body, k: h.Limits.NodeBytes, key: key, ctx: r.Context()}
	r.Body = rb
	// What ends the stream on a revocation: the registry calls it, so a handler blocked in a write to a
	// peer with no window, and the reader of the body, are released and not left until the node hangs up
	// (G2, W3-r2-7). It is armed only while this function runs, because the writer is not valid after.
	var amu sync.Mutex
	over := false
	abort := func() {
		amu.Lock()
		defer amu.Unlock()
		if !over {
			endStream(w)
		}
	}
	defer func() { amu.Lock(); over = true; amu.Unlock() }()
	r = r.WithContext(WithAbort(r.Context(), abort))
	ectx, ended := WithEnded(r.Context())
	defer ended() // after the answer is written: what a handler holds for the stream is held until here (EndedFrom)
	r = r.WithContext(ectx)
	if oneRequest(method) {
		// One small request message (RenewCert about 8 KiB, a transfer's request less): bounded and read
		// whole like an enrolment, so it never holds gRPC's per-read buffers either.
		if err := preread(w, r, UnaryBodyBytes, UnaryReadTimeout); err != nil {
			grpcRefuse(w, codes.InvalidArgument, "bad request")
			return
		}
		if isUnary(method) {
			h.NodeHub.ServeHTTP(newStartWriter(w, func() { setWriteDeadline(w) }), r)
			return
		}
		h.NodeHub.ServeHTTP(w, r)
		return
	}
	// A live body (Control and the uploads): what it has read and the handler has not taken is bounded.
	rb.g = newGauge()
	h.NodeHub.ServeHTTP(w, r.WithContext(withGauge(r.Context(), rb.g)))
}

// preread replaces r.Body by the whole body, read through a cap and a read deadline from the real clock
// (a test's frozen clock must not move the deadline).
func preread(w http.ResponseWriter, r *http.Request, limit int64, within time.Duration) error {
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(appclock.Now().Add(within))
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	_ = rc.SetReadDeadline(time.Time{})
	if err != nil {
		return err
	}
	r.Body = io.NopCloser(bytes.NewReader(b))
	return nil
}

func setWriteDeadline(w http.ResponseWriter) {
	_ = http.NewResponseController(w).SetWriteDeadline(appclock.Now().Add(ResponseWriteTimeout))
}

// startWriter runs start once, when the handler first writes: gRPC writes nothing until the handler
// has finished, so that moment is the end of the work and the start of the answer.
type startWriter struct {
	http.ResponseWriter
	once  sync.Once
	start func()
}

func newStartWriter(w http.ResponseWriter, start func()) *startWriter {
	return &startWriter{ResponseWriter: w, start: start}
}

func (s *startWriter) begin() { s.once.Do(s.start) }

func (s *startWriter) WriteHeader(code int) { s.begin(); s.ResponseWriter.WriteHeader(code) }

func (s *startWriter) Write(b []byte) (int, error) { s.begin(); return s.ResponseWriter.Write(b) }

func (s *startWriter) Flush() { s.begin(); _ = http.NewResponseController(s.ResponseWriter).Flush() }

func (s *startWriter) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// rateBody paces what a node's request bodies may read. A read that must wait does not read, so the
// HTTP/2 window credit of that stream is withheld and a flood stalls at the sender's connection.
type rateBody struct {
	rc  io.ReadCloser
	k   *hublimit.Keyed
	key string
	ctx context.Context
	g   *gauge // the unread budget of a live body; nil for a body read whole
}

func (b *rateBody) Close() error { return b.rc.Close() }

func (b *rateBody) Read(p []byte) (int, error) {
	if len(p) > 64<<10 {
		p = p[:64<<10]
	}
	if b.g != nil {
		if err := b.g.wait(b.ctx); err != nil {
			return 0, err
		}
	}
	n := float64(len(p))
	for !b.k.AllowN(b.key, n) {
		wait := b.k.Wait(b.key, n)
		if wait < time.Millisecond {
			wait = time.Millisecond
		}
		t := time.NewTimer(wait)
		select {
		case <-b.ctx.Done():
			t.Stop()
			return 0, b.ctx.Err()
		case <-t.C:
		}
	}
	got, err := b.rc.Read(p)
	if b.g != nil {
		b.g.read(got)
	}
	return got, err
}

// NewServer builds the http.Server of the port (5.1). Keepalive is the server's, since gRPC's own
// options do not apply under ServeHTTP: it pings a connection that sent no frame for 10 s and drops it
// after 10 s without an ack.
func NewServer(root http.Handler, base *http.Server, log *slog.Logger) *http.Server {
	srv := base
	if srv == nil {
		srv = &http.Server{}
	}
	srv.Handler = root
	srv.ReadHeaderTimeout = 10 * time.Second
	srv.IdleTimeout = 60 * time.Second
	srv.MaxHeaderBytes = 16 << 10
	srv.ConnContext = ConnContext
	srv.HTTP2 = &http.HTTP2Config{
		MaxConcurrentStreams: 100,
		SendPingTimeout:      10 * time.Second,
		PingTimeout:          10 * time.Second,
		// A stream's write deadline only queues a RST_STREAM, and the stream (and its handler) ends when
		// that frame has been written. A peer that stops reading the TCP socket blocks the write in
		// front of it, and a PING or WINDOW_UPDATE every few seconds keeps the keepalive satisfied, so
		// without this every deadline of the port is void against it. It fires only when no byte could
		// be written for the whole period, so a slow download that moves is not touched (W3-r3-3).
		WriteByteTimeout: WriteByteTimeout,
		// The default windows are 1 MiB a stream and a connection. What a peer has sent and no handler
		// has read sits in memory up to the window, so the windows are what an anonymous connection can
		// make the hub hold; 256 KiB still fills a 20 Mbit/s link at 100 ms (W3-r2-5).
		MaxReceiveBufferPerConnection: 256 << 10,
		MaxReceiveBufferPerStream:     256 << 10,
	}
	// The server's own error log would print request lines and peer addresses; this one keeps the class.
	srv.ErrorLog = httpx.ErrorLog(log)
	return srv
}
