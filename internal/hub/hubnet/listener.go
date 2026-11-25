// Package hubnet is the hub's one listener on the node port (p4-nodes 5.1): the TCP and TLS layer
// with its limits, the identity a connection carries, and the root handler that decides which of the
// two gRPC servers, the install files or a 404 a request reaches.
//
// Why a listener of our own. A node's handshake looks like anyone's until its certificate arrives, so
// the limits that keep a flood from the internet off the nodes have to sit before TLS (connections per
// source), around it (handshakes in progress, with slots only a node's address may use) and after it
// (connections that carry no node certificate). http.Server does none of that, and under
// ServeHTTP gRPC has no flow control of its own, so the bytes are bounded here too.
package hubnet

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/appclock"
	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hublimit"
	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubpki"
	"github.com/Kup1ng/CtrlZ-Panel/internal/safego"
)

// unit names the goroutines of this package for safego (a closed set, so a log line may carry it).
type unit string

const (
	unitAccept    unit = "hub_accept"
	unitHandshake unit = "hub_handshake"
)

func (u unit) Valid() bool { return u == unitAccept || u == unitHandshake }

// Defaults of D31 (p4-nodes 5.1).
const (
	MaxOpenPerSource   = 16
	NewConnsPerSecond  = 10
	MaxHandshakes      = 256
	ReservedHandshakes = 64
	HandshakesPerPref  = 32
	MaxNoCertConns     = 512
	MaxConnsPerNode    = 6
	HandshakeTimeout   = 10 * time.Second
	// MaxHandshakeBytes is what a peer may send before its handshake is done. Go reads a client
	// Certificate message of up to 256 KiB and parses every certificate in it before VerifyConnection
	// runs, so without this bound each of the 256 handshakes could hold about 2.5 MB of parsed junk for
	// the whole timeout (W3-r4-5). A ClientHello with ML-KEM, one node certificate and its
	// CertificateVerify is under 8 KiB.
	MaxHandshakeBytes = 32 << 10
	// maxPeerCerts is a node leaf, and room for the CA a client might add. Nothing else is read.
	maxPeerCerts = 2
)

// ListenerConfig is everything the listener needs from its surroundings.
type ListenerConfig struct {
	// TLS is the template: the hub leaf (Certificates or GetCertificate) and the protocols. The listener
	// adds client-certificate handling to a copy; it never changes this one.
	TLS *tls.Config
	CA  *hubpki.NodeCA
	Now func() time.Time
	// NodeAddr says whether a source address belongs to a node (its bind or advertised address, or the
	// address its enrolment came from). Such a source may use the reserved handshake slots.
	NodeAddr func(netip.Addr) bool

	Conns      *hublimit.Conns
	Handshakes *hublimit.Handshakes
	NoCert     *hublimit.Slots
	NodeConns  *hublimit.Counts

	HandshakeTimeout time.Duration
	Log              *slog.Logger
}

// NewLimits builds the limiters with the numbers of D31.
func NewLimits(now func() time.Time) (*hublimit.Conns, *hublimit.Handshakes, *hublimit.Slots, *hublimit.Counts) {
	return hublimit.NewConns(MaxOpenPerSource, NewConnsPerSecond, now),
		hublimit.NewHandshakes(MaxHandshakes, ReservedHandshakes, HandshakesPerPref),
		hublimit.NewSlots(MaxNoCertConns),
		hublimit.NewCounts(MaxConnsPerNode)
}

// Listener hands http.Server connections whose handshake is done and whose admission is decided.
type Listener struct {
	inner net.Listener
	cfg   ListenerConfig
	base  *tls.Config
	ready chan net.Conn
	done  chan struct{}
	once  sync.Once
}

// NewListener wraps inner and starts accepting.
func NewListener(inner net.Listener, cfg ListenerConfig) (*Listener, error) {
	if cfg.TLS == nil || cfg.CA == nil || cfg.Conns == nil || cfg.Handshakes == nil || cfg.NoCert == nil || cfg.NodeConns == nil {
		return nil, errors.New("hubnet: incomplete listener configuration")
	}
	if cfg.Now == nil {
		cfg.Now = appclock.Now
	}
	if cfg.NodeAddr == nil {
		cfg.NodeAddr = func(netip.Addr) bool { return false }
	}
	if cfg.HandshakeTimeout <= 0 {
		cfg.HandshakeTimeout = HandshakeTimeout
	}
	l := &Listener{inner: inner, cfg: cfg, ready: make(chan net.Conn, 64), done: make(chan struct{})}
	l.base = cfg.TLS.Clone()
	l.base.MinVersion = tls.VersionTLS13
	l.base.NextProtos = []string{"h2", "http/1.1"}
	// RequestClientCert and not Require: Enrollment and the install files take no certificate. A given
	// certificate is judged by VerifyConnection below, which fails the handshake for one that is not a
	// node's (the hub and NTS leaves never pass).
	l.base.ClientAuth = tls.RequestClientCert
	l.base.GetConfigForClient = l.configFor
	safego.Go(cfg.Log, unitAccept, l.acceptLoop)
	return l, nil
}

// rawConn is the accepted connection under TLS. It carries what the limiters took for it and gives
// them back in one Close, so no path out of the connection's life can leak a count.
type rawConn struct {
	net.Conn
	src netip.Addr

	mu       sync.Mutex
	node     uuid.UUID
	proposed uuid.UUID // the node id the certificate named, not yet counted: see Listener.handshake
	releases []func()
	closed   bool
	requests int // requests in progress that are not an admitted node's NodeHub calls

	// read counts the bytes taken off the socket until the handshake is done (see MaxHandshakeBytes). Only
	// the goroutine that runs the handshake reads before then, and capLifted is set by that goroutine
	// before it hands the connection on.
	read      int64
	capLifted bool
}

var errHandshakeBytes = errors.New("hubnet: too many bytes before the handshake finished")

// Read is the bound of MaxHandshakeBytes. It never asks the socket for more than the budget left plus
// one byte, so the one byte that overruns it is how the cap is noticed, and no read fills a larger buffer.
func (c *rawConn) Read(p []byte) (int, error) {
	if c.capLifted {
		return c.Conn.Read(p)
	}
	if left := MaxHandshakeBytes - c.read + 1; int64(len(p)) > left {
		p = p[:left]
	}
	n, err := c.Conn.Read(p)
	c.read += int64(n)
	if c.read > MaxHandshakeBytes {
		_ = c.Conn.Close()
		return 0, errHandshakeBytes
	}
	return n, err
}

func (c *rawConn) enterRequest() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.requests >= MaxRequestsPerConn {
		return false
	}
	c.requests++
	return true
}

func (c *rawConn) leaveRequest() {
	c.mu.Lock()
	c.requests--
	c.mu.Unlock()
}

func (c *rawConn) addRelease(f func()) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		f()
		return
	}
	c.releases = append(c.releases, f)
	c.mu.Unlock()
}

func (c *rawConn) propose(id uuid.UUID) {
	c.mu.Lock()
	c.proposed = id
	c.mu.Unlock()
}

// admit makes the proposed node id the connection's, once the handshake has proved the key.
func (c *rawConn) admit() (uuid.UUID, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.node = c.proposed
	return c.node, c.node != uuid.Nil
}

// Node is the node id this connection was admitted as, if any.
func (c *rawConn) Node() (uuid.UUID, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.node, c.node != uuid.Nil
}

func (c *rawConn) Close() error {
	c.mu.Lock()
	rel := c.releases
	c.releases, c.closed = nil, true
	c.mu.Unlock()
	for _, f := range rel {
		f()
	}
	return c.Conn.Close()
}

// configFor gives each connection its own copy of the config whose VerifyConnection knows the
// connection, so the node id of an admitted certificate lands on the connection that presented it.
func (l *Listener) configFor(h *tls.ClientHelloInfo) (*tls.Config, error) {
	rc, ok := h.Conn.(*rawConn)
	if !ok {
		return nil, errors.New("hubnet: unexpected connection type")
	}
	c := l.base.Clone()
	c.GetConfigForClient = nil
	c.VerifyConnection = func(cs tls.ConnectionState) error { return l.verify(rc, cs) }
	return c, nil
}

// verify is the handshake-time judgement of a client certificate (5.1). No certificate is allowed (the
// connection is then a non-node connection); a given one must chain to the node CA at now or within
// the 60-day renewal window past not_after, carry EKU clientAuth, and name a node id. The connection
// is counted against its node in handshake, after the key is proved. Which RPC may use the window is
// the interceptor's call.
func (l *Listener) verify(rc *rawConn, cs tls.ConnectionState) error {
	if len(cs.PeerCertificates) == 0 {
		return nil
	}
	// The node CA signs leaves directly, so a longer list is nobody the hub issued for, and nothing past
	// the leaf is used to build a chain (hubpki.VerifyClient).
	if len(cs.PeerCertificates) > maxPeerCerts {
		return errors.New("hubnet: client certificate refused")
	}
	id, err := l.cfg.CA.VerifyClient(cs.PeerCertificates[0], l.cfg.Now(), true)
	if err != nil {
		return errors.New("hubnet: client certificate refused")
	}
	// Only noted here. VerifyConnection runs after the client's Certificate message and before its
	// CertificateVerify is read, so a peer that shows a node's certificate without its key gets this far;
	// the certificate is not a secret. Counting it now would let such a peer fill the node's six places
	// for the length of the handshake timeout and lock the real node out.
	rc.propose(id)
	return nil
}

func (l *Listener) acceptLoop() {
	for {
		select {
		case <-l.done:
			return
		default:
		}
		conn, err := l.inner.Accept()
		if err != nil {
			select {
			case <-l.done:
				return
			default:
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				time.Sleep(5 * time.Millisecond)
				continue
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(5 * time.Millisecond)
			continue
		}
		l.acceptOne(conn)
	}
}

// acceptOne admits one connection or closes it, before any byte is read. A panic here costs this
// connection and not the accept loop.
func (l *Listener) acceptOne(conn net.Conn) {
	defer safego.Keep(l.cfg.Log, unitAccept)
	src := remoteAddr(conn)
	// Asked first: the node address set decides which sources the full-table rule of the connection
	// limiter spares, and the reserved handshake slots below (5.1, W3-r2-1).
	node := l.cfg.NodeAddr(src.Unmap())
	relConn, ok := l.cfg.Conns.AdmitFor(src, node)
	if !ok {
		_ = conn.Close()
		return
	}
	relHS, ok := l.cfg.Handshakes.Begin(src, node)
	if !ok {
		relConn()
		_ = conn.Close()
		return
	}
	rc := &rawConn{Conn: conn, src: src.Unmap()}
	rc.addRelease(relConn)
	safego.Go(l.cfg.Log, unitHandshake, func() {
		l.handshake(rc, relHS)
	})
}

func (l *Listener) handshake(rc *rawConn, relHS func()) {
	tc := tls.Server(rc, l.base)
	ctx, cancel := context.WithTimeout(context.Background(), l.cfg.HandshakeTimeout)
	err := tc.HandshakeContext(ctx)
	cancel()
	relHS()
	if err != nil {
		_ = rc.Close()
		return
	}
	rc.capLifted = true
	// The key is proved: now the node's connection is counted, and a seventh is refused (5.1).
	if !l.countNode(rc) {
		_ = rc.Close()
		return
	}
	// After the handshake: a connection that carries no node certificate holds one of the 512 slots for
	// as long as it lives, so node connections keep their room (5.1).
	if _, isNode := rc.Node(); !isNode {
		rel, ok := l.cfg.NoCert.Try()
		if !ok {
			_ = rc.Close()
			return
		}
		rc.addRelease(rel)
	}
	select {
	case l.ready <- tc:
	case <-l.done:
		_ = tc.Close()
	default:
		_ = tc.Close()
	}
}

// Accept returns the next connection that is through its handshake and its admission.
func (l *Listener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ready:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

// Close stops accepting and closes the connections that were ready and not yet served.
func (l *Listener) Close() error {
	var err error
	l.once.Do(func() {
		close(l.done)
		err = l.inner.Close()
		for {
			select {
			case c := <-l.ready:
				_ = c.Close()
			default:
				return
			}
		}
	})
	return err
}

// Addr is the address of the underlying listener.
func (l *Listener) Addr() net.Addr { return l.inner.Addr() }

func remoteAddr(c net.Conn) netip.Addr {
	if ta, ok := c.RemoteAddr().(*net.TCPAddr); ok {
		return ta.AddrPort().Addr()
	}
	if ap, err := netip.ParseAddrPort(c.RemoteAddr().String()); err == nil {
		return ap.Addr()
	}
	return netip.Addr{}
}

// connOf reaches the rawConn under a *tls.Conn that this listener produced.
func connOf(c net.Conn) *rawConn {
	if tc, ok := c.(*tls.Conn); ok {
		if rc, ok := tc.NetConn().(*rawConn); ok {
			return rc
		}
	}
	return nil
}

// countNode makes the node id the certificate named the connection's own and counts the connection
// against that node. It runs once the handshake has proved the client holds the key, and never before:
// a certificate is not a secret, and counting at VerifyConnection would let a peer that only shows one
// fill the node's places for the length of the handshake timeout. A connection with no node certificate
// is counted nowhere here. It says false when the node already holds its maximum.
func (l *Listener) countNode(rc *rawConn) bool {
	id, isNode := rc.admit()
	if !isNode {
		return true
	}
	rel, ok := l.cfg.NodeConns.Take(id.String())
	if !ok {
		return false
	}
	rc.addRelease(rel)
	return true
}
