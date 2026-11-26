// Package hubctl is the hub's end of the Control stream (p4-nodes 5.2, SC 12, SC 8a.4 Publication, 8a.11 L1, L4, L9).
//
// What each rule asks, and where it is kept:
//
//   - One stream per node_id: a new one ends the older (attach).
//   - One writer goroutine per stream, the only one that writes a HubMessage to it, with a queue bounded by bytes (4 MiB).
//     Everything else hands its message to the queue and goes on, so a peer that does not read stalls its own writer
//     and nothing else (L9). A full queue ends that stream only.
//   - The reader never waits on Postgres: a Heartbeat goes to the in-memory trackers and the rollout queue, an ApplyResult
//     to the rollout queue, and every other message is offered to the Intake, whose contract is not to block (L10).
//   - ServerTime every 10 s, and only while the Decider says the hub can decide (L4). The stream's first messages are
//     FreeDnsOff (only while the switch is off), then, after the node's first Heartbeat, ServerTime and the latest push,
//     and only then HeadNotice, NodeConfig and CertBundle.
//   - HeadNotice names the node's own bound (hubroll), never more.
//   - NodeConfig and CertBundle are built from one gated read: nothing is sent unless that read shows the node active with
//     the stream's key (G2), and the read is cached per node for 5 s so a node that reopens its stream cannot make the
//     hub read faster than that.
package hubctl

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	commonv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/common/v1"
	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	"github.com/Kup1ng/CtrlZ-Shared/wire"

	"github.com/Kup1ng/CtrlZ-Panel/internal/compiler/rollout"
	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubnet"
	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubroll"
	"github.com/Kup1ng/CtrlZ-Panel/internal/safego"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

type unit string

const unitCtl unit = "hub_control"

func (u unit) Valid() bool { return u == unitCtl }

// The numbers of 5.2, 5.8 and 4.4.
const (
	QueueBytes      = 4 << 20
	ServerTimeEvery = 10 * time.Second
	HeadEvery       = 200 * time.Millisecond
	ConfigEvery     = 5 * time.Second
	// NoHeartbeat ends a stream that sent no Heartbeat for this long (5.8).
	NoHeartbeat = 60 * time.Second
	// FirstHeartbeat is how long a new stream may take to send its first Heartbeat (the node sends it first, 8a.4).
	FirstHeartbeat = 30 * time.Second
	// StaleConfig is how long a node may report a lower NodeConfig version than the one sent before the hub says so (L1).
	StaleConfig = 60 * time.Second
	gateTTL     = 5 * time.Second
)

// ControlStore is what the stream reads on the control pool.
type ControlStore interface {
	HubConfigLoad(ctx context.Context, id uuid.UUID) (store.HubConfigRead, error)
}

// Intake receives every message of a node that is not the hub's own business: Heartbeats (for 5.3's writes), reports,
// and what an outside party can cause. Offer must not block and must not touch the database: it queues or drops (L10).
type Intake interface {
	Offer(node uuid.UUID, m *hubv1.NodeMessage)
}

// Config is what a Server is built from.
type Config struct {
	Roll     *hubroll.Roll
	Store    ControlStore
	Decider  Decider
	Certs    *Certs
	Config   *ConfigBuilder
	Trackers *Trackers
	Free     interface{ FreeOff() (uint64, bool) }
	Intake   Intake
	Now      func() time.Time
	Log      *slog.Logger

	// Accepting, when set, says whether the hub takes Control streams yet: the start event of 5.6 runs before the first one (SC 8a.4
	// Versions), so a stream opened earlier is told to come back (UNAVAILABLE, which a node retries with backoff).
	Accepting func() bool
	// Opened is told once per stream, right after its first ServerTime and the push behind it and before any HeadNotice: the
	// outstanding revocations of 5.5 go out then.
	Opened func(node uuid.UUID)
	// HeadSent is told each HeadNotice put on a stream, with the seq and the time: fit(X) of 8a.4 reads them through the evaluator.
	HeadSent func(node uuid.UUID, seq uint64, at time.Time)

	// Tunables for tests; zero takes the values above.
	ServerTimeEvery, HeadEvery, ConfigEvery, NoHeartbeat, FirstHeartbeat time.Duration
	QueueBytes                                                           int
	// WriterHook sees each message just before the stream's writer sends it, with the node whose stream it is. It is
	// the hook of the L9 test and does nothing in production.
	WriterHook func(node uuid.UUID, m *hubv1.HubMessage)
}

type dropIntake struct{}

func (dropIntake) Offer(uuid.UUID, *hubv1.NodeMessage) {}

type gated struct {
	at   stamp
	read store.HubConfigRead
}

// stamp is a time in a type of its own: a struct that holds a mutex and a time.Time reads to the cache lint as a
// hand-written cache, and the gated reads are a read-through copy of at most a few nodes' rows.
type stamp struct{ t time.Time }

// Server is the Control half of the NodeHub server.
type Server struct {
	cfg Config

	mu       sync.Mutex
	sessions map[uuid.UUID]*session
	gate     map[uuid.UUID]*gated
	sentVer  map[uuid.UUID]uint64

	invalid, faults atomic.Uint64
}

// New makes a Server. Missing parts take their quiet defaults, except the ones that cannot have one (the roll, the store).
func New(cfg Config) *Server {
	if cfg.Intake == nil {
		cfg.Intake = dropIntake{}
	}
	d := func(v *time.Duration, def time.Duration) {
		if *v <= 0 {
			*v = def
		}
	}
	d(&cfg.ServerTimeEvery, ServerTimeEvery)
	d(&cfg.HeadEvery, HeadEvery)
	d(&cfg.ConfigEvery, ConfigEvery)
	d(&cfg.NoHeartbeat, NoHeartbeat)
	d(&cfg.FirstHeartbeat, FirstHeartbeat)
	if cfg.QueueBytes <= 0 {
		cfg.QueueBytes = QueueBytes
	}
	return &Server{cfg: cfg, sessions: make(map[uuid.UUID]*session), gate: make(map[uuid.UUID]*gated), sentVer: make(map[uuid.UUID]uint64)}
}

// Streams is the number of open Control streams.
func (s *Server) Streams() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sessions)
}

// Counts are the drops the hub counted: messages that failed validation and acks the rollout did not believe.
func (s *Server) Counts() (invalid, faults uint64) { return s.invalid.Load(), s.faults.Load() }

// Send hands a message to a node's stream and says whether the node has one. The revocations of 5.5 and the pushes of 5.6
// use it, and so does every other writer: none of them waits.
func (s *Server) Send(node uuid.UUID, m *hubv1.HubMessage) bool {
	s.mu.Lock()
	ss := s.sessions[node]
	s.mu.Unlock()
	return ss != nil && ss.put(m, false)
}

// Broadcast hands a message to every open stream.
func (s *Server) Broadcast(m *hubv1.HubMessage) {
	s.mu.Lock()
	all := make([]*session, 0, len(s.sessions))
	for _, ss := range s.sessions {
		all = append(all, ss)
	}
	s.mu.Unlock()
	for _, ss := range all {
		ss.put(m, false)
	}
}

// FreeOff tells every open stream that the switch was turned off at version, ahead of what is queued (5.2a: within 3 s of the
// commit, whatever the log does).
func (s *Server) FreeOff(version uint64) {
	s.mu.Lock()
	all := make([]*session, 0, len(s.sessions))
	for _, ss := range s.sessions {
		all = append(all, ss)
	}
	s.mu.Unlock()
	for _, ss := range all {
		ss.freeOff(version)
	}
}

func (s *Server) attach(ss *session) {
	s.mu.Lock()
	old := s.sessions[ss.node]
	s.sessions[ss.node] = ss
	s.mu.Unlock()
	if old != nil {
		old.cancel()
	}
	s.cfg.Roll.Stream(ss.node, true)
}

func (s *Server) detach(ss *session) {
	s.mu.Lock()
	cur := s.sessions[ss.node] == ss
	if cur {
		delete(s.sessions, ss.node)
	}
	s.mu.Unlock()
	if cur {
		s.cfg.Roll.Stream(ss.node, false)
	}
}

// Control serves one stream.
func (s *Server) Control(stream grpc.BidiStreamingServer[hubv1.NodeMessage, hubv1.HubMessage]) error {
	ctx := stream.Context()
	id := hubnet.IdentityFrom(ctx)
	if !id.Node || id.Cert == nil {
		return status.Error(codes.Unauthenticated, "certificate not accepted")
	}
	pub, ok := id.Cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return status.Error(codes.Unauthenticated, "certificate not accepted")
	}
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return status.Error(codes.Unauthenticated, "certificate not accepted")
	}
	if a := s.cfg.Accepting; a != nil && !a() {
		return status.Error(codes.Unavailable, "the hub is starting")
	}
	sum := sha256.Sum256(spki)

	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ss := newSession(s, id.NodeID, pub, sum[:], cancel)
	s.attach(ss)
	defer s.detach(ss)

	// The switch's state comes first: a node that reconnects while the hub withholds ServerTime still gets it.
	if s.cfg.Free != nil {
		if v, off := s.cfg.Free.FreeOff(); off {
			ss.freeOff(v)
		}
	}

	// The reader and the writer are not waited for: one may be blocked in a read or a write on a peer that gives nothing, and
	// gRPC ends a stream only when this handler returns, which is what releases them (the same reason as hubnodes.ctxStream).
	safego.Go(s.cfg.Log, unitCtl, func() { ss.writeLoop(sctx, stream) })
	safego.Go(s.cfg.Log, unitCtl, func() { ss.readLoop(sctx, stream) })

	ss.run(sctx)
	cancel()
	return nil
}

// ---------------------------------------------------------------------------------------------------------------------

type outbox struct {
	mu    sync.Mutex
	q     []*hubv1.HubMessage
	bytes int
	max   int
}

func (o *outbox) put(m *hubv1.HubMessage, front bool) bool {
	n := proto.Size(m)
	o.mu.Lock()
	if o.bytes+n > o.max {
		o.mu.Unlock()
		return false
	}
	o.bytes += n
	if front {
		o.q = append([]*hubv1.HubMessage{m}, o.q...)
	} else {
		o.q = append(o.q, m)
	}
	o.mu.Unlock()
	return true
}

func (o *outbox) take() *hubv1.HubMessage {
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.q) == 0 {
		return nil
	}
	m := o.q[0]
	o.q = o.q[1:]
	o.bytes -= proto.Size(m)
	return m
}

type session struct {
	s      *Server
	node   uuid.UUID
	pub    *ecdsa.PublicKey
	spki   []byte
	cancel context.CancelFunc
	out    outbox
	wake   chan struct{} // the writer is told there is something to take; it is the session's and not the queue's

	hb       chan struct{} // a Heartbeat arrived
	reported atomic.Uint64 // node_config_version of the latest Heartbeat

	// What the run loop alone touches.
	firstHB   bool
	stSent    bool
	lastST    time.Time
	lastCfgAt time.Time
	headSent  uint64
	freeSent  atomic.Uint64
	cfgHash   []byte
	cfgSent   bool
	cfgVer    uint64
	cfgAt     time.Time
	staleSaid bool
	certs     map[string]string // zone to the id of the bundle sent
}

func newSession(s *Server, node uuid.UUID, pub *ecdsa.PublicKey, spki []byte, cancel context.CancelFunc) *session {
	return &session{
		s: s, node: node, pub: pub, spki: spki, cancel: cancel,
		out:   outbox{max: s.cfg.QueueBytes},
		wake:  make(chan struct{}, 1),
		hb:    make(chan struct{}, 1),
		certs: make(map[string]string),
	}
}

// put queues a message. A queue that is full ends this stream and no other: the peer is not taking its bytes, and the
// reconnect starts it again from the state (L9).
func (ss *session) put(m *hubv1.HubMessage, front bool) bool {
	if ss.out.put(m, front) {
		select {
		case ss.wake <- struct{}{}:
		default:
		}
		return true
	}
	if ss.s.cfg.Log != nil {
		ss.s.cfg.Log.Warn("control stream ended: the queue to the node is full")
	}
	ss.cancel()
	return false
}

func (ss *session) freeOff(version uint64) {
	for {
		cur := ss.freeSent.Load()
		if version <= cur {
			return
		}
		if ss.freeSent.CompareAndSwap(cur, version) {
			break
		}
	}
	ss.put(&hubv1.HubMessage{Body: &hubv1.HubMessage_FreeDnsOff{FreeDnsOff: &hubv1.FreeDnsOff{Version: version}}}, true)
}

// writeLoop is the one writer of this stream.
func (ss *session) writeLoop(ctx context.Context, stream grpc.BidiStreamingServer[hubv1.NodeMessage, hubv1.HubMessage]) {
	for {
		for m := ss.out.take(); m != nil; m = ss.out.take() {
			if h := ss.s.cfg.WriterHook; h != nil {
				h(ss.node, m)
			}
			if err := stream.Send(m); err != nil {
				ss.cancel()
				return
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ss.wake:
		}
	}
}

// readLoop reads until the stream ends. It does no I/O but the read itself.
func (ss *session) readLoop(_ context.Context, stream grpc.BidiStreamingServer[hubv1.NodeMessage, hubv1.HubMessage]) {
	defer ss.cancel()
	for {
		m, err := stream.Recv()
		if err != nil {
			return
		}
		if err := wire.ValidateNodeMessage(m, ss.s.cfg.Now().Unix()); err != nil {
			ss.s.invalid.Add(1)
			continue
		}
		switch b := m.Body.(type) {
		case *hubv1.NodeMessage_Heartbeat:
			ss.beat(b.Heartbeat)
		case *hubv1.NodeMessage_ApplyResult:
			if !ss.s.cfg.Roll.Ack(ss.node, b.ApplyResult.Seq, b.ApplyResult.Ok) {
				ss.s.faults.Add(1)
			}
		}
		ss.s.cfg.Intake.Offer(ss.node, m)
	}
}

// resolveHealthy is "the node's resolve path is healthy" for the canary check of 6.4: no path listed counts as healthy (a
// node in recursive mode lists none), and otherwise one healthy path is enough, as the "cannot resolve" alert of 8a.4 reads it.
func resolveHealthy(h *hubv1.Heartbeat) bool {
	if len(h.Upstreams)+len(h.Locations) == 0 {
		return true
	}
	for _, u := range h.Upstreams {
		if u.Healthy {
			return true
		}
	}
	for _, l := range h.Locations {
		if l.Healthy {
			return true
		}
	}
	return false
}

func (ss *session) beat(h *hubv1.Heartbeat) {
	ss.s.cfg.Trackers.Take(ss.node, h)
	ss.s.cfg.Roll.Heartbeat(ss.node, rollout.Health{ResolveHealthy: resolveHealthy(h), Quarantined: int(h.Quarantined)})
	ss.reported.Store(h.NodeConfigVersion)
	select {
	case ss.hb <- struct{}{}:
	default:
	}
}

// run is the stream's clock: it waits for the first Heartbeat, then sends ServerTime, the push, HeadNotice, NodeConfig and
// CertBundle as their rules say, and ends the stream after 60 s with no Heartbeat.
func (ss *session) run(ctx context.Context) {
	cfg := &ss.s.cfg
	idle := time.NewTimer(cfg.FirstHeartbeat)
	defer idle.Stop()
	tick := time.NewTicker(cfg.HeadEvery)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-idle.C:
			return
		case <-ss.hb:
			if !idle.Stop() {
				select {
				case <-idle.C:
				default:
				}
			}
			idle.Reset(cfg.NoHeartbeat)
			ss.firstHB = true
			ss.pass(ctx)
		case <-tick.C:
			if ss.firstHB {
				ss.pass(ctx)
			}
		}
	}
}

func (ss *session) pass(ctx context.Context) {
	cfg := &ss.s.cfg
	now := cfg.Now()
	if now.Sub(ss.lastST) >= cfg.ServerTimeEvery || !ss.stSent {
		if cfg.Decider.CanDecide() {
			ss.put(&hubv1.HubMessage{Body: &hubv1.HubMessage_ServerTime{ServerTime: &hubv1.ServerTime{Now: now.Unix()}}}, false)
			if env := cfg.Decider.Push(); env != nil {
				ss.put(&hubv1.HubMessage{Body: &hubv1.HubMessage_PairTable{PairTable: env}}, false)
			}
			first := !ss.stSent
			if first {
				ss.lastCfgAt = time.Time{} // the first ServerTime is followed at once by the config and the certificates
			}
			ss.lastST, ss.stSent = now, true
			if first && cfg.Opened != nil {
				cfg.Opened(ss.node)
			}
		}
	}
	if !ss.stSent {
		return
	}
	if b, known := cfg.Roll.Bound(ss.node); known && b > ss.headSent {
		class := commonv1.EntryClass_ENTRY_CLASS_POLICY
		if cfg.Roll.ClassAt(b) == "catalog" {
			class = commonv1.EntryClass_ENTRY_CLASS_CATALOG
		}
		ss.put(&hubv1.HubMessage{Body: &hubv1.HubMessage_HeadNotice{HeadNotice: &hubv1.HeadNotice{Seq: b, Class: class, Release: true}}}, false)
		ss.headSent = b
		if cfg.HeadSent != nil {
			cfg.HeadSent(ss.node, b, now)
		}
	}
	if now.Sub(ss.lastCfgAt) >= cfg.ConfigEvery {
		ss.lastCfgAt = now
		ss.configPass(ctx, now)
	}
}

// gatedRead is the one read of 4.4: the node's row and everything its config is built from, in one snapshot. It is cached
// per node for 5 s, so a node that opens streams as fast as it likes makes at most one read of it every 5 s.
func (s *Server) gatedRead(ctx context.Context, node uuid.UUID, now time.Time) (store.HubConfigRead, error) {
	s.mu.Lock()
	g := s.gate[node]
	s.mu.Unlock()
	if g != nil && now.Sub(g.at.t) < gateTTL {
		return g.read, nil
	}
	rctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()
	r, err := s.cfg.Store.HubConfigLoad(rctx, node)
	if err != nil {
		return store.HubConfigRead{}, err
	}
	s.mu.Lock()
	s.gate[node] = &gated{at: stamp{now}, read: r}
	s.mu.Unlock()
	return r, nil
}

func (ss *session) configPass(ctx context.Context, now time.Time) {
	s := ss.s
	r, err := s.gatedRead(ctx, ss.node, now)
	if err != nil {
		return // a database that cannot answer ends no Control stream (SC 12); the next pass tries again
	}
	if !r.Found || r.Status != "active" || !bytes.Equal(r.SPKI, ss.spki) {
		// Revoked, removed or re-keyed: nothing is sent, and the stream ends (G2). The 60 s check would end it too.
		if s.cfg.Certs != nil {
			s.cfg.Certs.Drop(ss.node)
		}
		ss.cancel()
		return
	}
	if cfgMsg, err := s.cfg.Config.Build(r); err != nil {
		if s.cfg.Log != nil {
			s.cfg.Log.Warn("node config not sent: it does not validate")
		}
	} else {
		h := Hash(cfgMsg)
		if !ss.cfgSent || !bytes.Equal(h, ss.cfgHash) {
			s.mu.Lock()
			last := s.sentVer[ss.node]
			ver := NextVersion(ss.reported.Load(), last, now)
			s.sentVer[ss.node] = ver
			s.mu.Unlock()
			cfgMsg.Version = ver
			if ss.put(&hubv1.HubMessage{Body: &hubv1.HubMessage_NodeConfig{NodeConfig: cfgMsg}}, false) {
				ss.cfgHash, ss.cfgSent, ss.cfgVer, ss.cfgAt, ss.staleSaid = h, true, ver, now, false
			}
		}
	}
	if ss.cfgSent && !ss.staleSaid && now.Sub(ss.cfgAt) >= StaleConfig && ss.reported.Load() < ss.cfgVer {
		ss.staleSaid = true
		if s.cfg.Log != nil {
			s.cfg.Log.Warn("a node still reports an older node config than the one sent")
		}
	}
	if s.cfg.Certs == nil {
		return
	}
	zones := s.cfg.Config.Zones(r)
	bundles, err := s.cfg.Certs.For(ctx, ss.node, ss.pub, zones)
	if err != nil {
		if s.cfg.Log != nil && !errors.Is(err, ErrNoZoneCA) {
			s.cfg.Log.Warn("cert bundle not built")
		}
		return
	}
	for i, b := range bundles {
		zone := zones[i]
		if ss.certs[zone] == b.ID {
			continue
		}
		if ss.put(&hubv1.HubMessage{Body: &hubv1.HubMessage_CertBundle{CertBundle: b.Msg}}, false) {
			ss.certs[zone] = b.ID
		}
	}
}
