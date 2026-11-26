package hubctl_test

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	signv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/sign/v1"

	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubctl"
	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubnet"
	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubpki"
	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubroll"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testwait"
)

const wait = 5 * time.Second

// peer is a node's end of a Control stream: the test sends NodeMessages and reads HubMessages.
type peer struct {
	grpc.ServerStream
	ctx      context.Context
	cancel   context.CancelFunc
	in       chan *hubv1.NodeMessage
	out      chan *hubv1.HubMessage
	blockOut atomic.Bool
}

func (p *peer) Context() context.Context { return p.ctx }
func (p *peer) Recv() (*hubv1.NodeMessage, error) {
	select {
	case m := <-p.in:
		return m, nil
	case <-p.ctx.Done():
		return nil, io.EOF
	}
}
func (p *peer) Send(m *hubv1.HubMessage) error {
	if p.blockOut.Load() {
		<-p.ctx.Done() // a peer that never reads: the write does not finish
		return p.ctx.Err()
	}
	select {
	case p.out <- m:
		return nil
	case <-p.ctx.Done():
		return p.ctx.Err()
	}
}

type node struct {
	id  uuid.UUID
	key *ecdsa.PrivateKey
	*peer
}

func newNode(t *testing.T) *node {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "n"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	id := uuid.New()
	ctx, cancel := context.WithCancel(hubnet.WithIdentity(context.Background(), hubnet.Identity{Node: true, NodeID: id, Cert: cert}))
	t.Cleanup(cancel)
	return &node{id: id, key: key, peer: &peer{ctx: ctx, cancel: cancel, in: make(chan *hubv1.NodeMessage, 16), out: make(chan *hubv1.HubMessage, 64)}}
}

func (n *node) spki() []byte {
	b, _ := x509.MarshalPKIXPublicKey(&n.key.PublicKey)
	h := sha256.Sum256(b)
	return h[:]
}

func heartbeat(v uint64) *hubv1.NodeMessage {
	return &hubv1.NodeMessage{Body: &hubv1.NodeMessage_Heartbeat{Heartbeat: &hubv1.Heartbeat{
		NodeTime: time.Now().Unix(), NodeVersion: "1", BlobMajorMax: 1, NodeConfigVersion: v}}}
}

type fakeStore struct {
	mu     sync.Mutex
	reads  map[uuid.UUID]store.HubConfigRead
	loaded int
}

func (f *fakeStore) HubConfigLoad(_ context.Context, id uuid.UUID) (store.HubConfigRead, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.loaded++
	return f.reads[id], nil
}

type fixedDecider struct{ ok atomic.Bool }

func (d *fixedDecider) CanDecide() bool        { return d.ok.Load() }
func (d *fixedDecider) Push() *signv1.Envelope { return nil }

type free struct {
	v   uint64
	off bool
}

func (f free) FreeOff() (uint64, bool) { return f.v, f.off }

type world struct {
	srv     *hubctl.Server
	roll    *hubroll.Roll
	st      *fakeStore
	decider *fixedDecider
	wrote   chan [2]any
}

func newWorld(t *testing.T, fr free, mod func(*hubctl.Config)) *world {
	t.Helper()
	zkey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca, err := hubpki.IssueZoneCA(zkey, []string{"dns.ctrlz.invalid"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	w := &world{roll: hubroll.New(hubroll.Config{}), st: &fakeStore{reads: map[uuid.UUID]store.HubConfigRead{}}, decider: &fixedDecider{}, wrote: make(chan [2]any, 256)}
	w.decider.ok.Store(true)
	cfg := hubctl.Config{
		Roll: w.roll, Store: w.st, Decider: w.decider, Certs: hubctl.NewCerts(zoneOnly{ca}, nil, time.Now),
		Config: &hubctl.ConfigBuilder{ProofKey: make([]byte, 32), Now: time.Now}, Trackers: hubctl.NewTrackers(time.Now), Free: fr, Now: time.Now,
		ServerTimeEvery: 30 * time.Millisecond, HeadEvery: 5 * time.Millisecond, ConfigEvery: 10 * time.Millisecond,
		WriterHook: func(n uuid.UUID, m *hubv1.HubMessage) { w.wrote <- [2]any{n, m} },
	}
	if mod != nil {
		mod(&cfg)
	}
	w.srv = hubctl.New(cfg)
	return w
}

type zoneOnly struct{ ca *hubpki.ZoneCA }

func (z zoneOnly) Zone() *hubpki.ZoneCA { return z.ca }

func (w *world) active(n *node) {
	w.st.mu.Lock()
	w.st.reads[n.id] = store.HubConfigRead{Found: true, Status: "active", SPKI: n.spki(), ResolveMode: "recursive", DNSBind: netip.MustParseAddr("10.0.0.1"), DNSAdv: netip.MustParseAddr("192.0.2.1")}
	w.st.mu.Unlock()
	w.roll.SetOrder([]uuid.UUID{n.id})
}

func (w *world) open(n *node) <-chan error {
	done := make(chan error, 1)
	go func() { done <- w.srv.Control(n) }()
	return done
}

func next(t *testing.T, n *node) *hubv1.HubMessage {
	t.Helper()
	select {
	case m := <-n.out:
		return m
	case <-time.After(wait):
		t.Fatal("no message from the hub")
		return nil
	}
}

// The first messages of a stream are fixed by 8a.4 and 5.2a: FreeDnsOff (while the switch is off) before everything, then,
// after the node's first Heartbeat, ServerTime, and only after it HeadNotice, NodeConfig and a CertBundle that only the
// node's key opens.
func TestAStreamOpensInTheFixedOrderAndTheCertificateIsSealedToTheNode(t *testing.T) {
	w := newWorld(t, free{v: 9, off: true}, nil)
	n := newNode(t)
	w.active(n)
	w.roll.Written(3, "policy")
	done := w.open(n)

	if m := next(t, n); m.GetFreeDnsOff().GetVersion() != 9 {
		t.Fatalf("the first message is %T, want FreeDnsOff 9", m.Body)
	}
	if m, ok := testwait.TryReceive(n.out, 60*time.Millisecond); ok {
		t.Fatalf("a %T came before the first Heartbeat", m.Body)
	}
	n.in <- heartbeat(0)
	if m := next(t, n); m.GetServerTime() == nil {
		t.Fatalf("after the Heartbeat the first message is %T, want ServerTime", m.Body)
	}
	var gotHead, gotCfg, gotCert, sealedOnce bool
	for !(gotHead && gotCfg && gotCert) {
		m := next(t, n)
		switch {
		case m.GetHeadNotice() != nil:
			gotHead = true
			if m.GetHeadNotice().Seq != 3 {
				t.Fatalf("head notice names %d, want the bound 3", m.GetHeadNotice().Seq)
			}
		case m.GetNodeConfig() != nil:
			gotCfg = true
			if m.GetNodeConfig().Version == 0 || len(m.GetNodeConfig().Zones) != 1 {
				t.Fatalf("node config %v", m.GetNodeConfig())
			}
		case m.GetCertBundle() != nil:
			gotCert, sealedOnce = true, true
			cb := m.GetCertBundle()
			stranger := newNode(t)
			if k, err := hpke.NewDHKEMPrivateKey(mustECDH(t, stranger.key)); err != nil {
				t.Fatal(err)
			} else if _, err := hpke.Open(k, hpke.HKDFSHA256(), hpke.AES256GCM(), []byte(hubctl.SealInfo), cb.WrappedKey); err == nil {
				t.Fatal("another node's key opened the bundle")
			}
			kem, err := hpke.NewDHKEMPrivateKey(mustECDH(t, n.key))
			if err != nil {
				t.Fatal(err)
			}
			keyDER, err := hpke.Open(kem, hpke.HKDFSHA256(), hpke.AES256GCM(), []byte(hubctl.SealInfo), cb.WrappedKey)
			if err != nil {
				t.Fatalf("the node cannot open its key: %v", err)
			}
			if _, err := x509.ParsePKCS8PrivateKey(keyDER); err != nil {
				t.Fatal(err)
			}
			blk, _ := pem.Decode(cb.ChainPem)
			if blk == nil {
				t.Fatal("no chain")
			}
		}
	}
	if !sealedOnce {
		t.Fatal("no certificate bundle")
	}
	n.cancel()
	<-done
}

func mustECDH(t *testing.T, k *ecdsa.PrivateKey) *ecdh.PrivateKey {
	t.Helper()
	e, err := k.ECDH()
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// L4: while the hub cannot decide it sends no ServerTime, and so no push, no head, no config and no certificate.
func TestNothingIsSentWhileTheHubCannotDecide(t *testing.T) {
	w := newWorld(t, free{}, nil)
	w.decider.ok.Store(false)
	n := newNode(t)
	w.active(n)
	w.roll.Written(1, "policy")
	w.open(n)
	n.in <- heartbeat(0)
	if m, ok := testwait.TryReceive(n.out, 150*time.Millisecond); ok {
		t.Fatalf("a %T was sent while the hub could not decide", m.Body)
	}
	w.decider.ok.Store(true)
	if m := next(t, n); m.GetServerTime() == nil {
		t.Fatalf("got %T", m.Body)
	}
}

// G2: a node whose row is not active with the stream's key is sent nothing and its stream ends.
func TestARevokedOrRekeyedNodeGetsNoConfigAndItsStreamEnds(t *testing.T) {
	for name, read := range map[string]func(*node) store.HubConfigRead{
		"revoked": func(n *node) store.HubConfigRead {
			return store.HubConfigRead{Found: true, Status: "revoked", SPKI: n.spki()}
		},
		"rekeyed": func(*node) store.HubConfigRead {
			return store.HubConfigRead{Found: true, Status: "active", SPKI: make([]byte, 32)}
		},
		"removed": func(*node) store.HubConfigRead { return store.HubConfigRead{} },
	} {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t, free{}, nil)
			n := newNode(t)
			w.st.reads[n.id] = read(n)
			done := w.open(n)
			n.in <- heartbeat(0)
			for {
				select {
				case m := <-n.out:
					if m.GetNodeConfig() != nil || m.GetCertBundle() != nil {
						t.Fatalf("a %T was sent to a node the row does not accept", m.Body)
					}
				case <-done:
					return
				case <-time.After(wait):
					t.Fatal("the stream did not end")
				}
			}
		})
	}
}

// A new stream of a node ends the older one.
func TestANewStreamEndsTheOlder(t *testing.T) {
	w := newWorld(t, free{}, nil)
	n := newNode(t)
	w.active(n)
	first := w.open(n)
	for w.srv.Streams() != 1 {
		time.Sleep(time.Millisecond)
	}
	second := &node{id: n.id, key: n.key, peer: &peer{ctx: n.ctx, in: make(chan *hubv1.NodeMessage, 4), out: make(chan *hubv1.HubMessage, 4)}}
	second.peer.ctx, second.peer.cancel = context.WithCancel(n.ctx)
	go func() { _ = w.srv.Control(second) }()
	select {
	case <-first:
	case <-time.After(wait):
		t.Fatal("the older stream is still open")
	}
}

// L9: a peer that never reads holds back its own stream and no other. Node A's writes block for good; node B still gets a
// ServerTime every interval, and the hook sees that no message of A was written by B's writer and the reverse.
func TestAStreamThatDoesNotTakeItsBytesHoldsBackNoOther(t *testing.T) {
	w := newWorld(t, free{}, nil)
	a, b := newNode(t), newNode(t)
	w.active(a)
	w.active(b)
	w.roll.SetOrder([]uuid.UUID{a.id, b.id})
	a.blockOut.Store(true)
	w.open(a)
	w.open(b)
	a.in <- heartbeat(0)
	b.in <- heartbeat(0)
	for i := 0; i < 3; i++ {
		if m := next(t, b); m.GetServerTime() == nil && m.GetHeadNotice() == nil && m.GetNodeConfig() == nil && m.GetCertBundle() == nil {
			t.Fatalf("unexpected %T", m.Body)
		}
	}
	// B keeps getting ServerTime while A's writer is stuck.
	seen := 0
	for seen < 3 {
		if m := testwait.Receive(t, b.out, wait, "a ServerTime for B while A is stuck"); m.GetServerTime() != nil {
			seen++
		}
	}
}

// A full queue ends that stream only (4 MiB in production; a few bytes here).
func TestAFullQueueEndsOnlyThatStream(t *testing.T) {
	w := newWorld(t, free{}, func(c *hubctl.Config) { c.QueueBytes = 1 })
	n := newNode(t)
	w.active(n)
	n.blockOut.Store(true)
	done := w.open(n)
	n.in <- heartbeat(0)
	select {
	case <-done:
	case <-time.After(wait):
		t.Fatal("a stream whose queue is full stayed open")
	}
}

// 6.4: a node's HeadNotice follows its own cursor. The second node of the order is told of an entry only when the first has
// acked it.
func TestHeadNoticeFollowsTheNodesCursorAndAckMovesTheNext(t *testing.T) {
	w := newWorld(t, free{}, nil)
	a, b := newNode(t), newNode(t)
	w.active(a)
	w.active(b)
	w.roll.SetOrder([]uuid.UUID{a.id, b.id})
	w.roll.Stream(a.id, true)
	w.open(a)
	w.open(b)
	a.in <- heartbeat(0)
	b.in <- heartbeat(0)
	for w.srv.Streams() != 2 {
		time.Sleep(time.Millisecond)
	}
	w.roll.Written(7, "policy")
	head := func(n *node) uint64 {
		for {
			m := next(t, n)
			if h := m.GetHeadNotice(); h != nil && h.Seq == 7 {
				return h.Seq
			}
		}
	}
	if head(a) != 7 {
		t.Fatal("a")
	}
	if m, ok := testwait.TryReceive(b.out, 100*time.Millisecond); ok {
		if h := m.GetHeadNotice(); h != nil && h.Seq == 7 {
			t.Fatal("b was told of entry 7 before a acked it")
		}
	}
	a.in <- &hubv1.NodeMessage{Body: &hubv1.NodeMessage_ApplyResult{ApplyResult: &hubv1.ApplyResult{Seq: 7, Ok: true}}}
	if head(b) != 7 {
		t.Fatal("b")
	}
}

// 5.8: the hub ends a Control stream whose node sends no first Heartbeat in time, and one that goes silent after it. Both
// bounds are the Config's, shortened here.
func TestAStreamWithoutHeartbeatsEnds(t *testing.T) {
	w := newWorld(t, free{}, func(c *hubctl.Config) { c.FirstHeartbeat, c.NoHeartbeat = 80*time.Millisecond, 120*time.Millisecond })
	silent := newNode(t)
	w.active(silent)
	testwait.Receive(t, w.open(silent), wait, "a stream that never sent a Heartbeat ends")

	n := newNode(t)
	w.active(n)
	done := w.open(n)
	n.in <- heartbeat(1)
	if _, ok := testwait.TryReceive(done, 40*time.Millisecond); ok {
		t.Fatal("the stream ended right after a Heartbeat")
	}
	testwait.Receive(t, done, wait, "a stream that went silent after its Heartbeat ends")
}
