package hubfail_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	commonv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/common/v1"
	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	signv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/sign/v1"
	"github.com/Kup1ng/CtrlZ-Shared/manifest"
	"github.com/Kup1ng/CtrlZ-Shared/wire"

	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubctl"
	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubfail"
	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubprobe"
	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubsign"
	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubview"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

func id16(b byte) []byte   { return bytes.Repeat([]byte{b}, 16) }
func uid(b byte) uuid.UUID { return uuid.UUID(id16(b)) }

const (
	nodeA byte = 1 // the global pair's primary
	nodeB byte = 2 // its fallback
)

func node(n byte) *policyv1.NodeEntry {
	return &policyv1.NodeEntry{NodeId: id16(n), DnsIp: []byte{93, 184, 216, n}, ProxyIp: []byte{93, 184, 216, n}, SpkiSha256: bytes.Repeat([]byte{n}, 32), Slot: uint32(n)}
}

func membership() *policyv1.PairTable {
	return &policyv1.PairTable{
		GlobalPairId: id16(1), Nodes: []*policyv1.NodeEntry{node(nodeA), node(nodeB)},
		Pairs: []*policyv1.Pair{{PairId: id16(1), Primary: id16(nodeA), Fallback: id16(nodeB)}},
	}
}

// ---------------------------------------------------------------------------------------------------------------------

// db is the L4 pool's tables as a map: pair_event_state, the failover columns, and the requests.
type db struct {
	mu          sync.Mutex
	version     uint64
	last        []byte
	nodes       map[uuid.UUID]store.HubFailNode
	reqs        []store.HubFailRequest
	decided     map[uuid.UUID][2]string
	commits     int
	failRead    bool
	failCmt     bool
	failState   bool
	states      map[uuid.UUID]store.HubNodeState
	stateWrites int
	// afterCommit runs once the event is in the database and before the commit returns: the lease can be lost there.
	afterCommit func()
}

func newDB() *db {
	return &db{nodes: map[uuid.UUID]store.HubFailNode{uid(nodeA): {ID: uid(nodeA)}, uid(nodeB): {ID: uid(nodeB)}}, decided: map[uuid.UUID][2]string{}, states: map[uuid.UUID]store.HubNodeState{}}
}

func (d *db) HubFailRead(context.Context) (store.HubFailState, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.failRead {
		return store.HubFailState{}, errors.New("down")
	}
	st := store.HubFailState{Version: d.version, LastTable: d.last, Requests: append([]store.HubFailRequest(nil), d.reqs...)}
	for _, n := range d.nodes {
		st.Nodes = append(st.Nodes, n)
	}
	return st, nil
}

func (d *db) HubFailCommit(_ context.Context, ev store.HubFailEvent) (uint64, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.failCmt {
		return 0, errors.New("cannot commit")
	}
	if ev.Last != d.version {
		return 0, store.ErrFailMoved
	}
	v := d.version + 1
	if ms := uint64(ev.Now.UnixMilli()); ms > v {
		v = ms
	}
	tbl, err := ev.Table(v)
	if err != nil {
		return 0, err
	}
	for _, c := range ev.Changed {
		d.nodes[c.Node] = store.HubFailNode{ID: c.Node, Withdrawn: c.Withdrawn, Hold: c.Hold, LastFailbackAt: c.LastFailbackAt, FlapUntil: c.FlapUntil}
	}
	d.version, d.last = v, tbl
	if ev.Request != uuid.Nil {
		d.decided[ev.Request] = [2]string{"done", ""}
		var keep []store.HubFailRequest
		for _, r := range d.reqs {
			if r.ID != ev.Request {
				keep = append(keep, r)
			}
		}
		d.reqs = keep
	}
	d.commits++
	if d.afterCommit != nil {
		d.afterCommit()
	}
	return v, nil
}

func (d *db) HubFailDecide(_ context.Context, id uuid.UUID, state, reason string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.decided[id] = [2]string{state, reason}
	var keep []store.HubFailRequest
	for _, r := range d.reqs {
		if r.ID != id {
			keep = append(keep, r)
		}
	}
	d.reqs = keep
	return nil
}

func (d *db) HubNodeStateWrite(_ context.Context, rows []store.HubNodeState) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.failState {
		return errors.New("cannot write")
	}
	for _, r := range rows {
		d.states[r.Node] = r
	}
	d.stateWrites++
	return nil
}

func (d *db) state(n byte) store.HubNodeState {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.states[uid(n)]
}

func (d *db) node(n byte) store.HubFailNode { d.mu.Lock(); defer d.mu.Unlock(); return d.nodes[uid(n)] }
func (d *db) ver() uint64                   { d.mu.Lock(); defer d.mu.Unlock(); return d.version }

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type lease struct{ held bool }

func (l *lease) Held() bool { return l.held }

type sent struct {
	node uuid.UUID // zero for a broadcast
	env  *signv1.Envelope
}

type streams struct {
	mu   sync.Mutex
	open map[uuid.UUID]bool
	out  []sent
}

func (s *streams) Send(n uuid.UUID, m *hubv1.HubMessage) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.open[n] {
		return false
	}
	s.out = append(s.out, sent{n, m.GetPairTable()})
	return true
}

func (s *streams) Broadcast(m *hubv1.HubMessage) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.out = append(s.out, sent{uuid.Nil, m.GetPairTable()})
}

func (s *streams) count() int { s.mu.Lock(); defer s.mu.Unlock(); return len(s.out) }

type alerts struct {
	mu sync.Mutex
	by map[store.HubAlertKind][]map[string]string
}

func (a *alerts) raise(_ string, k store.HubAlertKind, p map[string]string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.by[k] = append(a.by[k], p)
}
func (a *alerts) of(k store.HubAlertKind) []map[string]string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.by[k]
}

type world struct {
	t      *testing.T
	clk    *clock
	db     *db
	view   *hubview.View
	beats  *hubctl.Trackers
	lease  *lease
	str    *streams
	alerts *alerts
	loop   *hubfail.Loop
	pub    ed25519.PublicKey
}

// newWorld has the two nodes in the log's latest membership, paired, and every flag as the database holds it.
func newWorld(t *testing.T) *world {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	w := &world{t: t, clk: &clock{t: time.Unix(1_800_000_000, 0)}, db: newDB(), view: hubview.New(), lease: &lease{held: true}, pub: pub,
		str: &streams{open: map[uuid.UUID]bool{}}, alerts: &alerts{by: map[store.HubAlertKind][]map[string]string{}}}
	w.beats = hubctl.NewTrackers(w.clk.Now)
	e := &policyv1.ConfigEntry{Seq: 1, Class: commonv1.EntryClass_ENTRY_CLASS_POLICY, CreatedAt: w.clk.Now().Unix(), PairTable: membership()}
	w.view.Apply(e)
	w.loop = hubfail.New(hubfail.Config{
		Store: w.db, View: w.view, Beats: w.beats, Lease: w.lease, Signer: hubsign.New(priv), Alert: w.alerts.raise, Now: w.clk.Now,
	})
	w.loop.SetSender(w.str)
	return w
}

// settled gives the database the state of a zone that has run for a while: the two nodes paired, neither withdrawn, last_table
// the membership, so the start event is the refresh and no F0 is due.
func (w *world) settled() {
	pt := membership()
	pt.Version = 5
	b, _ := proto.MarshalOptions{Deterministic: true}.Marshal(pt)
	w.db.version, w.db.last = 5, b
}

func (w *world) tick() { w.loop.Tick(context.Background()) }

func (w *world) peerView(known ...*hubv1.PeerProbe) []byte {
	pv := &hubv1.PeerView{Peers: known}
	b, err := wire.EncodePeerView(pv)
	if err != nil {
		w.t.Fatal(err)
	}
	return b
}

func (w *world) heartbeat(n byte, pv []byte, f func(*hubv1.Heartbeat)) {
	hb := &hubv1.Heartbeat{NodeTime: w.clk.Now().Unix(), PeerView: pv}
	if f != nil {
		f(hb)
	}
	w.beats.Take(uid(n), hb)
}

func (w *world) round(n byte, ok bool) {
	w.loop.Report(hubprobe.Result{Node: uid(n), At: w.clk.Now(), DoT: ok, DoH: ok})
}

// run ticks once a second for d, with every 5 s the traffic a healthy zone has, except what the caller turns off.
func (w *world) run(d time.Duration, every func(sec int)) {
	for i := 0; i < int(d/time.Second); i++ {
		w.clk.add(time.Second)
		if every != nil {
			every(i)
		}
		w.tick()
	}
}

func (w *world) verifyPush() *policyv1.PairTable {
	w.t.Helper()
	env := w.loop.Push()
	if env == nil {
		w.t.Fatal("no push")
	}
	root := &signv1.Root{Version: 1, ExpiresAt: 1 << 40, Threshold: 1,
		Keys:  []*signv1.PublicKey{{KeyId: manifest.KeyID(w.pub), Ed25519: w.pub}},
		Roles: []*signv1.RoleGrant{{Role: signv1.Role_ROLE_POLICY, KeyIds: [][]byte{manifest.KeyID(w.pub)}, Threshold: 1, ExpiresAt: 1 << 40}}}
	payload, err := manifest.Verify(env, root, signv1.Role_ROLE_POLICY, manifest.TypePairTable, w.clk.Now().Unix())
	if err != nil {
		w.t.Fatalf("the push does not verify: %v", err)
	}
	var pt policyv1.PairTable
	if err := proto.Unmarshal(payload, &pt); err != nil {
		w.t.Fatal(err)
	}
	if err := wire.ValidatePairTablePush(&pt); err != nil {
		w.t.Fatalf("a node would refuse the push: %v", err)
	}
	return &pt
}

func flags(pt *policyv1.PairTable) map[byte]bool {
	m := map[byte]bool{}
	for _, n := range pt.Nodes {
		m[n.NodeId[0]] = n.DnsWithdrawn
	}
	return m
}

// ---------------------------------------------------------------------------------------------------------------------

// The start event commits before the hub decides anything: F0 for a new pair (the primary starts withdrawn), the version at least
// the clock in milliseconds, the table persisted as the plain PairTable it signed, and the push signed after.
func TestTheStartEventCommitsThenSignsAndTheHubTakesStreams(t *testing.T) {
	w := newWorld(t)
	if w.loop.Started() || w.loop.Ready() || w.loop.Push() != nil {
		t.Fatal("started before any tick")
	}
	if _, known := w.loop.Point(1); known {
		t.Fatal("the release point is known before pair_event_state was read")
	}
	w.tick()
	if !w.loop.Started() {
		t.Fatal("the start event did not commit")
	}
	if got := w.db.ver(); got < uint64(w.clk.Now().UnixMilli()) {
		t.Fatalf("version %d is below the clock in ms %d", got, w.clk.Now().UnixMilli())
	}
	if !w.db.node(nodeA).Withdrawn || w.db.node(nodeB).Withdrawn {
		t.Fatal("F0: the primary of a pair that had no peer starts withdrawn")
	}
	pt := w.verifyPush()
	if f := flags(pt); !f[nodeA] || f[nodeB] {
		t.Fatalf("flags of the push %v", f)
	}
	if pt.Version != w.db.ver() || pt.ExpiresAt != w.clk.Now().Add(30*time.Minute).Unix() {
		t.Fatalf("version %d expires %d", pt.Version, pt.ExpiresAt)
	}
	var persisted policyv1.PairTable
	if err := proto.Unmarshal(w.db.last, &persisted); err != nil || !proto.Equal(&persisted, pt) {
		t.Fatalf("last_table is the plain serialised table of the event: %v", err)
	}
	if w.str.count() != 1 {
		t.Fatalf("the event is pushed to every connected node at once: %d", w.str.count())
	}
	if p, known := w.loop.Point(1); !known || p != 1 {
		t.Fatalf("release point %d %v", p, known)
	}
	if !w.loop.Ready() {
		t.Fatal("the hub cannot decide after its start event")
	}
}

// With nothing due the start event is the refresh: a new version, no flag changed.
func TestWithNothingDueTheStartEventIsTheRefresh(t *testing.T) {
	w := newWorld(t)
	w.settled()
	w.tick()
	if !w.loop.Started() || w.db.ver() <= 5 {
		t.Fatalf("started %v version %d", w.loop.Started(), w.db.ver())
	}
	if w.db.node(nodeA).Withdrawn || w.db.node(nodeB).Withdrawn {
		t.Fatal("a refresh changes no flag")
	}
	if f := flags(w.verifyPush()); f[nodeA] || f[nodeB] {
		t.Fatalf("flags %v", f)
	}
}

// A hub that does not hold the lease reads, and knows the release point, but signs nothing and says it cannot decide.
// H-r1-9: the lease is checked when the tick begins, and the commit can take long. An event whose commit returns after the lease
// was lost is in the database but is not signed, pushed or broadcast by this hub.
func TestALeaseLostDuringTheCommitSignsAndPushesNothing(t *testing.T) {
	w := newWorld(t)
	w.db.afterCommit = func() { w.lease.held = false }
	w.tick()
	if w.db.commits == 0 {
		t.Fatal("the start event did not commit")
	}
	if w.loop.Push() != nil || w.str.count() != 0 || w.loop.Ready() {
		t.Fatal("a hub that lost its lease inside the commit signed or pushed the event")
	}
}

func TestWithoutTheLeaseNothingIsSigned(t *testing.T) {
	w := newWorld(t)
	w.settled()
	w.lease.held = false
	w.run(5*time.Second, nil)
	if w.db.commits != 0 || w.loop.Started() || w.loop.Ready() || w.loop.Push() != nil || w.str.count() != 0 {
		t.Fatal("a hub without the lease decided")
	}
	if p, known := w.loop.Point(9); !known || p != 9 {
		t.Fatalf("the point is known from the read alone: %d %v", p, known)
	}
	w.lease.held = true
	w.run(2*time.Second, nil)
	if !w.loop.Started() || w.db.commits == 0 {
		t.Fatal("the lease came, and the start event did not run")
	}
}

// Row F1 end to end: the primary's rounds fail and its Heartbeats stop, the fallback's view of it is down, and after the row's 5 s
// the primary is withdrawn: committed, then signed, then pushed, with the alert naming the node.
func TestADeadPrimaryIsWithdrawnByRowF1AndPushed(t *testing.T) {
	w := newWorld(t)
	w.settled()
	w.str.open[uid(nodeB)] = true
	w.tick() // the start event: a refresh
	startVer := w.db.ver()
	aDown := &hubv1.PeerProbe{NodeId: id16(nodeA), Known: true, Down: true}
	var withdrawnAt int
	w.run(40*time.Second, func(i int) {
		if i%5 == 0 {
			w.round(nodeA, false)
			w.round(nodeB, true)
			w.heartbeat(nodeB, w.peerView(aDown), nil)
		}
		if withdrawnAt == 0 && w.db.node(nodeA).Withdrawn {
			withdrawnAt = i
		}
	})
	if !w.db.node(nodeA).Withdrawn || w.db.node(nodeB).Withdrawn {
		t.Fatal("the dead primary was not withdrawn")
	}
	// Probe down at the third failed round (about 15 s), the inputs 5 s without a break, and a tick of 1 s.
	if withdrawnAt < 15 || withdrawnAt > 27 {
		t.Fatalf("withdrawn after %d s", withdrawnAt)
	}
	if w.db.ver() <= startVer {
		t.Fatal("the event took no new version")
	}
	if f := flags(w.verifyPush()); !f[nodeA] || f[nodeB] {
		t.Fatalf("the push carries the flags after the event: %v", f)
	}
	if got := w.alerts.of(store.HubAlertFailWithdrawal); len(got) != 1 || got[0]["node"] != uid(nodeA).String() || got[0]["row"] != "F1" {
		t.Fatalf("withdrawal alert %v", got)
	}
	if w.str.count() < 2 {
		t.Fatal("the event was not broadcast")
	}
}

// A tick whose event cannot commit does not end: no signature, no push, no new ServerTime readiness after the bound, and the
// next tick that can commit does the event.
func TestAnEventThatCannotCommitSignsNothingAndTheTickDoesNotEnd(t *testing.T) {
	w := newWorld(t)
	w.settled()
	w.tick()
	if !w.loop.Ready() {
		t.Fatal("not ready after the start event")
	}
	before := w.loop.Push()
	pushes := w.str.count()
	w.db.mu.Lock()
	w.db.failCmt = true
	w.db.mu.Unlock()
	aDown := &hubv1.PeerProbe{NodeId: id16(nodeA), Known: true, Down: true}
	// A's rounds fail from the start; B is fine. The refresh falls due at 10 minutes: make F1 due instead by running to it.
	w.run(11*time.Minute, func(i int) {
		if i%5 == 0 {
			w.round(nodeA, false)
			w.round(nodeB, true)
			w.heartbeat(nodeB, w.peerView(aDown), nil)
			w.heartbeat(nodeA, w.peerView(), nil)
		}
	})
	if w.loop.Push() != before || w.str.count() != pushes {
		t.Fatal("something was signed or pushed while no event could commit")
	}
	if w.loop.Ready() {
		t.Fatal("ServerTime would still flow while no event can commit")
	}
	if len(w.alerts.of(store.HubAlertFailNotDecided)) == 0 {
		t.Fatal("no alert for an event that cannot commit")
	}
	w.db.mu.Lock()
	w.db.failCmt = false
	w.db.mu.Unlock()
	w.run(2*time.Second, nil)
	if w.loop.Push() == before || !w.loop.Ready() {
		t.Fatal("the loop did not recover")
	}
}

// A database that cannot be read keeps the read from succeeding: the hub says it cannot decide within the bound.
func TestAFailedReadStopsTheHubDecidingWithinTheBound(t *testing.T) {
	w := newWorld(t)
	w.settled()
	w.tick()
	w.db.mu.Lock()
	w.db.failRead = true
	w.db.mu.Unlock()
	w.run(9*time.Second, func(i int) {
		if i%5 == 0 {
			w.round(nodeA, true)
			w.round(nodeB, true)
		}
	})
	if !w.loop.Ready() {
		t.Fatal("not ready within the 10 s of the last read")
	}
	w.run(2*time.Second, nil)
	if w.loop.Ready() {
		t.Fatal("ready more than 10 s after the last successful read")
	}
}

// A prober that has completed no round of a node for 15 s keeps the hub from deciding.
func TestAStalledProberStopsTheHubDeciding(t *testing.T) {
	w := newWorld(t)
	w.settled()
	w.tick()
	w.run(14*time.Second, nil)
	if !w.loop.Ready() {
		t.Fatal("a new node has one round's grace")
	}
	w.run(2*time.Second, nil)
	if w.loop.Ready() {
		t.Fatal("no round of any node for more than 15 s")
	}
	w.round(nodeA, true)
	w.round(nodeB, true)
	w.tick()
	if !w.loop.Ready() {
		t.Fatal("a round of each node did not restore it")
	}
}

// Another writer moving pair_event_state makes the hub drop what it holds and start again, from the row.
func TestAMovedVersionRestartsTheLoop(t *testing.T) {
	w := newWorld(t)
	w.settled()
	w.tick()
	v := w.db.ver()
	w.db.mu.Lock()
	w.db.version = v + 1000
	w.db.mu.Unlock()
	w.tick()
	if w.db.ver() <= v+1000 || !w.loop.Started() {
		t.Fatalf("version %d started %v", w.db.ver(), w.loop.Started())
	}
}

// Requests: one that is too old is expired, one whose conditions fail is refused with the reason of the first, and one that can
// be carried out is done in the event's own transaction.
func TestRequestsAreExpiredRefusedOrDoneByTheirRow(t *testing.T) {
	w := newWorld(t)
	w.settled()
	w.db.nodes[uid(nodeB)] = store.HubFailNode{ID: uid(nodeB), Withdrawn: true, Hold: true}
	w.tick()
	stale, notHeld, release := uid(0xe1), uid(0xe2), uid(0xe3)
	w.db.mu.Lock()
	w.db.reqs = []store.HubFailRequest{
		{ID: stale, Node: uid(nodeA), Kind: "release", Age: 11 * time.Second, RequestedAt: w.clk.Now()},
		{ID: notHeld, Node: uid(nodeA), Kind: "release", Age: time.Second, RequestedAt: w.clk.Now().Add(time.Millisecond)},
		{ID: release, Node: uid(nodeB), Kind: "release", Age: time.Second, RequestedAt: w.clk.Now().Add(2 * time.Millisecond)},
	}
	w.db.mu.Unlock()
	w.clk.add(time.Second)
	w.tick()
	if got := w.db.decided[stale]; got[0] != "expired" {
		t.Fatalf("stale %v", got)
	}
	if got := w.db.decided[notHeld]; got != [2]string{"refused", "not_held"} {
		t.Fatalf("not held %v", got)
	}
	if got := w.db.decided[release]; got[0] != "done" || w.db.node(nodeB).Hold || !w.db.node(nodeB).Withdrawn {
		t.Fatalf("release %v node %+v: the hold clears and the node stays withdrawn", got, w.db.node(nodeB))
	}
	if len(w.alerts.of(store.HubAlertFailRelease)) != 1 {
		t.Fatalf("release alert %v", w.alerts.of(store.HubAlertFailRelease))
	}
}

// Push time 3: a node whose PeerView is behind the latest event is sent the push again, at most once per 5 s, and one that is
// current is not.
func TestALaggingPeerViewIsSentThePushOncePerFiveSeconds(t *testing.T) {
	w := newWorld(t)
	w.settled()
	w.str.open[uid(nodeB)] = true
	w.tick()
	base := w.str.count()
	behind := func() []byte {
		pv := &hubv1.PeerView{PairTableVersion: 1}
		b, _ := wire.EncodePeerView(pv)
		return b
	}
	w.run(4*time.Second, func(int) { w.heartbeat(nodeB, behind(), nil) })
	if w.str.count() != base {
		t.Fatalf("a send inside 5 s of the broadcast: %d", w.str.count()-base)
	}
	w.run(2*time.Second, func(int) { w.heartbeat(nodeB, behind(), nil) })
	if w.str.count() != base+1 {
		t.Fatalf("one catch-up push at 5 s: %d", w.str.count()-base)
	}
	w.run(3*time.Second, func(int) { w.heartbeat(nodeB, behind(), nil) })
	if w.str.count() != base+1 {
		t.Fatal("a second inside the next 5 s")
	}
	cur := func() []byte {
		b, _ := wire.EncodePeerView(&hubv1.PeerView{PairTableVersion: w.loop.Version()})
		return b
	}
	w.run(10*time.Second, func(int) { w.heartbeat(nodeB, cur(), nil) })
	if w.str.count() != base+1 {
		t.Fatal("a node that is current was sent the push")
	}
}

// "Cannot resolve" is an alert and nothing else: once when it begins, not again while it lasts, again after it clears.
func TestCannotResolveAlertsOnceAndMovesNothing(t *testing.T) {
	w := newWorld(t)
	w.settled()
	w.tick()
	bad := func(h *hubv1.Heartbeat) { h.Upstreams = []*hubv1.UpstreamHealth{{Id: id16(9), Healthy: false}} }
	good := func(h *hubv1.Heartbeat) { h.Upstreams = []*hubv1.UpstreamHealth{{Id: id16(9), Healthy: true}} }
	ver := w.db.ver()
	w.run(3*time.Second, func(int) { w.heartbeat(nodeA, nil, bad) })
	if got := w.alerts.of(store.HubAlertNodeCannotResolve); len(got) != 1 || got[0]["node"] != uid(nodeA).String() {
		t.Fatalf("alerts %v", got)
	}
	w.run(3*time.Second, func(int) { w.heartbeat(nodeA, nil, bad) })
	if len(w.alerts.of(store.HubAlertNodeCannotResolve)) != 1 {
		t.Fatal("the alert repeats while the condition lasts")
	}
	w.run(2*time.Second, func(int) { w.heartbeat(nodeA, nil, good) })
	w.run(2*time.Second, func(int) { w.heartbeat(nodeA, nil, bad) })
	if len(w.alerts.of(store.HubAlertNodeCannotResolve)) != 2 {
		t.Fatal("the alert did not come again after it cleared")
	}
	if w.db.ver() != ver {
		t.Fatal("the alert moved a flag")
	}
}

// The release point follows what the loop has committed: an entry that changes a node's peer waits for its event.
func TestTheReleasePointWaitsForTheEventOfAPairChange(t *testing.T) {
	w := newWorld(t)
	w.settled()
	// A third node and a log entry that pairs it with A instead of B.
	e := &policyv1.ConfigEntry{Seq: 2, Class: commonv1.EntryClass_ENTRY_CLASS_POLICY, CreatedAt: w.clk.Now().Unix(), PairTable: &policyv1.PairTable{
		GlobalPairId: id16(1), Nodes: []*policyv1.NodeEntry{node(nodeA), node(nodeB), node(3)},
		Pairs: []*policyv1.Pair{{PairId: id16(1), Primary: id16(nodeA), Fallback: id16(3)}},
	}}
	w.view.Apply(e)
	w.lease.held = false
	w.tick()
	if p, known := w.loop.Point(2); !known || p != 1 {
		t.Fatalf("the entry that changes a peer is held while F0 is due: %d %v", p, known)
	}
	w.lease.held = true
	w.tick() // the start event: F0 for the new pair
	if p, _ := w.loop.Point(2); p != 2 {
		t.Fatalf("the event committed, so the entry is released: %d", p)
	}
	if got := w.alerts.of(store.HubAlertFailMembership); len(got) != 1 {
		t.Fatalf("membership alert %v", got)
	}
}
