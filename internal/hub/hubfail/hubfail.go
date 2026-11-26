// Package hubfail is the hub's failover loop (p4-nodes 5.6, SC 8a.4 and 8a.6): the 1 s evaluation tick under the hub-decider
// lease, on a database connection of its own (L4), that runs the decision table of shared/zone over the trackers the hub keeps
// in memory, commits each signing event with its flags and its version in one transaction, signs the PairTable only after the
// commit, and pushes it.
//
// What lives where. The decision itself is shared/zone's Evaluator (rows, inputs, flap and drain are data there, and the node's
// local mode and the vector generator read the same ones). This package is the glue the evaluator leaves to the hub:
//
//   - the inputs: the latest Heartbeat of each node (hubctl.Trackers), the prober's completed rounds, the HeadNotices sent;
//   - the persisted state: the failover columns, pair_event_state (version and last_table, the plain serialised PairTable the
//     last event signed) and node_dns_requests, read once a tick in one snapshot;
//   - the start event, which runs before the hub accepts any Control stream;
//   - signing: the event's PairTable, committed first, signed with the policy key after (the hub never signs an event that has
//     not committed, and never from a cached version: the version is chosen inside the transaction);
//   - the four push times and the release point of L12;
//   - the readiness the hub's ServerTime depends on (L4): a tick that ended, a read that succeeded, a prober that has completed a
//     round of every node, each recently enough. A tick whose event fails to commit does not count as ended.
package hubfail

import (
	"context"
	"errors"
	"log/slog"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	signv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/sign/v1"
	"github.com/Kup1ng/CtrlZ-Shared/manifest"
	"github.com/Kup1ng/CtrlZ-Shared/wire"
	"github.com/Kup1ng/CtrlZ-Shared/zone"

	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubprobe"
	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubsign"
	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubview"
	"github.com/Kup1ng/CtrlZ-Panel/internal/safego"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

type unit string

const unitFail unit = "hub_failover"

func (u unit) Valid() bool { return u == unitFail }

// The numbers of 8a.4 and 8a.11 L4.
const (
	// TickEvery is the evaluation tick.
	TickEvery = time.Second
	// PushLife is how long a signed PairTable stays valid on a node.
	PushLife = 30 * time.Minute
	// CatchUp is the least time between two pushes to a node whose PeerView is behind (push time 3).
	CatchUp = 5 * time.Second
	// TickFresh and ReadFresh are how recent the last ended tick and the last successful read of pair_event_state must be for the
	// hub to send ServerTime; RoundFresh is the same for the prober's round of each node.
	TickFresh  = 10 * time.Second
	ReadFresh  = 10 * time.Second
	RoundFresh = 15 * time.Second
	// HeartbeatFresh is the age at which a Heartbeat no longer counts for the "cannot resolve" alert and the catch-up push.
	HeartbeatFresh = 15 * time.Second
	// notCommittedEvery rate-limits the alert for an event that cannot commit.
	notCommittedEvery = time.Minute
)

// Store is the L4 pool's work.
type Store interface {
	HubFailRead(ctx context.Context) (store.HubFailState, error)
	HubFailCommit(ctx context.Context, ev store.HubFailEvent) (uint64, error)
	HubFailDecide(ctx context.Context, id uuid.UUID, state, reason string) error
	// HubNodeStateWrite writes what the admin page shows of each node's return and drain (T-542). A failed write is retried by the
	// next tick and never stops the loop.
	HubNodeStateWrite(ctx context.Context, states []store.HubNodeState) error
}

// Membership is the hub's log view as the loop reads it.
type Membership interface {
	// Membership is the PairTable of the latest entry that carried one.
	Membership() (t *policyv1.PairTable, seq uint64, found bool)
	// ReleasePoint is the release point of L12 for the pair peers of last_table.
	ReleasePoint(last map[string]string, latest uint64) uint64
}

// Beats are the hub's Heartbeat trackers.
type Beats interface {
	Latest(node uuid.UUID) (hb *hubv1.Heartbeat, at time.Time, found bool)
}

// Lease says whether this process holds hub-decider.
type Lease interface{ Held() bool }

// Sender puts messages on streams.
type Sender interface {
	Send(node uuid.UUID, m *hubv1.HubMessage) bool
	Broadcast(m *hubv1.HubMessage)
}

// Config is what a Loop is built from.
type Config struct {
	Store  Store
	View   Membership
	Beats  Beats
	Lease  Lease
	Signer *hubsign.Signer
	// Alert raises an alert on the telemetry pool; nil raises none.
	Alert func(severity string, kind store.HubAlertKind, params map[string]string)
	// Probing says whether the prober probes at all (it does not while no live zone is known); nil means it does.
	Probing func() bool
	Now     func() time.Time
	Log     *slog.Logger
	// Tick replaces TickEvery, for tests.
	Tick time.Duration
}

type pushState struct {
	env     *signv1.Envelope
	version uint64
}

type peersBox struct{ m map[string]string }

type headNote struct {
	node uuid.UUID
	seq  uint64
	at   time.Time
}

type roundNote struct {
	node     uuid.UUID
	at       time.Time
	dot, doh bool
}

// stamp is a time in a type of its own, so a struct that holds a mutex and a time.Time does not read as a hand-written cache.
type stamp struct{ t time.Time }

// Loop is the failover loop.
type Loop struct {
	cfg  Config
	send atomic.Pointer[senderBox]

	// What the prober and the streams hand in. The evaluator is not safe for concurrent use, so they queue here and the tick
	// takes everything at its start.
	mu      sync.Mutex
	heads   []headNote
	rounds  []roundNote
	round   map[uuid.UUID]stamp // when each node's latest round completed
	entered map[uuid.UUID]stamp // when each node of the membership entered it: a new node gets one round's grace
	targets []hubprobe.Target

	// What the tick alone touches.
	ev       *zone.Evaluator
	pt       *policyv1.PairTable
	ptSeq    uint64
	ptSet    bool
	version  uint64
	relVer   uint64
	relSeen  bool
	fed      map[uuid.UUID]stamp
	pvVer    map[uuid.UUID]uint64
	pushedTo map[uuid.UUID]stamp
	eventAt  stamp
	cannot   map[uuid.UUID]bool
	failAt   stamp

	// What the admin page shows (state.go): the table the latest event of this process signed, the drain of each node as the hub
	// sees it, and the rows last written, so a row is written when it changes and not on every tick.
	tbl        *zone.Table
	tblVer     uint64
	drains     map[uuid.UUID]*zone.Drain
	drainSince map[uuid.UUID]time.Time
	drainFed   map[uuid.UUID]uint64
	drainSeen  map[uuid.UUID]bool
	fullAt     stamp
	written    map[uuid.UUID]store.HubNodeState
	stateFail  stamp
	ctx        context.Context

	// What other goroutines read.
	started atomic.Bool
	tickEnd atomic.Int64
	readOK  atomic.Int64
	push    atomic.Pointer[pushState]
	peers   atomic.Pointer[peersBox]
}

type senderBox struct{ s Sender }

// New makes a Loop.
func New(cfg Config) *Loop {
	if cfg.Tick <= 0 {
		cfg.Tick = TickEvery
	}
	return &Loop{
		cfg: cfg, round: map[uuid.UUID]stamp{}, entered: map[uuid.UUID]stamp{}, fed: map[uuid.UUID]stamp{},
		pvVer: map[uuid.UUID]uint64{}, pushedTo: map[uuid.UUID]stamp{}, cannot: map[uuid.UUID]bool{},
		drains: map[uuid.UUID]*zone.Drain{}, drainSince: map[uuid.UUID]time.Time{}, drainFed: map[uuid.UUID]uint64{}, drainSeen: map[uuid.UUID]bool{}, written: map[uuid.UUID]store.HubNodeState{},
	}
}

// SetSender gives the loop the streams to push on. The Control server is built after the loop (it needs the loop as its
// Decider), so the hub sets it here.
func (l *Loop) SetSender(s Sender) { l.send.Store(&senderBox{s}) }

// Started says the start event has committed under the lease: the hub takes Control streams from then on (SC 8a.4 Versions).
func (l *Loop) Started() bool { return l.started.Load() }

// Push is the latest signed PairTable, nil before the start event.
func (l *Loop) Push() *signv1.Envelope {
	if p := l.push.Load(); p != nil {
		return p.env
	}
	return nil
}

// Version is the version of the latest event this process committed, 0 before one.
func (l *Loop) Version() uint64 {
	if p := l.push.Load(); p != nil {
		return p.version
	}
	return 0
}

// Point is the release point of L12 (hubroll.Release): known only once pair_event_state has been read.
func (l *Loop) Point(latest uint64) (uint64, bool) {
	p := l.peers.Load()
	if p == nil {
		return 0, false
	}
	return l.cfg.View.ReleasePoint(p.m, latest), true
}

// NoteHead records a HeadNotice sent to a node: fit(X) reads them (8a.4).
func (l *Loop) NoteHead(node uuid.UUID, seq uint64, at time.Time) {
	l.mu.Lock()
	l.heads = append(l.heads, headNote{node, seq, at})
	l.mu.Unlock()
}

// Report is the prober's callback: one completed round of one node.
func (l *Loop) Report(r hubprobe.Result) {
	l.mu.Lock()
	l.rounds = append(l.rounds, roundNote{r.Node, r.At, r.DoT, r.DoH})
	l.round[r.Node] = stamp{r.At}
	l.mu.Unlock()
}

// Targets is every node of the latest membership with its advertised address: what the prober probes.
func (l *Loop) Targets() []hubprobe.Target {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]hubprobe.Target(nil), l.targets...)
}

// Ready is the hub's "can decide" (8a.11 L4): the start event has committed under a lease the hub holds, and its last tick ended,
// its last read of pair_event_state succeeded and its prober completed a round of every node, each recently enough. Each part
// fails closed.
func (l *Loop) Ready() bool {
	now := l.cfg.Now()
	if !l.started.Load() || l.cfg.Lease == nil || !l.cfg.Lease.Held() {
		return false
	}
	if now.Sub(time.Unix(0, l.tickEnd.Load())) > TickFresh || now.Sub(time.Unix(0, l.readOK.Load())) > ReadFresh {
		return false
	}
	if l.cfg.Probing != nil && !l.cfg.Probing() {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, t := range l.targets {
		last := l.round[t.ID].t
		if e := l.entered[t.ID].t; e.After(last) {
			last = e
		}
		if now.Sub(last) > RoundFresh {
			return false
		}
	}
	return true
}

// Run ticks until ctx ends.
func (l *Loop) Run(ctx context.Context) {
	t := time.NewTicker(l.cfg.Tick)
	defer t.Stop()
	for {
		func() {
			defer safego.Keep(l.cfg.Log, unitFail)
			l.Tick(ctx)
		}()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (l *Loop) alert(sev string, kind store.HubAlertKind, params map[string]string) {
	if l.cfg.Alert != nil {
		l.cfg.Alert(sev, kind, params)
	}
}

func (l *Loop) reset() {
	l.ev = nil
	l.started.Store(false)
	l.fed = map[uuid.UUID]stamp{}
	l.pvVer = map[uuid.UUID]uint64{}
	l.pushedTo = map[uuid.UUID]stamp{}
	l.cannot = map[uuid.UUID]bool{}
	l.resetState()
}

// Tick runs one evaluation tick. The hub calls it from Run; tests call it with a test clock.
func (l *Loop) Tick(ctx context.Context) {
	now := l.cfg.Now()
	l.ctx = ctx
	st, err := l.cfg.Store.HubFailRead(ctx)
	if err != nil {
		return // the tick has not ended and the read has not succeeded: ServerTime stops within the L4 bounds
	}
	l.readOK.Store(now.UnixNano())
	l.release(st)
	if l.ev == nil {
		// What came in before a start event describes a hub that has not decided yet: every tracker starts unknown (8a.4).
		l.mu.Lock()
		l.heads, l.rounds = nil, nil
		l.mu.Unlock()
	}
	if l.cfg.Lease == nil || !l.cfg.Lease.Held() {
		if l.ev != nil {
			l.reset()
		}
		return
	}
	if l.ev != nil && st.Version != l.version {
		// Another writer moved pair_event_state: this process no longer decides from what it holds.
		l.reset()
	}
	l.membership(now)
	if l.ev == nil {
		if !l.start(now, st) {
			return
		}
		l.tickEnd.Store(now.UnixNano())
		return
	}
	l.drain()
	reqs := make([]zone.Request, 0, len(st.Requests))
	for _, r := range st.Requests {
		reqs = append(reqs, zone.Request{ID: r.ID.String(), Node: zone.NodeID(r.Node), Kind: zone.RequestKind(r.Kind), RequestedAt: r.RequestedAt, Age: r.Age})
	}
	outs, err := l.ev.Tick(now, reqs, l.commit)
	l.after(outs)
	if err != nil {
		l.notCommitted(now)
		return
	}
	l.tickEnd.Store(now.UnixNano())
	l.catchUp(now)
	l.cannotResolve(now)
	l.feedDrains()
	l.publishState(ctx, now)
}

// release keeps the pair peers of last_table, the input of the release point, as pair_event_state holds them. The point is
// unknown until the first read, and a last_table that does not parse leaves it unknown: the hub then serves nothing, which is
// what a log it cannot judge asks for.
func (l *Loop) release(st store.HubFailState) {
	if l.relSeen && st.Version == l.relVer {
		return
	}
	pt := &policyv1.PairTable{}
	if len(st.LastTable) > 0 {
		if err := proto.Unmarshal(st.LastTable, pt); err != nil {
			if l.cfg.Log != nil {
				l.cfg.Log.Error("pair_event_state holds a table that does not parse")
			}
			return
		}
	}
	l.peers.Store(&peersBox{hubview.PeersOf(pt)})
	l.relVer, l.relSeen = st.Version, true
}

// membership takes the hub's latest membership from the log view into the tick: the PairTable of the latest entry that carried
// one, as a zone.Table for the evaluator. A table the zone builder refuses is not taken (the log carries only tables the
// compiler checked, so this is a defect of the log, and the previous membership stands).
func (l *Loop) membership(now time.Time) {
	pt, seq, found := l.cfg.View.Membership()
	if l.ptSet && seq == l.ptSeq {
		return
	}
	if !found {
		pt = &policyv1.PairTable{}
	}
	t, err := zone.Build(wire.ZoneInput(pt))
	if err != nil {
		if l.cfg.Log != nil {
			l.cfg.Log.Error("the latest membership does not build")
		}
		return
	}
	l.pt, l.ptSeq, l.ptSet = pt, seq, true
	targets := make([]hubprobe.Target, 0, len(t.Nodes))
	for id, n := range t.Nodes {
		targets = append(targets, hubprobe.Target{ID: uuid.UUID(id), Addr: n.DNSIP})
	}
	sort.Slice(targets, func(i, j int) bool { return string(targets[i].ID[:]) < string(targets[j].ID[:]) })
	l.mu.Lock()
	known := map[uuid.UUID]bool{}
	for _, tg := range targets {
		known[tg.ID] = true
		if _, ok := l.entered[tg.ID]; !ok {
			l.entered[tg.ID] = stamp{now}
		}
	}
	for id := range l.entered {
		if !known[id] {
			delete(l.entered, id)
			delete(l.round, id)
		}
	}
	l.targets = targets
	l.mu.Unlock()
	if l.ev != nil {
		if err := l.ev.SetMembership(now, t); err != nil && l.cfg.Log != nil {
			l.cfg.Log.Error("the evaluator refused the membership")
		}
	}
}

func (l *Loop) memberTable() *zone.Table {
	t, err := zone.Build(wire.ZoneInput(l.pt))
	if err != nil {
		return nil
	}
	return t
}

// start builds the evaluator from the persisted state and runs the start event (8a.4 Versions). It reports whether the event
// committed; the hub takes Control streams only after it has.
func (l *Loop) start(now time.Time, st store.HubFailState) bool {
	if !l.ptSet {
		l.membership(now)
		if !l.ptSet {
			return false
		}
	}
	member := l.memberTable()
	if member == nil {
		return false
	}
	var last *zone.Table
	if len(st.LastTable) > 0 {
		var lp policyv1.PairTable
		if err := proto.Unmarshal(st.LastTable, &lp); err != nil {
			return false
		}
		t, err := zone.Build(wire.ZoneInput(&lp))
		if err != nil {
			if l.cfg.Log != nil {
				l.cfg.Log.Error("last_table does not build")
			}
			return false
		}
		last = t
	}
	cols := make(map[zone.NodeID]zone.Columns, len(st.Nodes))
	for _, n := range st.Nodes {
		cols[zone.NodeID(n.ID)] = zone.Columns{Withdrawn: n.Withdrawn, Hold: n.Hold, LastFailbackAt: n.LastFailbackAt, FlapUntil: n.FlapUntil}
	}
	ev, err := zone.NewEvaluator(now, member, last, cols)
	if err != nil {
		return false
	}
	l.ev, l.version = ev, st.Version
	outs, err := ev.Start(now, l.commit)
	l.after(outs)
	if err != nil {
		l.ev = nil
		l.notCommitted(now)
		return false
	}
	l.started.Store(true)
	return true
}

func (l *Loop) notCommitted(now time.Time) {
	if now.Sub(l.failAt.t) >= notCommittedEvery {
		l.failAt = stamp{now}
		l.alert("critical", store.HubAlertFailNotDecided, map[string]string{})
	}
}

// commit is the evaluator's CommitFunc: the event's flags, its version and its table in one transaction, then the signature, then
// the push. An event that does not commit changes nothing, signs nothing and pushes nothing.
func (l *Loop) commit(ev *zone.Event) error {
	pt := proto.Clone(l.pt).(*policyv1.PairTable)
	for _, n := range pt.Nodes {
		if len(n.NodeId) != 16 {
			continue
		}
		id := zone.NodeID(n.NodeId)
		flag := l.ev.Columns(id).Withdrawn
		if c, ok := ev.Changed[id]; ok {
			flag = c.Withdrawn
		}
		n.DnsWithdrawn = flag
	}
	pt.ExpiresAt = ev.At.Add(PushLife).Unix()
	var payload []byte
	changed := make([]store.HubFailChange, 0, len(ev.Changed))
	for id, c := range ev.Changed {
		changed = append(changed, store.HubFailChange{Node: uuid.UUID(id), Withdrawn: c.Withdrawn, Hold: c.Hold, LastFailbackAt: c.LastFailbackAt, FlapUntil: c.FlapUntil})
	}
	req := uuid.Nil
	if ev.Done != nil {
		if id, err := uuid.Parse(ev.Done.ID); err == nil {
			req = id
		}
	}
	version, err := l.cfg.Store.HubFailCommit(l.ctx, store.HubFailEvent{
		Changed: changed, Request: req, Now: ev.At, Last: l.version,
		Table: func(v uint64) ([]byte, error) {
			pt.Version = v
			if err := wire.ValidatePairTablePush(pt); err != nil {
				return nil, err
			}
			b, err := proto.MarshalOptions{Deterministic: true}.Marshal(pt)
			payload = b
			return b, err
		},
	})
	if err != nil {
		if errors.Is(err, store.ErrFailMoved) {
			l.version = ^uint64(0) // the next tick reads a version that is not this and starts again
		}
		return err
	}
	l.version = version
	l.rememberTable(pt, version)
	// The lease was checked when the tick began and the commit may have waited on the database since. An event committed by a hub
	// that no longer holds the lease is not signed or pushed: the next tick sees the lost lease and resets, and the hub that holds
	// it reads the version and goes on from there (H-r1-9).
	if l.cfg.Lease == nil || !l.cfg.Lease.Held() {
		return nil
	}
	l.peers.Store(&peersBox{hubview.PeersOf(pt)})
	l.relVer, l.relSeen = version, true
	env := l.cfg.Signer.Sign(manifest.TypePairTable, payload)
	l.push.Store(&pushState{env: env, version: version})
	l.eventAt = stamp{ev.At}
	l.pushedTo = map[uuid.UUID]stamp{}
	if sb := l.send.Load(); sb != nil {
		sb.s.Broadcast(&hubv1.HubMessage{Body: &hubv1.HubMessage_PairTable{PairTable: env}})
	}
	return nil
}

// after turns what a tick produced into alerts and decisions: every event but a refresh alerts with its row, and a request that
// was refused or expired is marked (one that was carried out was marked in its event's transaction).
func (l *Loop) after(outs []zone.Output) {
	for _, o := range outs {
		if o.Request != nil {
			id, err := uuid.Parse(o.Request.ID)
			if err != nil {
				continue
			}
			if err := l.cfg.Store.HubFailDecide(l.ctx, id, o.Request.Result, o.Request.Reason); err != nil && l.cfg.Log != nil {
				l.cfg.Log.Warn("a request decision was not written")
			}
			continue
		}
		if o.Event == nil {
			continue
		}
		for _, a := range o.Event.Alerts {
			kind, sev := alertOf(a.Kind)
			p := map[string]string{"row": o.Event.Row}
			if a.Named {
				p["node"] = uuid.UUID(a.Node).String()
			}
			if a.Detail != "" {
				p["detail"] = a.Detail
			}
			l.alert(sev, kind, p)
		}
	}
}

func alertOf(k string) (store.HubAlertKind, string) {
	switch k {
	case zone.AlertMembership:
		return store.HubAlertFailMembership, "info"
	case zone.AlertWithdrawal:
		return store.HubAlertFailWithdrawal, "warning"
	case zone.AlertWithdrawalResolve:
		return store.HubAlertFailWithdrawalResolve, "warning"
	case zone.AlertFailback:
		return store.HubAlertFailFailback, "info"
	case zone.AlertHold:
		return store.HubAlertFailHold, "info"
	case zone.AlertRelease:
		return store.HubAlertFailRelease, "info"
	case zone.AlertForceFailback:
		return store.HubAlertFailForceFailback, "info"
	}
	return store.HubAlertFailFlapping, "warning"
}

// drain hands the evaluator what the other goroutines queued and the latest Heartbeat of each node of the membership. The sender
// of a Heartbeat is the stream's own mTLS identity (the trackers are keyed by it), never a field.
func (l *Loop) drain() {
	l.mu.Lock()
	heads, rounds := l.heads, l.rounds
	l.heads, l.rounds = nil, nil
	targets := append([]hubprobe.Target(nil), l.targets...)
	l.mu.Unlock()
	for _, h := range heads {
		l.ev.HeadNotice(h.at, zone.NodeID(h.node), h.seq)
	}
	for _, r := range rounds {
		l.ev.ProbeRound(r.at, zone.NodeID(r.node), r.dot, r.doh)
	}
	for _, t := range targets {
		hb, at, ok := l.cfg.Beats.Latest(t.ID)
		if !ok || at.Equal(l.fed[t.ID].t) {
			continue
		}
		l.fed[t.ID] = stamp{at}
		r := zone.Report{Isolated: hb.Isolated, AppliedSeq: hb.AppliedSeq}
		for _, u := range hb.Upstreams {
			r.Paths = append(r.Paths, u.Healthy)
		}
		l.pvVer[t.ID] = 0
		if pv, err := wire.ValidatePeerView(hb.PeerView); err == nil {
			l.pvVer[t.ID] = pv.PairTableVersion
			for _, p := range pv.Peers {
				if len(p.NodeId) == 16 {
					r.Peers = append(r.Peers, zone.PeerEntry{Node: zone.NodeID(p.NodeId), Known: p.Known, Down: p.Known && p.Down})
				}
			}
		}
		l.ev.Heartbeat(at, zone.NodeID(t.ID), r)
	}
}

// catchUp is push time 3: to a node whose PeerView says it has not applied the latest event, at most once per 5 s. A push that
// was just broadcast counts as a send.
func (l *Loop) catchUp(now time.Time) {
	p := l.push.Load()
	sb := l.send.Load()
	if p == nil || sb == nil {
		return
	}
	for _, t := range l.Targets() {
		hb, at, ok := l.cfg.Beats.Latest(t.ID)
		if !ok || hb == nil || now.Sub(at) > HeartbeatFresh || l.pvVer[t.ID] >= p.version {
			continue
		}
		last := l.pushedTo[t.ID].t
		if l.eventAt.t.After(last) {
			last = l.eventAt.t
		}
		if now.Sub(last) < CatchUp {
			continue
		}
		if sb.s.Send(t.ID, &hubv1.HubMessage{Body: &hubv1.HubMessage_PairTable{PairTable: p.env}}) {
			l.pushedTo[t.ID] = stamp{now}
		}
	}
}

// cannotResolve is the alert of 8a.4 Admin for a node whose latest Heartbeat lists at least one resolve path and none healthy,
// whatever its peer reports. It moves no flag: the evaluator does not raise it. It fires when the condition begins.
func (l *Loop) cannotResolve(now time.Time) {
	for _, t := range l.Targets() {
		hb, at, ok := l.cfg.Beats.Latest(t.ID)
		bad := false
		if ok && hb != nil && now.Sub(at) <= HeartbeatFresh && len(hb.Upstreams) > 0 {
			bad = true
			for _, u := range hb.Upstreams {
				if u.Healthy {
					bad = false
					break
				}
			}
		}
		switch {
		case bad && !l.cannot[t.ID]:
			l.cannot[t.ID] = true
			l.alert("warning", store.HubAlertNodeCannotResolve, map[string]string{"node": t.ID.String()})
		case !bad && l.cannot[t.ID]:
			delete(l.cannot, t.ID)
		}
	}
}
