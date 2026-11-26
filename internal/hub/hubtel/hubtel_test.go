package hubtel

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	commonv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/common/v1"
	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	telemetryv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/telemetry/v1"
	"github.com/Kup1ng/CtrlZ-Shared/identity"

	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubctl"
	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubnet"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testwait"
)

// clock is a settable time: nothing in these tests sleeps.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// fakeDir lets each Endpoint be reported by the nodes it lists.
type fakeDir struct {
	pair map[uuid.UUID][]uuid.UUID
	cap  map[uuid.UUID]uint32
}

func (d *fakeDir) Allowed(ep, node uuid.UUID, _ time.Time) bool {
	for _, n := range d.pair[ep] {
		if n == node {
			return true
		}
	}
	return false
}
func (d *fakeDir) ClientCap(ep uuid.UUID) (uint32, bool) { c, ok := d.cap[ep]; return c, ok }

// fakeStore stands in for both pools and records what reached it.
type fakeStore struct {
	mu       sync.Mutex
	tenants  map[uuid.UUID]uuid.UUID
	beats    []store.HubBeat
	beatNode []uuid.UUID
	quar     map[string]map[uuid.UUID]bool
	alerts   []store.HubAlertKind
	writes   [][]store.HubActivityItem
	writeTn  []uuid.UUID
	writeErr []error
	learned  []store.HubLearn
	learnTn  []uuid.UUID
	proofs   []store.HubProof
	free     map[uint64]bool
	freeN    int
	label    map[string][3]uuid.UUID
	claimEp  uuid.UUID
}

func newFake() *fakeStore {
	return &fakeStore{tenants: map[uuid.UUID]uuid.UUID{}, quar: map[string]map[uuid.UUID]bool{}, free: map[uint64]bool{}, label: map[string][3]uuid.UUID{}}
}

func (f *fakeStore) HubAlert(_ context.Context, _ string, k store.HubAlertKind, _ map[string]string) error {
	f.mu.Lock()
	f.alerts = append(f.alerts, k)
	f.mu.Unlock()
	return nil
}
func (f *fakeStore) HubWriteBeat(_ context.Context, n uuid.UUID, in store.HubBeat) error {
	f.mu.Lock()
	f.beats, f.beatNode = append(f.beats, in), append(f.beatNode, n)
	f.mu.Unlock()
	return nil
}
func (f *fakeStore) HubQuarantineAdd(_ context.Context, n uuid.UUID, seq uint64, item, reason string) (bool, int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := item + "/" + reason + string(rune(seq))
	if f.quar[k] == nil {
		f.quar[k] = map[uuid.UUID]bool{}
	}
	ins := !f.quar[k][n]
	f.quar[k][n] = true
	return ins, len(f.quar[k]), nil
}
func (f *fakeStore) HubEndpointTenants(_ context.Context, ids []uuid.UUID) (map[uuid.UUID]uuid.UUID, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[uuid.UUID]uuid.UUID{}
	for _, id := range ids {
		if t, ok := f.tenants[id]; ok {
			out[id] = t
		}
	}
	return out, nil
}
func (f *fakeStore) HubActivityWrite(_ context.Context, tn uuid.UUID, items []store.HubActivityItem) (store.HubActivityResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.writeErr) > 0 {
		e := f.writeErr[0]
		f.writeErr = f.writeErr[1:]
		if e != nil {
			return store.HubActivityResult{}, e
		}
	}
	f.writes, f.writeTn = append(f.writes, items), append(f.writeTn, tn)
	return store.HubActivityResult{}, nil
}
func (f *fakeStore) HubFreeCounters(_ context.Context, _ uuid.UUID, batch uint64, _ int64, _ []store.HubFreeItem) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.freeN++
	if f.free[batch] {
		return false, nil
	}
	f.free[batch] = true
	return true, nil
}
func (f *fakeStore) HubLearnIP(_ context.Context, tn uuid.UUID, in store.HubLearn) (store.HubLearnOutcome, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.learned, f.learnTn = append(f.learned, in), append(f.learnTn, tn)
	return store.LearnWritten, nil
}
func (f *fakeStore) HubProofLookup(_ context.Context, label string) (uuid.UUID, uuid.UUID, uuid.UUID, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	l, ok := f.label[label]
	return l[0], l[1], l[2], ok, nil
}
func (f *fakeStore) HubProofObserve(_ context.Context, _ uuid.UUID, in store.HubProof, allow func(uuid.UUID) bool) (store.HubProofOutcome, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !allow(f.claimEp) {
		return store.ProofDenied, nil
	}
	f.proofs = append(f.proofs, in)
	return store.ProofWritten, nil
}

type world struct {
	t   *testing.T
	clk *clock
	fs  *fakeStore
	dir *fakeDir
	tel *Telemetry
	tr  *hubctl.Trackers
}

func newWorld(t *testing.T) *world {
	t.Helper()
	clk := &clock{t: time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)}
	fs := newFake()
	dir := &fakeDir{pair: map[uuid.UUID][]uuid.UUID{}, cap: map[uuid.UUID]uint32{}}
	tr := hubctl.NewTrackers(clk.now)
	tel := New(Config{Trackers: tr, Store: fs, Outside: fs, Directory: dir, ProofKey: []byte("0123456789abcdef-proof-key"), Now: clk.now})
	return &world{t, clk, fs, dir, tel, tr}
}

func id(b byte) uuid.UUID { return uuid.UUID{b, b, b, b, b, b, b, b, b, b, b, b, b, b, b, b} }

func hb(w *world, mut func(*hubv1.Heartbeat)) *hubv1.Heartbeat {
	h := &hubv1.Heartbeat{NodeTime: w.clk.now().Unix(), AppliedSeq: 7, NodeVersion: "1.0"}
	if mut != nil {
		mut(h)
	}
	return h
}

func TestHeartbeatFieldsAreWrittenAtMostEvery30Seconds(t *testing.T) {
	w := newWorld(t)
	n := id(1)
	w.tr.Take(n, hb(w, func(h *hubv1.Heartbeat) {
		h.Qps = 12
		h.Upstreams = []*hubv1.UpstreamHealth{{Id: []byte{1, 2}, Healthy: true}}
	}))
	w.tel.BeatPass(context.Background())
	w.clk.add(10 * time.Second)
	w.tr.Take(n, hb(w, func(h *hubv1.Heartbeat) { h.AppliedSeq = 9 }))
	w.tel.BeatPass(context.Background())
	if len(w.fs.beats) != 1 || w.fs.beats[0].AppliedSeq != 7 {
		t.Fatalf("a second write inside 30 s: %d writes", len(w.fs.beats))
	}
	w.clk.add(25 * time.Second)
	w.tel.BeatPass(context.Background())
	if len(w.fs.beats) != 2 || w.fs.beats[1].AppliedSeq != 9 {
		t.Fatalf("the write after 30 s carries the latest Heartbeat: %d writes", len(w.fs.beats))
	}
	if string(w.fs.beats[0].VersionInfo) == "" || !strings.Contains(string(w.fs.beats[0].VersionInfo), `"qps":12`) || !strings.Contains(string(w.fs.beats[0].VersionInfo), `"id":"0102"`) {
		t.Fatalf("version_info: %s", w.fs.beats[0].VersionInfo)
	}
}

// H-r1-1: a node that stopped speaking keeps its tracker for ten minutes, and the passes in that time must write nothing, so
// last_heartbeat_at keeps saying when the node last spoke.
func TestSilentNodeIsNotWrittenAsAliveAndCarriesItsArrivalTime(t *testing.T) {
	w := newWorld(t)
	n := id(1)
	heard := w.clk.now()
	w.tr.Take(n, hb(w, nil))
	w.tel.BeatPass(context.Background())
	if len(w.fs.beats) != 1 || !w.fs.beats[0].At.Equal(heard) {
		t.Fatalf("the write carries the Heartbeat's arrival time: %+v", w.fs.beats)
	}
	for i := 0; i < 8; i++ {
		w.clk.add(time.Minute)
		w.tel.BeatPass(context.Background())
	}
	if len(w.fs.beats) != 1 {
		t.Fatalf("a silent node was written again: %d writes", len(w.fs.beats))
	}
	w.tr.Take(n, hb(w, func(h *hubv1.Heartbeat) { h.AppliedSeq = 11 }))
	w.tel.BeatPass(context.Background())
	if len(w.fs.beats) != 2 || w.fs.beats[1].AppliedSeq != 11 {
		t.Fatalf("a new Heartbeat after the silence is written: %d writes", len(w.fs.beats))
	}
}

func TestSilentNodeLeavesTheTrackers(t *testing.T) {
	w := newWorld(t)
	w.tr.Take(id(1), hb(w, nil))
	w.clk.add(11 * time.Minute)
	w.tel.BeatPass(context.Background())
	if _, _, ok := w.tr.Latest(id(1)); ok {
		t.Fatal("a node silent for ten minutes is still tracked")
	}
}

func TestSkewAlertFiresOnceUntilTheClockIsBack(t *testing.T) {
	w := newWorld(t)
	n := id(1)
	offer := func(skew time.Duration) {
		w.tel.Offer(n, &hubv1.NodeMessage{Body: &hubv1.NodeMessage_Heartbeat{Heartbeat: hb(w, func(h *hubv1.Heartbeat) { h.NodeTime = w.clk.now().Add(skew).Unix() })}})
	}
	offer(2 * time.Second) // exactly the limit: no alert
	offer(3 * time.Second)
	offer(4 * time.Second)
	offer(-5 * time.Second)
	if len(w.tel.alerts) != 1 {
		t.Fatalf("one alert for one stretch of skew, got %d", len(w.tel.alerts))
	}
	offer(0)
	offer(-3 * time.Second)
	if len(w.tel.alerts) != 2 {
		t.Fatalf("the alert fires again after the clock was right: %d", len(w.tel.alerts))
	}
	a := <-w.tel.alerts
	if a.kind != store.HubAlertNodeClockSkew || a.params["node_id"] != n.String() {
		t.Fatalf("alert: %+v", a)
	}
}

func quarantine(seq uint64, item byte) *hubv1.NodeMessage {
	return &hubv1.NodeMessage{Body: &hubv1.NodeMessage_QuarantineReport{QuarantineReport: &hubv1.QuarantineReport{Seq: seq, Item: []byte{item}, Reason: "bad_section"}}}
}

func drainQuar(w *world) {
	for {
		select {
		case r := <-w.tel.quarQ:
			w.tel.quarantineWrite(context.Background(), r)
		default:
			return
		}
	}
}

func TestQuarantineRowsAreCappedPerNodeAnHourAndTwoNodesAlert(t *testing.T) {
	w := newWorld(t)
	a, b := id(1), id(2)
	for i := 0; i < QuarantinePerHour+5; i++ {
		w.tel.Offer(a, quarantine(uint64(i+1), byte(i)))
	}
	if got := w.tel.Stats()["drop_quarantine_cap"]; got != 5 {
		t.Fatalf("drops past the cap: %d", got)
	}
	// Another node is not held by A's count, and the same failure from it makes the alert; one node's report makes none.
	drainQuar(w)
	if len(w.tel.alerts) != 0 {
		t.Fatal("one node's report raised the two-node alert")
	}
	w.tel.Offer(b, quarantine(1, 0))
	drainQuar(w)
	if len(w.tel.alerts) != 1 || (<-w.tel.alerts).kind != store.HubAlertQuarantineTwoNodes {
		t.Fatal("the same failure from two nodes raised no alert")
	}
	w.clk.add(time.Hour)
	w.tel.Offer(a, quarantine(1000, 1))
	if w.tel.Stats()["drop_quarantine_cap"] != 5 {
		t.Fatal("the hour did not reset the count")
	}
}

func activityBatch(ep uuid.UUID, label string, last int64, mut func(*telemetryv1.ActivityEntry)) *telemetryv1.ActivityBatch {
	e := &telemetryv1.ActivityEntry{EndpointId: ep[:], ClientLabel: label, FirstSeenBucket: last, LastSeenBucket: last, Protocol: commonv1.Protocol_PROTOCOL_TCP}
	if mut != nil {
		mut(e)
	}
	return &telemetryv1.ActivityBatch{BatchId: 1, Entries: []*telemetryv1.ActivityEntry{e}}
}

func bucket(w *world, ago time.Duration) int64 { return (w.clk.now().Add(-ago).Unix() / 300) * 300 }

func TestActivityPairRuleDropsBeforeAnyWrite(t *testing.T) {
	w := newWorld(t)
	ep, tn := id(10), id(20)
	w.dir.pair[ep], w.dir.cap[ep] = []uuid.UUID{id(1), id(2)}, 5
	w.fs.tenants[ep] = tn
	outsider := id(3)
	w.tel.acceptActivity(outsider, activityBatch(ep, "default", bucket(w, time.Minute), nil))
	w.tel.act.Flush(context.Background())
	if len(w.fs.writes) != 0 || w.tel.Stats()["drop_pair"] != 1 || w.tel.act.Keys() != 0 {
		t.Fatalf("an entry from a node outside the pair was kept: writes %d stats %v", len(w.fs.writes), w.tel.Stats())
	}
	// A hub with no log view accepts nothing that needs a pair.
	w.tel.cfg.Directory = nil
	w.tel.acceptActivity(id(1), activityBatch(ep, "default", bucket(w, time.Minute), nil))
	if w.tel.act.Keys() != 0 {
		t.Fatal("a hub without a log view took a report")
	}
}

func TestActivityIsWrittenOnFirstSightingThenAtMostHourlyWithTheMaximumOverNodes(t *testing.T) {
	w := newWorld(t)
	ep, tn := id(10), id(20)
	w.dir.pair[ep], w.dir.cap[ep] = []uuid.UUID{id(1), id(2)}, 5
	w.fs.tenants[ep] = tn
	ctx := context.Background()
	b1 := bucket(w, 10*time.Minute)
	w.tel.acceptActivity(id(1), activityBatch(ep, "laptop", b1, nil))
	w.tel.acceptActivity(id(2), activityBatch(ep, "laptop", b1+300, nil)) // the later bucket of the other node wins
	w.tel.act.Flush(ctx)
	if len(w.fs.writes) != 1 || len(w.fs.writes[0]) != 1 {
		t.Fatalf("first sighting not written: %d", len(w.fs.writes))
	}
	it := w.fs.writes[0][0]
	if it.Last.Unix() != b1+300 || it.Node != id(2) || it.ClientCap != 5 || w.fs.writeTn[0] != tn {
		t.Fatalf("item: %+v tenant %v", it, w.fs.writeTn[0])
	}
	// A newer bucket 31 s later is held until an hour has passed.
	w.clk.add(31 * time.Second)
	w.tel.acceptActivity(id(1), activityBatch(ep, "laptop", b1+600, nil))
	w.tel.act.Flush(ctx)
	if len(w.fs.writes) != 1 {
		t.Fatal("a key was written twice inside an hour")
	}
	w.clk.add(time.Hour)
	w.tel.act.Flush(ctx)
	if len(w.fs.writes) != 2 || w.fs.writes[1][0].Last.Unix() != b1+600 {
		t.Fatalf("the hourly write is missing or stale: %d", len(w.fs.writes))
	}
	// Nothing new: nothing more to write.
	w.clk.add(2 * time.Hour)
	w.tel.act.Flush(ctx)
	if len(w.fs.writes) != 2 {
		t.Fatal("a key with no new bucket was written")
	}
}

func TestActivityBatchesComeAtMostEvery30Seconds(t *testing.T) {
	w := newWorld(t)
	ep := id(10)
	w.dir.pair[ep], w.dir.cap[ep] = []uuid.UUID{id(1)}, 5
	w.tel.acceptActivity(id(1), activityBatch(ep, "a", bucket(w, time.Minute), nil))
	w.clk.add(10 * time.Second)
	w.tel.acceptActivity(id(1), activityBatch(ep, "b", bucket(w, time.Minute), nil))
	if w.tel.act.Keys() != 1 || w.tel.Stats()["drop_batch_rate"] != 1 {
		t.Fatalf("a second batch inside 30 s was taken: %v", w.tel.Stats())
	}
	w.clk.add(21 * time.Second)
	w.tel.acceptActivity(id(1), activityBatch(ep, "b", bucket(w, time.Minute), nil))
	if w.tel.act.Keys() != 2 {
		t.Fatal("a batch after 30 s was refused")
	}
}

func TestActivityKeysAreBoundedPerNodeAndInTotal(t *testing.T) {
	w := newWorld(t)
	w.tel.cfg.KeysPerNode = 1000
	a := w.tel.act
	now := w.clk.now()
	per := w.tel.cfg.KeysPerNode
	for i := 0; i < per+3; i++ {
		var k akey
		k.ep = uuid.UUID{byte(i), byte(i >> 8), byte(i >> 16), 1}
		k.label = "x"
		a.take(id(1), k, 300, 300, now, w.tel)
	}
	if a.Keys() != per || w.tel.Stats()["drop_key_cap"] != 3 {
		t.Fatalf("keys %d, drops %v", a.Keys(), w.tel.Stats()["drop_key_cap"])
	}
	// Another node still has room: the bound is per node.
	a.take(id(2), akey{ep: id(9), label: "y"}, 300, 300, now, w.tel)
	if a.Keys() != per+1 {
		t.Fatal("one node's keys used up another's room")
	}
}

func TestActivityGoneEndpointAndRetryAndMissingRecord(t *testing.T) {
	w := newWorld(t)
	ep, gone, nored := id(10), id(11), id(12)
	w.dir.pair[ep], w.dir.cap[ep] = []uuid.UUID{id(1)}, 5
	w.dir.pair[gone], w.dir.cap[gone] = []uuid.UUID{id(1)}, 5
	w.dir.pair[nored] = []uuid.UUID{id(1)} // no record, so no client cap
	w.fs.tenants[ep], w.fs.tenants[nored] = id(20), id(20)
	w.fs.writeErr = []error{store.ErrRetry, nil} // a lost lock race is tried again
	for _, e := range []uuid.UUID{ep, gone, nored} {
		w.tel.act.take(id(1), akey{ep: e, label: "default"}, 300, 600, w.clk.now(), w.tel)
	}
	w.tel.act.Flush(context.Background())
	if len(w.fs.writes) != 1 || len(w.fs.writes[0]) != 1 || w.fs.writes[0][0].Endpoint != ep {
		t.Fatalf("writes: %v", w.fs.writes)
	}
	st := w.tel.Stats()
	if st["drop_no_tenant"] != 1 || st["drop_no_record"] != 1 {
		t.Fatalf("stats %v", st)
	}
	if w.tel.act.Keys() != 2 { // the gone Endpoint's key was let go; the one with no record waits for its record
		t.Fatalf("keys %d", w.tel.act.Keys())
	}
}

func TestActivityFailedWriteStaysDue(t *testing.T) {
	w := newWorld(t)
	ep := id(10)
	w.dir.pair[ep], w.dir.cap[ep] = []uuid.UUID{id(1)}, 5
	w.fs.tenants[ep] = id(20)
	w.fs.writeErr = []error{errors.New("down")}
	w.tel.act.take(id(1), akey{ep: ep, label: "default"}, 300, 600, w.clk.now(), w.tel)
	w.tel.act.Flush(context.Background())
	w.tel.act.Flush(context.Background())
	if len(w.fs.writes) != 1 {
		t.Fatalf("a failed write was not tried again: %d", len(w.fs.writes))
	}
}

func learned(ep uuid.UUID, p commonv1.Protocol, last byte) *hubv1.NodeMessage {
	return &hubv1.NodeMessage{Body: &hubv1.NodeMessage_LearnedIp{LearnedIp: &hubv1.LearnedIP{
		EndpointId: ep[:], SourceIp: []byte{203, 0, 113, last}, Protocol: p,
	}}}
}

func TestLearnedIPRules(t *testing.T) {
	w := newWorld(t)
	ep, tn := id(10), id(20)
	w.dir.pair[ep] = []uuid.UUID{id(1)}
	w.fs.tenants[ep] = tn
	ctx := context.Background()
	w.tel.Offer(id(1), learned(ep, commonv1.Protocol_PROTOCOL_DOT, 1)) // not a DoH address
	w.tel.Offer(id(3), learned(ep, commonv1.Protocol_PROTOCOL_DOH, 2)) // outside the pair
	w.tel.Offer(id(1), learned(ep, commonv1.Protocol_PROTOCOL_DOH, 3))
	w.tel.Offer(id(1), learned(ep, commonv1.Protocol_PROTOCOL_DOH3, 4))
	w.tel.Drain(ctx)
	if len(w.fs.learned) != 2 || w.fs.learnTn[0] != tn || w.fs.learned[0].Node != id(1) {
		t.Fatalf("learned: %+v", w.fs.learned)
	}
	st := w.tel.Stats()
	if st["drop_learn_proto"] != 1 || st["drop_pair"] != 1 {
		t.Fatalf("stats %v", st)
	}
	// 10 a minute for one Endpoint; two nodes of the pair share the Endpoint's bound.
	w.dir.pair[ep] = []uuid.UUID{id(1), id(2)}
	for i := 0; i < 12; i++ {
		w.tel.Offer(id(2), learned(ep, commonv1.Protocol_PROTOCOL_DOH, byte(10+i)))
		if i%5 == 4 {
			w.tel.Drain(ctx)
		}
	}
	w.tel.Drain(ctx)
	if got := len(w.fs.learned); got != 10 {
		t.Fatalf("rate per Endpoint: %d rows written, want 10 in the minute", got)
	}
	if w.tel.Stats()["drop_learn_rate"] != 4 {
		t.Fatalf("drops %v", w.tel.Stats())
	}
}

func TestOutsideMessagesAreBoundedPerNode(t *testing.T) {
	w := newWorld(t)
	ep := id(10)
	w.dir.pair[ep] = []uuid.UUID{id(1), id(2)}
	w.fs.tenants[ep] = id(20)
	for i := 0; i < OutsideRate+10; i++ { // 20 a second, then dropped before any queue
		w.tel.Offer(id(1), learned(ep, commonv1.Protocol_PROTOCOL_DOH, byte(i)))
	}
	if w.tel.Stats()["drop_outside_rate"] != 10 {
		t.Fatalf("rate drops: %v", w.tel.Stats())
	}
	// The queue holds 256 per node: fill it with a node whose rate is not the limit by moving the clock between sends.
	w2 := newWorld(t)
	for i := 0; i < OutsideQueue+4; i++ {
		w2.clk.add(time.Second)
		w2.tel.Offer(id(1), learned(ep, commonv1.Protocol_PROTOCOL_DOH, byte(i)))
	}
	if w2.tel.Stats()["drop_outside_full"] != 4 {
		t.Fatalf("queue drops: %v", w2.tel.Stats())
	}
	// A second node has its own queue.
	w2.tel.Offer(id(2), learned(ep, commonv1.Protocol_PROTOCOL_DOH, 1))
	if w2.tel.Stats()["drop_outside_full"] != 4 {
		t.Fatal("one node's backlog filled another's queue")
	}
}

func TestProofObservationUsesTheHubsOwnCodeAndThePairRule(t *testing.T) {
	w := newWorld(t)
	ep, claimEp := id(10), id(10)
	w.fs.claimEp = claimEp
	w.dir.pair[claimEp] = []uuid.UUID{id(1)}
	label := "abcdefghijklmnopqrstuvwxyz"[:26]
	tn, ch, claim := id(20), id(30), id(40)
	w.fs.label[label] = [3]uuid.UUID{tn, ch, claim}
	_ = ep
	src := netip.MustParseAddr("198.51.100.7")
	obs := &hubv1.NodeMessage{Body: &hubv1.NodeMessage_ProofObservation{ProofObservation: &hubv1.ProofObservation{
		Label: label, SourceIp: src.AsSlice(), Protocol: commonv1.Protocol_PROTOCOL_UDP,
	}}}
	w.tel.Offer(id(3), obs) // outside the claim's Endpoint's pair
	w.tel.Offer(id(1), obs)
	w.tel.Drain(context.Background())
	if len(w.fs.proofs) != 1 {
		t.Fatalf("proofs written: %d (stats %v)", len(w.fs.proofs), w.tel.Stats())
	}
	p := w.fs.proofs[0]
	want := sha256.Sum256([]byte(identity.ProofCode([]byte("0123456789abcdef-proof-key"), label, src)))
	if string(p.CodeHash) != string(want[:]) || p.Protocol != "udp" || p.Challenge != ch || p.Claim != claim || p.Node != id(1) {
		t.Fatalf("proof: %+v", p)
	}
	if w.tel.Stats()["drop_pair"] != 1 {
		t.Fatalf("stats %v", w.tel.Stats())
	}
	// An unknown label is dropped and counted.
	obs.GetProofObservation().Label = "zzzzzzzzzzzzzzzzzzzzzzzzzz"
	w.tel.Offer(id(1), obs)
	w.tel.Drain(context.Background())
	if w.tel.Stats()["drop_proof_invalid"] != 1 {
		t.Fatalf("stats %v", w.tel.Stats())
	}
}

// ---- upload streams --------------------------------------------------------------------------------------------------

type upStream[In, Out any] struct {
	grpc.ServerStream
	ctx    context.Context
	in     chan *In
	out    chan *Out
	cancel context.CancelFunc
}

func newUp[In, Out any](node uuid.UUID) *upStream[In, Out] {
	ctx, cancel := context.WithCancel(hubnet.WithIdentity(context.Background(), hubnet.Identity{Node: true, NodeID: node}))
	return &upStream[In, Out]{ctx: ctx, in: make(chan *In, 4), out: make(chan *Out, 4), cancel: cancel}
}
func (s *upStream[In, Out]) Context() context.Context { return s.ctx }
func (s *upStream[In, Out]) Recv() (*In, error) {
	select {
	case m := <-s.in:
		return m, nil
	case <-s.ctx.Done():
		return nil, io.EOF
	}
}
func (s *upStream[In, Out]) Send(m *Out) error {
	select {
	case s.out <- m:
		return nil
	case <-s.ctx.Done():
		return s.ctx.Err()
	}
}

func TestOneUploadStreamPerMethodPerNode(t *testing.T) {
	w := newWorld(t)
	a := newUp[telemetryv1.ActivityBatch, telemetryv1.Ack](id(1))
	done := make(chan error, 1)
	go func() { done <- w.tel.ReportActivity(a) }()
	testwait.Until(t, 5*time.Second, "the first stream holds its slot", func() bool { return w.tel.OpenUploads() == 1 })
	second := newUp[telemetryv1.ActivityBatch, telemetryv1.Ack](id(1))
	if err := w.tel.ReportActivity(second); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("a second activity stream of one node: %v", err)
	}
	// Another method of the same node, and the same method of another node, are free.
	c := newUp[telemetryv1.CountersBatch, telemetryv1.Ack](id(1))
	cdone := make(chan error, 1)
	go func() { cdone <- w.tel.UploadCounters(c) }()
	other := newUp[telemetryv1.ActivityBatch, telemetryv1.Ack](id(2))
	odone := make(chan error, 1)
	go func() { odone <- w.tel.ReportActivity(other) }()
	testwait.Until(t, 5*time.Second, "three streams open", func() bool { return w.tel.OpenUploads() == 3 })
	a.cancel()
	c.cancel()
	other.cancel()
	for _, ch := range []chan error{done, cdone, odone} {
		testwait.Receive(t, ch, 5*time.Second, "the stream ends")
	}
	testwait.Until(t, 5*time.Second, "slots are given back", func() bool { return w.tel.OpenUploads() == 0 })
	if err := w.tel.UploadLogs(nil); status.Code(err) != codes.Unimplemented {
		t.Fatalf("UploadLogs: %v", err)
	}
}

func TestReportActivityAcksEveryBatchAndKeepsTheStreamOnABadOne(t *testing.T) {
	w := newWorld(t)
	ep := id(10)
	w.dir.pair[ep], w.dir.cap[ep] = []uuid.UUID{id(1)}, 5
	s := newUp[telemetryv1.ActivityBatch, telemetryv1.Ack](id(1))
	done := make(chan error, 1)
	go func() { done <- w.tel.ReportActivity(s) }()
	bad := activityBatch(ep, "NOT A LABEL", bucket(w, time.Minute), nil)
	bad.BatchId = 5
	s.in <- bad
	a := testwait.Receive(t, s.out, 5*time.Second, "the ack of a bad batch")
	if a.BatchId != 5 || !a.Durable || w.tel.Stats()["drop_batch_invalid"] != 1 {
		t.Fatalf("ack %+v stats %v", a, w.tel.Stats())
	}
	good := activityBatch(ep, "laptop", bucket(w, time.Minute), nil)
	good.BatchId = 6
	s.in <- good
	if a := testwait.Receive(t, s.out, 5*time.Second, "the ack"); a.BatchId != 6 || !a.Durable {
		t.Fatalf("ack %+v", a)
	}
	if w.tel.act.Keys() != 1 {
		t.Fatal("the good batch was not taken")
	}
	s.cancel()
	testwait.Receive(t, done, 5*time.Second, "the stream ends")
}

func TestUploadCountersFreePartOnly(t *testing.T) {
	w := newWorld(t)
	s := newUp[telemetryv1.CountersBatch, telemetryv1.Ack](id(1))
	done := make(chan error, 1)
	go func() { done <- w.tel.UploadCounters(s) }()
	bk := (w.clk.now().Unix() / 300) * 300
	free := func(n uint64) []*telemetryv1.FreeCounter {
		return []*telemetryv1.FreeCounter{{Protocol: commonv1.Protocol_PROTOCOL_UDP, Outcome: telemetryv1.FreeOutcome_FREE_OUTCOME_ANSWERED, Count: n}}
	}
	send := func(b *telemetryv1.CountersBatch) *telemetryv1.Ack {
		w.clk.add(2 * time.Second) // the node waits 2 s between batches
		s.in <- b
		return testwait.Receive(t, s.out, 5*time.Second, "the ack")
	}
	if a := send(&telemetryv1.CountersBatch{BatchId: 1, BucketStart: bk, Free: free(3)}); a.BatchId != 1 || !a.Durable {
		t.Fatalf("ack %+v", a)
	}
	// The same batch again after a lost Ack: acknowledged, counted once.
	if a := send(&telemetryv1.CountersBatch{BatchId: 1, BucketStart: bk, Free: free(3)}); a.BatchId != 1 || !a.Durable {
		t.Fatalf("ack %+v", a)
	}
	if w.fs.freeN != 2 || len(w.fs.free) != 1 || w.tel.Stats()["wrote_free"] != 1 {
		t.Fatalf("free writes %d, batches %d", w.fs.freeN, len(w.fs.free))
	}
	// A bad free part is dropped, and the counters of the batch are still handled (here: dropped until P5).
	bad := &telemetryv1.CountersBatch{BatchId: 2, BucketStart: bk, Free: free(3),
		Counters: []*telemetryv1.Counter{{EndpointId: make([]byte, 16), Protocol: commonv1.Protocol_PROTOCOL_UDP, Action: commonv1.Action_ACTION_BLOCK, Count: 1}}}
	bad.Free[0].Rcode = 99
	if a := send(bad); a.BatchId != 2 || !a.Durable {
		t.Fatalf("ack %+v", a)
	}
	st := w.tel.Stats()
	if st["drop_counters_part"] != 1 || st["drop_counters_items"] != 1 || w.fs.freeN != 2 {
		t.Fatalf("stats %v free %d", st, w.fs.freeN)
	}
	s.cancel()
	testwait.Receive(t, done, 5*time.Second, "the stream ends")
}
