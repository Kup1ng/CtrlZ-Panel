package hubrev_test

import (
	"bytes"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	"github.com/Kup1ng/CtrlZ-Shared/wire"

	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubrev"
	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubview"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

func uid(b byte) uuid.UUID { return uuid.UUID(bytes.Repeat([]byte{b}, 16)) }

// world is the hub's end: streams that record what they are sent, nodes that report an applied_seq, a clock.
type world struct {
	mu      sync.Mutex
	now     time.Time
	streams map[uuid.UUID][]*policyv1.Revocation
	applied map[uuid.UUID]uint64
	heard   map[uuid.UUID]bool
	members []uuid.UUID
	alerts  []map[string]string
}

func newWorld(nodes ...uuid.UUID) *world {
	w := &world{now: time.Unix(1_000_000, 0), streams: map[uuid.UUID][]*policyv1.Revocation{}, applied: map[uuid.UUID]uint64{}, heard: map[uuid.UUID]bool{}, members: nodes}
	for _, n := range nodes {
		w.heard[n] = true
	}
	return w
}

func (w *world) Now() time.Time { w.mu.Lock(); defer w.mu.Unlock(); return w.now }
func (w *world) advance(d time.Duration) {
	w.mu.Lock()
	w.now = w.now.Add(d)
	w.mu.Unlock()
}

func (w *world) Send(n uuid.UUID, m *hubv1.HubMessage) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, open := w.streams[n]; !open {
		return false
	}
	w.streams[n] = append(w.streams[n], m.GetRevocation())
	return true
}

func (w *world) Broadcast(m *hubv1.HubMessage) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for n := range w.streams {
		w.streams[n] = append(w.streams[n], m.GetRevocation())
	}
}

func (w *world) Pending() []uuid.UUID { return w.members }
func (w *world) Applied(n uuid.UUID) (uint64, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.applied[n], w.heard[n]
}
func (w *world) open(n uuid.UUID) { w.mu.Lock(); w.streams[n] = nil; w.mu.Unlock() }
func (w *world) got(n uuid.UUID) []*policyv1.Revocation {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.streams[n]
}
func (w *world) alert(_ string, k store.HubAlertKind, p map[string]string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if k == store.HubAlertRevocationPending {
		w.alerts = append(w.alerts, p)
	}
}

func rev(seq uint64) hubview.Applied {
	return hubview.Applied{Seq: seq, Revs: []hubview.Rev{{Kind: policyv1.RevocationKind_REVOCATION_KIND_ENDPOINT, IDs: [][]byte{bytes.Repeat([]byte{9}, 16)}}}}
}

// The whole life of one Revocation: sent to the open streams at once, to a stream that opens meanwhile, again every 5 minutes to
// the node that lags, an alert at 60 s, and dropped once every node has applied it.
func TestARevocationIsSentKeptResentAndDropped(t *testing.T) {
	a, b := uid(1), uid(2)
	w := newWorld(a, b)
	w.open(a)
	k := hubrev.New(w, w, w.Now, w.alert, nil)
	k.Add(rev(7))
	got := w.got(a)
	if len(got) != 1 || got[0].RevSeq != 7 || got[0].ExpiresAt-got[0].IssuedAt != int64(hubrev.Life/time.Second) {
		t.Fatalf("the open stream gets it at once with a life of 15 minutes: %v", got)
	}
	if err := wire.ValidateRevocation(got[0]); err != nil {
		t.Fatalf("the node would refuse it: %v", err)
	}
	// b's stream opens meanwhile: it gets it after its first ServerTime (the Control server calls Opened then).
	w.open(b)
	k.Opened(b)
	if got := w.got(b); len(got) != 1 || got[0].RevSeq != 7 {
		t.Fatalf("a stream that opens meanwhile: %v", got)
	}
	// A node that already applied it is not sent it on open.
	w.mu.Lock()
	w.applied[b] = 7
	w.mu.Unlock()
	w.open(b)
	k.Opened(b)
	if len(w.got(b)) != 0 {
		t.Fatal("a node that applied it was sent it again")
	}
	// a lags: nothing before 5 minutes, then a fresh expiry.
	w.advance(4 * time.Minute)
	k.Tick()
	if len(w.got(a)) != 1 {
		t.Fatalf("resent before 5 minutes: %d", len(w.got(a)))
	}
	w.advance(time.Minute)
	k.Tick()
	if got := w.got(a); len(got) != 2 || got[1].ExpiresAt <= got[0].ExpiresAt {
		t.Fatalf("resent at 5 minutes with a fresh expiry: %v", got)
	}
	if len(w.alerts) != 1 || w.alerts[0]["node"] != a.String() {
		t.Fatalf("one alert for the node that is behind: %v", w.alerts)
	}
	if k.PendingFor(a) != 7 || k.PendingFor(b) != 0 {
		t.Fatalf("pending a %d b %d", k.PendingFor(a), k.PendingFor(b))
	}
	k.Tick()
	if len(w.alerts) != 1 {
		t.Fatal("the alert repeats")
	}
	w.mu.Lock()
	w.applied[a] = 8
	w.mu.Unlock()
	k.Tick()
	if len(k.Held()) != 0 {
		t.Fatalf("every node applied it, so it is dropped: %v", k.Held())
	}
}

// A node the hub never heard from holds a Revocation (it is behind by the only measure there is), and the oldest are let go past
// the bound.
func TestAnUnheardNodeHoldsItAndTheBoundLetsTheOldestGo(t *testing.T) {
	a := uid(1)
	w := newWorld(a)
	w.mu.Lock()
	w.heard[a] = false
	w.mu.Unlock()
	k := hubrev.New(w, w, w.Now, nil, nil)
	for i := 1; i <= hubrev.Keep+3; i++ {
		k.Add(rev(uint64(i)))
	}
	k.Tick()
	h := k.Held()
	if len(h) != hubrev.Keep || h[0] != 4 || k.Dropped() == 0 {
		t.Fatalf("held %d first %d dropped %d", len(h), h[0], k.Dropped())
	}
}

func bigRev(seq uint64, ids [][]byte) hubview.Applied {
	return hubview.Applied{Seq: seq, Revs: []hubview.Rev{{Kind: policyv1.RevocationKind_REVOCATION_KIND_ENDPOINT, IDs: ids}}}
}

func manyIDs(n int) [][]byte {
	out := make([][]byte, n)
	for i := range out {
		out[i] = bytes.Repeat([]byte{byte(i)}, 16)
	}
	return out
}

// H-r1-11: a node that is behind by many large Revocations is not sent them all in one burst, which would overflow its stream's
// queue and end the stream on every open; the rest comes with the next Tick.
func TestABurstOfLargeRevocationsIsSentInPassesWithinTheBudget(t *testing.T) {
	a := uid(1)
	w := newWorld(a)
	k := hubrev.New(w, w, w.Now, nil, nil)
	ids := manyIDs(20_000) // 400 KB of budget each: two fit in 1 MiB
	for i := uint64(1); i <= 4; i++ {
		k.Add(bigRev(i, ids))
	}
	w.open(a)
	k.Opened(a)
	if n := len(w.got(a)); n != 2 {
		t.Fatalf("the first pass sent %d, want 2", n)
	}
	k.Tick()
	if n := len(w.got(a)); n != 4 {
		t.Fatalf("after the Tick %d were sent, want 4", n)
	}
}

// H-r1-11: the held ids are bounded by bytes as well as by count, and the newest stay.
func TestTheKeeperIsBoundedByBytesAndKeepsTheNewest(t *testing.T) {
	a := uid(1)
	w := newWorld(a)
	w.mu.Lock()
	w.heard[a] = false
	w.mu.Unlock()
	k := hubrev.New(w, w, w.Now, nil, nil)
	ids := manyIDs(100_000) // 2 MB each
	for i := uint64(1); i <= 40; i++ {
		k.Add(bigRev(i, ids))
	}
	h := k.Held()
	if len(h) >= 40 || len(h) < 20 || h[len(h)-1] != 40 || k.Dropped() == 0 {
		t.Fatalf("held %d, newest %d, dropped %d", len(h), h[len(h)-1], k.Dropped())
	}
}
