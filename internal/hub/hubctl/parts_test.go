package hubctl_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"

	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubctl"
	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubpki"
	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubroll"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// L1: the version is above what the node reported, above what was sent and never below the clock, so a clock stepped back
// or a restarted hub does not leave a node refusing.
func TestNextVersionNeverGoesBackward(t *testing.T) {
	now := time.UnixMilli(1_000_000)
	if v := hubctl.NextVersion(0, 0, now); v != 1_000_000 {
		t.Fatalf("clock: %d", v)
	}
	if v := hubctl.NextVersion(5_000_000, 0, now); v != 5_000_001 {
		t.Fatalf("reported above the clock: %d", v)
	}
	if v := hubctl.NextVersion(0, 7_000_000, now); v != 7_000_001 {
		t.Fatalf("sent above the clock: %d", v)
	}
}

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

// A reconnect gets the same sealed certificate, the leaf is made again when a third of its life is left, and another node
// gets its own.
func TestZoneLeafIsReusedUntilAThirdOfItsLifeIsLeft(t *testing.T) {
	zkey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	clk := &clock{t: time.Now()}
	ca, err := hubpki.IssueZoneCA(zkey, []string{"dns.example.test"}, clk.now())
	if err != nil {
		t.Fatal(err)
	}
	c := hubctl.NewCerts(zoneOnly{ca}, nil, clk.now)
	a, b := newNode(t), newNode(t)
	zones := []string{"dns.example.test"}
	first, err := c.For(context.Background(), a.id, &a.key.PublicKey, zones)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := c.For(context.Background(), a.id, &a.key.PublicKey, zones)
	if first[0].ID != again[0].ID || string(first[0].Msg.WrappedKey) != string(again[0].Msg.WrappedKey) {
		t.Fatal("a reconnect made a new leaf")
	}
	other, _ := c.For(context.Background(), b.id, &b.key.PublicKey, zones)
	if other[0].ID == first[0].ID {
		t.Fatal("two nodes share a leaf")
	}
	clk.add(21 * 24 * time.Hour) // 30-day life, so a third (10 days) is left
	renewed, err := c.For(context.Background(), a.id, &a.key.PublicKey, zones)
	if err != nil || renewed[0].ID == first[0].ID {
		t.Fatalf("the leaf was not made again: %v", err)
	}
	// A key that is not the cached one gets a new leaf: the cache is keyed by the node's key too.
	rekeyed, _ := c.For(context.Background(), a.id, &b.key.PublicKey, zones)
	if rekeyed[0].ID == renewed[0].ID {
		t.Fatal("a new key kept the old leaf")
	}
	if _, err := c.For(context.Background(), a.id, &a.key.PublicKey, []string{"other.example.test"}); err == nil {
		t.Fatal("a zone the CA does not permit got a certificate")
	}
}

type fakeWild struct{ chain, key []byte }

func (f fakeWild) Covering(context.Context, string) ([]byte, []byte, time.Time, bool, error) {
	return f.chain, append([]byte(nil), f.key...), time.Unix(2_000_000_000, 0), true, nil
}

// A wildcard row that covers the zone is what every node gets, sealed to that node.
func TestAWildcardThatCoversTheZoneIsSealedPerNode(t *testing.T) {
	n := newNode(t)
	c := hubctl.NewCerts(zoneOnly{}, fakeWild{chain: []byte("chain"), key: []byte("pkcs8")}, time.Now)
	b, err := c.For(context.Background(), n.id, &n.key.PublicKey, []string{"z.example.test"})
	if err != nil || string(b[0].Msg.ChainPem) != "chain" || len(b[0].Msg.WrappedKey) == 0 || b[0].Msg.NotAfter != 2_000_000_000 {
		t.Fatalf("wildcard bundle: %v", err)
	}
}

type leaseStore struct {
	mu   sync.Mutex
	ok   bool
	fail bool
}

func (l *leaseStore) HubLeaseTake(context.Context, string, string, int) (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.fail {
		return false, errors.New("down")
	}
	return l.ok, nil
}
func (l *leaseStore) set(ok, fail bool) { l.mu.Lock(); l.ok, l.fail = ok, fail; l.mu.Unlock() }

// The lease counts as held for ten seconds after the last confirmed renewal and ends the moment another holder has it.
func TestLeaseHeldFollowsTheDatabaseAndExpires(t *testing.T) {
	clk := &clock{t: time.Now()}
	st := &leaseStore{ok: true}
	l := hubctl.NewLease(st, "me", clk.now, nil)
	if l.Held() {
		t.Fatal("held before a renewal")
	}
	l.Renew(context.Background())
	if !l.Held() {
		t.Fatal("not held after a renewal")
	}
	st.set(false, true) // the database cannot answer
	clk.add(9 * time.Second)
	l.Renew(context.Background())
	if !l.Held() {
		t.Fatal("lost within the ten seconds of a failed renewal")
	}
	clk.add(2 * time.Second)
	if l.Held() {
		t.Fatal("held past ten seconds with no confirmed renewal")
	}
	st.set(true, false)
	l.Renew(context.Background())
	st.set(false, false) // another holder took it
	l.Renew(context.Background())
	if l.Held() {
		t.Fatal("held while another holder has it")
	}
}

// L4: no lease, or a stream open with no recent Heartbeat, or a not-ready evaluator, and the hub does not decide.
func TestDeciderFailsClosedOnEachPart(t *testing.T) {
	clk := &clock{t: time.Now()}
	st := &leaseStore{ok: true}
	lease := hubctl.NewLease(st, "me", clk.now, nil)
	tr := hubctl.NewTrackers(clk.now)
	streams := 0
	d := &hubctl.LeaseDecider{Lease: lease, Trackers: tr, Streams: func() int { return streams }}
	if d.CanDecide() {
		t.Fatal("decided with no lease")
	}
	lease.Renew(context.Background())
	if !d.CanDecide() {
		t.Fatal("did not decide with the lease and no stream")
	}
	streams = 1
	if d.CanDecide() {
		t.Fatal("decided with a stream open and no Heartbeat taken")
	}
	tr.Take(uuid.New(), &hubv1.Heartbeat{})
	if !d.CanDecide() {
		t.Fatal("did not decide with a fresh Heartbeat")
	}
	clk.add(hubctl.HeartbeatFreshness + time.Second)
	lease.Renew(context.Background())
	if d.CanDecide() {
		t.Fatal("decided on a Heartbeat older than 15 s")
	}
}

type feedStore struct {
	mu    sync.Mutex
	log   []store.HubLogHead
	free  bool
	ver   uint64
	nodes store.HubMembership
}

func (f *feedStore) HubLogHeads(_ context.Context, after uint64, limit int) ([]store.HubLogHead, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []store.HubLogHead
	for _, h := range f.log {
		if h.Seq > after && len(out) < limit {
			out = append(out, h)
		}
	}
	return out, nil
}
func (f *feedStore) HubLogLatest(context.Context) (store.HubLogHead, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.log) == 0 {
		return store.HubLogHead{}, false, nil
	}
	return f.log[len(f.log)-1], true, nil
}
func (f *feedStore) HubMembership(context.Context) (store.HubMembership, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.nodes, nil
}
func (f *feedStore) HubFreeDNS(context.Context) (bool, uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.free, f.ver, nil
}

// The rollout starts at the head the hub finds at start, and what is written after it is walked: the new entry is held at
// the cursor of each node.
func TestFeedStartsAtTheHeadAndFollowsTheLogAndTheFreeSwitch(t *testing.T) {
	a, b := uuid.New(), uuid.New()
	fs := &feedStore{free: true, ver: 1, log: []store.HubLogHead{{Seq: 1}, {Seq: 2, Class: "policy"}},
		nodes: store.HubMembership{Nodes: []store.MemberNode{{ID: a, Status: "active", Slot: 1}, {ID: b, Status: "active", Slot: 2}}}}
	roll := hubroll.New(hubroll.Config{})
	var seen []uint64
	var offs []uint64
	f := &hubctl.Feed{St: fs, Roll: roll, OnEntry: []func(store.HubLogHead){func(h store.HubLogHead) { seen = append(seen, h.Seq) }},
		OnFreeOff: func(v uint64) { offs = append(offs, v) }}
	if err := f.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got, _ := roll.Bound(a); got != 2 {
		t.Fatalf("bound at start %d, want the head 2", got)
	}
	roll.Stream(a, true)
	fs.mu.Lock()
	fs.log = append(fs.log, store.HubLogHead{Seq: 3, Class: "policy"}, store.HubLogHead{Seq: 4, Class: "policy"})
	fs.mu.Unlock()
	f.PollLog(context.Background())
	if len(seen) != 2 || seen[0] != 3 || seen[1] != 4 || roll.Latest() != 4 {
		t.Fatalf("seen %v latest %d", seen, roll.Latest())
	}
	if got, _ := roll.Bound(a); got != 4 {
		t.Fatalf("first node bound %d", got)
	}
	if got, _ := roll.Bound(b); got != 2 {
		t.Fatalf("second node bound %d: it must wait for the first", got)
	}
	// The switch turns off: once per new version.
	fs.mu.Lock()
	fs.free, fs.ver = false, 5
	fs.mu.Unlock()
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		f.PollFree(ctx)
	}
	if len(offs) != 1 || offs[0] != 5 {
		t.Fatalf("free off messages %v", offs)
	}
	if v, off := f.FreeOff(); !off || v != 5 {
		t.Fatal("FreeOff does not say off")
	}
	fs.mu.Lock()
	fs.ver = 6
	fs.mu.Unlock()
	f.PollFree(ctx)
	if len(offs) != 2 || offs[1] != 6 {
		t.Fatalf("a new version while off was not announced: %v", offs)
	}
}
