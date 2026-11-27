package hubfail_test

import (
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	"github.com/Kup1ng/CtrlZ-Shared/wire"
	"github.com/Kup1ng/CtrlZ-Shared/zone"

	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubfail"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// The state the admin page reads (T-542): which F3 conditions keep a node out, when F3 would act, and the drain of a node that
// stopped being advertised. Each test reads the rows the loop wrote into the fake database and nothing else.

// pvAt is a PeerView that says the node applied table version v and that each node in votes is up.
func (w *world) pvAt(v uint64, votes ...byte) []byte {
	pv := &hubv1.PeerView{PairTableVersion: v}
	for _, n := range votes {
		pv.Peers = append(pv.Peers, &hubv1.PeerProbe{NodeId: id16(n), Known: true})
	}
	b, err := wire.EncodePeerView(pv)
	if err != nil {
		w.t.Fatal(err)
	}
	return b
}

// traffic is what a healthy zone sends every 5 s: a passing prober round for each node that is up, its Heartbeat carrying the
// version of the latest table, and the peer's vote that the other is up.
func (w *world) traffic(aUp, bVotesA bool) func(int) {
	return func(i int) {
		if i%5 != 0 {
			return
		}
		v := w.loop.Version()
		w.round(nodeB, true)
		if bVotesA {
			w.heartbeat(nodeB, w.pvAt(v, nodeA), nil)
		} else {
			w.heartbeat(nodeB, w.pvAt(v), nil)
		}
		if aUp {
			w.round(nodeA, true)
			w.heartbeat(nodeA, w.pvAt(v, nodeB), nil)
		}
	}
}

// holdA queues an admin Hold of A and runs the tick that decides it.
func (w *world) holdA() {
	w.t.Helper()
	w.db.mu.Lock()
	w.db.reqs = append(w.db.reqs, store.HubFailRequest{ID: uid(90), Node: uid(nodeA), Kind: "hold", RequestedAt: w.clk.Now()})
	w.db.mu.Unlock()
	w.run(time.Second, w.traffic(true, true))
	if n := w.db.node(nodeA); !n.Withdrawn || !n.Hold {
		w.t.Fatalf("the hold was not carried out: %v", n)
	}
}

func (d *db) writes() int { d.mu.Lock(); defer d.mu.Unlock(); return d.stateWrites }

// A withdrawn node's row names what keeps it out and, once every input holds, the moment F3 acts. A node that is not withdrawn
// has nothing to say.
//
// Fails if: publishState is not called in Tick (no row is ever written), if f3Unmet maps a condition to another name, or if
// TimerDue is not read (the due time stays zero).
func TestTheRowOfAWithdrawnNodeNamesWhatKeepsItOut(t *testing.T) {
	w := newWorld(t)
	w.str.open[uid(nodeB)] = true
	w.tick() // F0: a new pair starts with its primary withdrawn
	if !w.db.node(nodeA).Withdrawn {
		t.Fatal("setup: the primary of a new pair starts withdrawn")
	}

	// A says nothing: neither the hub's checks nor the peer's vote find it up.
	w.run(30*time.Second, w.traffic(false, false))
	if got := w.db.state(nodeA).F3Unmet; !reflect.DeepEqual(got, []string{hubfail.CondHubFit, hubfail.CondPeerView, hubfail.CondStablePeriod}) {
		t.Fatalf("a silent node: %v", got)
	}
	if !w.db.state(nodeA).F3DueAt.IsZero() {
		t.Fatal("a due time while conditions are unmet")
	}
	if b := w.db.state(nodeB); len(b.F3Unmet) != 0 || !b.F3DueAt.IsZero() {
		t.Fatalf("a node that is not withdrawn has no conditions: %v", b)
	}

	// A is fit but B has not voted it up.
	w.run(30*time.Second, w.traffic(true, false))
	if got := w.db.state(nodeA).F3Unmet; !reflect.DeepEqual(got, []string{hubfail.CondPeerView, hubfail.CondStablePeriod}) {
		t.Fatalf("a fit node the peer has not voted up: %v", got)
	}

	// Every input holds: only the wait is left, and the row says when it ends.
	w.run(10*time.Second, w.traffic(true, true))
	a := w.db.state(nodeA)
	if !reflect.DeepEqual(a.F3Unmet, []string{hubfail.CondStablePeriod}) {
		t.Fatalf("every input holds: %v", a.F3Unmet)
	}
	left := a.F3DueAt.Sub(w.clk.Now())
	if left <= 0 || left > zone.Inputs().Stable || left < zone.Inputs().Stable-30*time.Second {
		t.Fatalf("F3 is due in %v, the stable period is %v", left, zone.Inputs().Stable)
	}

	// A break in the inputs stops the count and the row loses its time.
	w.run(10*time.Second, w.traffic(true, false))
	if a := w.db.state(nodeA); !a.F3DueAt.IsZero() || a.F3Unmet[0] != hubfail.CondPeerView {
		t.Fatalf("the vote was withdrawn: %v", a)
	}

	// The wait passes and F3 returns the node: its row is empty again.
	w.run(zone.Inputs().Stable+30*time.Second, w.traffic(true, true))
	if w.db.node(nodeA).Withdrawn {
		t.Fatal("F3 did not return the node")
	}
	if a := w.db.state(nodeA); len(a.F3Unmet) != 0 || !a.F3DueAt.IsZero() {
		t.Fatalf("a returned node keeps conditions: %v", a)
	}
}

// A hold is named as a condition of its own, so the page tells a held node from one that waits.
//
// Fails if: f3Unmet drops the held condition (the PredHeld case).
func TestAHeldNodeNamesTheHold(t *testing.T) {
	w := newWorld(t)
	w.settled()
	w.str.open[uid(nodeB)] = true
	w.tick()
	w.run(40*time.Second, w.traffic(true, true))
	w.holdA()
	if got := w.db.state(nodeA).F3Unmet; len(got) < 2 || got[0] != hubfail.CondHeld || got[len(got)-1] != hubfail.CondStablePeriod {
		t.Fatalf("a held node: %v", got)
	}
}

// A node that stopped being advertised drains from the Heartbeat that reports the new table, and the page shows "done" 360 s
// after it. The other node of the pair never drains, and a table that advertises the node again cancels the drain.
//
// Fails if: feedDrains is not called in Tick or rememberTable is not called in commit (the drain stays none), if the drain began
// at the commit instead of the report (the "before the node reported" check), or if Done is read at another age.
func TestTheDrainOfAHeldPrimaryRunsFromItsReportAndIsDoneAt360s(t *testing.T) {
	w := newWorld(t)
	w.settled()
	w.str.open[uid(nodeB)] = true
	w.tick()
	w.run(40*time.Second, w.traffic(true, true))
	if got := w.db.state(nodeA).Drain; got != hubfail.DrainNone {
		t.Fatalf("a serving primary drains: %q", got)
	}

	w.holdA()
	// The hub signed the table but no Heartbeat has reported it applied: it has not seen A drain.
	w.run(3*time.Second, nil)
	if got := w.db.state(nodeA).Drain; got != hubfail.DrainNone {
		t.Fatalf("a drain before the node reported the table: %q", got)
	}

	reportedAt := w.clk.Now()
	w.heartbeat(nodeA, w.pvAt(w.loop.Version(), nodeB), nil)
	w.run(time.Second, nil)
	a := w.db.state(nodeA)
	if a.Drain != hubfail.DrainDraining || !a.DrainSince.Equal(reportedAt) {
		t.Fatalf("after the report: %v (reported at %v)", a, reportedAt)
	}
	if b := w.db.state(nodeB); b.Drain != hubfail.DrainNone {
		t.Fatalf("the node that took over drains: %v", b)
	}

	// Heartbeats go on, each carrying the same version: the drain neither restarts nor ends.
	w.run(358*time.Second, w.traffic(true, true))
	if got := w.db.state(nodeA); got.Drain != hubfail.DrainDraining || !got.DrainSince.Equal(reportedAt) {
		t.Fatalf("359 s after the report: %v", got)
	}
	w.run(time.Second, w.traffic(true, true))
	if got := w.db.state(nodeA).Drain; got != hubfail.DrainDone {
		t.Fatalf("360 s after the report: %q", got)
	}

	// Release, and F3 returns A after its stable period: the table that advertises it again cancels the drain.
	w.db.mu.Lock()
	w.db.reqs = append(w.db.reqs, store.HubFailRequest{ID: uid(91), Node: uid(nodeA), Kind: "release", RequestedAt: w.clk.Now()})
	w.db.mu.Unlock()
	w.run(zone.Inputs().Stable+60*time.Second, w.traffic(true, true))
	if w.db.node(nodeA).Withdrawn {
		t.Fatal("setup: A was not returned")
	}
	if a := w.db.state(nodeA); a.Drain != hubfail.DrainNone || !a.DrainSince.IsZero() {
		t.Fatalf("a table that advertises the node again leaves its drain: %v", a)
	}
}

// A row is written when it changes, not on every tick.
//
// Fails if: publishState writes every target on every tick (the writes grow in the quiet minutes).
func TestRowsAreWrittenOnChangeOnly(t *testing.T) {
	w := newWorld(t)
	w.settled()
	w.str.open[uid(nodeB)] = true
	w.run(20*time.Second, w.traffic(true, true))
	n := w.db.writes()
	if n == 0 {
		t.Fatal("nothing was written")
	}
	w.run(120*time.Second, w.traffic(true, true))
	if m := w.db.writes(); m != n {
		t.Fatalf("%d writes in 120 quiet seconds", m-n)
	}
}

// A write that fails neither stops the decision loop nor is lost: the next tick that can write does. A hub that takes the lease
// again writes every row once more, whatever another hub left.
//
// Fails if: a failed write is recorded as written (the rows never come), or if resetState does not clear what was written (the
// rows are not written again after the lease).
func TestRowsAreWrittenAgainAfterAFailedWriteAndAfterTheLease(t *testing.T) {
	w := newWorld(t)
	w.settled()
	w.str.open[uid(nodeB)] = true
	w.db.mu.Lock()
	w.db.failState = true
	w.db.mu.Unlock()
	w.run(20*time.Second, w.traffic(true, true))
	if !w.loop.Ready() {
		t.Fatal("a failed write of the page's rows stopped the decision loop")
	}
	if w.db.writes() != 0 {
		t.Fatal("setup: a write succeeded")
	}
	w.db.mu.Lock()
	w.db.failState = false
	w.db.mu.Unlock()
	w.run(2*time.Second, w.traffic(true, true))
	if w.db.writes() == 0 {
		t.Fatal("the rows were not written once the database could take them")
	}

	// Another hub rewrote the rows while this one lost the lease.
	w.db.mu.Lock()
	w.db.states = map[uuid.UUID]store.HubNodeState{}
	w.db.mu.Unlock()
	w.lease.held = false
	w.run(2*time.Second, w.traffic(true, true))
	w.lease.held = true
	w.run(10*time.Second, w.traffic(true, true))
	if got := w.db.state(nodeA); got.Node != uid(nodeA) {
		t.Fatal("the rows were not written again after the lease came back")
	}
}

// GP-r1-1: a hub that takes the lease again (a restart, or a failover) does not know the drain of a node that is still withdrawn,
// and must not write "none" over the "done" the last hub wrote. A node it sees advertised again does get its "none".
//
// Fails if: HubNodeState.DrainKnown is not set from what the process has seen (the row of A is overwritten with none).
func TestADrainTheHubHasNotSeenIsNotOverwrittenWithNone(t *testing.T) {
	w := newWorld(t)
	w.settled()
	w.str.open[uid(nodeB)] = true
	w.tick()
	w.run(40*time.Second, w.traffic(true, true))
	w.holdA()
	w.run(3*time.Second, nil)
	w.heartbeat(nodeA, w.pvAt(w.loop.Version(), nodeB), nil)
	w.run(365*time.Second, w.traffic(true, true))
	before := w.db.state(nodeA)
	if before.Drain != hubfail.DrainDone || before.DrainSince.IsZero() {
		t.Fatalf("setup: A is %v", before)
	}

	w.lease.held = false
	w.run(2*time.Second, nil)
	w.lease.held = true
	w.run(30*time.Second, w.traffic(true, true))
	if w.db.writes() == 0 || !w.db.node(nodeA).Withdrawn {
		t.Fatal("setup: the hub did not decide again or A was returned")
	}
	if got := w.db.state(nodeA); got.Drain != before.Drain || !got.DrainSince.Equal(before.DrainSince) {
		t.Fatalf("a hub that has not seen A advertised rewrote its drain: %v, was %v", got, before)
	}
	if b := w.db.state(nodeB); b.Drain != hubfail.DrainNone {
		t.Fatalf("B: %v", b)
	}
}

// GP-r3-1: the hub that took the lease again learns a returned node has no drain from the table that advertises it, not from a
// drain it saw (it saw none). That is the only way the stored "done" of a node that is serving again becomes "none".
//
// Fails if: feedDrains marks a node as seen only when it is draining (A keeps drain_state done for good after F3 returns it).
func TestARestartedHubClearsTheStoredDrainOfANodeItSeesAdvertisedAgain(t *testing.T) {
	w := newWorld(t)
	w.settled()
	w.str.open[uid(nodeB)] = true
	w.tick()
	w.run(40*time.Second, w.traffic(true, true))
	w.holdA()
	w.run(3*time.Second, nil)
	w.heartbeat(nodeA, w.pvAt(w.loop.Version(), nodeB), nil)
	w.run(365*time.Second, w.traffic(true, true))
	if before := w.db.state(nodeA); before.Drain != hubfail.DrainDone {
		t.Fatalf("setup: A is %v", before)
	}

	// The restart: this process never saw A drain.
	w.lease.held = false
	w.run(2*time.Second, nil)
	w.lease.held = true
	w.run(30*time.Second, w.traffic(true, true))
	if got := w.db.state(nodeA); got.Drain != hubfail.DrainDone || !w.db.node(nodeA).Withdrawn {
		t.Fatalf("setup: the restarted hub touched A: %v", got)
	}

	w.db.mu.Lock()
	w.db.reqs = append(w.db.reqs, store.HubFailRequest{ID: uid(92), Node: uid(nodeA), Kind: "release", RequestedAt: w.clk.Now()})
	w.db.mu.Unlock()
	w.run(zone.Inputs().Stable+60*time.Second, w.traffic(true, true))
	if w.db.node(nodeA).Withdrawn {
		t.Fatal("setup: A was not returned")
	}
	if a := w.db.state(nodeA); a.Drain != hubfail.DrainNone || !a.DrainSince.IsZero() {
		t.Fatalf("a node that serves again keeps its stored drain: %v", a)
	}
}

// GP-r1-10: the tick checks the lease at its start, and the rows are written at its end. A hub whose lease went in between
// writes nothing.
//
// Fails if: publishState writes without asking the lease again.
func TestAHubThatLostTheLeaseDuringTheTickWritesNoRows(t *testing.T) {
	w := newWorld(t)
	w.settled()
	w.str.open[uid(nodeB)] = true
	w.db.mu.Lock()
	w.db.failState = true
	w.db.mu.Unlock()
	w.run(20*time.Second, w.traffic(true, true)) // quiet ticks with rows waiting to be written
	before := w.lease.calls
	w.run(time.Second, nil)
	perTick := w.lease.calls - before
	w.db.mu.Lock()
	w.db.failState = false
	w.db.mu.Unlock()
	w.lease.dropAt = w.lease.calls + perTick // the last question of the next tick is the one before the write
	w.run(time.Second, nil)
	if n := w.db.writes(); n != 0 {
		t.Fatalf("%d writes by a hub whose lease was gone", n)
	}
}

// GP-r1-10: the write carries no fence, so the leader writes every row again from time to time; a stale row that got in after the
// lease moved does not stay for good.
//
// Fails if: publishState never writes an unchanged row again.
func TestRowsAreRewrittenFromTimeToTime(t *testing.T) {
	w := newWorld(t)
	w.settled()
	w.str.open[uid(nodeB)] = true
	w.run(20*time.Second, w.traffic(true, true))
	if w.db.writes() == 0 {
		t.Fatal("setup: nothing was written")
	}
	w.db.mu.Lock()
	w.db.states[uid(nodeA)] = store.HubNodeState{Node: uid(nodeA), Drain: hubfail.DrainDraining, DrainSince: w.clk.Now(), DrainKnown: true}
	w.db.mu.Unlock() // what a hub that lost the lease mid-write left
	w.run(6*time.Minute, w.traffic(true, true))
	if got := w.db.state(nodeA); got.Drain != hubfail.DrainNone {
		t.Fatalf("the stale row stayed: %v", got)
	}
}

// GW2-r2-1: a drain that began before a restart for a node that is not withdrawn (a pair change, not a withdrawal) is over for the
// node's clients once its time has passed, and the hub that took over ends it. The node is not advertised in the table it applied
// and the new hub has no drain of it in memory, so without this the stored "draining" stays for good.
//
// Fails if: HubNodeState.DrainSettled is not set for a node fed a table that does not advertise it (B keeps drain_state draining),
// or is set before the stored drain has run for its time (B turns done at once).
func TestAStoredDrainOfANodeThatIsNotWithdrawnEndsWhenItsTimeHasPassed(t *testing.T) {
	w := newWorld(t)
	w.settled()
	w.str.open[uid(nodeB)] = true
	old, young := w.clk.Now().Add(-10*time.Minute), w.clk.Now().Add(-time.Minute)
	w.db.mu.Lock()
	w.db.states[uid(nodeB)] = store.HubNodeState{Node: uid(nodeB), Drain: hubfail.DrainDraining, DrainSince: old, DrainKnown: true}
	w.db.mu.Unlock()
	w.tick()
	w.heartbeat(nodeB, w.pvAt(w.loop.Version(), nodeA), nil)
	w.run(10*time.Second, w.traffic(true, true))
	if got := w.db.state(nodeB); got.Drain != hubfail.DrainDone || !got.DrainSince.Equal(old) {
		t.Fatalf("an old stored drain of B was not ended: %v", got)
	}

	w = newWorld(t)
	w.settled()
	w.str.open[uid(nodeB)] = true
	w.db.mu.Lock()
	w.db.states[uid(nodeB)] = store.HubNodeState{Node: uid(nodeB), Drain: hubfail.DrainDraining, DrainSince: young, DrainKnown: true}
	w.db.mu.Unlock()
	w.tick()
	w.heartbeat(nodeB, w.pvAt(w.loop.Version(), nodeA), nil)
	w.run(10*time.Second, w.traffic(true, true))
	if got := w.db.state(nodeB); got.Drain != hubfail.DrainDraining {
		t.Fatalf("a drain that has not run for its time was ended: %v", got)
	}
}

// GW3-r1-1: a stored drain that was young when the hub first wrote the settled row ends when its 360 s have passed, not at some later
// full refresh. The drain here began 10 s before the first write, so the refresh 300 s later still finds it young and the next one is
// 600 s away; only the rewrite after the first settled write can end it by 370 s.
//
// Fails if: publishState does not write a settled row again once 360 s have passed since its first settled write (the row stays
// draining at 370 s), or writes it early (it is done at 300 s).
func TestAYoungStoredDrainOfANodeThatIsNotWithdrawnEndsWhenItsTimeHasPassedWithNoOtherChange(t *testing.T) {
	w := newWorld(t)
	w.settled()
	w.str.open[uid(nodeB)] = true
	young := w.clk.Now().Add(-10 * time.Second)
	w.db.mu.Lock()
	w.db.states[uid(nodeB)] = store.HubNodeState{Node: uid(nodeB), Drain: hubfail.DrainDraining, DrainSince: young, DrainKnown: true}
	w.db.mu.Unlock()
	w.tick()
	w.heartbeat(nodeB, w.pvAt(w.loop.Version(), nodeA), nil)
	w.run(320*time.Second, w.traffic(true, true))
	if got := w.db.state(nodeB); got.Drain != hubfail.DrainDraining {
		t.Fatalf("the drain of B ended before its time: %v", got)
	}
	w.run(50*time.Second, w.traffic(true, true))
	if got := w.db.state(nodeB); got.Drain != hubfail.DrainDone || !got.DrainSince.Equal(young) {
		t.Fatalf("the drain of B did not end when its time passed: %v", got)
	}
}
