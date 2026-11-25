package zone

import (
	"errors"
	"testing"
	"time"
)

// evalFixture is a pair (A, B) with A dead and B ready, so F1 acts for A 5 s
// after the tick on which dead(A) first holds.
func evalFixture(t *testing.T) (*Evaluator, time.Time) {
	t.Helper()
	tb := tbl(t, nil, bp('p', 'A', 'B'))
	t0 := time.Unix(1_000_000, 0)
	e := newEval(t, t0, tb, tb, map[NodeID]Columns{nid('A'): {}, nid('B'): {}, nid('C'): {}})
	at := func(s int) time.Time { return t0.Add(time.Duration(s) * time.Second) }
	for s := 5; s <= 15; s += 5 {
		e.ProbeRound(at(s), nid('B'), true, true)
	}
	e.Heartbeat(at(12), nid('B'), Report{Paths: []bool{true}, Peers: []PeerEntry{{Node: nid('A'), Known: true, Down: true}}})
	return e, t0
}

// A tick whose event fails to commit ends there, changes nothing, and the same
// event is decided again on the next tick (8a.4 Versions, 8a.6 Order on a tick).
func TestCommitFailureEndsTheTickAndChangesNothing(t *testing.T) {
	e, t0 := evalFixture(t)
	boom := errors.New("commit failed")
	for s := 0; s <= 19; s++ {
		e.Heartbeat(t0.Add(time.Duration(s)*time.Second), nid('B'), Report{Paths: []bool{true}, Peers: []PeerEntry{{Node: nid('A'), Known: true, Down: true}}})
		if outs, err := e.Tick(t0.Add(time.Duration(s)*time.Second), nil, nil); err != nil || len(outs) != 0 {
			t.Fatalf("tick %d: %v %v", s, outs, err)
		}
	}
	// dead(A) began to hold at 15 s (hb(A) is 15 s old): F1 is due at 20 s.
	now := t0.Add(20 * time.Second)
	e.Heartbeat(now, nid('B'), Report{Paths: []bool{true}, Peers: []PeerEntry{{Node: nid('A'), Known: true, Down: true}}})
	outs, err := e.Tick(now, nil, func(*Event) error { return boom })
	if !errors.Is(err, boom) || len(outs) != 0 {
		t.Fatalf("a failed commit: %v %v", outs, err)
	}
	if e.Columns(nid('A')).Withdrawn {
		t.Fatal("a failed commit changed the columns")
	}
	if e.LastTable() == nil {
		t.Fatal("last table lost")
	}
	now = now.Add(time.Second)
	e.Heartbeat(now, nid('B'), Report{Paths: []bool{true}, Peers: []PeerEntry{{Node: nid('A'), Known: true, Down: true}}})
	outs, err = e.Tick(now, nil, nil)
	if err != nil || len(outs) != 1 || outs[0].Event.Row != F1 || !e.Columns(nid('A')).Withdrawn {
		t.Fatalf("the event is decided again: %v %v", outs, err)
	}
}

// The start event is F0 when a node's peer differs from last_table and the
// refresh otherwise, and it reads no tracker.
func TestStartEvent(t *testing.T) {
	tb := tbl(t, nil, bp('p', 'A', 'B'))
	t0 := time.Unix(5000, 0)
	e := newEval(t, t0, tb, tb, map[NodeID]Columns{})
	outs, err := e.Start(t0, nil)
	if err != nil || len(outs) != 1 || outs[0].Event.Row != F7 {
		t.Fatalf("no difference: %v %v", outs, err)
	}
	e = newEval(t, t0, tb, &Table{}, map[NodeID]Columns{})
	outs, err = e.Start(t0, nil)
	if err != nil || len(outs) != 1 || outs[0].Event.Row != F0 || !e.Columns(nid('A')).Withdrawn {
		t.Fatalf("a new pair: %v %v", outs, err)
	}
}

// A node that leaves the membership takes its columns and trackers with it.
func TestRemovedNodeIsForgotten(t *testing.T) {
	tb := tbl(t, nil, bp('p', 'A', 'B'))
	t0 := time.Unix(5000, 0)
	e := newEval(t, t0, tb, tb, map[NodeID]Columns{nid('C'): {Withdrawn: true}})
	if !e.Columns(nid('C')).Withdrawn {
		t.Fatal("setup")
	}
	if err := e.SetMembership(t0, &Table{Nodes: map[NodeID]Node{nid('A'): tb.Nodes[nid('A')]}, Pairs: map[PairID]Pair{}}); err != nil {
		t.Fatal(err)
	}
	if e.Columns(nid('C')) != (Columns{}) {
		t.Fatal("a removed node keeps its columns")
	}
}

func newEval(t *testing.T, now time.Time, member, last *Table, cols map[NodeID]Columns) *Evaluator {
	t.Helper()
	e, err := NewEvaluator(now, member, last, cols)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// readyNode gives x three passing rounds and a fresh Heartbeat, so that
// ready(x) and fit(x) hold at now.
func readyNode(e *Evaluator, now time.Time, x NodeID) {
	for s := 15; s >= 5; s -= 5 {
		e.ProbeRound(now.Add(-time.Duration(s)*time.Second), x, true, true)
	}
	e.Heartbeat(now.Add(-time.Second), x, Report{Paths: []bool{true}})
}

// The notice list stays bounded however many HeadNotices the hub sends, and
// folding does not change what fit says (8a.4: only the highest seq among the
// notices older than the grace counts).
func TestHeadNoticeListIsBounded(t *testing.T) {
	tb := tbl(t, nil, bp('p', 'A', 'B'))
	t0 := time.Unix(1_000_000, 0)
	e := newEval(t, t0, tb, tb, map[NodeID]Columns{})
	const n = 100_000
	for i := 1; i <= n; i++ {
		e.HeadNotice(t0.Add(time.Duration(i)*time.Second), nid('A'), uint64(i))
	}
	last := t0.Add(n * time.Second)
	// One notice per second and a 30 s grace: the folded one plus about 30.
	if got := len(e.trk[nid('A')].notices); got > 40 {
		t.Fatalf("%d notices kept after %d", got, n)
	}
	now := last.Add(40 * time.Second)
	readyNode(e, now, nid('A'))
	// Every notice is past the grace now; the highest seq is n.
	e.Heartbeat(now, nid('A'), Report{Paths: []bool{true}, AppliedSeq: n - 1})
	if e.fit(now, nid('A')) {
		t.Fatal("fit holds with applied_seq below the highest old notice")
	}
	e.Heartbeat(now, nid('A'), Report{Paths: []bool{true}, AppliedSeq: n})
	if !e.fit(now, nid('A')) {
		t.Fatal("fit fails with applied_seq at the highest notice")
	}
}

// A notice still inside the grace never blocks fit, and a lower seq sent later
// never hides a higher one that is already old.
func TestHeadNoticeFoldKeepsTheHighestOldSeq(t *testing.T) {
	tb := tbl(t, nil, bp('p', 'A', 'B'))
	t0 := time.Unix(1_000_000, 0)
	e := newEval(t, t0, tb, tb, map[NodeID]Columns{})
	e.HeadNotice(t0, nid('A'), 9)
	e.HeadNotice(t0.Add(40*time.Second), nid('A'), 3) // folds the 9 in
	e.HeadNotice(t0.Add(41*time.Second), nid('Z'), 1) // not in the membership
	now := t0.Add(42 * time.Second)
	readyNode(e, now, nid('A'))
	e.Heartbeat(now, nid('A'), Report{Paths: []bool{true}, AppliedSeq: 5})
	if e.fit(now, nid('A')) {
		t.Fatal("the old notice with seq 9 was lost by folding")
	}
	e.Heartbeat(now, nid('A'), Report{Paths: []bool{true}, AppliedSeq: 9})
	if !e.fit(now, nid('A')) {
		t.Fatal("seq 3 is still inside the grace and must not block")
	}
}

// A nil table is refused and changes nothing: it is not an empty membership.
func TestNilMembershipIsRefused(t *testing.T) {
	tb := tbl(t, nil, bp('p', 'A', 'B'))
	t0 := time.Unix(5000, 0)
	if _, err := NewEvaluator(t0, nil, tb, nil); !errors.Is(err, ErrNoMembership) {
		t.Fatalf("NewEvaluator(nil): %v", err)
	}
	cols := map[NodeID]Columns{nid('A'): {Withdrawn: true, Hold: true, LastFailbackAt: t0, FlapUntil: t0.Add(time.Hour)}}
	e := newEval(t, t0, tb, tb, cols)
	if err := e.SetMembership(t0.Add(time.Second), nil); !errors.Is(err, ErrNoMembership) {
		t.Fatalf("SetMembership(nil): %v", err)
	}
	if e.Columns(nid('A')) != cols[nid('A')] {
		t.Fatal("a refused nil table changed the columns")
	}
	if len(e.trk) != len(tb.Nodes) || e.member != tb {
		t.Fatal("a refused nil table changed the membership or the trackers")
	}
}

// Only F1 and F2 run the flap rule (8a.6). F4, F6 and F0 also withdraw or clear
// a node, but a failback less than 3600 s ago is no flap for them: no
// flap_until and no alert.
func TestOnlyF1AndF2RunTheFlapRule(t *testing.T) {
	t0 := time.Unix(2_000_000, 0)
	now := t0.Add(20 * time.Second)
	recent := now.Add(-3599 * time.Second)
	noFlap := func(t *testing.T, what string, ev *Event) {
		t.Helper()
		for id, c := range ev.Changed {
			if !c.FlapUntil.IsZero() {
				t.Fatalf("%s set flap_until on %x", what, id[0])
			}
		}
		for _, a := range ev.Alerts {
			if a.Kind == AlertFlapping {
				t.Fatalf("%s raised a flapping alert", what)
			}
		}
	}
	only := func(t *testing.T, outs []Output, row string) *Event {
		t.Helper()
		if len(outs) != 1 || outs[0].Event == nil || outs[0].Event.Row != row {
			t.Fatalf("want one %s event, got %+v", row, outs)
		}
		return outs[0].Event
	}
	tb := tbl(t, nil, bp('p', 'A', 'B'))

	// F4: Hold on A, whose peer B is fit.
	e := newEval(t, t0, tb, tb, map[NodeID]Columns{nid('A'): {LastFailbackAt: recent}})
	readyNode(e, now, nid('B'))
	outs, err := e.Tick(now, []Request{{ID: "h", Node: nid('A'), Kind: ReqHold, RequestedAt: now}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ev := only(t, outs, F4)
	if !e.Columns(nid('A')).Withdrawn || !e.Columns(nid('A')).Hold {
		t.Fatal("setup: the Hold did not withdraw and hold A")
	}
	noFlap(t, "F4", ev)

	// F6: Force failback of a withdrawn A that is fit.
	e = newEval(t, t0, tb, tb, map[NodeID]Columns{nid('A'): {Withdrawn: true, LastFailbackAt: recent}})
	readyNode(e, now, nid('A'))
	outs, err = e.Tick(now, []Request{{ID: "f", Node: nid('A'), Kind: ReqForceFailback, RequestedAt: now}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	noFlap(t, "F6", only(t, outs, F6))

	// F0: A leaves the pair while advertised, so F0 withdraws it.
	e = newEval(t, t0, tb, tb, map[NodeID]Columns{nid('A'): {LastFailbackAt: recent}})
	if err := e.SetMembership(now, tbl(t, nil, bp('p', 'C', 'B'))); err != nil {
		t.Fatal(err)
	}
	outs, err = e.Tick(now, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	ev = only(t, outs, F0)
	if !e.Columns(nid('A')).Withdrawn {
		t.Fatal("setup: F0 did not withdraw the leaving A")
	}
	noFlap(t, "F0", ev)
}

// When several notices are already past the grace, the fold keeps the highest
// seq, not the first or the lowest: 9 then 5 leaves 9 (8a.4 fit).
func TestHeadNoticeFoldKeepsTheHighestOfSeveralOldSeqs(t *testing.T) {
	tb := tbl(t, nil, bp('p', 'A', 'B'))
	t0 := time.Unix(1_000_000, 0)
	e := newEval(t, t0, tb, tb, map[NodeID]Columns{})
	e.HeadNotice(t0, nid('A'), 9)
	e.HeadNotice(t0.Add(time.Second), nid('A'), 5)
	e.HeadNotice(t0.Add(40*time.Second), nid('A'), 7) // folds 9 and 5, both old
	now := t0.Add(41 * time.Second)
	readyNode(e, now, nid('A'))
	for seq := uint64(5); seq <= 8; seq++ {
		e.Heartbeat(now, nid('A'), Report{Paths: []bool{true}, AppliedSeq: seq})
		if e.fit(now, nid('A')) {
			t.Fatalf("fit holds with applied_seq %d below the old notice 9", seq)
		}
	}
	e.Heartbeat(now, nid('A'), Report{Paths: []bool{true}, AppliedSeq: 9})
	if !e.fit(now, nid('A')) {
		t.Fatal("fit fails with applied_seq 9; seq 7 is inside the grace")
	}
}

// rd(X) needs at least one listed resolve path (8a.4): an X whose Heartbeat
// lists none, as before its first health check or in upstream mode with no
// upstream, is not a node that cannot resolve.
func TestRdNeedsAListedPath(t *testing.T) {
	tb := tbl(t, nil, bp('p', 'A', 'B'))
	t0 := time.Unix(1_000_000, 0)
	e := newEval(t, t0, tb, tb, map[NodeID]Columns{})
	now := t0.Add(time.Second)
	e.Heartbeat(now, nid('B'), Report{Paths: []bool{true}})
	e.Heartbeat(now, nid('A'), Report{Paths: []bool{false}})
	if !e.rd(now, nid('A')) {
		t.Fatal("setup: one unhealthy listed path beside a healthy peer is rd")
	}
	e.Heartbeat(now, nid('A'), Report{Paths: nil})
	if e.rd(now, nid('A')) {
		t.Fatal("rd holds for a Heartbeat that lists no resolve path")
	}
}
