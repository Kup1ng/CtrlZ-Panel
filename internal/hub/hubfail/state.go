package hubfail

import (
	"context"
	"sort"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Shared/wire"
	"github.com/Kup1ng/CtrlZ-Shared/zone"

	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// The state the admin page reads (T-542, p4-nodes 5.6, SC 8a.4 Admin and 8a.6 drain). The hub keeps the F3 conditions that
// are unmet and the drain of each node in memory, because they come from trackers no other process has. This file turns them
// into rows of node_dns_state when they change. The hub never reads the rows back: they are a view, and the loop that decides
// does so from its memory.
//
// The names of unmet F3 conditions are the ones the node page renders (packages/ui admin nodes nodeParts F3_CONDITIONS), and the
// migration's CHECK holds the same closed list.
const (
	CondHeld         = "held"
	CondHubFit       = "hub_fit"
	CondPeerView     = "peer_view"
	CondStablePeriod = "stable_period"
	CondFlapping     = "flapping"

	DrainNone     = "none"
	DrainDraining = "draining"
	DrainDone     = "done"
)

func (l *Loop) resetState() {
	l.tbl, l.tblVer = nil, 0
	l.drains = map[uuid.UUID]*zone.Drain{}
	l.drainSince = map[uuid.UUID]time.Time{}
	l.drainFed = map[uuid.UUID]uint64{}
	// A hub that takes the lease again writes every row once more, whatever another hub wrote meanwhile.
	l.written = map[uuid.UUID]store.HubNodeState{}
}

// rememberTable keeps the table an event just signed (flags after the event) as the one nodes are asked to apply: the drain of a
// node is fed from it when the node reports that version.
func (l *Loop) rememberTable(pt *policyv1.PairTable, version uint64) {
	t, err := zone.Build(wire.ZoneInput(pt))
	if err != nil {
		// The push was validated before it was written, so this is a defect; the drain state stays as it was.
		if l.cfg.Log != nil {
			l.cfg.Log.Error("the signed table does not build for the drain view")
		}
		return
	}
	l.tbl, l.tblVer = t, version
}

// feedDrains gives each node's Drain the latest table once the node has reported that it applied it. The hub cannot see the node's
// own clock, so the drain starts at the Heartbeat that first carried the version: later than the real apply by at most a
// Heartbeat interval, so "done" is never shown early. A node whose Heartbeats do not reach the hub is never fed and never drains
// here, which is also what the hub knows of it.
func (l *Loop) feedDrains() {
	if l.tbl == nil {
		return
	}
	for _, t := range l.Targets() {
		id := t.ID
		if l.pvVer[id] < l.tblVer || l.drainFed[id] == l.tblVer {
			continue
		}
		l.drainFed[id] = l.tblVer
		d := l.drains[id]
		if d == nil {
			d = &zone.Drain{}
			l.drains[id] = d
		}
		was := d.Draining()
		at := l.fed[id].t
		d.Applied(at, l.tbl, nil, zone.NodeID(id)) // v1 has the global pair only (D30)
		switch {
		case d.Draining() && !was:
			l.drainSince[id] = at
		case !d.Draining():
			delete(l.drainSince, id)
		}
	}
}

// nodeState is the row of one node now.
func (l *Loop) nodeState(now time.Time, id uuid.UUID) store.HubNodeState {
	nid := zone.NodeID(id)
	st := store.HubNodeState{Node: id, Drain: DrainNone}
	if names, ok := l.f3Unmet(now, nid); ok {
		st.F3Unmet = names
		if len(names) > 0 && onlyTiming(names) {
			if due, running := l.ev.TimerDue(now, zone.F3, nid); running {
				st.F3DueAt = due
			}
		}
	}
	if d := l.drains[id]; d != nil && d.Draining() {
		st.Drain, st.DrainSince = DrainDraining, l.drainSince[id]
		if d.Done(now) {
			st.Drain = DrainDone
		}
	}
	return st
}

// f3Unmet names what keeps a node out of F3's return, in the order of the row. It says nothing (false) for a node F3 does not
// apply to: in no pair, or not withdrawn. For a withdrawn node it lists the stable period while the node has not been returned,
// because F3 acts the moment the period has passed with every other condition holding.
func (l *Loop) f3Unmet(now time.Time, nid zone.NodeID) ([]string, bool) {
	var names []string
	for _, c := range l.ev.Unmet(now, zone.F3, nid) {
		switch c.Pred {
		case zone.PredHasPeer, zone.PredWithdrawn:
			return nil, false
		case zone.PredHeld:
			names = append(names, CondHeld)
		case zone.PredFit:
			names = append(names, CondHubFit)
		case zone.PredViewUp:
			names = append(names, CondPeerView)
		}
	}
	if now.Before(l.ev.Columns(nid).FlapUntil) {
		names = append(names, CondFlapping)
	}
	return append(names, CondStablePeriod), true
}

// onlyTiming says the unmet list holds nothing but the waiting itself: every input holds and the count is running.
func onlyTiming(names []string) bool {
	for _, n := range names {
		if n != CondStablePeriod && n != CondFlapping {
			return false
		}
	}
	return true
}

func sameState(a, b store.HubNodeState) bool {
	if a.Node != b.Node || a.Drain != b.Drain || !a.F3DueAt.Equal(b.F3DueAt) || !a.DrainSince.Equal(b.DrainSince) || len(a.F3Unmet) != len(b.F3Unmet) {
		return false
	}
	for i := range a.F3Unmet {
		if a.F3Unmet[i] != b.F3Unmet[i] {
			return false
		}
	}
	return true
}

// publishState writes the rows that changed since the last write, in one transaction. A failed write is tried again on the next
// tick; it never ends the tick and never stops the hub (the page is a view), and its warning is rate-limited.
func (l *Loop) publishState(ctx context.Context, now time.Time) {
	var batch []store.HubNodeState
	for _, t := range l.Targets() {
		st := l.nodeState(now, t.ID)
		if prev, ok := l.written[t.ID]; ok && sameState(prev, st) {
			continue
		}
		batch = append(batch, st)
	}
	if len(batch) == 0 {
		return
	}
	sort.Slice(batch, func(i, j int) bool { return string(batch[i].Node[:]) < string(batch[j].Node[:]) })
	if err := l.cfg.Store.HubNodeStateWrite(ctx, batch); err != nil {
		if l.cfg.Log != nil && now.Sub(l.stateFail.t) >= notCommittedEvery {
			l.stateFail = stamp{now}
			l.cfg.Log.Warn("node dns state was not written")
		}
		return
	}
	for _, st := range batch {
		l.written[st.Node] = st
	}
}
