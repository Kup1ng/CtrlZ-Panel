package policy

import (
	"github.com/Kup1ng/CtrlZ-Shared/blob"
	"github.com/Kup1ng/CtrlZ-Shared/schedule"
)

// NewStack builds the Stack for one or two profiles. p2 may be nil. The merge
// is computed here, once, so a query only reads it (R27). pairLocs is the
// location bitmap of the Endpoint's pair.
func NewStack(p1, p2 *blob.Profile, pairLocs []uint64) *Stack {
	st := &Stack{Slots: [2]*blob.Profile{p1, p2}, PairLocs: pairLocs}
	var def blob.Options
	o1, o2 := &def, &def
	if p1 != nil {
		o1 = p1.Options()
	}
	if p2 != nil {
		o2 = p2.Options()
	}
	merged := blob.Merge(o1, o2)
	st.Merged = &merged
	st.eff[0] = merged.Effective()
	st.eff[1] = o1.Effective()
	st.eff[2] = o2.Effective()
	for _, p := range st.Slots {
		if p == nil {
			continue
		}
		h := p.Header()
		st.HasDestGeo = st.HasDestGeo || h.HasDestGeo()
		st.Explicit = st.Explicit || h.Explicit()
		if h.MaxLabels > st.MaxDepth {
			st.MaxDepth = h.MaxLabels
		}
	}
	return st
}

// active reports whether slot i (0 or 1) is in force at now. A slot is active
// when now >= disabled_until, evaluated at query time so a Disable that lapses
// during a panel outage still ends on time (5.3).
func (st *Stack) active(i int, now int64) bool {
	p := st.Slots[i]
	return p != nil && p.Active(now)
}

// options returns the effective options and the number of active slots.
func (st *Stack) options(now int64) (*blob.Effective, int) {
	a0, a1 := st.active(0, now), st.active(1, now)
	switch {
	case a0 && a1:
		return &st.eff[0], 2
	case a0:
		return &st.eff[1], 1
	case a1:
		return &st.eff[2], 1
	}
	return &defaultEffective, 0
}

// defaultEffective is the options value used when no slot is active. It is
// written once at start and only read afterwards.
var defaultEffective = (&blob.Options{}).Effective()

// EndpointView is the evaluator's view of one Endpoint. Node glue converts the
// compiled records into it, so this package never imports the generated
// protobuf types.
type EndpointView struct {
	ID    [16]byte
	Base  *Stack
	Sched *schedule.Schedule // nil when the Endpoint has no schedule
	// Windows[n] is the stack of window n+1 (grid value n+1), and
	// WindowIDs[n] its id for logs.
	Windows   []*Stack
	WindowIDs [][16]byte
	// Clients maps ClientHash to that client's own stack. A client without its
	// own profile is simply absent.
	Clients map[[16]byte]*Stack
}

// SelectStack picks the stack for a query, most specific first (5.7):
//
//  1. a client with its own profile, always: it ignores the schedule;
//  2. the schedule window of this moment, which replaces the whole base stack,
//     Profile 2 included, so nothing from the base carries over;
//  3. the Endpoint's base stack.
//
// windowID is the schedule window used, zero otherwise, for the log.
func SelectStack(ep *EndpointView, clientHash [16]byte, now int64) (st *Stack, windowID [16]byte) {
	if clientHash != ([16]byte{}) {
		if cs, ok := ep.Clients[clientHash]; ok && cs != nil {
			return cs, windowID
		}
	}
	if ep.Sched != nil {
		if cell := int(ep.Sched.Cell(now)); cell > 0 && cell <= len(ep.Windows) && ep.Windows[cell-1] != nil {
			if cell <= len(ep.WindowIDs) {
				windowID = ep.WindowIDs[cell-1]
			}
			return ep.Windows[cell-1], windowID
		}
	}
	return ep.Base, windowID
}
