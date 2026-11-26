package lockrank

import "fmt"

// State is what one transaction holds. It is not safe for concurrent use; a
// transaction runs on one goroutine.
type State struct {
	held         map[string]Mode
	highest      Rank
	highestTable string
}

// OrderError is a lock requested below one the transaction already holds. It
// names tables and ranks only, never a statement or a value.
type OrderError struct {
	Table, Held   string
	Rank, HeldRnk Rank
}

func (e *OrderError) Error() string {
	return fmt.Sprintf("lock order: %s (rank %d) requested while holding %s (rank %d)", e.Table, e.Rank, e.Held, e.HeldRnk)
}

// Acquire applies the touches of one statement in order. A touch that a lock
// already held satisfies is not an acquisition: the same transaction asking
// again for a row it holds (Refresh takes the user's key share first so that
// the key share its refresh insert needs later is already held) cannot wait for
// itself. Anything else must not rank below the highest table held, unless it
// never waits (SKIP LOCKED).
//
// Two limits are deliberate. The check knows tables, not rows, so "already
// held" assumes the same row; the transactions of the system work on one user,
// one session or one singleton at a time, and the pairwise race tests cover the
// rest. And an insert is trusted: its row is invisible to everyone else.
func (s *State) Acquire(ts []Touch) error {
	if s.held == nil {
		s.held = map[string]Mode{}
	}
	for _, t := range ts {
		if t.Mode == KeyShare && Inert(t.Table) {
			continue
		}
		r, ok := Of(t.Table)
		if !ok {
			return fmt.Errorf("lock order: table %q is not ranked", t.Table)
		}
		if t.Mode == Insert {
			if s.held[t.Table] < Write {
				s.held[t.Table] = Write
			}
			continue
		}
		if s.held[t.Table] >= t.Mode {
			continue
		}
		if !t.NoWait && r < s.highest {
			return &OrderError{Table: t.Table, Rank: r, Held: s.highestTable, HeldRnk: s.highest}
		}
		s.held[t.Table] = t.Mode
		if r >= s.highest {
			s.highest, s.highestTable = r, t.Table
		}
	}
	return nil
}

// RankRiver is where River's own statements sit: after everything, the audit log included. River's tables are in schema
// river, which nothing else of the module touches, and its statements run on the transaction directly and are not read by
// Analyze, so the one call that lets them run (store.GlobalTx.RiverInsert) declares them last: any statement that follows
// in the transaction would take a lock below them and is refused with an OrderError.
const RankRiver Rank = 950

// AcquireRiver declares that River's statements ran in this transaction.
func (s *State) AcquireRiver() error {
	if s.held == nil {
		s.held = map[string]Mode{}
	}
	if s.highest > RankRiver {
		return &OrderError{Table: "river", Rank: RankRiver, Held: s.highestTable, HeldRnk: s.highest}
	}
	s.held["river"] = Write
	s.highest, s.highestTable = RankRiver, "river"
	return nil
}
