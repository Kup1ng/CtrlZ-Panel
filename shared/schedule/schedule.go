// Package schedule evaluates a weekly Schedule grid in a local-time zone that
// may change offset (DST) during the compiled horizon.
package schedule

import (
	"errors"
	"sort"
	"time"
)

const (
	// Cells is the number of 30-minute cells in a week.
	Cells = 336
	// MinutesPerCell is the grid resolution. 30 and not 60 because Iran uses
	// UTC+3:30, and a one-hour grid could not express a half-hour zone.
	MinutesPerCell = 30
	weekMinutes    = 7 * 24 * 60
)

// Transition switches the UTC offset (seconds east) at Unix time At.
type Transition struct {
	At     int64
	Offset int32
}

// Schedule is the compiled form: base offset, ordered transitions and the grid.
// Grid value 0 means the base stack, n means window n-1.
type Schedule struct {
	BaseOffset  int32
	Transitions []Transition // ascending At
	Grid        [Cells]byte
}

var (
	ErrGridSize        = errors.New("schedule: grid must be exactly 336 bytes")
	ErrTransitionOrder = errors.New("schedule: transitions must be strictly ascending")
	ErrWindowRange     = errors.New("schedule: grid value refers to a window that does not exist")
)

// New validates and builds a Schedule. windows is the number of windows, so a
// grid value above windows is rejected rather than silently meaning "base".
func New(baseOffset int32, trans []Transition, grid []byte, windows int) (*Schedule, error) {
	if len(grid) != Cells {
		return nil, ErrGridSize
	}
	for i := 1; i < len(trans); i++ {
		if trans[i].At <= trans[i-1].At {
			return nil, ErrTransitionOrder
		}
	}
	s := &Schedule{BaseOffset: baseOffset, Transitions: append([]Transition(nil), trans...)}
	copy(s.Grid[:], grid)
	for _, v := range s.Grid {
		if int(v) > windows {
			return nil, ErrWindowRange
		}
	}
	return s, nil
}

// Offset returns the UTC offset in force at now: the last transition with
// At <= now, else the base offset. After the last transition the last offset
// holds, which is why the panel recompiles monthly to keep the list ahead.
func (s *Schedule) Offset(now int64) int32 {
	i := sort.Search(len(s.Transitions), func(i int) bool { return s.Transitions[i].At > now })
	if i == 0 {
		return s.BaseOffset
	}
	return s.Transitions[i-1].Offset
}

// CellIndex is the grid index (0 is Sunday 00:00 local) for now.
//
//	t      = now + offset
//	minute = floorDiv(t, 60) + 4*1440, then modulo 10080
//
// The 4*1440 shifts the Unix epoch (a Thursday) onto a Sunday-based week.
// Floor division keeps the arithmetic right for negative local times.
func (s *Schedule) CellIndex(now int64) int {
	t := now + int64(s.Offset(now))
	minute := floorDiv(t, 60) + 4*1440
	minute = ((minute % weekMinutes) + weekMinutes) % weekMinutes
	return int(minute / MinutesPerCell)
}

// Cell returns the grid value for now: 0 is the base stack, n is window n-1.
func (s *Schedule) Cell(now int64) uint16 { return uint16(s.Grid[s.CellIndex(now)]) }

func floorDiv(a, b int64) int64 {
	q := a / b
	if (a%b != 0) && ((a < 0) != (b < 0)) {
		q--
	}
	return q
}

// BuildTransitions lists every offset change of loc in [from, to) and the
// offset at from. The panel uses it at compile time; the node never needs a
// time zone database because it only reads the resulting list. Changes are
// found by probing each hour (no real zone rule changes twice inside an hour)
// and then bisecting to the second.
func BuildTransitions(loc *time.Location, from, to int64) (base int32, out []Transition) {
	_, b := time.Unix(from, 0).In(loc).Zone()
	base = int32(b)
	prev := base
	const step = 3600
	for t := from; t < to; t += step {
		_, off := time.Unix(t+step, 0).In(loc).Zone()
		if int32(off) == prev {
			continue
		}
		lo, hi := t, t+step
		for hi-lo > 1 {
			mid := lo + (hi-lo)/2
			if _, o := time.Unix(mid, 0).In(loc).Zone(); int32(o) == prev {
				lo = mid
			} else {
				hi = mid
			}
		}
		out = append(out, Transition{At: hi, Offset: int32(off)})
		prev = int32(off)
	}
	return base, out
}
