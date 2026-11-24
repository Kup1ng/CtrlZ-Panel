package endpoints

import (
	"slices"
	"sort"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Shared/schedule"
)

// Stack is the ordered pair of profiles an identity is filtered by: position 0 is the enforced profile and 1 is Profile 2
// (SC 5.6). The nil id is an absent profile.
type Stack struct{ First, Second uuid.UUID }

// list is the stack as a slice, position by position, the nil id standing for an absent profile.
func (s Stack) list() []uuid.UUID { return []uuid.UUID{s.First, s.Second} }

// pos is the position of the profile in the stack, or -1.
func (s Stack) pos(p uuid.UUID) int {
	for i, x := range s.list() {
		if x != uuid.Nil && x == p {
			return i
		}
	}
	return -1
}

// Window is one schedule window: minutes [Start, End) of the week in the Endpoint's zone, Sunday 00:00 being 0, both
// multiples of 30.
type Window struct {
	ID         uuid.UUID
	Start, End int
	Stack      Stack
}

// Grid is the one function that turns the windows of an Endpoint into the cells of the compiled schedule (spec 3.2, SC 5.9):
// windows ordered by their start, window n (1-based) fills cells Start/30 to End/30-1 with n, and every other cell is 0, the
// base stack. P4's compiler calls it, so the panel's check of which profiles a change removes and the node's schedule are
// one reading. A window across Saturday to Sunday is two rows; the editor splits it.
func Grid(ws []Window) [schedule.Cells]byte {
	var g [schedule.Cells]byte
	for n, w := range sortedWindows(ws) {
		for c := w.Start / schedule.MinutesPerCell; c < w.End/schedule.MinutesPerCell && c < schedule.Cells; c++ {
			g[c] = byte(n + 1)
		}
	}
	return g
}

func sortedWindows(ws []Window) []Window {
	out := slices.Clone(ws)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Start < out[j].Start })
	return out
}

// Away says which identities of an Endpoint a request turns away, so that they have no stack after it (spec 3.3: hard and
// soft disable, deleting the Endpoint, rotation, Require Authorized IPs, deleting authorized rows).
type Away uint8

const (
	// AwayNone turns nobody away.
	AwayNone Away = iota
	// AwayEncrypted turns away every identity but the Plain DNS ones: rotation changes the resolver id and the token, which
	// a plain query never carries.
	AwayEncrypted
	// AwayAll turns away every identity.
	AwayAll
)

// Input is everything of one Endpoint that decides the stack that applies to an identity, as of one moment of the data
// (spec 3.3).
type Input struct {
	// Zone is the IANA name of the Endpoint's time zone.
	Zone string
	Base Stack
	// Windows need not be sorted.
	Windows []Window
	// Clients are the clients that have a stack of their own, by label. A label with no row, and a client with no stack of
	// its own, resolve as no client.
	Clients map[string]Stack
	// Plain are the ids of the claims that stand for a Plain DNS identity: active or grace claims of an Endpoint with Legacy
	// DNS on. Each resolves as the client "default".
	Plain []uuid.UUID
	// Away is what the request does to the identities after it. It is read from the after side only.
	Away Away
}

// horizon is how far ahead the stack is evaluated (spec 3.3): the 366 days a compile covers.
const horizon = 366 * 24 * time.Hour

// Needed returns the profiles whose lock password a change needs: those that are in the stack of some identity at some
// 30-minute step of the next 366 days before the change, and after it are not in that stack or are at a later position
// (adding a profile, or moving one earlier, needs nothing: the lock guards content, not attachment, P2 7.3). The caller
// keeps only the profiles that are locked. after nil is a delete of the Endpoint.
//
// Cost: the weekly grid has at most 336 cells, so when the windows and the zone do not change, the grid values that some
// cell holds are the only ones to try and one evaluation per value answers the question for all 366 days. Only a change of
// the windows or of the zone steps through the days, in 17,568 steps of a cell lookup each. E3 compares both with the
// 30-minute reference.
func Needed(now time.Time, before, after *Input) []uuid.UUID {
	removed := map[uuid.UUID]bool{}
	pairs := cellPairs(now, before, after)
	for _, id := range identities(before, after) {
		for pr := range pairs {
			sb := before.stackOf(id, pr[0])
			sa := after.stackAfter(id, pr[1])
			for i, p := range sb.list() {
				if p == uuid.Nil {
					continue
				}
				if j := sa.pos(p); j < 0 || j > i {
					removed[p] = true
				}
			}
		}
	}
	out := make([]uuid.UUID, 0, len(removed))
	for p := range removed {
		out = append(out, p)
	}
	slices.SortFunc(out, func(a, b uuid.UUID) int { return slices.Compare(a[:], b[:]) })
	return out
}

// ident is an identity of an Endpoint: its traffic with no client, one client label, or one Plain DNS claim.
type ident struct {
	none  bool
	label string
	plain uuid.UUID
}

func identities(before, after *Input) []ident {
	out := []ident{{none: true}}
	labels := map[string]bool{}
	for l := range before.Clients {
		labels[l] = true
	}
	if after != nil {
		for l := range after.Clients {
			labels[l] = true
		}
	}
	names := make([]string, 0, len(labels))
	for l := range labels {
		names = append(names, l)
	}
	sort.Strings(names)
	for _, l := range names {
		out = append(out, ident{label: l})
	}
	for _, c := range before.Plain {
		out = append(out, ident{plain: c})
	}
	return out
}

// cellStack is the stack the base or a window gives at grid value c (0 is the base).
func (in *Input) cellStack(ws []Window, c int) Stack {
	if c <= 0 || c > len(ws) {
		return in.Base
	}
	return ws[c-1].Stack
}

// stackOf is the stack of an identity when the grid value is c, in the state this input describes.
func (in *Input) stackOf(id ident, c int) Stack {
	switch {
	case id.none:
	case id.plain != uuid.Nil:
		if s, ok := in.Clients["default"]; ok {
			return s
		}
	default:
		if s, ok := in.Clients[id.label]; ok {
			return s
		}
	}
	return in.cellStack(sortedWindows(in.Windows), c)
}

// stackAfter is stackOf for the state after the change: empty for an identity the change turns away, or that no longer
// exists (a Plain DNS identity whose claim went, or whose Legacy DNS was switched off).
func (in *Input) stackAfter(id ident, c int) Stack {
	if in == nil {
		return Stack{}
	}
	switch in.Away {
	case AwayAll:
		return Stack{}
	case AwayEncrypted:
		if id.plain == uuid.Nil {
			return Stack{}
		}
	}
	if id.plain != uuid.Nil && !slices.Contains(in.Plain, id.plain) {
		return Stack{}
	}
	return in.stackOf(id, c)
}

// cellFn maps an absolute instant to the grid value of the Endpoint at it, in the Endpoint's zone.
func (in *Input) cellFn() func(unix int64) int {
	ws := sortedWindows(in.Windows)
	if len(ws) == 0 {
		return func(int64) int { return 0 }
	}
	g := Grid(ws)
	loc, err := time.LoadLocation(in.Zone)
	if err != nil {
		loc = time.UTC
	}
	return func(unix int64) int {
		t := time.Unix(unix, 0).In(loc)
		minute := int(t.Weekday())*24*60 + t.Hour()*60 + t.Minute()
		return int(g[minute/schedule.MinutesPerCell])
	}
}

func sameSchedule(a, b *Input) bool {
	if a.Zone != b.Zone || len(a.Windows) != len(b.Windows) {
		return false
	}
	aw, bw := sortedWindows(a.Windows), sortedWindows(b.Windows)
	for i := range aw {
		if aw[i].Start != bw[i].Start || aw[i].End != bw[i].End {
			return false
		}
	}
	return true
}

// cellPairs are the (before, after) grid values that some instant of the horizon has. For an after that is nil or turns
// everybody away, or a schedule that did not change, the two sides are the same grid and the pairs are its values.
func cellPairs(now time.Time, before, after *Input) map[[2]int]struct{} {
	out := map[[2]int]struct{}{}
	if after == nil || after.Away == AwayAll || sameSchedule(before, after) {
		// One grid: every value of it that a cell holds. 0 is there only while some cell holds the base.
		for _, v := range Grid(before.Windows) {
			out[[2]int{int(v), int(v)}] = struct{}{}
		}
		return out
	}
	fb, fa := before.cellFn(), after.cellFn()
	step := int64(schedule.MinutesPerCell * 60)
	start := now.Unix() - now.Unix()%step
	end := now.Add(horizon).Unix()
	for t := start; t <= end; t += step {
		out[[2]int{fb(t), fa(t)}] = struct{}{}
	}
	return out
}

// Profiles lists every profile that is in some stack of the input, sorted.
func (in *Input) Profiles() []uuid.UUID {
	set := map[uuid.UUID]bool{}
	add := func(s Stack) {
		for _, p := range s.list() {
			if p != uuid.Nil {
				set[p] = true
			}
		}
	}
	add(in.Base)
	for _, w := range in.Windows {
		add(w.Stack)
	}
	for _, s := range in.Clients {
		add(s)
	}
	out := make([]uuid.UUID, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	slices.SortFunc(out, func(a, b uuid.UUID) int { return slices.Compare(a[:], b[:]) })
	return out
}
