package endpoints

import (
	"math/rand"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
)

var (
	pA = uuid.MustParse("00000000-0000-7000-8000-00000000000a")
	pB = uuid.MustParse("00000000-0000-7000-8000-00000000000b")
	pC = uuid.MustParse("00000000-0000-7000-8000-00000000000c")
	pD = uuid.MustParse("00000000-0000-7000-8000-00000000000d")
)

var now0 = time.Date(2026, 11, 24, 10, 7, 0, 0, time.UTC)

func ids(ps ...uuid.UUID) []uuid.UUID {
	out := slices.Clone(ps)
	slices.SortFunc(out, func(a, b uuid.UUID) int { return slices.Compare(a[:], b[:]) })
	return out
}

func same(a, b []uuid.UUID) bool { return slices.Equal(ids(a...), ids(b...)) }

func TestGridFillsCellsInWindowOrder(t *testing.T) {
	ws := []Window{
		{Start: 600, End: 660}, // second by start
		{Start: 0, End: 90},    // first: cells 0..2
	}
	g := Grid(ws)
	for c, want := range map[int]byte{0: 1, 1: 1, 2: 1, 3: 0, 19: 0, 20: 2, 21: 2, 22: 0} {
		if g[c] != want {
			t.Errorf("cell %d is %d, want %d", c, g[c], want)
		}
	}
	// A window to the end of the week fills the last cell and nothing wraps.
	g = Grid([]Window{{Start: 10050, End: 10080}})
	if g[335] != 1 || g[0] != 0 {
		t.Errorf("last cell %d, first cell %d", g[335], g[0])
	}
}

func TestNeededBaseStack(t *testing.T) {
	base := func(a, b uuid.UUID) *Input { return &Input{Zone: "Asia/Tehran", Base: Stack{a, b}} }
	cases := []struct {
		name          string
		before, after *Input
		want          []uuid.UUID
	}{
		{"nothing changes", base(pA, pB), base(pA, pB), nil},
		{"a profile is added", base(pA, uuid.Nil), base(pA, pB), nil},
		{"profile 2 moves up to the enforced slot", base(pA, pB), base(pB, uuid.Nil), []uuid.UUID{pA}},
		{"the two swap: the one that goes later needs its password", base(pA, pB), base(pB, pA), []uuid.UUID{pA}},
		{"the enforced profile is replaced", base(pA, uuid.Nil), base(pC, uuid.Nil), []uuid.UUID{pA}},
		{"profile 2 is cleared", base(pA, pB), base(pA, uuid.Nil), []uuid.UUID{pB}},
		{"the endpoint is deleted", base(pA, pB), nil, []uuid.UUID{pA, pB}},
	}
	for _, c := range cases {
		if got := Needed(now0, c.before, c.after); !same(got, c.want) {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

func TestNeededAway(t *testing.T) {
	mk := func(away Away) *Input {
		return &Input{Zone: "Asia/Tehran", Base: Stack{pA, uuid.Nil}, Away: away, Plain: []uuid.UUID{pD}}
	}
	before := &Input{Zone: "Asia/Tehran", Base: Stack{pA, uuid.Nil}, Plain: []uuid.UUID{pD}}
	if got := Needed(now0, before, mk(AwayAll)); !same(got, []uuid.UUID{pA}) {
		t.Errorf("away all: %v", got)
	}
	// Rotation turns the encrypted identities away, and the Plain DNS identity keeps its stack: the profile is still removed
	// from the traffic with no client.
	if got := Needed(now0, before, mk(AwayEncrypted)); !same(got, []uuid.UUID{pA}) {
		t.Errorf("away encrypted: %v", got)
	}
	// An Endpoint whose only identity is a Plain DNS one and has no encrypted traffic is not special: the no-client identity is
	// always there, so the rotation always needs the password of the base profiles.
	none := mk(AwayNone)
	if got := Needed(now0, before, none); len(got) != 0 {
		t.Errorf("away none: %v", got)
	}
}

func TestNeededPlainIdentityEnds(t *testing.T) {
	// Legacy DNS off: the claim is no identity after, so a client "default" with its own profile loses it for the devices of
	// the claim, though the client row stays.
	before := &Input{Zone: "UTC", Base: Stack{pA, uuid.Nil}, Clients: map[string]Stack{"default": {pB, uuid.Nil}}, Plain: []uuid.UUID{pD}}
	after := &Input{Zone: "UTC", Base: Stack{pA, uuid.Nil}, Clients: map[string]Stack{"default": {pB, uuid.Nil}}}
	if got := Needed(now0, before, after); !same(got, []uuid.UUID{pB}) {
		t.Errorf("the devices of the claim lose the default client's profile: %v", got)
	}
}

func TestNeededClients(t *testing.T) {
	base := Stack{pA, uuid.Nil}
	before := &Input{Zone: "UTC", Base: base}
	// A client row that gives a label a stack without the base profile removes it from that label's traffic.
	after := &Input{Zone: "UTC", Base: base, Clients: map[string]Stack{"kid": {pB, uuid.Nil}}}
	if got := Needed(now0, before, after); !same(got, []uuid.UUID{pA}) {
		t.Errorf("a new client stack: %v", got)
	}
	// And the client's own profile, deleted, falls back to the base: the client's profile leaves the label.
	if got := Needed(now0, after, before); !same(got, []uuid.UUID{pB}) {
		t.Errorf("a deleted client stack: %v", got)
	}
	// A client stack that keeps the base profile first needs nothing.
	keep := &Input{Zone: "UTC", Base: base, Clients: map[string]Stack{"kid": {pA, pB}}}
	if got := Needed(now0, before, keep); len(got) != 0 {
		t.Errorf("a client stack that keeps the profile: %v", got)
	}
}

func TestNeededWindows(t *testing.T) {
	win := func(s, e int, a, b uuid.UUID) Window {
		return Window{ID: uuid.New(), Start: s, End: e, Stack: Stack{a, b}}
	}
	before := &Input{Zone: "UTC", Base: Stack{pA, uuid.Nil}, Windows: []Window{win(60, 120, pB, uuid.Nil)}}
	// Same windows, the window's profile replaced: only that profile.
	after := &Input{Zone: "UTC", Base: Stack{pA, uuid.Nil}, Windows: []Window{win(60, 120, pC, uuid.Nil)}}
	if got := Needed(now0, before, after); !same(got, []uuid.UUID{pB}) {
		t.Errorf("a window's profile replaced: %v", got)
	}
	// The window moves: in the old place the base applies after, and the window profile leaves its old minutes.
	moved := &Input{Zone: "UTC", Base: Stack{pA, uuid.Nil}, Windows: []Window{win(300, 360, pB, uuid.Nil)}}
	// In the old minutes pB was in force and after the move the base is, and in the new minutes the base was in force and pB is: each
	// leaves some instant.
	if got := Needed(now0, before, moved); !same(got, []uuid.UUID{pA, pB}) {
		t.Errorf("a window moved: %v", got)
	}
	// All windows deleted: the window's profile leaves.
	gone := &Input{Zone: "UTC", Base: Stack{pA, uuid.Nil}}
	if got := Needed(now0, before, gone); !same(got, []uuid.UUID{pB}) {
		t.Errorf("all windows deleted: %v", got)
	}
}

// TestNeededZoneChange: the same windows in another zone cover other instants, so a profile that was in a window at some
// instant of the year and is in none of the same instants after is needed (spec 3.3).
func TestNeededZoneChange(t *testing.T) {
	w := Window{ID: uuid.New(), Start: 0, End: 10080 - 60, Stack: Stack{pB, uuid.Nil}} // the whole week but the last hour
	before := &Input{Zone: "Asia/Tehran", Base: Stack{pA, uuid.Nil}, Windows: []Window{w}}
	after := &Input{Zone: "America/New_York", Base: Stack{pA, uuid.Nil}, Windows: []Window{w}}
	// Both are windows of pB for almost every instant, but the last hour of the week differs: at some instant Tehran is in the
	// window while New York is in the base hour, so pB is removed there, and the other way round for the base profile pA.
	if got := Needed(now0, before, after); !same(got, []uuid.UUID{pA, pB}) {
		t.Errorf("a zone change: %v", got)
	}
}

// reference is the 30-minute reference of E3: it walks the 366 days step by step, finds the window that covers the local
// time by its minutes (not through the grid), and applies the rule of spec 3.3 to every identity.
func reference(now time.Time, before, after *Input) []uuid.UUID {
	removed := map[uuid.UUID]bool{}
	zones := map[string]*time.Location{}
	local := func(in *Input, unix int64) Stack {
		loc, ok := zones[in.Zone]
		if !ok {
			l, err := time.LoadLocation(in.Zone)
			if err != nil {
				l = time.UTC
			}
			loc, zones[in.Zone] = l, l
		}
		t := time.Unix(unix, 0).In(loc)
		minute := int(t.Weekday())*1440 + t.Hour()*60 + t.Minute()
		for _, w := range in.Windows {
			if minute >= w.Start && minute < w.End {
				return w.Stack
			}
		}
		return in.Base
	}
	stack := func(in *Input, id ident, unix int64) Stack {
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
		return local(in, unix)
	}
	for _, id := range identities(before, after) {
		step := int64(900) // a quarter hour: the zones the panel allows have offsets of that grain (spec 3.3)
		start := now.Unix() - now.Unix()%step
		for t := start; t <= now.Add(horizon).Unix(); t += step {
			sb := stack(before, id, t)
			var sa Stack
			switch {
			case after == nil, after.Away == AwayAll, after.Away == AwayEncrypted && id.plain == uuid.Nil:
			case id.plain != uuid.Nil && !slices.Contains(after.Plain, id.plain):
			default:
				sa = stack(after, id, t)
			}
			for i, p := range sb.list() {
				if p != uuid.Nil {
					if j := sa.pos(p); j < 0 || j > i {
						removed[p] = true
					}
				}
			}
		}
	}
	out := make([]uuid.UUID, 0, len(removed))
	for p := range removed {
		out = append(out, p)
	}
	return ids(out...)
}

func randomInput(r *rand.Rand, zone string, profiles []uuid.UUID) *Input {
	pick := func() uuid.UUID {
		if r.Intn(4) == 0 {
			return uuid.Nil
		}
		return profiles[r.Intn(len(profiles))]
	}
	stack := func() Stack {
		a := profiles[r.Intn(len(profiles))]
		b := pick()
		if b == a {
			b = uuid.Nil
		}
		return Stack{a, b}
	}
	in := &Input{Zone: zone, Base: stack()}
	cuts := r.Intn(4)
	at := 0
	for i := 0; i < cuts; i++ {
		start := at + 30*r.Intn(40)
		end := start + 30*(1+r.Intn(60))
		if end > 10080 {
			break
		}
		in.Windows = append(in.Windows, Window{ID: uuid.New(), Start: start, End: end, Stack: stack()})
		at = end
	}
	for _, l := range []string{"a", "b", "default"} {
		if r.Intn(3) == 0 {
			if in.Clients == nil {
				in.Clients = map[string]Stack{}
			}
			in.Clients[l] = stack()
		}
	}
	if r.Intn(2) == 0 {
		in.Plain = []uuid.UUID{pD}
	}
	return in
}

// TestNeededMatchesTheReference is E3: Needed against the 30-minute reference over random Endpoints, with the same zone
// (one grid) and with another zone and other windows (the stepped path).
func TestNeededMatchesTheReference(t *testing.T) {
	r := rand.New(rand.NewSource(7))
	profiles := []uuid.UUID{pA, pB, pC}
	zones := []string{"Asia/Tehran", "UTC", "America/New_York", "Europe/London", "Asia/Kathmandu", "Australia/Eucla", "Pacific/Chatham"}
	for i := 0; i < 160; i++ {
		before := randomInput(r, zones[r.Intn(len(zones))], profiles)
		after := randomInput(r, before.Zone, profiles)
		if r.Intn(3) == 0 {
			after.Zone = zones[r.Intn(len(zones))]
		}
		if r.Intn(4) == 0 {
			after.Windows = before.Windows // an unchanged schedule: the one-grid path
			after.Zone = before.Zone
		}
		after.Away = Away(r.Intn(3))
		var a *Input = after
		if r.Intn(10) == 0 {
			a = nil
		}
		want, got := reference(now0, before, a), Needed(now0, before, a)
		if !same(got, want) {
			t.Fatalf("case %d: Needed %v, reference %v\nbefore %+v\nafter %+v", i, got, want, before, a)
		}
	}
}

// TestNeededQuarterHourZone: Kathmandu is +5:45, so its 30-minute cells start at :15 and :45 of UTC. A UTC window of the
// locked profile at Monday 00:00 to 00:30 moved to the same local minutes, 05:30 to 06:00 (UTC 23:45 to 00:15), leaves the
// profile in force from 00:15 to 00:30 of UTC no more, which a walk that only looks at :00 and :30 of UTC never sees.
func TestNeededQuarterHourZone(t *testing.T) {
	mon := 1440
	utc := &Input{Zone: "UTC", Base: Stack{pA, uuid.Nil},
		Windows: []Window{{ID: uuid.New(), Start: mon, End: mon + 30, Stack: Stack{pB, uuid.Nil}}}}
	kat := &Input{Zone: "Asia/Kathmandu", Base: Stack{pA, uuid.Nil},
		Windows: []Window{{ID: uuid.New(), Start: mon + 330, End: mon + 360, Stack: Stack{pB, uuid.Nil}}}}
	if got := Needed(now0, utc, kat); !same(got, []uuid.UUID{pA, pB}) {
		t.Errorf("a zone change to a quarter-hour offset: %v", got)
	}
	if got, want := Needed(now0, utc, kat), reference(now0, utc, kat); !same(got, want) {
		t.Errorf("Needed %v, reference %v", got, want)
	}
}

// TestNeededCostIsBoundedByDistinctStacks: 3,000 clients that lose their own stack, over a stepped path with 64 windows, are
// one evaluation per distinct stack and not one per client and pair (the probe is uncharged, so this is the bound).
func TestNeededCostIsBoundedByDistinctStacks(t *testing.T) {
	var ws []Window
	for i := 0; i < 64; i++ {
		ws = append(ws, Window{ID: uuid.New(), Start: i * 120, End: i*120 + 60, Stack: Stack{pB, uuid.Nil}})
	}
	before := &Input{Zone: "UTC", Base: Stack{pA, uuid.Nil}, Windows: ws, Clients: map[string]Stack{}}
	for i := 0; i < 3000; i++ {
		before.Clients[uuid.NewString()] = Stack{pC, uuid.Nil}
	}
	after := &Input{Zone: "Asia/Tehran", Base: Stack{pA, uuid.Nil}, Windows: ws}
	start := time.Now()
	got := Needed(now0, before, after)
	if !same(got, []uuid.UUID{pA, pB, pC}) {
		t.Fatalf("needed %v", got)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("3,000 clients took %v: the work is per client again", d)
	}
}
