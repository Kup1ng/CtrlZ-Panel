package zone

import "time"

// ProbeState is the state of one node as one observer has probed it (8a.4).
type ProbeState uint8

const (
	ProbeUnknown ProbeState = iota
	ProbeUp
	ProbeDown
)

func (s ProbeState) String() string {
	switch s {
	case ProbeUp:
		return "up"
	case ProbeDown:
		return "down"
	}
	return "unknown"
}

// Probe is the probe state machine of one observed node. The zero value is a
// fresh tracker: unknown, which is also what it is when an observer starts
// and when a node first enters its membership.
//
// The state changes only after Inputs().ProbeRounds rounds in a row with one
// result, so a lone failed round changes nothing, and it falls back to
// unknown when no round has completed for Inputs().ProbeUnknown, so a stalled
// prober never keeps a stale up or down.
type Probe struct {
	state     ProbeState
	streak    int
	lastPass  bool
	lastRound time.Time
	seen      bool
}

// Round records a completed round. pass is true when both parts, DoT and DoH,
// passed.
func (p *Probe) Round(now time.Time, pass bool) {
	spec := Inputs()
	if p.seen && spec.ProbeUnknown.Passed(now.Sub(p.lastRound)) {
		// The state already read as unknown; the count starts again too, so
		// two rounds before the stall and one after do not make three.
		*p = Probe{}
	}
	if p.streak > 0 && p.lastPass == pass {
		p.streak++
	} else {
		p.streak, p.lastPass = 1, pass
	}
	if p.streak >= spec.ProbeRounds {
		if pass {
			p.state = ProbeUp
		} else {
			p.state = ProbeDown
		}
	}
	p.lastRound, p.seen = now, true
}

// State is the state at now.
func (p *Probe) State(now time.Time) ProbeState {
	if !p.seen || Inputs().ProbeUnknown.Passed(now.Sub(p.lastRound)) {
		return ProbeUnknown
	}
	return p.state
}

// PeerDownTracker is a node's own view of one other node while the panel is
// unreachable (8a.5): down after PeerDownAfter of failed rounds without a
// break, up again after PeerUpAfter of passing rounds without a break. The
// zero value is up, so a node that has never failed a round is not down.
type PeerDownTracker struct {
	down      bool
	runPass   bool
	runStart  time.Time
	lastRound time.Time
	hasRun    bool
}

// Round records a completed round and returns whether the node is now down.
func (t *PeerDownTracker) Round(now time.Time, pass bool) bool {
	spec := Inputs()
	// A silence as long as ProbeUnknown breaks the run, as it does for Probe:
	// a stalled prober's gap is not evidence that the node failed (or passed)
	// for that whole time, so two rounds either side of it are not one run.
	stalled := t.hasRun && spec.ProbeUnknown.Passed(now.Sub(t.lastRound))
	if !t.hasRun || t.runPass != pass || stalled {
		t.runPass, t.runStart, t.hasRun = pass, now, true
	}
	t.lastRound = now
	run := now.Sub(t.runStart)
	switch {
	case !pass && run >= spec.PeerDownAfter:
		t.down = true
	case pass && run >= spec.PeerUpAfter:
		t.down = false
	}
	return t.down
}

// Down is the current view.
func (t *PeerDownTracker) Down() bool { return t.down }

// PeerDownSet keeps one tracker for each node a node probes and gives the map
// that Local.PeerDown wants.
type PeerDownSet struct {
	by map[NodeID]*PeerDownTracker
}

// Round records a round of node id.
func (s *PeerDownSet) Round(now time.Time, id NodeID, pass bool) {
	if s.by == nil {
		s.by = map[NodeID]*PeerDownTracker{}
	}
	t := s.by[id]
	if t == nil {
		t = &PeerDownTracker{}
		s.by[id] = t
	}
	t.Round(now, pass)
}

// Forget drops a node that left the membership.
func (s *PeerDownSet) Forget(id NodeID) { delete(s.by, id) }

// Snapshot returns the nodes that are down. The map is new on every call, so
// a Local built from it never changes under a reader.
func (s *PeerDownSet) Snapshot() map[NodeID]bool {
	out := map[NodeID]bool{}
	for id, t := range s.by {
		if t.down {
			out[id] = true
		}
	}
	return out
}

// Columns are the failover columns of a node, which only the hub writes
// (8a.4 State on the hub). A zero time is NULL.
type Columns struct {
	Withdrawn      bool
	Hold           bool
	LastFailbackAt time.Time
	FlapUntil      time.Time
}

// StablePeriod is S(X): how long a withdrawn node must be eligible before F3
// brings it back (invariant 7).
func StablePeriod(c Columns, now time.Time) time.Duration {
	spec := Inputs()
	if now.Before(c.FlapUntil) {
		return spec.StableFlapping
	}
	return spec.Stable
}

// Flap is the flap rule: a withdrawal by F1 or F2 at now, less than
// FlapWindow after the last failback, sets dns_flap_until a day ahead. It
// returns the new columns and whether the rule fired. Nothing else writes
// dns_flap_until.
func Flap(c Columns, now time.Time) (Columns, bool) {
	spec := Inputs()
	if c.LastFailbackAt.IsZero() || now.Sub(c.LastFailbackAt) >= spec.FlapWindow {
		return c, false
	}
	c.FlapUntil = now.Add(spec.FlapFor)
	return c, true
}

// NextVersion is the version of a signing event: max(last+1, now in Unix
// milliseconds) (8a.4 Versions). It never goes backwards for a hub whose clock
// does not.
func NextVersion(last uint64, now time.Time) uint64 {
	v := last + 1
	if ms := now.UnixMilli(); ms > 0 && uint64(ms) > v {
		v = uint64(ms)
	}
	return v
}

// Advertised reports whether node self is the node Target returns, with no
// local view, for the global pair or for any pair in inUse (the pairs that an
// Endpoint's pair_id names; in v1 none, D30).
func Advertised(t *Table, inUse []PairID, self NodeID) bool {
	if t == nil {
		return false
	}
	pairs := append([]PairID{t.Global}, inUse...)
	for _, p := range pairs {
		if n, ok := Target(t, p, Local{}); ok && n.ID == self {
			return true
		}
	}
	return false
}

// Drain is the drain rule of one node (8a.6). Feed it every table the node
// applies. A node drains when it stops being the advertised node of every
// pair in use; a node that was never advertised, such as a fallback that has
// just started, does not drain. A table that makes it advertised again
// cancels the drain.
type Drain struct {
	known      bool
	advertised bool
	draining   bool
	since      time.Time
}

// Applied records a table that was applied at now.
func (d *Drain) Applied(now time.Time, t *Table, inUse []PairID, self NodeID) {
	adv := Advertised(t, inUse, self)
	switch {
	case adv:
		d.draining = false
	case d.known && d.advertised && !d.draining:
		d.draining, d.since = true, now
	}
	d.known, d.advertised = true, adv
}

// Draining reports whether a drain is pending or running.
func (d *Drain) Draining() bool { return d.draining }

// MayClose reports whether the node may start closing its DoH, DoT and DoQ
// connections. Each close also needs the node to check, just before, that it
// is still advertised by no pair in use; the random spread over DrainSpread
// is the node's own.
func (d *Drain) MayClose(now time.Time) bool {
	return d.draining && now.Sub(d.since) >= Inputs().DrainFrom
}

// Done reports whether the drain has had its whole time: what the node page
// shows as "drain done".
func (d *Drain) Done(now time.Time) bool {
	return d.draining && now.Sub(d.since) >= Inputs().DrainDone
}
