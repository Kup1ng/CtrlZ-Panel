// Package failovergen writes the zone-failover vector group (contract 8a.10).
//
// It is an independent oracle for zone.Evaluator. It reads the data
// zone.Rows and zone.Inputs, lays out events with its own arithmetic on those
// thresholds, and writes the expected output by construction. It calls no
// function of zone: not the evaluator, not the input predicates, not the
// probe state machine, the flap and drain rules or the PeerDown tracker. A
// test (TestGeneratorUsesOnlyTheData) fails when this package refers to any
// other identifier of zone, so a bug in the evaluator cannot be copied into
// its own vectors by a regenerate.
package failovergen

import (
	"fmt"
	"sort"

	"github.com/Kup1ng/CtrlZ-Shared/zone"
)

// Column and Event aliases keep the case builders short.
type (
	col = Columns
	ev  = Event
)

// th holds the thresholds, in milliseconds, read from the data once.
type thresholds struct {
	tick, hbEvery, probeEvery                    int64
	hbStale, viewStale, probeUnknown, headNotice int64
	probeRounds                                  int64
	stable, stableFlapping, flapWindow, flapFor  int64
	refresh, requestMax                          int64
	f1For, f2For                                 int64
	headNoticeStrict, requestStrict              bool
	f1Reasons, f4Reasons, f5Reasons, f6Reasons   []string
	alertF0, alertF1, alertF2, alertF3           string
	alertF4, alertF5, alertF6, alertFlap         string
	reqF4, reqF5, reqF6                          string
}

func ms(d interface{ Milliseconds() int64 }) int64 { return d.Milliseconds() }

func load() thresholds {
	in := zone.Inputs()
	t := thresholds{
		tick: ms(in.Tick), hbEvery: ms(in.HeartbeatEvery), probeEvery: ms(in.ProbeEvery),
		hbStale: ms(in.HeartbeatStale.D), viewStale: ms(in.ViewStale.D), probeUnknown: ms(in.ProbeUnknown.D),
		headNotice: ms(in.HeadNoticeGrace.D), probeRounds: int64(in.ProbeRounds),
		stable: ms(in.Stable), stableFlapping: ms(in.StableFlapping), flapWindow: ms(in.FlapWindow), flapFor: ms(in.FlapFor),
		refresh: ms(in.RefreshEvery), requestMax: ms(in.RequestMaxAge.D),
		headNoticeStrict: in.HeadNoticeGrace.Strict, requestStrict: in.RequestMaxAge.Strict,
		alertFlap: zone.AlertFlapping,
	}
	for _, r := range zone.Rows() {
		switch r.ID {
		case zone.F0:
			t.alertF0 = r.Alert
		case zone.F1:
			t.f1For, t.alertF1 = int64(r.For.Seconds)*1000, r.Alert
		case zone.F2:
			t.f2For, t.alertF2 = int64(r.For.Seconds)*1000, r.Alert
		case zone.F3:
			t.alertF3 = r.Alert
		case zone.F4:
			t.alertF4, t.reqF4 = r.Alert, string(r.Request)
			t.f4Reasons = reasons(r)
		case zone.F5:
			t.alertF5, t.reqF5 = r.Alert, string(r.Request)
			t.f5Reasons = reasons(r)
		case zone.F6:
			t.alertF6, t.reqF6 = r.Alert, string(r.Request)
			t.f6Reasons = reasons(r)
		}
	}
	return t
}

func reasons(r zone.Row) []string {
	var out []string
	for _, c := range r.Inputs {
		out = append(out, c.Reason)
	}
	return out
}

// flipAt is the first tick at which an observation made at t, with age
// threshold d, has passed the limit. A strict limit is "more than d".
func flipAt(t, d int64, strict bool, tick int64) int64 {
	if strict {
		return t + d + tick
	}
	return t + d
}

// cs is a case under construction. The expectation is written in the order the
// evaluator must emit it; withRefresh then adds the F7 events.
type cs struct {
	th    thresholds
	c     Case
	cur   map[string]col // columns as the expectation has left them, for F7's s
	items []item
	nodes []string
}

// item is an expected event with the time it happens, so withRefresh can place
// F7 between them.
type item struct {
	at       int64
	isEvent  bool
	changes  map[string]col
	exp      []Expect
	hasEvent bool
}

func (t thresholds) newCase(id, row, why string, nodes ...string) *cs {
	c := &cs{th: t, cur: map[string]col{}, nodes: nodes}
	c.c.ID, c.c.Row, c.c.Why = id, row, why
	c.c.Start.Nodes = map[string]col{}
	for _, n := range nodes {
		c.c.Start.Nodes[n] = col{}
	}
	c.c.Start.Membership = Membership{
		Pairs:  []Pair{{ID: "p1", Primary: "A", Fallback: "B"}},
		Global: "p1",
	}
	return c
}

// start sets the starting columns of a node.
func (c *cs) start(n string, v col) *cs {
	c.c.Start.Nodes[n] = v
	c.cur[n] = v
	return c
}

// membership sets the starting pairs.
func (c *cs) pairs(global string, p ...Pair) *cs {
	if p == nil {
		p = []Pair{}
	}
	c.c.Start.Membership.Pairs, c.c.Start.Membership.Global = p, global
	return c
}

func (c *cs) add(e ev) { c.c.Events = append(c.c.Events, e) }

func i64(v int64) *int64 { return &v }

// ---- event kit ------------------------------------------------------------

// hbSpec describes the Heartbeats of one node.
type hbSpec struct {
	node, peer string
	phase      int64
	from, to   int64 // inclusive; from 0 when zero
	// view of the peer: 0 up, 1 down, 2 unknown (known false)
	view     func(t int64) int
	paths    func(t int64) []bool
	isolated func(t int64) bool
	seq      func(t int64) uint64
	omitPeer bool // PeerView with no entries
}

func up(int64) int   { return 0 }
func down(int64) int { return 1 }

func healthy(int64) []bool { return []bool{true} }

func (c *cs) heartbeats(s hbSpec) {
	if s.view == nil {
		s.view = up
	}
	if s.paths == nil {
		s.paths = healthy
	}
	for t := s.phase; t <= s.to; t += c.th.hbEvery {
		if t < s.from {
			continue
		}
		c.add(c.hbAt(t, s))
	}
}

func (c *cs) hbAt(t int64, s hbSpec) ev {
	e := ev{At: t, Kind: "heartbeat", Node: s.node, AppliedSeq: 10}
	if s.seq != nil {
		e.AppliedSeq = s.seq(t)
	}
	ps := s.paths(t)
	for i, h := range ps {
		id := fmt.Sprintf("u%d", i+1)
		if len(ps) == 1 {
			// Recursive mode reports only the local Unbound, under the reserved id (8a.4).
			id = localUnboundID
		}
		e.Upstreams = append(e.Upstreams, Upstream{ID: id, Healthy: h})
	}
	if s.isolated != nil {
		e.Isolated = s.isolated(t)
	}
	pv := &PeerView{PairTableVersion: 1, Peers: []PeerEntry{}}
	if s.peer != "" && !s.omitPeer {
		v := s.view(t)
		pv.Peers = append(pv.Peers, PeerEntry{Node: s.peer, Known: v != 2, Down: v == 1})
	}
	e.PeerView = pv
	return e
}

// hbOne adds a single Heartbeat at t with the spec's content.
func (c *cs) hbOne(t int64, s hbSpec) {
	if s.view == nil {
		s.view = up
	}
	if s.paths == nil {
		s.paths = healthy
	}
	c.add(c.hbAt(t, s))
}

// roundSpec describes the prober's rounds of one node.
type roundSpec struct {
	node     string
	from, to int64
	pass     func(t int64) bool
}

func pass(int64) bool { return true }
func fail(int64) bool { return false }

// rounds adds a round every probeEvery from the first multiple at or after
// max(from, probeEvery) up to to. DoH fails when pass is false, so a round
// fails by one part alone, which is how a dead dns beside a live agent looks.
func (c *cs) rounds(s roundSpec) {
	if s.pass == nil {
		s.pass = pass
	}
	for t := c.th.probeEvery; t <= s.to; t += c.th.probeEvery {
		if t >= s.from {
			c.roundAt(t, s.node, s.pass(t))
		}
	}
}

func (c *cs) roundAt(t int64, node string, ok bool) {
	e := ev{At: t, Kind: "hub_round", Node: node, DoT: "pass", DoH: "pass"}
	if !ok {
		e.DoH = "fail"
	}
	c.add(e)
}

// ---- expectation kit ------------------------------------------------------

func (c *cs) event(at int64, row string, nodes map[string]col) *cs {
	for n, v := range nodes {
		c.cur[n] = v
	}
	c.items = append(c.items, item{at: at, hasEvent: true, changes: nodes, exp: []Expect{c.eventItem(at, row, nodes)}})
	return c
}

// eventItem builds the event item, with s for each withdrawn node by the
// stable period then in force.
func (c *cs) eventItem(at int64, row string, nodes map[string]col) Expect {
	e := Expect{At: at, Kind: "event", Row: row}
	if len(nodes) > 0 {
		e.Nodes = nodes
	}
	e.S = c.stableFor(at)
	return e
}

func (c *cs) stableFor(at int64) map[string]int64 {
	var s map[string]int64
	for n, v := range c.cur {
		if v.Withdrawn {
			if s == nil {
				s = map[string]int64{}
			}
			s[n] = c.th.stable / 1000
			if v.FlapUntil != nil && at < *v.FlapUntil {
				s[n] = c.th.stableFlapping / 1000
			}
		}
	}
	return s
}

// then adds items that follow the last event at the same time.
func (c *cs) alert(at int64, kind, node, detail string) *cs {
	c.append(Expect{At: at, Kind: "alert", Alert: kind, Node: node, Detail: detail})
	return c
}

func (c *cs) done(at int64, id string) *cs {
	c.append(Expect{At: at, Kind: "request", ID: id, Result: "done"})
	return c
}

func (c *cs) refused(at int64, id, reason string) *cs {
	c.items = append(c.items, item{at: at, exp: []Expect{{At: at, Kind: "request", ID: id, Result: "refused", Reason: reason}}})
	return c
}

func (c *cs) expired(at int64, id string) *cs {
	c.items = append(c.items, item{at: at, exp: []Expect{{At: at, Kind: "request", ID: id, Result: "expired"}}})
	return c
}

func (c *cs) append(e Expect) {
	last := &c.items[len(c.items)-1]
	last.exp = append(last.exp, e)
}

// finish sets the end, adds the F7 refresh events the case implies, and
// returns the case. A refresh comes refresh after the last signing event, and
// a signing event on its tick replaces it (8a.6).
func (c *cs) finish(end int64) Case {
	c.c.End = end
	var out []Expect
	last := int64(0)
	cur := map[string]col{}
	for n, v := range c.c.Start.Nodes {
		cur[n] = v
	}
	refreshTo := func(limit int64) {
		for last+c.th.refresh <= limit {
			last += c.th.refresh
			e := Expect{At: last, Kind: "event", Row: zone.F7}
			for n, v := range cur {
				if v.Withdrawn {
					if e.S == nil {
						e.S = map[string]int64{}
					}
					e.S[n] = c.th.stable / 1000
					if v.FlapUntil != nil && last < *v.FlapUntil {
						e.S[n] = c.th.stableFlapping / 1000
					}
				}
			}
			out = append(out, e)
		}
	}
	for _, it := range c.items {
		if it.hasEvent {
			// An event at the refresh tick replaces it: refresh only up to just before.
			refreshTo(it.at - 1)
			last = it.at
			for n, v := range it.changes {
				cur[n] = v
			}
		}
		out = append(out, it.exp...)
	}
	refreshTo(end)
	c.c.Expect = out
	if c.c.Expect == nil {
		c.c.Expect = []Expect{}
	}
	sort.SliceStable(c.c.Events, func(i, j int) bool { return c.c.Events[i].At < c.c.Events[j].At })
	if c.c.Events == nil {
		c.c.Events = []Event{}
	}
	return c.c
}

// localUnboundID is wire.LocalUnboundID in text: the Max UUID of RFC 9562.
const localUnboundID = "ffffffff-ffff-ffff-ffff-ffffffffffff"
