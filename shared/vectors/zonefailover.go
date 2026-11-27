package vectors

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Shared/zone"
)

// The zone-failover group (contract 15, 8a.10). The cases are written by
// `sharedtool failover-vectors`, which reads only the data zone.Rows and
// zone.Inputs, so this runner is the other half of an independent check: it
// drives the real evaluator through each case and compares everything the
// evaluator emits, in order, with the case's expectation.

// FailoverColumns are the failover columns of a node, in milliseconds from the
// case start (null for none).
type FailoverColumns struct {
	Withdrawn      bool   `json:"withdrawn"`
	Hold           bool   `json:"hold"`
	LastFailbackAt *int64 `json:"last_failback_at"`
	FlapUntil      *int64 `json:"flap_until"`
}

// FailoverPair is a pair of a membership, by node names.
type FailoverPair struct {
	ID       string `json:"id"`
	Primary  string `json:"primary"`
	Fallback string `json:"fallback"`
}

// FailoverMembership is a membership. Nodes lists the nodes of the table; in
// start it is left out and the keys of start.nodes are the nodes, in an event
// a missing list leaves the nodes as they were. Revoked lists the nodes whose
// spki_sha256 is empty.
type FailoverMembership struct {
	Nodes   []string       `json:"nodes,omitempty"`
	Pairs   []FailoverPair `json:"pairs"`
	Global  string         `json:"global"`
	Revoked []string       `json:"revoked,omitempty"`
}

// FailoverStart is the state of the hub at the start of a case.
type FailoverStart struct {
	Nodes      map[string]FailoverColumns `json:"nodes"`
	Membership FailoverMembership         `json:"membership"`
}

// FailoverUpstream is one entry of Heartbeat.upstreams.
type FailoverUpstream struct {
	ID      string `json:"id"`
	Healthy bool   `json:"healthy"`
}

// FailoverPeerEntry is one entry of a PeerView.
type FailoverPeerEntry struct {
	Node  string `json:"node"`
	Known bool   `json:"known"`
	Down  bool   `json:"down"`
}

// FailoverPeerView is a Heartbeat's PeerView.
type FailoverPeerView struct {
	PairTableVersion uint64              `json:"pair_table_version"`
	Peers            []FailoverPeerEntry `json:"peers"`
}

// FailoverEvent is something that happens to the hub, at At milliseconds from
// the case start. Kind is heartbeat, hub_round, head_notice, membership,
// request, revoke or hub_start. A request's own kind is Op, because the
// event's Kind is taken.
type FailoverEvent struct {
	At   int64  `json:"at"`
	Kind string `json:"kind"`
	Node string `json:"node,omitempty"`

	AppliedSeq uint64             `json:"applied_seq,omitempty"`
	Isolated   bool               `json:"isolated,omitempty"`
	Upstreams  []FailoverUpstream `json:"upstreams,omitempty"`
	PeerView   *FailoverPeerView  `json:"peer_view,omitempty"`

	DoT string `json:"dot,omitempty"`
	DoH string `json:"doh,omitempty"`

	Seq uint64 `json:"seq,omitempty"`

	Membership *FailoverMembership `json:"membership,omitempty"`

	ID          string `json:"id,omitempty"`
	Op          string `json:"op,omitempty"`
	RequestedAt *int64 `json:"requested_at,omitempty"`
}

// FailoverExpect is one thing the evaluator must emit, in order. Kind is
// event, request or alert.
type FailoverExpect struct {
	At   int64  `json:"at"`
	Kind string `json:"kind"`

	// event
	Row   string                     `json:"row,omitempty"`
	Nodes map[string]FailoverColumns `json:"nodes,omitempty"`
	S     map[string]int64           `json:"s,omitempty"`

	// request
	ID     string `json:"id,omitempty"`
	Result string `json:"result,omitempty"`
	Reason string `json:"reason,omitempty"`

	// alert
	Alert  string `json:"alert,omitempty"`
	Node   string `json:"node,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// FailoverCase is one case of the group.
type FailoverCase struct {
	ID     string           `json:"id"`
	Why    string           `json:"why"`
	Row    string           `json:"row"`
	Start  FailoverStart    `json:"start"`
	Events []FailoverEvent  `json:"events"`
	End    int64            `json:"end"`
	Expect []FailoverExpect `json:"expect"`
}

func runZoneFailoverGroup(t *testing.T, g *GroupFile) {
	var cases []FailoverCase
	if err := decodeStrict(g.Cases, &cases); err != nil {
		t.Fatalf("%s: %v", g.Group, err)
	}
	if len(cases) == 0 {
		t.Fatalf("%s has no cases", g.Group)
	}
	seen := map[string]bool{}
	for i := range cases {
		c := &cases[i]
		if c.ID == "" || seen[c.ID] {
			t.Errorf("duplicate or empty case id %q", c.ID)
		}
		seen[c.ID] = true
		t.Run(c.ID, func(t *testing.T) {
			got, err := RunFailoverCase(c)
			if err != nil {
				t.Fatalf("%v\n  case: %s", err, c.Why)
			}
			if msg := diffExpect(c.Expect, got); msg != "" {
				t.Errorf("%s\n  case: %s", msg, c.Why)
			}
		})
	}
}

// diffExpect compares two ordered lists item by item through canonical JSON.
func diffExpect(want, got []FailoverExpect) string {
	line := func(e FailoverExpect) string { b, _ := json.Marshal(e); return string(b) }
	n := len(want)
	if len(got) > n {
		n = len(got)
	}
	for i := 0; i < n; i++ {
		var w, g string
		if i < len(want) {
			w = line(want[i])
		}
		if i < len(got) {
			g = line(got[i])
		}
		if w != g {
			var b strings.Builder
			fmt.Fprintf(&b, "item %d differs\n  want: %s\n  got:  %s\nwant list:", i, orNone(w), orNone(g))
			for _, e := range want {
				b.WriteString("\n    " + line(e))
			}
			b.WriteString("\ngot list:")
			for _, e := range got {
				b.WriteString("\n    " + line(e))
			}
			return b.String()
		}
	}
	return ""
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

// failoverEpoch is the case start; any instant works, the evaluator only
// subtracts.
const failoverEpochSec int64 = 1_700_000_000

func fAt(ms int64) time.Time {
	return time.Unix(failoverEpochSec, 0).Add(time.Duration(ms) * time.Millisecond)
}

func fMS(t time.Time) int64 { return t.Sub(time.Unix(failoverEpochSec, 0)).Milliseconds() }

// FailoverNodeID maps a fixture name to a node id whose byte order is the
// name's, so "node_id byte order" in a case is the order of the names.
func FailoverNodeID(name string) zone.NodeID {
	var id zone.NodeID
	copy(id[:], name)
	return id
}

func fPairID(name string) zone.PairID {
	var id zone.PairID
	copy(id[:], name)
	return id
}

type fMember struct {
	nodes   []string
	pairs   []FailoverPair
	global  string
	revoked map[string]bool
}

func (m *fMember) table() *zone.Table {
	t := &zone.Table{Nodes: map[zone.NodeID]zone.Node{}, Pairs: map[zone.PairID]zone.Pair{}, Global: fPairID(m.global)}
	for i, n := range m.nodes {
		id := FailoverNodeID(n)
		t.Nodes[id] = zone.Node{ID: id, Slot: uint8(i + 1), Revoked: m.revoked[n]}
	}
	for _, p := range m.pairs {
		pr := zone.Pair{ID: fPairID(p.ID), Primary: FailoverNodeID(p.Primary)}
		if p.Fallback != "" {
			pr.Fallback, pr.HasFallback = FailoverNodeID(p.Fallback), true
		}
		t.Pairs[pr.ID] = pr
	}
	return t
}

func toCols(c FailoverColumns) zone.Columns {
	out := zone.Columns{Withdrawn: c.Withdrawn, Hold: c.Hold}
	if c.LastFailbackAt != nil {
		out.LastFailbackAt = fAt(*c.LastFailbackAt)
	}
	if c.FlapUntil != nil {
		out.FlapUntil = fAt(*c.FlapUntil)
	}
	return out
}

func fromCols(c zone.Columns) FailoverColumns {
	out := FailoverColumns{Withdrawn: c.Withdrawn, Hold: c.Hold}
	if !c.LastFailbackAt.IsZero() {
		v := fMS(c.LastFailbackAt)
		out.LastFailbackAt = &v
	}
	if !c.FlapUntil.IsZero() {
		v := fMS(c.FlapUntil)
		out.FlapUntil = &v
	}
	return out
}

// RunFailoverCase drives the evaluator through a case and returns everything
// it emitted, in the order of the case's expectation.
func RunFailoverCase(c *FailoverCase) ([]FailoverExpect, error) {
	nameOf := map[zone.NodeID]string{}
	name := func(id zone.NodeID) string {
		if n, ok := nameOf[id]; ok {
			return n
		}
		return fmt.Sprintf("%x", id[:])
	}
	mem := &fMember{revoked: map[string]bool{}}
	for n := range c.Start.Nodes {
		mem.nodes = append(mem.nodes, n)
		nameOf[FailoverNodeID(n)] = n
	}
	sort.Strings(mem.nodes)
	mem.pairs, mem.global = c.Start.Membership.Pairs, c.Start.Membership.Global
	for _, n := range c.Start.Membership.Revoked {
		mem.revoked[n] = true
	}
	cols := map[zone.NodeID]zone.Columns{}
	for n, col := range c.Start.Nodes {
		cols[FailoverNodeID(n)] = toCols(col)
	}
	ev, err := zone.NewEvaluator(fAt(0), mem.table(), mem.table(), cols)
	if err != nil {
		return nil, err
	}

	events := append([]FailoverEvent(nil), c.Events...)
	sort.SliceStable(events, func(i, j int) bool { return events[i].At < events[j].At })
	var pending []zone.Request
	var got []FailoverExpect

	emit := func(at int64, outs []zone.Output) {
		for _, o := range outs {
			if o.Request != nil {
				got = append(got, FailoverExpect{At: at, Kind: "request", ID: o.Request.ID, Result: o.Request.Result, Reason: o.Request.Reason})
				continue
			}
			e := o.Event
			item := FailoverExpect{At: at, Kind: "event", Row: e.Row}
			if len(e.Changed) > 0 {
				item.Nodes = map[string]FailoverColumns{}
				for id, col := range e.Changed {
					item.Nodes[name(id)] = fromCols(col)
				}
			}
			if len(e.Stable) > 0 {
				item.S = map[string]int64{}
				for id, s := range e.Stable {
					item.S[name(id)] = int64(s / time.Second)
				}
			}
			got = append(got, item)
			if e.Done != nil {
				got = append(got, FailoverExpect{At: at, Kind: "request", ID: e.Done.ID, Result: e.Done.Result})
			}
			for _, a := range e.Alerts {
				ai := FailoverExpect{At: at, Kind: "alert", Alert: a.Kind, Detail: a.Detail}
				if a.Named {
					ai.Node = name(a.Node)
				}
				got = append(got, ai)
			}
		}
	}
	drop := func(outs []zone.Output) {
		done := map[string]bool{}
		for _, o := range outs {
			if o.Request != nil {
				done[o.Request.ID] = true
			}
			if o.Event != nil && o.Event.Done != nil {
				done[o.Event.Done.ID] = true
			}
		}
		keep := pending[:0]
		for _, r := range pending {
			if !done[r.ID] {
				keep = append(keep, r)
			}
		}
		pending = keep
	}

	idx := 0
	for tick := int64(0); tick <= c.End; tick += 1000 {
		for idx < len(events) && events[idx].At <= tick {
			e := events[idx]
			idx++
			now := fAt(e.At)
			switch e.Kind {
			case "heartbeat":
				r := zone.Report{AppliedSeq: e.AppliedSeq, Isolated: e.Isolated}
				for _, u := range e.Upstreams {
					r.Paths = append(r.Paths, u.Healthy)
				}
				if e.PeerView != nil {
					for _, p := range e.PeerView.Peers {
						r.Peers = append(r.Peers, zone.PeerEntry{Node: FailoverNodeID(p.Node), Known: p.Known, Down: p.Down})
					}
				}
				ev.Heartbeat(now, FailoverNodeID(e.Node), r)
			case "hub_round":
				ev.ProbeRound(now, FailoverNodeID(e.Node), e.DoT == "pass", e.DoH == "pass")
			case "head_notice":
				ev.HeadNotice(now, FailoverNodeID(e.Node), e.Seq)
			case "membership":
				m := e.Membership
				if m == nil {
					return nil, fmt.Errorf("membership event at %d has no membership", e.At)
				}
				if len(m.Nodes) > 0 {
					mem.nodes = append([]string(nil), m.Nodes...)
					sort.Strings(mem.nodes)
					for _, n := range m.Nodes {
						nameOf[FailoverNodeID(n)] = n
					}
				}
				mem.pairs, mem.global = m.Pairs, m.Global
				for _, n := range m.Revoked {
					mem.revoked[n] = true
				}
			case "revoke":
				mem.revoked[e.Node] = true
			case "request":
				if e.RequestedAt == nil {
					return nil, fmt.Errorf("request %s has no requested_at", e.ID)
				}
				pending = append(pending, zone.Request{ID: e.ID, Node: FailoverNodeID(e.Node), Kind: zone.RequestKind(e.Op), RequestedAt: fAt(*e.RequestedAt)})
			case "hub_start":
				// A restart keeps what the database holds, the failover columns
				// and last_table, and nothing else: every tracker starts again.
				next, err := zone.NewEvaluator(now, mem.table(), ev.LastTable(), columnsOf(ev, mem))
				if err != nil {
					return nil, err
				}
				ev = next
				outs, err := ev.Start(now, nil)
				if err != nil {
					return nil, err
				}
				emit(e.At, outs)
			default:
				return nil, fmt.Errorf("unknown event kind %q", e.Kind)
			}
		}
		now := fAt(tick)
		if err := ev.SetMembership(now, mem.table()); err != nil {
			return nil, err
		}
		reqs := make([]zone.Request, len(pending))
		for i, r := range pending {
			r.Age = now.Sub(r.RequestedAt)
			reqs[i] = r
		}
		outs, err := ev.Tick(now, reqs, nil)
		if err != nil {
			return nil, err
		}
		drop(outs)
		emit(tick, outs)
	}
	return got, nil
}

func columnsOf(ev *zone.Evaluator, m *fMember) map[zone.NodeID]zone.Columns {
	out := map[zone.NodeID]zone.Columns{}
	for _, n := range m.nodes {
		id := FailoverNodeID(n)
		out[id] = ev.Columns(id)
	}
	return out
}

// DiffFailoverExpect compares two ordered lists of expectations and describes
// the first difference, or returns "". The generator's tests use it.
func DiffFailoverExpect(want, got []FailoverExpect) string { return diffExpect(want, got) }
