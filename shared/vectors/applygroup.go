package vectors

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	"github.com/Kup1ng/CtrlZ-Shared/wire"
	"github.com/Kup1ng/CtrlZ-Shared/zone"
)

// The pair-table-apply group (contract 15, 8a.4 Node apply, 8a.5, 8a.10). A case
// starts a node in a stated persisted state, runs steps against it (a push, a log
// entry, a restart, a ServerTime, a tick) and says what the node reports and what
// its table in use gives after each one. The panel runs the reference model
// below, which is a transcription of 8a.4 and 8a.5 over the shared pieces
// (zone.FlagMap, zone.WithFlags, zone.Build, the wire validators); the node runs
// the same cases through its own harness over its real table writer, so a node
// that drifts from the rules fails here.
//
// What the group leaves to the node's own tests, because no harness can cause it
// through plain data: a signature that fails manifest.Verify with a real key (a
// push step says defect "signature" and the node's harness damages the signature),
// a build that panics, a disk that fails, the Control stream itself (the group
// models a stream that stays up) and PeerNode trust (P4b builds PeerNode; here
// the NS set and the answers show that a revoked node is trusted for nothing).

// ApplyNodeSetup is the node before the first step. The node has just started at
// clock, with the persisted state below (8a.4, At start).
type ApplyNodeSetup struct {
	Self string `json:"self"`
	// Membership is the table of the node's last applied log entry, null for none.
	Membership *PairInput `json:"membership"`
	AppliedSeq uint64     `json:"applied_seq"`
	// Flags, VersionUsed and Highest are the persisted flag map, the version of
	// the push that set it and the highest version ever used (0 means VersionUsed).
	Flags       map[string]bool `json:"flags"`
	VersionUsed uint64          `json:"version_used"`
	Highest     uint64          `json:"highest"`
	// ExpiresAt is the expires_at of the persisted push, 0 when there is none.
	ExpiresAt int64 `json:"expires_at"`
	// Clock is the node's own clock at start, in Unix seconds.
	Clock int64 `json:"clock"`
}

// ApplyStep is one event. At is seconds after the node's start.
//
//	push         Table is the pushed PairTable (its version and expires_at count). Defect
//	             "empty" is an envelope with no payload and "signature" one that does
//	             not verify, both refused as SIGNATURE before the table is read.
//	log          Table is the table of an applied log entry with config_seq ConfigSeq.
//	restart      the process starts again from what it persisted. CorruptPush damages
//	             the persisted push, so the checks of 8a.4 (At start) fail.
//	server_time  the hub's clock is Offset seconds ahead of the node's at At.
//	tick         nothing happens; the node is observed.
type ApplyStep struct {
	At          int64      `json:"at"`
	Kind        string     `json:"kind"`
	Table       *PairInput `json:"table"`
	Defect      string     `json:"defect"`
	ConfigSeq   uint64     `json:"config_seq"`
	Offset      int64      `json:"offset"`
	CorruptPush bool       `json:"corrupt_push"`
}

// ApplyExpect is what a case asserts after a step. A field left out is not
// checked, except Result, which every item has.
type ApplyExpect struct {
	// Result is applied, redelivered, refused or none.
	Result string `json:"result"`
	// Reason is the PUSH_REFUSAL_ name without its prefix, "" for none.
	Reason      *string          `json:"reason"`
	Flags       *map[string]bool `json:"flags"`
	VersionUsed *uint64          `json:"version_used"`
	PanelStale  *bool            `json:"panel_stale"`
	ExpiresAt   *int64           `json:"expires_at"`
	LastRefusal *string          `json:"last_refusal"`
	Refusals    *uint64          `json:"refusals"`
	AppliedSeq  *uint64          `json:"applied_seq"`
	// Quarantine is the scope of the QuarantineReport the step sent, "" for none.
	Quarantine *string `json:"quarantine"`
	// InUse is whether the node has a table in use (8a.5, Table in use).
	InUse *bool `json:"in_use"`
	// NSSet is the ns<slot> names of the apex NS answer of the table in use.
	NSSet *[]string `json:"ns_set"`
	// Answers is the address the table in use gives an Endpoint hostname of each
	// pair, by pair name, as seen from the node itself with no local view.
	Answers *map[string]string `json:"answers"`
}

// ApplyCase is one case of the group.
type ApplyCase struct {
	ID     string         `json:"id"`
	Why    string         `json:"why"`
	Node   ApplyNodeSetup `json:"node"`
	Steps  []ApplyStep    `json:"steps"`
	Expect []ApplyExpect  `json:"expect"`
	// Pairs names the pairs whose answer a step's Expect.Answers may list. It is
	// derived from every table of the case, so it is not in the file.
}

// ApplyObserved is what a node reports after a step, with the same meaning as
// ApplyExpect. A harness fills every field; the runner compares the ones a case
// asserts.
type ApplyObserved struct {
	Result      string
	Reason      string
	Flags       map[string]bool
	VersionUsed uint64
	PanelStale  bool
	ExpiresAt   int64
	LastRefusal string
	Refusals    uint64
	AppliedSeq  uint64
	Quarantine  string
	InUse       bool
	NSSet       []string
	Answers     map[string]string
}

// ApplyNode is one started node.
type ApplyNode interface {
	// Step runs step i of the case and reports the node after it. now is the
	// node's clock at that step, which is Node.Clock plus the step's At.
	Step(i int, s *ApplyStep, now int64) (ApplyObserved, error)
}

// ApplyHarness starts a node for a case. The reference one is in this package;
// the node's glue harness starts its real table writer on a temporary directory.
type ApplyHarness interface {
	Start(c *ApplyCase) (ApplyNode, error)
}

// Table is the plain table as the PairTable a push or an applied entry carries,
// for a harness that has to sign or encode it.
func (in *PairInput) Table() (*policyv1.PairTable, error) { return in.table() }

// PairVectorID is the 16-byte id the vectors give a node or pair by name.
func PairVectorID(name string) []byte { return vecID(name) }

// Names returns every node and pair name of the case, so a harness can turn the
// ids it sees back into names.
func (c *ApplyCase) Names() (nodes, pairs []string) {
	seenN, seenP := map[string]bool{}, map[string]bool{}
	add := func(in *PairInput) {
		if in == nil {
			return
		}
		for _, n := range in.Nodes {
			if !seenN[n.ID] {
				seenN[n.ID] = true
				nodes = append(nodes, n.ID)
			}
		}
		for _, p := range in.Pairs {
			if !seenP[p.ID] {
				seenP[p.ID] = true
				pairs = append(pairs, p.ID)
			}
		}
	}
	add(c.Node.Membership)
	for id := range c.Node.Flags {
		if !seenN[id] {
			seenN[id] = true
			nodes = append(nodes, id)
		}
	}
	for i := range c.Steps {
		add(c.Steps[i].Table)
	}
	sort.Strings(nodes)
	sort.Strings(pairs)
	return nodes, pairs
}

// runPairTableApplyGroup is the group inside Run. The apply rules are the node's table writer, which no evaluator Harness has, so
// the group runs through h only when h is an ApplyHarness. The reference harness runs the reference model, which is what the
// panel's own test of the model is. Any other harness does not run it, and says so: running the panel's model for it and
// reporting green would say a node conforms that nobody tested (GP-r1-11). A node runs the group itself with RunPairTableApply.
// It is not a t.Skip, because a skip in a node's Run would fail the skip check of CI for a group that node runs on its own.
// It reports whether the group ran.
func runPairTableApplyGroup(t *testing.T, g *GroupFile, h Harness) bool {
	switch hh := h.(type) {
	case ApplyHarness:
		RunPairTableApplyGroup(t, g, hh)
	case Reference:
		RunPairTableApplyGroup(t, g, ReferenceApply{})
	default:
		t.Log("pair-table-apply is not run by this harness (no ApplyHarness): run the group with vectors.RunPairTableApply")
		return false
	}
	return true
}

// RunPairTableApply runs the group through a harness that is not the reference
// one, as the node's glue does.
func RunPairTableApply(t *testing.T, h ApplyHarness) {
	t.Helper()
	g, err := ReadGroup("pair-table-apply")
	if err != nil {
		t.Fatal(err)
	}
	RunPairTableApplyGroup(t, g, h)
}

// RunPairTableApplyGroup runs a read group through h.
func RunPairTableApplyGroup(t *testing.T, g *GroupFile, h ApplyHarness) {
	t.Helper()
	var cases []ApplyCase
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
			if len(c.Steps) == 0 || len(c.Steps) != len(c.Expect) {
				t.Fatalf("%d steps and %d expectations: a case has one expectation per step", len(c.Steps), len(c.Expect))
			}
			n, err := h.Start(c)
			if err != nil {
				t.Fatalf("start: %v\n  case: %s", err, c.Why)
			}
			for i := range c.Steps {
				s := &c.Steps[i]
				got, err := n.Step(i, s, c.Node.Clock+s.At)
				if err != nil {
					t.Fatalf("step %d (%s): %v\n  case: %s", i, s.Kind, err, c.Why)
				}
				for _, d := range diffApply(&c.Expect[i], &got) {
					t.Errorf("step %d (%s at %d): %s\n  case: %s", i, s.Kind, s.At, d, c.Why)
				}
			}
		})
	}
}

// diffApply lists what differs between an expectation and what a node reported.
func diffApply(e *ApplyExpect, o *ApplyObserved) []string {
	var d []string
	cmp := func(field string, got, want any) {
		if !reflect.DeepEqual(got, want) {
			d = append(d, fmt.Sprintf("%s = %v, want %v", field, got, want))
		}
	}
	cmp("result", o.Result, e.Result)
	if e.Reason != nil {
		cmp("reason", o.Reason, *e.Reason)
	}
	if e.Flags != nil {
		got := o.Flags
		if got == nil {
			got = map[string]bool{}
		}
		cmp("flags", got, *e.Flags)
	}
	if e.VersionUsed != nil {
		cmp("version_used", o.VersionUsed, *e.VersionUsed)
	}
	if e.PanelStale != nil {
		cmp("panel_stale", o.PanelStale, *e.PanelStale)
	}
	if e.ExpiresAt != nil {
		cmp("expires_at", o.ExpiresAt, *e.ExpiresAt)
	}
	if e.LastRefusal != nil {
		cmp("last_refusal", o.LastRefusal, *e.LastRefusal)
	}
	if e.Refusals != nil {
		cmp("refusals", o.Refusals, *e.Refusals)
	}
	if e.AppliedSeq != nil {
		cmp("applied_seq", o.AppliedSeq, *e.AppliedSeq)
	}
	if e.Quarantine != nil {
		cmp("quarantine", o.Quarantine, *e.Quarantine)
	}
	if e.InUse != nil {
		cmp("in_use", o.InUse, *e.InUse)
	}
	if e.NSSet != nil {
		got := append([]string{}, o.NSSet...)
		sort.Strings(got)
		cmp("ns_set", got, *e.NSSet)
	}
	if e.Answers != nil {
		got := o.Answers
		if got == nil {
			got = map[string]string{}
		}
		cmp("answers", got, *e.Answers)
	}
	return d
}

// ---- the reference model ------------------------------------------------------

// ReferenceApply is the reference ApplyHarness: 8a.4 Node apply and 8a.5 as a
// small state machine over the shared pieces. It reads no clock and touches no
// disk, so "persisted" is the fields that survive a restart.
type ReferenceApply struct{}

// Start implements ApplyHarness.
func (ReferenceApply) Start(c *ApplyCase) (ApplyNode, error) {
	m := &refApplyNode{c: c, self: zone.NodeID(vecID(c.Node.Self))}
	m.nodeName, m.pairName = map[zone.NodeID]string{}, map[zone.PairID]string{}
	nodes, pairs := c.Names()
	for _, n := range nodes {
		m.nodeName[zone.NodeID(vecID(n))] = n
	}
	for _, p := range pairs {
		m.pairName[zone.PairID(vecID(p))] = p
	}
	if c.Node.Membership != nil {
		pt, err := c.Node.Membership.table()
		if err != nil {
			return nil, err
		}
		m.member = pt
	}
	m.appliedSeq = c.Node.AppliedSeq
	m.flags = zone.FlagMap{}
	for n, f := range c.Node.Flags {
		m.flags[zone.NodeID(vecID(n))] = f
	}
	m.version, m.highest, m.expiresAt = c.Node.VersionUsed, c.Node.Highest, c.Node.ExpiresAt
	if m.highest < m.version {
		m.highest = m.version
	}
	m.start(c.Node.Clock)
	return m, nil
}

type refApplyNode struct {
	c        *ApplyCase
	self     zone.NodeID
	nodeName map[zone.NodeID]string
	pairName map[zone.PairID]string

	// Persisted: they survive a restart.
	member     *policyv1.PairTable
	appliedSeq uint64
	flags      zone.FlagMap
	version    uint64
	highest    uint64
	expiresAt  int64

	// Per process: a restart resets them.
	started       int64
	accepted      bool
	refusals      uint64
	lastRefusal   hubv1.PushRefusal
	latestRefusal hubv1.PushRefusal
	offset        int64
	lastST        int64
	hasST         bool
	table         *zone.Table
}

// start is the process start: the table is rebuilt from the applied log entry and
// the persisted flags, and every counter begins again.
func (m *refApplyNode) start(now int64) {
	m.started, m.accepted, m.refusals = now, false, 0
	m.lastRefusal, m.latestRefusal = hubv1.PushRefusal_PUSH_REFUSAL_UNSPECIFIED, hubv1.PushRefusal_PUSH_REFUSAL_UNSPECIFIED
	m.offset, m.hasST, m.lastST = 0, false, 0
	m.table = m.build()
	if m.member != nil && m.table == nil { // a build that fails drops the flags (At start)
		m.dropFlags()
	}
}

// dropFlags is what a persisted push that fails its checks leaves: no flags, no
// version in use, and the highest version kept so an older push is still refused.
func (m *refApplyNode) dropFlags() {
	m.flags, m.version, m.expiresAt = zone.FlagMap{}, 0, 0
	m.table = m.build()
}

func (m *refApplyNode) build() *zone.Table {
	if m.member == nil {
		return nil
	}
	t, err := zone.Build(zone.WithFlags(wire.ZoneInput(m.member), m.version, m.flags))
	if err != nil {
		return nil
	}
	return t
}

func memberIDs(pt *policyv1.PairTable) []zone.NodeID {
	var ids []zone.NodeID
	for _, n := range pt.GetNodes() {
		if len(n.GetNodeId()) == 16 {
			ids = append(ids, zone.NodeID(n.GetNodeId()))
		}
	}
	return ids
}

// Step implements ApplyNode.
func (m *refApplyNode) Step(_ int, s *ApplyStep, now int64) (ApplyObserved, error) {
	res, reason, quarantine := "none", hubv1.PushRefusal_PUSH_REFUSAL_UNSPECIFIED, ""
	switch s.Kind {
	case "push":
		var err error
		if res, reason, err = m.push(s, now); err != nil {
			return ApplyObserved{}, err
		}
	case "log":
		var err error
		if res, quarantine, err = m.log(s); err != nil {
			return ApplyObserved{}, err
		}
	case "restart":
		m.start(now)
		if s.CorruptPush {
			m.dropFlags()
		}
	case "server_time":
		m.offset, m.lastST, m.hasST = s.Offset, now, true
	case "tick":
	default:
		return ApplyObserved{}, fmt.Errorf("unknown step kind %q", s.Kind)
	}
	return m.observe(now, res, reason, quarantine), nil
}

// push is 8a.4 Node apply, steps 1 to 4, in the order the contract gives.
func (m *refApplyNode) push(s *ApplyStep, now int64) (string, hubv1.PushRefusal, error) {
	refuse := func(r hubv1.PushRefusal) (string, hubv1.PushRefusal, error) {
		m.refusals++
		m.lastRefusal = r
		// A refused lower version leaves PanelStale as it was (SC 15, 8a.5): it must not replace the refusal that set it.
		if r != hubv1.PushRefusal_PUSH_REFUSAL_LOWER_VERSION {
			m.latestRefusal = r
		}
		return "refused", r, nil
	}
	hubNow := now + m.offset
	if s.Defect == "empty" || s.Defect == "signature" {
		return refuse(hubv1.PushRefusal_PUSH_REFUSAL_SIGNATURE)
	}
	if s.Defect != "" {
		return "", 0, fmt.Errorf("unknown defect %q", s.Defect)
	}
	if s.Table == nil {
		return "", 0, fmt.Errorf("a push step needs a table")
	}
	pt, err := s.Table.table()
	if err != nil {
		return "", 0, err
	}
	if err := wire.ValidatePairTablePush(pt); err != nil {
		return refuse(hubv1.PushRefusal_PUSH_REFUSAL_INVALID)
	}
	if pt.Version == 0 { // a signed 0 is not a push: PeerView uses 0 for "none yet"
		return refuse(hubv1.PushRefusal_PUSH_REFUSAL_INVALID)
	}
	if pt.ExpiresAt <= hubNow {
		return refuse(hubv1.PushRefusal_PUSH_REFUSAL_EXPIRED)
	}
	if pt.Version < m.highest {
		return refuse(hubv1.PushRefusal_PUSH_REFUSAL_LOWER_VERSION)
	}
	pushed := wire.PushFlags(pt)
	accept := func() {
		m.accepted = true
		m.latestRefusal = hubv1.PushRefusal_PUSH_REFUSAL_UNSPECIFIED
	}
	// Step 2: the version in use again. An equal version that is not the one in
	// use (the state after a dropped persisted push) applies like a higher one.
	if m.version != 0 && pt.Version == m.version {
		if !m.flags.Redelivery(pushed) {
			return refuse(hubv1.PushRefusal_PUSH_REFUSAL_FLAG_CONFLICT)
		}
		accept()
		if pt.ExpiresAt > m.expiresAt {
			m.expiresAt = pt.ExpiresAt
		}
		return "redelivered", 0, nil
	}
	// Steps 3 and 4: take the flags onto the node's own membership and build.
	next := m.flags.Take(pushed, memberIDs(m.member))
	if m.member != nil {
		t, err := zone.Build(zone.WithFlags(wire.ZoneInput(m.member), pt.Version, next))
		if err != nil {
			return refuse(hubv1.PushRefusal_PUSH_REFUSAL_BUILD)
		}
		m.table = t
	}
	m.flags, m.version, m.expiresAt = next, pt.Version, pt.ExpiresAt
	if pt.Version > m.highest {
		m.highest = pt.Version
	}
	accept()
	return "applied", 0, nil
}

// log is 9.7 item 1 and 4 for an entry that carries a PairTable: the table must
// validate and build with the flags as they are, and then it is the membership.
// The entry carries no flags, so the flag map is not touched.
func (m *refApplyNode) log(s *ApplyStep) (string, string, error) {
	if s.Table == nil {
		return "", "", fmt.Errorf("a log step needs a table")
	}
	pt, err := s.Table.table()
	if err != nil {
		return "", "", err
	}
	if err := wire.ValidatePairTable(pt); err != nil {
		return "refused", "entry", nil
	}
	t, err := zone.Build(zone.WithFlags(wire.ZoneInput(pt), m.version, m.flags))
	if err != nil {
		return "refused", "entry", nil
	}
	m.member, m.table, m.appliedSeq = pt, t, s.ConfigSeq
	return "applied", "", nil
}

// inUse is 8a.5 (Table in use): a built table is served once a push was accepted
// in this run or 30 s have passed since start.
func (m *refApplyNode) inUse(now int64) bool {
	return m.table != nil && (m.accepted || now-m.started >= 30)
}

// panelStale is 8a.5, with the Control stream taken as up.
func (m *refApplyNode) panelStale(now int64) bool {
	last := m.started
	if m.hasST {
		last = m.lastST
	}
	if now-last >= 30 || !m.accepted {
		return true
	}
	if m.expiresAt != 0 && m.expiresAt <= now+m.offset {
		return true
	}
	return m.latestRefusal != hubv1.PushRefusal_PUSH_REFUSAL_UNSPECIFIED && m.latestRefusal != hubv1.PushRefusal_PUSH_REFUSAL_LOWER_VERSION
}

func refusalName(r hubv1.PushRefusal) string {
	if r == hubv1.PushRefusal_PUSH_REFUSAL_UNSPECIFIED {
		return ""
	}
	return strings.TrimPrefix(r.String(), "PUSH_REFUSAL_")
}

func (m *refApplyNode) observe(now int64, res string, reason hubv1.PushRefusal, quarantine string) ApplyObserved {
	o := ApplyObserved{
		Result: res, Reason: refusalName(reason), Flags: map[string]bool{}, VersionUsed: m.version,
		PanelStale: m.panelStale(now), ExpiresAt: m.expiresAt, LastRefusal: refusalName(m.lastRefusal),
		Refusals: m.refusals, AppliedSeq: m.appliedSeq, Quarantine: quarantine, InUse: m.inUse(now),
		Answers: map[string]string{},
	}
	for id, f := range m.flags {
		o.Flags[m.nodeName[id]] = f
	}
	if o.InUse {
		for _, n := range zone.NameServers(m.table) {
			o.NSSet = append(o.NSSet, fmt.Sprintf("ns%d", n.Slot))
		}
		for id, name := range m.pairName {
			if n, ok := zone.Target(m.table, id, zone.Local{Self: m.self}); ok && m.table.Pairs[id].ID == id {
				o.Answers[name] = n.DNSIP.String()
			}
		}
	}
	return o
}
