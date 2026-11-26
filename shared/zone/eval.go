package zone

import (
	"errors"
	"sort"
	"time"
)

// This file is the evaluator of 8a.6: the hub's in-memory trackers, the input
// predicates of 8a.4, and one loop that runs the rows of Rows() in order. It
// holds no timer of its own: a timed row counts from the tick on which its
// State and Inputs first held together, and the caller supplies every time.

// PeerEntry is one entry of a node's PeerView: its probe state of Node.
type PeerEntry struct {
	Node  NodeID
	Known bool
	Down  bool // false when Known is false
}

// Report is what one valid Heartbeat tells the evaluator.
type Report struct {
	// Paths has one entry for each resolve path the node's mode uses, true
	// when it is healthy (Heartbeat.upstreams, 8a.4 Resolve health).
	Paths      []bool
	Isolated   bool
	AppliedSeq uint64
	Peers      []PeerEntry // PeerView.peers
}

// View is the answer of view(X).
type View uint8

const (
	ViewNone View = iota
	ViewUp
	ViewDown
)

// Request is a pending row of node_dns_requests. Age is the database's
// now() - requested_at, so a hub whose clock differs from the database's
// still judges the 10 s bound by the database clock (8a.4 Requests).
type Request struct {
	ID          string
	Node        NodeID
	Kind        RequestKind
	RequestedAt time.Time // only to order requests on one tick
	Age         time.Duration
}

// Request results.
const (
	ResultDone    = "done"
	ResultRefused = "refused"
	ResultExpired = "expired"
)

// RequestResult is the hub's decision on a request.
type RequestResult struct {
	ID     string
	Result string
	Reason string // for a refusal, the reason of the first condition that failed
}

// Alert is one alert of 8a.6. Node is the node it names (zero NodeID when it
// names none) and Detail how: "" for the node the row acted on, and for F0
// and for the peer of F1 and F2 "withdrawn", "cleared" or "cleared_hold".
type Alert struct {
	Kind   string
	Node   NodeID
	Named  bool // false when the alert names no node
	Detail string
}

// Detail values of an Alert.
const (
	DetailWithdrawn   = "withdrawn"
	DetailCleared     = "cleared"
	DetailClearedHold = "cleared_hold"
)

// Event is one signing event: one action of a row. Changed holds the columns
// after the event of every node it changed. Stable is S for each withdrawn
// node after the event.
type Event struct {
	Row     string
	At      time.Time
	Changed map[NodeID]Columns
	Stable  map[NodeID]time.Duration
	Alerts  []Alert
	// Done is the request this event carried out, if any.
	Done *RequestResult
	// Membership is the table the event signs: the hub's latest membership.
	// The caller persists it as last_table with the flags and the version.
	Membership *Table
}

// Output is one thing a tick produced, in order: an event, or a request that
// was refused or expired and so caused none.
type Output struct {
	Event   *Event
	Request *RequestResult
}

// CommitFunc persists an event in the hub's one transaction (flags,
// pair_event_state) before it is signed. A tick whose event fails to commit
// ends there: nothing of that event is applied, no later row acts, and the
// error is returned (8a.4 Versions, 8a.6 Order on a tick).
type CommitFunc func(*Event) error

// ErrNoMembership is returned when the evaluator is given no membership table
// at all (a nil Table). It never means "no nodes": that is a Table with none.
var ErrNoMembership = errors.New("zone: no membership table")

type notice struct {
	seq uint64
	at  time.Time
}

type tracker struct {
	hbAt    time.Time // the latest Heartbeat, or the hub's start, or when the node first entered the membership
	hb      *Report   // nil until a real Heartbeat arrives
	probe   Probe
	notices []notice
}

type timerKey struct {
	row  string
	node NodeID
}

// Evaluator is the hub's failover state: trackers in memory, the failover
// columns and last_table as read from the database. It is not safe for
// concurrent use; the hub's evaluation loop owns it.
type Evaluator struct {
	member    *Table
	last      *Table
	cols      map[NodeID]Columns
	trk       map[NodeID]*tracker
	lastEvent time.Time
	since     map[timerKey]time.Time
	rows      []Row
}

// NewEvaluator starts the trackers at now, which is a hub start or the start
// of a case: every probe state is unknown and no Heartbeat has arrived. cols
// are the failover columns of every node of member, and last is last_table,
// both as persisted. A nil last is a table with no pair.
func NewEvaluator(now time.Time, member, last *Table, cols map[NodeID]Columns) (*Evaluator, error) {
	if member == nil {
		return nil, ErrNoMembership
	}
	e := &Evaluator{
		cols:      map[NodeID]Columns{},
		trk:       map[NodeID]*tracker{},
		lastEvent: now,
		since:     map[timerKey]time.Time{},
		rows:      Rows(),
		last:      last,
	}
	for id, c := range cols {
		e.cols[id] = c
	}
	if err := e.SetMembership(now, member); err != nil {
		return nil, err
	}
	return e, nil
}

// SetMembership sets the hub's latest membership, the PairTable of the
// latest log entry. A node that enters it starts with unknown trackers, and
// one that leaves it takes its trackers and columns with it (its row is
// deleted, 8a.4 Membership). Call it before Tick on every tick.
func (e *Evaluator) SetMembership(now time.Time, t *Table) error {
	if t == nil {
		// A log entry with no PairTable is not an empty membership: taking it
		// for one would forget every hold and withdrawal, and the next F7
		// would sign that empty table as last_table. Only a built Table with
		// no node means an empty membership; the previous one stays.
		return ErrNoMembership
	}
	e.member = t
	for id := range t.Nodes {
		if e.trk[id] == nil {
			e.trk[id] = &tracker{hbAt: now}
		}
	}
	for id := range e.trk {
		if _, ok := t.Nodes[id]; !ok {
			delete(e.trk, id)
			delete(e.cols, id)
			for k := range e.since {
				if k.node == id {
					delete(e.since, k)
				}
			}
		}
	}
	return nil
}

// Heartbeat records a valid Heartbeat from node at now. The caller has
// identified the sender by the stream's mTLS identity, never by a field.
func (e *Evaluator) Heartbeat(now time.Time, node NodeID, r Report) {
	if t := e.trk[node]; t != nil {
		t.hbAt = now
		rc := r
		t.hb = &rc
	}
}

// ProbeRound records a completed round of the hub's prober, both parts.
func (e *Evaluator) ProbeRound(now time.Time, node NodeID, dotOK, dohOK bool) {
	if t := e.trk[node]; t != nil {
		t.probe.Round(now, dotOK && dohOK)
	}
}

// HeadNotice records a HeadNotice with seq sent to node at now.
//
// fit(X) only asks for the highest seq among the notices that are already
// older than the grace, so every such notice but that one is dead weight. The
// hub sends one notice per log entry for the life of the process; keeping them
// all would grow its memory and the cost of every fit without bound. A notice
// that has passed the grace stays past it, so folding here loses nothing.
func (e *Evaluator) HeadNotice(now time.Time, node NodeID, seq uint64) {
	t := e.trk[node]
	if t == nil {
		return
	}
	grace := Inputs().HeadNoticeGrace
	var old *notice
	kept := make([]notice, 0, len(t.notices)+1)
	for i := range t.notices {
		n := t.notices[i]
		if grace.Passed(now.Sub(n.at)) {
			if old == nil || n.seq > old.seq {
				c := n
				old = &c
			}
			continue
		}
		kept = append(kept, n)
	}
	if old != nil {
		kept = append([]notice{*old}, kept...)
	}
	t.notices = append(kept, notice{seq: seq, at: now})
}

// Columns returns the failover columns of a node as the evaluator holds them.
func (e *Evaluator) Columns(node NodeID) Columns { return e.cols[node] }

// LastTable is the membership of the last signing event.
func (e *Evaluator) LastTable() *Table { return e.last }

// --- Inputs of 8a.4 -------------------------------------------------------

func (e *Evaluator) peer(x NodeID) (NodeID, bool) { return e.member.PeerOf(x) }

func (e *Evaluator) revoked(x NodeID) bool { return e.member.Nodes[x].Revoked }

// hb(X): a valid Heartbeat from the last 15 s, the count starting at the
// hub's start (or the node's entry into the membership) when none has come.
func (e *Evaluator) hb(now time.Time, x NodeID) bool {
	t := e.trk[x]
	return t != nil && !Inputs().HeartbeatStale.Passed(now.Sub(t.hbAt))
}

// fresh returns the latest real Heartbeat of x when it is from the last 15 s.
func (e *Evaluator) fresh(now time.Time, x NodeID) *Report {
	t := e.trk[x]
	if t == nil || t.hb == nil || Inputs().HeartbeatStale.Passed(now.Sub(t.hbAt)) {
		return nil
	}
	return t.hb
}

func (e *Evaluator) probe(now time.Time, x NodeID) ProbeState {
	if t := e.trk[x]; t != nil {
		return t.probe.State(now)
	}
	return ProbeUnknown
}

// view(X): the entry for X in the latest PeerView of its pair peer Y, when
// that Heartbeat is from the last 10 s and the entry is known.
func (e *Evaluator) view(now time.Time, x NodeID) View {
	y, ok := e.peer(x)
	if !ok {
		return ViewNone
	}
	t := e.trk[y]
	if t == nil || t.hb == nil || Inputs().ViewStale.Passed(now.Sub(t.hbAt)) {
		return ViewNone
	}
	for _, p := range t.hb.Peers {
		if p.Node == x && p.Known {
			if p.Down {
				return ViewDown
			}
			return ViewUp
		}
	}
	return ViewNone
}

func (e *Evaluator) dead(now time.Time, x NodeID) bool {
	if e.revoked(x) {
		return true
	}
	return (!e.hb(now, x) || e.probe(now, x) == ProbeDown) && e.view(now, x) == ViewDown
}

// rd(X): X reports resolve paths and none healthy, while Y reports at least
// one healthy. Comparative on purpose: a cut that hits both live nodes moves
// nothing. A Y with no fresh Heartbeat has no healthy path.
func (e *Evaluator) rd(now time.Time, x NodeID) bool {
	y, ok := e.peer(x)
	if !ok {
		return false
	}
	rx := e.fresh(now, x)
	if rx == nil || len(rx.Paths) == 0 || anyTrue(rx.Paths) {
		return false
	}
	ry := e.fresh(now, y)
	return ry != nil && anyTrue(ry.Paths)
}

func anyTrue(b []bool) bool {
	for _, v := range b {
		if v {
			return true
		}
	}
	return false
}

func (e *Evaluator) ready(now time.Time, x NodeID) bool {
	return !e.revoked(x) && e.hb(now, x) && e.probe(now, x) == ProbeUp && !e.rd(now, x)
}

func (e *Evaluator) fit(now time.Time, x NodeID) bool {
	if !e.ready(now, x) {
		return false
	}
	r := e.fresh(now, x)
	if r == nil || r.Isolated {
		return false
	}
	grace := Inputs().HeadNoticeGrace
	for _, n := range e.trk[x].notices {
		if grace.Passed(now.Sub(n.at)) && r.AppliedSeq < n.seq {
			return false
		}
	}
	return true
}

// holds evaluates one condition for node x.
func (e *Evaluator) holds(now time.Time, c Cond, x NodeID) bool {
	who := x
	if c.Of == Y {
		y, ok := e.peer(x)
		if !ok {
			// A condition on Y presupposes a peer (8a.6); without one it fails
			// whatever its sign, so the case "only not_paired fails" is X in
			// no pair.
			return false
		}
		who = y
	}
	var v bool
	switch c.Pred {
	case PredHasPeer:
		_, v = e.peer(who)
	case PredWithdrawn:
		v = e.cols[who].Withdrawn
	case PredHeld:
		v = e.cols[who].Hold
	case PredDead:
		v = e.dead(now, who)
	case PredReady:
		v = e.ready(now, who)
	case PredFit:
		v = e.fit(now, who)
	case PredResolveDown:
		v = e.rd(now, who)
	case PredViewUp:
		v = e.view(now, who) == ViewUp
	}
	return v != c.Not
}

func (e *Evaluator) allHold(now time.Time, cs []Cond, x NodeID) bool {
	for _, c := range cs {
		if !e.holds(now, c, x) {
			return false
		}
	}
	return true
}

// --- The tick -------------------------------------------------------------

func (e *Evaluator) nodeIDs() []NodeID {
	ids := make([]NodeID, 0, len(e.member.Nodes))
	for id := range e.member.Nodes {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return string(ids[i][:]) < string(ids[j][:]) })
	return ids
}

// Tick runs the rows once, in id order, on the state the rows before left
// (8a.6 Order on a tick). reqs are the pending requests the hub read. It
// returns what happened in order. If commit fails the tick ends and the error
// is returned along with what had already been committed.
func (e *Evaluator) Tick(now time.Time, reqs []Request, commit CommitFunc) ([]Output, error) {
	var out []Output
	for _, row := range e.rows {
		var err error
		switch row.Kind {
		case RowMembership:
			out, err = e.tickMembership(now, row, out, commit)
		case RowNode:
			out, err = e.tickNodes(now, row, out, commit)
		case RowRequest:
			out, err = e.tickRequests(now, row, reqs, out, commit)
		case RowRefresh:
			out, err = e.tickRefresh(now, row, out, commit)
		}
		if err != nil {
			return out, err
		}
	}
	e.settle(now)
	return out, nil
}

// settle starts the timer of every timed row whose State and Inputs hold at the
// end of the tick, so a later row's event (a Release, a Force failback) starts
// the counting of an earlier row on the tick it happened, not the next: F3's S
// begins at the Release (8a.6). It never fires a row.
func (e *Evaluator) settle(now time.Time) {
	for _, row := range e.rows {
		if row.Kind != RowNode {
			continue
		}
		for _, x := range e.nodeIDs() {
			key := timerKey{row.ID, x}
			if !e.allHold(now, row.State, x) || !e.allHold(now, row.Inputs, x) {
				delete(e.since, key)
			} else if _, ok := e.since[key]; !ok {
				e.since[key] = now
			}
		}
	}
}

// Start is the start event (8a.4 Versions): F0 when the pair peer of some
// node differs from last_table, otherwise the F7 refresh. The hub runs it
// before it accepts any Control stream. It reads no tracker, which are all
// unknown at start.
func (e *Evaluator) Start(now time.Time, commit CommitFunc) ([]Output, error) {
	var out []Output
	if len(e.differing()) > 0 {
		return e.tickMembership(now, e.row(F0), out, commit)
	}
	// The refresh row waits for its interval; the start event does not.
	return e.signRefresh(now, e.row(F7), out, commit)
}

func (e *Evaluator) row(id string) Row {
	for _, r := range e.rows {
		if r.ID == id {
			return r
		}
	}
	panic("zone: no row " + id)
}

// apply commits an event and, only if that succeeds, makes it the state.
func (e *Evaluator) apply(ev *Event, newCols map[NodeID]Columns, commit CommitFunc) error {
	ev.Changed = map[NodeID]Columns{}
	for id, c := range newCols {
		if e.cols[id] != c {
			ev.Changed[id] = c
		}
	}
	ev.Membership = e.member
	merged := map[NodeID]Columns{}
	for id, c := range e.cols {
		merged[id] = c
	}
	for id, c := range ev.Changed {
		merged[id] = c
	}
	ev.Stable = map[NodeID]time.Duration{}
	for id, c := range merged {
		if c.Withdrawn {
			ev.Stable[id] = StablePeriod(c, ev.At)
		}
	}
	if commit != nil {
		if err := commit(ev); err != nil {
			return err
		}
	}
	for id, c := range ev.Changed {
		e.cols[id] = c
	}
	e.last = e.member
	e.lastEvent = ev.At
	return nil
}

func (e *Evaluator) copyCols() map[NodeID]Columns {
	m := make(map[NodeID]Columns, len(e.cols))
	for id := range e.member.Nodes {
		m[id] = e.cols[id]
	}
	return m
}

// step runs one Step of a node or request row on cols. It reports whether the
// flap rule fired for the withdrawn node.
func step(s Step, now time.Time, x, y NodeID, hasY bool, wasWithdrawn map[NodeID]bool, cols map[NodeID]Columns) (flapped bool) {
	who := x
	if s.On == Y {
		if !hasY {
			return false
		}
		who = y
	}
	if s.IfWasWithdrawn && !wasWithdrawn[who] {
		return false
	}
	c := cols[who]
	switch s.Op {
	case OpWithdraw:
		c.Withdrawn = true
		if s.Flap {
			c, flapped = Flap(c, now)
		}
	case OpClearWithdrawal:
		c.Withdrawn = false
	case OpSetHold:
		c.Hold = true
	case OpClearHold:
		c.Hold = false
	case OpSetFailbackAt:
		c.LastFailbackAt = now
	}
	cols[who] = c
	return flapped
}

// runSteps applies a row's steps for x and returns the alerts of the nodes it
// touched beyond x itself (the peer's cleared hold) and whether the flap rule fired.
func (e *Evaluator) runSteps(row Row, now time.Time, x NodeID) (map[NodeID]Columns, []Alert, bool) {
	y, hasY := e.peer(x)
	cols := e.copyCols()
	was := map[NodeID]bool{}
	for id, c := range cols {
		was[id] = c.Withdrawn
	}
	flapped := false
	for _, s := range row.Action {
		if step(s, now, x, y, hasY, was, cols) {
			flapped = true
		}
	}
	var alerts []Alert
	if hasY && e.cols[y].Hold && !cols[y].Hold {
		alerts = append(alerts, Alert{Kind: row.Alert, Node: y, Named: true, Detail: DetailClearedHold})
	}
	return cols, alerts, flapped
}

func (e *Evaluator) tickNodes(now time.Time, row Row, out []Output, commit CommitFunc) ([]Output, error) {
	for _, x := range e.nodeIDs() {
		key := timerKey{row.ID, x}
		if !e.allHold(now, row.State, x) || !e.allHold(now, row.Inputs, x) {
			delete(e.since, key)
			continue
		}
		start, ok := e.since[key]
		if !ok {
			start = now
			e.since[key] = now
		}
		need := time.Duration(row.For.Seconds) * time.Second
		if row.For.Stable {
			need = StablePeriod(e.cols[x], now)
		}
		if now.Sub(start) < need {
			continue
		}
		cols, extra, flapped := e.runSteps(row, now, x)
		ev := &Event{Row: row.ID, At: now}
		ev.Alerts = append(ev.Alerts, Alert{Kind: row.Alert, Node: x, Named: true})
		ev.Alerts = append(ev.Alerts, extra...)
		if flapped {
			ev.Alerts = append(ev.Alerts, Alert{Kind: AlertFlapping, Node: x, Named: true})
		}
		if err := e.apply(ev, cols, commit); err != nil {
			return out, err
		}
		// The row has acted for x; its timer ends with the State that held.
		delete(e.since, key)
		out = append(out, Output{Event: ev})
	}
	return out, nil
}

func (e *Evaluator) tickRequests(now time.Time, row Row, reqs []Request, out []Output, commit CommitFunc) ([]Output, error) {
	var mine []Request
	for _, r := range reqs {
		if r.Kind == row.Request {
			mine = append(mine, r)
		}
	}
	sort.SliceStable(mine, func(i, j int) bool {
		if !mine[i].RequestedAt.Equal(mine[j].RequestedAt) {
			return mine[i].RequestedAt.Before(mine[j].RequestedAt)
		}
		return mine[i].ID < mine[j].ID
	})
	for _, r := range mine {
		if Inputs().RequestMaxAge.Passed(r.Age) {
			out = append(out, Output{Request: &RequestResult{ID: r.ID, Result: ResultExpired}})
			continue
		}
		refused := ""
		for _, c := range row.Inputs {
			if !e.holds(now, c, r.Node) {
				refused = c.Reason
				break
			}
		}
		if refused != "" {
			out = append(out, Output{Request: &RequestResult{ID: r.ID, Result: ResultRefused, Reason: refused}})
			continue
		}
		cols, extra, _ := e.runSteps(row, now, r.Node)
		ev := &Event{Row: row.ID, At: now, Done: &RequestResult{ID: r.ID, Result: ResultDone}}
		ev.Alerts = append(ev.Alerts, Alert{Kind: row.Alert, Node: r.Node, Named: true})
		ev.Alerts = append(ev.Alerts, extra...)
		if err := e.apply(ev, cols, commit); err != nil {
			return out, err
		}
		out = append(out, Output{Event: ev})
	}
	return out, nil
}

func (e *Evaluator) tickRefresh(now time.Time, row Row, out []Output, commit CommitFunc) ([]Output, error) {
	if now.Sub(e.lastEvent) < Inputs().RefreshEvery {
		return out, nil
	}
	return e.signRefresh(now, row, out, commit)
}

func (e *Evaluator) signRefresh(now time.Time, row Row, out []Output, commit CommitFunc) ([]Output, error) {
	ev := &Event{Row: row.ID, At: now}
	if err := e.apply(ev, e.copyCols(), commit); err != nil {
		return out, err
	}
	return append(out, Output{Event: ev}), nil
}
