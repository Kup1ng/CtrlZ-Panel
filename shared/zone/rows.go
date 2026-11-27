package zone

import "time"

// This file is the decision table of 8a.6 and the thresholds of 8a.4 as data.
// The evaluator (eval.go) runs these rows and nothing else, and the
// zone-failover vector generator reads only Rows and Inputs and what they
// return (8a.10), so a change of a row is one change here, in 8a.6 and in the
// hand-written sequences. They are functions that return fresh values because
// the module has no package-level mutable state (section 1).

// Row ids of 8a.6.
const (
	F0 = "F0"
	F1 = "F1"
	F2 = "F2"
	F3 = "F3"
	F4 = "F4"
	F5 = "F5"
	F6 = "F6"
	F7 = "F7"
)

// RowKind says what a row looks at.
type RowKind uint8

const (
	// RowMembership is F0: the hub's latest membership against last_table.
	RowMembership RowKind = iota + 1
	// RowNode is F1 to F3: every node that has a pair peer, in node_id order.
	RowNode
	// RowRequest is F4 to F6: every pending request of the row's kind.
	RowRequest
	// RowRefresh is F7.
	RowRefresh
)

// Role names a node in a condition: X is the node the row is about, Y its pair
// peer.
type Role uint8

const (
	X Role = iota + 1
	Y
)

// Pred is a predicate of 8a.4 or a flag of the failover columns.
type Pred string

const (
	PredHasPeer     Pred = "has_peer"  // the node has a pair peer in the hub's latest membership
	PredWithdrawn   Pred = "withdrawn" // the node's dns_withdrawn column
	PredHeld        Pred = "held"      // the node's dns_hold column
	PredDead        Pred = "dead"      // dead(X), 8a.4
	PredReady       Pred = "ready"     // ready(X)
	PredFit         Pred = "fit"       // fit(X)
	PredResolveDown Pred = "rd"        // rd(X)
	PredViewUp      Pred = "view_up"   // view(X) is up
	PredPeerDiffers Pred = "peer_differs"
)

// Cond is one condition of a row: Pred of the node Of, true or, with Not,
// false. Reason is the refusal reason of a request row (8a.6: a request is
// refused with the reason of the first of its conditions that fails).
type Cond struct {
	Pred   Pred
	Of     Role
	Not    bool
	Reason string
}

// Refusal reasons of the request rows.
const (
	ReasonNotPaired     = "not_paired"
	ReasonPeerNotFit    = "peer_not_fit"
	ReasonPeerWithdrawn = "peer_withdrawn"
	ReasonNotHeld       = "not_held"
	ReasonNotWithdrawn  = "not_withdrawn"
	ReasonNotFit        = "not_fit"
)

// RequestKind is the kind of a row in node_dns_requests.
type RequestKind string

const (
	ReqHold          RequestKind = "hold"
	ReqRelease       RequestKind = "release"
	ReqForceFailback RequestKind = "force_failback"
)

// Timer is the "for" of a row: its State and Inputs must have held together,
// without a break, for Seconds. Stable means the stable period S(X) instead
// (Inputs.Stable or Inputs.StableFlapping, by the flap rule).
type Timer struct {
	Seconds int
	Stable  bool
}

// Op is one step of a row's action.
type Op string

const (
	OpWithdraw        Op = "withdraw"         // set dns_withdrawn
	OpClearWithdrawal Op = "clear_withdrawal" // clear dns_withdrawn
	OpSetHold         Op = "set_hold"         // set dns_hold
	OpClearHold       Op = "clear_hold"       // clear dns_hold
	OpSetFailbackAt   Op = "set_failback_at"  // dns_last_failback_at = now
	OpMembership      Op = "membership"       // F0's three steps (membership.go)
	OpRefresh         Op = "refresh"          // a new version and expiry, no flag change
)

// Step is one step of an action. Flap makes a withdrawal run the flap rule;
// IfWasWithdrawn makes the step apply only to a node that was withdrawn.
type Step struct {
	Op             Op
	On             Role
	Flap           bool
	IfWasWithdrawn bool
}

// Alert kinds of 8a.6. The evaluator raises no other (8a.4 Admin lists the
// rest, and they come from the hub's other parts).
const (
	AlertMembership        = "membership"
	AlertWithdrawal        = "withdrawal"
	AlertWithdrawalResolve = "withdrawal_resolve"
	AlertFailback          = "failback"
	AlertHold              = "hold"
	AlertRelease           = "release"
	AlertForceFailback     = "force_failback"
	AlertFlapping          = "flapping"
)

// Row is a row of the decision table.
type Row struct {
	ID    string
	Name  string
	Kind  RowKind
	State []Cond // the State of X column
	// Inputs are the conditions of the Inputs column. For a request row they
	// are checked in order and each has its Reason.
	Inputs  []Cond
	For     Timer
	Request RequestKind // the request kind of F4 to F6
	Action  []Step
	Alert   string
}

// Rows is 8a.6 transcribed. The review of a change compares it with the text
// row by row.
func Rows() []Row {
	// withdrawX is the action of F1 and F2.
	withdrawX := []Step{
		{Op: OpWithdraw, On: X, Flap: true},
		{Op: OpClearWithdrawal, On: Y},
		{Op: OpClearHold, On: Y},
		{Op: OpSetFailbackAt, On: Y, IfWasWithdrawn: true},
	}
	return []Row{
		{
			ID: F0, Name: "Membership", Kind: RowMembership,
			State:  []Cond{{Pred: PredPeerDiffers, Of: X}},
			Action: []Step{{Op: OpMembership}},
			Alert:  AlertMembership,
		},
		{
			ID: F1, Name: "Dead", Kind: RowNode,
			State:  []Cond{{Pred: PredHasPeer, Of: X}, {Pred: PredWithdrawn, Of: X, Not: true}},
			Inputs: []Cond{{Pred: PredDead, Of: X}, {Pred: PredReady, Of: Y}},
			For:    Timer{Seconds: 5},
			Action: withdrawX,
			Alert:  AlertWithdrawal,
		},
		{
			ID: F2, Name: "Cannot resolve", Kind: RowNode,
			State:  []Cond{{Pred: PredHasPeer, Of: X}, {Pred: PredWithdrawn, Of: X, Not: true}},
			Inputs: []Cond{{Pred: PredResolveDown, Of: X}, {Pred: PredReady, Of: Y}},
			For:    Timer{Seconds: 30},
			Action: withdrawX,
			Alert:  AlertWithdrawalResolve,
		},
		{
			ID: F3, Name: "Failback", Kind: RowNode,
			State:  []Cond{{Pred: PredHasPeer, Of: X}, {Pred: PredWithdrawn, Of: X}, {Pred: PredHeld, Of: X, Not: true}},
			Inputs: []Cond{{Pred: PredFit, Of: X}, {Pred: PredViewUp, Of: X}},
			For:    Timer{Stable: true},
			Action: []Step{{Op: OpClearWithdrawal, On: X}, {Op: OpSetFailbackAt, On: X}},
			Alert:  AlertFailback,
		},
		{
			ID: F4, Name: "Hold", Kind: RowRequest, Request: ReqHold,
			Inputs: []Cond{
				{Pred: PredHasPeer, Of: X, Reason: ReasonNotPaired},
				{Pred: PredFit, Of: Y, Reason: ReasonPeerNotFit},
				{Pred: PredWithdrawn, Of: Y, Not: true, Reason: ReasonPeerWithdrawn},
			},
			Action: []Step{{Op: OpWithdraw, On: X}, {Op: OpSetHold, On: X}},
			Alert:  AlertHold,
		},
		{
			ID: F5, Name: "Release", Kind: RowRequest, Request: ReqRelease,
			Inputs: []Cond{{Pred: PredHeld, Of: X, Reason: ReasonNotHeld}},
			Action: []Step{{Op: OpClearHold, On: X}},
			Alert:  AlertRelease,
		},
		{
			ID: F6, Name: "Force failback", Kind: RowRequest, Request: ReqForceFailback,
			Inputs: []Cond{
				{Pred: PredHasPeer, Of: X, Reason: ReasonNotPaired},
				{Pred: PredWithdrawn, Of: X, Reason: ReasonNotWithdrawn},
				{Pred: PredFit, Of: X, Reason: ReasonNotFit},
			},
			Action: []Step{{Op: OpClearWithdrawal, On: X}, {Op: OpClearHold, On: X}, {Op: OpSetFailbackAt, On: X}},
			Alert:  AlertForceFailback,
		},
		{
			ID: F7, Name: "Refresh", Kind: RowRefresh,
			Action: []Step{{Op: OpRefresh}},
		},
	}
}

// Limit is an age threshold. Passed reports whether an observation of that
// age no longer counts. "From the last 15 s" is the half-open window
// (now-15 s, now], so a Heartbeat that is exactly 15 s old has passed the
// limit: 8a.3 has the hub's first signal at 15 s after a kill that follows a
// Heartbeat. Strict limits are the ones the text words as "more than".
type Limit struct {
	D      time.Duration
	Strict bool
}

// Passed reports whether age has reached the limit.
func (l Limit) Passed(age time.Duration) bool {
	if l.Strict {
		return age > l.D
	}
	return age >= l.D
}

// InputSpec holds every number of 8a.4, 8a.5 and 8a.6.
type InputSpec struct {
	// Tick is the hub's evaluation tick; the vector clock is on it.
	Tick time.Duration
	// HeartbeatEvery and ProbeEvery are how often a Heartbeat and a probe
	// round come in a healthy zone. The evaluator does not use them; the
	// vector generator builds its healthy traffic from them.
	HeartbeatEvery time.Duration
	ProbeEvery     time.Duration

	// HeartbeatStale: hb(X) false, and a Heartbeat that rd reads no longer
	// counted, when the latest Heartbeat is this old. After a hub restart the
	// age counts from the hub's start.
	HeartbeatStale Limit
	// ViewStale: view(X) is none when Y's latest Heartbeat is this old.
	ViewStale Limit
	// ProbeRounds is how many rounds in a row with one result change a probe
	// state; ProbeUnknown makes it unknown when no round has completed for so long.
	ProbeRounds  int
	ProbeUnknown Limit
	// HeadNoticeGrace: fit(X) needs applied_seq at or above every HeadNotice
	// the hub sent more than this long ago.
	HeadNoticeGrace Limit

	// Stable is S(X), StableFlapping while now < dns_flap_until(X).
	Stable         time.Duration
	StableFlapping time.Duration
	// FlapWindow: a withdrawal this soon after a failback is a flap; FlapFor
	// is how long S stays StableFlapping then.
	FlapWindow time.Duration
	FlapFor    time.Duration
	// RefreshEvery is F7's interval after the last signing event.
	RefreshEvery time.Duration
	// RequestMaxAge: a request read when it is older than this is expired.
	RequestMaxAge Limit

	// 8a.5: a node's PeerDown, and PanelStale after silence.
	PeerDownAfter   time.Duration
	PeerUpAfter     time.Duration
	PanelStaleAfter time.Duration

	// The drain rule (8a.6): connections are closed from DrainFrom after the
	// table was applied, spread over DrainSpread; DrainDone is when the node
	// page shows "drain done".
	DrainFrom   time.Duration
	DrainSpread time.Duration
	DrainDone   time.Duration
}

// Inputs returns the thresholds of the inputs.
func Inputs() InputSpec {
	return InputSpec{
		Tick:            time.Second,
		HeartbeatEvery:  5 * time.Second,
		ProbeEvery:      5 * time.Second,
		HeartbeatStale:  Limit{D: 15 * time.Second},
		ViewStale:       Limit{D: 10 * time.Second},
		ProbeRounds:     3,
		ProbeUnknown:    Limit{D: 15 * time.Second},
		HeadNoticeGrace: Limit{D: 30 * time.Second, Strict: true},
		Stable:          300 * time.Second,
		StableFlapping:  1800 * time.Second,
		FlapWindow:      3600 * time.Second,
		FlapFor:         24 * time.Hour,
		RefreshEvery:    10 * time.Minute,
		RequestMaxAge:   Limit{D: 10 * time.Second, Strict: true},
		PeerDownAfter:   90 * time.Second,
		PeerUpAfter:     300 * time.Second,
		PanelStaleAfter: 30 * time.Second,
		DrainFrom:       60 * time.Second,
		DrainSpread:     300 * time.Second,
		DrainDone:       360 * time.Second,
	}
}
