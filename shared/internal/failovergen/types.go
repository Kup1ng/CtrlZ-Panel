package failovergen

// The JSON shape of the zone-failover group (contract 15). The generator
// defines its own copy of the types on purpose: it shares no code with the
// runner in vectors, which decodes the file strictly, so a drift in a field
// name or a type fails the vectors' tests instead of passing on both sides.
// (vectors, which takes a *testing.T, may be imported by test files only.)

// Columns are the failover columns of a node, in milliseconds from the case
// start (null for none).
type Columns struct {
	Withdrawn      bool   `json:"withdrawn"`
	Hold           bool   `json:"hold"`
	LastFailbackAt *int64 `json:"last_failback_at"`
	FlapUntil      *int64 `json:"flap_until"`
}

// Pair is a pair of a membership, by node names.
type Pair struct {
	ID       string `json:"id"`
	Primary  string `json:"primary"`
	Fallback string `json:"fallback"`
}

// Membership is a membership: pairs, the global pair and the revoked nodes,
// and in an event the nodes of the table.
type Membership struct {
	Nodes   []string `json:"nodes,omitempty"`
	Pairs   []Pair   `json:"pairs"`
	Global  string   `json:"global"`
	Revoked []string `json:"revoked,omitempty"`
}

// Start is the state of the hub at the start of a case.
type Start struct {
	Nodes      map[string]Columns `json:"nodes"`
	Membership Membership         `json:"membership"`
}

// Upstream is one entry of Heartbeat.upstreams.
type Upstream struct {
	ID      string `json:"id"`
	Healthy bool   `json:"healthy"`
}

// PeerEntry is one entry of a PeerView.
type PeerEntry struct {
	Node  string `json:"node"`
	Known bool   `json:"known"`
	Down  bool   `json:"down"`
}

// PeerView is a Heartbeat's PeerView.
type PeerView struct {
	PairTableVersion uint64      `json:"pair_table_version"`
	Peers            []PeerEntry `json:"peers"`
}

// Event is something that happens to the hub.
type Event struct {
	At   int64  `json:"at"`
	Kind string `json:"kind"`
	Node string `json:"node,omitempty"`

	AppliedSeq uint64     `json:"applied_seq,omitempty"`
	Isolated   bool       `json:"isolated,omitempty"`
	Upstreams  []Upstream `json:"upstreams,omitempty"`
	PeerView   *PeerView  `json:"peer_view,omitempty"`

	DoT string `json:"dot,omitempty"`
	DoH string `json:"doh,omitempty"`

	Seq uint64 `json:"seq,omitempty"`

	Membership *Membership `json:"membership,omitempty"`

	ID          string `json:"id,omitempty"`
	Op          string `json:"op,omitempty"`
	RequestedAt *int64 `json:"requested_at,omitempty"`
}

// Expect is one thing the evaluator must emit, in order.
type Expect struct {
	At   int64  `json:"at"`
	Kind string `json:"kind"`

	Row   string             `json:"row,omitempty"`
	Nodes map[string]Columns `json:"nodes,omitempty"`
	S     map[string]int64   `json:"s,omitempty"`

	ID     string `json:"id,omitempty"`
	Result string `json:"result,omitempty"`
	Reason string `json:"reason,omitempty"`

	Alert  string `json:"alert,omitempty"`
	Node   string `json:"node,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// Case is one case of the group.
type Case struct {
	ID     string   `json:"id"`
	Why    string   `json:"why"`
	Row    string   `json:"row"`
	Start  Start    `json:"start"`
	Events []Event  `json:"events"`
	End    int64    `json:"end"`
	Expect []Expect `json:"expect"`
}
