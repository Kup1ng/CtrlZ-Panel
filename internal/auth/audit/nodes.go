package audit

import (
	"net/netip"
	"strings"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/logattr"
)

// The admin events of the node routes (p4-nodes 9.2). They live in a file of their own so that the routes
// of P4 add events without touching the P1 list. None carries a token or a key; the two that give addresses up
// carry the old ones as NodeAddr, an operator's infrastructure address and no client's.
type (
	// NodeEnrollmentCreate records that an enrolment token was made. The token is nowhere: only its hash is stored,
	// in the enrolment row, and Bound says whether it was bound to a source address.
	NodeEnrollmentCreate struct {
		Enrollment uuid.UUID `json:"-"`
		Bound      bool      `json:"bound"`
	}
	// NodeEnrollmentConfirm records that the admin confirmed the fingerprint of a record and the pending node row
	// that followed.
	NodeEnrollmentConfirm struct {
		Enrollment uuid.UUID `json:"-"`
		Node       uuid.UUID `json:"node_id"`
		Slot       int       `json:"slot"`
	}
	// NodeEnrollmentReject records that a token or a pending record was rejected.
	NodeEnrollmentReject struct {
		Enrollment uuid.UUID `json:"-"`
	}
)

func (NodeEnrollmentCreate) Action() string  { return "node_enrollment.create" }
func (NodeEnrollmentConfirm) Action() string { return "node_enrollment.confirm" }
func (NodeEnrollmentReject) Action() string  { return "node_enrollment.reject" }

func (e NodeEnrollmentCreate) Target() string  { return idTarget("node_enrollment", e.Enrollment) }
func (e NodeEnrollmentConfirm) Target() string { return idTarget("node_enrollment", e.Enrollment) }
func (e NodeEnrollmentReject) Target() string  { return idTarget("node_enrollment", e.Enrollment) }

func (NodeEnrollmentCreate) adminEvent()  {}
func (NodeEnrollmentConfirm) adminEvent() {}
func (NodeEnrollmentReject) adminEvent()  {}

// The audit values of the node routes that are not ids or numbers. Each is a closed type (rule
// closed-values-in-logs): a node address and a node name come from the operator, never from a client or a user,
// and each type's grammar cannot spell a phone number or a secret.

// NodeAddr is an address of a node host as the audit row of a removal or an address edit records it, so that
// the nodes page can list the addresses the panel gave up (SC 8a.4). The grammar is an IP address with no zone:
// a phone number, a token or a name does not parse as one. Empty means the node had no such address.
type NodeAddr string

// NodeAddrOf maps the text of an address to its member: the text itself when it is an IP address, else empty. It
// takes text and not an address so that this package never renders an address (the network-cut rule lists the
// few functions that do); the route gets the text from nodeadmin.AddrText.
func NodeAddrOf(s string) NodeAddr {
	if a := NodeAddr(s); a != "" && a.Valid() {
		return a
	}
	return ""
}

// Valid reports membership.
func (a NodeAddr) Valid() bool { return a == "" || nodeAddrGrammar(string(a)) }

// nodeAddrGrammar is an IP address with no zone, at most 45 characters: a phone number, a token or a name does not
// parse as one.
func nodeAddrGrammar(s string) bool {
	if len(s) > 45 || strings.ContainsRune(s, '%') {
		return false
	}
	_, err := netip.ParseAddr(s)
	return err == nil
}

// NodeName is the name an admin gave a node, when it fits a plain grammar: ASCII letters, digits, space, dot,
// underscore and hyphen, 1 to 64 characters, and fewer digits than a phone number has (logattr.FewDigits, the
// one rule of the log grammars). A name outside it is NodeNameInvalid and never a cleaned copy.
type NodeName string

// NodeNameInvalid stands for a node name that is not in the grammar.
const NodeNameInvalid NodeName = "invalid"

// NodeNameOf maps a node name to its member.
func NodeNameOf(s string) NodeName {
	if nodeNameGrammar(s) {
		return NodeName(s)
	}
	return NodeNameInvalid
}

// Valid reports membership.
func (n NodeName) Valid() bool { return n == NodeNameInvalid || nodeNameGrammar(string(n)) }

func nodeNameGrammar(s string) bool {
	if len(s) == 0 || len(s) > 64 || !logattr.FewDigits(s) {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == ' ', c == '.', c == '_', c == '-':
		default:
			return false
		}
	}
	return true
}

// DNSRequestKind is what an admin asked the hub to do with a node's DNS answer (SC 8a.4, Requests).
type DNSRequestKind string

const (
	DNSRequestHold          DNSRequestKind = "hold"
	DNSRequestRelease       DNSRequestKind = "release"
	DNSRequestForceFailback DNSRequestKind = "force_failback"
)

// ParseDNSRequestKind is the one way a text becomes a DNSRequestKind; ok is false for anything that is not a member.
func ParseDNSRequestKind(s string) (DNSRequestKind, bool) {
	k := DNSRequestKind(s)
	return k, k.Valid()
}

// Valid reports membership.
func (k DNSRequestKind) Valid() bool {
	return k == DNSRequestHold || k == DNSRequestRelease || k == DNSRequestForceFailback
}

type (
	// NodeApprove records the move of a node from pending to active.
	NodeApprove struct {
		Node uuid.UUID `json:"-"`
	}
	// NodeRevoke records the move of a node from active to revoked, which is terminal.
	NodeRevoke struct {
		Node uuid.UUID `json:"-"`
	}
	// NodeRemove records the removal of a node row and the addresses it gave up. The old addresses and the name
	// are what GET /nodes/addresses-given-up reads back.
	NodeRemove struct {
		Node       uuid.UUID `json:"-"`
		OldDNSIP   NodeAddr  `json:"old_dns_ip"`
		OldProxyIP NodeAddr  `json:"old_proxy_ip"`
		Name       NodeName  `json:"name"`
	}
	// NodeAddressesChange records an edit of the advertised addresses and the old values it gave up.
	NodeAddressesChange struct {
		Node       uuid.UUID `json:"-"`
		OldDNSIP   NodeAddr  `json:"old_dns_ip"`
		OldProxyIP NodeAddr  `json:"old_proxy_ip"`
		Name       NodeName  `json:"name"`
	}
	// NodeUpdate records an edit of the node form: whether the name changed and the proxy_blocked value after.
	NodeUpdate struct {
		Node         uuid.UUID `json:"-"`
		Renamed      bool      `json:"renamed"`
		ProxyBlocked bool      `json:"proxy_blocked"`
	}
	// NodeDNSRequest records a Hold, Release or Force failback asked of the hub.
	NodeDNSRequest struct {
		Node uuid.UUID      `json:"-"`
		Kind DNSRequestKind `json:"kind"`
	}
	// PairCreate records a new node pair.
	PairCreate struct {
		Pair       uuid.UUID `json:"-"`
		MakeGlobal bool      `json:"make_global"`
	}
	// PairUpdate records a change of the members of a pair.
	PairUpdate struct {
		Pair       uuid.UUID `json:"-"`
		MakeGlobal bool      `json:"make_global"`
	}
	// PairDelete records the dissolution of a pair no Endpoint uses.
	PairDelete struct {
		Pair uuid.UUID `json:"-"`
	}
	// GlobalPairSet records the switch of the global pair.
	GlobalPairSet struct {
		Pair uuid.UUID `json:"-"`
	}
)

func (NodeApprove) Action() string         { return "node.approve" }
func (NodeRevoke) Action() string          { return "node.revoke" }
func (NodeRemove) Action() string          { return "node.remove" }
func (NodeAddressesChange) Action() string { return "node.addresses_change" }
func (NodeUpdate) Action() string          { return "node.update" }
func (NodeDNSRequest) Action() string      { return "node.dns_request" }
func (PairCreate) Action() string          { return "pair.create" }
func (PairUpdate) Action() string          { return "pair.update" }
func (PairDelete) Action() string          { return "pair.delete" }
func (GlobalPairSet) Action() string       { return "settings.global_pair" }

func (e NodeApprove) Target() string         { return idTarget("node", e.Node) }
func (e NodeRevoke) Target() string          { return idTarget("node", e.Node) }
func (e NodeRemove) Target() string          { return idTarget("node", e.Node) }
func (e NodeAddressesChange) Target() string { return idTarget("node", e.Node) }
func (e NodeUpdate) Target() string          { return idTarget("node", e.Node) }
func (e NodeDNSRequest) Target() string      { return idTarget("node", e.Node) }
func (e PairCreate) Target() string          { return idTarget("pair", e.Pair) }
func (e PairUpdate) Target() string          { return idTarget("pair", e.Pair) }
func (e PairDelete) Target() string          { return idTarget("pair", e.Pair) }
func (e GlobalPairSet) Target() string       { return idTarget("pair", e.Pair) }

func (NodeApprove) adminEvent()         {}
func (NodeRevoke) adminEvent()          {}
func (NodeRemove) adminEvent()          {}
func (NodeAddressesChange) adminEvent() {}
func (NodeUpdate) adminEvent()          {}
func (NodeDNSRequest) adminEvent()      {}
func (PairCreate) adminEvent()          {}
func (PairUpdate) adminEvent()          {}
func (PairDelete) adminEvent()          {}
func (GlobalPairSet) adminEvent()       {}
