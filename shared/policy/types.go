// Package policy is the evaluator: given a query and the compiled profiles of
// the active stack, it decides Block, Bypass or Redirect and builds the
// answer. It is pure (D1): the caller supplies the time, the geo database and
// every DNS lookup, so the same code runs on the node, in Domain Test, in
// More Info and in the filter preview (R45). There is one evaluator and the
// golden vectors pin it.
package policy

import (
	"context"
	"net/netip"

	"github.com/Kup1ng/CtrlZ-Shared/blob"
	"github.com/Kup1ng/CtrlZ-Shared/gtable"
	"github.com/Kup1ng/CtrlZ-Shared/names"
)

// Action, TargetKind: the numbers equal the proto enums and the blob records.
type Action = blob.Action
type TargetKind = blob.TargetKind

const (
	ActionNone     = blob.ActNone
	ActionBlock    = blob.ActBlock
	ActionBypass   = blob.ActBypass
	ActionRedirect = blob.ActRedirect

	TargetNone     = blob.TargetNone
	TargetLocation = blob.TargetLocation
	TargetAuto     = blob.TargetAuto
	TargetRandom   = blob.TargetRandom
	TargetIP       = blob.TargetIP
	TargetHost     = blob.TargetHost
)

// Stage is the level that decided.
type Stage uint8

const (
	StageNone         Stage = 0
	StageRule         Stage = 1
	StageGeo          Stage = 2
	StageService      Stage = 3
	StageFilter       Stage = 4
	StageDefault      Stage = 5
	StageSystem       Stage = 6
	StageSoftDisabled Stage = 7
)

func (s Stage) String() string {
	switch s {
	case StageRule:
		return "rule"
	case StageGeo:
		return "geo"
	case StageService:
		return "service"
	case StageFilter:
		return "filter"
	case StageDefault:
		return "default"
	case StageSystem:
		return "system"
	case StageSoftDisabled:
		return "soft_disabled"
	}
	return "none"
}

// Protocol the query arrived on.
type Protocol uint8

const (
	ProtoUDP Protocol = 1
	ProtoTCP Protocol = 2
	ProtoDoH Protocol = 3
	ProtoDoT Protocol = 4
	ProtoDoQ Protocol = 5
	// ProtoDoH3 is DoH on HTTP/3 (D51). It is a transport of its own: its limits and
	// counters are separate, but a name is decided exactly as over DoH.
	ProtoDoH3 Protocol = 6
)

// Validation is the DNSSEC state of a true answer. Only Unbound sets it.
type Validation uint8

const (
	Indeterminate Validation = 0
	Secure        Validation = 1
	Insecure      Validation = 2
	Bogus         Validation = 3
)

// RefKind says what Ref names.
type RefKind uint8

const (
	RefNone         RefKind = 0
	RefRule         RefKind = 1
	RefService      RefKind = 2
	RefFilter       RefKind = 3
	RefExfiltration RefKind = 4
	RefDefault      RefKind = 5
	RefSystem       RefKind = 6
)

// Ref identifies what decided: a rule id, a service wire id, a filter id, or
// one of the fixed references.
type Ref struct {
	Kind RefKind
	ID   [16]byte // RefRule
	Wire uint32   // RefService (service wire id) and RefFilter (filter id)
}

// Flags annotate a Final.
type Flags uint16

const (
	FlagLocationUnavailable Flags = 1 << iota
	FlagDoNotLog
	FlagViaCNAME
	FlagRebindBlocked
	FlagSafeSearch
	FlagDeferred
)

var flagNames = [...]string{"location_unavailable", "do_not_log", "via_cname", "rebind_blocked", "safe_search", "deferred"}

// Names lists the set flags in declaration order.
func (f Flags) Names() []string {
	out := []string{}
	for i, n := range flagNames {
		if f&(1<<uint(i)) != 0 {
			out = append(out, n)
		}
	}
	return out
}

// DNS constants used by the evaluator.
const (
	TypeA     = 1
	TypeNS    = 2
	TypeCNAME = 5
	TypeSOA   = 6
	TypePTR   = 12
	TypeHINFO = 13
	TypeMX    = 15
	TypeTXT   = 16
	TypeNULL  = 10
	TypeAAAA  = 28
	TypeDS    = 43
	TypeRRSIG = 46
	TypeNSEC  = 47
	TypeNSEC3 = 50
	TypeSVCB  = 64
	TypeHTTPS = 65
	TypeANY   = 255

	ClassIN = 1

	RCodeNoError  = 0
	RCodeServFail = 2
	RCodeNXDomain = 3
	RCodeRefused  = 5
)

// RR is a resource record. Data is the RDATA in wire form with names
// uncompressed, so records can be compared and rewritten without a DNS
// library.
type RR struct {
	Name  names.Name
	Type  uint16
	Class uint16
	TTL   uint32
	Data  []byte
}

// Addr returns the address of an A or AAAA record.
func (r *RR) Addr() (netip.Addr, bool) {
	switch {
	case r.Type == TypeA && len(r.Data) == 4:
		return netip.AddrFrom4([4]byte(r.Data)), true
	case r.Type == TypeAAAA && len(r.Data) == 16:
		return netip.AddrFrom16([16]byte(r.Data)), true
	}
	return netip.Addr{}, false
}

// Input is one query as the evaluator sees it.
type Input struct {
	Name       names.Name
	QType      uint16
	Now        int64 // Unix seconds, supplied by the caller (no clock reads in this module)
	Src        netip.Addr
	SrcCountry [2]byte // zero when unknown
	Protocol   Protocol
	EndpointID [16]byte
	CD, DO, AD bool // from the client query
	Trace      bool // fill Final.Trace for Domain Test and More Info
}

// Stack is the pair of profiles in force for a query and everything derived
// from them that does not depend on the query.
type Stack struct {
	Slots      [2]*blob.Profile // Slots[1] may be nil
	Merged     *blob.Options    // both slots' options merged, first non-null wins
	HasDestGeo bool             // any @, !@ rule in either slot
	Explicit   bool             // any rule, service, filter or exfiltration in either slot
	MaxDepth   uint8
	PairLocs   []uint64 // location bitmap of the Endpoint's pair (R1)

	eff [3]blob.Effective // 0: both active, 1: slot 1 only, 2: slot 2 only
}

// ResolveParams are the inputs that change the true answer, so they are part
// of the cache key (R28).
type ResolveParams struct {
	EffectiveCD bool
	ECS         netip.Prefix
}

// Validation and answer of a true lookup.
type TrueAnswer struct {
	RCode      uint16
	Failed     bool         // SERVFAIL, timeout, or no route
	Chain      []names.Name // qname first, then each CNAME target in order
	Answer     []RR
	Authority  []RR
	Validation Validation
	// ECSScope is the SCOPE PREFIX-LENGTH the upstream returned, echoed back
	// to a client that sent ECS (RFC 7871).
	ECSScope uint8
}

// Resolver is the only door to the outside. Lookups read through the cache;
// nothing the evaluator builds is written back to it.
type Resolver interface {
	Lookup(ctx context.Context, n names.Name, qtype uint16, p ResolveParams) (*TrueAnswer, error)
}

// GeoView answers geography questions about addresses.
type GeoView interface {
	Country(addr netip.Addr) [2]byte // zero when unknown
	ASN(addr netip.Addr) uint32      // zero when unknown
}

// LocationView is the node's live view of its proxy locations.
type LocationView interface {
	// Healthy reports whether this node has a usable config for the location.
	Healthy(wire uint16) bool
	// Auto returns the candidate with the lowest measured latency, with the
	// hysteresis the agent applies. Latency is an input, never computed here.
	Auto(candidates []uint16) (uint16, bool)
}

// SelfAddrs are the addresses of this node and its pair peer.
type SelfAddrs struct {
	DNSIP           netip.Addr
	ProxyIP         netip.Addr
	PeerProxyIP     netip.Addr // zero when there is no peer
	PeerProxyUsable bool       // false when the peer is proxy_blocked or down
}

// Rewrite is the versioned exact-name table behind Safe Search and Restricted
// YouTube (R15). Keys are canonical wire names.
type Rewrite struct {
	SafeSearch map[string]names.Name
	YouTube    map[string]names.Name
}

// Catalog is the set of opened global tables.
type Catalog struct {
	Services *gtable.Table
	// Filters maps (filter_id<<16 | mode_wire) to that mode's table.
	Filters  map[uint32]*gtable.Table
	Category *gtable.Table
	Rewrite  Rewrite
	// Key is the SipHash key shared by every table of this catalog_version.
	Key [16]byte
	// MaxDepth is the deepest name in any table, so a query hashes at most
	// this many suffixes.
	MaxDepth int
}

// Env is everything the evaluator reads that is not the query.
type Env struct {
	Cat  *Catalog
	Geo  GeoView
	Locs LocationView
	Self SelfAddrs
	// NeverProxied reports whether a name is Iranian under D42 (contract 10.5): at or
	// under .ir or .ایران, or on catalog_no_redirect_domain. A Redirect for such a name
	// is a Bypass (T-524). The caller passes the one predicate of the shared module
	// (P2's noredirect.Name over the catalog rows it holds), so the write path and this
	// evaluator cannot disagree about which names are Iranian. policy takes it as a
	// function so it stays free of the catalog and the generated code. A nil function
	// means no name is on the list, which is right only where there is no list (a
	// test), so the node and Domain Test must always set it.
	NeverProxied func(n names.Name) bool
}

// Answer is the response body the node sends.
type Answer struct {
	RCode     uint16
	AD        bool
	Answer    []RR
	Authority []RR
	// ECS is set when the query went upstream with ECS and the client should
	// see it echoed.
	ECS *ECSEcho
}

// ECSEcho is an EDNS Client Subnet option to place in the response.
type ECSEcho struct {
	Source netip.Prefix
	Scope  uint8
}

// TraceStep records one evaluation step for Domain Test and More Info.
type TraceStep struct {
	Level  uint8 // 1 to 5 as in the precedence table; 0 for steps outside the levels
	Stage  Stage
	Slot   uint8
	Hit    bool
	Detail string
}

// PreResult is what Pre decides.
type PreResult struct {
	Done     bool // Final is complete, do not resolve
	Final    Final
	Params   ResolveParams
	Deferred bool // levels 2 to 5 run in Post
	Walk     bool // qname reached level 5, Post runs the CNAME walk
	Opts     *blob.Options
	// SynthOnly: the decision is made but the answer needs the redirect
	// host's records, so Post must run without resolving the qname first.
	SynthOnly bool

	held decision // the decision Post starts from when Walk is set
}

// Final is the outcome.
type Final struct {
	Action     Action
	Stage      Stage
	Ref        Ref
	Slot       uint8 // 1 or 2, 0 if none
	Target     TargetKind
	Location   uint16   // chosen location wire id
	Effective  []uint16 // set Auto or Random drew from, for grant acceptance
	DialHost   names.Name
	WantGrant  bool  // true only when a proxy A answer was synthesized
	Widenable  bool  // false for a wildcard rule match (10.4)
	GrantKind  uint8 // 1 redirect, 2 block page
	Flags      Flags
	HopIndex   uint8 // Chain index of the deciding hop
	TrafficCat uint16
	Answer     Answer // a per-request copy
	Trace      []TraceStep
	// TableMissing is set when a filter or service table the stack needs is
	// not on this node. The node reports it; the lookup counts as no match.
	TableMissing bool
}

// Grant kinds.
const (
	GrantRedirect  uint8 = 1
	GrantBlockPage uint8 = 2
)
