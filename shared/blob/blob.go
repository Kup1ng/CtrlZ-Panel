// Package blob builds, validates and reads CZPB profile blobs (contract 9.2,
// 9.3).
//
// A blob is the compiled form of one profile. The panel builds it, the node
// maps it and reads it with Open's guarantees. Open does every bounds check up
// front, so the readers below can use plain slices and indexes without
// re-checking, and a logic error elsewhere is a recovered panic, never a
// memory fault.
package blob

import (
	"crypto/sha256"
	"encoding/binary"
	"sort"

	"github.com/Kup1ng/CtrlZ-Shared/names"
	"github.com/Kup1ng/CtrlZ-Shared/rules"
)

var le = binary.LittleEndian

const (
	Magic     = "CZPB"
	Major     = 1
	Minor     = 0
	HeaderLen = 48
	// MaxSize is the profile blob cap from the contract (64 MiB).
	MaxSize = 64 << 20
	// MaxBucket bounds one wildcard bucket so a query's worst case is fixed
	// (provisional until the P4 load test, D31).
	MaxBucket = 64

	// MaxPlainRun bounds the plain rules whose names share one 64-bit hash. A
	// hash collision between two different names is possible but vanishingly
	// rare; a long run is a crafted blob, so Open refuses it.
	MaxPlainRun = 8
	// NoTarget is the "no target" value in RULE, SVCS and DFLT records.
	NoTarget = 0xFFFFFFFF
	maxSecs  = 32
)

// Section ids.
const (
	SecOPTS = 1
	SecDFLT = 2
	SecTARG = 3
	SecLSET = 4
	SecSTRS = 5
	SecRULE = 6
	SecPLIX = 7
	SecWBKT = 8
	SecWILD = 9
	SecGEOR = 10
	SecSVCS = 11
	SecFLTS = 12
	numSecs = 13
)

// Record sizes. 0 marks a byte pool.
const (
	sizeOPTS = OptsSize
	sizeDFLT = 8
	sizeTARG = 40
	sizeRULE = 40
	sizePLIX = 16
	sizeWBKT = 16
	sizeWILD = 8
	sizeGEOR = 16
	sizeSVCS = 16
	sizeFLTS = 4
)

func recSize(id int) int {
	switch id {
	case SecOPTS:
		return sizeOPTS
	case SecDFLT:
		return sizeDFLT
	case SecTARG:
		return sizeTARG
	case SecRULE:
		return sizeRULE
	case SecPLIX:
		return sizePLIX
	case SecWBKT:
		return sizeWBKT
	case SecWILD:
		return sizeWILD
	case SecGEOR:
		return sizeGEOR
	case SecSVCS:
		return sizeSVCS
	case SecFLTS:
		return sizeFLTS
	}
	return 0 // LSET and STRS are pools
}

func secName(id int) string {
	n := [...]string{"", "OPTS", "DFLT", "TARG", "LSET", "STRS", "RULE", "PLIX", "WBKT", "WILD", "GEOR", "SVCS", "FLTS"}
	if id >= 0 && id < len(n) {
		return n[id]
	}
	return "unknown"
}

// Header flags.
const (
	FlagHasDestGeo = 1 << 0
	FlagExplicit   = 1 << 1
)

// RULE flags.
const (
	RuleDoNotLog            = 1 << 0
	RuleLocationUnavailable = 1 << 1
)

// Header is the decoded file header.
type Header struct {
	Major, Minor  uint16
	SectionCount  uint32
	TotalLen      uint64
	RuleCount     uint32
	WildCount     uint32
	MaxLabels     uint8
	Flags         uint8
	DisabledUntil int64
}

// HasDestGeo reports whether any @ or !@ rule exists.
func (h Header) HasDestGeo() bool { return h.Flags&FlagHasDestGeo != 0 }

// Explicit reports whether any rule, service, filter or exfiltration exists.
func (h Header) Explicit() bool { return h.Flags&FlagExplicit != 0 }

// Rule is one decoded RULE record.
type Rule struct {
	ID        [16]byte
	ExpiresAt int64
	NameOff   uint32
	NameLen   uint16
	Kind      rules.Kind
	Action    Action
	Flags     uint8
	Target    uint32
}

// Expired reports whether the rule has lapsed at now. 0 means it never does.
func (r *Rule) Expired(now int64) bool { return r.ExpiresAt != 0 && now >= r.ExpiresAt }

// Wild is one decoded WILD record.
type Wild struct {
	Rule     uint32
	Kind     rules.Kind // KindSubdomains or KindGlob
	Labels   uint8
	LitBytes uint16
}

// Geo is one decoded GEOR record, in level-2 order.
type Geo struct {
	Class   uint8 // 0 dest_as, 1 dest_cc, 2 src_cc
	Negated bool
	CC      [2]byte
	ASN     uint32
	Rule    uint32
}

// Service is one decoded SVCS record.
type Service struct {
	Wire   uint32
	Action Action
	Flags  uint8
	Target uint32
}

// Target is one decoded TARG record.
type Target struct {
	Kind     TargetKind
	HasV4    bool
	HasV6    bool
	Location uint16
	SetOff   uint32
	HostOff  uint32
	HostLen  uint16
	V4       [4]byte
	V6       [16]byte
}

// Profile is a validated blob. It is read-only and safe for concurrent use.
type Profile struct {
	data []byte
	hdr  Header
	sec  [numSecs][]byte
	opts Options
	dflt Action
	dtgt uint32
	hash [32]byte
}

// Hash returns the SHA-256 of the whole blob, its content address.
func (p *Profile) Hash() [32]byte { return p.hash }

// Bytes returns the blob data. Callers must not modify it.
func (p *Profile) Bytes() []byte { return p.data }

// Header returns the decoded header.
func (p *Profile) Header() Header { return p.hdr }

// Options returns the profile's nullable options.
func (p *Profile) Options() *Options { return &p.opts }

// DisabledUntil is the Unix time until which the profile is disabled, 0 for never.
func (p *Profile) DisabledUntil() int64 { return p.hdr.DisabledUntil }

// Active reports whether the profile is in force at now (5.3). Evaluated at
// query time so a Disable that lapses during a panel outage still ends on time.
func (p *Profile) Active(now int64) bool { return now >= p.hdr.DisabledUntil }

// Default returns the Default Rule action (ActNone when null) and its target.
func (p *Profile) Default() (Action, uint32) { return p.dflt, p.dtgt }

// RuleCount is the number of RULE records.
func (p *Profile) RuleCount() int { return len(p.sec[SecRULE]) / sizeRULE }

// Rule decodes RULE record i. i must be below RuleCount.
func (p *Profile) Rule(i int) Rule {
	b := p.sec[SecRULE][i*sizeRULE:]
	var r Rule
	copy(r.ID[:], b[0:16])
	r.ExpiresAt = int64(le.Uint64(b[16:]))
	r.NameOff = le.Uint32(b[24:])
	r.NameLen = le.Uint16(b[28:])
	r.Kind = rules.Kind(b[30])
	r.Action = Action(b[31])
	r.Flags = b[32]
	r.Target = le.Uint32(b[36:])
	return r
}

// Str returns bytes of the string pool.
func (p *Profile) Str(off uint32, n uint16) []byte {
	return p.sec[SecSTRS][off : uint32(off)+uint32(n)]
}

// RuleName returns the wire pattern stored for a name-kind rule.
func (p *Profile) RuleName(r *Rule) []byte { return p.Str(r.NameOff, r.NameLen) }

// TargetCount is the number of TARG records.
func (p *Profile) TargetCount() int { return len(p.sec[SecTARG]) / sizeTARG }

// Target decodes TARG record i, which must be below TargetCount.
func (p *Profile) Target(i uint32) Target {
	b := p.sec[SecTARG][int(i)*sizeTARG:]
	var t Target
	t.Kind = TargetKind(b[0])
	t.HasV4 = b[1]&1 != 0
	t.HasV6 = b[1]&2 != 0
	t.Location = le.Uint16(b[2:])
	t.SetOff = le.Uint32(b[4:])
	t.HostOff = le.Uint32(b[8:])
	t.HostLen = le.Uint16(b[12:])
	copy(t.V4[:], b[16:20])
	copy(t.V6[:], b[20:36])
	return t
}

// LocSet returns the location wire ids of the set at off.
func (p *Profile) LocSet(off uint32) []uint16 {
	b := p.sec[SecLSET][off:]
	n := int(le.Uint16(b))
	out := make([]uint16, n)
	for i := range out {
		out[i] = le.Uint16(b[2+2*i:])
	}
	return out
}

// PlainRules calls yield with the index of every domain rule whose stored hash
// equals h, in rule order, until yield returns false. A hash match is only a
// candidate: the caller confirms by comparing wire bytes.
func (p *Profile) PlainRules(h uint64, yield func(rule int) bool) {
	b := p.sec[SecPLIX]
	n := len(b) / sizePLIX
	i := sort.Search(n, func(i int) bool { return le.Uint64(b[i*sizePLIX:]) >= h })
	for ; i < n && le.Uint64(b[i*sizePLIX:]) == h; i++ {
		if !yield(int(le.Uint32(b[i*sizePLIX+8:]))) {
			return
		}
	}
}

// WildBucket finds the WILD range for a literal-suffix hash.
func (p *Profile) WildBucket(h uint64) (first, count int, ok bool) {
	b := p.sec[SecWBKT]
	n := len(b) / sizeWBKT
	i := sort.Search(n, func(i int) bool { return le.Uint64(b[i*sizeWBKT:]) >= h })
	if i < n && le.Uint64(b[i*sizeWBKT:]) == h {
		return int(le.Uint32(b[i*sizeWBKT+8:])), int(le.Uint32(b[i*sizeWBKT+12:])), true
	}
	return 0, 0, false
}

// Wild decodes WILD record i.
func (p *Profile) Wild(i int) Wild {
	b := p.sec[SecWILD][i*sizeWILD:]
	return Wild{Rule: le.Uint32(b[0:]), Kind: rules.Kind(b[4]), Labels: b[5], LitBytes: le.Uint16(b[6:])}
}

// GeoCount is the number of GEOR records.
func (p *Profile) GeoCount() int { return len(p.sec[SecGEOR]) / sizeGEOR }

// Geo decodes GEOR record i (level-2 order).
func (p *Profile) Geo(i int) Geo {
	b := p.sec[SecGEOR][i*sizeGEOR:]
	return Geo{Class: b[0], Negated: b[1] != 0, CC: [2]byte{b[2], b[3]}, ASN: le.Uint32(b[4:]), Rule: le.Uint32(b[8:])}
}

// ServiceCount is the number of enabled services.
func (p *Profile) ServiceCount() int { return len(p.sec[SecSVCS]) / sizeSVCS }

func (p *Profile) service(i int) Service {
	b := p.sec[SecSVCS][i*sizeSVCS:]
	return Service{Wire: le.Uint32(b[0:]), Action: Action(b[4]), Flags: b[5], Target: le.Uint32(b[8:])}
}

// Service looks a catalog service up by wire id. Absent means the service is
// not enabled in this profile, which is different from enabled with Bypass.
func (p *Profile) Service(wire uint32) (Service, bool) {
	n := p.ServiceCount()
	i := sort.Search(n, func(i int) bool { return le.Uint32(p.sec[SecSVCS][i*sizeSVCS:]) >= wire })
	if i < n {
		if s := p.service(i); s.Wire == wire {
			return s, true
		}
	}
	return Service{}, false
}

// FilterCount is the number of enabled filters.
func (p *Profile) FilterCount() int { return len(p.sec[SecFLTS]) / sizeFLTS }

// Filter returns filter i as (filter_id, mode_wire), ascending by filter_id.
func (p *Profile) Filter(i int) (id, mode uint16) {
	b := p.sec[SecFLTS][i*sizeFLTS:]
	return le.Uint16(b[0:]), le.Uint16(b[2:])
}

// LiteralSuffixOf returns the wire suffix a wildcard rule is indexed by.
func (p *Profile) LiteralSuffixOf(r *Rule) []byte {
	pat := rules.Pattern{Kind: r.Kind, Wire: p.RuleName(r)}
	return pat.LiteralSuffix()
}

// Wildcard matching helpers shared by the reader and the evaluator.

// WildMatches reports whether wildcard rule r matches name n, given that the
// caller already probed the bucket of r's literal suffix. It confirms the
// literal suffix by bytes (a hash hit proves nothing), then applies the
// kind's rule: subdomains need the name to be strictly longer than the suffix;
// glob needs an equal label count and a label-by-label match where '*' covers
// zero or more bytes inside its one label (or exactly one whole label when it
// is the entire label).
func WildMatches(kind rules.Kind, pattern []byte, n *names.Name) bool {
	switch kind {
	case rules.KindSubdomains:
		pn, err := names.FromCanonicalWire(pattern)
		if err != nil || n.Labels() <= pn.Labels() {
			return false
		}
		return string(n.SuffixWire(pn.Labels())) == string(pattern)
	case rules.KindGlob:
		pn, err := names.FromCanonicalWire(pattern)
		if err != nil || n.Labels() != pn.Labels() {
			return false
		}
		for i := 0; i < pn.Labels(); i++ {
			if !globLabel(pn.Label(i), n.Label(i)) {
				return false
			}
		}
		return true
	}
	return false
}

// globLabel matches one label against a pattern label holding at most one '*'.
// An exact "*" is a whole label wildcard and must match at least one byte
// (labels are never empty); inside a longer label it covers zero or more bytes.
func globLabel(pat, lbl []byte) bool {
	star := -1
	for i, c := range pat {
		if c == '*' {
			star = i
			break
		}
	}
	if star < 0 {
		return string(pat) == string(lbl)
	}
	pre, post := pat[:star], pat[star+1:]
	if len(lbl) < len(pre)+len(post) {
		return false
	}
	return string(lbl[:len(pre)]) == string(pre) && string(lbl[len(lbl)-len(post):]) == string(post)
}

func contentHash(data []byte) [32]byte { return sha256.Sum256(data) }
