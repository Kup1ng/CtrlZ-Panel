package vectors

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"testing"

	commonv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/common/v1"
	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	telemetryv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/telemetry/v1"
	"github.com/Kup1ng/CtrlZ-Shared/netclass"
	"github.com/Kup1ng/CtrlZ-Shared/wire"
	"github.com/Kup1ng/CtrlZ-Shared/zone"
)

// WireExpect is the verdict of a wire-validator case: {"ok": true}, or the negative
// shape of section 15, {"error": true, "error_contains": "<text>"}. A negative
// case passes only when the error contains its text, so a case cannot pass for a
// reason other than its own.
type WireExpect struct {
	OK            bool   `json:"ok"`
	Error         bool   `json:"error"`
	ErrorContains string `json:"error_contains"`
}

// wireVerdict compares a validator's error with the case's expectation. It
// returns "" for a pass.
func wireVerdict(e WireExpect, err error) string {
	switch {
	case e.OK == e.Error:
		return "the case must be ok or error, exactly one"
	case e.OK && err != nil:
		return "rejected: " + err.Error()
	case e.OK:
		return ""
	case e.ErrorContains == "":
		return "a negative case without error_contains"
	case err == nil:
		return "accepted, want an error containing " + strconv.Quote(e.ErrorContains)
	case !strings.Contains(err.Error(), e.ErrorContains):
		return "error " + strconv.Quote(err.Error()) + " is for another reason than " + strconv.Quote(e.ErrorContains)
	}
	return ""
}

// ---- pair-table-validate --------------------------------------------------------

// PairValidateCase is one case of pair-table-validate (section 15): op is table
// (wire.ValidatePairTable, and zone.Build on its ZoneInput), push
// (wire.ValidatePairTablePush) or peer_view (wire.ValidatePeerView). build is
// "release" or "lab": a case with a build runs only in a binary of that kind, so
// the same file serves both and each build's refusal of a Private address is
// pinned.
type PairValidateCase struct {
	ID     string          `json:"id"`
	Why    string          `json:"why"`
	Op     string          `json:"op"`
	Input  json.RawMessage `json:"input"`
	Build  string          `json:"build"`
	Expect WireExpect      `json:"expect"`
	// WireOnly marks a case that breaks a field BuildInput does not carry
	// (proxy_ip, spki_sha256, the bitmap), which only the wire validator judges.
	// Every other table case also runs through zone.Build and must agree.
	WireOnly bool `json:"wire_only"`
}

// PairInput is the plain form of a table. Ids are names, turned into 16 bytes by
// vecID. A node's addresses are text, or *_hex when the case needs bytes no
// address prints as. spki is a length in bytes (default 32, 0 is a revoked node).
type PairInput struct {
	Nil     bool        `json:"nil"` // push only: the table is absent
	Version uint64      `json:"version"`
	Global  string      `json:"global"`
	Nodes   []PairNode  `json:"nodes"`
	Pairs   []PairPair  `json:"pairs"`
	Extra   *PairExtras `json:"extra"`
}

// PairExtras generates many nodes or pairs, for the size bound.
type PairExtras struct {
	Nodes int `json:"nodes"`
}

type PairNode struct {
	ID        string `json:"id"`
	DNSIP     string `json:"dns_ip"`
	DNSIPHex  string `json:"dns_ip_hex"`
	ProxyIP   string `json:"proxy_ip"`
	Slot      uint32 `json:"slot"`
	Spki      *int   `json:"spki"`
	Withdrawn bool   `json:"withdrawn"`
}

type PairPair struct {
	ID        string `json:"id"`
	Primary   string `json:"primary"`
	Fallback  string `json:"fallback"`
	BitmapLen int    `json:"bitmap_len"`
}

// PeerViewInput is the plain form of a PeerView, or raw bytes.
type PeerViewInput struct {
	Hex          string      `json:"hex"`
	Zeros        int         `json:"zeros"` // that many zero bytes
	Version      uint64      `json:"pair_table_version"`
	Peers        []PeerProbe `json:"peers"`
	LastRefusal  int32       `json:"last_refusal"`
	Refusals     uint64      `json:"refusals"`
	ShortNodeIDs bool        `json:"short_node_ids"`
}

type PeerProbe struct {
	Node  string `json:"node"`
	Known bool   `json:"known"`
	Down  bool   `json:"down"`
}

// vecID derives the 16-byte id of a named node or pair.
func vecID(name string) []byte {
	h := sha256.Sum256([]byte("vector-pair:" + name))
	return h[:16]
}

func addrBytes(text string) ([]byte, error) {
	if text == "" {
		return nil, nil
	}
	a, err := netip.ParseAddr(text)
	if err != nil {
		return nil, err
	}
	return a.AsSlice(), nil
}

func (in *PairInput) table() (*policyv1.PairTable, error) {
	pt := &policyv1.PairTable{Version: in.Version}
	if in.Global != "" {
		pt.GlobalPairId = vecID(in.Global)
	}
	for _, n := range in.Nodes {
		ne := &policyv1.NodeEntry{NodeId: vecID(n.ID), Slot: n.Slot, DnsWithdrawn: n.Withdrawn}
		var err error
		if n.DNSIPHex != "" {
			if ne.DnsIp, err = hex.DecodeString(n.DNSIPHex); err != nil {
				return nil, err
			}
		} else if ne.DnsIp, err = addrBytes(n.DNSIP); err != nil {
			return nil, err
		}
		if ne.ProxyIp, err = addrBytes(n.ProxyIP); err != nil {
			return nil, err
		}
		spki := 32
		if n.Spki != nil {
			spki = *n.Spki
		}
		if spki > 0 {
			ne.SpkiSha256 = make([]byte, spki)
			ne.SpkiSha256[0] = 1
		}
		pt.Nodes = append(pt.Nodes, ne)
	}
	for _, p := range in.Pairs {
		pe := &policyv1.Pair{PairId: vecID(p.ID), Primary: vecID(p.Primary)}
		if p.Fallback != "" {
			pe.Fallback = vecID(p.Fallback)
		}
		if p.BitmapLen > 0 {
			pe.LocationBitmap = make([]byte, p.BitmapLen)
		}
		pt.Pairs = append(pt.Pairs, pe)
	}
	return pt, nil
}

func (in *PeerViewInput) bytes() ([]byte, error) {
	if in.Hex != "" {
		return hex.DecodeString(in.Hex)
	}
	if in.Zeros > 0 {
		return make([]byte, in.Zeros), nil
	}
	v := &hubv1.PeerView{PairTableVersion: in.Version, LastRefusal: hubv1.PushRefusal(in.LastRefusal), Refusals: in.Refusals}
	for _, p := range in.Peers {
		id := vecID(p.Node)
		if in.ShortNodeIDs {
			id = id[:3]
		}
		v.Peers = append(v.Peers, &hubv1.PeerProbe{NodeId: id, Known: p.Known, Down: p.Down})
	}
	return wire.EncodePeerView(v)
}

func runPairTableValidateGroup(t *testing.T, g *GroupFile) {
	var cases []PairValidateCase
	if err := decodeStrict(g.Cases, &cases); err != nil {
		t.Fatalf("%s: %v", g.Group, err)
	}
	for _, c := range cases {
		t.Run(c.ID, func(t *testing.T) {
			switch c.Build {
			case "":
			case "release", "lab":
				if lab := netclass.AllowPrivatePairAddrs; (c.Build == "lab") != lab {
					t.Skipf("a %s case, and this is not a %s build", c.Build, c.Build)
				}
			default:
				t.Fatalf("build %q", c.Build)
			}
			if msg := runPairValidate(&c); msg != "" {
				t.Errorf("%s: %s\n  case: %s", c.ID, msg, c.Why)
			}
		})
	}
}

func runPairValidate(c *PairValidateCase) string {
	switch c.Op {
	case "table", "push":
		var in PairInput
		if err := decodeStrict(c.Input, &in); err != nil {
			return "input: " + err.Error()
		}
		var pt *policyv1.PairTable
		if !in.Nil {
			var err error
			if pt, err = in.table(); err != nil {
				return "input: " + err.Error()
			}
			if in.Extra != nil {
				for i := 0; i < in.Extra.Nodes; i++ {
					pt.Nodes = append(pt.Nodes, &policyv1.NodeEntry{NodeId: vecID("extra" + strconv.Itoa(i)), Slot: 1})
				}
			}
		}
		var err error
		if c.Op == "push" {
			err = wire.ValidatePairTablePush(pt)
		} else {
			err = wire.ValidatePairTable(pt)
		}
		if msg := wireVerdict(c.Expect, err); msg != "" {
			return "wire: " + msg
		}
		if c.Op != "table" || c.WireOnly || pt == nil {
			return ""
		}
		// One vector through both validators: zone.Build refuses what
		// ValidatePairTable refuses (8a.10), with the same phrase.
		_, berr := zone.Build(wire.ZoneInput(pt))
		if msg := wireVerdict(c.Expect, berr); msg != "" {
			return "zone.Build: " + msg
		}
	case "peer_view":
		var in PeerViewInput
		if err := decodeStrict(c.Input, &in); err != nil {
			return "input: " + err.Error()
		}
		raw, err := in.bytes()
		if err != nil {
			return "input: " + err.Error()
		}
		_, err = wire.ValidatePeerView(raw)
		return wireVerdict(c.Expect, err)
	default:
		return "unknown vector op " + strconv.Quote(c.Op)
	}
	return ""
}

// ---- telemetry-validate ---------------------------------------------------------

// TelemetryValidateCase is one case of telemetry-validate: op is activity
// (wire.ValidateActivityBatch) or free_counters (wire.ValidateFreeCounters).
// Times are
// seconds relative to now, which is a multiple of 300.
type TelemetryValidateCase struct {
	ID     string          `json:"id"`
	Why    string          `json:"why"`
	Op     string          `json:"op"`
	Input  json.RawMessage `json:"input"`
	Expect WireExpect      `json:"expect"`
}

const telemetryNow = 1_800_000_000

// ActivityInput lists entries. claim_len and hash_len are byte lengths, 0 for the
// field being absent: the three forms of an entry are claim only, hash only and
// neither (p4-nodes 7.6), and both is refused.
type ActivityInput struct {
	Entries []ActivityEntryInput `json:"entries"`
}

type ActivityEntryInput struct {
	ClaimLen int    `json:"claim_len"`
	HashLen  int    `json:"hash_len"`
	Label    string `json:"label"`
	Protocol string `json:"protocol"`
	First    int64  `json:"first"`
	Last     int64  `json:"last"`
}

// FreeInput is a CountersBatch with a free part.
type FreeInput struct {
	Bucket   int64      `json:"bucket"`
	Counters int        `json:"counters"` // plain counters in the batch
	Free     []FreeItem `json:"free"`
	Repeat   int        `json:"repeat"` // add this many items, each with another rcode and outcome
}

type FreeItem struct {
	Protocol string `json:"protocol"`
	Outcome  string `json:"outcome"`
	Rcode    uint32 `json:"rcode"`
	Count    string `json:"count"`
}

func protocolEnum(s string) (commonv1.Protocol, error) {
	v, ok := commonv1.Protocol_value["PROTOCOL_"+strings.ToUpper(s)]
	if !ok {
		return 0, fmt.Errorf("protocol %q", s)
	}
	return commonv1.Protocol(v), nil
}

func (in *ActivityInput) batch() (*telemetryv1.ActivityBatch, error) {
	b := &telemetryv1.ActivityBatch{}
	for _, e := range in.Entries {
		p, err := protocolEnum(e.Protocol)
		if err != nil {
			return nil, err
		}
		b.Entries = append(b.Entries, &telemetryv1.ActivityEntry{
			EndpointId: vecID("endpoint"), ClientLabel: e.Label, Protocol: p,
			ClaimId: make([]byte, e.ClaimLen), SourceIpHash: make([]byte, e.HashLen),
			FirstSeenBucket: telemetryNow + e.First, LastSeenBucket: telemetryNow + e.Last,
		})
	}
	return b, nil
}

func (in *FreeInput) batch() (*telemetryv1.CountersBatch, error) {
	b := &telemetryv1.CountersBatch{BatchId: 1, BucketStart: telemetryNow + in.Bucket}
	for i := 0; i < in.Counters; i++ {
		b.Counters = append(b.Counters, &telemetryv1.Counter{EndpointId: vecID("endpoint"), Protocol: commonv1.Protocol_PROTOCOL_UDP, Action: commonv1.Action_ACTION_BLOCK, Count: 1})
	}
	for _, f := range in.Free {
		p, err := protocolEnum(f.Protocol)
		if err != nil {
			return nil, err
		}
		o, ok := telemetryv1.FreeOutcome_value["FREE_OUTCOME_"+strings.ToUpper(f.Outcome)]
		if !ok {
			return nil, fmt.Errorf("outcome %q", f.Outcome)
		}
		n, err := strconv.ParseUint(f.Count, 10, 64)
		if err != nil {
			return nil, err
		}
		b.Free = append(b.Free, &telemetryv1.FreeCounter{Protocol: p, Outcome: telemetryv1.FreeOutcome(o), Rcode: f.Rcode, Count: n})
	}
	for i := 0; i < in.Repeat; i++ {
		// 14 outcomes x 24 rcodes per protocol; udp first, then tcp.
		p := commonv1.Protocol_PROTOCOL_UDP
		if i >= 14*24 {
			p = commonv1.Protocol_PROTOCOL_TCP
		}
		b.Free = append(b.Free, &telemetryv1.FreeCounter{
			Protocol: p, Outcome: telemetryv1.FreeOutcome(1 + (i/24)%14), Rcode: uint32(i % 24), Count: 1})
	}
	return b, nil
}

func runTelemetryValidateGroup(t *testing.T, g *GroupFile) {
	var cases []TelemetryValidateCase
	if err := decodeStrict(g.Cases, &cases); err != nil {
		t.Fatalf("%s: %v", g.Group, err)
	}
	for _, c := range cases {
		t.Run(c.ID, func(t *testing.T) {
			if msg := runTelemetryValidate(&c); msg != "" {
				t.Errorf("%s: %s\n  case: %s", c.ID, msg, c.Why)
			}
		})
	}
}

func runTelemetryValidate(c *TelemetryValidateCase) string {
	switch c.Op {
	case "activity":
		var in ActivityInput
		if err := decodeStrict(c.Input, &in); err != nil {
			return "input: " + err.Error()
		}
		b, err := in.batch()
		if err != nil {
			return "input: " + err.Error()
		}
		return wireVerdict(c.Expect, wire.ValidateActivityBatch(b, telemetryNow))
	case "free_counters":
		var in FreeInput
		if err := decodeStrict(c.Input, &in); err != nil {
			return "input: " + err.Error()
		}
		b, err := in.batch()
		if err != nil {
			return "input: " + err.Error()
		}
		return wireVerdict(c.Expect, wire.ValidateFreeCounters(b, telemetryNow))
	default:
		return "unknown vector op " + strconv.Quote(c.Op)
	}
}
