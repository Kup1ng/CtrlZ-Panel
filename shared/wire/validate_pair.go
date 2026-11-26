package wire

import (
	"encoding/binary"
	"errors"

	"google.golang.org/protobuf/proto"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	"github.com/Kup1ng/CtrlZ-Shared/reason"
	"github.com/Kup1ng/CtrlZ-Shared/zone"
)

// LocalUnboundID is the reserved UpstreamHealth.id of a node's local Unbound
// (8a.4): the Max UUID of RFC 9562, all bits set. No upstream row can have it,
// because upstream ids are generated UUIDs, so a Heartbeat can tell the local
// resolver from any configured upstream. A function, not a variable, so no
// importer can change it.
func LocalUnboundID() [16]byte {
	return [16]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
}

// ZoneInput is the field copy of 8a.2: a PairTable as plain input for zone.Build.
// It checks nothing, so Build and ValidatePairTable stay the only judges of a
// table. Revoked is set when spki_sha256 is empty (8a.4, Versions).
//
// Node glue runs it, with zone.Build, on the PairTable of each log entry as part
// of applying it (9.7 items 1 and 4), never on a pushed one: the nodes, addresses,
// slots and revocations, and with them the NS answers and PeerNode trust, come
// from the log alone. From a push the glue takes only the version and the
// withdrawal flags (PushFlags, zone.FlagMap, zone.WithFlags).
func ZoneInput(pt *policyv1.PairTable) zone.BuildInput {
	if pt == nil {
		return zone.BuildInput{}
	}
	in := zone.BuildInput{
		Version: pt.Version,
		Global:  pt.GlobalPairId,
		Nodes:   make([]zone.BuildNode, 0, len(pt.Nodes)),
		Pairs:   make([]zone.BuildPair, 0, len(pt.Pairs)),
	}
	for _, n := range pt.Nodes {
		in.Nodes = append(in.Nodes, zone.BuildNode{
			ID:        n.GetNodeId(),
			DNSIP:     n.GetDnsIp(),
			Slot:      n.GetSlot(),
			Revoked:   len(n.GetSpkiSha256()) == 0,
			Withdrawn: n.GetDnsWithdrawn(),
		})
	}
	for _, p := range pt.Pairs {
		in.Pairs = append(in.Pairs, zone.BuildPair{ID: p.GetPairId(), Primary: p.GetPrimary(), Fallback: p.GetFallback()})
	}
	return in
}

// PushFlags returns the withdrawal flags of a pushed table by node_id, which is
// all a node takes from a push besides its version (8a.4 Node apply, step 3). A
// node_id that is not 16 bytes is skipped: ValidatePairTablePush has refused such
// a table before any caller gets here.
func PushFlags(pt *policyv1.PairTable) map[zone.NodeID]bool {
	out := make(map[zone.NodeID]bool, len(pt.GetNodes()))
	for _, n := range pt.GetNodes() {
		if id := n.GetNodeId(); len(id) == 16 {
			out[zone.NodeID(id)] = n.GetDnsWithdrawn()
		}
	}
	return out
}

// ValidatePairTable checks a PairTable (8a.7). A nil table is valid: an entry
// that carries none changes nothing.
//
// The rules zone.Build repeats are not written twice. The checks of the fields
// Build does not carry (proxy_ip, spki_sha256, the bitmap) run here, and the rest
// run through Build on ZoneInput, so the two cannot disagree and a vector can
// name one error phrase for both. A table is valid when this accepts it and Build
// builds a table from its ZoneInput (8a.4, Valid table).
func ValidatePairTable(p *policyv1.PairTable) error {
	const w = "pair_table"
	if p == nil {
		return nil
	}
	if len(p.Nodes) > MaxNodes || len(p.Pairs) > MaxNodes*MaxNodes {
		return bad(reason.SizeCap, w, "too many nodes or pairs")
	}
	for _, n := range p.Nodes {
		// An empty SPKI is a revoked node (8a.4, Versions); anything else must be
		// a SHA-256.
		if len(n.GetSpkiSha256()) != 0 {
			if err := lenIs(w, "spki_sha256", n.SpkiSha256, 32); err != nil {
				return err
			}
		}
		if _, err := zone.PairAddr("proxy_ip", n.GetProxyIp()); err != nil {
			return buildErr(w, err)
		}
	}
	for _, pr := range p.Pairs {
		if len(pr.GetLocationBitmap()) > MaxBitmapBytes {
			return bad(reason.SizeCap, w, "location_bitmap too large")
		}
	}
	if _, err := zone.Build(ZoneInput(p)); err != nil {
		return buildErr(w, err)
	}
	return nil
}

// buildErr turns a zone error into a wire error with the same phrase.
func buildErr(where string, err error) error {
	var be *zone.BuildError
	if !errors.As(err, &be) {
		return bad(reason.BadSection, where, "%v", err)
	}
	code := reason.BadSection
	switch be.Msg {
	case "too many nodes or pairs":
		code = reason.SizeCap
	case "pair names a node that is not in the table":
		code = reason.IndexRange
	}
	return bad(code, where, "%s: %s", be.Field, be.Msg)
}

// ValidatePairTablePush is ValidatePairTable on a table that must be there: the
// push path never accepts the nil that an entry without a table is allowed.
func ValidatePairTablePush(p *policyv1.PairTable) error {
	if p == nil {
		return bad(reason.BadSection, "pair_table", "missing")
	}
	return ValidatePairTable(p)
}

// ValidatePeerView decodes Heartbeat.peer_view under MaxPeerView and checks it
// (8a.7). Empty bytes are an empty view, as a P0 node sends. At most MaxNodes
// peers, each with a 16-byte node_id no other peer has, down never set while known
// is false, and last_refusal a defined value. The hub reads only the pair peer's
// entry from the stream whose mTLS identity is that peer, so no check of the
// sender is needed here.
func ValidatePeerView(b []byte) (*hubv1.PeerView, error) {
	const w = "peer_view"
	if len(b) > MaxPeerView {
		return nil, bad(reason.SizeCap, w, "%d bytes", len(b))
	}
	v := &hubv1.PeerView{}
	if len(b) == 0 {
		return v, nil
	}
	// Count the peer entries on the wire before decoding: a valid view is about 120
	// bytes, and proto.Unmarshal would allocate a PeerProbe for each of the 32768
	// two-byte entries that fit under MaxPeerView before the count check below.
	if peerEntries(b) > MaxNodes {
		return nil, bad(reason.SizeCap, w, "more than %d peers", MaxNodes)
	}
	if err := proto.Unmarshal(b, v); err != nil {
		return nil, bad(reason.BadSection, w, "not a PeerView: %v", err)
	}
	if len(v.Peers) > MaxNodes {
		return nil, bad(reason.SizeCap, w, "more than %d peers", MaxNodes)
	}
	seen := map[string]bool{}
	for _, p := range v.Peers {
		if err := lenIs(w, "node_id", p.GetNodeId(), 16); err != nil {
			return nil, err
		}
		if seen[string(p.NodeId)] {
			return nil, bad(reason.BadSection, w, "duplicate node_id")
		}
		seen[string(p.NodeId)] = true
		if p.Down && !p.Known {
			return nil, bad(reason.BadSection, w, "down is set while known is false")
		}
	}
	if _, ok := hubv1.PushRefusal_name[int32(v.LastRefusal)]; !ok {
		return nil, bad(reason.BadEnum, w, "last_refusal %d", v.LastRefusal)
	}
	return v, nil
}

// EncodePeerView serializes a PeerView for Heartbeat.peer_view. The node sends
// these bytes and ValidatePeerView reads them, so both ends and the vectors use one
// encoder (deterministic, like MarshalEntry).
func EncodePeerView(v *hubv1.PeerView) ([]byte, error) {
	return proto.MarshalOptions{Deterministic: true}.Marshal(v)
}

// peerEntries counts the field-2 (peers) entries of a serialized PeerView without
// allocating one. It stops counting once the count passes MaxNodes, and at the
// first byte it cannot walk (a group, a bad varint, a length past the end): a
// malformed buffer is left to proto.Unmarshal, which names the error. It uses the
// standard library because shared/ lists its third-party imports (D63) and the
// walk is a few lines.
func peerEntries(b []byte) int {
	n := 0
	for len(b) > 0 {
		tag, tl := binary.Uvarint(b)
		if tl <= 0 {
			return n
		}
		b = b[tl:]
		var skip uint64
		switch tag & 7 {
		case 0: // varint
			_, vl := binary.Uvarint(b)
			if vl <= 0 {
				return n
			}
			skip = uint64(vl)
		case 1: // fixed64
			skip = 8
		case 2: // length-delimited
			l, vl := binary.Uvarint(b)
			if vl <= 0 || l > uint64(len(b)-vl) {
				return n
			}
			skip = uint64(vl) + l
			if tag>>3 == 2 {
				if n++; n > MaxNodes {
					return n
				}
			}
		case 5: // fixed32
			skip = 4
		default: // groups and undefined types
			return n
		}
		if skip > uint64(len(b)) {
			return n
		}
		b = b[skip:]
	}
	return n
}
