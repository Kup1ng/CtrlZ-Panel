package nodeadmin

import (
	"encoding/json"
	"errors"
	"slices"
	"sync"

	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// The checks of the routes that change membership (p4-nodes 4.5, 9.2). Like the rest of this package they take rows
// and bytes in and give a verdict back: the store reads, the route decides what to do with the verdict.

// SecondPeer says whether a pair of primary and fallback would give a node a second peer. It is the rule of the
// constraint trigger node_pairs_one_peer (migration 0100) and of wire.ValidatePairTable, read in Go so that the
// route can answer second_peer by name instead of with the generic refusal of a deferred trigger at commit. self
// is the pair being changed (the nil uuid for a new one), whose own row does not count.
//
// (A, B) beside (B, A) is accepted, and (A, B) beside (A, C) is not.
func SecondPeer(pairs []store.MemberPair, self, primary, fallback uuid.UUID) bool {
	for _, p := range pairs {
		if p.ID == self {
			continue
		}
		for _, mine := range []uuid.UUID{primary, fallback} {
			other := fallback
			if mine == fallback {
				other = primary
			}
			// p holds `mine` and its peer in p is not the peer this pair gives it.
			switch mine {
			case p.Primary:
				if p.Fallback != other {
					return true
				}
			case p.Fallback:
				if p.Primary != other {
					return true
				}
			}
		}
	}
	return false
}

// ErrTableDecode is a stored table that does not parse. A removal that cannot read a table does not guess: it is
// refused with an internal error, which is loud, and the admin's next step is the runbook and not a retry.
var ErrTableDecode = errors.New("nodeadmin: a stored pair table does not parse")

// pairsNode says whether a node is in a pair of a table.
func pairsNode(pt *policyv1.PairTable, node uuid.UUID) bool {
	for _, p := range pt.GetPairs() {
		if string(p.GetPrimary()) == string(node[:]) || string(p.GetFallback()) == string(node[:]) {
			return true
		}
	}
	return false
}

// pairTableField is the field number of ConfigEntry.pair_table, read from the descriptor so that a renumbering of
// the proto cannot leave this file reading another field.
var pairTableField = sync.OnceValue(func() protowire.Number {
	return protowire.Number((&policyv1.ConfigEntry{}).ProtoReflect().Descriptor().Fields().ByName("pair_table").Number())
})

// EntryPairTable returns the bytes of the PairTable a stored config_log entry carries and whether it carries one.
// An entry carries a table only when the membership changed (wire.ValidatePairTable: an entry that carries none
// changes nothing), which is why the table the log last carried is not always in the newest entry.
//
// It walks the top-level fields and never decodes the entry: one entry may hold up to about 15 MiB of records
// (p4-nodes 6.1), and decoding it builds a hundred thousand objects in an admin container that has 128 MiB, so a
// removal during a compromise could take the console down. A field that repeats is merged by the wire rules, which
// for a message is the concatenation of its bytes.
func EntryPairTable(entry []byte) (table []byte, found bool, err error) {
	for len(entry) > 0 {
		num, typ, n := protowire.ConsumeTag(entry)
		if n < 0 {
			return nil, false, ErrTableDecode
		}
		entry = entry[n:]
		if num == pairTableField() && typ == protowire.BytesType {
			v, n := protowire.ConsumeBytes(entry)
			if n < 0 {
				return nil, false, ErrTableDecode
			}
			table = append(table, v...)
			found = true
			entry = entry[n:]
			continue
		}
		n = protowire.ConsumeFieldValue(num, typ, entry)
		if n < 0 {
			return nil, false, ErrTableDecode
		}
		entry = entry[n:]
	}
	return table, found, nil
}

// InSomeTable says whether the last table the log carried, or the table of the hub's last signing event, pairs the
// node (SC 8a.4 Membership: a removal waits until neither does, so row F0 has decided the node as a leaving one).
//
// logTable is the PairTable of the newest config_log entry that carries one (EntryPairTable; nil when none does) and
// lastTable the bytes the hub wrote to pair_event_state.last_table (nil before its first event): a serialised
// PairTable, which the hub writes in the transaction of the event before it signs those same bytes.
func InSomeTable(logTable, lastTable []byte, node uuid.UUID) (bool, error) {
	if len(logTable) > 0 {
		var pt policyv1.PairTable
		if err := proto.Unmarshal(logTable, &pt); err != nil {
			return false, ErrTableDecode
		}
		if pairsNode(&pt, node) {
			return true, nil
		}
	}
	if len(lastTable) > 0 {
		var pt policyv1.PairTable
		if err := proto.Unmarshal(lastTable, &pt); err != nil {
			return false, ErrTableDecode
		}
		if pairsNode(&pt, node) {
			return true, nil
		}
	}
	return false, nil
}

// MaxRevokedNodeIDs bounds the node_ids of a node_revoked job. Four slots exist (D25), so a chain of superseded
// revocations that grows past this is a defect, and the list stops growing instead of the row: the revocation itself is
// never refused for it (the answer to a compromise is not held back by the state of other rows).
const MaxRevokedNodeIDs = 64

// RevokedJobParams builds the params of the node_revoked job a revocation queues: this node plus the node_ids of the
// jobs it supersedes (p4-nodes 8), so a job that never finished loses nothing to the newer one. The result is sorted
// and unique, which makes the same set the same bytes.
//
// Past MaxRevokedNodeIDs the carried list is cut, never the revocation: this node always stays, the others are kept in id
// order, and dropped says how many ids lost their clean-up so the caller can log it.
func RevokedJobParams(node uuid.UUID, superseded [][]byte) (params []byte, dropped int, err error) {
	self := node.String()
	var others []string
	for _, raw := range superseded {
		var p struct {
			NodeIDs []string `json:"node_ids"`
		}
		if json.Unmarshal(raw, &p) != nil {
			continue
		}
		for _, s := range p.NodeIDs {
			if id, err := uuid.Parse(s); err == nil && id.String() != self {
				others = append(others, id.String())
			}
		}
	}
	slices.Sort(others)
	others = slices.Compact(others)
	if len(others) > MaxRevokedNodeIDs-1 {
		dropped = len(others) - (MaxRevokedNodeIDs - 1)
		others = others[:MaxRevokedNodeIDs-1]
	}
	ids := append([]string{self}, others...)
	slices.Sort(ids)
	params, err = json.Marshal(map[string]any{"node_ids": ids})
	return params, dropped, err
}
