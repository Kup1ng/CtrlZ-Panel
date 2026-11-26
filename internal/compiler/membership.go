package compiler

import (
	"bytes"
	"errors"
	"slices"
	"sort"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	"github.com/Kup1ng/CtrlZ-Shared/wire"
	"github.com/Kup1ng/CtrlZ-Shared/zone"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// Membership is what the PairTable is built from: nodes, pairs and the global pair (SC 8a.4, Versions).
type Membership struct {
	Nodes  []store.MemberNode
	Pairs  []store.MemberPair
	Global uuid.UUID
}

// BuildPairTable is the table the next entry would carry from the rows. Rules of SC 8a.4, in their words:
//   - the table holds every node whose status is active or revoked; a pending node is in no table;
//   - a revoked node has an empty spki_sha256, and the rest of its entry is unchanged;
//   - the log carries no withdrawal state: dns_withdrawn is false and version is 0;
//   - a pair is carried only when both of its nodes are, and the global pair only when it is among them.
//
// It checks nothing: ValidateTable is the judge, and a refusal falls back to the last table (6.2).
func BuildPairTable(m *Membership) *policyv1.PairTable { return BuildPairTableAs(m, uuid.Nil) }

// BuildPairTableAs is BuildPairTable with the node activate counted as active, whatever its row says. The node routes use
// it to judge the table a confirmation or an approval would produce before they commit it (internal/nodeadmin), so the
// rows are read by one rule, the compiler's, and a table the route accepts is one the compiler would write.
func BuildPairTableAs(m *Membership, activate uuid.UUID) *policyv1.PairTable {
	pt := &policyv1.PairTable{}
	in := map[uuid.UUID]bool{}
	nodes := slices.Clone(m.Nodes)
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].Slot < nodes[j].Slot })
	for _, n := range nodes {
		if n.ID == activate {
			n.Status = "active"
		}
		if n.Status != "active" && n.Status != "revoked" {
			continue
		}
		ne := &policyv1.NodeEntry{NodeId: n.ID[:], ProxyBlocked: n.ProxyBlocked, Slot: uint32(n.Slot)}
		if b, err := ipBytes(n.DNSIP); err == nil {
			ne.DnsIp = b
		}
		if b, err := ipBytes(n.ProxyIP); err == nil {
			ne.ProxyIp = b
		}
		if n.Status == "active" {
			ne.SpkiSha256 = n.SPKI
		}
		pt.Nodes = append(pt.Nodes, ne)
		in[n.ID] = true
	}
	pairs := slices.Clone(m.Pairs)
	sort.Slice(pairs, func(i, j int) bool { return bytes.Compare(pairs[i].ID[:], pairs[j].ID[:]) < 0 })
	for _, p := range pairs {
		if !in[p.Primary] || !in[p.Fallback] {
			continue
		}
		pt.Pairs = append(pt.Pairs, &policyv1.Pair{PairId: p.ID[:], Primary: p.Primary[:], Fallback: p.Fallback[:]})
		if p.ID == m.Global {
			pt.GlobalPairId = p.ID[:]
		}
	}
	return pt
}

// ValidateTable is the validity of a table by itself: wire.ValidatePairTable accepts it and zone.Build builds a table from
// it with no error and no panic. It cannot see a missing SPKI, since an empty one is how a revoked node is written; that
// refusal (SC 8a.4, invariant 6) needs the rows and is made by activeWithoutSPKI.
//
// Both judges run, and the error is the builder's when it refused (a *zone.BuildError names the field and the rule in a stable
// phrase, which the node routes return to the admin), else the wire validator's.
func ValidateTable(pt *policyv1.PairTable) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = ErrBuilderPanic
		}
	}()
	werr := wire.ValidatePairTable(pt)
	if _, berr := zone.Build(wire.ZoneInput(pt)); berr != nil {
		return berr
	}
	return werr
}

// ErrBuilderPanic is what ValidateTable returns for a table that panics the builder: a refusal, as for the nodes.
var ErrBuilderPanic = errors.New("compiler: pair table panics the builder")

// emptyTable is a table that says nothing: no node and no pair. An entry without a table leaves the membership as it
// is, so an empty one need not be written.
func emptyTable(pt *policyv1.PairTable) bool {
	return pt == nil || (len(pt.Nodes) == 0 && len(pt.Pairs) == 0 && len(pt.GlobalPairId) == 0)
}

// NextPairTable is the table the next entry carries, or nil when nothing about the membership changed. last is the
// table of the latest entry.
//
// A table that is not valid is not written (it would quarantine on every node): the entry carries the last table,
// after the nodes that have no row any more are taken out and each revoked row's SPKI is emptied, so the tenant
// changes of the entry still go out, a revocation still reaches the nodes, and refused is true so the caller alerts.
// Revocation is applied last to whatever is written, and once empty an SPKI is never written non-empty again.
func NextPairTable(m *Membership, last *policyv1.PairTable) (next *policyv1.PairTable, refused bool) {
	pt := BuildPairTable(m)
	keepRevoked(pt, last)
	// An active node with no key would be written as a revoked one, and a revocation is never undone (keepRevoked): the
	// table is refused whole, and the last one stands until the row is whole.
	if activeWithoutSPKI(m) || ValidateTable(pt) != nil {
		refused = true
		pt = fallbackTable(m, last)
		if pt != nil && ValidateTable(pt) != nil {
			return nil, true
		}
	}
	if (emptyTable(pt) && emptyTable(last)) || proto.Equal(pt, last) {
		return nil, refused
	}
	return pt, refused
}

// activeWithoutSPKI says a row is active and has no SPKI of 32 bytes. nodes.spki_sha256 is nullable and no constraint ties it to
// the status, so the compiler is the one that must not read the gap as a revocation.
func activeWithoutSPKI(m *Membership) bool { return ActiveWithoutSPKI(m, uuid.Nil) }

// ActiveWithoutSPKI is activeWithoutSPKI with the node activate counted as active. The node routes refuse such a table
// before they commit, by the rule the compiler refuses it with, so a change is never answered with success and then left
// unpublished.
func ActiveWithoutSPKI(m *Membership, activate uuid.UUID) bool {
	for _, n := range m.Nodes {
		if (n.Status == "active" || n.ID == activate) && len(n.SPKI) != 32 {
			return true
		}
	}
	return false
}

// keepRevoked empties the SPKI of every node the last table already had empty, whatever the rows say now.
func keepRevoked(pt, last *policyv1.PairTable) {
	if last == nil {
		return
	}
	gone := map[string]bool{}
	for _, n := range last.Nodes {
		if len(n.SpkiSha256) == 0 {
			gone[string(n.NodeId)] = true
		}
	}
	for _, n := range pt.Nodes {
		if gone[string(n.NodeId)] {
			n.SpkiSha256 = nil
		}
	}
}

// fallbackTable is the last table with the removed nodes left out (and the pairs and global pair that named them) and
// the revoked rows' SPKI emptied.
func fallbackTable(m *Membership, last *policyv1.PairTable) *policyv1.PairTable {
	if last == nil {
		return nil
	}
	rows := map[uuid.UUID]store.MemberNode{}
	for _, n := range m.Nodes {
		rows[n.ID] = n
	}
	out := proto.Clone(last).(*policyv1.PairTable)
	kept := out.Nodes[:0]
	live := map[string]bool{}
	for _, n := range out.Nodes {
		id, err := uuid.FromBytes(n.NodeId)
		if err != nil {
			continue
		}
		row, ok := rows[id]
		if !ok {
			continue
		}
		if row.Status == "revoked" {
			n.SpkiSha256 = nil
		}
		kept = append(kept, n)
		live[string(n.NodeId)] = true
	}
	out.Nodes = kept
	pairs := out.Pairs[:0]
	for _, p := range out.Pairs {
		if live[string(p.Primary)] && live[string(p.Fallback)] {
			pairs = append(pairs, p)
		}
	}
	out.Pairs = pairs
	if !slices.ContainsFunc(out.Pairs, func(p *policyv1.Pair) bool { return bytes.Equal(p.PairId, out.GlobalPairId) }) {
		out.GlobalPairId = nil
	}
	return out
}
