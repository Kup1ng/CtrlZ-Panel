package compiler

import (
	"errors"
	"fmt"
	"sort"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	signv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/sign/v1"
	"github.com/Kup1ng/CtrlZ-Shared/wire"
)

// blobInfo is what the compiler knows of one blob: the BlobRef nodes are told and the collection mark.
type blobInfo struct {
	size     uint64
	kind     policyv1.BlobKind
	firstSeq uint64
	// gcAfter is the seq of the entry that left the hash unbound, 0 while it is bound (policy_artifacts.gc_after_seq).
	gcAfter uint64
}

// View is the compiler's picture of the log: the state a node reaches by applying every entry (the latest snapshot
// plus the entries after it). It is the only "previous state" a pass compares with; no table holds compiled state
// (6.1). It is not safe for concurrent use: one pass owns it.
type View struct {
	Seq  uint64
	Head []byte // entry hash of Seq, 32 zero bytes for an empty log

	Endpoints map[string]*policyv1.EndpointRecord
	Claims    map[string]*policyv1.ClaimRecord
	Pair      *policyv1.PairTable
	Free      *policyv1.FreeDns
	Catalog   *policyv1.CatalogRef
	// Major is the blob major of the latest entry, 1 while the log is empty (SC 8a.11 L5).
	Major uint32

	blobs map[string]*blobInfo
	// refs counts the records of the latest state that bind each hash.
	refs map[string]int
	// owner says which tenant each Endpoint and claim was last compiled for. The log keeps no tenant (R18), so this
	// is learned as tenants compile and is empty after the lease starts until a full pass has run.
	owner map[string]uuid.UUID
}

// NewView is the view of an empty log.
func NewView(major uint32) *View {
	return &View{Head: make([]byte, 32), Major: major, Endpoints: map[string]*policyv1.EndpointRecord{}, Claims: map[string]*policyv1.ClaimRecord{},
		blobs: map[string]*blobInfo{}, refs: map[string]int{}, owner: map[string]uuid.UUID{}}
}

// bindingsOf lists the profile hashes of one record, each once, in the order the record names them.
func bindingsOf(e *policyv1.EndpointRecord) [][]byte { return bindings(e) }

func (v *View) bind(e *policyv1.EndpointRecord, d int) {
	for _, h := range bindingsOf(e) {
		v.refs[string(h)] += d
		if v.refs[string(h)] <= 0 {
			delete(v.refs, string(h))
		}
	}
}

// Apply moves the view to the state after one entry that the caller has validated and chained. The order is the
// node's (quarantine.Apply): deletes of Endpoints, then puts; deletes of claims, then puts.
func (v *View) Apply(e *policyv1.ConfigEntry, hash []byte) {
	tab := stackTable{}
	for _, id := range e.DelEndpoints {
		if old := v.Endpoints[string(id)]; old != nil {
			v.bind(old, -1)
			delete(v.Endpoints, string(id))
		}
		delete(v.owner, string(id))
	}
	for _, rec := range e.PutEndpoints {
		tab.intern(rec)
		if old := v.Endpoints[string(rec.EndpointId)]; old != nil {
			v.bind(old, -1)
		}
		v.Endpoints[string(rec.EndpointId)] = rec
		v.bind(rec, 1)
	}
	for _, id := range e.DelClaims {
		delete(v.Claims, string(id))
		delete(v.owner, string(id))
	}
	for _, c := range e.PutClaims {
		v.Claims[string(c.ClaimId)] = c
	}
	for _, b := range e.PutBlobs {
		bi := v.blobs[string(b.Hash)]
		if bi == nil {
			bi = &blobInfo{firstSeq: e.Seq}
			v.blobs[string(b.Hash)] = bi
		}
		bi.size, bi.kind, bi.gcAfter = b.Size, b.Kind, 0
	}
	for _, h := range e.DelBlobs {
		if bi := v.blobs[string(h)]; bi != nil && v.refs[string(h)] == 0 {
			bi.gcAfter = e.Seq
		}
	}
	if e.PairTable != nil {
		v.Pair = e.PairTable
	}
	if e.FreeDns != nil {
		v.Free = e.FreeDns
	}
	if e.Catalog != nil {
		v.Catalog = e.Catalog
	}
	if e.MinBlobMajor != 0 {
		v.Major = e.MinBlobMajor
	}
	v.Seq, v.Head = e.Seq, hash
}

// Chain checks one stored entry against the view and applies it: the seq follows, prev_hash is the head, and the hash is
// SHA-256(prev_hash + stored bytes) (SC 9.6).
func (v *View) Chain(seq uint64, prev, hash, payload []byte) error {
	if seq != v.Seq+1 {
		return fmt.Errorf("compiler: entry %d does not follow %d", seq, v.Seq)
	}
	e, err := wire.DecodeEntry(payload)
	if err != nil {
		return errors.New("compiler: stored entry does not decode")
	}
	if e.Seq != seq || string(e.PrevHash) != string(v.Head) || (len(prev) != 0 && string(prev) != string(v.Head)) {
		return errors.New("compiler: stored entry does not chain")
	}
	var p [32]byte
	copy(p[:], v.Head)
	want := wire.EntryHash(p, payload)
	if string(want[:]) != string(hash) {
		return errors.New("compiler: stored entry hash is wrong")
	}
	v.Apply(e, hash)
	return nil
}

// FromSnapshot makes the view of a snapshot (SC 12).
func FromSnapshot(s *signv1.Snapshot, major uint32) *View {
	v := NewView(major)
	v.Seq, v.Head = s.Seq, s.EntryHash
	tab := stackTable{}
	for _, e := range s.Endpoints {
		tab.intern(e)
		v.Endpoints[string(e.EndpointId)] = e
		v.bind(e, 1)
	}
	for _, c := range s.Claims {
		v.Claims[string(c.ClaimId)] = c
	}
	for _, b := range s.Blobs {
		v.blobs[string(b.Hash)] = &blobInfo{size: b.Size, kind: b.Kind, firstSeq: s.Seq}
	}
	v.Pair, v.Catalog, v.Free = s.PairTable, s.Catalog, s.FreeDns
	return v
}

// Snapshot is the state at the head as a Snapshot message: the blobs that are bound, the records, the table, the
// catalog reference and the free DNS value (SC 12). Everything is sorted so the file is the same for the same state.
func (v *View) Snapshot() *signv1.Snapshot {
	s := &signv1.Snapshot{Seq: v.Seq, EntryHash: v.Head, PairTable: v.Pair, Catalog: v.Catalog, FreeDns: v.Free}
	for _, h := range sortedKeys(v.refs) {
		if bi := v.blobs[h]; bi != nil {
			s.Blobs = append(s.Blobs, &policyv1.BlobRef{Hash: []byte(h), Size: bi.size, Kind: bi.kind})
		} else {
			s.Blobs = append(s.Blobs, &policyv1.BlobRef{Hash: []byte(h), Kind: policyv1.BlobKind_BLOB_KIND_PROFILE})
		}
	}
	for _, k := range sortedKeys(v.Endpoints) {
		s.Endpoints = append(s.Endpoints, v.Endpoints[k])
	}
	for _, k := range sortedKeys(v.Claims) {
		s.Claims = append(s.Claims, v.Claims[k])
	}
	return s
}

// MarshalSnapshot encodes a snapshot deterministically.
func MarshalSnapshot(s *signv1.Snapshot) ([]byte, error) {
	return proto.MarshalOptions{Deterministic: true}.Marshal(s)
}

// LoadArtifacts merges the policy_artifacts rows into the view: sizes and kinds of blobs the nodes may hold, and the
// collection marks.
func (v *View) LoadArtifacts(rows []artifactRow) {
	for _, r := range rows {
		kind := policyv1.BlobKind_BLOB_KIND_PROFILE
		if r.Kind == kindBlockPage {
			kind = policyv1.BlobKind_BLOB_KIND_BLOCK_PAGE
		}
		v.blobs[string(r.Hash)] = &blobInfo{size: uint64(r.Size), kind: kind, firstSeq: r.FirstSeq, gcAfter: r.GCAfter}
	}
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// stackKey is the content of a StackRecord, so equal stacks can be told apart from different ones without marshalling.
type stackKey struct {
	p1, p2, opts string
	depth        uint32
	geo, exp     bool
}

// stackTable makes equal stacks of what it is given one object. The clients of an Endpoint usually share a few stacks, and each
// decoded client carries its own copy (two hashes and the merged options): at 50,000 clients that is most of what the view
// holds. The table lives for one entry or one snapshot, so it cannot grow with the log (W4-r4-4).
type stackTable map[stackKey]*policyv1.StackRecord

func (t stackTable) of(s *policyv1.StackRecord) *policyv1.StackRecord {
	if s == nil {
		return nil
	}
	k := stackKey{string(s.Profile1Hash), string(s.Profile2Hash), string(s.MergedOptions), s.MaxDepth, s.HasDestGeo, s.Explicit}
	if have, ok := t[k]; ok {
		return have
	}
	t[k] = s
	return s
}

// intern replaces the stacks of a decoded record by the shared ones. The record is the caller's own, fresh from a decode.
func (t stackTable) intern(rec *policyv1.EndpointRecord) {
	rec.Base = t.of(rec.Base)
	for _, w := range rec.GetSchedule().GetWindows() {
		w.Stack = t.of(w.Stack)
	}
	for _, c := range rec.Clients {
		c.Stack = t.of(c.Stack)
	}
}
