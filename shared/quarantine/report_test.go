package quarantine

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"google.golang.org/protobuf/proto"

	commonv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/common/v1"
	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	"github.com/Kup1ng/CtrlZ-Shared/wire"
)

// reportOf is what node glue sends for a Failure.
func reportOf(f *Failure) *hubv1.QuarantineReport {
	return &hubv1.QuarantineReport{Seq: f.Seq, Scope: hubv1.Scope(f.Scope), Item: f.Item, Reason: string(f.Reason), Section: f.Section, Offset: f.Offset}
}

// Every Failure that Apply can emit must pass the hub's validator: a report the
// hub refuses is a report that never raises the "two nodes report the same
// failure" alert of 9.7. The chain mismatch and a bad pair table are the
// failures that alert exists for.
func TestEveryFailureApplyEmitsPassesTheHubValidator(t *testing.T) {
	good := mkBlob(t, "ads.example.com")
	badMagic := append([]byte(nil), mkBlob(t, "x.example.com")...)
	badMagic[0] = 'X'
	truncated := mkBlob(t, "y.example.com")
	truncated = truncated[:len(truncated)-1]
	evil, err := proto.Marshal(&policyv1.BlockPage{ProfileId: bytes.Repeat([]byte{9}, 16), Title: "Blocked", UnblockMode: policyv1.UnblockMode_UNBLOCK_MODE_URL, UnblockUrl: "javascript:alert(1)"})
	if err != nil {
		t.Fatal(err)
	}
	evilHash := sha256.Sum256(evil)
	evilRef := &policyv1.BlobRef{Hash: evilHash[:], Size: uint64(len(evil)), Kind: policyv1.BlobKind_BLOB_KIND_BLOCK_PAGE}
	flipped := append([]byte(nil), good...)
	flipped[len(flipped)-1] ^= 1

	srv := store{
		sha256.Sum256(good):      flipped, // a damaged transfer
		sha256.Sum256(badMagic):  badMagic,
		sha256.Sum256(truncated): truncated,
		evilHash:                 evil,
	}
	entry := func(st *State, e *policyv1.ConfigEntry) []byte {
		e.Class = commonv1.EntryClass_ENTRY_CLASS_POLICY
		e.PrevHash = st.Head[:]
		b, err := wire.MarshalEntry(e)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}

	type scenario struct {
		name string
		run  func(st *State) []*Failure
	}
	apply := func(raw func(st *State) []byte) func(st *State) []*Failure {
		return func(st *State) []*Failure {
			rep := Apply(st, raw(st), srv)
			var out []*Failure
			if rep.Entry != nil {
				out = append(out, rep.Entry)
			}
			for i := range rep.Quarantined {
				out = append(out, &rep.Quarantined[i])
			}
			for i := range rep.Failed {
				out = append(out, &rep.Failed[i])
			}
			return out
		}
	}
	scenarios := []scenario{
		{"chain mismatch", apply(func(st *State) []byte {
			e := &policyv1.ConfigEntry{Seq: 1, Class: commonv1.EntryClass_ENTRY_CLASS_POLICY, PrevHash: bytes.Repeat([]byte{7}, 32)}
			b, _ := wire.MarshalEntry(e)
			return b
		})},
		{"sequence gap", apply(func(st *State) []byte { return entry(st, &policyv1.ConfigEntry{Seq: 5}) })},
		{"garbage", apply(func(*State) []byte { return []byte{1, 2, 3} })},
		{"bad pair table", apply(func(st *State) []byte {
			return entry(st, &policyv1.ConfigEntry{Seq: 1, PairTable: &policyv1.PairTable{GlobalPairId: []byte{1}}})
		})},
		{"bad catalog", apply(func(st *State) []byte {
			return entry(st, &policyv1.ConfigEntry{Seq: 1, Catalog: &policyv1.CatalogRef{Key: []byte{1}}})
		})},
		{"bad endpoint", apply(func(st *State) []byte {
			return entry(st, &policyv1.ConfigEntry{Seq: 1, PutEndpoints: []*policyv1.EndpointRecord{{EndpointId: []byte{1}}}})
		})},
		{"bad claim", apply(func(st *State) []byte {
			return entry(st, &policyv1.ConfigEntry{Seq: 1, PutClaims: []*policyv1.ClaimRecord{{ClaimId: []byte{1}}}})
		})},
		{"bad blob ref", apply(func(st *State) []byte {
			return entry(st, &policyv1.ConfigEntry{Seq: 1, PutBlobs: []*policyv1.BlobRef{{Hash: []byte{1}}}})
		})},
		{"blobs: damaged transfer, bad magic, truncated, hostile block page", apply(func(st *State) []byte {
			return entry(st, &policyv1.ConfigEntry{Seq: 1, PutBlobs: []*policyv1.BlobRef{ref(good), ref(badMagic), ref(truncated), evilRef}})
		})},
	}
	seen := 0
	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			fails := sc.run(NewState())
			if len(fails) == 0 {
				t.Fatal("the scenario produced no failure")
			}
			for _, f := range fails {
				seen++
				if err := wire.ValidateQuarantineReport(reportOf(f)); err != nil {
					t.Errorf("the hub refuses the report of %+v: %v", *f, err)
				}
			}
		})
	}
	if seen < 8 {
		t.Fatalf("only %d failures were checked", seen)
	}
}
