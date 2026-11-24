package vectors

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Shared/blob"
	commonv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/common/v1"
	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	"github.com/Kup1ng/CtrlZ-Shared/quarantine"
	"github.com/Kup1ng/CtrlZ-Shared/rules"
	"github.com/Kup1ng/CtrlZ-Shared/wire"
)

// QuarantineCase scripts a node receiving entries (contract 9.7): blobs are
// named and built from rule tokens, some deliberately corrupted or withheld,
// and each step is one entry with the outcome the node must reach.
type QuarantineCase struct {
	ID    string           `json:"id"`
	Why   string           `json:"why"`
	Blobs map[string]QBlob `json:"blobs"`
	Steps []QuarantineStep `json:"steps"`
}

type QBlob struct {
	// Rules are rule tokens, all Block. Two blobs with different tokens have
	// different hashes.
	Rules []string `json:"rules"`
	// Corrupt is "", "bad_magic", "truncated" or "plix_hash" (the bytes
	// themselves are bad, so their hash is bad too), or "flip_transfer": the
	// blob is good but the node first receives it with one bit flipped, until a
	// step releases it.
	Corrupt string `json:"corrupt"`
	// Withheld blobs are named by an entry but not available to fetch.
	Withheld bool `json:"withheld"`
}

type QuarantineStep struct {
	Raw string `json:"raw"` // if set, apply these garbage bytes instead of an entry
	// Release makes withheld blobs fetchable before the step runs.
	Release []string `json:"release"`
	// Retry calls quarantine.Retry instead of applying an entry.
	Retry        bool             `json:"retry"`
	PutBlobs     []string         `json:"put_blobs"`
	DelBlobs     []string         `json:"del_blobs"`
	PutEndpoints []QEndpoint      `json:"put_endpoints"`
	DelEndpoints []string         `json:"del_endpoints"`
	Seq          uint64           `json:"seq"` // 0 means the next seq
	Expect       QuarantineExpect `json:"expect"`
}

type QEndpoint struct {
	ID    string `json:"id"`
	Blob  string `json:"blob"`
	Admin string `json:"admin"` // enabled, soft_disabled, hard_disabled
}

type QuarantineExpect struct {
	Advanced     bool              `json:"advanced"`
	AppliedSeq   uint64            `json:"applied_seq"`
	EntryFailure string            `json:"entry_failure"` // reason code, "" for none
	Quarantined  []string          `json:"quarantined"`   // "blob:reason"
	Failed       []string          `json:"failed"`        // "blob:reason", transfers that delivered the wrong bytes
	Missing      []string          `json:"missing"`       // blob names
	Promoted     []string          `json:"promoted"`      // endpoint ids that switched to a pending binding
	KeptPrevious []string          `json:"kept_previous"` // endpoint ids
	Degraded     []string          `json:"degraded"`      // endpoint ids
	Endpoints    map[string]string `json:"endpoints"`     // id -> "blob/admin" or "blob/admin/degraded"
}

type qStore map[[32]byte][]byte

func (s qStore) Fetch(h [32]byte, _ policyv1.BlobKind, _ uint64) ([]byte, bool) {
	d, ok := s[h]
	return d, ok
}

func adminOf(s string) commonv1.AdminState {
	switch s {
	case "soft_disabled":
		return commonv1.AdminState_ADMIN_STATE_SOFT_DISABLED
	case "hard_disabled":
		return commonv1.AdminState_ADMIN_STATE_HARD_DISABLED
	}
	return commonv1.AdminState_ADMIN_STATE_ENABLED
}

func adminText(a commonv1.AdminState) string {
	switch a {
	case commonv1.AdminState_ADMIN_STATE_SOFT_DISABLED:
		return "soft_disabled"
	case commonv1.AdminState_ADMIN_STATE_HARD_DISABLED:
		return "hard_disabled"
	}
	return "enabled"
}

func runQuarantineGroup(t *testing.T, g *GroupFile) {
	var cases []QuarantineCase
	if err := decodeStrict(g.Cases, &cases); err != nil {
		t.Fatalf("%s: %v", g.Group, err)
	}
	for i := range cases {
		c := &cases[i]
		t.Run(c.ID, func(t *testing.T) { runQuarantineCase(t, c) })
	}
}

func runQuarantineCase(t *testing.T, c *QuarantineCase) {
	// Build the named blobs.
	data := map[string][]byte{}
	hash := map[string][32]byte{}
	byHash := map[[32]byte]string{}
	store := qStore{}
	for name, qb := range c.Blobs {
		spec := &blob.Spec{}
		for i, tok := range qb.Rules {
			p, err := rules.Parse(tok)
			if err != nil {
				t.Fatalf("blob %s: %v", name, err)
			}
			spec.Rules = append(spec.Rules, blob.RuleSpec{ID: [16]byte{byte(i + 1)}, Pattern: p, Action: blob.ActBlock})
		}
		b, err := blob.Build(spec)
		if err != nil {
			t.Fatalf("blob %s: %v", name, err)
		}
		switch qb.Corrupt {
		case "bad_magic":
			b[0] = 'X'
		case "truncated":
			b = b[:len(b)-1]
		case "plix_hash":
			po := sectionOffset(b, blob.SecPLIX)
			b[po+1] ^= 1
		}
		data[name] = b
		h := sha256.Sum256(b)
		hash[name], byHash[h] = h, name
		switch {
		case qb.Withheld:
		case qb.Corrupt == "flip_transfer":
			flipped := append([]byte(nil), b...)
			flipped[len(flipped)-1] ^= 1
			store[h] = flipped
		default:
			store[h] = b
		}
	}
	ref := func(name string) *policyv1.BlobRef {
		h := hash[name]
		return &policyv1.BlobRef{Hash: h[:], Size: uint64(len(data[name])), Kind: policyv1.BlobKind_BLOB_KIND_PROFILE}
	}
	st := quarantine.NewState()
	for si, step := range c.Steps {
		for _, n := range step.Release {
			store[hash[n]] = data[n]
		}
		var stored []byte
		if step.Retry {
			// no entry: the node's fetch path recovered
		} else if step.Raw != "" {
			stored = []byte(step.Raw)
		} else {
			e := &policyv1.ConfigEntry{Seq: st.AppliedSeq + 1, Class: commonv1.EntryClass_ENTRY_CLASS_POLICY, PrevHash: st.Head[:], CreatedAt: 1}
			if step.Seq != 0 {
				e.Seq = step.Seq
			}
			for _, n := range step.PutBlobs {
				e.PutBlobs = append(e.PutBlobs, ref(n))
			}
			for _, n := range step.DelBlobs {
				h := hash[n]
				e.DelBlobs = append(e.DelBlobs, h[:])
			}
			for _, ep := range step.PutEndpoints {
				id := EndpointID(ep.ID)
				h := hash[ep.Blob]
				e.PutEndpoints = append(e.PutEndpoints, &policyv1.EndpointRecord{
					EndpointId: id[:], RidHash: id[:], DohTokenHash: bytes.Repeat(id[:2], 16), PairId: id[:],
					AdminState: adminOf(ep.Admin), AnalyticsLevel: commonv1.AnalyticsLevel_ANALYTICS_LEVEL_SOME,
					Base: &policyv1.StackRecord{Profile1Hash: h[:]},
				})
			}
			for _, id := range step.DelEndpoints {
				b := EndpointID(id)
				e.DelEndpoints = append(e.DelEndpoints, b[:])
			}
			var err error
			if stored, err = wire.MarshalEntry(e); err != nil {
				t.Fatalf("step %d: %v", si, err)
			}
		}
		var rep quarantine.Report
		if step.Retry {
			rep = quarantine.Retry(st, store)
		} else {
			rep = quarantine.Apply(st, stored, store)
		}
		exp := step.Expect
		where := fmt.Sprintf("step %d (%s)", si, c.Why)
		if rep.Advanced != exp.Advanced || st.AppliedSeq != exp.AppliedSeq {
			t.Errorf("%s: advanced=%v applied_seq=%d, want %v %d", where, rep.Advanced, st.AppliedSeq, exp.Advanced, exp.AppliedSeq)
		}
		gotEntry := ""
		if rep.Entry != nil {
			gotEntry = string(rep.Entry.Reason)
		}
		if gotEntry != exp.EntryFailure {
			t.Errorf("%s: entry failure %q, want %q", where, gotEntry, exp.EntryFailure)
		}
		var q []string
		for _, f := range rep.Quarantined {
			var h [32]byte
			copy(h[:], f.Item)
			q = append(q, byHash[h]+":"+string(f.Reason))
		}
		var failed []string
		for _, f := range rep.Failed {
			var h [32]byte
			copy(h[:], f.Item)
			failed = append(failed, byHash[h]+":"+string(f.Reason))
		}
		var miss []string
		for _, h := range rep.Missing {
			miss = append(miss, byHash[h])
		}
		epName := func(ids [][16]byte) []string {
			var out []string
			for _, id := range ids {
				out = append(out, endpointName(id, c))
			}
			return out
		}
		same := func(field string, got, want []string) {
			sort.Strings(got)
			w := append([]string(nil), want...)
			sort.Strings(w)
			if strings.Join(got, ",") != strings.Join(w, ",") {
				t.Errorf("%s: %s = %v, want %v", where, field, got, want)
			}
		}
		same("quarantined", q, exp.Quarantined)
		same("failed", failed, exp.Failed)
		same("missing", miss, exp.Missing)
		same("kept_previous", epName(rep.KeptPrevious), exp.KeptPrevious)
		same("degraded", epName(rep.Degraded), exp.Degraded)
		same("promoted", epName(rep.Promoted), exp.Promoted)
		for name, want := range exp.Endpoints {
			id := EndpointID(name)
			ep, ok := st.Endpoints[id]
			if !ok {
				t.Errorf("%s: endpoint %s absent, want %s", where, name, want)
				continue
			}
			var bound [32]byte
			copy(bound[:], ep.Base.Profile1Hash)
			got := byHash[bound] + "/" + adminText(ep.AdminState)
			if st.Degraded[id] {
				got += "/degraded"
			}
			if got != want {
				t.Errorf("%s: endpoint %s = %s, want %s", where, name, got, want)
			}
		}
	}
}

// endpointName maps an endpoint id back to its label by searching the steps.
func endpointName(id [16]byte, c *QuarantineCase) string {
	for _, s := range c.Steps {
		for _, ep := range s.PutEndpoints {
			if EndpointID(ep.ID) == id {
				return ep.ID
			}
		}
	}
	return fmt.Sprintf("%x", id[:4])
}

// sectionOffset returns the file offset of a CZPB section's data.
func sectionOffset(b []byte, id int) int {
	n := int(binary.LittleEndian.Uint32(b[12:]))
	for i := 0; i < n; i++ {
		o := blob.HeaderLen + 16*i
		if int(binary.LittleEndian.Uint32(b[o:])) == id {
			return int(binary.LittleEndian.Uint32(b[o+8:]))
		}
	}
	panic("vectors: no such section")
}
