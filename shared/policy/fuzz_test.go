package policy_test

import (
	"context"
	"hash/fnv"
	"math/rand"
	"net/netip"
	"reflect"
	"testing"

	"github.com/Kup1ng/CtrlZ-Shared/blob"
	"github.com/Kup1ng/CtrlZ-Shared/locations"
	"github.com/Kup1ng/CtrlZ-Shared/names"
	"github.com/Kup1ng/CtrlZ-Shared/policy"
	"github.com/Kup1ng/CtrlZ-Shared/rules"
)

// randomSpec builds a valid profile from seed bytes. The point of the fuzz
// target is that Pre and Post never panic and keep their invariants on any
// blob the builder can produce, so the profile content must vary widely while
// staying valid.
func randomSpec(r *rand.Rand) *blob.Spec {
	tokens := []string{
		"a.com", "b.a.com", "c.b.a.com", "*.a.com", "x-*.a.com", "*.b.a.com", "a.*.a.com", "ads.example.com", "example.com",
		"@US", "!@US", "@IR", "!@IR", "#IR", "!#IR", "#US", "@AS13335", "!@AS44244", "@DE",
	}
	actions := []blob.Action{blob.ActBlock, blob.ActBypass, blob.ActRedirect}
	target := func() *blob.TargetSpec {
		switch r.Intn(6) {
		case 0:
			return &blob.TargetSpec{Kind: blob.TargetLocation, Location: uint16(r.Intn(6))}
		case 1:
			return &blob.TargetSpec{Kind: blob.TargetAuto, Set: []uint16{uint16(r.Intn(6)), uint16(r.Intn(6) + 6)}}
		case 2:
			return &blob.TargetSpec{Kind: blob.TargetRandom, Set: []uint16{1, 2, 3}}
		case 3:
			return &blob.TargetSpec{Kind: blob.TargetIP, V4: netip.MustParseAddr("203.0.113.7")}
		case 4:
			h := names.MustString("target.example.net")
			return &blob.TargetSpec{Kind: blob.TargetHost, Host: h.Wire()}
		}
		return &blob.TargetSpec{Kind: blob.TargetLocation, Location: 2}
	}
	s := &blob.Spec{}
	if r.Intn(5) == 0 {
		s.DisabledUntil = int64(1_700_000_000 + r.Intn(200_000_000))
	}
	for _, bit := range []uint32{blob.OptExfiltration, blob.OptRebind, blob.OptDisableDNSSEC, blob.OptDNS64, blob.OptFlatten, blob.OptSafeSearch} {
		if r.Intn(3) == 0 {
			s.Options.Present |= bit
			if r.Intn(2) == 0 {
				s.Options.Bools |= uint8(bit)
			}
		}
	}
	if r.Intn(3) == 0 {
		s.Options.Present |= blob.OptBlockResponse
		s.Options.BlockResponse = uint8(1 + r.Intn(5))
		s.Options.BlockV4 = [4]byte{192, 0, 2, 9}
	}
	if r.Intn(3) == 0 {
		s.Options.Present |= blob.OptBypassTTL
		s.Options.BypassTTL = uint32(r.Intn(1000))
	}
	if r.Intn(3) == 0 {
		s.Options.Present |= blob.OptECS
		s.Options.ECSMode = uint8(1 + r.Intn(3))
		s.Options.ECSV4Prefix, s.Options.ECSV6Prefix = 24, 56
		s.Options.ECSV4 = [4]byte{203, 0, 113, 0}
		s.Options.ECSV6 = [16]byte{0x20, 0x01, 0x0d, 0xb8}
	}
	if a := actions[r.Intn(3)]; r.Intn(2) == 0 {
		s.Default = a
		if a == blob.ActRedirect {
			s.DefaultTarget = target()
		}
	}
	used := map[string]bool{}
	for i, n := 0, r.Intn(7); i < n; i++ {
		tok := tokens[r.Intn(len(tokens))]
		p, err := rules.Parse(tok)
		if err != nil || used[p.Key()] {
			continue
		}
		used[p.Key()] = true
		a := actions[r.Intn(3)]
		rs := blob.RuleSpec{ID: [16]byte{byte(i + 1)}, Pattern: p, Action: a, LocationUnavailable: r.Intn(8) == 0}
		if a == blob.ActRedirect {
			rs.Target = target()
		}
		if r.Intn(6) == 0 {
			rs.ExpiresAt = int64(1_700_000_000 + r.Intn(200_000_000))
		}
		s.Rules = append(s.Rules, rs)
	}
	return s
}

type fuzzGeo struct{}

func (fuzzGeo) Country(a netip.Addr) [2]byte {
	if a.Is4() && a.As4()[0]%2 == 0 {
		return [2]byte{'I', 'R'}
	}
	return [2]byte{'U', 'S'}
}
func (fuzzGeo) ASN(a netip.Addr) uint32 {
	if a.Is4() {
		return 13335 + uint32(a.As4()[0]%2)*31000
	}
	return 0
}

type fuzzLocs struct{ mask uint8 }

func (l fuzzLocs) Healthy(w uint16) bool { return w < 8 && l.mask&(1<<w) != 0 }
func (l fuzzLocs) Auto(c []uint16) (uint16, bool) {
	if len(c) == 0 {
		return 0, false
	}
	return c[len(c)-1], true
}

// fuzzResolver derives its answer from the question alone, so the same query
// gets the same answer and a divergence between two runs is the evaluator's.
type fuzzResolver struct{}

func (fuzzResolver) Lookup(_ context.Context, n names.Name, qtype uint16, _ policy.ResolveParams) (*policy.TrueAnswer, error) {
	h := fnv.New32a()
	h.Write(n.Wire())
	h.Write([]byte{byte(qtype), byte(qtype >> 8)})
	v := h.Sum32()
	ta := &policy.TrueAnswer{Chain: []names.Name{n}, Validation: policy.Validation(v % 4)}
	switch v % 7 {
	case 0:
		ta.Failed, ta.RCode = true, policy.RCodeServFail
		return ta, nil
	case 1:
		ta.RCode = policy.RCodeNXDomain
		return ta, nil
	}
	owner := n
	for i := uint32(0); i < v%4; i++ {
		next := names.MustString([]string{"a.com", "x-1.a.com", "target.example.net", "ads.example.com"}[(v>>3+i)%4])
		ta.Answer = append(ta.Answer, policy.RR{Name: owner, Type: policy.TypeCNAME, Class: policy.ClassIN, TTL: 30 + v%50, Data: append([]byte(nil), next.Wire()...)})
		ta.Chain = append(ta.Chain, next)
		owner = next
	}
	ips := [][]byte{{93, 184, 216, 34}, {2, 176, 0, 1}, {10, 0, 0, 7}, {151, 101, 1, 1}}
	if qtype == policy.TypeA || qtype == policy.TypeANY {
		ta.Answer = append(ta.Answer, policy.RR{Name: owner, Type: policy.TypeA, Class: policy.ClassIN, TTL: 20 + v%100, Data: ips[v%4]})
		if v%5 == 0 {
			ta.Answer = append(ta.Answer, policy.RR{Name: owner, Type: policy.TypeA, Class: policy.ClassIN, TTL: 20, Data: ips[(v+1)%4]})
		}
	}
	if qtype == policy.TypeAAAA && v%3 != 0 {
		d := make([]byte, 16)
		d[0], d[1], d[15] = 0x20, 0x01, byte(v)
		ta.Answer = append(ta.Answer, policy.RR{Name: owner, Type: policy.TypeAAAA, Class: policy.ClassIN, TTL: 50, Data: d})
	}
	return ta, nil
}

// FuzzPrePost: Pre plus Post (through Decide) on random valid blobs and random
// queries. It checks that nothing panics and that the invariants the node
// relies on hold, and that two runs agree.
func FuzzPrePost(f *testing.F) {
	f.Add([]byte("seed-one"), "x-1.a.com", uint16(1), int64(1_794_000_000), false, false)
	f.Add([]byte{1, 2, 3, 4, 5, 6, 7, 8}, "www.example.com", uint16(28), int64(0), true, true)
	f.Add([]byte{9, 9, 9}, "c.b.a.com", uint16(65), int64(1_900_000_000), false, true)
	f.Add([]byte("another"), "ads.example.com", uint16(255), int64(1_794_000_000), true, false)
	f.Fuzz(func(t *testing.T, seed []byte, qname string, qtype uint16, now int64, cd, do bool) {
		n, err := names.ParseUser(qname)
		if err != nil {
			return
		}
		h := fnv.New64a()
		h.Write(seed)
		r := rand.New(rand.NewSource(int64(h.Sum64())))
		p1, err := blob.Build(randomSpec(r))
		if err != nil {
			return
		}
		a, err := blob.Open(p1)
		if err != nil {
			t.Fatalf("builder output rejected: %v", err)
		}
		var b *blob.Profile
		if r.Intn(2) == 0 {
			if p2, err := blob.Build(randomSpec(r)); err == nil {
				b, _ = blob.Open(p2)
			}
		}
		pairBM := locations.BitmapFromBytes([]byte{byte(r.Intn(256))})
		st := policy.NewStack(a, b, pairBM)
		env := &policy.Env{
			Geo:  fuzzGeo{},
			Locs: fuzzLocs{mask: uint8(r.Intn(256))},
			Self: policy.SelfAddrs{
				DNSIP: netip.MustParseAddr("198.51.100.1"), ProxyIP: netip.MustParseAddr("198.51.100.2"),
				PeerProxyIP: netip.MustParseAddr("198.51.100.3"), PeerProxyUsable: r.Intn(2) == 0,
			},
		}
		in := &policy.Input{
			Name: n, QType: qtype, Now: now, Src: netip.MustParseAddr("5.160.0.1"), SrcCountry: [2]byte{'I', 'R'},
			Protocol: policy.ProtoDoH, EndpointID: [16]byte{1}, CD: cd, DO: do, Trace: r.Intn(2) == 0,
		}
		res := fuzzResolver{}
		f1 := policy.Decide(context.Background(), in, st, env, res)
		f2 := policy.Decide(context.Background(), in, st, env, res)
		if !reflect.DeepEqual(f1.Answer, f2.Answer) || f1.Action != f2.Action || f1.Stage != f2.Stage || f1.Location != f2.Location || f1.Flags != f2.Flags {
			t.Fatalf("two runs differ")
		}
		if f1.Action < blob.ActBlock || f1.Action > blob.ActRedirect {
			t.Fatalf("action %d", f1.Action)
		}
		if f1.Stage < policy.StageRule || f1.Stage > policy.StageDefault {
			t.Fatalf("stage %d", f1.Stage)
		}
		switch f1.Answer.RCode {
		case policy.RCodeNoError, policy.RCodeServFail, policy.RCodeNXDomain, policy.RCodeRefused:
		default:
			t.Fatalf("rcode %d", f1.Answer.RCode)
		}
		if f1.WantGrant {
			ok := false
			for _, rr := range f1.Answer.Answer {
				if ad, good := rr.Addr(); good && (ad == env.Self.ProxyIP || ad == env.Self.PeerProxyIP) {
					ok = true
				}
			}
			if !ok {
				t.Fatalf("WantGrant without a proxy address in the answer")
			}
			if f1.Answer.AD {
				t.Fatalf("a synthesized answer has AD set")
			}
		}
		if f1.Action == blob.ActRedirect && (f1.Target == blob.TargetLocation || f1.Target == blob.TargetAuto || f1.Target == blob.TargetRandom) {
			if !locations.BitmapHas(pairBM, f1.Location) {
				t.Fatalf("redirect to location %d outside the pair", f1.Location)
			}
		}
		if f1.Action == blob.ActBlock && f1.Answer.AD {
			t.Fatalf("a Block answer has AD set")
		}
	})
}
