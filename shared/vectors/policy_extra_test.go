package vectors

import (
	"bytes"
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Shared/blob"
	commonv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/common/v1"
	"github.com/Kup1ng/CtrlZ-Shared/names"
	"github.com/Kup1ng/CtrlZ-Shared/policy"
	"github.com/Kup1ng/CtrlZ-Shared/wire"
)

// stubResolver answers every lookup with one public A record.
type stubResolver struct{}

func (stubResolver) Lookup(_ context.Context, n names.Name, qtype uint16, _ policy.ResolveParams) (*policy.TrueAnswer, error) {
	ta := &policy.TrueAnswer{Chain: []names.Name{n}}
	if qtype == policy.TypeA {
		ta.Answer = []policy.RR{{Name: n, Type: policy.TypeA, Class: policy.ClassIN, TTL: 60, Data: []byte{93, 184, 216, 34}}}
	}
	return ta, nil
}

func baseEnv(t *testing.T) (*Fixture, policy.Env) {
	t.Helper()
	fx, err := LoadFixture("base")
	if err != nil {
		t.Fatal(err)
	}
	env, _, err := fx.Env()
	if err != nil {
		t.Fatal(err)
	}
	return fx, env
}

func inputFor(name string, qtype uint16, ep string) policy.Input {
	n := names.MustString(name)
	return policy.Input{Name: n, QType: qtype, Now: 1_794_000_000, Src: netip.MustParseAddr("5.160.0.1"), EndpointID: EndpointID(ep)}
}

// TestAcceptGrant covers the receiver side of a forwarded Grant (10.3): the
// carried location must be in the receiver's own effective set, but it need not
// be the location the receiver itself would have picked; the kind and the dial
// host must be exactly what the receiver would grant itself.
func TestAcceptGrant(t *testing.T) {
	fx, env := baseEnv(t)
	redirect := func(loc uint16) policy.GrantOffer {
		return policy.GrantOffer{Kind: policy.GrantRedirect, Location: loc}
	}
	cases := []struct {
		name  string
		ep    string
		offer policy.GrantOffer
		want  bool
	}{
		{"auto.example", "e-loc", redirect(2), true},  // the receiver's own pick
		{"auto.example", "e-loc", redirect(1), true},  // a different pick from the sender, still inside the set
		{"auto.example", "e-loc", redirect(3), true},  // likewise
		{"auto.example", "e-loc", redirect(4), false}, // healthy and in the pair, but not in the rule's set
		{"auto.example", "e-loc", redirect(9), false}, // outside the pair
		{"loc.example", "e-loc", redirect(2), true},   // fixed location: must be exact
		{"loc.example", "e-loc", redirect(1), false},
		{"unlisted.test", "e-loc", redirect(2), false}, // not a Redirect on this node at all
		{"far.example", "e-loc", redirect(9), false},   // location unavailable here: acts as Bypass

		// The kind is the receiver's too: a block page offer for a Redirect name
		// and the reverse are both refused.
		{"loc.example", "e-loc", policy.GrantOffer{Kind: policy.GrantBlockPage, Location: 2}, false},
		{"bl.example", "e-qm-branded", policy.GrantOffer{Kind: policy.GrantBlockPage}, true},
		{"bl.example", "e-qm-branded", policy.GrantOffer{Kind: policy.GrantBlockPage, Location: 7}, true}, // no location to compare
		{"bl.example", "e-qm-branded", redirect(2), false},
		{"other.example", "e-qm-branded", policy.GrantOffer{Kind: policy.GrantBlockPage}, false}, // not blocked here
		{"bl.example", "e-qm-zero", policy.GrantOffer{Kind: policy.GrantBlockPage}, false},       // 0.0.0.0 block: no Grant at all

		// The dial host is the receiver's own. A peer may neither add one nor
		// drop the Safe Search host.
		{"loc.example", "e-loc", policy.GrantOffer{Kind: policy.GrantRedirect, Location: 2, DialHost: names.MustString("evil.example")}, false},
		{"www.google.com", "e-opt-safe-redir", policy.GrantOffer{Kind: policy.GrantRedirect, Location: 2, DialHost: names.MustString("forcesafesearch.google.com")}, true},
		{"www.google.com", "e-opt-safe-redir", redirect(2), false},
		{"www.google.com", "e-opt-safe-redir", policy.GrantOffer{Kind: policy.GrantRedirect, Location: 2, DialHost: names.MustString("evil.example")}, false},
		{"bl.example", "e-qm-branded", policy.GrantOffer{Kind: policy.GrantBlockPage, DialHost: names.MustString("evil.example")}, false},
	}
	for _, c := range cases {
		in := inputFor(c.name, policy.TypeA, c.ep)
		st := fx.Endpoints[c.ep].Base
		if _, got := policy.AcceptGrant(&in, st, &env, stubResolver{}, c.offer); got != c.want {
			t.Errorf("%s on %s, offer %+v: got %v want %v", c.name, c.ep, c.offer, got, c.want)
		}
	}
}

// A receiver with no proxy address answers SERVFAIL and creates no Grant, so
// it has nothing to accept.
func TestAcceptGrantNeedsAGrantToAccept(t *testing.T) {
	fx, env := baseEnv(t)
	in := inputFor("loc.example", policy.TypeA, "e-loc")
	st := fx.Endpoints["e-loc"].Base
	offer := policy.GrantOffer{Kind: policy.GrantRedirect, Location: 2}
	if _, ok := policy.AcceptGrant(&in, st, &env, stubResolver{}, offer); !ok {
		t.Fatal("control: the offer is refused with a proxy address")
	}
	env.Self.ProxyIP = netip.Addr{}
	env.Self.PeerProxyIP = netip.Addr{}
	if _, ok := policy.AcceptGrant(&in, st, &env, stubResolver{}, offer); ok {
		t.Error("accepted a grant the receiver would not have created")
	}
}

// TestPeerUnusable: PROXY_IPs leave out a peer that is blocked or down (R11),
// and own is always first.
func TestPeerUnusable(t *testing.T) {
	fx, env := baseEnv(t)
	st := fx.Endpoints["e-loc"].Base
	in := inputFor("loc.example", policy.TypeA, "e-loc")
	f := policy.Decide(context.Background(), &in, st, &env, stubResolver{})
	if len(f.Answer.Answer) != 2 || FormatRR(f.Answer.Answer[0]) != "loc.example. 60 IN A 198.51.100.2" {
		t.Fatalf("with peer: %v", f.Answer.Answer)
	}
	env.Self.PeerProxyUsable = false
	f = policy.Decide(context.Background(), &in, st, &env, stubResolver{})
	if len(f.Answer.Answer) != 1 || !f.WantGrant {
		t.Fatalf("peer down: %v want_grant=%v", f.Answer.Answer, f.WantGrant)
	}
	env.Self.ProxyIP = netip.Addr{}
	f = policy.Decide(context.Background(), &in, st, &env, stubResolver{})
	if f.Action != policy.ActionBypass || f.Flags&policy.FlagLocationUnavailable == 0 || f.WantGrant || f.Answer.RCode == policy.RCodeServFail {
		t.Fatalf("no proxy address at all is Bypass with location_unavailable (4.4), not an error: %+v", f)
	}
}

// TestDecideIsPure runs the same query twice and compares: the evaluator reads
// only its inputs, so two runs are identical.
func TestDecideIsPure(t *testing.T) {
	fx, env := baseEnv(t)
	for _, c := range []struct{ ep, name string }{{"e-prec", "tracker.example"}, {"e-loc", "rand.example"}, {"e-merge", "strictonly.example"}} {
		in := inputFor(c.name, policy.TypeA, c.ep)
		a := policy.Decide(context.Background(), &in, fx.Endpoints[c.ep].Base, &env, stubResolver{})
		b := policy.Decide(context.Background(), &in, fx.Endpoints[c.ep].Base, &env, stubResolver{})
		if FormatAnswer(a.Answer) != FormatAnswer(b.Answer) || a.Action != b.Action || a.Location != b.Location {
			t.Errorf("%s: two runs differ", c.name)
		}
	}
}

// FormatAnswer renders an Answer on one line, for comparisons and messages.
func FormatAnswer(a policy.Answer) string {
	s := rcodeName(a.RCode)
	for _, r := range a.Answer {
		s += " | " + FormatRR(r)
	}
	for _, r := range a.Authority {
		s += " | auth " + FormatRR(r)
	}
	return s
}

// A log row may carry the qname and every hop the walk can take, and no more:
// the wire bound follows the evaluator's, so raising one without the other
// fails here.
func TestLogRowChainBoundIsTheWalkLimit(t *testing.T) {
	if wire.MaxCNAMEChain != policy.MaxCNAMEHops+1 {
		t.Errorf("wire.MaxCNAMEChain = %d, want the walk limit %d plus the qname", wire.MaxCNAMEChain, policy.MaxCNAMEHops)
	}
}

// The evaluator's Protocol numbers are the proto enum's (common.proto: converting
// between them is a cast), DoH3 included (D51).
func TestPolicyProtocolsMatchTheProtoEnum(t *testing.T) {
	for p, want := range map[policy.Protocol]commonv1.Protocol{
		policy.ProtoUDP: commonv1.Protocol_PROTOCOL_UDP, policy.ProtoTCP: commonv1.Protocol_PROTOCOL_TCP,
		policy.ProtoDoH: commonv1.Protocol_PROTOCOL_DOH, policy.ProtoDoT: commonv1.Protocol_PROTOCOL_DOT,
		policy.ProtoDoQ: commonv1.Protocol_PROTOCOL_DOQ, policy.ProtoDoH3: commonv1.Protocol_PROTOCOL_DOH3,
	} {
		if commonv1.Protocol(p) != want {
			t.Errorf("policy protocol %d is %v in the proto enum, want %v", p, commonv1.Protocol(p), want)
		}
	}
}

// proxyList returns the A addresses of a Decide answer, in order.
func proxyList(f policy.Final) []string {
	var out []string
	for _, r := range f.Answer.Answer {
		if a, ok := r.Addr(); ok {
			out = append(out, a.String())
		}
	}
	return out
}

// TestProxyIPOrder pins 4.4 of p4b-proxy: own first, own last when it is
// proxy_blocked and the peer is usable, own left out while the proxy is down, and
// an unusable peer never listed.
func TestProxyIPOrder(t *testing.T) {
	fx, env := baseEnv(t)
	st := fx.Endpoints["e-loc"].Base
	in := inputFor("loc.example", policy.TypeA, "e-loc")
	own, peer := env.Self.ProxyIP.String(), env.Self.PeerProxyIP.String()
	for _, c := range []struct {
		name                      string
		blocked, down, peerUsable bool
		want                      []string
	}{
		{"both usable", false, false, true, []string{own, peer}},
		{"own blocked, peer usable: own last", true, false, true, []string{peer, own}},
		{"own blocked, peer unusable: own alone", true, false, false, []string{own}},
		{"own down, peer usable: peer alone", false, true, true, []string{peer}},
		{"own down and blocked, peer usable: peer alone", true, true, true, []string{peer}},
		{"own down, peer unusable: nothing", false, true, false, nil},
	} {
		e := env
		e.Self.ProxyBlocked, e.Self.ProxyDown, e.Self.PeerProxyUsable = c.blocked, c.down, c.peerUsable
		f := policy.Decide(context.Background(), &in, st, &e, stubResolver{})
		// With no address the answer is the true one (Bypass), which is no PROXY_IP list.
		if got := strings.Join(proxyList(f), ","); len(c.want) != 0 && got != strings.Join(c.want, ",") {
			t.Errorf("%s: %v want %v", c.name, proxyList(f), c.want)
		}
		if len(c.want) == 0 && (f.WantGrant || f.Action != policy.ActionBypass || f.Flags&policy.FlagLocationUnavailable == 0) {
			t.Errorf("%s: a redirect with no address must be Bypass with location_unavailable and no Grant: %+v", c.name, f)
		}
	}
}

// TestBrandedWithNoProxyAddress: with no usable PROXY_IP a Branded block answers
// 0.0.0.0 with the Block TTL and no Grant, never the true answer and never an error.
func TestBrandedWithNoProxyAddress(t *testing.T) {
	fx, env := baseEnv(t)
	st := fx.Endpoints["e-qm-branded"].Base
	in := inputFor("bl.example", policy.TypeA, "e-qm-branded")
	env.Self.ProxyDown, env.Self.PeerProxyUsable = true, false
	f := policy.Decide(context.Background(), &in, st, &env, stubResolver{})
	if f.WantGrant || f.Answer.RCode != policy.RCodeNoError || len(f.Answer.Answer) != 1 || f.Answer.Answer[0].Type != policy.TypeA || !bytes.Equal(f.Answer.Answer[0].Data, []byte{0, 0, 0, 0}) {
		t.Fatalf("branded block with no proxy address: %+v want_grant=%v", f.Answer, f.WantGrant)
	}
	// AAAA stays NODATA, as in every Branded answer.
	in6 := inputFor("bl.example", policy.TypeAAAA, "e-qm-branded")
	f = policy.Decide(context.Background(), &in6, st, &env, stubResolver{})
	if f.WantGrant || len(f.Answer.Answer) != 0 || f.Answer.RCode != policy.RCodeNoError {
		t.Errorf("AAAA: %+v", f.Answer)
	}
}

// TestProxyAnswerTTLCap: a Redirect or Block TTL above MaxProxyTTL is cut in the
// answer that carries PROXY_IPs, and only there.
func TestProxyAnswerTTLCap(t *testing.T) {
	proxy := []netip.Addr{netip.MustParseAddr("198.51.100.1")}
	n := names.MustString("x.example")
	for _, c := range []struct {
		name string
		in   policy.SynthIn
		want uint32
	}{
		{"redirect 86400", policy.SynthIn{Name: n, QType: policy.TypeA, Action: policy.ActionRedirect, TargetKind: policy.TargetLocation, Eff: &blob.Effective{RedirectTTL: 86400}, Proxy: proxy}, policy.MaxProxyTTL},
		{"redirect 60", policy.SynthIn{Name: n, QType: policy.TypeA, Action: policy.ActionRedirect, TargetKind: policy.TargetLocation, Eff: &blob.Effective{RedirectTTL: 60}, Proxy: proxy}, 60},
		{"redirect 3600", policy.SynthIn{Name: n, QType: policy.TypeA, Action: policy.ActionRedirect, TargetKind: policy.TargetLocation, Eff: &blob.Effective{RedirectTTL: 3600}, Proxy: proxy}, 3600},
		{"branded 7200", policy.SynthIn{Name: n, QType: policy.TypeA, Action: policy.ActionBlock, Eff: &blob.Effective{BlockResponse: blob.BlockBranded, BlockTTL: 7200}, Proxy: proxy}, policy.MaxProxyTTL},
	} {
		out := policy.Synthesize(&c.in)
		if !out.WantGrant || len(out.Answer.Answer) != 1 || out.Answer.Answer[0].TTL != c.want {
			t.Errorf("%s: %+v want ttl %d", c.name, out, c.want)
		}
	}
	// The 0.0.0.0 of a Branded block with no address keeps the Block TTL: it is no
	// proxy answer and no Grant stands behind it.
	out := policy.Synthesize(&policy.SynthIn{Name: n, QType: policy.TypeA, Action: policy.ActionBlock, Eff: &blob.Effective{BlockResponse: blob.BlockBranded, BlockTTL: 7200}})
	if out.WantGrant || len(out.Answer.Answer) != 1 || out.Answer.Answer[0].TTL != 7200 {
		t.Errorf("branded with no address: %+v", out)
	}
}

// TestAcceptGrantReturnsTheReceiversFinal: the receiver stores its own pick mode,
// widening and page hash, not the sender's.
func TestAcceptGrantReturnsTheReceiversFinal(t *testing.T) {
	fx, env := baseEnv(t)
	in := inputFor("auto.example", policy.TypeA, "e-loc")
	f, ok := policy.AcceptGrant(&in, fx.Endpoints["e-loc"].Base, &env, stubResolver{}, policy.GrantOffer{Kind: policy.GrantRedirect, Location: 1})
	if !ok || f.Target != policy.TargetAuto || f.Location != 2 || len(f.Effective) == 0 {
		t.Errorf("auto: ok=%v target=%v location=%d effective=%v", ok, f.Target, f.Location, f.Effective)
	}
	in = inputFor("bl.example", policy.TypeA, "e-qm-branded")
	f, ok = policy.AcceptGrant(&in, fx.Endpoints["e-qm-branded"].Base, &env, stubResolver{}, policy.GrantOffer{Kind: policy.GrantBlockPage})
	if !ok || f.GrantKind != policy.GrantBlockPage {
		t.Errorf("branded: ok=%v kind=%d", ok, f.GrantKind)
	}
	// A refused offer still hands back the receiver's result.
	in = inputFor("unlisted.test", policy.TypeA, "e-loc")
	f, ok = policy.AcceptGrant(&in, fx.Endpoints["e-loc"].Base, &env, stubResolver{}, policy.GrantOffer{Kind: policy.GrantRedirect, Location: 2})
	if ok || f.Action != policy.ActionBypass {
		t.Errorf("a name that is no Redirect here: ok=%v action=%v", ok, f.Action)
	}
}

// B1-r1-6: when the proxy is down and the peer is not usable, the LocationView has no
// location, so every Redirect that goes to a proxy (a location, Auto, Random) is Bypass
// with location_unavailable for every qtype. It must not depend on the order in which
// the node reads the LocationView and the Env.
func TestRedirectToAProxyIsBypassWhenNoProxyAddressIsUsable(t *testing.T) {
	fx, env := baseEnv(t)
	st := fx.Endpoints["e-loc"].Base
	down := env
	down.Self.ProxyDown, down.Self.PeerProxyUsable = true, false
	for _, name := range []string{"loc.example", "auto.example", "rand.example"} {
		for _, qt := range []uint16{policy.TypeA, policy.TypeAAAA, policy.TypeHTTPS} {
			in := inputFor(name, qt, "e-loc")
			if f := policy.Decide(context.Background(), &in, st, &env, stubResolver{}); f.Action != policy.ActionRedirect {
				t.Fatalf("control %s/%d: %v", name, qt, f.Action)
			}
			f := policy.Decide(context.Background(), &in, st, &down, stubResolver{})
			if f.Action != policy.ActionBypass || f.Flags&policy.FlagLocationUnavailable == 0 || f.WantGrant || f.Answer.RCode == policy.RCodeServFail {
				t.Errorf("%s/%d with no usable proxy address: action %v flags %v rcode %d grant %v", name, qt, f.Action, f.Flags, f.Answer.RCode, f.WantGrant)
			}
		}
	}
}
