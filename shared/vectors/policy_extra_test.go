package vectors

import (
	"context"
	"net/netip"
	"testing"

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
		if got := policy.AcceptGrant(&in, st, &env, stubResolver{}, c.offer); got != c.want {
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
	if !policy.AcceptGrant(&in, st, &env, stubResolver{}, offer) {
		t.Fatal("control: the offer is refused with a proxy address")
	}
	env.Self.ProxyIP = netip.Addr{}
	env.Self.PeerProxyIP = netip.Addr{}
	if policy.AcceptGrant(&in, st, &env, stubResolver{}, offer) {
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
	if f.Answer.RCode != policy.RCodeServFail || f.WantGrant {
		t.Fatalf("no proxy address at all must fail loudly, not answer with nothing: %+v", f.Answer)
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
