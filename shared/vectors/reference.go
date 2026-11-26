package vectors

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/Kup1ng/CtrlZ-Shared/names"
	"github.com/Kup1ng/CtrlZ-Shared/policy"
	"github.com/Kup1ng/CtrlZ-Shared/sysnames"
)

// Reference is the harness the panel runs. It wires the shared packages the
// way node glue does: system names first, then stack selection, Pre, one
// lookup and Post. The node's own harness must give the same outcomes.
type Reference struct{}

type refEval struct {
	fx  *Fixture
	env policy.Env
	sys *sysnames.Matcher
}

type fixtureGeo struct {
	country map[netip.Addr][2]byte
	asn     map[netip.Addr]uint32
}

func (g fixtureGeo) Country(a netip.Addr) [2]byte { return g.country[a] }
func (g fixtureGeo) ASN(a netip.Addr) uint32      { return g.asn[a] }

type fixtureLocs struct {
	healthy map[uint16]bool
	latency map[uint16]uint32
}

func (l fixtureLocs) Healthy(w uint16) bool { return l.healthy[w] }

// Auto picks the lowest latency, then the lowest wire id. candidates arrive
// sorted ascending, so the first minimum is the lowest id.
func (l fixtureLocs) Auto(c []uint16) (uint16, bool) {
	if len(c) == 0 {
		return 0, false
	}
	best, bestLat := c[0], l.lat(c[0])
	for _, w := range c[1:] {
		if x := l.lat(w); x < bestLat {
			best, bestLat = w, x
		}
	}
	return best, true
}

func (l fixtureLocs) lat(w uint16) uint32 {
	if v, ok := l.latency[w]; ok {
		return v
	}
	return 1 << 30
}

// Prepare implements Harness.
func (Reference) Prepare(fx *Fixture) (Evaluator, error) {
	env, panel, err := fx.Env()
	if err != nil {
		return nil, err
	}
	return &refEval{fx: fx, sys: sysnames.NewMatcher(panel), env: env}, nil
}

// Env builds the evaluator environment (geo, locations, own addresses and the
// catalog) the fixture describes, and the panel hostnames the system-names
// step needs. Another harness can reuse it.
func (fx *Fixture) Env() (policy.Env, []names.Name, error) {
	f := fx.File
	geo := fixtureGeo{country: map[netip.Addr][2]byte{}, asn: map[netip.Addr]uint32{}}
	for ip, cc := range f.Geo.Country {
		a, err := netip.ParseAddr(ip)
		if err != nil || len(cc) != 2 {
			return policy.Env{}, nil, fmt.Errorf("geo country %q=%q", ip, cc)
		}
		geo.country[a] = [2]byte{cc[0], cc[1]}
	}
	for ip, as := range f.Geo.ASN {
		a, err := netip.ParseAddr(ip)
		if err != nil {
			return policy.Env{}, nil, err
		}
		geo.asn[a] = as
	}
	locs := fixtureLocs{healthy: map[uint16]bool{}, latency: map[uint16]uint32{}}
	for _, w := range f.Locations.Healthy {
		locs.healthy[w] = true
	}
	for k, v := range f.Locations.Latency {
		n, err := strconv.ParseUint(k, 10, 16)
		if err != nil {
			return policy.Env{}, nil, err
		}
		locs.latency[uint16(n)] = v
	}
	self := policy.SelfAddrs{PeerProxyUsable: f.Self.PeerUsable}
	for _, p := range []struct {
		s string
		d *netip.Addr
	}{{f.Self.DNSIP, &self.DNSIP}, {f.Self.ProxyIP, &self.ProxyIP}, {f.Self.PeerProxyIP, &self.PeerProxyIP}} {
		if p.s == "" {
			continue
		}
		a, err := netip.ParseAddr(p.s)
		if err != nil {
			return policy.Env{}, nil, err
		}
		*p.d = a
	}
	var panel []names.Name
	for _, h := range f.Self.PanelHostnames {
		n, err := names.FromString(h)
		if err != nil {
			return policy.Env{}, nil, err
		}
		panel = append(panel, n)
	}
	never, err := neverProxied(f.Catalog.NoRedirect)
	if err != nil {
		return policy.Env{}, nil, err
	}
	return policy.Env{Cat: fx.Catalog, Geo: geo, Locs: locs, Self: self, NeverProxied: never}, panel, nil
}

// neverProxied is the reference harness's predicate for D42 (contract 10.5): a name
// is Iranian when it is at or under .ir or .xn--mgba3a4f16a (.ایران), at or under a
// domain entry, or equal to a host entry. It is a stand-in for the shared
// noredirect.Name of the P2 build, which the node and Domain Test pass in
// production; it lives here, in a test-only package, so this module needs no
// import of P2's package to pin the evaluator. When that package is merged, the
// harness should call it instead.
func neverProxied(rows []string) (func(names.Name) bool, error) {
	domain, host := map[string]bool{}, map[string]bool{}
	for _, r := range rows {
		m := domain
		if t, ok := strings.CutPrefix(r, "host:"); ok {
			r, m = t, host
		}
		n, err := names.FromString(r)
		if err != nil {
			return nil, fmt.Errorf("no_redirect %q: %w", r, err)
		}
		m[n.String()] = true
	}
	return func(n names.Name) bool {
		if n.Labels() == 0 {
			return false
		}
		if tld := string(n.Label(n.Labels() - 1)); tld == "ir" || tld == "xn--mgba3a4f16a" {
			return true
		}
		for k := 1; k <= n.Labels(); k++ {
			s, err := names.FromCanonicalWire(n.SuffixWire(k))
			if err != nil {
				continue
			}
			if domain[s.String()] || (k == n.Labels() && host[s.String()]) {
				return true
			}
		}
		return false
	}, nil
}

// Evaluate implements Evaluator.
func (e *refEval) Evaluate(ctx context.Context, r *Request) (*Outcome, error) {
	ep, ok := e.fx.Endpoints[r.Endpoint]
	if !ok {
		return nil, fmt.Errorf("unknown endpoint %q (have %v)", r.Endpoint, e.fx.sortedEndpoints())
	}
	in := r.Input
	if r.NoPolicy {
		return e.defaultOutcome(ctx, &in, r), nil
	}
	// Pipeline step 2: system names come before identity and any profile (R24).
	if ent, ok := e.sys.Lookup(&in.Name, in.QType, r.Isolated); ok {
		return e.systemOutcome(ctx, &in, ent, r), nil
	}
	st, _ := policy.SelectStack(ep, r.ClientHash, in.Now)
	f, pre := policy.DecideWithPre(ctx, &in, st, &e.env, r.Resolver)
	return &Outcome{PreDone: pre.Done, Deferred: pre.Deferred, Walk: pre.Walk, Final: f}, nil
}

// systemOutcome answers a system name. Policy never sees these queries.
func (e *refEval) systemOutcome(ctx context.Context, in *policy.Input, ent sysnames.Entry, r *Request) *Outcome {
	f := policy.Final{Action: policy.ActionBypass, Stage: policy.StageSystem, Ref: policy.Ref{Kind: policy.RefSystem}, Widenable: true}
	synthDNSIP := func() policy.Answer {
		if in.QType == policy.TypeA && e.env.Self.DNSIP.Is4() {
			a := e.env.Self.DNSIP.As4()
			return policy.Answer{Answer: []policy.RR{{Name: in.Name, Type: policy.TypeA, Class: policy.ClassIN, TTL: ent.TTL, Data: a[:]}}}
		}
		return policy.Answer{Authority: []policy.RR{policy.SyntheticSOA(in.Name, ent.TTL)}}
	}
	switch ent.Outcome {
	case sysnames.OutcomeTrue:
		ta, err := r.Resolver.Lookup(ctx, in.Name, in.QType, policy.ResolveParams{EffectiveCD: in.CD})
		switch {
		case err != nil || ta == nil || ta.Failed:
			if ent.FallbackSynth {
				f.Answer = synthDNSIP()
			} else {
				f.Answer = policy.Answer{RCode: policy.RCodeServFail}
			}
		default:
			f.Answer = policy.Answer{RCode: ta.RCode, Answer: ta.Answer, Authority: ta.Authority,
				AD: ta.Validation == policy.Secure && !in.CD && (in.DO || in.AD)}
		}
	case sysnames.OutcomeSynthDNSIP:
		f.Answer = synthDNSIP()
	case sysnames.OutcomeLocal:
		if len(ent.Records) == 0 {
			f.Answer = policy.Answer{Authority: []policy.RR{policy.SyntheticSOA(in.Name, ent.TTL)}}
			break
		}
		for _, rec := range ent.Records {
			f.Answer.Answer = append(f.Answer.Answer, policy.RR{Name: in.Name, Type: rec.Type, Class: policy.ClassIN, TTL: ent.TTL, Data: rec.RData})
		}
	case sysnames.OutcomeNXDomain:
		f.Answer = policy.Answer{RCode: policy.RCodeNXDomain, Authority: []policy.RR{policy.SyntheticSOA(in.Name, ent.TTL)}}
	}
	return &Outcome{Final: f, Wildcard: ent.Wildcard}
}

// defaultOutcome is the path with no policy: the caller resolves the name as the
// glue does (the client's CD, no ECS, ANY never resolved) and PostDefault shapes
// the answer. The Endpoint's profile is not read.
func (e *refEval) defaultOutcome(ctx context.Context, in *policy.Input, r *Request) *Outcome {
	var ans *policy.TrueAnswer
	if in.QType != policy.TypeANY {
		var err error
		ans, err = r.Resolver.Lookup(ctx, in.Name, in.QType, policy.ResolveParams{EffectiveCD: in.CD})
		if err != nil || ans == nil {
			ans = &policy.TrueAnswer{Failed: true, RCode: policy.RCodeServFail}
		}
	}
	return &Outcome{Final: policy.PostDefault(in, ans)}
}
