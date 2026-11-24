package policy

import (
	"bytes"
	"context"
	"net/netip"

	"github.com/Kup1ng/CtrlZ-Shared/blob"
	"github.com/Kup1ng/CtrlZ-Shared/locations"
	"github.com/Kup1ng/CtrlZ-Shared/names"
)

// MaxCNAMEHops bounds the CNAME walk, and wire.MaxCNAMEChain follows it. A
// resolver stops long before this; the cap only keeps a hostile or buggy
// TrueAnswer from costing unbounded work.
const MaxCNAMEHops = 32

// Pre runs everything that needs no DNS answer: the options, custom rules,
// source-country rules and, when the profile has no destination-geo rules,
// service rules, filters and the Default Rule.
//
// If the stack has a destination-geo rule, Pre stops after level 1 and returns
// Deferred. A source-country rule must not return early in that case, because
// a destination rule ranks above it (5.8).
func Pre(in *Input, st *Stack, env *Env) PreResult {
	return newEval(in, st, env).pre()
}

func (ev *eval) pre() PreResult {
	res := PreResult{Params: ev.params}
	res.Opts = ev.activeOptions()
	ev.qc = ev.newName(&ev.in.Name)

	if ev.nact == 0 {
		// No profile in force: default options and a plain Bypass, no CNAME walk.
		d := decision{hit: true, action: ActionBypass, stage: StageDefault, ref: Ref{Kind: RefDefault}, target: blob.NoTarget, widenable: true}
		res.Final = ev.seal(ev.baseFinal(d))
		return res
	}
	if d := ev.level1(ev.qc); d.hit {
		return ev.conclude(res, d)
	}
	if ev.st.HasDestGeo {
		res.Deferred = true
		res.Final = ev.baseFinal(decision{})
		res.Final.Flags |= FlagDeferred
		res.Final = ev.seal(res.Final)
		return res
	}
	// Source tokens only exist on this path, so there is no answer to wait for.
	if d := ev.level2(func() []netip.Addr { return nil }); d.hit {
		return ev.conclude(res, d)
	}
	if d := ev.level3(ev.qc); d.hit {
		return ev.conclude(res, d)
	}
	if d := ev.level4(ev.qc, true); d.hit {
		return ev.conclude(res, d)
	}
	d := ev.defaultDecision()
	ev.tr(5, StageDefault, d.slot, true, "default")
	if !ev.st.Explicit && (d.action == ActionBlock || d.action == ActionRedirect) {
		// Nothing a CNAME hop could match, so the answer need not be fetched.
		return ev.conclude(res, d)
	}
	res.Walk = true
	res.held = d
	res.Final = ev.seal(ev.baseFinal(d))
	return res
}

// conclude turns a decision made in Pre into a PreResult.
func (ev *eval) conclude(res PreResult, d decision) PreResult {
	f, comp := ev.complete(d, nil)
	switch comp {
	case compDone:
		res.Done = true
	case compNeedHost:
		res.SynthOnly = true
		res.held = d
	}
	res.Final = ev.seal(f)
	return res
}

// Post finishes a query after the true answer is known. ans may be nil only
// when pre.SynthOnly is set. Post calls r.Lookup only for the A set of 5.8,
// the Safe Search target, the DNS64 A lookup and the Redirect host target;
// those read through the cache, and nothing Post builds is written to it.
func Post(ctx context.Context, in *Input, st *Stack, env *Env, pre *PreResult, ans *TrueAnswer, r Resolver) Final {
	ev := newEval(in, st, env)
	ev.qc = ev.newName(&ev.in.Name)
	return ev.post(ctx, pre, ans, r)
}

func (ev *eval) post(ctx context.Context, pre *PreResult, ans *TrueAnswer, r Resolver) Final {
	ev.trace = pre.Final.Trace
	if pre.SynthOnly {
		return ev.finish(ctx, pre.held, nil, r)
	}
	var d decision
	walk := pre.Walk
	switch {
	case pre.Deferred:
		d, walk = ev.levels2to5(ctx, ans, r)
	case pre.Walk:
		d = pre.held
	default:
		// Pre already reached a Bypass verdict (explicit match, no profile in
		// force, or an unavailable location). Only the shaping remains.
		f := pre.Final
		ev.shapeBypass(ctx, &f, ans, r)
		return ev.seal(f)
	}
	// A Bogus answer is SERVFAIL when CD is off (5.11), so it must not choose a
	// policy outcome either: an on-path forger could otherwise pick the verdict
	// with a chain that ends at a blocked or redirected name (review L2-F18).
	if walk && ans != nil && !ans.Failed && !ev.bogusRefused(ans) {
		// Runs on every cache hit too, because the result is per tenant and is
		// never stored (5.10).
		for i := 1; i < len(ans.Chain) && i <= MaxCNAMEHops; i++ {
			hop := ans.Chain[i]
			if hd := ev.explicitMatch(&hop); hd.hit {
				hd.hop, hd.hopSet = uint8(i), true
				d = hd
				ev.tr(0, d.stage, d.slot, true, "cname hop")
				break
			}
		}
	}
	return ev.finish(ctx, d, ans, r)
}

// bogusRefused reports whether an answer fails DNSSEC validation and the query
// does not ask to skip validation. Such an answer is SERVFAIL in the output
// (5.11), and nothing in it may be used to decide.
func (ev *eval) bogusRefused(a *TrueAnswer) bool {
	return a != nil && a.Validation == Bogus && !ev.params.EffectiveCD
}

// levels2to5 runs the deferred part in full order: geo, services, filters,
// exfiltration, default. reached5 means nothing explicit matched, so the CNAME
// walk applies.
func (ev *eval) levels2to5(ctx context.Context, ans *TrueAnswer, r Resolver) (decision, bool) {
	if d := ev.level2(func() []netip.Addr { return ev.destAddrs(ctx, ans, r) }); d.hit {
		return d, false
	}
	if d := ev.level3(ev.qc); d.hit {
		return d, false
	}
	if d := ev.level4(ev.qc, true); d.hit {
		return d, false
	}
	d := ev.defaultDecision()
	ev.tr(5, StageDefault, d.slot, true, "default")
	return d, true
}

// finish turns a final decision into a Final.
func (ev *eval) finish(ctx context.Context, d decision, ans *TrueAnswer, r Resolver) Final {
	fetch := func() *TrueAnswer {
		if r == nil {
			return nil
		}
		qt := uint16(TypeA)
		if ev.in.QType == TypeAAAA {
			qt = TypeAAAA
		}
		// The target host is resolved like any name: through the cache, with
		// the same CD and ECS as the query.
		h, err := r.Lookup(ctx, ev.hostTarget(d), qt, ev.params)
		if err != nil {
			return nil
		}
		return h
	}
	f, comp := ev.complete(d, fetch)
	if comp == compBypass {
		ev.shapeBypass(ctx, &f, ans, r)
	}
	return ev.seal(f)
}

// Decide is Pre, one lookup, Post. It is what Domain Test, More Info and the
// filter preview call. The node calls Pre and Post itself so it can put its
// cache and router between them.
func Decide(ctx context.Context, in *Input, st *Stack, env *Env, r Resolver) Final {
	f, _ := DecideWithPre(ctx, in, st, env, r)
	return f
}

// DecideWithPre is Decide that also returns what Pre decided, so the golden
// vectors can pin the Done, Deferred and Walk flags too.
func DecideWithPre(ctx context.Context, in *Input, st *Stack, env *Env, r Resolver) (Final, PreResult) {
	pre := Pre(in, st, env)
	if pre.Done {
		return pre.Final, pre
	}
	var ans *TrueAnswer
	if !pre.SynthOnly {
		if in.QType == TypeANY {
			// ANY is never resolved: Bypass answers it with HINFO (RFC 8482).
			ans = &TrueAnswer{Chain: []names.Name{in.Name}}
		} else {
			a, err := r.Lookup(ctx, in.Name, in.QType, pre.Params)
			if err != nil || a == nil {
				a = &TrueAnswer{Failed: true, RCode: RCodeServFail}
			}
			ans = a
		}
	}
	return Post(ctx, in, st, env, &pre, ans, r), pre
}

// GrantOffer is what a peer forwarded in a GrantForward that the receiver can
// check against its own decision. It is a value, so a caller cannot forget a
// field: a missing dial host means "none", and is compared like any other.
type GrantOffer struct {
	Kind     uint8      // GrantRedirect or GrantBlockPage
	Location uint16     // the location the sender chose; ignored for a block page
	DialHost names.Name // the safe host the proxy would dial; the zero Name means none
}

// AcceptGrant is the receiver side of a forwarded Grant (10.3). It runs Decide
// again with the receiver's own state and accepts only an offer that matches
// what the receiver would have granted itself:
//
//   - the same grant kind (a Redirect grants kind 1, a Branded block kind 2),
//     and a proxy answer actually given (WantGrant);
//   - for a Redirect, the carried location is the receiver's fixed target or
//     inside the set its own Auto or Random drew from. An identical pick is not
//     required: two nodes see different latencies and health, and rejecting a
//     grant for that would break the connection the client already made;
//   - the dial host equals the receiver's own Final.DialHost. The sender does
//     not get to choose where the receiver's proxy connects, and a Safe Search
//     host cannot be dropped by leaving it out.
//
// A receiver behind the sender's config_seq keeps the grant short until it
// catches up; that stays in the receiver's glue.
func AcceptGrant(in *Input, st *Stack, env *Env, r Resolver, offer GrantOffer) bool {
	f := Decide(context.Background(), in, st, env, r)
	if !f.WantGrant || !bytes.Equal(f.DialHost.Wire(), offer.DialHost.Wire()) {
		return false
	}
	switch f.Action {
	case ActionBlock:
		// A Branded block page: every node serves the same page, so there is no
		// location to compare.
		return offer.Kind == GrantBlockPage
	case ActionRedirect:
		if offer.Kind != GrantRedirect {
			return false
		}
		if f.Target == TargetLocation {
			return f.Location == offer.Location
		}
		for _, l := range f.Effective {
			if l == offer.Location {
				return true
			}
		}
	}
	return false
}

// ---- completion ---------------------------------------------------------------

type completion uint8

const (
	compDone     completion = iota // Final is complete
	compBypass                     // Bypass: the true answer is needed
	compNeedHost                   // Redirect host: needs the host's records first
)

func (ev *eval) activeOptions() *blob.Options {
	switch {
	case ev.active[0] && ev.active[1]:
		return ev.st.Merged
	case ev.active[0]:
		return ev.st.Slots[0].Options()
	case ev.active[1]:
		return ev.st.Slots[1].Options()
	}
	return &blob.Options{}
}

// baseFinal copies a decision into a Final with no answer.
func (ev *eval) baseFinal(d decision) Final {
	f := Final{
		Action: d.action, Stage: d.stage, Ref: d.ref, Slot: d.slot,
		Widenable: d.widenable, Flags: d.flags, HopIndex: d.hop,
	}
	if d.hopSet {
		f.Flags |= FlagViaCNAME
	}
	return f
}

// seal adds what every outcome carries: the traffic category (the lookup
// always runs, R39), the trace and the table-health flag.
func (ev *eval) seal(f Final) Final {
	f.TrafficCat = ev.trafficCat(ev.qc)
	f.Trace = ev.trace
	f.TableMissing = ev.missing
	return f
}

func (ev *eval) proxyIPs() []netip.Addr {
	var out []netip.Addr
	if ev.env.Self.ProxyIP.IsValid() {
		out = append(out, ev.env.Self.ProxyIP)
	}
	if ev.env.Self.PeerProxyIP.IsValid() && ev.env.Self.PeerProxyUsable {
		out = append(out, ev.env.Self.PeerProxyIP)
	}
	return out
}

// hostTarget returns the Redirect host name of a decision.
func (ev *eval) hostTarget(d decision) names.Name {
	p := ev.st.Slots[d.slot-1]
	t := p.Target(d.target)
	n, _ := names.FromCanonicalWire(p.Str(t.HostOff, t.HostLen))
	return n
}

// complete resolves the target of a Redirect (10.2), synthesizes Block and
// Redirect answers, and reports what is still needed. fetch supplies the
// redirect host's records and is nil in Pre.
func (ev *eval) complete(d decision, fetch func() *TrueAnswer) (Final, completion) {
	f := ev.baseFinal(d)
	switch d.action {
	case ActionBlock:
		out := Synthesize(&SynthIn{Name: ev.in.Name, QType: ev.in.QType, Action: ActionBlock, Eff: ev.eff, Proxy: ev.proxyIPs()})
		f.Answer, f.WantGrant, f.GrantKind = out.Answer, out.WantGrant, out.GrantKind
		return f, compDone
	case ActionRedirect:
		return ev.completeRedirect(d, f, fetch)
	}
	return f, compBypass
}

func (ev *eval) unavailable(f Final) (Final, completion) {
	f.Action = ActionBypass
	f.Flags |= FlagLocationUnavailable
	return f, compBypass
}

func (ev *eval) completeRedirect(d decision, f Final, fetch func() *TrueAnswer) (Final, completion) {
	if d.flags&FlagLocationUnavailable != 0 || d.slot == 0 || d.target == blob.NoTarget {
		return ev.unavailable(f)
	}
	p := ev.st.Slots[d.slot-1]
	tg := p.Target(d.target)
	f.Target = tg.Kind
	in := SynthIn{Name: ev.in.Name, QType: ev.in.QType, Action: ActionRedirect, Eff: ev.eff, TargetKind: tg.Kind}

	switch tg.Kind {
	case TargetLocation:
		if !ev.locAvailable(tg.Location) {
			return ev.unavailable(f)
		}
		f.Location = tg.Location
	case TargetAuto, TargetRandom:
		cands := locations.Candidates(p.LocSet(tg.SetOff), ev.st.PairLocs, ev.healthy)
		if len(cands) == 0 {
			return ev.unavailable(f)
		}
		f.Effective = cands
		if tg.Kind == TargetAuto {
			if ev.env.Locs == nil {
				return ev.unavailable(f)
			}
			loc, ok := ev.env.Locs.Auto(cands)
			if !ok {
				return ev.unavailable(f)
			}
			f.Location = loc
		} else {
			f.Location = locations.RandomPick(cands, ev.in.EndpointID, ev.in.Name.Wire(), ev.in.Now)
		}
	case TargetIP:
		if tg.HasV4 {
			in.V4 = netip.AddrFrom4(tg.V4)
		}
		if tg.HasV6 {
			in.V6 = netip.AddrFrom16(tg.V6)
		}
	case TargetHost:
		h, err := names.FromCanonicalWire(p.Str(tg.HostOff, tg.HostLen))
		if err != nil {
			return ev.unavailable(f)
		}
		in.Host = h
		qt := ev.in.QType
		if qt == TypeANY {
			qt = TypeA
		}
		if qt == TypeA || qt == TypeAAAA {
			if fetch == nil {
				return f, compNeedHost
			}
			in.HostAnswer = fetch()
			// A Bogus host answer with CD off is SERVFAIL (5.11), like a failed
			// Safe Search target: its records must not reach the client.
			if ev.bogusRefused(in.HostAnswer) {
				f.Answer = Answer{RCode: RCodeServFail}
				return f, compDone
			}
		}
	default:
		return ev.unavailable(f)
	}
	in.Proxy = ev.proxyIPs()
	out := Synthesize(&in)
	f.Answer, f.WantGrant, f.GrantKind = out.Answer, out.WantGrant, out.GrantKind
	if f.WantGrant {
		// Safe Search on a redirected name: the proxy dials the safe host, and
		// the answer the client sees is unchanged (R15).
		if t, ok := ev.rewriteTarget(ev.in.Name); ok {
			f.DialHost = t
			f.Flags |= FlagSafeSearch
		}
	}
	return f, compDone
}

func (ev *eval) healthy(id uint16) bool { return ev.env.Locs != nil && ev.env.Locs.Healthy(id) }

// locAvailable: a fixed location is available when it is in the pair's bitmap
// and this node has a working config for it (10.2).
func (ev *eval) locAvailable(id uint16) bool {
	return locations.BitmapHas(ev.st.PairLocs, id) && ev.healthy(id)
}

// rewriteTarget looks the name up in the Safe Search table, then the
// Restricted YouTube table, whichever the profile enables.
func (ev *eval) rewriteTarget(n names.Name) (names.Name, bool) {
	cat := ev.env.Cat
	if cat == nil {
		return names.Name{}, false
	}
	key := string(n.Wire())
	if ev.eff.SafeSearch {
		if t, ok := cat.Rewrite.SafeSearch[key]; ok {
			return t, true
		}
	}
	if ev.eff.RestrictedYouTube {
		if t, ok := cat.Rewrite.YouTube[key]; ok {
			return t, true
		}
	}
	return names.Name{}, false
}
