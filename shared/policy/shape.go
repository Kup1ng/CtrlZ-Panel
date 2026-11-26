package policy

import (
	"context"

	"github.com/Kup1ng/CtrlZ-Shared/names"
	"github.com/Kup1ng/CtrlZ-Shared/netclass"
)

// rewriteNegTTL is the TTL of the NODATA given to HTTPS and SVCB on a Safe
// Search rewritten name. There is no action TTL for a rewrite, so it uses the
// Block TTL default; provisional with the other TTLs (D31).
const rewriteNegTTL = 60

func copyRRs(in []RR) []RR {
	if in == nil {
		return nil
	}
	return append([]RR(nil), in...)
}

// shapeBypass builds the answer for a Bypass or default outcome from the true
// answer, in the contract's order (5.8 step 5). Each step works on a copy, so
// nothing here can reach the shared cache, and the result is per tenant.
//
//  1. Safe Search and Restricted YouTube rewrite
//  2. Rebind check
//  3. DNS64
//  4. CNAME Flattening
//  5. TTL override
//  6. ECS echo
//  7. DNSSEC shaping
func (ev *eval) shapeBypass(ctx context.Context, f *Final, ans *TrueAnswer, r Resolver) {
	in := ev.in
	if in.QType == TypeANY {
		// RFC 8482: one HINFO, not the full set. Cheaper, and it denies an
		// amplification vector.
		f.Answer = HINFOAnswer(in.Name)
		return
	}
	if ans == nil || ans.Failed {
		f.Answer = Answer{RCode: RCodeServFail}
		return
	}
	// A Bogus answer with CD off is SERVFAIL and decides nothing else (5.11). The
	// check comes before Rebind, DNS64 and every other step, so a forged answer
	// cannot pick Block over SERVFAIL by what it contains, or feed them.
	if ev.bogusRefused(ans) {
		f.Answer = Answer{RCode: RCodeServFail}
		return
	}
	out := Answer{RCode: ans.RCode, Answer: copyRRs(ans.Answer), Authority: copyRRs(ans.Authority)}
	val := ans.Validation
	modified := false // synthesized or rewritten: signatures and AD no longer hold
	// rewritten is the Safe Search target when step 1 replaced an AAAA answer.
	// DNS64 must look up the A set of that name and not of the qname, or an AAAA
	// query would reach the unrestricted address through the NAT64 prefix.
	var rewritten names.Name
	isRewritten := false

	// 1. Rewrite.
	if target, ok := ev.rewriteTarget(in.Name); ok {
		switch in.QType {
		case TypeA, TypeAAAA:
			var t *TrueAnswer
			if r != nil {
				t, _ = r.Lookup(ctx, target, in.QType, ev.params)
			}
			f.Flags |= FlagSafeSearch
			// A Bogus target is refused here, before Rebind sees it: a forged
			// private address must not pick Block over SERVFAIL (5.11).
			if t == nil || t.Failed || ev.bogusRefused(t) {
				f.Answer = Answer{RCode: RCodeServFail}
				return
			}
			rewritten, isRewritten = target, in.QType == TypeAAAA
			out = Answer{RCode: t.RCode, Authority: copyRRs(t.Authority)}
			for _, rr := range t.Answer {
				if rr.Type == in.QType {
					rr.Name = in.Name
					out.Answer = append(out.Answer, rr)
				}
			}
			val = t.Validation
			modified = true
		case TypeHTTPS, TypeSVCB:
			// The safe host has its own HTTPS record, if any; handing the
			// client the original's would let it bypass the rewrite.
			f.Flags |= FlagSafeSearch
			out = negative(in.Name, RCodeNoError, rewriteNegTTL)
			modified = true
		}
	}

	// 2. Rebind. Stage default only: an explicit Bypass is the user's own
	// declaration that this name may point at their intranet. A Redirect that
	// fell back to Bypass because its location is unavailable is not that
	// declaration, even though it carries the stage of its rule, geo or
	// service match, so Rebind applies to it too.
	rebind := ev.eff.Rebind && (f.Stage == StageDefault || f.Flags&FlagLocationUnavailable != 0)
	blockRebind := func() {
		so := Synthesize(&SynthIn{Name: in.Name, QType: in.QType, Action: ActionBlock, Eff: ev.eff, Proxy: ev.proxyIPs()})
		f.Action = ActionBlock
		f.Flags |= FlagRebindBlocked
		f.Answer, f.WantGrant, f.GrantKind = so.Answer, so.WantGrant, so.GrantKind
	}
	if rebind && out.RCode == RCodeNoError && hasPrivateAddr(out.Answer) {
		blockRebind()
		return
	}

	// 3. DNS64: only for a Bypass or default AAAA that came back empty. Never
	// on Block or Redirect (R23), which do not reach this function.
	if ev.eff.DNS64 && in.QType == TypeAAAA && out.RCode == RCodeNoError && !hasType(out.Answer, TypeAAAA) && r != nil {
		// A Bogus A lookup counts as a failed one: nothing is synthesized from a
		// forged address, and the client keeps the true NODATA.
		lookupName := in.Name
		if isRewritten {
			lookupName = rewritten
		}
		if t, err := r.Lookup(ctx, lookupName, TypeA, ev.params); err == nil && t != nil && !t.Failed && t.RCode == RCodeNoError && !ev.bogusRefused(t) {
			// The A set is what the client will end up connecting to once the
			// NAT64 translates it, so it gets the Rebind check before it is
			// hidden behind a 64:ff9b:: prefix.
			if rebind && hasPrivateAddr(t.Answer) {
				blockRebind()
				return
			}
			var syn []RR
			found := false
			for _, rr := range t.Answer {
				switch rr.Type {
				case TypeCNAME:
					// Step 1 keeps only records of the query type, so on a
					// rewritten name the target's chain stays out here too.
					if !isRewritten {
						syn = append(syn, rr)
					}
				case TypeA:
					if len(rr.Data) == 4 {
						if isRewritten {
							rr.Name = in.Name
						}
						d := make([]byte, 16)
						copy(d, []byte{0x00, 0x64, 0xff, 0x9b}) // 64:ff9b::/96
						copy(d[12:], rr.Data)
						rr.Type, rr.Data = TypeAAAA, d
						syn = append(syn, rr)
						found = true
					}
				}
			}
			if found {
				out.Answer, out.Authority = syn, nil
				modified = true
			}
		}
	}

	// 4. CNAME Flattening: A and AAAA only. The answer is placed at the qname,
	// and its TTL is the minimum over the chain, so the flattened record never
	// outlives the shortest link it replaced.
	if ev.eff.Flatten && (in.QType == TypeA || in.QType == TypeAAAA) && hasType(out.Answer, TypeCNAME) && hasType(out.Answer, in.QType) {
		min := uint32(0xFFFFFFFF)
		for _, rr := range out.Answer {
			if rr.Type != TypeRRSIG && rr.TTL < min {
				min = rr.TTL
			}
		}
		var flat []RR
		for _, rr := range out.Answer {
			if rr.Type == in.QType {
				rr.Name, rr.TTL = in.Name, min
				flat = append(flat, rr)
			}
		}
		out.Answer = flat
		modified = true
	}

	// 5. TTL override replaces every answer TTL.
	if ev.eff.HasBypassTTL {
		for i := range out.Answer {
			out.Answer[i].TTL = ev.eff.BypassTTL
		}
	}

	// 6. ECS echo, only when the query went upstream with ECS.
	if ev.params.ECS.IsValid() {
		out.ECS = &ECSEcho{Source: ev.params.ECS, Scope: ans.ECSScope}
	}

	// 7. DNSSEC shaping (5.11). The answer was checked at the top; this covers
	// the validation state of a Safe Search target, which replaced it.
	if val == Bogus && !ev.params.EffectiveCD {
		f.Answer = Answer{RCode: RCodeServFail}
		return
	}
	out.AD = !modified && val == Secure && !ev.params.EffectiveCD && (in.DO || in.AD)
	if !in.DO || modified {
		out.Answer = stripDNSSEC(out.Answer, !in.DO)
		out.Authority = stripDNSSEC(out.Authority, !in.DO)
	}
	f.Answer = out
}

// hasPrivateAddr reports whether any A or AAAA record, or any address hint of an
// HTTPS or SVCB record, holds an address Rebind treats as private. A client may
// connect to a hint without ever asking for the A record.
func hasPrivateAddr(rrs []RR) bool {
	for i := range rrs {
		if a, ok := rrs[i].Addr(); ok && netclass.RebindPrivate(a) {
			return true
		}
		if rrs[i].Type == TypeHTTPS || rrs[i].Type == TypeSVCB {
			for _, a := range svcHints(rrs[i].Data) {
				if netclass.RebindPrivate(a) {
					return true
				}
			}
		}
	}
	return false
}

func hasType(rrs []RR, t uint16) bool {
	for i := range rrs {
		if rrs[i].Type == t {
			return true
		}
	}
	return false
}

// stripDNSSEC removes RRSIG always, and NSEC and NSEC3 too when denial is true.
// An answer we modified keeps its denial records (they still describe the zone
// truthfully) but loses its signatures, which no longer verify.
func stripDNSSEC(rrs []RR, denial bool) []RR {
	out := rrs[:0:0]
	for _, rr := range rrs {
		switch rr.Type {
		case TypeRRSIG:
			continue
		case TypeNSEC, TypeNSEC3:
			if denial {
				continue
			}
		}
		out = append(out, rr)
	}
	return out
}
