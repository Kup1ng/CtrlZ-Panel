package policy

import (
	"encoding/binary"
	"net/netip"

	"github.com/Kup1ng/CtrlZ-Shared/blob"
	"github.com/Kup1ng/CtrlZ-Shared/names"
)

// SynthIn is everything Synthesize needs to build a Block or Redirect answer.
type SynthIn struct {
	Name   names.Name
	QType  uint16
	Action Action // ActionBlock or ActionRedirect
	Eff    *blob.Effective

	// Redirect target.
	TargetKind TargetKind
	V4, V6     netip.Addr  // TargetIP
	Host       names.Name  // TargetHost
	HostAnswer *TrueAnswer // the host's own records, for TargetHost; may be nil

	// Proxy holds PROXY_IPs, own first, then the pair peer when usable.
	Proxy []netip.Addr
}

// SynthOut is the synthesized answer.
type SynthOut struct {
	Answer    Answer
	WantGrant bool
	GrantKind uint8
}

// Synthesize is the normative qtype by action table of contract 7 (R26). It
// has no side effects and reads nothing but its input, so the table can be
// checked cell by cell by the qtype-matrix vectors.
//
// Every synthesized answer has QR=1, AA=0, RA=1, AD=0 and no RRSIG, which is
// why none of those appear in Answer. WantGrant is true only when PROXY_IPs
// were placed in the answer: an AAAA, HTTPS or SVCB query never creates a
// Grant, because the client would never connect to what it was given.
func Synthesize(in *SynthIn) SynthOut {
	qt := in.QType
	if qt == TypeANY {
		qt = TypeA // ANY is treated as A (section 0, "ANY on a policy match")
	}
	if in.Action == ActionBlock {
		return synthBlock(in, qt)
	}
	return synthRedirect(in, qt)
}

func synthBlock(in *SynthIn, qt uint16) SynthOut {
	e := in.Eff
	ttl := e.BlockTTL
	switch e.BlockResponse {
	case blob.BlockNXDomain:
		return SynthOut{Answer: negative(in.Name, RCodeNXDomain, ttl)}
	case blob.BlockRefused:
		return SynthOut{Answer: Answer{RCode: RCodeRefused}} // no SOA on REFUSED
	case blob.BlockBranded:
		if qt == TypeA {
			return proxyAnswer(in, ttl, GrantBlockPage)
		}
		return SynthOut{Answer: negative(in.Name, RCodeNoError, ttl)}
	case blob.BlockCustom:
		switch qt {
		case TypeA:
			if e.BlockV4 != ([4]byte{}) {
				return SynthOut{Answer: addrAnswer(in.Name, TypeA, ttl, e.BlockV4[:])}
			}
		case TypeAAAA:
			if e.BlockV6 != ([16]byte{}) {
				return SynthOut{Answer: addrAnswer(in.Name, TypeAAAA, ttl, e.BlockV6[:])}
			}
		}
		return SynthOut{Answer: negative(in.Name, RCodeNoError, ttl)}
	}
	// 0.0.0.0 and ::
	switch qt {
	case TypeA:
		return SynthOut{Answer: addrAnswer(in.Name, TypeA, ttl, make([]byte, 4))}
	case TypeAAAA:
		return SynthOut{Answer: addrAnswer(in.Name, TypeAAAA, ttl, make([]byte, 16))}
	}
	return SynthOut{Answer: negative(in.Name, RCodeNoError, ttl)}
}

func synthRedirect(in *SynthIn, qt uint16) SynthOut {
	ttl := in.Eff.RedirectTTL
	switch in.TargetKind {
	case TargetIP:
		switch {
		case qt == TypeA && in.V4.IsValid():
			a := in.V4.As4()
			return SynthOut{Answer: addrAnswer(in.Name, TypeA, ttl, a[:])}
		case qt == TypeAAAA && in.V6.IsValid():
			a := in.V6.As16()
			return SynthOut{Answer: addrAnswer(in.Name, TypeAAAA, ttl, a[:])}
		}
		return SynthOut{Answer: negative(in.Name, RCodeNoError, ttl)}
	case TargetHost:
		cname := RR{Name: in.Name, Type: TypeCNAME, Class: ClassIN, TTL: ttl, Data: append([]byte(nil), in.Host.Wire()...)}
		out := Answer{Answer: []RR{cname}}
		if (qt == TypeA || qt == TypeAAAA) && in.HostAnswer != nil && !in.HostAnswer.Failed {
			for i := range in.HostAnswer.Answer {
				r := in.HostAnswer.Answer[i]
				if r.Type == qt || r.Type == TypeCNAME {
					r.TTL = ttl
					out.Answer = append(out.Answer, r)
				}
			}
		}
		return SynthOut{Answer: out}
	}
	// location, auto, random: the client is sent to this node's proxy.
	if qt == TypeA {
		return proxyAnswer(in, ttl, GrantRedirect)
	}
	return SynthOut{Answer: negative(in.Name, RCodeNoError, ttl)}
}

// proxyAnswer answers with PROXY_IPs, own first. An empty list would mean a
// misconfigured node (own is always present), and an answer pointing nowhere
// is worse than an error, so it becomes SERVFAIL with no Grant.
func proxyAnswer(in *SynthIn, ttl uint32, kind uint8) SynthOut {
	var rrs []RR
	for _, a := range in.Proxy {
		if a.Is4() {
			v := a.As4()
			rrs = append(rrs, RR{Name: in.Name, Type: TypeA, Class: ClassIN, TTL: ttl, Data: v[:]})
		}
	}
	if len(rrs) == 0 {
		return SynthOut{Answer: Answer{RCode: RCodeServFail}}
	}
	return SynthOut{Answer: Answer{Answer: rrs}, WantGrant: true, GrantKind: kind}
}

func addrAnswer(n names.Name, typ uint16, ttl uint32, data []byte) Answer {
	return Answer{Answer: []RR{{Name: n, Type: typ, Class: ClassIN, TTL: ttl, Data: append([]byte(nil), data...)}}}
}

// negative builds NODATA (RCodeNoError) or NXDOMAIN with the synthetic SOA of
// contract 7: owner is the qname, MNAME ns.invalid., RNAME hostmaster.invalid.,
// and both the RR TTL and MINIMUM equal the action TTL, so a resolver caches
// the negative exactly as long as we meant it to.
func negative(qname names.Name, rcode uint16, ttl uint32) Answer {
	return Answer{RCode: rcode, Authority: []RR{SyntheticSOA(qname, ttl)}}
}

// SyntheticSOA is the SOA placed in Authority of synthesized negatives.
func SyntheticSOA(qname names.Name, ttl uint32) RR {
	d := []byte("\x02ns\x07invalid\x00\x0ahostmaster\x07invalid\x00")
	d = binary.BigEndian.AppendUint32(d, 1)     // SERIAL
	d = binary.BigEndian.AppendUint32(d, 3600)  // REFRESH
	d = binary.BigEndian.AppendUint32(d, 600)   // RETRY
	d = binary.BigEndian.AppendUint32(d, 86400) // EXPIRE
	d = binary.BigEndian.AppendUint32(d, ttl)   // MINIMUM
	return RR{Name: qname, Type: TypeSOA, Class: ClassIN, TTL: ttl, Data: d}
}

// HINFOAnswer is the RFC 8482 answer for ANY on a Bypass or default outcome:
// one HINFO record, CPU "RFC8482", OS empty, TTL 3600, at the qname. It saves
// resolving ANY, which is large and abused for amplification.
func HINFOAnswer(qname names.Name) Answer {
	return Answer{Answer: []RR{{Name: qname, Type: TypeHINFO, Class: ClassIN, TTL: 3600, Data: []byte("\x07RFC8482\x00")}}}
}
