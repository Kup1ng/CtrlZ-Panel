package vectors

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/Kup1ng/CtrlZ-Shared/names"
	"github.com/Kup1ng/CtrlZ-Shared/policy"
)

// Resource records appear in vector files as presentation text, for example
// "ads.example.com. 300 IN A 93.184.216.34". Only the handful of types the
// vectors use have a typed form; everything else is the generic RFC 3597 form
// "TYPE \# <length> <hex>", which is also how DNSSEC records are written.

func typeName(t uint16) string {
	switch t {
	case policy.TypeA:
		return "A"
	case policy.TypeNS:
		return "NS"
	case policy.TypeCNAME:
		return "CNAME"
	case policy.TypeSOA:
		return "SOA"
	case policy.TypePTR:
		return "PTR"
	case policy.TypeHINFO:
		return "HINFO"
	case policy.TypeMX:
		return "MX"
	case policy.TypeTXT:
		return "TXT"
	case policy.TypeAAAA:
		return "AAAA"
	case policy.TypeDS:
		return "DS"
	case policy.TypeRRSIG:
		return "RRSIG"
	case policy.TypeNSEC:
		return "NSEC"
	case policy.TypeNSEC3:
		return "NSEC3"
	case policy.TypeSVCB:
		return "SVCB"
	case policy.TypeHTTPS:
		return "HTTPS"
	case policy.TypeANY:
		return "ANY"
	case policy.TypeNULL:
		return "NULL"
	}
	return "TYPE" + strconv.Itoa(int(t))
}

func typeFromName(s string) (uint16, error) {
	for t := uint16(1); t <= 255; t++ {
		if typeName(t) == s {
			return t, nil
		}
	}
	if v, ok := strings.CutPrefix(s, "TYPE"); ok {
		n, err := strconv.ParseUint(v, 10, 16)
		if err == nil {
			return uint16(n), nil
		}
	}
	return 0, fmt.Errorf("unknown type %q", s)
}

func rcodeName(r uint16) string {
	switch r {
	case policy.RCodeNoError:
		return "NOERROR"
	case policy.RCodeServFail:
		return "SERVFAIL"
	case policy.RCodeNXDomain:
		return "NXDOMAIN"
	case policy.RCodeRefused:
		return "REFUSED"
	}
	return "RCODE" + strconv.Itoa(int(r))
}

func rcodeFromName(s string) (uint16, error) {
	for r := uint16(0); r < 16; r++ {
		if rcodeName(r) == s {
			return r, nil
		}
	}
	return 0, fmt.Errorf("unknown rcode %q", s)
}

func nameText(n *names.Name) string {
	if n.IsRoot() {
		return "."
	}
	return n.String() + "."
}

func parseNameText(s string) (names.Name, error) { return names.FromString(s) }

// tokens splits on spaces but keeps "quoted strings" whole.
func tokens(s string) []string {
	var out []string
	for i := 0; i < len(s); {
		if s[i] == ' ' {
			i++
			continue
		}
		if s[i] == '"' {
			j := i + 1
			for j < len(s) && s[j] != '"' {
				j++
			}
			out = append(out, s[i:min(j+1, len(s))])
			i = j + 1
			continue
		}
		j := i
		for j < len(s) && s[j] != ' ' {
			j++
		}
		out = append(out, s[i:j])
		i = j
	}
	return out
}

// ParseRR parses presentation text into an RR.
func ParseRR(s string) (policy.RR, error) {
	f := tokens(s)
	if len(f) < 4 || f[2] != "IN" {
		return policy.RR{}, fmt.Errorf("rr %q: want \"name ttl IN TYPE rdata\"", s)
	}
	n, err := parseNameText(f[0])
	if err != nil {
		return policy.RR{}, fmt.Errorf("rr %q: %w", s, err)
	}
	ttl, err := strconv.ParseUint(f[1], 10, 32)
	if err != nil {
		return policy.RR{}, fmt.Errorf("rr %q: ttl: %w", s, err)
	}
	t, err := typeFromName(f[3])
	if err != nil {
		return policy.RR{}, err
	}
	rr := policy.RR{Name: n, Type: t, Class: policy.ClassIN, TTL: uint32(ttl)}
	rd := f[4:]
	switch {
	case len(rd) >= 1 && rd[0] == `\#`:
		if len(rd) != 3 {
			return rr, fmt.Errorf("rr %q: generic rdata needs a length and hex", s)
		}
		b, err := hex.DecodeString(rd[2])
		if err != nil {
			return rr, err
		}
		rr.Data = b
	case t == policy.TypeA || t == policy.TypeAAAA:
		if len(rd) != 1 {
			return rr, fmt.Errorf("rr %q: address missing", s)
		}
		a, err := netip.ParseAddr(rd[0])
		if err != nil {
			return rr, err
		}
		if t == policy.TypeA {
			v := a.As4()
			rr.Data = v[:]
		} else {
			v := a.As16()
			rr.Data = v[:]
		}
	case t == policy.TypeCNAME || t == policy.TypeNS || t == policy.TypePTR:
		tn, err := parseNameText(rd[0])
		if err != nil {
			return rr, err
		}
		rr.Data = append([]byte(nil), tn.Wire()...)
	case t == policy.TypeMX:
		p, err := strconv.ParseUint(rd[0], 10, 16)
		if err != nil {
			return rr, err
		}
		tn, err := parseNameText(rd[1])
		if err != nil {
			return rr, err
		}
		rr.Data = binary.BigEndian.AppendUint16(nil, uint16(p))
		rr.Data = append(rr.Data, tn.Wire()...)
	case t == policy.TypeSOA:
		if len(rd) != 7 {
			return rr, fmt.Errorf("rr %q: SOA needs 7 fields", s)
		}
		for i := 0; i < 2; i++ {
			tn, err := parseNameText(rd[i])
			if err != nil {
				return rr, err
			}
			rr.Data = append(rr.Data, tn.Wire()...)
		}
		for i := 2; i < 7; i++ {
			v, err := strconv.ParseUint(rd[i], 10, 32)
			if err != nil {
				return rr, err
			}
			rr.Data = binary.BigEndian.AppendUint32(rr.Data, uint32(v))
		}
	case t == policy.TypeHINFO:
		for _, q := range rd {
			v := strings.Trim(q, `"`)
			rr.Data = append(rr.Data, byte(len(v)))
			rr.Data = append(rr.Data, v...)
		}
	case t == policy.TypeTXT:
		v := strings.Trim(strings.Join(rd, " "), `"`)
		rr.Data = append([]byte{byte(len(v))}, v...)
	default:
		return rr, fmt.Errorf("rr %q: use the generic \\# form for %s", s, f[3])
	}
	return rr, nil
}

// FormatRR renders an RR in the same presentation form.
func FormatRR(rr policy.RR) string {
	head := fmt.Sprintf("%s %d IN %s ", nameText(&rr.Name), rr.TTL, typeName(rr.Type))
	d := rr.Data
	switch rr.Type {
	case policy.TypeA, policy.TypeAAAA:
		if a, ok := rr.Addr(); ok {
			return head + a.String()
		}
	case policy.TypeCNAME, policy.TypeNS, policy.TypePTR:
		if n, err := names.FromCanonicalWire(d); err == nil {
			return head + nameText(&n)
		}
	case policy.TypeMX:
		if len(d) > 2 {
			if n, err := names.FromCanonicalWire(d[2:]); err == nil {
				return head + fmt.Sprintf("%d %s", binary.BigEndian.Uint16(d), nameText(&n))
			}
		}
	case policy.TypeSOA:
		m, next, err := names.FromWire(d, 0)
		if err == nil {
			r, next2, err := names.FromWire(d, next)
			if err == nil && len(d)-next2 == 20 {
				u := func(i int) uint32 { return binary.BigEndian.Uint32(d[next2+4*i:]) }
				return head + fmt.Sprintf("%s %s %d %d %d %d %d", nameText(&m), nameText(&r), u(0), u(1), u(2), u(3), u(4))
			}
		}
	case policy.TypeHINFO:
		if len(d) >= 1 && int(d[0])+1 <= len(d) {
			cpu := string(d[1 : 1+d[0]])
			rest := d[1+d[0]:]
			if len(rest) >= 1 && int(rest[0])+1 == len(rest) {
				return head + fmt.Sprintf("%q %q", cpu, string(rest[1:]))
			}
		}
	}
	return head + fmt.Sprintf(`\# %d %s`, len(d), hex.EncodeToString(d))
}
