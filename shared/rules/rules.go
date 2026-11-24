// Package rules is the one validator for rule tokens. The API, Import, Upload
// Folder and rule-from-log all call Parse, so a token means the same thing
// wherever it enters the system.
package rules

import (
	"errors"
	"strconv"
	"strings"

	"golang.org/x/net/publicsuffix"

	"github.com/Kup1ng/CtrlZ-Shared/names"
)

// Kind values are the RULE record kind bytes of the CZPB format (9.2).
type Kind uint8

const (
	KindDomain     Kind = 1
	KindSubdomains Kind = 2
	KindGlob       Kind = 3
	KindDestCC     Kind = 4
	KindDestAS     Kind = 5
	KindSrcCC      Kind = 6
)

func (k Kind) String() string {
	switch k {
	case KindDomain:
		return "domain"
	case KindSubdomains:
		return "subdomains"
	case KindGlob:
		return "glob"
	case KindDestCC:
		return "dest_cc"
	case KindDestAS:
		return "dest_as"
	case KindSrcCC:
		return "src_cc"
	}
	return "unknown"
}

// IsName reports whether the kind matches on the query name (levels 1).
func (k Kind) IsName() bool { return k >= KindDomain && k <= KindGlob }

// IsWildcard reports whether the kind belongs to the wildcard tier.
func (k Kind) IsWildcard() bool { return k == KindSubdomains || k == KindGlob }

var (
	ErrEmpty         = errors.New("rules: empty token")
	ErrIPLiteral     = errors.New("rules: IP literals are not valid rules")
	ErrBadGeo        = errors.New("rules: bad geo token")
	ErrSourceASN     = errors.New("rules: source ASN rules do not exist")
	ErrBadCC         = errors.New("rules: country code must be two letters")
	ErrBadASN        = errors.New("rules: ASN must be decimal from 1 to 4294967295 without leading zeros")
	ErrStarCount     = errors.New("rules: at most one '*' is allowed, and only in one label")
	ErrStarUnicode   = errors.New("rules: a label with '*' must be ASCII")
	ErrNoRegistrable = errors.New("rules: the part right of '*' must contain a registrable domain")
	ErrNegatedName   = errors.New("rules: '!' only applies to geo tokens")
	ErrPunycode      = errors.New("rules: bad domain")
)

// Pattern is a parsed token.
type Pattern struct {
	Kind    Kind
	Negated bool
	CC      [2]byte // uppercase, for the CC kinds
	ASN     uint32

	// Wire is the pattern in wire form. For KindDomain it is the name. For
	// KindGlob it is the whole pattern with the '*' byte kept inside its label.
	// For KindSubdomains it is the literal suffix without the star label.
	Wire []byte
	// Labels is the number of labels in the full pattern. For KindSubdomains
	// that counts the star label, so *.a.com has 3.
	Labels int
	// LitLabels is the number of labels right of the star (or all labels of a
	// plain domain). It is the key into the wildcard index.
	LitLabels int
	// LitBytes counts pattern bytes that are not '*', length octets excluded.
	// It orders wildcards of equal suffix depth (5.5 rule 3).
	LitBytes int
}

// Key is rule_key: the canonical text that is unique per profile.
func (p *Pattern) Key() string {
	switch p.Kind {
	case KindDomain:
		return keyOfWire(p.Wire)
	case KindSubdomains:
		return "*." + keyOfWire(p.Wire)
	case KindGlob:
		return keyOfWire(p.Wire)
	}
	var b strings.Builder
	if p.Negated {
		b.WriteByte('!')
	}
	switch p.Kind {
	case KindDestCC:
		b.WriteByte('@')
		b.Write(p.CC[:])
	case KindSrcCC:
		b.WriteByte('#')
		b.Write(p.CC[:])
	case KindDestAS:
		b.WriteString("@AS")
		b.WriteString(strconv.FormatUint(uint64(p.ASN), 10))
	}
	return b.String()
}

func keyOfWire(w []byte) string {
	n, err := names.FromCanonicalWire(w)
	if err != nil {
		return ""
	}
	// A star byte is legal only inside a glob pattern. The presentation form would
	// escape it as backslash-042, but rule_key must read the way the user typed it.
	return strings.ReplaceAll(n.String(), "\\042", "*")
}

// LiteralSuffix returns the wire bytes the wildcard index is keyed by: the
// labels right of the star. For a plain domain it is the whole name.
func (p *Pattern) LiteralSuffix() []byte {
	if p.Kind != KindGlob {
		return p.Wire
	}
	// Skip labels up to and including the one that holds '*'.
	i := 0
	for i < len(p.Wire) && p.Wire[i] != 0 {
		l := int(p.Wire[i])
		star := strings.IndexByte(string(p.Wire[i+1:i+1+l]), '*') >= 0
		i += 1 + l
		if star {
			return p.Wire[i:]
		}
	}
	return p.Wire[len(p.Wire)-1:]
}

// Parse validates one token.
func Parse(input string) (Pattern, error) {
	s := strings.Trim(input, " ")
	if s == "" {
		return Pattern{}, ErrEmpty
	}
	// First, so the glob path (ToLower, Split) and IDNA both see bounded input.
	if len(s) > names.MaxUserInput {
		return Pattern{}, names.ErrInputLen
	}
	neg := false
	if s[0] == '!' {
		neg = true
		s = s[1:]
		if s == "" || (s[0] != '@' && s[0] != '#') {
			return Pattern{}, ErrNegatedName
		}
	}
	switch s[0] {
	case '@':
		return parseDest(s[1:], neg)
	case '#':
		return parseSrc(s[1:], neg)
	}
	return parseName(s)
}

func parseCC(s string) ([2]byte, bool) {
	if len(s) != 2 {
		return [2]byte{}, false
	}
	var cc [2]byte
	for i := 0; i < 2; i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' {
			c -= 'a' - 'A'
		}
		if c < 'A' || c > 'Z' {
			return [2]byte{}, false
		}
		cc[i] = c
	}
	return cc, true
}

// The country-code check is shape only (two ASCII letters), not membership in
// ISO 3166-1. A table would reject user-assigned codes such as XK that GeoIP
// databases really emit, and would need a release whenever ISO adds one.

func parseDest(s string, neg bool) (Pattern, error) {
	if len(s) > 2 && (s[0] == 'A' || s[0] == 'a') && (s[1] == 'S' || s[1] == 's') {
		digits := s[2:]
		if digits[0] == '0' {
			return Pattern{}, ErrBadASN
		}
		v, err := strconv.ParseUint(digits, 10, 32)
		if err != nil || v == 0 || strings.ContainsAny(digits, "+-_") {
			return Pattern{}, ErrBadASN
		}
		return Pattern{Kind: KindDestAS, Negated: neg, ASN: uint32(v)}, nil
	}
	cc, ok := parseCC(s)
	if !ok {
		return Pattern{}, ErrBadCC
	}
	return Pattern{Kind: KindDestCC, Negated: neg, CC: cc}, nil
}

func parseSrc(s string, neg bool) (Pattern, error) {
	if len(s) > 2 && (s[0] == 'A' || s[0] == 'a') && (s[1] == 'S' || s[1] == 's') {
		return Pattern{}, ErrSourceASN
	}
	cc, ok := parseCC(s)
	if !ok {
		return Pattern{}, ErrBadCC
	}
	return Pattern{Kind: KindSrcCC, Negated: neg, CC: cc}, nil
}

func parseName(s string) (Pattern, error) {
	stars := strings.Count(s, "*")
	if stars == 0 {
		n, err := names.ParseUser(s)
		if err != nil {
			if errors.Is(err, names.ErrIPLiteral) || errors.Is(err, names.ErrNumeric) {
				return Pattern{}, ErrIPLiteral
			}
			return Pattern{}, err
		}
		return fromName(KindDomain, n, n.Labels()), nil
	}
	if stars > 1 {
		return Pattern{}, ErrStarCount
	}
	s = strings.TrimSuffix(strings.ToLower(s), ".")
	labels := strings.Split(s, ".")
	si := -1
	for i, l := range labels {
		if strings.Contains(l, "*") {
			si = i
		}
	}
	star := labels[si]
	// ASCII only: the Punycode of a fragment of a label is not a fragment of
	// the Punycode of the label, so Unicode around a star cannot be converted.
	for i := 0; i < len(star); i++ {
		c := star[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '*') {
			return Pattern{}, ErrStarUnicode
		}
	}
	if len(star) > names.MaxLabel {
		return Pattern{}, names.ErrLabelLen
	}
	if si == len(labels)-1 {
		return Pattern{}, ErrNoRegistrable
	}
	// The part right of the star decides the registrable-domain check, and is
	// also where IDNA is applied.
	suffix := strings.Join(labels[si+1:], ".")
	sn, err := names.ParseUser(suffix)
	if err != nil {
		return Pattern{}, err
	}
	if _, err := publicsuffix.EffectiveTLDPlusOne(sn.String()); err != nil {
		return Pattern{}, ErrNoRegistrable
	}
	// Labels left of the star must match exactly, so they are IDNA-converted too.
	var wire []byte
	for i := 0; i < si; i++ {
		ln, err := names.ParseUserPart(labels[i])
		if err != nil || ln.Labels() != 1 {
			return Pattern{}, ErrPunycode
		}
		wire = append(wire, ln.Wire()[:ln.Len()-1]...)
	}
	wire = append(wire, byte(len(star)))
	wire = append(wire, star...)
	wire = append(wire, sn.Wire()...)
	full, err := names.FromCanonicalWire(wire)
	if err != nil {
		return Pattern{}, err
	}
	p := Pattern{Kind: KindGlob, Wire: append([]byte(nil), full.Wire()...), Labels: full.Labels(), LitLabels: sn.Labels()}
	if si == 0 && star == "*" {
		p.Kind = KindSubdomains
		p.Wire = append([]byte(nil), sn.Wire()...)
	}
	for i := 0; i < full.Labels(); i++ {
		for _, c := range full.Label(i) {
			if c != '*' {
				p.LitBytes++
			}
		}
	}
	return p, nil
}

func fromName(k Kind, n names.Name, lit int) Pattern {
	p := Pattern{Kind: k, Wire: append([]byte(nil), n.Wire()...), Labels: n.Labels(), LitLabels: lit}
	for i := 0; i < n.Labels(); i++ {
		p.LitBytes += len(n.Label(i))
	}
	return p
}
