package names

import (
	"errors"
	"net/netip"
	"strings"

	"golang.org/x/net/idna"
)

var (
	ErrIPLiteral = errors.New("names: IP literal is not a domain name")
	ErrBadByte   = errors.New("names: byte outside [a-z0-9_-] in label")
	ErrEmptyLbl  = errors.New("names: empty label")
	ErrInputLen  = errors.New("names: input longer than MaxUserInput bytes")
	ErrNumeric   = errors.New("names: the last label is a number, which resolvers read as an IPv4 address")
)

// MaxUserInput caps what ParseUser and rules.Parse accept before any IDNA
// work. A valid name is at most 253 ASCII bytes and its Unicode spelling is
// well under 1 KiB. Punycode encoding of a long non-ASCII label is
// super-linear, so without this cap one request carrying a few 60 KB tokens
// pins a CPU for seconds before the length checks below ever run.
const MaxUserInput = 1024

// userProfile returns the IDNA profile of contract 2.2. It is a function, not a
// package variable, because the module forbids package-level mutable state and
// ParseUser runs only in the panel where building it per call is cheap. Transitional
// is off so the German sharp s and similar stay distinct, as modern browsers do.
// StrictDomainName(false) keeps underscores legal, which service-discovery and
// DKIM style names need.
func userProfile() *idna.Profile {
	return idna.New(
		idna.MapForLookup(),
		// MapForLookup also turns on the hyphen rules of IDNA 2008 (no leading or
		// trailing hyphen, no "--" in positions 3 and 4), which are registration
		// rules. Blocklists are full of valid DNS names that break them, such as
		// "-ad.example.com", and a user must be able to block those.
		idna.CheckHyphens(false),
		idna.Transitional(false),
		idna.BidiRule(),
		idna.StrictDomainName(false),
	)
}

// ParseUser converts text typed by a person into a canonical Name. Panel side
// only: nodes compare wire forms and never run IDNA.
func ParseUser(s string) (Name, error) { return parseUser(s, true) }

// ParseUserPart is ParseUser for a piece of a longer name, such as a label left
// of the star in a glob rule: "10" in "10.*.example.com" is a fine label there,
// where "10" alone would read as an address.
func ParseUserPart(s string) (Name, error) { return parseUser(s, false) }

func parseUser(s string, whole bool) (Name, error) {
	s = strings.Trim(s, " ")
	s = strings.TrimSuffix(s, ".")
	if s == "" {
		return Name{}, ErrEmpty
	}
	// Exactly one trailing dot is stripped. A second one is an empty label, not
	// something to forgive.
	if strings.HasSuffix(s, ".") {
		return Name{}, ErrEmptyLbl
	}
	if len(s) > MaxUserInput {
		return Name{}, ErrInputLen
	}
	if isIPLiteral(s) {
		return Name{}, ErrIPLiteral
	}
	a, err := userProfile().ToASCII(s)
	if err != nil {
		return Name{}, err
	}
	// ToASCII may map a trailing ideographic full stop, so trim again.
	a = strings.TrimSuffix(a, ".")
	if a == "" {
		return Name{}, ErrEmpty
	}
	if isIPLiteral(a) {
		return Name{}, ErrIPLiteral
	}
	labels := strings.Split(a, ".")
	// "127.1", "0x7f.1" and "2130706433" are IPv4 addresses to a browser or a
	// socket library, and no TLD is a number. A rule for one would claim to
	// block a name while meaning an address.
	if whole && numericLabel(labels[len(labels)-1]) {
		return Name{}, ErrNumeric
	}
	var w [MaxWire]byte
	total := 0
	for _, l := range labels {
		if l == "" {
			return Name{}, ErrEmptyLbl
		}
		if len(l) > MaxLabel {
			return Name{}, ErrLabelLen
		}
		if total+1+len(l)+1 > MaxWire {
			return Name{}, ErrNameLen
		}
		w[total] = byte(len(l))
		for i := 0; i < len(l); i++ {
			c := l[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
				return Name{}, ErrBadByte
			}
			w[total+1+i] = c
		}
		total += 1 + len(l)
	}
	w[total] = 0
	total++
	return FromCanonicalWire(w[:total])
}

// numericLabel reports whether a label is all decimal digits, or 0x followed
// by hex digits (possibly none), the two spellings the WHATWG host parser
// reads as a number.
func numericLabel(l string) bool {
	if l == "" {
		return false
	}
	if len(l) >= 2 && l[0] == '0' && (l[1] == 'x' || l[1] == 'X') {
		for i := 2; i < len(l); i++ {
			c := l[i]
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
				return false
			}
		}
		return true
	}
	for i := 0; i < len(l); i++ {
		if l[i] < '0' || l[i] > '9' {
			return false
		}
	}
	return true
}

func isIPLiteral(s string) bool {
	if len(s) >= 2 && s[0] == '[' && s[len(s)-1] == ']' {
		return true
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return true
	}
	return false
}

// FromString builds a Name from an already-normalized ASCII presentation string
// with no escapes. It is for fixtures, config literals and tests, not for user
// input (use ParseUser). The root is "." or "".
func FromString(s string) (Name, error) {
	s = strings.TrimSuffix(s, ".")
	if s == "" {
		return Root(), nil
	}
	var w [MaxWire]byte
	total := 0
	for _, l := range strings.Split(s, ".") {
		if l == "" {
			return Name{}, ErrEmptyLbl
		}
		if len(l) > MaxLabel {
			return Name{}, ErrLabelLen
		}
		if total+1+len(l)+1 > MaxWire {
			return Name{}, ErrNameLen
		}
		w[total] = byte(len(l))
		copy(w[total+1:], l)
		total += 1 + len(l)
	}
	w[total] = 0
	total++
	return FromCanonicalWire(w[:total])
}

// MustString is FromString for literals known to be valid. It panics on
// error, so it is for package-level tables and tests only.
func MustString(s string) Name {
	n, err := FromString(s)
	if err != nil {
		panic("names.MustString(" + s + "): " + err.Error())
	}
	return n
}
