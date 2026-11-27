package xrayschema

import (
	"encoding/base64"
	"encoding/hex"
	"net/netip"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// The closed kinds of 7.2. fits judges one value against the kind of its key and returns
// the reason it is not of that kind, or "". A reason names the kind and its bound and
// never the value, because a value may be a password. A value that is not of its kind is
// a warning at its path, never a rejection and never a pass.

const (
	maxHostBytes = 253
	maxTextBytes = 255
	maxLabel     = 63
)

func fits(n *node, v *val) string {
	switch n.k {
	case kBool:
		if v.k != 'b' {
			return "must be true or false"
		}
	case kInt:
		if v.k != 'n' || !wholeIn(v.s, n.lim) {
			return intText(n.lim)
		}
	case kRange:
		switch v.k {
		case 'n':
			if !wholeIn(v.s, n.lim) {
				return rangeText(n.lim)
			}
		case 's':
			if !rangeIn(v.s, n.lim) {
				return rangeText(n.lim)
			}
		default:
			return rangeText(n.lim)
		}
	case kEnum:
		// Inside a choice an enum matches its canonical spelling only; Check writes the
		// canonical form of a plain enum before it gets here.
		if v.k != 's' || n.enum[strings.ToLower(v.s)] != v.s {
			return "must be one of the values the table lists"
		}
	case kHost:
		if v.k != 's' || !hostOK(v.s) {
			return "must be an IP address or a DNS name with a dot, at most 253 bytes"
		}
	case kHostPort:
		if v.k != 's' || !hostPortOK(v.s) {
			return "must be host:port, with the host an IP address or a DNS name with a dot"
		}
	case kText:
		if v.k != 's' || !textOK(v.s, maxTextBytes) {
			return "must be text of 1 to 255 bytes with no control character"
		}
	case kPath:
		if v.k != 's' || !pathOK(v.s, maxTextBytes) {
			return "must be 1 to 255 printable ASCII characters with no space"
		}
	case kHeaders:
		return headersFit(n, v)
	case kUUIDText:
		if v.k != 's' || !(uuidOK(v.s) || textOK(v.s, 30)) {
			return "must be a UUID, or text of at most 30 bytes"
		}
	case kKey32:
		if v.k != 's' || !key32OK(v.s) {
			return "must be a key of 32 bytes in hex or base64"
		}
	case kKey32URL:
		if v.k != 's' || !key32URLOK(v.s) {
			return "must be a key of 32 bytes in base64url"
		}
	case kIP:
		if v.k != 's' || !ipOK(v.s) {
			return "must be an IP address or a prefix"
		}
	case kPrefix:
		if v.k != 's' || !prefixOK(v.s) {
			return "must be an IP prefix with its length, such as 10.0.0.1/32"
		}
	case kHTTPHost:
		if v.k != 's' || !httpHostOK(v.s) {
			return "must be an IP address or a DNS name of ASCII labels with a dot, with an optional :port"
		}
	case kPins:
		if v.k != 's' || !pinsOK(v.s) {
			return "must be 1 to 4 SHA-256 hashes in hex, joined by commas"
		}
	case kShortID:
		if v.k != 's' || !shortIDOK(v.s) {
			return "must be at most 16 hex digits"
		}
	case kSpiderX:
		if v.k != 's' || !spiderXOK(v.s) {
			return "must be a path of / and at most 254 of A-Z a-z 0-9 / . _ ~ - with no query and no escape"
		}
	case kOneOf:
		for _, a := range n.alts {
			if fits(a, v) == "" {
				return ""
			}
		}
		return "must be one of the forms the table lists"
	}
	return ""
}

// wholeIn says whether text is a whole decimal number in [lo, hi]. An exponent or a
// fraction is not one: Go's decoder refuses 1e3 for an integer field.
func wholeIn(text string, l *limit) bool {
	if !isDecimal(strings.TrimPrefix(text, "-")) || len(text) > 18 {
		return false
	}
	i, err := strconv.ParseInt(text, 10, 64)
	return err == nil && i >= l.lo && i <= l.hi
}

func isDecimal(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// rangeIn reads "a" or "a-b" (digits only) with both ends in [lo, hi] and a not above b.
func rangeIn(s string, l *limit) bool {
	a, b, two := strings.Cut(s, "-")
	if !isDecimal(a) || len(a) > 18 || two && (!isDecimal(b) || len(b) > 18) {
		return false
	}
	x, _ := strconv.ParseInt(a, 10, 64)
	y := x
	if two {
		y, _ = strconv.ParseInt(b, 10, 64)
	}
	return x >= l.lo && y <= l.hi && x <= y
}

func intText(l *limit) string {
	if l.lo == l.hi {
		return "must be the number " + strconv.FormatInt(l.lo, 10)
	}
	return "must be a whole number from " + strconv.FormatInt(l.lo, 10) + " to " + strconv.FormatInt(l.hi, 10)
}

func rangeText(l *limit) string {
	return "must be a whole number from " + strconv.FormatInt(l.lo, 10) + " to " + strconv.FormatInt(l.hi, 10) +
		", or a range x-y of such numbers with x not above y"
}

// hostOK: an IP literal with no zone (a zone names an interface of the host), or a DNS
// name of ASCII labels with at least one dot. So "fromMitm" and a name with a space are
// no host.
func hostOK(s string) bool {
	if s == "" || len(s) > maxHostBytes {
		return false
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return a.Zone() == ""
	}
	if !strings.Contains(s, ".") {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > maxLabel || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return false
			}
		}
	}
	return true
}

// hostPortOK reads host:port, or [v6]:port. A bare IPv6 address has no port to find, so it
// is no host:port.
func hostPortOK(s string) bool {
	var h, p string
	if strings.HasPrefix(s, "[") {
		end := strings.Index(s, "]:")
		if end < 0 {
			return false
		}
		h, p = s[1:end], s[end+2:]
	} else {
		i := strings.LastIndexByte(s, ':')
		if i < 0 || strings.Contains(s[:i], ":") {
			return false
		}
		h, p = s[:i], s[i+1:]
	}
	return hostOK(h) && wholeIn(p, &limit{1, 65535})
}

func textOK(s string, max int) bool {
	if s == "" || len(s) > max || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func pathOK(s string, max int) bool {
	if s == "" || len(s) > max {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] <= 0x20 || s[i] >= 0x7f {
			return false
		}
	}
	return true
}

// printable is 0x20 to 0x7e, a space included.
func printable(s string, max int) bool {
	if len(s) > max {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] >= 0x7f {
			return false
		}
	}
	return true
}

// token is an HTTP token (RFC 9110 5.6.2) of 1 to 64 bytes.
func token(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0) {
			return false
		}
	}
	return true
}

func headersFit(n *node, v *val) string {
	const why = "must be an object of at most 16 HTTP header names, each with a value of at most 255 printable ASCII characters"
	if v.k != 'o' || len(v.members) > 16 {
		return why
	}
	for _, m := range v.members {
		if !token(m.key) {
			return why
		}
		switch m.v.k {
		case 's':
			if !printable(m.v.s, 255) {
				return why
			}
		case 'a':
			if !n.multi || len(m.v.items) < 1 || len(m.v.items) > 8 {
				return why
			}
			for _, it := range m.v.items {
				if it.k != 's' || !printable(it.s, 255) {
					return why
				}
			}
		default:
			return why
		}
	}
	return ""
}

// uuidOK accepts what uuid.ParseString of the release reads as a UUID: 32 hex digits, or
// the 36-character form with its four dashes. The loader also takes other dash
// placements and ignores trailing characters; those stay warnings, because a kind may
// be narrower than the loader as long as it is never wider.
func uuidOK(s string) bool {
	if len(s) == 32 {
		return allHex(s)
	}
	if len(s) != 36 {
		return false
	}
	for i := 0; i < len(s); i++ {
		switch {
		case i == 8 || i == 13 || i == 18 || i == 23:
			if s[i] != '-' {
				return false
			}
		case !isHex(s[i]):
			return false
		}
	}
	return true
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func allHex(s string) bool {
	for i := 0; i < len(s); i++ {
		if !isHex(s[i]) {
			return false
		}
	}
	return true
}

// key32OK reads a WireGuard key as ParseWireGuardKey does: 64 hex digits, or base64 of
// 32 bytes where "-" and "_" stand for "+" and "/". The loader trims one trailing "="
// and decodes with the Raw encodings, so a key with no padding is as valid as one with.
func key32OK(s string) bool {
	if len(s) == 64 && allHex(s) {
		_, err := hex.DecodeString(s)
		return err == nil
	}
	s = strings.TrimSuffix(s, "=")
	s = strings.NewReplacer("-", "+", "_", "/").Replace(s)
	b, err := base64.RawStdEncoding.DecodeString(s)
	return err == nil && len(b) == 32
}

// key32URLOK reads a REALITY key: base64url with no padding, 32 bytes.
func key32URLOK(s string) bool {
	b, err := base64.RawURLEncoding.DecodeString(s)
	return err == nil && len(b) == 32
}

func ipOK(s string) bool {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Addr().Zone() == ""
	}
	a, err := netip.ParseAddr(s)
	return err == nil && a.Zone() == ""
}

// pinsOK: one to four SHA-256 hashes in hex, joined by ",". TLSConfig.Build of the
// release splits the value on "," alone and hex-decodes each part, so a pair joined by
// "~" is a build error of the whole tlsSettings (the share-link converter turns the "~"
// of a link into ",").
func pinsOK(s string) bool {
	parts := strings.Split(s, ",")
	if len(parts) > 4 {
		return false
	}
	for _, p := range parts {
		if len(p) != 64 || !allHex(p) {
			return false
		}
	}
	return true
}

// prefixOK: wireguard-go reads allowed_ip with netip.ParsePrefix, which refuses a bare
// address, so the allowedIPs of a peer need the length.
func prefixOK(s string) bool {
	p, err := netip.ParsePrefix(s)
	return err == nil && p.Addr().Zone() == ""
}

// httpHostOK is a Host or :authority value that Go will write: ASCII labels only
// (hostOK), and an optional port. A byte above 0x7f passes url.String and NewRequest of
// the client but fails Request.Write with an idna error, and the xhttp upload runs
// common.Must on that, which ends the process that all locations share.
func httpHostOK(s string) bool {
	return hostOK(s) || hostPortOK(s)
}

func shortIDOK(s string) bool { return s != "" && len(s) <= 16 && allHex(s) }

// spiderXOK is a path with no query part and no escape: the loader reads p, c, t, i
// and r of a query as crawler settings of the REALITY fallback.
func spiderXOK(s string) bool {
	if len(s) < 1 || len(s) > 255 || s[0] != '/' {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("/._~-", c) >= 0) {
			return false
		}
	}
	return true
}
