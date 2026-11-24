package sms

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/digits"
)

// MaxProviderField is the longest provider-supplied id, cost or balance text a
// driver puts in a Result. Each reaches sms_deliveries or the admin page, and a
// real id is a few dozen characters at most; a longer value is the provider's (or a
// middlebox's) doing and is dropped, not stored (sms-r4-3).
const MaxProviderField = 64

// Field is a value a provider's reply supplied that the service stores or shows:
// a message id, a cost, a balance. It is the only type a Result can hold such a value
// in, and the only ways to make one are ParseField and the JSON decoder, so a driver
// cannot hand a raw reply string to the database (rule boundary-input).
//
// A Field is at most MaxProviderField characters of one closed alphabet: ASCII
// letters and digits and the four marks "-", "_", ".", "+" (which a decimal number
// in exponent form needs). Anything else makes the whole value empty, never a
// cleaned-up version of it: a cleaned id would look real and match nothing at the
// provider. Digits are folded in the decoder: a gateway that answers with Persian
// or Arabic-Indic digits gives the same Field as one that uses ASCII.
//
// The zero Field is "the reply held nothing usable". Both bookkeeping fields are
// optional, so that is never an error: failing a send the provider accepted would
// send it again through the fallback, and the user would hold two codes.
type Field struct{ s string }

// String is the stored text; empty for the zero Field.
func (f Field) String() string { return f.s }

// IsZero says the reply held nothing usable.
func (f Field) IsZero() bool { return f.s == "" }

// ParseField makes a Field from reply text: surrounding white space is dropped,
// digits are folded to ASCII, and the rest must be 1 to MaxProviderField characters
// of the alphabet or the result is the zero Field.
func ParseField(s string) Field {
	s = digits.ToASCII(strings.TrimSpace(s))
	if s == "" || len(s) > MaxProviderField {
		return Field{}
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '-', c == '_', c == '.', c == '+':
		default:
			return Field{}
		}
	}
	return Field{s}
}

// UnmarshalJSON reads a JSON number (as the provider wrote it, so a long id is not
// rounded through a float) or a JSON string. Any other value, and a value that is
// not a Field, leaves the zero Field. It never returns an error, so a struct that
// holds Fields decodes whatever the provider sends.
func (f *Field) UnmarshalJSON(b []byte) error {
	*f = Field{}
	b = bytes.TrimSpace(b)
	if len(b) == 0 || len(b) > 4*MaxProviderField {
		return nil
	}
	switch c := b[0]; {
	case c == '"':
		var s string
		if json.Unmarshal(b, &s) == nil {
			*f = ParseField(s)
		}
	case c == '-' || c >= '0' && c <= '9':
		var n json.Number
		if json.Unmarshal(b, &n) == nil {
			*f = ParseField(n.String())
		}
	}
	return nil
}

// Number is a Field that only a JSON number can fill, for a value the provider
// reports as an amount. A string in its place ("free") is the provider's prose, not
// a cost, and reads as nothing.
type Number struct{ Field }

// UnmarshalJSON accepts a JSON number and ignores every other value. It never
// returns an error, like Field's.
func (n *Number) UnmarshalJSON(b []byte) error {
	*n = Number{}
	if b = bytes.TrimSpace(b); len(b) > 0 && (b[0] == '-' || b[0] >= '0' && b[0] <= '9') {
		return n.Field.UnmarshalJSON(b)
	}
	return nil
}

// Scrubbed returns r without any Field that holds the recipient's number or a value
// that was sent. A provider (or a proxy in front of one) can echo what it was given as
// its message id, and the id is stored in sms_deliveries for 90 days where the admin
// role reads it; that table holds no number and no code by design (spec 9.8, sms-r1-14).
// The alphabet of a Field cannot see this, since a phone number and a code are digits.
//
// The router applies it to every accepted attempt, so a driver cannot forget it
// (sms-r5-8). A field is dropped whole, never cleaned: a cleaned id would look real and
// match nothing at the provider. A field is judged as written, with only its digits kept, and
// folded on both sides (echoFold), so "0912-123-4567" is a number and an invite code echoed
// without its hyphens or in lower case is a code (sms-r11-4). Dropping a field that only looks like an
// echo by chance costs nothing, since both fields are optional bookkeeping.
func (r Result) Scrubbed(m Message) Result {
	needles := numberNeedles(m.To)
	for _, v := range m.Values {
		if s := digits.ToASCII(v.Reveal()); len(s) >= minEchoLen {
			needles = append(needles, s)
		}
	}
	return Result{ProviderID: r.ProviderID.without(needles), CostRaw: r.CostRaw.without(needles)}
}

// without returns the zero Field when f contains any needle, in any of three readings: as
// written, with only its digits kept (so a number split by letters or marks is found), and
// folded (echoFold) on both sides, so a code echoed without its hyphens or in the other case is
// found too (sms-r11-4).
func (f Field) without(needles []string) Field {
	if f.s == "" {
		return f
	}
	digitsOnly := strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, f.s)
	folded := echoFold(f.s)
	for _, n := range needles {
		if strings.Contains(f.s, n) || strings.Contains(digitsOnly, n) {
			return Field{}
		}
		if fn := echoFold(n); len(fn) >= minEchoLen && strings.Contains(folded, fn) {
			return Field{}
		}
	}
	return f
}

// echoFold is the one reading of "the same value written another way" for a sent value: ASCII
// digits, letters in lower case, every other character removed, and the look-alikes of the
// Crockford alphabet that invite and recovery codes are typed in read as the characters they
// stand for (o as 0, i and l as 1), the same folding as invite.Canonical. It is deliberately
// coarse. It only ever decides to DROP an optional bookkeeping field, so a real id that matches
// by chance costs nothing, and a code that comes back as "abcde-fghjk" or "ABCDEFGHJK" or with a
// zero for its letter O must not be kept. The invite code is the case that matters most: it is a
// registration credential, and a stored copy would let anyone who reads sms_deliveries register
// before the invitee does.
func echoFold(s string) string {
	var b strings.Builder
	for _, r := range digits.ToASCII(s) {
		switch {
		case r >= 'A' && r <= 'Z':
			r += 'a' - 'A'
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		default:
			continue
		}
		switch r {
		case 'o':
			r = '0'
		case 'i', 'l':
			r = '1'
		}
		b.WriteRune(r)
	}
	return b.String()
}

// numberNeedles are the digit strings that identify a recipient: the E.164 digits
// (989121234567), the national form with a leading zero (09121234567) and without
// (9121234567). The shortest is a substring of the other two, but each is listed so the
// intent reads plainly, and a number outside +98 is matched by its own digits.
func numberNeedles(e164 string) []string {
	d := strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, e164)
	if d == "" {
		return nil
	}
	out := []string{d}
	if rest, ok := strings.CutPrefix(d, "98"); ok && len(rest) >= 9 {
		out = append(out, "0"+rest, rest)
	}
	return out
}

// minEchoLen is the shortest sent value that counts as an echo. A value of one to three
// characters is not a code, and as a substring it would drop real ids by chance.
const minEchoLen = 4

// ParseCredit reads a provider's reply to a balance question. It is the one judge of what a
// balance is, and every driver's Balance must pass its reply through it (sms-r10-7): a plain
// non-negative number, ASCII digits with at most one decimal point that has a digit on each
// side, and no sign, exponent or letter. The Field alphabet is wider on purpose (an id may hold
// letters, and a cost may be written 1e3), so a reply that only fits the alphabet was read as a
// credit: a gateway or a middlebox answering "Error", "-5" or "1e9" with a 200 showed an
// operator a dead or misconfigured account as a funded one. Round 9 closed that for
// Melipayamak alone and the class stayed open in the other driver. The result is the zero Field
// and false for anything else, so the driver answers Transient bad_reply.
func ParseCredit(s string) (Field, bool) {
	f := ParseField(s)
	if f.IsZero() {
		return Field{}, false
	}
	t := f.String()
	dot := strings.IndexByte(t, '.')
	if dot == 0 || dot == len(t)-1 {
		return Field{}, false
	}
	for i := 0; i < len(t); i++ {
		if i == dot {
			continue
		}
		if t[i] < '0' || t[i] > '9' {
			return Field{}, false
		}
	}
	return f, true
}
