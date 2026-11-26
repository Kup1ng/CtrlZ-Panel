// Package phone turns what a person typed into the one E.164 form the database
// stores, and turns a stored number into the masked form that may be shown or
// logged (spec 14.3, 12.1).
//
// v1 accepts Iranian mobile numbers only, "+989XXXXXXXXX". The column accepts
// any E.164 number (its CHECK is "^\+[1-9][0-9]{7,14}$"), so widening this later
// needs no migration (section 19 item 6).
package phone

import (
	"errors"
	"strings"

	"golang.org/x/text/unicode/norm"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/digits"
)

// ErrInvalid is the one error: the handler answers 422 invalid_phone, or 401
// invalid_credentials on password login, where a bad format must not vary the
// response (4.5). It never repeats the input.
var ErrInvalid = errors.New("phone: not an Iranian mobile number")

// maxInput bounds the work done on hostile input. A real number with spaces,
// hyphens and marks is far shorter.
const maxInput = 64

// Normalize accepts Persian, Arabic and ASCII digits, spaces and hyphens, and
// the forms 09…, 9…, 989…, +989…, 00989… (and +98 0 9… as people write it). The
// result is "+989XXXXXXXXX".
//
// NFKC runs first, which folds fullwidth digits and compatibility spaces; the
// digit mapping then handles the scripts NFKC leaves alone.
func Normalize(raw string) (string, error) {
	if len(raw) > maxInput*4 {
		return "", ErrInvalid
	}
	s := digits.ToASCII(norm.NFKC.String(raw))

	var d strings.Builder
	plus := false
	started := false
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
			started = true
			d.WriteRune(r)
		case r == '+':
			// Only as the first meaningful character.
			if started || plus {
				return "", ErrInvalid
			}
			plus = true
		case isSeparator(r):
			// Ignored. Copy-paste from a chat app brings direction marks and
			// non-breaking spaces; a person types spaces and hyphens.
		default:
			return "", ErrInvalid
		}
	}
	n := d.String()
	if len(n) > maxInput {
		return "", ErrInvalid
	}

	// Strip the country prefix in whichever spelling, leaving the national
	// 10-digit number that starts with 9.
	switch {
	case plus && strings.HasPrefix(n, "98"):
		n = n[2:]
	case !plus && strings.HasPrefix(n, "0098"):
		n = n[4:]
	case !plus && strings.HasPrefix(n, "98") && len(n) == 12:
		n = n[2:]
	case plus:
		// A plus with another country code.
		return "", ErrInvalid
	}
	// "+98 0 912…": the trunk zero written after the country code.
	n = strings.TrimPrefix(n, "0")

	if len(n) != 10 || n[0] != '9' {
		return "", ErrInvalid
	}
	return "+98" + n, nil
}

// isSeparator reports characters that may sit between the digits: the space kinds, the hyphen and
// dash kinds, the minus sign, parentheses, and every paste mark (digits.PasteMark: the invisible
// characters a right-to-left keyboard or a chat app leaves behind, by class and not by a list,
// round 14, primitives-r14-1; tab, line feed and carriage return). A visible character that is
// none of these is not a separator, so "09ab" is still not a number.
func isSeparator(r rune) bool {
	switch r {
	case ' ', '-', '(', ')',
		0x00a0,                                         // no-break space
		0x2010, 0x2011, 0x2012, 0x2013, 0x2014, 0x2015, // hyphens and dashes
		0x2212: // minus sign
		return true
	}
	return digits.PasteMark(r)
}

// Mask shows the start and the last four digits and hides the middle:
// "+989121234567" becomes "+98912***4567" (12.1). It is for the UI, audit rows
// and the authenticator's display name, never for lookups. A value too short to
// hide anything useful is shown as "+***" plus its last two digits, so Mask can
// never return a full number.
func Mask(e164 string) string {
	if !strings.HasPrefix(e164, "+") {
		return "***"
	}
	d := e164[1:]
	if len(d) < 8 {
		if len(d) < 3 {
			return "+***"
		}
		return "+***" + d[len(d)-2:]
	}
	// Keep five leading digits and four trailing ones, hide the rest.
	head, tail := 5, 4
	hidden := len(d) - head - tail
	if hidden < 3 {
		head -= 3 - hidden
		hidden = 3
	}
	return "+" + d[:head] + strings.Repeat("*", hidden) + d[len(d)-tail:]
}

// MaskForLog is the form of a number in an audit row and in anything an operator, a backup
// or a leaked export can read: the country code and operator prefix and the last two
// digits, "+989121234567" becomes "+98912*****67". Mask leaves 1,000 candidates for an
// Iranian number and a person who can read the audit log recovers the whole number with at
// most 1,000 tries against any per-number oracle (an OTP request, a public list); this form
// leaves 100,000, and the log shows what is needed to tell two numbers of one account apart
// (primitives-r5-13, spec 12.1 and 13.3). Mask is for the owner looking at their own number.
// A value too short to hide five digits shows fewer leading ones, and one under 8 digits is
// Mask's own short form.
func MaskForLog(e164 string) string {
	if !strings.HasPrefix(e164, "+") || len(e164)-1 < 8 {
		return Mask(e164)
	}
	d := e164[1:]
	head, tail := 5, 2
	hidden := len(d) - head - tail
	if hidden < 5 {
		head -= 5 - hidden
		hidden = 5
	}
	return "+" + d[:head] + strings.Repeat("*", hidden) + d[len(d)-tail:]
}

// Valid reports whether s is already in the canonical form Normalize produces.
// Code that reads a number from the database or a signed token uses it as a
// cheap sanity check.
func Valid(s string) bool {
	n, err := Normalize(s)
	return err == nil && n == s
}

// SearchPrefix turns what an admin typed into the filter of the Users list: a
// prefix of the canonical "+989XXXXXXXXX". It accepts the same digits, spaces
// and the same leading forms as Normalize, but a partial number is fine, so
// "0912", "912", "+98912" and "۰۹۱۲" all mean the same prefix. A complete number
// returns exactly Normalize's result. It reports ErrInvalid for anything that
// cannot start an Iranian mobile number, so the filter never carries text a
// LIKE or a log could misread.
func SearchPrefix(raw string) (string, error) {
	if full, err := Normalize(raw); err == nil {
		return full, nil
	}
	if len(raw) > maxInput*4 {
		return "", ErrInvalid
	}
	s := digits.ToASCII(norm.NFKC.String(raw))
	var d strings.Builder
	plus := false
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
			d.WriteRune(r)
		case r == '+':
			if d.Len() > 0 || plus {
				return "", ErrInvalid
			}
			plus = true
		case isSeparator(r):
		default:
			return "", ErrInvalid
		}
	}
	n := d.String()
	if len(n) > maxInput {
		return "", ErrInvalid
	}
	switch {
	case plus:
		// "+" alone, or "+9…" typed by someone who forgot the country code.
		n = strings.TrimPrefix(n, "98")
	case strings.HasPrefix(n, "0098"):
		n = n[4:]
	case strings.HasPrefix(n, "98"):
		n = n[2:]
	}
	n = strings.TrimPrefix(n, "0")
	// What remains is the national part; it must start with 9 and fit in 10 digits.
	if len(n) > 10 || (n != "" && n[0] != '9') {
		return "", ErrInvalid
	}
	return "+98" + n, nil
}
