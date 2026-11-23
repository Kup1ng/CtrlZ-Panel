// Package digits turns the digits people type into ASCII ones. Phones, TOTP
// codes and passwords all arrive from Persian keyboards, where the digit keys
// produce U+06F0..U+06F9, and from Arabic ones, which produce U+0660..U+0669.
// One small package keeps the three callers on one table.
package digits

import (
	"strings"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

// ToASCII replaces Persian (extended Arabic-Indic), Arabic-Indic and fullwidth
// digits with 0-9 and leaves every other rune alone. Fullwidth digits are also
// folded by NFKC, which the callers run first, but a caller that skips NFKC
// should not get a different answer.
func ToASCII(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		b.WriteRune(Rune(r))
	}
	return b.String()
}

// Rune maps one rune the way ToASCII does.
func Rune(r rune) rune {
	switch {
	case r >= '۰' && r <= '۹':
		return '0' + (r - '۰')
	case r >= '٠' && r <= '٩':
		return '0' + (r - '٠')
	case r >= '０' && r <= '９':
		return '0' + (r - '０')
	}
	return r
}

// Invisible reports a code point that is typed and not shown: the format characters (Unicode
// category Cf: the zero-width space, joiners and marks U+200B to U+200F, the Arabic letter
// mark, the word joiner and the invisible operators U+2060 to U+2064, the soft hyphen, the byte
// order mark, the bidi embeddings and isolates, the tag block), the variation selectors and the
// other default-ignorable code points (the combining grapheme joiner, the Hangul fillers).
//
// It is a class and not a list, on purpose (round 14, primitives-r14-1, -3): the list this
// replaced held 17 marks and every round found one more that a right-to-left editor or a chat
// app inserts (the Arabic letter mark, the word joiner, the soft hyphen). The password
// strength gate, the phone parser and every typed code now ask this one function, and the
// request schemas' pattern for those fields is built from it (see PastePattern), so the three
// cannot drift apart.
func Invisible(r rune) bool {
	return unicode.In(r, unicode.Cf, unicode.Variation_Selector, unicode.Other_Default_Ignorable_Code_Point)
}

// PasteMark reports a character a paste carries along with a code or a phone number and that
// can never be part of what the person meant: the invisible characters, and the white space a
// copy from a line-wrapped note brings (tab, carriage return, line feed, the line and paragraph
// separators). A visible character is never one, so a letter that is not in a code is still
// "not a code".
//
// The one narrowing: a default-ignorable code point that Unicode has not assigned (U+2065, the
// block of U+FFF0, the tag block's gaps) is not a paste mark. The request schemas refuse every
// unassigned code point, as they refuse private use, and no editor inserts one; leaving them out
// keeps the fold and the pattern one rule (PastePattern is "not other, or a format character, or
// tab, line feed, carriage return"), which a test can compare code point by code point.
func PasteMark(r rune) bool {
	switch r {
	case '\t', '\n', '\r', 0x2028, 0x2029:
		return true
	}
	return unicode.Is(unicode.Cf, r) || (Invisible(r) && !unicode.Is(unicode.C, r))
}

// PastePattern is the request schemas' pattern (api/openapi.yaml and api/admin-openapi.yaml,
// the `pasted` anchor) for a field that is folded by Typed or by the phone parser. It is the
// `text` pattern (no control, format or private-use character) widened by exactly the part of
// PasteMark that `text` refuses: the format characters (category Cf) and the three control
// characters tab, line feed and carriage return. The rest of PasteMark is category Mn, Lo, Cn,
// Zl or Zp, which `text` already accepts. TestPastePatternIsThePasteMarkClass walks every code
// point through this pattern and PasteMark and fails for a disagreement, so a pattern that
// drifts from the rule is a test failure and not a code a route refuses (the fold of round 13
// was dead code for the marks it was written for because the schema refused them first).
const PastePattern = `^(?:[^\p{C}]|\p{Cf}|[\t\n\r])*$`

// PasteContentPattern is PastePattern for a typed code, phone or token that must be there: it needs a
// character that is neither a paste mark nor a separator, so an empty value, a blank one and one
// made only of marks never reach a keyed step (as the `content` pattern does for the rest). Marks AND
// separators may come before it: the fold drops both, and a phone pasted with a leading space
// worked on the `pasted` pattern and must keep working (round 18, tenant-r18-20).
const PasteContentPattern = `^(?:\p{Cf}|\p{Z}|[\t\n\r])*[^\p{C}\p{Z}](?:[^\p{C}]|\p{Cf}|[\t\n\r])*$`

// MaxTypedBytes bounds the raw bytes of a typed code before the fold runs (NFKC can expand one
// code point into eighteen). Every typed code refuses what is longer and none truncates it
// (round 14, primitives-r14-1): the SMS code used to read the first 64 bytes and ignore the
// rest, the other two refused at 96 and 128. It is the schema's 64 characters at four bytes
// each, so whatever the request schema lets through is read.
const MaxTypedBytes = 256

// Typed is the one fold every typed code goes through (round 13, primitives-r13-1):
// NFKC (a no-break space or a fullwidth form becomes its plain one), the digits of
// the Persian and Arabic keyboards as ASCII, and the paste marks dropped (PasteMark).
// otp.NormalizeCode, totp and recovery each folded in their own way, so a recovery
// code pasted with a direction mark was "not a code" and spent one of five tries
// while the same paste into the SMS box worked. It keeps the visible characters,
// spaces and hyphens included: grouping is each caller's own business.
//
// The caller bounds the input before the call (MaxTypedBytes), since NFKC can expand a single
// code point into eighteen.
func Typed(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range norm.NFKC.String(s) {
		if PasteMark(r) {
			continue
		}
		b.WriteRune(Rune(r))
	}
	return b.String()
}
