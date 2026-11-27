package phone_test

import (
	"strings"
	"testing"
	"unicode"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/digits"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/phone"
)

func TestNormalize(t *testing.T) {
	const want = "+989121234567"
	for _, in := range []string{
		// The five forms of spec 14.3.
		"09121234567", "9121234567", "989121234567", "+989121234567", "00989121234567",
		// Separators.
		"0912 123 4567", "0912-123-4567", "+98 912 123 4567", "+98-912-123-4567", "(0912) 123-4567", "  09121234567  ",
		"+98 (0) 912 123 4567", "+98 0912 123 4567", "+9809121234567",
		// Persian, Arabic-Indic and fullwidth digits.
		"۰۹۱۲۱۲۳۴۵۶۷", "٠٩١٢١٢٣٤٥٦٧", "０９１２１２３４５６７", "+۹۸۹۱۲۱۲۳۴۵۶۷", "۰۹۱۲ ۱۲۳ ۴۵۶۷",
		// Mixed scripts, and the invisible marks of a copy from a chat app.
		"0912١٢٣4567",
		marks(0x200e) + "+98" + marks(0xa0) + "912" + marks(0x2011) + "123" + marks(0x2011) + "4567" + marks(0x200f),
		marks(0x202a) + "09121234567" + marks(0x202c),
		// A non-breaking and an ideographic space fold through NFKC.
		"0912" + marks(0xa0) + "123" + marks(0xa0) + "4567", "0912" + marks(0x3000) + "123" + marks(0x3000) + "4567",
	} {
		got, err := phone.Normalize(in)
		if err != nil || got != want {
			t.Errorf("Normalize(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
}

func TestNormalizeRefuses(t *testing.T) {
	for name, in := range map[string]string{
		"empty":                 "",
		"spaces":                "   ",
		"letters":               "0912abc4567",
		"too short":             "091212345",
		"too long":              "091212345678",
		"landline (Tehran)":     "02112345678",
		"landline with plus":    "+982112345678",
		"does not start with 9": "08121234567",
		"other country":         "+14155550123",
		"other country 0044":    "00447911123456",
		"plus in the middle":    "0912+1234567",
		"two pluses":            "++989121234567",
		"plus after digits":     "98+9121234567",
		"dot separators":        "0912.123.4567",
		"slash":                 "0912/1234567",
		"trailing text":         "09121234567 call me",
		"sql":                   "0912'; DROP TABLE users;--",
		"only country code":     "+98",
		"98 with 13 digits":     "9809121234567890",
		"huge":                  strings.Repeat("9", 5000),
		"invalid utf8":          "0912\xff1234567",
		"emoji":                 "09121234567😀",
		"unicode letter":        "0912123456٧a",
	} {
		if got, err := phone.Normalize(in); err == nil {
			t.Errorf("%s: Normalize(%q) = %q, want an error", name, in, got)
		} else if err != phone.ErrInvalid || strings.Contains(err.Error(), "0912") {
			t.Errorf("%s: error = %q", name, err)
		}
	}
}

// TestNormalizeIsIdempotent: the output is itself a valid input that maps to
// itself, which Valid relies on.
func TestNormalizeIsIdempotent(t *testing.T) {
	for _, in := range []string{"09121234567", "+989351234567", "00989901234567", "9999999999"} {
		once, err := phone.Normalize(in)
		if err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		twice, err := phone.Normalize(once)
		if err != nil || twice != once {
			t.Errorf("%q -> %q -> %q, %v", in, once, twice, err)
		}
		if !phone.Valid(once) {
			t.Errorf("Valid(%q) = false", once)
		}
	}
	for _, s := range []string{"09121234567", "", "+14155550123", "+98912123456"} {
		if phone.Valid(s) {
			t.Errorf("Valid(%q) = true", s)
		}
	}
}

func TestMask(t *testing.T) {
	for in, want := range map[string]string{
		"+989121234567":  "+98912***4567", // spec 12.1
		"+989351234567":  "+98935***4567",
		"+14155550123":   "+1415***0123",
		"+4915112345678": "+49151****5678",
		"+12345678":      "+1***5678",
		"+1234567":       "+***67",
		"+12":            "+***",
		"":               "***",
		"989121234567":   "***", // no plus: not an E.164 number
		"not a phone":    "***",
	} {
		got := phone.Mask(in)
		if got != want {
			t.Errorf("Mask(%q) = %q, want %q", in, got, want)
		}
		if len(in) > 4 && strings.Contains(got, in[1:]) {
			t.Errorf("Mask(%q) holds the whole number", in)
		}
	}
	// Whatever the length, no more than 9 digits survive and the middle is hidden.
	for n := 0; n <= 16; n++ {
		in := "+" + strings.Repeat("7", n)
		out := phone.Mask(in)
		if n >= 1 && out == in {
			t.Errorf("Mask(%q) is unchanged", in)
		}
		if strings.Count(out, "7") > 9 {
			t.Errorf("Mask(%q) = %q shows too many digits", in, out)
		}
	}
}

// marks builds a string from code points, so the invisible characters in the
// cases above are readable in the source.
func marks(rs ...rune) string { return string(rs) }

func TestSearchPrefix(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"09121234567", "+989121234567"}, // a full number is Normalize's answer
		{"0912", "+989 12"},
		{"912", "+98912"},
		{"+98912", "+98912"},
		{"+98", "+98"},
		{"9", "+989"},
		{"0", "+98"},
		{"98912", "+98912"},
		{"۰۹۱۲", "+98912"},
		{"0912 12", "+9891212"},
		{"", "+98"},
	} {
		got, err := phone.SearchPrefix(c.in)
		want := strings.ReplaceAll(c.want, " ", "")
		if err != nil || got != want {
			t.Errorf("phone.SearchPrefix(%q) = %q, %v; want %q", c.in, got, err, want)
		}
	}
	for _, bad := range []string{"abc", "0812", "+1555", "12", "09121234567890123", "09'; DROP", "%"} {
		if got, err := phone.SearchPrefix(bad); err == nil {
			t.Errorf("SearchPrefix(%q) = %q, want an error", bad, got)
		}
	}
}

// TestMaskForLogLeavesAHundredThousandCandidates (primitives-r5-13): the form of an audit row
// keeps the operator prefix and the last two digits, so a reader of the log cannot recover
// a number by trying the 1,000 completions the display form leaves.
func TestMaskForLogLeavesAHundredThousandCandidates(t *testing.T) {
	for in, want := range map[string]string{
		"+989121234567":  "+98912*****67",
		"+989351112233":  "+98935*****33",
		"+14155550123":   "+1415*****23",
		"+4915112345678": "+49151******78",
		"+12345678":      "+1*****78",
		"+1234567":       "+***67",
		"":               "***",
		"989121234567":   "***",
	} {
		if got := phone.MaskForLog(in); got != want {
			t.Errorf("MaskForLog(%q) = %q, want %q", in, got, want)
		}
	}
	for n := 8; n <= 15; n++ {
		in := "+" + strings.Repeat("7", n)
		out := phone.MaskForLog(in)
		if strings.Count(out, "*") < 5 || strings.Count(out, "7") > 7 {
			t.Errorf("MaskForLog(%q) = %q hides fewer than 5 digits or shows more than 7", in, out)
		}
	}
}

// TestEveryPasteMarkIsASeparator plants every code point of the paste class (format characters,
// variation selectors, assigned default-ignorables, tab, line feed, carriage return, the line and
// paragraph separators) at the front, inside and at the end of a number (round 14,
// primitives-r14-1). The separator rule is digits.PasteMark, so a mark nobody listed is read the
// day Unicode has it; a visible letter is still not a separator.
func TestEveryPasteMarkIsASeparator(t *testing.T) {
	const want = "+989121234567"
	n := 0
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if !digits.PasteMark(r) {
			continue
		}
		n++
		m := string(r)
		in := m + "0912" + m + "1234567" + m
		if got, err := phone.Normalize(in); err != nil || got != want {
			t.Fatalf("Normalize with U+%04X: %q %v", r, got, err)
		}
		if got, err := phone.SearchPrefix(m + "0912" + m); err != nil || got != "+98912" {
			t.Fatalf("SearchPrefix with U+%04X: %q %v", r, got, err)
		}
	}
	if n < 400 {
		t.Fatalf("only %d paste marks: the class has shrunk", n)
	}
	for _, bad := range []string{"0912a1234567", "0912\u0000" + "1234567", "0912\ue0001234567", "0912\u00001234567"} {
		if _, err := phone.Normalize(bad); err == nil {
			t.Errorf("%q was read as a number", bad)
		}
	}
}
