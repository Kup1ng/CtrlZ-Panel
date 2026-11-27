package httpx

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"unicode"

	"github.com/Kup1ng/CtrlZ-Panel/api"
)

// TestMultilinePatternIsTheOnePatternOfTheDocument holds the Go constant and the document together, and walks every code point
// through the pattern: a character passes exactly when it is not a control, format or private-use character, or when it is one of
// the marks MultilineMark names (p3-D6-r2-1 and -10).
func TestMultilinePatternIsTheOnePatternOfTheDocument(t *testing.T) {
	if !strings.Contains(string(api.Tenant()), "multiline: &multiline '"+MultilinePattern+"'") {
		t.Fatal("api/openapi.yaml does not carry httpx.MultilinePattern as the anchor multiline")
	}
	re := regexp.MustCompile(MultilinePattern)
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if r >= 0xd800 && r <= 0xdfff {
			continue
		}
		want := !unicode.In(r, unicode.C) || MultilineMark(r)
		if got := re.MatchString("a" + string(r) + "a"); got != want {
			t.Fatalf("MultilinePattern on U+%04X: %v, want %v", r, got, want)
		}
	}
}

// TestFeedbackBodyTakesLinesAndRefusesTheRest runs the feedback schema itself: a two-paragraph Persian message with the marks passes,
// and a NUL, a bidi override, a zero width space, a message that starts with a blank or a line break and an empty one do not.
func TestFeedbackBodyTakesLinesAndRefusesTheRest(t *testing.T) {
	v, ops := bulkValidator(t)
	op := opByID(t, ops, "createFeedback")
	check := func(body string) *Error {
		raw, _ := json.Marshal(map[string]string{"kind": "feature", "body": body})
		return checkBody(t, v, op, string(raw))
	}
	for name, body := range map[string]string{
		"two lines":           "سلام\nلطفا حالت تاریک اضافه کنید\n",
		"crlf":                "a\r\nb",
		"a tab":               "a\tb",
		"the marks":           "سلام\u200f و hello\u200e نیم\u200cفاصله \u200d",
		"a message of 4000":   strings.Repeat("ب\n", 2000),
		"a trailing new line": "a\n\n",
	} {
		if e := check(body); e != nil {
			t.Errorf("%s is refused: %d %s", name, e.Status, e.Code)
		}
	}
	for name, body := range map[string]string{
		"NUL":                        "a\x00b",
		"a bell":                     "a\x07b",
		"NEL":                        "a\u0085b",
		"the right to left override": "a\u202eb",
		"an isolate":                 "a\u2067b",
		"a zero width space":         "a\u200bb",
		"a private use point":        "a\ue000b",
		"a leading new line":         "\nhello",
		"a leading blank":            " hello",
		"empty":                      "",
	} {
		if e := check(body); e == nil {
			t.Errorf("%s is accepted", name)
		}
	}
}
