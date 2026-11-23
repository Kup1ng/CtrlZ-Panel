package pwstrength_test

// What may sit between the digits of the user's own phone number inside a password
// (round 13, primitives-r13-4; rule strength-gate-corpus). Round 10 closed the invisible
// characters and left a block list of four visible separators, so "0912/123/4567" was accepted
// at score 3. The rule is now the complement (only letters and digits are part of a number),
// and these tests do not list separators: they take them from the Unicode classes and from the
// phone package, so a separator nobody thought of is still planted.

import (
	"strconv"
	"strings"
	"testing"
	"unicode"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/password"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/phone"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/pwstrength"
)

// separatorSamples is one or two members of every Unicode class that is not a letter, a digit
// or a mark of a letter: punctuation (Pc Pd Ps Pe Pi Pf Po), symbols (Sm Sc Sk So), separators
// (Zs Zl Zp), controls and format characters (Cc Cf), combining marks (Mn). The first and the
// middle range of each table are taken, so the sample is not a hand-picked list. The characters
// of the finding itself come first, as numbers because several are invisible or look alike.
func separatorSamples() []rune {
	out := []rune{'/', ',', '(', ')', '+', 0x5c, '|', ':', ';', '*', '#', '~',
		0x2010, 0x2011, 0x2012, 0x2013, 0x2014, 0x2015, 0x2212,
		0x060c, 0x066c, 0x066b, 0x061b, 0x00a0, 0x3000, 0x200b, 0x200c, 0x200f}
	seen := map[rune]bool{}
	for _, r := range out {
		seen[r] = true
	}
	for _, tab := range []*unicode.RangeTable{
		unicode.Pc, unicode.Pd, unicode.Ps, unicode.Pe, unicode.Pi, unicode.Pf, unicode.Po,
		unicode.Sm, unicode.Sc, unicode.Sk, unicode.So, unicode.Zs, unicode.Zl, unicode.Zp,
		unicode.Cc, unicode.Cf, unicode.Mn,
	} {
		for _, i := range []int{0, len(tab.R16) / 2} {
			if i < len(tab.R16) {
				if r := rune(tab.R16[i].Lo); !seen[r] {
					seen[r] = true
					out = append(out, r)
				}
			}
		}
		if len(tab.R32) > 0 {
			if r := rune(tab.R32[0].Lo); !seen[r] {
				seen[r] = true
				out = append(out, r)
			}
		}
	}
	return out
}

// phoneForms are the ways one number is written: national, and with the country code and a plus
// (the form with the code alone has the same last seven digits).
var phoneForms = []string{"09121234567", "+989121234567"}

// phoneSeparatedRules writes the phone in each form with one separator at every position of
// the digits, and with the separator at the groups people write ("0912/123/4567"). A strong
// prefix keeps the rest of the password out of the way, so the only thing that can refuse it
// is the phone rule.
func phoneSeparatedRules() []candidate {
	var out []candidate
	for _, sep := range separatorSamples() {
		s := string(sep)
		tag := "phone separated by U+" + strconv.FormatInt(int64(sep), 16)
		for _, form := range phoneForms {
			rs := []rune(form)
			for at := len(rs) - 6; at < len(rs); at++ { // a cut outside the last seven digits hides nothing
				out = append(out, candidate{pw: "Zq!lantern-" + string(rs[:at]) + s + string(rs[at:]), how: tag + " at " + strconv.Itoa(at)})
			}
		}
		out = append(out,
			candidate{pw: "Zq!lantern-0912" + s + "123" + s + "4567", how: tag + " in groups 4-3-4"},
			candidate{pw: "Zq!lantern-+98" + s + "912" + s + "123" + s + "4567", how: tag + " in groups 98-3-3-4"},
			candidate{pw: "Zq!lantern-+98(912)123" + s + "4567", how: tag + " with parentheses"},
		)
	}
	return out
}

func TestPhoneIsRefusedWhateverSitsBetweenItsDigits(t *testing.T) {
	c := pwstrength.New()
	in := pwstrength.Input{Phone: testPhone}
	cands := phoneSeparatedRules()
	for _, k := range []password.Kind{password.User, password.Admin} {
		for _, cand := range cands {
			if r := check(c, cand.pw, in, k); r.OK || r.Reason != pwstrength.ContainsPhone {
				t.Errorf("kind %v, %s -> %q: %+v", k, cand.how, cand.pw, r)
			}
		}
	}
	// The two spellings of the finding, as written there.
	for _, pw := range []string{"0912/123/4567", "+98(912)123/4567", "0912,123,4567", "0912\u060c123\u060c4567"} {
		if r := check(c, pw, in, password.User); r.Reason != pwstrength.ContainsPhone {
			t.Errorf("%q: %+v", pw, r)
		}
	}
}

// TestEverySeparatorOfThePhoneParserIsSeenThrough ties the two definitions of "the characters
// that sit between the digits of a phone number" together: the phone package accepts them, the
// strength rule must see through every one. The set is read from phone.Normalize over all code
// points, so a separator added to the parser later is covered without a line here.
func TestEverySeparatorOfThePhoneParserIsSeenThrough(t *testing.T) {
	const want = "+989121234567"
	c := pwstrength.New()
	in := pwstrength.Input{Phone: want}
	var accepted []rune
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if r >= 0xd800 && r <= 0xdfff {
			continue
		}
		if got, err := phone.Normalize("0912" + string(r) + "123" + string(r) + "4567"); err == nil && got == want {
			accepted = append(accepted, r)
		}
	}
	// The premise: the parser has separators at all, and the usual ones are among them.
	have := map[rune]bool{}
	for _, r := range accepted {
		have[r] = true
	}
	for _, r := range []rune{' ', '-', '(', ')', 0x00a0, 0x2013, 0x2212, 0x200f} {
		if !have[r] {
			t.Fatalf("the phone parser does not accept U+%04X: the premise of this test is gone (%d separators read)", r, len(accepted))
		}
	}
	for _, r := range accepted {
		pw := "Zq!lantern-0912" + string(r) + "123" + string(r) + "4567"
		if res := check(c, pw, in, password.User); res.Reason != pwstrength.ContainsPhone {
			t.Errorf("U+%04X is a separator of the phone parser and hides the number from the strength rule: %+v", r, res)
		}
	}
}

func TestALetterBetweenTheDigitsStillBreaksTheRun(t *testing.T) {
	c := pwstrength.New()
	in := pwstrength.Input{Phone: testPhone}
	for _, pw := range []string{"Tehran123x4567Zq", "Tehran123/x/4567Zq", "Tehran123/\u0627/4567Zq", "Tehran123,12,3456Zq"} {
		if r := check(c, pw, in, password.User); r.Reason == pwstrength.ContainsPhone {
			t.Errorf("%q was flagged: %+v", pw, r)
		}
	}
	if !strings.Contains(testPhone, "1234567") {
		t.Fatal("the test phone changed")
	}
}
