package pwstrength_test

// Invisible characters (round 10, primitives-r10-1 and -2). A zero-width character is typed and not
// shown, so it splits a phone number, a keyboard walk or a word for a scorer that reads the typed
// text and means nothing to a guesser who runs the dictionary. The Persian keyboard types the
// zero-width non-joiner on Shift+B, which makes it the likeliest separator. The checker scores every
// reading a second time with them removed and the lowest score counts; these tests are that rule.
//
// The code points are numbers, not literals: an invisible character in a source file is the
// thing a reviewer cannot see.

import (
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/password"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/pwstrength"
)

// invisibles are one of each kind the rule names: the format characters (zero-width space, non-joiner, joiner,
// marks, word joiner, soft hyphen, byte order mark, Arabic letter mark), a variation selector, and the
// default-ignorable code points outside Cf (combining grapheme joiner, Hangul filler).
var invisibles = []rune{0x200b, 0x200c, 0x200d, 0x200e, 0x200f, 0x2060, 0x2063, 0x00ad, 0xfeff, 0x061c, 0xfe0f, 0x034f, 0x115f}

// insertAt puts r into s after n runes.
func insertAt(s string, n int, r rune) string {
	rs := []rune(s)
	n = min(n, len(rs))
	return string(rs[:n]) + string(r) + string(rs[n:])
}

func TestContainsPhoneSeesThroughInvisibleCharacters(t *testing.T) {
	c := pwstrength.New()
	in := pwstrength.Input{Phone: "+989121234567"}
	base := "Tehran1234567xYq"
	if r := check(c, base, in, password.User); r.Reason != pwstrength.ContainsPhone {
		t.Fatalf("the control is not refused for the phone: %+v", r)
	}
	for _, inv := range invisibles {
		// Between every pair of the seven digits, and next to a separator.
		for n := len("Tehran") + 1; n < len("Tehran1234567"); n++ {
			pw := insertAt(base, n, inv)
			if r := check(c, pw, in, password.User); r.OK || r.Reason != pwstrength.ContainsPhone || r.Score != 0 {
				t.Errorf("U+%04X after %d runes: %+v", inv, n, r)
			}
		}
		pw := strings.Replace(base, "123", "12-"+string(inv)+"3", 1)
		if r := check(c, pw, in, password.User); r.Reason != pwstrength.ContainsPhone {
			t.Errorf("U+%04X next to a hyphen: %+v", inv, r)
		}
	}
	// A character that is not invisible still keeps the digits apart: six digits and a letter is fine.
	if r := check(c, "Tehran123x4567Zq", in, password.User); r.Reason == pwstrength.ContainsPhone {
		t.Error("a visible letter between the digits was flagged")
	}
}

func TestAnInvisibleCharacterInsideAWeakPasswordDoesNotMakeItStrong(t *testing.T) {
	c := pwstrength.New()
	in := pwstrength.Input{Phone: "+989121234567"}
	for _, weak := range []string{"qwertyuiop12", "abcdefghijkl", "password1234", "iloveyou2024", "1q2w3e4r5t6y"} {
		if r := check(c, weak, in, password.User); r.OK {
			t.Fatalf("the control %q is accepted: %+v", weak, r)
		}
		for _, inv := range invisibles {
			for _, n := range []int{3, len(weak) / 2, len(weak) - 2} {
				pw := insertAt(weak, n, inv)
				if r := check(c, pw, in, password.User); r.OK {
					t.Errorf("%q with U+%04X after %d runes is accepted: score %d", weak, inv, n, r.Score)
				}
			}
		}
	}
}

func TestInvisibleCharactersDoNotRefuseAStrongPassword(t *testing.T) {
	// The reading with them removed can only lower a score; a strong password with a
	// zero-width non-joiner in a Persian word (as the keyboard types it) stays strong.
	c := pwstrength.New()
	for _, pw := range []string{insertAt("Vk9#Lmq2-zT", 6, 0x200c), insertAt("plum-Zq9-lantern-Xr4", 9, 0x200b)} {
		if r := check(c, pw, pwstrength.Input{}, password.User); !r.OK {
			t.Errorf("%q refused: %+v", pw, r)
		}
	}
}
