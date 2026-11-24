package pwstrength_test

import (
	"strings"
	"testing"

	"github.com/ccojocar/zxcvbn-go"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/password"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/pwstrength"
)

// TestPersianPasswordsAreRefusedWithAReason is primitives-r18-1 (D64 persian-passwords): a password in
// Persian letters that zxcvbn scored 3 or 4 is refused at the user level, as too_common, in every
// writing and every layout a person types it in; a password made of many words, or of letters no
// word explains, still passes.
func TestPersianPasswordsAreRefusedWithAReason(t *testing.T) {
	c := pwstrength.New()
	in := pwstrength.Input{Phone: "+989121234567", Username: "ali"}
	for name, pw := range map[string]string{
		"password and 123456":                   "پسورد123456",
		"the words for secret and password":     "رمزعبور1234",
		"hello and 123456":                      "سلام123456",
		"love and Persian digits":               "عشقمن۱۲۳۴۵۶",
		"two common words":                      "کتابخانهبزرگ",
		"one word three times":                  "ایرانایرانایران",
		"the same with the Arabic yeh":          "پسوردي123456",
		"the same with a half-space inside":     "پس\u200cورد123456",
		"the same with a zero-width space":      "پس\u200bورد123456",
		"the same typed blind on a US keyboard": "vlcufmv123456",
		"a Finglish word and 123456":            "salam123456",
		"a Finglish word with the long vowel":   "khoobi1234",
		"a Finglish name capitalised":           "Tehran1234",
		// zxcvbn alone scores each of these 3 or 4, so only the Finglish matching can refuse them
		// (primitives-r18-18: the three short cases above are low without it, and a mutant that removed
		// the matching survived).
		"Finglish words run together (love you)":  "doostdaramtoro",
		"Finglish words and a year (goodbye)":     "khodahafez2024",
		"Finglish words run together (thank you)": "mamnunamazshoma",
		"Finglish words run together (my mother)": "madaremmehraban",
	} {
		r := check(c, pw, in, password.User)
		if r.OK || r.Reason == "" {
			t.Errorf("%s (%q): %+v, want it refused with a reason", name, pw, r)
		}
		if a := check(c, pw, in, password.Admin); a.OK {
			t.Errorf("%s (%q): accepted at the admin level: %+v", name, pw, a)
		}
	}
	// The reason says what is wrong, the way the English words do.
	if r := check(c, "پسورد123456", in, password.User); r.Reason != pwstrength.TooCommon {
		t.Errorf("a Persian common word: reason %s, want too_common", r.Reason)
	}
	for name, pw := range map[string]string{
		"eight words":                  "اینیکرمزخیلیطولانیوقویاست",
		"five uncommon words in a row": "کلیدبنفشهمیزسیب",
		"letters no word explains":     "ژسذ%ضبقغ۷۱۹ءئ",
		"an English phrase":            "correcthorsebatterystaple",
		"a random Latin password":      "Xk9#mTq2$vLp",
	} {
		if r := check(c, pw, in, password.User); !r.OK {
			t.Errorf("%s (%q): %+v, want it accepted", name, pw, r)
		}
	}
}

// TestPersianScaleMatchesZxcvbn holds the one place the layer borrows from zxcvbn-go: the arithmetic
// that turns an entropy into a score. The Persian layer sums bits and asks scoreOfEntropy; if a bump of
// the module changes its scale, this fails, because the layer's score would then sit on another scale
// than the score it is compared with.
func TestPersianScaleMatchesZxcvbn(t *testing.T) {
	for _, s := range []string{"a", "ab12", "password", "Tr0ub4dor&3", "correcthorsebatterystaple", "qwertyuiop", "Xk9#mTq2$vLp", "1234567890", "iloveyou", "zxcvbnm,./", "aaaaaaaaaaaa", "abcdefghijklmnopqrstuvwxyz", "Zx8!qL3@wR7#tY5$", "monkey", "dragon123"} {
		res := zxcvbn.PasswordStrength(s, nil)
		if got := pwstrength.ScoreOfEntropy(res.Entropy); got != res.Score {
			t.Errorf("%q: entropy %.3f scores %d here and %d in zxcvbn-go", s, res.Entropy, got, res.Score)
		}
	}
}

// TestPersianLayerBoundIsAfterTheFold is primitives-r19-4: NFKC expands a compatibility character into
// several, so a text cut at 24 typed runes can have 100 after the fold, and zxcvbn is superlinear in
// what it is given. The layer cuts the folded text.
func TestPersianLayerBoundIsAfterTheFold(t *testing.T) {
	typed := "سلام" + strings.Repeat("⒇", 20) // twenty "(20)" signs: 4 + 80 runes folded
	if got := len([]rune(pwstrength.FoldedHead(typed))); got != 24 {
		t.Errorf("the layer scores %d runes of an expanding text, want 24", got)
	}
}

// TestFinglishTypedOnAPersianKeyboardIsRefused is primitives-r20-2: a Finglish phrase meant as a Latin
// password but typed with the Persian layout active reaches the checker as Persian letters, whose key
// positions read back as the Finglish phrase. Round 19 switched the Finglish matching off for those
// readings, and these phrases (zxcvbn scores each 3 or 4) were accepted at both floors. The matching
// runs there again, and counts only when it explains the whole run of Latin letters.
func TestFinglishTypedOnAPersianKeyboardIsRefused(t *testing.T) {
	c := pwstrength.New()
	in := pwstrength.Input{Phone: "+989121234567", Username: "ali"}
	for _, latin := range []string{"doostdaramtoro", "khodahafez2024", "mamnunamazshoma", "madaremmehraban"} {
		for i, typed := range pwstrength.OnPersianKeyboard(c, latin) {
			if typed == latin {
				t.Fatalf("%s: layout %d typed the Latin text itself, the test would not reach the key reading", latin, i)
			}
			if r := check(c, typed, in, password.User); r.OK || r.Reason != pwstrength.TooCommon {
				t.Errorf("%s on Persian layout %d (%q), user: %+v, want too_common", latin, i, typed, r)
			}
			if r := check(c, typed, in, password.Admin); r.OK {
				t.Errorf("%s on Persian layout %d (%q), admin: accepted: %+v", latin, i, typed, r)
			}
		}
	}
}

// TestShortPersianWordsInAPhraseCount is primitives-r20-3: a word of two letters (من, تو) is in every
// random run, so it counts only as a whole run or next to another piece, and Persian is typed without
// spaces, so the phrase "I am in love with you" is one run. It was priced as random letters and passed.
func TestShortPersianWordsInAPhraseCount(t *testing.T) {
	c := pwstrength.New()
	in := pwstrength.Input{Phone: "+989121234567", Username: "ali"}
	for _, pw := range []string{"منعاشقتوهستم", "منوتوباهمیم"} {
		if r := check(c, pw, in, password.User); r.OK || r.Reason != pwstrength.TooCommon {
			t.Errorf("%q: %+v, want too_common", pw, r)
		}
	}
}

// TestFinglishWithAnExtraLetterOnAPersianKeyboardIsRefused is primitives-r21-1: one Latin letter that no
// spelling explains switched the whole-run Finglish matching off, so the four phrases of r20-2 with a
// letter added before, after or in the middle were accepted on a Persian layout while the same Latin
// text is refused. The answer must not depend on which layout was on: a text is refused on the Persian
// layouts at a floor exactly when its Latin form is refused there.
func TestFinglishWithAnExtraLetterOnAPersianKeyboardIsRefused(t *testing.T) {
	c := pwstrength.New()
	in := pwstrength.Input{Phone: "+989121234567", Username: "ali"}
	for _, base := range []string{"doostdaramtoro", "khodahafez2024", "mamnunamazshoma", "madaremmehraban"} {
		mid := len(base) / 2
		for _, latin := range []string{"x" + base, base + "x", base[:mid] + "x" + base[mid:], base + "q"} {
			for _, kind := range []password.Kind{password.User, password.Admin} {
				if check(c, latin, in, kind).OK {
					continue // the Latin form passes at this floor, so there is nothing to hold the Persian layouts to
				}
				for i, typed := range pwstrength.OnPersianKeyboard(c, latin) {
					if r := check(c, typed, in, kind); r.OK {
						t.Errorf("%s on Persian layout %d (%q), kind %v: accepted (%+v), but the Latin text is refused", latin, i, typed, kind, r)
					}
				}
			}
		}
	}
}
