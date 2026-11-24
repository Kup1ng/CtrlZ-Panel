package pwstrength_test

import (
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/password"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/pwstrength"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
)

// TestBlindTypedPersianWordInFullwidthLettersIsRefusedAsTheAsciiFormIs is primitives-r26-1. The stored password
// is the NFKC form, so "ｓｇｈｌｓｇｈｌ1400" is "sghlsghl1400" to a guesser, but the blind-typed Persian reading
// began from the typed text alone and never saw the word.
func TestBlindTypedPersianWordInFullwidthLettersIsRefusedAsTheAsciiFormIs(t *testing.T) {
	c := pwstrength.New()
	in := pwstrength.Input{Phone: "+989121234567", Username: "ali"}
	for _, tc := range []struct{ ascii, wide string }{
		{"sghlsghl1400", "ｓｇｈｌｓｇｈｌ1400"},
		{"vlcufmv123456", "ｖｌｃｕｆｍｖ123456"},
		{"Sghlsghl1400", "Ｓｇｈｌｓｇｈｌ1400"}, // a capital that is fullwidth too
		{"Vlcufmv123456", "Ｖｌｃｕｆｍｖ123456"},
	} {
		if r := check(c, tc.ascii, in, password.User); r.OK {
			t.Fatalf("%s: accepted %+v, the premise of the test is that it is refused", tc.ascii, r)
		}
		if r := check(c, tc.wide, in, password.User); r.OK {
			t.Errorf("%s: accepted %+v, want refused as %s is", tc.wide, r, tc.ascii)
		}
	}
}

// TestCheckScoresARepeatedStringOnce is primitives-r26-4. The readings of one password (typed, normalised, the
// layout readings, the stripped ones, the blind Persian ones) share their tails and residues, and a check
// used to run zxcvbn on each of them again. A password with a long tail after a short head and an invisible
// character has the same tail in every reading, so zxcvbn must run on it once.
func TestCheckScoresARepeatedStringOnce(t *testing.T) {
	c := pwstrength.New()
	in := pwstrength.Input{Phone: "+989121234567", Username: "ali"}
	for _, pw := range []string{
		"\u200bسلامسلام@dm1n\u200b!5ecr3t-Zq7Lp9Xv2Kd8Wm4Rt6Yb3Nh5Jc1Gf0-Tail-Tail",
		"Vlcufmv\u200b1400-Zq7Lp9Xv2Kd8Wm4Rt6Yb3Nh5Jc1Gf0Ut8Se2Ao9Bi4Ol6",
	} {
		p, err := password.Prepare(secret.New(pw), password.User)
		if err != nil {
			t.Fatal(err)
		}
		lookups, runs := pwstrength.ZxCounts(c, p, in, password.User)
		if runs == 0 || runs >= lookups {
			t.Errorf("%q: zxcvbn ran %d times for %d lookups, want fewer runs than lookups", pw, runs, lookups)
		}
	}
}

// TestCheckStopsAtTheFirstReadingThatScoresZero is primitives-r26-4. Nothing scores below 0, so the readings after a 0
// cannot change the verdict and cost a scoring slot for nothing. "iloveyou" followed by Persian letters scores 0
// as typed and has a layout reading and the blind readings besides.
func TestCheckStopsAtTheFirstReadingThatScoresZero(t *testing.T) {
	c := pwstrength.New()
	in := pwstrength.Input{Phone: "+989121234567", Username: "ali"}
	p, err := password.Prepare(secret.New("iloveyouشسیشسی1"), password.User)
	if err != nil {
		t.Fatal(err)
	}
	if got := pwstrength.ScoredReadings(c, p, in, password.User); got > 2 {
		t.Errorf("%d readings were scored, want 2 at most: the typed text and the layout reading that scores 0, and nothing after it", got)
	}
}
