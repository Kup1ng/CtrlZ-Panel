package pwstrength_test

import (
	"math/rand/v2"
	"strings"
	"testing"

	"github.com/ccojocar/zxcvbn-go"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/password"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/pwstrength"
)

// TestRandomPasswordsAreNotRefusedAsCommon is primitives-r19-1 and r19-3: the Persian layer only
// lowers a score, and it priced random text far below its entropy (a run of random letters that
// reduces to the vowel-free skeleton of a common word was "Finglish"), so a strong random password was
// refused as too_common. A seeded set of random passwords of the lengths people really draw is judged by
// the checker and by zxcvbn alone; the layer may refuse none that zxcvbn accepts, beyond a rounding
// slack, so a user who drew a random password is not told it is common. zxcvbn alone is the typed
// reading and the Latin readings of Persian letters (the readings Check scores with it), so a refusal
// that is zxcvbn's own is not counted.
func TestRandomPasswordsAreNotRefusedAsCommon(t *testing.T) {
	const (
		lower   = "abcdefghijklmnopqrstuvwxyz"
		mixed   = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
		persian = "ابپتثجچحخدذرزژسشصضطظعغفقکگلمنوهی"
	)
	c := pwstrength.New()
	in := pwstrength.Input{Phone: "+989121234567", Username: "ali"}
	rng := rand.New(rand.NewPCG(19, 3))
	draw := func(alphabet string, n int) string {
		rs := []rune(alphabet)
		var b strings.Builder
		for range n {
			b.WriteRune(rs[rng.IntN(len(rs))])
		}
		return b.String()
	}
	for _, tc := range []struct {
		name     string
		alphabet string
		n        int
		kind     password.Kind
		slack    int // draws of 300 the layer may refuse
	}{
		{"user, 10 random lowercase letters", lower, 10, password.User, 12},
		{"user, 12 random lowercase letters", lower, 12, password.User, 2},
		{"user, 12 random letters and digits", mixed, 12, password.User, 2},
		{"user, 10 random letters and digits", mixed, 10, password.User, 12},
		{"user, 10 random Persian letters", persian, 10, password.User, 12},
		{"user, 12 random Persian letters", persian, 12, password.User, 2},
		{"admin, 14 random letters and digits", mixed, 14, password.Admin, 2},
		{"admin, 14 random Persian letters", persian, 14, password.Admin, 2},
		{"admin, 14 random lowercase letters", lower, 14, password.Admin, 2},
		{"admin, 16 random letters and digits", mixed, 16, password.Admin, 2},
	} {
		const draws = 300
		extra := 0
		var first string
		for range draws {
			pw := draw(tc.alphabet, tc.n)
			if zxcvbnRefuses(c, pw, tc.kind) {
				continue // refused by zxcvbn alone: not this layer's doing
			}
			if r := check(c, pw, in, tc.kind); !r.OK {
				extra++
				if first == "" {
					first = pw
				}
			}
		}
		// The slack is two in 300 (under 1 percent) from 12 characters up. A random run of 10 letters
		// reduces to the skeleton of a short common word in a few percent of draws, and the layer
		// used to refuse 13 to 20 percent of them.
		if extra > tc.slack {
			t.Errorf("%s: the Persian layer refused %d of %d random passwords that zxcvbn accepts (first: %q)", tc.name, extra, draws, first)
		}
	}
}

// zxcvbnRefuses is whether zxcvbn alone, on the typed text and on the Latin readings of Persian
// letters, scores the password below the minimum for the kind.
func zxcvbnRefuses(c *pwstrength.Checker, pw string, kind password.Kind) bool {
	for _, r := range append([]string{pw}, pwstrength.Readings(c, pw)...) {
		if zxcvbn.PasswordStrength(r, nil).Score < pwstrength.MinScore(kind) {
			return true
		}
	}
	return false
}
