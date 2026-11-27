package pwstrength_test

import (
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/password"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/pwstrength"
)

// TestBlindTypedPersianWordWithCapitalsIsRefusedAsTheLowerCaseFormIs is primitives-r25-2. A Persian word
// typed with the keyboard left on US ("vlcufmv", the word for "password") was read back to Persian from
// the keys, but an upper-case Latin letter was read only as the shifted output of its key (Shift+V is a
// dagger alef that the fold removes, Shift+N a combining hamza), so "Vlcufmv1400" was no longer the word in
// any reading and scored as random letters while "vlcufmv1400" is refused. A capital is what a password
// form asks for, so the habit is the common one. The test builds the family from the checked-in word list
// and the layout data, the same path as the corpus, and holds the capitalised and the all-capitals form to
// the verdict of the lower-case form.
func TestBlindTypedPersianWordWithCapitalsIsRefusedAsTheLowerCaseFormIs(t *testing.T) {
	c := pwstrength.New()
	in := pwstrength.Input{Phone: "+989121234567", Username: "ali"}

	// The two cases the review measured, pinned as plain text.
	for _, pw := range []string{"Vlcufmv123456", "Sghlsghl1400"} {
		if r := check(c, pw, in, password.User); r.OK {
			t.Errorf("%s: accepted %+v, want refused as %s is", pw, r, strings.ToLower(pw))
		}
	}

	words := persianWords(t)[:400]
	tails := []string{"123456", "1400", "@1400"}
	checked, refusedLower := 0, 0
	for _, w := range words {
		if len([]rune(w)) < 4 {
			continue
		}
		for _, layout := range []string{"isiri9147", "kbdfa"} {
			us, ok := usKeys(t, layout, w)
			if !ok {
				continue
			}
			lower := strings.ToLower(us)
			if lower != us {
				continue // a word with a shifted key is not in the lower-case family this test compares
			}
			for _, tail := range tails {
				for _, kind := range []password.Kind{password.User, password.Admin} {
					base := check(c, lower+tail, in, kind)
					checked++
					if base.OK {
						continue
					}
					refusedLower++
					for _, form := range []string{strings.ToUpper(lower[:1]) + lower[1:], strings.ToUpper(lower)} {
						got := check(c, form+tail, in, kind)
						if got.OK {
							t.Errorf("%s%s (%s, kind %v): accepted %+v, %s%s is refused", form, tail, layout, kind, got, lower, tail)
						}
					}
				}
			}
		}
	}
	if refusedLower < 50 {
		t.Fatalf("only %d of %d lower-case blind words were refused, the family is too small to prove anything", refusedLower, checked)
	}
}
