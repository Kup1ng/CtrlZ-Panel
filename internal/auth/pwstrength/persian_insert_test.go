package pwstrength_test

import (
	"math/rand/v2"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/password"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/pwstrength"
)

// TestFinglishWithInsertedLettersIsNotEasierOnAPersianKeyboard is primitives-r22-2: the r21 test added a
// letter at the edge or middle of four phrases, and a letter inside a word (or a few at the edges) still
// switched the whole-run reading off, because the share of Latin letters the spellings explain fell
// below the bar. The rule is the one of r21-1, held on a seeded draw: one to four random letters
// inserted anywhere in a Finglish phrase, and the Persian layouts never accept what the Latin text is
// refused.
func TestFinglishWithInsertedLettersIsNotEasierOnAPersianKeyboard(t *testing.T) {
	c := pwstrength.New()
	in := pwstrength.Input{Phone: "+989121234567", Username: "ali"}
	rng := rand.New(rand.NewPCG(22, 2))
	const letters = "abcdefghijklmnopqrstuvwxyz"
	holes, tried := 0, 0
	for _, base := range []string{"doostdaramtoro", "khodahafez2024", "mamnunamazshoma", "madaremmehraban", "salamkhoobi", "doostdaram", "khodahafezkhoobi", "azizamdoostdaram", "mohabbatdelam", "tehranirani"} {
		for range 40 {
			rs := []rune(base)
			for range 1 + rng.IntN(4) {
				at := rng.IntN(len(rs) + 1)
				rs = append(rs[:at], append([]rune{rune(letters[rng.IntN(len(letters))])}, rs[at:]...)...)
			}
			latin := string(rs)
			for _, kind := range []password.Kind{password.User, password.Admin} {
				if check(c, latin, in, kind).OK {
					continue
				}
				for i, typed := range pwstrength.OnPersianKeyboard(c, latin) {
					tried++
					if r := check(c, typed, in, kind); r.OK {
						holes++
						if holes <= 10 {
							t.Logf("%s on layout %d, kind %v: accepted (%+v)", latin, i, kind, r)
						}
					}
				}
			}
		}
	}
	if holes > 0 {
		t.Errorf("%d of %d Persian-layout texts are accepted while their Latin form is refused", holes, tried)
	}
}

// TestShortFinglishWordWithFillerIsNotEasierOnAPersianKeyboard is primitives-r23-3 (and r23-4): the r22
// test drew only long phrases, which always keep five spelled letters, and the bar of five was tuned to
// it. A single short word with letters inserted inside it and a digit or symbol filler explains four
// letters or fewer, so the reading of a Persian layout was dropped while its Latin text is refused.
// The key-position reading is the Latin text itself, so it must be scored like it: on every layout the
// score is no higher than the Latin score, and a text refused in Latin is refused on the layout, at both
// floors.
func TestShortFinglishWordWithFillerIsNotEasierOnAPersianKeyboard(t *testing.T) {
	c := pwstrength.New()
	in := pwstrength.Input{Phone: "+989121234567", Username: "ali"}
	rng := rand.New(rand.NewPCG(23, 3))
	const letters = "abcdefghijklmnopqrstuvwxyz"
	words := []string{"tehran", "iran", "salam", "dast", "doost", "khoda", "ghalb", "ghamar", "baran", "daram", "azizam", "mehr", "shahr", "madar"}
	fillers := []string{"1", "12", "1380", "1399", "!!", "#1", "12345", "@", "2024", "00"}
	holes, tried := 0, 0
	for _, word := range words {
		for range 30 {
			rs := []rune(word)
			for range rng.IntN(4) {
				at := rng.IntN(len(rs) + 1)
				rs = append(rs[:at], append([]rune{rune(letters[rng.IntN(len(letters))])}, rs[at:]...)...)
			}
			filler := fillers[rng.IntN(len(fillers))]
			for _, latin := range []string{string(rs) + filler, filler + string(rs), "!!" + string(rs)} {
				for _, kind := range []password.Kind{password.User, password.Admin} {
					want := check(c, latin, in, kind)
					for i, typed := range pwstrength.OnPersianKeyboard(c, latin) {
						tried++
						got := check(c, typed, in, kind)
						if got.Score > want.Score || (!want.OK && got.OK) {
							holes++
							if holes <= 10 {
								t.Logf("%s on layout %d, kind %v: layout %+v, latin %+v", latin, i, kind, got, want)
							}
						}
					}
				}
			}
		}
	}
	if holes > 0 {
		t.Errorf("%d of %d Persian-layout texts score above their Latin form or are accepted while it is refused", holes, tried)
	}
}
