package pwstrength_test

import (
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/pwstrength/layouts"
)

// The Persian families of the strength-gate corpus (rule strength-gate-corpus, round 18,
// primitives-r18-1, D64 persian-passwords). Until round 18 a password written in Persian letters scored
// as random text, because zxcvbn has English dictionaries only and counts bytes. The families are built
// from the checked-in list by a path that does not go through the code under test: the words are read
// from persian/words.txt as text, the US-key rendering is made from the layout data files (a second path
// from the generated tables), and the Finglish spellings are written by hand.

// persianWords reads the list as text, in rank order.
func persianWords(t testing.TB) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("persian", "words.txt"))
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimRight(string(b), "\n"), "\n")
}

// usKeys renders a Persian word as the US keys that type it on a layout, or false when a letter is not
// typed by any key (the layout data is the source, not the generated tables).
func usKeys(t testing.TB, layout string, w string) (string, bool) {
	t.Helper()
	l, err := layouts.Load(layout)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, r := range w {
		found := false
		for _, k := range l.Keys {
			if len([]rune(k.US)) != 1 {
				continue
			}
			switch string(r) {
			case k.Normal:
				b.WriteString(k.US)
				found = true
			case k.Shift:
				b.WriteString(k.USShift)
				found = true
			}
			if found {
				break
			}
		}
		if !found {
			return "", false
		}
	}
	return b.String(), true
}

// persianRules builds the Persian candidates: a seeded sample of the most frequent words, each written
// the ways a person writes a password from a word, and two and three words together.
func persianRules(t testing.TB, rng *rand.Rand) []candidate {
	t.Helper()
	words := persianWords(t)
	var pool []string
	for _, w := range words[:3000] {
		if len([]rune(w)) >= 4 {
			pool = append(pool, w)
		}
	}
	var out []candidate
	add := func(pw, how string) { out = append(out, candidate{pw: pw, how: "persian: " + how}) }
	for range 28 {
		w := pool[rng.IntN(len(pool))]
		rs := []rune(w)
		add(w+"123456", "word and 123456")
		add(w+"۱۲۳۴۵۶", "word and Persian digits")
		add(w+w, "word typed twice")
		add(w+"-"+w, "word twice with a dash")
		add("1"+w+"1", "digit on both sides")
		add(w+"@2024", "word and a year")
		add(string(rs[:2])+"\u200c"+string(rs[2:])+"1234567", "half-space inside the word")
		add(strings.NewReplacer("ی", "ي", "ک", "ك").Replace(w)+"123456", "Arabic yeh and kaf")
		if us, ok := usKeys(t, "isiri9147", w); ok {
			add(us+"123456", "typed blind on a US keyboard, ISIRI 9147")
		}
		if us, ok := usKeys(t, "kbdfa", w); ok {
			add(us+"123456", "typed blind on a US keyboard, legacy layout")
		}
	}
	// Two and three of the commonest words together: a phrase.
	// A phrase of three words is judged by what it costs a guesser, as in English: three words of
	// the commonest eighty (ranks below about 250) and two separators are about 2^32, below the user bar, and a phrase of
	// words from further down the list is a passphrase and passes (the test below).
	top, few := pool[:600], pool[:80]
	for range 14 {
		a, b := top[rng.IntN(len(top))], top[rng.IntN(len(top))]
		x, y, z := few[rng.IntN(len(few))], few[rng.IntN(len(few))], few[rng.IntN(len(few))]
		add(a+b, "two common words")
		add(a+" "+b, "two common words with a space")
		add(x+y+z, "three common words")
		add(x+" "+y+" "+z, "three common words with spaces")
		add(x+"-"+y+"-"+z, "three common words with dashes")
	}
	// The commonest Finglish spellings, written by hand: the same words typed on a Latin keyboard.
	for _, f := range []string{"salam", "khoobi", "doost", "mamad", "tehran", "iran", "azizam", "delam", "mohabbat", "khodahafez", "dustdaram", "ghashang"} {
		add(f+"123456", "Finglish word and 123456")
		add(f+f, "Finglish word typed twice")
		add(strings.ToUpper(f[:1])+f[1:]+"1234", "Finglish capitalised")
	}
	return out
}
