package pwstrength

import (
	"embed" // persianWordsFS: the list is data compiled into the binary, never fetched at run time
	"math"
	"strings"
	"sync"
	"unicode"

	"github.com/ccojocar/zxcvbn-go"
	"golang.org/x/text/unicode/norm"
)

// The Persian layer (round 18, primitives-r18-1, owner decision D64 persian-passwords).
//
// zxcvbn-go ships English dictionaries only, and it counts the length of a password in bytes, so a
// password written in Persian letters (a Persian "password" followed by 123456, one word typed twice, a
// phrase of three common words) was scored as random text and scored 3 or 4. For an Iranian user base
// these are exactly the passwords people choose. The layer scores the same text a second time against a
// compiled-in ranked list of Persian words, and the lowest score of the two counts, so it can only
// lower a score.
//
// The list (persian/words.txt) is the 50,000 most frequent words of Persian film subtitles
// (FrequencyWords, OpenSubtitles2018, CC-BY-SA 4.0; persian/NOTICE.md and docs/licences), folded and
// filtered by the generator test (persian_gen_test.go) and kept in frequency order, so the line number
// is the rank. No leaked password dump is used. It is read once, lazily, into a map.
//
// A password is not matched as a whole. A password is cut into pieces by the cheapest decomposition:
// a word of the list (its cost is log2 of its rank, plus one bit), a run of Latin letters that is
// the Finglish spelling of one of the commonest words (below), or one character at brute-force cost. The
// characters that are not Persian letters (the digits and the symbols around a word) are then scored
// by zxcvbn as one residue, so "123456" after a word costs what it costs on its own, and a word with its
// affix stripped is a word. The sum is turned into a score with the arithmetic of zxcvbn-go itself
// (scoreOfEntropy), so the two scores are on one scale and a test compares them.
//
// Three readings reach the layer through Check: what was typed, its NFKC form and the Persian letters
// read off the key positions; and a Persian word typed blind on a US keyboard ("vlcufmv" for the word
// for "password") is read the other way, through the layout tables (persianFromLatin), because that is
// a common habit.

// persianWordsFS holds the list as an embed.FS and not as a string variable: a package-level string is mutable
// state (TestNoPackageLevelMutableState), a read-only file system baked in at build time is not.
//
//go:embed persian/words.txt
var persianWordsFS embed.FS

// persianWordsText is the text of the list. The file is part of the build, so a read that fails is a broken
// binary and not a state to recover from.
func persianWordsText() string {
	b, err := persianWordsFS.ReadFile("persian/words.txt")
	if err != nil {
		panic("pwstrength: the embedded Persian word list is missing: " + err.Error())
	}
	return string(b)
}

const (
	// persianMinWord is the shortest word of the list that counts as a piece: a single letter is in
	// every text.
	persianMinWord = 2
	// persianMaxWord bounds the pieces looked up, and the work of one scan.
	persianMaxWord = 24
	// persianMinInRun is the shortest word of the list that counts inside a longer run of Persian
	// letters on its own; a word of persianMinWord letters counts only when it is the whole run or
	// touches another word piece.
	persianMinInRun = 3
	// finglishTopRank and finglishMinTyped bound the Finglish spellings: the commonest words only, and
	// a run of at least four Latin letters (a shorter run is in every text).
	finglishTopRank  = 6000
	finglishMinTyped = 4
	// The brute-force cost of one character the list does not cover, in bits: a Persian letter (the
	// alphabet has 32 letters and the keyboard a few more), a digit, a Latin letter and anything else.
	persianLetterBits = 5.2
	digitBits         = 3.33
	latinLetterBits   = 4.7
	otherCharBits     = 6.6
	// separatorBits is what one separator between pieces costs: a guesser who joins words tries a
	// handful of separators (a space, a dash, an underscore, a dot, a comma, a slash), not any symbol.
	separatorBits = 2.5
	// finglishVowelBits is what each vowel dropped from a Finglish spelling costs: the same word is
	// written with "oo", "u" or "o", and the skeleton does not say which. What keeps this low price from
	// pricing random text as a word is not the price but the shape a run must have to count at all
	// (latinSkeleton, finglishMinConsonants and finglishShortSkeleton; primitives-r19-1).
	finglishVowelBits = 1.5
	// finglishMinConsonants is the shortest skeleton that counts at all, and a skeleton shorter than
	// finglishShortSkeleton counts only next to another piece. A skeleton of one or two consonants is in
	// a large share of random runs ("emon", "mone" and "onek" all reduce to the word for "I"), so a match
	// on one says nothing about the run; next to a word it is the next word of a phrase.
	finglishMinConsonants = 2
	finglishShortSkeleton = 3
	// finglishMaxCluster is the longest run of consonants (a digraph such as "kh" is one) in a Finglish
	// spelling: Persian has clusters of two, not "jst" or "ydl".
	finglishMaxCluster = 2
	// caseBits is what an upper-case letter in a Finglish piece costs: the guesser tries the capitalised
	// and the all-capitals forms, and any other case is guessed one letter at a time.
	caseBits = 1.0
)

// persianDict is the list in memory.
type persianDict struct {
	rank     map[string]int // folded word -> 1-based rank
	finglish map[string]int // consonant skeleton of a Latin spelling -> best rank
}

// persianDictionary builds the dictionary on first use. A process that never checks a password pays
// nothing, and the build is a few milliseconds and a few megabytes, once.
var persianDictionary = sync.OnceValue(func() *persianDict {
	words := strings.Split(strings.TrimRight(persianWordsText(), "\n"), "\n")
	d := &persianDict{rank: make(map[string]int, len(words)), finglish: map[string]int{}}
	for i, w := range words {
		rank := i + 1
		if _, dup := d.rank[w]; !dup {
			d.rank[w] = rank
		}
		if rank > finglishTopRank {
			continue
		}
		for _, k := range finglishSkeletons(w) {
			if len([]rune(k)) < finglishMinConsonants {
				continue
			}
			if old, ok := d.finglish[k]; !ok || rank < old {
				d.finglish[k] = rank
			}
		}
	}
	return d
})

// persianFold is the one normal form of the list and of a password, so that the writing variants of
// one word are one entry: NFKC, the Arabic yeh, alef maksura and kaf written as the Persian letters,
// the hamza forms of alef as alef, the diacritics, the tatweel and every invisible code point (the
// half-space of the Persian keyboard among them) removed. Latin letters keep their case, because
// the case of a random password is entropy that the residue and the Finglish pieces must be scored on
// (primitives-r19-1); the lookups lower-case for themselves. The generator test uses it for the list, so
// a word and the text it is looked up in cannot differ.
func persianFold(s string) string {
	s = norm.NFKC.String(s)
	var b strings.Builder
	for _, r := range s {
		switch {
		case invisible(r), r == 0x0640, r >= 0x064b && r <= 0x065f, r == 0x0670:
			continue
		case r == 0x064a, r == 0x0649:
			r = 0x06cc // ي ى -> ی
		case r == 0x0643:
			r = 0x06a9 // ك -> ک
		case r == 0x0629, r == 0x06d5:
			r = 0x0647 // ة ە -> ه
		case r == 0x0623, r == 0x0625, r == 0x0622, r == 0x0671:
			r = 0x0627 // أ إ آ ٱ -> ا
		}
		b.WriteRune(r)
	}
	return b.String()
}

// isPersianLetter says whether a folded rune is a letter of the Arabic script.
func isPersianLetter(r rune) bool { return unicode.Is(unicode.Arabic, r) && unicode.IsLetter(r) }

// spansWholeRun says whether the half-open span [i, j) of rs is a whole run of Persian letters, with no
// Persian letter before or after it: a two-letter word counts only then (persianMinInRun).
func spansWholeRun(rs []rune, i, j int) bool {
	return (i == 0 || !isPersianLetter(rs[i-1])) && (j == len(rs) || !isPersianLetter(rs[j]))
}

// finglishSkeletons are the consonant skeletons a Latin spelling of a Persian word can have: the
// consonants in order, a digraph (kh, sh, ch, zh, gh) as one letter, the vowels of both scripts
// dropped. The letter waw is a vowel in "khoob" and a consonant in "ravan", so a word that has it is
// given both skeletons, and a final he (silent in "khoobe") is dropped.
func finglishSkeletons(w string) []string {
	var variants [2]strings.Builder
	rs := []rune(w)
	hasWaw := false
	for i, r := range rs {
		var c string
		switch r {
		case 0x0628:
			c = "b"
		case 0x067e:
			c = "p"
		case 0x062a, 0x0637:
			c = "t"
		case 0x062b, 0x0633, 0x0635:
			c = "s"
		case 0x062c:
			c = "j"
		case 0x0686:
			c = "C" // ch
		case 0x062d:
			c = "h"
		case 0x062e:
			c = "K" // kh
		case 0x062f:
			c = "d"
		case 0x0630, 0x0632, 0x0636, 0x0638:
			c = "z"
		case 0x0631:
			c = "r"
		case 0x0698:
			c = "Z" // zh
		case 0x0634:
			c = "S" // sh
		case 0x0639, 0x0626, 0x0621, 0x0627, 0x06cc:
			c = "" // a vowel, an ain or a hamza
		case 0x063a, 0x0642:
			c = "G" // gh and q
		case 0x0641:
			c = "f"
		case 0x06a9:
			c = "k"
		case 0x06af:
			c = "g"
		case 0x0644:
			c = "l"
		case 0x0645:
			c = "m"
		case 0x0646:
			c = "n"
		case 0x0647:
			if i == len(rs)-1 && len(rs) > 2 {
				c = ""
			} else {
				c = "h"
			}
		case 0x0648:
			hasWaw = true
			variants[1].WriteString("v")
			continue
		default:
			return nil // not a word of Persian letters
		}
		variants[0].WriteString(c)
		variants[1].WriteString(c)
	}
	out := []string{variants[0].String()}
	if hasWaw {
		out = append(out, variants[1].String())
	}
	return out
}

// latinSkeleton is finglishSkeletons for the typed side: a run of Latin letters in lower case, with
// the digraphs as one letter, "q" as gh, the vowels (and "w", which is a vowel in "khoob") dropped. It
// returns the number of vowels it dropped, which cost bits, and false for a run that is not spelled the
// way Persian is written in Latin letters (primitives-r19-1): a run of vowels that is not a spelling
// (see vowelRun), a cluster of more than finglishMaxCluster consonants, or more vowels than
// consonants. Without these limits the vowel-free skeleton of a run of random letters matched the
// skeleton of a common word, and the layer scored the run as that word.
func latinSkeleton(run []rune) (skeleton string, vowels int, ok bool) {
	var b strings.Builder
	consonants, cluster := 0, 0
	for i := 0; i < len(run); i++ {
		r := run[i]
		next := rune(0)
		if i+1 < len(run) {
			next = run[i+1]
		}
		if strings.ContainsRune("aeiouyw", r) {
			j := i
			for j < len(run) && strings.ContainsRune("aeiouyw", run[j]) {
				j++
			}
			if !vowelRun(string(run[i:j])) {
				return "", 0, false
			}
			vowels += j - i
			i = j - 1
			cluster = 0
			continue
		}
		consonants++
		if cluster++; cluster > finglishMaxCluster {
			return "", 0, false
		}
		switch {
		case r == 'k' && next == 'h':
			b.WriteByte('K')
			i++
		case r == 's' && next == 'h':
			b.WriteByte('S')
			i++
		case r == 'c' && next == 'h':
			b.WriteByte('C')
			i++
		case r == 'z' && next == 'h':
			b.WriteByte('Z')
			i++
		case r == 'g' && next == 'h', r == 'q':
			b.WriteByte('G')
			if r == 'g' {
				i++
			}
		case r == 'c':
			b.WriteByte('k')
		case r == 'x':
			b.WriteString("ks")
		default:
			b.WriteRune(r)
		}
	}
	if vowels > consonants {
		return "", 0, false
	}
	return b.String(), vowels, true
}

// vowelRun says whether a run of vowel letters is a way to write a vowel of Persian in Latin letters:
// one of a e i o u; a doubled one or one of the common pairs ("aa", "oo", "ee", "ai", "ei", "ou", "au",
// "ie", "oi"); or a pair with "y" or "w" and another vowel ("ay", "ey", "ya", "aw", "ow"). A lone "y" or
// "w" between consonants is not a vowel of any spelling, and a run of three or more is not a spelling at all.
func vowelRun(v string) bool {
	switch len(v) {
	case 1:
		return v != "y" && v != "w"
	case 2:
		if v[0] == v[1] {
			return v[0] != 'y' && v[0] != 'w'
		}
		if strings.ContainsAny(v, "yw") {
			return !strings.Contains("yw", v[:1]) || !strings.Contains("yw", v[1:])
		}
		return strings.Contains(" ai ei oi ou au ie ", " "+v+" ")
	}
	return false
}

// piece is one step of the cheapest decomposition of a text.
type piece struct {
	from int
	bits float64
	kind byte // 'w' a word of the list, 'f' a Finglish spelling, 'c' one character
}

// finglishMode says how far a run of Latin letters may be read as a spelling of a Persian word.
type finglishMode uint8

const (
	// finglishOff: never. A text that is itself the Persian layer's reading of Latin keys has no Finglish.
	finglishOff finglishMode = iota
	// finglishFree: a spelling counts wherever it sits in the text. Every reading of the password is scored
	// this way, the key-position reading of a Persian layout included (primitives-r23-3).
	finglishFree
)

// persianEntropy cuts text (already folded) into the cheapest pieces. It returns the entropy in bits
// of the cut and whether any piece is a word of the list or a Finglish spelling; a text with none is
// not this layer's to judge. The residue of characters that are not Persian letters is scored by
// zxcvbn once, as the text a guesser would try after the words.
//
// finglish says whether, and how far, a run of Latin letters may be read as a spelling of a Persian word.
func persianEntropy(text string, inputs []string, finglish finglishMode) (bits float64, hit bool) {
	rs := []rune(text)
	n := len(rs)
	if n == 0 {
		return 0, false
	}
	d := persianDictionary()
	best := make([]float64, n+1)
	from := make([]piece, n+1)
	for i := 1; i <= n; i++ {
		best[i] = math.Inf(1)
	}
	for i := 0; i < n; i++ {
		// One character at brute-force cost.
		if cb := charBits(rs[i]); best[i]+cb < best[i+1] {
			best[i+1], from[i+1] = best[i]+cb, piece{from: i, bits: cb, kind: 'c'}
		}
		// A word of the list. A word of two letters is in every random run (primitives-r19-3), so it
		// counts only as a whole run or next to another word piece (primitives-r20-3): Persian is typed
		// without spaces, and a phrase of the commonest two-letter words is one run.
		if isPersianLetter(rs[i]) {
			for l := persianMinWord; l <= min(persianMaxWord, n-i) && isPersianLetter(rs[i+l-1]); l++ {
				rank, ok := d.rank[string(rs[i:i+l])]
				if !ok {
					continue
				}
				if l < persianMinInRun && !spansWholeRun(rs, i, i+l) &&
					!(i > 0 && from[i].kind == 'w') && !wordStartsAt(d, rs, i+l) {
					continue
				}
				cost := math.Log2(float64(rank)) + 1
				if c := best[i] + cost; c < best[i+l] {
					best[i+l], from[i+l] = c, piece{from: i, bits: cost, kind: 'w'}
				}
			}
		}
		// A Finglish spelling: a run of at least finglishMinTyped Latin letters.
		if finglish != finglishOff && isLatinLetter(rs[i]) {
			for l := finglishMinTyped; l <= min(persianMaxWord, n-i) && isLatinLetter(rs[i+l-1]); l++ {
				skel, vowels, spelled := latinSkeleton(lowerLatin(rs[i : i+l]))
				if !spelled {
					continue
				}
				rank, ok := d.finglish[skel]
				if !ok {
					continue
				}
				if len([]rune(skel)) < finglishShortSkeleton && !(i > 0 && (from[i].kind == 'w' || from[i].kind == 'f')) {
					continue
				}
				cost := math.Log2(float64(rank)) + 1 + finglishVowelBits*float64(vowels) + caseCost(rs[i:i+l])
				if c := best[i] + cost; c < best[i+l] {
					best[i+l], from[i+l] = c, piece{from: i, bits: cost, kind: 'f'}
				}
			}
		}
	}
	var residue []rune
	for j := n; j > 0; j = from[j].from {
		p := from[j]
		switch p.kind {
		case 'w', 'f':
			hit = true
			bits += p.bits
		default:
			switch {
			case isPersianLetter(rs[j-1]):
				bits += persianLetterBits
			case isSeparator(rs[j-1]):
				bits += separatorBits
			default:
				residue = append(residue, rs[j-1])
			}
		}
	}
	if !hit {
		return 0, false
	}
	if len(residue) > 0 {
		// The residue was collected from the end; zxcvbn reads it in typing order.
		for i, j := 0, len(residue)-1; i < j; i, j = i+1, j-1 {
			residue[i], residue[j] = residue[j], residue[i]
		}
		bits += zxcvbn.PasswordStrength(string(residue), inputs).Entropy
	}
	return bits, true
}

// wordStartsAt says whether a word of the list of at least persianMinInRun letters starts at i: the
// right-hand neighbour that lets a two-letter word before it count.
func wordStartsAt(d *persianDict, rs []rune, i int) bool {
	for l := persianMinInRun; l <= min(persianMaxWord, len(rs)-i) && isPersianLetter(rs[i+l-1]); l++ {
		if _, ok := d.rank[string(rs[i:i+l])]; ok {
			return true
		}
	}
	return false
}

func isLatinLetter(r rune) bool { return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' }

func isUpperLatin(r rune) bool { return r >= 'A' && r <= 'Z' }

// lowerLatin is a copy of a run of Latin letters in lower case, for the Finglish lookup.
func lowerLatin(run []rune) []rune {
	out := make([]rune, len(run))
	for i, r := range run {
		if isUpperLatin(r) {
			r += 'a' - 'A'
		}
		out[i] = r
	}
	return out
}

// caseCost is what the case of a Finglish piece costs in bits: nothing for lower case, one bit for a
// capital first letter or for all capitals (the two forms a guesser tries), and one bit per capital
// for any other mix.
func caseCost(run []rune) float64 {
	upper := 0
	for _, r := range run {
		if isUpperLatin(r) {
			upper++
		}
	}
	switch {
	case upper == 0:
		return 0
	case upper == len(run), upper == 1 && isUpperLatin(run[0]):
		return caseBits
	}
	return caseBits * float64(upper)
}

// isSeparator reports the characters a person puts between the words of a phrase.
func isSeparator(r rune) bool { return strings.ContainsRune(" -_./,", r) }

func charBits(r rune) float64 {
	switch {
	case isPersianLetter(r):
		return persianLetterBits
	case isSeparator(r):
		return separatorBits
	case r >= '0' && r <= '9':
		return digitBits
	case isUpperLatin(r):
		return latinLetterBits + caseBits
	case isLatinLetter(r):
		return latinLetterBits
	}
	return otherCharBits
}

// entropyScoreBits are the entropies at which zxcvbn-go's score steps up, from its own arithmetic: a
// password falls in a 10 ms, 100 core guess model, the crack time is half the guesses times that, and
// the score steps are at 1e2, 1e4, 1e6 and 1e8 seconds (scoring.go of the pinned module). Computed, not
// typed, from the same constants, and TestPersianScaleMatchesZxcvbn compares the result with the module's
// own score for a spread of texts, so a bump of the module that changes the scale fails there.
func entropyScoreBits() []float64 {
	const secondsPerGuess = 0.010 / 100
	var out []float64
	for _, seconds := range []float64{1e2, 1e4, 1e6, 1e8} {
		out = append(out, math.Log2(seconds/(0.5*secondsPerGuess)))
	}
	return out
}

// scoreOfEntropy is zxcvbn-go's score for an entropy in bits.
func scoreOfEntropy(bits float64) int {
	score := 0
	for _, step := range entropyScoreBits() {
		if bits >= step {
			score++
		}
	}
	return score
}

// foldedHead is the folded text cut to scoredRunes runes.
func foldedHead(text string) string {
	folded := []rune(persianFold(text))
	if len(folded) > scoredRunes {
		folded = folded[:scoredRunes]
	}
	return string(folded)
}

// persianScore is the Persian layer's score for a reading, and whether the layer found anything in it.
//
// The text is cut after the fold, not before: NFKC expands a compatibility character into several, and
// the scoring bound (scoredRunes) is there because zxcvbn is superlinear in the length it is given
// (primitives-r19-4).
func persianScore(text string, inputs []string, finglish finglishMode) (score int, hit bool) {
	bits, hit := persianEntropy(foldedHead(text), inputs, finglish)
	if !hit {
		return maxScore, false
	}
	return scoreOfEntropy(bits), true
}

// persianFromLatin reads a text typed on a US keyboard as the Persian text the layout types on the same
// keys, and reports whether any key was a letter with a Persian reading.
func persianFromLatin(from func(r rune) (string, bool), s string) (string, bool) {
	changed := false
	var b strings.Builder
	for _, r := range s {
		if t, ok := from(r); ok && isPersianLetterText(t) {
			changed = true
			b.WriteString(t)
			continue
		}
		b.WriteRune(r)
	}
	return b.String(), changed
}

func isPersianLetterText(t string) bool {
	for _, r := range t {
		if isPersianLetter(r) {
			return true
		}
	}
	return false
}
