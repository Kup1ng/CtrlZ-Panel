// Package pwstrength decides whether a new password is strong enough (spec 4.3,
// T-100). The server decides; the meter in the browser is advice. The check is
// offline: the dictionaries are compiled into the zxcvbn module, and nothing
// here opens a socket.
//
// On top of zxcvbn it adds what an Iranian user base needs: Persian keyboard
// positions read as Latin ("ضصثقفغ" is "qwerty"), Persian and Arabic digits read
// as ASCII, and an outright refusal of a password that holds the phone number.
package pwstrength

import (
	"context"
	"runtime"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/ccojocar/zxcvbn-go"
	"github.com/ccojocar/zxcvbn-go/match"
	"golang.org/x/text/unicode/norm"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/digits"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/password"
)

// Reason is why a password was refused. The values are the API's (4.3).
type Reason string

// The reasons. An accepted password has no reason.
const (
	TooShort      Reason = "too_short"
	TooCommon     Reason = "too_common"
	ContainsPhone Reason = "contains_phone"
	Repeated      Reason = "repeated"
	Sequence      Reason = "sequence"
	Weak          Reason = "weak"
)

// Required scores: 3 for users, 4 for admins (4.2).
const (
	MinScoreUser  = 3
	MinScoreAdmin = 4
)

// MinScore is the lowest accepted score for the kind.
func MinScore(k password.Kind) int {
	if k == password.Admin {
		return MinScoreAdmin
	}
	return MinScoreUser
}

// Result is the verdict. Score is zxcvbn's 0 to 4, the lowest of the readings
// below. Reason is empty when OK.
type Result struct {
	Score  int
	Reason Reason
	OK     bool
}

// Input is what the password must not resemble.
type Input struct {
	Phone    string // E.164, "+989121234567"; empty if unknown
	Username string
}

// Persian letters are read by key position, through two layouts: ISIRI 9147, the standard
// ("Persian (Standard)" in Windows 8 and later), and the legacy Windows layout (KBDFA) that
// older installs still use. Their tables are generated (layouts_gen.go) from the data files
// in layouts/, which were read from the operating system's own layouts and not typed from
// memory (rule strength-gate-corpus; review rounds 1 and 2 had found wrong tables twice).
// Change the data, run go generate, and TestLayoutTablesAreGenerated keeps the two honest.
//
//go:generate go run ./layouts/gen layouts_gen.go

// Scoring is bounded, because zxcvbn is not linear: its l33t and dictionary
// matchers cost about 0.6 s for 32 runes and several seconds for 128 (review
// round 1, primitives-r1-10). Only the first scoredRunes are scored as the
// head. A tail of bonusTailRunes or more raises the score by one, but only when
// the first scoredRunes of the tail score tailMinScore on their own (round 2,
// primitives-r2-2 and -6: a tail nobody looked at could be sixteen 1s). Repeats
// are folded away before any of this (reduceRepeats). The number of checks in
// flight is capped.
const (
	scoredRunes    = 24
	bonusTailRunes = 16
	// nearMinCopy and nearMaxChanged bound a near repeat (primitives-r3-5): the
	// second copy matches at least four positions and misses at most two of its own
	// length. Six was the first bound and let a six-letter word with one changed
	// letter through ("mOnKeYmOnKe?"); four still leaves a chance match in random
	// text nothing to fold but four characters of its entropy.
	nearMinCopy = 4
	// minFoldRun is the shortest run of repeated positions that is a copy.
	minFoldRun = 2
	// foldAbsolute is how many repeated positions fold whatever the rest of the text
	// is: a padding tail or a walk after a word explains a few characters and not half
	// of them, and random text does not repeat a run of six by chance.
	foldAbsolute   = 6
	nearMaxChanged = 2
	// tailMinScore is what a tail must reach by itself to count as more
	// entropy, not as padding: the top score. A reversed keyboard walk still
	// scores 3, so a lower bar lets a walk through.
	tailMinScore = maxScore
	// maxScore is zxcvbn's top score.
	maxScore = 4
	// DefaultWait is how long a check waits for a CPU slot before ErrBusy.
	DefaultWait = 2 * time.Second
)

// Checker holds the prepared key maps and the gate that bounds concurrent
// scoring. It is safe for concurrent use.
type Checker struct {
	keymaps []keyReader // ISIRI 9147 first, then the legacy Windows layout
	gate    *password.Gate
}

// New builds the Checker of the signed-in and admin routes. It scores at most
// half of GOMAXPROCS passwords at once (at least one) and makes a caller wait up
// to DefaultWait for a slot. The other half is left to Argon2 and to the rest of
// the request path, so a burst of scoring cannot take every core (review round
// 3, primitives-r3-6).
func New() *Checker { return NewWithLimit(max(1, runtime.GOMAXPROCS(0)/2), DefaultWait) }

// NewUnauthenticated builds the Checker for a route whose caller holds a proof and no
// session: POST /auth/password/reset/complete (a live reset ticket) and POST
// /auth/register (a right code). It is a separate, smaller gate, a quarter of
// GOMAXPROCS and at least one, so holders of such proofs who send strong passwords
// can fill this one and no other: signed-in password changes and the admin routes never
// share its slots (primitives-r3-6). Both routes reach it only after the ticket or the
// code has been checked (rule proof-before-work), so a made-up proof takes no slot.
func NewUnauthenticated() *Checker {
	return NewWithLimit(max(1, runtime.GOMAXPROCS(0)/4), DefaultWait)
}

// NewWithLimit is New with an explicit gate, for tests.
func NewWithLimit(n int, wait time.Duration) *Checker {
	return &Checker{
		keymaps: []keyReader{isiriKey, legacyKey},
		gate:    password.NewGate(n, wait),
	}
}

// Gate is the scoring gate. Production code never needs it; the oracle test
// fills it to put the service in its "gate held" state.
func (c *Checker) Gate() *password.Gate { return c.gate }

// Scorings is how many times a check reached the scoring gate, refused ones
// included. The oracle test compares it between a known and an unknown subject.
func (c *Checker) Scorings() uint64 { return c.gate.Attempts() }

// keyReader reads one character of a layout as the US key it sits on (generated).
type keyReader func(r rune) (key rune, ok bool)

// Check scores a prepared password. It takes a password.Prepared and not a secret.String so
// that it always sees both what was typed and its NFKC form (primitives-r7-5): the layout readings
// and the typed reading start from the typed text, the minimum is the counted length that
// Prepare used, and the whole-text readings from the normalised one. A Prepared made by Typed
// (no minimum) that is too short is answered too_short with score 0. The error is only for
// the machinery: password.ErrBusy when no scoring slot came free (503 server_busy, the same as
// a full Argon2 gate), or the context's error.
func (c *Checker) Check(ctx context.Context, pw password.Prepared, in Input, kind password.Kind) (Result, error) {
	text := digits.ToASCII(pw.Normalized().Reveal())
	if pw.Counted() < kind.MinLength() {
		return Result{Score: 0, Reason: TooShort}, nil
	}
	if containsPhone(text, in.Phone) {
		return Result{Score: 0, Reason: ContainsPhone}, nil
	}

	release, err := c.gate.Acquire(ctx)
	if err != nil {
		return Result{}, err
	}
	defer release()

	inputs := userInputs(in)
	// The readings are made from the whole text, because repeats are found
	// before the text is cut into head and tail. The layout readings start from what
	// was typed, not from the NFKC form: NFKC puts a run of combining marks in a
	// canonical order, and the Persian layouts keep their marks on the shifted top
	// row, so a walk along it came out scrambled (found by the corpus).
	typed := digits.ToASCII(pw.Typed().Reveal())
	readings := []string{text}
	// What was typed is a reading too (primitives-r6-1): a compatibility
	// character that NFKC expands into a phrase would otherwise be scored as the
	// phrase, which no dictionary has, and not as the few characters a guesser
	// enumerates.
	if typed != text {
		readings = append(readings, typed)
	}
	for _, km := range c.keymaps {
		if mapped, changed := latinFromPersian(km, typed); changed && !slices.Contains(readings, mapped) {
			readings = append(readings, mapped)
		}
	}

	// Every reading is also scored with the characters a keyboard types and a screen does not show taken
	// out (round 10, primitives-r10-2): a zero-width space or word joiner inside a walk or a word splits it
	// into pieces that zxcvbn scores as short random text, and a guesser who runs the dictionary never
	// types it. The lowest score of all the readings counts, so the stripped one can only lower it. This is
	// the one place the class is handled; a reading added above is covered without a line of its own.
	for _, r := range slices.Clone(readings) {
		if s := stripInvisible(r); s != r && !slices.Contains(readings, s) {
			readings = append(readings, s)
		}
	}

	worst := c.scoreReading(readings[0], inputs)
	for _, r := range readings[1:] {
		if s := c.scoreReading(r, inputs); s.score < worst.score {
			worst = s
		}
	}
	if worst.score >= MinScore(kind) {
		return Result{Score: worst.score, OK: true}, nil
	}
	reason := reasonFor(worst.seq, worst.length)
	switch worst.fold {
	case foldWalk:
		reason = Sequence
	case foldRepeat:
		// The user repeated something; say so, whatever the repeated unit is.
		reason = Repeated
	}
	return Result{Score: worst.score, Reason: reason}, nil
}

// reading is the verdict on one reading of the password.
type reading struct {
	score  int
	seq    []match.Match
	length int
	fold   foldKind // repeats or walks were folded away before scoring
}

// scoreReading folds repeats, scores the head, and adds the tail bonus.
func (c *Checker) scoreReading(text string, inputs []string) reading {
	runes, fold := reduceRepeats([]rune(text))
	head := runes[:min(len(runes), scoredRunes)]
	hs := zxcvbn.PasswordStrength(string(head), inputs)
	r := reading{score: hs.Score, seq: hs.MatchSequence, length: len(hs.Password), fold: fold}
	if hs.Score < maxScore && len(runes)-scoredRunes >= bonusTailRunes {
		// The tail is folded on its own too: "abababababababab" alone scores 3.
		tail, _ := reduceRepeats(runes[scoredRunes:min(len(runes), 2*scoredRunes)])
		if len(tail) >= bonusTailRunes && zxcvbn.PasswordStrength(string(tail), inputs).Score >= tailMinScore {
			r.score++
		}
	}
	return r
}

// reduceRepeats removes what a guesser who tries "unit, repeated" does not have
// to guess (round 2, primitives-r2-5). zxcvbn-go finds runs of one character
// only, so "xyxyxyxyxyxyxy" or "Summer2024!Summer2024!" would be scored as
// random text. For each lag p, a position repeats when it equals the one p
// before it, and a repeat is a run of at least minFoldRun such positions in a
// row: the copy of a unit, not a double letter. If the best lag explains at
// least half of the text (or foldAbsolute positions, whatever the rest), the
// positions of its runs are dropped and what is left is scored instead.
//
// Only runs, because a lone match is the double letter of a word: dropping every
// position equal to its neighbour turned "Football0000000000000000" into
// "Fotbal0", which is not a dictionary word and scored 3 (found by the corpus of
// corpus_test.go, rule strength-gate-corpus).
//
// A copy may also sit one key away. A keyboard walk is a repeat in that sense:
// "qwerty" repeats its predecessor one key to the right, "q1w2e3r4" repeats the
// one before last one key to the right, and "1qaz2wsx3edc" repeats a column of four
// one key to the right. zxcvbn-go finds the straight walks along a row and
// nothing else, so each of those scored 3 or 4 (found by the same corpus). The
// shifts are the eight neighbours on the grid of the US legend (usGrid, from the
// layout data), and the exact repeat is the shift by nothing.
//
// A near repeat is folded the same way (round 3, primitives-r3-5): offline
// rule sets try "unit, repeated, last character changed" and "unit, one
// character, unit" just as readily, so a second copy that differs in up to two
// positions of its own length, or that sits one character away, is not a second
// piece of entropy. Such a copy has to match at least nearMinCopy positions, or a
// chance match in random text would fold. Every matching position of the copy is
// dropped; the changed ones stay and are scored.
//
// A pass can expose a shorter repeat (a unit that is itself "xyxy"), so it runs
// again, a few times. The text is at most 128 runes, so the search is a few
// hundred thousand comparisons.
func reduceRepeats(s []rune) ([]rune, foldKind) {
	kind := foldNone
	for range 4 {
		n := len(s)
		grid := gridOf(s)
		var best, near foldChoice
		// Lags past n/2 only matter to a near repeat with a gap between the copies.
		for lag := 1; lag <= n-nearMinCopy; lag++ {
			for _, v := range shifts() {
				hit := hits(s, grid, lag, v)
				all := 0
				for _, h := range hit {
					if h {
						all++
					}
				}
				if all < minFoldRun {
					continue
				}
				run := keepRuns(hit)
				runHits := 0
				for _, h := range run {
					if h {
						runHits++
					}
				}
				if runHits > best.hits { // the smallest lag, then the exact repeat, wins a tie
					best = foldChoice{hit: run, hits: runHits, shift: v}
				}
				if all >= nearMinCopy && n-lag-all <= nearMaxChanged && all > near.hits {
					near = foldChoice{hit: hit, hits: all, shift: v}
				}
			}
		}
		// A near repeat that drops more than the best run (a copy with a changed letter
		// inside it also matches the letter before the change) is the better fold.
		pick := best
		if near.hits > best.hits || (best.hits*2 < n && best.hits < foldAbsolute) {
			pick = near
		}
		if pick.hits == 0 {
			break
		}
		kept := make([]rune, 0, n-pick.hits)
		for i, r := range s {
			if !pick.hit[i] {
				kept = append(kept, r)
			}
		}
		s = kept
		// A repeat is a repeat; a fold that only ever moved a copy along the keys is a
		// walk, and the answer to the user says so.
		if pick.shift == ([2]int{}) {
			kind = foldRepeat
		} else if kind == foldNone {
			kind = foldWalk
		}
	}
	return s, kind
}

// foldKind says what reduceRepeats found.
type foldKind int

const (
	foldNone foldKind = iota
	foldRepeat
	foldWalk
)

// foldChoice is a lag and a shift of the keyboard with the positions it drops.
type foldChoice struct {
	hit   []bool
	hits  int
	shift [2]int
}

// shifts are the offsets on the key grid a copy may be moved by, the exact repeat
// first.
func shifts() [][2]int {
	return [][2]int{{0, 0}, {0, 1}, {0, -1}, {1, 0}, {-1, 0}, {1, 1}, {1, -1}, {-1, 1}, {-1, -1}}
}

// point is a place on the key grid; ok is false for a character with no key.
type point struct {
	row, col int
	ok       bool
}

func gridOf(s []rune) []point {
	out := make([]point, len(s))
	for i, r := range s {
		out[i].row, out[i].col, out[i].ok = usGrid(r)
	}
	return out
}

// hits marks every position that repeats the one lag before it, moved by v. The
// first lag positions are never marked.
func hits(s []rune, grid []point, lag int, v [2]int) []bool {
	out := make([]bool, len(s))
	for i := lag; i < len(s); i++ {
		if v == ([2]int{}) {
			out[i] = s[i] == s[i-lag]
			continue
		}
		a, b := grid[i], grid[i-lag]
		out[i] = a.ok && b.ok && a.row == b.row+v[0] && a.col == b.col+v[1]
	}
	return out
}

// keepRuns clears the marks that are not part of a run of at least minFoldRun.
func keepRuns(hit []bool) []bool {
	out := make([]bool, len(hit))
	for i := 0; i < len(hit); {
		if !hit[i] {
			i++
			continue
		}
		j := i
		for j < len(hit) && hit[j] {
			j++
		}
		if j-i >= minFoldRun {
			for k := i; k < j; k++ {
				out[k] = true
			}
		}
		i = j
	}
	return out
}

// latinFromPersian maps every character the layout types to the Latin key at its
// position and reports whether anything changed. Each rune is put in NFKC form on
// its own, so the characters keep the order they were typed in.
func latinFromPersian(km keyReader, s string) (string, bool) {
	changed := false
	var b strings.Builder
	for _, typed := range s {
		// The typed character first: the table holds a code point that NFKC expands into a phrase (the rial
		// sign U+FDFC on Shift+4 of ISIRI 9147) under its own value, and after NFKC it would read as the four
		// letters of the phrase and not as the key (round 10, primitives-r10-8).
		if l, ok := km(typed); ok {
			changed = true
			if l != 0 {
				b.WriteRune(l)
			}
			continue
		}
		for _, r := range norm.NFKC.String(string(typed)) {
			if l, ok := km(r); ok {
				changed = true
				if l != 0 { // 0 is a combining mark: part of the key press before it
					b.WriteRune(l)
				}
				continue
			}
			// A zero-width non-joiner is typed with the Persian layout's own key and
			// means nothing in a keyboard walk.
			if r == 0x200c || r == 0x200d {
				changed = true
				continue
			}
			b.WriteRune(r)
		}
	}
	return b.String(), changed
}

// invisible reports a code point that is typed and not shown: the format characters (category Cf: the
// zero-width space, joiners and marks U+200B to U+200F, the word joiner and invisible operators
// U+2060 to U+2064, the soft hyphen, the byte order mark, the Arabic letter mark), the variation selectors
// and the other default-ignorable code points (the combining grapheme joiner, the Hangul fillers). The
// Persian keyboard types the zero-width non-joiner on Shift+B, so it is the likeliest separator a user puts
// inside a password, and a guesser who holds the dictionary does not type any of them.
func invisible(r rune) bool {
	return digits.Invisible(r)
}

// stripInvisible removes every invisible code point (see invisible) and returns s itself when there is none.
func stripInvisible(s string) string {
	if !strings.ContainsFunc(s, invisible) {
		return s
	}
	return strings.Map(func(r rune) rune {
		if invisible(r) {
			return -1
		}
		return r
	}, s)
}

// containsPhone is 4.3 step 3: the last 7 digits of the number, anywhere in the
// password, also when anything that is neither a letter nor a digit was typed between the digits.
// The decision is on a skeleton: the text with every such rune removed. Round 10 (primitives-r10-1)
// removed the invisible characters and a block list of four separators, and round 13 (primitives-r13-4)
// found "0912/123/4567" and "+98(912)123/4567" accepted, because a list of separators is a list of
// the cases seen. The rule is the complement: a letter still breaks a run ("Tehran123x4567Zq" is fine),
// a digit or a letter is all that can be part of a number, and nothing else can hide one.
func containsPhone(text, phone string) bool {
	d := phoneDigits(phone)
	if len(d) < 7 {
		return false
	}
	last7 := d[len(d)-7:]
	if strings.Contains(text, last7) {
		return true
	}
	return strings.Contains(skeleton(text), last7)
}

// skeleton keeps only the letters and digits of s, in order. The invisible characters, the
// punctuation, the symbols, the spaces and the combining marks are all dropped, whatever their kind;
// so are the invisible code points that Unicode files under letters (the Hangul fillers), which round 10 covered.
func skeleton(s string) string {
	return strings.Map(func(r rune) rune {
		if !invisible(r) && (unicode.IsLetter(r) || unicode.IsDigit(r)) {
			return r
		}
		return -1
	}, s)
}

func phoneDigits(phone string) string {
	var b strings.Builder
	for _, r := range digits.ToASCII(phone) {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// userInputs are the words zxcvbn is told to treat as guessable: the phone with
// and without the country code, the username and the product name (4.3).
func userInputs(in Input) []string {
	out := []string{"ctrlz"}
	if d := phoneDigits(in.Phone); d != "" {
		out = append(out, d)
		if rest, ok := strings.CutPrefix(d, "98"); ok {
			out = append(out, rest, "0"+rest)
		}
	}
	if in.Username != "" {
		out = append(out, strings.ToLower(in.Username))
	}
	return out
}

// reasonFor names the kind of pattern that covers most of the weakest reading.
// Matches are added up per reason, because "iloveyou123" is three dictionary
// words and a run, and the user should hear "too common". If the biggest kind
// covers less than half the password, it is just weak.
func reasonFor(seq []match.Match, length int) Reason {
	covered := map[Reason]int{}
	for _, m := range seq {
		covered[reasonOf(m.Pattern)] += m.J - m.I + 1
	}
	best, bestLen := Weak, 0
	for r, n := range covered {
		// Ties go to the more specific reason, so the answer does not depend on
		// map order.
		if n > bestLen || (n == bestLen && rank(r) > rank(best)) {
			best, bestLen = r, n
		}
	}
	if bestLen*2 < length {
		return Weak
	}
	return best
}

func reasonOf(pattern string) Reason {
	switch pattern {
	case "dictionary":
		return TooCommon
	case "repeat":
		return Repeated
	case "sequence", "spatial":
		// A keyboard walk is a sequence the way "abcd" is.
		return Sequence
	}
	return Weak
}

func rank(r Reason) int {
	switch r {
	case TooCommon:
		return 3
	case Repeated:
		return 2
	case Sequence:
		return 1
	}
	return 0
}
