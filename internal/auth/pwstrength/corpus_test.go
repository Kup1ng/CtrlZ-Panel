package pwstrength_test

// The strength gate is defined by what it must refuse (spec 4.3, rule
// strength-gate-corpus). zxcvbn, the folds and the layout tables are how it does
// that, and four rounds of review had each found one more transformation of a weak
// password that they did not see: a layout table typed from memory, a repeated unit,
// a padding tail, a near repeat. Each was patched as a case and pinned by a test
// that copied the patch. This file replaces those cases with a generated corpus.
//
// The corpus is what a standard offline cracking session tries before it tries
// random text, built from three sources and mangled by the usual rules:
//
//   - keyboard walks of the two Persian layouts and the US layout, typed through
//     the checked-in layout data (layouts/), not through the tables of the code;
//   - common passwords (testdata/common-passwords.txt), typed on a Latin and on each
//     Persian layout, because an Iranian user whose layout is Persian types
//     "password" as "پشسسصخقی";
//   - the mangling rules: repeat, near repeat, insertion, case, l33t, years and
//     padding tails, applied to a common password and to the composed forms people
//     think of as "my password, but stronger" (Word2024!).
//
// Every candidate that is long enough to reach the strength check must be refused at
// the user level (score 3). A failure is not a case to pin: it is a hole in the
// gate, and the fix belongs in the gate. The corpus is seeded and its size is
// capped, so it is the same on every machine and a mutant is judged against the
// same candidates.

import (
	_ "embed"
	"math/rand/v2"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/password"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/pwstrength"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/pwstrength/layouts"
)

//go:embed testdata/common-passwords.txt
var commonPasswordFile string

const (
	// The seeds are fixed so a red run is reproducible and every mutant is judged
	// against the same corpus.
	corpusSeedA = 0x5eed1e55
	corpusSeedB = 0xc0ffee21

	// The CPU budget of the corpus: the number of candidates it may hold, and the
	// wall time it may take on a machine that is not starved. A gate that got slower
	// fails here before it hurts a login.
	maxCandidates = 7800 // 6000 before the phone separator family (round 13): about 1000 candidates that return early; 7000 before the Persian families (round 18): about 600 more
	minCandidates = 4000
	corpusTime    = 2 * time.Minute

	// minUserRunes is the user minimum (4.2). A shorter candidate is refused as
	// too_short, which proves nothing about strength, so it is not in the corpus.
	minUserRunes = 10
)

type candidate struct {
	pw  string
	how string // what made it, for a failure message
	// layout is 0 for a candidate typed on the US layout, 1 for ISIRI 9147 and 2 for
	// the legacy layout. One typed on a Persian layout is also checked by a Checker
	// that reads that layout alone: the default Checker reads both, and a hole in one
	// table would be covered by the other.
	layout int
}

// corpusRows are the letter rows of a US keyboard. A Persian layout is read by the
// key it shares with a US key, so the walks are cut from these rows.
var corpusRows = []string{"`1234567890-=", "qwertyuiop[]\\", "asdfghjkl;'", "zxcvbnm,./"}

// loadTypists reads both layouts and returns, per name, how a US key is typed there.
func loadTypists(t testing.TB) map[string]typist {
	t.Helper()
	out := map[string]typist{"us": {}}
	for i, name := range layouts.Names() {
		l, err := layouts.Load(name)
		if err != nil {
			t.Fatal(err)
		}
		keys := map[string]layouts.Key{}
		for _, k := range l.Keys {
			if _, dup := keys[k.US]; !dup { // the ISO key repeats the backslash
				keys[k.US] = k
			}
		}
		out[name] = typist{keys: keys, layout: i + 1}
	}
	return out
}

// typist types text on one layout. A nil keys map is the US layout itself.
type typist struct {
	keys   map[string]layouts.Key
	layout int // see candidate
}

// press is what one US key types here, shifted or not. A key that types nothing
// usable (no key, a macro, an ASCII symbol on shift) keeps its US character, as a
// user who switched layout in the middle of a word would.
func (ty typist) press(us rune, shifted bool) string {
	k, ok := ty.keys[string(us)]
	if !ok {
		return string(us)
	}
	out := k.Normal
	if shifted {
		out = k.Shift
	}
	rs := []rune(out)
	switch {
	case len(rs) != 1:
		return string(us)
	case shifted && rs[0] < 0x80:
		return ty.press(us, false)
	}
	return out
}

func (ty typist) text(s string, shifted bool) string {
	var b strings.Builder
	for _, r := range s {
		b.WriteString(ty.press(r, shifted))
	}
	return b.String()
}

// walks are the keyboard walks of a layout: along a row, forward and backward, and
// the zigzag and column walks, typed with and without the shifted letters.
func walks(ty typist) []candidate {
	var out []candidate
	add := func(us, how string) {
		for _, shifted := range []bool{false, true} {
			if ty.keys == nil && shifted {
				continue // the US layout's shifted keys are capitals, which the case rule covers
			}
			out = append(out, candidate{pw: ty.text(us, shifted), how: how, layout: ty.layout})
		}
	}
	for _, row := range corpusRows {
		rs := []rune(row)
		for n := minUserRunes; n <= len(rs); n++ {
			for start := 0; start+n <= len(rs); start++ {
				seg := string(rs[start : start+n])
				add(seg, "row walk")
				add(reverse(seg), "row walk reversed")
			}
		}
	}
	for _, s := range []string{
		"1q2w3e4r5t6y7u", "q1w2e3r4t5y6u7", "qazwsxedcrfv", "1qaz2wsx3edc", "zaq12wsxcde3", "zaq1xsw2cde3",
		"qazxswedcvfr", "1qazxsw23edcvfr4", "asdfqwerzxcv", "qwertyasdfgh", "azsxdcfvgbhn", "poiuytlkjhgf",
		"mnbvcxzlkjhgfdsa", "qweasdzxc123", "123qweasdzxc", "1234qwerasdf", "qwer1234asdf",
	} {
		add(s, "column or zigzag walk")
	}
	return out
}

func reverse(s string) string {
	rs := []rune(s)
	slices.Reverse(rs)
	return string(rs)
}

func capitalize(s string) string {
	rs := []rune(s)
	if len(rs) > 0 {
		rs[0] = unicode.ToUpper(rs[0])
	}
	return string(rs)
}

func alternate(s string) string {
	rs := []rune(s)
	for i := range rs {
		if i%2 == 1 {
			rs[i] = unicode.ToUpper(rs[i])
		}
	}
	return string(rs)
}

// leet applies the standard substitutions. With all false only the first letter that
// has one is replaced, which is what a user who "adds a number" does.
func leet(s string, all bool) string {
	sub := map[rune]string{'a': "4", 'e': "3", 'i': "1", 'o': "0", 's': "$", 't': "7"}
	var b strings.Builder
	done := false
	for _, r := range s {
		if x, ok := sub[r]; ok && (all || !done) {
			b.WriteString(x)
			done = true
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// changeLast is the "last character changed" of a near repeat.
func changeLast(rs []rune) string {
	out := slices.Clone(rs)
	if out[len(out)-1] == '?' {
		out[len(out)-1] = '!'
	} else {
		out[len(out)-1] = '?'
	}
	return string(out)
}

func years(rng *rand.Rand) []string {
	ys := []string{"2024", "2025", "1990"}
	for range 3 {
		ys = append(ys, strconv.Itoa(1960+rng.IntN(67)))
	}
	return ys
}

// foldRules are the repeat and near-repeat rules on one unit: what a guesser who
// already holds the unit gets for free. A repeated or lightly changed copy is not a
// second piece of entropy, so a weak unit stays weak under all of them.
func foldRules(u string, wide bool) []candidate {
	var out []candidate
	add := func(pw, how string) { out = append(out, candidate{pw: pw, how: how}) }
	rs := []rune(u)

	add(u+u, "repeat x2")
	add(u+u+u, "repeat x3")
	add(u+"-"+u, "repeat with a dash")
	// near repeat: a copy that differs in a position or two, or a character between.
	add(u+changeLast(rs), "near repeat, last character changed")
	add(u+string(rs[:len(rs)-1])+"7", "near repeat, last character replaced by a digit")
	add(u+"x"+u, "near repeat, one character between")
	add(u+"1"+u, "near repeat, a digit between")
	add(u+"!"+u, "near repeat, a symbol between")
	if wide { // two new characters are two characters of entropy; a composed unit that scores just under 3 would pass with them
		add(u+"#$"+u, "near repeat, two symbols between")
	}
	add(u+capitalize(u), "near repeat, second copy capitalised")
	add(u+string(rs[:1])+"Z"+string(rs[2:]), "near repeat, second character changed")
	return out
}

// suffixRules are the insertion, year and padding rules on one unit, one rule deep:
// a symbol or digit in front, in the middle or behind, a year, and a tail that adds
// length and nothing else. They are applied to a root that is a common password or
// a walk, never to a composed unit that already carries a year: two suffix rules
// deep is not what a cracking session tries first, and the gate is not asked to
// refuse it.
func suffixRules(u string, ys []string, pairs bool) []candidate {
	var out []candidate
	add := func(pw, how string) { out = append(out, candidate{pw: pw, how: how}) }
	rs := []rune(u)

	add(u, "unit")
	add("!"+u, "symbol in front")
	add("1"+u+"1", "digit on both sides")
	add(u+"!", "symbol at the end")
	add(u+"123", "123 at the end")
	add(u+"@#", "two symbols at the end")
	add(string(rs[:len(rs)/2])+"1"+string(rs[len(rs)/2:]), "digit in the middle")
	for _, y := range ys {
		add(u+y, "year")
		add(u+y[2:], "short year")
		if pairs {
			add(u+"@"+y, "year after a symbol")
			add(u+y+"!", "year and a symbol")
		}
	}
	for _, pad := range []string{
		strings.Repeat("0", 16), strings.Repeat("1", 16), strings.Repeat("x", 20), strings.Repeat("!", 16),
		"abcdefghijklmnop", "1234567890123456", "qwertyuiopasdfgh", strings.Repeat("ab", 8), strings.Repeat("12", 10),
	} {
		add(u+pad, "padding tail "+pad[:2])
	}
	add(u+string(rs[:len(rs)/2])+strings.Repeat("0", 16), "padding after a partial copy")
	return out
}

// bases are the roots of one common password after the case and l33t rules.
func bases(w string) []string {
	return slices.Compact([]string{
		w, capitalize(w), strings.ToUpper(w), alternate(w), leet(w, true), leet(w, false), capitalize(leet(w, true)),
	})
}

// composed are the "my password, but stronger" forms people really use (Word2024!).
// They are roots for the fold rules only, and only when the gate already refuses
// them alone: a composed form that scores 3 is an acceptable password, and so is
// its repetition.
func composed(w string, ys []string) []string {
	return []string{capitalize(w) + ys[0] + "!", capitalize(w) + "@" + ys[1], leet(capitalize(w), true) + ys[2]}
}

func commonPasswords() []string {
	var out []string
	for _, line := range strings.Split(commonPasswordFile, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}

// refusedAlone reports whether the gate refuses the unit on its own, at the user
// level. The corpus uses it to keep only roots that are weak by themselves.
func refusedAlone(chk *pwstrength.Checker, u string) bool {
	if len([]rune(u)) < minUserRunes {
		return true // too short: refused for length, so a repetition of it is a fresh password to judge
	}
	r, err := judge(chk, u, pwstrength.Input{Phone: testPhone}, password.User)
	return err == nil && !r.OK
}

const testPhone = "+989121234567"

// buildCorpus is deterministic: the same seeds give the same candidates in the same
// order.
func buildCorpus(t testing.TB, chk *pwstrength.Checker) []candidate {
	t.Helper()
	rng := rand.New(rand.NewPCG(corpusSeedA, corpusSeedB))
	typists := loadTypists(t)
	order := []string{"us", "isiri9147", "kbdfa"}

	var all []candidate
	tag := func(prefix string, layout int, cs []candidate) {
		for _, c := range cs {
			c.how, c.layout = prefix+c.how, layout
			all = append(all, c)
		}
	}
	// Keyboard walks, typed on every layout; some of them are also the roots of the
	// rules (a walk with a year, a walk repeated, a walk padded).
	var walkRoots []candidate
	for _, name := range order {
		ws := walks(typists[name])
		all = append(all, ws...)
		// The roots of the suffix and fold rules are the straight walks only: a snake
		// of six turns is not what a rule set stacks a year on, and its own score sits
		// near the bar, so a suffix would be asking the gate for more than the spec.
		straight := slices.DeleteFunc(slices.Clone(ws), func(c candidate) bool { return !strings.HasPrefix(c.how, "row walk") })
		for range 6 {
			walkRoots = append(walkRoots, straight[rng.IntN(len(straight))])
		}
	}
	// Common passwords: the head of the list, because every rule set starts with the
	// most common ones, and a seeded sample of the rest.
	words := commonPasswords()
	sample := slices.Clone(words[:12])
	for range 12 {
		sample = append(sample, words[12+rng.IntN(len(words)-12)])
	}
	for i, w := range sample {
		ys := years(rng)
		for _, name := range order {
			ty := typists[name]
			if name != "us" {
				// Case and l33t exist on the Latin layout; a Persian layout types the
				// word as it is. A third of the sample on each keeps the budget.
				if i%3 == 0 {
					u := ty.text(w, false)
					tag(name+": "+w+": ", ty.layout, foldRules(u, true))
					tag(name+": "+w+": ", ty.layout, suffixRules(u, ys, true))
				}
				continue
			}
			tag("us: "+w+": ", 0, invisibleRules(w+"1234"))
			for _, u := range bases(w) {
				tag("us: "+w+": ", 0, foldRules(u, true))
				// One case or l33t rule under a suffix rule, not two; the year-with-a-symbol
				// forms only on the bare word (see suffixRules).
				if u == w || u == capitalize(w) || u == strings.ToUpper(w) || u == leet(w, true) {
					tag("us: "+w+": ", 0, suffixRules(u, ys, u == w))
				}
			}
			for _, u := range composed(w, ys) {
				if refusedAlone(chk, u) {
					tag("us: "+w+": composed: ", 0, foldRules(u, false))
				}
			}
		}
	}
	for _, root := range walkRoots {
		tag("walk root: ", root.layout, foldRules(root.pw, true))
		tag("walk root: ", root.layout, suffixRules(root.pw, years(rng), true))
		tag("walk root: ", root.layout, invisibleRules(root.pw))
	}
	// The user's own phone number with something between its digits (round 13, primitives-r13-4).
	tag("", 0, phoneSeparatedRules())
	// Persian words in Persian letters, typed blind on a US keyboard and in Finglish (round 18, primitives-r18-1).
	all = append(all, persianRules(t, rng)...)

	// Keep what reaches the strength check, drop duplicates.
	seen := map[string]bool{}
	var out []candidate
	for _, c := range all {
		if len([]rune(c.pw)) < minUserRunes || seen[c.pw] {
			continue
		}
		seen[c.pw] = true
		out = append(out, c)
	}
	return out
}

func TestCorpusIsBounded(t *testing.T) {
	chk := pwstrength.NewWithLimit(4, time.Minute)
	c := buildCorpus(t, chk)
	if len(c) < minCandidates || len(c) > maxCandidates {
		t.Fatalf("the corpus has %d candidates, want %d to %d (its CPU budget): resize the sample, do not drop a rule", len(c), minCandidates, maxCandidates)
	}
	again := buildCorpus(t, chk)
	if !slices.Equal(c, again) {
		t.Fatal("the corpus is not deterministic")
	}
	// Every rule family is in it; a corpus that quietly lost one would pass for free.
	for _, how := range []string{
		"row walk", "row walk reversed", "column or zigzag walk", "repeat x2", "near repeat, last character changed",
		"near repeat, one character between", "digit in the middle", "year and a symbol", "padding tail", "isiri9147:", "kbdfa:", "composed:",
		"walk root:", "invisible character", "phone separated by",
		"persian: word and 123456", "persian: word typed twice", "persian: half-space inside the word", "persian: Arabic yeh and kaf",
		"persian: typed blind on a US keyboard, ISIRI 9147", "persian: two common words", "persian: three common words", "persian: Finglish word and 123456",
	} {
		if !slices.ContainsFunc(c, func(x candidate) bool { return strings.Contains(x.how, how) }) {
			t.Errorf("no candidate of the family %q", how)
		}
	}
}

// TestCorpusIsRefused is the rule: every candidate is refused at the user level.
func TestCorpusIsRefused(t *testing.T) {
	workers := max(2, min(8, runtime.NumCPU()))
	chk := pwstrength.NewWithLimit(workers, time.Minute)
	cands := buildCorpus(t, chk)
	// A candidate typed on a Persian layout meets a Checker that reads only that
	// layout, so a wrong table cannot hide behind the other one.
	checkers := []*pwstrength.Checker{chk, pwstrength.OnlyLayout(chk, 0), pwstrength.OnlyLayout(chk, 1)}
	in := pwstrength.Input{Phone: testPhone}

	var (
		mu     sync.Mutex
		failed []string
		wg     sync.WaitGroup
	)
	start := time.Now()
	jobs := make(chan candidate)
	for range workers {
		wg.Go(func() {
			for c := range jobs {
				r, err := judge(checkers[c.layout], c.pw, in, password.User)
				if err != nil || r.OK {
					mu.Lock()
					failed = append(failed, c.how+" -> "+c.pw+" "+describe(r, err))
					mu.Unlock()
				}
			}
		})
	}
	for _, c := range cands {
		jobs <- c
	}
	close(jobs)
	wg.Wait()
	took := time.Since(start)
	t.Logf("%d candidates, %d accepted, %s on %d workers", len(cands), len(failed), took.Round(time.Millisecond), workers)

	if len(failed) > 0 {
		slices.Sort(failed)
		// A summary by family first: a hole in one rule shows as one big line.
		families := map[string]int{}
		for _, f := range failed {
			how, _, _ := strings.Cut(f, " -> ")
			families[how[strings.LastIndex(how, ": ")+1:]]++
		}
		var sum []string
		for f, n := range families {
			sum = append(sum, strconv.Itoa(n)+" "+strings.TrimSpace(f))
		}
		slices.Sort(sum)
		shown := failed[:min(len(failed), 25)]
		t.Errorf("%d of %d weak passwords were accepted\nby family: %s\nfirst %d:\n  %s", len(failed), len(cands), strings.Join(sum, "; "), len(shown), strings.Join(shown, "\n  "))
	}
	if took > corpusTime {
		t.Errorf("the corpus took %s, over its budget of %s: the gate got slower", took, corpusTime)
	}
}

func describe(r pwstrength.Result, err error) string {
	if err != nil {
		return "error: " + err.Error()
	}
	return "accepted with score " + strconv.Itoa(r.Score)
}

// invisibleRules put one invisible character into a root at two places (round 10, primitives-r10-2): the
// guesser runs the root and never types the character, so the gate must score the root. The zero-width
// non-joiner is the Persian keyboard's own, the others come from a paste.
func invisibleRules(u string) []candidate {
	var out []candidate
	rs := []rune(u)
	for _, inv := range []rune{0x200c, 0x200b, 0x2060, 0x00ad} {
		for _, at := range []int{len(rs) / 2, len(rs) - 2} {
			pw := string(rs[:at]) + string(inv) + string(rs[at:])
			out = append(out, candidate{pw: pw, how: "invisible character U+" + strconv.FormatInt(int64(inv), 16) + " inserted"})
		}
	}
	return out
}
