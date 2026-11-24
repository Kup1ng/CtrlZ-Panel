package pwstrength_test

import (
	"bytes"
	"context"
	"errors"
	"math/rand/v2"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
	"unicode"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/password"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/pwstrength"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/pwstrength/layouts"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
	"github.com/Kup1ng/CtrlZ-Panel/internal/toolcmd"
	"golang.org/x/text/unicode/norm"
)

// judge is what the routes do, in the order they do it: password.Prepare (the length rules,
// refused as a 422 before anything is scored), then Check on the Prepared value it returns. A test
// that scores a raw string any other way tests a path no route takes, which is how rule 21's
// typed reading went dead in production while every test passed (round 7, primitives-r7-5).
// A password Prepare refuses is refused at the user level, whatever the reason.
func judge(c *pwstrength.Checker, pw string, in pwstrength.Input, k password.Kind) (pwstrength.Result, error) {
	p, err := password.Prepare(secret.New(pw), k)
	switch {
	case errors.Is(err, password.ErrTooShort):
		return pwstrength.Result{Reason: pwstrength.TooShort}, nil
	case err != nil:
		return pwstrength.Result{Reason: pwstrength.Weak}, nil
	}
	return c.Check(context.Background(), p, in, k)
}

func check(c *pwstrength.Checker, pw string, in pwstrength.Input, k password.Kind) pwstrength.Result {
	r, err := judge(c, pw, in, k)
	if err != nil {
		panic(err) // the gate is never full in these tests
	}
	return r
}

func TestWeakPasswordsAreRefusedWithAReason(t *testing.T) {
	c := pwstrength.New()
	in := pwstrength.Input{Phone: "+989121234567", Username: "ali"}
	for name, tc := range map[string]struct {
		pw     string
		reason pwstrength.Reason
	}{
		"common":        {"password123", pwstrength.TooCommon},
		"common 2":      {"iloveyou123", pwstrength.TooCommon},
		"repeated":      {"aaaaaaaaaaaa", pwstrength.Repeated},
		"repeated word": {"abcabcabcabcabc", pwstrength.Repeated},
		"sequence":      {"abcdefghijkl", pwstrength.Sequence},
		"digits run":    {"234567890123", pwstrength.Sequence},
		// A keyboard walk is a sequence (4.3), even when the dictionary also knows it.
		"top row word": {"qwertyuiop", pwstrength.Sequence},
		"too short":    {"abc", pwstrength.TooShort},
		"nine":         {"Xk3$9fQw2", pwstrength.TooShort},
	} {
		r := check(c, tc.pw, in, password.User)
		if r.OK || r.Reason != tc.reason {
			t.Errorf("%s: %+v, want reason %s", name, r, tc.reason)
		}
	}
}

func TestStrongPasswordsPass(t *testing.T) {
	c := pwstrength.New()
	in := pwstrength.Input{Phone: "+989121234567"}
	for _, pw := range []string{
		"correct horse battery staple",
		"Tr0ub4dor&3-purple-lantern",
		"v9#Lq2!xRm8@Zt4w",
		"گربه‌ی-سیاه-روی-دیوار-خوابید",
	} {
		r := check(c, pw, in, password.User)
		if !r.OK || r.Reason != "" || r.Score < 3 {
			t.Errorf("%q: %+v", pw, r)
		}
	}
	// A long passphrase is accepted for an admin, a plain eleven-letter word is not.
	if r := check(c, "correct horse battery staple extra words", pwstrength.Input{}, password.Admin); !r.OK || r.Score != 4 {
		t.Errorf("admin passphrase: %+v", r)
	}
	if r := check(c, "dragonflyer", pwstrength.Input{}, password.Admin); r.OK {
		t.Errorf("admin short word: %+v", r)
	}
	if r := check(c, "Tr0ub4dor&3x", pwstrength.Input{}, password.Admin); r.Reason != pwstrength.TooShort {
		t.Errorf("12 characters must be too_short for an admin (14), got %+v", r)
	}
}

// TestPersianKeyboardIsReadAsLatin is 4.3 step 1: "ضصثقفغ" scores as "qwerty",
// on both layouts an Iranian machine may have.
func TestPersianKeyboardIsReadAsLatin(t *testing.T) {
	c := pwstrength.New()
	in := pwstrength.Input{}
	latin := check(c, "qwertyuiop[]", in, password.User)
	persian := check(c, "ضصثقفغعهخحجچ", in, password.User)
	if persian.OK || latin.OK {
		t.Fatalf("a keyboard row passed: latin %+v persian %+v", latin, persian)
	}
	if persian.Reason != pwstrength.Sequence {
		t.Errorf("Persian row: %+v, want sequence", persian)
	}
	if r := check(c, "شسیبلاتنمکگ", in, password.User); r.OK {
		t.Errorf("home row in Persian passed: %+v", r)
	}
	// The bottom row, walked and walked back, on each layout. The first string
	// is ISIRI 9147 (پ on M), the second the legacy Windows layout (ئ on M).
	// Each used to be read correctly on one layout only (primitives-r1-1, -12).
	for name, pw := range map[string]string{
		"ISIRI forward":   "ظطزرذدپوظطز",
		"ISIRI backward":  "پدذرزطظپدذرزطظ",
		"legacy forward":  "ظطزرذدئوظطز",
		"legacy backward": "ئدذرزطظئدذرزطظ",
	} {
		if r := check(c, pw, in, password.User); r.OK {
			t.Errorf("%s: %q passed: %+v", name, pw, r)
		}
	}
	if r := check(c, "ظطزرذدپوظطز", in, password.User); r.Reason != pwstrength.Sequence {
		t.Errorf("ISIRI bottom row: %+v, want reason sequence", r)
	}
	if r := check(c, "ظطزرذدئوظطز", in, password.User); r.Reason != pwstrength.Sequence {
		t.Errorf("legacy bottom row: %+v, want reason sequence", r)
	}
}

// TestLegacyShiftedRowIsAWalk: on a legacy Windows machine Shift+Z..M types
// ة ي ژ ؤ إ أ ء, a bottom-row walk. It is caught as one (primitives-r2-1).
func TestLegacyShiftedRowIsAWalk(t *testing.T) {
	c := pwstrength.New()
	if r := check(c, "ةيژؤإأءآةيژؤ", pwstrength.Input{}, password.User); r.OK {
		t.Errorf("legacy shifted bottom row passed: %+v", r)
	}
}

// TestEveryLayoutKeyReadsAsItsUSKey replaces the table the old test copied from
// the code (primitives-r1-2, primitives-r2-1): every key of both layouts, shifted
// and not, is read through the generated tables and must come out as the US key it
// sits on. The expectation comes from the layout data files, which are the
// operating system's own layouts, so a wrong letter in the data is a diff against
// dump.ps1 and a wrong letter in the generated code is caught here.
func TestEveryLayoutKeyReadsAsItsUSKey(t *testing.T) {
	c := pwstrength.New()
	checked := 0
	for i, name := range layouts.Names() { // the order of Readings: ISIRI, then legacy
		l, err := layouts.Load(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, k := range l.Keys {
			us := []rune(k.US)
			if len(us) != 1 {
				continue
			}
			for _, out := range []string{k.Normal, k.Shift} {
				n := []rune(norm.NFKC.String(out))
				// A macro (the rial sign), an ASCII character and a joiner have no
				// reading; a letter with marks after it reads as the letter.
				if len(n) == 0 || n[0] < 0x80 || unicode.Is(unicode.Cf, n[0]) || !onlyMarks(n[1:]) {
					continue
				}
				got := pwstrength.Readings(c, out)[i]
				if got != string(us) {
					t.Errorf("%s key %s: %q (%U) reads as %q, want %q", name, k.Scan, out, n[0], got, string(us))
				}
				checked++
			}
		}
	}
	if checked < 100 {
		t.Fatalf("only %d characters checked: the layout data lost its keys", checked)
	}
	// The facts of spec 4.3 that the data must still show (it is the one place a
	// regenerated file could change them without anyone noticing): ISIRI has the
	// letter peh on M and ZWNJ-free shifted letters on the home row; the legacy
	// layout has peh on the backslash and no keh key.
	for _, tc := range []struct {
		layout       int
		letter, want string
	}{
		{0, "پ", "m"}, {1, "پ", "\\"}, {0, "ئ", "s"}, {1, "ئ", "m"}, {0, "ك", "z"}, {1, "ك", "ك"}, {0, "ؤ", "a"}, {1, "ؤ", "v"},
	} {
		if got := pwstrength.Readings(c, tc.letter)[tc.layout]; got != tc.want {
			t.Errorf("layout %d: %s reads as %q, want %q (spec 4.3)", tc.layout, tc.letter, got, tc.want)
		}
	}
	// ZWNJ is typed on Shift+B and Shift+Space and means nothing in a walk.
	for i, got := range pwstrength.Readings(c, "ب‌ب") {
		if got != "ff" {
			t.Errorf("layout %d: ZWNJ between two letters reads as %q, want ff", i, got)
		}
	}
}

func onlyMarks(rs []rune) bool {
	for _, r := range rs {
		if !unicode.Is(unicode.Mn, r) {
			return false
		}
	}
	return true
}

// TestLayoutTablesAreGenerated is the drift test of rule strength-gate-corpus: the
// tables of the code are the output of the generator over the layout data, byte for
// byte. Editing layouts_gen.go by hand (or the data without running go generate)
// fails here.
func TestLayoutTablesAreGenerated(t *testing.T) {
	want, err := layouts.Generate()
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile("layouts_gen.go")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bytes.ReplaceAll(got, []byte("\r\n"), []byte("\n")), want) {
		t.Fatal("layouts_gen.go differs from what the generator makes of layouts/*.tsv: run go generate ./internal/auth/pwstrength")
	}
}

// TestLongPasswordCostIsBounded is primitives-r1-10: zxcvbn is worse than
// linear in the length, so a 128-rune l33t password must not be scored whole.
func TestLongPasswordCostIsBounded(t *testing.T) {
	c := pwstrength.New()
	// Not a repeated unit: that would be folded to 20 runes before scoring.
	const alphabet = "4@8(6<{[3&9!|1$5+7%2abcdefg"
	rng := rand.New(rand.NewPCG(1, 2))
	var sb strings.Builder
	for range 128 {
		sb.WriteByte(alphabet[rng.IntN(len(alphabet))])
	}
	pw := sb.String()
	start := time.Now()
	r := check(c, pw, pwstrength.Input{}, password.Admin)
	took := time.Since(start)
	t.Logf("128 runes: %v, %+v", took, r)
	if took > 750*time.Millisecond {
		t.Errorf("checking 128 runes took %v, want well under a second", took)
	}
}

// TestTailRaisesTheScoreByOne pins the length bonus: the head is scored, and a
// than the maximum. The head here is two dictionary words and two numbers, score 2,
// which a user (needs 3) is refused. It was a keyboard walk until the gate learned
// to fold walks (rule strength-gate-corpus): a folded walk scores 0, and the tail
// bonus is about length, so the control needs a head that is weak but not a pattern.
// (needs 3) is refused.
func TestTailRaisesTheScoreByOne(t *testing.T) {
	c := pwstrength.New()
	head := "sunshine2024princess1990"
	if len([]rune(head)) != 24 {
		t.Fatalf("test head is %d runes", len([]rune(head)))
	}
	base := check(c, head, pwstrength.Input{}, password.User)
	if base.OK || base.Score != 2 {
		t.Fatalf("control head: %+v, want a refused score 2", base)
	}
	good := "Qm7!rT2#vL9$wK4z"
	if r := check(c, head+good, pwstrength.Input{}, password.User); !r.OK || r.Score != base.Score+1 {
		t.Errorf("a strong 16-rune tail: %+v, want score %d", r, base.Score+1)
	}
	// Fifteen runes are not a tail, however strong.
	if r := check(c, head+good[:15], pwstrength.Input{}, password.User); r.Score != base.Score {
		t.Errorf("a 15-rune tail changed the score: %+v", r)
	}
	// A head at the top cannot go over it.
	top := check(c, "Vk9#Lmq2-zT4!pRw8@Xn5&Bd"+good, pwstrength.Input{}, password.Admin)
	if top.Score != 4 {
		t.Errorf("top score with a tail: %+v", top)
	}
	// A weak head is not rescued by length alone: the repeat stays refused.
	if r := check(c, strings.Repeat("a", 24)+strings.Repeat("b", 100), pwstrength.Input{}, password.User); r.OK {
		t.Errorf("a repeated head with a long tail passed: %+v", r)
	}
}

// TestPaddingGetsNoTailBonus is primitives-r2-2 and -6: a tail that holds no
// entropy must not lift a weak head over the gate, whether it is one character,
// a keyboard walk, or the head again.
func TestPaddingGetsNoTailBonus(t *testing.T) {
	c := pwstrength.New()
	head := "sunshine2024princess1990"
	for name, tail := range map[string]string{
		"one letter":       strings.Repeat("a", 16),
		"ones":             strings.Repeat("1", 16),
		"another walk":     "poiuytrewqlkjhgf",
		"longer walk":      "poiuytrewqlkjhgfdsamnbvc",
		"two letters":      strings.Repeat("ab", 8),
		"the head again":   head,
		"the head, a half": head[:12] + head[:12],
	} {
		for _, k := range []password.Kind{password.User, password.Admin} {
			if r := check(c, head+tail, pwstrength.Input{}, k); r.OK {
				t.Errorf("kind %v, %s: %+v passed", k, name, r)
			}
		}
	}
	// An admin whose head scores 3 gets nothing for padding either.
	three := head + "Qm7!rT2#vL9$wK4z"
	if r := check(c, three+strings.Repeat("1", 20), pwstrength.Input{}, password.Admin); r.OK {
		t.Errorf("admin: score-3 password plus padding passed: %+v", r)
	}
}

// TestRepeatedUnitsAreRefused is primitives-r2-5: zxcvbn finds repeats of one
// character only, so a repeated unit of two or more characters was scored as
// random text. The unit alone is scored instead.
func TestRepeatedUnitsAreRefused(t *testing.T) {
	c := pwstrength.New()
	for name, tc := range map[string]struct {
		pw   string
		kind password.Kind
	}{
		"admin xy":        {"xyxyxyxyxyxyxy", password.Admin},
		"admin ab":        {"abababababababab", password.Admin},
		"admin summer":    {"Summer2024!Summer2024!", password.Admin},
		"admin summer x3": {"Summer2024!Summer2024!Summer2024!", password.Admin},
		"user ab":         {"abababababab", password.User},
		"user salaam":     {"سلامسلامسلام", password.User},
		"user salaam x4":  {"سلامسلامسلامسلام", password.User},
		"user summer":     {"Summer2024!Summer2024!", password.User},
		"one stray char":  {"xyxyxyxyxyxyxyZ", password.User},
		"nested repeat":   {"xyxyxyxyxyxyxyxyxyxyxyxyZ", password.Admin},

		"password repeated": {"password123password123", password.User},
		// primitives-r3-5: a second copy that differs a little is not new entropy.
		"user summer last changed": {"Summer2024!Summer2024?", password.User},
		"user summer inserted":     {"Summer2024!xSummer2024!", password.User},
		"user michael inserted":    {"Michael88xMichael88", password.User},
		"user ninja year bumped":   {"ninja2024ninja2025", password.User},
		"admin summer changed":     {"Summer2024!Summer2024?", password.Admin},
	} {
		r := check(c, tc.pw, pwstrength.Input{}, tc.kind)
		if r.OK || r.Reason != pwstrength.Repeated {
			t.Errorf("%s: %q gave %+v, want refused as repeated", name, tc.pw, r)
		}
	}
	// A strong unit repeated stays as strong as the unit: not refused for the
	// repetition, and no better than the unit.
	unit := "v9#Lq2!xRm8@Zt4w"
	r := check(c, unit+unit, pwstrength.Input{}, password.Admin)
	alone := check(c, unit, pwstrength.Input{}, password.Admin)
	if !r.OK || r.Score > alone.Score {
		t.Errorf("strong unit twice: %+v, alone %+v", r, alone)
	}
	// A strong unit with a changed copy stays as strong as the unit alone.
	r = check(c, unit+"v9#Lq2!xRm8@Zt4W", pwstrength.Input{}, password.Admin)
	if !r.OK || r.Score > alone.Score {
		t.Errorf("strong unit, changed copy: %+v, alone %+v", r, alone)
	}
	// Ordinary text with a few doubled letters is not folded.
	for _, pw := range []string{"correct horse battery staple", "Tr0ub4dor&3-purple-lantern", "bookkeeper-mississippi-4Q"} {
		if r := check(c, pw, pwstrength.Input{}, password.User); !r.OK {
			t.Errorf("%q refused: %+v", pw, r)
		}
	}
}

// TestScoringIsGated: when every slot is taken, Check answers password.ErrBusy
// after the wait, and a cancelled context ends the wait at once.
func TestScoringIsGated(t *testing.T) {
	c := pwstrength.NewWithLimit(1, 50*time.Millisecond)
	release := pwstrength.HoldSlot(c)
	pw := "Vk9#Lmq2-zT4!pRw"
	if _, err := judge(c, pw, pwstrength.Input{}, password.User); !errors.Is(err, password.ErrBusy) {
		t.Fatalf("full gate: %v, want ErrBusy", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p, _ := password.Prepare(secret.New(pw), password.User)
	if _, err := c.Check(ctx, p, pwstrength.Input{}, password.User); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled context: %v", err)
	}
	// A refusal that needs no scoring (too short) does not take a slot.
	if r, err := judge(c, "abc", pwstrength.Input{}, password.User); err != nil || r.Reason != pwstrength.TooShort {
		t.Errorf("short password with a full gate: %+v %v", r, err)
	}
	release()
	if r, err := judge(c, pw, pwstrength.Input{}, password.User); err != nil || !r.OK {
		t.Errorf("after release: %+v %v", r, err)
	}
}

func TestPersianAndArabicDigitsAreASCII(t *testing.T) {
	c := pwstrength.New()
	in := pwstrength.Input{}
	// Persian digits typed as a run: the same as the ASCII run.
	for _, pw := range []string{"۱۲۳۴۵۶۷۸۹۰۱۲", "١٢٣٤٥٦٧٨٩٠١٢", "123456789012"} {
		r := check(c, pw, in, password.User)
		if r.OK || r.Reason != pwstrength.Sequence {
			t.Errorf("%q: %+v, want sequence", pw, r)
		}
	}
	// And a phone written in Persian digits is caught as the phone.
	r := check(c, "x۱۲۳۴۵۶۷y-long-enough", pwstrength.Input{Phone: "+989121234567"}, password.User)
	if r.OK || r.Reason != pwstrength.ContainsPhone {
		t.Errorf("Persian-digit phone: %+v", r)
	}
}

func TestContainsPhone(t *testing.T) {
	c := pwstrength.New()
	in := pwstrength.Input{Phone: "+989121234567"}
	for name, pw := range map[string]string{
		"last 7":            "Zq!1234567-lantern-77",
		"whole national":    "9121234567Zq!lantern",
		"with 0":            "09121234567-Zq-lantern",
		"with country code": "989121234567Zq!lantern",
		"inside":            "plum-1234567-orchard-Zq",
		"hyphen separated":  "plum-123-4567-orchard-Zq9",
		"underscore group":  "plum_123_4567_orchard_Zq9",
		"fullwidth digits":  "plum１２３４５６７orchard-Zq9",
		"arabic-indic":      "plum١٢٣٤٥٦٧orchard-Zq9",
	} {
		r := check(c, pw, in, password.User)
		if r.OK || r.Reason != pwstrength.ContainsPhone || r.Score != 0 {
			t.Errorf("%s: %+v", name, r)
		}
	}
	// Six of the seven digits, or the digits apart, is fine.
	for _, pw := range []string{"plum-123456-orchard-Zq9-lantern"} {
		if r := check(c, pw, in, password.User); r.Reason == pwstrength.ContainsPhone {
			t.Errorf("%q flagged as containing the phone", pw)
		}
	}
	// With no phone known, nothing is flagged.
	if r := check(c, "plum-1234567-orchard-Zq9-lantern", pwstrength.Input{}, password.User); r.Reason == pwstrength.ContainsPhone {
		t.Error("flagged with no phone")
	}
}

func TestUserInputsAreGuessable(t *testing.T) {
	c := pwstrength.New()
	// The product name and the username are in the dictionary of guesses.
	plain := check(c, "Vk9#Lmq2-zT", pwstrength.Input{}, password.User)
	if !plain.OK {
		t.Fatalf("control password refused: %+v", plain)
	}
	in := pwstrength.Input{Phone: "+989121234567", Username: "zarathustra"}
	for _, pw := range []string{"ctrlzctrlz1234", "zarathustra1234", "ctrlz-zarathustra"} {
		if r := check(c, pw, in, password.User); r.OK {
			t.Errorf("%q passed although it is built from the inputs: %+v", pw, r)
		}
	}
}

func TestUnusableInput(t *testing.T) {
	c := pwstrength.New()
	if r, _ := judge(c, "", pwstrength.Input{}, password.User); r.OK || r.Reason != pwstrength.TooShort {
		t.Errorf("empty: %+v", r)
	}
	if r := check(c, "abcdefghij\xff", pwstrength.Input{}, password.User); r.OK {
		t.Errorf("invalid UTF-8 passed: %+v", r)
	}
	if r := check(c, strings.Repeat("a", 10000), pwstrength.Input{}, password.User); r.OK {
		t.Errorf("huge input passed: %+v", r)
	}
}

// TestDependencyGate is the acceptance gate of 4.3 for github.com/ccojocar/zxcvbn-go:
// no network package in the dependency graph, and a bounded heap.
func TestNoNetworkInDependencies(t *testing.T) {
	if testing.Short() {
		t.Skip("shells out to the go tool")
	}
	out, err := toolcmd.Go(context.Background(), nil, "list", "-deps", "github.com/Kup1ng/CtrlZ-Panel/internal/auth/pwstrength").CombinedOutput()
	if err != nil {
		t.Skipf("go list unavailable: %v", err)
	}
	for _, pkg := range strings.Fields(string(out)) {
		if pkg == "net" || strings.HasPrefix(pkg, "net/") || pkg == "crypto/tls" || pkg == "os/exec" {
			t.Errorf("pwstrength depends on %s: the check must be offline", pkg)
		}
	}
}

func TestHeapStaysSmall(t *testing.T) {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	c := pwstrength.New()
	check(c, "correct horse battery staple", pwstrength.Input{Phone: "+989121234567"}, password.User)
	check(c, "ضصثقفغعهخحجچ", pwstrength.Input{}, password.User)
	runtime.GC()
	runtime.ReadMemStats(&after)
	// The dictionaries are loaded when the module initialises, before this
	// test, so "before" already holds them; what the check adds on top is small.
	added := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	t.Logf("heap in use after GC: %d KiB before first use, %d KiB after (added %d KiB)", before.HeapAlloc>>10, after.HeapAlloc>>10, added>>10)
	if added > 16<<20 {
		t.Errorf("first use added %d MiB, limit 16", added>>20)
	}
	if after.HeapAlloc > 64<<20 {
		t.Errorf("heap in use is %d MiB with the dictionaries loaded", after.HeapAlloc>>20)
	}
}

func BenchmarkCheck(b *testing.B) {
	c := pwstrength.New()
	in := pwstrength.Input{Phone: "+989121234567"}
	pw, _ := password.Prepare(secret.New("correct horse battery staple"), password.User)
	for b.Loop() {
		c.Check(context.Background(), pw, in, password.User)
	}
}

// TestWalksAreRefusedAsSequences: the shapes the corpus found that zxcvbn does not
// see, each on its own so a failure names the shape. A walk is a repeat of itself
// moved one key (rule strength-gate-corpus), and the answer is `sequence`.
func TestWalksAreRefusedAsSequences(t *testing.T) {
	c := pwstrength.New()
	for name, pw := range map[string]string{
		"row repeated":      "qwertyuiopqwertyuiopqwertyuiop",
		"zigzag":            "q1w2e3r4t5y6u7",
		"column sweep":      "1qaz2wsx3edc",
		"column sweep plus": "1qaz2wsx3edc@1990",
		"row stack":         "asdfqwerzxcv",
		"persian zigzag":    "ض1ص2ث3ق4ف5غ6ع7",
		"persian row":       "ضصثقفغعهخحجچ",
	} {
		r := check(c, pw, pwstrength.Input{}, password.User)
		if r.OK || r.Reason != pwstrength.Sequence {
			t.Errorf("%s: %q gave %+v, want refused as sequence", name, pw, r)
		}
	}
}

// TestDoubleLettersSurviveTheFold: a word with doubled letters followed by padding
// is scored as the word, not as the word with its doubles removed ("Fotbal0" is not
// in any dictionary and scored 3).
func TestDoubleLettersSurviveTheFold(t *testing.T) {
	c := pwstrength.New()
	for _, pw := range []string{"Football0000000000000000", "Football" + strings.Repeat("x", 20), "bookkeeper" + strings.Repeat("1", 16)} {
		if r := check(c, pw, pwstrength.Input{}, password.User); r.OK {
			t.Errorf("%q passed: %+v", pw, r)
		}
	}
}

// TestMarksKeepTheirOrder: the Persian layouts keep their diacritics on the shifted
// top row, and NFKC sorts a run of marks, so a walk of them was read in the wrong
// order. The layout reading starts from what was typed.
func TestMarksKeepTheirOrder(t *testing.T) {
	c := pwstrength.New()
	// ISIRI Shift+Q..I, in key order.
	typed := "ًٌٍَُِّْ"
	if got := pwstrength.Readings(c, typed)[0]; got != "qwertyui" {
		t.Errorf("ISIRI marks read as %q, want qwertyui", got)
	}
}

// TestRandomPasswordsAreNotFolded is the other side of the corpus: a gate that
// refused everything would pass it. Random text over a wide alphabet must not be
// folded by a chance repeat or a chance walk (a fold only removes what repeats, but
// the gate must not take points from a password that is strong). The seed is fixed.
func TestRandomPasswordsAreNotFolded(t *testing.T) {
	c := pwstrength.NewWithLimit(4, time.Minute)
	rng := rand.New(rand.NewPCG(7, 9))
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+"
	for _, n := range []int{14, 20, 40} {
		for range 300 {
			b := make([]byte, n)
			for i := range b {
				b[i] = alphabet[rng.IntN(len(alphabet))]
			}
			if r := check(c, string(b), pwstrength.Input{}, password.User); !r.OK {
				t.Errorf("random %d characters refused: %q %+v", n, b, r)
			}
		}
	}
}

// TestLayoutDataShowsTheFactsOfSpec43 (primitives-r5-2) is the independent anchor of the layout
// data. TestEveryLayoutKeyReadsAsItsUSKey and TestLayoutTablesAreGenerated compare the
// code with the data files, and the corpus is built from the same files, so a dump taken
// on a Windows build where a key differs would still leave every one of them green. These
// are the facts spec 4.3 states, typed here from the published layouts (Wikipedia, Persian
// keyboard layout; kbdlayout.info/kbdfa) and not from the dump: a regenerated data file that
// disagrees with them fails here and has to be looked at by a person.
func TestLayoutDataShowsTheFactsOfSpec43(t *testing.T) {
	const (
		peh, yehHamza, hamza, kaf, yeh = "پ", "ئ", "ء", "ك", "ي"
		jeh, wawHamza, alefHamzaAbove  = "ژ", "ؤ", "أ"
		alefHamzaBelow, alefMadda, teh = "إ", "آ", "ة" // teh marbuta
		zwnj                           = "‌"
	)
	keyOf := func(l layouts.Layout, us string) layouts.Key {
		for _, k := range l.Keys {
			if k.US == us {
				return k
			}
		}
		t.Fatalf("%s has no key whose US legend is %q", l.Name, us)
		return layouts.Key{}
	}
	isiri, err := layouts.Load("isiri9147")
	if err != nil {
		t.Fatal(err)
	}
	kbdfa, err := layouts.Load("kbdfa")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []struct {
		l       layouts.Layout
		us      string
		shifted bool
		want    string
		what    string
	}{
		// ISIRI 9147
		{isiri, "m", false, peh, "peh on M"},
		{isiri, "s", true, yehHamza, "yeh with hamza on Shift+S"},
		{isiri, "m", true, hamza, "hamza on Shift+M"},
		{isiri, "z", true, kaf, "Arabic kaf on Shift+Z"},
		{isiri, "d", true, yeh, "Arabic yeh on Shift+D"},
		{isiri, "c", true, jeh, "jeh on Shift+C"},
		{isiri, "a", true, wawHamza, "waw with hamza on Shift+A"},
		{isiri, "g", true, alefHamzaAbove, "alef with hamza above on Shift+G"},
		{isiri, "f", true, alefHamzaBelow, "alef with hamza below on Shift+F"},
		{isiri, "h", true, alefMadda, "alef madda on Shift+H"},
		{isiri, "j", true, teh, "teh marbuta on Shift+J"},
		{isiri, "b", true, zwnj, "ZWNJ on Shift+B"},
		{isiri, " ", true, zwnj, "ZWNJ on Shift+Space"},
		// The legacy Windows layout (KBDFA): the bottom row shifted, peh on the backslash.
		{kbdfa, "\\", false, peh, "peh on the backslash"},
		{kbdfa, "m", false, yehHamza, "yeh with hamza on M"},
		{kbdfa, "z", true, teh, "teh marbuta on Shift+Z"},
		{kbdfa, "x", true, yeh, "Arabic yeh on Shift+X"},
		{kbdfa, "c", true, jeh, "jeh on Shift+C"},
		{kbdfa, "v", true, wawHamza, "waw with hamza on Shift+V"},
		{kbdfa, "b", true, alefHamzaBelow, "alef with hamza below on Shift+B"},
		{kbdfa, "n", true, alefHamzaAbove, "alef with hamza above on Shift+N"},
		{kbdfa, "m", true, hamza, "hamza on Shift+M"},
		{kbdfa, "h", true, alefMadda, "alef madda on Shift+H"},
	} {
		k := keyOf(f.l, f.us)
		got := k.Normal
		if f.shifted {
			got = k.Shift
		}
		if got != f.want {
			t.Errorf("%s: %s, the data has %q (%U), the spec says %q (%U)", f.l.Name, f.what, got, []rune(got), f.want, []rune(f.want))
		}
	}
	// The legacy layout has no Arabic kaf key at all.
	for _, k := range kbdfa.Keys {
		if k.Normal == kaf || k.Shift == kaf {
			t.Errorf("kbdfa has a kaf on key %s; the spec says it has none", k.Scan)
		}
	}
	// The shifted bottom row of ISIRI 9147 is pinned against the standard as published (Wikipedia, "Persian
	// keyboard layout"), not against the operating system: kbdfar.dll types tah on Shift+X, which is the
	// unshifted letter again, and the standard has the combining maddah above (U+0653) there (round 9,
	// primitives-r9-1; round 8 pinned the system's tah and the test could not see the system deviate). The row
	// is the only place the file departs from a dump, so it is checked cell by cell, and so is the SET of
	// letter keys whose shifted cell equals the unshifted one, which must be empty: a wrong cell on any key
	// makes it grow.
	for _, c := range []struct{ us, want string }{
		{"z", "\u0643"}, {"x", "\u0653"}, {"c", "\u0698"}, {"v", "\u0670"}, {"b", "\u200c"}, {"n", "\u0654"}, {"m", "\u0621"},
	} {
		if got := keyOf(isiri, c.us).Shift; got != c.want {
			t.Errorf("ISIRI 9147 Shift+%s types %U, the standard says %U", strings.ToUpper(c.us), []rune(got), []rune(c.want))
		}
	}
	// The WHOLE shifted number row, pinned against the standard the same way (round 10, primitives-r10-8; round
	// 11, primitives-r11-5): the dump reported the unshifted ZWJ on Shift+` and the four letters of the rial sign
	// (the NFKC form of U+FDFC) on Shift+4, the same fault as Shift+X, and no test looked at a key that is not a
	// letter. Round 10 pinned five of the thirteen cells and trusted the dump for the other eight, so a changed
	// Shift+2 or Shift+3 (the two it listed as not checked) could not fail anything: every cell is a code point
	// of the standard here, and the row is complete, so a key added to or lost from it fails as well.
	shiftedNumberRow := []struct {
		us   string
		want rune
	}{
		{"`", 0x00f7}, {"1", 0x0021}, {"2", 0x066c}, {"3", 0x066b}, {"4", 0xfdfc}, {"5", 0x066a}, {"6", 0x00d7},
		{"7", 0x060c}, {"8", 0x002a}, {"9", 0x0029}, {"0", 0x0028}, {"-", 0x0640}, {"=", 0x002b},
	}
	numberRowKeys := map[string]bool{"`": true, "-": true, "=": true}
	for d := '0'; d <= '9'; d++ {
		numberRowKeys[string(d)] = true
	}
	for _, c := range shiftedNumberRow {
		delete(numberRowKeys, c.us)
	}
	if len(numberRowKeys) != 0 {
		t.Errorf("the pinned shifted number row lacks the keys %v", numberRowKeys)
	}
	for _, c := range shiftedNumberRow {
		if got := []rune(keyOf(isiri, c.us).Shift); len(got) != 1 || got[0] != c.want {
			t.Errorf("ISIRI 9147 Shift+%s types %U, the standard says %U", c.us, got, c.want)
		}
	}
	// No key of ISIRI 9147 types the same character shifted and unshifted, except the ones listed here (a
	// reviewed list: each is a key the standard really leaves the same on both levels; today it is empty).
	// Every key, not the letter keys only: a wrong cell on any key makes the set grow.
	reviewedSame := map[string]bool{}
	for _, k := range isiri.Keys {
		if k.Normal == k.Shift && !reviewedSame[k.Scan] {
			t.Errorf("ISIRI 9147 key %s (US %q) types %q on both levels: a cell the operating system reported and the standard does not have, or a key to add to the reviewed list", k.Scan, k.US, k.Normal)
		}
	}
	// The rial sign and the division sign read as the keys they are on, not as the letters of their expansion.
	for _, c := range []struct {
		typed rune
		key   string
	}{{0xfdfc, "4"}, {0x00f7, "`"}, {0x00d7, "6"}} {
		if got := pwstrength.Readings(pwstrength.New(), string(c.typed))[0]; got != c.key {
			t.Errorf("%U reads as %q under ISIRI 9147, want %q", c.typed, got, c.key)
		}
	}
	// A shifted walk typed on a keyboard that follows the standard reads as the Latin walk, maddah included.
	if got := pwstrength.Readings(pwstrength.New(), "\u0643\u0653\u0698")[0]; got != "zxc" {
		t.Errorf("Shift+Z, Shift+X, Shift+C read as %q, want zxc", got)
	}
}

// One typed character that NFKC expands into a phrase is not a long password
// (review round 6, primitives-r6-1): the minimum counts what the person typed,
// and the phrase an attacker enumerates from a few hundred compatibility
// characters is not scored as if it were text.
func TestCompatibilityCharactersDoNotCountAsTheirExpansion(t *testing.T) {
	c := pwstrength.New()
	in := pwstrength.Input{Phone: "+989121234567"}
	for _, kind := range []password.Kind{password.User, password.Admin} {
		for _, pw := range []string{"ﷺ", "ﷺ1", "ﷺ﷽", "ﷻﷺ﷽ﷲ", "ﷺﷺﷺ﷽﷽﷽"} {
			r := check(c, pw, in, kind)
			if r.OK || r.Reason != pwstrength.TooShort {
				t.Errorf("kind %v %q: %+v, want too_short", kind, pw, r)
			}
		}
	}
	// Check keeps its own minimum for a Prepared made without one (password.Typed), so the count does not
	// rest on Prepare having run first: the same characters, handed to Check directly.
	for _, pw := range []string{"ﷺ", "ﷺ1", "ﷺ﷽", "ﷻﷺ﷽ﷲ"} {
		p, err := password.Typed(secret.New(pw))
		if err != nil {
			t.Fatal(err)
		}
		r, err := c.Check(context.Background(), p, in, password.Admin)
		if err != nil || r.OK || r.Reason != pwstrength.TooShort {
			t.Errorf("%q handed to Check without Prepare: %+v %v, want too_short", pw, r, err)
		}
	}
}

// TestThePasswordIsScoredOnWhatWasTypedNotOnItsNFKCForm is primitives-r7-5. The routes run
// password.Prepare and then Check on what it returns; when Prepare returned the NFKC text as a plain
// secret.String, Check's typed reading was that same text, so the reading of primitives-r6-1 never ran
// in production and 'Password12345' plus one compatibility character was accepted (score 4) where the
// typed text is refused (too_common). Check takes the Prepared value now. The first half drives the
// route path; the second shows what the type prevents: the NFKC text, made into a Prepared of its own,
// is accepted, which is exactly the hole.
func TestThePasswordIsScoredOnWhatWasTypedNotOnItsNFKCForm(t *testing.T) {
	c := pwstrength.New()
	for _, tc := range []struct {
		pw   string
		kind password.Kind
	}{
		{"Password12345ﷻ", password.Admin}, // 14 typed code points, 13 + the expansion of U+FDFB
		{"qwerty123ﷻ", password.User},
		{"Password1ﷺ", password.User},
	} {
		r := check(c, tc.pw, pwstrength.Input{}, tc.kind)
		if r.OK {
			t.Errorf("%q passed the route path (Prepare, then Check) with score %d: the typed reading did not run", tc.pw, r.Score)
		}
		n, err := password.Normalize(secret.New(tc.pw))
		if err != nil {
			t.Fatal(err)
		}
		hole, err := password.Typed(n) // what a route did before: the NFKC text as if it were what was typed
		if err != nil {
			t.Fatal(err)
		}
		if got, err := c.Check(context.Background(), hole, pwstrength.Input{}, tc.kind); err != nil || !got.OK {
			t.Logf("%q: the NFKC text alone is refused too (%+v), so this case does not show the hole", tc.pw, got)
		}
	}
	// A Prepared that nobody made is refused, never scored as an empty password that passes.
	if r, err := c.Check(context.Background(), password.Prepared{}, pwstrength.Input{}, password.User); err != nil || r.OK {
		t.Errorf("the zero Prepared: %+v %v", r, err)
	}
}
