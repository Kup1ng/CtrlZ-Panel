package digits_test

import (
	"context"
	"regexp"
	"strings"
	"testing"
	"time"
	"unicode"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/appclock"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/digits"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/invite"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/otp"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/recovery"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/totp"
	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
)

func TestToASCII(t *testing.T) {
	for in, want := range map[string]string{
		"۰۱۲۳۴۵۶۷۸۹": "0123456789", // Persian
		"٠١٢٣٤٥٦٧٨٩": "0123456789", // Arabic-Indic
		"０１２３４５６７８９": "0123456789", // fullwidth
		"0123456789": "0123456789",
		"۰۹۱۲ abc-٣": "0912 abc-3",
		"":           "",
		"ضصثقفغ":     "ضصثقفغ",
	} {
		if got := digits.ToASCII(in); got != want {
			t.Errorf("ToASCII(%q) = %q, want %q", in, got, want)
		}
	}
}

// typedGuard is a guard that lets every check through; the test wants the
// verdict on the text, not the throttle.
type typedGuard struct{}

func (typedGuard) Hit(context.Context) (bool, time.Duration, error) { return true, 0, nil }
func (typedGuard) Spend(context.Context, int64) (bool, error)       { return true, nil }
func (typedGuard) Reset(context.Context) error                      { return nil }

// TestEveryTypedCodeSurvivesTheSameMarks is the one table over the three typed
// codes (round 13, primitives-r13-1): an SMS code, an authenticator code and a
// recovery code take the same paste. Each used to have its own fold, and a mark
// that one accepted made the next "not a code" and cost a try.
func TestEveryTypedCodeSurvivesTheSameMarks(t *testing.T) {
	const (
		lrm  = "\u200e"
		rlm  = "\u200f"
		zwnj = "\u200c"
		nbsp = "\u00a0"
	)
	// Wrappers a chat app, a note or a right-to-left editor puts around or
	// inside a code. The same list is applied to all three codes.
	wrap := map[string]func(group []string) string{
		"plain":           func(g []string) string { return strings.Join(g, "") },
		"rlm around":      func(g []string) string { return rlm + strings.Join(g, "") + rlm },
		"lrm between":     func(g []string) string { return strings.Join(g, lrm) },
		"zwnj between":    func(g []string) string { return strings.Join(g, zwnj) },
		"nbsp between":    func(g []string) string { return strings.Join(g, nbsp) },
		"tab between":     func(g []string) string { return strings.Join(g, "\t") },
		"hyphen+rlm":      func(g []string) string { return strings.Join(g, "-"+rlm) },
		"embedding":       func(g []string) string { return "\u202a" + strings.Join(g, " ") + "\u202c" },
		"isolate":         func(g []string) string { return "\u2066" + strings.Join(g, "") + "\u2069" },
		"bom and zwsp":    func(g []string) string { return "\ufeff" + strings.Join(g, "\u200b") },
		"fullwidth space": func(g []string) string { return strings.Join(g, "\u3000") },
	}

	seed := secret.NewBytes([]byte("12345678901234567890"))
	now := appclock.Now()
	totpCode := totp.Generate(seed, now)
	rec, err := recovery.NewSet()
	if err != nil {
		t.Fatal(err)
	}
	recCode := strings.ReplaceAll(rec.Codes[0].Reveal(), "-", "")
	smsCode := "482915"
	// The invite link is the fourth pasted value (round 15, tenant-r15-1 and -5; D67): the same table, minus the
	// wrappers that add a hyphen, because a hyphen is a base64url character of the token and is kept.
	inviteRing, err := keyring.NewEphemeral(keyring.DomainInviteSign)
	if err != nil {
		t.Fatal(err)
	}
	invitePub, err := inviteRing.Public(keyring.DomainInviteSign)
	if err != nil {
		t.Fatal(err)
	}
	inviteID := uuid.New()
	inviteTok, _, err := invite.Mint(inviteRing, inviteID, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	inviteCode := inviteTok.Reveal()
	split := func(s string, n int) []string {
		var out []string
		for len(s) > n {
			out, s = append(out, s[:n]), s[n:]
		}
		return append(out, s)
	}

	for name, w := range wrap {
		if got := otp.NormalizeCode(w(split(smsCode, 3))); got != smsCode {
			t.Errorf("sms code, %s: %q", name, got)
		}
		in := secret.New(w(split(totpCode, 3)))
		if err := totp.CheckAt(context.Background(), typedGuard{}, seed, in, now); err != nil {
			t.Errorf("totp code, %s: %v", name, err)
		}
		if got, ok := recovery.Canonical(w(split(recCode, 4))); !ok || got != recCode {
			t.Errorf("recovery code, %s: %q %v", name, got, ok)
		}
		if strings.Contains(name, "hyphen") {
			continue
		}
		if ref, ok := invite.Open(invitePub, now, w(split(inviteCode, 5))); !ok || ref.ID != inviteID {
			t.Errorf("invite link, %s: %v", name, ok)
		}
	}
	// Persian and Arabic digits are the digits of the link, as in the other three.
	persian := strings.NewReplacer("0", "۰", "1", "۱", "2", "۲", "3", "۳", "4", "۴", "5", "۵", "6", "۶", "7", "۷", "8", "۸", "9", "۹").Replace(inviteCode)
	if ref, ok := invite.Open(invitePub, now, persian); !ok || ref.ID != inviteID {
		t.Errorf("invite link with Persian digits: %v", ok)
	}
	if _, ok := invite.Open(invitePub, now, inviteCode[:len(inviteCode)-1]+"."); ok {
		t.Error("invite: a visible stray character was read as part of the link")
	}
	// The control: a visible stray character is still not a code, in all three.
	if otp.NormalizeCode("48x915") == smsCode {
		t.Error("sms: a letter was dropped")
	}
	if err := totp.CheckAt(context.Background(), typedGuard{}, seed, secret.New(totpCode[:5]+"x"), now); err == nil {
		t.Error("totp: a letter was read as a digit")
	}
	if _, ok := recovery.Canonical(recCode[:15] + "U"); ok {
		t.Error("recovery: U is not in the alphabet")
	}
}

func TestTypedKeepsVisibleCharacters(t *testing.T) {
	for in, want := range map[string]string{
		"۰۹ ab-\u200f٣": "09 ab-3",
		"\u00a0١٢":      " 12", // NFKC makes the no-break space a plain space
		"":              "",
		"ｑ１":            "q1",
	} {
		if got := digits.Typed(in); got != want {
			t.Errorf("Typed(%q) = %q, want %q", in, got, want)
		}
	}
}

// everyPasteMark lists the code points the fold must drop, by walking the Unicode tables and not
// by writing marks down (round 14, primitives-r14-1): every code point of the format category,
// the variation selectors and the other default-ignorable code points, plus the white space a
// paste of a wrapped line brings. A mark nobody thought of is in this list the day Unicode has it.
func everyPasteMark() []rune {
	var out []rune
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if r >= 0xd800 && r <= 0xdfff {
			continue
		}
		// An unassigned default-ignorable code point is the one thing left out (see PasteMark).
		if unicode.Is(unicode.Cf, r) || (unicode.In(r, unicode.Variation_Selector, unicode.Other_Default_Ignorable_Code_Point) && !unicode.Is(unicode.C, r)) {
			out = append(out, r)
		}
	}
	return append(out, '\t', '\n', '\r', 0x2028, 0x2029)
}

// TestEveryTypedCodeDropsEveryPasteMark plants every code point of the class, at the front, inside
// and at the end of each of the three typed codes. NFKC runs first, so a mark NFKC turns into
// something else would show here too.
func TestEveryTypedCodeDropsEveryPasteMark(t *testing.T) {
	marks := everyPasteMark()
	if len(marks) < 400 {
		t.Fatalf("only %d marks: the walk of the tables has stopped finding them", len(marks))
	}
	seed := secret.NewBytes([]byte("12345678901234567890"))
	now := appclock.Now()
	totpCode := totp.Generate(seed, now)
	rec, err := recovery.NewSet()
	if err != nil {
		t.Fatal(err)
	}
	recCode := strings.ReplaceAll(rec.Codes[0].Reveal(), "-", "")
	const smsCode = "482915"
	inviteRing, err := keyring.NewEphemeral(keyring.DomainInviteSign)
	if err != nil {
		t.Fatal(err)
	}
	invitePub, err := inviteRing.Public(keyring.DomainInviteSign)
	if err != nil {
		t.Fatal(err)
	}
	inviteID := uuid.New()
	inviteTok, _, err := invite.Mint(inviteRing, inviteID, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	inviteCode := inviteTok.Reveal()
	for _, m := range marks {
		w := func(s string) string { return string(m) + s[:3] + string(m) + s[3:] + string(m) }
		if got := otp.NormalizeCode(w(smsCode)); got != smsCode {
			t.Errorf("sms code with U+%04X: %q", m, got)
		}
		if err := totp.CheckAt(context.Background(), typedGuard{}, seed, secret.New(w(totpCode)), now); err != nil {
			t.Errorf("totp code with U+%04X: %v", m, err)
		}
		if got, ok := recovery.Canonical(w(recCode)); !ok || got != recCode {
			t.Errorf("recovery code with U+%04X: %q %v", m, got, ok)
		}
		if ref, ok := invite.Open(invitePub, now, string(m)+inviteCode[:5]+string(m)+inviteCode[5:]+string(m)); !ok || ref.ID != inviteID {
			t.Errorf("invite link with U+%04X: %v", m, ok)
		}
		if got := digits.Typed(string(m)); got != "" {
			t.Errorf("Typed(U+%04X) = %q, want nothing", m, got)
		}
	}
}

// TestAVisibleCharacterIsNeverAPasteMark is the other half: the rule must not grow into the
// letters, digits, punctuation and spaces a code is written with.
func TestAVisibleCharacterIsNeverAPasteMark(t *testing.T) {
	for _, r := range "0123456789abcXYZ-_ .,:;+()\u00a0\u3000\u0660\u06f0\uff10\u0627" {
		if digits.PasteMark(r) {
			t.Errorf("U+%04X is visible and is a paste mark", r)
		}
	}
}

// TestPastePatternIsThePasteMarkClass ties the request schemas' patterns to the rule (round 14,
// primitives-r14-3): every code point goes through both patterns, wrapped as "1x1", and the
// pattern must accept it exactly when `text` would, or when the fold drops it. Before the patterns
// existed the schema refused every format character, so the fold was dead code on every route.
func TestPastePatternIsThePasteMarkClass(t *testing.T) {
	plain := regexp.MustCompile(`^[^\p{C}]*$`)
	pasted := regexp.MustCompile(digits.PastePattern)
	content := regexp.MustCompile(digits.PasteContentPattern)
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if r >= 0xd800 && r <= 0xdfff {
			continue
		}
		s := "1" + string(r) + "1"
		want := plain.MatchString(s) || digits.PasteMark(r)
		if got := pasted.MatchString(s); got != want {
			t.Fatalf("PastePattern on U+%04X: %v, want %v", r, got, want)
		}
		// The identifier form differs only in what may come first, so inside a value it agrees.
		if got := content.MatchString(s); got != want {
			t.Fatalf("PasteContentPattern on U+%04X: %v, want %v", r, got, want)
		}
	}
	// A value made of nothing is refused by the identifier form and a leading mark does not hide it.
	for _, s := range []string{"", "   ", "\u200f", "\u200f \u200f", "\t"} {
		if content.MatchString(s) {
			t.Errorf("PasteContentPattern accepts %q", s)
		}
	}
	if !content.MatchString("\u200f123456\u200f") {
		t.Error("PasteContentPattern refuses a code in marks")
	}
	// A leading separator is dropped by the fold, so the schema lets it through (tenant-r18-20): a phone pasted
	// as " 0912..." worked on the pasted pattern, and the content pattern must not turn it into a 400.
	for _, s := range []string{" 09121234567", "\u00a0 09121234567", " \u200f 09121234567 ", "\u3000123456"} {
		if !content.MatchString(s) {
			t.Errorf("PasteContentPattern refuses %q", s)
		}
	}
}

// TestACodeOverTheBoundIsRefusedNotCut: the SMS code used to read the first 64 bytes and ignore
// the rest, the other two refused; all three refuse over MaxTypedBytes now.
func TestACodeOverTheBoundIsRefusedNotCut(t *testing.T) {
	long := "482915" + strings.Repeat(" ", digits.MaxTypedBytes) // spaces: a cut inside a mark leaves a replacement character and hides the difference
	if got := otp.NormalizeCode(long); got == "482915" {
		t.Error("sms: a code with an over-long tail was read")
	}
	if got := otp.NormalizeCode("482915" + strings.Repeat("\u200f", (digits.MaxTypedBytes-6)/3)); got != "482915" {
		t.Errorf("sms: a code at the bound is refused: %q", got)
	}
	seed := secret.NewBytes([]byte("12345678901234567890"))
	now := appclock.Now()
	code := totp.Generate(seed, now)
	if err := totp.CheckAt(context.Background(), typedGuard{}, seed, secret.New(code+strings.Repeat(" ", digits.MaxTypedBytes)), now); err == nil {
		t.Error("totp: an over-long code was read")
	}
	rec, err := recovery.NewSet()
	if err != nil {
		t.Fatal(err)
	}
	rc := strings.ReplaceAll(rec.Codes[0].Reveal(), "-", "")
	if _, ok := recovery.Canonical(rc + strings.Repeat(" ", digits.MaxTypedBytes)); ok {
		t.Error("recovery: an over-long code was read")
	}
}
