package pwstrength_test

import (
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/password"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/pwstrength"
)

// TestShiftedKeysOnAPersianKeyboardAreReadAsTheirKey is primitives-r24-2. A shifted key whose output is not
// a Persian letter (ISIRI 9147 types "[" on Shift+P and "]" on Shift+O, the legacy layout types "\" and "["
// there, and the four letters of "rial" on Shift+R) was left in the key reading as it was, so a capitalised
// common password typed with the layout left on had a stray symbol or four stray letters in place of the
// capital and passed at both floors, while the Latin text was refused. A text is no easier on a Persian
// layout than it is in Latin.
func TestShiftedKeysOnAPersianKeyboardAreReadAsTheirKey(t *testing.T) {
	c := pwstrength.New()
	in := pwstrength.Input{Phone: "+989121234567", Username: "ali"}

	// The two cases the review measured.
	pinned := []struct {
		latin  string
		layout int
	}{{"Realmadrid", 1}, {"Persepolis1", 0}}
	for _, p := range pinned {
		typed := pwstrength.OnPersianKeyboard(c, p.latin)[p.layout]
		if typed == p.latin || strings.ContainsAny(typed, "RP") {
			t.Fatalf("%s: layout %d typed %q, the test would not reach the shifted key", p.latin, p.layout, typed)
		}
		if r := check(c, typed, in, password.User); r.OK {
			t.Errorf("%s on layout %d (%q), user: accepted %+v, want refused as the Latin text is", p.latin, p.layout, typed, r)
		}
	}

	words := []string{"realmadrid", "persepolis", "password", "iloveyou", "football", "doostdaram", "khodahafez", "tehran", "esteghlal"}
	forms := []func(string) string{
		func(s string) string { return s },
		func(s string) string { return strings.ToUpper(s[:1]) + s[1:] },
		strings.ToUpper,
	}
	tails := []string{"", "1", "123", "1380", "!", "@1380", "#123", "$"}
	for _, w := range words {
		for _, form := range forms {
			for _, tail := range tails {
				latin := form(w) + tail
				for _, kind := range []password.Kind{password.User, password.Admin} {
					want := check(c, latin, in, kind)
					if want.Reason == pwstrength.TooShort {
						continue // the typed text has more characters (a macro is four), so the lengths differ and nothing is compared
					}
					for i, typed := range pwstrength.OnPersianKeyboard(c, latin) {
						got := check(c, typed, in, kind)
						if got.OK && !want.OK {
							t.Errorf("%s on layout %d (%q), kind %v: accepted (%+v), the Latin text is refused (%+v)", latin, i, typed, kind, got, want)
						}
						if got.Score > want.Score {
							t.Errorf("%s on layout %d (%q), kind %v: scores %d, the Latin text %d", latin, i, typed, kind, got.Score, want.Score)
						}
					}
				}
			}
		}
	}
}
