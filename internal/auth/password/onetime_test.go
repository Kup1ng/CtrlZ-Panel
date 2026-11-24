package password

import (
	"encoding/base32"
	"fmt"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
)

func TestNewOneTime(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		pw, err := NewOneTime()
		if err != nil {
			t.Fatal(err)
		}
		s := pw.Reveal()
		if len(s) != OneTimeLength {
			t.Fatalf("length %d", len(s))
		}
		// RFC 4648 base32, no padding, and 120 bits that round-trip.
		raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
		if err != nil || len(raw) != 15 {
			t.Fatalf("not base32 of 15 bytes: %v", err)
		}
		if seen[s] {
			t.Fatal("a repeat in 200 draws")
		}
		seen[s] = true
		// A stray %v prints the marker, never the password.
		if out := fmt.Sprintf("%v %+v %s", pw, pw, pw); out == "" || containsAll(out, s) {
			t.Fatalf("formatting reveals the password: %q", out)
		}
	}
	// It meets the admin minimum without the strength check.
	if OneTimeLength < MinLengthAdmin {
		t.Fatal("shorter than the admin minimum")
	}
	if UserOneTimeLife.Hours() != 72 || AdminOneTimeLife.Hours() != 24 {
		t.Fatal("lifetimes of D31 / 10.1")
	}
}

func containsAll(out, s string) bool {
	for i := 0; i+len(s) <= len(out); i++ {
		if out[i:i+len(s)] == s {
			return true
		}
	}
	return false
}

// TestMayBeOneTime is the shape gate the admin login uses to refuse a request of a spent class before
// it reads anything (admin-r8-1, -4). Everything NewOneTime writes must pass it, and what cannot be a
// generated password must not, including text that only becomes one after the NFKC step every verify
// makes, and bodies too large to be worth normalising.
func TestMayBeOneTime(t *testing.T) {
	for i := 0; i < 200; i++ {
		pw, err := NewOneTime()
		if err != nil {
			t.Fatal(err)
		}
		if !MayBeOneTime(pw) {
			t.Fatal("a password NewOneTime wrote is refused by the gate: the owner's first login would be turned away")
		}
	}
	const real = "ONETIMEPASSWORDXYZ234567"
	// Full-width letters normalise to the ASCII ones, so the typed text is the console password.
	fullWidth := ""
	for _, r := range real {
		if r >= 'A' && r <= 'Z' {
			r = r - 'A' + 'Ａ'
		} else {
			r = r - '0' + '０'
		}
		fullWidth += string(r)
	}
	if !MayBeOneTime(secret.New(fullWidth)) {
		t.Error("the full-width spelling of a console password is refused, and Verify would accept it")
	}
	for name, s := range map[string]string{
		"empty":             "",
		"a chosen password": "Granite-lantern-Harbor-4471-quill",
		"23 characters":     real[:23],
		"25 characters":     real + "A",
		"lower case":        "onetimepasswordxyz234567",
		"a digit outside":   "ONETIMEPASSWORDXYZ234561",
		"one letter":        "AAAAAAAAAAAAAAAAAAAAAAAA",
		"a short phrase":    "ABABABABABABABABABABABAB",
		"invalid UTF-8":     "ONETIMEPASSWORDXYZ2345\xff\xfe",
		"a 16 KiB body":     string(make([]byte, 16<<10)),
	} {
		if MayBeOneTime(secret.New(s)) {
			t.Errorf("%s passes the gate", name)
		}
	}
}
