package token_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/token"
)

func TestNewHasTheShapeAndIsDifferentEachTime(t *testing.T) {
	a, err := token.New()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := token.New()
	if !token.Valid(a.Reveal()) || !token.Valid(b.Reveal()) {
		t.Fatal("a fresh token must be valid")
	}
	if a.Equal(b) {
		t.Fatal("two tokens were equal")
	}
	if got := token.Hash(a); len(got) != 32 || bytes.Equal(got, token.Hash(b)) {
		t.Fatal("hash must be 32 bytes and differ per token")
	}
}

func TestValidRefusesJunk(t *testing.T) {
	for _, s := range []string{"", "short", string(make([]byte, 43)), "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA+AA"} {
		if token.Valid(s) {
			t.Errorf("%q must not be valid", s)
		}
	}
	if !token.Valid("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-_A") {
		t.Error("url-safe characters must be valid")
	}
}

// TestOnlyTheCanonicalSpellingIsValid: 43 base64url characters carry 258 bits for 256, and
// a lenient decoder reads four spellings of the last character as one token. Each would
// get a lookup key and a budget of its own (primitives-r5-9), so Valid accepts the one
// New writes and refuses the other three.
func TestOnlyTheCanonicalSpellingIsValid(t *testing.T) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	for i := 0; i < 200; i++ {
		tk, err := token.New()
		if err != nil {
			t.Fatal(err)
		}
		s := tk.Reveal()
		if !token.Valid(s) {
			t.Fatalf("a token New made is not valid: %q", s)
		}
		last := strings.IndexByte(alphabet, s[len(s)-1])
		valid := 0
		for spare := 0; spare < 4; spare++ {
			variant := s[:len(s)-1] + string(alphabet[last&^3|spare])
			if token.Valid(variant) {
				valid++
			}
		}
		if valid != 1 {
			t.Fatalf("%q has %d valid spellings, want 1", s, valid)
		}
	}
}
