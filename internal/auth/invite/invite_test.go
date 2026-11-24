package invite

import (
	"bytes"
	"strings"
	"testing"
)

func TestNewIsTwentyCharactersAndHashesFromCanonicalText(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		code, hash, err := New()
		if err != nil {
			t.Fatal(err)
		}
		shown := code.Reveal()
		if len(shown) != 23 || strings.Count(shown, "-") != 3 {
			t.Fatalf("display form has the wrong shape: %d characters", len(shown))
		}
		canon, ok := Canonical(shown)
		if !ok || len(canon) != codeChars {
			t.Fatal("a fresh code is not canonical")
		}
		got, err := Hash(strings.ToLower(shown))
		if err != nil || !bytes.Equal(got, hash) {
			t.Fatal("the hash of what a person types differs from the stored hash")
		}
		if seen[canon] {
			t.Fatal("two codes collided")
		}
		seen[canon] = true
	}
}

func TestCanonicalReadsLookAlikes(t *testing.T) {
	a, ok1 := Canonical("O1IL0-abcde-ABCDE-12345")
	b, ok2 := Canonical("01110ABCDEABCDE12345")
	if !ok1 || !ok2 || a != b {
		t.Fatalf("look-alikes are not folded: %q %q", a, b)
	}
}

func TestCanonicalRefusesWrongShapes(t *testing.T) {
	for _, s := range []string{"", "short", strings.Repeat("A", 19), strings.Repeat("A", 21), strings.Repeat("U", 20), strings.Repeat("A", 200), "AAAAA-AAAAA-AAAAA-AAAAé"} {
		if _, ok := Canonical(s); ok {
			t.Fatalf("%q was accepted", s)
		}
		if _, err := Hash(s); err != ErrFormat {
			t.Fatalf("Hash(%q) = %v", s, err)
		}
	}
}
