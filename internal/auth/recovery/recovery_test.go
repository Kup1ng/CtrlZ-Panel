package recovery_test

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/recovery"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
)

var shape = regexp.MustCompile(`^[0-9A-HJKMNP-TV-Z]{4}(-[0-9A-HJKMNP-TV-Z]{4}){3}$`)

func TestEncodePinsTheBitPacking(t *testing.T) {
	for name, tc := range map[string]struct {
		in   [10]byte
		want string
	}{
		"zero": {[10]byte{}, "0000-0000-0000-0000"},
		"ones": {[10]byte{255, 255, 255, 255, 255, 255, 255, 255, 255, 255}, "ZZZZ-ZZZZ-ZZZZ-ZZZZ"},
		// Crockford's own digits 0..7 in 5-bit groups are 00 44 32 14 C7.
		"0-7":   {[10]byte{0x00, 0x44, 0x32, 0x14, 0xC7, 0, 0, 0, 0, 0}, "0123-4567-0000-0000"},
		"count": {[10]byte{0x08, 0x86, 0x42, 0x98, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x01}, "1234-5670-0000-0001"},
	} {
		if got := recovery.Encode(tc.in); got != tc.want {
			t.Errorf("%s: %q, want %q", name, got, tc.want)
		}
	}
}

func TestNewSet(t *testing.T) {
	s, err := recovery.NewSet()
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Codes) != recovery.Count || len(s.Hashes) != recovery.Count || recovery.Count != 10 {
		t.Fatalf("%d codes, %d hashes", len(s.Codes), len(s.Hashes))
	}
	seenCode, seenHash := map[string]bool{}, map[string]bool{}
	for i, c := range s.Codes {
		if !shape.MatchString(c.Reveal()) {
			t.Errorf("code %d has the wrong shape: %q", i, c.Reveal())
		}
		if seenCode[c.Reveal()] || seenHash[string(s.Hashes[i])] {
			t.Errorf("code %d repeats", i)
		}
		seenCode[c.Reveal()], seenHash[string(s.Hashes[i])] = true, true
		h, err := recovery.Hash(c)
		if err != nil || !bytes.Equal(h, s.Hashes[i]) {
			t.Errorf("code %d: Hash does not match the stored hash (%v)", i, err)
		}
		if len(s.Hashes[i]) != sha256.Size {
			t.Errorf("hash %d is %d bytes", i, len(s.Hashes[i]))
		}
		if fmt.Sprintf("%v %+v", c, c) == c.Reveal() || strings.Contains(fmt.Sprint(c), c.Reveal()) {
			t.Errorf("code %d prints", i)
		}
	}
}

// TestCodesLookUniform draws many codes and checks every character of the
// alphabet turns up in every position about equally often. A skew would mean the
// packing loses bits.
func TestCodesLookUniform(t *testing.T) {
	const sets = 300
	var counts [16]map[byte]int
	for i := range counts {
		counts[i] = map[byte]int{}
	}
	for range sets {
		s, err := recovery.NewSet()
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range s.Codes {
			canon, _ := recovery.Canonical(c.Reveal())
			for i := range canon {
				counts[i][canon[i]]++
			}
		}
	}
	total := sets * recovery.Count
	for pos, m := range counts {
		if len(m) != 32 {
			t.Errorf("position %d used %d of 32 characters", pos, len(m))
		}
		for ch, n := range m {
			// Expected total/32 = 93.75 per character; 5 sigma is about 48.
			if n < 30 || n > 170 {
				t.Errorf("position %d char %c: %d of %d draws", pos, ch, n, total)
			}
		}
	}
}

func TestCanonicalAndHash(t *testing.T) {
	const code = "0123-4567-89AB-CDEF"
	want, err := recovery.Hash(secret.New(code))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("0123456789ABCDEF"))
	if !bytes.Equal(want, sum[:]) {
		t.Error("Hash is not SHA-256 of the canonical text")
	}
	// Hyphens, spaces and case do not matter; Crockford look-alikes fold.
	for _, in := range []string{"0123456789abcdef", "0123 4567 89ab cdef", "0123-4567-89ab-cdef", "  0123-4567-89AB-CDEF ", "O123-4567-89AB-CDEF", "o123-4567-89AB-CDEF", "0123-4567-89AB-CDEF-", "۰۱۲۳-۴۵۶۷-۸۹AB-CDEF", "٠١٢٣-٤٥٦٧-٨٩ab-cdef", "０１２３４５６７８９ABCDEF"} {
		got, err := recovery.Hash(secret.New(in))
		if err != nil || !bytes.Equal(got, want) {
			t.Errorf("%q: %v", in, err)
		}
	}
	if h1, _ := recovery.Hash(secret.New("I123-4567-89AB-CDEF")); !bytes.Equal(h1, mustHash(t, "1123-4567-89AB-CDEF")) {
		t.Error("I is not read as 1")
	}
	if h1, _ := recovery.Hash(secret.New("L123-4567-89AB-CDEF")); !bytes.Equal(h1, mustHash(t, "1123-4567-89AB-CDEF")) {
		t.Error("L is not read as 1")
	}
	for name, in := range map[string]string{
		"empty":     "",
		"short":     "0123-4567-89AB-CDE",
		"long":      "0123-4567-89AB-CDEF0",
		"U":         "0123-4567-89AB-CDEU",
		"symbol":    "0123-4567-89AB-CDE!",
		"unicode":   "0123-4567-89AB-CDEٴ",
		"huge":      strings.Repeat("A", 100000),
		"other kin": "123456",
	} {
		if h, err := recovery.Hash(secret.New(in)); err != recovery.ErrFormat || h != nil {
			t.Errorf("%s: %x %v", name, h, err)
		}
	}
	// A different code gives a different hash.
	if bytes.Equal(want, mustHash(t, "0123-4567-89AB-CDEE")) {
		t.Error("collision")
	}
	if !recovery.Equal(want, want) || recovery.Equal(want, want[:5]) || recovery.Equal(want, mustHash(t, "0123-4567-89AB-CDEE")) {
		t.Error("Equal")
	}
}

func mustHash(t *testing.T, s string) []byte {
	t.Helper()
	h, err := recovery.Hash(secret.New(s))
	if err != nil {
		t.Fatal(err)
	}
	return h
}
