package hubtoken

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	tok, hash, err := New(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(tok) != 43 || strings.ContainsAny(tok, "=+/ ") {
		t.Fatalf("token form: %q", tok)
	}
	got, ok := Parse(tok)
	if !ok || !bytes.Equal(got, hash) {
		t.Fatal("Parse does not give the stored hash")
	}
	// The hash is of the raw bytes, so the hex spelling of the same bytes finds the same row.
	raw, _ := base64.RawURLEncoding.DecodeString(tok)
	if got, ok := Parse(hex.EncodeToString(raw)); !ok || !bytes.Equal(got, hash) {
		t.Fatal("the hex spelling does not give the same hash")
	}
	want := sha256.Sum256(raw)
	if !bytes.Equal(hash, want[:]) {
		t.Fatal("hash is not the SHA-256 of the raw token")
	}
	t2, _, _ := New(nil)
	if t2 == tok {
		t.Fatal("two tokens are equal")
	}
}

func TestParseRefuses(t *testing.T) {
	tok, _, _ := New(nil)
	for _, bad := range []string{"", tok[:42], tok + "A", tok + "=", " " + tok[1:], tok[:42] + "+", tok[:42] + "/", strings.Repeat("0", 63) + "g", strings.Repeat("a", 300)} {
		if _, ok := Parse(bad); ok {
			t.Errorf("%q accepted", bad)
		}
	}
	// 32 bytes fill 42 characters and 4 bits of the 43rd; its other two bits must be zero, or one token
	// would have several spellings. 'B' has a low bit set.
	if _, ok := Parse(tok[:42] + "B"); ok {
		t.Error("a non-canonical final character was accepted")
	}
}
