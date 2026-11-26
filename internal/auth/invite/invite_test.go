package invite

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
)

var now = time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)

func rings(t *testing.T) (*keyring.Ring, *keyring.PublicRing) {
	t.Helper()
	r, err := keyring.NewEphemeral(keyring.DomainInviteSign)
	if err != nil {
		t.Fatal(err)
	}
	p, err := r.Public(keyring.DomainInviteSign)
	if err != nil {
		t.Fatal(err)
	}
	return r, p
}

// mint makes a token at run time: no token literal is ever written in a test (the publisher scans for secrets).
func mint(t *testing.T, r *keyring.Ring, id uuid.UUID, exp time.Time) (string, []byte) {
	t.Helper()
	tok, hash, err := Mint(r, id, exp)
	if err != nil {
		t.Fatal(err)
	}
	return tok.Reveal(), hash
}

func TestALinkOpensWithItsIdAndExpiry(t *testing.T) {
	r, p := rings(t)
	id := uuid.Must(uuid.NewV7())
	exp := now.Add(72 * time.Hour)
	text, hash := mint(t, r, id, exp)
	if len(text) != TokenChars {
		t.Fatalf("a token is %d characters, want %d", len(text), TokenChars)
	}
	ref, ok := Open(p, now, text)
	if !ok || ref.ID != id || !ref.Expires.Equal(exp) || !bytes.Equal(ref.Hash, hash) {
		t.Fatalf("Open = %+v, %v", ref, ok)
	}
	// The same link pasted the way a chat or a right-to-left message hands it over.
	for name, pasted := range map[string]string{
		"spaces":         text[:20] + " " + text[20:] + "  ",
		"newline":        "\n" + text + "\n",
		"direction mark": "‏" + text + "‎",
		"zero width":     text[:70] + "​" + text[70:],
	} {
		got, ok := Open(p, now, pasted)
		if !ok || got.ID != id || !bytes.Equal(got.Hash, hash) {
			t.Errorf("%s: a pasted link did not open (%v)", name, ok)
		}
	}
	// Two links for one invite are two tokens, with two hashes.
	other, otherHash := mint(t, r, id, exp)
	if other == text || bytes.Equal(hash, otherHash) {
		t.Error("two links of one invite are the same")
	}
	if _, _, err := Mint(r, uuid.Nil, exp); err == nil {
		t.Error("a link was made for the nil id")
	}
	if _, _, err := Mint(r, id, time.Unix(0, 0)); err == nil {
		t.Error("a link was made with no expiry")
	}
}

func TestALinkWithAnyByteChangedDoesNotOpen(t *testing.T) {
	r, p := rings(t)
	id := uuid.Must(uuid.NewV7())
	text, _ := mint(t, r, id, now.Add(time.Hour))
	raw, err := base64.RawURLEncoding.DecodeString(text)
	if err != nil {
		t.Fatal(err)
	}
	// Every byte, every bit of it: version, number, id, expiry, random, signature.
	for i := range raw {
		for bit := 0; bit < 8; bit++ {
			bad := append([]byte(nil), raw...)
			bad[i] ^= 1 << bit
			if _, ok := Open(p, now, base64.RawURLEncoding.EncodeToString(bad)); ok {
				t.Fatalf("byte %d bit %d changed and the link still opens", i, bit)
			}
		}
	}
	// Another key of another process.
	r2, _ := rings(t)
	foreign, _ := mint(t, r2, id, now.Add(time.Hour))
	if _, ok := Open(p, now, foreign); ok {
		t.Error("a link of another key opened")
	}
	// The same signature under another key number.
	renumbered := append([]byte(nil), raw...)
	renumbered[2] = 9
	if _, ok := Open(p, now, base64.RawURLEncoding.EncodeToString(renumbered)); ok {
		t.Error("a link with another key number opened")
	}
	// A moved id: another invite's id under this signature.
	moved := append([]byte(nil), raw...)
	other := uuid.Must(uuid.NewV7())
	copy(moved[3:19], other[:])
	if _, ok := Open(p, now, base64.RawURLEncoding.EncodeToString(moved)); ok {
		t.Error("a link with a moved id opened")
	}
	// Spellings that decode to the same bytes: padding, the standard alphabet's last two characters, a changed
	// spare bit (there is none at 140 characters, so any other character changes the bytes), lower case.
	for name, s := range map[string]string{
		"padding":   text + "=",
		"short":     text[:TokenChars-1],
		"long":      text + "A",
		"empty":     "",
		"lower":     strings.ToLower(text),
		"upper":     strings.ToUpper(text),
		"std plus":  strings.ReplaceAll(text, "-", "+"),
		"std slash": strings.ReplaceAll(text, "_", "/"),
		"too much":  strings.Repeat(text, 6),
		"non-ascii": text[:139] + "é",
	} {
		if s == text {
			continue // a token with no such character: the case of the test, not of the code
		}
		if _, ok := Open(p, now, s); ok {
			t.Errorf("%s: a different spelling opened", name)
		}
	}
	// A token for a nil id is refused even when the signer signed it.
	var zero [rawLen]byte
	if _, ok := Open(p, now, base64.RawURLEncoding.EncodeToString(zero[:])); ok {
		t.Error("an all-zero token opened")
	}
}

func TestALinkPastItsExpiryDoesNotOpen(t *testing.T) {
	r, p := rings(t)
	exp := now.Add(time.Hour)
	text, _ := mint(t, r, uuid.Must(uuid.NewV7()), exp)
	for d, want := range map[time.Duration]bool{
		-time.Hour: true, -time.Second: true, -2 * time.Second: true, 0: false, time.Second: false, 24 * time.Hour: false,
	} {
		_, ok := Open(p, exp.Add(d), text)
		if ok != want {
			t.Errorf("at expiry%+v: opens = %v, want %v", d, ok, want)
		}
	}
}

// The raw bound (800 bytes) applies before the fold, as it does for every typed code.
func TestOpenBoundsTheRawInput(t *testing.T) {
	r, p := rings(t)
	text, _ := mint(t, r, uuid.Must(uuid.NewV7()), now.Add(time.Hour))
	// Marks that the fold drops, in a text over the 800 byte bound: refused whole, not cut.
	if _, ok := Open(p, now, text+strings.Repeat("​", 300)); ok {
		t.Error("a text past the byte bound was read")
	}
	if _, ok := Open(p, now, text+strings.Repeat(" ", 60)); !ok {
		t.Error("a text inside the bound with spaces did not open")
	}
}
