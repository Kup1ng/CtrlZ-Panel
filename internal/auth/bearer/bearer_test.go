package bearer

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
)

func signer(t *testing.T, now *time.Time) *Signer {
	t.Helper()
	ring, err := keyring.NewEphemeral(keyring.DomainAuthMAC)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(ring, func() time.Time { return *now })
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func mint(t *testing.T, s *Signer, k Kind, id uuid.UUID, exp time.Time) string {
	t.Helper()
	v, err := s.Mint(k, id, exp)
	if err != nil {
		t.Fatal(err)
	}
	return v.Reveal()
}

func TestAValueScreensWithItsRowIdAndOnlyAsItsOwnKind(t *testing.T) {
	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	s := signer(t, &now)
	id := uuid.New()
	for _, k := range []Kind{APIToken, ShareLink, DownloadLink} {
		v := mint(t, s, k, id, now.Add(time.Hour))
		if len(v) != Len {
			t.Fatalf("length %d, want %d", len(v), Len)
		}
		b, ok := s.Screen(k, v)
		if !ok || b.ID != id || !b.Expires.Equal(now.Add(time.Hour)) {
			t.Fatalf("kind %c: a fresh value does not screen as its own: %+v %v", k, b, ok)
		}
		for _, other := range []Kind{APIToken, ShareLink, DownloadLink} {
			if other != k {
				if _, ok := s.Screen(other, v); ok {
					t.Errorf("a value of kind %c screened as kind %c: the labels do not separate them", k, other)
				}
			}
		}
	}
}

func TestAValueIsRefusedPastItsExpiryAndWhenChanged(t *testing.T) {
	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	s := signer(t, &now)
	id := uuid.New()
	v := mint(t, s, ShareLink, id, now.Add(time.Minute))
	now = now.Add(time.Minute) // the expiry second itself still lives
	if _, ok := s.Screen(ShareLink, v); !ok {
		t.Fatal("a value is refused in its last second")
	}
	now = now.Add(time.Second)
	if _, ok := s.Screen(ShareLink, v); ok {
		t.Fatal("a value past its expiry screens")
	}
	now = now.Add(-time.Minute)
	raw, _ := base64.RawURLEncoding.DecodeString(v)
	for i := 0; i < len(raw); i++ {
		c := append([]byte(nil), raw...)
		c[i] ^= 1
		if _, ok := s.Screen(ShareLink, base64.RawURLEncoding.EncodeToString(c)); ok {
			t.Fatalf("a value with byte %d changed screens", i)
		}
	}
	for _, junk := range []string{"", "x", strings.Repeat("A", Len), strings.Repeat("A", Len+1), v[:Len-1], v + "=", strings.Repeat("-", Len)} {
		if _, ok := s.Screen(ShareLink, junk); ok {
			t.Errorf("junk of length %d screens", len(junk))
		}
	}
}

func TestOnlyTheCanonicalSpellingScreens(t *testing.T) {
	// 64 characters carry 384 bits for 384: there are no spare bits, so Strict decoding has nothing to refuse, and the
	// test holds that to be so: a changed last character is another value, never the same one.
	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	s := signer(t, &now)
	v := mint(t, s, DownloadLink, uuid.New(), now.Add(time.Hour))
	if base64.RawURLEncoding.DecodedLen(Len) != bodyLen+tagLen {
		t.Fatalf("the value has spare bits: %d characters decode to %d bytes", Len, base64.RawURLEncoding.DecodedLen(Len))
	}
	other := []byte(v)
	other[Len-1] = 'A'
	if string(other) != v {
		if _, ok := s.Screen(DownloadLink, string(other)); ok {
			t.Error("two spellings of one value screen")
		}
	}
}

func TestTheIdIsRequiredAndTheHashIsStable(t *testing.T) {
	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	s := signer(t, &now)
	if _, err := s.Mint(ShareLink, uuid.Nil, now); err == nil {
		t.Error("a value with no row id was made")
	}
	if _, err := s.Mint(Kind('x'), uuid.New(), now); err == nil {
		t.Error("a value of an unknown kind was made")
	}
	if len(Hash("abc")) != 32 {
		t.Error("the stored hash is not SHA-256")
	}
	a, err := s.MintWith(ShareLink, uuid.MustParse("0b6c1d1e-6c1f-4a52-9d6c-3f3c0f4f9a11"), make([]byte, 20), now)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := s.MintWith(ShareLink, uuid.MustParse("0b6c1d1e-6c1f-4a52-9d6c-3f3c0f4f9a11"), make([]byte, 20), now)
	if a.Reveal() != b.Reveal() {
		t.Error("the same inputs make two values")
	}
}

func TestARingWithoutAuthMACIsRefused(t *testing.T) {
	ring, err := keyring.NewEphemeral(keyring.DomainUserTOTP)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(ring, nil); err == nil {
		t.Error("a ring with no auth_mac was accepted")
	}
}
