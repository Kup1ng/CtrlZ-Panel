package ticket_test

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/ticket"
	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// The sealed ceremony ticket of rule proof-before-work: a passkey login begin that writes
// no row. Everything here is in memory; the single-use half is TicketSpend, raced in
// internal/store.

func sealedService(t *testing.T, now *time.Time) *ticket.Service {
	t.Helper()
	ring, err := keyring.NewEphemeral(keyring.DomainAuthMAC)
	if err != nil {
		t.Fatal(err)
	}
	return ticket.New(store.AuthLookups{}).WithSealing(ring, func() time.Time { return *now })
}

func TestCeremonyRoundTrip(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	s := sealedService(t, &now)
	tok, err := s.SealCeremony([]byte(`{"challenge":"abc"}`), true, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	c, ok := s.OpenCeremony(tok.Reveal())
	if !ok || !c.Remember || string(c.Session) != `{"challenge":"abc"}` || c.Left != 5*time.Minute || len(c.Spend) != 32 {
		t.Fatalf("opened = %+v ok %v", c, ok)
	}
	// Two tickets carry different nonces, so each is spent on its own.
	tok2, _ := s.SealCeremony([]byte(`{"challenge":"abc"}`), true, 5*time.Minute)
	c2, _ := s.OpenCeremony(tok2.Reveal())
	if string(c.Spend) == string(c2.Spend) {
		t.Fatal("two tickets share a nonce")
	}
	// The same ticket always spends the same value, whichever process opens it.
	again, _ := s.OpenCeremony(tok.Reveal())
	if string(c.Spend) != string(again.Spend) {
		t.Fatal("a ticket opened twice gave two spend values")
	}
}

func TestCeremonyRefusesWhatNoApiMade(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	s := sealedService(t, &now)
	tok, _ := s.SealCeremony([]byte(`{"challenge":"abc"}`), false, time.Minute)
	raw, _ := base64.RawURLEncoding.DecodeString(tok.Reveal())
	flip := func(i int) string {
		b := append([]byte(nil), raw...)
		b[i] ^= 1
		return base64.RawURLEncoding.EncodeToString(b)
	}
	cases := map[string]string{
		"empty":                "",
		"junk":                 "not-a-ticket",
		"a token-shaped value": strings.Repeat("A", 43),
		"a long value":         strings.Repeat("a", 700),
		"too long":             strings.Repeat("a", 9000),
		"expiry changed":       flip(3),
		"remember changed":     flip(9),
		"nonce changed":        flip(12),
		"session changed":      flip(30),
		"tag changed":          flip(len(raw) - 1),
		"truncated":            base64.RawURLEncoding.EncodeToString(raw[:len(raw)-1]),
		"padded":               base64.RawURLEncoding.EncodeToString(append(append([]byte(nil), raw...), 0)),
	}
	for name, v := range cases {
		if _, ok := s.OpenCeremony(v); ok {
			t.Errorf("%s was accepted", name)
		}
	}
	// A ticket from another ring (another deployment, a rotated-out key) is refused too.
	other := sealedService(t, &now)
	if _, ok := other.OpenCeremony(tok.Reveal()); ok {
		t.Error("a ticket sealed under another key was accepted")
	}
}

func TestCeremonyExpires(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	s := sealedService(t, &now)
	tok, _ := s.SealCeremony([]byte(`{"challenge":"abc"}`), false, time.Minute)
	now = now.Add(time.Minute - time.Second)
	if _, ok := s.OpenCeremony(tok.Reveal()); !ok {
		t.Fatal("refused before its expiry")
	}
	now = now.Add(time.Second)
	if _, ok := s.OpenCeremony(tok.Reveal()); ok {
		t.Fatal("accepted at its expiry")
	}
}

func TestCeremonyRefusesToSealNothingOrTooMuch(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	s := sealedService(t, &now)
	if _, err := s.SealCeremony(nil, false, time.Minute); err == nil {
		t.Error("sealed empty session data")
	}
	if _, err := s.SealCeremony(make([]byte, 5000), false, time.Minute); err == nil {
		t.Error("sealed 5000 bytes of session data")
	}
	if _, err := ticket.New(store.AuthLookups{}).SealCeremony([]byte("x"), false, time.Minute); err == nil {
		t.Error("a service with no ring sealed a ticket")
	}
	if _, ok := ticket.New(store.AuthLookups{}).OpenCeremony("AAAA"); ok {
		t.Error("a service with no ring opened a ticket")
	}
}

// TestCeremonyHasOneSpelling: base64 has spare bits in its last character when the byte
// count is not a multiple of three, and a lenient decoder gives every value of those bits
// the same bytes, so one ticket would be a handful of different strings (round 5: the
// passkey flow test flipped the last character and was now and then let in, one run in
// about a dozen). The session cookie decoder is strict for the same reason. Every other
// letter in the last place must be refused, for each of the three residues of the length.
func TestCeremonyHasOneSpelling(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	s := sealedService(t, &now)
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	residues := map[int]bool{}
	for _, n := range []int{20, 21, 22} {
		tok, err := s.SealCeremony([]byte(strings.Repeat("s", n)), false, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		text := tok.Reveal()
		residues[len(text)%4] = true
		for _, c := range alphabet {
			if byte(c) == text[len(text)-1] {
				continue
			}
			if _, ok := s.OpenCeremony(text[:len(text)-1] + string(c)); ok {
				t.Fatalf("a ticket of %d characters was accepted with last character %q: it has more than one spelling", len(text), c)
			}
		}
	}
	if len(residues) < 3 {
		t.Fatalf("the sizes covered only the residues %v: the test does not reach every number of spare bits", residues)
	}
}
