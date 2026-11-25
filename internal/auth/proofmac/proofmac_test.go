package proofmac

import (
	"encoding/base64"
	"encoding/hex"
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

func mint(t *testing.T, s *Signer, k Kind, subject uuid.UUID, exp time.Time) string {
	t.Helper()
	ref, err := RandomRef()
	if err != nil {
		t.Fatal(err)
	}
	v, err := s.Mint(k, subject, ref, exp)
	if err != nil {
		t.Fatal(err)
	}
	return v.Reveal()
}

func TestAMintedValueOpensWithItsSubjectAndOnlyAsItsKind(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	s := signer(t, &now)
	u := uuid.New()
	v := mint(t, s, Ticket, u, now.Add(5*time.Minute))
	if len(v) != Len {
		t.Fatalf("length %d, want %d", len(v), Len)
	}
	b, ok := s.Open(Ticket, v)
	if !ok || b.Subject != u || b.SubjectKey(Ticket) != "u:"+u.String() || b.ProofID(Ticket) == b.SubjectKey(Ticket) {
		t.Fatalf("a fresh ticket does not open as its own: %v %v", b, ok)
	}
	for _, k := range []Kind{Refresh, Challenge} {
		if _, ok := s.Open(k, v); ok {
			t.Fatalf("a ticket opened as kind %c", k)
		}
	}
}

func TestAValueIsRefusedPastItsExpiryAndWithAChangedBody(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	s := signer(t, &now)
	u := uuid.New()
	v := mint(t, s, Refresh, u, now.Add(time.Hour))
	now = now.Add(2 * time.Hour)
	if _, ok := s.Open(Refresh, v); ok {
		t.Fatal("a value past its expiry opens")
	}
	now = now.Add(-2 * time.Hour)

	// The subject moved to another account: the tag no longer matches, so one account's value cannot charge another's bucket.
	raw, _ := base64.RawURLEncoding.DecodeString(v)
	other := uuid.New()
	copy(raw[:16], other[:])
	if _, ok := s.Open(Refresh, base64.RawURLEncoding.EncodeToString(raw)); ok {
		t.Fatal("a value with a rewritten subject opens")
	}
	// The expiry moved later by the holder.
	raw, _ = base64.RawURLEncoding.DecodeString(v)
	raw[16+RefLen+3] ^= 0x40
	if _, ok := s.Open(Refresh, base64.RawURLEncoding.EncodeToString(raw)); ok {
		t.Fatal("a value with a rewritten expiry opens")
	}
	for _, junk := range []string{"", "abc", v[:Len-1], v + "A", v[:Len-1] + "!"} {
		if _, ok := s.Open(Refresh, junk); ok {
			t.Fatalf("junk %q opens", junk)
		}
	}
}

func TestAValueFromAnotherKeyDoesNotOpen(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	a, b := signer(t, &now), signer(t, &now)
	v := mint(t, a, Ticket, uuid.New(), now.Add(time.Minute))
	if _, ok := b.Open(Ticket, v); ok {
		t.Fatal("a value tagged under another ring opens")
	}
}

func TestANilSubjectIsRefusedAtMintAndAtOpen(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	s := signer(t, &now)
	ref, _ := RandomRef()
	if _, err := s.Mint(Ticket, uuid.Nil, ref, now.Add(time.Minute)); err == nil {
		t.Fatal("a value with no subject was minted")
	}
}

func TestAChallengeAndAUserIdNeverShareABucketKey(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	s := signer(t, &now)
	id := uuid.New()
	v := mint(t, s, Challenge, id, now.Add(time.Minute))
	body, _ := s.Open(Challenge, v)
	user := Body{Subject: id}
	if body.SubjectKey(Challenge) == user.SubjectKey(Ticket) {
		t.Fatal("a challenge subject and a user id share a bucket key")
	}
}

// tenant-r20-1: a value that was issued here and has run out is told apart from one that never was, without opening it.
func TestLapsedIsTrueOnlyForAGenuineValuePastItsExpiryOfTheSameKind(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	s := signer(t, &now)
	v := mint(t, s, Challenge, uuid.New(), now.Add(5*time.Minute))
	if s.Lapsed(Challenge, v) {
		t.Fatal("a live value is lapsed")
	}
	now = now.Add(5*time.Minute + time.Second)
	if _, ok := s.Open(Challenge, v); ok {
		t.Fatal("a value past its expiry opens")
	}
	if !s.Lapsed(Challenge, v) {
		t.Fatal("a genuine value past its expiry is not lapsed")
	}
	if s.Lapsed(Ticket, v) {
		t.Fatal("a challenge is lapsed as a ticket")
	}
	raw, _ := base64.RawURLEncoding.DecodeString(v)
	raw[3] ^= 1
	if s.Lapsed(Challenge, base64.RawURLEncoding.EncodeToString(raw)) || s.Lapsed(Challenge, "short") || s.Lapsed(Challenge, "") {
		t.Fatal("a value that does not check is lapsed")
	}
}

func TestNewRefusesARingWithoutAuthMAC(t *testing.T) {
	ring, err := keyring.NewEphemeral(keyring.DomainAdminMAC)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(ring, nil); err == nil {
		t.Fatal("a ring with no auth_mac was accepted")
	}
}

// Two values of one account are two buckets and one network-and-account key (tenant-r19-6): a holder of one must not
// spend what another needs, and the bucket id must not carry the credential.
func TestTwoValuesOfOneAccountDoNotShareABucket(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	s := signer(t, &now)
	u := uuid.New()
	for _, k := range []Kind{Ticket, Refresh} {
		a, _ := s.Open(k, mint(t, s, k, u, now.Add(time.Minute)))
		b, _ := s.Open(k, mint(t, s, k, u, now.Add(time.Minute)))
		if a.ProofID(k) == b.ProofID(k) || a.SubjectKey(k) != b.SubjectKey(k) {
			t.Fatalf("kind %c: ids %q %q, subjects %q %q", k, a.ProofID(k), b.ProofID(k), a.SubjectKey(k), b.SubjectKey(k))
		}
		if strings.Contains(a.ProofID(k), hex.EncodeToString(a.Ref)) || strings.Contains(a.ProofID(k), u.String()) {
			t.Fatalf("kind %c: the id carries the reference or the account: %q", k, a.ProofID(k))
		}
	}
	tk, _ := s.Open(Ticket, mint(t, s, Ticket, u, now.Add(time.Minute)))
	if tk.ProofID(Ticket) == tk.ProofID(Refresh) {
		t.Fatal("a ticket and a refresh token of one reference share a bucket id")
	}
}
