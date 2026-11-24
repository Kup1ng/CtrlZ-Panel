package sms_test

import (
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms"
)

// TestASealOfTheZeroRowIsRefused is primitives-r17-7 for the two sealed columns of this package that
// take a row id: a row id that was never read (uuid.Nil) makes one context for every row, so the
// ring refuses it and the seal never exists. The other half is that a real id still seals and opens.
func TestASealOfTheZeroRowIsRefused(t *testing.T) {
	ring, err := keyring.NewEphemeral(keyring.DomainSMSCred)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sms.SealOutbox(ring, uuid.Nil, "+989121234567", secret.New("v")); !errors.Is(err, keyring.ErrSeal) {
		t.Errorf("SealOutbox under the zero id = %v, want ErrSeal", err)
	}
	if _, err := sms.SealCredentials(ring, uuid.Nil, "sms_ir", secret.NewBytes([]byte(`{"api_key":"k"}`))); !errors.Is(err, keyring.ErrSeal) {
		t.Errorf("SealCredentials under the zero id = %v, want ErrSeal", err)
	}
	id := uuid.New()
	ct, err := sms.SealCredentials(ring, id, "sms_ir", secret.NewBytes([]byte(`{"api_key":"k"}`)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sms.OpenCredentials(ring, uuid.Nil, "sms_ir", ct); !errors.Is(err, keyring.ErrOpen) {
		t.Errorf("OpenCredentials under the zero id = %v, want ErrOpen", err)
	}
	if got, err := sms.OpenCredentials(ring, id, "sms_ir", ct); err != nil || string(got.Reveal()) != `{"api_key":"k"}` {
		t.Errorf("a real id does not open: %v", err)
	}
}

// TestAnOTPSealOfEmptyPartsOrAnUnusableHashIsRefused is primitives-r17-13 and primitives-r18-2. The
// OTP context has no row id: it is phone, purpose and the code hash the challenge row will hold. The
// zero value of a part is the empty string, and of the hash nothing or zeros; each is refused where the
// context is built (keyring.DigestContext), so neither seals nor opens, and nothing can seal under the
// context of two empty strings any more, since the type has no way to say it.
func TestAnOTPSealOfEmptyPartsOrAnUnusableHashIsRefused(t *testing.T) {
	ring, err := keyring.NewEphemeral(keyring.DomainOTPDelivery)
	if err != nil {
		t.Fatal(err)
	}
	d := sms.OTPDelivery{Template: "otp", Locale: "fa", Code: secret.New("012345")}
	hash := []byte("0123456789abcdef0123456789abcdef")
	type in struct {
		phone, purpose string
		hash           []byte
	}
	unusable := map[string]in{
		"both empty": {"", "", hash}, "empty phone": {"", "login", hash}, "empty purpose": {"+989121234567", "", hash},
		"no hash": {"+989121234567", "login", nil}, "a zero hash": {"+989121234567", "login", make([]byte, 32)},
		"a short hash": {"+989121234567", "login", []byte("abc")},
	}
	for name, c := range unusable {
		if _, err := sms.SealOTP(ring, c.phone, c.purpose, c.hash, d); !errors.Is(err, keyring.ErrSeal) {
			t.Errorf("%s: SealOTP = %v, want ErrSeal", name, err)
		}
	}
	ct, err := sms.SealOTP(ring, "+989121234567", "login", hash, d)
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range unusable {
		if _, err := sms.OpenOTP(ring, c.phone, c.purpose, c.hash, ct); !errors.Is(err, keyring.ErrOpen) {
			t.Errorf("%s: OpenOTP = %v, want ErrOpen", name, err)
		}
	}
}

// TestAnOTPCopiedOntoAnotherChallengeDoesNotOpen is primitives-r18-2 (D64 otp-aad-row). The attack was a
// writer of otp_challenges copying an old delivery_ct onto a fresh row of the same phone and purpose, so
// that the sender delivered the old code while the row held the hash of the new one. The delivery text
// is bound to the hash of its own row, so it opens only against that hash.
func TestAnOTPCopiedOntoAnotherChallengeDoesNotOpen(t *testing.T) {
	ring, err := keyring.NewEphemeral(keyring.DomainOTPDelivery)
	if err != nil {
		t.Fatal(err)
	}
	d := sms.OTPDelivery{Template: "otp", Locale: "fa", Code: secret.New("012345")}
	oldHash, newHash := []byte("old-challenge-hash-0123456789abc"), []byte("new-challenge-hash-0123456789abc")
	ct, err := sms.SealOTP(ring, "+989121234567", "login", oldHash, d)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sms.OpenOTP(ring, "+989121234567", "login", oldHash, ct); err != nil {
		t.Fatalf("the row's own hash does not open it: %v", err)
	}
	if _, err := sms.OpenOTP(ring, "+989121234567", "login", newHash, ct); !errors.Is(err, keyring.ErrOpen) {
		t.Errorf("the copy opened on a fresh challenge of the same phone and purpose: %v", err)
	}
}
