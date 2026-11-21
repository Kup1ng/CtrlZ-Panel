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

// TestAnOTPOpenOfAOneSidedEmptyContextIsRefused seals through the ring directly, as a writer that
// bypassed SealOTP would, under the context of an empty phone and a real purpose, and asserts
// OpenOTP does not open it (the ring floor does not see this context as empty).
func TestAnOTPOpenOfAOneSidedEmptyContextIsRefused(t *testing.T) {
	ring, err := keyring.NewEphemeral(keyring.DomainOTPDelivery)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := ring.Seal(keyring.DomainOTPDelivery, []byte("\x00login"), []byte(`{"t":"otp","c":"1","l":"fa"}`))
	if err != nil {
		t.Fatalf("the ring refused a one-sided context (the ring is not what judges it): %v", err)
	}
	if _, err := sms.OpenOTP(ring, "", "login", ct); !errors.Is(err, keyring.ErrOpen) {
		t.Errorf("OpenOTP of an empty phone = %v, want ErrOpen", err)
	}
}

// TestAnOTPSealOfEmptyStringsIsRefused is primitives-r17-13: otpAAD has no row id, only phone and
// purpose, so the zero value of its parts is the empty string. Both empty is one NUL byte (the ring's
// floor refuses it); one empty is refused where the parts are still apart. Neither seals or opens.
func TestAnOTPSealOfEmptyStringsIsRefused(t *testing.T) {
	ring, err := keyring.NewEphemeral(keyring.DomainOTPDelivery)
	if err != nil {
		t.Fatal(err)
	}
	d := sms.OTPDelivery{Template: "otp", Locale: "fa", Code: secret.New("012345")}
	empties := map[string][2]string{
		"both empty": {"", ""}, "empty phone": {"", "login"}, "empty purpose": {"+989121234567", ""},
	}
	for name, c := range empties {
		if _, err := sms.SealOTP(ring, c[0], c[1], d); !errors.Is(err, keyring.ErrSeal) {
			t.Errorf("%s: SealOTP = %v, want ErrSeal", name, err)
		}
	}
	ct, err := sms.SealOTP(ring, "+989121234567", "login", d)
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range empties {
		if _, err := sms.OpenOTP(ring, c[0], c[1], ct); !errors.Is(err, keyring.ErrOpen) {
			t.Errorf("%s: OpenOTP = %v, want ErrOpen", name, err)
		}
	}
	// A writer that bypasses SealOTP and seals under the context of two empty strings (one NUL byte)
	// is refused by the ring itself, so the sms package is not the only guard.
	if _, err := ring.Seal(keyring.DomainOTPDelivery, []byte("\x00"), []byte("x")); !errors.Is(err, keyring.ErrSeal) {
		t.Errorf("the ring sealed under the context of two empty strings: %v", err)
	}
}
