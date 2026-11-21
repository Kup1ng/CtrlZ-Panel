package totp_test

import (
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/totp"
	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
)

// TestSeedAADBindsTenantAndUser is primitives-r3-2. A sealed seed copied to
// another row must not open (spec 6.2, 8.2). The keyring tests prove a different
// AAD fails; this pins the AAD helpers themselves, because the api, the rekey
// tool and admincli all build their context here and a refactor that dropped the
// tenant, or the separator, would keep every seal-and-open round trip green.
func TestSeedAADBindsTenantAndUser(t *testing.T) {
	t1, t2 := uuid.New(), uuid.New()
	u1, u2 := uuid.New(), uuid.New()

	// The exact bytes: the text forms of the ids around one NUL.
	if got, want := string(totp.UserAAD(t1, u1)), t1.String()+"\x00"+u1.String(); got != want {
		t.Fatalf("UserAAD = %q, want %q", got, want)
	}
	if got, want := string(totp.AdminAAD(u1)), u1.String(); got != want {
		t.Fatalf("AdminAAD = %q, want %q", got, want)
	}

	ring, err := keyring.NewEphemeral(keyring.DomainUserTOTP, keyring.DomainAdminTOTP)
	if err != nil {
		t.Fatal(err)
	}
	seed := []byte("0123456789abcdefghij")
	ct, err := ring.Seal(keyring.DomainUserTOTP, totp.UserAAD(t1, u1), seed)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := ring.Open(keyring.DomainUserTOTP, totp.UserAAD(t1, u1), ct); err != nil || string(got.Reveal()) != string(seed) {
		t.Fatalf("own row does not open: %v", err)
	}
	for name, aad := range map[string][]byte{
		"same user id, other tenant": totp.UserAAD(t2, u1),
		"same tenant, other user":    totp.UserAAD(t1, u2),
		"swapped ids":                totp.UserAAD(u1, t1),
		"admin context":              totp.AdminAAD(u1),
		"no separator":               []byte(t1.String() + u1.String()),
	} {
		if _, err := ring.Open(keyring.DomainUserTOTP, aad, ct); err == nil {
			t.Errorf("%s: the seed opened", name)
		}
	}
	// And the other way: an admin seed does not open as a user's.
	act, err := ring.Seal(keyring.DomainAdminTOTP, totp.AdminAAD(u1), seed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ring.Open(keyring.DomainAdminTOTP, totp.AdminAAD(u2), act); err == nil {
		t.Error("an admin seed opened for another admin")
	}
	if _, err := ring.Open(keyring.DomainAdminTOTP, totp.UserAAD(t1, u1), act); err == nil {
		t.Error("an admin seed opened under a user context")
	}
}

// TestASeedSealedUnderAZeroIDIsRefused is primitives-r17-7: a tenant, user or admin id that was never
// read from a row is all zero, the context built from it is the same for every row, and the ring
// refuses it, so a seed is never sealed (or opened) under it. Both AAD functions, every position.
func TestASeedSealedUnderAZeroIDIsRefused(t *testing.T) {
	ring, err := keyring.NewEphemeral(keyring.DomainUserTOTP, keyring.DomainAdminTOTP)
	if err != nil {
		t.Fatal(err)
	}
	a, b := uuid.New(), uuid.New()
	seed := []byte("0123456789abcdefghij")
	for name, c := range map[string]struct {
		domain string
		aad    []byte
	}{
		"user, zero tenant": {keyring.DomainUserTOTP, totp.UserAAD(uuid.Nil, a)},
		"user, zero user":   {keyring.DomainUserTOTP, totp.UserAAD(a, uuid.Nil)},
		"user, both zero":   {keyring.DomainUserTOTP, totp.UserAAD(uuid.Nil, uuid.Nil)},
		"admin, zero admin": {keyring.DomainAdminTOTP, totp.AdminAAD(uuid.Nil)},
	} {
		if _, err := ring.Seal(c.domain, c.aad, seed); !errors.Is(err, keyring.ErrSeal) {
			t.Errorf("%s: Seal = %v, want ErrSeal", name, err)
		}
	}
	if _, err := ring.Seal(keyring.DomainUserTOTP, totp.UserAAD(a, b), seed); err != nil {
		t.Errorf("real ids: %v", err)
	}
}
