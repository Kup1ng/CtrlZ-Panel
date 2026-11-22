package keyring

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func allRing(t *testing.T) *Ring {
	t.Helper()
	numbers := map[string][]uint16{}
	for _, d := range Domains() {
		numbers[d] = []uint16{1}
	}
	return mustRing(t, numbers)
}

// sealOpen drives one seal and one open of a context through the form that suits the domain (a sealed
// domain takes Seal, a labeled one SealLabeled), so a test of the context runs on every domain. When the
// seal is refused the open is tried on a ciphertext made under a real context.
func sealOpen(r *Ring, d string, seal, open Context) (sealErr, openErr error) {
	m, _ := ModeOf(d)
	label := LabelDevice
	if d == DomainAdminMAC {
		label = LabelAdminDevice
	}
	var ct []byte
	if m == ModeSealed {
		ct, sealErr = r.Seal(d, seal, []byte("x"))
		if sealErr != nil {
			ct, _ = r.Seal(d, tc("fallback"), []byte("x"))
		}
		_, openErr = r.Open(d, open, ct)
		return
	}
	ct, sealErr = r.SealLabeled(d, label, seal, []byte("x"))
	if sealErr != nil {
		ct, _ = r.SealLabeled(d, label, tc("fallback"), []byte("x"))
	}
	_, openErr = r.OpenLabeled(d, label, open, ct)
	return
}

// TestAnEmptyContextBindsNothingAndIsRefused is primitives-r12-3, now by construction (primitives-r18-13).
// The zero Context is what a variable nobody filled is and what every refused construction returns;
// Seal and Open refuse it on every domain, in the plain and the labeled form, and the same ciphertext
// opens under its own context, so the refusal is the context's and not the domain's.
func TestAnEmptyContextBindsNothingAndIsRefused(t *testing.T) {
	r := allRing(t)
	for _, d := range Domains() {
		sealErr, _ := sealOpen(r, d, Context{}, tc("row"))
		if !errors.Is(sealErr, ErrSeal) {
			t.Errorf("%s: sealing under the zero Context = %v, want ErrSeal", d, sealErr)
		}
		own, openErr := sealOpen(r, d, tc("row"), Context{})
		if own != nil {
			t.Errorf("%s: sealing under a real context: %v", d, own)
		}
		if !errors.Is(openErr, ErrOpen) {
			t.Errorf("%s: opening under the zero Context = %v, want ErrOpen", d, openErr)
		}
		if _, openErr := sealOpen(r, d, tc("row"), tc("row")); openErr != nil {
			t.Errorf("%s: the ciphertext does not open under its own context: %v", d, openErr)
		}
	}
}

// TestAContextOfTheZeroRowBindsNothingAndIsRefused is primitives-r17-7 and primitives-r18-13. A row id
// that was never read from a row is all zero, and a context built from it is the same for every row of
// the tenant. Rounds 12 to 17 searched the bytes of a context for the spellings of that id (the text,
// the raw bytes, a run of NULs) and a hex spelling still passed. The constructors refuse it where it is
// made: the id as an id, in any position, and as text in any part, in any spelling or grouping, and
// every part that carries nothing. Each is refused on every domain, in both forms.
func TestAContextOfTheZeroRowBindsNothingAndIsRefused(t *testing.T) {
	r := allRing(t)
	real := uuid.New()
	zero := uuid.Nil
	digest := []byte("0123456789abcdef")
	bad := map[string]Context{
		"the zero id alone":                  RowContext([]uuid.UUID{zero}),
		"the zero id after a real one":       RowContext([]uuid.UUID{real, zero}),
		"the zero id before a real one":      RowContext([]uuid.UUID{zero, real}),
		"the zero id of a struct field read": RowContext([]uuid.UUID{{}}, "x"),
		"the zero id beside a part":          RowContext([]uuid.UUID{zero}, "login"),
		"no id at all":                       RowContext(nil, "login"),
		"an empty list of ids":               RowContext([]uuid.UUID{}, "login"),
		"the text of the zero id as a part":  RowContext([]uuid.UUID{real}, zero.String()),
		"the hex of the zero id as a part":   RowContext([]uuid.UUID{real}, strings.Repeat("0", 32)),
		"the zero id in other grouping":      RowContext([]uuid.UUID{real}, "0000-0000-0000-0000"),
		"a part of hyphens":                  RowContext([]uuid.UUID{real}, "---"),
		"an empty part":                      RowContext([]uuid.UUID{real}, ""),
		"an empty part after a real one":     RowContext([]uuid.UUID{real}, "phone", ""),
		"a part that holds the separator":    RowContext([]uuid.UUID{real}, "a\x00b"),
		"a part of one NUL":                  RowContext([]uuid.UUID{real}, "\x00"),
		"a context past the bound":           RowContext([]uuid.UUID{real}, strings.Repeat("a", maxContext)),
		"a digest of zeros":                  DigestContext(make([]byte, 32), "phone", "login"),
		"a digest that is too short":         DigestContext([]byte{1, 2, 3}, "phone", "login"),
		"no digest":                          DigestContext(nil, "phone", "login"),
		"a digest with an empty phone":       DigestContext(digest, "", "login"),
		"a digest with an empty purpose":     DigestContext(digest, "+98912", ""),
		"a digest with no part at all":       DigestContext(digest),
		"a digest with a zero-spelled part":  DigestContext(digest, strings.Repeat("0", 32), "login"),
		"the zero Context itself":            {},
	}
	for name, ctx := range bad {
		if !ctx.zero() {
			t.Errorf("%s: the constructor returned a context that binds something: %q", name, ctx.Bytes())
		}
		for _, d := range Domains() {
			if sealErr, _ := sealOpen(r, d, ctx, tc("row")); !errors.Is(sealErr, ErrSeal) {
				t.Errorf("%s: %s: Seal = %v, want ErrSeal", name, d, sealErr)
			}
			if _, openErr := sealOpen(r, d, tc("row"), ctx); !errors.Is(openErr, ErrOpen) {
				t.Errorf("%s: %s: Open = %v, want ErrOpen", name, d, openErr)
			}
		}
	}
	good := map[string]Context{
		"two ids":             RowContext([]uuid.UUID{real, uuid.New()}),
		"an id and a part":    RowContext([]uuid.UUID{real}, "+989121234567"),
		"an id and two parts": RowContext([]uuid.UUID{real}, "melipayamak", "v3"),
		"a digest":            DigestContext(digest, "+989121234567", "login"),
	}
	for name, ctx := range good {
		if ctx.zero() {
			t.Errorf("%s: a real context was refused by its constructor", name)
			continue
		}
		for _, d := range Domains() {
			if sealErr, openErr := sealOpen(r, d, ctx, ctx); sealErr != nil || openErr != nil {
				t.Errorf("%s: %s: seal %v, open %v", name, d, sealErr, openErr)
			}
		}
	}
}

// TestContextEncodingIsFrozen is the golden test of the bytes: the ciphertexts already in a database were
// sealed under them, so the construction must not change a byte (rule one-primitive-per-key, round 18).
// The ids and parts are literals, so the expected text is written out and not built by the code it checks.
func TestContextEncodingIsFrozen(t *testing.T) {
	tenant := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	user := uuid.MustParse("22222222-2222-4222-8222-222222222222")
	cases := []struct {
		name string
		got  Context
		want string
	}{
		{"a tenant and a user (totp.UserAAD)", RowContext([]uuid.UUID{tenant, user}), "11111111-1111-4111-8111-111111111111\x0022222222-2222-4222-8222-222222222222"},
		{"an admin (totp.AdminAAD)", RowContext([]uuid.UUID{user}), "22222222-2222-4222-8222-222222222222"},
		{"an outbox row and a phone (sms outboxAAD)", RowContext([]uuid.UUID{tenant}, "+989121234567"), "11111111-1111-4111-8111-111111111111\x00+989121234567"},
		{"a gateway and a provider (sms credentialsAAD)", RowContext([]uuid.UUID{tenant}, "melipayamak"), "11111111-1111-4111-8111-111111111111\x00melipayamak"},
		{"a marker (subject, then the kind's tag)", RowContext([]uuid.UUID{user}, "ctrlz-device-v3"), "22222222-2222-4222-8222-222222222222\x00ctrlz-device-v3"},
		{"an OTP delivery (phone, purpose, hex of the code hash)", DigestContext([]byte{0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}, "+989121234567", "login"), "+989121234567\x00login\x00deadbeef0102030405060708090a0b0c"},
	}
	for _, c := range cases {
		if string(c.got.Bytes()) != c.want {
			t.Errorf("%s: %q, want %q", c.name, c.got.Bytes(), c.want)
		}
	}
}

// TestContextHasNoWayToBeBuiltOutsideTheConstructors holds the construction: the type has one field and
// it is unexported, so a package other than this one can make the zero Context and what the two
// constructors return, and nothing else.
func TestContextHasNoWayToBeBuiltOutsideTheConstructors(t *testing.T) {
	typ := reflect.TypeOf(Context{})
	if typ.NumField() != 1 || typ.Field(0).IsExported() {
		t.Fatalf("Context has %d fields and the first is exported=%v: a field a caller can set is a context the constructors did not check", typ.NumField(), typ.Field(0).IsExported())
	}
}

// TestOpenRefusesTheZeroContextForACiphertextMadeUnderIt is primitives-r18-25. Seal refuses the zero
// Context, so no ciphertext of this build is made under it, but a stored one from an earlier build, or
// one made with the key by other code, can be: its AAD ends where the domain ends. Open must refuse the
// zero Context itself, because the AEAD check alone would accept that ciphertext for every row.
func TestOpenRefusesTheZeroContextForACiphertextMadeUnderIt(t *testing.T) {
	r := allRing(t)
	for _, d := range Domains() {
		m, _ := ModeOf(d)
		label := ""
		if m != ModeSealed {
			label = LabelDevice
			if d == DomainAdminMAC {
				label = LabelAdminDevice
			}
		}
		dk := r.domains[d]
		raw, err := rawKey(dk.newest.k, label)
		if err != nil {
			t.Fatalf("%s: %v", d, err)
		}
		gcm, err := newGCM(raw)
		if err != nil {
			t.Fatalf("%s: %v", d, err)
		}
		// The framing of seal, written out, with the AAD of the zero Context: the code under test is Open.
		ct := make([]byte, headerLen+nonceLen)
		ct[0], ct[1], ct[2] = magic0, magic1, formatVersion
		ct[3], ct[4] = byte(dk.newest.n>>8), byte(dk.newest.n)
		ct = gcm.Seal(ct, ct[headerLen:headerLen+nonceLen], []byte("x"), aadFor(d, label, Context{}))
		var openErr error
		if m == ModeSealed {
			_, openErr = r.Open(d, Context{}, ct)
		} else {
			_, openErr = r.OpenLabeled(d, label, Context{}, ct)
		}
		if !errors.Is(openErr, ErrOpen) {
			t.Errorf("%s: a ciphertext made under the zero Context opened (%v)", d, openErr)
		}
	}
}
