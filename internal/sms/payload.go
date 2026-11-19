package sms

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
)

// What the api and admin seal for the worker, and how the worker opens it. The
// shapes and the AAD of each live here, once, so the three services cannot
// disagree (8.2). Every function returns fixed errors that name no key and no
// plaintext.

// ErrPayload is a sealed value that opened but is not what it should be.
var ErrPayload = errors.New("sms: unreadable payload")

// OTPDelivery is the opened delivery_ct of an otp_challenges row (5.2).
type OTPDelivery struct {
	Template string
	Locale   string
	Code     secret.String // empty for account_exists
}

type otpJSON struct {
	T string `json:"t"`
	C string `json:"c"`
	L string `json:"l"`
}

// otpAAD is phone \0 purpose (5.2). Binding the row's own phone and purpose to
// the ciphertext means a ciphertext copied onto another challenge does not open.
func otpAAD(phone, purpose string) []byte { return []byte(phone + "\x00" + purpose) }

// SealOTP seals the delivery payload under otp_delivery: {"t": template,
// "c": code, "l": locale}. The locale rides in the payload so otp_challenges
// needs no column for it.
func SealOTP(ring *keyring.Ring, phone, purpose string, d OTPDelivery) ([]byte, error) {
	if !ValidTemplate(d.Template) || !ValidLocale(d.Locale) {
		return nil, ErrPayload
	}
	plain, err := json.Marshal(otpJSON{T: d.Template, C: d.Code.Reveal(), L: d.Locale})
	if err != nil {
		return nil, ErrPayload
	}
	defer wipe(plain)
	return ring.Seal(keyring.DomainOTPDelivery, otpAAD(phone, purpose), plain)
}

// OpenOTP opens delivery_ct. A wrong key, a damaged row and a payload of the
// wrong shape all return an error with no detail.
func OpenOTP(ring *keyring.Ring, phone, purpose string, ct []byte) (OTPDelivery, error) {
	plain, err := ring.Open(keyring.DomainOTPDelivery, otpAAD(phone, purpose), ct)
	if err != nil {
		return OTPDelivery{}, err
	}
	defer plain.Wipe()
	var j otpJSON
	if err := strictJSON(plain.Reveal(), &j); err != nil {
		return OTPDelivery{}, ErrPayload
	}
	if !ValidTemplate(j.T) || !ValidLocale(j.L) {
		return OTPDelivery{}, ErrPayload
	}
	return OTPDelivery{Template: j.T, Locale: j.L, Code: secret.New(j.C)}, nil
}

type outboxJSON struct {
	V string `json:"v"`
}

// outboxAAD is id \0 phone (8.2). The id is generated in Go before the insert,
// because the database default is unknown until the row exists.
func outboxAAD(id uuid.UUID, phone string) []byte { return []byte(id.String() + "\x00" + phone) }

// SealOutbox seals the value of an sms_outbox row (an invite code, or the
// number of a test send) under sms_cred. The admin service calls it with the id
// it will insert.
func SealOutbox(ring *keyring.Ring, id uuid.UUID, phone string, value secret.String) ([]byte, error) {
	plain, err := json.Marshal(outboxJSON{V: value.Reveal()})
	if err != nil {
		return nil, ErrPayload
	}
	defer wipe(plain)
	return ring.Seal(keyring.DomainSMSCred, outboxAAD(id, phone), plain)
}

// OpenOutbox opens params_ct.
func OpenOutbox(ring *keyring.Ring, id uuid.UUID, phone string, ct []byte) (secret.String, error) {
	plain, err := ring.Open(keyring.DomainSMSCred, outboxAAD(id, phone), ct)
	if err != nil {
		return secret.String{}, err
	}
	defer plain.Wipe()
	var j outboxJSON
	if err := strictJSON(plain.Reveal(), &j); err != nil {
		return secret.String{}, ErrPayload
	}
	return secret.New(j.V), nil
}

// credentialsAAD is id \0 provider (8.2).
func credentialsAAD(id uuid.UUID, provider string) []byte {
	return []byte(id.String() + "\x00" + provider)
}

// SealCredentials seals a gateway's credentials JSON under sms_cred. plain is
// {"api_key": ...} for sms_ir and {"username": ..., "password": ...} for
// melipayamak; the drivers' ParseCredentials check the shape.
func SealCredentials(ring *keyring.Ring, id uuid.UUID, provider string, plain secret.Bytes) ([]byte, error) {
	return ring.Seal(keyring.DomainSMSCred, credentialsAAD(id, provider), plain.Reveal())
}

// OpenCredentials opens credentials_ct. The caller wipes the result.
func OpenCredentials(ring *keyring.Ring, id uuid.UUID, provider string, ct []byte) (secret.Bytes, error) {
	return ring.Open(keyring.DomainSMSCred, credentialsAAD(id, provider), ct)
}

// strictJSON decodes one JSON object and refuses unknown fields and trailing
// data, so a payload from a future format fails closed.
func strictJSON(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return ErrPayload
	}
	return nil
}

// wipe zeroes a plaintext buffer the caller built.
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// keyHintMinLength is the shortest secret that may show a hint at all. The hint is the last four
// characters, so a key of four or fewer would show itself whole and a key of eight would give half
// of it away (round 5, admin-r5-5). At sixteen the hint is a quarter of the key; a real sms.ir key
// is several times that, and a shorter value is a test value or a wrong paste that the page
// should not echo.
const keyHintMinLength = 16

// KeyHint is Hint for a value that is a secret (the sms.ir API key): the last four characters,
// and only when the key is at least keyHintMinLength long. Shorter keys show no hint. The
// Melipayamak username is an identifier and not a secret, so it keeps Hint.
func KeyHint(s string) string {
	s = strings.TrimSpace(s)
	if len([]rune(s)) < keyHintMinLength {
		return ""
	}
	return Hint(s)
}

// Hint is the plain-text suffix shown beside a gateway on the SMS page: the last
// four characters of the sms.ir API key or of the Melipayamak username, never
// derived from a password (15.2).
func Hint(s string) string {
	s = strings.TrimSpace(s)
	r := []rune(s)
	if len(r) > 4 {
		r = r[len(r)-4:]
	}
	return string(r)
}
