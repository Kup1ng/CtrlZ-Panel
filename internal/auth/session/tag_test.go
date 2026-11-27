package session

import (
	"encoding/base64"
	"encoding/binary"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
)

// These tests are in the package because they need newSessionToken, and they need no
// database: Screen is a decision made with no I/O, which is the point of it.

func tagManager(t *testing.T, now *time.Time) *Manager {
	t.Helper()
	ring, err := keyring.NewEphemeral(keyring.DomainAuthMAC)
	if err != nil {
		t.Fatal(err)
	}
	m := NewManager(nil, DefaultPolicy(), func() time.Time { return *now })
	if err := m.WithKeys(ring, keyring.DomainAuthMAC); err != nil {
		t.Fatal(err)
	}
	return m
}

// TestScreenRefusesACookiePastItsAbsoluteExpiryWithNoIO (primitives-r5-9): a cookie kept
// after its session ran out of age stops being plausible, so it costs no lookup and no
// budget, at the second the session ends and not at the end of the key line's life.
func TestScreenRefusesACookiePastItsAbsoluteExpiryWithNoIO(t *testing.T) {
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	m := tagManager(t, &now)
	abs := now.Add(24 * time.Hour)
	tok, err := m.newSessionToken(audienceTenant, abs, uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, ok := m.Screen(tok.Reveal()); !ok {
		t.Fatal("a fresh cookie is not plausible")
	}
	now = abs.Add(-time.Second)
	if _, _, ok := m.Screen(tok.Reveal()); !ok {
		t.Fatal("a cookie one second before its expiry is refused")
	}
	now = abs.Add(2 * time.Second)
	if _, _, ok := m.Screen(tok.Reveal()); ok {
		t.Fatal("a cookie past its absolute expiry is still plausible")
	}
}

// TestTheExpiryIsUnderTheTag: a cookie whose expiry bytes were moved later by the holder
// fails the tag, so the expiry cannot be lengthened to keep a dead cookie plausible.
func TestTheExpiryIsUnderTheTag(t *testing.T) {
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	m := tagManager(t, &now)
	tok, _ := m.newSessionToken(audienceTenant, now.Add(time.Hour), uuid.New())
	raw, err := base64.RawURLEncoding.DecodeString(tok.Reveal())
	if err != nil {
		t.Fatal(err)
	}
	raw[tokenSessionLen+tokenRandLen+3] ^= 0x40 // some seconds-or-minutes later
	if _, _, ok := m.Screen(base64.RawURLEncoding.EncodeToString(raw)); ok {
		t.Fatal("an expiry the holder changed passes the tag")
	}
}

// TestACookieHasOneSpelling: a tagged cookie is 48 bytes, which is 64 characters with no spare bit, so
// no second spelling decodes to the same bytes; any change of one character, or a different length, is
// not plausible, and a cookie has one lookup key and one budget.
func TestACookieHasOneSpelling(t *testing.T) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	m := tagManager(t, &now)
	tok, _ := m.newSessionToken(audienceTenant, now.Add(time.Hour), uuid.New())
	s := tok.Reveal()
	if len(s) != CookieLen {
		t.Fatalf("a tagged cookie is %d characters, want %d", len(s), CookieLen)
	}
	if _, _, ok := m.Screen(s); !ok {
		t.Fatal("the cookie as issued is not plausible")
	}
	for i := range s {
		for j := range alphabet {
			if alphabet[j] == s[i] {
				continue
			}
			if _, _, ok := m.Screen(s[:i] + string(alphabet[j]) + s[i+1:]); ok {
				t.Fatalf("a cookie with character %d changed to %q is plausible", i, alphabet[j])
			}
		}
	}
	for _, other := range []string{s[:len(s)-1], s + "A", s + "=", ""} {
		if _, _, ok := m.Screen(other); ok {
			t.Errorf("a cookie of %d characters is plausible", len(other))
		}
	}
}

// TestTheSessionIDIsUnderTheTag is primitives-r7-6 and tenant-r8-3. The session-miss budget is keyed on the session a
// cookie opens, read from the cookie, so the id must be under the tag: a holder who
// rewrote it to charge another session's budget, or to dodge his own, fails the tag. Screen returns
// the session id for a cookie that checks, and none for a manager with no keys (it has no tag to trust).
func TestTheSessionIDIsUnderTheTag(t *testing.T) {
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	m := tagManager(t, &now)
	a, b := uuid.New(), uuid.New()
	tokA, _ := m.newSessionToken(audienceTenant, now.Add(time.Hour), a)
	tokB, _ := m.newSessionToken(audienceTenant, now.Add(time.Hour), b)
	if _, sessionID, ok := m.Screen(tokA.Reveal()); !ok || sessionID != a.String() {
		t.Fatalf("the sessionID of a's cookie is %q (ok %v), want %s", sessionID, ok, a)
	}
	raw, _ := base64.RawURLEncoding.DecodeString(tokA.Reveal())
	copy(raw[:tokenSessionLen], b[:]) // a's cookie, made to name session b
	if _, _, ok := m.Screen(base64.RawURLEncoding.EncodeToString(raw)); ok {
		t.Fatal("a cookie whose session id was rewritten to another session passes the tag")
	}
	if _, sessionID, _ := m.Screen(tokB.Reveal()); sessionID != b.String() {
		t.Fatalf("the sessionID of b's cookie is %q", sessionID)
	}
	// The nil id is no session: a cookie that names it is refused, so the budget never meets "".
	nilTok := forgeFor(t, m, now.Add(time.Hour), uuid.Nil)
	if _, _, ok := m.Screen(nilTok.Reveal()); ok {
		t.Error("a cookie for no session is plausible")
	}
	plain := NewManager(nil, DefaultPolicy(), func() time.Time { return now })
	untagged, _ := plain.newSessionToken(audienceTenant, now.Add(time.Hour), a)
	if _, sessionID, ok := plain.Screen(untagged.Reveal()); !ok || sessionID != "" {
		t.Errorf("a manager with no keys gave sessionID %q (ok %v), want none", sessionID, ok)
	}
}

// TestATaggedTokenCannotBeMadeForNoSession: AdminRotate was called with an AdminSessionInfo that had no
// AdminID, and the cookie it issued was refused as a plain 401 on its next request. Issuing refuses it.
func TestATaggedTokenCannotBeMadeForNoSession(t *testing.T) {
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	m := tagManager(t, &now)
	if _, err := m.newSessionToken(audienceTenant, now.Add(time.Hour), uuid.Nil); err != ErrNoSessionID {
		t.Fatalf("a token for the nil session id: %v, want ErrNoSessionID", err)
	}
}

// forgeFor builds a validly tagged token for any session id, the nil one included, which
// newSessionToken refuses to make.
func forgeFor(t *testing.T, m *Manager, abs time.Time, sessionID uuid.UUID) secret.String {
	t.Helper()
	var raw [tokenBodyLen + tokenTagLen]byte
	copy(raw[:tokenSessionLen], sessionID[:])
	binary.BigEndian.PutUint32(raw[tokenSessionLen+tokenRandLen:tokenBodyLen], expiryOf(abs))
	copy(raw[tokenBodyLen:], m.ring.MAC(m.tagDomain, keyring.LabelSession, raw[:tokenBodyLen])[:tokenTagLen])
	return secret.New(base64.RawURLEncoding.EncodeToString(raw[:]))
}

// TestWithKeysRefusesADomainTheSessionTagCannotUse (primitives-r11-1): a ring that holds a sealed domain
// (its key is an AES key, and Ring.MAC panics for it) or a domain that lists no session label used to be
// accepted, and the service panicked at the first login. It is refused at start now, whatever the ring holds.
func TestWithKeysRefusesADomainTheSessionTagCannotUse(t *testing.T) {
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	for _, domain := range keyring.Domains() {
		ring, err := keyring.NewEphemeral(domain)
		if err != nil {
			t.Fatal(err)
		}
		m := NewManager(nil, DefaultPolicy(), func() time.Time { return now })
		err = m.WithKeys(ring, domain)
		usable := domain == keyring.DomainAuthMAC || domain == keyring.DomainAdminMAC
		if usable && err != nil {
			t.Errorf("%s: refused: %v", domain, err)
		}
		if !usable {
			if err == nil {
				t.Errorf("%s: accepted, and the first login would panic in Ring.MAC", domain)
			}
			if m.ring != nil {
				t.Errorf("%s: refused and still installed", domain)
			}
		}
	}
	// The registry says which domains list the session label; the test must agree with it, or the
	// two lines above would pass for a registry that gained a third service.
	for _, d := range []string{keyring.DomainAuthMAC, keyring.DomainAdminMAC} {
		if !keyring.PairListed(d, keyring.LabelSession) {
			t.Errorf("%s no longer lists the session label", d)
		}
	}
}

// TestASessionIsNotTaggedUnderTheOtherServicesDomain (primitives-r11-1): the tenant and the admin session
// tags must not share one key and label, so a manager given admin_mac refuses to issue a tenant session
// and the reverse, and a cookie made under one does not screen under the other.
func TestASessionIsNotTaggedUnderTheOtherServicesDomain(t *testing.T) {
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	ring, err := keyring.NewEphemeral(keyring.DomainAuthMAC, keyring.DomainAdminMAC)
	if err != nil {
		t.Fatal(err)
	}
	mk := func(domain string) *Manager {
		m := NewManager(nil, DefaultPolicy(), func() time.Time { return now })
		if err := m.WithKeys(ring, domain); err != nil {
			t.Fatal(err)
		}
		return m
	}
	tenant, admin := mk(keyring.DomainAuthMAC), mk(keyring.DomainAdminMAC)
	if _, err := tenant.newSessionToken(audienceAdmin, now.Add(time.Hour), uuid.New()); err != ErrWrongTagDomain {
		t.Errorf("an admin session under auth_mac: %v, want ErrWrongTagDomain", err)
	}
	if _, err := admin.newSessionToken(audienceTenant, now.Add(time.Hour), uuid.New()); err != ErrWrongTagDomain {
		t.Errorf("a tenant session under admin_mac: %v, want ErrWrongTagDomain", err)
	}
	tok, err := tenant.newSessionToken(audienceTenant, now.Add(time.Hour), uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, ok := admin.Screen(tok.Reveal()); ok {
		t.Error("a tenant cookie screens under the admin key")
	}
}
