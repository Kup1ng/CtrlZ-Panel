package ticket

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/proofmac"
	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
)

// A sealed ceremony ticket carries a passkey login's WebAuthn session data itself, under
// a tag only the api can make, so POST /auth/passkey/login/begin writes no row (P1 auth
// review round 5, rule proof-before-work; spec 7.5). The route needs no proof, and a row
// per call was a table an anonymous flood could fill from enough networks; the per-network
// charge bounded each source, never the whole. The row now appears at finish, once, and only
// after an assertion verified.
//
// Layout, before base64url: version (1) | expiry, unix seconds (8) | remember (1) |
// nonce (16) | length of the session data (2) | session data | tag (16). The tag is
// the first 16 bytes of the HMAC of everything before it under auth_mac, label
// passkey_ceremony, which no other value of the system is tagged with. Nothing in it is
// secret: the session data is the challenge the browser already holds. The tag is what
// stops a client from choosing its own challenge and expiry.

const (
	sealedVersion = 1
	sealedHeader  = 1 + 8 + 1 + 16 + 2
	sealedTagLen  = 16
	// maxSessionData bounds what a ceremony carries. Discoverable session data is a few
	// hundred bytes; the cap keeps a header the pipeline can read.
	maxSessionData = 2048
	// maxSealedText is the longest ticket Open looks at, before any decoding.
	maxSealedText = (sealedHeader+maxSessionData+sealedTagLen)*4/3 + 4
)

// Ceremony is what a sealed ticket carries.
type Ceremony struct {
	Remember bool
	// Session is the WebAuthn session data as the passkey package returned it.
	Session []byte
	// Spend is the SHA-256 of the ticket's nonce: the value TicketSpend records, so the
	// ticket can be used once whichever api process receives it.
	Spend []byte
	// Left is how much of the ticket's life remains, at least a second: the life of the row
	// TicketSpend writes, so it is swept with the other tickets.
	Left time.Duration
	// Expires is the instant after which the ticket is refused.
	Expires time.Time
}

// WithSealing lets the service make and open sealed tickets. now is the clock of the
// expiry (the api's clock, so a test can move it).
func (s *Service) WithSealing(ring *keyring.Ring, now func() time.Time) *Service {
	s.ring, s.now = ring, now
	// A ring that holds auth_mac also tags the DB tickets. One that does not (a test of the sealed tickets alone) leaves them plain.
	if t, err := proofmac.New(ring, now); err == nil {
		s.tags = t
	}
	return s
}

func (s *Service) sealTag(body []byte) []byte {
	return s.ring.MAC(keyring.DomainAuthMAC, keyring.LabelCeremony, body)[:sealedTagLen]
}

// SealCeremony makes the ticket for a passkey login that has just begun.
func (s *Service) SealCeremony(session []byte, remember bool, life time.Duration) (secret.String, error) {
	if s.ring == nil || len(session) == 0 || len(session) > maxSessionData {
		return secret.String{}, ErrSealed
	}
	raw := make([]byte, sealedHeader, sealedHeader+len(session)+sealedTagLen)
	raw[0] = sealedVersion
	binary.BigEndian.PutUint64(raw[1:9], uint64(s.now().Add(life).Unix()))
	if remember {
		raw[9] = 1
	}
	if _, err := rand.Read(raw[10:26]); err != nil {
		return secret.String{}, err
	}
	binary.BigEndian.PutUint16(raw[26:28], uint16(len(session)))
	raw = append(raw, session...)
	raw = append(raw, s.sealTag(raw)...)
	return secret.New(base64.RawURLEncoding.EncodeToString(raw)), nil
}

// OpenCeremony verifies a sealed ticket and returns what it carries. It costs one HMAC
// and touches no database, so it is the check of a route that has no row to look at. Any
// value that is not a ticket this api made and that has not expired is refused, without
// saying which.
func (s *Service) OpenCeremony(text string) (Ceremony, bool) {
	if s.ring == nil || len(text) > maxSealedText || len(text) < sealedHeader {
		return Ceremony{}, false
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(text)
	if err != nil || len(raw) < sealedHeader+sealedTagLen || raw[0] != sealedVersion {
		return Ceremony{}, false
	}
	body, tag := raw[:len(raw)-sealedTagLen], raw[len(raw)-sealedTagLen:]
	n := int(binary.BigEndian.Uint16(body[26:28]))
	if n == 0 || n > maxSessionData || len(body) != sealedHeader+n {
		return Ceremony{}, false
	}
	if !s.ring.VerifyMAC(keyring.DomainAuthMAC, keyring.LabelCeremony, tag, body) {
		return Ceremony{}, false
	}
	exp := time.Unix(int64(binary.BigEndian.Uint64(body[1:9])), 0)
	if !s.now().Before(exp) {
		return Ceremony{}, false
	}
	spend := sha256.Sum256(body[10:26])
	return Ceremony{Remember: body[9] == 1, Session: body[sealedHeader:], Spend: spend[:], Left: max(exp.Sub(s.now()), time.Second), Expires: exp}, true
}
