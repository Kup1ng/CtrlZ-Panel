package session

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"math"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/token"
	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
)

// A session token carries a keyed tag so that a cookie nobody issued is refused
// without a charge and without a database call (review round 4, tenant-r4-4).
//
// Before the tag, the only way to keep random cookies from queueing lookups on
// the pool was to charge every cookie to its source network before it was looked
// up. That bucket is shared by everyone behind one carrier NAT, so one host's
// junk emptied it and every live session on the network was refused with a 429.
// A tag the server can check in-process removes the reason to charge junk at
// all: a cookie that fails the tag costs one HMAC, and only a cookie that was
// issued here, and so is worth a lookup, is charged, to its own bucket.
//
// The token keeps one body and one tag: a 40 byte body (the id of the session it opens, 16 bytes; 20
// random; 4 of expiry) and an 8 byte tag are 48 bytes, 64 characters of base64url with no spare bits (a
// multiple of three bytes, so one spelling per value without a rule for it). The tag is a filter and not
// the credential. A forged cookie still has to be a stored 160 bit value to open a session, and the 64
// bit tag only decides whether it is worth looking up.
//
// The session id is in the body so that the cost of a dead cookie can be charged to the session it was
// made for (round 7, primitives-r7-6; round 8, tenant-r8-3). The set of dead cookies (internal/httpx
// deadSet) is bounded and forgets the oldest, so a holder of more dead cookies than it holds could send
// them round and round, each one a lookup again, with nothing that bounded the total: the per-cookie
// classes allow far more than one use per cycle, and a session route has no network bucket by design. A
// miss is charged before the lookup to a bucket keyed on the session id, which the tag makes
// unforgeable (the key is server-only, so a body cannot be rewritten to name another session) and which
// no eviction can reset.
//
// The key is the SESSION and not the account, on purpose. Round 7 keyed it on the account, and the dead
// cookies of one stolen session (a rotation chain makes any number of them) then spent the budget of
// EVERY session of that account, the ones opened after logout-all included, so a thief could keep the
// owner out for as long as he cared to send them. A session's id is fixed for its life (a rotation keeps
// it) and is made in Go before the row is inserted, so the cookie can carry it: the dead cookies of one
// session draw on that session's budget and on nobody else's.
const (
	tokenSessionLen = 16 // the id of the session the cookie opens (sessions.id or admin_sessions.id)
	tokenRandLen    = 20 // the random part of the body
	tokenExpLen     = 4  // the absolute expiry, Unix seconds, big endian
	tokenBodyLen    = tokenSessionLen + tokenRandLen + tokenExpLen
	tokenTagLen     = 8
	// CookieLen is the length of a tagged session cookie in characters.
	CookieLen = (tokenBodyLen + tokenTagLen) * 4 / 3
)

// ErrNoKeys is returned by WithKeys for a ring that lacks the domain, or for a domain the session tag cannot use.
var ErrNoKeys = errors.New("session: the key ring lacks a usable MAC domain for the session tag")

// ErrWrongTagDomain is returned when a manager is asked to issue a session of one kind under the tag domain
// of the other (a tenant session under admin_mac, an admin session under auth_mac). One Manager type serves
// both services and cannot know at WithKeys which one it is, so the issuing call says so.
var ErrWrongTagDomain = errors.New("session: the tag domain of the manager is not the one of the kind of session it was asked to issue")

// audience is the kind of session a token opens, and so the one tag domain it may be made under.
type audience string

const (
	audienceTenant audience = keyring.DomainAuthMAC
	audienceAdmin  audience = keyring.DomainAdminMAC
)

// ErrNoSessionID is returned when a tagged session token is asked for with no session id to carry.
var ErrNoSessionID = errors.New("session: a token needs the id of the session it opens")

// WithKeys makes the manager tag the session tokens it issues and check the tag
// of the cookies it is given: user sessions under auth_mac, admin sessions under
// admin_mac. A process serves one of the two, so only the domain of its role is
// needed. The services call it at start-up and fail if it errors; a manager
// without keys (some unit tests) issues untagged tokens and screens by shape only.
//
// The domain is refused here unless the ring can actually tag a session under it: a labeled domain
// (ModeOf) that lists the session label (PairListed), which is what Ring.MAC checks and panics on.
// Checking only that the ring holds the key let a wrong domain (a sealed one such as user_totp) start the
// service and panic at the first login (round 11, primitives-r11-1). That the domain is the one of this
// service's role is checked at issue, by audience, because the manager does not know its role here.
func (m *Manager) WithKeys(r *keyring.Ring, domain string) error {
	if r == nil || !r.Has(domain) {
		return ErrNoKeys
	}
	if mode, ok := keyring.ModeOf(domain); !ok || mode != keyring.ModeLabeled || !keyring.PairListed(domain, keyring.LabelSession) {
		return ErrNoKeys
	}
	m.ring, m.tagDomain = r, domain
	return nil
}

// newSessionToken is token.New with the session id and the tag, or plain token.New for a manager with no
// keys. The body holds the id of the session it opens (16 bytes), 20 random bytes and the
// session's absolute expiry (4 bytes, Unix seconds, big endian), and the tag covers all three. The
// random part is still 160 bits, far beyond guessing, and the expiry lets Screen refuse a cookie of a
// session that ended by age with no I/O at all: a cookie kept after its session ran out used to stay
// plausible for as long as its key line was loaded and to cost a database lookup for every request
// (primitives-r5-9). The row in the database stays the authority: the expiry and the session id in the
// token are only ever read as a reason to refuse sooner or to count a miss, never to accept.
func (m *Manager) newSessionToken(aud audience, abs time.Time, sessionID uuid.UUID) (secret.String, error) {
	if m.ring == nil {
		return token.New()
	}
	// The two services must not share one key and label for their session tags (round 11, primitives-r11-1).
	if m.tagDomain != string(aud) {
		return secret.String{}, ErrWrongTagDomain
	}
	// A token that names no session would be refused by Screen as a plain 401, long after the caller
	// that built it with a zero id: refuse it here, where the mistake is.
	if sessionID == uuid.Nil {
		return secret.String{}, ErrNoSessionID
	}
	var raw [tokenBodyLen + tokenTagLen]byte
	copy(raw[:tokenSessionLen], sessionID[:])
	if _, err := rand.Read(raw[tokenSessionLen : tokenSessionLen+tokenRandLen]); err != nil {
		return secret.String{}, err
	}
	binary.BigEndian.PutUint32(raw[tokenSessionLen+tokenRandLen:tokenBodyLen], expiryOf(abs))
	copy(raw[tokenBodyLen:], m.ring.MAC(m.tagDomain, keyring.LabelSession, raw[:tokenBodyLen])[:tokenTagLen])
	return secret.New(base64.RawURLEncoding.EncodeToString(raw[:])), nil
}

// expiryOf is the expiry as the token holds it, saturated to what 4 bytes can say
// (the year 2106; a session lives at most 90 days).
func expiryOf(abs time.Time) uint32 {
	u := abs.Unix()
	switch {
	case u < 0:
		return 0
	case u > math.MaxUint32:
		return math.MaxUint32
	}
	return uint32(u)
}

// Screen says whether a session cookie can have been issued by this service and has not
// run out of age, without any I/O, and returns the key its lookup is charged to and the id of the session it
// opens (empty for a manager with no keys, whose tokens carry none). The key
// is a hash of the cookie under a label of its own, so the rate limiter's store never
// holds the cookie or the hash that is stored in the database. ok is false for a cookie
// of the wrong shape, with a wrong tag or past its absolute expiry; the request is then
// answered 401 session_expired and charges nothing.
func (m *Manager) Screen(cookie string) (key, sessionID string, ok bool) {
	if m.ring == nil {
		if !token.Valid(cookie) {
			return "", "", false
		}
		return lookupKeyOf(cookie), "", true
	}
	// 48 bytes are 64 characters with no spare bit, so the strict decoder has nothing to refuse
	// beyond the alphabet and the length, and a cookie has one spelling, one key and one budget.
	if len(cookie) != CookieLen {
		return "", "", false
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(cookie)
	if err != nil || len(raw) != tokenBodyLen+tokenTagLen ||
		!m.ring.VerifyMAC(m.tagDomain, keyring.LabelSession, raw[tokenBodyLen:], raw[:tokenBodyLen]) {
		return "", "", false
	}
	if m.now().Unix() > int64(binary.BigEndian.Uint32(raw[tokenSessionLen+tokenRandLen:tokenBodyLen])) {
		return "", "", false
	}
	id, err := uuid.FromBytes(raw[:tokenSessionLen])
	if err != nil || id == uuid.Nil {
		return "", "", false
	}
	return lookupKeyOf(cookie), id.String(), true
}

func lookupKeyOf(cookie string) string {
	sum := sha256.Sum256([]byte("ctrlz-session-lookup-v1|" + cookie))
	return base64.RawURLEncoding.EncodeToString(sum[:16])
}
