// Package bearer makes and screens the three bearer values of P3: API tokens, share links and Apple profile download links
// (docs/specs/p3-endpoints.md 6.2).
//
// Why one format. The three are secrets that a person pastes or scans, and each is looked up by the hash of its text. A lookup
// costs a database read, and a stranger can send any text, so a value carries what the server can check with no I/O: the id of
// the row that was issued with it, the instant it dies, and a keyed tag over both. A value that fails Screen is answered at
// once and charges nothing (a dead value costs the price of one MAC); one that passes earns the budget of the row it names, so
// what a holder of many dead values can spend is bounded by how many rows his tenant was allowed to mint (spec 6.2, 9.1).
//
// Layout (48 bytes, 64 base64url characters, no padding, canonical spelling only): the row id (16 bytes, made in Go before the
// INSERT), 20 random bytes, the expiry (4 bytes, Unix seconds, from the application clock that the row's expires_at shares), and
// the first 8 bytes of HMAC(subkey(auth_mac, label), the first 40 bytes). The label is one per kind (keyring.LabelAPIToken,
// LabelSetupShare, LabelProfileDownload), so a tag made for a share link is no tag for a download link.
//
// The tag is a filter and never the credential. The database stays the authority: the stored SHA-256 of the 64 characters must
// match a live row, and the consume statement decides the rest. The 20 random bytes are the secret; the id and the expiry are
// readable by whoever holds the value, which tells them nothing they could use.
package bearer

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"math"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/appclock"
	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
)

// Kind is what a value is for. It selects the label of the tag.
type Kind byte

// The kinds.
const (
	APIToken     Kind = 'a'
	ShareLink    Kind = 's'
	DownloadLink Kind = 'd'
)

const (
	idLen     = 16
	randomLen = 20
	expLen    = 4
	bodyLen   = idLen + randomLen + expLen
	tagLen    = 8
	// Len is the length of a value in characters.
	Len = (bodyLen + tagLen) * 4 / 3
)

// ErrNoKeys is returned by New for a ring that cannot tag under the three labels.
var ErrNoKeys = errors.New("bearer: the key ring lacks auth_mac or one of the bearer labels")

// ErrNoID is returned when a value is asked for with no row id: the tag would then name nobody.
var ErrNoID = errors.New("bearer: a value names the row it was issued with")

// ErrKind is returned for a kind that is none of the three.
var ErrKind = errors.New("bearer: unknown kind")

// Signer makes and screens values.
type Signer struct {
	ring *keyring.Ring
	now  func() time.Time
}

// New returns a Signer over the ring. now nil means the application clock.
func New(ring *keyring.Ring, now func() time.Time) (*Signer, error) {
	if ring == nil || !ring.Has(keyring.DomainAuthMAC) {
		return nil, ErrNoKeys
	}
	for _, l := range []string{keyring.LabelAPIToken, keyring.LabelSetupShare, keyring.LabelProfileDownload} {
		if !keyring.PairListed(keyring.DomainAuthMAC, l) {
			return nil, ErrNoKeys
		}
	}
	if now == nil {
		now = appclock.Now
	}
	return &Signer{ring: ring, now: now}, nil
}

// Body is what a value says once its tag and expiry check.
type Body struct {
	// ID is the id of the row the value was issued with.
	ID      uuid.UUID
	Expires time.Time
}

// mac and verify name each label as a constant, so the keyring lint can read the pair of every call.
func (s *Signer) mac(k Kind, body []byte) ([]byte, error) {
	switch k {
	case APIToken:
		return s.ring.MAC(keyring.DomainAuthMAC, keyring.LabelAPIToken, body), nil
	case ShareLink:
		return s.ring.MAC(keyring.DomainAuthMAC, keyring.LabelSetupShare, body), nil
	case DownloadLink:
		return s.ring.MAC(keyring.DomainAuthMAC, keyring.LabelProfileDownload, body), nil
	}
	return nil, ErrKind
}

func (s *Signer) verify(k Kind, tag, body []byte) bool {
	switch k {
	case APIToken:
		return s.ring.VerifyMAC(keyring.DomainAuthMAC, keyring.LabelAPIToken, tag, body)
	case ShareLink:
		return s.ring.VerifyMAC(keyring.DomainAuthMAC, keyring.LabelSetupShare, tag, body)
	case DownloadLink:
		return s.ring.VerifyMAC(keyring.DomainAuthMAC, keyring.LabelProfileDownload, tag, body)
	}
	return false
}

// Mint makes a value for the row id with the expiry (saturated to what four bytes can say).
func (s *Signer) Mint(k Kind, id uuid.UUID, expires time.Time) (secret.String, error) {
	var random [randomLen]byte
	if _, err := rand.Read(random[:]); err != nil {
		return secret.String{}, err
	}
	return s.MintWith(k, id, random[:], expires)
}

// MintWith is Mint with the random part given, for tests that need a value they can reproduce.
func (s *Signer) MintWith(k Kind, id uuid.UUID, random []byte, expires time.Time) (secret.String, error) {
	if id == uuid.Nil {
		return secret.String{}, ErrNoID
	}
	if len(random) != randomLen {
		return secret.String{}, errors.New("bearer: the random part is 20 bytes")
	}
	var raw [bodyLen + tagLen]byte
	copy(raw[:idLen], id[:])
	copy(raw[idLen:idLen+randomLen], random)
	binary.BigEndian.PutUint32(raw[idLen+randomLen:bodyLen], expiryOf(expires))
	tag, err := s.mac(k, raw[:bodyLen])
	if err != nil {
		return secret.String{}, err
	}
	copy(raw[bodyLen:], tag[:tagLen])
	return secret.New(base64.RawURLEncoding.EncodeToString(raw[:])), nil
}

func expiryOf(t time.Time) uint32 {
	u := t.Unix()
	switch {
	case u < 0:
		return 0
	case u > math.MaxUint32:
		return math.MaxUint32
	}
	return uint32(u)
}

// Screen checks the shape, the tag and the expiry of a value of kind k with no I/O. ok is false for anything this service did
// not issue under that kind, and for a value past its expiry. A value that fails is answered at once and charges nothing.
func (s *Signer) Screen(k Kind, text string) (Body, bool) {
	if len(text) != Len {
		return Body{}, false
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(text)
	if err != nil || len(raw) != bodyLen+tagLen || !s.verify(k, raw[bodyLen:], raw[:bodyLen]) {
		return Body{}, false
	}
	var b Body
	copy(b.ID[:], raw[:idLen])
	if b.ID == uuid.Nil {
		return Body{}, false
	}
	b.Expires = time.Unix(int64(binary.BigEndian.Uint32(raw[idLen+randomLen:bodyLen])), 0)
	if s.now().Unix() > b.Expires.Unix() {
		return Body{}, false
	}
	return b, true
}

// Hash is what a row stores for a value: SHA-256 of its 64 characters. The value has 160 random bits, so an unkeyed hash is
// the right thing to store.
func Hash(text string) []byte {
	h := sha256.Sum256([]byte(text))
	return h[:]
}
