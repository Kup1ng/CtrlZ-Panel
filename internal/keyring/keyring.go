// Package keyring holds the keys that protect secrets at rest (spec 8): TOTP
// seeds, SMS credentials, the OTP text waiting for the worker, and the MAC keys
// that hash OTP codes and throttle keys.
//
// The design in one paragraph. A host-only root derives one key per domain, and
// each container is given the key files of its own domains only, so a
// compromised api cannot read SMS credentials and a compromised worker cannot
// read TOTP seeds. A key file lists numbered keys: the highest number
// encrypts, every number decrypts, which is what makes rotation a matter of
// adding a line, recreating the container and re-encrypting at leisure.
//
// Nothing here returns key bytes. The callers get Seal, Open, MAC and the
// labelled variants, and the keys sit in secret.Bytes inside an unexported type.
// The one exception is the key-file writer in file.go, which exists for
// "ctrlz keys derive" and hands back a secret.Bytes of the file text.
//
// There is no process-wide ring. The workspace rule forbids package-level
// mutable state, so a *Ring is built at start-up and handed to whoever needs it
// (spec 8.2 shows free functions; section 19 of the P1 spec records the change).
package keyring

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"

	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
)

// The domains of spec 8.1. A domain is a name for one purpose, so that a key
// found by one container cannot decrypt another purpose's column.
const (
	DomainUserTOTP    = "user_totp"    // users.totp_secret_ct
	DomainAdminTOTP   = "admin_totp"   // admin_users.totp_secret_ct
	DomainSMSCred     = "sms_cred"     // sms_gateways.credentials_ct, sms_outbox.params_ct
	DomainOTPDelivery = "otp_delivery" // otp_challenges.delivery_ct
	DomainAuthMAC     = "auth_mac"     // OTP code hash, throttle keys, device cookie
	DomainAdminMAC    = "admin_mac"    // admin throttle keys
	DomainDOHToken    = "doh_token"    // endpoints.doh_token_ct (P3); no rekey tool, see `ctrlz-admin keys status doh_token`
	DomainCertWrap    = "cert_wrap"    // reserved for P6
)

// Labels name subkeys of a domain key (8.2). A label separates uses of one key
// so a MAC made for one purpose is never valid for another.
const (
	LabelOTP         = "otp"              // auth_mac: OTP code hash
	LabelThrottle    = "throttle"         // auth_mac and admin_mac: throttle keys
	LabelDevice      = "device"           // auth_mac: the __Host-ctrlz_device cookie
	LabelAdminDevice = "admin_device"     // admin_mac: the __Host-ctrlz_admin_device cookie
	LabelSession     = "session"          // auth_mac and admin_mac: the tag inside a session token
	LabelCeremony    = "passkey_ceremony" // auth_mac: the tag of a stateless passkey login ticket
	LabelProof       = "proof"            // auth_mac: the tag inside a ticket, an OTP challenge id and a refresh token (internal/auth/proofmac)
	// The three bearer values of P3 (spec 6.2, internal/auth/bearer): one format, one label each, so a tag made for a share
	// link never verifies as a download link or an API token.
	LabelAPIToken        = "api_token"        // auth_mac: the tag inside an API token
	LabelSetupShare      = "setup_share"      // auth_mac: the tag inside a share link
	LabelProfileDownload = "profile_download" // auth_mac: the tag inside an Apple profile download link
)

// Domains lists every defined domain, reserved ones included.
func Domains() []string {
	return []string{DomainUserTOTP, DomainAdminTOTP, DomainSMSCred, DomainOTPDelivery, DomainAuthMAC, DomainAdminMAC, DomainDOHToken, DomainCertWrap}
}

// ValidDomain reports whether name is a defined domain.
func ValidDomain(name string) bool {
	for _, d := range Domains() {
		if d == name {
			return true
		}
	}
	return false
}

// The ciphertext layout of spec 8.2.
const (
	magic0, magic1 = 'C', 'Z'
	formatVersion  = 0x01
	headerLen      = 5 // "CZ", version, key number
	nonceLen       = 12
	keyLen         = 32
	tagLen         = 16
	// maxPlain bounds what Seal accepts. Everything sealed here is a seed, a
	// credential or a small JSON payload; a large input is a bug.
	maxPlain = 64 << 10
)

// Errors are fixed strings. None names a key, a plaintext or a ciphertext, and
// Open returns one value for every failure, so a caller cannot tell a wrong key
// from a damaged row and neither can a log reader (8.2, 8.6).
var (
	ErrNotLoaded = errors.New("keyring: domain not loaded")
	ErrOpen      = errors.New("keyring: cannot open ciphertext")
	ErrSeal      = errors.New("keyring: cannot seal")
)

// key is one numbered key of a domain.
type key struct {
	n uint16
	k secret.Bytes
}

// domainKeys holds the keys of one domain. newest encrypts.
type domainKeys struct {
	newest key
	byNum  map[uint16]key
}

// Ring is the set of domains one process holds. It is immutable after
// construction, so it is safe for concurrent use without a lock.
type Ring struct {
	domains map[string]*domainKeys
}

// newRing builds a Ring from parsed keys. Every domain needs at least one key.
func newRing(keys map[string][]key) (*Ring, error) {
	r := &Ring{domains: make(map[string]*domainKeys, len(keys))}
	for d, list := range keys {
		if len(list) == 0 {
			return nil, fmt.Errorf("keyring: domain %s: no keys", d)
		}
		dk := &domainKeys{byNum: make(map[uint16]key, len(list))}
		for _, k := range list {
			dk.byNum[k.n] = k
			if k.n > dk.newest.n {
				dk.newest = k
			}
		}
		r.domains[d] = dk
	}
	return r, nil
}

// NewEphemeral makes a Ring with one random key per domain, living only in this
// process. It is for tests and for the "test" environment of the app; a key that
// dies with the process would strand every ciphertext in a real database.
func NewEphemeral(domains ...string) (*Ring, error) {
	keys := make(map[string][]key, len(domains))
	for _, d := range domains {
		if !ValidDomain(d) {
			return nil, fmt.Errorf("keyring: unknown domain %q", d)
		}
		b := make([]byte, keyLen)
		if _, err := rand.Read(b); err != nil {
			return nil, errors.New("keyring: no randomness")
		}
		keys[d] = []key{{n: 1, k: secret.NewBytes(b)}}
		clear(b)
	}
	return newRing(keys)
}

// Has reports whether the domain is loaded.
func (r *Ring) Has(domain string) bool {
	_, ok := r.domains[domain]
	return ok
}

// Loaded lists the loaded domains, sorted.
func (r *Ring) Loaded() []string {
	out := make([]string, 0, len(r.domains))
	for d := range r.domains {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

// Numbers lists the key numbers of a domain, ascending, for status output. A
// number is a label for a key, not the key.
func (r *Ring) Numbers(domain string) []uint16 {
	dk := r.domains[domain]
	if dk == nil {
		return nil
	}
	out := make([]uint16, 0, len(dk.byNum))
	for n := range dk.byNum {
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Newest is the number new ciphertext is written under.
func (r *Ring) Newest(domain string) (uint16, bool) {
	dk := r.domains[domain]
	if dk == nil {
		return 0, false
	}
	return dk.newest.n, true
}

// Require fails if any of the domains is not loaded. A process calls it once at
// start, so that a missing key stops the start-up and not the first request.
func (r *Ring) Require(domains ...string) error {
	var errs []error
	for _, d := range domains {
		if !r.Has(d) {
			errs = append(errs, fmt.Errorf("%w: %s", ErrNotLoaded, d))
		}
	}
	return errors.Join(errs...)
}

// aadFor builds the AAD of spec 8.2: "ctrlz" 0x00 domain 0x00 context. The label
// of a labelled seal sits before the context, so a ciphertext made under one
// label does not open under another or with none.
func aadFor(domain, label string, context Context) []byte {
	b := make([]byte, 0, 8+len(domain)+len(label)+len(context.b))
	b = append(b, "ctrlz\x00"...)
	b = append(b, domain...)
	b = append(b, 0)
	if label != "" {
		b = append(b, label...)
		b = append(b, 0)
	}
	return append(b, context.b...)
}

// subkey is HKDF-Expand(key, info = label, L = 32). The caller wipes it.
func subkey(k secret.Bytes, label string) ([]byte, error) {
	return hkdf.Expand(sha256.New, k.Reveal(), label, keyLen)
}

// Seal encrypts plain under the newest key of the domain. context binds the
// ciphertext to its row (6.2, 5.2, 8.2), so a ciphertext copied elsewhere fails
// to open. The zero Context is refused with ErrSeal, and Open refuses it with ErrOpen.
func (r *Ring) Seal(domain string, context Context, plain []byte) ([]byte, error) {
	return r.seal(domain, "", context, plain)
}

// SealLabeled is Seal under the labelled subkey of the newest key.
func (r *Ring) SealLabeled(domain, label string, context Context, plain []byte) ([]byte, error) {
	if !labelFor(label, SealOnly) {
		return nil, ErrSeal
	}
	return r.seal(domain, label, context, plain)
}

func (r *Ring) seal(domain, label string, context Context, plain []byte) ([]byte, error) {
	dk := r.domains[domain]
	if dk == nil {
		return nil, fmt.Errorf("%w: %s", ErrNotLoaded, domain)
	}
	// The zero Context binds the ciphertext to nothing, so it would open under any row that holds a
	// copy (round 12, primitives-r12-3). It is what a refused RowContext or DigestContext returns and
	// what a Context nobody filled is, and the type has no other way to say "nothing" (round 18,
	// primitives-r18-13); lint keyringcontext_test.go asks in addition that the context is built by a
	// named AAD function that takes the row's identity.
	if context.zero() {
		return nil, ErrSeal
	}
	if len(plain) > maxPlain {
		return nil, ErrSeal
	}
	// The domain key is the AES key of an unlabeled seal and the HKDF root of a labelled one, never
	// both (labels.go ModeOf, primitives-r6-8).
	if !modeAllowsLabel(domain, label) {
		return nil, ErrSeal
	}
	raw, err := rawKey(dk.newest.k, label)
	if err != nil {
		return nil, ErrSeal
	}
	defer clear(raw)
	gcm, err := newGCM(raw)
	if err != nil {
		return nil, ErrSeal
	}
	out := make([]byte, headerLen+nonceLen, headerLen+nonceLen+len(plain)+tagLen)
	out[0], out[1], out[2] = magic0, magic1, formatVersion
	binary.BigEndian.PutUint16(out[3:5], dk.newest.n)
	if _, err := rand.Read(out[headerLen : headerLen+nonceLen]); err != nil {
		return nil, ErrSeal
	}
	return gcm.Seal(out, out[headerLen:headerLen+nonceLen], plain, aadFor(domain, label, context)), nil
}

// Open decrypts a ciphertext made by Seal. Every failure returns ErrOpen, except
// a domain that is not loaded, which is a start-up mistake and says so.
func (r *Ring) Open(domain string, context Context, ct []byte) (secret.Bytes, error) {
	return r.open(domain, "", context, ct)
}

// OpenLabeled is Open for SealLabeled.
func (r *Ring) OpenLabeled(domain, label string, context Context, ct []byte) (secret.Bytes, error) {
	if !labelFor(label, SealOnly) {
		return secret.Bytes{}, ErrOpen
	}
	return r.open(domain, label, context, ct)
}

func (r *Ring) open(domain, label string, context Context, ct []byte) (secret.Bytes, error) {
	dk := r.domains[domain]
	if dk == nil {
		return secret.Bytes{}, fmt.Errorf("%w: %s", ErrNotLoaded, domain)
	}
	if context.zero() {
		return secret.Bytes{}, ErrOpen
	}
	if len(ct) < headerLen+nonceLen+tagLen || ct[0] != magic0 || ct[1] != magic1 || ct[2] != formatVersion {
		return secret.Bytes{}, ErrOpen
	}
	if !modeAllowsLabel(domain, label) {
		return secret.Bytes{}, ErrOpen
	}
	k, ok := dk.byNum[binary.BigEndian.Uint16(ct[3:5])]
	if !ok {
		return secret.Bytes{}, ErrOpen
	}
	raw, err := rawKey(k.k, label)
	if err != nil {
		return secret.Bytes{}, ErrOpen
	}
	defer clear(raw)
	gcm, err := newGCM(raw)
	if err != nil {
		return secret.Bytes{}, ErrOpen
	}
	plain, err := gcm.Open(nil, ct[headerLen:headerLen+nonceLen], ct[headerLen+nonceLen:], aadFor(domain, label, context))
	if err != nil {
		return secret.Bytes{}, ErrOpen
	}
	s := secret.NewBytes(plain)
	clear(plain)
	return s, nil
}

// rawKey returns the AES key for a seal: a copy of the domain key, or the
// labelled subkey. The caller wipes it.
func rawKey(k secret.Bytes, label string) ([]byte, error) {
	if label == "" {
		return append([]byte(nil), k.Reveal()...), nil
	}
	return subkey(k, label)
}

func newGCM(raw []byte) (cipher.AEAD, error) {
	blk, err := aes.NewCipher(raw)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

// MAC is HMAC-SHA256 over the parts under the labelled subkey of the newest key
// of the domain. Each part carries a 4-byte length prefix, so moving a byte from
// one field to the next changes the MAC (8.2).
//
// It panics when the domain is not loaded, is not a labeled domain (labels.go ModeOf: the key of a
// sealed domain is an AES key and is never a MAC root), or the label is not registered for MACs
// (labels.go PrimitiveOf; a seal label would key two primitives with one subkey). A MAC that
// returned an empty result would be accepted as the hash of nothing, and
// Require at start-up makes this a programming error, not a runtime condition.
// The panic text names the domain, which is not a secret.
func (r *Ring) MAC(domain, label string, parts ...[]byte) []byte {
	dk := r.domains[domain]
	if dk == nil || !labelFor(label, MACOnly) || !modeAllowsLabel(domain, label) {
		panic("keyring: MAC with an unloaded domain, a domain that is not labeled or a label not registered for MACs: " + domain)
	}
	return macWith(dk.newest.k, label, parts)
}

// macWith is the HMAC of MAC under one key.
func macWith(k secret.Bytes, label string, parts [][]byte) []byte {
	sub, err := subkey(k, label)
	if err != nil {
		panic("keyring: cannot derive a subkey for a MAC")
	}
	defer clear(sub)
	m := hmac.New(sha256.New, sub)
	var n [4]byte
	for _, p := range parts {
		binary.BigEndian.PutUint32(n[:], uint32(len(p)))
		m.Write(n[:])
		m.Write(p)
	}
	return m.Sum(nil)
}

// VerifyMAC reports whether tag is the start of the MAC of the parts under the
// labelled subkey of any key the domain holds, not only the newest. A value
// made before a key rotation therefore stays good for as long as its old key is
// loaded, and stops being good when that key is removed. tag may be a
// truncation (8 bytes at least); that is the caller's choice. The comparison is
// constant time, and a domain that is not loaded verifies nothing.
func (r *Ring) VerifyMAC(domain, label string, tag []byte, parts ...[]byte) bool {
	dk := r.domains[domain]
	if dk == nil || !labelFor(label, MACOnly) || !modeAllowsLabel(domain, label) || len(tag) < 8 || len(tag) > sha256.Size {
		return false
	}
	ok := false
	for _, k := range dk.byNum {
		if hmac.Equal(macWith(k.k, label, parts)[:len(tag)], tag) {
			ok = true
		}
	}
	return ok
}

// KeyNumber reads the key number from bytes 3-4 of a ciphertext, for
// "ctrlz-admin keys status" (8.4). It checks nothing else.
func KeyNumber(ct []byte) (uint16, bool) {
	if len(ct) < headerLen || ct[0] != magic0 || ct[1] != magic1 || ct[2] != formatVersion {
		return 0, false
	}
	return binary.BigEndian.Uint16(ct[3:5]), true
}

// DomainName is a key domain as a closed string for a log line, which may carry only
// members of a closed set (rule closed-values-in-logs). The domain names are code,
// not data; Valid is the registry.
type DomainName string

// Valid reports whether d is a defined domain.
func (d DomainName) Valid() bool { return ValidDomain(string(d)) }

// LoadedNames is Loaded as DomainNames.
func (r *Ring) LoadedNames() []DomainName {
	loaded := r.Loaded()
	out := make([]DomainName, len(loaded))
	for i, d := range loaded {
		out[i] = DomainName(d)
	}
	return out
}
