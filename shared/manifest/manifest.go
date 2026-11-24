// Package manifest checks signed envelopes and bundle contents (contract 13).
//
// The rule that shapes everything here: a signature is verified before the
// payload is decompressed or parsed. Parsing attacker-controlled bytes first
// and checking the signature afterwards is how signed-update systems get
// exploited, so Verify returns the payload only after the signature passes.
package manifest

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"strings"

	"google.golang.org/protobuf/proto"

	signv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/sign/v1"
)

const (
	// MaxEnvelope is the size cap for a manifest, delegation or head (4 MiB).
	MaxEnvelope = 4 << 20
	// MaxFileSize caps one bundle file; MaxBundleFiles the file count.
	MaxFileSize    = 4 << 30
	MaxBundleFiles = 100_000
	MaxPathLen     = 255

	// MaxSignatures caps the signatures one envelope may carry. Each signature
	// of an allowed key id costs one Ed25519 verification over the whole payload
	// (up to 4 MiB), so without a cap one envelope could repeat a bad signature
	// thousands of times and pin a core for minutes. A root rotation carries the
	// signatures of two key sets, which is why the bound is a constant and not
	// the size of one grant.
	MaxSignatures = 64

	signContext = "ctrlz-sign-v1\x00"
)

var (
	ErrTooLarge     = errors.New("manifest: envelope too large")
	ErrRootExpired  = errors.New("manifest: root expired")
	ErrNoRole       = errors.New("manifest: role not granted by the root")
	ErrRoleExpired  = errors.New("manifest: role delegation expired")
	ErrThreshold    = errors.New("manifest: not enough valid signatures")
	ErrBadRoot      = errors.New("manifest: malformed root")
	ErrBadPath      = errors.New("manifest: unsafe bundle path")
	ErrNotRegular   = errors.New("manifest: bundle entry is not a regular file")
	ErrNotListed    = errors.New("manifest: file is not listed in the manifest")
	ErrSizeMismatch = errors.New("manifest: file size differs from the manifest")
	ErrBadManifest  = errors.New("manifest: malformed manifest")
	ErrNoExpiry     = errors.New("manifest: root or delegation without an expiry")

	ErrTooManySignatures = errors.New("manifest: more signatures than keys that could sign")
)

// SigningInput is what a signature covers:
// "ctrlz-sign-v1\0" + big-endian u64 length of payload_type + payload_type + payload.
// The length prefix makes the split between type and payload unambiguous, so a
// signature over one (type, payload) pair can never be replayed as another.
func SigningInput(payloadType string, payload []byte) []byte {
	out := make([]byte, 0, len(signContext)+8+len(payloadType)+len(payload))
	out = append(out, signContext...)
	out = binary.BigEndian.AppendUint64(out, uint64(len(payloadType)))
	out = append(out, payloadType...)
	return append(out, payload...)
}

// Payload types. Each names exactly one kind of payload, and PayloadType is
// inside the signed bytes (SigningInput), so a signature over one type cannot
// be replayed as another. RoleFor binds each type to the one role allowed to
// sign it; Verify refuses everything else.
const (
	// TypeHead is a SignedHead, signed by the policy role.
	TypeHead = "ctrlz/head"
	// TypePairTable is a PairTable, signed by the policy role.
	TypePairTable = "ctrlz/pair-table"
	// TypeRoot is a Root, signed by the offline root keys (VerifyRoot).
	TypeRoot = "ctrlz/root"

	typeManifestPrefix = "ctrlz/manifest/"
)

var (
	ErrPayloadType     = errors.New("manifest: unknown payload type")
	ErrRoleMismatch    = errors.New("manifest: role may not sign this payload type")
	ErrManifestExpired = errors.New("manifest: manifest expired")
	ErrRollback        = errors.New("manifest: version lower than the highest seen")
	ErrBelowMinVersion = errors.New("manifest: rollback target below min_version")
	ErrRootVersion     = errors.New("manifest: new root version is not the old version plus one")
	ErrKindMismatch    = errors.New("manifest: kind differs from the payload type")
	ErrRootNotCoSigned = errors.New("manifest: new root is not signed by its own keys")
	ErrUnsignableRoot  = errors.New("manifest: new root has fewer offline keys than its threshold")
)

// ManifestPayloadType is the payload type of a Manifest of the given kind.
func ManifestPayloadType(k signv1.Kind) string {
	return typeManifestPrefix + strings.ToLower(strings.TrimPrefix(k.String(), "KIND_"))
}

// catalogKind reports whether a kind is data the online catalog key may sign:
// filters, geoip, services, dnsroot, certs (contract 13). Every other kind is
// code or images and verifies only against the offline bundle keys.
func catalogKind(k signv1.Kind) bool {
	switch k {
	case signv1.Kind_KIND_FILTERS, signv1.Kind_KIND_GEOIP, signv1.Kind_KIND_SERVICES, signv1.Kind_KIND_DNSROOT, signv1.Kind_KIND_CERTS:
		return true
	}
	return false
}

// RoleFor returns the one role allowed to sign a payload type. The table is
// built from the Kind enum, so a new kind cannot be left out by accident: it
// defaults to the offline bundle role, which is the safe side.
func RoleFor(payloadType string) (signv1.Role, bool) {
	switch payloadType {
	case TypeHead, TypePairTable:
		return signv1.Role_ROLE_POLICY, true
	}
	for n := range signv1.Kind_name {
		k := signv1.Kind(n)
		if k == signv1.Kind_KIND_UNSPECIFIED {
			continue
		}
		if payloadType == ManifestPayloadType(k) {
			if catalogKind(k) {
				return signv1.Role_ROLE_CATALOG, true
			}
			return signv1.Role_ROLE_BUNDLE, true
		}
	}
	return signv1.Role_ROLE_UNSPECIFIED, false
}

// KeyID is the identifier a Root must give a key: the first 16 bytes of the
// SHA-256 of the raw public key. Deriving it removes the choice, so one key
// cannot appear under two ids and be counted as two signers.
func KeyID(pub []byte) []byte {
	h := sha256.Sum256(pub)
	return h[:16]
}

// DelegationExpired reports whether the root or the role's delegation has
// lapsed at now. Verify ignores expiry for the policy role, because tenant
// policy must keep flowing under the online key and mTLS (contract 13); a
// caller uses this to raise the alert the contract asks for. A root or grant
// with no expiry is malformed and counts as expired.
func DelegationExpired(root *signv1.Root, role signv1.Role, now int64) bool {
	if root == nil || root.ExpiresAt == 0 || now >= root.ExpiresAt {
		return true
	}
	for _, g := range root.Roles {
		if g.Role == role {
			return g.ExpiresAt == 0 || now >= g.ExpiresAt
		}
	}
	return true
}

// Verify checks env against root at time now and returns the payload. The
// caller says what it expects: wantType is the one payload type it is about to
// parse, and role is the role that type belongs to (RoleFor). It counts
// distinct keys of the role's grant with a valid signature; the same key
// signing twice counts once.
//
// Nothing is taken on the envelope's word. env.PayloadType must equal wantType,
// so a PairTable (signed by the same policy key) cannot be presented where a
// SignedHead is expected, and wantType must belong to role, so passing the
// online policy role for a node-binary manifest fails here instead of
// accepting code signed by the online key. An expired root or delegation
// blocks every role except policy.
//
// A root with no expiry (expires_at 0), a grant with no expiry, a key whose id
// is not KeyID of its public key, or the same public key listed twice is
// malformed: "never expires" is not a value an offline root may have.
func Verify(env *signv1.Envelope, root *signv1.Root, role signv1.Role, wantType string, now int64) ([]byte, error) {
	return verify(env, root, role, wantType, now, ed25519.Verify)
}

// sigCheck is the signature primitive. Verify passes ed25519.Verify; a test
// passes a counting wrapper to prove how many verifications an envelope costs.
type sigCheck func(pub ed25519.PublicKey, msg, sig []byte) bool

func verify(env *signv1.Envelope, root *signv1.Root, role signv1.Role, wantType string, now int64, check sigCheck) ([]byte, error) {
	if env == nil || root == nil {
		return nil, ErrBadRoot
	}
	if len(env.Payload) > MaxEnvelope {
		return nil, ErrTooLarge
	}
	if len(env.Signatures) > MaxSignatures {
		return nil, ErrTooManySignatures
	}
	want, ok := RoleFor(wantType)
	if !ok {
		return nil, ErrPayloadType
	}
	if want != role {
		return nil, ErrRoleMismatch
	}
	if env.PayloadType != wantType {
		return nil, ErrPayloadType
	}
	if root.ExpiresAt == 0 {
		return nil, ErrNoExpiry
	}
	if role != signv1.Role_ROLE_POLICY && now >= root.ExpiresAt {
		return nil, ErrRootExpired
	}
	var grant *signv1.RoleGrant
	for _, g := range root.Roles {
		if g.Role == role {
			grant = g
			break
		}
	}
	if grant == nil || grant.Threshold == 0 {
		return nil, ErrNoRole
	}
	if grant.ExpiresAt == 0 {
		return nil, ErrNoExpiry
	}
	if role != signv1.Role_ROLE_POLICY && now >= grant.ExpiresAt {
		return nil, ErrRoleExpired
	}
	pub, err := keyMap(root)
	if err != nil {
		return nil, err
	}
	// A root that reached this node some other way than VerifyRoot is still
	// held to the same key rules, so a bundle grant cannot hold an online key.
	if _, err := rootSigners(root, pub); err != nil {
		return nil, err
	}
	allowed := map[string]bool{}
	for _, id := range grant.KeyIds {
		if _, ok := pub[string(id)]; !ok {
			return nil, ErrBadRoot
		}
		allowed[string(id)] = true
	}
	// No honest envelope has more signatures than the grant has keys; refusing
	// it before the first verification is what bounds the work.
	if len(env.Signatures) > len(allowed) {
		return nil, ErrTooManySignatures
	}
	if n := countValid(env, pub, allowed, check); n < grant.Threshold {
		return nil, fmt.Errorf("%w: %d of %d", ErrThreshold, n, grant.Threshold)
	}
	return env.Payload, nil
}

func keyMap(root *signv1.Root) (map[string]ed25519.PublicKey, error) {
	pub := map[string]ed25519.PublicKey{}
	seenKey := map[string]bool{}
	for _, k := range root.Keys {
		if len(k.Ed25519) != ed25519.PublicKeySize || !bytes.Equal(k.KeyId, KeyID(k.Ed25519)) {
			return nil, ErrBadRoot
		}
		// The derived id makes a repeated key a repeated id; both are refused,
		// so the threshold counts people with keys, not entries in a list.
		if _, dup := pub[string(k.KeyId)]; dup || seenKey[string(k.Ed25519)] {
			return nil, ErrBadRoot
		}
		seenKey[string(k.Ed25519)] = true
		pub[string(k.KeyId)] = k.Ed25519
	}
	return pub, nil
}

// countValid counts distinct allowed keys with a valid signature over env. A
// key id is marked tried before its signature is checked, so each id costs at
// most one verification whatever the envelope repeats.
func countValid(env *signv1.Envelope, pub map[string]ed25519.PublicKey, allowed map[string]bool, check sigCheck) uint32 {
	msg := SigningInput(env.PayloadType, env.Payload)
	tried := map[string]bool{}
	var valid uint32
	for _, s := range env.Signatures {
		id := string(s.KeyId)
		if !allowed[id] || tried[id] || len(s.Sig) != ed25519.SignatureSize {
			continue
		}
		tried[id] = true
		if check(pub[id], msg, s.Sig) {
			valid++
		}
	}
	return valid
}

// rootSigners returns the keys that may sign a Root: exactly Root.root_key_ids.
// They are named, not derived from the grants, because a derivation by
// exclusion turns every key that is not in an online grant into a root signer:
// a bundle key, or an online key that was retired from its role but left in
// keys. The root is malformed when a root key is also granted to an online
// role, when a bundle grant holds a key that is not a root key (bundle kinds
// verify only against offline keys, contract 13), or when root_key_ids names
// a key that is not in keys or lists one twice.
func rootSigners(root *signv1.Root, pub map[string]ed25519.PublicKey) (map[string]bool, error) {
	signers := make(map[string]bool, len(root.RootKeyIds))
	for _, id := range root.RootKeyIds {
		if _, ok := pub[string(id)]; !ok || signers[string(id)] {
			return nil, ErrBadRoot
		}
		signers[string(id)] = true
	}
	for _, g := range root.Roles {
		// verifyRoot compares a grant's threshold with len(KeyIds), but a key
		// signs once, so a repeated id makes the threshold look reachable when
		// no set of signers can meet it. Refuse it here, where Verify agrees.
		seen := make(map[string]bool, len(g.KeyIds))
		for _, id := range g.KeyIds {
			if seen[string(id)] {
				return nil, ErrBadRoot
			}
			seen[string(id)] = true
			switch g.Role {
			case signv1.Role_ROLE_POLICY, signv1.Role_ROLE_CATALOG:
				if signers[string(id)] {
					return nil, ErrBadRoot
				}
			case signv1.Role_ROLE_BUNDLE:
				if !signers[string(id)] {
					return nil, ErrBadRoot
				}
			}
		}
	}
	return signers, nil
}

// VerifyRoot checks a new Root envelope against the trusted old root and
// returns the new root (contract 13: a new root is signed by the old one).
//
// The envelope must carry TypeRoot, meet the old root's threshold with the
// old root's root_key_ids, and also meet the new root's own threshold with the
// new root's root_key_ids, so a typo in the new key set cannot lock the root
// out for good. Its version must be exactly old+1. The old root's expiry is
// deliberately not checked: rotation is how an expired root is replaced.
func VerifyRoot(env *signv1.Envelope, old *signv1.Root) (*signv1.Root, error) {
	return verifyRoot(env, old, ed25519.Verify)
}

func verifyRoot(env *signv1.Envelope, old *signv1.Root, check sigCheck) (*signv1.Root, error) {
	if env == nil || old == nil {
		return nil, ErrBadRoot
	}
	if len(env.Payload) > MaxEnvelope {
		return nil, ErrTooLarge
	}
	if len(env.Signatures) > MaxSignatures {
		return nil, ErrTooManySignatures
	}
	if env.PayloadType != TypeRoot {
		return nil, ErrPayloadType
	}
	oldPub, err := keyMap(old)
	if err != nil {
		return nil, err
	}
	oldSigners, err := rootSigners(old, oldPub)
	if err != nil {
		return nil, err
	}
	if old.Threshold == 0 {
		return nil, ErrBadRoot
	}
	if n := countValid(env, oldPub, oldSigners, check); n < old.Threshold {
		return nil, fmt.Errorf("%w: %d of %d", ErrThreshold, n, old.Threshold)
	}
	// Only now is the payload parsed.
	next := &signv1.Root{}
	if err := proto.Unmarshal(env.Payload, next); err != nil {
		return nil, ErrBadRoot
	}
	if next.Version != old.Version+1 {
		return nil, ErrRootVersion
	}
	newPub, err := keyMap(next)
	if err != nil {
		return nil, err
	}
	if next.Threshold == 0 {
		return nil, ErrBadRoot
	}
	if next.ExpiresAt == 0 {
		return nil, ErrNoExpiry
	}
	for _, g := range next.Roles {
		if g.Threshold == 0 || int(g.Threshold) > len(g.KeyIds) {
			return nil, ErrBadRoot
		}
		if g.ExpiresAt == 0 {
			return nil, ErrNoExpiry
		}
		for _, id := range g.KeyIds {
			if _, ok := newPub[string(id)]; !ok {
				return nil, ErrBadRoot
			}
		}
	}
	offline, err := rootSigners(next, newPub)
	if err != nil {
		return nil, err
	}
	if uint32(len(offline)) < next.Threshold {
		return nil, ErrUnsignableRoot
	}
	if n := countValid(env, newPub, offline, check); n < next.Threshold {
		return nil, fmt.Errorf("%w: %d of %d", ErrRootNotCoSigned, n, next.Threshold)
	}
	return next, nil
}

// VerifyManifest verifies a manifest envelope of the kind the caller is about
// to install and returns the parsed manifest. The role comes from the kind,
// never from the caller. The payload is parsed only after the signature
// passes, and the kind inside must match the kind in the payload type, so a
// signature for one kind cannot install another.
func VerifyManifest(env *signv1.Envelope, root *signv1.Root, kind signv1.Kind, now int64) (*signv1.Manifest, error) {
	if env == nil {
		return nil, ErrBadRoot
	}
	wantType := ManifestPayloadType(kind)
	role, ok := RoleFor(wantType)
	if !ok || !strings.HasPrefix(wantType, typeManifestPrefix) {
		return nil, ErrPayloadType
	}
	payload, err := Verify(env, root, role, wantType, now)
	if err != nil {
		return nil, err
	}
	m := &signv1.Manifest{}
	if err := proto.Unmarshal(payload, m); err != nil {
		return nil, ErrBadManifest
	}
	if m.Kind != kind {
		return nil, ErrKindMismatch
	}
	if err := CheckManifest(m); err != nil {
		return nil, err
	}
	return m, nil
}

// CheckManifestFresh is the freshness and anti-rollback check of contract 13.
// highestSeen is the highest version the node has persisted for m.Kind. A
// replayed old, validly signed manifest fails here, because a signature says
// nothing about whether the manifest is still current.
func CheckManifestFresh(m *signv1.Manifest, now int64, highestSeen uint64) error {
	if m == nil || m.MinVersion > m.Version {
		return ErrBadManifest
	}
	if m.ExpiresAt != 0 && now >= m.ExpiresAt {
		return ErrManifestExpired
	}
	if m.Version < highestSeen {
		return ErrRollback
	}
	return nil
}

// CheckRollbackTarget is the check for an automatic rollback from the current
// manifest: it may go back, but never below the current min_version.
func CheckRollbackTarget(current *signv1.Manifest, target uint64) error {
	if current == nil {
		return ErrBadManifest
	}
	if target < current.MinVersion {
		return ErrBelowMinVersion
	}
	return nil
}

// CheckPath refuses a bundle path that could escape its directory or name
// something other than a plain file on Windows: empty, absolute (including
// Windows drive and UNC forms), containing "..", a backslash, a NUL, a colon
// anywhere (an NTFS alternate data stream is "file:stream"), an empty element,
// an element that Windows would rename (a trailing dot or space) or that is a
// reserved device name (CON, PRN, AUX, NUL, COM1-9, LPT1-9, with or without an
// extension), or longer than 255 bytes.
func CheckPath(p string) error {
	if p == "" || len(p) > MaxPathLen {
		return ErrBadPath
	}
	if strings.ContainsAny(p, "\\\x00:") || strings.HasPrefix(p, "/") {
		return ErrBadPath
	}
	for _, el := range strings.Split(p, "/") {
		if el == "" || el == "." || el == ".." {
			return ErrBadPath
		}
		if last := el[len(el)-1]; last == '.' || last == ' ' {
			return ErrBadPath
		}
		if reservedDeviceName(el) {
			return ErrBadPath
		}
	}
	return nil
}

// reservedDeviceName reports whether a path element is a DOS device name. On
// Windows "con", "CON.txt" and "con.tar.gz" all open the console.
func reservedDeviceName(el string) bool {
	stem := el
	if i := strings.IndexByte(stem, '.'); i >= 0 {
		stem = stem[:i]
	}
	stem = strings.ToLower(strings.TrimRight(stem, " "))
	switch stem {
	case "con", "prn", "aux", "nul":
		return true
	}
	if len(stem) == 4 && (strings.HasPrefix(stem, "com") || strings.HasPrefix(stem, "lpt")) && stem[3] >= '1' && stem[3] <= '9' {
		return true
	}
	return false
}

// CheckManifest validates the file list of a manifest: every path safe and
// unique (also under case folding, so two paths cannot collide on Windows),
// every hash 32 bytes, sizes within the cap.
func CheckManifest(m *signv1.Manifest) error {
	if m == nil || len(m.Files) > MaxBundleFiles {
		return ErrBadManifest
	}
	seen := map[string]bool{}
	for _, f := range m.Files {
		if err := CheckPath(f.Path); err != nil {
			return err
		}
		if len(f.Sha256) != 32 || f.Size > MaxFileSize {
			return ErrBadManifest
		}
		k := strings.ToLower(f.Path)
		if seen[k] {
			return ErrBadManifest
		}
		seen[k] = true
	}
	return nil
}

// Index is a manifest's file list keyed by path, built once per archive. A
// linear scan per entry would cost up to MaxBundleFiles squared comparisons, and
// a large validly signed bundle would pin the CPU of every node installing it.
type Index struct {
	files map[string]*signv1.FileEntry
}

// NewIndex checks the manifest (CheckManifest) and indexes its files.
func NewIndex(m *signv1.Manifest) (*Index, error) {
	if err := CheckManifest(m); err != nil {
		return nil, err
	}
	ix := &Index{files: make(map[string]*signv1.FileEntry, len(m.Files))}
	for _, f := range m.Files {
		ix.files[f.Path] = f
	}
	return ix, nil
}

// CheckEntry is the per-entry check while unpacking an archive: the path is
// safe, the entry is a regular file (no symlink, device, pipe or directory
// trick), it is listed in the manifest, and its size matches.
func (ix *Index) CheckEntry(path string, mode fs.FileMode, size uint64) error {
	if err := CheckPath(path); err != nil {
		return err
	}
	if !mode.IsRegular() {
		return ErrNotRegular
	}
	f, ok := ix.files[path]
	if !ok {
		return ErrNotListed
	}
	if f.Size != size {
		return ErrSizeMismatch
	}
	return nil
}
