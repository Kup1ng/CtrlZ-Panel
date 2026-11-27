package appleprofile

import (
	"crypto/sha1" // RFC 9562 UUIDv5 is SHA-1 of namespace and name: an identifier, not a MAC and not a code.
	"errors"
)

// namespace is the fixed UUIDv5 namespace of every Ctrl Z profile identifier,
// a function because the module has no package-level mutable state. It is
// random and never changes: changing it would give every installed profile a
// new identity, so a reinstall would add a second profile and not replace the
// first.
func namespace() [16]byte {
	return [16]byte{
		0x5f, 0x0e, 0x2c, 0x6a, 0x3b, 0x1d, 0x4d, 0x57,
		0x9c, 0x42, 0x8e, 0x7a, 0x1b, 0x6d, 0x4f, 0x93,
	}
}

const identifierPrefix = "com.ctrlz.dns."

// clientMarker sets a client apart from the payload suffixes. "dns" and "root"
// are valid client labels, so joining a client to the Endpoint id with a bare
// dot would make the outer identifier of client "dns" equal the DNS payload of
// the Endpoint's own profile (and "root" its root payload), with the same
// UUIDv5. With the marker the identifiers of the Endpoint profile are base,
// base.dns, base.root and those of a client are base.c.<client> with the same
// suffixes: a client label has no dot, so no name of one profile is a name of
// another. Changing this later would break reinstall-replace, so it is fixed
// now.
const clientMarker = ".c."

// Identity is what makes an installed profile replaceable. It derives from the
// Endpoint id and the client only, never from the resolver_id, the protocol or
// the content, so a profile downloaded again after a rotation, or with another
// protocol, replaces the one on the device (T-247). The Endpoint id is a UUID
// the user already sees in the panel's URLs, and no secret enters it.
type Identity struct {
	// The outer Configuration payload.
	PayloadIdentifier string
	PayloadUUID       string
	// The com.apple.dnsSettings.managed payload inside it.
	ContentIdentifier string
	ContentUUID       string
	// The com.apple.security.root payload of private CA mode (P3 7.3).
	RootIdentifier string
	RootUUID       string
}

// Identify derives the identity of the profile for an Endpoint and a client.
// endpointID must be a lowercase canonical UUID; client is empty or a valid
// client label.
func Identify(endpointID, client string) (Identity, error) {
	if !canonicalUUID(endpointID) {
		return Identity{}, errors.New("appleprofile: the endpoint id is not a lowercase UUID")
	}
	if err := checkClient(client); err != nil {
		return Identity{}, err
	}
	id := identifierPrefix + endpointID
	if client != "" {
		id += clientMarker + client
	}
	return Identity{
		PayloadIdentifier: id,
		PayloadUUID:       uuidV5(namespace(), id),
		ContentIdentifier: id + ".dns",
		ContentUUID:       uuidV5(namespace(), id+".dns"),
		RootIdentifier:    id + ".root",
		RootUUID:          uuidV5(namespace(), id+".root"),
	}, nil
}

// canonicalUUID accepts only the 36-byte lowercase form, so two spellings of
// one id cannot give two identities.
func canonicalUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
				return false
			}
		}
	}
	return true
}

// uuidV5 is RFC 9562 section 5.5: SHA-1 over the namespace and the name, with
// the version and variant bits set, printed in the canonical uppercase form
// Apple tools use for PayloadUUID.
func uuidV5(ns [16]byte, name string) string {
	h := sha1.New()
	h.Write(ns[:])
	h.Write([]byte(name))
	sum := h.Sum(nil)
	var u [16]byte
	copy(u[:], sum[:16])
	u[6] = u[6]&0x0f | 0x50
	u[8] = u[8]&0x3f | 0x80
	const hexd = "0123456789ABCDEF"
	out := make([]byte, 0, 36)
	for i, b := range u {
		if i == 4 || i == 6 || i == 8 || i == 10 {
			out = append(out, '-')
		}
		out = append(out, hexd[b>>4], hexd[b&0xf])
	}
	return string(out)
}

const blockIdentifierPrefix = "com.ctrlz.block."

// BlockRootIdentity is the identity of the Apple profile that installs an account's
// block page root (p4b-proxy 10.3): one com.apple.security.root payload, removable,
// named "Ctrl Z Block Page". It derives from the account hash alone, so a new root
// of the same account (a rotation of block_root_key) replaces the profile on the
// device instead of adding a second one.
type BlockRootIdentity struct {
	// The outer Configuration payload.
	PayloadIdentifier string
	PayloadUUID       string
	// The com.apple.security.root payload inside it.
	RootIdentifier string
	RootUUID       string
}

// IdentifyBlockRoot derives the identity for an account hash of 16 bytes
// (identity.AccountHash). The identifiers are com.ctrlz.block.<hash in lower-case
// hex> and the same with ".root"; the UUIDs are their UUIDv5 in the one namespace of
// this package. The prefix differs from the Endpoint profile's, so the two kinds
// never collide.
func IdentifyBlockRoot(accountHash []byte) (BlockRootIdentity, error) {
	if len(accountHash) != 16 {
		return BlockRootIdentity{}, errors.New("appleprofile: the account hash is not 16 bytes")
	}
	const hexd = "0123456789abcdef"
	hx := make([]byte, 0, 32)
	for _, b := range accountHash {
		hx = append(hx, hexd[b>>4], hexd[b&0xf])
	}
	id := blockIdentifierPrefix + string(hx)
	return BlockRootIdentity{
		PayloadIdentifier: id,
		PayloadUUID:       uuidV5(namespace(), id),
		RootIdentifier:    id + ".root",
		RootUUID:          uuidV5(namespace(), id+".root"),
	}, nil
}
