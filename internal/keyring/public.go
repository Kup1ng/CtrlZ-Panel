package keyring

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"

	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
)

// Public key files (spec 8.3, D67):
//
//	# ctrlz public keys domain=invite_sign
//	1 <base64url of the 32 byte Ed25519 public key>
//
// The file belongs to the process that only checks signatures: the api. It is a pure function of the key
// file of the signing domain, so `ctrlz keys derive` can always rebuild it, and it holds no secret, which is
// the point: a compromised api can open invite links and cannot make one.

const (
	publicHeaderFm = "# ctrlz public keys domain="
	publicPre      = "pub_"
)

// PublicFileName is the name of the public key file of a signing domain inside the key directory, which is
// also the Docker secret name.
func PublicFileName(domain string) string { return publicPre + domain }

// PublicDomains lists the domains that have a public half.
func PublicDomains() []string { return []string{DomainInviteSign} }

// PublicRing holds the public keys of one signing domain by number. It is immutable and safe for
// concurrent use. It has one method that matters, Verify, and no way to produce a signature.
type PublicRing struct {
	domain string
	label  string
	byNum  map[uint16]ed25519.PublicKey
}

// publicKeyOf derives the public key of one key of a signing domain, wiping the seed.
func publicKeyOf(k secret.Bytes, label string) (ed25519.PublicKey, error) {
	seed, err := subkey(k, label)
	if err != nil {
		return nil, errors.New("keyring: cannot derive a public key")
	}
	defer clear(seed)
	priv := ed25519.NewKeyFromSeed(seed)
	defer clear(priv)
	return append(ed25519.PublicKey(nil), priv.Public().(ed25519.PublicKey)...), nil
}

// Public is the public ring of a signing domain this ring holds, for tests and the "test" environment of the
// app, where one process holds both halves. Production reads the file (LoadPublic).
func (r *Ring) Public(domain string) (*PublicRing, error) {
	label, ok := SigningLabel(domain)
	if !ok {
		return nil, fmt.Errorf("keyring: domain %s has no public half", domain)
	}
	dk := r.domains[domain]
	if dk == nil {
		return nil, fmt.Errorf("%w: %s", ErrNotLoaded, domain)
	}
	p := &PublicRing{domain: domain, label: label, byNum: make(map[uint16]ed25519.PublicKey, len(dk.byNum))}
	for n, k := range dk.byNum {
		pub, err := publicKeyOf(k.k, label)
		if err != nil {
			return nil, err
		}
		p.byNum[n] = pub
	}
	return p, nil
}

// PublicText renders the public key file of a signing domain from the text of its key file. The result is no
// secret, but the input is, so the caller wipes it as it does for every key file.
func PublicText(domain string, keyFileText secret.Bytes) ([]byte, error) {
	label, ok := SigningLabel(domain)
	if !ok {
		return nil, fmt.Errorf("keyring: domain %s has no public half", domain)
	}
	keys, err := parseFile(domain, keyFileText)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	buf.WriteString(publicHeaderFm + domain + "\n")
	for _, k := range keys { // parseFile sorts ascending
		pub, err := publicKeyOf(k.k, label)
		k.k.Wipe()
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(&buf, "%d %s\n", k.n, base64.RawURLEncoding.EncodeToString(pub))
	}
	return buf.Bytes(), nil
}

// parsePublic reads the text of a public key file with the strictness of a key file: the header names the
// domain, a number is 1 to 65535 with no leading zero and appears once, and a key is base64url of 32 bytes.
// Errors name the line and the problem, never the key.
func parsePublic(domain string, text []byte) (map[uint16]ed25519.PublicKey, error) {
	out := make(map[uint16]ed25519.PublicKey)
	sawHeader := false
	fail := func(line int, why string) (map[uint16]ed25519.PublicKey, error) {
		return nil, fmt.Errorf("keyring: public keys of %s: line %d: %s", domain, line, why)
	}
	for i, ln := range bytes.Split(text, []byte("\n")) {
		line := i + 1
		ln = bytes.TrimSpace(ln)
		if len(ln) == 0 {
			continue
		}
		if ln[0] == '#' {
			if !sawHeader {
				if !bytes.HasPrefix(ln, []byte(publicHeaderFm)) {
					return fail(line, "the first line must be the ctrlz public keys header")
				}
				if string(bytes.TrimSpace(ln[len(publicHeaderFm):])) != domain {
					return fail(line, "the header names another domain")
				}
				sawHeader = true
			}
			continue
		}
		if !sawHeader {
			return fail(line, "the first line must be the ctrlz public keys header")
		}
		num, enc, ok := bytes.Cut(ln, []byte(" "))
		if !ok {
			return fail(line, "expected a number and a key")
		}
		n, err := strconv.ParseUint(string(num), 10, 16)
		if err != nil || n == 0 || (len(num) > 1 && num[0] == '0') {
			return fail(line, "the key number must be 1 to 65535 with no leading zero")
		}
		if _, dup := out[uint16(n)]; dup {
			return fail(line, "the key number appears twice")
		}
		raw := make([]byte, base64.RawURLEncoding.DecodedLen(len(bytes.TrimSpace(enc))))
		got, err := base64.RawURLEncoding.Decode(raw, bytes.TrimSpace(enc))
		if err != nil || got != ed25519.PublicKeySize {
			return fail(line, "the key must be base64url of exactly 32 bytes")
		}
		out[uint16(n)] = ed25519.PublicKey(raw[:got])
	}
	if !sawHeader {
		return fail(1, "no ctrlz public keys header")
	}
	if len(out) == 0 {
		return fail(1, "no keys")
	}
	return out, nil
}

// LoadPublic reads pub_<domain> from dir. A missing or malformed file stops the start-up and the error names
// the domain and the problem.
func LoadPublic(dir, domain string) (*PublicRing, error) {
	label, ok := SigningLabel(domain)
	if !ok {
		return nil, fmt.Errorf("keyring: domain %s has no public half", domain)
	}
	text, err := os.ReadFile(filepath.Join(dir, PublicFileName(domain)))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("keyring: domain %s: public key file %s is missing", domain, PublicFileName(domain))
		}
		return nil, fmt.Errorf("keyring: domain %s: public key file %s cannot be read", domain, PublicFileName(domain))
	}
	keys, err := parsePublic(domain, text)
	if err != nil {
		return nil, err
	}
	return &PublicRing{domain: domain, label: label, byNum: keys}, nil
}

// Numbers lists the key numbers the ring holds, ascending, for status output.
func (p *PublicRing) Numbers() []uint16 {
	out := make([]uint16, 0, len(p.byNum))
	for n := range p.byNum {
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Verify reports whether sig is the signature of msg under the one key the number names. An unknown number, a
// label that is not the domain's, a signature of the wrong length and a wrong signature are all false, and the
// answer carries nothing else. Only the key the number names is tried: a signature that opened under any key
// would let an old line that was removed from the file keep working through a newer number.
func (p *PublicRing) Verify(label string, n uint16, msg, sig []byte) bool {
	if p == nil || label != p.label || len(sig) != ed25519.SignatureSize {
		return false
	}
	pub, ok := p.byNum[n]
	if !ok {
		return false
	}
	return ed25519.Verify(pub, msg, sig)
}
