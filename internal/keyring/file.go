package keyring

import (
	"bytes"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
)

// Key files (spec 8.1):
//
//	# ctrlz keyring domain=user_totp
//	1 <base64url of 32 bytes>
//	2 <base64url of 32 bytes>
//
// The header names the domain so that a file copied to the wrong secret name is
// refused at start. Other lines starting with # are comments.

const (
	rootLen  = 32
	kdfSalt  = "ctrlz-kek-v1"
	headerFm = "# ctrlz keyring domain="
	filePre  = "kek_"
)

// ErrRootMismatch is returned by Rotate when a number in the key file is not the
// key that kek_root derives for it.
var ErrRootMismatch = errors.New("keyring: kek_root does not match the key file")

// RootFileName is the host-only root. It is never mounted into a container.
const RootFileName = "kek_root"

// FileName is the name of a domain's key file inside the key directory, which
// is also the Docker secret name.
func FileName(domain string) string { return filePre + domain }

// deriveKey is key(domain, n) = HKDF-SHA256(ikm = root, salt = "ctrlz-kek-v1",
// info = domain || 0x00 || n, L = 32). n is two bytes, big endian, the width
// the ciphertext header gives it.
func deriveKey(root secret.Bytes, domain string, n uint16) (secret.Bytes, error) {
	if root.Len() != rootLen {
		return secret.Bytes{}, errors.New("keyring: root is not 32 bytes")
	}
	if !ValidDomain(domain) {
		return secret.Bytes{}, fmt.Errorf("keyring: unknown domain %q", domain)
	}
	if n == 0 {
		return secret.Bytes{}, errors.New("keyring: key numbers start at 1")
	}
	var num [2]byte
	binary.BigEndian.PutUint16(num[:], n)
	k, err := hkdf.Key(sha256.New, root.Reveal(), []byte(kdfSalt), domain+"\x00"+string(num[:]), keyLen)
	if err != nil {
		return secret.Bytes{}, errors.New("keyring: derivation failed")
	}
	s := secret.NewBytes(k)
	clear(k)
	return s, nil
}

// LoadRoot reads the host-only root: exactly 32 raw bytes.
func LoadRoot(path string) (secret.Bytes, error) {
	b, err := secret.BytesFromFile(path)
	if err != nil {
		return secret.Bytes{}, err
	}
	if b.Len() != rootLen {
		b.Wipe()
		return secret.Bytes{}, fmt.Errorf("keyring: root %s is not %d bytes", filepath.Base(path), rootLen)
	}
	return b, nil
}

// FromRoot builds a Ring straight from a root and key numbers, with no files.
// Tests use it to stage a rotation; production reads files.
func FromRoot(root secret.Bytes, numbers map[string][]uint16) (*Ring, error) {
	keys := make(map[string][]key, len(numbers))
	for d, ns := range numbers {
		for _, n := range ns {
			k, err := deriveKey(root, d, n)
			if err != nil {
				return nil, err
			}
			keys[d] = append(keys[d], key{n: n, k: k})
		}
	}
	return newRing(keys)
}

// FileText renders the key file of a domain with the given numbers, derived from
// the root. The result is secret.Bytes: it holds key material, and "ctrlz keys
// derive" writes it to a file and never prints it.
func FileText(root secret.Bytes, domain string, numbers ...uint16) (secret.Bytes, error) {
	if len(numbers) == 0 {
		return secret.Bytes{}, errors.New("keyring: no key numbers")
	}
	var buf bytes.Buffer
	buf.WriteString(headerFm + domain + "\n")
	for _, n := range numbers {
		k, err := deriveKey(root, domain, n)
		if err != nil {
			clear(buf.Bytes())
			return secret.Bytes{}, err
		}
		fmt.Fprintf(&buf, "%d %s\n", n, base64.RawURLEncoding.EncodeToString(k.Reveal()))
		k.Wipe()
	}
	s := secret.NewBytes(buf.Bytes())
	clear(buf.Bytes())
	return s, nil
}

// Provenance is what a root proves about a key file, one line at a time: the
// line for number N is either the key this root derives for N or it is not. It is
// the only way a key tool learns which root a file came from (review round 5, rule
// key-identity). A key number says nothing about the root, and neither does a file
// being there or missing: after a total loss the host regenerates the root and the
// files, and number 1 is a different key.
type Provenance struct {
	Domain string
	Lines  []LineProvenance // ascending by number
}

// LineProvenance is one numbered line of a key file.
type LineProvenance struct {
	N        uint16
	FromRoot bool
}

// NewestFromRoot reports whether the highest-numbered line is the key the root
// derives for it. The newest line is the one that encrypts, so it decides whether
// the file belongs to this root. Older lines may come from an earlier root (spec
// 8.5 keeps them readable until their data is re-encrypted).
func (p Provenance) NewestFromRoot() bool {
	return len(p.Lines) > 0 && p.Lines[len(p.Lines)-1].FromRoot
}

// Newest is the highest number in the file.
func (p Provenance) Newest() uint16 {
	if len(p.Lines) == 0 {
		return 0
	}
	return p.Lines[len(p.Lines)-1].N
}

// Foreign lists the numbers whose line is not the root's key for that number.
func (p Provenance) Foreign() []uint16 {
	var out []uint16
	for _, l := range p.Lines {
		if !l.FromRoot {
			out = append(out, l.N)
		}
	}
	return out
}

// Identify derives every number in the key file from the root and compares it in
// constant time with the line. It reads nothing but the file's text and the root,
// so no caller can end up deciding from a number or a path. Errors name the line
// and the problem, never a key.
func Identify(root secret.Bytes, domain string, text secret.Bytes) (Provenance, error) {
	keys, err := parseFile(domain, text)
	if err != nil {
		return Provenance{}, err
	}
	p := Provenance{Domain: domain, Lines: make([]LineProvenance, 0, len(keys))}
	for _, k := range keys {
		want, derr := deriveKey(root, domain, k.n)
		match := derr == nil && subtle.ConstantTimeCompare(want.Reveal(), k.k.Reveal()) == 1
		want.Wipe()
		k.k.Wipe()
		p.Lines = append(p.Lines, LineProvenance{N: k.n, FromRoot: match})
	}
	return p, nil
}

// MismatchError is the refusal for a file the root does not own: it names the
// domain and the numbers, never a key.
func (p Provenance) MismatchError() error {
	var nums []string
	for _, n := range p.Foreign() {
		nums = append(nums, strconv.Itoa(int(n)))
	}
	return fmt.Errorf("%w: domain %s, key %s", ErrRootMismatch, p.Domain, strings.Join(nums, ", "))
}

// Rotate takes the current text of a domain's key file and returns the text
// with number n+1 appended, n being the highest present (8.4 step 1). It
// returns the new number as well, which is what the command prints. The root must
// be the one the file's newest key came from; Identify proves it.
func Rotate(root secret.Bytes, domain string, current secret.Bytes) (secret.Bytes, uint16, error) {
	return rotate(root, domain, current, true)
}

// RotateToNewRoot is Rotate for the one case where the root is not the one the
// file came from on purpose: kek_root was lost and a new one was made (spec
// 8.5). It appends number n+1 derived from the new root and does not require the
// older lines to be the root's, which stay readable until their data is
// re-encrypted and the lines are removed (8.4 step 5).
func RotateToNewRoot(root secret.Bytes, domain string, current secret.Bytes) (secret.Bytes, uint16, error) {
	return rotate(root, domain, current, false)
}

func rotate(root secret.Bytes, domain string, current secret.Bytes, sameRoot bool) (secret.Bytes, uint16, error) {
	prov, err := Identify(root, domain, current)
	if err != nil {
		return secret.Bytes{}, 0, err
	}
	// A root that is not the one the file came from (a wrong backup, or a root remade
	// after the old one was lost) would otherwise append a key that no restore could
	// re-derive. The newest line is the proof: it is the key that encrypts, so a
	// file whose newest line the root derives belongs to it, whatever older lines
	// say. A routine rotation after the one of 8.5 therefore needs no flag.
	if sameRoot && !prov.NewestFromRoot() {
		return secret.Bytes{}, 0, prov.MismatchError()
	}
	top := prov.Newest()
	if top == 65535 {
		return secret.Bytes{}, 0, errors.New("keyring: key numbers are used up")
	}
	next := top + 1
	k, err := deriveKey(root, domain, next)
	if err != nil {
		return secret.Bytes{}, 0, err
	}
	defer k.Wipe()
	var buf bytes.Buffer
	buf.Write(current.Reveal())
	if !bytes.HasSuffix(buf.Bytes(), []byte("\n")) {
		buf.WriteByte('\n')
	}
	fmt.Fprintf(&buf, "%d %s\n", next, base64.RawURLEncoding.EncodeToString(k.Reveal()))
	out := secret.NewBytes(buf.Bytes())
	clear(buf.Bytes())
	return out, next, nil
}

// parseFile reads the text of a key file. Errors say which line is wrong and
// why, never what it holds.
func parseFile(domain string, text secret.Bytes) ([]key, error) {
	var keys []key
	seen := make(map[uint16]bool)
	sawHeader := false
	fail := func(line int, why string) ([]key, error) {
		for _, k := range keys {
			k.k.Wipe()
		}
		return nil, fmt.Errorf("keyring: domain %s: line %d: %s", domain, line, why)
	}
	for i, ln := range bytes.Split(text.Reveal(), []byte("\n")) {
		line := i + 1
		ln = bytes.TrimSpace(ln)
		if len(ln) == 0 {
			continue
		}
		if ln[0] == '#' {
			if !sawHeader {
				if !bytes.HasPrefix(ln, []byte(headerFm)) {
					return fail(line, "the first line must be the ctrlz keyring header")
				}
				if string(bytes.TrimSpace(ln[len(headerFm):])) != domain {
					return fail(line, "the header names another domain")
				}
				sawHeader = true
			}
			continue
		}
		if !sawHeader {
			return fail(line, "the first line must be the ctrlz keyring header")
		}
		num, enc, ok := bytes.Cut(ln, []byte(" "))
		if !ok {
			return fail(line, "expected a number and a key")
		}
		n, err := strconv.ParseUint(string(num), 10, 16)
		if err != nil || n == 0 || (len(num) > 1 && num[0] == '0') {
			return fail(line, "the key number must be 1 to 65535 with no leading zero")
		}
		if seen[uint16(n)] {
			return fail(line, "the key number appears twice")
		}
		enc = bytes.TrimRight(bytes.TrimSpace(enc), "=")
		raw := make([]byte, base64.RawURLEncoding.DecodedLen(len(enc)))
		got, err := base64.RawURLEncoding.Decode(raw, enc)
		if err != nil || got != keyLen {
			clear(raw)
			return fail(line, "the key must be base64url of exactly 32 bytes")
		}
		seen[uint16(n)] = true
		keys = append(keys, key{n: uint16(n), k: secret.NewBytes(raw[:got])})
		clear(raw)
	}
	if !sawHeader {
		return fail(1, "no ctrlz keyring header")
	}
	if len(keys) == 0 {
		return fail(1, "no keys")
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].n < keys[j].n })
	return keys, nil
}

// Load reads the key file of every listed domain from dir (kek_<domain>) and
// builds a Ring. A missing or malformed file stops the start-up, and the error
// names the domain and the problem, never a key (18.3 "Key file missing"). All
// problems are reported together so the operator fixes them in one go.
func Load(dir string, domains ...string) (*Ring, error) {
	keys := make(map[string][]key, len(domains))
	var errs []error
	for _, d := range domains {
		if !ValidDomain(d) {
			errs = append(errs, fmt.Errorf("keyring: unknown domain %q", d))
			continue
		}
		text, err := secret.BytesFromFile(filepath.Join(dir, FileName(d)))
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				errs = append(errs, fmt.Errorf("keyring: domain %s: key file %s is missing", d, FileName(d)))
			} else {
				errs = append(errs, fmt.Errorf("keyring: domain %s: key file %s cannot be read", d, FileName(d)))
			}
			continue
		}
		list, err := parseFile(d, text)
		text.Wipe()
		if err != nil {
			errs = append(errs, err)
			continue
		}
		keys[d] = list
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return newRing(keys)
}
