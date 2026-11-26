package keyring

import (
	"bytes"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
)

// testRoot is a fixed root so that derived keys are the same on every run.
func testRoot() secret.Bytes {
	b := make([]byte, rootLen)
	for i := range b {
		b[i] = byte(i + 1)
	}
	return secret.NewBytes(b)
}

func mustRing(t *testing.T, numbers map[string][]uint16) *Ring {
	t.Helper()
	r, err := FromRoot(testRoot(), numbers)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// TestHKDFVector pins the primitive the whole design rests on to RFC 5869,
// test case 1, for both the extract-and-expand form (key derivation from the
// root) and the expand-only form (labelled subkeys).
func TestHKDFVector(t *testing.T) {
	ikm, _ := hex.DecodeString("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	salt, _ := hex.DecodeString("000102030405060708090a0b0c")
	info, _ := hex.DecodeString("f0f1f2f3f4f5f6f7f8f9")
	wantPRK := "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
	wantOKM := "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"

	prk, err := hkdf.Extract(sha256.New, ikm, salt)
	if err != nil || hex.EncodeToString(prk) != wantPRK {
		t.Fatalf("Extract = %x, %v", prk, err)
	}
	okm, err := hkdf.Expand(sha256.New, prk, string(info), 42)
	if err != nil || hex.EncodeToString(okm) != wantOKM {
		t.Fatalf("Expand = %x, %v", okm, err)
	}
	okm, err = hkdf.Key(sha256.New, ikm, salt, string(info), 42)
	if err != nil || hex.EncodeToString(okm) != wantOKM {
		t.Fatalf("Key = %x, %v", okm, err)
	}
}

// TestDeriveIsPinned fixes the derivation of 8.1 for one root, so a change to
// the salt, the info layout or the number's width fails here. Such a change
// would make every key file on every host derive differently.
func TestDeriveIsPinned(t *testing.T) {
	k, err := deriveKey(testRoot(), DomainUserTOTP, 1)
	if err != nil {
		t.Fatal(err)
	}
	// Independent computation straight from the spec text.
	want, err := hkdf.Key(sha256.New, testRoot().Reveal(), []byte("ctrlz-kek-v1"), "user_totp\x00\x00\x01", 32)
	if err != nil || !bytes.Equal(k.Reveal(), want) {
		t.Fatal("deriveKey does not match HKDF-SHA256(root, salt, domain || 0 || n)")
	}
	for _, other := range []struct {
		d string
		n uint16
	}{{DomainUserTOTP, 2}, {DomainAdminTOTP, 1}} {
		o, _ := deriveKey(testRoot(), other.d, other.n)
		if bytes.Equal(k.Reveal(), o.Reveal()) {
			t.Errorf("(%s,%d) derives the same key as (user_totp,1)", other.d, other.n)
		}
	}
	if _, err := deriveKey(testRoot(), "nope", 1); err == nil {
		t.Error("unknown domain")
	}
	if _, err := deriveKey(testRoot(), DomainUserTOTP, 0); err == nil {
		t.Error("key number 0")
	}
	if _, err := deriveKey(secret.NewBytes([]byte("short")), DomainUserTOTP, 1); err == nil {
		t.Error("short root")
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	r := mustRing(t, map[string][]uint16{DomainUserTOTP: {1}})
	aad := tc("tenant-user")
	ct, err := r.Seal(DomainUserTOTP, aad, []byte("seed-bytes"))
	if err != nil {
		t.Fatal(err)
	}
	if ct[0] != 'C' || ct[1] != 'Z' || ct[2] != 1 || ct[3] != 0 || ct[4] != 1 {
		t.Errorf("header = % x, want CZ 01 0001", ct[:5])
	}
	if len(ct) != 5+12+len("seed-bytes")+16 {
		t.Errorf("length %d", len(ct))
	}
	got, err := r.Open(DomainUserTOTP, aad, ct)
	if err != nil || string(got.Reveal()) != "seed-bytes" {
		t.Fatalf("Open = %v", err)
	}
	// Two seals of one plaintext differ: the nonce is random.
	ct2, _ := r.Seal(DomainUserTOTP, aad, []byte("seed-bytes"))
	if bytes.Equal(ct, ct2) {
		t.Error("nonce reuse: identical ciphertexts")
	}
	if n, ok := KeyNumber(ct); !ok || n != 1 {
		t.Errorf("KeyNumber = %d, %v", n, ok)
	}
	if _, ok := KeyNumber([]byte("xx")); ok {
		t.Error("KeyNumber accepted garbage")
	}
	// Empty plaintext is legal (a zero-length payload still authenticates).
	ct, err = r.Seal(DomainUserTOTP, aad, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := r.Open(DomainUserTOTP, aad, ct); err != nil || got.Len() != 0 {
		t.Errorf("empty round trip: %v", err)
	}
}

// TestOpenFailsTheSameWay: every way to fail is one error value with no detail.
func TestOpenFailsTheSameWay(t *testing.T) {
	r := mustRing(t, map[string][]uint16{DomainUserTOTP: {1}, DomainSMSCred: {1}})
	other := mustRing(t, map[string][]uint16{DomainUserTOTP: {2}})
	aad := tc("row-1")
	ct, _ := r.Seal(DomainUserTOTP, aad, []byte("secret-seed"))

	flip := func(i int) []byte { c := bytes.Clone(ct); c[i] ^= 1; return c }
	cases := map[string][]byte{
		"truncated":    ct[:len(ct)-1],
		"short":        ct[:10],
		"nil":          nil,
		"bad magic":    flip(0),
		"bad version":  flip(2),
		"unknown key":  flip(4), // key number 1 -> 0
		"bad nonce":    flip(7),
		"bad body":     flip(len(ct) - 20),
		"bad tag":      flip(len(ct) - 1),
		"appended":     append(bytes.Clone(ct), 0),
		"all zero":     make([]byte, len(ct)),
		"other domain": mustSealOther(t, r, aad),
	}
	for name, c := range cases {
		_, err := r.Open(DomainUserTOTP, aad, c)
		if err != ErrOpen {
			t.Errorf("%s: err = %v, want ErrOpen", name, err)
		}
	}
	if _, err := r.Open(DomainUserTOTP, tc("row-2"), ct); err != ErrOpen {
		t.Errorf("another row's aad: %v", err)
	}
	if _, err := other.Open(DomainUserTOTP, aad, ct); err != ErrOpen {
		t.Errorf("a ring without key 1: %v", err)
	}
	// A ring that holds the same number but another key fails the same way.
	wrong, _ := NewEphemeral(DomainUserTOTP)
	if _, err := wrong.Open(DomainUserTOTP, aad, ct); err != ErrOpen {
		t.Errorf("wrong key: %v", err)
	}
	// Opening a domain the process does not hold is a start-up error, and says which.
	if _, err := r.Open(DomainAdminTOTP, aad, ct); !errors.Is(err, ErrNotLoaded) {
		t.Errorf("unloaded domain: %v", err)
	}
	if _, err := r.Seal(DomainAdminTOTP, aad, nil); !errors.Is(err, ErrNotLoaded) {
		t.Errorf("seal in an unloaded domain: %v", err)
	}
	if err := ErrOpen; strings.Contains(err.Error(), "seed") {
		t.Error("error text holds data")
	}
}

// mustSealOther seals under another domain with the same context and key
// number, to prove the domain is bound into the AAD and the key.
func mustSealOther(t *testing.T, r *Ring, aad Context) []byte {
	t.Helper()
	ct, err := r.Seal(DomainSMSCred, aad, []byte("secret-seed"))
	if err != nil {
		t.Fatal(err)
	}
	return ct
}

func TestLabeledSubkeys(t *testing.T) {
	r := mustRing(t, map[string][]uint16{DomainAuthMAC: {1}})
	aad := tc("ctx")
	ct, err := r.SealLabeled(DomainAuthMAC, LabelDevice, aad, []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := r.OpenLabeled(DomainAuthMAC, LabelDevice, aad, ct)
	if err != nil || string(got.Reveal()) != "payload" {
		t.Fatalf("OpenLabeled: %v", err)
	}
	if _, err := r.OpenLabeled(DomainAuthMAC, LabelOTP, aad, ct); err != ErrOpen {
		t.Errorf("another label opened it: %v", err)
	}
	if _, err := r.Open(DomainAuthMAC, aad, ct); err != ErrOpen {
		t.Errorf("an unlabelled open succeeded: %v", err)
	}
	plain, _ := r.Seal(DomainAuthMAC, aad, []byte("payload"))
	if _, err := r.OpenLabeled(DomainAuthMAC, LabelDevice, aad, plain); err != ErrOpen {
		t.Errorf("an unlabelled seal opened as labelled: %v", err)
	}
	if _, err := r.SealLabeled(DomainAuthMAC, "", aad, nil); err == nil {
		t.Error("empty label")
	}
	if _, err := r.OpenLabeled(DomainAuthMAC, "", aad, ct); err == nil {
		t.Error("empty label on open")
	}
}

func TestMAC(t *testing.T) {
	r := mustRing(t, map[string][]uint16{DomainAuthMAC: {1}})
	a := r.MAC(DomainAuthMAC, LabelOTP, []byte("ab"), []byte("c"))
	if len(a) != 32 {
		t.Fatalf("length %d", len(a))
	}
	if !bytes.Equal(a, r.MAC(DomainAuthMAC, LabelOTP, []byte("ab"), []byte("c"))) {
		t.Error("MAC is not deterministic")
	}
	for name, b := range map[string][]byte{
		"shifted field":  r.MAC(DomainAuthMAC, LabelOTP, []byte("a"), []byte("bc")),
		"merged fields":  r.MAC(DomainAuthMAC, LabelOTP, []byte("abc")),
		"extra empty":    r.MAC(DomainAuthMAC, LabelOTP, []byte("ab"), []byte("c"), nil),
		"other label":    r.MAC(DomainAuthMAC, LabelThrottle, []byte("ab"), []byte("c")),
		"no parts":       r.MAC(DomainAuthMAC, LabelOTP),
		"another key":    mustRing(t, map[string][]uint16{DomainAuthMAC: {2}}).MAC(DomainAuthMAC, LabelOTP, []byte("ab"), []byte("c")),
		"another domain": mustRing(t, map[string][]uint16{DomainAdminMAC: {1}}).MAC(DomainAdminMAC, LabelThrottle, []byte("ab"), []byte("c")),
	} {
		if bytes.Equal(a, b) {
			t.Errorf("%s collides", name)
		}
	}
	// The newest key is the one that MACs: with keys 1 and 2, MAC equals ring {2}.
	two := mustRing(t, map[string][]uint16{DomainAuthMAC: {1, 2}})
	only2 := mustRing(t, map[string][]uint16{DomainAuthMAC: {2}})
	if !bytes.Equal(two.MAC(DomainAuthMAC, LabelOTP, []byte("x")), only2.MAC(DomainAuthMAC, LabelOTP, []byte("x"))) {
		t.Error("MAC did not use the newest key")
	}
	for name, f := range map[string]func(){
		"unloaded domain": func() { r.MAC(DomainAdminMAC, LabelOTP, nil) },
		"empty label":     func() { r.MAC(DomainAuthMAC, "", nil) },
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: MAC did not panic", name)
				}
			}()
			f()
		}()
	}
}

// TestRotation walks 8.4: add key 2, old rows still open, new rows use key 2,
// and removing key 1 early makes old rows fail with the generic error.
func TestRotation(t *testing.T) {
	d := DomainUserTOTP
	aad := tc("row")
	one := mustRing(t, map[string][]uint16{d: {1}})
	both := mustRing(t, map[string][]uint16{d: {1, 2}})
	two := mustRing(t, map[string][]uint16{d: {2}})

	old, _ := one.Seal(d, aad, []byte("seed"))
	if got, err := both.Open(d, aad, old); err != nil || string(got.Reveal()) != "seed" {
		t.Fatalf("the old row must still open after the new key is added: %v", err)
	}
	if n, _ := both.Newest(d); n != 2 {
		t.Errorf("Newest = %d", n)
	}
	fresh, _ := both.Seal(d, aad, []byte("seed"))
	if n, _ := KeyNumber(fresh); n != 2 {
		t.Errorf("new rows use key %d, want 2", n)
	}
	if _, err := two.Open(d, aad, fresh); err != nil {
		t.Errorf("a ring with only key 2 must open new rows: %v", err)
	}
	if _, err := two.Open(d, aad, old); err != ErrOpen {
		t.Errorf("old key removed early: %v, want ErrOpen", err)
	}
	if got := both.Numbers(d); len(got) != 2 || got[0] != 1 || got[1] != 2 {
		t.Errorf("Numbers = %v", got)
	}
	// Re-encrypting: open under both, seal again, now readable without key 1.
	pt, _ := both.Open(d, aad, old)
	re, _ := both.Seal(d, aad, pt.Reveal())
	if _, err := two.Open(d, aad, re); err != nil {
		t.Errorf("re-encrypted row: %v", err)
	}
}

func writeKeyFiles(t *testing.T, dir string, domains ...string) {
	t.Helper()
	for _, d := range domains {
		txt, err := FileText(testRoot(), d, 1)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, FileName(d)), txt.Reveal(), 0o444); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLoadMatchesFromRoot(t *testing.T) {
	dir := t.TempDir()
	writeKeyFiles(t, dir, DomainUserTOTP, DomainAuthMAC)
	loaded, err := Load(dir, DomainUserTOTP, DomainAuthMAC)
	if err != nil {
		t.Fatal(err)
	}
	derived := mustRing(t, map[string][]uint16{DomainUserTOTP: {1}, DomainAuthMAC: {1}})
	ct, _ := derived.Seal(DomainUserTOTP, tc("a"), []byte("x"))
	if _, err := loaded.Open(DomainUserTOTP, tc("a"), ct); err != nil {
		t.Errorf("a key file and the derivation must agree: %v", err)
	}
	if !bytes.Equal(loaded.MAC(DomainAuthMAC, LabelOTP, []byte("m")), derived.MAC(DomainAuthMAC, LabelOTP, []byte("m"))) {
		t.Error("MAC differs between file and derivation")
	}
	if got := loaded.Loaded(); len(got) != 2 {
		t.Errorf("Loaded = %v", got)
	}
	if err := loaded.Require(DomainUserTOTP, DomainAuthMAC); err != nil {
		t.Error(err)
	}
	if err := loaded.Require(DomainUserTOTP, DomainSMSCred); !errors.Is(err, ErrNotLoaded) || !strings.Contains(err.Error(), DomainSMSCred) {
		t.Errorf("Require = %v", err)
	}
}

// TestLoadRefusals is "Key file missing: start refused, names the domain, not a
// value" (18.3), and every malformed file the same way.
func TestLoadRefusals(t *testing.T) {
	good, _ := FileText(testRoot(), DomainUserTOTP, 1)
	goodText := string(good.Reveal())
	keyLine := strings.Split(strings.TrimSpace(goodText), "\n")[1]
	b64 := strings.Fields(keyLine)[1]
	for name, content := range map[string]string{
		"empty":            "",
		"no header":        "1 " + b64 + "\n",
		"wrong domain":     "# ctrlz keyring domain=admin_totp\n1 " + b64 + "\n",
		"header only":      "# ctrlz keyring domain=user_totp\n",
		"short key":        "# ctrlz keyring domain=user_totp\n1 " + b64[:20] + "\n",
		"not base64":       "# ctrlz keyring domain=user_totp\n1 " + strings.Repeat("!", 43) + "\n",
		"long key":         "# ctrlz keyring domain=user_totp\n1 " + b64 + b64 + "\n",
		"duplicate number": "# ctrlz keyring domain=user_totp\n1 " + b64 + "\n1 " + b64 + "\n",
		"number zero":      "# ctrlz keyring domain=user_totp\n0 " + b64 + "\n",
		"leading zero":     "# ctrlz keyring domain=user_totp\n01 " + b64 + "\n",
		"number too big":   "# ctrlz keyring domain=user_totp\n65536 " + b64 + "\n",
		"no key":           "# ctrlz keyring domain=user_totp\n1\n",
		"key before head":  "1 " + b64 + "\n# ctrlz keyring domain=user_totp\n",
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "kek_user_totp"), []byte(content), 0o444); err != nil {
				t.Fatal(err)
			}
			_, err := Load(dir, DomainUserTOTP)
			if err == nil {
				t.Fatal("Load accepted it")
			}
			if !strings.Contains(err.Error(), "user_totp") {
				t.Errorf("the error does not name the domain: %v", err)
			}
			if strings.Contains(err.Error(), b64) || strings.Contains(err.Error(), b64[:12]) {
				t.Errorf("the error carries key text: %v", err)
			}
		})
	}

	// Missing files: every domain is named in one error.
	dir := t.TempDir()
	_, err := Load(dir, DomainUserTOTP, DomainOTPDelivery)
	if err == nil || !strings.Contains(err.Error(), "user_totp") || !strings.Contains(err.Error(), "otp_delivery") {
		t.Errorf("missing files: %v", err)
	}
	if _, err := Load(dir, "bogus"); err == nil {
		t.Error("unknown domain")
	}

	// Comments, blank lines, CRLF and padded base64 are tolerated.
	dir = t.TempDir()
	lenient := "# ctrlz keyring domain=user_totp\r\n\r\n# note\r\n7 " + b64 + "=\r\n"
	if err := os.WriteFile(filepath.Join(dir, "kek_user_totp"), []byte(lenient), 0o444); err != nil {
		t.Fatal(err)
	}
	r, err := Load(dir, DomainUserTOTP)
	if err != nil {
		t.Fatalf("lenient file: %v", err)
	}
	if n, _ := r.Newest(DomainUserTOTP); n != 7 {
		t.Errorf("Newest = %d", n)
	}
}

func TestRotateAppendsTheNextNumber(t *testing.T) {
	cur, _ := FileText(testRoot(), DomainUserTOTP, 1)
	next, n, err := Rotate(testRoot(), DomainUserTOTP, cur)
	if err != nil || n != 2 {
		t.Fatalf("Rotate = %d, %v", n, err)
	}
	next2, n, err := Rotate(testRoot(), DomainUserTOTP, next)
	if err != nil || n != 3 {
		t.Fatalf("second Rotate = %d, %v", n, err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "kek_user_totp"), next2.Reveal(), 0o444); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(dir, DomainUserTOTP)
	if err != nil {
		t.Fatal(err)
	}
	if got := loaded.Numbers(DomainUserTOTP); fmt.Sprint(got) != "[1 2 3]" {
		t.Errorf("Numbers = %v", got)
	}
	// The appended key is the one the root derives for that number.
	want := mustRing(t, map[string][]uint16{DomainUserTOTP: {3}})
	ct, _ := want.Seal(DomainUserTOTP, tc("c"), []byte("x"))
	if _, err := loaded.Open(DomainUserTOTP, tc("c"), ct); err != nil {
		t.Errorf("rotated key differs from the derivation: %v", err)
	}
	// A file for another domain is refused.
	if _, _, err := Rotate(testRoot(), DomainAdminTOTP, cur); err == nil {
		t.Error("Rotate accepted a file of another domain")
	}
	// A file with no trailing newline still gets its line on a line of its own.
	trim := secret.NewBytes(bytes.TrimRight(cur.Reveal(), "\n"))
	if out, _, err := Rotate(testRoot(), DomainUserTOTP, trim); err != nil {
		t.Errorf("no trailing newline: %v", err)
	} else if _, err := parseFile(DomainUserTOTP, out); err != nil {
		t.Errorf("result does not parse: %v", err)
	}
}

func TestLoadRoot(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, RootFileName)
	if err := os.WriteFile(p, testRoot().Reveal(), 0o400); err != nil {
		t.Fatal(err)
	}
	if r, err := LoadRoot(p); err != nil || !r.Equal(testRoot()) {
		t.Errorf("LoadRoot: %v", err)
	}
	if err := os.Remove(p); err != nil { // a 0400 file cannot be overwritten on Windows
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("short"), 0o400); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRoot(p); err == nil {
		t.Error("short root")
	}
	if _, err := LoadRoot(filepath.Join(dir, "none")); err == nil {
		t.Error("missing root")
	}
}

// TestNothingPrintsAKey: a Ring and its errors, formatted every way, show no
// key byte, hex or base64 (8.6).
func TestNothingPrintsAKey(t *testing.T) {
	r := mustRing(t, map[string][]uint16{DomainUserTOTP: {1}})
	k, _ := deriveKey(testRoot(), DomainUserTOTP, 1)
	txt, _ := FileText(testRoot(), DomainUserTOTP, 1)
	for _, v := range []any{r, *r, r.domains, k, txt, testRoot()} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%x", "%s"} {
			out := fmt.Sprintf(verb, v)
			if strings.Contains(out, hex.EncodeToString(k.Reveal())) {
				t.Errorf("%s of %T leaks the key as hex", verb, v)
			}
		}
	}
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("ring", "ring", r, "key", k, "file", txt)
	if bytes.Contains(buf.Bytes(), k.Reveal()) {
		t.Error("slog leaks the key")
	}
}

func TestEphemeral(t *testing.T) {
	r, err := NewEphemeral(DomainUserTOTP, DomainAuthMAC)
	if err != nil {
		t.Fatal(err)
	}
	ct, _ := r.Seal(DomainUserTOTP, tc("c"), []byte("x"))
	if _, err := r.Open(DomainUserTOTP, tc("c"), ct); err != nil {
		t.Error(err)
	}
	r2, _ := NewEphemeral(DomainUserTOTP)
	if _, err := r2.Open(DomainUserTOTP, tc("c"), ct); err == nil {
		t.Error("two ephemeral rings share a key")
	}
	if _, err := NewEphemeral("bogus"); err == nil {
		t.Error("unknown domain")
	}
}

func TestSealRefusesHugeInput(t *testing.T) {
	r := mustRing(t, map[string][]uint16{DomainUserTOTP: {1}})
	if _, err := r.Seal(DomainUserTOTP, tc("c"), make([]byte, maxPlain+1)); err != ErrSeal {
		t.Errorf("err = %v", err)
	}
}

func TestConcurrentUse(t *testing.T) {
	r := mustRing(t, map[string][]uint16{DomainUserTOTP: {1}, DomainAuthMAC: {1}})
	done := make(chan error, 8)
	for i := range 8 {
		go func() {
			for j := range 50 {
				aad := tc(fmt.Sprint(i, j))
				ct, err := r.Seal(DomainUserTOTP, aad, []byte("v"))
				if err == nil {
					_, err = r.Open(DomainUserTOTP, aad, ct)
				}
				r.MAC(DomainAuthMAC, LabelOTP, aad.Bytes())
				if err != nil {
					done <- err
					return
				}
			}
			done <- nil
		}()
	}
	for range 8 {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
}

// Review round 1 (admin-r1-8): Rotate must refuse a root that is not the one the
// file's keys were derived from, and must not name a key in its error.
func TestRotateRefusesAnotherRoot(t *testing.T) {
	cur, _ := FileText(testRoot(), DomainUserTOTP, 1, 2)
	other := make([]byte, rootLen)
	for i := range other {
		other[i] = byte(200 - i)
	}
	_, _, err := Rotate(secret.NewBytes(other), DomainUserTOTP, cur)
	if !errors.Is(err, ErrRootMismatch) {
		t.Fatalf("Rotate with another root = %v", err)
	}
	if !strings.Contains(err.Error(), DomainUserTOTP) || !strings.Contains(err.Error(), "key 1") {
		t.Errorf("the error does not name the domain and number: %v", err)
	}
	// A file whose second key came from another root is refused too.

	k1, _ := FileText(testRoot(), DomainUserTOTP, 1)
	k2, _ := FileText(secret.NewBytes(other), DomainUserTOTP, 2)
	_, line2, _ := bytes.Cut(bytes.TrimRight(k2.Reveal(), "\n"), []byte("\n"))
	file := secret.NewBytes(append(append(append([]byte{}, k1.Reveal()...), line2...), '\n'))
	if _, _, err := Rotate(testRoot(), DomainUserTOTP, file); !errors.Is(err, ErrRootMismatch) {
		t.Fatalf("Rotate over a mixed file = %v", err)
	}
}

// TestVerifyMAC is the check behind the tag in a session token (round 4,
// tenant-r4-4): it accepts a truncated MAC from any key the domain holds, so a
// value made before a rotation stays good until its key is removed, and nothing
// else.
func TestVerifyMAC(t *testing.T) {
	old := mustRing(t, map[string][]uint16{DomainAuthMAC: {1}})
	body := []byte("body")
	tag := old.MAC(DomainAuthMAC, LabelSession, body)[:8]
	if !old.VerifyMAC(DomainAuthMAC, LabelSession, tag, body) {
		t.Fatal("a tag made under the loaded key does not verify")
	}
	rotated := mustRing(t, map[string][]uint16{DomainAuthMAC: {1, 2}})
	if !rotated.VerifyMAC(DomainAuthMAC, LabelSession, tag, body) {
		t.Fatal("a tag made under the previous key stopped verifying at rotation")
	}
	removed := mustRing(t, map[string][]uint16{DomainAuthMAC: {2}})
	if removed.VerifyMAC(DomainAuthMAC, LabelSession, tag, body) {
		t.Fatal("a tag verifies after its key was removed")
	}
	if old.VerifyMAC(DomainAuthMAC, LabelDevice, tag, body) {
		t.Fatal("a tag verifies under another label")
	}
	if old.VerifyMAC(DomainAuthMAC, LabelSession, tag, []byte("bodz")) {
		t.Fatal("a tag verifies for another body")
	}
	if old.VerifyMAC(DomainAuthMAC, LabelSession, tag[:4], body) || old.VerifyMAC(DomainAuthMAC, LabelSession, nil, body) {
		t.Fatal("a tag shorter than 8 bytes verifies")
	}
	if old.VerifyMAC(DomainAdminMAC, LabelSession, tag, body) {
		t.Fatal("an unloaded domain verifies")
	}
}

// TestIdentifyProvesWhichRootAFileCameFrom is the base of rule key-identity: a key
// file's origin is read off the keys, line by line, never off a number or a name.
// A second root gives the same numbers, so numbers prove nothing.
func TestIdentifyProvesWhichRootAFileCameFrom(t *testing.T) {
	other := make([]byte, rootLen)
	for i := range other {
		other[i] = byte(200 - i)
	}
	otherRoot := secret.NewBytes(other)
	// 1 from the test root, 2 from the other: a file rotated onto a new root (8.5).
	k1, _ := FileText(testRoot(), DomainUserTOTP, 1)
	k2, _ := FileText(otherRoot, DomainUserTOTP, 2)
	_, line2, _ := bytes.Cut(bytes.TrimRight(k2.Reveal(), "\n"), []byte("\n"))
	file := secret.NewBytes(append(append([]byte{}, k1.Reveal()...), append(line2, '\n')...))

	p, err := Identify(otherRoot, DomainUserTOTP, file)
	if err != nil || !p.NewestFromRoot() || fmt.Sprint(p.Foreign()) != "[1]" || p.Newest() != 2 {
		t.Fatalf("the newer root: %+v, %v", p, err)
	}
	p, err = Identify(testRoot(), DomainUserTOTP, file)
	if err != nil || p.NewestFromRoot() || fmt.Sprint(p.Foreign()) != "[2]" {
		t.Fatalf("the older root owns key 1 and not the newest: %+v, %v", p, err)
	}
	// Key 1 of either root looks the same to a reader of numbers.
	same, _ := FileText(otherRoot, DomainUserTOTP, 1)
	if p, _ := Identify(testRoot(), DomainUserTOTP, same); p.NewestFromRoot() {
		t.Fatal("key 1 of another root was taken for this root's key 1")
	}
	// A routine rotation after the recovery of 8.5 needs no flag: the newest key is the root's.
	if _, n, err := Rotate(otherRoot, DomainUserTOTP, file); err != nil || n != 3 {
		t.Fatalf("Rotate after a rotation onto a new root = %d, %v", n, err)
	}
	// The old root is refused: its key is not the newest.
	if _, _, err := Rotate(testRoot(), DomainUserTOTP, file); !errors.Is(err, ErrRootMismatch) {
		t.Fatalf("Rotate with the old root over a file whose newest key is newer = %v", err)
	}
	if _, err := Identify(testRoot(), DomainAdminTOTP, file); err == nil {
		t.Error("Identify read a file of another domain")
	}
}

// TestEveryLabelHasOnePrimitive (primitives-r5-5): a label is a subkey, so one label that
// keyed an HMAC and an AES-GCM would feed 32 bytes to two primitives. Each registered
// label serves the one primitive PrimitiveOf says, the other is refused, and an
// unregistered label is refused by both.
func TestEveryLabelHasOnePrimitive(t *testing.T) {
	r := mustRing(t, map[string][]uint16{DomainAuthMAC: {1}, DomainAdminMAC: {1}})
	aad := tc("ctx")
	labels := []string{LabelOTP, LabelThrottle, LabelDevice, LabelAdminDevice, LabelSession, LabelCeremony}
	for _, l := range labels {
		d := domainOfLabel(t, l)
		p, ok := PrimitiveOf(l)
		if !ok {
			t.Fatalf("label %q is not registered", l)
		}
		macErr := didPanic(func() { r.MAC(d, l, []byte("x")) })
		_, sealErr := r.SealLabeled(d, l, aad, []byte("x"))
		switch p {
		case MACOnly:
			if macErr || sealErr == nil {
				t.Errorf("%s is a MAC label: MAC refused %v, seal error %v", l, macErr, sealErr)
			}
			tag := r.MAC(d, l, []byte("x"))[:8]
			if !r.VerifyMAC(d, l, tag, []byte("x")) {
				t.Errorf("%s: its own tag does not verify", l)
			}
		case SealOnly:
			if !macErr || sealErr != nil {
				t.Errorf("%s is a seal label: MAC panicked %v, seal error %v", l, macErr, sealErr)
			}
			// VerifyMAC refuses the seal label too, whatever tag it is given.
			if r.VerifyMAC(d, l, make([]byte, 8), []byte("x")) {
				t.Errorf("%s: VerifyMAC accepted a seal label", l)
			}
		}
	}
	if !didPanic(func() { r.MAC(DomainAuthMAC, "made_up", []byte("x")) }) {
		t.Error("MAC accepted an unregistered label")
	}
	if _, err := r.SealLabeled(DomainAuthMAC, "made_up", aad, []byte("x")); err == nil {
		t.Error("SealLabeled accepted an unregistered label")
	}
	// Uses names only registered labels, and none of them twice for the other primitive.
	for _, u := range Uses() {
		if u.Label == "" {
			continue
		}
		if _, ok := PrimitiveOf(u.Label); !ok {
			t.Errorf("Uses lists the unregistered label %q", u.Label)
		}
	}
}

func didPanic(f func()) (p bool) {
	defer func() { p = recover() != nil }()
	f()
	return false
}

// TestEveryDomainHasOneMode is primitives-r6-8. The label registry gives each label one primitive;
// the domain key itself is the AES key of an unlabeled seal and the HKDF root of every labelled
// subkey, so it needs the same rule. Every domain of Domains has a registered mode, a sealed domain
// refuses MACs and labelled seals, a labeled domain refuses the unlabeled seal and open, and each
// still does what it is for.
func TestEveryDomainHasOneMode(t *testing.T) {
	numbers := map[string][]uint16{}
	for _, d := range Domains() {
		numbers[d] = []uint16{1}
	}
	r := mustRing(t, numbers)
	aad, plain := tc("ctx"), []byte("secret")
	for _, d := range Domains() {
		m, ok := ModeOf(d)
		if !ok {
			t.Errorf("domain %s has no registered mode", d)
			continue
		}
		unlabeled, uerr := r.Seal(d, aad, plain)
		sealLabel := LabelDevice // a registered seal label of the labeled domain (admin_mac has its own)
		if d == DomainAdminMAC {
			sealLabel = LabelAdminDevice
		}
		_, lerr := r.SealLabeled(d, sealLabel, aad, plain)
		macPanics := didPanic(func() { r.MAC(d, LabelThrottle, []byte("x")) })
		verifies := false
		if !macPanics {
			tag := r.MAC(d, LabelThrottle, []byte("x"))[:8]
			verifies = r.VerifyMAC(d, LabelThrottle, tag, []byte("x"))
		}
		switch m {
		case ModeSealed:
			if uerr != nil {
				t.Errorf("%s: a sealed domain refused the unlabeled seal: %v", d, uerr)
			} else if got, err := r.Open(d, aad, unlabeled); err != nil || string(got.Reveal()) != "secret" {
				t.Errorf("%s: the unlabeled seal does not open: %v", d, err)
			}
			if lerr == nil {
				t.Errorf("%s: a sealed domain accepted a labelled seal: its key is also an HKDF root", d)
			}
			if !macPanics || verifies {
				t.Errorf("%s: a sealed domain made or verified a MAC: its key is an AES key", d)
			}
		case ModeSigning:
			if uerr == nil || lerr == nil {
				t.Errorf("%s: a signing domain sealed: its key is an Ed25519 seed", d)
			}
			if !macPanics || verifies {
				t.Errorf("%s: a signing domain made or verified a MAC", d)
			}
		case ModeLabeled:
			if uerr == nil {
				t.Errorf("%s: a labeled domain accepted the unlabeled seal: its key is also an AES key", d)
			}
			if _, err := r.Open(d, aad, append([]byte{magic0, magic1, formatVersion, 0, 1}, make([]byte, nonceLen+tagLen+4)...)); err == nil {
				t.Errorf("%s: a labeled domain opened an unlabeled ciphertext", d)
			}
			if lerr != nil {
				t.Errorf("%s: a labeled domain refused a registered seal label: %v", d, lerr)
			}
			if macPanics || !verifies {
				t.Errorf("%s: a labeled domain refused its own MAC", d)
			}
		}
	}
	// A domain nobody registered has no mode, whatever Domains says tomorrow.
	if _, ok := ModeOf("made_up"); ok {
		t.Error("an unregistered domain has a mode")
	}
}

// domainOfLabel is the first domain Uses lists the label under.
func domainOfLabel(t *testing.T, label string) string {
	t.Helper()
	for _, u := range Uses() {
		if u.Label == label {
			return u.Domain
		}
	}
	t.Fatalf("label %q is in no line of Uses", label)
	return ""
}

// TestEveryLabelIsUsedOnlyUnderTheDomainsUsesListsIt is primitives-r7-3. PrimitiveOf and ModeOf
// judge a label and a domain apart, so any registered label was accepted under any labeled domain:
// LabelAdminDevice under auth_mac, LabelCeremony under admin_mac. Two uses that share one HKDF
// subkey inside a domain verify as each other, which defeats the separation the labels are for.
// Every operation is run on every (domain, label) pair, and exactly the pairs of Uses work.
func TestEveryLabelIsUsedOnlyUnderTheDomainsUsesListsIt(t *testing.T) {
	numbers := map[string][]uint16{}
	for _, d := range Domains() {
		numbers[d] = []uint16{1}
	}
	r := mustRing(t, numbers)
	aad := tc("ctx")
	listed := map[[2]string]bool{}
	for _, u := range Uses() {
		listed[[2]string{u.Domain, u.Label}] = true
	}
	tried := 0
	for _, d := range Domains() {
		if m, _ := ModeOf(d); m != ModeLabeled {
			continue
		}
		for _, l := range LabelNames() {
			want := listed[[2]string{d, l}]
			p, _ := PrimitiveOf(l)
			var worked bool
			switch p {
			case MACOnly:
				if !didPanic(func() { r.MAC(d, l, []byte("x")) }) {
					tag := r.MAC(d, l, []byte("x"))[:8]
					worked = r.VerifyMAC(d, l, tag, []byte("x"))
				} else if r.VerifyMAC(d, l, make([]byte, 8), []byte("x")) {
					t.Errorf("%s/%s: VerifyMAC accepted a pair that MAC refuses", d, l)
				}
			case SealOnly:
				if ct, err := r.SealLabeled(d, l, aad, []byte("x")); err == nil {
					_, err = r.OpenLabeled(d, l, aad, ct)
					worked = err == nil
				} else if _, oerr := r.OpenLabeled(d, l, aad, make([]byte, 64)); oerr == nil {
					t.Errorf("%s/%s: OpenLabeled accepted a pair that SealLabeled refuses", d, l)
				}
			}
			if worked != want {
				t.Errorf("%s under %s: works = %v, Uses lists it = %v", l, d, worked, want)
			}
			tried++
		}
	}
	if tried < 10 {
		t.Fatalf("only %d pairs were tried", tried)
	}
	// Every line of Uses is a pair that works, so the registry cannot list a use the code refuses.
	for pair := range listed {
		if pair[1] != "" && !PairListed(pair[0], pair[1]) {
			t.Errorf("PairListed refuses the listed pair %v", pair)
		}
	}
}

// tc is a test context: the ring's own constructor over a fixed row id, so a test that is not about
// the context still seals under a real one.
func tc(part string) Context { return RowContext([]uuid.UUID{testRow}, part) }

var testRow = uuid.MustParse("0b6c1d1e-6c1f-4a52-9d6c-3f3c0f4f9a11")
