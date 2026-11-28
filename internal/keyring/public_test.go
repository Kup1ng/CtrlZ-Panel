package keyring

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func signRing(t *testing.T, nums ...uint16) *Ring {
	t.Helper()
	return mustRing(t, map[string][]uint16{DomainInviteSign: nums})
}

// TestASignatureVerifiesOnlyUnderItsKeyNumberAndLabel is the keyring half of D67: one signature opens under
// the number that made it and nothing else, and Sign refuses every domain and label but its own.
func TestASignatureVerifiesOnlyUnderItsKeyNumberAndLabel(t *testing.T) {
	r := signRing(t, 1, 2)
	pub, err := r.Public(DomainInviteSign)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("a message")
	n, sig, err := r.Sign(DomainInviteSign, LabelInviteLink, msg)
	if err != nil || n != 2 {
		t.Fatalf("Sign = %d, %v, want the newest number 2", n, err)
	}
	if !pub.Verify(LabelInviteLink, n, msg, sig) {
		t.Fatal("a signature does not verify under its own number")
	}
	if pub.Verify(LabelInviteLink, 1, msg, sig) {
		t.Error("a signature verified under the other key of the ring")
	}
	if pub.Verify(LabelInviteLink, 3, msg, sig) || pub.Verify(LabelInviteLink, 0, msg, sig) {
		t.Error("a signature verified under an unknown number")
	}
	if pub.Verify(LabelProof, n, msg, sig) {
		t.Error("a signature verified under another label")
	}
	if pub.Verify(LabelInviteLink, n, append([]byte("x"), msg...), sig) {
		t.Error("a signature verified over another message")
	}
	for i := range sig {
		bad := append([]byte(nil), sig...)
		bad[i] ^= 1
		if pub.Verify(LabelInviteLink, n, msg, bad) {
			t.Fatalf("a signature with byte %d changed verified", i)
		}
	}
	if pub.Verify(LabelInviteLink, n, msg, sig[:63]) || pub.Verify(LabelInviteLink, n, msg, nil) {
		t.Error("a short signature verified")
	}
	// Another ring of the same domain has other keys.
	eph, _ := NewEphemeral(DomainInviteSign)
	other, _ := eph.Public(DomainInviteSign)
	if other.Verify(LabelInviteLink, n, msg, sig) {
		t.Error("a signature verified under another ring")
	}
	// Sign is refused on every other domain and every other label.
	all := allRing(t)
	for _, d := range Domains() {
		for _, l := range append(LabelNames(), "", "made_up") {
			_, _, err := all.Sign(d, l, msg)
			want := d == DomainInviteSign && l == LabelInviteLink
			if (err == nil) != want {
				t.Errorf("Sign(%s, %q) error = %v, allowed = %v", d, l, err, want)
			}
		}
	}
	if _, _, err := mustRing(t, map[string][]uint16{DomainAuthMAC: {1}}).Sign(DomainInviteSign, LabelInviteLink, msg); !errors.Is(err, ErrNotLoaded) {
		t.Errorf("Sign on an unloaded domain = %v", err)
	}
	// The key of a signing domain does nothing else.
	if _, err := all.Seal(DomainInviteSign, tc("x"), []byte("x")); err == nil {
		t.Error("a signing domain sealed")
	}
	if !didPanic(func() { all.MAC(DomainInviteSign, LabelInviteLink, []byte("x")) }) {
		t.Error("a signing domain made a MAC")
	}
}

// TestThePublicFileIsDerivedFromTheKeyFile covers the round trip of derive and load, that the file holds no
// private byte, and that a malformed file is refused.
func TestThePublicFileIsDerivedFromTheKeyFile(t *testing.T) {
	root := testRoot()
	keyText, err := FileText(root, DomainInviteSign, 1, 2)
	if err != nil {
		t.Fatal(err)
	}
	text, err := PublicText(DomainInviteSign, keyText)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(text, []byte("# ctrlz public keys domain=invite_sign\n")) {
		t.Fatalf("header: %q", text)
	}
	// No private byte: no line of the key file, and no base64 of the seed, is in it.
	for _, ln := range strings.Split(string(keyText.Reveal()), "\n") {
		if _, enc, ok := strings.Cut(ln, " "); ok && strings.Contains(string(text), enc) {
			t.Error("the public file holds a line of the key file")
		}
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, PublicFileName(DomainInviteSign)), text, 0o444); err != nil {
		t.Fatal(err)
	}
	pub, err := LoadPublic(dir, DomainInviteSign)
	if err != nil {
		t.Fatal(err)
	}
	ring, err := FromRoot(root, map[string][]uint16{DomainInviteSign: {1, 2}})
	if err != nil {
		t.Fatal(err)
	}
	n, sig, err := ring.Sign(DomainInviteSign, LabelInviteLink, []byte("m"))
	if err != nil || !pub.Verify(LabelInviteLink, n, []byte("m"), sig) {
		t.Fatalf("a signature of the key file does not verify under its public file: %v", err)
	}
	if got := pub.Numbers(); len(got) != 2 || got[0] != 1 || got[1] != 2 {
		t.Errorf("numbers = %v", got)
	}
	// The same text twice is the same file: derive may compare and skip the write.
	again, _ := PublicText(DomainInviteSign, keyText)
	if !bytes.Equal(text, again) {
		t.Error("PublicText is not a pure function of the key file")
	}
	// Ring.Public agrees with the file.
	viaRing, _ := ring.Public(DomainInviteSign)
	if !viaRing.Verify(LabelInviteLink, n, []byte("m"), sig) {
		t.Error("Ring.Public disagrees with the file")
	}

	b64 := strings.Fields(string(text))[len(strings.Fields(string(text)))-1]
	bad := map[string]string{
		"no header":         "1 " + b64 + "\n",
		"another domain":    "# ctrlz public keys domain=user_totp\n1 " + b64 + "\n",
		"the key file head": "# ctrlz keyring domain=invite_sign\n1 " + b64 + "\n",
		"no keys":           "# ctrlz public keys domain=invite_sign\n",
		"number zero":       "# ctrlz public keys domain=invite_sign\n0 " + b64 + "\n",
		"leading zero":      "# ctrlz public keys domain=invite_sign\n01 " + b64 + "\n",
		"duplicate number":  "# ctrlz public keys domain=invite_sign\n1 " + b64 + "\n1 " + b64 + "\n",
		"short key":         "# ctrlz public keys domain=invite_sign\n1 " + b64[:20] + "\n",
		"not base64":        "# ctrlz public keys domain=invite_sign\n1 !!!!\n",
		"no key":            "# ctrlz public keys domain=invite_sign\n1\n",
	}
	for name, body := range bad {
		d := t.TempDir()
		if err := os.WriteFile(filepath.Join(d, PublicFileName(DomainInviteSign)), []byte(body), 0o444); err != nil {
			t.Fatal(err)
		}
		_, err := LoadPublic(d, DomainInviteSign)
		if err == nil {
			t.Errorf("%s: the file was accepted", name)
		} else if strings.Contains(err.Error(), b64) {
			t.Errorf("%s: the error repeats the key", name)
		}
	}
	if _, err := LoadPublic(t.TempDir(), DomainInviteSign); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Errorf("a missing file = %v", err)
	}
	// Domains without a public half have none.
	if _, err := PublicText(DomainAuthMAC, keyText); err == nil {
		t.Error("PublicText served a labeled domain")
	}
	if _, err := LoadPublic(dir, DomainAuthMAC); err == nil {
		t.Error("LoadPublic served a labeled domain")
	}
	// A key file of another domain is refused by the parser.
	other, _ := FileText(root, DomainAuthMAC, 1)
	if _, err := PublicText(DomainInviteSign, other); err == nil {
		t.Error("PublicText took a key file of another domain")
	}
}
