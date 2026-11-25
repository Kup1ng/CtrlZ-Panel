package admincli_test

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/admincli"
	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
)

// TestDeriveWritesAndRefreshesThePublicFile covers spec 8.3 (D67): pub_invite_sign is a pure function of
// kek_invite_sign, so every derive that passed the proof of the key files rewrites it when it differs, a
// rotation does it at once, and a refused run writes nothing.
func TestDeriveWritesAndRefreshesThePublicFile(t *testing.T) {
	pubName := keyring.PublicFileName(keyring.DomainInviteSign)
	keyName := keyring.FileName(keyring.DomainInviteSign)
	root := bytes.Repeat([]byte{7}, 32)
	newDir := func() string {
		d := t.TempDir()
		if err := os.WriteFile(filepath.Join(d, keyring.RootFileName), root, 0o400); err != nil {
			t.Fatal(err)
		}
		return d
	}
	derive := func(dir string, extra ...string) (int, string) {
		var out, errb bytes.Buffer
		code := runCtrlzKeys(append([]string{"derive", "--dir", dir}, extra...), &out, &errb)
		noKeys(t, out.String()+errb.String(), snapshot(t, dir))
		return code, out.String() + errb.String()
	}
	wantPublic := func(dir string) string {
		t.Helper()
		kf, err := os.ReadFile(filepath.Join(dir, keyName))
		if err != nil {
			t.Fatal(err)
		}
		want, err := keyring.PublicText(keyring.DomainInviteSign, secret.NewBytes(kf))
		if err != nil {
			t.Fatal(err)
		}
		return string(want)
	}
	read := func(dir, name string) string {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return string(b)
	}

	dir := newDir()
	if code, out := derive(dir); code != 0 || !strings.Contains(out, "wrote "+pubName) {
		t.Fatalf("first run: %d %q", code, out)
	}
	first := read(dir, pubName)
	if first != wantPublic(dir) || strings.Count(first, "\n") != 2 {
		t.Fatalf("the public file is not the public text of the key file: %q", first)
	}
	if runtime.GOOS != "windows" {
		if st, _ := os.Stat(filepath.Join(dir, pubName)); st.Mode().Perm() != 0o444 {
			t.Errorf("the public file has mode %v, want 0444 like every key file", st.Mode().Perm())
		}
	}
	// No private byte: the key file's line does not appear in it, and a verifier built from the file opens a
	// signature of the key (the round trip of keyring.TestThePublicFileIsDerivedFromTheKeyFile, through the tool).
	for _, ln := range strings.Split(read(dir, keyName), "\n") {
		if _, enc, ok := strings.Cut(ln, " "); ok && strings.Contains(first, enc) {
			t.Error("the public file holds a line of the key file")
		}
	}

	// A second run keeps it.
	if code, out := derive(dir); code != 0 || !strings.Contains(out, "kept "+pubName) || read(dir, pubName) != first {
		t.Fatalf("second run: %d %q", code, out)
	}

	// A rotation brings the public file up to date in the same command, so the api can be recreated first.
	if code, out := derive(dir, "--rotate", keyring.DomainInviteSign); code != 0 || !strings.Contains(out, "key 2 added") {
		t.Fatalf("rotate: %d %q", code, out)
	}
	rotated := read(dir, pubName)
	if rotated == first || rotated != wantPublic(dir) || strings.Count(rotated, "\n") != 3 {
		t.Fatalf("the public file did not follow the rotation: %q", rotated)
	}
	pub, err := keyring.LoadPublic(dir, keyring.DomainInviteSign)
	if err != nil {
		t.Fatal(err)
	}
	ring, err := keyring.FromRoot(secret.NewBytes(root), map[string][]uint16{keyring.DomainInviteSign: {1, 2}})
	if err != nil {
		t.Fatal(err)
	}
	n, sig, err := ring.Sign(keyring.DomainInviteSign, keyring.LabelInviteLink, []byte("m"))
	if err != nil || n != 2 || !pub.Verify(keyring.LabelInviteLink, n, []byte("m"), sig) {
		t.Fatalf("a signature of key 2 does not open under the file the rotation wrote: %v", err)
	}

	// The old line removed from the key file (spec 8.4 step 5): the next derive drops it from the public file too.
	kf := strings.Split(strings.TrimRight(read(dir, keyName), "\n"), "\n")
	if len(kf) != 3 {
		t.Fatalf("key file lines: %v", len(kf))
	}
	if err := os.Remove(filepath.Join(dir, keyName)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, keyName), []byte(kf[0]+"\n"+kf[2]+"\n"), 0o444); err != nil {
		t.Fatal(err)
	}
	if code, out := derive(dir); code != 0 || !strings.Contains(out, "wrote "+pubName) {
		t.Fatalf("after the old line was removed: %d %q", code, out)
	}
	if got := read(dir, pubName); got != wantPublic(dir) || strings.Count(got, "\n") != 2 {
		t.Fatalf("the removed line is still public: %q", got)
	}

	// A hand edit, and a missing file, are both made right: the file is never judged, only rewritten.
	if err := os.Remove(filepath.Join(dir, pubName)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, pubName), []byte("garbage\n"), 0o444); err != nil {
		t.Fatal(err)
	}
	if code, _ := derive(dir); code != 0 || read(dir, pubName) != wantPublic(dir) {
		t.Fatalf("a hand-edited public file was not rewritten: %q", read(dir, pubName))
	}
	if err := os.Remove(filepath.Join(dir, pubName)); err != nil {
		t.Fatal(err)
	}
	if code, _ := derive(dir); code != 0 || read(dir, pubName) != wantPublic(dir) {
		t.Fatal("a missing public file was not made")
	}

	// A refused run writes nothing, and a public file that is missing at the time counts as a missing key file
	// (exit 4): the run could not make it, because a file is made only from the root that owns the rest.
	other := newDir()
	if code, _ := derive(other); code != 0 {
		t.Fatal("setup")
	}
	foreign := bytes.Repeat([]byte{9}, 32)
	text, err := keyring.FileText(secret.NewBytes(foreign), keyring.DomainAuthMAC, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(other, keyring.FileName(keyring.DomainAuthMAC))); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(other, keyring.FileName(keyring.DomainAuthMAC)), text.Reveal(), 0o444); err != nil {
		t.Fatal(err)
	}
	before := snapshot(t, other)
	var out, errb bytes.Buffer
	if code := runCtrlzKeys([]string{"derive", "--dir", other}, &out, &errb); code != admincli.ExitRefused {
		t.Fatalf("a foreign key file: exit %d, want %d", code, admincli.ExitRefused)
	}
	if !equalSnap(before, snapshot(t, other)) {
		t.Error("a refused run changed the directory")
	}
	if err := os.Remove(filepath.Join(other, pubName)); err != nil {
		t.Fatal(err)
	}
	before = snapshot(t, other)
	out.Reset()
	errb.Reset()
	if code := runCtrlzKeys([]string{"derive", "--dir", other}, &out, &errb); code != admincli.ExitRefusedMissing || !strings.Contains(errb.String(), pubName) {
		t.Fatalf("a refusal with the public file missing: exit %d %q, want %d naming %s", code, errb.String(), admincli.ExitRefusedMissing, pubName)
	}
	if !equalSnap(before, snapshot(t, other)) {
		t.Error("a refused run that left the public file missing wrote it")
	}

	// A public file that still lists a key line the key file dropped is stale. kek_root off the host always ends
	// in a refusal, so a refusal must tell a stale file from a good one, or the api would trust a removed key
	// for ever (review dec-a-r1-4). It is exit 4 naming the file, and nothing is written.
	droppedKey, err := keyring.FileText(secret.NewBytes(foreign), keyring.DomainInviteSign, 1)
	if err != nil {
		t.Fatal(err)
	}
	stale, err := keyring.PublicText(keyring.DomainInviteSign, droppedKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(other, pubName), stale, 0o444); err != nil {
		t.Fatal(err)
	}
	before = snapshot(t, other)
	out.Reset()
	errb.Reset()
	if code := runCtrlzKeys([]string{"derive", "--dir", other}, &out, &errb); code != admincli.ExitRefusedMissing || !strings.Contains(errb.String(), pubName) {
		t.Fatalf("a refusal with a stale public file: exit %d %q, want %d naming %s", code, errb.String(), admincli.ExitRefusedMissing, pubName)
	}
	if !equalSnap(before, snapshot(t, other)) {
		t.Error("a refused run rewrote a stale public file")
	}
}

func equalSnap(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || w != v {
			return false
		}
	}
	return true
}
