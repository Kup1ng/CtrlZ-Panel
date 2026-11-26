package hubinstall

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	signv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/sign/v1"
	"github.com/Kup1ng/CtrlZ-Shared/manifest"
)

// writeBundle writes root.json and the signed node bundle 1 (one file, bin/x) under dir and returns the manifest's bytes.
func writeBundle(t *testing.T, dir string, now time.Time) []byte {
	t.Helper()
	var keys []*signv1.PublicKey
	var priv []ed25519.PrivateKey
	var ids [][]byte
	for i := 0; i < 3; i++ {
		pub, pk, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		id := manifest.KeyID(pub)
		keys, priv, ids = append(keys, &signv1.PublicKey{KeyId: id, Ed25519: pub}), append(priv, pk), append(ids, id)
	}
	exp := now.Add(365 * 24 * time.Hour).Unix()
	root := &signv1.Root{Version: 1, ExpiresAt: exp, Keys: keys, Threshold: 2, RootKeyIds: ids,
		Roles: []*signv1.RoleGrant{{Role: signv1.Role_ROLE_BUNDLE, KeyIds: ids, Threshold: 2, ExpiresAt: exp}}}
	rj, err := protojson.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("binary")
	sum := sha256.Sum256(body)
	m := &signv1.Manifest{Kind: signv1.Kind_KIND_NODE, Version: 1, CreatedAt: now.Unix(), ExpiresAt: exp, MinVersion: 1,
		Files: []*signv1.FileEntry{{Path: "bin/x", Sha256: sum[:], Size: uint64(len(body))}}}
	payload, err := proto.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	typ := manifest.ManifestPayloadType(signv1.Kind_KIND_NODE)
	signed := &signv1.Envelope{PayloadType: typ, Payload: payload}
	for i := 0; i < 2; i++ {
		signed.Signatures = append(signed.Signatures, &signv1.Signature{KeyId: ids[i], Sig: ed25519.Sign(priv[i], manifest.SigningInput(typ, payload))})
	}
	sj, err := protojson.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	for p, b := range map[string][]byte{"root.json": rj, "node/1/manifest.json": sj, "node/1/bin/x": body} {
		full := filepath.Join(dir, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return sj
}

func readAll(t *testing.T, f *os.File, size int64) []byte {
	t.Helper()
	defer f.Close()
	b, err := io.ReadAll(io.NewSectionReader(f, 0, size))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// GN-r1-2: the node's bundle downloader asks FetchBundle for manifest.json first, and the manifest lists every file but itself.
// OpenBundleFile serves it as the install door does, the bytes that verified; a bundle that does not verify, a manifest file that
// changed since it was verified, and a name the manifest does not list are all the same ErrNoFile.
//
// Fails if: manifest.json is looked up in the manifest's own sizes (ErrNoFile for the one file the node must read first).
func TestOpenBundleFileServesTheVerifiedManifest(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	raw := writeBundle(t, dir, now)
	h := New(Config{BundlesDir: dir, Now: func() time.Time { return now }})

	f, size, err := h.OpenBundleFile(1, "manifest.json")
	if err != nil {
		t.Fatalf("the manifest is not served: %v", err)
	}
	if got := readAll(t, f, size); !bytes.Equal(got, raw) || size != int64(len(raw)) {
		t.Fatalf("served %d bytes, want the %d of the verified manifest", len(got), len(raw))
	}
	if f, size, err := h.OpenBundleFile(1, "bin/x"); err != nil || string(readAll(t, f, size)) != "binary" {
		t.Fatalf("a listed file: %v", err)
	}
	for _, rel := range []string{"unlisted", "Manifest.json", "../manifest.json", "node/1/manifest.json"} {
		if _, _, err := h.OpenBundleFile(1, rel); !errors.Is(err, ErrNoFile) {
			t.Errorf("%q: %v, want ErrNoFile", rel, err)
		}
	}
	if _, _, err := h.OpenBundleFile(2, "manifest.json"); !errors.Is(err, ErrNoFile) {
		t.Errorf("a version that is not there: %v", err)
	}

	// The file is replaced while the verified copy is still cached: it is not served as the verified one.
	if err := os.WriteFile(filepath.Join(dir, "node", "1", "manifest.json"), append(bytes.Clone(raw), ' '), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := h.OpenBundleFile(1, "manifest.json"); !errors.Is(err, ErrNoFile) {
		t.Errorf("a manifest that changed after it verified: %v", err)
	}
}

// A manifest that does not verify is not served by this door either.
func TestOpenBundleFileRefusesAManifestThatDoesNotVerify(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	writeBundle(t, dir, now)
	if err := os.WriteFile(filepath.Join(dir, "node", "1", "manifest.json"), []byte(`{"payloadType":"x"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	h := New(Config{BundlesDir: dir, Now: func() time.Time { return now }})
	if _, _, err := h.OpenBundleFile(1, "manifest.json"); !errors.Is(err, ErrNoFile) {
		t.Fatalf("an unverified manifest was served: %v", err)
	}
}
