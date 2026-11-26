package compiler

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTheStoreKeepsWhatItIsGivenUnderItsHash(t *testing.T) {
	dir := t.TempDir()
	a, err := NewDirArtifacts(dir)
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("a profile blob")
	h := sha256Sum(data)
	if a.Has(h, int64(len(data))) || a.Size(h) != -1 {
		t.Fatal("the store has a file it was never given")
	}
	if err := a.Put(h, data); err != nil {
		t.Fatal(err)
	}
	if err := a.Put(h, data); err != nil {
		t.Fatalf("a second Put of the same bytes: %v", err)
	}
	if got, err := a.Get(h); err != nil || string(got) != string(data) {
		t.Fatalf("Get: %q %v", got, err)
	}
	if !a.Has(h, int64(len(data))) || a.Has(h, 3) {
		t.Fatal("Has does not compare the size")
	}
	// No temporary file is left behind, and the name is the hex hash.
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 || entries[0].Name() != hexOf(h) {
		t.Fatalf("the directory holds %d entries", len(entries))
	}
	if err := a.Delete(h); err != nil || a.Size(h) != -1 {
		t.Fatalf("Delete: %v", err)
	}
	if err := a.Delete(h); err != nil {
		t.Fatalf("Delete of a file that is not there: %v", err)
	}
}

func TestTheStoreRefusesBytesUnderAWrongNameAndAFileThatChanged(t *testing.T) {
	dir := t.TempDir()
	a, _ := NewDirArtifacts(dir)
	if err := a.Put(sha256Sum([]byte("x")), []byte("y")); err == nil {
		t.Fatal("bytes were stored under a hash that is not theirs")
	}
	if err := a.Put([]byte("short"), []byte("y")); err == nil {
		t.Fatal("a hash that is not 32 bytes was accepted")
	}
	data := []byte("good")
	h := sha256Sum(data)
	if err := a.Put(h, data); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, hexOf(h)), []byte("evil"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Get(h); err == nil {
		t.Fatal("a file that no longer matches its name was read")
	}
}

func TestAddressesGoToTheWireAsTheirBytes(t *testing.T) {
	b, err := ipBytes("203.0.113.9")
	if err != nil || len(b) != 4 || b[3] != 9 {
		t.Fatalf("v4: %v %v", b, err)
	}
	b, err = ipBytes("2001:db8::1")
	if err != nil || len(b) != 16 {
		t.Fatalf("v6: %v %v", b, err)
	}
	if _, err := ipBytes("not an address"); err == nil {
		t.Fatal("garbage was accepted")
	}
	p, err := cidrWire("198.51.100.0/24")
	if err != nil || len(p.Addr) != 4 || p.Bits != 24 {
		t.Fatalf("cidr: %v %v", p, err)
	}
}

// W4-r1-16: Ensure does not trust the size of a file that is there.
func TestEnsureWritesAgainWhatIsMissingOrCorrupt(t *testing.T) {
	dir := t.TempDir()
	a, _ := NewDirArtifacts(dir)
	data := []byte("a profile blob")
	h := sha256Sum(data)
	if err := a.Ensure(h, data); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, hexOf(h)), []byte("a profile BLOB"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := a.Ensure(h, data); err != nil {
		t.Fatal(err)
	}
	if got, err := a.Get(h); err != nil || string(got) != string(data) {
		t.Fatalf("a corrupt file of the right size stayed: %v", err)
	}
}
