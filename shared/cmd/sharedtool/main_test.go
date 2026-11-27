package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, dir, rel, content string) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func do(t *testing.T, args ...string) (int, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(args, &out, &errb)
	return code, out.String() + errb.String()
}

// tree builds a small canonical tree in a directory whose name has spaces,
// like the real repositories.
func tree(t *testing.T) string {
	dir := filepath.Join(t.TempDir(), "Ctrl Z Panel", "shared")
	write(t, dir, "go.mod", "module x\n\ngo 1.27.3\n")
	write(t, dir, "names/name.go", "package names\n")
	write(t, dir, "vectors/a.json", "{}\n")
	write(t, dir, "buf.bin", "\x00\x01\x02\r\n") // binary: CR is fine
	return dir
}

func TestHashThenVerify(t *testing.T) {
	d := tree(t)
	if c, out := do(t, "hash", d); c != 0 {
		t.Fatalf("hash: %d %s", c, out)
	}
	raw, _ := os.ReadFile(filepath.Join(d, "CHECKSUMS"))
	lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	if len(lines) != 4 || !strings.HasSuffix(lines[0], "  buf.bin") || !strings.HasSuffix(lines[3], "  vectors/a.json") {
		t.Fatalf("CHECKSUMS not sorted by path bytes with slash paths:\n%s", raw)
	}
	if len(lines[0]) != 64+2+len("buf.bin") {
		t.Fatalf("format: %q", lines[0])
	}
	if c, out := do(t, "verify", d); c != 0 || !strings.Contains(out, "ok ") {
		t.Fatalf("verify: %d %s", c, out)
	}
}

func TestVerifyCatches(t *testing.T) {
	for name, mutate := range map[string]func(d string){
		"changed file": func(d string) { write(t, d, "names/name.go", "package names // edited\n") },
		"missing file": func(d string) { os.Remove(filepath.Join(d, "names", "name.go")) },
		"extra file":   func(d string) { write(t, d, "new.go", "package x\n") },
		"crlf in go":   func(d string) { write(t, d, "names/name.go", "package names\r\n") },
		"bad checksums line": func(d string) {
			os.WriteFile(filepath.Join(d, "CHECKSUMS"), []byte("nonsense\n"), 0o644)
		},
		"no checksums": func(d string) { os.Remove(filepath.Join(d, "CHECKSUMS")) },
	} {
		d := tree(t)
		do(t, "hash", d)
		mutate(d)
		if c, out := do(t, "verify", d); c != 1 {
			t.Errorf("%s: exit %d, want 1\n%s", name, c, out)
		}
	}
}

func TestCRInTextRefusesToHash(t *testing.T) {
	d := tree(t)
	write(t, d, "readme.md", "line\r\nline\r\n")
	if c, out := do(t, "hash", d); c != 1 || !strings.Contains(out, "carriage return in readme.md") {
		t.Fatalf("%d %s", c, out)
	}
}

func TestCaseFoldCollision(t *testing.T) {
	d := tree(t)
	write(t, d, "Names/Name.go", "package names\n")
	write(t, d, "names/NAME.go", "package names\n")
	// On a case-insensitive file system the second write overwrote the first, so
	// only assert when two real files exist.
	files, problems, err := scan(d)
	if err != nil {
		t.Fatal(err)
	}
	_ = files
	lower := map[string]int{}
	for _, f := range files {
		lower[strings.ToLower(f.path)]++
	}
	collides := false
	for _, n := range lower {
		if n > 1 {
			collides = true
		}
	}
	if collides && len(problems) == 0 {
		t.Fatal("two paths equal under case folding were not reported")
	}
}

func TestSymlinkIsAProblem(t *testing.T) {
	d := tree(t)
	if err := os.Symlink(filepath.Join(d, "go.mod"), filepath.Join(d, "link.go")); err != nil {
		t.Skip("symlinks not available:", err)
	}
	if c, out := do(t, "hash", d); c != 1 || !strings.Contains(out, "symlink: link.go") {
		t.Fatalf("%d %s", c, out)
	}
}

func TestSyncAndTreeHash(t *testing.T) {
	src := tree(t)
	dst := filepath.Join(t.TempDir(), "Ctrl Z Node", "shared")
	if c, out := do(t, "sync", "--from", src, "--to", dst); c != 0 {
		t.Fatalf("first sync: %d %s", c, out)
	}
	if c, out := do(t, "verify", src, dst); c != 0 || !strings.Contains(out, "2 copies identical") {
		t.Fatalf("verify both: %d %s", c, out)
	}
	// A second sync with nothing changed writes nothing.
	if c, out := do(t, "sync", "--from", src, "--to", dst); c != 0 || !strings.Contains(out, "written=0") {
		t.Fatalf("idempotent sync: %d %s", c, out)
	}
	// A canonical change propagates, including a deletion.
	write(t, src, "names/name.go", "package names // v2\n")
	os.Remove(filepath.Join(src, "vectors", "a.json"))
	if c, out := do(t, "sync", "--from", src, "--to", dst); c != 0 || !strings.Contains(out, "deleted=1") {
		t.Fatalf("propagating sync: %d %s", c, out)
	}
	if _, err := os.Stat(filepath.Join(dst, "vectors")); err == nil {
		t.Fatal("empty directory left behind")
	}
	if c, out := do(t, "verify", src, dst); c != 0 {
		t.Fatalf("after propagate: %d %s", c, out)
	}
}

func TestSyncRefusesLocalEditsUnlessForced(t *testing.T) {
	src := tree(t)
	dst := filepath.Join(t.TempDir(), "Ctrl Z Node", "shared")
	do(t, "sync", "--from", src, "--to", dst)
	// Someone edits the Node copy.
	write(t, dst, "names/name.go", "package names // edited in the wrong place\n")
	write(t, dst, "stray.go", "package x\n")
	c, out := do(t, "sync", "--from", src, "--to", dst)
	if c != 1 || !strings.Contains(out, "refusing to overwrite") {
		t.Fatalf("expected refusal: %d %s", c, out)
	}
	// The refused sync must not have touched anything.
	got, _ := os.ReadFile(filepath.Join(dst, "names", "name.go"))
	if !strings.Contains(string(got), "wrong place") {
		t.Fatal("a refused sync changed the target")
	}
	c, out = do(t, "sync", "--from", src, "--to", dst, "--force")
	if c != 0 || !strings.Contains(out, "overwrite names/name.go") || !strings.Contains(out, "delete stray.go") {
		t.Fatalf("forced sync: %d %s", c, out)
	}
	if c, out := do(t, "verify", src, dst); c != 0 {
		t.Fatalf("after force: %d %s", c, out)
	}
}

func TestReverseEditShowsUpAsCopyMismatch(t *testing.T) {
	src := tree(t)
	dst := filepath.Join(t.TempDir(), "Ctrl Z Node", "shared")
	do(t, "sync", "--from", src, "--to", dst)
	// An edit in the Node copy, with its CHECKSUMS regenerated to hide it.
	write(t, dst, "names/name.go", "package names // sneaky\n")
	do(t, "hash", dst)
	if c, out := do(t, "verify", src, dst); c != 1 || !strings.Contains(out, "copies differ") {
		t.Fatalf("%d %s", c, out)
	}
}

func TestUsageErrors(t *testing.T) {
	d := tree(t)
	for _, args := range [][]string{{}, {"bogus"}, {"hash"}, {"verify"}, {"sync"}, {"sync", "--from", d}, {"sync", "--from", d, "--to", d}} {
		if c, _ := do(t, args...); c != 2 {
			t.Errorf("%v: exit %d, want 2", args, c)
		}
	}
	if c, _ := do(t, "verify", filepath.Join(d, "nope")); c != 2 {
		t.Error("missing directory should be an I/O error")
	}
}

func TestFailoverVectorsWriteAndCheck(t *testing.T) {
	path := filepath.Join(t.TempDir(), "zone-failover.json")
	if code, out := do(t, "failover-vectors", "--out", path); code != exitOK {
		t.Fatalf("write: %d %s", code, out)
	}
	if code, out := do(t, "failover-vectors", "--check", path); code != exitOK {
		t.Fatalf("check of a fresh file: %d %s", code, out)
	}
	if err := os.WriteFile(path, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, out := do(t, "failover-vectors", "--check", path); code != exitMismatch || !strings.Contains(out, "differs") {
		t.Fatalf("check of an edited file: %d %s", code, out)
	}
	if code, _ := do(t, "failover-vectors"); code != exitUsage {
		t.Fatalf("no flag: %d", code)
	}
	if code, _ := do(t, "failover-vectors", "--out", path, "--check", path); code != exitUsage {
		t.Fatalf("both flags: %d", code)
	}
}
