package compiler

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
)

// Artifacts is the content-addressed store behind policy_artifacts (P4 6.5, R37). A file is named by the hex SHA-256 of
// its bytes, so a writer and a reader never need a record to agree on what a name means, and a stage-3 store can swap
// in behind this interface.
type Artifacts interface {
	// Put stores data under its hash. A second Put of the same bytes changes nothing.
	Put(hash []byte, data []byte) error
	// Ensure makes sure the hash is stored with bytes that match it: a file that is missing, or whose bytes are not the hash
	// (a size that matches is no proof), is written again.
	Ensure(hash []byte, data []byte) error
	// Has says whether the hash is stored with the size it was written with.
	Has(hash []byte, size int64) bool
	// Size is the stored size of the hash, -1 when it is not there.
	Size(hash []byte) int64
	// Get reads the bytes and checks them against the name.
	Get(hash []byte) ([]byte, error)
	// Delete removes the file; a file that is not there is not an error.
	Delete(hash []byte) error
}

// DirArtifacts is the store of the `artifacts` volume: one directory, files named by hash, written by the compiler and
// mounted read-only into the hub.
type DirArtifacts struct{ dir string }

// NewDirArtifacts opens (and makes) the directory.
func NewDirArtifacts(dir string) (*DirArtifacts, error) {
	if dir == "" {
		return nil, errors.New("compiler: no artifacts directory")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("compiler: artifacts directory: %w", err)
	}
	return &DirArtifacts{dir: dir}, nil
}

// path is the file of a hash. A hash that is not 32 bytes has no file, so a caller cannot name a path with it.
func (d *DirArtifacts) path(hash []byte) (string, error) {
	if len(hash) != 32 {
		return "", errors.New("compiler: artifact hash is not 32 bytes")
	}
	return filepath.Join(d.dir, hex.EncodeToString(hash)), nil
}

// Put writes through a temporary file, syncs it and renames it, so a reader never sees half a file and a crash leaves
// either no file or the whole one. The hash is checked first: a store that took bytes under a wrong name would make
// every node refuse them.
func (d *DirArtifacts) Put(hash []byte, data []byte) error {
	p, err := d.path(hash)
	if err != nil {
		return err
	}
	if sum := sha256.Sum256(data); string(sum[:]) != string(hash) {
		return errors.New("compiler: artifact bytes do not match their hash")
	}
	if d.Has(hash, int64(len(data))) {
		return nil
	}
	return d.write(p, data)
}

// Ensure is Put that does not trust the size of a file that is there: it reads the file and writes it again when the
// bytes are not the hash. The full pass of the compiler uses it for every bound blob, once per lease.
func (d *DirArtifacts) Ensure(hash []byte, data []byte) error {
	p, err := d.path(hash)
	if err != nil {
		return err
	}
	if sum := sha256.Sum256(data); string(sum[:]) != string(hash) {
		return errors.New("compiler: artifact bytes do not match their hash")
	}
	if _, err := d.Get(hash); err == nil {
		return nil
	}
	return d.write(p, data)
}

// write is the temporary file, its sync, its rename and the sync of the directory that holds the new name.
func (d *DirArtifacts) write(p string, data []byte) error {
	tmp, err := os.CreateTemp(d.dir, ".put-*")
	if err != nil {
		return fmt.Errorf("compiler: artifact temp file: %w", err)
	}
	name := tmp.Name()
	defer os.Remove(name) // a no-op after the rename
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("compiler: artifact write: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("compiler: artifact sync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("compiler: artifact close: %w", err)
	}
	if err := os.Chmod(name, 0o644); err != nil {
		return fmt.Errorf("compiler: artifact mode: %w", err)
	}
	if err := os.Rename(name, p); err != nil {
		return fmt.Errorf("compiler: artifact rename: %w", err)
	}
	// The rename is in the directory until the directory is synced: after a power loss the entry may name a hash whose
	// file never reached the disk, while Postgres has committed the entry.
	return syncDir(d.dir)
}

// syncDir flushes a directory. Windows has no such call for a directory, and the store runs on Linux in production.
func syncDir(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	f, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("compiler: artifact directory: %w", err)
	}
	defer f.Close()
	if err := f.Sync(); err != nil {
		return fmt.Errorf("compiler: artifact directory sync: %w", err)
	}
	return nil
}

// Size is the size of the stored file, -1 for none. A link, a directory or anything else that is not a regular file
// reads as none.
func (d *DirArtifacts) Size(hash []byte) int64 {
	p, err := d.path(hash)
	if err != nil {
		return -1
	}
	fi, err := os.Lstat(p)
	if err != nil || !fi.Mode().IsRegular() {
		return -1
	}
	return fi.Size()
}

// Has reports a stored file of that size.
func (d *DirArtifacts) Has(hash []byte, size int64) bool { return d.Size(hash) == size }

// Get reads a file whole and checks it against its name.
func (d *DirArtifacts) Get(hash []byte) ([]byte, error) {
	p, err := d.path(hash)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, fmt.Errorf("compiler: artifact: %w", err)
	}
	defer f.Close()
	// The bound is the largest thing the store holds: a table (2 GiB) never goes through Get, a blob or a snapshot
	// does, and a snapshot is under four times the entry cap.
	data, err := io.ReadAll(io.LimitReader(f, 1<<30))
	if err != nil {
		return nil, fmt.Errorf("compiler: artifact read: %w", err)
	}
	if sum := sha256.Sum256(data); string(sum[:]) != string(hash) {
		return nil, errors.New("compiler: artifact does not match its name")
	}
	return data, nil
}

// Delete removes the file of a hash.
func (d *DirArtifacts) Delete(hash []byte) error {
	p, err := d.path(hash)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("compiler: artifact delete: %w", err)
	}
	return nil
}

// sha256Sum is the name of a stored file.
func sha256Sum(b []byte) []byte {
	s := sha256.Sum256(b)
	return s[:]
}
