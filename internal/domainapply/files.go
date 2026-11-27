package domainapply

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// Files of the Caddy data volume are written the way a crash leaves either the old or the new content and never half of
// one: the bytes go to a temporary name in the same directory, are flushed, and the rename puts them in place. A reader
// (Caddy, at start) sees the old file or the new file. The pair of a certificate and its key is made atomic one level up,
// by naming them with the id of the certificate and pointing at them from one small snippet that is renamed last
// (apply.go).

// tmpPrefix starts the name of a file being written. It begins with a dot so that the glob Caddy imports the snippet by
// ("<host>.cadd?") never matches it.
const tmpPrefix = ".tmp-"

// tmpName is the temporary name of a file being written. It is a hash of the final name and not the name itself: a final
// name may already be near the 255 bytes a file name holds, and a prefix on it would push it over (R34-r1-12).
func tmpName(name string) string {
	sum := sha256.Sum256([]byte(name))
	return tmpPrefix + hex.EncodeToString(sum[:8])
}

// writeAtomic writes data to dir/name with the given mode and replaces any file there in one rename.
func writeAtomic(dir, name string, data []byte, mode os.FileMode) (err error) {
	tmp := filepath.Join(dir, tmpName(name))
	// A leftover of a crashed run: one process writes here at a time (the script holds a lock), so it is stale.
	if rerr := os.Remove(tmp); rerr != nil && !errors.Is(rerr, os.ErrNotExist) {
		return rerr
	}
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = f.Close()
			_ = os.Remove(tmp)
		}
	}()
	if _, err = f.Write(data); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmp, filepath.Join(dir, name)); err != nil {
		return err
	}
	syncDir(dir)
	return nil
}

// syncDir flushes the directory entry of a rename. It is best effort: some filesystems refuse to sync a directory, the
// rename is atomic for every reader either way, and a power cut that loses it is repaired by the next run.
func syncDir(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	_ = d.Sync()
	_ = d.Close()
}

// ours says whether a name in the directory is one this tool writes. Anything else is left alone.
func ours(name string) bool {
	return strings.HasPrefix(name, tmpPrefix) || strings.HasSuffix(name, ".caddy") || strings.HasSuffix(name, ".crt") || strings.HasSuffix(name, ".key")
}

// prune removes every file of ours that is not in keep: the pairs and snippets of an earlier apply, and the temporary
// files of a crashed one. It runs only from Prune, after the services have been recreated on the new .env: until then
// the old containers, and a restart of the old Caddy, still read the old files (R34-r2-1, r2-5). A failure here leaves a
// correct directory with some stale files, which the next run removes.
func prune(dir string, keep map[string]bool) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() || keep[e.Name()] || !ours(e.Name()) {
			continue
		}
		if err := os.Remove(filepath.Join(dir, e.Name())); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

// snippetPath is where the snippet of a host lives in the directory.
func snippetPath(dir, host string) string { return filepath.Join(dir, snippetName(host)) }

// keepNamed adds to keep the snippet of every host in hosts and the files that snippet names. The snippet is read as text
// this tool wrote: the two paths after `tls`, each reduced to its base name and kept only when it is one of ours. What
// the snippet on disk names is kept whatever the plan says, because that is what Caddy reads at its next start. A host
// with no snippet has nothing to keep; a snippet that cannot be read is an error, never "no snippet", because the
// clean-up would then delete the files of a host that is being served (R34-r3-3).
func keepNamed(dir string, hosts []string, keep map[string]bool) error {
	for _, h := range hosts {
		b, err := os.ReadFile(snippetPath(dir, h))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("read the snippet of the host %s: %w", h, err)
		}
		keep[snippetName(h)] = true
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) != 3 || f[0] != "tls" {
				continue
			}
			for _, p := range f[1:] {
				if base := path.Base(p); ours(base) && !strings.HasPrefix(base, tmpPrefix) {
					keep[base] = true
				}
			}
		}
	}
	return nil
}
