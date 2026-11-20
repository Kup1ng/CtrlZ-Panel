// Command sharedtool keeps the two copies of the shared module identical.
//
// "Ctrl Z Panel/shared" is canonical and "Ctrl Z Node/shared" is a copy. A
// copy that drifts silently is how a node and a panel end up deciding the same
// query differently, so the copy is checked byte for byte: every file has a
// SHA-256 in CHECKSUMS, and the hash of CHECKSUMS itself is the tree hash two
// copies must share.
//
// It is plain Go with only the standard library, so it behaves the same on
// Windows and Linux. It never starts a shell and never normalizes line
// endings: a CRLF that sneaks into a source file is an error, not something to
// fix up silently. Paths come in as arguments, so directories with spaces in
// their names work.
//
// Usage:
//
//	sharedtool hash <dir>
//	sharedtool verify <dir> [<dir>...]
//	sharedtool sync --from <dir> --to <dir> [--force]
//
// Exit codes: 0 ok, 1 mismatch, 2 usage or I/O error. Output names paths and
// hashes and never prints file contents.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const checksumsName = "CHECKSUMS"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

const (
	exitOK       = 0
	exitMismatch = 1
	exitUsage    = 2
)

func run(args []string, out, errw io.Writer) int {
	if len(args) == 0 {
		usage(errw)
		return exitUsage
	}
	switch args[0] {
	case "hash":
		if len(args) != 2 {
			usage(errw)
			return exitUsage
		}
		return cmdHash(args[1], out, errw)
	case "verify":
		if len(args) < 2 {
			usage(errw)
			return exitUsage
		}
		return cmdVerify(args[1:], out, errw)
	case "sync":
		return cmdSync(args[1:], out, errw)
	}
	usage(errw)
	return exitUsage
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "usage:\n  sharedtool hash <dir>\n  sharedtool verify <dir> [<dir>...]\n  sharedtool sync --from <dir> --to <dir> [--force]")
}

// file is one tracked file: its slash path relative to the root and SHA-256.
type file struct {
	path string
	sum  string
}

// textExt are the extensions in which a carriage return is an error. The two
// copies are compared byte for byte, and .gitattributes pins eol=lf, so a CR
// means a tool on one machine rewrote line endings.
var textExt = map[string]bool{".go": true, ".proto": true, ".json": true, ".yaml": true, ".md": true}

// scan lists the tracked files of dir and every problem found on the way:
// symlinks, carriage returns in text files, and paths that collide under case
// folding (two files that cannot both exist on Windows).
func scan(dir string) (files []file, problems []string, err error) {
	root, err := filepath.Abs(dir)
	if err != nil {
		return nil, nil, err
	}
	st, err := os.Stat(root)
	if err != nil {
		return nil, nil, err
	}
	if !st.IsDir() {
		return nil, nil, fmt.Errorf("%s is not a directory", dir)
	}
	folded := map[string]string{}
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if rel == checksumsName {
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			problems = append(problems, "symlink: "+rel)
			return nil
		}
		if !d.Type().IsRegular() {
			problems = append(problems, "not a regular file: "+rel)
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if textExt[strings.ToLower(filepath.Ext(rel))] && bytes.IndexByte(data, '\r') >= 0 {
			problems = append(problems, "carriage return in "+rel)
		}
		key := strings.ToLower(rel)
		if prev, dup := folded[key]; dup {
			problems = append(problems, fmt.Sprintf("paths equal under case folding: %s and %s", prev, rel))
		}
		folded[key] = rel
		sum := sha256.Sum256(data)
		files = append(files, file{path: rel, sum: hex.EncodeToString(sum[:])})
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	sort.Slice(files, func(i, j int) bool { return files[i].path < files[j].path })
	sort.Strings(problems)
	return files, problems, nil
}

// render builds CHECKSUMS: "<sha256 hex>  <path>\n", sorted by path bytes.
func render(files []file) []byte {
	var b bytes.Buffer
	for _, f := range files {
		fmt.Fprintf(&b, "%s  %s\n", f.sum, f.path)
	}
	return b.Bytes()
}

func treeHash(checksums []byte) string {
	s := sha256.Sum256(checksums)
	return hex.EncodeToString(s[:])
}

// parseChecksums reads CHECKSUMS strictly: any line that is not exactly
// "<64 hex>  <path>" is an error, so a hand-edited file cannot slip through.
func parseChecksums(data []byte) (map[string]string, error) {
	m := map[string]string{}
	if len(data) == 0 {
		return m, nil
	}
	if data[len(data)-1] != '\n' {
		return nil, errors.New("CHECKSUMS does not end with a newline")
	}
	last := ""
	for i, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		if len(line) < 67 || line[64] != ' ' || line[65] != ' ' {
			return nil, fmt.Errorf("CHECKSUMS line %d is malformed", i+1)
		}
		if _, err := hex.DecodeString(line[:64]); err != nil || strings.ToLower(line[:64]) != line[:64] {
			return nil, fmt.Errorf("CHECKSUMS line %d has a bad hash", i+1)
		}
		p := line[66:]
		if p <= last {
			return nil, fmt.Errorf("CHECKSUMS line %d is out of order or repeated", i+1)
		}
		last = p
		m[p] = line[:64]
	}
	return m, nil
}

// writeAtomic writes data to path through a temporary file in the same
// directory, so a crash leaves the old file or the new one, never half.
func writeAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".sharedtool-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Chmod(name, 0o644); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Rename(name, path); err != nil {
		os.Remove(name)
		return err
	}
	return nil
}

func cmdHash(dir string, out, errw io.Writer) int {
	files, problems, err := scan(dir)
	if err != nil {
		fmt.Fprintln(errw, "error:", err)
		return exitUsage
	}
	if len(problems) > 0 {
		for _, p := range problems {
			fmt.Fprintln(out, "FAIL", p)
		}
		return exitMismatch
	}
	data := render(files)
	if err := writeAtomic(filepath.Join(dir, checksumsName), data); err != nil {
		fmt.Fprintln(errw, "error:", err)
		return exitUsage
	}
	fmt.Fprintf(out, "hashed %s files=%d tree=%s\n", dir, len(files), treeHash(data))
	return exitOK
}

// check compares dir against its CHECKSUMS and returns the problems and the
// tree hash. A nil problems list means the directory is exactly what its
// CHECKSUMS says.
func check(dir string) (problems []string, tree string, err error) {
	files, scanProblems, err := scan(dir)
	if err != nil {
		return nil, "", err
	}
	problems = append(problems, scanProblems...)
	raw, err := os.ReadFile(filepath.Join(dir, checksumsName))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return append(problems, "CHECKSUMS is missing"), "", nil
		}
		return nil, "", err
	}
	want, err := parseChecksums(raw)
	if err != nil {
		return append(problems, err.Error()), "", nil
	}
	have := map[string]string{}
	for _, f := range files {
		have[f.path] = f.sum
		w, ok := want[f.path]
		switch {
		case !ok:
			problems = append(problems, "extra file: "+f.path)
		case w != f.sum:
			problems = append(problems, fmt.Sprintf("hash mismatch: %s have %s want %s", f.path, f.sum, w))
		}
	}
	for p := range want {
		if _, ok := have[p]; !ok {
			problems = append(problems, "missing file: "+p)
		}
	}
	sort.Strings(problems)
	return problems, treeHash(raw), nil
}

func cmdVerify(dirs []string, out, errw io.Writer) int {
	code := exitOK
	trees := make([]string, len(dirs))
	for i, d := range dirs {
		problems, tree, err := check(d)
		if err != nil {
			fmt.Fprintln(errw, "error:", err)
			return exitUsage
		}
		trees[i] = tree
		if len(problems) > 0 {
			code = exitMismatch
			for _, p := range problems {
				fmt.Fprintf(out, "FAIL %s: %s\n", d, p)
			}
			continue
		}
		fmt.Fprintf(out, "ok %s tree=%s\n", d, tree)
	}
	if len(dirs) > 1 && code == exitOK {
		for i := 1; i < len(dirs); i++ {
			if trees[i] != trees[0] {
				fmt.Fprintf(out, "FAIL copies differ: %s tree=%s, %s tree=%s\n", dirs[0], trees[0], dirs[i], trees[i])
				code = exitMismatch
			}
		}
		if code == exitOK {
			fmt.Fprintf(out, "ok %d copies identical tree=%s\n", len(dirs), trees[0])
		}
	}
	return code
}

func cmdSync(args []string, out, errw io.Writer) int {
	fset := flag.NewFlagSet("sync", flag.ContinueOnError)
	fset.SetOutput(errw)
	from := fset.String("from", "", "canonical directory (Ctrl Z Panel/shared)")
	to := fset.String("to", "", "directory to overwrite (Ctrl Z Node/shared)")
	force := fset.Bool("force", false, "overwrite local edits in the target and print each path")
	if err := fset.Parse(args); err != nil || *from == "" || *to == "" || fset.NArg() != 0 {
		usage(errw)
		return exitUsage
	}
	if a, _ := filepath.Abs(*from); a == mustAbs(*to) {
		fmt.Fprintln(errw, "error: --from and --to are the same directory")
		return exitUsage
	}

	// 1. The source must describe itself truthfully before it is copied.
	if c := cmdHash(*from, io.Discard, errw); c != exitOK {
		fmt.Fprintf(out, "FAIL source %s cannot be hashed (symlink, carriage return or case collision)\n", *from)
		return c
	}
	if problems, _, err := check(*from); err != nil {
		fmt.Fprintln(errw, "error:", err)
		return exitUsage
	} else if len(problems) > 0 {
		for _, p := range problems {
			fmt.Fprintf(out, "FAIL %s: %s\n", *from, p)
		}
		return exitMismatch
	}
	srcFiles, _, err := scan(*from)
	if err != nil {
		fmt.Fprintln(errw, "error:", err)
		return exitUsage
	}

	// 2. Refuse to overwrite local edits in the target. Edits belong in the
	// canonical copy; an edit made in the Node copy would be lost silently by
	// a plain sync, so it must be asked for.
	if st, err := os.Stat(*to); err == nil && st.IsDir() {
		dstFiles, _, err := scan(*to)
		if err != nil {
			fmt.Fprintln(errw, "error:", err)
			return exitUsage
		}
		if len(dstFiles) > 0 {
			problems, _, err := check(*to)
			if err != nil {
				fmt.Fprintln(errw, "error:", err)
				return exitUsage
			}
			if len(problems) > 0 && !*force {
				for _, p := range problems {
					fmt.Fprintf(out, "FAIL %s: %s\n", *to, p)
				}
				fmt.Fprintln(out, "refusing to overwrite: the target does not match its own CHECKSUMS (local edits). Re-run with --force to overwrite them.")
				return exitMismatch
			}
		}
	} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
		fmt.Fprintln(errw, "error:", err)
		return exitUsage
	}

	// 3. Mirror.
	if err := os.MkdirAll(*to, 0o755); err != nil {
		fmt.Fprintln(errw, "error:", err)
		return exitUsage
	}
	want := map[string]bool{}
	written := 0
	for _, f := range srcFiles {
		want[f.path] = true
		data, err := os.ReadFile(filepath.Join(*from, filepath.FromSlash(f.path)))
		if err != nil {
			fmt.Fprintln(errw, "error:", err)
			return exitUsage
		}
		dst := filepath.Join(*to, filepath.FromSlash(f.path))
		if cur, err := os.ReadFile(dst); err == nil {
			if bytes.Equal(cur, data) {
				continue
			}
			if *force {
				fmt.Fprintln(out, "overwrite", f.path)
			}
		}
		if err := writeAtomic(dst, data); err != nil {
			fmt.Fprintln(errw, "error:", err)
			return exitUsage
		}
		written++
	}
	dstFiles, _, err := scan(*to)
	if err != nil {
		fmt.Fprintln(errw, "error:", err)
		return exitUsage
	}
	deleted := 0
	for _, f := range dstFiles {
		if want[f.path] {
			continue
		}
		if *force {
			fmt.Fprintln(out, "delete", f.path)
		}
		if err := os.Remove(filepath.Join(*to, filepath.FromSlash(f.path))); err != nil {
			fmt.Fprintln(errw, "error:", err)
			return exitUsage
		}
		deleted++
	}
	removeEmptyDirs(*to)
	sum, err := os.ReadFile(filepath.Join(*from, checksumsName))
	if err != nil {
		fmt.Fprintln(errw, "error:", err)
		return exitUsage
	}
	if err := writeAtomic(filepath.Join(*to, checksumsName), sum); err != nil {
		fmt.Fprintln(errw, "error:", err)
		return exitUsage
	}

	// 4. Prove it: both copies verify and share one tree hash.
	if c := cmdVerify([]string{*from, *to}, out, errw); c != exitOK {
		return c
	}
	fmt.Fprintf(out, "synced %s -> %s written=%d deleted=%d\n", *from, *to, written, deleted)
	return exitOK
}

func mustAbs(p string) string {
	a, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	return a
}

// removeEmptyDirs deletes directories left empty after extra files were
// removed. It never touches .git.
func removeEmptyDirs(root string) {
	var dirs []string
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.IsDir() && p != root {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			dirs = append(dirs, p)
		}
		return nil
	})
	for i := len(dirs) - 1; i >= 0; i-- {
		if ents, err := os.ReadDir(dirs[i]); err == nil && len(ents) == 0 {
			_ = os.Remove(dirs[i])
		}
	}
}
