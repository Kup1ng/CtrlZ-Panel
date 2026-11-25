package admincli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
)

// RunKeys is `ctrlz keys <command>`. It needs no database: `keys derive` turns
// the host's kek_root into the per-domain key files (spec 8.3), and
// scripts/gen-secrets.sh runs it in a throwaway container with no network.
func RunKeys(ctx context.Context, args []string, env Env) int {
	env = env.withDefaults()
	if len(args) > 0 {
		switch args[0] {
		case "derive":
			return finish(env, deriveKeys(env, args[1:]))
		}
	}
	fmt.Fprintln(env.Stderr, "usage: ctrlz keys derive [--dir DIR] [--new-root] [--rotate DOMAIN]")
	return ExitUsage
}

// deriveKeys writes kek_<domain> version 1 for every domain that has no file, or
// with --rotate appends the next number to one domain's file. The output names
// domains and key numbers; it never prints a key.
//
// Which root a file belongs to is proved, not guessed (review round 5, rule
// key-identity): every file that exists is derived again from kek_root and
// compared, and a file whose newest key the root does not derive is refused with
// nothing written. Skipping "a file that exists" by its name is how a wrong
// backup, or a root made again, used to pass as good.
func deriveKeys(env Env, args []string) error {
	fs := newFlags(env, "keys derive")
	dir := fs.String("dir", "/secrets", "the directory holding kek_root and the key files")
	rotate := fs.String("rotate", "", "append a new key number to this domain's file")
	newRoot := fs.Bool("new-root", false, "kek_root is a new root made after the old one was lost (spec 8.5): key files it does not own are kept as they are, and with --rotate the new key comes from it")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 0 {
		return usageErr("keys derive takes no arguments besides its flags")
	}
	root, err := keyring.LoadRoot(filepath.Join(*dir, keyring.RootFileName))
	if err != nil {
		// The root's path is the operator's; the error names the file and the
		// problem, not its content.
		return fmt.Errorf("%s: %w", keyring.RootFileName, err)
	}
	defer root.Wipe()
	if *rotate != "" {
		return rotateDomain(env, *dir, root, *rotate, *newRoot)
	}
	return deriveAll(env, *dir, root, *newRoot)
}

// missingKeyFilesError is a refusal that left key files missing as well: the files that exist are not
// the root's, so nothing was written, and the ones that do not exist could not be made. It keeps the
// refusal for errors.Is and has its own exit code (ExitRefusedMissing).
type missingKeyFilesError struct {
	missing []string // file names
	stale   []string // public files that no longer say what their key file says
	refusal error
}

func (e missingKeyFilesError) Error() string {
	msg := e.refusal.Error()
	if len(e.missing) > 0 {
		msg += "; " + strings.Join(e.missing, ", ") + " is missing and was not made, because a key file is made only from the root that owns the rest"
	}
	if len(e.stale) > 0 {
		// Said apart so the operator does not look for a file that is there: it exists but would give a
		// verifier a key the key file has dropped.
		msg += "; " + strings.Join(e.stale, ", ") + " does not match its key file and was not rewritten, because a refused run writes nothing"
	}
	return msg
}

func (e missingKeyFilesError) Unwrap() error { return e.refusal }

// deriveAll proves every existing key file against the root first and writes the
// missing ones only when none was refused, so a refusal leaves the directory as it
// was and never a mix of files from two roots.
func deriveAll(env Env, dir string, root secret.Bytes, newRoot bool) error {
	var missing, foreign []string
	// missingPublic counts as a missing key file when a refusal stops the run: a public file is a pure
	// function of its key file, so it is made only from a key file the root has proved.
	var missingPublic, stalePublic []string
	var refused []error
	for _, d := range keyring.Domains() {
		text, err := secret.BytesFromFile(filepath.Join(dir, keyring.FileName(d)))
		if errors.Is(err, os.ErrNotExist) {
			missing = append(missing, d)
			continue
		}
		if err != nil {
			return fmt.Errorf("%s: cannot be read", keyring.FileName(d))
		}
		prov, err := keyring.Identify(root, d, text)
		text.Wipe()
		if err != nil {
			return fmt.Errorf("%s: %w", keyring.FileName(d), err)
		}
		if !prov.NewestFromRoot() {
			if !newRoot {
				refused = append(refused, prov.MismatchError())
				continue
			}
			foreign = append(foreign, d)
		}
	}
	for _, d := range keyring.PublicDomains() {
		// Read, not looked at: a key tool does not decide from a file being there (rule key-identity), and the text
		// it reads here is judged by nobody, since the public file is rewritten from the key file whatever it says.
		have, err := secret.BytesFromFile(filepath.Join(dir, keyring.PublicFileName(d)))
		if errors.Is(err, os.ErrNotExist) {
			missingPublic = append(missingPublic, d)
			continue
		}
		if err != nil {
			continue
		}
		// A stale file is told apart from a good one even when a refusal stops the run (review dec-a-r1-4): the
		// public text needs no root, and an install whose kek_root is off the host always ends in a refusal, so a
		// public file that still lists a key line the operator removed would stay and be trusted by the api for
		// ever. A key file that is missing is counted above, and one that does not parse was refused above.
		if keyText, kerr := secret.BytesFromFile(filepath.Join(dir, keyring.FileName(d))); kerr == nil {
			if want, werr := keyring.PublicText(d, keyText); werr == nil && !bytes.Equal(have.Reveal(), want) {
				stalePublic = append(stalePublic, d)
			}
			keyText.Wipe()
		}
		have.Wipe()
	}
	if len(refused) > 0 {
		err := fmt.Errorf("%w; put back the kek_root these files came from, or if it is lost for good run again with --new-root (spec 8.5)", errors.Join(refused...))
		if len(missing) > 0 || len(missingPublic) > 0 || len(stalePublic) > 0 {
			// Nothing is written on a refusal, so these were not made or refreshed either.
			var names, stale []string
			for _, d := range stalePublic {
				stale = append(stale, keyring.PublicFileName(d))
			}
			for _, d := range missing {
				names = append(names, keyring.FileName(d))
			}
			for _, d := range missingPublic {
				names = append(names, keyring.PublicFileName(d))
			}
			return missingKeyFilesError{missing: names, stale: stale, refusal: err}
		}
		return err
	}
	for _, d := range keyring.Domains() {
		if !slices.Contains(missing, d) {
			if slices.Contains(foreign, d) {
				fmt.Fprintf(env.Stdout, "kept %s (not derived from this kek_root)\n", keyring.FileName(d))
			} else {
				fmt.Fprintf(env.Stdout, "kept %s\n", keyring.FileName(d))
			}
			continue
		}
		text, err := keyring.FileText(root, d, 1)
		if err != nil {
			return err
		}
		err = writeKeyFile(filepath.Join(dir, keyring.FileName(d)), text, false)
		text.Wipe()
		if err != nil {
			return fmt.Errorf("%s: %w", keyring.FileName(d), err)
		}
		fmt.Fprintf(env.Stdout, "wrote %s (key 1)\n", keyring.FileName(d))
	}
	for _, d := range keyring.PublicDomains() {
		if err := refreshPublic(env, dir, d); err != nil {
			return err
		}
	}
	if len(foreign) > 0 {
		// On stderr so the installer script, which hides the list above, still shows
		// it: these files are not what a restore from this root would give back.
		fmt.Fprintf(env.Stderr, "ctrlz: the key files of %s are NOT derived from this kek_root; rotate each onto it: ctrlz keys derive --rotate DOMAIN --new-root (spec 8.5)\n", strings.Join(foreign, ", "))
	}
	return nil
}

// rotateDomain appends number n+1 to a domain's key file (8.4 step 1).
func rotateDomain(env Env, dir string, root secret.Bytes, domain string, newRoot bool) error {
	if !keyring.ValidDomain(domain) {
		return usageErr("unknown domain %q", domain)
	}
	path := filepath.Join(dir, keyring.FileName(domain))
	current, err := secret.BytesFromFile(path)
	if err != nil {
		return fmt.Errorf("%s: cannot be read", keyring.FileName(domain))
	}
	defer current.Wipe()
	// By default the root must be the one the file's keys came from (review round 1):
	// appending a key from another root would mix two roots in one file and make
	// "re-derive from the root" untrue. --new-root is the explicit act of 8.5.
	rotateFn := keyring.Rotate
	if newRoot {
		rotateFn = keyring.RotateToNewRoot
	}
	next, n, err := rotateFn(root, domain, current)
	if err != nil {
		return err
	}
	defer next.Wipe()
	if err := writeKeyFile(path, next, true); err != nil {
		return fmt.Errorf("%s: %w", keyring.FileName(domain), err)
	}
	fmt.Fprintf(env.Stdout, "domain %s: key %d added\n", domain, n)
	// The public half follows the key file at once, so the api can be recreated with the new number
	// before admin signs under it (spec 8.4).
	if slices.Contains(keyring.PublicDomains(), domain) {
		return refreshPublic(env, dir, domain)
	}
	return nil
}

// refreshPublic writes pub_<domain> from the text of kek_<domain>, or leaves it when it already says the same.
// The file is a pure function of the key file, so it is never judged, only rewritten when it differs (spec 8.3,
// D67): a stale file after a rotation, a hand edit and a removed key line all end the same way.
func refreshPublic(env Env, dir, domain string) error {
	keyText, err := secret.BytesFromFile(filepath.Join(dir, keyring.FileName(domain)))
	if err != nil {
		return fmt.Errorf("%s: cannot be read", keyring.FileName(domain))
	}
	want, err := keyring.PublicText(domain, keyText)
	keyText.Wipe()
	if err != nil {
		return fmt.Errorf("%s: %w", keyring.FileName(domain), err)
	}
	path := filepath.Join(dir, keyring.PublicFileName(domain))
	if have, err := secret.BytesFromFile(path); err == nil {
		same := bytes.Equal(have.Reveal(), want)
		have.Wipe()
		if same {
			fmt.Fprintf(env.Stdout, "kept %s\n", keyring.PublicFileName(domain))
			return nil
		}
	}
	// The text holds no secret, but the writer is the key file's, with the same mode and the same rename.
	text := secret.NewBytes(want)
	defer text.Wipe()
	if err := writeKeyFile(path, text, true); err != nil {
		return fmt.Errorf("%s: %w", keyring.PublicFileName(domain), err)
	}
	fmt.Fprintf(env.Stdout, "wrote %s\n", keyring.PublicFileName(domain))
	return nil
}

// writeKeyFile writes a key file with mode 0444, the rule every secret file
// follows (8.3). A new file is created exclusively, so a concurrent writer or an
// existing file is never overwritten silently; a rotation replaces the file by
// renaming a finished temporary over it, so a crash leaves the old file whole
// and never a half-written key.
func writeKeyFile(path string, text secret.Bytes, replace bool) error {
	if !replace {
		return writeNew(path, text)
	}
	tmp := path + ".new"
	_ = os.Remove(tmp)
	if err := writeNew(tmp, text); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		// Some platforms refuse to rename over a read-only file. Remove it and try
		// again; the finished temporary is still there if this second step fails.
		if rmErr := os.Remove(path); rmErr != nil {
			_ = os.Remove(tmp)
			return errors.New("cannot be replaced")
		}
		if err := os.Rename(tmp, path); err != nil {
			return errors.New("cannot be replaced, the new text is in " + filepath.Base(tmp))
		}
	}
	return nil
}

func writeNew(path string, text secret.Bytes) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o444)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return errors.New("already exists")
		}
		return errors.New("cannot be created")
	}
	_, werr := f.Write(text.Reveal())
	cerr := f.Close()
	if werr != nil || cerr != nil {
		_ = os.Remove(path)
		return errors.New("cannot be written")
	}
	return nil
}
