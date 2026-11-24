package migrategen

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// The migration manifest (rule applied-migrations-are-frozen, P1 auth review round 7).
//
// README says "a migration that has been applied anywhere is never edited", and nothing enforced
// it: goose records version numbers and no checksum, and Generate only checks that the sources
// and the expansions agree. A fix edited into an applied file reaches fresh databases only, every
// test runs on a fresh database, and the deployed ones keep the old body, grant or policy. It
// fails open, in the security direction.
//
// migrations/postgres/applied.sum holds the SHA-256 of every expanded migration, one line each.
// A listed file whose text differs, a listed file that is gone and a migration that is not listed
// all fail. Adding a migration therefore takes one line in the manifest, written by genmig
// itself, and CHANGING a line is an explicit "genmig -bump NNNN_name.sql", a diff a reviewer
// reads as "somebody edited an applied migration" and asks why.

// ManifestHeader opens the manifest file and says what the file is for.
const ManifestHeader = `# SHA-256 of every expanded migration (migrations/postgres/0*.sql), line endings read as LF.
# A migration that has been applied anywhere is never edited (README, Rules): internal/migrategen
# fails for a listed file whose text changed, for a listed file that is gone and for a migration
# that is not listed. "go run ./tools/genmig" adds the line of a new migration. Changing a line
# is "go run ./tools/genmig -bump <file>" and a reviewed decision, not a routine step.
# The "newest:" line names the newest migration; genmig moves it forward when a migration is added
# and refuses to run when the migration it names has lost its line, so deleting the line of the
# newest migration does not lower the floor a new migration is measured from.
#
# One-time exception, recorded when this file was started (round 7): the comments inside the
# bodies of auth_otp_issue in 0010, 0011 and 0023 were reworded in round 6 (commit ff1dc2c) before
# anything was released. Behaviour did not change, and the manifest pins them as they are.
`

// HashMigration returns the hex SHA-256 of a migration's text with CRLF read as LF, so a checkout
// with other line endings hashes the same.
func HashMigration(text []byte) string {
	text = bytes.ReplaceAll(text, []byte("\r\n"), []byte("\n"))
	sum := sha256.Sum256(text)
	return hex.EncodeToString(sum[:])
}

// MigrationHashes hashes every 0*.sql of dir, by file name.
func MigrationHashes(dir string) (map[string]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), "0") || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		out[e.Name()] = HashMigration(b)
	}
	return out, nil
}

// NewestPrefix opens the line that names the newest migration of the manifest.
const NewestPrefix = "# newest: "

// ReadManifest reads the manifest. A missing file is an error (fs.ErrNotExist wrapped): the
// manifest is the enforcement, and an enforcement that can be deleted silently is none.
func ReadManifest(path string) (map[string]string, error) {
	out, _, err := readManifest(path)
	return out, err
}

// readManifest also returns the name on the "# newest:" line, or "" when the file has none. That
// line is the floor of "a new migration sorts after every listed one": taken from the listed lines
// alone, deleting the line of the newest migration (or of the last several) lowers the floor, the
// edited file is no longer below it, and the plain command lists it again with its current hash
// and no bump (db-r9-1). Keeping it apart from the lines means no deleted line can move it.
func readManifest(path string) (map[string]string, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, "", fmt.Errorf("migrategen: the migration manifest: %w", err)
	}
	defer f.Close()
	out := map[string]string{}
	newest := ""
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, NewestPrefix) {
			if newest != "" {
				return nil, "", fmt.Errorf("migrategen: %s names the newest migration twice", path)
			}
			newest = strings.TrimSpace(strings.TrimPrefix(line, NewestPrefix))
			if newest == "" || strings.ContainsAny(newest, " \t") {
				return nil, "", fmt.Errorf("migrategen: %s line %d is not \"# newest: <file>\"", path, n)
			}
			continue
		}
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 || len(fields[0]) != 64 {
			return nil, "", fmt.Errorf("migrategen: %s line %d is not \"<sha256>  <file>\"", path, n)
		}
		if _, dup := out[fields[1]]; dup {
			return nil, "", fmt.Errorf("migrategen: %s lists %s twice", path, fields[1])
		}
		out[fields[1]] = fields[0]
	}
	return out, newest, sc.Err()
}

// maxName is the greatest key of a set of migration names, "" for none.
func maxName(m map[string]string) string {
	newest := ""
	for name := range m {
		if name > newest {
			newest = name
		}
	}
	return newest
}

// VerifyManifest fails for every migration of dir that changed since it was listed, every listed
// migration that is gone, and every migration that is not listed.
func VerifyManifest(dir, manifest string) error {
	want, newest, err := readManifest(manifest)
	if err != nil {
		return err
	}
	have, err := MigrationHashes(dir)
	if err != nil {
		return err
	}
	var changed, gone, unlisted []string
	for name, h := range want {
		cur, ok := have[name]
		switch {
		case !ok:
			gone = append(gone, name)
		case cur != h:
			changed = append(changed, name)
		}
	}
	for name := range have {
		if _, ok := want[name]; !ok {
			unlisted = append(unlisted, name)
		}
	}
	sort.Strings(changed)
	sort.Strings(gone)
	sort.Strings(unlisted)
	base := filepath.Base(manifest)
	var problems []string
	if len(changed) > 0 {
		problems = append(problems, fmt.Sprintf("migrations edited after they were listed in %s: %s (an applied migration is never edited: fix forward with a new file, or `genmig -bump` if nothing ran this file anywhere)", base, strings.Join(changed, ", ")))
	}
	if len(gone) > 0 {
		problems = append(problems, fmt.Sprintf("migrations listed in %s that are gone: %s", base, strings.Join(gone, ", ")))
	}
	if len(unlisted) > 0 {
		problems = append(problems, fmt.Sprintf("migrations not listed in %s: %s (run go run ./tools/genmig)", base, strings.Join(unlisted, ", ")))
	}
	// The newest line must be there and must still be the newest listed migration: a deleted line
	// (of the newest migration or of the last several) leaves it naming a file that has no line, and
	// a deleted header leaves it missing, so neither is a quiet edit (db-r9-1).
	if len(want) > 0 {
		switch {
		case newest == "":
			problems = append(problems, fmt.Sprintf("%s has no %q line (restore it from version control)", base, strings.TrimSpace(NewestPrefix)))
		case want[newest] == "":
			problems = append(problems, fmt.Sprintf("%s names %s as the newest migration but lists no line for it: the line was removed (restore it from version control)", base, newest))
		case newest != maxName(want):
			problems = append(problems, fmt.Sprintf("%s names %s as the newest migration but lists %s", base, newest, maxName(want)))
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("migrategen: %s", strings.Join(problems, "; "))
	}
	return nil
}

// UpdateManifest writes the manifest for dir: a migration that is not listed gets its line, a
// listed one whose text changed is refused unless its name is in bump, and a listed one that is
// gone is refused always (deleting an applied migration is never a routine step). It returns the
// names it added and the names it bumped.
//
// A manifest that is missing or lists nothing while dir holds migrations is refused unless
// initialise is set (genmig -init), and a migration that sorts before the newest listed one is
// refused as unlisted. Both would otherwise be a second way to do what -bump does: delete the
// file (or one line of it), run the plain command, and every edited migration is listed again
// with its current hash and nothing says "bump" (db-r8-3). Starting a manifest is a decision the
// same size as a bump, so it is as explicit.
func UpdateManifest(dir, manifest string, bump []string, initialise bool) (added, bumped []string, err error) {
	want, floor, err := readManifest(manifest)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, nil, err
		}
		want = map[string]string{}
	}
	have, err := MigrationHashes(dir)
	if err != nil {
		return nil, nil, err
	}
	if len(want) == 0 && len(have) > 0 && !initialise {
		return nil, nil, fmt.Errorf("migrategen: %s is missing or lists no migration while %s holds %d; an applied migration edited since would be listed again with its new hash and no bump. Restore the file from version control, or pass -init if this really is the first listing", filepath.Base(manifest), dir, len(have))
	}
	// A newest line whose migration has no line, or no newest line at all over listed migrations,
	// means a line was removed by hand (db-r9-1). Only -init lifts the refusal, the same decision
	// as a bump.
	if len(want) > 0 && !initialise {
		switch {
		case floor == "":
			return nil, nil, fmt.Errorf("migrategen: %s has no %q line while it lists %d migrations; restore the file from version control, or pass -init if this really is the first listing", filepath.Base(manifest), strings.TrimSpace(NewestPrefix), len(want))
		case want[floor] == "":
			return nil, nil, fmt.Errorf("migrategen: %s names %s as the newest migration but lists no line for it: the line was removed. A removed line would be listed again with whatever the file says now; restore it from version control, or use `genmig -bump` for an accepted edit", filepath.Base(manifest), floor)
		}
	}
	bumpSet := map[string]bool{}
	for _, b := range bump {
		bumpSet[b] = true
	}
	var problems []string
	for name, h := range want {
		cur, ok := have[name]
		switch {
		case !ok:
			problems = append(problems, name+" is listed and gone")
		case cur != h && !bumpSet[name]:
			problems = append(problems, name+" was edited after it was listed")
		case cur != h:
			want[name] = cur
			bumped = append(bumped, name)
		}
	}
	for b := range bumpSet {
		if _, listed := want[b]; !listed {
			problems = append(problems, b+" is not listed, so there is nothing to bump")
		}
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return nil, nil, fmt.Errorf("migrategen: %s (an applied migration is never edited: fix forward with a new file, or `genmig -bump <file>` if nothing ran it anywhere)", strings.Join(problems, "; "))
	}
	// Migrations are applied in order and goose does not run a lower version that appears later, so
	// a new one always sorts after the floor (what the manifest says is newest, never less than
	// what it lists); an unlisted name at or below it means its line was removed.
	newest := floor
	if m := maxName(want); m > newest {
		newest = m
	}
	var below []string
	for name := range have {
		if _, ok := want[name]; !ok && name <= newest {
			below = append(below, name)
		}
	}
	if len(below) > 0 {
		sort.Strings(below)
		return nil, nil, fmt.Errorf("migrategen: %s is at or below %s, the newest migration the manifest names: its line was removed from the manifest or it is out of order (a removed line would be listed again with whatever the file says now; restore the line from version control, or use `genmig -bump` for an accepted edit)", strings.Join(below, ", "), newest)
	}
	for name, h := range have {
		if _, ok := want[name]; !ok {
			want[name] = h
			added = append(added, name)
		}
	}
	sort.Strings(added)
	sort.Strings(bumped)
	names := make([]string, 0, len(want))
	for n := range want {
		names = append(names, n)
	}
	sort.Strings(names)
	var b strings.Builder
	b.WriteString(ManifestHeader)
	b.WriteString("\n")
	if len(names) > 0 {
		b.WriteString(NewestPrefix + names[len(names)-1] + "\n\n")
	}
	for _, n := range names {
		fmt.Fprintf(&b, "%s  %s\n", want[n], n)
	}
	if err := os.WriteFile(manifest, []byte(b.String()), 0o644); err != nil {
		return nil, nil, err
	}
	return added, bumped, nil
}

// VerifyAppendOnly compares the manifest with the one of an EARLIER version of the repository (the last
// snapshot that was published) and fails for a line that was there and is changed or gone, and for a
// "# newest:" floor that moved back (db-r16-9, db-r16-18). Rule applied-migrations-are-frozen stops the
// routine command from re-listing an edited migration, but the manifest is a text file in the same
// commit: editing a hash by hand, deleting the manifest and the line of the newest migration, or lowering
// the newest line together with the lines leaves every check of one tree green, and the edit reaches fresh
// databases only while the deployed ones keep the old grant or function body (it fails open, in the
// security direction). The earlier manifest is the one fact the edit cannot also rewrite, so this is
// the check that makes it visible without a reviewer reading a diff: a line that was published is never
// changed or removed, and a line may be added. allow names the files whose change was decided on purpose
// (the owner's decision, passed by hand on the command line, never by the publisher).
//
// It judges two manifests; where the earlier one comes from is the caller's: scripts/publish.mjs hands it
// the applied.sum of the snapshot it is about to replace.
func VerifyAppendOnly(current, earlier string, allow []string) error {
	now, newestNow, err := readManifest(current)
	if err != nil {
		return err
	}
	was, newestWas, err := readManifest(earlier)
	if err != nil {
		return err
	}
	allowed := map[string]bool{}
	for _, a := range allow {
		allowed[strings.TrimSpace(a)] = true
	}
	var problems []string
	names := make([]string, 0, len(was))
	for name := range was {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		h, ok := now[name]
		switch {
		case allowed[name]:
		case !ok:
			problems = append(problems, fmt.Sprintf("%s was listed in the earlier manifest and its line is gone", name))
		case h != was[name]:
			problems = append(problems, fmt.Sprintf("%s was listed with another hash in the earlier manifest: a migration that was published is never edited", name))
		}
	}
	if newestWas != "" && newestNow < newestWas {
		problems = append(problems, fmt.Sprintf("the newest line moved back from %s to %s", newestWas, newestNow))
	}
	if len(problems) > 0 {
		return fmt.Errorf("migrategen: the manifest is not an extension of the earlier one: %s", strings.Join(problems, "; "))
	}
	return nil
}
