package migrategen_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/migrategen"
)

// TestGeneratedMigrationsAreCurrent fails when a source file under
// migrations/postgres/src was changed without regenerating the SQL that goose
// applies. Applied migrations must never change, so the committed expansion is
// the truth and this test keeps the source honest.
func TestGeneratedMigrationsAreCurrent(t *testing.T) {
	names, err := migrategen.Generate("../../migrations/postgres/src", "../../migrations/postgres", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) < 7 {
		t.Errorf("only %d source files; the schema has at least 7", len(names))
	}
}

func TestExpand(t *testing.T) {
	out, err := migrategen.Expand("x.sql", `CREATE TABLE t (
  {{tid}},
  id uuid,
  {{actionset "t" "" "inherit"}}
  {{ts}}
);
{{rls "t"}}
{{grant "t" "tenant" "S I"}}`)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"tenant_id uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE",
		"CONSTRAINT t_action_set CHECK (COALESCE(",
		"(action = 'inherit' AND",
		"ALTER TABLE t FORCE ROW LEVEL SECURITY;",
		"CREATE POLICY tenant_isolation ON t",
		"USING (tenant_id = ctrlz.current_tenant_id())",
		"WITH CHECK (tenant_id = ctrlz.current_tenant_id())",
		"SELECT pg_temp.grant_dsl('t', 'ctrlz_tenant', 'S I');",
		"Code generated",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expansion lacks %q", want)
		}
	}
	if strings.Contains(out, "{{") {
		t.Error("a macro was left unexpanded")
	}
	// A nullable action adds the unset branch, and no inherit branch.
	out, err = migrategen.Expand("y.sql", `{{actionset "f" "" "null"}}`)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "(action IS NULL AND") || strings.Contains(out, "'inherit'") || !strings.Contains(out, "action text,") {
		t.Errorf("nullable action set:\n%s", out)
	}
	// A prefix is applied to every column.
	out, _ = migrategen.Expand("z.sql", `{{actionset "o" "default_" "null"}}`)
	if !strings.Contains(out, "default_target_location_id uuid REFERENCES locations (id)") {
		t.Errorf("prefixed action set:\n%s", out)
	}
}

func TestUnknownMacroIsAnError(t *testing.T) {
	if _, err := migrategen.Expand("bad.sql", `{{nosuchmacro "x"}}`); err == nil {
		t.Error("an unknown macro must fail the build")
	}
	if _, err := migrategen.Expand("bad.sql", `{{rls}}`); err == nil {
		t.Error("a macro with missing arguments must fail the build")
	}
}

// TestAMigrationWithNoSourceFails: the migrator applies every 0*.sql in the
// output directory, so one that no source produced would run without ever being
// checked against a macro expansion.
func TestAMigrationWithNoSourceFails(t *testing.T) {
	src, out := t.TempDir(), t.TempDir()
	write := func(dir, name, text string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	const body = "-- +goose Up\nSELECT 1;\n"
	write(src, "0001_a.sql", body)
	expanded, err := migrategen.Expand("0001_a.sql", body)
	if err != nil {
		t.Fatal(err)
	}
	write(out, "0001_a.sql", expanded)
	if _, err := migrategen.Generate(src, out, true); err != nil {
		t.Fatalf("a clean pair: %v", err)
	}

	// A hand-written or leftover migration beside it.
	write(out, "0002_stray.sql", "-- +goose Up\nGRANT SELECT ON ctrlz.users TO PUBLIC;\n")
	for _, check := range []bool{true, false} {
		_, err := migrategen.Generate(src, out, check)
		if err == nil || !strings.Contains(err.Error(), "0002_stray.sql") {
			t.Errorf("check=%v: a migration with no source gave %v, want an error naming it", check, err)
		}
	}
	// Files that are not migrations are left alone.
	if err := os.Remove(filepath.Join(out, "0002_stray.sql")); err != nil {
		t.Fatal(err)
	}
	write(out, "embed.go", "package postgres\n")
	write(out, "README.md", "x")
	if _, err := migrategen.Generate(src, out, true); err != nil {
		t.Errorf("non-migration files in the output directory: %v", err)
	}
}

// TestAppliedMigrationsAreFrozen is rule applied-migrations-are-frozen on the real tree: every
// expanded migration is listed in applied.sum with the hash it has now. An edit of an applied
// file (a comment, a grant, a function body) fails here, so the next in-place fix cannot reach
// fresh databases only (db-r7-3, db-r7-6).
func TestAppliedMigrationsAreFrozen(t *testing.T) {
	if err := migrategen.VerifyManifest("../../migrations/postgres", "../../migrations/postgres/applied.sum"); err != nil {
		t.Fatal(err)
	}
}

// TestManifestCanFail plants every way the rule exists for: an edited file, a deleted file, a new
// file nobody listed, a missing manifest, and a bump that was not asked for. The manifest of a
// clean directory passes.
func TestManifestCanFail(t *testing.T) {
	dir := t.TempDir()
	sum := filepath.Join(t.TempDir(), "applied.sum")
	write := func(name, text string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("0001_a.sql", "-- +goose Up\nSELECT 1;\n")
	write("0002_b.sql", "-- +goose Up\nGRANT SELECT ON ctrlz.users TO ctrlz_tenant;\n")

	if err := migrategen.VerifyManifest(dir, sum); err == nil {
		t.Fatal("a missing manifest passed: the enforcement can be deleted without a word")
	}
	// The plain command does not start a manifest either: deleting applied.sum and running it would
	// list every edited migration again with its new hash and no bump (db-r8-3). Neither does a
	// manifest cut down to its header, and a refusal leaves nothing behind.
	if _, _, err := migrategen.UpdateManifest(dir, sum, nil, false); err == nil || !strings.Contains(err.Error(), "-init") {
		t.Fatalf("the plain update started a manifest that was missing: %v", err)
	}
	if _, statErr := os.Stat(sum); statErr == nil {
		t.Fatal("a refused update wrote a manifest")
	}
	if err := os.WriteFile(sum, []byte(migrategen.ManifestHeader), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := migrategen.UpdateManifest(dir, sum, nil, false); err == nil {
		t.Fatal("the plain update started a manifest that listed nothing")
	}
	if err := migrategen.VerifyManifest(dir, sum); err == nil {
		t.Fatal("a manifest that lists nothing passed")
	}
	if err := os.Remove(sum); err != nil {
		t.Fatal(err)
	}
	// A tree with no migration has nothing to hide, so it starts without the flag.
	if _, _, err := migrategen.UpdateManifest(t.TempDir(), filepath.Join(t.TempDir(), "applied.sum"), nil, false); err != nil {
		t.Fatalf("an empty tree: %v", err)
	}
	added, bumped, err := migrategen.UpdateManifest(dir, sum, nil, true)
	if err != nil || len(added) != 2 || len(bumped) != 0 {
		t.Fatalf("first listing: %v %v %v", added, bumped, err)
	}
	if err := migrategen.VerifyManifest(dir, sum); err != nil {
		t.Fatalf("a clean pair: %v", err)
	}

	// A CRLF checkout of the same text is the same migration.
	write("0001_a.sql", "-- +goose Up\r\nSELECT 1;\r\n")
	if err := migrategen.VerifyManifest(dir, sum); err != nil {
		t.Errorf("line endings changed the hash: %v", err)
	}
	write("0001_a.sql", "-- +goose Up\nSELECT 1;\n")

	// Even a comment of an applied migration is an edit.
	write("0002_b.sql", "-- +goose Up\n-- reworded\nGRANT SELECT ON ctrlz.users TO ctrlz_tenant;\n")
	if err := migrategen.VerifyManifest(dir, sum); err == nil || !strings.Contains(err.Error(), "0002_b.sql") {
		t.Errorf("an edited applied migration gave %v", err)
	}
	// Regenerating does not hide it: the update refuses without an explicit bump.
	if _, _, err := migrategen.UpdateManifest(dir, sum, nil, false); err == nil || !strings.Contains(err.Error(), "0002_b.sql") {
		t.Errorf("the update accepted an edit without a bump: %v", err)
	}
	if err := migrategen.VerifyManifest(dir, sum); err == nil {
		t.Error("a refused update changed the manifest")
	}
	// A bump names the file and is the one way to accept it; it cannot name a file never listed.
	if _, _, err := migrategen.UpdateManifest(dir, sum, []string{"0003_c.sql"}, false); err == nil {
		t.Error("a bump of an unlisted file passed")
	}
	if _, bumped, err := migrategen.UpdateManifest(dir, sum, []string{"0002_b.sql"}, false); err != nil || len(bumped) != 1 {
		t.Fatalf("the explicit bump: %v %v", bumped, err)
	}
	if err := migrategen.VerifyManifest(dir, sum); err != nil {
		t.Errorf("after the bump: %v", err)
	}

	// A migration nobody listed.
	write("0003_c.sql", "-- +goose Up\nSELECT 3;\n")
	if err := migrategen.VerifyManifest(dir, sum); err == nil || !strings.Contains(err.Error(), "0003_c.sql") {
		t.Errorf("an unlisted migration gave %v", err)
	}
	if added, _, err := migrategen.UpdateManifest(dir, sum, nil, false); err != nil || len(added) != 1 {
		t.Fatalf("listing a new migration: %v %v", added, err)
	}

	// A deleted migration, listed and gone.
	if err := os.Remove(filepath.Join(dir, "0001_a.sql")); err != nil {
		t.Fatal(err)
	}
	if err := migrategen.VerifyManifest(dir, sum); err == nil || !strings.Contains(err.Error(), "0001_a.sql") {
		t.Errorf("a deleted applied migration gave %v", err)
	}
	if _, _, err := migrategen.UpdateManifest(dir, sum, []string{"0001_a.sql"}, false); err == nil {
		t.Error("the update dropped a listed migration")
	}
}

// TestManifestLineRemovedThenRegeneratedIsRefused is the other way round the bump: the line of an
// edited migration is deleted from the manifest and the plain command lists it again with its new
// hash. A name that sorts before the newest listed one can only be a removed line (db-r8-3).
func TestManifestLineRemovedThenRegeneratedIsRefused(t *testing.T) {
	dir := t.TempDir()
	sum := filepath.Join(t.TempDir(), "applied.sum")
	write := func(name, text string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("0001_a.sql", "-- +goose Up\nSELECT 1;\n")
	write("0002_b.sql", "-- +goose Up\nSELECT 2;\n")
	if _, _, err := migrategen.UpdateManifest(dir, sum, nil, true); err != nil {
		t.Fatal(err)
	}
	write("0001_a.sql", "-- +goose Up\nGRANT SELECT ON ctrlz.users TO PUBLIC;\n")
	b, err := os.ReadFile(sum)
	if err != nil {
		t.Fatal(err)
	}
	var kept []string
	for _, l := range strings.Split(string(b), "\n") {
		if !strings.HasSuffix(l, "0001_a.sql") {
			kept = append(kept, l)
		}
	}
	if err := os.WriteFile(sum, []byte(strings.Join(kept, "\n")), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := migrategen.UpdateManifest(dir, sum, nil, false); err == nil || !strings.Contains(err.Error(), "0001_a.sql") {
		t.Fatalf("a removed line was listed again with the edited text: %v", err)
	}
	if err := migrategen.VerifyManifest(dir, sum); err == nil {
		t.Error("the check passed an unlisted migration")
	}
}

// TestManifestNewestLineRemovedThenRegeneratedIsRefused is db-r9-1: the floor of "a new migration
// sorts after every listed one" must not be computed from the lines a developer can delete. The
// newest migration is the one most likely to be deployed and most likely to be edited, and deleting
// its own line (or the last several) lowered the maximum so the edited file stopped being "below"
// it and the plain command listed it again. Every shape must be refused by the update and by the
// check, and nothing may be written.
func TestManifestNewestLineRemovedThenRegeneratedIsRefused(t *testing.T) {
	setup := func(t *testing.T) (dir, sum string, write func(name, text string)) {
		t.Helper()
		dir = t.TempDir()
		sum = filepath.Join(t.TempDir(), "applied.sum")
		write = func(name, text string) {
			t.Helper()
			if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		write("0001_a.sql", "-- +goose Up\nSELECT 1;\n")
		write("0002_b.sql", "-- +goose Up\nSELECT 2;\n")
		write("0003_c.sql", "-- +goose Up\nSELECT 3;\n")
		if _, _, err := migrategen.UpdateManifest(dir, sum, nil, true); err != nil {
			t.Fatal(err)
		}
		return dir, sum, write
	}
	dropLines := func(t *testing.T, sum string, drop ...string) {
		t.Helper()
		b, err := os.ReadFile(sum)
		if err != nil {
			t.Fatal(err)
		}
		var kept []string
		for _, l := range strings.Split(string(b), "\n") {
			skip := false
			for _, d := range drop {
				if strings.HasSuffix(l, d) && !strings.HasPrefix(l, "#") {
					skip = true
				}
			}
			if !skip {
				kept = append(kept, l)
			}
		}
		if err := os.WriteFile(sum, []byte(strings.Join(kept, "\n")), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	refused := func(t *testing.T, dir, sum, why string) {
		t.Helper()
		before, _ := os.ReadFile(sum)
		if _, _, err := migrategen.UpdateManifest(dir, sum, nil, false); err == nil {
			t.Fatalf("%s: the plain update listed the edited migration again", why)
		}
		after, _ := os.ReadFile(sum)
		if string(before) != string(after) {
			t.Fatalf("%s: a refused update wrote the manifest", why)
		}
		if err := migrategen.VerifyManifest(dir, sum); err == nil {
			t.Fatalf("%s: the check passed", why)
		}
	}

	t.Run("last line", func(t *testing.T) {
		dir, sum, write := setup(t)
		write("0003_c.sql", "-- +goose Up\nGRANT SELECT ON ctrlz.users TO PUBLIC;\n")
		dropLines(t, sum, "0003_c.sql")
		refused(t, dir, sum, "the newest line was deleted")
	})
	t.Run("last two lines", func(t *testing.T) {
		dir, sum, write := setup(t)
		write("0002_b.sql", "-- +goose Up\nGRANT SELECT ON ctrlz.users TO PUBLIC;\n")
		write("0003_c.sql", "-- +goose Up\nGRANT SELECT ON ctrlz.tenants TO PUBLIC;\n")
		dropLines(t, sum, "0002_b.sql", "0003_c.sql")
		refused(t, dir, sum, "the last two lines were deleted")
	})
	t.Run("middle line", func(t *testing.T) {
		dir, sum, write := setup(t)
		write("0002_b.sql", "-- +goose Up\nGRANT SELECT ON ctrlz.users TO PUBLIC;\n")
		dropLines(t, sum, "0002_b.sql")
		refused(t, dir, sum, "a middle line was deleted")
	})
	t.Run("newest line deleted", func(t *testing.T) {
		dir, sum, write := setup(t)
		write("0003_c.sql", "-- +goose Up\nGRANT SELECT ON ctrlz.users TO PUBLIC;\n")
		b, err := os.ReadFile(sum)
		if err != nil {
			t.Fatal(err)
		}
		var kept []string
		for _, l := range strings.Split(string(b), "\n") {
			if !strings.HasPrefix(l, migrategen.NewestPrefix) {
				kept = append(kept, l)
			}
		}
		if err := os.WriteFile(sum, []byte(strings.Join(kept, "\n")), 0o644); err != nil {
			t.Fatal(err)
		}
		dropLines(t, sum, "0003_c.sql")
		refused(t, dir, sum, "the newest line and the line of the newest migration were both deleted")
	})
	t.Run("a new migration still moves the floor", func(t *testing.T) {
		dir, sum, write := setup(t)
		write("0004_d.sql", "-- +goose Up\nSELECT 4;\n")
		added, _, err := migrategen.UpdateManifest(dir, sum, nil, false)
		if err != nil || len(added) != 1 {
			t.Fatalf("a new migration: %v %v", added, err)
		}
		if err := migrategen.VerifyManifest(dir, sum); err != nil {
			t.Fatal(err)
		}
		b, _ := os.ReadFile(sum)
		if !strings.Contains(string(b), migrategen.NewestPrefix+"0004_d.sql") {
			t.Fatalf("the newest line did not move: %s", b)
		}
	})
}
