package mutant_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/mutant"
)

// The runner is itself a security control (a surviving mutant must fail CI), so it gets
// the treatment it demands of the others: a tiny module with one test that checks
// something and one that only looks as if it did, and a mutant for each way the
// runner could be fooled.

const fxGoMod = "module fx\n\ngo 1.21\n"

const fxSrc = `package p

func Add(a, b int) int { return a + b }

func Allowed(role string) bool { return role == "admin" }
`

// TestAdd checks the sum. TestAllowedDecorative has its comparison deleted, the shape
// of the meta check named by the rule: it runs, passes, and can never fail.
const fxTest = `package p

import "testing"

func TestAdd(t *testing.T) {
	if Add(1, 2) != 3 {
		t.Fatal("sum")
	}
}

func TestAllowedDecorative(t *testing.T) {
	_ = Allowed("user")
}

func TestAllowedReal(t *testing.T) {
	if Allowed("user") {
		t.Fatal("a user is allowed")
	}
}

func TestBrokenOnItsOwn(t *testing.T) { t.Fatal("always") }

func TestSkipsItself(t *testing.T) { t.Skip("no probe") }
`

func fixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range map[string]string{"go.mod": fxGoMod, "p/p.go": fxSrc, "p/p_test.go": fxTest} {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func mut(id string, old, repl string, tests ...string) mutant.Mutant {
	return mutant.Mutant{
		ID: id, Rule: "tests-that-cannot-fail", Why: "fixture",
		Edits:    []mutant.Edit{{File: "p/p.go", Old: old, New: repl}},
		MustFail: []mutant.Expected{{Pkg: "./p", Tests: tests}},
	}
}

func run(t *testing.T, dir string, ms ...mutant.Mutant) map[string]mutant.Result {
	t.Helper()
	reg := &mutant.Registry{Mutants: ms}
	res, _ := mutant.Run(context.Background(), reg, mutant.Options{Root: dir, Timeout: 2 * time.Minute, Jobs: 3})
	out := map[string]mutant.Result{}
	for _, r := range res {
		out[r.ID] = r
	}
	return out
}

func TestRunnerCanFail(t *testing.T) {
	if testing.Short() {
		t.Skip("runs go test in a scratch module")
	}
	dir := fixture(t)
	// Run refuses a registry whose edit does not apply, before any test starts: a
	// mutant that did not apply proves nothing.
	if res := run(t, dir, mut("no-such-text", "a * b", "a - b", "TestAdd")); len(res) != 0 {
		t.Fatalf("an edit that does not apply must stop the run, got %v", res)
	}
	res := run(t, dir,
		mut("killed", "a + b", "a - b", "TestAdd"),
		mut("killed-real-check", `role == "admin"`, `true`, "TestAllowedReal"),
		mut("decorative-survives", `role == "admin"`, `true`, "TestAllowedDecorative"),
		mut("one-of-two-survives", "a + b", "a - b", "TestAdd", "TestAllowedDecorative"),
		mut("does-not-compile", "a + b", "a +", "TestAdd"),
		mut("fails-before-the-edit", "a + b", "a - b", "TestBrokenOnItsOwn"),
		mut("skips", "a + b", "a - b", "TestSkipsItself"),
	)
	want := map[string]mutant.Status{
		"killed":                mutant.Killed,
		"killed-real-check":     mutant.Killed,
		"decorative-survives":   mutant.Survived,
		"one-of-two-survives":   mutant.Survived,
		"does-not-compile":      mutant.Invalid,
		"fails-before-the-edit": mutant.Invalid,
		"skips":                 mutant.Invalid,
	}
	for id, st := range want {
		if got := res[id].Status; got != st {
			t.Errorf("%s: status %q (%s), want %q", id, got, res[id].Detail, st)
		}
	}
	if !strings.Contains(res["does-not-compile"].Detail, "compile") {
		t.Errorf("a build failure must say so, got %q", res["does-not-compile"].Detail)
	}
	if !strings.Contains(res["one-of-two-survives"].Detail, "TestAllowedDecorative passed") {
		t.Errorf("the survivor must be named, got %q", res["one-of-two-survives"].Detail)
	}
	// The run must have put every file back.
	if b, _ := os.ReadFile(filepath.Join(dir, "p", "p.go")); string(b) != fxSrc {
		t.Error("the real tree was written")
	}
}

// TestRunFailsWhileAMutantSurvives is the exit code: Run returns an error for one
// survivor among killed mutants, and none when all die.
func TestRunFailsWhileAMutantSurvives(t *testing.T) {
	if testing.Short() {
		t.Skip("runs go test in a scratch module")
	}
	dir := fixture(t)
	reg := &mutant.Registry{Mutants: []mutant.Mutant{
		mut("killed", "a + b", "a - b", "TestAdd"),
		mut("survivor", `role == "admin"`, `true`, "TestAllowedDecorative"),
	}}
	res, err := mutant.Run(context.Background(), reg, mutant.Options{Root: dir, Timeout: 2 * time.Minute, Jobs: 2})
	if err == nil || !strings.Contains(err.Error(), "survivor") {
		t.Fatalf("a surviving mutant must fail the run, got %v", err)
	}
	if len(res) != 2 {
		t.Fatalf("results = %v", res)
	}
	reg.Mutants = reg.Mutants[:1]
	if _, err := mutant.Run(context.Background(), reg, mutant.Options{Root: dir, Timeout: 2 * time.Minute}); err != nil {
		t.Fatalf("all killed: %v", err)
	}
	// -short leaves a docker mutant out and says so, without counting it as killed.
	reg.Mutants[0].Docker = true
	res, err = mutant.Run(context.Background(), reg, mutant.Options{Root: dir, Short: true})
	if err != nil || len(res) != 1 || res[0].Status != mutant.Skipped {
		t.Fatalf("short: %v %v", res, err)
	}
}

func TestApplyNeedsExactlyOneHit(t *testing.T) {
	src := []byte("a\nb\na\r\n")
	if _, err := mutant.Apply(src, []mutant.Edit{{File: "f", Old: "a", New: "c"}}); err == nil {
		t.Error("two hits must fail")
	}
	if _, err := mutant.Apply(src, []mutant.Edit{{File: "f", Old: "z", New: "c"}}); err == nil {
		t.Error("no hit must fail")
	}
	got, err := mutant.Apply([]byte("x\r\ny\r\n"), []mutant.Edit{{File: "f", Old: "x\ny", New: "x\nz"}})
	if err != nil || string(got) != "x\r\nz\r\n" {
		t.Errorf("CRLF file: %q %v", got, err)
	}
	// Edits run in order: the second one sees the first one's result.
	got, err = mutant.Apply([]byte("one"), []mutant.Edit{{File: "f", Old: "one", New: "two"}, {File: "f", Old: "two", New: "three"}})
	if err != nil || string(got) != "three" {
		t.Errorf("sequence: %q %v", got, err)
	}
}

func TestValidateCanFail(t *testing.T) {
	dir := fixture(t)
	good := mut("good", "a + b", "a - b", "TestAdd")
	if p := mutant.Validate(&mutant.Registry{Mutants: []mutant.Mutant{good}}, dir); len(p) != 0 {
		t.Fatalf("the clean registry has problems: %v", p)
	}
	cases := map[string]func(m *mutant.Mutant){
		"the id is used twice":    nil, // handled below
		"old text not found":      func(m *mutant.Mutant) { m.Edits[0].Old = "nope" },
		"changes nothing":         func(m *mutant.Mutant) { m.Edits[0].New = m.Edits[0].Old },
		"cannot be read":          func(m *mutant.Mutant) { m.Edits[0].File = "p/missing.go" },
		"relative slash path":     func(m *mutant.Mutant) { m.Edits[0].File = "../x.go" },
		"no edits":                func(m *mutant.Mutant) { m.Edits = nil },
		"no tests that must fail": func(m *mutant.Mutant) { m.MustFail = nil },
		"is not a test function":  func(m *mutant.Mutant) { m.MustFail[0].Tests = []string{"TestNoSuch"} },
		"lists no tests":          func(m *mutant.Mutant) { m.MustFail[0].Tests = nil },
		"is not a rule key":       func(m *mutant.Mutant) { m.Rule = "Not A Key" },
		"no why":                  func(m *mutant.Mutant) { m.Why = "" },
		"must start with ./":      func(m *mutant.Mutant) { m.MustFail[0].Pkg = "p" },
		"is not a top-level test": func(m *mutant.Mutant) { m.MustFail[0].Tests = []string{"TestAdd/sub"} },
		"old is empty":            func(m *mutant.Mutant) { m.Edits[0].Old = "" },
		"listed twice":            func(m *mutant.Mutant) { m.MustFail[0].Tests = []string{"TestAdd", "TestAdd"} },
		"id must be lower case":   func(m *mutant.Mutant) { m.ID = "Bad ID" },
	}
	for want, brk := range cases {
		m := good
		m.Edits = append([]mutant.Edit(nil), good.Edits...)
		m.MustFail = []mutant.Expected{{Pkg: good.MustFail[0].Pkg, Tests: append([]string(nil), good.MustFail[0].Tests...)}}
		reg := &mutant.Registry{Mutants: []mutant.Mutant{m}}
		if brk == nil {
			reg.Mutants = append(reg.Mutants, m)
		} else {
			brk(&reg.Mutants[0])
		}
		joined := strings.Join(mutant.Validate(reg, dir), "\n")
		if !strings.Contains(joined, want) {
			t.Errorf("planted %q: problems = %q", want, joined)
		}
	}
}

// A mutant that edits a migration which a later migration repeats edits dead text: the
// later CREATE OR REPLACE is what the database runs. The check must flag it, and must
// leave the newest copy, an unrelated later file and a non-migration file alone.
func TestValidateFlagsAnEditOfASupersededMigration(t *testing.T) {
	dir := t.TempDir()
	mig := filepath.Join(dir, "migrations", "postgres")
	if err := os.MkdirAll(mig, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(mig, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("0001_a.sql", "IF x THEN\n  RETURN 1;\n")
	write("0002_b.sql", "-- the function was replaced\nIF x THEN\n  RETURN 1;\n")
	write("0003_c.sql", "SELECT 1;\n")
	m := func(file string) *mutant.Registry {
		return &mutant.Registry{Mutants: []mutant.Mutant{{
			ID: "m", Rule: "r", Why: "w",
			Edits:    []mutant.Edit{{File: file, Old: "IF x THEN\n", New: "IF true THEN\n"}},
			MustFail: []mutant.Expected{{Pkg: "./internal/mutant", Tests: []string{"TestApplyNeedsExactlyOneHit"}}},
		}}}
	}
	// Only the migration checks matter here: put the test package in the temp tree.
	if err := os.MkdirAll(filepath.Join(dir, "internal", "mutant"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "internal", "mutant", "x_test.go"), []byte("package mutant\nfunc TestApplyNeedsExactlyOneHit() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(mutant.Validate(m("migrations/postgres/0001_a.sql"), dir), "\n"); !strings.Contains(got, "superseded") || !strings.Contains(got, "0002_b.sql") {
		t.Errorf("an edit of the older copy: problems = %q, want superseded by 0002_b.sql", got)
	}
	if got := strings.Join(mutant.Validate(m("migrations/postgres/0002_b.sql"), dir), "\n"); strings.Contains(got, "superseded") {
		t.Errorf("an edit of the newest copy is flagged: %q", got)
	}
}

func TestParseRefusesUnknownKeys(t *testing.T) {
	if _, err := mutant.Parse([]byte("mutants:\n  - id: a\n    docker_only: true\n")); err == nil {
		t.Fatal("a misspelt key must not be ignored")
	}
}

// TestATestThatDidNotRunSaysWhy: a package that dies before its tests start (a TestMain that
// could not start a container, an init that panics) leaves its named tests with no result,
// which is Invalid. The detail must carry what the package printed, or the next flake of
// this kind has nothing to be told apart by from a defect (round 5, role-reach mutant).
func TestATestThatDidNotRunSaysWhy(t *testing.T) {
	if testing.Short() {
		t.Skip("runs go test in a scratch module")
	}
	dir := fixture(t)
	res := run(t, dir, mut("dies-at-start",
		"func Add(a, b int) int { return a + b }",
		"func init() { panic(\"cluster did not start\") }\n\nfunc Add(a, b int) int { return a + b }", "TestAdd"))
	got := res["dies-at-start"]
	if got.Status != mutant.Invalid || !strings.Contains(got.Detail, "TestAdd did not run") {
		t.Fatalf("got %q %q, want Invalid with TestAdd did not run", got.Status, got.Detail)
	}
	if !strings.Contains(got.Detail, "cluster did not start") {
		t.Errorf("the detail does not say why: %q", got.Detail)
	}
}
