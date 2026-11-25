package lint_test

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/mutant"
)

// The tests-that-cannot-fail rule (P1 auth review, round 5, topic 20; spec 18.6 and
// 18.7). A security test that has never been seen failing proves nothing, and rounds 1
// to 4 found six of them: a count in place of a name, one route in place of all, a
// probe that passed when it did not run, a lint with no self-test, an unlock check that
// filled 6 of 30 hits. The rule: every rule of docs/reviews/p1-auth/rules.md owns at
// least one registered mutant in mutants.yaml, and CI (scripts/ci.sh, tools/mutants)
// applies it and requires the named tests to fail.
//
// This file is the paperwork half, which needs no container and no second go test:
//
//   - every rule has a mutant (or is declared unbuilt, and stops being allowed to be
//     the day its "As built" paragraph is written);
//   - every mutant names a rule that exists, edits text that is still in the tree, and
//     names tests that are still test functions;
//   - ci.sh runs the runner.
//
// The runner is internal/mutant, with its own self-test (TestRunnerCanFail) that
// plants a mutant which survives, one that does not apply, one that does not compile
// and a test that fails before the edit.

// rulesFile finds docs/reviews/p1-auth/rules.md the way specFile finds the spec: in the
// workspace around this repository, with CTRLZ_RULES as the override for a clone made
// for a review. A repository checked out alone has no rules.md and the test skips; inside
// a workspace a missing file is a failure, so the check cannot go quiet by a moved file.
func rulesFile(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("CTRLZ_RULES"); p != "" {
		return p
	}
	ws := filepath.Dir(repoRoot(t))
	p := filepath.Join(ws, "docs", "reviews", "p1-auth", "rules.md")
	if _, err := os.Stat(p); err == nil {
		return p
	}
	if _, err := os.Stat(filepath.Join(ws, "Plan.md")); err == nil {
		t.Fatalf("the workspace is at %s but %s is missing", ws, p)
	}
	t.Skip("no workspace around this repository, so docs/reviews/p1-auth/rules.md is not available")
	return ""
}

// ruleEntry is one numbered section of rules.md.
type ruleEntry struct {
	key   string
	line  int
	built bool // the section has a paragraph that says how it was built
}

var (
	ruleHeadingRE = regexp.MustCompile(`^## (\d+)\. ([a-z0-9-]+) \(([a-z]+)\)\s*$`)
	// builtRE are the openings the built sections use. A section that has one is no
	// longer a plan, so its rule must have a mutant.
	builtRE = regexp.MustCompile(`^(As built|Implemented \(|Enforcement \(built\))`)
)

func parseRules(text string) []ruleEntry {
	var out []ruleEntry
	for i, l := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		if m := ruleHeadingRE.FindStringSubmatch(l); m != nil {
			out = append(out, ruleEntry{key: m[2], line: i + 1})
			continue
		}
		if len(out) > 0 && builtRE.MatchString(l) {
			out[len(out)-1].built = true
		}
	}
	return out
}

// ruleMutantProblems is the whole rule: it compares rules.md with the registry in both
// directions.
func ruleMutantProblems(rules []ruleEntry, reg *mutant.Registry) []string {
	var out []string
	if len(rules) < 20 {
		out = append(out, fmt.Sprintf("only %d rules found in rules.md; the heading format changed or the file is cut", len(rules)))
	}
	known := map[string]ruleEntry{}
	for _, r := range rules {
		if prev, dup := known[r.key]; dup {
			out = append(out, fmt.Sprintf("rules.md: %s is a heading on lines %d and %d", r.key, prev.line, r.line))
		}
		known[r.key] = r
	}
	for _, r := range rules {
		n := len(reg.ForRule(r.key))
		unbuilt := reg.IsUnbuilt(r.key)
		switch {
		case n == 0 && !unbuilt:
			out = append(out, fmt.Sprintf("rule %s (rules.md line %d) has no mutant in mutants.yaml: a rule whose test has never been seen failing is not enforced", r.key, r.line))
		case n > 0 && unbuilt:
			out = append(out, fmt.Sprintf("rule %s has a mutant and is also listed as unbuilt; remove it from unbuilt", r.key))
		case unbuilt && r.built:
			out = append(out, fmt.Sprintf("rule %s has an \"As built\" paragraph (rules.md line %d) and is still listed as unbuilt; register its mutants", r.key, r.line))
		}
	}
	for _, m := range reg.Mutants {
		if _, ok := known[m.Rule]; !ok {
			out = append(out, fmt.Sprintf("mutant %s names rule %s, which is not in rules.md", m.ID, m.Rule))
		}
	}
	for _, u := range reg.Unbuilt {
		if _, ok := known[u.Rule]; !ok {
			out = append(out, fmt.Sprintf("unbuilt lists %s, which is not in rules.md", u.Rule))
		}
	}
	sort.Strings(out)
	return out
}

// ciRunsTheMutants says whether ci.sh calls the runner, and passes -short on. The step
// is what turns a surviving mutant into a failed build; without it the registry is a
// list.
func ciRunsTheMutants(ci string) []string {
	for _, l := range strings.Split(ci, "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "#") || !strings.Contains(l, "./tools/mutants") {
			continue
		}
		if !strings.Contains(l, "go run") {
			return []string{"scripts/ci.sh mentions ./tools/mutants but does not `go run` it"}
		}
		if !strings.Contains(l, "$short") {
			return []string{"scripts/ci.sh runs the mutants without $short, so ci.sh -short would start containers"}
		}
		return nil
	}
	return []string{"scripts/ci.sh does not run ./tools/mutants: a surviving mutant would not fail the build"}
}

func loadRegistry(t *testing.T) *mutant.Registry {
	t.Helper()
	reg, err := mutant.Load(filepath.Join(repoRoot(t), "mutants.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return reg
}

// TestMutantRegistry checks mutants.yaml against the tree: every edit still applies
// exactly once and every named test is still a test function. It does not run anything;
// tools/mutants does.
func TestMutantRegistry(t *testing.T) {
	reg := loadRegistry(t)
	if len(reg.Mutants) < 20 {
		t.Fatalf("only %d mutants registered", len(reg.Mutants))
	}
	for _, p := range mutant.Validate(reg, repoRoot(t)) {
		t.Error(p)
	}
}

// TestEveryRuleHasAMutant is the enforcement of the rule itself.
func TestEveryRuleHasAMutant(t *testing.T) {
	b, err := os.ReadFile(rulesFile(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range ruleMutantProblems(parseRules(string(b)), loadRegistry(t)) {
		t.Error(p)
	}
}

func TestCIRunsTheMutants(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(repoRoot(t), "scripts", "ci.sh"))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range ciRunsTheMutants(string(b)) {
		t.Error(p)
	}
}

// TestMutantLintCanFail plants each way the paperwork could rot, and the clean cases
// that must stay clean, so this lint is itself shown to fail.
func TestMutantLintCanFail(t *testing.T) {
	rules := func(keys ...string) string {
		var sb strings.Builder
		for i := 0; i < 22; i++ {
			fmt.Fprintf(&sb, "## %d. filler-%d (db)\n\nRule: x.\n\n", i+1, i)
		}
		for i, k := range keys {
			fmt.Fprintf(&sb, "## %d. %s (db)\n\nRule: x.\n\n", 30+i, k)
		}
		return sb.String()
	}
	built := func(key string) string { return rules(key) + "As built (Panel).\n" }
	fillers := func() []mutant.Mutant {
		var ms []mutant.Mutant
		for i := 0; i < 22; i++ {
			ms = append(ms, mutant.Mutant{ID: fmt.Sprintf("m%d", i), Rule: fmt.Sprintf("filler-%d", i)})
		}
		return ms
	}
	with := func(extra ...mutant.Mutant) *mutant.Registry {
		return &mutant.Registry{Mutants: append(fillers(), extra...)}
	}

	cases := []struct {
		name  string
		rules string
		reg   *mutant.Registry
		want  string // "" for clean
	}{
		{"clean", rules("new-rule"), with(mutant.Mutant{ID: "n", Rule: "new-rule"}), ""},
		{"a rule with no mutant", rules("new-rule"), with(), "rule new-rule"},
		{"a rule with no mutant that is built", built("new-rule"), with(), "has no mutant"},
		{"an unbuilt rule is allowed", rules("new-rule"),
			&mutant.Registry{Mutants: fillers(), Unbuilt: []mutant.Unbuilt{{Rule: "new-rule", Reason: "later"}}}, ""},
		{"an unbuilt rule that has been built", built("new-rule"),
			&mutant.Registry{Mutants: fillers(), Unbuilt: []mutant.Unbuilt{{Rule: "new-rule", Reason: "later"}}}, "still listed as unbuilt"},
		{"an unbuilt rule that has a mutant", rules("new-rule"),
			&mutant.Registry{Mutants: append(fillers(), mutant.Mutant{ID: "n", Rule: "new-rule"}), Unbuilt: []mutant.Unbuilt{{Rule: "new-rule", Reason: "later"}}}, "remove it from unbuilt"},
		{"a mutant of a rule that does not exist", rules(), with(mutant.Mutant{ID: "n", Rule: "gone"}), "names rule gone"},
		{"an unbuilt entry for a rule that does not exist", rules(),
			&mutant.Registry{Mutants: fillers(), Unbuilt: []mutant.Unbuilt{{Rule: "gone", Reason: "later"}}}, "unbuilt lists gone"},
		{"a heading used twice", rules("new-rule", "new-rule"), with(mutant.Mutant{ID: "n", Rule: "new-rule"}), "is a heading on lines"},
		{"a rules file the parser cannot read", "# nothing here\n", with(), "only 0 rules found"},
	}
	for _, tc := range cases {
		got := strings.Join(ruleMutantProblems(parseRules(tc.rules), tc.reg), "\n")
		switch {
		case tc.want == "" && got != "":
			t.Errorf("%s: unexpected problems:\n%s", tc.name, got)
		case tc.want != "" && !strings.Contains(got, tc.want):
			t.Errorf("%s: problems = %q, want one containing %q", tc.name, got, tc.want)
		}
	}

	// The shapes of the section openings the parser relies on, all three.
	for _, open := range []string{"As built (Panel, \"x\").", "Implemented (Panel, \"x\").", "Enforcement (built): x"} {
		rs := parseRules("## 1. a-rule (db)\n\nRule: x.\n\n" + open + "\n")
		if len(rs) != 1 || !rs[0].built {
			t.Errorf("%q is not read as a built section: %+v", open, rs)
		}
	}

	ci := map[string]struct{ text, want string }{
		"the runner is there":      {"set -eu\ngo run ./tools/mutants $short\n", ""},
		"the step is gone":         {"set -eu\ngo vet ./...\n", "does not run"},
		"the step is only a note":  {"# go run ./tools/mutants $short\n", "does not run"},
		"the runner is not run":    {"./tools/mutants $short\n", "does not `go run`"},
		"short is not passed on":   {"go run ./tools/mutants\n", "without $short"},
		"an unrelated tools entry": {"go run ./tools/genmig -check\n", "does not run"},
	}
	for name, tc := range ci {
		got := strings.Join(ciRunsTheMutants(tc.text), "\n")
		if (tc.want == "") != (got == "") || !strings.Contains(got, tc.want) {
			t.Errorf("ci %s: %q, want %q", name, got, tc.want)
		}
	}
}
