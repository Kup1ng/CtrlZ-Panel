package lint_test

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Rule tests-that-cannot-fail, round 18 (primitives-r18-5, owner decision D64 mutant-pairing). The rule
// holds one mutant per rule and one per guard clause a fix adds (TestEveryRuleHasAMutant), and the
// coverage map of the spec (18.7) names about 550 security tests, of which most are named by no mutant: a
// security test that no mutant names can stay green when the code it guards is deleted. The owner accepted
// the existing ones (D64: pairing them all would be hundreds of mutants at one to three minutes of CI
// each) on one condition, a ratchet: every security test added to the map from now on names a mutant that
// it kills.
//
// The ratchet reads two sources that do not depend on this file, the coverage table of the spec
// (compareCoverage reads the same table) and mutants.yaml (the tests of every must_fail), and a golden file
// of the tests that were unpaired at the commit that built it (testdata/mutant-pairing.golden). A test of
// the map is fine if a mutant names it or it is in the golden file. The golden file can only shrink: an
// entry that is paired now, or is no longer in the map, fails until it is removed, so a test that gets a
// mutant leaves the list and cannot come back. Run with -update-mutant-pairing to rewrite the file from
// the current state; a reviewer reads the diff, and the file may not gain a name that was not already in
// it.

var updatePairing = flag.Bool("update-mutant-pairing", false, "rewrite testdata/mutant-pairing.golden from the coverage map and mutants.yaml")

// pairingGoldenCeiling is the most names the golden file may hold: the number it held when the ratchet was
// built. It only goes down (primitives-r18-24): the file alone was guarded by a reviewer reading its diff, so
// a name added to it by hand, or by -update-mutant-pairing, passed. Now raising the list is an edit of two
// files, this constant and the file, which no run of the update flag makes on its own; lower the constant
// when names leave the file.
const pairingGoldenCeiling = 389

// coverageTestNames is the set of test functions the coverage table names, wildcards expanded against
// the tests of the repository, read by the same walk as compareCoverage.
func coverageTestNames(tb specTable, ix testIndex) map[string]bool {
	out := map[string]bool{}
	for _, r := range tb.rows {
		for _, tok := range ticks(r[tb.column("Test")]) {
			if !testNameRE.MatchString(tok) {
				continue
			}
			name := strings.TrimSuffix(tok, "*")
			if !strings.HasSuffix(tok, "*") {
				out[name] = true
				continue
			}
			for n := range ix.all {
				if strings.HasPrefix(n, name) {
					out[n] = true
				}
			}
		}
	}
	return out
}

// pairedTestNames is every test a mutant must see fail.
func pairedTestNames(t *testing.T) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, m := range loadRegistry(t).Mutants {
		for _, e := range m.MustFail {
			for _, n := range e.Tests {
				out[n] = true
			}
		}
	}
	return out
}

// pairingProblems judges the map against the mutants and the golden list.
func pairingProblems(covered, paired, golden map[string]bool) []string {
	var out []string
	if len(golden) > pairingGoldenCeiling {
		out = append(out, fmt.Sprintf("testdata/mutant-pairing.golden holds %d names and pairingGoldenCeiling is %d: the list of accepted unpaired tests only shrinks, so name a mutant for the new test instead of adding it", len(golden), pairingGoldenCeiling))
	}
	for n := range covered {
		if !paired[n] && !golden[n] {
			out = append(out, n+" is in the coverage map of the spec (18.7) and no mutant names it: a security test added to the map names a mutant it kills (mutants.yaml must_fail), so it is shown able to fail (D64 mutant-pairing); the list of accepted unpaired tests is closed and a new name is not added to it")
		}
	}
	for n := range golden {
		switch {
		case paired[n]:
			out = append(out, n+" is on testdata/mutant-pairing.golden and a mutant names it now: remove it from the list, which only shrinks")
		case !covered[n]:
			out = append(out, n+" is on testdata/mutant-pairing.golden and is not in the coverage map any more: remove it from the list")
		}
	}
	sort.Strings(out)
	return out
}

// pairingUpdate is the list -update-mutant-pairing writes: the mapped tests no mutant names. It only ever
// removes names (primitives-r18-24): a name the old file did not hold is an error, so the flag cannot be
// the way the list grows.
func pairingUpdate(covered, paired, old map[string]bool) ([]string, error) {
	var unpaired []string
	for n := range covered {
		if !paired[n] {
			unpaired = append(unpaired, n)
		}
	}
	sort.Strings(unpaired)
	for _, n := range unpaired {
		if !old[n] {
			return nil, fmt.Errorf("%s is in the coverage map and no mutant names it, and it is not on the list: the list may not gain a name, so name a mutant it kills (mutants.yaml must_fail)", n)
		}
	}
	return unpaired, nil
}

func pairingGoldenPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(repoRoot(t), "internal", "lint", "testdata", "mutant-pairing.golden")
}

func readPairingGolden(t *testing.T) map[string]bool {
	t.Helper()
	f, err := os.Open(pairingGoldenPath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	out := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); l != "" && !strings.HasPrefix(l, "#") {
			out[l] = true
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestEveryMappedSecurityTestIsPairedWithAMutantOrAccepted(t *testing.T) {
	lines := readSpec(t)
	tables, problems := markedTables(lines)
	if len(problems) > 0 {
		t.Fatal(strings.Join(problems, "\n"))
	}
	cv, ok := tables["coverage"]
	if !ok {
		t.Fatal("the spec has no table marked <!-- spec-fact: coverage -->")
	}
	covered := coverageTestNames(cv, buildTestIndex(t))
	if len(covered) < 300 {
		t.Fatalf("only %d tests read from the coverage map: the ratchet judges nothing", len(covered))
	}
	paired := pairedTestNames(t)
	if *updatePairing {
		unpaired, err := pairingUpdate(covered, paired, readPairingGolden(t))
		if err != nil {
			t.Fatal(err)
		}
		body := "# Security tests of the coverage map (spec 18.7) that no mutant of mutants.yaml names, accepted by owner decision D64\n" +
			"# (mutant-pairing) at the commit that built this file. The list can only shrink: a test that a mutant names, or that\n" +
			"# leaves the map, must be removed (internal/lint TestEveryMappedSecurityTestIsPairedWithAMutantOrAccepted). A test added\n" +
			"# to the map from now on names a mutant it kills and is never added here.\n" + strings.Join(unpaired, "\n") + "\n"
		if err := os.WriteFile(pairingGoldenPath(t), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	for _, p := range pairingProblems(covered, paired, readPairingGolden(t)) {
		t.Error(p)
	}
}

// TestMutantPairingRatchetCanFail plants each way the ratchet could go quiet: a new mapped test with no
// mutant, a test that got a mutant and stayed on the list, a test that left the map and stayed on the list,
// and the clean cases (a paired test, an accepted one).
func TestMutantPairingRatchetCanFail(t *testing.T) {
	set := func(names ...string) map[string]bool {
		m := map[string]bool{}
		for _, n := range names {
			m[n] = true
		}
		return m
	}
	bigSet := func(n int) map[string]bool {
		m := map[string]bool{}
		for i := range n {
			m[fmt.Sprintf("TestN%d", i)] = true
		}
		return m
	}
	cases := []struct {
		name                    string
		covered, paired, golden map[string]bool
		want                    int
	}{
		{"a paired test", set("TestA"), set("TestA"), set(), 0},
		{"an accepted unpaired test", set("TestA"), set(), set("TestA"), 0},
		{"a new mapped test with no mutant", set("TestA", "TestNew"), set(), set("TestA"), 1},
		{"a test that got a mutant and stayed on the list", set("TestA"), set("TestA"), set("TestA"), 1},
		{"a test that left the map and stayed on the list", set(), set(), set("TestGone"), 1},
		{"a test that is paired and left the map", set(), set("TestGone"), set("TestGone"), 1},
		{"a golden file above its ceiling", bigSet(pairingGoldenCeiling + 1), set(), bigSet(pairingGoldenCeiling + 1), 1},
		{"a golden file at its ceiling", bigSet(pairingGoldenCeiling), set(), bigSet(pairingGoldenCeiling), 0},
	}
	// The update refuses to add a name and drops the ones that are paired now.
	if _, err := pairingUpdate(set("TestA", "TestNew"), set(), set("TestA")); err == nil {
		t.Error("the update wrote a name the list did not hold")
	}
	if got, err := pairingUpdate(set("TestA", "TestB"), set("TestB"), set("TestA", "TestB")); err != nil || len(got) != 1 || got[0] != "TestA" {
		t.Errorf("the update of a list that shrinks: %v %v", got, err)
	}
	for _, c := range cases {
		if got := pairingProblems(c.covered, c.paired, c.golden); len(got) != c.want {
			t.Errorf("%s: %d problems %v, want %d", c.name, len(got), got, c.want)
		}
	}
}
