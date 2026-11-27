// Package mutant is the registry and the runner of rule tests-that-cannot-fail (P1 auth
// review, round 5). A security test that has never been seen failing proves nothing: it
// may count a proxy, walk one route, or pass because its probe did not run. So every
// rule of docs/reviews/p1-auth/rules.md owns at least one registered mutant, a small
// edit of the source that breaks the thing the rule protects, and the tests that must
// fail under it. CI applies each edit in a scratch copy of the tree and runs those
// tests; a mutant that survives, does not apply or does not compile fails the build.
//
// The registry is mutants.yaml at the repository root. It is data, not code, so a new
// mutant needs no change here, and the lint in internal/lint reads the same file to
// require an entry for every rule.
package mutant

import (
	"bytes"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Registry is the content of mutants.yaml.
type Registry struct {
	// Unbuilt names the rules of rules.md whose enforcement is not written yet, so there
	// is nothing to break. It is an allow list that shrinks: the lint fails for a rule
	// here whose "As built" paragraph exists, and for one that also has a mutant, so
	// the entry has to go in the same commit that builds the rule.
	Unbuilt []Unbuilt `yaml:"unbuilt"`
	Mutants []Mutant  `yaml:"mutants"`
}

// Unbuilt is one rule that has no enforcement yet.
type Unbuilt struct {
	Rule   string `yaml:"rule"`
	Reason string `yaml:"reason"`
}

// Mutant is one source edit and the tests that must notice it.
type Mutant struct {
	ID string `yaml:"id"`
	// Rule is the key of the rule in rules.md that this mutant protects.
	Rule string `yaml:"rule"`
	// Finding is the review finding the mutant stands for, when there is one.
	Finding string `yaml:"finding"`
	// Why says what the edit breaks, in a sentence, so a reader can judge the tests.
	Why string `yaml:"why"`
	// Docker marks a mutant whose tests start containers. -short skips it, as ci.sh -short
	// skips the container tests.
	Docker bool `yaml:"docker"`
	// Workspace marks a mutant whose tests read the spec or rules.md of the workspace
	// that holds this repository. A checkout of the repository alone cannot run it.
	Workspace bool       `yaml:"workspace"`
	Edits     []Edit     `yaml:"edits"`
	MustFail  []Expected `yaml:"must_fail"`
}

// Edit replaces Old with New in File. Old has to occur exactly once, so an edit can
// neither miss (a refactor moved the code) nor hit two places.
type Edit struct {
	File string `yaml:"file"`
	Old  string `yaml:"old"`
	New  string `yaml:"new"`
}

// Expected is a package and the top-level tests in it that must fail under the mutant.
type Expected struct {
	Pkg   string   `yaml:"pkg"`
	Tests []string `yaml:"tests"`
}

// Load reads and strictly decodes the registry: an unknown key is an error, so a
// misspelt field cannot silently switch a check off.
func Load(file string) (*Registry, error) {
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	return Parse(b)
}

// Parse decodes registry text.
func Parse(b []byte) (*Registry, error) {
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	var r Registry
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("mutants.yaml: %w", err)
	}
	return &r, nil
}

// lineEnd returns the line ending a file uses, so that an edit written with \n applies
// to a checkout that git converted to \r\n.
func lineEnd(b []byte) string {
	if bytes.Contains(b, []byte("\r\n")) {
		return "\r\n"
	}
	return "\n"
}

// Apply runs the edits of one file over its content, in order. It fails unless every
// Old occurs exactly once at its turn.
func Apply(content []byte, edits []Edit) ([]byte, error) {
	eol := lineEnd(content)
	s := string(content)
	for i, e := range edits {
		old, repl := e.Old, e.New
		if eol != "\n" {
			old = strings.ReplaceAll(old, "\n", eol)
			repl = strings.ReplaceAll(repl, "\n", eol)
		}
		if old == "" {
			return nil, fmt.Errorf("edit %d of %s: old is empty", i+1, e.File)
		}
		switch n := strings.Count(s, old); n {
		case 1:
			s = strings.Replace(s, old, repl, 1)
		case 0:
			return nil, fmt.Errorf("edit %d of %s: old text not found (the code moved, or an earlier edit removed it)", i+1, e.File)
		default:
			return nil, fmt.Errorf("edit %d of %s: old text found %d times, it must be unique", i+1, e.File, n)
		}
	}
	return []byte(s), nil
}

var (
	idRE   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
	testRE = regexp.MustCompile(`^Test[A-Za-z0-9_]+$`)
	funcRE = regexp.MustCompile(`(?m)^func (Test[A-Za-z0-9_]+)\(`)
)

// IsRuleKey reports whether s has the shape of a rule key such as lock-order.
func IsRuleKey(s string) bool { return idRE.MatchString(s) }

// Validate checks the registry against the tree at root without running anything:
// ids are unique, every edit file exists and every Old text is unique at its turn,
// and every named test is a top-level test function of the named package. It returns
// one problem per line.
func Validate(r *Registry, root string) []string {
	var problems []string
	add := func(format string, a ...any) { problems = append(problems, fmt.Sprintf(format, a...)) }

	seen := map[string]bool{}
	for _, u := range r.Unbuilt {
		if !idRE.MatchString(u.Rule) {
			add("unbuilt: %q is not a rule key", u.Rule)
		}
		if strings.TrimSpace(u.Reason) == "" {
			add("unbuilt %s: no reason", u.Rule)
		}
	}
	for _, m := range r.Mutants {
		who := "mutant " + m.ID
		switch {
		case !idRE.MatchString(m.ID):
			add("mutant %q: the id must be lower case words joined by hyphens", m.ID)
			continue
		case seen[m.ID]:
			add("%s: the id is used twice", who)
		}
		seen[m.ID] = true
		if !idRE.MatchString(m.Rule) {
			add("%s: %q is not a rule key", who, m.Rule)
		}
		if strings.TrimSpace(m.Why) == "" {
			add("%s: no why", who)
		}
		if len(m.Edits) == 0 {
			add("%s: no edits", who)
		}
		if len(m.MustFail) == 0 {
			add("%s: no tests that must fail", who)
		}

		byFile := map[string][]Edit{}
		var order []string
		for _, e := range m.Edits {
			if e.File == "" || path.IsAbs(e.File) || strings.Contains(e.File, "..") || strings.Contains(e.File, `\`) {
				add("%s: edit file %q must be a relative slash path inside the repository", who, e.File)
				continue
			}
			if e.Old == e.New {
				add("%s: an edit of %s changes nothing", who, e.File)
			}
			if _, ok := byFile[e.File]; !ok {
				order = append(order, e.File)
			}
			byFile[e.File] = append(byFile[e.File], e)
		}
		for _, f := range order {
			b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(f)))
			if err != nil {
				add("%s: %s cannot be read: %v", who, f, err)
				continue
			}
			if _, err := Apply(b, byFile[f]); err != nil {
				add("%s: %v", who, err)
			}
			for _, p := range supersededEdits(root, f, byFile[f]) {
				add("%s: %s", who, p)
			}
		}

		for _, ex := range m.MustFail {
			dir := strings.TrimPrefix(ex.Pkg, "./")
			if !strings.HasPrefix(ex.Pkg, "./") || strings.Contains(dir, "..") {
				add("%s: package %q must start with ./ and stay inside the repository", who, ex.Pkg)
				continue
			}
			if len(ex.Tests) == 0 {
				add("%s: package %s lists no tests", who, ex.Pkg)
			}
			have, err := testFuncs(filepath.Join(root, filepath.FromSlash(dir)))
			if err != nil {
				add("%s: package %s: %v", who, ex.Pkg, err)
				continue
			}
			dup := map[string]bool{}
			for _, tn := range ex.Tests {
				switch {
				case !testRE.MatchString(tn):
					add("%s: %q is not a top-level test name", who, tn)
				case dup[tn]:
					add("%s: %s listed twice for %s", who, tn, ex.Pkg)
				case !have[tn]:
					add("%s: %s is not a test function of %s", who, tn, ex.Pkg)
				}
				dup[tn] = true
			}
		}
	}
	sort.Strings(problems)
	return problems
}

var migrationFileRE = regexp.MustCompile(`^(.*/)?(\d{4})_[a-z0-9_]+\.sql$`)

// supersededEdits catches a mutant that edits a migration whose text a later migration
// repeats. Migrations apply in order and a CREATE OR REPLACE of the same function in a
// later file wins, so an edit of the earlier copy applies, compiles, changes nothing the
// database runs, and every test "passes" under it: the mutant survives, but only the full
// run at the end of ci.sh says so, an hour in (P1 auth review round 10: four mutants of
// the sms_counters guard still edited 0038 after 0040 had replaced the function). The
// rule is structural: the old text of an edit must not occur in any later migration, so
// whoever replaces a function has to move its mutants in the same change, and this check
// fails in seconds, without a container.
func supersededEdits(root, file string, edits []Edit) []string {
	m := migrationFileRE.FindStringSubmatch(file)
	if m == nil {
		return nil
	}
	dir := filepath.Join(root, filepath.FromSlash(m[1]))
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, ent := range ents {
		lm := migrationFileRE.FindStringSubmatch(ent.Name())
		if ent.IsDir() || lm == nil || lm[2] <= m[2] {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, ent.Name()))
		if err != nil {
			continue
		}
		text := strings.ReplaceAll(string(b), "\r\n", "\n")
		for i, e := range edits {
			if strings.Contains(text, strings.ReplaceAll(e.Old, "\r\n", "\n")) {
				out = append(out, fmt.Sprintf("edit %d of %s is superseded: the same text is in the later migration %s, which is the one the database runs; edit that one", i+1, file, ent.Name()))
			}
		}
	}
	return out
}

// testFuncs lists the top-level test functions in the _test.go files of one directory.
func testFuncs(dir string) (map[string]bool, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		for _, m := range funcRE.FindAllSubmatch(b, -1) {
			out[string(m[1])] = true
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no test functions found in %s", dir)
	}
	return out, nil
}

// ForRule returns the mutants registered for one rule key.
func (r *Registry) ForRule(rule string) []Mutant {
	var out []Mutant
	for _, m := range r.Mutants {
		if m.Rule == rule {
			out = append(out, m)
		}
	}
	return out
}

// IsUnbuilt reports whether the rule is on the allow list of rules with no enforcement.
func (r *Registry) IsUnbuilt(rule string) bool {
	for _, u := range r.Unbuilt {
		if u.Rule == rule {
			return true
		}
	}
	return false
}
