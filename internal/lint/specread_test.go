package lint_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// Reading the spec for rule spec-fact-drift (P1 auth review, round 5). The spec's fact
// tables are copies of facts that live in code. A copy the machine can find is a copy the
// machine can compare, so each one carries a marker line right above its table:
//
//	<!-- spec-fact: audit-tenant -->
//
// and TestSpecFactTables compares the table with the registry it copies, in both
// directions. The reading code below is only the parsing; the comparisons are in
// speccompare_test.go and the registries in specfacts_test.go.

// specFile finds docs/specs/p1-auth.md. The spec lives in the workspace repository, one
// folder above this one, so a checkout of this repository alone does not have it: the
// test then skips, but only when there is no workspace around at all. Inside the
// workspace (Plan.md next to the repository) a missing spec is a failure, so the rule
// cannot go quiet by a moved file. CTRLZ_SPEC overrides the path for a clone made for a
// review.
func specFile(t *testing.T) string { return specFileNamed(t, "p1-auth.md") }

// specFileNamed is specFile for another spec of docs/specs (the P2 spec holds the table routes-profiles).
func specFileNamed(t *testing.T, name string) string {
	t.Helper()
	if p := os.Getenv("CTRLZ_SPEC"); p != "" {
		// The override names p1-auth.md; the other specs of docs/specs sit next to it.
		if name == "p1-auth.md" {
			return p
		}
		return filepath.Join(filepath.Dir(p), name)
	}
	root := repoRoot(t)
	ws := filepath.Dir(root)
	p := filepath.Join(ws, "docs", "specs", name)
	if _, err := os.Stat(p); err == nil {
		return p
	}
	if _, err := os.Stat(filepath.Join(ws, "Plan.md")); err == nil {
		t.Fatalf("the workspace is at %s but %s is missing", ws, p)
	}
	t.Skip("no workspace around this repository, so docs/specs/" + name + " is not available")
	return ""
}

func readSpec(t *testing.T) []string {
	t.Helper()
	b, err := os.ReadFile(specFile(t))
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n")
}

// specTable is one marked table: the header, the rows, and the 1-based line of each row.
type specTable struct {
	name   string
	line   int
	header []string
	rows   [][]string
	lines  []int
}

var markerRE = regexp.MustCompile(`^<!-- spec-fact: ([a-z0-9-]+) -->$`)

// markedTables returns every marked table by name. A marker with no table under it, a
// name used twice, and a row whose cell count differs from the header all fail.
func markedTables(lines []string) (map[string]specTable, []string) {
	out := map[string]specTable{}
	var problems []string
	for i := 0; i < len(lines); i++ {
		m := markerRE.FindStringSubmatch(strings.TrimSpace(lines[i]))
		if m == nil {
			continue
		}
		name := m[1]
		if _, dup := out[name]; dup {
			problems = append(problems, "spec-fact "+name+" is marked twice")
			continue
		}
		j := i + 1
		for j < len(lines) && strings.TrimSpace(lines[j]) == "" {
			j++
		}
		if j+1 >= len(lines) || !strings.HasPrefix(lines[j], "|") || !strings.HasPrefix(lines[j+1], "|") {
			problems = append(problems, "spec-fact "+name+": no table under the marker")
			continue
		}
		tb := specTable{name: name, line: i + 1, header: splitRow(lines[j])}
		k := j + 2
		for ; k < len(lines) && strings.HasPrefix(lines[k], "|"); k++ {
			cells := splitRow(lines[k])
			if len(cells) != len(tb.header) {
				problems = append(problems, specAt(name, k+1)+": "+itoa(len(cells))+" cells, the header has "+itoa(len(tb.header)))
				continue
			}
			tb.rows = append(tb.rows, cells)
			tb.lines = append(tb.lines, k+1)
		}
		out[name] = tb
		i = k - 1
	}
	return out, problems
}

func specAt(name string, line int) string { return "spec-fact " + name + " (line " + itoa(line) + ")" }

func itoa(n int) string { return strconv.Itoa(n) }

// splitRow splits a Markdown table row into trimmed cells. A pipe written \| belongs
// to the cell (the request column writes enums that way).
func splitRow(line string) []string {
	line = strings.TrimSpace(line)
	line = strings.TrimPrefix(line, "|")
	line = strings.TrimSuffix(line, "|")
	var cells []string
	var cur strings.Builder
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case c == '\\' && i+1 < len(line) && line[i+1] == '|':
			cur.WriteByte('|')
			i++
		case c == '|':
			cells = append(cells, strings.TrimSpace(cur.String()))
			cur.Reset()
		default:
			cur.WriteByte(c)
		}
	}
	return append(cells, strings.TrimSpace(cur.String()))
}

var tickRE = regexp.MustCompile("`([^`]*)`")

// ticks lists the backticked spans of a cell.
func ticks(cell string) []string {
	var out []string
	for _, m := range tickRE.FindAllStringSubmatch(cell, -1) {
		out = append(out, m[1])
	}
	return out
}

// unticked removes the backticks of a cell that is written as code.
func unticked(cell string) string { return strings.ReplaceAll(cell, "`", "") }

// column returns the index of a header column, or -1.
func (tb specTable) column(name string) int {
	for i, h := range tb.header {
		if h == name {
			return i
		}
	}
	return -1
}

// needColumns checks the header names the columns the comparison reads.
func (tb specTable) needColumns(names ...string) []string {
	var problems []string
	for _, n := range names {
		if tb.column(n) < 0 {
			problems = append(problems, "spec-fact "+tb.name+": no column "+n+" (header: "+strings.Join(tb.header, " | ")+")")
		}
	}
	return problems
}

// section returns the text of "### N.M title" up to the next heading of the same or a
// higher level, with the lines of every marked table removed (a table is checked on its
// own). prefix is "8.4" and so on.
func section(lines []string, prefix string) (string, bool) {
	start := -1
	for i, l := range lines {
		if strings.HasPrefix(l, "### "+prefix+" ") || strings.HasPrefix(l, "## "+prefix+" ") {
			start = i
			break
		}
	}
	if start < 0 {
		return "", false
	}
	level := len(lines[start]) - len(strings.TrimLeft(lines[start], "#"))
	var b strings.Builder
	inMarked := false
	for i := start + 1; i < len(lines); i++ {
		l := lines[i]
		if strings.HasPrefix(l, "#") {
			if lv := len(l) - len(strings.TrimLeft(l, "#")); lv <= level {
				break
			}
		}
		if markerRE.MatchString(strings.TrimSpace(l)) {
			inMarked = true
			continue
		}
		if inMarked {
			if strings.HasPrefix(l, "|") || strings.TrimSpace(l) == "" {
				continue
			}
			inMarked = false
		}
		b.WriteString(l)
		b.WriteByte('\n')
	}
	return b.String(), true
}

// readSpecFile reads another spec of docs/specs by file name.
func readSpecFile(t *testing.T, name string) []string {
	t.Helper()
	b, err := os.ReadFile(specFileNamed(t, name))
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n")
}
