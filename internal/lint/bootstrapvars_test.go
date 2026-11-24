package lint_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The psql variables of the bootstrap files are one decision (P1 auth review round 16, db-r16-26).
//
// 15-role-bounds.sql and 20-database.sql are run twice in life: by the initdb hook on the first start, and by
// repair.sh on an installed database (the command ctrlz migrate names). Before round 16 the \set lines lived in
// the hook alone, so the repair could not be run as written. migrations/postgres/bootstrap/vars.sh now holds
// them, and both callers source it.
//
// Contract. This guard reads every psql variable the two repair files use (a :name, :'name' or :"name"
// outside a comment and outside a :: cast) and requires that vars.sh sets exactly those (an `echo "\\set name`
// line), so a variable added to one of the files without a line in vars.sh fails, and one that vars.sh sets and
// no file uses fails too (a stale line is a decision nobody reads). It requires that the initdb hook and
// repair.sh both source vars.sh and set none of those variables themselves. It judges these five files and
// nothing else: 10-cluster.sql has its own variables (the passwords), which only the hook sets from the Docker
// secrets.

var psqlVar = regexp.MustCompile(`(?:^|[^:])(?::'([a-z_]+)'|:"([a-z_]+)"|:([a-z_]+))`)

func psqlVariablesOf(sql string) []string {
	var lines []string
	for _, ln := range strings.Split(sql, "\n") {
		if i := strings.Index(ln, "--"); i >= 0 {
			ln = ln[:i]
		}
		lines = append(lines, ln)
	}
	seen := map[string]bool{}
	for _, m := range psqlVar.FindAllStringSubmatch(strings.Join(lines, "\n"), -1) {
		for _, g := range m[1:] {
			if g != "" {
				seen[g] = true
			}
		}
	}
	out := make([]string, 0, len(seen))
	for v := range seen {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// setsVariable matches the echo of a \set line (one or more backslashes, as the shell needs).
var setsVariable = regexp.MustCompile(`echo "\\+set ([a-z_]+) `)

func bootstrapVarsProblems(files map[string]string) []string {
	var out []string
	used := map[string]bool{}
	for _, name := range []string{"15-role-bounds.sql", "20-database.sql"} {
		for _, v := range psqlVariablesOf(files[name]) {
			used[v] = true
		}
	}
	set := map[string]bool{}
	for _, m := range setsVariable.FindAllStringSubmatch(files["vars.sh"], -1) {
		set[m[1]] = true
	}
	for v := range used {
		if !set[v] {
			out = append(out, "a bootstrap file uses the psql variable "+v+", which vars.sh does not set: the repair would die on a syntax error")
		}
	}
	for v := range set {
		if !used[v] {
			out = append(out, "vars.sh sets "+v+", which neither 15-role-bounds.sql nor 20-database.sql uses: remove the line")
		}
	}
	for _, c := range []string{"10-bootstrap.sh", "repair.sh"} {
		src := files[c]
		if !strings.Contains(src, `. "$files/vars.sh"`) || !strings.Contains(src, "ctrlz_bootstrap_vars") {
			out = append(out, c+" does not source vars.sh and call ctrlz_bootstrap_vars")
		}
		for _, m := range setsVariable.FindAllStringSubmatch(src, -1) {
			if set[m[1]] {
				out = append(out, c+" sets "+m[1]+" itself: it belongs in vars.sh, which is the one place both callers read")
			}
		}
	}
	sort.Strings(out)
	return out
}

func readBootstrapVarFiles(t *testing.T) map[string]string {
	t.Helper()
	root := repoRoot(t)
	files := map[string]string{}
	for name, rel := range map[string]string{
		"15-role-bounds.sql": "migrations/postgres/bootstrap/15-role-bounds.sql",
		"20-database.sql":    "migrations/postgres/bootstrap/20-database.sql",
		"vars.sh":            "migrations/postgres/bootstrap/vars.sh",
		"repair.sh":          "migrations/postgres/bootstrap/repair.sh",
		"10-bootstrap.sh":    "deploy/compose/postgres/initdb/10-bootstrap.sh",
	} {
		b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatal(err)
		}
		files[name] = string(b)
	}
	return files
}

func TestBootstrapVariablesAreOneFile(t *testing.T) {
	for _, p := range bootstrapVarsProblems(readBootstrapVarFiles(t)) {
		t.Error(p)
	}
}

func TestBootstrapVariablesLintCanFail(t *testing.T) {
	good := readBootstrapVarFiles(t)
	if ps := bootstrapVarsProblems(good); len(ps) != 0 {
		t.Fatalf("the real files are not clean: %v", ps)
	}
	plant := func(file, old, new string) map[string]string {
		m := map[string]string{}
		for k, v := range good {
			m[k] = v
		}
		if strings.Count(m[file], old) < 1 {
			t.Fatalf("the plant %q is not in %s", old, file)
		}
		m[file] = strings.Replace(m[file], old, new, 1)
		return m
	}
	for _, c := range []struct {
		name  string
		files map[string]string
		want  string
	}{
		{"a variable a file uses and vars.sh forgot", plant("vars.sh", `echo "\\set conn_keytool`, `echo "\\set conn_ignored`), "conn_keytool, which vars.sh does not set"},
		{"a new variable in a bootstrap file", plant("20-database.sql", "REVOKE ALL ON DATABASE :\"db_name\" FROM PUBLIC;", "REVOKE ALL ON DATABASE :\"db_name\" FROM PUBLIC; SELECT :new_variable;"), "new_variable, which vars.sh does not set"},
		{"a stale line in vars.sh", plant("vars.sh", "}\n", "  echo \"\\\\set unused_thing 1\"\n}\n"), "unused_thing, which neither"},
		{"the hook sets a variable itself", plant("10-bootstrap.sh", "  ctrlz_bootstrap_vars\n", "  ctrlz_bootstrap_vars\n  echo \"\\\\set conn_hub 3 \"\n"), "10-bootstrap.sh sets conn_hub itself"},
		{"the repair does not source vars.sh", plant("repair.sh", `. "$files/vars.sh"`, ""), "repair.sh does not source vars.sh"},
	} {
		got := strings.Join(bootstrapVarsProblems(c.files), "\n")
		if !strings.Contains(got, c.want) {
			t.Errorf("%s: the lint said %q, want a line with %q", c.name, got, c.want)
		}
	}
	// A cast and a comment are not variables.
	if v := psqlVariablesOf("SELECT 1::int; -- :not_a_var\nSELECT :a, :'b', :\"c\"; SELECT x::text"); strings.Join(v, ",") != "a,b,c" {
		t.Errorf("variables read as %v, want a, b and c", v)
	}
}
