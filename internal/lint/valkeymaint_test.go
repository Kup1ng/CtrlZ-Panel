package lint_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Rule "a service credential cannot hold Valkey" (rules.md topic 29; admin-r13-5, admin-r14-1,
// admin-r14-4, admin-r14-5). valkey-cli exits 0 when the server answers with an error reply, so a decision
// made on its exit status (`cli script kill || cli shutdown`, `cli script load || ok=0`, `if cli ...`)
// never sees NOTBUSY, UNKILLABLE, NOPERM or a script that does not compile. Every call of cli in
// maintain.sh is therefore captured (`r=$(cli ...)`) or sent to /dev/null on a line of its own that decides
// nothing, and what is decided is read from the reply text. The container tests of valkeyacl_test.go run
// the unkillable and the unloadable case against the real image.
var cliByStatus = regexp.MustCompile(`(^|[^\w$])(if|while|until|!)\s+cli\b|\bcli\b[^\n]*(\|\||&&)|(\|\||&&)\s*cli\b`)

func maintainStatusProblems(text string) []string {
	var out []string
	for i, ln := range strings.Split(text, "\n") {
		trim := strings.TrimSpace(ln)
		if strings.HasPrefix(trim, "#") || strings.HasPrefix(trim, "cli()") {
			continue
		}
		if cliByStatus.MatchString(ln) {
			out = append(out, "line "+itoa(i+1)+": a decision on the exit status of valkey-cli, which is 0 for an error reply: "+trim)
		}
	}
	return out
}

func TestMaintainScriptNeverJudgesValkeyCliByItsExitStatus(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(repoRoot(t), "deploy", "compose", "valkey", "maintain.sh"))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range maintainStatusProblems(string(b)) {
		t.Error(p)
	}
}

func TestMaintainStatusCheckCanFail(t *testing.T) {
	for _, tc := range []struct {
		name, line string
		bad        bool
	}{
		{"the round 13 kill line", `cli script kill >/dev/null 2>&1 || cli shutdown nosave >/dev/null 2>&1`, true},
		{"the round 13 load line", `cli -x script load <"$f" >/dev/null 2>&1 || ok=0`, true},
		{"an if", `if cli ping; then`, true},
		{"a negated if", `if ! cli ping >/dev/null; then`, true},
		{"a while", `while cli ping; do`, true},
		{"and then", `ok && cli shutdown nosave`, true},
		{"a captured reply", `r=$(cli script kill 2>&1)`, false},
		{"a shutdown decided by the reply", `cli shutdown nosave >/dev/null 2>&1`, false},
		{"a comment", `# cli x || cli y`, false},
		{"the definition", `cli() { REDISCLI_AUTH=$pw valkey-cli --user "$user" "$@" || true; }`, false},
	} {
		if got := maintainStatusProblems(tc.line); (len(got) > 0) != tc.bad {
			t.Errorf("%s: %q, want a problem: %v", tc.name, got, tc.bad)
		}
	}
}
