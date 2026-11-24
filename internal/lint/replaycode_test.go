package lint_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A test that asserts "the same code twice is totp_step_reused" must send ONE code twice. A line
// that makes its code from the clock where it asserts the replay (codeAt(seed, time.Now()),
// totpNow(seed)) makes a code of whatever step it runs in (a code from a time value taken once,
// codeAt(seed, now), is the right way), and a 30 second boundary between the
// first use and the replay turns that into a fresh code the server rightly accepts: TestForgotPassword
// failed in one full CI run of three for that reason, after the same test had passed twice.
//
// The rule: in the API tests, a line that expects totp_step_reused does not call totpNow and
// does not read time.Now(). A line that does so on purpose (an offset into an earlier
// step is a replay at either side of the boundary) says so with a "clock-safe:" comment.
func replayCodeProblems(path, src string) []string {
	var out []string
	for i, line := range strings.Split(src, "\n") {
		if !strings.Contains(line, `"totp_step_reused")`) {
			continue
		}
		if !(strings.Contains(line, "totpNow(") || strings.Contains(line, "time.Now()")) {
			continue
		}
		if strings.Contains(line, "clock-safe:") {
			continue
		}
		out = append(out, path+":"+itoa(i+1)+": a totp_step_reused assertion makes its code from the clock; generate the code once and send that value twice")
	}
	return out
}

func TestAReplayAssertionSendsTheSameCode(t *testing.T) {
	root := repoRoot(t)
	for _, dir := range []string{"internal/api", "internal/adminapi"} {
		files, err := filepath.Glob(filepath.Join(root, filepath.FromSlash(dir), "*_test.go"))
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range files {
			b, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			rel, _ := filepath.Rel(root, p)
			for _, problem := range replayCodeProblems(filepath.ToSlash(rel), string(b)) {
				t.Error(problem)
			}
		}
	}
}

func TestReplayCodeLintCanFail(t *testing.T) {
	cases := map[string]struct {
		src  string
		want int
	}{
		"a fresh code at the replay": {`c.post(u, m{"totp_code": codeAt(seed, time.Now())}).want(401, "totp_step_reused")`, 1},
		"totpNow at the replay":      {`b.post(u, m{"code": totpNow(seed)}).want(401, "totp_step_reused")`, 1},
		"the clock at the replay":    {`x(time.Now()).want(401, "totp_step_reused")`, 1},
		"a time taken once":          {`c.post(u, m{"totp_code": codeAt(seed, now)}).want(401, "totp_step_reused")`, 0},
		"one code sent twice":        {`c.post(u, m{"totp_code": code}).want(401, "totp_step_reused")`, 0},
		"an offset that says why":    {`c.post(u, m{"totp_code": codeAt(seed, time.Now().Add(-30*time.Second))}).want(401, "totp_step_reused") // clock-safe: an earlier step is spent on both sides of a boundary`, 0},
		"another code":               {`c.post(u, m{"totp_code": codeAt(seed, time.Now())}).want(401, "totp_invalid")`, 0},
	}
	for name, c := range cases {
		if got := len(replayCodeProblems("x_test.go", c.src)); got != c.want {
			t.Errorf("%s: %d findings, want %d", name, got, c.want)
		}
	}
}
