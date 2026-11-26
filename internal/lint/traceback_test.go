package lint_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// tracebackProblems judges the one setting that keeps the runtime's crash output out of the
// container log (round 17, primitives-r17-9). Contract: it reads the LAST stage of a Dockerfile (the
// image that runs) and the environment of every Compose service. The LAST assignment of GOTRACEBACK
// in that stage must be none (Docker applies ENV lines in order, so a later line that raises the
// level wins over an earlier none, primitives-r17-12), and no service may set GOTRACEBACK to anything
// else (an environment entry of the Compose file wins over the image's). Continuation lines are
// joined and comment lines skipped. It does not judge what an operator passes with `docker run -e`,
// which is outside the repository.
func tracebackProblems(dockerfile string, serviceEnv map[string]map[string]string) []string {
	var out []string
	lines := strings.Split(strings.ReplaceAll(dockerfile, "\r\n", "\n"), "\n")
	// A line that ends in a backslash continues on the next one, as in Docker, so an ENV split over
	// several lines is one instruction.
	var ins []string
	for i := 0; i < len(lines); i++ {
		l := strings.TrimSpace(lines[i])
		for strings.HasSuffix(l, "\\") && i+1 < len(lines) {
			i++
			l = strings.TrimSpace(strings.TrimSuffix(l, "\\") + " " + strings.TrimSpace(lines[i]))
		}
		if strings.HasPrefix(l, "#") {
			continue
		}
		ins = append(ins, l)
	}
	last := 0
	for i, l := range ins {
		if strings.HasPrefix(strings.ToUpper(l), "FROM ") {
			last = i
		}
	}
	value, assigned := "", false
	for _, l := range ins[last:] {
		f := strings.Fields(l)
		if len(f) < 2 || !strings.EqualFold(f[0], "ENV") {
			continue
		}
		if !strings.Contains(f[1], "=") {
			// The legacy `ENV KEY value` form: the rest of the line is the one value.
			if f[1] == "GOTRACEBACK" {
				value, assigned = strings.Trim(strings.Join(f[2:], " "), `"`), true
			}
			continue
		}
		for _, kv := range f[1:] {
			if k, v, ok := strings.Cut(kv, "="); ok && k == "GOTRACEBACK" {
				value, assigned = strings.Trim(v, `"`), true
			}
		}
	}
	switch {
	case !assigned:
		out = append(out, "the last stage of the Dockerfile does not set ENV GOTRACEBACK=none: a crash prints the arguments of every frame into the container log")
	case value != "none":
		out = append(out, "the last ENV GOTRACEBACK of the last stage of the Dockerfile is "+value+", not none: a crash prints the arguments of every frame into the container log")
	}
	for svc, env := range serviceEnv {
		if v, ok := env["GOTRACEBACK"]; ok && v != "none" {
			out = append(out, "service "+svc+" sets GOTRACEBACK to "+v+", which undoes the image's none")
		}
	}
	return out
}

func TestTheImageSilencesGoCrashTracebacks(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(repoRoot(t), "deploy", "docker", "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	c := loadCompose(t)
	env := map[string]map[string]string{}
	for name, s := range c.Services {
		env[name] = s.Environment
	}
	for _, p := range tracebackProblems(string(b), env) {
		t.Error(p)
	}
}

func TestTracebackLintCanFail(t *testing.T) {
	const good = "FROM a AS build\nRUN x\nFROM scratch\nUSER 1\nENV GOTRACEBACK=none\nENTRYPOINT [\"x\"]\n"
	for name, tc := range map[string]struct {
		df   string
		env  map[string]map[string]string
		want int
	}{
		"the image sets none":            {good, nil, 0},
		"the legacy ENV form":            {"FROM scratch\nENV GOTRACEBACK none\n", nil, 0},
		"one ENV line with several keys": {"FROM scratch\nENV A=b GOTRACEBACK=none\n", nil, 0},
		"no setting":                     {"FROM scratch\nUSER 1\n", nil, 1},
		"set in the build stage only":    {"FROM a AS build\nENV GOTRACEBACK=none\nFROM scratch\nUSER 1\n", nil, 1},
		"a lower level":                  {"FROM scratch\nENV GOTRACEBACK=single\n", nil, 1},
		"a later line raises it":         {"FROM scratch\nENV GOTRACEBACK=none\nENV GOTRACEBACK=all\n", nil, 1},
		"a later legacy line raises it":  {"FROM scratch\nENV GOTRACEBACK=none\nENV GOTRACEBACK crash\n", nil, 1},
		"a later key in one line":        {"FROM scratch\nENV GOTRACEBACK=none A=b GOTRACEBACK=all\n", nil, 1},
		"a later line sets none again":   {"FROM scratch\nENV GOTRACEBACK=all\nENV GOTRACEBACK=none\n", nil, 0},
		"a continued ENV":                {"FROM scratch\nENV A=b \\\n    GOTRACEBACK=none\n", nil, 0},
		"a continued ENV that raises":    {"FROM scratch\nENV GOTRACEBACK=none\nENV A=b \\\n    GOTRACEBACK=all\n", nil, 1},
		"a commented-out raise":          {"FROM scratch\nENV GOTRACEBACK=none\n# ENV GOTRACEBACK=all\n", nil, 0},
		"a service raises it":            {good, map[string]map[string]string{"api": {"GOTRACEBACK": "all"}}, 1},
		"a service sets none":            {good, map[string]map[string]string{"api": {"GOTRACEBACK": "none"}}, 0},
		"a service sets something else":  {good, map[string]map[string]string{"api": {"CTRLZ_X": "1"}}, 0},
	} {
		if got := tracebackProblems(tc.df, tc.env); len(got) != tc.want {
			t.Errorf("%s: %v, want %d", name, got, tc.want)
		}
	}
}
