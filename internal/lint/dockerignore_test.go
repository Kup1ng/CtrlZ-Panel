package lint_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDockerignoreKeepsSecretsAndBundlesOutOfTheContext: the Go image is built with `COPY . .` from the repository root, so a file
// that is not named in .dockerignore lands in a layer and in the build cache. The secret files, the signed node bundles, every copy
// of the host's .env and the NTS keys are mostly gitignored, so no review sees one enter a layer; this test is the only thing that
// notices a line leaving the list. deploy/compose/.env.example must stay in the context (the image embeds the compose file beside
// it), and the negation has to come after the pattern that would drop it.
func TestDockerignoreKeepsSecretsAndBundlesOutOfTheContext(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(repoRoot(t), ".dockerignore"))
	if err != nil {
		t.Fatal(err)
	}
	index := map[string]int{}
	for i, line := range strings.Split(strings.ReplaceAll(string(b), "\r", ""), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if _, seen := index[line]; !seen {
			index[line] = i
		}
	}
	for _, want := range []string{"secrets", "**/secrets", "deploy/bundles", "deploy/compose/.env*", "deploy/chrony/nts"} {
		if _, ok := index[want]; !ok {
			t.Errorf(".dockerignore has no line %q: a Dockerfile COPY . . would carry it into a layer", want)
		}
	}
	neg, ok := index["!deploy/compose/.env.example"]
	if !ok {
		t.Fatal(".dockerignore does not re-include deploy/compose/.env.example, which the Go image embeds")
	}
	if pat, ok := index["deploy/compose/.env*"]; ok && neg < pat {
		t.Error("the negation of deploy/compose/.env.example comes before deploy/compose/.env*, so the pattern drops the example again")
	}
}
