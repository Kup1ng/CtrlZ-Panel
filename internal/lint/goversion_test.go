package lint_test

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The Go version has ONE source of truth: the `go` directive of the root
// go.mod. Everything else that names a toolchain must agree with it, and this
// file fails for any copy that does not. Review round 8 found the same class
// twice (go-bump findings c1, c2, c3, s1, s2): the Dockerfile kept building
// the release binary with the old compiler while CI vetted and ran govulncheck
// with the new one, so the gate judged bytes that never shipped. A one-off fix
// per bump would leave the class open; this rule closes it.
//
// What it covers: shared/go.mod, every `FROM golang:<tag>` in a Dockerfile and
// every `golang:<tag>` image in deploy/ YAML, any `toolchain` line, and the two
// pins in the docs that scripts read (.claude/CLAUDE.md, shared/README.md).
// What it cannot cover: the host compiler (scripts/go-pin-check.sh, run by
// ci.sh) and the binary inside the built image (scripts/image-smoke.sh).

var (
	goDirectiveRe = regexp.MustCompile(`(?m)^go[ \t]+(\d+\.\d+\.\d+)[ \t]*$`)
	toolchainRe   = regexp.MustCompile(`(?m)^toolchain[ \t]+(\S+)`)
	golangImageRe = regexp.MustCompile(`\bgolang:([^\s"'@]+)`)
	claudePinRe   = regexp.MustCompile("Go (\\d+\\.\\d+\\.\\d+) \\(`go\\.mod`\\)")
	sharedReadRe  = regexp.MustCompile(`\(Go (\d+\.\d+\.\d+)\)`)
)

// goPins is every file the rule reads.
type goPins struct {
	goMod, sharedMod, claudeMD, sharedReadme string
	// images holds the text of each Dockerfile and deploy YAML, by
	// repository-relative slash path.
	images map[string]string
}

// stripComments drops whole-line # comments, so a comment that mentions
// "golang:1.20" for history does not count as a pin and cannot hide a real one.
func stripComments(s string) string {
	var out []string
	for _, ln := range strings.Split(s, "\n") {
		if strings.HasPrefix(strings.TrimSpace(ln), "#") {
			continue
		}
		out = append(out, ln)
	}
	return strings.Join(out, "\n")
}

// goVersionDrift returns one line per disagreement. An empty slice means the
// pins agree. A pin that cannot be found is a disagreement too: a reworded
// line must not turn the rule off silently.
func goVersionDrift(p goPins) []string {
	m := goDirectiveRe.FindStringSubmatch(p.goMod)
	if m == nil {
		return []string{"go.mod has no `go X.Y.Z` directive"}
	}
	want := m[1]
	var bad []string
	if tm := toolchainRe.FindStringSubmatch(p.goMod); tm != nil && tm[1] != "go"+want {
		bad = append(bad, fmt.Sprintf("go.mod has toolchain %s, want go%s", tm[1], want))
	}
	if sm := goDirectiveRe.FindStringSubmatch(p.sharedMod); sm == nil {
		bad = append(bad, "shared/go.mod has no `go X.Y.Z` directive")
	} else if sm[1] != want {
		bad = append(bad, fmt.Sprintf("shared/go.mod says go %s, go.mod says %s", sm[1], want))
	}
	// A toolchain line is a second source of truth; it must not exist or must
	// equal the directive.
	if tm := toolchainRe.FindStringSubmatch(p.sharedMod); tm != nil && tm[1] != "go"+want {
		bad = append(bad, fmt.Sprintf("shared/go.mod has toolchain %s, want go%s", tm[1], want))
	}
	for _, c := range []struct {
		name string
		re   *regexp.Regexp
		text string
	}{{".claude/CLAUDE.md", claudePinRe, p.claudeMD}, {"shared/README.md", sharedReadRe, p.sharedReadme}} {
		cm := c.re.FindStringSubmatch(c.text)
		switch {
		case cm == nil:
			bad = append(bad, c.name+" no longer states the Go version in the form this rule reads")
		case cm[1] != want:
			bad = append(bad, fmt.Sprintf("%s says Go %s, go.mod says %s", c.name, cm[1], want))
		}
	}
	buildStage := false
	for name, text := range p.images {
		for _, im := range golangImageRe.FindAllStringSubmatch(stripComments(text), -1) {
			if im[1] != want {
				bad = append(bad, fmt.Sprintf("%s uses golang:%s, go.mod says %s", name, im[1], want))
			}
			if strings.HasPrefix(filepath.Base(name), "Dockerfile") {
				buildStage = true
			}
		}
	}
	// Fail closed: the release image must be built from a golang image this
	// rule can read. A Dockerfile that stopped using one (a digest-only or
	// private base) would otherwise pass with nothing compared.
	if !buildStage {
		bad = append(bad, "no Dockerfile has a `FROM golang:<tag>` build stage")
	}
	return bad
}

func readGoPins(t *testing.T) goPins {
	t.Helper()
	root := repoRoot(t)
	read := func(rel string) string {
		b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	p := goPins{
		goMod:        read("go.mod"),
		sharedMod:    read("shared/go.mod"),
		claudeMD:     read(".claude/CLAUDE.md"),
		sharedReadme: read("shared/README.md"),
		images:       map[string]string{},
	}
	skip := map[string]bool{"node_modules": true, ".git": true, ".codegraph": true, ".next": true}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skip[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		base := d.Name()
		isDockerfile := strings.HasPrefix(base, "Dockerfile") || strings.HasSuffix(base, ".Dockerfile")
		isDeployYAML := strings.HasPrefix(rel, "deploy/") && (strings.HasSuffix(base, ".yml") || strings.HasSuffix(base, ".yaml"))
		if isDockerfile || isDeployYAML {
			p.images[rel] = read(rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// TestGoVersionPinsAgree is the rule on the real tree.
func TestGoVersionPinsAgree(t *testing.T) {
	if bad := goVersionDrift(readGoPins(t)); len(bad) > 0 {
		t.Fatalf("the Go version pins disagree (change go.mod, then every line below, in one commit):\n  %s", strings.Join(bad, "\n  "))
	}
}

// TestGoVersionRuleCatchesDrift proves the rule fails for each way a bump can
// be half done, not only for the Dockerfile case that was seen.
func TestGoVersionRuleCatchesDrift(t *testing.T) {
	sha := "@sha256:" + strings.Repeat("a", 64)
	good := func() goPins {
		return goPins{
			goMod:        "module x\n\ngo 1.27.4\n",
			sharedMod:    "module y\n\ngo 1.27.4\n",
			claudeMD:     "Go 1.27.4 (`go.mod`), pnpm 12\n",
			sharedReadme: "Module: `y` (Go 1.27.4). Spec\n",
			images: map[string]string{
				"deploy/docker/Dockerfile": "# old: golang:1.20\nFROM golang:1.27.4 AS build\nFROM scratch\n",
			},
		}
	}
	if bad := goVersionDrift(good()); len(bad) != 0 {
		t.Fatalf("a consistent tree reported drift: %v", bad)
	}
	cases := []struct {
		name   string
		mutate func(*goPins)
	}{
		{"dockerfile tag old", func(p *goPins) { p.images["deploy/docker/Dockerfile"] = "FROM golang:1.27.3 AS build\n" }},
		{"dockerfile floating tag", func(p *goPins) { p.images["deploy/docker/Dockerfile"] = "FROM golang:latest AS build\n" }},
		{"dockerfile variant tag", func(p *goPins) { p.images["deploy/docker/Dockerfile"] = "FROM golang:1.27.4-alpine AS build\n" }},
		{"dockerfile second stage old", func(p *goPins) {
			p.images["deploy/docker/Dockerfile"] += "FROM golang:1.27.3 AS tools\n"
		}},
		{"dockerfile digest on old tag", func(p *goPins) {
			p.images["deploy/docker/Dockerfile"] = "FROM golang:1.27.3" + sha + " AS build\n"
		}},
		{"dockerfile has no golang stage", func(p *goPins) { p.images["deploy/docker/Dockerfile"] = "FROM scratch\n" }},
		{"no dockerfile at all", func(p *goPins) { p.images = map[string]string{} }},
		{"compose image old", func(p *goPins) { p.images["deploy/compose/ci.yml"] = "    image: golang:1.26.0\n" }},
		{"shared go.mod old", func(p *goPins) { p.sharedMod = "go 1.27.3\n" }},
		{"shared go.mod no directive", func(p *goPins) { p.sharedMod = "module y\n" }},
		{"toolchain line old", func(p *goPins) { p.goMod += "toolchain go1.27.3\n" }},
		{"shared toolchain line old", func(p *goPins) { p.sharedMod += "toolchain go1.27.3\n" }},
		{"claude md old", func(p *goPins) { p.claudeMD = "Go 1.27.3 (`go.mod`), pnpm\n" }},
		{"claude md reworded", func(p *goPins) { p.claudeMD = "Go toolchain: see go.mod\n" }},
		{"shared readme old", func(p *goPins) { p.sharedReadme = "(Go 1.27.3)" }},
		{"root go.mod no directive", func(p *goPins) { p.goMod = "module x\n" }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := good()
			c.mutate(&p)
			if len(goVersionDrift(p)) == 0 {
				t.Fatalf("drift not detected")
			}
		})
	}
	// A matching toolchain line and a matching digest pin stay allowed.
	p := good()
	p.goMod += "toolchain go1.27.4\n"
	p.images["deploy/docker/Dockerfile"] = "FROM golang:1.27.4" + sha + " AS build\n"
	if bad := goVersionDrift(p); len(bad) != 0 {
		t.Fatalf("matching toolchain line or digest pin rejected: %v", bad)
	}
}
