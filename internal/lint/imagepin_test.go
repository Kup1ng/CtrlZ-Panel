package lint_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Rule images-are-pinned (round 16, admin-r16-1, -9, -15; the topic had drawn the Postgres finding of
// the database area and a CI run that failed only because the runner pulled a newer postgres:18).
//
// The invariant: every image the stack or a test runs is named in ONE place, by tag AND digest
// (tag@sha256:<index digest>), so a run on a runner, on the owner's server or in the offline bundle of P6
// gets the bytes that were reviewed, and a tag that moves upstream changes nothing here.
//
// What it judges (one source of truth, nothing here is a list of spellings):
//
//  1. every `image:` of docker-compose.yml, at any depth, with `${VAR:-default}` resolved to its default;
//  2. every FROM of every Dockerfile in the repository (a stage name and scratch are not images; a FROM
//     that takes its reference from a variable is refused, because the lint cannot read what it will be);
//  3. the repositories those two name (derived, not typed here): outside the Compose file and the
//     Dockerfiles, no .go string literal and no non-comment line of a script, YAML or env file may name
//     `<repository>:<tag>` at all, pinned or not (a second copy of a digest is the drift this rule
//     removes: tests read the reference through deploy.Image, scripts read it from the Compose file);
//  4. the variables those images are overridden by (POSTGRES_IMAGE and the like, derived from (1)):
//     outside the Compose file a value assigned to one, or given as its default, must itself be pinned,
//     or be read out of the Compose file;
//  5. the USES of an image, which imageuse_test.go judges as an allow list and not as a list of references
//     (round 16, admin-r16-18): every testcontainers Run, every `Image:` field and every assignment to one
//     reads its image through deploy.Image; every `docker run|create|pull` of a script names a variable or a
//     pinned reference; every `image:` or `container:` of another YAML file is pinned. An image that the
//     Compose file does not run (redis:7, alpine:3.20) is therefore refused where it is used.
//
// The second-place check (3) takes any tag of a Compose repository, not only a number, and the registry and
// library prefixes Docker fills in (docker.io/library/postgres:18).
//
// 6. (round 17) an image a Go test hands to the docker command line cannot be found by reading, so it cannot be
//    written: deploy.DockerRun takes the image as a parameter and refuses anything that is not tag@sha256,
//    deploy.Docker takes only verbs that bring no image, and dockerexec_test.go fails for any other os/exec call
//    that is not a literal go or git (a container runtime, a variable, a Cmd literal). The Panel image is built
//    from the Dockerfile and never pulled (imageExempt, imagePullProblems). The reaper testcontainers starts
//    beside every test is pinned from outside the library by deploy.PinReaper (imagereaper_test.go).
//
// What it does not judge: an image named only in a place it does not read (a workflow outside this
// repository, a markdown file, mutants.yaml, whose old/new texts are source), and a Dockerfile or script of a
// directory the walk skips (the web workspaces, docs and test data).
//
// A reference is pinned when it has a tag and a sha256 digest. The tag stays because a reader needs to
// know what the digest is; Docker uses the digest and ignores the tag when both are given.

var (
	pinnedImageRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9._/-]*:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}$`)
	composeDefault = regexp.MustCompile(`^\$\{([A-Z][A-Z0-9_]*):-(.*)\}$`)
	fromLine       = regexp.MustCompile(`(?i)^\s*FROM\s+(?:--\S+\s+)*(\S+)(?:\s+AS\s+(\S+))?`)
)

// imageExempt names the references that are built here and not pinned, with the reason. The exemption stands
// on a fact the lint checks and does not assume (round 17, admin-r17-4): "built here" is true only when no
// command can pull the name, and `docker compose pull` and `up` pull every service that has no build section
// and no policy, a bare name being docker.io/ctrlz/panel to a registry or a mirror. So a service that runs an
// exempt reference needs `pull_policy: never` (imagePullProblems), and every docker run, create and pull of a
// script says --pull never unless its image is a pinned reference (dockerLineProblems).
var imageExempt = map[string]string{
	"ctrlz/panel:dev":     "the Panel image, built from deploy/docker/Dockerfile by the stack itself and never pulled",
	"ctrlz/web-panel:dev": "the panel dashboard, built from deploy/docker/web.Dockerfile and never pulled",
	"ctrlz/web-admin:dev": "the admin dashboard, built from deploy/docker/web.Dockerfile and never pulled",
}

// imageCopyExempt are the files that may repeat a reference of the Compose file, with the reason. Only the exact
// pinned reference of the Compose file is let through, so a copy whose digest has drifted still fails (that is the
// drift rule 3 exists for). A stale entry (a file that holds no copy any more) fails, like imageSecondPlaceExempt.
var imageCopyExempt = map[string]string{
	"deploy/compose/e2e-offline.yml": "the one-shot container that cuts Caddy's route: an override file cannot read the reference out of docker-compose.yml",
}

// imageSecondPlaceExempt are the files that name a reference on purpose, with the reason. A stale entry (a
// file that is gone or that no longer names one) fails, so the list cannot outlive its cause.
var imageSecondPlaceExempt = map[string]string{
	"internal/lint/goversion_test.go": "plants unpinned golang references to prove its own lint can fail",
}

// imageSources is everything the rule reads, so the can-fail test can plant a break in any part.
type imageSources struct {
	compose     string
	dockerfiles map[string]string // path -> text
	goFiles     map[string]string // path -> source
	others      map[string]string // path -> text of scripts, YAML and env files
}

func splitRepo(ref string) string {
	if i := strings.IndexAny(ref, "@"); i >= 0 {
		ref = ref[:i]
	}
	if i := strings.LastIndex(ref, ":"); i >= 0 && !strings.Contains(ref[i:], "/") {
		ref = ref[:i]
	}
	return ref
}

// walkImages collects the image fields of a decoded YAML document.
func walkImages(n any, out *[]string) {
	switch v := n.(type) {
	case map[string]any:
		for k, x := range v {
			if s, ok := x.(string); ok && k == "image" {
				*out = append(*out, s)
				continue
			}
			walkImages(x, out)
		}
	case []any:
		for _, x := range v {
			walkImages(x, out)
		}
	}
}

func nonComment(text string) string {
	var out []string
	for _, ln := range strings.Split(text, "\n") {
		if strings.HasPrefix(strings.TrimSpace(ln), "#") {
			continue
		}
		out = append(out, ln)
	}
	return strings.Join(out, "\n")
}

// goStrings returns every string literal of a Go file (comments are not literals). The uses of an image are
// judged by goImageProblems (imageuse_test.go), which reads the calls and the fields and not the strings.
func goStrings(path, src string) (lits string, problems []string) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, 0)
	if err != nil {
		return "", []string{path + ": " + err.Error()}
	}
	var b strings.Builder
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.BasicLit:
			if x.Kind == token.STRING {
				if s, err := strconv.Unquote(x.Value); err == nil {
					b.WriteString(s)
					b.WriteByte('\n')
				}
			}
		case *ast.KeyValueExpr:
			if k, ok := x.Key.(*ast.Ident); ok && k.Name == "Image" {
				switch v := x.Value.(type) {
				case *ast.BasicLit:
					problems = append(problems, path+": an Image field is a string literal; read it through deploy.Image")
				case *ast.BinaryExpr:
					problems = append(problems, path+": an Image field is built by concatenation; read it through deploy.Image")
				default:
					_ = v
				}
			}
		}
		return true
	})
	return b.String(), problems
}

func imagePinProblems(s imageSources) []string {
	var out []string
	var refs []string
	vars := map[string]bool{}
	repos := map[string]bool{}

	var doc any
	if err := yaml.Unmarshal([]byte(s.compose), &doc); err != nil {
		return []string{"docker-compose.yml: " + err.Error()}
	}
	var images []string
	walkImages(doc, &images)
	if len(images) == 0 {
		out = append(out, "docker-compose.yml has no image: the lint would judge nothing")
	}
	for _, im := range images {
		if m := composeDefault.FindStringSubmatch(im); m != nil {
			// The variable of an exempt image (CTRLZ_IMAGE) is not an override of a pinned one. Any other
			// image written as ${VAR:-default} is: an .env that holds the variable wins over the pin
			// (admin-r17-6), so a third-party image is a literal reference and nothing else.
			if _, ok := imageExempt[m[2]]; !ok {
				out = append(out, "image "+im+" is a variable with a default: write the pinned literal, an .env would override it")
				vars[m[1]] = true
			}
			im = m[2]
		} else if strings.Contains(im, "$") {
			out = append(out, "image "+im+" holds a variable the lint cannot resolve: write the pinned literal")
		}
		refs = append(refs, im)
	}
	out = append(out, imagePullProblems(doc)...)
	// The names a process may still override a reference by are the ones deploy.Image answers to, read from its
	// table; Compose reads none of them any more (admin-r17-6), so a script or an env file that assigns one is
	// judged like any other place that names an image.
	for _, v := range deployImageNames(s.goFiles["deploy/images.go"]) {
		vars[v] = true
	}
	stages := map[string]bool{"scratch": true}
	var from []string
	for path, text := range s.dockerfiles {
		for _, ln := range strings.Split(text, "\n") {
			m := fromLine.FindStringSubmatch(ln)
			if m == nil {
				continue
			}
			ref := m[1]
			switch {
			case stages[strings.ToLower(ref)]:
			case strings.Contains(ref, "$"):
				out = append(out, path+": FROM "+ref+" takes its image from a variable; name it with its digest")
			default:
				from = append(from, ref)
			}
			if m[2] != "" {
				stages[strings.ToLower(m[2])] = true
			}
		}
	}
	refs = append(refs, from...)
	for _, ref := range refs {
		if _, ok := imageExempt[ref]; ok {
			continue
		}
		if !pinnedImageRe.MatchString(ref) {
			out = append(out, "image "+ref+" is not pinned by tag and sha256 digest")
		}
		repos[splitRepo(ref)] = true
	}

	// (3) a second place that names one of those repositories.
	var names []string
	for r := range repos {
		names = append(names, r)
	}
	sort.Strings(names)
	var secondPlace []*regexp.Regexp
	for _, r := range names {
		// Any tag a reader could mistake for a version or a flavour (latest, 8.1, 18-alpine, bookworm, alpine),
		// with or without the registry and library prefixes Docker fills in. A port is no tag: it is four digits
		// or more.
		secondPlace = append(secondPlace, regexp.MustCompile(`(?:^|[^A-Za-z0-9._/-])(?:(?:index\.docker\.io|registry-1\.docker\.io|docker\.io)/)?(?:library/)?`+regexp.QuoteMeta(r)+`:(?:latest|[0-9]{1,3}(?:[.-][0-9A-Za-z._-]*)?|[A-Za-z_][A-Za-z0-9._-]*)(?:@|$|[^0-9A-Za-z._-])`))
	}
	var varNames []string
	for v := range vars {
		varNames = append(varNames, v)
	}
	sort.Strings(varNames)
	check := func(path, text string) {
		for i, re := range secondPlace {
			if re.MatchString(text) {
				out = append(out, path+" names "+names[i]+" with a tag: the reference lives in docker-compose.yml only (deploy.Image in Go, a read of the file in a script)")
			}
		}
		for _, v := range varNames {
			assign := regexp.MustCompile(`\b` + v + `(?:=|:-)([^\s"'}]*)`)
			for _, ln := range strings.Split(text, "\n") {
				// A line that reads the default out of the Compose file is the way a script is allowed to
				// know it (compose-smoke.sh, compose-net-test.sh).
				if strings.Contains(ln, "docker-compose.yml") || strings.Contains(ln, `"$file"`) {
					continue
				}
				for _, m := range assign.FindAllStringSubmatch(ln, -1) {
					val := m[1]
					switch {
					case val == "" || val == "$" || pinnedImageRe.MatchString(val):
					default:
						out = append(out, path+": "+v+" is set to "+val+", which is not a pinned reference")
					}
				}
			}
		}
	}
	idx := buildGoImageIndex(s.goFiles)
	for path, src := range s.goFiles {
		lits, problems := goStrings(path, src)
		out = append(out, problems...)
		out = append(out, goImageProblems(path, src, idx)...)
		if _, ok := imageSecondPlaceExempt[path]; ok {
			continue
		}
		check(path, lits)
	}
	for path, text := range s.others {
		body := nonComment(text)
		if _, ok := imageCopyExempt[path]; ok {
			// Only the pinned references of the Compose file and the Dockerfiles are removed before the scan, so a
			// copy with another digest, or a reference that nothing here runs, is still a second place.
			for _, ref := range refs {
				if pinnedImageRe.MatchString(ref) {
					body = strings.ReplaceAll(body, ref, "")
				}
			}
		}
		check(path, body)
		switch {
		case strings.HasSuffix(path, ".sh"):
			out = append(out, dockerImageProblems(path, text)...)
		case strings.HasSuffix(path, ".yml"), strings.HasSuffix(path, ".yaml"):
			out = append(out, yamlImageProblems(path, text)...)
		}
	}
	sort.Strings(out)
	return out
}

// realImageSources reads the tree. mutants.yaml, docs, the web workspaces and test data are not read.
func realImageSources(t *testing.T) imageSources {
	t.Helper()
	s, err := imageSourcesAt(repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// imageSourcesAt is realImageSources over any root, so that a test can plant a tree (the published tree has
// .github/ci, which the work tree has not) and see what the walk reads.
func imageSourcesAt(root string) (imageSources, error) {
	s := imageSources{dockerfiles: map[string]string{}, goFiles: map[string]string{}, others: map[string]string{}}
	b, err := os.ReadFile(filepath.Join(root, "deploy", "compose", "docker-compose.yml"))
	if err != nil {
		return s, err
	}
	s.compose = string(b)
	skip := map[string]bool{".git": true, "node_modules": true, "docs": true, "apps": true, "packages": true, ".claude": true, ".codegraph": true, "testdata": true}
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skip[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		name := d.Name()
		if rel == "deploy/compose/docker-compose.yml" || rel == "mutants.yaml" {
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		switch {
		case strings.HasPrefix(name, "Dockerfile"):
			s.dockerfiles[rel] = string(data)
		case strings.HasSuffix(name, ".go"):
			// unreadRel (gotree_test.go) is the one list of the places whose Go is not the product's: the CI overlay
			// .github/ci of the published tree, whose helpers run with go run and start the go tool directly because
			// they cannot import internal/toolcmd. Its .sh and .yml files are still read below, for the image pins.
			if !unreadRel(rel) {
				s.goFiles[rel] = string(data)
			}
		case strings.HasSuffix(name, ".sh"), strings.HasSuffix(name, ".yml"), strings.HasSuffix(name, ".yaml"),
			strings.HasSuffix(name, ".mjs"), strings.HasSuffix(name, ".env"), strings.HasPrefix(name, ".env"):
			s.others[rel] = string(data)
		}
		return nil
	})
	return s, err
}

// TestImageWalkReadsNoGoOfTheCIOverlay plants the published tree's overlay beside a product file: the Go helpers of
// .github/ci start the go tool directly and are not product code (the exec lint would refuse them), while the overlay's
// scripts and workflows are read for their image pins like any other (CI review round 24, ci-r24-1: the same defect as
// ci-r13-3 in a second walker, which made every published snapshot of Panel main fail this package).
func TestImageWalkReadsNoGoOfTheCIOverlay(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"deploy/compose/docker-compose.yml": "services: {}\n",
		"internal/x/x.go":                   "package x\n",
		".github/ci/plan/main.go":           "package main\n\nimport \"os/exec\"\n\nvar c = exec.Command(\"go\")\n",
		".github/ci/images.sh":              "#!/bin/sh\ntrue\n",
		".github/workflows/ci.yml":          "name: ci\n",
	}
	for rel, body := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	s, err := imageSourcesAt(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.goFiles["internal/x/x.go"]; !ok {
		t.Error("the product Go file was not read: the walk reads nothing")
	}
	if _, ok := s.goFiles[".github/ci/plan/main.go"]; ok {
		t.Error("the overlay's Go helper was read as product code")
	}
	for _, rel := range []string{".github/ci/images.sh", ".github/workflows/ci.yml"} {
		if _, ok := s.others[rel]; !ok {
			t.Errorf("%s of the overlay was not read for its image pins", rel)
		}
	}
}

func TestEveryImageIsPinnedByDigest(t *testing.T) {
	s := realImageSources(t)
	if len(s.dockerfiles) == 0 {
		t.Fatal("no Dockerfile was found: the lint would judge nothing")
	}
	for path := range imageSecondPlaceExempt {
		src, ok := s.goFiles[path]
		if !ok {
			t.Errorf("the exemption for %s is stale: the file is gone", path)
			continue
		}
		lits, _ := goStrings(path, src)
		if !strings.Contains(lits, "golang:") {
			t.Errorf("the exemption for %s is stale: it names no image any more", path)
		}
	}
	// An imageCopyExempt entry whose file holds no copy is an exemption that somebody may use unseen.
	for path := range imageCopyExempt {
		held := false
		for _, ref := range realImageRefs(t, s) {
			held = held || strings.Contains(s.others[path], ref)
		}
		if !held {
			t.Errorf("imageCopyExempt lists %s, which holds no copy of a pinned reference any more: remove the entry", path)
		}
	}
	// A pullAllowed entry whose file no longer pulls is a pull that somebody may bring back unseen.
	for path := range pullAllowed {
		if !strings.Contains(s.others[path], "docker pull") {
			t.Errorf("pullAllowed lists %s, which has no docker pull any more: remove the entry", path)
		}
	}
	if p := imagePinProblems(s); len(p) != 0 {
		t.Fatalf("%s", strings.Join(p, "\n"))
	}
}

// TestImagePinLintCanFail plants each shape the rule must refuse, in each place the rule reads, and one
// good tree that must pass. The planted references are assembled from pieces so this file does not name
// a reference itself.
func TestImagePinLintCanFail(t *testing.T) {
	d := "sha256:" + strings.Repeat("a", 64)
	pin := func(repo, tag string) string { return repo + ":" + tag + "@" + d }
	good := func() imageSources {
		return imageSources{
			compose:     "services:\n  a:\n    image: " + pin("valkey/valkey", "8.1") + "\n  b:\n    image: ${CTRLZ_IMAGE:-ctrlz/panel:dev}\n    pull_policy: never\n  c:\n    image: " + pin("caddy", "2.10") + "\n  w:\n    image: ${CTRLZ_WEB_PANEL_IMAGE:-ctrlz/web-panel:dev}\n    pull_policy: never\n",
			dockerfiles: map[string]string{"deploy/docker/Dockerfile": "FROM " + pin("golang", "1.27.4") + " AS build\nFROM scratch\nCOPY --from=build /a /b\n"},
			goFiles: map[string]string{
				"x/x.go": "package x\nfunc F() string { return deployImage(\"A_IMAGE\") }\n",
				// The names deploy.Image answers to: the variables a script or an env file may not set to a tag.
				"deploy/images.go": "package deploy\nfunc serviceOf(n string) (string, bool) {\n\tswitch n {\n\tcase \"A_IMAGE\":\n\t\treturn \"a\", true\n\t}\n\treturn \"\", false\n}\n",
				// The allowed expressions: deploy.Image with a literal, a wrapper of it (also a method), a
				// variable that only ever holds one, and testcontainers' Run fed by them.
				"x/ok.go": "package x\nimport (\n\t\"github.com/Kup1ng/CtrlZ-Panel/deploy\"\n\t\"github.com/testcontainers/testcontainers-go/modules/redis\"\n)\n" +
					"func Img() string { return deploy.Image(\"A_IMAGE\") }\nfunc Img2() string { return Img() }\ntype lab struct{}\nfunc (lab) image() string { return Img2() }\n" +
					"var pkgImg = deploy.Image(\"A_IMAGE\")\n" +
					"func f(l lab) {\n\tr := deploy.Image(\"A_IMAGE\")\n\t_ = struct{ Image string }{Image: r}\n\t_ = struct{ Image string }{Image: Img()}\n\t_ = struct{ Image string }{Image: l.image()}\n\t_ = struct{ Image string }{Image: pkgImg}\n\tredis.Run(nil, Img2())\n}\n",
			},
			others: map[string]string{
				"scripts/s.sh": "# valkey/valkey" + ":8.1 is named in a comment only\nbb=\"${A_IMAGE:-$(sed -n p deploy/compose/docker-compose.yml)}\"\n" +
					"docker run --pull never --rm -v a:b -p 80:80 --name n -e \"X=1\" --network none \"$bb\" true\n" +
					"MSYS_NO_PATHCONV=1 docker run --pull=never --rm --network none \x5c\n  --user \"$(id -u):$(id -g)\" \"$image\" keys\n" +
					"cid=$(docker create --pull never \"$image\")\n" +
					"docker compose -p x up -d\ndocker ps\ndocker rm -f x\n" +
					"dc() { docker compose -p x \"$@\"; }\ndc up -d\ndc exec -T api true\ndc run -T --rm admin ctrlz-admin x\n",
				// The one kind of pull a script may have: the placeholder, in a file of pullAllowed.
				"scripts/compose-smoke.sh": "bb=\"$(sed -n p deploy/compose/docker-compose.yml)\"\ndocker pull -q \"$bb\"\n",
				// An indented wrapper, a variable that holds the -f pairs, a function with a fixed compose command that a
				// trap calls, and the one build that says --pull=false (ci-web.sh, web-deps-stamp.sh).
				"scripts/w.sh": "if true; then\n  files=\"-f a.yml -f b.yml\"\n  w() {\n    docker compose -p x $files \"$@\"\n  }\n  w up -d\n  cleanup() {\n    docker compose -p x $files down\n  }\n  trap cleanup EXIT\nfi\ndocker build --pull=false -q -t x .\n",
				// An override file that repeats a pinned reference of the Compose file (imageCopyExempt).
				"deploy/compose/e2e-offline.yml": "services:\n  cut:\n    image: " + pin("caddy", "2.10") + "\n",
				"ci/ok.yml":                      "jobs:\n  a:\n    container:\n      image: " + pin("alpine", "3.20") + "\n    steps:\n      - image: ${X}\n",
			},
		}
	}
	if p := imagePinProblems(good()); len(p) != 0 {
		t.Fatalf("the good tree is refused: %v", p)
	}
	for name, mutate := range map[string]func(*imageSources){
		"a compose default with only a tag": func(s *imageSources) {
			s.compose = strings.Replace(s.compose, "@"+d, "", 1)
		},
		"a compose image with only a tag": func(s *imageSources) {
			s.compose = strings.Replace(s.compose, pin("caddy", "2.10"), "caddy"+":2.10", 1)
		},
		"a digest without a tag": func(s *imageSources) {
			s.compose = strings.Replace(s.compose, pin("caddy", "2.10"), "caddy@"+d, 1)
		},
		"an image nested deeper in the document": func(s *imageSources) {
			s.compose += "x-extra:\n  deep:\n    - image: busybox" + ":1.37\n"
		},
		"a Dockerfile FROM with a tag": func(s *imageSources) {
			s.dockerfiles["deploy/docker/Dockerfile"] = "FROM golang" + ":1.27.4 AS build\n"
		},
		"a Dockerfile FROM from a variable": func(s *imageSources) {
			s.dockerfiles["deploy/docker/Dockerfile"] += "FROM $BASE AS tools\n"
		},
		"a second Dockerfile": func(s *imageSources) {
			s.dockerfiles["deploy/docker/Dockerfile.tools"] = "FROM --platform=linux/amd64 busybox" + ":1.37\n"
		},
		"a Go string naming a compose repository": func(s *imageSources) {
			s.goFiles["x/y.go"] = "package x\nconst img2 = \"valkey/valkey" + ":8.1\"\n"
		},
		"a Go string naming it with a digest too": func(s *imageSources) {
			s.goFiles["x/y.go"] = "package x\nvar img = `" + pin("valkey/valkey", "8.1") + "`\n"
		},
		"a testcontainers Image literal": func(s *imageSources) {
			s.goFiles["x/y.go"] = "package x\nvar r = struct{ Image string }{Image: \"redis:7\"}\n"
		},
		"a testcontainers Image concatenation": func(s *imageSources) {
			s.goFiles["x/y.go"] = "package x\nvar r = struct{ Image string }{Image: \"redis\" + \":7\"}\n"
		},
		"a script default with a tag": func(s *imageSources) {
			s.others["scripts/s.sh"] += "bb=\"${A_IMAGE:-valkey/valkey" + ":8.1}\"\n"
		},
		"a script default that is another variable": func(s *imageSources) {
			s.others["scripts/s.sh"] += "bb=\"${A_IMAGE:-$OTHER}\"\n"
		},
		"an env file that sets the variable": func(s *imageSources) {
			s.others["deploy/compose/.env.example"] = "A_IMAGE=valkey/valkey" + ":8.1\n"
		},
		"a YAML file that names a repository": func(s *imageSources) {
			s.others["ci/x.yml"] = "services:\n  v:\n    image: caddy" + ":2.10\n"
		},
		// Round 17, admin-r17-4 and -6: the Panel image is a bare name a registry would resolve, and a
		// third-party image is a literal that no .env can override.
		"the Panel image with no pull policy": func(s *imageSources) {
			s.compose = strings.Replace(s.compose, "    pull_policy: never\n", "", 1)
		},
		"the Panel image that may be pulled when missing": func(s *imageSources) {
			s.compose = strings.Replace(s.compose, "pull_policy: never", "pull_policy: missing", 1)
		},
		"the Panel image that is pulled always": func(s *imageSources) {
			s.compose = strings.Replace(s.compose, "pull_policy: never", "pull_policy: always", 1)
		},
		"a third-party image with a pull policy": func(s *imageSources) {
			s.compose = strings.Replace(s.compose, "  c:\n", "  c:\n    pull_policy: never\n", 1)
		},
		"a third-party image that an .env can override": func(s *imageSources) {
			s.compose = strings.Replace(s.compose, pin("caddy", "2.10"), "${C_IMAGE:-"+pin("caddy", "2.10")+"}", 1)
		},
		"a third-party image from a bare variable": func(s *imageSources) {
			s.compose = strings.Replace(s.compose, pin("caddy", "2.10"), "${C_IMAGE}", 1)
		},
		"a script assigns a name deploy.Image answers to": func(s *imageSources) {
			s.others["scripts/s.sh"] += "A_IMAGE=busybox" + ":1.37\n"
		},
		"a script runs a variable image that may be pulled": func(s *imageSources) {
			s.others["scripts/s.sh"] += "docker run --rm \"$image\" true\n"
		},
		"a script creates a variable image that may be pulled": func(s *imageSources) {
			s.others["scripts/s.sh"] += "cid=$(docker create \"$bb\")\n"
		},
		// Round 17 fix gate, admin-r17-16: a pull is an allow list, and so is a compose subcommand; the --pull
		// flag is judged on every docker command.
		"a script pulls a variable image": func(s *imageSources) {
			s.others["scripts/s.sh"] += "docker pull -q \"$image\"\n"
		},
		"an allowed file pulls another variable": func(s *imageSources) {
			s.others["scripts/compose-smoke.sh"] += "docker pull -q \"$image\"\n"
		},
		"a script pulls through compose": func(s *imageSources) {
			s.others["scripts/s.sh"] += "docker compose -p x pull\n"
		},
		"a script builds through compose": func(s *imageSources) {
			s.others["scripts/s.sh"] += "docker compose -p x build\n"
		},
		"a script says --pull always to compose up": func(s *imageSources) {
			s.others["scripts/s.sh"] += "docker compose -p x up -d --pull always\n"
		},
		"a script builds with --pull": func(s *imageSources) {
			s.others["scripts/s.sh"] += "docker build --pull -t x .\n"
		},
		"a script says --pull=always": func(s *imageSources) {
			s.others["scripts/s.sh"] += "docker run --pull=always --rm \"$image\" true\n"
		},
		"a wrapper of compose pulls": func(s *imageSources) {
			s.others["scripts/s.sh"] += "dc pull\n"
		},
		"a wrapper of compose says --pull always": func(s *imageSources) {
			s.others["scripts/s.sh"] += "dc up -d --pull always\n"
		},
		"a wrapper of compose under another name pulls": func(s *imageSources) {
			s.others["scripts/t.sh"] = "stack() { docker compose \"$@\"; }\nstack pull\n"
		},
		"compose passes the words on outside a wrapper": func(s *imageSources) {
			s.others["scripts/s.sh"] += "docker compose -p x \"$@\"\n"
		},
		"docker-compose pulls": func(s *imageSources) {
			s.others["scripts/s.sh"] += "docker-compose pull\n"
		},
		"a script says --pull always": func(s *imageSources) {
			s.others["scripts/s.sh"] += "docker run --pull always --rm \"$image\" true\n"
		},
		"a script run in a command substitution that may pull": func(s *imageSources) {
			s.others["scripts/s.sh"] += "out=$(docker run --rm -i \"$image\" cat)\n"
		},
		"a web image with no pull policy": func(s *imageSources) {
			s.compose = strings.Replace(s.compose, "ctrlz/web-panel:dev}\n    pull_policy: never\n", "ctrlz/web-panel:dev}\n", 1)
		},
		"a web image that may be pulled when missing": func(s *imageSources) {
			s.compose = strings.Replace(s.compose, "ctrlz/web-panel:dev}\n    pull_policy: never", "ctrlz/web-panel:dev}\n    pull_policy: missing", 1)
		},
		"a web image that is a bare tag no exemption names": func(s *imageSources) {
			s.compose = strings.Replace(s.compose, "${CTRLZ_WEB_PANEL_IMAGE:-ctrlz/web-panel:dev}", "ctrlz/web-panel:latest", 1)
		},
		"a copy of a reference in a file that is not on the exemption list": func(s *imageSources) {
			s.others["ci/y.yml"] = "services:\n  cut:\n    image: " + pin("caddy", "2.10") + "\n"
		},
		"a copy with another digest in the exempt file": func(s *imageSources) {
			s.others["deploy/compose/e2e-offline.yml"] = "services:\n  cut:\n    image: caddy" + ":2.10@sha256:" + strings.Repeat("b", 64) + "\n"
		},
		"an indented wrapper pulls": func(s *imageSources) {
			s.others["scripts/w.sh"] += "if true; then\n  w pull\nfi\n"
		},
		"a variable of -f pairs that holds a subcommand": func(s *imageSources) {
			s.others["scripts/w.sh"] = strings.Replace(s.others["scripts/w.sh"], "files=\"-f a.yml -f b.yml\"", "files=\"-f a.yml pull\"", 1)
		},
		// webi-r1-9: the variable is assigned once with -f pairs and again with a subcommand; `$files` is then not only flags.
		"a variable of -f pairs that is assigned again with a subcommand": func(s *imageSources) {
			s.others["scripts/w.sh"] = strings.Replace(s.others["scripts/w.sh"], "  w() {", "  files=\"$files pull\"\n  w() {", 1)
		},
		"a variable of -f pairs that is appended to with a subcommand": func(s *imageSources) {
			s.others["scripts/w.sh"] = strings.Replace(s.others["scripts/w.sh"], "  w() {", "  files+=\" pull\"\n  w() {", 1)
		},
		"a build that pulls": func(s *imageSources) {
			s.others["scripts/w.sh"] += "docker build --pull=true -q -t x .\n"
		},
		"a bare --pull on a build": func(s *imageSources) {
			s.others["scripts/w.sh"] += "docker build --pull -q -t x .\n"
		},
		"a run that says --pull=false": func(s *imageSources) {
			s.others["scripts/w.sh"] += "docker run --pull=false --rm \"$image\" true\n"
		},
		"no image in the compose file": func(s *imageSources) {
			s.compose = "services: {}\n"
		},
		// Round 16, admin-r16-18: an image that Compose does not run, in each place an image is used.
		"a redis container started by a literal": func(s *imageSources) {
			s.goFiles["x/y.go"] = "package x\nimport \"github.com/testcontainers/testcontainers-go/modules/redis\"\nfunc f() { redis.Run(nil, \"redis\" + \":7\") }\n"
		},
		"a redis container started by a plain literal": func(s *imageSources) {
			s.goFiles["x/y.go"] = "package x\nimport \"github.com/testcontainers/testcontainers-go/modules/redis\"\nfunc f() { redis.Run(nil, \"redis:7\") }\n"
		},
		"a generic container from an aliased import": func(s *imageSources) {
			s.goFiles["x/y.go"] = "package x\nimport tc \"github.com/testcontainers/testcontainers-go\"\nfunc f() { tc.Run(nil, \"alpine:3.20\") }\n"
		},
		"an Image field from a package variable": func(s *imageSources) {
			s.goFiles["x/y.go"] = "package x\nvar img = \"alpine:3.20\"\nvar r = struct{ Image string }{Image: img}\n"
		},
		"an Image field from a local variable": func(s *imageSources) {
			s.goFiles["x/y.go"] = "package x\nfunc f() { img := \"alpine:3.20\"; _ = struct{ Image string }{Image: img} }\n"
		},
		"an Image field from a parameter": func(s *imageSources) {
			s.goFiles["x/y.go"] = "package x\nfunc f(img string) { _ = struct{ Image string }{Image: img} }\n"
		},
		"an Image field from the environment": func(s *imageSources) {
			s.goFiles["x/y.go"] = "package x\nimport \"os\"\nfunc f() { _ = struct{ Image string }{Image: os.Getenv(\"X\")} }\n"
		},
		"an Image assigned later": func(s *imageSources) {
			s.goFiles["x/y.go"] = "package x\nfunc f() { var r struct{ Image string }; r.Image = \"alpine:3.20\" }\n"
		},
		"deploy.Image with a name that is not a literal": func(s *imageSources) {
			s.goFiles["x/y.go"] = "package x\nimport \"github.com/Kup1ng/CtrlZ-Panel/deploy\"\nfunc f(n string) { _ = struct{ Image string }{Image: deploy.Image(n)} }\n"
		},
		"a variable with one good and one bad value": func(s *imageSources) {
			s.goFiles["x/y.go"] = "package x\nimport \"github.com/Kup1ng/CtrlZ-Panel/deploy\"\nfunc f() { img := deploy.Image(\"A_IMAGE\"); img = \"alpine:3.20\"; _ = struct{ Image string }{Image: img} }\n"
		},
		"a wrapper that returns a literal": func(s *imageSources) {
			s.goFiles["x/y.go"] = "package x\nfunc Lit() string { return \"alpine:3.20\" }\nfunc f() { _ = struct{ Image string }{Image: Lit()} }\n"
		},
		"a script runs an image of its own": func(s *imageSources) {
			s.others["scripts/s.sh"] += "docker run --rm alpine" + ":3.20 true\n"
		},
		"a script runs a bare name": func(s *imageSources) {
			s.others["scripts/s.sh"] += "docker run --rm busybox true\n"
		},
		"a script runs a bare name after flag values": func(s *imageSources) {
			s.others["scripts/s.sh"] += "docker run --rm -v a:b -p 80:80 --name n -e \"X=1\" --network none busybox true\n"
		},
		"a script runs a bare name on a continued line": func(s *imageSources) {
			s.others["scripts/s.sh"] += "docker run --rm \x5c\n  --network none busybox true\n"
		},
		"a script pulls": func(s *imageSources) {
			s.others["scripts/s.sh"] += "docker pull alpine" + ":3.20\n"
		},
		"a script creates": func(s *imageSources) {
			s.others["scripts/s.sh"] += "cid=$(docker create nginx)\n"
		},
		"a script uses docker container run": func(s *imageSources) {
			s.others["scripts/s.sh"] += "docker container run --rm busybox true\n"
		},
		"a script uses docker image pull": func(s *imageSources) {
			s.others["scripts/s.sh"] += "docker image pull busybox\n"
		},
		"a script has a flag nobody listed": func(s *imageSources) {
			s.others["scripts/s.sh"] += "docker run --weird-flag value \"$img\" true\n"
		},
		"a script pins an image in its own text": func(s *imageSources) {
			s.others["scripts/s.sh"] += "docker run --rm " + pin("busybox", "1.37") + " true\n"
		},
		"a docker run after a pipe": func(s *imageSources) {
			s.others["scripts/s.sh"] += "echo | docker run -i busybox cat\n"
		},
		"a second place with a flavour tag": func(s *imageSources) {
			s.goFiles["x/y.go"] = "package x\nconst img = \"valkey/valkey" + ":bookworm\"\n"
		},
		"a second place with a flavour tag, short name": func(s *imageSources) {
			s.others["scripts/s.sh"] += "echo caddy" + ":alpine\n"
		},
		"a second place with the registry prefix": func(s *imageSources) {
			s.others["scripts/s.sh"] += "echo docker.io/library/caddy" + ":2.10\n"
		},
		"a second place with the registry and a namespace": func(s *imageSources) {
			s.others["scripts/s.sh"] += "echo docker.io/valkey/valkey" + ":8.1\n"
		},
		"a YAML image of its own": func(s *imageSources) {
			s.others["ci/x.yml"] = "jobs:\n  a:\n    container:\n      image: alpine" + ":3.20\n"
		},
		"a YAML container string": func(s *imageSources) {
			s.others["ci/x.yml"] = "jobs:\n  a:\n    container: alpine\n"
		},
		"a YAML image in a list": func(s *imageSources) {
			s.others["ci/x.yml"] = "services:\n  - image: busybox\n"
		},
	} {
		s := good()
		mutate(&s)
		if len(imagePinProblems(s)) == 0 {
			t.Errorf("%s: no problem reported", name)
		}
	}
}

// deployImageNames returns the names deploy.Image answers to: the string cases of the function serviceOf in
// deploy/images.go (a switch, because a package-level table is mutable state).
func deployImageNames(src string) []string {
	if src == "" {
		return nil
	}
	f, err := parser.ParseFile(token.NewFileSet(), "images.go", src, 0)
	if err != nil {
		return nil
	}
	var out []string
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Name.Name != "serviceOf" || fd.Body == nil {
			continue
		}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if cc, ok := n.(*ast.CaseClause); ok {
				for _, e := range cc.List {
					if lit, ok := e.(*ast.BasicLit); ok && lit.Kind == token.STRING {
						if k, err := strconv.Unquote(lit.Value); err == nil {
							out = append(out, k)
						}
					}
				}
			}
			return true
		})
	}
	return out
}

// imagePullProblems holds the premise of imageExempt (admin-r17-4): every service whose image is an exempt
// reference has `pull_policy: never`, and no other service has a pull_policy at all (a third-party image is
// pulled by design, pinned by digest, and a policy that says otherwise would make the stack depend on what
// happens to be on the machine). The doc is the generic decode of the Compose file, merges resolved.
func imagePullProblems(doc any) []string {
	var out []string
	root, _ := doc.(map[string]any)
	services, _ := root["services"].(map[string]any)
	names := make([]string, 0, len(services))
	for n := range services {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		s, _ := services[n].(map[string]any)
		im, _ := s["image"].(string)
		ref := im
		if m := composeDefault.FindStringSubmatch(im); m != nil {
			ref = m[2]
		}
		_, exempt := imageExempt[ref]
		policy, has := s["pull_policy"]
		switch {
		case exempt && policy != "never":
			out = append(out, n+" runs an image built here (a bare name a registry would resolve), and its pull_policy is not never: docker compose pull and up would fetch it")
		case !exempt && has:
			out = append(out, n+" has a pull_policy: only the images built here are never pulled, and every other image is pinned by digest and pulled by design")
		}
	}
	return out
}

// realImageRefs are the pinned references the Compose file names, for the staleness check of imageCopyExempt.
func realImageRefs(t *testing.T, s imageSources) []string {
	t.Helper()
	var doc any
	if err := yaml.Unmarshal([]byte(s.compose), &doc); err != nil {
		t.Fatal(err)
	}
	var images, out []string
	walkImages(doc, &images)
	for _, im := range images {
		if pinnedImageRe.MatchString(im) {
			out = append(out, im)
		}
	}
	return out
}
