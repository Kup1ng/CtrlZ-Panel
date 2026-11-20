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
// What it does not judge: an image named only in a place it does not read (a workflow outside this
// repository, a markdown file, mutants.yaml, whose old/new texts are source), an image a Go test hands to the
// docker command line, and an image read from a variable that is not assigned in the same function. The Panel's
// own image (ctrlz/panel:dev) is built from the Dockerfile here and is the one reviewed exemption. The reaper
// testcontainers starts beside every test is a constant of the library (TestTheReaperImageIsTheReviewedOne).
//
// A reference is pinned when it has a tag and a sha256 digest. The tag stays because a reader needs to
// know what the digest is; Docker uses the digest and ignores the tag when both are given.

var (
	pinnedImageRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9._/-]*:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}$`)
	composeDefault = regexp.MustCompile(`^\$\{([A-Z][A-Z0-9_]*):-(.*)\}$`)
	fromLine       = regexp.MustCompile(`(?i)^\s*FROM\s+(?:--\S+\s+)*(\S+)(?:\s+AS\s+(\S+))?`)
)

// imageExempt names the references that are not pulled: built here, with the reason.
var imageExempt = map[string]string{
	"ctrlz/panel:dev": "the Panel image, built from deploy/docker/Dockerfile by the stack itself",
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
			// The variable of an exempt image (CTRLZ_IMAGE) is not an override of a pinned one.
			if _, ok := imageExempt[m[2]]; !ok {
				vars[m[1]] = true
			}
			im = m[2]
		}
		refs = append(refs, im)
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
		check(path, nonComment(text))
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
	root := repoRoot(t)
	s := imageSources{dockerfiles: map[string]string{}, goFiles: map[string]string{}, others: map[string]string{}}
	b, err := os.ReadFile(filepath.Join(root, "deploy", "compose", "docker-compose.yml"))
	if err != nil {
		t.Fatal(err)
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
			s.goFiles[rel] = string(data)
		case strings.HasSuffix(name, ".sh"), strings.HasSuffix(name, ".yml"), strings.HasSuffix(name, ".yaml"),
			strings.HasSuffix(name, ".mjs"), strings.HasSuffix(name, ".env"), strings.HasPrefix(name, ".env"):
			s.others[rel] = string(data)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
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
			compose:     "services:\n  a:\n    image: ${A_IMAGE:-" + pin("valkey/valkey", "8.1") + "}\n  b:\n    image: ${CTRLZ_IMAGE:-ctrlz/panel:dev}\n  c:\n    image: " + pin("caddy", "2.10") + "\n",
			dockerfiles: map[string]string{"deploy/docker/Dockerfile": "FROM " + pin("golang", "1.27.4") + " AS build\nFROM scratch\nCOPY --from=build /a /b\n"},
			goFiles: map[string]string{
				"x/x.go": "package x\nfunc F() string { return deployImage(\"A_IMAGE\") }\n",
				// The allowed expressions: deploy.Image with a literal, a wrapper of it (also a method), a
				// variable that only ever holds one, and testcontainers' Run fed by them.
				"x/ok.go": "package x\nimport (\n\t\"github.com/Kup1ng/CtrlZ-Panel/deploy\"\n\t\"github.com/testcontainers/testcontainers-go/modules/redis\"\n)\n" +
					"func Img() string { return deploy.Image(\"A_IMAGE\") }\nfunc Img2() string { return Img() }\ntype lab struct{}\nfunc (lab) image() string { return Img2() }\n" +
					"var pkgImg = deploy.Image(\"A_IMAGE\")\n" +
					"func f(l lab) {\n\tr := deploy.Image(\"A_IMAGE\")\n\t_ = struct{ Image string }{Image: r}\n\t_ = struct{ Image string }{Image: Img()}\n\t_ = struct{ Image string }{Image: l.image()}\n\t_ = struct{ Image string }{Image: pkgImg}\n\tredis.Run(nil, Img2())\n}\n",
			},
			others: map[string]string{
				"scripts/s.sh": "# valkey/valkey" + ":8.1 is named in a comment only\nbb=\"${A_IMAGE:-$(sed -n p deploy/compose/docker-compose.yml)}\"\n" +
					"docker run --rm -v a:b -p 80:80 --name n -e \"X=1\" --network none \"$bb\" true\n" +
					"MSYS_NO_PATHCONV=1 docker run --rm --network none \x5c\n  --user \"$(id -u):$(id -g)\" \"$image\" keys\n" +
					"cid=$(docker create \"$image\")\n" +
					"docker compose -p x up -d\ndocker ps\ndocker rm -f x\n",
				"ci/ok.yml": "jobs:\n  a:\n    container:\n      image: " + pin("alpine", "3.20") + "\n    steps:\n      - image: ${X}\n",
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
