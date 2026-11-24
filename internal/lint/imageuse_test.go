package lint_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// The other half of rule images-are-pinned (round 16, admin-r16-18): where an image is USED, as opposed to where
// a reference is written. The first version judged the references the Compose file names and the places that
// repeat one of them, so an image that Compose does not run (`redis.Run(ctx, "redis:7")`,
// `docker run alpine:3.20`, a `var img = "alpine:3.20"` behind `Image: img`) was invisible: the lint could only
// find a second copy of something it already knew.
//
// What it judges is an allow list, not a list of images:
//
//  1. In Go, every call of Run or GenericContainer of a testcontainers package takes its image from an
//     allowed expression, and so does every `Image:` field of a composite literal and every assignment to a
//     field named Image. An allowed expression is a call of deploy.Image with a string literal (the one
//     construction that reads the reference out of the Compose file), a call of a function that has no
//     parameters and returns an allowed expression (testpg.DefaultImage, testvalkey.Image: found by reading
//     the bodies, to a fixpoint), or an identifier all of whose assignments in the function (or the file's
//     package-level variables) are allowed. A string literal, a concatenation, a parameter, an environment
//     read or anything else is refused.
//  2. In a script, every `docker run`, `docker create` and `docker pull` (also `docker container ...` and
//     `docker image pull`) names its image as a variable (`"$image"`, which the scripts read from the Compose
//     file or from CTRLZ_IMAGE) or as a pinned reference. The image word is the first word that is not a flag
//     or a flag's value; the flags that take a value are on dockerValueFlags, and an unknown flag followed by a
//     word makes that word the image, which fails closed.
//  3. In a YAML file other than the Compose file, every `image:` and `container:` value is pinned or a variable.
//
// What it does not judge: an image a Go test passes to the docker command line (its arguments are built in
// slices that grow by append, where the position of the image is not in the source), an image read from a
// variable that is not assigned in the same function, and any file this walk does not read (a workflow outside
// the repository, a markdown file, mutants.yaml).

// testcontainersCalls are the functions of a testcontainers package that start a container from an image.
var testcontainersCalls = map[string]bool{"Run": true, "GenericContainer": true}

// goImageIndex is what the Go judge reads of the whole tree before it judges one file: the functions that
// have no parameters and return an allowed image expression.
type goImageIndex struct{ wrappers map[string]bool }

type goFile struct {
	ast     *ast.File
	imports map[string]string // local name -> import path
	pkgVars map[string][]ast.Expr
}

func parseGoFile(path, src string) (*goFile, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, 0)
	if err != nil {
		return nil, err
	}
	gf := &goFile{ast: f, imports: map[string]string{}, pkgVars: map[string][]ast.Expr{}}
	for _, im := range f.Imports {
		p, _ := strconv.Unquote(im.Path.Value)
		name := filepath.Base(p)
		if im.Name != nil {
			name = im.Name.Name
		}
		gf.imports[name] = p
	}
	for _, d := range f.Decls {
		if gd, ok := d.(*ast.GenDecl); ok && (gd.Tok == token.VAR || gd.Tok == token.CONST) {
			for _, sp := range gd.Specs {
				vs := sp.(*ast.ValueSpec)
				for i, n := range vs.Names {
					if i < len(vs.Values) {
						gf.pkgVars[n.Name] = append(gf.pkgVars[n.Name], vs.Values[i])
					}
				}
			}
		}
	}
	return gf, nil
}

// assignmentsOf collects every value assigned to a plain identifier in a function body.
func assignmentsOf(body ast.Node) map[string][]ast.Expr {
	env := map[string][]ast.Expr{}
	ast.Inspect(body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.AssignStmt:
			if len(x.Lhs) == len(x.Rhs) {
				for i, l := range x.Lhs {
					if id, ok := l.(*ast.Ident); ok {
						env[id.Name] = append(env[id.Name], x.Rhs[i])
					}
				}
			} else {
				// A multi-value assignment (a, err := f()): the value is not an image expression.
				for _, l := range x.Lhs {
					if id, ok := l.(*ast.Ident); ok {
						env[id.Name] = append(env[id.Name], &ast.BadExpr{})
					}
				}
			}
		case *ast.ValueSpec:
			for i, nm := range x.Names {
				if i < len(x.Values) {
					env[nm.Name] = append(env[nm.Name], x.Values[i])
				} else {
					env[nm.Name] = append(env[nm.Name], &ast.BadExpr{})
				}
			}
		}
		return true
	})
	return env
}

func (idx *goImageIndex) allowed(e ast.Expr, gf *goFile, env map[string][]ast.Expr, seen map[string]bool) bool {
	switch x := e.(type) {
	case *ast.ParenExpr:
		return idx.allowed(x.X, gf, env, seen)
	case *ast.CallExpr:
		switch fn := x.Fun.(type) {
		case *ast.SelectorExpr:
			if id, ok := fn.X.(*ast.Ident); ok && gf.imports[id.Name] == module+"/deploy" && fn.Sel.Name == "Image" {
				lit, isLit := ast.Expr(nil), false
				if len(x.Args) == 1 {
					lit = x.Args[0]
					bl, ok := lit.(*ast.BasicLit)
					isLit = ok && bl.Kind == token.STRING
				}
				return isLit
			}
			return len(x.Args) == 0 && idx.wrappers[fn.Sel.Name]
		case *ast.Ident:
			return len(x.Args) == 0 && idx.wrappers[fn.Name]
		}
	case *ast.Ident:
		if seen[x.Name] {
			return false
		}
		vals := env[x.Name]
		if len(vals) == 0 {
			vals = gf.pkgVars[x.Name]
		}
		if len(vals) == 0 {
			return false
		}
		seen[x.Name] = true
		defer delete(seen, x.Name)
		for _, v := range vals {
			if !idx.allowed(v, gf, env, seen) {
				return false
			}
		}
		return true
	}
	return false
}

// buildGoImageIndex finds the wrapper functions of every Go file to a fixpoint.
func buildGoImageIndex(files map[string]string) *goImageIndex {
	idx := &goImageIndex{wrappers: map[string]bool{}}
	parsed := map[string]*goFile{}
	for path, src := range files {
		if gf, err := parseGoFile(path, src); err == nil {
			parsed[path] = gf
		}
	}
	for changed := true; changed; {
		changed = false
		for _, gf := range parsed {
			for _, d := range gf.ast.Decls {
				fd, ok := d.(*ast.FuncDecl)
				if !ok || fd.Body == nil || idx.wrappers[fd.Name.Name] || fd.Type.Params.NumFields() != 0 || len(fd.Body.List) != 1 {
					continue
				}
				ret, ok := fd.Body.List[0].(*ast.ReturnStmt)
				if !ok || len(ret.Results) != 1 {
					continue
				}
				if idx.allowed(ret.Results[0], gf, nil, map[string]bool{}) {
					idx.wrappers[fd.Name.Name] = true
					changed = true
				}
			}
		}
	}
	return idx
}

// goImageProblems judges the uses of an image in one Go file (rule point 1).
func goImageProblems(path, src string, idx *goImageIndex) []string {
	gf, err := parseGoFile(path, src)
	if err != nil {
		return []string{path + ": " + err.Error()}
	}
	var out []string
	check := func(where string, e ast.Expr, env map[string][]ast.Expr) {
		if !idx.allowed(e, gf, env, map[string]bool{}) {
			out = append(out, path+": "+where+" does not read its image through deploy.Image (a literal, a parameter or another expression names a reference of its own)")
		}
	}
	judge := func(n ast.Node, env map[string][]ast.Expr) {
		ast.Inspect(n, func(m ast.Node) bool {
			switch x := m.(type) {
			case *ast.CallExpr:
				if sel, ok := x.Fun.(*ast.SelectorExpr); ok && testcontainersCalls[sel.Sel.Name] {
					if id, ok := sel.X.(*ast.Ident); ok && strings.HasPrefix(gf.imports[id.Name], "github.com/testcontainers/testcontainers-go") &&
						sel.Sel.Name == "Run" && len(x.Args) >= 2 {
						check("a call of "+id.Name+".Run", x.Args[1], env)
					}
				}
			case *ast.KeyValueExpr:
				if k, ok := x.Key.(*ast.Ident); ok && k.Name == "Image" {
					check("an Image field", x.Value, env)
				}
			case *ast.AssignStmt:
				if len(x.Lhs) == len(x.Rhs) {
					for i, l := range x.Lhs {
						if s, ok := l.(*ast.SelectorExpr); ok && s.Sel.Name == "Image" {
							check("an assignment to an Image field", x.Rhs[i], env)
						}
					}
				}
			}
			return true
		})
	}
	for _, d := range gf.ast.Decls {
		switch dd := d.(type) {
		case *ast.FuncDecl:
			if dd.Body != nil {
				judge(dd.Body, assignmentsOf(dd.Body))
			}
		case *ast.GenDecl:
			judge(dd, nil)
		}
	}
	sort.Strings(out)
	return out
}

// dockerValueFlags are the flags of `docker run|create|pull` that take their value as the next word. A flag
// that is not here and not written as --flag=value ends the flag list's meaning: the next word is read as the
// image, so a flag nobody listed fails closed.
var dockerValueFlags = map[string]bool{
	"name": true, "network": true, "net": true, "user": true, "u": true, "entrypoint": true, "v": true, "volume": true,
	"e": true, "env": true, "env-file": true, "p": true, "publish": true, "tmpfs": true, "cap-add": true, "cap-drop": true,
	"workdir": true, "w": true, "mount": true, "label": true, "l": true, "memory": true, "m": true, "cpus": true,
	"pids-limit": true, "restart": true, "security-opt": true, "hostname": true, "h": true, "add-host": true, "dns": true,
	"platform": true, "pull": true, "log-driver": true, "log-opt": true, "ip": true, "ip6": true, "shm-size": true,
	"ulimit": true, "stop-timeout": true, "stop-signal": true, "health-cmd": true, "health-interval": true,
	"health-retries": true, "health-timeout": true, "health-start-period": true, "network-alias": true, "cidfile": true,
	"device": true, "group-add": true, "ipc": true, "pid": true, "uts": true, "userns": true, "cgroup-parent": true,
	"sysctl": true, "expose": true, "annotation": true, "attach": true, "a": true, "cpu-shares": true, "c": true,
	"memory-swap": true, "gpus": true, "runtime": true, "volumes-from": true, "link": true, "dns-search": true,
	"mac-address": true, "oom-score-adj": true, "cgroupns": true, "isolation": true,
}

// pullAllowed is every `docker pull` a script may run, by file, with the image word it may pull. Both are the
// one placeholder image that the Compose file pins by digest (web-panel), pulled when a machine does not have
// it yet. A pull is the only command that fetches a reference by name on purpose, so it is an allow list and not
// a judgement of the image word: any other `docker pull`, of a variable as well, fails, because a variable that
// holds the Panel image would fetch docker.io/ctrlz/panel from whoever owns the namespace and hand it every
// secret of the stack (round 17 fix gate, admin-r17-16).
var pullAllowed = map[string]string{
	"scripts/compose-net-test.sh": "$bb",
	"scripts/compose-smoke.sh":    "$bb",
}

// composeSubcommands are the `docker compose` subcommands a script may run. `pull` and `build` are not on it:
// they fetch images by name whatever the services say about their policy, and `up`, `run` and `create` take
// the policy from the Compose file (pull_policy: never for the Panel image) unless a --pull flag overrides it,
// which dockerLineProblems judges on every docker command. An allow list, so a subcommand this lint has not
// heard of fails.
var composeSubcommands = map[string]bool{
	"up": true, "down": true, "run": true, "exec": true, "ps": true, "logs": true, "config": true, "stop": true,
	"start": true, "restart": true, "rm": true, "kill": true, "cp": true, "port": true, "top": true, "images": true,
	"version": true, "create": true,
}

// composeValueFlags are the global flags of `docker compose` that take a value as the next word. An unknown flag
// followed by a word makes that word the subcommand, which is not on the list, so the line fails.
var composeValueFlags = map[string]bool{
	"p": true, "project-name": true, "f": true, "file": true, "env-file": true, "profile": true,
	"project-directory": true, "ansi": true, "parallel": true,
}

// dockerCtx is what one script text says about its own shell functions.
type dockerCtx struct {
	wrappers  map[string]bool // functions whose body runs docker compose: a call of one is a docker compose
	inWrapper bool            // the line is inside the body of such a function, where "$@" is the caller's words
}

var shellFuncStart = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)\(\)\s*\{`)

// dockerWrappers finds the shell functions of a text that run docker compose, and the physical lines of their
// bodies. Derived from the text and not from the name `dc`, so a wrapper called anything is judged as the
// command it stands for.
func dockerWrappers(text string) (names map[string]bool, lines map[int]bool) {
	names, lines = map[string]bool{}, map[int]bool{}
	phys := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	for s := 0; s < len(phys); s++ {
		m := shellFuncStart.FindStringSubmatch(phys[s])
		if m == nil {
			continue
		}
		e := s
		if !strings.HasSuffix(strings.TrimSpace(phys[s]), "}") {
			for e = s + 1; e < len(phys) && strings.TrimSpace(phys[e]) != "}"; e++ {
			}
		}
		body := strings.Join(phys[s:min(e+1, len(phys))], "\n")
		if strings.Contains(body, "docker compose") || strings.Contains(body, "docker-compose") {
			names[m[1]] = true
			for n := s; n <= e; n++ {
				lines[n+1] = true
			}
		}
	}
	return names, lines
}

// dockerImageProblems judges every docker command of a shell text (rule point 2), also inside a command
// substitution: the image word of run, create and pull, the --pull flag of any command, the pull allow list and
// the docker compose subcommands. Whoever wrote the line, a variable is accepted as the image of a run or a
// create (the scripts read the reference out of the Compose file or take it from CTRLZ_IMAGE), and a literal has
// to be pinned.
func dockerImageProblems(path, text string) []string {
	var out []string
	wrappers, wrapperLines := dockerWrappers(text)
	nums, _, joined := logicalLines(text)
	for k, ln := range joined {
		trim := strings.TrimSpace(ln)
		if trim == "" || strings.HasPrefix(trim, "#") {
			continue
		}
		ctx := dockerCtx{wrappers: wrappers, inWrapper: wrapperLines[nums[k]]}
		for _, p := range dockerLineProblems(path, trim, ctx) {
			out = append(out, path+":"+itoa(nums[k])+": "+p)
		}
	}
	return out
}

// pullFlagProblem judges the --pull flag in the words of one command: its value is never. A bare --pull (a
// boolean of `docker build`) is the value true, and so is any other word, so only the literal never passes.
func pullFlagProblem(words []envWord) string {
	for m, wd := range words {
		w := unquote(wd.text)
		switch {
		case w == "--pull":
			if m+1 >= len(words) || unquote(words[m+1].text) != "never" {
				return "--pull without the value never: a flag on the command line overrides pull_policy: never"
			}
		case strings.HasPrefix(w, "--pull="):
			if w != "--pull=never" {
				return "--pull with a value other than never: a flag on the command line overrides pull_policy: never"
			}
		}
	}
	return ""
}

// dockerLineProblems judges one logical line of shell text.
func dockerLineProblems(path, line string, ctx dockerCtx) []string {
	var out []string
	words := shellWords(line)
	for i := 0; i < len(words); i++ {
		if words[i].sep {
			continue
		}
		for _, inner := range innerCommands(words[i].text) {
			out = append(out, dockerLineProblems(path, inner, ctx)...)
		}
		head := baseName(unquote(words[i].text))
		isWrapper := ctx.wrappers[head]
		if head != "docker" && head != "docker-compose" && !isWrapper {
			continue
		}
		end := i + 1
		for end < len(words) && !words[end].sep {
			end++
		}
		// `dc() { ... }` is the definition of the wrapper and not a call of it: the shell reader ends the command
		// at the parenthesis, so the name has no words after it (a bare call of the wrapper has none either, and
		// compose with no subcommand fetches nothing). The body is judged line by line like any other text.
		if isWrapper && end == i+1 {
			continue
		}
		if p := pullFlagProblem(words[i+1 : end]); p != "" {
			out = append(out, head+": "+p)
		}
		j := i + 1
		sub := ""
		for ; j < end; j++ {
			w := unquote(words[j].text)
			if strings.HasPrefix(w, "-") {
				continue
			}
			if (w == "container" || w == "image") && sub == "" {
				sub = w
				continue
			}
			sub = w
			break
		}
		// docker compose, docker-compose and a wrapper function of one: the subcommand is the first word after
		// the global flags, and it must be on the allow list.
		if sub == "compose" || head == "docker-compose" || isWrapper {
			from := j + 1
			if head == "docker-compose" || isWrapper {
				from = i + 1
			}
			csub := ""
			for m := from; m < end; m++ {
				w := unquote(words[m].text)
				if strings.HasPrefix(w, "-") {
					if !strings.Contains(w, "=") && composeValueFlags[strings.TrimLeft(w, "-")] {
						m++
					}
					continue
				}
				csub = w
				break
			}
			switch {
			case (csub == "$@" || csub == "$*") && ctx.inWrapper:
				// The body of a wrapper passes its caller's words on; the calls of the wrapper are judged.
			case !composeSubcommands[csub]:
				out = append(out, head+" "+csub+": a docker compose subcommand that is not on the list of those that cannot fetch an image by name")
			}
			continue
		}
		if j >= end || (sub != "run" && sub != "create" && sub != "pull") {
			continue
		}
		// The image word: the first word after the subcommand that is no flag and no flag's value.
		var image string
		found := false
		pullNever := false
		for m := j + 1; m < end; m++ {
			w := unquote(words[m].text)
			if strings.HasPrefix(w, "-") {
				name := strings.TrimLeft(w, "-")
				if name == "pull=never" {
					pullNever = true
				}
				if !strings.Contains(w, "=") && dockerValueFlags[name] {
					if name == "pull" && m+1 < end && unquote(words[m+1].text) == "never" {
						pullNever = true
					}
					m++
				}
				continue
			}
			image, found = w, true
			break
		}
		switch {
		case !found:
			out = append(out, "a docker "+sub+" with no image word the lint can read")
		case sub == "pull":
			// An allow list of whole commands (pullAllowed), not a judgement of the image word.
			if want, ok := pullAllowed[path]; !ok || want != image {
				out = append(out, "docker pull of "+image+" is not one of the pulls on the allow list (pullAllowed): a pull fetches the name from a registry")
			}
		case strings.HasPrefix(image, "$") || strings.Contains(image, "${"):
			// A variable: the scripts read the reference out of the Compose file or from CTRLZ_IMAGE. A run or a
			// create that could pull says so: the Panel image is a bare name that a registry resolves to
			// somebody else's, so no command that starts it may pull (admin-r17-4). The rule is on the shape of
			// the command and not on which variable holds which image, so a variable that is added later is
			// judged too; the third-party references the scripts use are on the machine already (the stack, or an
			// explicit pull of the pinned reference, which is a pull and not a run).
			if (sub == "run" || sub == "create") && !pullNever {
				out = append(out, "docker "+sub+" of "+image+" does not say --pull never: a bare image name would be fetched from a registry if it were missing")
			}
		case pinnedImageRe.MatchString(image):
			out = append(out, "docker "+sub+" names the pinned image "+image+" in a script: read it from the Compose file")
		default:
			out = append(out, "docker "+sub+" runs "+image+", which is not read from the Compose file (a tag moves; a bare name is latest)")
		}
	}
	return out
}

var yamlImageKey = regexp.MustCompile(`(?m)^[ \t]*(?:-[ \t]+)?(?:image|container)[ \t]*:[ \t]*['"]?([^\s'"#]+)`)

// yamlImageProblems judges the `image:` and `container:` values of a YAML file other than the Compose file
// (rule point 3): pinned, or a variable.
func yamlImageProblems(path, text string) []string {
	var out []string
	for _, m := range yamlImageKey.FindAllStringSubmatch(nonComment(text), -1) {
		v := m[1]
		if strings.Contains(v, "$") || pinnedImageRe.MatchString(v) {
			continue
		}
		out = append(out, path+": image "+v+" is not pinned by tag and sha256 digest")
	}
	return out
}
