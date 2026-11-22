package lint_test

import (
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// Rule images-are-pinned, the Go half of the use of an image (round 17, admin-r17-10).
//
// The invariant: a test or a tool that runs a container gets the image from deploy.Image and nowhere else. The
// image lint of round 16 (imageuse_test.go) reads every place an image is named, and declared one place it
// cannot read: an image a Go test appends to the arguments of `docker run` (`args = append(args, "alpine:3.20",
// ...)`), because the position of the image is not in the source. That was a limit recorded as not judged, and
// each way round it (a variable assigned elsewhere, an append, a wrapper) ran a floating image with every lint
// green. The class is closed by construction and not by reading harder: deploy.DockerRun takes the image as a
// parameter and refuses (panics) anything that is not tag@sha256, and deploy.Docker takes only the verbs that
// bring no image (exec, logs, inspect, ...). This lint then requires that nothing else in Go can start a
// container runtime:
//
//  1. every call of os/exec's Command and CommandContext, however the package was imported, names its program
//     by a string literal that is on execPrograms (empty: go and git go through toolcmd.Go and toolcmd.Git), or by a variable in a file of execFromVariable (the
//     host shell found with LookPath, which runs this repository's own scripts; the scripts are judged by the
//     shell lints). A literal that is docker, podman, nerdctl, buildah or any program nobody listed fails, and so
//     does a variable, a constant and an expression in any other file. deploy/docker.go is the one file that
//     builds a container command, and it is not read;
//  2. a literal of the type exec.Cmd (which can name its Path without a call) and a call of os.StartProcess fail
//     everywhere else, since either starts any program. A zero exec.Cmd (var c exec.Cmd, new(exec.Cmd)) is no
//     clause of its own since clause 3: it can only run a program once its Path is assigned, which clause 3
//     refuses by the type of the expression.
//
//  3. (round 17 fix gate, admin-r17-17) the program an exec.Cmd runs is chosen by its Path and Args, which any
//     assignment can change after a call with a good literal, so the fields of a Cmd that a file may assign are
//     a closed list judged by the TYPE of the expression (cmdSettable: where the output goes, the directory,
//     the environment, the wait), and every other field fails, as does taking its address. The files that
//     import os/exec are type-checked for this, with the standard library read from source and every other
//     import a stub package, so the Cmd is found whatever the variable is called;
//  4. a dot import of os/exec or os fails, since no selector then names the package; and a file may import
//     syscall only in the directories that syscallMembers lists for it (the escape-hatch ban's own source of
//     truth, which also judges the members they use), and golang.org/x/sys nowhere, since syscall.ForkExec,
//     syscall.Exec and syscall.StartProcess start any program with no os/exec at all.
//
// What it does not judge: a program a listed shell script runs (the shell lints and the image-use lint of
// scripts do). The arguments and the environment of go and git are judged by toolcmd.Go and toolcmd.Git when the
// command is made (round 18, admin-r18-13), and TestGoAndGitJudgeTheirCommandLine runs the plants.

// execPrograms are the programs a Go file may start by name.
// It is empty since round 18 (admin-r18-13): go and git can run any command their arguments or environment
// name (`git -c alias.x=!cmd x`, `go test -exec cmd`, GOFLAGS, GIT_SSH_COMMAND), so a file starts them through
// toolcmd.Go and toolcmd.Git, which judge the verb, the flags and the environment by value, and expose no field
// of the command to reassign. The map stays, empty, so that a program added here is a reviewed line.
var execPrograms = map[string]string{}

// execFromVariable are the files that start the host shell through a variable (found with LookPath), each with
// the reason.
var execFromVariable = map[string]string{
	"internal/admincli/keyidentity_test.go":     "runs scripts/gen-secrets.sh with the host shell",
	"internal/admincli/review_r5_admin_test.go": "runs scripts/gen-secrets.sh with the host shell",
	"internal/lint/composenet_test.go":          "runs scripts/compose-net-test.sh with the host shell",
	"internal/lint/composesmoke_test.go":        "runs a block of scripts/compose-smoke.sh with the host shell",
	"internal/lint/compose_p1_test.go":          "runs scripts/image-smoke.sh with the host shell",
	"internal/lint/compose_test.go":             "runs scripts/gen-secrets.sh with the host shell",
	"internal/lint/secretcanary_test.go":        "runs scripts/secret-canary.sh with the host shell",
	"internal/lint/selectprofile_test.go":       "runs scripts/select-profile.sh in a scratch tree with the host shell",
}

// execSelf are the files that re-run the running test binary, named os.Args[0], in a child process (to read what
// the Go runtime prints when a process dies), each with the reason. os.Args[0] is the binary being run, so it
// cannot be a container runtime; any other expression still needs execFromVariable. (Merge of the round 17
// fixes of the primitives and admin areas: primitives-r17-9 needed this form, which admin-r17-10 refused.)
var execSelf = map[string]string{
	"internal/logattr/crash_test.go": "re-runs the test binary in a child that dies of an unrecovered panic, to show that GOTRACEBACK=none keeps frames out of the crash output",
}

// cmdSettable are the fields of os/exec.Cmd that a file may assign: none of them chooses the program. Every other
// field (Path, Args, Err, Lookup, SysProcAttr, ExtraFiles, Process, ...) fails, so a field a later Go release
// adds starts refused.
var cmdSettable = map[string]string{
	"Dir": "the working directory", "Env": "the environment", "Stdin": "input", "Stdout": "output",
	"Stderr": "output", "WaitDelay": "how long to wait for the pipes", "Cancel": "what to do when the context ends",
}

// execTypes type-checks one file that imports os/exec. The standard library comes from one shared source
// importer (read once, then cached) and every other import path is an empty stub package, so a file that imports
// this module still checks and the errors that follow are ignored: the types this lint asks about are the ones
// of os/exec, which are real.
var execTypes struct {
	mu  sync.Mutex
	imp types.Importer
}

type stubImporter struct{ std types.Importer }

func (s stubImporter) Import(p string) (*types.Package, error) {
	if isStdPath(p) {
		if pkg, err := s.std.Import(p); err == nil {
			return pkg, nil
		}
	}
	pkg := types.NewPackage(p, path.Base(p))
	pkg.MarkComplete()
	return pkg, nil
}

func execTypeInfo(fset *token.FileSet, f *ast.File) *types.Info {
	execTypes.mu.Lock()
	defer execTypes.mu.Unlock()
	if execTypes.imp == nil {
		execTypes.imp = stubImporter{std: importer.ForCompiler(token.NewFileSet(), "source", nil)}
	}
	info := &types.Info{Types: map[ast.Expr]types.TypeAndValue{}, Uses: map[*ast.Ident]types.Object{}, Selections: map[*ast.SelectorExpr]*types.Selection{}}
	conf := types.Config{Importer: execTypes.imp, Error: func(error) {}, FakeImportC: true}
	_, _ = conf.Check("x", fset, []*ast.File{f}, info)
	return info
}

// isExecCmd reports whether t is os/exec.Cmd or a pointer to it.
func isExecCmd(t types.Type) bool {
	if p, ok := t.(*types.Pointer); ok {
		t = p.Elem()
	}
	n, ok := t.(*types.Named)
	return ok && n.Obj().Pkg() != nil && n.Obj().Pkg().Path() == "os/exec" && n.Obj().Name() == "Cmd"
}

// execProblems judges one Go file; path is relative to the repository root.
func execProblems(path, src string) []string {
	if path == "deploy/docker.go" || path == "internal/toolcmd/toolcmd.go" {
		return nil
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, 0)
	if err != nil {
		return []string{path + ": " + err.Error()}
	}
	// Every name the file gives os/exec and os is judged (localNames, primitives-r18-22: the loop kept the
	// last import of a path, so a second import under another name hid its selectors; test files may
	// import a path twice, which the one-name-per-import rule of non-test files does not forbid).
	execNames := usableNames(localNames(f, "os/exec"))
	osNames := usableNames(localNames(f, "os"))
	var bad []string
	for _, im := range f.Imports {
		p, _ := strconv.Unquote(im.Path.Value)
		name := ""
		if im.Name != nil {
			name = im.Name.Name
		}
		switch {
		case p == "syscall":
			if _, ok := syscallMembers[dirOf(path)]; !ok || strings.HasSuffix(path, "_test.go") {
				bad = append(bad, path+": imports syscall, whose ForkExec, Exec and StartProcess start any program with no os/exec; only the directories that syscallMembers lists for it may, in a non-test file")
			}
		case strings.HasPrefix(p, "golang.org/x/sys"):
			bad = append(bad, path+": imports "+p+", which can start any program with no os/exec")
		}
		if name == "." && (p == "os/exec" || p == "os") {
			bad = append(bad, path+": a dot import of "+p+" hides which member is used; import it by name")
		}
	}
	if len(execNames) == 0 && len(osNames) == 0 {
		return bad
	}
	pos := func(n ast.Node) string { return path + ":" + strconv.Itoa(fset.Position(n.Pos()).Line) + ": " }
	out := bad
	var info *types.Info
	if len(execNames) > 0 {
		info = execTypeInfo(fset, f)
	}
	// called holds the selectors that are the function of a call, so that one used as a value (`c := exec.Command`,
	// handed to a helper) is found as well: a call shape alone is the guard that round 16 retired.
	called := map[*ast.SelectorExpr]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.AssignStmt:
			for _, l := range x.Lhs {
				out = append(out, cmdFieldProblem(pos, info, l)...)
			}
		case *ast.IncDecStmt:
			out = append(out, cmdFieldProblem(pos, info, x.X)...)
		case *ast.UnaryExpr:
			if x.Op == token.AND {
				out = append(out, cmdFieldProblem(pos, info, x.X)...)
			}
		case *ast.SelectorExpr:
			if !called[x] && (selIsAny(x, execNames, "Command") || selIsAny(x, execNames, "CommandContext") || selIsAny(x, osNames, "StartProcess")) {
				out = append(out, pos(x)+"a function that starts a program is used as a value: call it with a literal program, or use deploy.Docker or deploy.DockerRun")
			}
		case *ast.CompositeLit:
			if sel, ok := x.Type.(*ast.SelectorExpr); ok && selIsAny(sel, execNames, "Cmd") {
				out = append(out, pos(x)+"an exec.Cmd literal can name any program; use deploy.Docker, deploy.DockerRun or toolcmd.Go and toolcmd.Git")
			}
		case *ast.CallExpr:
			sel, ok := x.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			called[sel] = true
			switch {
			case selIsAny(sel, osNames, "StartProcess"):
				out = append(out, pos(x)+"os.StartProcess starts any program; use deploy.Docker or deploy.DockerRun for a container")
			case selIsAny(sel, execNames, "Command") || selIsAny(sel, execNames, "CommandContext"):
				idx := 0
				if sel.Sel.Name == "CommandContext" {
					idx = 1
				}
				if len(x.Args) <= idx {
					return true
				}
				if lit, ok := x.Args[idx].(*ast.BasicLit); ok && lit.Kind == token.STRING {
					prog, _ := strconv.Unquote(lit.Value)
					if _, ok := execPrograms[prog]; !ok {
						out = append(out, pos(x)+"exec."+sel.Sel.Name+" starts "+strconv.Quote(prog)+", which is not on execPrograms (go and git go through toolcmd.Go and toolcmd.Git, a container runtime through deploy.Docker or deploy.DockerRun)")
					}
					return true
				}
				if _, ok := execSelf[path]; ok && isOsArgs0(x.Args[idx], osNames) {
					return true
				}
				if _, ok := execFromVariable[path]; !ok {
					out = append(out, pos(x)+"exec."+sel.Sel.Name+" names its program by an expression, which could be a container runtime; use toolcmd.Go, toolcmd.Git, deploy.Docker or deploy.DockerRun")
				}
			}
		}
		return true
	})
	return out
}

// cmdFieldProblem judges an assigned (or addressed) expression: a field of an exec.Cmd that is not on cmdSettable.
func cmdFieldProblem(pos func(ast.Node) string, info *types.Info, e ast.Expr) []string {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok || info == nil {
		return nil
	}
	t := info.TypeOf(sel.X)
	if t == nil || !isExecCmd(t) {
		return nil
	}
	if _, ok := cmdSettable[sel.Sel.Name]; ok {
		return nil
	}
	return []string{pos(sel) + "the field " + sel.Sel.Name + " of an exec.Cmd is assigned or addressed: it can change the program or how it starts (only the fields of cmdSettable may be); use deploy.Docker or deploy.DockerRun for a container"}
}

// isOsArgs0 reports whether e is the expression os.Args[0].
func isOsArgs0(e ast.Expr, osNames []string) bool {
	ix, ok := e.(*ast.IndexExpr)
	if !ok || len(osNames) == 0 {
		return false
	}
	sel, ok := ix.X.(*ast.SelectorExpr)
	lit, ok2 := ix.Index.(*ast.BasicLit)
	return ok && ok2 && selIsAny(sel, osNames, "Args") && lit.Kind == token.INT && lit.Value == "0"
}

// selIsAny reports whether sel is name written through any of the local names of a package.
func selIsAny(sel *ast.SelectorExpr, pkgs []string, name string) bool {
	for _, p := range pkgs {
		if selIs(sel, p, name) {
			return true
		}
	}
	return false
}

// selIs reports whether sel is pkg.name.
func selIs(sel *ast.SelectorExpr, pkg, name string) bool {
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == pkg && sel.Sel.Name == name
}

func TestGoRunsNoContainerCommandOutsideDeploy(t *testing.T) {
	s := realImageSources(t)
	var out []string
	used := map[string]bool{}
	paths := make([]string, 0, len(s.goFiles))
	for p := range s.goFiles {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		out = append(out, execProblems(p, s.goFiles[p])...)
		if _, ok := execFromVariable[p]; ok && strings.Contains(s.goFiles[p], "exec.Command(sh") {
			used[p] = true
		}
	}
	for p := range execSelf {
		if !strings.Contains(s.goFiles[p], "exec.Command(os.Args[0]") {
			out = append(out, "execSelf lists "+p+", which no longer re-runs the test binary: remove the entry")
		}
	}
	for p := range execFromVariable {
		if !used[p] {
			out = append(out, "execFromVariable lists "+p+", which starts no program by the variable sh any more: remove the entry")
		}
	}
	if len(out) != 0 {
		t.Fatalf("%s", strings.Join(out, "\n"))
	}
}

// TestGoExecLintCanFail plants every form Go gives for starting a container runtime in good-faith code: the
// direct call, the context form, an aliased import, a wrapper, a method value, a constant, a variable, a
// package-level variable, the Cmd literal and os.StartProcess; and the clean ones.
func TestGoExecLintCanFail(t *testing.T) {
	cases := []struct {
		name, path, src string
		bad             bool
	}{
		{"the test binary itself, in a file that may re-run it", "internal/logattr/crash_test.go", "package x\nimport (\n\"os\"\n\"os/exec\"\n)\nfunc f() { exec.Command(os.Args[0], \"-test.run=X\") }\n", false},
		{"the test binary itself, in a file nobody listed", "x/a.go", "package x\nimport (\n\"os\"\n\"os/exec\"\n)\nfunc f() { exec.Command(os.Args[0], \"-test.run=X\") }\n", true},
		{"another argument, in a file that may re-run the binary", "internal/logattr/crash_test.go", "package x\nimport (\n\"os\"\n\"os/exec\"\n)\nfunc f() { exec.Command(os.Args[1]) }\n", true},
		{"docker run by literal", "x/a.go", "package x\nimport \"os/exec\"\nfunc f() { exec.Command(\"docker\", \"run\", \"alpine\") }\n", true},
		{"docker with a safe verb by literal", "x/a.go", "package x\nimport \"os/exec\"\nfunc f() { exec.Command(\"docker\", \"logs\", \"c\") }\n", true},
		{"podman", "x/a.go", "package x\nimport \"os/exec\"\nfunc f() { exec.Command(\"podman\", \"run\", \"x\") }\n", true},
		{"nerdctl through the context form", "x/a.go", "package x\nimport (\n\"context\"\n\"os/exec\"\n)\nfunc f(c context.Context) { exec.CommandContext(c, \"nerdctl\", \"run\") }\n", true},
		{"an aliased import", "x/a.go", "package x\nimport ex \"os/exec\"\nfunc f() { ex.Command(\"docker\", \"run\") }\n", true},
		{"a wrapper with spread args", "x/a.go", "package x\nimport \"os/exec\"\nfunc d(args ...string) *exec.Cmd { return exec.Command(\"docker\", args...) }\n", true},
		{"a variable program", "x/a.go", "package x\nimport \"os/exec\"\nfunc f(p string) { exec.Command(p, \"run\") }\n", true},
		{"a constant program", "x/a.go", "package x\nimport \"os/exec\"\nconst rt = \"docker\"\nfunc f() { exec.Command(rt, \"run\") }\n", true},
		{"a package variable program", "x/a.go", "package x\nimport \"os/exec\"\nvar rt = \"docker\"\nfunc f() { exec.Command(rt) }\n", true},
		{"a method value", "x/a.go", "package x\nimport \"os/exec\"\nfunc f() { c := exec.Command; c(\"docker\", \"run\") }\n", true},
		{"a function value handed to a helper", "x/a.go", "package x\nimport \"os/exec\"\nfunc g(func(string, ...string) *exec.Cmd) {}\nfunc f() { g(exec.Command) }\n", true},
		{"a zero Cmd", "x/a.go", "package x\nimport \"os/exec\"\nfunc f() { var c exec.Cmd; c.Path = \"docker\" }\n", true},
		{"new(exec.Cmd)", "x/a.go", "package x\nimport \"os/exec\"\nfunc f() { c := new(exec.Cmd); c.Path = \"docker\" }\n", true},
		{"a *exec.Cmd result type starts nothing", "x/a.go", "package x\nimport \"os/exec\"\nfunc f(c *exec.Cmd) *exec.Cmd { return c }\n", false},
		{"a Cmd literal", "x/a.go", "package x\nimport \"os/exec\"\nvar c = &exec.Cmd{Path: \"/usr/bin/docker\"}\n", true},
		{"os.StartProcess", "x/a.go", "package x\nimport \"os\"\nfunc f() { os.StartProcess(\"/usr/bin/docker\", nil, nil) }\n", true},
		{"a program nobody listed", "x/a.go", "package x\nimport \"os/exec\"\nfunc f() { exec.Command(\"curl\", \"x\") }\n", true},
		{"go list by literal", "x/a.go", "package x\nimport \"os/exec\"\nfunc f() { exec.Command(\"go\", \"list\") }\n", true},
		{"git with an alias that runs docker", "x/a.go", "package x\nimport \"os/exec\"\nfunc f() { exec.Command(\"git\", \"-c\", \"alias.r=!docker run alpine:3.20\", \"r\") }\n", true},
		{"go test -exec", "x/a.go", "package x\nimport \"os/exec\"\nfunc f() { exec.Command(\"go\", \"test\", \"-exec\", \"docker run x\", \"./x\") }\n", true},
		{"git through the context form", "x/a.go", "package x\nimport \"os/exec\"\nfunc f() { exec.CommandContext(nil, \"git\", \"status\") }\n", true},
		{"toolcmd.Go", "x/a.go", "package x\nimport \"github.com/Kup1ng/CtrlZ-Panel/internal/toolcmd\"\nfunc f() { toolcmd.Go(nil, nil, \"list\") }\n", false},
		{"toolcmd.Git", "x/a.go", "package x\nimport \"github.com/Kup1ng/CtrlZ-Panel/internal/toolcmd\"\nfunc f() { toolcmd.Git(nil, \"\", nil, \"status\") }\n", false},
		{"the host shell in a listed file", "internal/lint/composenet_test.go", "package x\nimport \"os/exec\"\nfunc f(sh string) { exec.Command(sh, \"s.sh\") }\n", false},
		{"the host shell in a file nobody listed", "internal/lint/other_test.go", "package x\nimport \"os/exec\"\nfunc f(sh string) { exec.Command(sh, \"s.sh\") }\n", true},
		{"deploy.DockerRun", "x/a.go", "package x\nimport \"github.com/Kup1ng/CtrlZ-Panel/deploy\"\nfunc f() { deploy.DockerRun(nil, deploy.Image(\"CADDY_IMAGE\"), nil) }\n", false},
		{"deploy/docker.go itself", "deploy/docker.go", "package deploy\nimport \"os/exec\"\nfunc f() { exec.Command(\"docker\", \"run\") }\n", false},
		{"internal/toolcmd/toolcmd.go itself", "internal/toolcmd/toolcmd.go", "package toolcmd\nimport \"os/exec\"\nfunc f() { exec.Command(\"go\", \"list\") }\n", false},
		// Round 17 fix gate, admin-r17-17: the forms that the names of the first version did not see.
		{"a dot import of os/exec", "x/a.go", "package x\nimport . \"os/exec\"\nfunc f() { Command(\"docker\", \"run\", \"alpine\") }\n", true},
		{"syscall.ForkExec in a test", "x/a_test.go", "package x\nimport \"syscall\"\nfunc f() { syscall.ForkExec(\"/usr/bin/docker\", nil, nil) }\n", true},
		{"syscall in a directory nobody listed", "x/a.go", "package x\nimport \"syscall\"\nfunc f() { syscall.Exec(\"/usr/bin/docker\", nil, nil) }\n", true},
		{"syscall in a listed directory", "cmd/ctrlz/a.go", "package main\nimport \"syscall\"\nvar s = syscall.SIGTERM\n", false},
		{"x/sys", "x/a.go", "package x\nimport \"golang.org/x/sys/unix\"\nfunc f() { unix.Exec(\"/usr/bin/docker\", nil, nil) }\n", true},
		{"the Path of a Cmd from a good literal", "x/a.go", "package x\nimport \"os/exec\"\nfunc f() { c := exec.Command(\"go\", \"list\"); c.Path = \"/usr/bin/docker\" }\n", true},
		{"the Args of a Cmd from a good literal", "x/a.go", "package x\nimport \"os/exec\"\nfunc f() { c := exec.Command(\"go\", \"list\"); c.Args = []string{\"docker\", \"run\"} }\n", true},
		{"the Path of a Cmd behind a parameter", "x/a.go", "package x\nimport \"os/exec\"\nfunc f(c *exec.Cmd) { c.Path = \"docker\" }\n", true},
		{"the address of the Path of a Cmd", "x/a.go", "package x\nimport \"os/exec\"\nfunc f(c *exec.Cmd) *string { return &c.Path }\n", true},
		// Round 18 fix gate, primitives-r18-22: a test file may import a path twice, and every name is judged.
		{"os/exec imported twice, the first name starts docker", "x/a_test.go", "package x\nimport \"os/exec\"\nimport x \"os/exec\"\nfunc f() { exec.Command(\"docker\", \"run\") }\n", true},
		{"os/exec imported twice, the last name starts docker", "x/a_test.go", "package x\nimport \"os/exec\"\nimport x \"os/exec\"\nfunc f() { x.Command(\"docker\", \"run\") }\n", true},
		{"os imported twice, the first name starts a process", "x/a_test.go", "package x\nimport \"os\"\nimport o \"os\"\nfunc f() { os.StartProcess(\"/usr/bin/docker\", nil, nil) }\n", true},
		{"os/exec imported twice, a literal Cmd through the first name", "x/a_test.go", "package x\nimport \"os/exec\"\nimport x \"os/exec\"\nvar c = &exec.Cmd{Path: \"/usr/bin/docker\"}\n", true},
		{"os/exec imported twice and used cleanly through both", "internal/lint/composenet_test.go", "package x\nimport \"os/exec\"\nimport x \"os/exec\"\nfunc f(sh string) { exec.Command(sh, \"list\"); x.Command(sh, \"status\") }\n", false},
		{"the Stdout and Dir of a Cmd", "internal/lint/composenet_test.go", "package x\nimport (\n\"os/exec\"\n\"io\"\n)\nfunc f(w io.Writer, sh string) { c := exec.Command(sh, \"list\"); c.Dir = \"d\"; c.Stdout = w }\n", false},
		{"a Path field of another type", "internal/lint/composenet_test.go", "package x\nimport \"os/exec\"\ntype r struct{ Path string }\nfunc f(v *r, sh string) *exec.Cmd { v.Path = \"x\"; return exec.Command(sh) }\n", false},
		{"a file that imports neither", "x/a.go", "package x\nfunc f() {}\n", false},
	}
	for _, c := range cases {
		got := execProblems(c.path, c.src)
		if (len(got) > 0) != c.bad {
			t.Errorf("%s: problems %v, want a problem: %v", c.name, got, c.bad)
		}
	}
}

// A bare *exec.Cmd never crosses a package boundary (round 18 fix gate, admin-r18-18; the same class as
// admin-r18-13). The fields Path, Args and Env of an exec.Cmd are assignable from any file, including one that
// never imports os/exec, so a helper that returns the Cmd lets a test build a checked `docker ps` and then assign
// c.Args to a floating `docker run --privileged alpine:3.20`, and no lint of the call sites can see it (execProblems
// returns before any type check for a file that imports neither os/exec nor os). The wrapper types toolcmd.Cmd and
// deploy.Cmd keep the exec.Cmd in an unexported field and expose only the ways to run it. This lint is the
// construction's test: it fails for any non-test file of the module that lets an os/exec.Cmd out of its package
// through an exported function or method (a parameter or a result), an exported type that is one, any struct that
// embeds one, an exported field of one, or an exported variable of one, whatever the import is called. It does not judge a Cmd
// that stays inside its package (an unexported field, an unexported function), which is how the wrappers hold it.
func execCmdLeakProblems(path, src string) []string {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, 0)
	if err != nil {
		return []string{path + ": " + err.Error()}
	}
	name := ""
	for _, im := range f.Imports {
		if p, _ := strconv.Unquote(im.Path.Value); p == "os/exec" {
			name = "exec"
			if im.Name != nil {
				name = im.Name.Name
			}
		}
	}
	if name == "" || name == "_" {
		return nil
	}
	if name == "." {
		return []string{path + ": a dot import of os/exec hides every use of exec.Cmd"}
	}
	mentions := func(n ast.Node) bool {
		hit := false
		ast.Inspect(n, func(x ast.Node) bool {
			if sel, ok := x.(*ast.SelectorExpr); ok && selIs(sel, name, "Cmd") {
				hit = true
			}
			return !hit
		})
		return hit
	}
	line := func(n ast.Node) string { return path + ":" + strconv.Itoa(fset.Position(n.Pos()).Line) + ": " }
	var out []string
	const why = " lets an os/exec.Cmd out of its package, whose Path, Args and Env any file can then assign; return a wrapper that keeps it in an unexported field (toolcmd.Cmd, deploy.Cmd)"
	for _, d := range f.Decls {
		switch d := d.(type) {
		case *ast.FuncDecl:
			if d.Name.IsExported() && mentions(d.Type) {
				out = append(out, line(d)+"the exported "+d.Name.Name+why)
			}
		case *ast.GenDecl:
			for _, sp := range d.Specs {
				switch sp := sp.(type) {
				case *ast.TypeSpec:
					if st, ok := sp.Type.(*ast.StructType); ok {
						// An embedded Cmd promotes its exported fields into the struct, so it leaks through an
						// unexported struct as well, as soon as any exported function returns that struct.
						for _, fld := range st.Fields.List {
							if (len(fld.Names) == 0 || sp.Name.IsExported() && fld.Names[0].IsExported()) && mentions(fld.Type) {
								out = append(out, line(fld)+"an exported or embedded field of "+sp.Name.Name+why)
							}
						}
					} else if sp.Name.IsExported() && mentions(sp.Type) {
						out = append(out, line(sp)+"the exported type "+sp.Name.Name+why)
					}
				case *ast.ValueSpec:
					for _, id := range sp.Names {
						if id.IsExported() && (sp.Type != nil && mentions(sp.Type) || len(sp.Values) > 0 && func() bool {
							for _, v := range sp.Values {
								if c, ok := v.(*ast.CallExpr); ok {
									if sel, ok := c.Fun.(*ast.SelectorExpr); ok && (selIs(sel, name, "Command") || selIs(sel, name, "CommandContext")) {
										return true
									}
								}
							}
							return false
						}()) {
							out = append(out, line(sp)+"the exported variable "+id.Name+why)
						}
					}
				}
			}
		}
	}
	return out
}

func TestNoBareExecCmdLeavesItsPackage(t *testing.T) {
	s := realImageSources(t)
	var out []string
	for p, src := range s.goFiles {
		if strings.HasSuffix(p, "_test.go") {
			continue
		}
		out = append(out, execCmdLeakProblems(p, src)...)
	}
	sort.Strings(out)
	if len(out) != 0 {
		t.Fatalf("%s", strings.Join(out, "\n"))
	}
}

func TestExecCmdLeakLintCanFail(t *testing.T) {
	const imp = "package x\nimport \"os/exec\"\n"
	cases := []struct {
		name, src string
		bad       bool
	}{
		{"an exported function returning *exec.Cmd", imp + "func Docker() *exec.Cmd { return nil }\n", true},
		{"an exported function returning an exec.Cmd value", imp + "func Docker() exec.Cmd { return exec.Cmd{} }\n", true},
		{"an exported function taking one", imp + "func Run(c *exec.Cmd) {}\n", true},
		{"an exported method returning one", imp + "type T struct{}\nfunc (T) Cmd() *exec.Cmd { return nil }\n", true},
		{"a function returning a slice of them", imp + "func Many() []*exec.Cmd { return nil }\n", true},
		{"a function returning a func that returns one", imp + "func Maker() func() *exec.Cmd { return nil }\n", true},
		{"an alias", imp + "type Cmd = exec.Cmd\n", true},
		{"a defined type over it", imp + "type Cmd exec.Cmd\n", true},
		{"an embedded field", imp + "type W struct{ *exec.Cmd }\n", true},
		{"an exported field", imp + "type W struct{ C *exec.Cmd }\n", true},
		{"an exported variable by type", imp + "var C *exec.Cmd\n", true},
		{"an exported variable by value", imp + "var C = exec.Command(\"x\")\n", true},
		{"an interface that returns one", imp + "type I interface{ Cmd() *exec.Cmd }\n", true},
		{"an aliased import", "package x\nimport ex \"os/exec\"\nfunc Docker() *ex.Cmd { return nil }\n", true},
		{"a dot import", "package x\nimport . \"os/exec\"\nfunc Docker() *Cmd { return nil }\n", true},
		{"the wrapper: an unexported field and an exported constructor of the wrapper", imp + "type Cmd struct{ c *exec.Cmd }\nfunc Docker() *Cmd { return &Cmd{exec.Command(\"docker\")} }\nfunc (d *Cmd) Run() error { return d.c.Run() }\n", false},
		{"an unexported function returning one", imp + "func docker() *exec.Cmd { return nil }\n", false},
		{"an unexported type embedding one", imp + "type w struct{ *exec.Cmd }\n", true},
		{"an unexported type with an unexported field of one", imp + "type w struct{ c *exec.Cmd }\n", false},
		{"an unexported variable", imp + "var c *exec.Cmd\n", false},
		{"a file that does not import it", "package x\nfunc F() {}\n", false},
	}
	for _, c := range cases {
		if got := execCmdLeakProblems("x/a.go", c.src); (len(got) > 0) != c.bad {
			t.Errorf("%s: problems %v, want a problem: %v", c.name, got, c.bad)
		}
	}
}
