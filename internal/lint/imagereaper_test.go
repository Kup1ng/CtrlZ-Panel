package lint_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/deploy"
	"github.com/testcontainers/testcontainers-go"
)

// Rule images-are-pinned, the reaper (round 16, admin-r16-19; closed in round 17, admin-r17-2 and -8).
//
// testcontainers starts `testcontainers/ryuk` beside every container test and it holds the Docker socket. Its
// reference is a constant of the library, named by tag alone, so the digest cannot be set in the library's
// request. Round 16 compared the TAG TEXT and left the rest as the owner's decision with no number: a registry
// or a mirror that moved the tag ran other bytes with the socket mounted, and the test stayed green because the
// text had not changed. The bytes are pinned from outside the library instead: deploy.PinReaper makes the local
// image named by that tag the one of the reviewed digest (pulls it by digest and moves the tag, or refuses),
// and Docker pulls a tag only when it is missing, so the library finds the reviewed bytes and fetches nothing.
//
// What this file holds, in two parts:
//
//  1. the tag the library asks for is the tag whose digest was reviewed (deploy.ReaperTag): a library bump that
//     changes it fails here, which is when somebody reads the new image and its digest;
//  2. every function that starts a container through testcontainers (a call of Run or GenericContainer of the
//     root package or a module) has, as one of its own top-level statements BEFORE the first such call, the
//     guard that makes the error of deploy.PinReaper stop it:
//
//     if err := deploy.PinReaper(ctx); err != nil { ...; return }
//
//     (the body ends in a return or a panic, the condition is err != nil and nothing else, and there is no
//     else). Round 17 asked only whether the file contained a call anywhere, so a call whose error was dropped,
//     one made after the start, or one in dead code was accepted, although PinReaper's whole value is its error
//     (it fails closed when the reviewed image cannot be had; round 17 fix gate, admin-r17-18). A start outside
//     any function (a package variable) fails, since no statement can come before it.
//
// What it does not judge: the reaper's bytes themselves (the digest is the review), a start through a package
// that is neither in the module nor a testcontainers module, and a call to a helper that starts the container
// for the caller (the helper is itself a function with a start in it and is judged on its own).

// reaperGuard reports whether s is the guard of part 2 for the deploy package named deployName.
func reaperGuard(s ast.Stmt, deployName string) bool {
	ifs, ok := s.(*ast.IfStmt)
	if !ok || ifs.Else != nil || ifs.Init == nil || len(ifs.Body.List) == 0 {
		return false
	}
	as, ok := ifs.Init.(*ast.AssignStmt)
	if !ok || len(as.Lhs) != 1 || len(as.Rhs) != 1 || (as.Tok != token.DEFINE && as.Tok != token.ASSIGN) {
		return false
	}
	errID, ok := as.Lhs[0].(*ast.Ident)
	if !ok {
		return false
	}
	call, ok := as.Rhs[0].(*ast.CallExpr)
	if !ok || deployName == "" {
		return false
	}
	if sel, ok := call.Fun.(*ast.SelectorExpr); !ok || !selIs(sel, deployName, "PinReaper") {
		return false
	}
	cond, ok := ifs.Cond.(*ast.BinaryExpr)
	if !ok || cond.Op != token.NEQ {
		return false
	}
	x, okx := cond.X.(*ast.Ident)
	y, oky := cond.Y.(*ast.Ident)
	if !okx || !oky || x.Name != errID.Name || y.Name != "nil" {
		return false
	}
	switch last := ifs.Body.List[len(ifs.Body.List)-1].(type) {
	case *ast.ReturnStmt:
		return true
	case *ast.ExprStmt:
		c, ok := last.X.(*ast.CallExpr)
		id, isID := ast.Expr(nil), false
		if ok {
			id, isID = c.Fun.(*ast.Ident)
		}
		return isID && id.(*ast.Ident).Name == "panic"
	}
	return false
}

// tcInertMembers are the members of the testcontainers packages the harnesses use that build a request or a
// wait or exec option and start nothing, by import path. The packages wait and exec are inert as a whole. A
// member that is not here needs the guard before it: the list fails closed, so it is the one place a person
// reads when a harness starts to use something new.
var tcInertMembers = map[string]map[string]bool{
	"github.com/testcontainers/testcontainers-go": {
		"Container": true, "ContainerFile": true, "ReaperDefaultImage": true, "ContainerRequest": true, "GenericContainerRequest": true,
		"WithCmdArgs": true, "WithEnv": true, "WithHostConfigModifier": true, "WithWaitStrategy": true,
	},
	"github.com/testcontainers/testcontainers-go/modules/postgres": {
		"PostgresContainer": true, "WithDatabase": true, "WithPassword": true, "WithUsername": true,
	},
}

func tcInert(pkg, member string) bool {
	if strings.HasSuffix(pkg, "/wait") || strings.HasSuffix(pkg, "/exec") {
		return true
	}
	return tcInertMembers[pkg][member]
}

// reaperProblems judges one Go file (part 2).
func reaperProblems(path, src string) []string {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, 0)
	if err != nil {
		return []string{path + ": " + err.Error()}
	}
	tcNames := map[string]string{} // local name -> import path of every testcontainers package
	deployName := ""
	var out []string
	line := func(p token.Pos) string { return path + ":" + strconv.Itoa(fset.Position(p).Line) + ": " }
	for _, im := range f.Imports {
		p, _ := strconv.Unquote(im.Path.Value)
		name := ""
		if im.Name != nil {
			name = im.Name.Name
		}
		switch {
		case strings.HasPrefix(p, "github.com/testcontainers/"):
			switch name {
			case "":
				// The package's own name, which its path does not spell for the root package.
				name = p[strings.LastIndex(p, "/")+1:]
				if p == "github.com/testcontainers/testcontainers-go" {
					name = "testcontainers"
				}
			case ".", "_":
				out = append(out, line(im.Pos())+"a testcontainers package imported as "+name+": the names it brings in cannot be judged")
				continue
			}
			tcNames[name] = p
		case p == "github.com/Kup1ng/CtrlZ-Panel/deploy":
			deployName = "deploy"
			if name != "" {
				deployName = name
			}
		}
	}
	if len(tcNames) == 0 {
		return out
	}
	// startsIn returns the position of the first use below n of anything of a testcontainers package that is
	// not on the inert list: a call, a function value, a method expression, whatever the member is called. A
	// start is every use the list does not clear, so a member the library adds, a package that starts a network
	// or a group of containers (network.New, GenericNetwork, ParallelContainers) and a function kept in a
	// variable (start := testcontainers.GenericContainer) all need the guard, with no name listed as a starter
	// (round 18, admin-r18-12).
	startsIn := func(n ast.Node) token.Pos {
		first := token.NoPos
		ast.Inspect(n, func(m ast.Node) bool {
			if sel, ok := m.(*ast.SelectorExpr); ok {
				if id, ok := sel.X.(*ast.Ident); ok {
					if pkg, isTC := tcNames[id.Name]; isTC && !tcInert(pkg, sel.Sel.Name) && (first == token.NoPos || sel.Pos() < first) {
						first = sel.Pos()
					}
				}
			}
			return true
		})
		return first
	}
	for _, d := range f.Decls {
		switch x := d.(type) {
		case *ast.FuncDecl:
			if x.Body == nil {
				continue
			}
			first := startsIn(x.Body)
			if first == token.NoPos {
				continue
			}
			guarded := false
			for _, s := range x.Body.List {
				if s.End() <= first && reaperGuard(s, deployName) {
					guarded = true
				}
			}
			if !guarded {
				out = append(out, line(first)+x.Name.Name+" starts a container and has no `if err := deploy.PinReaper(...); err != nil { return }` before it among its own statements: the reaper it starts would be whatever the tag names that day")
			}
		case *ast.GenDecl:
			if first := startsIn(x); first != token.NoPos {
				out = append(out, line(first)+"a container is started outside any function, where no PinReaper can come before it")
			}
		}
	}
	return out
}

// TestTheReaperImageIsTheReviewedOne: see the file comment, part 1.
func TestTheReaperImageIsTheReviewedOne(t *testing.T) {
	if testcontainers.ReaperDefaultImage != deploy.ReaperTag {
		t.Fatalf("testcontainers now starts %s beside every container test, which holds the Docker socket; read the new image, take its index digest (docker buildx imagetools inspect), and change deploy.ReaperTag and deploy.ReaperDigest together", testcontainers.ReaperDefaultImage)
	}
}

func TestEveryTestcontainersStarterPinsTheReaper(t *testing.T) {
	s := realImageSources(t)
	paths := make([]string, 0, len(s.goFiles))
	for p := range s.goFiles {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	var out []string
	starters := 0
	for _, p := range paths {
		got := reaperProblems(p, s.goFiles[p])
		out = append(out, got...)
		if strings.Contains(s.goFiles[p], "testcontainers-go\"") || strings.Contains(s.goFiles[p], "testcontainers-go/modules/") {
			starters++
		}
	}
	if starters < 3 {
		t.Fatalf("only %d files import testcontainers: the lint no longer sees the harnesses", starters)
	}
	if len(out) != 0 {
		t.Fatalf("%s", strings.Join(out, "\n"))
	}
}

func TestReaperPinLintCanFail(t *testing.T) {
	const root = "github.com/testcontainers/testcontainers-go"
	const hdr = "package x\nimport (\n\"context\"\n\"" + root + "\"\n\"github.com/Kup1ng/CtrlZ-Panel/deploy\"\n)\n"
	const start = "testcontainers.GenericContainer(c, testcontainers.GenericContainerRequest{})"
	const guard = "if err := deploy.PinReaper(c); err != nil { return }\n"
	cases := []struct {
		name, src string
		bad       bool
	}{
		{"a starter that pins and stops", hdr + "func f(c context.Context) {\n" + guard + start + "\n}\n", false},
		{"a starter that pins and panics", hdr + "func f(c context.Context) {\nif err := deploy.PinReaper(c); err != nil { panic(err) }\n" + start + "\n}\n", false},
		{"a start inside a closure after a guard of the function", hdr + "func f(c context.Context) {\n" + guard + "go func() { " + start + " }()\n}\n", false},
		{"a starter that does not", "package x\nimport (\n\"context\"\n\"" + root + "\"\n)\nfunc f(c context.Context) { " + start + " }\n", true},
		{"a module starter that does not", "package x\nimport \"" + root + "/modules/redis\"\nfunc f() { redis.Run(nil, \"x\") }\n", true},
		{"an aliased starter that does not", "package x\nimport tc \"" + root + "\"\nfunc f() { tc.GenericContainer(nil, tc.GenericContainerRequest{}) }\n", true},
		{"a call whose error is dropped", hdr + "func f(c context.Context) {\ndeploy.PinReaper(c)\n" + start + "\n}\n", true},
		{"a call whose error is thrown away", hdr + "func f(c context.Context) {\n_ = deploy.PinReaper(c)\n" + start + "\n}\n", true},
		{"a call made after the start", hdr + "func f(c context.Context) {\n" + start + "\n" + guard + "}\n", true},
		{"a guard in dead code", hdr + "func f(c context.Context) {\nif false {\n" + guard + "}\n" + start + "\n}\n", true},
		{"a guard that cannot fire", hdr + "func f(c context.Context) {\nif err := deploy.PinReaper(c); err != nil && false { return }\n" + start + "\n}\n", true},
		{"a guard that stops when the pin succeeded", hdr + "func f(c context.Context) {\nif err := deploy.PinReaper(c); err == nil { return }\n" + start + "\n}\n", true},
		{"a guard that does not stop", hdr + "func f(c context.Context) {\nif err := deploy.PinReaper(c); err != nil { _ = err }\n" + start + "\n}\n", true},
		{"a guard on another error", hdr + "func f(c context.Context, e error) {\nif err := deploy.PinReaper(c); e != nil { return }\n" + start + "\n}\n", true},
		{"a guard with an else", hdr + "func f(c context.Context) {\nif err := deploy.PinReaper(c); err != nil { return } else { _ = err }\n" + start + "\n}\n", true},
		{"a closure that pins and is never called", hdr + "func f(c context.Context) {\nvar _ = func() { " + guard + " }\n" + start + "\n}\n", true},
		{"another function pins", hdr + "func g(c context.Context) {\n" + guard + "}\nfunc f(c context.Context) {\n" + start + "\n}\n", true},
		{"a start in a package variable", hdr + "var r, _ = " + strings.ReplaceAll(start, "(c,", "(context.Background(),") + "\n", true},
		{"a starter that names the function and never calls it", "package x\nimport (\n\"" + root + "\"\n\"github.com/Kup1ng/CtrlZ-Panel/deploy\"\n)\nvar _ = deploy.PinReaper\nfunc f() { testcontainers.GenericContainer(nil, testcontainers.GenericContainerRequest{}) }\n", true},
		{"an aliased deploy that pins", "package x\nimport (\n\"" + root + "\"\nd \"github.com/Kup1ng/CtrlZ-Panel/deploy\"\n)\nfunc f() { if err := d.PinReaper(nil); err != nil { return }\ntestcontainers.GenericContainer(nil, testcontainers.GenericContainerRequest{}) }\n", false},
		{"a file that only names a type", "package x\nimport \"" + root + "\"\nvar _ testcontainers.Container\nfunc f(c testcontainers.Container) {}\n", false},
		{"a file that only waits", "package x\nimport \"" + root + "/wait\"\nvar _ = wait.ForLog\n", false},
		{"a file with no testcontainers", "package x\nfunc f() {}\n", false},
		{"a network started by the network package", "package x\nimport \"" + root + "/network\"\nfunc f() { network.New(nil) }\n", true},
		{"a network started by the root package", hdr + "func f(c context.Context) {\ntestcontainers.GenericNetwork(c, testcontainers.GenericNetworkRequest{})\n}\n", true},
		{"a group of containers", hdr + "func f(c context.Context) {\ntestcontainers.ParallelContainers(c, nil)\n}\n", true},
		{"a starter kept in a variable", hdr + "func f(c context.Context) {\nrun := testcontainers.GenericContainer\nrun(c, testcontainers.GenericContainerRequest{})\n}\n", true},
		{"a starter passed as an argument", hdr + "func g(f any) {}\nfunc f(c context.Context) {\ng(testcontainers.GenericContainer)\n}\n", true},
		{"a member of a module nobody listed", "package x\nimport \"" + root + "/modules/redis\"\nfunc f() { redis.RunContainer(nil) }\n", true},
		{"a module option the list clears", "package x\nimport \"" + root + "/modules/postgres\"\nvar _ = postgres.WithDatabase(\"x\")\n", false},
		{"a dot import of the library", "package x\nimport . \"" + root + "\"\nfunc f() {}\n", true},
		{"a blank import of a module", "package x\nimport _ \"" + root + "/modules/postgres\"\n", true},
		{"a second import of the library under another name", "package x\nimport (\n\"" + root + "\"\ntc \"" + root + "\"\n)\nfunc f() { tc.GenericContainer(nil, tc.GenericContainerRequest{}) }\nvar _ testcontainers.Container\n", true},
	}
	for _, c := range cases {
		if got := reaperProblems("x/"+strings.ReplaceAll(c.name, " ", "_")+".go", c.src); (len(got) > 0) != c.bad {
			t.Errorf("%s: problems %v, want a problem: %v", c.name, got, c.bad)
		}
	}
}

// containerHarnessFiles are the only Go files of the module that may import a testcontainers package, with
// the reason. The harnesses are the one place a container is started (testpg for Postgres, testvalkey for
// Valkey), so every start goes through the code that calls deploy.PinReaper first; a test package that wants
// a container asks a harness for it. imagereaper_test.go reads one constant of the library and starts nothing.
// An importer anywhere else is a diff that has to add itself here and say why (round 18, admin-r18-12).
var containerHarnessFiles = map[string]string{
	"internal/testpg/container.go":      "the Postgres harness",
	"internal/testpg/testpg.go":         "the Postgres harness",
	"internal/testpg/wiring.go":         "the Postgres harness",
	"internal/testvalkey/testvalkey.go": "the Valkey harness",
	"internal/lint/imagereaper_test.go": "reads testcontainers.ReaperDefaultImage; starts nothing",
}

// containerImporters returns the files of src that import a testcontainers package.
func containerImporters(src map[string]string) []string {
	var out []string
	for p, text := range src {
		f, err := parser.ParseFile(token.NewFileSet(), p, text, parser.ImportsOnly)
		if err != nil || f == nil {
			out = append(out, p) // unreadable: judged as an importer, so it fails
			continue
		}
		for _, im := range f.Imports {
			if path, _ := strconv.Unquote(im.Path.Value); strings.HasPrefix(path, "github.com/testcontainers/") {
				out = append(out, p)
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

func TestOnlyTheContainerHarnessesImportTestcontainers(t *testing.T) {
	s := realImageSources(t)
	got := map[string]bool{}
	for _, p := range containerImporters(s.goFiles) {
		got[p] = true
		if _, ok := containerHarnessFiles[p]; !ok {
			t.Errorf("%s imports a testcontainers package and is not a harness: start containers through internal/testpg or internal/testvalkey, which pin the reaper (or add the file to containerHarnessFiles with its reason)", p)
		}
	}
	for p := range containerHarnessFiles {
		if !got[p] {
			t.Errorf("containerHarnessFiles lists %s, which does not import testcontainers any more: remove the entry", p)
		}
	}
}

func TestContainerImporterLintCanFail(t *testing.T) {
	src := map[string]string{
		"a/ok.go":      "package a\nfunc f() {}\n",
		"a/root.go":    "package a\nimport \"github.com/testcontainers/testcontainers-go\"\nvar _ testcontainers.Container\n",
		"a/aliased.go": "package a\nimport tc \"github.com/testcontainers/testcontainers-go/network\"\nvar _ = tc.New\n",
		"a/blank.go":   "package a\nimport _ \"github.com/testcontainers/testcontainers-go/modules/redis\"\n",
		"a/broken.go":  "package a\nimport (\n",
		"a/other.go":   "package a\nimport \"github.com/docker/docker/client\"\nvar _ client.Client\n",
	}
	got := strings.Join(containerImporters(src), ",")
	if got != "a/aliased.go,a/blank.go,a/broken.go,a/root.go" {
		t.Fatalf("importers = %s", got)
	}
}
