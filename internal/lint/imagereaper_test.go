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

// reaperProblems judges one Go file (part 2).
func reaperProblems(path, src string) []string {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, 0)
	if err != nil {
		return []string{path + ": " + err.Error()}
	}
	tcNames := map[string]bool{}
	deployName := ""
	for _, im := range f.Imports {
		p, _ := strconv.Unquote(im.Path.Value)
		name := ""
		if im.Name != nil {
			name = im.Name.Name
		}
		switch {
		case p == "github.com/testcontainers/testcontainers-go":
			if name == "" {
				name = "testcontainers" // the package's own name, which its path does not spell
			}
			tcNames[name] = true
		case strings.HasPrefix(p, "github.com/testcontainers/testcontainers-go/modules/"):
			if name == "" {
				name = p[strings.LastIndex(p, "/")+1:]
			}
			tcNames[name] = true
		case p == "github.com/Kup1ng/CtrlZ-Panel/deploy":
			deployName = "deploy"
			if name != "" {
				deployName = name
			}
		}
	}
	if len(tcNames) == 0 {
		return nil
	}
	// startsIn returns the position of the first start of a container below n, or token.NoPos.
	startsIn := func(n ast.Node) token.Pos {
		first := token.NoPos
		ast.Inspect(n, func(m ast.Node) bool {
			if c, ok := m.(*ast.CallExpr); ok {
				if sel, ok := c.Fun.(*ast.SelectorExpr); ok && testcontainersCalls[sel.Sel.Name] {
					if id, ok := sel.X.(*ast.Ident); ok && tcNames[id.Name] && (first == token.NoPos || c.Pos() < first) {
						first = c.Pos()
					}
				}
			}
			return true
		})
		return first
	}
	var out []string
	line := func(p token.Pos) string { return path + ":" + strconv.Itoa(fset.Position(p).Line) + ": " }
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
	}
	for _, c := range cases {
		if got := reaperProblems("x/"+strings.ReplaceAll(c.name, " ", "_")+".go", c.src); (len(got) > 0) != c.bad {
			t.Errorf("%s: problems %v, want a problem: %v", c.name, got, c.bad)
		}
	}
}
