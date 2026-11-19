package lint_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"sort"
	"strings"
	"testing"
)

// The admin-cli-secret-output rule (P1 auth review, round 5, topic 12; spec 10.1, 17.2, 18.4).
//
// ctrlz-admin never writes a secret to stdout or stderr. Four rounds tried to tell
// from the process (character device, PID 1, PPID 0) whether its stdout was safe from
// `docker logs`, and each round found a launch form for which the guess was wrong
// (`compose run`, `docker run -t`, `--init`), and the positive branch was never run.
// The guess is gone: a one-time password goes only to the --out-file writer, and
// stdout carries only that file's path.
//
// What this file enforces, over the non-test files of internal/admincli and cmd:
//
//  1. Taint by type. A value of a secret type (secret.String, secret.Bytes, which is
//     what password.NewOneTime returns) is tainted, and so is the result of its
//     Reveal, a conversion of a tainted value, a standard-library call on one, and a
//     local variable assigned from one. A tainted value may not be an argument to a
//     sink: any function of fmt, log, log/slog, io, bufio, os, errors, flag, syscall
//     or net; any method called Write*, Print*, Fprint*, Log, Debug, Info, Warn,
//     Error*, Fatal* or Panic*; the builtins print, println and panic; or a function
//     of these packages with a parameter that is not a secret type (a secret may pass
//     from function to function only as a secret, so the callee is judged by the same
//     rule). Plain text made by Reveal may not be returned, stored in a field, an
//     element or a channel, or sent to a local function: it stays in a local variable
//     until it is handed to a call outside the sinks (a Seal, a hash).
//  2. The two writers. writeFile functions in allowedWriters are the only places that
//     may write a tainted value; each one writes to a file it was given or created,
//     and may not mention Stdout or Stderr.
//  3. No terminal detection. The identifiers and imports that told a terminal from a
//     log (ModeCharDevice, IsTerminal, Getpid, Getppid, Pid, Ppid, isatty, x/term) do
//     not appear, so a guess cannot grow back.
//
// The behaviour half is internal/admincli TestSecretNeverReachesStdoutOrStderr.

const secretPkg = module + "/internal/secret"

// adminOutputDirs are the code that runs as ctrlz-admin.
func adminOutputScope(p string) bool {
	return strings.HasPrefix(p, "internal/admincli/") || strings.HasPrefix(p, "cmd/")
}

// allowedWriters name the functions that may write a tainted value, each with the
// reason. A third entry needs a reviewer.
var allowedWriters = map[string]string{
	"internal/admincli/output.go:write":    "the --out-file writer: the 0600 file created with O_EXCL",
	"internal/admincli/derive.go:writeNew": "keys derive writes a key file next to the root key, never to stdout",
}

// sinkPkgs are the standard-library packages whose functions print, log, wrap into
// an error text or write to a descriptor.
var sinkPkgs = map[string]bool{
	"fmt": true, "log": true, "log/slog": true, "io": true, "bufio": true, "os": true,
	"errors": true, "flag": true, "syscall": true, "net": true, "net/http": true,
	"text/template": true, "html/template": true,
}

// printerPkgs are the packages every function of which writes or formats; in the
// others (os, flag, net) only the Write-like names are sinks, so os.Getenv may be
// stored in the Env that tests replace.
var printerPkgs = map[string]bool{"fmt": true, "log": true, "log/slog": true, "io": true, "bufio": true, "errors": true}

func sinkMethod(name string) bool {
	for _, p := range []string{"Write", "Print", "Fprint", "Log", "Debug", "Info", "Warn", "Error", "Fatal", "Panic"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// bannedIdents are the pieces of the old guess. A struct field, a function or a
// selector with one of these names is a terminal or process-id test coming back.
var bannedIdents = map[string]bool{
	"IsTerminal": true, "isTerminal": true, "ModeCharDevice": true, "isCharDevice": true,
	"Getpid": true, "Getppid": true, "Pid": true, "Ppid": true, "Isatty": true,
	"IsCygwinTerminal": true, "errNotTerminal": true,
}

func isSecretType(t types.Type) bool {
	for {
		p, ok := t.(*types.Pointer)
		if !ok {
			break
		}
		t = p.Elem()
	}
	if s, ok := t.(*types.Slice); ok {
		t = s.Elem()
	}
	n, ok := t.(*types.Named)
	if !ok || n.Obj().Pkg() == nil {
		return false
	}
	return n.Obj().Pkg().Path() == secretPkg && (n.Obj().Name() == "String" || n.Obj().Name() == "Bytes")
}

// adminOutputFinder judges one function body.
type adminOutputFinder struct {
	fset     *token.FileSet
	info     *types.Info
	tainted  map[types.Object]bool
	problems []string
	allowed  bool
}

func (a *adminOutputFinder) add(n ast.Node, format string, args ...any) {
	a.problems = append(a.problems, fmt.Sprintf("%s: %s", a.fset.Position(n.Pos()), fmt.Sprintf(format, args...)))
}

func (a *adminOutputFinder) pkgOf(e ast.Expr) string {
	sel, ok := unparen(e).(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	id, ok := sel.X.(*ast.Ident)
	if !ok {
		return ""
	}
	if pn, ok := a.info.Uses[id].(*types.PkgName); ok {
		return pn.Imported().Path()
	}
	return ""
}

func (a *adminOutputFinder) isSecretExpr(e ast.Expr) bool {
	tv, ok := a.info.Types[e]
	return ok && tv.Type != nil && isSecretType(tv.Type)
}

// isTainted says whether e carries a secret or the plain text of one.
func (a *adminOutputFinder) isTainted(e ast.Expr) bool {
	e = unparen(e)
	if e == nil {
		return false
	}
	if a.isSecretExpr(e) {
		return true
	}
	switch x := e.(type) {
	case *ast.Ident:
		return a.tainted[a.info.Uses[x]] || a.tainted[a.info.Defs[x]]
	case *ast.BinaryExpr:
		return a.isTainted(x.X) || a.isTainted(x.Y)
	case *ast.UnaryExpr:
		return a.isTainted(x.X)
	case *ast.StarExpr:
		return a.isTainted(x.X)
	case *ast.SliceExpr:
		return a.isTainted(x.X)
	case *ast.IndexExpr:
		return a.isTainted(x.X)
	case *ast.SelectorExpr:
		return a.isTainted(x.X)
	case *ast.KeyValueExpr:
		return a.isTainted(x.Value)
	case *ast.CompositeLit:
		for _, el := range x.Elts {
			if a.isTainted(el) {
				return true
			}
		}
	case *ast.CallExpr:
		if sel, ok := unparen(x.Fun).(*ast.SelectorExpr); ok && sel.Sel.Name == "Reveal" && a.isSecretExpr(sel.X) {
			return true
		}
		// A conversion or a builtin such as append carries the taint through.
		if tv, ok := a.info.Types[x.Fun]; ok && tv.IsType() {
			return len(x.Args) == 1 && a.isTainted(x.Args[0])
		}
		if id, ok := unparen(x.Fun).(*ast.Ident); ok {
			if _, isBuiltin := a.info.Uses[id].(*types.Builtin); isBuiltin {
				return a.anyTainted(x.Args)
			}
		}
		// A standard-library call on a tainted value (strings.TrimSpace) returns text
		// that is still the secret. Calls into the module and its dependencies (a
		// Seal, a hash) return something else.
		if p := a.pkgOf(x.Fun); p != "" && !strings.Contains(strings.SplitN(p, "/", 2)[0], ".") {
			return a.anyTainted(x.Args)
		}
		if sel, ok := unparen(x.Fun).(*ast.SelectorExpr); ok && a.pkgOf(x.Fun) == "" && a.isTainted(sel.X) {
			return true
		}
	}
	return false
}

func (a *adminOutputFinder) anyTainted(es []ast.Expr) bool {
	for _, e := range es {
		if a.isTainted(e) {
			return true
		}
	}
	return false
}

func (a *adminOutputFinder) mark(lhs ast.Expr) bool {
	id, ok := unparen(lhs).(*ast.Ident)
	if !ok || id.Name == "_" {
		return false
	}
	obj := a.info.Defs[id]
	if obj == nil {
		obj = a.info.Uses[id]
	}
	if obj == nil || a.tainted[obj] {
		return false
	}
	a.tainted[obj] = true
	return true
}

// propagate marks every local variable that is assigned a tainted value. It runs
// to a fixed point, since an assignment may come before the one that taints its
// right-hand side.
func (a *adminOutputFinder) propagate(body ast.Node) {
	for changed := true; changed; {
		changed = false
		ast.Inspect(body, func(n ast.Node) bool {
			switch s := n.(type) {
			case *ast.AssignStmt:
				if len(s.Lhs) == len(s.Rhs) {
					for i := range s.Lhs {
						if a.isTainted(s.Rhs[i]) && a.mark(s.Lhs[i]) {
							changed = true
						}
					}
				} else if len(s.Rhs) == 1 && a.isTainted(s.Rhs[0]) {
					for _, l := range s.Lhs {
						if a.mark(l) {
							changed = true
						}
					}
				}
			case *ast.ValueSpec:
				for i, v := range s.Values {
					if a.isTainted(v) && len(s.Names) == len(s.Values) && a.mark(s.Names[i]) {
						changed = true
					}
				}
			case *ast.RangeStmt:
				if a.isTainted(s.X) {
					for _, e := range []ast.Expr{s.Key, s.Value} {
						if e != nil && a.mark(e) {
							changed = true
						}
					}
				}
			}
			return true
		})
	}
}

// plainTainted is tainted text that is not typed as a secret any more.
func (a *adminOutputFinder) plainTainted(e ast.Expr) bool {
	return a.isTainted(e) && !a.isSecretExpr(e)
}

func (a *adminOutputFinder) check(body ast.Node) {
	a.propagate(body)
	callFuns := map[ast.Node]bool{}
	ast.Inspect(body, func(n ast.Node) bool {
		if c, ok := n.(*ast.CallExpr); ok {
			callFuns[unparen(c.Fun)] = true
		}
		return true
	})
	ast.Inspect(body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.SelectorExpr:
			if a.allowed && (x.Sel.Name == "Stdout" || x.Sel.Name == "Stderr") {
				a.add(x, "a secret writer mentions %s", x.Sel.Name)
			}
			// A sink taken as a value could be called later with a secret and the
			// call would not name it.
			if !callFuns[x] {
				if p := a.pkgOf(x); sinkPkgs[p] && a.isFunc(x) && (sinkMethod(x.Sel.Name) || printerPkgs[p]) {
					a.add(x, "%s.%s is taken as a value; call it directly so its arguments can be judged", p, x.Sel.Name)
				}
			}
		case *ast.ReturnStmt:
			if a.allowed {
				return true
			}
			for _, r := range x.Results {
				if a.plainTainted(r) {
					a.add(r, "the plain text of a secret is returned; return the secret type")
				}
			}
		case *ast.SendStmt:
			if !a.allowed && a.plainTainted(x.Value) {
				a.add(x, "the plain text of a secret is sent on a channel")
			}
		case *ast.AssignStmt:
			if a.allowed || len(x.Lhs) != len(x.Rhs) {
				return true
			}
			for i, l := range x.Lhs {
				if _, local := unparen(l).(*ast.Ident); !local && a.plainTainted(x.Rhs[i]) {
					a.add(l, "the plain text of a secret is stored outside a local variable")
				}
			}
		case *ast.CompositeLit:
			if a.allowed {
				return true
			}
			for _, el := range x.Elts {
				v := el
				if kv, ok := el.(*ast.KeyValueExpr); ok {
					v = kv.Value
				}
				if a.plainTainted(v) {
					if tv, ok := a.info.Types[x]; ok && tv.Type != nil {
						if _, isSlice := tv.Type.Underlying().(*types.Slice); isSlice {
							continue // a list handed straight to a call is judged at the call
						}
					}
					a.add(el, "the plain text of a secret is stored in a composite value")
				}
			}
		case *ast.CallExpr:
			a.call(x)
		}
		return true
	})
}

// isFunc reports a selector that names a function or method (not a variable, constant or type).
func (a *adminOutputFinder) isFunc(s *ast.SelectorExpr) bool {
	_, ok := a.info.Uses[s.Sel].(*types.Func)
	return ok
}

func (a *adminOutputFinder) call(c *ast.CallExpr) {
	if a.allowed {
		return
	}
	if tv, ok := a.info.Types[c.Fun]; ok && tv.IsType() {
		return
	}
	if !a.anyTainted(c.Args) && !a.receiverTainted(c) {
		return
	}
	fun := unparen(c.Fun)
	if id, ok := fun.(*ast.Ident); ok {
		switch a.info.Uses[id].(type) {
		case *types.Builtin:
			if id.Name == "print" || id.Name == "println" || id.Name == "panic" {
				a.add(c, "a secret reaches the builtin %s", id.Name)
			}
			return
		case *types.Func, *types.Var:
			a.localCall(c)
			return
		}
		return
	}
	sel, ok := fun.(*ast.SelectorExpr)
	if !ok {
		a.localCall(c)
		return
	}
	if p := a.pkgOf(sel); p != "" {
		if sinkPkgs[p] {
			a.add(c, "a secret reaches %s.%s; only an --out-file writer may write one", p, sel.Sel.Name)
		}
		return
	}
	if sinkMethod(sel.Sel.Name) {
		a.add(c, "a secret reaches the method %s; only an --out-file writer may write one", sel.Sel.Name)
		return
	}
	// A method of a local type or a function-typed field.
	if obj := a.info.Uses[sel.Sel]; obj != nil && obj.Pkg() != nil && !adminOutputScope(a.pkgDir(obj.Pkg().Path())+"/") {
		return // a method of the module outside the scope or of a dependency: a Seal, a hash
	}
	a.localCall(c)
}

func (a *adminOutputFinder) receiverTainted(c *ast.CallExpr) bool {
	sel, ok := unparen(c.Fun).(*ast.SelectorExpr)
	return ok && a.pkgOf(sel) == "" && a.isTainted(sel.X)
}

func (a *adminOutputFinder) pkgDir(p string) string { return strings.TrimPrefix(p, module+"/") }

// localCall judges a call to code in scope: a tainted value may be passed only
// where the parameter is a secret type, so the callee is read by this same rule.
func (a *adminOutputFinder) localCall(c *ast.CallExpr) {
	tv, ok := a.info.Types[c.Fun]
	if !ok {
		a.add(c, "a secret reaches a call whose signature is unknown")
		return
	}
	sig, ok := tv.Type.Underlying().(*types.Signature)
	if !ok {
		a.add(c, "a secret reaches a call whose signature is unknown")
		return
	}
	for i, arg := range c.Args {
		if !a.isTainted(arg) {
			continue
		}
		var pt types.Type
		switch {
		case i < sig.Params().Len():
			pt = sig.Params().At(i).Type()
		case sig.Variadic() && sig.Params().Len() > 0:
			pt = sig.Params().At(sig.Params().Len() - 1).Type()
		}
		if sl, ok := pt.(*types.Slice); ok && sig.Variadic() && i >= sig.Params().Len()-1 {
			pt = sl.Elem()
		}
		if pt == nil || !isSecretType(pt) {
			a.add(arg, "a secret is passed to a parameter that is not a secret type; the callee cannot be judged")
		}
	}
}

// adminOutputProblems runs the rule over the files and returns what it found,
// with the number of function bodies examined and of tainted calls seen.
func adminOutputProblems(fset *token.FileSet, files []file, info *types.Info) (problems []string, funcs int) {
	for _, f := range files {
		if f.test || !adminOutputScope(f.path) {
			continue
		}
		for _, imp := range f.ast.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			if strings.Contains(p, "isatty") || strings.HasPrefix(p, "golang.org/x/term") {
				problems = append(problems, fmt.Sprintf("%s: import of %s: terminal detection is not allowed", fset.Position(imp.Pos()), p))
			}
		}
		ast.Inspect(f.ast, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok && bannedIdents[id.Name] {
				problems = append(problems, fmt.Sprintf("%s: %s: terminal and process-id tests are not allowed here; a secret goes to --out-file only", fset.Position(id.Pos()), id.Name))
			}
			return true
		})
		for _, d := range f.ast.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			funcs++
			key := f.path + ":" + fd.Name.Name
			_, allowed := allowedWriters[key]
			a := &adminOutputFinder{fset: fset, info: info, tainted: map[types.Object]bool{}, allowed: allowed}
			// A parameter of a secret type is tainted by its type; the others by flow.
			a.check(fd.Body)
			problems = append(problems, a.problems...)
		}
	}
	sort.Strings(problems)
	return dedupe(problems), funcs
}

func TestAdminCLINeverWritesASecretOutsideAFile(t *testing.T) {
	fset, files := parseRepo(t)
	info, ok := typeInfoReal(fset, files, adminStdlib...)
	if !ok {
		t.Fatal("type information unavailable")
	}
	problems, funcs := adminOutputProblems(fset, files, info)
	for _, p := range problems {
		t.Error(p)
	}
	if funcs < 30 {
		t.Fatalf("only %d functions examined in internal/admincli and cmd; the lint is not looking at them", funcs)
	}
	// The allow list may not rot: each named writer must exist.
	for key := range allowedWriters {
		found := false
		for _, f := range files {
			if f.test || !strings.HasPrefix(key, f.path+":") {
				continue
			}
			ast.Inspect(f.ast, func(n ast.Node) bool {
				if fd, ok := n.(*ast.FuncDecl); ok && f.path+":"+fd.Name.Name == key {
					found = true
				}
				return !found
			})
		}
		if !found {
			t.Errorf("allowed writer %s does not exist; remove it from the list", key)
		}
	}
}

// adminStdlib are type-checked from source, so a function is told from a variable by its type.
var adminStdlib = []string{"fmt", "io", "os", "errors", "log/slog", "strings", "flag"}

const stubKeyring = `package keyring
type Ring struct{}
func (*Ring) Seal(string, string) {}
`

const stubSecret = `package secret
type String struct{ p *string }
func (s String) Reveal() string { return "" }
func New(s string) String { return String{} }
type Bytes struct{ p *[]byte }
func (b Bytes) Reveal() []byte { return nil }
`

// TestAdminCLILintCanFail plants each way a secret could reach an output, and the
// clean uses that must stay allowed, so the rule is shown to fail and to pass.
func TestAdminCLILintCanFail(t *testing.T) {
	cases := []struct {
		name string
		path string
		src  string
		want int
	}{
		{"a Reveal to an exec-style Fprintf", "", `func f(w io.Writer, s secret.String) { fmt.Fprintf(w, "%s", s.Reveal()) }`, 1},
		{"the secret itself to Fprintln", "", `func f(w io.Writer, s secret.String) { fmt.Fprintln(w, s) }`, 1},
		{"os.Stdout.WriteString", "", `func f(s secret.String) { os.Stdout.WriteString(s.Reveal()) }`, 1},
		{"through a local variable", "", `func f(w io.Writer, s secret.String) { p := s.Reveal(); q := strings.TrimSpace(p); fmt.Fprint(w, q) }`, 1},
		{"through a conversion", "", `func f(w io.Writer, s secret.String) { w.Write([]byte(s.Reveal())) }`, 1},
		{"a concatenation", "", `func f(s secret.String) error { return errors.New("bad " + s.Reveal()) }`, 2},
		{"slog", "", `func f(l *slog.Logger, s secret.String) { l.Info("x", "k", s.Reveal()) }`, 1},
		{"the builtin println", "", `func f(s secret.String) { println(s.Reveal()) }`, 1},
		{"a secret to a function that takes any", "", `func show(v any) {}
func f(s secret.String) { show(s) }`, 1},
		{"plain text to a local function", "", `func show(v string) {}
func f(s secret.String) { show(s.Reveal()) }`, 1},
		{"plain text returned", "", `func f(s secret.String) string { return s.Reveal() }`, 1},
		{"plain text stored in a field", "", `type t struct{ v string }
func f(x *t, s secret.String) { x.v = s.Reveal() }`, 1},
		{"a sink taken as a value", "", `func f(s secret.String) { g := fmt.Fprintf; _ = g }`, 1},
		{"a secret as secret to a local function", "", `func show(v secret.String) {}
func f(s secret.String) { show(s) }`, 0},
		{"a Reveal handed to a dependency", "", `func f(s secret.String, ring *keyring.Ring) { ring.Seal("d", s.Reveal()) }`, 0},
		{"printing the path", "", `func f(w io.Writer, path string) { fmt.Fprintln(w, path) }`, 0},
		{"the restored terminal test", "", `func f(w *os.File) bool { fi, _ := w.Stat(); return fi.Mode()&os.ModeCharDevice != 0 }`, 1},
		{"a Getppid", "", `func f() int { return os.Getppid() }`, 1},
		{"a field named IsTerminal", "", `type Env struct{ IsTerminal func(io.Writer) bool }`, 1},
		{"the file writer may write", "internal/admincli/output.go", `func write(f *os.File, s secret.String) error { _, err := f.Write([]byte(s.Reveal())); return err }`, 0},
		{"the file writer may not reach stdout", "internal/admincli/output.go", `func write(s secret.String) error { _, err := os.Stdout.Write([]byte(s.Reveal())); return err }`, 1},
		{"another function in the writer file", "internal/admincli/output.go", `func other(f *os.File, s secret.String) error { _, err := f.Write([]byte(s.Reveal())); return err }`, 1},
	}
	for _, c := range cases {
		fset := token.NewFileSet()
		parse := func(p, src string) file {
			f, err := parser.ParseFile(fset, p, src, parser.ParseComments)
			if err != nil {
				t.Fatalf("%s: %v", c.name, err)
			}
			return file{path: p, ast: f}
		}
		p := c.path
		if p == "" {
			p = "internal/admincli/x.go"
		}
		src := "package admincli\nimport (\n\t\"errors\"\n\t\"fmt\"\n\t\"io\"\n\t\"log/slog\"\n\t\"os\"\n\t\"strings\"\n\t\"" + secretPkg + "\"\n\t\"" + module + "/internal/keyring\"\n)\n" +
			"var _ = errors.New\nvar _ = fmt.Sprint\nvar _ io.Writer\nvar _ slog.Level\nvar _ = os.Exit\nvar _ = strings.TrimSpace\nvar _ secret.String\nvar _ keyring.Ring\n" + c.src + "\n"
		fs := []file{parse("internal/secret/secret.go", stubSecret), parse("internal/keyring/ring.go", stubKeyring), parse(p, src)}
		info, ok := typeInfoReal(fset, fs, adminStdlib...)
		if !ok {
			t.Fatalf("%s: no type information", c.name)
		}
		got, _ := adminOutputProblems(fset, fs, info)
		if len(got) != c.want {
			t.Errorf("%s: %d findings %v, want %d", c.name, len(got), got, c.want)
		}
	}
}
