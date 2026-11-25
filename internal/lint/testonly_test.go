package lint_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// Two allow lists that hold the doors of the SMS layer shut for the whole module, not for a list of
// packages a gateway call is known to reach (P1 auth review round 16, sms-r16-6, sms-r16-11). Each
// judges every non-test file of the module, takes its facts from go/types objects and import paths,
// and fails for anything it does not recognise; an entry that matches nothing fails too, so a list
// cannot rot into a free pass. A test file may import anything. The third door of round 16, reflect,
// is judged with the other escape hatches by the one ban in capabilities_test.go (owner decision D63).

// harnessPackages are the packages that exist for tests and hand out something a production binary
// must never hold: a certificate authority whose private key is published in Go's source tree
// (testtls), a database cluster with the superuser (testpg, authtest), a Valkey with no ACL
// (testvalkey), a passkey authenticator (passkeytest) and the catalog checks (catalogtest). The
// prefix of a directory covers its subdirectories. A non-test file outside this set that imports one
// fails: with TLS verification still on, so that every other check stays green, a production caller
// that passed testtls.Roots() as RootCAs would trust a key anyone can use.
var harnessPackages = map[string]string{
	"deploy":                            "the image references of the container harnesses (testpg, testvalkey); production code never names an image",
	"internal/testtls":                  "trusts the certificate every httptest TLS server presents, whose key is published",
	"internal/testpg":                   "starts a real Postgres cluster and holds the superuser",
	"internal/testvalkey":               "starts a Valkey with no ACL",
	"internal/testwait":                 "the waits of a test: polls a condition and receives from a channel with a limit",
	"internal/authtest":                 "the two-tenant and oracle harness of the auth packages, built on testpg",
	"internal/auth/passkey/passkeytest": "a software authenticator",
	"internal/store/catalogtest":        "the catalog checks, which read the whole database as the superuser",
}

// dirOf returns the directory of a slash path.
func dirOf(p string) string { return p[:strings.LastIndex(p, "/")] }

func underAny(dir string, set map[string]string) (string, bool) {
	for d := range set {
		if dir == d || strings.HasPrefix(dir, d+"/") {
			return d, true
		}
	}
	return "", false
}

// testOnlyProblems judges the harness importers over files, and says which entries of the list
// matched nothing.
func testOnlyProblems(fset *token.FileSet, files []file) []string {
	var out []string
	usedHarness := map[string]bool{}
	dirs := map[string]bool{}
	for _, f := range files {
		dir := dirOf(f.path)
		if !f.test {
			dirs[dir] = true
		}
		if f.test {
			continue
		}
		for _, im := range f.ast.Imports {
			// Read as Go reads it: a raw string path spells the same package as a quoted one.
			p, err := strconv.Unquote(im.Path.Value)
			if err != nil {
				out = append(out, fmt.Sprintf("%s: the import path %s cannot be read", fset.Position(im.Pos()), im.Path.Value))
				continue
			}
			if strings.HasPrefix(p, module+"/") {
				target := strings.TrimPrefix(p, module+"/")
				if h, isHarness := underAny(target, harnessPackages); isHarness {
					if _, fromHarness := underAny(dir, harnessPackages); fromHarness {
						usedHarness[h] = true
						continue
					}
					out = append(out, fmt.Sprintf("%s: non-test code of %s imports the test harness %s (%s); a harness is imported from test files and from other harness packages only", fset.Position(im.Pos()), dir, target, harnessPackages[h]))
				}
			}
		}
	}
	for dir := range harnessPackages {
		if !dirs[dir] && !hasPrefixDir(dirs, dir) {
			out = append(out, "harnessPackages lists "+dir+", which has no non-test source: remove the entry")
		}
	}
	sort.Strings(out)
	return out
}

func hasPrefixDir(dirs map[string]bool, d string) bool {
	for x := range dirs {
		if strings.HasPrefix(x, d+"/") {
			return true
		}
	}
	return false
}

func TestTheTestHarnessesAreImportedOnlyWhereListed(t *testing.T) {
	fset, files := parseRepo(t)
	for _, p := range testOnlyProblems(fset, files) {
		t.Error(p)
	}
}

// driverConfigs are the struct types a gateway is built from, with the only fields non-test code
// outside the declaring package may touch and the package that may touch them. BaseURL, RootCAs and
// Timeout exist so a test can point a driver at an httptest server with its own trust; the worker
// leaves them at their zero values, and only a field named here may be set by production code, so
// a field added to a Config tomorrow starts refused. smshttp.Options is built only by the two
// drivers, which pass on what their own Config holds.
var driverConfigs = map[string]map[string][]string{
	"internal/sms/smsir.Config":       {"internal/sms/senders": {"Credentials"}},
	"internal/sms/melipayamak.Config": {"internal/sms/senders": {"Credentials"}},
	"internal/sms/smshttp.Options":    {"internal/sms/smsir": {"Total", "RootCAs"}, "internal/sms/melipayamak": {"Total", "RootCAs"}},
}

// driverConfigProblems judges the FIELD OBJECTS of the driver Config types, not the type an
// expression happens to have (sms-r16-20). It resolves each struct type of driverConfigs to its
// go/types fields once, then reports every identifier of non-test code that resolves to one of those
// field objects outside the package that declares the type, unless the importer is listed for that
// field. So a field promoted through an embedding (type W struct{ smsir.Config }; w.RootCAs), a key
// of a keyed literal, a selector through a pointer, an alias and a method-free closure are all the
// same object and are judged alike. Two ways to build or read the fields without naming one are
// refused as such: a positional literal (every field is set by position) and a conversion between a
// Config and any other struct type (the fields travel under other names). The contract: it judges
// non-test code of the module for the fields of these three types; it does not follow a value after
// it is an interface (a Config in an any cannot have its field set without a type assertion, which
// is a conversion to the type and is judged on the next use), and it does not judge reflection or
// unsafe or any other escape hatch, which the escape-hatch ban (capabilities_test.go) judges once.
func driverConfigProblems(fset *token.FileSet, files []file, info *types.Info) []string {
	var out []string
	type guarded struct{ typ, name string }
	fields := map[*types.Var]guarded{}
	declDir := map[string]string{} // type key to the directory that declares it
	for _, o := range info.Defs {
		tn, ok := o.(*types.TypeName)
		if !ok || tn.Pkg() == nil || tn.IsAlias() {
			continue
		}
		k := strings.TrimPrefix(tn.Pkg().Path(), module+"/") + "." + tn.Name()
		if _, ok := driverConfigs[k]; !ok {
			continue
		}
		st, ok := tn.Type().Underlying().(*types.Struct)
		if !ok {
			continue
		}
		declDir[k] = strings.TrimPrefix(tn.Pkg().Path(), module+"/")
		for i := 0; i < st.NumFields(); i++ {
			fields[st.Field(i)] = guarded{k, st.Field(i).Name()}
		}
	}
	allowed := func(typ, importer, field string) bool {
		for _, f := range driverConfigs[typ][importer] {
			if f == field {
				return true
			}
		}
		return false
	}
	// guardedType names the driver Config a type is (through pointers and aliases), or "".
	guardedType := func(t types.Type) string {
		for t != nil {
			t = types.Unalias(t)
			p, ok := t.(*types.Pointer)
			if !ok {
				break
			}
			t = p.Elem()
		}
		n, ok := t.(*types.Named)
		if !ok || n.Obj().Pkg() == nil {
			return ""
		}
		k := strings.TrimPrefix(n.Obj().Pkg().Path(), module+"/") + "." + n.Obj().Name()
		if _, ok := driverConfigs[k]; ok {
			return k
		}
		return ""
	}
	for _, f := range files {
		if f.test {
			continue
		}
		importer := dirOf(f.path)
		ast.Inspect(f.ast, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.Ident:
				v, ok := info.Uses[x].(*types.Var)
				if !ok {
					return true
				}
				g, ok := fields[v]
				if !ok || declDir[g.typ] == importer {
					return true
				}
				if !allowed(g.typ, importer, g.name) {
					out = append(out, fmt.Sprintf("%s: %s uses field %s of %s; production code may not (the field exists for tests)", fset.Position(x.Pos()), importer, g.name, g.typ))
				}
			case *ast.CompositeLit:
				tv, ok := info.Types[x]
				if !ok {
					return true
				}
				k := guardedType(tv.Type)
				if k == "" || declDir[k] == importer {
					return true
				}
				for _, el := range x.Elts {
					if _, keyed := el.(*ast.KeyValueExpr); !keyed {
						out = append(out, fmt.Sprintf("%s: a positional literal of %s outside its package; name the fields so each one can be judged", fset.Position(el.Pos()), k))
					}
				}
			case *ast.CallExpr:
				ft, ok := info.Types[x.Fun]
				if !ok || !ft.IsType() || len(x.Args) != 1 {
					return true
				}
				at, ok := info.Types[x.Args[0]]
				if !ok || at.Type == nil {
					return true
				}
				to, from := guardedType(ft.Type), guardedType(at.Type)
				if (to == "" && from == "") || to == from {
					return true
				}
				k := to
				if k == "" {
					k = from
				}
				if declDir[k] != importer {
					out = append(out, fmt.Sprintf("%s: %s converts between %s and another type; the fields travel under other names and cannot be judged one by one", fset.Position(x.Pos()), importer, k))
				}
			}
			return true
		})
	}
	sort.Strings(out)
	return dedupe(out)
}

func TestDriverConfigFieldsAreSetByTestsOnly(t *testing.T) {
	fset, files := parseRepo(t)
	info, ok := typeInfoReal(fset, files)
	if !ok {
		t.Fatal("type information unavailable")
	}
	for _, p := range driverConfigProblems(fset, files, info) {
		t.Error(p)
	}
	// The allow list must name types that exist, or it judges nothing.
	for k := range driverConfigs {
		dir := k[:strings.LastIndex(k, ".")]
		found := false
		for _, f := range files {
			if !f.test && dirOf(f.path) == dir {
				found = true
			}
		}
		if !found {
			t.Errorf("driverConfigs names %s, whose package has no source", k)
		}
	}
}

// wholeFile starts a planted source that carries its own package clause and build constraint.
const wholeFile = "WHOLE-FILE:"

// planted files for the can-fail tests: a path and the source after the package clause.
func parsePlanted(t *testing.T, fset *token.FileSet, srcs []planted) []file {
	t.Helper()
	var fs []file
	for _, s := range srcs {
		pkg := filepath.Base(dirOf(s.path))
		src := "package " + pkg + "\n" + s.src + "\n"
		// A source marked as a whole file brings its own package clause: an ignored generator (package
		// main) in a directory of another package, which go/types would drop (q9-1, q9-7, q9-11).
		if rest, ok := strings.CutPrefix(s.src, wholeFile); ok {
			src = rest + "\n"
		}
		af, err := parser.ParseFile(fset, s.path, src, parser.ParseComments)
		if err != nil {
			t.Fatalf("%s: %v", s.path, err)
		}
		fs = append(fs, file{path: s.path, test: strings.HasSuffix(s.path, "_test.go"), ast: af})
	}
	return fs
}

// TestTestOnlyImportsLintCanFail plants every way production code can reach a harness package: a
// direct import, an aliased one, a blank one, a raw string path, one from a package that is a harness of its
// own, and a package declared in harnessPackages or not (the classification is TestEveryPackageIsProductionOrADeclaredHarness).
func TestTestOnlyImportsLintCanFail(t *testing.T) {
	m := module
	// Each case is judged with the declared packages present, so no list entry goes stale.
	base := []planted{
		{"internal/testtls/t.go", `var X int`},
		{"internal/testpg/t.go", `var X int`},
		{"internal/testvalkey/t.go", `var X int`},
		{"internal/testwait/t.go", `var X int`},
		{"internal/authtest/t.go", `var X int`},
		{"internal/auth/passkey/passkeytest/t.go", `var X int`},
		{"internal/store/catalogtest/t.go", `var X int`},
		{"deploy/t.go", `var X int`},
	}
	cases := []struct {
		name  string
		extra []planted
		want  int
	}{
		{"nothing else", nil, 0},
		{"testtls imported by a raw string path", []planted{{"internal/app/x.go", "import _ `" + m + "/internal/testtls`"}}, 1},
		{"testtls imported by a driver", []planted{{"internal/sms/smsir/x.go", `import "` + m + `/internal/testtls"
var _ = testtls.X`}}, 1},
		{"testtls imported blank", []planted{{"internal/sms/senders/x.go", `import _ "` + m + `/internal/testtls"`}}, 1},
		{"testtls imported under an alias", []planted{{"internal/app/x.go", `import tt "` + m + `/internal/testtls"
var _ = tt.X`}}, 1},
		{"testpg imported by the store", []planted{{"internal/store/x.go", `import "` + m + `/internal/testpg"
var _ = testpg.X`}}, 1},
		{"a harness package under authtest", []planted{{"internal/authtest/flood/x.go", `import "` + m + `/internal/testpg"
var _ = testpg.X`}}, 0},
		{"authtest imported by the api", []planted{{"internal/api/x.go", `import "` + m + `/internal/authtest"
var _ = authtest.X`}}, 1},
		{"a harness imported by a harness", []planted{{"internal/authtest/y.go", `import "` + m + `/internal/store/catalogtest"
var _ = catalogtest.X`}}, 0},
		{"a test file imports anything", []planted{{"internal/api/x_test.go", `import "` + m + `/internal/testtls"
var _ = testtls.X`}}, 0},
		{"a testdata directory is data", []planted{{"internal/foo/testdata/x.go", `var X int`}}, 0},
	}
	for _, c := range cases {
		fset := token.NewFileSet()
		fs := parsePlanted(t, fset, append(append([]planted(nil), base...), c.extra...))
		got := testOnlyProblems(fset, fs)
		if (c.want == 0) != (len(got) == 0) {
			t.Errorf("%s: %d problems, want %d or more: %v", c.name, len(got), c.want, got)
		}
	}
	// A harness entry with no source fails.
	fset := token.NewFileSet()
	fs := parsePlanted(t, fset, base[:len(base)-1])
	if got := testOnlyProblems(fset, fs); len(got) == 0 {
		t.Error("a harnessPackages entry with no source was not reported")
	}
}

// TestDriverConfigLintCanFail plants every form Go gives for setting a test-only field of a driver
// Config in production code: a keyed literal, a positional one, a selector assignment, an assignment
// through a pointer, a field of the shared Options, and a method value. The senders' own use stays
// clean, and so does the declaring package's.
func TestDriverConfigLintCanFail(t *testing.T) {
	m := module
	decl := []planted{
		{"internal/sms/smsir/s.go", `type Config struct {
	Credentials string
	BaseURL     string
	RootCAs     int
	Timeout     int
}
func New(c Config) {}`},
		{"internal/sms/melipayamak/s.go", `type Config struct {
	Credentials string
	BaseURL     string
	RootCAs     int
	Timeout     int
}
func New(c Config) {}`},
		{"internal/sms/smshttp/s.go", `type Options struct{ Total, RootCAs int }
type Client struct{ c int }`},
		{"internal/sms/noop/s.go", `type Sender struct{ file string }`},
	}
	imp := `import "` + m + `/internal/sms/smsir"
import "` + m + `/internal/sms/melipayamak"
import "` + m + `/internal/sms/smshttp"
`
	cases := []struct {
		name, path, src string
		want            int
	}{
		{"the senders' own use", "internal/sms/senders/s.go", imp + `func f() { smsir.New(smsir.Config{Credentials: "k"}); melipayamak.New(melipayamak.Config{Credentials: "k"}) }`, 0},
		{"a keyed literal with RootCAs", "internal/worker/x/x.go", imp + `func f() { smsir.New(smsir.Config{Credentials: "k", RootCAs: 1}) }`, 1},
		{"a keyed literal with BaseURL", "internal/app/x.go", imp + `func f() { melipayamak.New(melipayamak.Config{BaseURL: "http://x"}) }`, 1},
		{"a positional literal", "internal/app/x.go", imp + `func f() { smsir.New(smsir.Config{"k", "u", 1, 2}) }`, 1},
		{"a selector assignment", "internal/app/x.go", imp + `func f() { var c smsir.Config; c.BaseURL = "x"; smsir.New(c) }`, 1},
		{"an assignment through a pointer", "internal/app/x.go", imp + `func f() { c := &smsir.Config{}; c.RootCAs = 1; smsir.New(*c) }`, 1},
		{"new then a field", "internal/app/x.go", imp + `func f() { c := new(melipayamak.Config); c.Timeout = 3; melipayamak.New(*c) }`, 1},
		{"a read of a field", "internal/app/x.go", imp + `func f(c smsir.Config) string { return c.BaseURL }`, 1},
		{"Options built by something that is not a driver", "internal/worker/x/x.go", imp + `func f() { _ = smshttp.Options{Total: 1} }`, 1},
		{"Options built by a driver", "internal/sms/smsir/y.go", `import "` + m + `/internal/sms/smshttp"
func g() { _ = smshttp.Options{Total: 1, RootCAs: 2} }`, 0},
		{"a field of the opaque client", "internal/app/x.go", imp + `func f(c *smshttp.Client) {}`, 0},
		{"the noop sender's file field", "internal/app/x.go", `import "` + m + `/internal/sms/noop"
func f(s *noop.Sender) { _ = s }`, 0},
		{"a test file sets everything", "internal/worker/x/x_test.go", imp + `func f() { smsir.New(smsir.Config{BaseURL: "x", RootCAs: 1, Timeout: 2}) }`, 0},
		{"the declaring package", "internal/sms/smsir/z.go", `func h(c Config) string { return c.BaseURL }`, 0},

		// sms-r16-20: the judgement is by field object, so a promoted field and a conversion are seen.
		{"a field promoted through an embedding, set", "internal/worker/x/x.go", imp + `type W struct{ smsir.Config }
func f(w *W) { w.RootCAs = 1 }`, 1},
		{"a field promoted through an embedding, read", "internal/worker/x/x.go", imp + `type W struct{ smsir.Config }
func f(w W) string { return w.BaseURL }`, 1},
		{"a field promoted through an embedded pointer", "internal/worker/x/x.go", imp + `type W struct{ *melipayamak.Config }
func f(w W) { w.Timeout = 2 }`, 1},
		{"an embedding that sets a field of the inner literal", "internal/worker/x/x.go", imp + `type W struct{ smsir.Config }
func f() W { return W{Config: smsir.Config{RootCAs: 1}} }`, 1},
		{"a Config built by conversion from another struct", "internal/worker/x/x.go", imp + `type raw struct {
	Credentials string
	BaseURL     string
	RootCAs     int
	Timeout     int
}
func f() smsir.Config { return smsir.Config(raw{BaseURL: "x"}) }`, 1},
		{"a Config read by conversion to another struct", "internal/worker/x/x.go", imp + `type raw struct {
	Credentials string
	BaseURL     string
	RootCAs     int
	Timeout     int
}
func f(c smsir.Config) raw { return raw(c) }`, 1},
		{"a field through an alias", "internal/worker/x/x.go", imp + `type C = smsir.Config
func f() C { return C{RootCAs: 1} }`, 1},
		{"a field through an anonymous struct embedding", "internal/worker/x/x.go", imp + `func f() { v := struct{ smsir.Config }{}; v.BaseURL = "x" }`, 1},
		{"a closure that sets a field", "internal/worker/x/x.go", imp + `var set = func(c *smsir.Config) { c.BaseURL = "x" }`, 1},
		{"a Config handed on whole", "internal/worker/x/x.go", imp + `func f(c smsir.Config) { smsir.New(c) }`, 0},
		{"a conversion of the same type", "internal/worker/x/x.go", imp + `func f(c smsir.Config) smsir.Config { return smsir.Config(c) }`, 0},
	}
	for _, c := range cases {
		fset := token.NewFileSet()
		fs := parsePlanted(t, fset, append(append([]planted(nil), decl...), planted{c.path, c.src}))
		info, ok := typeInfoReal(fset, fs)
		if !ok {
			t.Fatalf("%s: no type information", c.name)
		}
		got := driverConfigProblems(fset, fs, info)
		if (c.want == 0) != (len(got) == 0) {
			t.Errorf("%s: %d problems, want %d or more: %v", c.name, len(got), c.want, got)
		}
	}
}
