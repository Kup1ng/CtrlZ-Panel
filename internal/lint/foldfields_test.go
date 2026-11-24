package lint_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
)

// Rule boundary-input, the fields that are folded (review round 15, primitives-r15-1).
//
// A field the server folds (a typed code through digits.Typed, a phone number through the phone
// parser) must reach the handler with the marks a paste carries, so its schema takes the `pasted`
// pattern. Round 14 listed the eight fields known to fold, in `codeFields`, and the lint held them
// on the pasted patterns; the list was kept by hand, so the Users filter `q`, which the handler
// hands to phone.SearchPrefix, stayed on the `text` pattern and answered 400 to the very marks the
// fold drops. A list of names is a rule that holds for the names somebody remembered.
//
// This file derives the list from the code. The question is "which fields of a generated request
// type reach a fold?", and the answer is a demand that flows backwards from the folds:
//
//   - the base folds are the first parameter of phone.Normalize, phone.SearchPrefix and
//     digits.Typed;
//   - a variable (a parameter, a local, a struct field) is folded when it is handed to a folded
//     parameter, assigned to a folded variable, or written into a folded struct field, and then
//     every variable that the expression carries is folded too;
//   - the generated request fields (a struct of a `gen` package that carries a json or form tag)
//     that end up folded are the answer, by their wire name.
//
// Variables are the type checker's objects, not names, so a local named like a field is its own.
// What the analysis cannot see (a call through an interface, a closure) is what `codeFields` is
// the floor for: the derived set is added to it, and TestFoldDerivationSeesTheKnownFolds fails if
// the derivation stops finding what it must, so a derivation that reads nothing cannot pass.

// foldBases are the folds themselves: package path suffix and function name, parameter 0.
var foldBases = map[string]bool{
	"internal/auth/phone.Normalize":    true,
	"internal/auth/phone.SearchPrefix": true,
	"internal/auth/digits.Typed":       true,
}

// foldedNames derives the wire names of the request fields that reach a fold.
func foldedNames(fset *token.FileSet, files []file, info *types.Info) map[string][]string {
	folded := map[types.Object]bool{}
	for _, f := range files {
		if f.test {
			continue
		}
		for _, d := range f.ast.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Recv != nil {
				continue
			}
			fn, _ := info.Defs[fd.Name].(*types.Func)
			if fn == nil || fn.Pkg() == nil {
				continue
			}
			key := strings.TrimPrefix(fn.Pkg().Path(), module+"/") + "." + fn.Name()
			if foldBases[key] && fn.Type().(*types.Signature).Params().Len() > 0 {
				folded[fn.Type().(*types.Signature).Params().At(0)] = true
			}
		}
	}

	// varsIn lists the variables an expression carries. A field selected from a value carries the
	// field and not the value (b.Phone is the field Phone; folding it says nothing of b.Password),
	// and a struct literal carries nothing of its own: its fields are demanded one by one (the
	// KeyValueExpr and CompositeLit cases below), because a struct handed to a function that folds
	// one member does not fold the others (round 15: a locale was derived as folded).
	varsIn := func(e ast.Node) []types.Object {
		var out []types.Object
		var walk func(n ast.Node)
		walk = func(n ast.Node) {
			ast.Inspect(n, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.CompositeLit:
					return false
				case *ast.SelectorExpr:
					if o, ok := info.Uses[x.Sel].(*types.Var); ok && o.IsField() {
						out = append(out, o)
						return false
					}
				case *ast.Ident:
					if o, ok := info.Uses[x].(*types.Var); ok {
						out = append(out, o)
					}
				}
				return true
			})
		}
		walk(e)
		return out
	}
	mark := func(e ast.Node) bool {
		changed := false
		for _, o := range varsIn(e) {
			if !folded[o] {
				folded[o] = true
				changed = true
			}
		}
		return changed
	}
	// lhsFolded says whether an assignment target is a folded variable.
	lhsFolded := func(e ast.Expr) bool {
		switch x := unparen(e).(type) {
		case *ast.Ident:
			o := info.Defs[x]
			if o == nil {
				o = info.Uses[x]
			}
			return o != nil && folded[o]
		case *ast.SelectorExpr:
			o := info.Uses[x.Sel]
			return o != nil && folded[o]
		}
		return false
	}
	calleeSig := func(c *ast.CallExpr) *types.Signature {
		var obj types.Object
		switch fun := unparen(c.Fun).(type) {
		case *ast.Ident:
			obj = info.Uses[fun]
		case *ast.SelectorExpr:
			if s := info.Selections[fun]; s != nil {
				obj = s.Obj()
			} else {
				obj = info.Uses[fun.Sel]
			}
		}
		fn, ok := obj.(*types.Func)
		if !ok {
			return nil
		}
		sig, _ := fn.Type().(*types.Signature)
		return sig
	}

	for changed := true; changed; {
		changed = false
		for _, f := range files {
			if f.test {
				continue
			}
			ast.Inspect(f.ast, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.CallExpr:
					sig := calleeSig(x)
					if sig == nil {
						return true
					}
					for i, a := range x.Args {
						pi := i
						if sig.Variadic() && pi >= sig.Params().Len()-1 {
							pi = sig.Params().Len() - 1
						}
						if pi < sig.Params().Len() && folded[sig.Params().At(pi)] && mark(a) {
							changed = true
						}
					}
				case *ast.AssignStmt:
					if len(x.Lhs) == len(x.Rhs) {
						for i := range x.Lhs {
							if lhsFolded(x.Lhs[i]) && mark(x.Rhs[i]) {
								changed = true
							}
						}
					}
				case *ast.ValueSpec:
					if len(x.Names) == len(x.Values) {
						for i, id := range x.Names {
							if o := info.Defs[id]; o != nil && folded[o] && mark(x.Values[i]) {
								changed = true
							}
						}
					}
				case *ast.CompositeLit:
					// A literal of a type from a package the loader holds only as a stub (River, since P2) has no recorded type, and
					// no field of it is a folded request field.
					lt := info.TypeOf(x)
					if lt == nil {
						return true
					}
					st, _ := lt.Underlying().(*types.Struct)
					if st == nil {
						return true
					}
					for i, el := range x.Elts {
						if kv, ok := el.(*ast.KeyValueExpr); ok {
							if id, ok := kv.Key.(*ast.Ident); ok {
								if o := info.Uses[id]; o != nil && folded[o] && mark(kv.Value) {
									changed = true
								}
							}
						} else if i < st.NumFields() && folded[st.Field(i)] && mark(el) {
							changed = true // a positional literal: the element stands where the field does
						}
					}
				}
				return true
			})
		}
	}

	// The wire name of a generated field is the first name of its json or form tag.
	out := map[string][]string{}
	for _, f := range files {
		if f.test || !strings.Contains(f.path, "/gen/") {
			continue
		}
		ast.Inspect(f.ast, func(n ast.Node) bool {
			st, ok := n.(*ast.StructType)
			if !ok {
				return true
			}
			for _, fld := range st.Fields.List {
				if fld.Tag == nil || len(fld.Names) == 0 {
					continue
				}
				tag := reflect.StructTag(strings.Trim(fld.Tag.Value, "`"))
				name := tag.Get("json")
				if name == "" {
					name = tag.Get("form")
				}
				name = strings.Split(name, ",")[0]
				if name == "" || name == "-" {
					continue
				}
				for _, id := range fld.Names {
					if o := info.Defs[id]; o != nil && folded[o] && stringish(o.Type()) {
						out[name] = append(out[name], fset.Position(id.Pos()).String())
					}
				}
			}
			return true
		})
	}
	return out
}

// stringish says whether a field holds text: a string or a pointer to one.
func stringish(t types.Type) bool {
	if p, ok := t.(*types.Pointer); ok {
		t = p.Elem()
	}
	b, ok := t.Underlying().(*types.Basic)
	return ok && b.Kind() == types.String
}

var (
	derivedOnce  sync.Once
	derivedNames map[string]bool
	derivedErr   error
)

// derivedFoldNames is foldedNames over the real repository, computed once for the package.
func derivedFoldNames() (map[string]bool, error) {
	derivedOnce.Do(func() {
		root, err := repoRootErr()
		if err != nil {
			derivedErr = err
			return
		}
		fset, files, err := parseRepoAt(root)
		if err != nil {
			derivedErr = err
			return
		}
		info, ok := typeInfoReal(fset, files)
		if !ok {
			derivedErr = errNoTypes
			return
		}
		derivedNames = map[string]bool{}
		for n := range foldedNames(fset, files, info) {
			derivedNames[n] = true
		}
	})
	return derivedNames, derivedErr
}

type lintError string

func (e lintError) Error() string { return string(e) }

const errNoTypes = lintError("type information unavailable")

// mustFold are the wire names the derivation has to find in the repository as it stands: the code
// and phone fields of round 14 and the Users filter and the invite code (round 15, tenant-r15-1 and -5). A derivation that finds fewer has stopped
// reading the code, and an empty one would let every schema through.
var mustFold = []string{"code", "totp_code", "recovery_code", "otp_code", "old_code", "new_code", "phone", "new_phone", "q", "invite_token", "token"}

func TestFoldDerivationSeesTheKnownFolds(t *testing.T) {
	got, err := derivedFoldNames()
	if err != nil {
		t.Fatal(err)
	}
	var missing []string
	for _, n := range mustFold {
		if !got[n] {
			missing = append(missing, n)
		}
	}
	if len(missing) > 0 {
		t.Errorf("the derivation no longer finds these folded request fields: %v (found %v)", missing, sortedNames(got))
	}
}

func sortedNames(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for n := range m {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// TestFoldDerivationCanFail plants handlers and shows the derivation follows a field through a
// local, a helper parameter and a struct field, and leaves alone a field that is not folded.
func TestFoldDerivationCanFail(t *testing.T) {
	const phonePkg = `package phone
func Normalize(raw string) (string, error) { return raw, nil }
func SearchPrefix(raw string) (string, error) { return raw, nil }
`
	const genPkg = "package gen\n" +
		"type Body struct {\n" +
		"\tPhone string `json:\"phone\"`\n" +
		"\tPassword string `json:\"password\"`\n" +
		"\tCode *string `json:\"code,omitempty\"`\n" +
		"\tFilter *string `json:\"filter,omitempty\"`\n" +
		"\tNote string `json:\"note\"`\n" +
		"\tCount int `json:\"count\"`\n" +
		"}\n" +
		"type Params struct {\n\tQ *string `form:\"q,omitempty\"`\n}\n"
	cases := []struct {
		name, handler string
		want          []string
	}{
		{"a direct call", `func h(b *gen.Body) { phone.Normalize(b.Phone) }`, []string{"phone"}},
		{"through a local", `func h(b *gen.Body) { p := b.Phone; _, _ = phone.Normalize(p) }`, []string{"phone"}},
		{"through a wrapper call", `func clean(v *string) string { if v == nil { return "" }; return *v }
func h(p *gen.Params) { q := clean(p.Q); _, _ = phone.SearchPrefix(q) }`, []string{"q"}},
		{"through a helper parameter", `func use(code string) { _, _ = phone.Normalize(code) }
func h(b *gen.Body) { use(*b.Code) }`, []string{"code"}},
		{"through a struct field", `type in struct{ Code string }
func use(i in) { _, _ = phone.Normalize(i.Code) }
func h(b *gen.Body) { use(in{Code: *b.Code}) }`, []string{"code"}},
		{"through a second helper", `func inner(s string) { _, _ = phone.Normalize(s) }
func outer(s string) { inner(s) }
func h(b *gen.Body) { outer(b.Phone) }`, []string{"phone"}},
		{"a field that is only read", `func h(b *gen.Body) { _ = b.Password; _ = len(b.Note) }`, nil},
		{"a folded field beside an unfolded one", `func h(b *gen.Body) { _, _ = phone.Normalize(b.Phone); _ = b.Password }`, []string{"phone"}},
		{"a number is not text", `func h(b *gen.Body) { _ = b.Count }`, nil},
		{"a local that shadows a field name", `func h(b *gen.Body) { Phone := "x"; _, _ = phone.Normalize(Phone); _ = b.Password }`, nil},
	}
	for _, c := range cases {
		src := "package api\nimport (\n\t\"" + module + "/internal/api/gen\"\n\t\"" + module + "/internal/auth/phone\"\n)\n" + c.handler
		fset := token.NewFileSet()
		files := parseSources(t, fset, map[string]string{
			"internal/auth/phone/p.go": phonePkg,
			"internal/api/gen/g.go":    genPkg,
			"internal/api/h.go":        src,
		})
		info, ok := typeInfoReal(fset, files)
		if !ok {
			t.Fatalf("%s: no type information", c.name)
		}
		var got []string
		for n := range foldedNames(fset, files, info) {
			got = append(got, n)
		}
		sort.Strings(got)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: derived %v, want %v", c.name, got, c.want)
		}
	}
}

// parseSources parses planted files into the shape the lints read.
func parseSources(t *testing.T, fset *token.FileSet, src map[string]string) []file {
	t.Helper()
	var out []file
	for p, s := range src {
		af, err := parser.ParseFile(fset, p, s, 0)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		out = append(out, file{path: p, ast: af})
	}
	return out
}
