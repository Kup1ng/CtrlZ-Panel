package lint_test

import (
	"go/ast"
	"path"
	"sort"
	"strconv"
	"strings"
)

// plausibleCallers is the one file that may call totp.Plausible: the look at a second factor that
// a reset does before heavy work (round 12, primitives-r12-1). Plausible spends no step and
// counts no attempt, so it is not a verification; a file list, not a directory, is what keeps a
// new route from using it as one.
func plausibleCallers() map[string]bool {
	return map[string]bool{"internal/api/routes_totp.go": true}
}

// guardMethods are the three methods of totp.Guard. A type whose method set holds all of them,
// declared or promoted, can be passed to totp.Check.
func guardMethods() []string { return []string{"Hit", "Spend", "Reset"} }

// guardOwner says whether a package may build a guard: throttle makes the one real one, which
// needs the proof of a charge, and totp declares the interface.
func guardOwner(dir string) bool {
	return dir == "internal/auth/throttle" || dir == "internal/auth/totp"
}

// guardRef names a type of the repository by package directory and name, or is the interface
// totp.Guard itself.
type guardRef struct {
	dir, name string
	guard     bool
}

type guardType struct {
	// own is what the type declares: its methods, or the method names of an interface.
	own map[string]bool
	// embeds are the types whose methods it promotes: the embedded fields of a struct and the
	// embedded interfaces of an interface.
	embeds []guardRef
	// alias is the type that an alias (`type A = T`) or a defined type (`type D T`) is made from.
	alias   *guardRef
	isAlias bool
	isIface bool
}

// guardWorld is every non-test package of the repository, read once.
type guardWorld struct {
	types map[guardRef]*guardType
	// where maps a type to the file that declares it, for the message.
	where map[guardRef]string
}

// refOf turns the type expression of an embedded field, an alias or a defined type into a guardRef.
// imports maps the local package names of the file to import paths. A type of another module or of
// the standard library gives false: it cannot hold the three methods of a guard by promotion
// unless the repository declares them, and the repository's own types, shared/ included, are all in
// the world.
func refOf(dir string, e ast.Expr, imports map[string]string) (guardRef, bool) {
	for {
		switch x := e.(type) {
		case *ast.StarExpr:
			e = x.X
			continue
		case *ast.IndexExpr:
			e = x.X
			continue
		case *ast.IndexListExpr:
			e = x.X
			continue
		case *ast.ParenExpr:
			e = x.X
			continue
		}
		break
	}
	switch x := e.(type) {
	case *ast.Ident:
		return guardRef{dir: dir, name: x.Name}, true
	case *ast.SelectorExpr:
		id, ok := x.X.(*ast.Ident)
		if !ok {
			return guardRef{}, false
		}
		p := imports[id.Name]
		switch {
		case strings.HasSuffix(p, totpImportSuffix) && x.Sel.Name == "Guard":
			return guardRef{guard: true}, true
		case strings.HasPrefix(p, module+"/"):
			return guardRef{dir: strings.TrimPrefix(p, module+"/"), name: x.Sel.Name}, true
		}
		// The shared module is ours and its directories are in the world (round 13,
		// primitives-r13-3): a type declared there with the three methods, or a Panel struct
		// embedding one, is a guard like any other.
		if d, ok := sharedDir(p); ok {
			return guardRef{dir: d, name: x.Sel.Name}, true
		}
	}
	return guardRef{}, false
}

// fileImports maps the name a file gives each import to its path. A dot import has no name to
// resolve a selector by, so a type brought in by one is read as a local identifier and found only
// if the package declares it; the repository has no dot import of its own packages outside
// tests.
func fileImports(f *ast.File) map[string]string {
	m := map[string]string{}
	for _, imp := range f.Imports {
		p, _ := strconv.Unquote(imp.Path.Value)
		name := path.Base(p)
		if imp.Name != nil {
			name = imp.Name.Name
		}
		m[name] = p
	}
	return m
}

func embedsOf(dir string, st *ast.StructType, imports map[string]string) []guardRef {
	var out []guardRef
	for _, fl := range st.Fields.List {
		if len(fl.Names) != 0 {
			continue
		}
		if r, ok := refOf(dir, fl.Type, imports); ok {
			out = append(out, r)
		}
	}
	return out
}

// buildGuardWorld reads the type declarations and the methods of every package in byDir.
func buildGuardWorld(byDir map[string]map[string]*ast.File) *guardWorld {
	w := &guardWorld{types: map[guardRef]*guardType{}, where: map[guardRef]string{}}
	get := func(r guardRef) *guardType {
		ti := w.types[r]
		if ti == nil {
			ti = &guardType{own: map[string]bool{}}
			w.types[r] = ti
		}
		return ti
	}
	for dir, files := range byDir {
		for name, f := range files {
			imports := fileImports(f)
			for _, d := range f.Decls {
				switch x := d.(type) {
				case *ast.FuncDecl:
					if x.Recv == nil || len(x.Recv.List) != 1 {
						continue
					}
					if tn := receiverTypeName(x.Recv.List[0].Type); tn != "" {
						r := guardRef{dir: dir, name: tn}
						get(r).own[x.Name.Name] = true
						w.where[r] = name
					}
				case *ast.GenDecl:
					for _, sp := range x.Specs {
						ts, ok := sp.(*ast.TypeSpec)
						if !ok {
							continue
						}
						r := guardRef{dir: dir, name: ts.Name.Name}
						ti := get(r)
						w.where[r] = name
						switch t := ts.Type.(type) {
						case *ast.StructType:
							ti.embeds = append(ti.embeds, embedsOf(dir, t, imports)...)
						case *ast.InterfaceType:
							ti.isIface = true
							for _, m := range t.Methods.List {
								if len(m.Names) > 0 {
									for _, n := range m.Names {
										ti.own[n.Name] = true
									}
									continue
								}
								if er, ok := refOf(dir, m.Type, imports); ok {
									ti.embeds = append(ti.embeds, er)
								}
							}
						default:
							if tr, ok := refOf(dir, ts.Type, imports); ok {
								ti.alias = &tr
								ti.isAlias = ts.Assign.IsValid()
							}
						}
					}
				}
			}
		}
	}
	return w
}

func (w *guardWorld) isInterface(r guardRef, depth int) bool {
	if r.guard {
		return true
	}
	ti := w.types[r]
	if ti == nil || depth > 16 {
		return false
	}
	if ti.isIface {
		return true
	}
	return ti.alias != nil && w.isInterface(*ti.alias, depth+1)
}

// methodSet is the set of method names a type has, declared or promoted through embedded fields,
// aliases and defined types of an interface. The walk over-approximates on purpose: a name that
// the real method set hides by shadowing still counts, because a lint that fails closed costs one
// allow-list line and one that fails open costs the rule.
func (w *guardWorld) methodSet(r guardRef, seen map[guardRef]bool, withOwn bool) map[string]bool {
	out := map[string]bool{}
	if r.guard {
		for _, m := range guardMethods() {
			out[m] = true
		}
		return out
	}
	if seen[r] {
		return out
	}
	seen[r] = true
	ti := w.types[r]
	if ti == nil {
		return out
	}
	if withOwn {
		for m := range ti.own {
			out[m] = true
		}
	}
	for _, e := range ti.embeds {
		for m := range w.methodSet(e, seen, true) {
			out[m] = true
		}
	}
	if ti.alias != nil {
		// An alias is its target. A defined type made from an interface has the interface's
		// methods, and one made from a struct only the struct's embedded fields, not the
		// methods the struct declares.
		for m := range w.methodSet(*ti.alias, seen, ti.isAlias || w.isInterface(*ti.alias, 0)) {
			out[m] = true
		}
	}
	return out
}

func hasGuardMethods(m map[string]bool) bool {
	for _, g := range guardMethods() {
		if !m[g] {
			return false
		}
	}
	return true
}

// guardImplementorsOf is the other half of the rule of spec 6.3: totp.Check takes any totp.Guard,
// so a type that implements it with a Hit that always says yes would walk past the throttle
// without a compile error (primitives-r6-3 and -6). The only implementation is throttle's, whose
// guard cannot be built without the proof of a charge. Any other type in non-test code, in any
// package but internal/auth/throttle and the totp package itself, whose method set holds Hit,
// Spend and Reset fails here. The method set is the real one, not the declared one: methods
// promoted through an embedded local type, an alias of totp.Guard, a defined type of it, or a type
// of another package of the repository count (round 12, primitives-r12-1; the declared-methods
// version was walked around by embedding). byDir maps a package directory to its non-test files.
func guardImplementorsOf(byDir map[string]map[string]*ast.File) []string {
	w := buildGuardWorld(byDir)
	var out []string
	for r := range w.types {
		if guardOwner(r.dir) || r.guard || w.isInterface(r, 0) || byDir[r.dir] == nil {
			continue
		}
		if hasGuardMethods(w.methodSet(r, map[guardRef]bool{}, true)) {
			out = append(out, w.where[r]+": type "+r.name+" has Hit, Spend and Reset, declared or promoted, so it is a totp.Guard of its own; the only guard is throttle's, which needs the proof of a charge")
		}
	}
	// Struct types written inline, in a function body or a composite literal, are in no
	// declaration table. A struct that is a declared type's own body is already judged above.
	for dir, files := range byDir {
		if guardOwner(dir) {
			continue
		}
		for name, f := range files {
			imports := fileImports(f)
			declared := map[*ast.StructType]bool{}
			for _, d := range f.Decls {
				if gd, ok := d.(*ast.GenDecl); ok {
					for _, sp := range gd.Specs {
						if ts, ok := sp.(*ast.TypeSpec); ok {
							if st, ok := ts.Type.(*ast.StructType); ok {
								declared[st] = true
							}
						}
					}
				}
			}
			ast.Inspect(f, func(n ast.Node) bool {
				st, ok := n.(*ast.StructType)
				if !ok || declared[st] {
					return true
				}
				m := map[string]bool{}
				for _, e := range embedsOf(dir, st, imports) {
					for k := range w.methodSet(e, map[guardRef]bool{}, true) {
						m[k] = true
					}
				}
				if hasGuardMethods(m) {
					out = append(out, name+": an inline struct embeds types that give it Hit, Spend and Reset, so it is a totp.Guard of its own")
				}
				return true
			})
		}
	}
	sort.Strings(out)
	return out
}

// guardImplementors is guardImplementorsOf for one package, which is what the planted sources of
// the tests are.
func guardImplementors(dir string, files map[string]*ast.File) []string {
	return guardImplementorsOf(map[string]map[string]*ast.File{dir: files})
}
