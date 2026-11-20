package lint_test

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"sort"
	"strings"
	"sync"
)

// Rule one-primitive-per-key, the typed reading of every use of the keyring's six operations
// (review round 13, primitives-r13-2 and -5). Rounds 7 and 12 read the calls by their syntax: a
// selector call named Seal with three arguments, a context built by a function whose name ends in
// AAD. A method value (`seal := s.keys.Seal`), a method expression, a func-typed parameter that is
// handed k.Open, or an AAD function that returns a constant were all outside what that reading could
// judge, and the run-time floor of the keyring refuses only an empty context, so a constant one
// opened a ciphertext copied into another tenant's row. This file reads the repository through
// go/types (as the health mux rule of round 12 does) and judges three things:
//
//  1. every use of a method of *keyring.Ring outside the keyring is the function of a direct call,
//     and every use is resolved by the type checker (a use that is not resolved is a use the lint
//     cannot judge, which is a failure and not a pass);
//  2. the context of a seal or an open is the result of an AAD function that, by its declaration,
//     takes the row's identity (a uuid.UUID, or one of the listed exceptions), returns []byte, and
//     uses every parameter, or a variable that holds only such results and is never written after;
//  3. the (domain, label) pair of the labelled operations is read from constant values, not from the
//     name of an identifier.

// ringMethodNames are the six operations of *keyring.Ring that bind a value to a key.
func ringMethodNames() map[string]bool {
	return map[string]bool{"Seal": true, "Open": true, "SealLabeled": true, "OpenLabeled": true, "MAC": true, "VerifyMAC": true}
}

const keyringPkg = module + "/internal/keyring"

// aadWithoutRowID lists the AAD functions that take no uuid.UUID, each with the reason. A function
// stays on the list only while it takes none: a new one needs a reviewer.
var aadWithoutRowID = map[string]string{
	"otpAAD": "an OTP delivery payload is sealed before any row of its own exists and is bound to the phone and the purpose the challenge row holds (spec 5.2)",
}

// ringUse is one use of a method of *keyring.Ring outside the keyring.
type ringUse struct {
	f    file
	sel  *ast.SelectorExpr
	call *ast.CallExpr // set when sel is the function of this call, nil for a method value or expression
	name string
}

// declRef is a function declaration with the file it is in.
type declRef struct {
	fd *ast.FuncDecl
	f  file
}

// keyringWorld is the repository read once through the type checker.
type keyringWorld struct {
	fset  *token.FileSet
	files []file
	info  *types.Info
	decls map[token.Pos]declRef
	uses  []ringUse
	// unresolved are selectors named like a ring method whose type the checker could not give.
	unresolved []unresolvedUse
	aadVars    map[types.Object]bool
	flow       flowFacts
}

type unresolvedUse struct {
	f    file
	sel  *ast.SelectorExpr
	name string
}

// ringMethod says whether sel selects one of the six methods of keyring.Ring, however it got there
// (declared on Ring, or promoted through an embedded field).
func ringMethod(info *types.Info, sel *ast.SelectorExpr) (string, bool) {
	s := info.Selections[sel]
	if s == nil || (s.Kind() != types.MethodVal && s.Kind() != types.MethodExpr) {
		return "", false
	}
	fn, ok := s.Obj().(*types.Func)
	if !ok || fn.Pkg() == nil || fn.Pkg().Path() != keyringPkg || !ringMethodNames()[fn.Name()] {
		return "", false
	}
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return "", false
	}
	t := sig.Recv().Type()
	if p, ok := t.(*types.Pointer); ok {
		t = p.Elem()
	}
	if n, ok := t.(*types.Named); ok && n.Obj().Name() == "Ring" {
		return fn.Name(), true
	}
	return "", false
}

// newKeyringWorld reads every non-test file of the module (the files are already parsed).
func newKeyringWorld(fset *token.FileSet, files []file) (*keyringWorld, bool) {
	info, ok := typeInfoReal(fset, files)
	if !ok {
		return nil, false
	}
	w := &keyringWorld{fset: fset, files: files, info: info, decls: map[token.Pos]declRef{}}
	for _, f := range files {
		if f.test {
			continue
		}
		for _, d := range f.ast.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok {
				w.decls[fd.Name.Pos()] = declRef{fd, f}
			}
		}
	}
	for _, f := range files {
		if f.test || strings.HasPrefix(f.path, "internal/keyring/") {
			continue
		}
		var stack []ast.Node
		ast.Inspect(f.ast, func(n ast.Node) bool {
			if n == nil {
				stack = stack[:len(stack)-1]
				return true
			}
			if sel, ok := n.(*ast.SelectorExpr); ok {
				if name, ok := ringMethod(info, sel); ok {
					u := ringUse{f: f, sel: sel, name: name}
					i := len(stack) - 1
					for i >= 0 {
						if _, paren := stack[i].(*ast.ParenExpr); !paren {
							break
						}
						i--
					}
					if i >= 0 {
						if c, ok := stack[i].(*ast.CallExpr); ok && unparen(c.Fun) == sel && info.Selections[sel].Kind() == types.MethodVal {
							u.call = c
						}
					}
					w.uses = append(w.uses, u)
				} else if ringMethodNames()[sel.Sel.Name] && info.Selections[sel] == nil && info.Uses[sel.Sel] == nil && !isPackageName(info, sel.X) {
					w.unresolved = append(w.unresolved, unresolvedUse{f, sel, sel.Sel.Name})
				}
			}
			stack = append(stack, n)
			return true
		})
	}
	w.aadVars = w.findAADVars()
	return w, true
}

// isPackageName says whether e names an imported package (os.Open, store.Open): a function of a
// package is never a method of Ring.
func isPackageName(info *types.Info, e ast.Expr) bool {
	id, ok := unparen(e).(*ast.Ident)
	if !ok {
		return false
	}
	_, pkg := info.Uses[id].(*types.PkgName)
	return pkg
}

func (w *keyringWorld) at(n ast.Node) string { return w.fset.Position(n.Pos()).String() }

// shapeProblems fails every use of the named methods that is not a direct call, every selector the
// type checker could not resolve, and every interface outside the keyring that a *keyring.Ring
// would satisfy for one of the names (a value of it reaches Seal with no selector at all).
func (w *keyringWorld) shapeProblems(names map[string]bool) []string {
	var out []string
	for _, u := range w.uses {
		if names[u.name] && u.call == nil {
			out = append(out, w.at(u.sel)+": "+u.name+" of the keyring is used as a method value or expression, not called; the lint judges calls only, so call it where it is used")
		}
	}
	for _, u := range w.unresolved {
		if names[u.name] {
			out = append(out, w.at(u.sel)+": "+u.name+" is selected on a value whose type the lint could not resolve, so it cannot tell whether it is the keyring's; give the value a type the repository declares")
		}
	}
	ring := w.ringMethodTypes()
	// Every interface type written anywhere outside the keyring, named or not: a declared type, an
	// alias of a literal, a literal used as a parameter, a field or a variable type, a type
	// assertion. The earlier reading looked at declared non-alias types only, and the literal
	// `interface{ Seal(...) }` as a parameter type, or `type sealer = interface{...}`, took a
	// *keyring.Ring through a call whose selector belongs to the interface and not to the keyring
	// (round 14, primitives-r14-5). A value gets into an interface only by conversion, and the type
	// it converts to has to be written somewhere in the repository, so reading the types written is
	// reading every way in.
	seen := map[token.Pos]bool{}
	for _, f := range w.files {
		if f.test || strings.HasPrefix(f.path, "internal/keyring/") {
			continue
		}
		ast.Inspect(f.ast, func(n ast.Node) bool {
			lit, ok := n.(*ast.InterfaceType)
			if !ok || seen[lit.Pos()] {
				return true
			}
			seen[lit.Pos()] = true
			tv, ok := w.info.Types[lit]
			if !ok || tv.Type == nil {
				return true
			}
			it, ok := tv.Type.Underlying().(*types.Interface)
			if !ok {
				return true
			}
			for i := range it.NumMethods() {
				m := it.Method(i)
				if rt, ok := ring[m.Name()]; ok && names[m.Name()] && types.Identical(m.Type(), rt) {
					out = append(out, w.at(lit)+": an interface has "+m.Name()+" with the signature of the keyring's, so a *keyring.Ring can be called through it where no lint reads the call")
				}
			}
			return true
		})
	}
	sort.Strings(out)
	return out
}

// ringMethodTypes is the signature of each of the six methods, read from the keyring package the
// checker loaded.
func (w *keyringWorld) ringMethodTypes() map[string]types.Type {
	out := map[string]types.Type{}
	for _, obj := range w.info.Defs {
		tn, ok := obj.(*types.TypeName)
		if !ok || tn.Pkg() == nil || tn.Pkg().Path() != keyringPkg || tn.Name() != "Ring" {
			continue
		}
		ms := types.NewMethodSet(types.NewPointer(tn.Type()))
		for i := range ms.Len() {
			if fn, ok := ms.At(i).Obj().(*types.Func); ok && ringMethodNames()[fn.Name()] {
				out[fn.Name()] = fn.Type()
			}
		}
	}
	return out
}

func (w *keyringWorld) objOf(e ast.Expr) types.Object {
	id, ok := unparen(e).(*ast.Ident)
	if !ok {
		return nil
	}
	if o := w.info.Defs[id]; o != nil {
		return o
	}
	return w.info.Uses[id]
}

// rootObj is the variable an element, slice or field expression writes into.
func (w *keyringWorld) rootObj(e ast.Expr) types.Object {
	for {
		switch x := unparen(e).(type) {
		case *ast.IndexExpr:
			e = x.X
		case *ast.SliceExpr:
			e = x.X
		case *ast.StarExpr:
			e = x.X
		case *ast.SelectorExpr:
			e = x.X
		case *ast.Ident:
			return w.objOf(x)
		default:
			return nil
		}
	}
}

// findAADVars lists the variables that are assigned the result of an AAD function and nothing else,
// and whose bytes are never written after: not by an index or slice assignment, copy, clear or
// append into them, not by a range, an increment, or a taken address. Identity is the type
// checker's object, not the name, so a shadowing variable is its own.
func (w *keyringWorld) findAADVars() map[types.Object]bool {
	good, bad := map[types.Object]bool{}, map[types.Object]bool{}
	for _, f := range w.files {
		if f.test || strings.HasPrefix(f.path, "internal/keyring/") {
			continue
		}
		ast.Inspect(f.ast, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.AssignStmt:
				for i, l := range x.Lhs {
					if id, ok := unparen(l).(*ast.Ident); ok {
						o := w.objOf(id)
						if o == nil {
							continue
						}
						if (x.Tok == token.DEFINE || x.Tok == token.ASSIGN) && len(x.Rhs) == len(x.Lhs) && w.aadCall(x.Rhs[i]) == "" {
							good[o] = true
						} else {
							bad[o] = true
						}
					} else if r := w.rootObj(l); r != nil {
						bad[r] = true
					}
				}
			case *ast.ValueSpec:
				for i, id := range x.Names {
					o := w.objOf(id)
					if o == nil {
						continue
					}
					if len(x.Values) == len(x.Names) && w.aadCall(x.Values[i]) == "" {
						good[o] = true
					} else {
						bad[o] = true
					}
				}
			case *ast.RangeStmt:
				for _, e := range []ast.Expr{x.Key, x.Value} {
					if e == nil {
						continue
					}
					if r := w.rootObj(e); r != nil {
						bad[r] = true
					}
				}
			case *ast.IncDecStmt:
				if r := w.rootObj(x.X); r != nil {
					bad[r] = true
				}
			case *ast.UnaryExpr:
				if x.Op == token.AND {
					if r := w.rootObj(x.X); r != nil {
						bad[r] = true
					}
				}
			case *ast.CallExpr:
				if id, ok := unparen(x.Fun).(*ast.Ident); ok && len(x.Args) > 0 {
					if _, builtin := w.info.Uses[id].(*types.Builtin); builtin && (id.Name == "copy" || id.Name == "clear" || id.Name == "append") {
						if r := w.rootObj(x.Args[0]); r != nil {
							bad[r] = true
						}
					}
				}
			}
			return true
		})
	}
	for o := range bad {
		delete(good, o)
	}
	// A variable that holds a context may be handed to the four operations as their context and to
	// nothing else (round 14, primitives-r14-2). The writes listed above are the writes the lint
	// knew by shape; a helper that rewrites the slice it is given (`reverse(aad)`, `fill(aad)`), a
	// method of a defined byte type, or a closure that stores into it is a write by none of them. So
	// the use is judged and not the write: every other mention of the variable, a read included,
	// makes it a context the lint cannot vouch for, and the call that seals under it fails.
	ctxArg := map[*ast.Ident]bool{}
	for _, u := range w.uses {
		if idx, ok := contextIndex(u.name); ok && u.call != nil && len(u.call.Args) > idx {
			if id, ok := unparen(u.call.Args[idx]).(*ast.Ident); ok {
				ctxArg[id] = true
			}
		}
	}
	for id, o := range w.info.Uses {
		if good[o] && !ctxArg[id] {
			delete(good, o)
		}
	}
	return good
}

// aadCall judges an expression that is meant to be the context of a seal. It returns "" when the
// expression is a call of a well-formed AAD function, and the reason when it is not.
func (w *keyringWorld) aadCall(e ast.Expr) string {
	c, ok := unparen(e).(*ast.CallExpr)
	if !ok {
		return "it is not a call of an AAD function"
	}
	var obj types.Object
	switch fun := unparen(c.Fun).(type) {
	case *ast.Ident:
		obj = w.info.Uses[fun]
	case *ast.SelectorExpr:
		if s := w.info.Selections[fun]; s != nil {
			obj = s.Obj()
		} else {
			obj = w.info.Uses[fun.Sel]
		}
	}
	fn, ok := obj.(*types.Func)
	if !ok {
		return "the callee is not a function the lint can resolve"
	}
	if !strings.HasSuffix(fn.Name(), "AAD") {
		return "the callee " + fn.Name() + " is not named ...AAD"
	}
	d, ok := w.decls[fn.Pos()]
	if !ok {
		return "the AAD function " + fn.Name() + " is not declared in this repository"
	}
	if why := w.aadDeclProblem(d); why != "" {
		return "the AAD function " + fn.Name() + " " + why
	}
	// The arguments are judged one by one by an allow list (round 16, primitives-r16-7). The check
	// of rounds 12 to 15 refused a call only when ALL its arguments were constants, nil or a
	// selector named Nil, so one fixed value next to a real one (rowAAD(tenant, uuid.Nil)), a fixed
	// value that is not named Nil (uuid.UUID{}, uuid.Max, a package-level MustParse) or the same id
	// twice (UserAAD(tenant, tenant)) passed, and each seals every row of a tenant under one
	// context, which a writer of the column copies a ciphertext it knows the plaintext of between.
	// A call with no argument binds nothing: the loop below leaves anyBound false and the call fails.
	//
	// Every argument that is a uuid.UUID is a row's identity and must be bound (a fixed identity
	// makes every row of a tenant one context); the other arguments (a phone, a provider, a label) may
	// be constants, but at least one argument of the call must be bound, or the context is a fixed
	// string. No two bound arguments are the same expression.
	//
	// Which parameter is a uuid.UUID is read from the AAD function's declaration (its import of
	// github.com/google/uuid), because the type checker of this lint does not load third-party
	// packages and cannot type an argument as one.
	uuidParam := aadUUIDParams(d)
	seen, anyBound := map[string]bool{}, false
	for i, a := range c.Args {
		bound := w.argIsRowBound(a)
		anyBound = anyBound || bound
		if i < len(uuidParam) && uuidParam[i] && !bound {
			return "the AAD function " + fn.Name() + " is called with " + types.ExprString(a) + " for a uuid.UUID, which is not a value taken from a variable of the calling function (a constant, a literal, a package-level value or a call that holds none), so it binds the value to no row"
		}
		if !bound {
			continue
		}
		key := w.canon(a, 0)
		if seen[key] {
			return "the AAD function " + fn.Name() + " is called with " + key + " twice, so two of its inputs are one value and the context does not tell the rows of a tenant apart"
		}
		seen[key] = true
	}
	if !anyBound {
		return "the AAD function " + fn.Name() + " is called with fixed values only, which binds the value to no row"
	}
	return ""
}

// aadUUIDParams says, for each parameter of an AAD function in order, whether it is declared as a
// github.com/google/uuid.UUID.
func aadUUIDParams(d declRef) []bool {
	imports := fileImports(d.f.ast)
	var out []bool
	for _, p := range d.fd.Type.Params.List {
		n := max(1, len(p.Names))
		for range n {
			out = append(out, isUUIDType(p.Type, imports))
		}
	}
	return out
}

// argIsRowBound is the allow list for one argument of an AAD call: it must be read from a variable
// that a row supplies, or from a field, element, method or conversion of one, or be a call that is
// handed such a value. A constant, a literal, a function literal, a package-level variable or
// constant (uuid.Nil, uuid.Max, a package-level MustParse) and a call that is given none of them are
// fixed values, and a value that is fixed is the same for every row.
//
// A local variable or a parameter is not bound because it is a variable (round 16, primitives-r16-17:
// `fixed := uuid.Nil; rowAAD(a, fixed)` and a wrapper `func seal(id uuid.UUID)` called with uuid.Nil
// passed that reading). It is judged by where it gets its value, through the type checker's objects:
//   - a local is bound only if EVERY assignment to it (a definition, an assignment, a var with a
//     value, a range over a collection) is bound; a local that is only declared and filled through a
//     pointer (Scan, Unmarshal) is read from outside and is bound;
//   - a parameter of a declared function is bound only if EVERY call that can reach it passes a
//     bound argument for it: a direct call, a call of an interface method of the same name and
//     signature, and, for a function that is also used as a value, a call of a func value of its
//     signature (the same name and signature is an over-approximation, so it is the stricter side).
//     A function that no such call reaches (an entry point, a handler the framework calls) takes its
//     arguments from outside this repository's text, and a value that arrives from outside is not a
//     value written here as a constant, so its parameter is bound;
//   - the receiver and the parameters of a function literal are values the enclosing code or the
//     store hands in from a row, and are bound;
//   - a call of a function or method that this repository declares and that returns a uuid.UUID is bound
//     only if every value the declaration returns in that position is bound (so a method that returns
//     a constant is as fixed as the constant); a library function, an interface method and a func
//     value are judged by their receiver and arguments only.
//
// Two arguments that are the same value are found through copies: a local that is only a copy of an
// expression is replaced by it before the arguments are compared (`t := tenant; UserAAD(t, tenant)`).
// What is not found is two values that are equal at run time and written as different expressions
// (two rows read twice from one query); the AAD function's own declaration check and the review of
// the call stand there.
func (w *keyringWorld) argIsRowBound(e ast.Expr) bool {
	return w.argBound(e, newBindMemo())
}

func (w *keyringWorld) argBound(e ast.Expr, memo *bindMemo) bool {
	e = unparen(e)
	if tv, ok := w.info.Types[e]; ok && tv.Value != nil {
		return false
	}
	switch x := e.(type) {
	case *ast.Ident:
		v, ok := w.info.Uses[x].(*types.Var)
		// A package-level variable has the package scope as its parent; a field has none.
		if !ok || v.IsField() || v.Parent() == nil || v.Pkg() == nil || v.Parent() == v.Pkg().Scope() {
			return false
		}
		return w.varBound(v, memo)
	case *ast.SelectorExpr:
		if isPackageName(w.info, x.X) {
			return false
		}
		return w.argBound(x.X, memo)
	case *ast.StarExpr:
		return w.argBound(x.X, memo)
	case *ast.IndexExpr:
		return w.argBound(x.X, memo)
	case *ast.SliceExpr:
		return w.argBound(x.X, memo)
	case *ast.UnaryExpr:
		return w.argBound(x.X, memo)
	case *ast.CompositeLit:
		// A struct or array built from variables carries what they hold; a literal of constants
		// (uuid.UUID{}, uuid.UUID{1, 2, ...}) is fixed.
		for _, el := range x.Elts {
			if kv, ok := el.(*ast.KeyValueExpr); ok {
				el = kv.Value
			}
			if w.argBound(el, memo) {
				return true
			}
		}
		return false
	case *ast.CallExpr:
		if tv, ok := w.info.Types[x.Fun]; ok && tv.IsType() {
			return len(x.Args) == 1 && w.argBound(x.Args[0], memo)
		}
		if w.freshID(x) {
			return true
		}
		if bound, judged := w.resultsBound(x, memo); judged {
			return bound
		}
		if w.uuidMust(x) {
			return len(x.Args) == 1 && w.argBound(x.Args[0], memo)
		}
		if sel, ok := unparen(x.Fun).(*ast.SelectorExpr); ok && !isPackageName(w.info, sel.X) && w.argBound(sel.X, memo) {
			return true
		}
		for _, a := range x.Args {
			if w.argBound(a, memo) {
				return true
			}
		}
		return false
	}
	return false
}

// uuidFunc names a function of github.com/google/uuid called as uuid.X(...), or "".
func (w *keyringWorld) uuidFunc(c *ast.CallExpr) string {
	sel, ok := unparen(c.Fun).(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	id, ok := unparen(sel.X).(*ast.Ident)
	if !ok {
		return ""
	}
	pn, ok := w.info.Uses[id].(*types.PkgName)
	if !ok || pn.Imported().Path() != "github.com/google/uuid" {
		return ""
	}
	return sel.Sel.Name
}

// freshID says whether c is one of the generators of github.com/google/uuid that return a new random
// or time-ordered value on every call. An id made in Go before the insert (the outbox row, a
// gateway) is the identity of its own row: it differs from every other row's, which is what the seal
// context needs. The list is closed; a function that parses or builds a fixed value (MustParse,
// FromBytes, NewSHA1, NewMD5, the Nil and Max values) is not on it.
func (w *keyringWorld) freshID(c *ast.CallExpr) bool {
	switch w.uuidFunc(c) {
	case "New", "NewRandom", "NewRandomFromReader", "NewV6", "NewV7":
		return true
	}
	return false
}

// uuidMust says whether c is uuid.Must(x), whose result is as bound as x.
func (w *keyringWorld) uuidMust(c *ast.CallExpr) bool { return w.uuidFunc(c) == "Must" }

// bindMemo is the state of one judgement: the answer for each variable (nil while it is being judged)
// and the declared functions whose results are being judged.
type bindMemo struct {
	vars  map[*types.Var]*bool
	funcs map[token.Pos]bool
}

func newBindMemo() *bindMemo {
	return &bindMemo{vars: map[*types.Var]*bool{}, funcs: map[token.Pos]bool{}}
}

// resultsBound judges a call of a function or method declared in this repository whose results
// include a uuid.UUID: the call is bound only if every value the declaration returns in that
// position is (round 16 fix gate, primitives-r16-17: a method of a variable that returns a constant
// is as fixed as the constant). judged is false for a callee the repository does not declare (a
// library, an interface method, a func value) and for one that returns no uuid.UUID, which keep the
// rule that a call is bound when it is handed a bound value.
func (w *keyringWorld) resultsBound(c *ast.CallExpr, memo *bindMemo) (bound, judged bool) {
	fn, ok := w.calleeObj(c.Fun).(*types.Func)
	if !ok {
		return false, false
	}
	d, ok := w.decls[fn.Origin().Pos()]
	if !ok || d.fd.Body == nil || d.fd.Type.Results == nil {
		return false, false
	}
	imports := fileImports(d.f.ast)
	var idx []int
	i := 0
	for _, r := range d.fd.Type.Results.List {
		for range max(1, len(r.Names)) {
			if isUUIDType(r.Type, imports) {
				idx = append(idx, i)
			}
			i++
		}
	}
	nres := i
	if len(idx) == 0 {
		return false, false
	}
	if memo.funcs[fn.Origin().Pos()] {
		return true, true // a function met again while it is being judged rests on its other returns
	}
	memo.funcs[fn.Origin().Pos()] = true
	defer delete(memo.funcs, fn.Origin().Pos())
	bound = true
	ast.Inspect(d.fd.Body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.ReturnStmt:
			switch {
			case len(x.Results) == 0:
				// A naked return gives the named results as the body left them.
			case len(x.Results) == 1 && nres > 1:
				bound = bound && w.argBound(x.Results[0], memo) // return f(): the call's own judgement
			default:
				for _, k := range idx {
					if k < len(x.Results) && !w.argBound(x.Results[k], memo) {
						bound = false
					}
				}
			}
		}
		return true
	})
	return bound, true
}

// canon is the text of an expression with every local variable that is only a copy of another
// expression replaced by that expression, and every variable named by its declaration, so two
// spellings of one value (`t := tenant; UserAAD(t, tenant)`) and two variables of one name in
// different scopes are told right.
func (w *keyringWorld) canon(e ast.Expr, depth int) string {
	e = unparen(e)
	switch x := e.(type) {
	case *ast.Ident:
		if v, ok := w.info.Uses[x].(*types.Var); ok && !v.IsField() {
			w.flow.once.Do(w.buildFlow)
			if _, isParam := w.flow.params[v]; !isParam && len(w.flow.assigns[v]) == 1 && depth < 16 {
				switch unparen(w.flow.assigns[v][0]).(type) {
				case *ast.Ident, *ast.SelectorExpr, *ast.StarExpr, *ast.IndexExpr, *ast.CallExpr:
					return w.canon(w.flow.assigns[v][0], depth+1)
				}
			}
			return fmt.Sprintf("%s#%d", x.Name, v.Pos())
		}
		return x.Name
	case *ast.SelectorExpr:
		return w.canon(x.X, depth) + "." + x.Sel.Name
	case *ast.StarExpr:
		return "*" + w.canon(x.X, depth)
	case *ast.IndexExpr:
		return w.canon(x.X, depth) + "[" + types.ExprString(x.Index) + "]"
	case *ast.CallExpr:
		var parts []string
		for _, a := range x.Args {
			parts = append(parts, w.canon(a, depth))
		}
		return w.canon(x.Fun, depth) + "(" + strings.Join(parts, ",") + ")"
	}
	return types.ExprString(e)
}

// varBound judges a local variable or parameter by where its value comes from. A variable met again
// while it is being judged (a loop, a recursive call) is assumed bound: the answer then rests on the
// other assignments, and a cycle alone supplies no fixed value.
func (w *keyringWorld) varBound(v *types.Var, memo *bindMemo) bool {
	if r, ok := memo.vars[v]; ok {
		return r == nil || *r
	}
	memo.vars[v] = nil
	res := w.varBoundUncached(v, memo)
	memo.vars[v] = &res
	return res
}

func (w *keyringWorld) varBoundUncached(v *types.Var, memo *bindMemo) bool {
	w.flow.once.Do(w.buildFlow)
	if p, ok := w.flow.params[v]; ok {
		calls := append([]*ast.CallExpr(nil), w.flow.calls[p.fn]...)
		if p.sig != "" {
			calls = append(calls, w.flow.viaIface[p.sig]...)
			if w.flow.asValue[p.fn] {
				calls = append(calls, w.flow.viaValue[p.sig]...)
			}
		}
		for _, c := range calls {
			if p.idx >= len(c.Args) || (len(c.Args) == 1 && p.count > 1) {
				return false
			}
			if !w.argBound(c.Args[p.idx], memo) {
				return false
			}
		}
		return true
	}
	for _, rhs := range w.flow.assigns[v] {
		if !w.argBound(rhs, memo) {
			return false
		}
	}
	return true
}

// paramRef says which parameter of which declared function a variable is.
type paramRef struct {
	fn         types.Object
	idx, count int
	sig        string // name and signature without receiver, for a method; signature for a function
}

// flowFacts is what varBound reads: for every variable the expressions assigned to it, for every
// parameter of a declared function its position, and for every declared function the calls that name
// it and whether it is also used as a value (a method value, a function handed on), which hides
// callers.
type flowFacts struct {
	once    sync.Once
	assigns map[*types.Var][]ast.Expr
	params  map[*types.Var]paramRef
	calls   map[types.Object][]*ast.CallExpr
	asValue map[types.Object]bool
	// viaIface are the calls of an interface method, keyed by "name signature"; viaValue the calls
	// of a func value, keyed by signature.
	viaIface map[string][]*ast.CallExpr
	viaValue map[string][]*ast.CallExpr
}

// sigKey is a signature without its receiver, as text.
func sigKey(sig *types.Signature) string {
	return types.NewSignatureType(nil, nil, nil, sig.Params(), sig.Results(), sig.Variadic()).String()
}

// calleeObj resolves the function a call names, through a selector, a parenthesis or an explicit
// instantiation, or nil.
func (w *keyringWorld) calleeObj(fun ast.Expr) types.Object {
	for {
		switch f := unparen(fun).(type) {
		case *ast.IndexExpr:
			fun = f.X
			continue
		case *ast.IndexListExpr:
			fun = f.X
			continue
		case *ast.Ident:
			return w.info.Uses[f]
		case *ast.SelectorExpr:
			if s := w.info.Selections[f]; s != nil {
				return s.Obj()
			}
			return w.info.Uses[f.Sel]
		}
		return nil
	}
}

func (w *keyringWorld) buildFlow() {
	fl := &w.flow
	fl.assigns = map[*types.Var][]ast.Expr{}
	fl.params = map[*types.Var]paramRef{}
	fl.calls = map[types.Object][]*ast.CallExpr{}
	fl.asValue = map[types.Object]bool{}
	fl.viaIface = map[string][]*ast.CallExpr{}
	fl.viaValue = map[string][]*ast.CallExpr{}
	varOf := func(e ast.Expr) *types.Var {
		id, ok := unparen(e).(*ast.Ident)
		if !ok {
			return nil
		}
		o := w.info.Defs[id]
		if o == nil {
			o = w.info.Uses[id]
		}
		v, _ := o.(*types.Var)
		return v
	}
	add := func(l ast.Expr, rhs ast.Expr) {
		if v := varOf(l); v != nil {
			fl.assigns[v] = append(fl.assigns[v], rhs)
		}
	}
	direct := map[types.Object]int{}
	for _, f := range w.files {
		if f.test {
			continue
		}
		ast.Inspect(f.ast, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.FuncDecl:
				fo := w.info.Defs[x.Name]
				if fo == nil || x.Type.Params == nil {
					return true
				}
				sigKeyOf := ""
				if sig, ok := fo.Type().(*types.Signature); ok {
					sigKeyOf = sigKey(sig)
					if sig.Recv() != nil {
						sigKeyOf = fo.Name() + " " + sigKeyOf
					}
				}
				count := 0
				for _, p := range x.Type.Params.List {
					count += max(1, len(p.Names))
				}
				i := 0
				for _, p := range x.Type.Params.List {
					if len(p.Names) == 0 {
						i++
						continue
					}
					for _, name := range p.Names {
						if v, ok := w.info.Defs[name].(*types.Var); ok {
							fl.params[v] = paramRef{fo, i, count, sigKeyOf}
						}
						i++
					}
				}
			case *ast.CallExpr:
				if fo, ok := w.calleeObj(x.Fun).(*types.Func); ok {
					fo = fo.Origin()
					fl.calls[fo] = append(fl.calls[fo], x)
					direct[fo]++
					if sig, ok := fo.Type().(*types.Signature); ok && sig.Recv() != nil {
						if _, iface := sig.Recv().Type().Underlying().(*types.Interface); iface {
							k := fo.Name() + " " + sigKey(sig)
							fl.viaIface[k] = append(fl.viaIface[k], x)
						}
					}
				} else if tv, ok := w.info.Types[x.Fun]; ok && !tv.IsType() && !tv.IsBuiltin() {
					if sig, ok := tv.Type.Underlying().(*types.Signature); ok {
						fl.viaValue[sigKey(sig)] = append(fl.viaValue[sigKey(sig)], x)
					}
				}
			case *ast.AssignStmt:
				for i, l := range x.Lhs {
					switch {
					case len(x.Rhs) == len(x.Lhs):
						add(l, x.Rhs[i])
					case len(x.Rhs) == 1:
						add(l, x.Rhs[0])
					}
				}
			case *ast.ValueSpec:
				for i, name := range x.Names {
					switch {
					case len(x.Values) == len(x.Names):
						add(name, x.Values[i])
					case len(x.Values) == 1:
						add(name, x.Values[0])
					}
				}
			case *ast.RangeStmt:
				for _, e := range []ast.Expr{x.Key, x.Value} {
					if e != nil {
						add(e, x.X)
					}
				}
			}
			return true
		})
	}
	// Every use of a declared function that is not the function of a direct call is a use as a value.
	for _, o := range w.info.Uses {
		if fo, ok := o.(*types.Func); ok {
			direct[fo.Origin()]--
		}
	}
	for o, n := range direct {
		if n != 0 {
			fl.asValue[o] = true
		}
	}
}

// aadDeclProblem judges the declaration of an AAD function: what it takes, what it gives, and that
// every parameter reaches the bytes it returns.
//
// The body is one return statement and nothing else (round 14, primitives-r14-2 and -4). The earlier
// reading collected the names of every identifier in the body and called a parameter used when its
// name occurred, so `_ = id; return []byte("x")`, a comparison, a shadowing local or a field of the
// same name passed with a constant result. A function that only returns an expression has nowhere to
// hide a blank use, a second return or a local that rewrites the result, and the question "does the
// parameter reach the result" is then read from the checker's own objects. Round 15
// (primitives-r15-2): the returned expression is judged by an allow list (aadExprProblem), not by a
// list of shapes to refuse. It may be made of constant strings, parameters, +, append, string and
// []byte conversions, p[:] and uuid.UUID.String(), and nothing else; a call of any other function
// (one that drops its argument), a bounded slice (cut to nothing), another method of the id (the
// same number for every row) or an index is a shape the rule has not read, and it fails closed.
// Each parameter object must then be carried by that expression, and a parameter that is not, or
// a function the rule cannot read, fails.
func (w *keyringWorld) aadDeclProblem(d declRef) string {
	fd := d.fd
	if fd.Body == nil {
		return "has no body"
	}
	res := fd.Type.Results
	if res == nil || len(res.List) != 1 || len(res.List[0].Names) > 1 || !isByteSlice(res.List[0].Type) {
		return "does not return exactly one []byte"
	}
	imports := fileImports(d.f.ast)
	var params []*ast.Ident
	rowID := false
	for _, p := range fd.Type.Params.List {
		if len(p.Names) == 0 {
			return "has an unnamed parameter, which it cannot use"
		}
		params = append(params, p.Names...)
		if sel, ok := p.Type.(*ast.SelectorExpr); ok && sel.Sel.Name == "UUID" {
			if id, ok := sel.X.(*ast.Ident); ok && imports[id.Name] == "github.com/google/uuid" {
				rowID = true
			}
		}
	}
	if len(params) == 0 {
		return "takes no parameter, so it returns the same bytes for every row"
	}
	if !rowID {
		if _, listed := aadWithoutRowID[fd.Name.Name]; !listed {
			return "takes no uuid.UUID (the row's identity) and is not in aadWithoutRowID"
		}
	}
	if len(fd.Body.List) != 1 {
		return "is not one return statement: an AAD function returns an expression of its parameters and does nothing else"
	}
	ret, ok := fd.Body.List[0].(*ast.ReturnStmt)
	if !ok || len(ret.Results) != 1 {
		return "is not one return statement of one expression"
	}
	// The expression is judged by an allow list that fails closed (round 15, primitives-r15-2). The
	// rounds before judged it by a deny list of shapes (a func literal, a comparison, len), and each
	// round a new shape slipped through: a call of a function that drops its argument, a slice cut to
	// nothing, a method of the id that returns the same number for every row. What binds a context to
	// its row is the bytes of the parameters, so the expression may be made of those bytes and of
	// constants, joined, converted and appended, and of nothing else.
	paramType := map[types.Object]ast.Expr{}
	for _, p := range fd.Type.Params.List {
		for _, n := range p.Names {
			if o := w.info.Defs[n]; o != nil {
				paramType[o] = p.Type
			}
		}
	}
	reached := map[types.Object]bool{}
	if why := w.aadExprProblem(ret.Results[0], paramType, imports, reached); why != "" {
		return "returns an expression the rule cannot read (" + why + "): an AAD function returns only its parameters' bytes, constants, + , append, []byte and string conversions, p[:] and uuid.UUID.String()"
	}
	for _, p := range params {
		o := w.info.Defs[p]
		if p.Name == "_" || o == nil {
			return "ignores a parameter (a blank one), so two rows can give the same bytes"
		}
		if !reached[o] {
			return "does not return anything built from its parameter " + p.Name + ", so two rows can give the same bytes"
		}
	}
	return ""
}

func isByteSlice(e ast.Expr) bool {
	at, ok := e.(*ast.ArrayType)
	if !ok || at.Len != nil {
		return false
	}
	id, ok := at.Elt.(*ast.Ident)
	return ok && (id.Name == "byte" || id.Name == "uint8")
}

// contextIndex is the position of the context argument of the four operations that take one.
func contextIndex(name string) (int, bool) {
	switch name {
	case "Seal", "Open":
		return 1, true
	case "SealLabeled", "OpenLabeled":
		return 2, true
	}
	return 0, false
}

// stringConst reads the constant string value of an argument, whatever it is spelled as.
func (w *keyringWorld) stringConst(e ast.Expr) (string, bool) {
	tv, ok := w.info.Types[e]
	if !ok || tv.Value == nil || tv.Value.Kind() != constant.String {
		return "", false
	}
	return constant.StringVal(tv.Value), true
}

// aadExprProblem judges one expression of an AAD function's return against the allow list and
// records the parameters whose bytes it carries. It returns "" for an expression made only of:
//
//   - a constant string;
//   - a parameter;
//   - a + of two allowed expressions;
//   - a conversion to string or []byte of one allowed expression;
//   - append of allowed expressions;
//   - p[:] of a parameter with no bounds (a bound could cut the bytes to nothing);
//   - p.String() of a parameter of type uuid.UUID (the one method whose result is the whole id).
//
// Anything else (a call of any other function, a method, an index, a composite literal, a slice
// with a bound, a comparison) returns its kind, so a shape nobody thought of fails and a reviewer
// adds it here on purpose.
func (w *keyringWorld) aadExprProblem(e ast.Expr, params map[types.Object]ast.Expr, imports map[string]string, reached map[types.Object]bool) string {
	e = unparen(e)
	if tv, ok := w.info.Types[e]; ok && tv.Value != nil {
		if tv.Value.Kind() == constant.String {
			return ""
		}
		return "a constant that is not a string"
	}
	param := func(x ast.Expr) (types.Object, bool) {
		id, ok := unparen(x).(*ast.Ident)
		if !ok {
			return nil, false
		}
		o := w.info.Uses[id]
		_, isParam := params[o]
		return o, o != nil && isParam
	}
	switch x := e.(type) {
	case *ast.Ident:
		if o, ok := param(x); ok {
			reached[o] = true
			return ""
		}
		return "the name " + x.Name + " is not a parameter"
	case *ast.BinaryExpr:
		if x.Op != token.ADD {
			return "an operator other than +"
		}
		if why := w.aadExprProblem(x.X, params, imports, reached); why != "" {
			return why
		}
		return w.aadExprProblem(x.Y, params, imports, reached)
	case *ast.SliceExpr:
		o, ok := param(x.X)
		if !ok || x.Low != nil || x.High != nil || x.Max != nil {
			return "a slice that is not p[:] of a parameter"
		}
		reached[o] = true
		return ""
	case *ast.CallExpr:
		if tv, ok := w.info.Types[x.Fun]; ok && tv.IsType() {
			if len(x.Args) != 1 || !stringOrBytes(tv.Type) {
				return "a conversion to something other than string or []byte"
			}
			return w.aadExprProblem(x.Args[0], params, imports, reached)
		}
		if id, ok := unparen(x.Fun).(*ast.Ident); ok {
			if _, builtin := w.info.Uses[id].(*types.Builtin); builtin && id.Name == "append" {
				for _, a := range x.Args {
					if why := w.aadExprProblem(a, params, imports, reached); why != "" {
						return why
					}
				}
				return ""
			}
		}
		if sel, ok := unparen(x.Fun).(*ast.SelectorExpr); ok && sel.Sel.Name == "String" && len(x.Args) == 0 {
			if o, ok := param(sel.X); ok && isUUIDType(params[o], imports) {
				reached[o] = true
				return ""
			}
		}
		return "a call of a function or method that is not on the list"
	}
	return fmt.Sprintf("%T", e)
}

// stringOrBytes says whether t is string or []byte, the two conversions an AAD function may make.
func stringOrBytes(t types.Type) bool {
	switch u := t.Underlying().(type) {
	case *types.Basic:
		return u.Kind() == types.String
	case *types.Slice:
		b, ok := u.Elem().Underlying().(*types.Basic)
		return ok && b.Kind() == types.Uint8
	}
	return false
}

// isUUIDType says whether a parameter's declared type is github.com/google/uuid.UUID, read from the
// import and not from the name, so a local type called UUID is not one.
func isUUIDType(t ast.Expr, imports map[string]string) bool {
	sel, ok := t.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "UUID" {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && imports[id.Name] == "github.com/google/uuid"
}
