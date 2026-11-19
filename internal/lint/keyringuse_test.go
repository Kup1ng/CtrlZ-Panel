package lint_test

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"sort"
	"strings"
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
	// An AAD function called with nothing but constants binds to nothing either.
	allConst := len(c.Args) > 0
	for _, a := range c.Args {
		if tv, ok := w.info.Types[a]; !ok || tv.Value == nil {
			// nil and uuid.Nil are as fixed as a literal.
			isNil := false
			switch x := unparen(a).(type) {
			case *ast.Ident:
				isNil = x.Name == "nil"
			case *ast.SelectorExpr:
				isNil = x.Sel.Name == "Nil"
			}
			if !isNil {
				allConst = false
			}
		}
	}
	if allConst || len(c.Args) == 0 {
		return "the AAD function " + fn.Name() + " is called with constants only, which binds the value to no row"
	}
	return ""
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
