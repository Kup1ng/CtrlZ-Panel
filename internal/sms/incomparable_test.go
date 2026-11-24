package sms_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"reflect"
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/sms"
)

// sms-r18-12: both carriers of the class are incomparable by construction. A comparison of two Status
// values, of two dereferenced Errors, a map keyed by Status and a switch on one all read the class
// without naming a Class operand, which is all the lint of rule sms-failure-classification sees. The
// compiler refuses every one of them for a type that holds a func-typed field, so the property is the
// type's, and this test is what keeps it: a future edit that drops the field fails here and not in a
// round of review.
func TestStatusAndErrorAreIncomparable(t *testing.T) {
	for name, ty := range map[string]reflect.Type{
		"Status": reflect.TypeFor[sms.Status](),
		"Error":  reflect.TypeFor[sms.Error](),
	} {
		if ty.Comparable() {
			t.Errorf("sms.%s is comparable: == , a map key and a switch on it read the class outside classify", name)
		}
	}
	// A pointer to an Error stays comparable: errors.Is compares by pointer, and that reads no class.
	if !reflect.TypeFor[*sms.Error]().Comparable() {
		t.Error("*sms.Error must stay comparable for errors.Is")
	}
}

// sms-r18-19: the types that hold a Class are found in the source and not listed by hand, so a carrier
// added tomorrow (another alert, a result type) fails here until it is incomparable too. Every struct
// type of this package with a field of type Class must be in the table below and incomparable.
func TestEveryTypeThatHoldsAClassIsIncomparable(t *testing.T) {
	known := map[string]reflect.Type{
		"Status":        reflect.TypeFor[sms.Status](),
		"Error":         reflect.TypeFor[sms.Error](),
		"GatewayAlert":  reflect.TypeFor[sms.GatewayAlert](),
		"TemplateAlert": reflect.TypeFor[sms.TemplateAlert](),
	}
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi fs.FileInfo) bool { return !strings.HasSuffix(fi.Name(), "_test.go") }, 0)
	if err != nil {
		t.Fatal(err)
	}
	structs := map[string]*ast.StructType{}
	for _, p := range pkgs {
		for _, f := range p.Files {
			for _, d := range f.Decls {
				if gd, ok := d.(*ast.GenDecl); ok && gd.Tok == token.TYPE {
					for _, s := range gd.Specs {
						if ts := s.(*ast.TypeSpec); ts.Type != nil {
							if st, ok := ts.Type.(*ast.StructType); ok {
								structs[ts.Name.Name] = st
							}
						}
					}
				}
			}
		}
	}
	// A struct holds a Class when a field is one, or an array of them. A struct that holds another carrier
	// by value is incomparable through it (a func-typed field makes every holder incomparable), a slice,
	// map or func field is incomparable anyway, and a pointer compares the address and reads no class.
	holds := map[string]bool{}
	var isClass func(e ast.Expr) bool
	isClass = func(e ast.Expr) bool {
		switch e := e.(type) {
		case *ast.Ident:
			return e.Name == "Class"
		case *ast.ArrayType:
			return e.Len != nil && isClass(e.Elt)
		}
		return false
	}
	for name, st := range structs {
		for _, f := range st.Fields.List {
			if isClass(f.Type) {
				holds[name] = true
			}
		}
	}
	if len(holds) < len(known) {
		t.Fatalf("the source shows %d types that hold a Class, the table %d: the reader is looking at the wrong thing (%v)", len(holds), len(known), holds)
	}
	for name := range holds {
		ty, ok := known[name]
		switch {
		case !ok:
			t.Errorf("sms.%s holds a Class and is not in the table of incomparable types: give it a blank [0]func() field and list it", name)
		case ty.Comparable():
			t.Errorf("sms.%s holds a Class and is comparable", name)
		}
	}
}
