package closed_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/closed"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
)

type colour string

func (c colour) Valid() bool { return c == "red" || c == "green" }

type noValid string

type wrongValid string

func (wrongValid) Valid() int { return 1 }

type opaque struct{ s string }

func (opaque) ClosedOpaque() {}

func TestCheckType(t *testing.T) {
	type ok struct {
		C  colour
		Cs []colour
		N  int
		U  uint8
		B  bool
		ID uuid.UUID
		O  opaque
	}
	if err := closed.CheckType(reflect.TypeOf(ok{})); err != nil {
		t.Fatalf("a record of closed kinds was refused: %v", err)
	}
	if err := closed.CheckType(reflect.TypeOf(&ok{})); err != nil {
		t.Fatalf("a pointer to one was refused: %v", err)
	}
	for name, v := range map[string]any{
		"plain string":        struct{ Note string }{},
		"string slice":        struct{ Notes []string }{},
		"named, no Valid":     struct{ X noValid }{},
		"Valid of wrong type": struct{ X wrongValid }{},
		"map":                 struct{ M map[string]colour }{},
		"interface":           struct{ A any }{},
		"byte slice":          struct{ B []byte }{},
		"secret string":       struct{ S secret.String }{},
		"secret bytes":        struct{ S secret.Bytes }{},
		"float":               struct{ F float64 }{},
		"time":                struct{ T time.Time }{},
		"nested struct":       struct{ S struct{ C colour } }{},
		"pointer field":       struct{ P *colour }{},
		"unexported":          struct{ c colour }{},
		"array of strings":    struct{ A [2]string }{},
		"slice of slices":     struct{ S [][]string }{},
	} {
		if closed.CheckType(reflect.TypeOf(v)) == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if closed.CheckType(reflect.TypeOf(1)) == nil {
		t.Error("a non-struct was accepted")
	}
}

func TestCheckValueAndMarshal(t *testing.T) {
	type rec struct {
		C  colour   `json:"c"`
		Cs []colour `json:"cs"`
		N  int      `json:"n"`
	}
	good := rec{C: "red", Cs: []colour{"green", "red"}, N: 3}
	b, err := closed.Marshal(good)
	if err != nil || string(b) != `{"c":"red","cs":["green","red"],"n":3}` {
		t.Fatalf("%s %v", b, err)
	}
	if _, err := closed.Marshal(&good); err != nil {
		t.Fatalf("pointer: %v", err)
	}
	for name, v := range map[string]rec{
		"off the list":   {C: "09121234567"},
		"empty":          {C: ""},
		"in a slice":     {C: "red", Cs: []colour{"red", "blue 09121234567"}},
		"script variant": {C: "red", Cs: []colour{"०९१२१२३४५६७"}},
	} {
		_, err := closed.Marshal(v)
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if strings.Contains(err.Error(), "912") || strings.Contains(err.Error(), "blue") {
			t.Errorf("%s: the error repeats the value: %v", name, err)
		}
	}
	if _, err := closed.Marshal(struct{ Note string }{"x"}); err == nil {
		t.Error("a plain string field was marshalled")
	}
	// HTML is not escaped: the stored text is the plain value.
	type html struct {
		P colour `json:"p"`
	}
	if b, _ := closed.Marshal(html{"red"}); string(b) != `{"p":"red"}` {
		t.Errorf("%s", b)
	}
}

type word string

func (w word) String() string { return string(w) }
func (word) Valid() bool      { return true }

type badWord string

func (w badWord) String() string { return string(w) }
func (badWord) Valid() bool      { return false }

func TestKeyAndParams(t *testing.T) {
	id := uuid.MustParse("11111111-2222-3333-4444-555555555555")
	k := closed.NewKey(closed.ID(id), word("auth"), closed.HourOf(time.Date(2026, 11, 9, 14, 59, 1, 0, time.UTC)))
	if k.String() != "11111111-2222-3333-4444-555555555555:auth:2026-11-09T14" {
		t.Errorf("key %q", k)
	}
	if closed.NewKey(word("a"), badWord("09121234567")).String() != "" {
		t.Error("a key with a part off its list must be empty")
	}
	if closed.NewKey().String() != "" {
		t.Error("a key with no part is empty, which the store refuses")
	}
	if string(closed.Params{}.JSON()) != "{}" {
		t.Error("zero Params is {}")
	}
	p, err := closed.NewParams(struct {
		C colour `json:"c"`
	}{"red"})
	if err != nil || string(p.JSON()) != `{"c":"red"}` {
		t.Errorf("%s %v", p.JSON(), err)
	}
	// JSON returns a copy.
	j := p.JSON()
	j[0] = 'X'
	if string(p.JSON()) != `{"c":"red"}` {
		t.Error("Params can be changed through the slice JSON returned")
	}
}

type leakyOpaque struct{ Text string }

func (leakyOpaque) ClosedOpaque() {}

type namedOpaque string

func (namedOpaque) ClosedOpaque() {}
func (namedOpaque) Valid() bool   { return true }

// TestOpaqueIsCheckedNotTrusted (primitives-r5-3): the escape hatch accepts a struct whose
// fields are all unexported and nothing else, so declaring ClosedOpaque on a type with an
// exported string, or on a named string, no longer lets free text into a record.
func TestOpaqueIsCheckedNotTrusted(t *testing.T) {
	for name, v := range map[string]any{
		"exported string field": struct{ N leakyOpaque }{},
		"named string":          struct{ N namedOpaque }{},
		"pointer to a leak":     struct{ N *leakyOpaque }{},
	} {
		if err := closed.CheckType(reflect.TypeOf(v)); err == nil {
			t.Errorf("%s: an Opaque type that can hold text was accepted", name)
		}
	}
	if err := closed.CheckType(reflect.TypeOf(struct{ N opaque }{})); err != nil {
		t.Errorf("a struct of unexported fields was refused: %v", err)
	}
}

// TestOpaqueTypesAreTheKnownOnes: the set of types that declare ClosedOpaque in the module
// is a reviewed list. A new one must be added here by someone who read its constructor,
// because the check above cannot see what a constructor puts in an unexported field.
func TestOpaqueTypesAreTheKnownOnes(t *testing.T) {
	root := filepath.Join("..", "..")
	var found []string
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", ".codegraph", "web":
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, p, nil, parser.SkipObjectResolution)
		if err != nil {
			return nil // a generated or broken file is not this test's business
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || fn.Name.Name != "ClosedOpaque" || len(fn.Recv.List) == 0 {
				continue
			}
			typ := fn.Recv.List[0].Type
			if star, ok := typ.(*ast.StarExpr); ok {
				typ = star.X
			}
			if id, ok := typ.(*ast.Ident); ok {
				found = append(found, filepath.ToSlash(filepath.Dir(p))+"."+id.Name)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(found)
	want := []string{"../../internal/auth/audit.Masked"}
	if strings.Join(found, ",") != strings.Join(want, ",") {
		t.Fatalf("types that declare ClosedOpaque: %v, reviewed list: %v", found, want)
	}
}

// sms-r17-23: CheckFields judges every field, the unexported ones too, by the same kinds as CheckType.
func TestCheckFieldsJudgesTheUnexportedFieldsToo(t *testing.T) {
	type ok struct {
		C colour
		c colour
		n int
		o opaque
	}
	if err := closed.CheckFields(reflect.TypeOf(ok{})); err != nil {
		t.Fatalf("a struct of closed kinds, private ones included, was refused: %v", err)
	}
	// CheckType still refuses the private field: it cannot be marshalled, so it is not the whole record.
	if closed.CheckType(reflect.TypeOf(ok{})) == nil {
		t.Error("CheckType accepted an unexported field")
	}
	for name, v := range map[string]any{
		"an unexported plain string":    struct{ note string }{},
		"an unexported named no Valid":  struct{ x noValid }{},
		"an unexported interface":       struct{ a any }{},
		"an unexported map":             struct{ m map[string]colour }{},
		"an exported plain string":      struct{ Note string }{},
		"an unexported byte slice":      struct{ b []byte }{},
		"an unexported nested struct":   struct{ s struct{ C colour } }{},
		"an unexported slice of string": struct{ s []string }{},
	} {
		if closed.CheckFields(reflect.TypeOf(v)) == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if closed.CheckFields(reflect.TypeOf(1)) == nil {
		t.Error("a non-struct was accepted")
	}
}

// A blank field of size zero is the marker that makes a type incomparable (sms-r18-12) and holds no value, so
// the check passes it; a blank field that can hold a value is judged like every other field.
func TestAZeroSizeBlankFieldHoldsNothingAndIsSkipped(t *testing.T) {
	type marked struct {
		_ [0]func()
		C colour
	}
	if err := closed.CheckFields(reflect.TypeOf(marked{})); err != nil {
		t.Fatalf("an incomparability marker was refused: %v", err)
	}
	type blankValue struct {
		_ string
		C colour
	}
	if closed.CheckFields(reflect.TypeOf(blankValue{})) == nil {
		t.Fatal("a blank field that can hold a string was passed")
	}
}
