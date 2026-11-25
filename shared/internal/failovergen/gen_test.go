package failovergen

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"encoding/json"
	"github.com/Kup1ng/CtrlZ-Shared/vectors"
)

// The checked-in file is what a fresh run writes (8a.10: shared-verify fails
// when it differs), and every case passes through the real evaluator. The
// first test is the one a regenerate cannot silence: the generator's
// expectations come from its own arithmetic, so a wrong evaluator fails here.
func TestGeneratedCasesPassTheEvaluator(t *testing.T) {
	for _, c := range append(generated(), sequences()...) {
		c := c
		t.Run(c.ID, func(t *testing.T) {
			// The runner reads the case as the file is read, strictly.
			raw, err := json.Marshal(c)
			if err != nil {
				t.Fatal(err)
			}
			var vc vectors.FailoverCase
			dec := json.NewDecoder(bytes.NewReader(raw))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&vc); err != nil {
				t.Fatal(err)
			}
			got, err := vectors.RunFailoverCase(&vc)
			if err != nil {
				t.Fatal(err)
			}
			if msg := vectors.DiffFailoverExpect(vc.Expect, got); msg != "" {
				t.Errorf("%s\n  case: %s", msg, c.Why)
			}
		})
	}
}

func TestCheckedInFileIsFresh(t *testing.T) {
	want, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("..", "..", "vectors", "zone-failover.json")
	have, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run: go run ./cmd/sharedtool failover-vectors --out vectors/zone-failover.json)", err)
	}
	if !bytes.Equal(have, want) {
		t.Fatal("vectors/zone-failover.json differs from a fresh run of the generator; run: go run ./cmd/sharedtool failover-vectors --out vectors/zone-failover.json")
	}
	// The file also decodes strictly, as the runner reads it.
	var f struct {
		Cases []Case `json:"cases"`
	}
	dec := json.NewDecoder(bytes.NewReader(have))
	if err := dec.Decode(&f); err != nil || len(f.Cases) == 0 {
		t.Fatalf("decode: %v", err)
	}
}

// TestGeneratorUsesOnlyTheData: the package may use zone.Rows, zone.Inputs and
// the types and constants those return, and nothing else of zone (8a.10).
// Two ways round a check on the literal text "zone.X" are closed too: the
// import under another name, and a method of a zone type reached through a
// returned value (Inputs().ViewStale.Passed(d) is zone code even though no
// selector in it names the package).
func TestGeneratorUsesOnlyTheData(t *testing.T) {
	allowed := map[string]bool{
		"Rows": true, "Inputs": true, "Row": true, // the data and its type
		"F0": true, "F1": true, "F2": true, "F3": true, "F4": true, "F5": true, "F6": true, "F7": true,
		"AlertFlapping": true,
	}
	const zonePath = "github.com/Kup1ng/CtrlZ-Shared/zone"
	fset := token.NewFileSet()

	// Exported methods declared by zone: a call to one of these names in the
	// generator is zone code. Only calls count, because the generator's own
	// struct fields (c.c.Start) share a few of the names.
	methods := map[string]bool{}
	zfiles, _ := filepath.Glob(filepath.Join("..", "..", "zone", "*.go"))
	for _, name := range zfiles {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv != nil && fd.Name.IsExported() {
				methods[fd.Name.Name] = true
			}
		}
	}
	if !methods["Passed"] {
		t.Fatal("the method list lost zone.Limit.Passed; the scan of zone is broken")
	}

	files, _ := filepath.Glob("*.go")
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		local := ""
		for _, im := range f.Imports {
			if path, _ := strconv.Unquote(im.Path.Value); path != zonePath {
				continue
			}
			local = "zone"
			if im.Name != nil {
				local = im.Name.Name
			}
			if local == "." || local == "_" {
				t.Errorf("%s imports zone as %q, which hides what it uses", name, local)
				local = ""
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.SelectorExpr:
				if id, ok := n.X.(*ast.Ident); ok && local != "" && id.Name == local && !allowed[n.Sel.Name] {
					t.Errorf("%s refers to %s.%s, which is not data", name, local, n.Sel.Name)
				}
			case *ast.CallExpr:
				if sel, ok := n.Fun.(*ast.SelectorExpr); ok && methods[sel.Sel.Name] {
					t.Errorf("%s calls .%s(), a method of a zone type: that is zone code, not data", name, sel.Sel.Name)
				}
			}
			return true
		})
	}
}
