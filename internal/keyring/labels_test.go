package keyring

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
	"time"
)

// TestUsesCoverEveryLabel keeps the registry whole: a Label constant added to
// keyring.go without a Use fails here, and so does a Use whose label is not a
// constant, so the spec table of 8.2 (internal/lint TestSpecFactTables) and the
// operator text cannot miss a label.
func TestUsesCoverEveryLabel(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "keyring.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var consts []string
	ast.Inspect(f, func(n ast.Node) bool {
		if vs, ok := n.(*ast.ValueSpec); ok {
			for _, id := range vs.Names {
				if strings.HasPrefix(id.Name, "Label") {
					consts = append(consts, id.Name)
				}
			}
		}
		return true
	})
	if len(consts) != len(LabelNames()) {
		t.Fatalf("keyring.go declares %d Label constants %v, LabelNames lists %d", len(consts), consts, len(LabelNames()))
	}
	used := map[string]bool{}
	for _, u := range Uses() {
		if u.Label != "" {
			used[u.Label] = true
		}
	}
	for _, l := range LabelNames() {
		if !used[l] {
			t.Errorf("label %q has no entry in Uses", l)
		}
	}
	known := map[string]bool{}
	for _, l := range LabelNames() {
		known[l] = true
	}
	for _, u := range Uses() {
		if u.Label != "" && !known[u.Label] {
			t.Errorf("use of %s names label %q, which is not a constant", u.Domain, u.Label)
		}
	}
}

func TestUsesAreWellFormed(t *testing.T) {
	order := map[string]int{}
	for i, d := range Domains() {
		order[d] = i
	}
	seen := map[string]bool{}
	prevDomain, prevLife := -1, time.Duration(0)
	for _, u := range Uses() {
		if !ValidDomain(u.Domain) || u.What == "" || u.IfRemoved == "" || u.Life <= 0 {
			t.Errorf("malformed use %+v", u)
		}
		k := u.Domain + "/" + u.Label
		if seen[k] {
			t.Errorf("use %s listed twice", k)
		}
		seen[k] = true
		// The spec table and the operator text show this order.
		if order[u.Domain] < prevDomain {
			t.Errorf("use %s is out of domain order", k)
		}
		if order[u.Domain] == prevDomain && u.Life > prevLife {
			t.Errorf("use %s outlives the one before it in its domain", k)
		}
		prevDomain, prevLife = order[u.Domain], u.Life
	}
}

func TestLifeText(t *testing.T) {
	for d, want := range map[time.Duration]string{
		5 * time.Minute: "5 minutes", time.Hour: "1 hour", 8 * time.Hour: "8 hours", 24 * time.Hour: "1 day",
		90 * 24 * time.Hour: "90 days", 365 * 24 * time.Hour: "365 days", 90 * time.Second: "90 seconds", time.Minute: "1 minute",
	} {
		if got := LifeText(d); got != want {
			t.Errorf("LifeText(%v) = %q, want %q", d, got, want)
		}
	}
	got := LongestLife(DomainAdminMAC)
	if got != LifeAdminDevice {
		t.Errorf("longest admin_mac life = %v", got)
	}
}
