package adminname_test

import (
	"regexp"
	"testing"
	"unicode/utf8"

	"gopkg.in/yaml.v3"

	"github.com/Kup1ng/CtrlZ-Panel/api"
	"github.com/Kup1ng/CtrlZ-Panel/internal/adminname"
)

// documentPattern is the `content` pattern of the admin OpenAPI document, which is the schema the
// login request is checked against.
func documentPattern(t *testing.T) string {
	t.Helper()
	// The pattern is a YAML anchor (`content: &content ...`) that every string schema reuses.
	var root yaml.Node
	if err := yaml.Unmarshal(api.Admin(), &root); err != nil {
		t.Fatal(err)
	}
	var found string
	var walk func(n *yaml.Node)
	walk = func(n *yaml.Node) {
		if n.Kind == yaml.MappingNode {
			for i := 0; i+1 < len(n.Content); i += 2 {
				if n.Content[i].Value == "content" && n.Content[i+1].Anchor == "content" {
					found = n.Content[i+1].Value
				}
			}
		}
		for _, c := range n.Content {
			walk(c)
		}
	}
	walk(&root)
	if found == "" {
		t.Fatal("api/admin-openapi.yaml has no `content` pattern anchor")
	}
	return found
}

func TestPatternIsTheDocumentsContentPattern(t *testing.T) {
	if got := documentPattern(t); got != adminname.Pattern {
		t.Fatalf("api/admin-openapi.yaml content = %q, adminname.Pattern = %q: the CLI and the login schema would disagree", got, adminname.Pattern)
	}
}

// TestEveryCodePointGetsTheSameVerdictOrAStricterOne walks every code point through both rules, in
// first and in later position. The CLI may refuse more than the schema (a separator inside a name),
// and must never accept what the schema refuses: such a name is an admin that cannot sign in.
func TestEveryCodePointGetsTheSameVerdictOrAStricterOne(t *testing.T) {
	schema := regexp.MustCompile(documentPattern(t))
	stricter := 0
	for r := rune(0); r <= utf8.MaxRune; r++ {
		if r >= 0xD800 && r <= 0xDFFF {
			continue // not a rune a Go string can hold
		}
		for _, name := range []string{string(r) + "admin", "ad" + string(r) + "min"} {
			cli, doc := adminname.Valid(name), schema.MatchString(name)
			if cli && !doc {
				t.Fatalf("U+%04X in %q: ctrlz-admin accepts a username that the login schema refuses", r, name)
			}
			if doc && !cli {
				stricter++
			}
		}
	}
	// The planted cases of the finding: private use and unassigned.
	for _, s := range []string{"ad\U000f0000min", "ad\u0378min", "ad\u200bmin", "ad\u0000min", " admin", "admin ", ""} {
		if adminname.Valid(s) {
			t.Errorf("Valid(%q) is true", s)
		}
	}
	for _, s := range []string{"admin", "admin.root", "مدیر", "a"} {
		if !adminname.Valid(s) {
			t.Errorf("Valid(%q) is false", s)
		}
	}
	if stricter == 0 {
		t.Log("the CLI is exactly the schema")
	}
}
