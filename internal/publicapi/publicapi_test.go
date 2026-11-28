package publicapi_test

import (
	"bytes"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/Kup1ng/CtrlZ-Panel/api"
	"github.com/Kup1ng/CtrlZ-Panel/internal/apispec"
	"github.com/Kup1ng/CtrlZ-Panel/internal/publicapi"
	"github.com/Kup1ng/CtrlZ-Panel/internal/ratelimit"
)

// The committed file is what the generator writes (T-320): an operation cannot join or leave the public API, and a schema it
// reaches cannot change, without the file showing it.
func TestThePublicDocumentIsWhatTheGeneratorWrites(t *testing.T) {
	want, err := publicapi.Generate(api.Tenant())
	if err != nil {
		t.Fatal(err)
	}
	have := bytes.ReplaceAll(api.Public(), []byte("\r\n"), []byte("\n"))
	if !bytes.Equal(have, want) {
		t.Fatal("api/public-openapi.yaml is stale: run `go run ./tools/genpublicapi` and commit the result")
	}
}

func TestThePublicDocumentHoldsExactlyTheTokenOperations(t *testing.T) {
	if err := publicapi.Check(api.Public(), api.Tenant()); err != nil {
		t.Fatal(err)
	}
	// And the same by the apispec reading of the tenant document: every operation with a token is there, and none else.
	ops, err := apispec.Parse(api.Tenant(), ratelimit.Tenant)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := publicapi.Operations(api.Public())
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, op := range ops {
		_, in := pub[op.Key()]
		if (op.Token == "read" || op.Token == "write") != in {
			t.Errorf("%s has x-ctrlz-token %q and is in the public document: %v", op.ID, op.Token, in)
		}
		if in {
			n++
		}
	}
	if n == 0 || n != len(pub) {
		t.Errorf("%d token operations, %d in the public document", n, len(pub))
	}
}

// Every reference of the public document is defined in it, so a renderer needs nothing else, and no extension of the pipeline's
// is left in it except the token value of an operation.
func TestThePublicDocumentIsSelfContained(t *testing.T) {
	var doc map[string]any
	if err := yaml.Unmarshal(api.Public(), &doc); err != nil {
		t.Fatal(err)
	}
	comps := doc["components"].(map[string]any)
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, c := range x {
				if strings.HasPrefix(k, "x-ctrlz-") && k != "x-ctrlz-token" {
					t.Errorf("the public document keeps the extension %s", k)
				}
				if s, ok := c.(string); ok && k == "$ref" {
					rest, ok := strings.CutPrefix(s, "#/components/")
					if !ok {
						t.Errorf("a reference outside the components: %s", s)
						continue
					}
					kind, name, _ := strings.Cut(rest, "/")
					if g, _ := comps[kind].(map[string]any); g[name] == nil {
						t.Errorf("%s is referenced and not defined", s)
					}
					continue
				}
				walk(c)
			}
		case []any:
			for _, c := range x {
				walk(c)
			}
		}
	}
	walk(doc)
	if _, ok := comps["securitySchemes"].(map[string]any)["apiToken"]; !ok {
		t.Error("the bearer security scheme is missing")
	}
	// Nothing of the session API leaks: no schema of a login, and no operation that takes no token.
	for _, banned := range []string{"LoginPasswordRequest", "ReauthRequest", "ChangePasswordRequest", "ApiTokenCreated", "ApiTokenCreate"} {
		if _, ok := comps["schemas"].(map[string]any)[banned]; ok {
			t.Errorf("the public document holds the schema %s", banned)
		}
	}
}

// The check can fail: a none operation in the public document, a token operation missing from it, and a changed kind.
func TestCheckFailsForAWrongPublicDocument(t *testing.T) {
	good := string(api.Public())
	tenant := api.Tenant()
	mutations := map[string]string{
		"a none operation":  strings.Replace(good, "paths:\n", "paths:\n  /auth/login:\n    post:\n      operationId: loginPassword\n      x-ctrlz-token: none\n", 1),
		"a read made write": strings.Replace(good, "x-ctrlz-token: read", "x-ctrlz-token: write", 1),
		"an operation gone": strings.Replace(good, "operationId: getLimits", "operationId: gone", 1),
	}
	for name, doc := range mutations {
		if doc == good {
			t.Fatalf("%s: the mutation changed nothing", name)
		}
		if name == "an operation gone" {
			// Dropping the whole operation: remove its path from the parsed document.
			var m map[string]any
			if err := yaml.Unmarshal([]byte(good), &m); err != nil {
				t.Fatal(err)
			}
			delete(m["paths"].(map[string]any), "/account/limits")
			b, err := yaml.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			doc = string(b)
		}
		if publicapi.Check([]byte(doc), tenant) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestGenerateRefusesADocumentWithNoTokenOperation(t *testing.T) {
	if _, err := publicapi.Generate([]byte("openapi: 3.1.0\npaths:\n  /a:\n    get: {operationId: a, x-ctrlz-token: none}\n")); err == nil {
		t.Error("a document with no token operation was accepted")
	}
}
