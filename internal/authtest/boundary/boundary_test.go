package boundary_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/go-chi/chi/v5"

	"github.com/Kup1ng/CtrlZ-Panel/api"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/digits"
	"github.com/Kup1ng/CtrlZ-Panel/internal/authtest/boundary"
	"github.com/Kup1ng/CtrlZ-Panel/internal/httpx"
)

// The schema half of the boundary-input fuzz (rules.md topic 9): the generated
// requests of every operation of both documents go through httpx.Validator without
// a router, a database or a session, so it runs in a second. The baseline of each
// operation must pass and every other request must be refused, 400 or 413. The
// end-to-end half, through the real servers, is TestBoundaryFuzz in internal/api and
// internal/adminapi.

func request(c boundary.Case) *http.Request {
	var body *bytes.Reader
	if c.Body != nil {
		body = bytes.NewReader(c.Body)
	} else {
		body = bytes.NewReader(nil)
	}
	r := httptest.NewRequest(c.Method, "/api/v1"+c.Path, body)
	for k, v := range c.Header {
		r.Header.Set(k, v)
	}
	rc := chi.NewRouteContext()
	for k, v := range c.PathParams {
		rc.URLParams.Add(k, v)
	}
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rc))
}

func TestEveryGeneratedRequestIsJudgedByTheValidator(t *testing.T) {
	for name, doc := range map[string][]byte{"tenant": api.Tenant(), "admin": api.Admin()} {
		v, err := httpx.NewValidator(doc)
		if err != nil {
			t.Fatal(err)
		}
		cases, err := boundary.Cases(doc)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		baselines, refused := 0, 0
		for _, c := range cases {
			e := v.Check(request(c), c.Key)
			switch {
			case c.Baseline && e != nil:
				t.Errorf("%s %s: the baseline is refused (%d %s): the generator no longer builds a valid request", name, c.Name, e.Status, e.Code)
			case c.Baseline:
				baselines++
			case e == nil:
				t.Errorf("%s %s: accepted, want 400 or 413", name, c.Name)
			case e.Status != http.StatusBadRequest && e.Status != http.StatusRequestEntityTooLarge:
				t.Errorf("%s %s: status %d, want 400 or 413", name, c.Name, e.Status)
			default:
				refused++
			}
		}
		t.Logf("%s: %d baselines and %d refused requests", name, baselines, refused)
		if baselines < 30 || refused < 500 {
			t.Errorf("%s: only %d baselines and %d refusals: the generator has stopped covering the document", name, baselines, refused)
		}
	}
}

// TestEmptyAndBlankValuesAreSentWhereTheSchemaAcceptsThem is the self-test of the Edge cases
// (round 5, admin-r5-1): a string the document lets an empty or a blank value through gets a
// request with it, and a string that refuses them gets none (it gets the refusal case).
func TestEmptyAndBlankValuesAreSentWhereTheSchemaAcceptsThem(t *testing.T) {
	const head = "openapi: 3.1.0\ninfo: {title: t, version: '1'}\npaths:\n  /x:\n    post:\n      operationId: x\n      requestBody:\n        content:\n          application/json:\n            schema:\n              type: object\n              additionalProperties: false\n              required: [a, b]\n              properties:\n"
	const text = `'^[^\p{C}]*$'`
	const content = `'^[^\p{C}\p{Z}][^\p{C}]*$'`
	raw := head + "                a: {type: string, maxLength: 8, pattern: " + text + "}\n" +
		"                b: {type: string, maxLength: 8, pattern: " + content + "}\n" +
		"      responses:\n        '200': {description: ok}\n"
	cases, err := boundary.Cases([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	edges := map[string]bool{}
	for _, c := range cases {
		if c.Edge {
			if !c.Baseline {
				t.Errorf("%s: an edge case is a baseline", c.Name)
			}
			edges[c.Name] = true
		}
	}
	for _, want := range []string{"x/body:a/empty", "x/body:a/blank"} {
		if !edges[want] {
			t.Errorf("no edge case %q: %v", want, edges)
		}
	}
	for name := range edges {
		if strings.HasPrefix(name, "x/body:b") {
			t.Errorf("the schema refuses an empty b, so %q must not be an edge case", name)
		}
	}
}

func TestBothDocumentsHaveEdgeCases(t *testing.T) {
	for name, doc := range map[string][]byte{"tenant": api.Tenant(), "admin": api.Admin()} {
		cases, err := boundary.Cases(doc)
		if err != nil {
			t.Fatal(err)
		}
		edges := 0
		for _, c := range cases {
			if c.Edge {
				edges++
			}
		}
		// The admin document is bounded to refuse empty identifiers, so it keeps only the few
		// strings that may be empty (a password, a search); the tenant one still has many.
		if edges < 4 {
			t.Errorf("%s: only %d edge cases: the generator has stopped sending empty and blank values", name, edges)
		}
	}
}

// TestDeclaredKeysAreSentInAnotherLetterCase is the self-test of the case-variant mutation
// (round 5, tenant-r5-7). The two real documents close every object, so the fuzz above
// passes whether or not the generator sends the variants: it would go blind without any
// test noticing. This one builds the same operation with an object left open and requires
// that the variants are generated and that the validator is what lets them through, so a
// generator that stops sending them fails here and a document that left an object open
// fails the fuzz above.
func TestDeclaredKeysAreSentInAnotherLetterCase(t *testing.T) {
	const head = "openapi: 3.1.0\ninfo: {title: t, version: '1'}\npaths:\n  /x:\n    post:\n      operationId: x\n      requestBody:\n        content:\n          application/json:\n            schema:\n              type: object\n              required: [skey]\n              properties:\n                skey: {type: string, maxLength: 8}\n      responses:\n        '200': {description: ok}\n"
	closed := strings.Replace(head, "type: object\n              required", "type: object\n              additionalProperties: false\n              required", 1)

	variants := func(raw string) (names []string, validator *httpx.Validator, cases []boundary.Case) {
		cases, err := boundary.Cases([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		validator, err = httpx.NewValidator([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range cases {
			if strings.Contains(c.Name, "case variant") {
				names = append(names, c.Name)
			}
		}
		return names, validator, cases
	}

	names, v, cases := variants(closed)
	// SKEY (all upper), Skey (first letter flipped), the long s and the Kelvin sign, each with
	// a NUL; the first member also with a 64 KiB value.
	if len(names) < 4*2 {
		t.Fatalf("closed object: only %d case-variant cases %q: the generator has stopped sending declared keys in another case", len(names), names)
	}
	for _, c := range cases {
		if strings.Contains(c.Name, "case variant") && v.Check(request(c), c.Key) == nil {
			t.Errorf("%s: a closed object accepted a case variant", c.Name)
		}
	}

	// The same member in an open object: the variant is not a member the document declares,
	// so it passes. That the fuzz can see this is what makes it a check of "closed".
	_, v, cases = variants(head)
	accepted := 0
	for _, c := range cases {
		if strings.Contains(c.Name, "case variant") && !c.Baseline && v.Check(request(c), c.Key) == nil {
			accepted++
		}
	}
	if accepted == 0 {
		t.Error("an open object accepted no case variant: the variants are not distinguishable from a refusal")
	}
}

// TestAPastedCodeReachesTheHandler is the route-level half of primitives-r14-3: the fold of
// internal/auth/digits drops the marks a paste carries (a right-to-left mark, a zero-width joiner,
// the Arabic letter mark, a tab), and it ran only in unit tests because the request schema refused
// every one of them before any handler ran. Each baseline request that carries a typed code or a
// phone is sent again with the value wrapped in marks, and the validator must let it through; the
// same value with a NUL must not (the generated fuzz above holds the refusals).
func TestAPastedCodeReachesTheHandler(t *testing.T) {
	fields := map[string]bool{"code": true, "totp_code": true, "recovery_code": true, "otp_code": true,
		"old_code": true, "new_code": true, "phone": true, "new_phone": true, "invite_token": true, "token": true}
	const marks = "\u200f\u061c\u2060\u00ad\t"
	var rewrite func(v any) int
	rewrite = func(v any) int {
		n := 0
		switch x := v.(type) {
		case map[string]any:
			for k, e := range x {
				if s, ok := e.(string); ok && fields[k] && s != "" {
					x[k] = marks + s + marks
					n++
					continue
				}
				n += rewrite(e)
			}
		case []any:
			for _, e := range x {
				n += rewrite(e)
			}
		}
		return n
	}
	for name, doc := range map[string][]byte{"tenant": api.Tenant(), "admin": api.Admin()} {
		v, err := httpx.NewValidator(doc)
		if err != nil {
			t.Fatal(err)
		}
		cases, err := boundary.Cases(doc)
		if err != nil {
			t.Fatal(err)
		}
		covered := 0
		for _, c := range cases {
			if !c.Baseline || c.Edge || len(c.Body) == 0 {
				continue
			}
			var body any
			if err := json.Unmarshal(c.Body, &body); err != nil {
				continue
			}
			if rewrite(body) == 0 {
				continue
			}
			raw, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			c.Body = raw
			covered++
			if e := v.Check(request(c), c.Key); e != nil {
				t.Errorf("%s %s: a value wrapped in paste marks is refused (%d %s)", name, c.Op, e.Status, e.Code)
			}
		}
		if covered < 4 {
			t.Errorf("%s: only %d requests with a typed code or phone: the test has stopped covering the document", name, covered)
		}
	}
}

// TestAPastedQueryReachesTheHandler is the query half of the paste rule (round 15, primitives-r15-1).
// The Users filter `q` goes to phone.SearchPrefix, which drops the marks of a paste, and its schema
// was the `text` pattern, so the validator answered 400 to the marks the handler was written for. The
// body test above picks its fields by name; this one picks them from the schema: every query
// parameter of either document that is on a pasted pattern (the patterns exist for a folded value)
// is sent wrapped in marks and must pass the validator. The lint in internal/lint derives which
// fields are folded from the code and holds them on those patterns, so a folded parameter on
// another pattern fails there and a parameter on a pasted pattern is proven here.
func TestAPastedQueryReachesTheHandler(t *testing.T) {
	const marks = "\u200f\u061c\u2060\u00ad\t"
	covered := 0
	for name, raw := range map[string][]byte{"tenant": api.Tenant(), "admin": api.Admin()} {
		v, err := httpx.NewValidator(raw)
		if err != nil {
			t.Fatal(err)
		}
		doc, err := openapi3.NewLoader().LoadFromData(raw)
		if err != nil {
			t.Fatal(err)
		}
		for path, item := range doc.Paths.Map() {
			if strings.Contains(path, "{") {
				continue // the path parameters would need values of their own
			}
			for method, op := range item.Operations() {
				for _, pr := range op.Parameters {
					p := pr.Value
					if p == nil || p.In != "query" || p.Schema == nil || p.Schema.Value == nil {
						continue
					}
					if pat := p.Schema.Value.Pattern; pat != digits.PastePattern && pat != digits.PasteContentPattern {
						continue
					}
					covered++
					q := url.Values{p.Name: {marks + "0912" + marks + "345"}}
					r := httptest.NewRequest(method, "/api/v1"+path+"?"+q.Encode(), nil)
					if e := v.Check(r, method+" "+path); e != nil {
						t.Errorf("%s %s %s: the query value %q wrapped in paste marks is refused (%d %s)", name, method, path, p.Name, e.Status, e.Code)
					}
					q = url.Values{p.Name: {"0912\x00"}}
					r = httptest.NewRequest(method, "/api/v1"+path+"?"+q.Encode(), nil)
					if e := v.Check(r, method+" "+path); e == nil {
						t.Errorf("%s %s %s: a NUL in the query value %q is accepted", name, method, path, p.Name)
					}
				}
			}
		}
	}
	if covered < 1 {
		t.Error("no query parameter is on a pasted pattern: the Users filter has left the document or the test has stopped looking")
	}
}
