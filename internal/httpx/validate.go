package httpx

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"unicode/utf8"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"
	"github.com/go-chi/chi/v5"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// Validator is the one place a client's input is bounded (rule boundary-input,
// spec 2.3 step 8a and 14.2). It checks each request against the OpenAPI
// operation it was routed to, before any handler runs: every string has a length
// and an alphabet, every number a range, every list a size, every map a number of
// keys. The documents are the contract and this is what makes them one, so a
// handler never meets a NUL, a bidi override, a 64 KiB name or an integer that
// does not fit, and there is no per-field check to forget when a field is added.
//
// What it decides and what it does not. A request that breaks its schema is 400
// bad_request with no detail: the error text of the library repeats the offending
// value, which may be a password. A body over its limit is 413. Whether a value is
// right (a phone that does not parse, a code that is wrong) is for the handler and
// stays a 422 or a 401 there; the schema only keeps the shape of the input safe to
// look at.
type Validator struct {
	doc    *openapi3.T
	routes map[string]*routers.Route
}

// NewValidator reads an OpenAPI document. It fails on a document it cannot load, so
// a broken document stops the service at start-up and is never served unchecked.
func NewValidator(doc []byte) (*Validator, error) {
	d, err := openapi3.NewLoader().LoadFromData(doc)
	if err != nil {
		return nil, fmt.Errorf("httpx: load the OpenAPI document: %w", err)
	}
	inlineRefs(d)
	if err := compileAll(d); err != nil {
		return nil, err
	}
	v := &Validator{doc: d, routes: map[string]*routers.Route{}}
	for path, item := range d.Paths.Map() {
		for method, op := range item.Operations() {
			v.routes[method+" "+path] = &routers.Route{Spec: d, Path: path, PathItem: item, Method: method, Operation: op}
		}
	}
	return v, nil
}

// inlineRefs clears the $ref of every schema of the document, keeping the schema it
// points to. The library checks an OpenAPI 3.1 schema with a JSON Schema 2020-12
// engine, which it hands the schema as JSON on its own, so a $ref inside it points
// at nothing; it then falls back, silently, to the older engine, which ignores
// patternProperties, propertyNames and the rest of 2020-12. A schema that is
// whole in itself is never sent there. The schemas of this service are a tree, so
// inlining ends; a cycle would overflow the stack at start-up, which is loud.
func inlineRefs(d *openapi3.T) {
	seen := map[*openapi3.Schema]bool{}
	var walk func(r *openapi3.SchemaRef)
	walk = func(r *openapi3.SchemaRef) {
		if r == nil {
			return
		}
		r.Ref = ""
		s := r.Value
		if s == nil || seen[s] {
			return
		}
		seen[s] = true
		walk(s.Items)
		walk(s.Not)
		walk(s.PropertyNames)
		walk(s.AdditionalProperties.Schema)
		for _, c := range s.Properties {
			walk(c)
		}
		for _, c := range s.PatternProperties {
			walk(c)
		}
		for _, list := range [][]*openapi3.SchemaRef{s.AllOf, s.OneOf, s.AnyOf} {
			for _, c := range list {
				walk(c)
			}
		}
	}
	params := func(ps openapi3.Parameters) {
		for _, p := range ps {
			if p != nil && p.Value != nil {
				walk(p.Value.Schema)
			}
		}
	}
	for _, item := range d.Paths.Map() {
		params(item.Parameters)
		for _, op := range item.Operations() {
			params(op.Parameters)
			if op.RequestBody != nil && op.RequestBody.Value != nil {
				for _, mt := range op.RequestBody.Value.Content {
					walk(mt.Schema)
				}
			}
		}
	}
}

// compileAll checks that the 2020-12 engine can take every schema a request is
// checked against. The library falls back to the older engine, in silence, for a
// schema that engine cannot compile, and the older one ignores patternProperties and
// propertyNames, so a map would lose its bound on the day somebody wrote a keyword
// the engine refuses. Failing here stops the service at start-up instead.
func compileAll(d *openapi3.T) error {
	check := func(where string, s *openapi3.SchemaRef) error {
		if s == nil || s.Value == nil {
			return nil
		}
		raw, err := json.Marshal(s.Value)
		if err != nil {
			return fmt.Errorf("httpx: %s: %w", where, err)
		}
		if bytes.Contains(raw, []byte(`"$ref"`)) {
			return fmt.Errorf("httpx: %s still holds a $ref after inlining", where)
		}
		var doc map[string]any
		if err := json.Unmarshal(raw, &doc); err != nil {
			return fmt.Errorf("httpx: %s: %w", where, err)
		}
		c := jsonschema.NewCompiler()
		c.DefaultDraft(jsonschema.Draft2020)
		const url = "https://schema.invalid/request.json"
		if err := c.AddResource(url, doc); err != nil {
			return fmt.Errorf("httpx: %s: %w", where, err)
		}
		if _, err := c.Compile(url); err != nil {
			return fmt.Errorf("httpx: %s does not compile as a 2020-12 schema, so the library would check it with its older engine: %w", where, err)
		}
		return nil
	}
	for path, item := range d.Paths.Map() {
		for method, op := range item.Operations() {
			where := method + " " + path
			for _, p := range append(append(openapi3.Parameters{}, item.Parameters...), op.Parameters...) {
				if p != nil && p.Value != nil {
					if err := check(where+" parameter "+p.Value.Name, p.Value.Schema); err != nil {
						return err
					}
				}
			}
			if op.RequestBody != nil && op.RequestBody.Value != nil {
				for mt, m := range op.RequestBody.Value.Content {
					if err := check(where+" body "+mt, m.Schema); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

// Check validates r against the operation key (method and path as the document
// writes them). It returns the refusal to send, or nil. On success r.Body can be
// read again by the handler.
func (v *Validator) Check(r *http.Request, key string) *Error {
	route, ok := v.routes[key]
	if !ok {
		// An operation the pipeline knows and the document does not cannot happen
		// when both come from the same bytes; fail closed if it ever does.
		return Internal()
	}

	// Invalid UTF-8 is refused before the schema looks at it. A JSON decoder would
	// replace the bad bytes with U+FFFD, which is a legal character, so the value
	// that reached the handler would no longer be the value that was sent.
	for k, vs := range r.URL.Query() {
		if !utf8.ValidString(k) {
			return BadRequest()
		}
		for _, s := range vs {
			if !utf8.ValidString(s) {
				return BadRequest()
			}
		}
	}
	params := map[string]string{}
	if rc := chi.RouteContext(r.Context()); rc != nil {
		for i, name := range rc.URLParams.Keys {
			if i < len(rc.URLParams.Values) {
				if !utf8.ValidString(rc.URLParams.Values[i]) {
					return BadRequest()
				}
				params[name] = rc.URLParams.Values[i]
			}
		}
	}

	if route.Operation.RequestBody != nil && r.Body != nil && r.Body != http.NoBody {
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			var mbe *http.MaxBytesError
			switch {
			case errors.As(err, &mbe):
				return New(http.StatusRequestEntityTooLarge, CodeTooLarge)
			case r.Context().Err() != nil:
				return clientGone()
			}
			return BadRequest()
		}
		if !utf8.Valid(raw) {
			return BadRequest()
		}
		r.Body = io.NopCloser(bytes.NewReader(raw))
	}

	err := openapi3filter.ValidateRequest(r.Context(), &openapi3filter.RequestValidationInput{
		Request: r, PathParams: params, Route: route,
		Options: &openapi3filter.Options{
			// Authentication is the pipeline's own (steps 8 to 10); the document's
			// security entry only says which cookie the route reads.
			AuthenticationFunc: openapi3filter.NoopAuthenticationFunc,
		},
	})
	if err != nil {
		// Never wrap, log or return err: it quotes the value that failed.
		if r.Context().Err() != nil {
			return clientGone()
		}
		return BadRequest()
	}
	return nil
}

// clientGone is the marker for a client that left while its body was read. The
// pipeline answers it with a bare 499 (API.fail).
func clientGone() *Error {
	return &Error{Status: StatusClientClosedRequest, Code: "client_closed_request"}
}
