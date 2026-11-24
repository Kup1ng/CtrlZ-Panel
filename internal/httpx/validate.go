package httpx

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
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
	// components are the named schemas a handler checks a value against by name (CheckComponent): the two document roots.
	components map[string]*jsonschema.Schema
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
	comps, err := compileComponents(d)
	if err != nil {
		return nil, err
	}
	v := &Validator{doc: d, routes: map[string]*routers.Route{}, components: comps}
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

// documentRoots are the named schemas whose values a handler checks itself, with CheckComponent: the profile document
// and the rules document (spec 6.2). They are roots of inlineRefs and compileAll like a request body is, so every member
// of them has the bounds and the alphabet of rule boundary-input under the same 2020-12 engine.
// A function, not a variable: nothing may change the list at run time (no package-level mutable state).
func documentRoots() []string {
	return []string{"ProfileDocument", "RulesDocument", "DocRule", "RulesDocumentRule"}
}

// documentRuleItem is the component of the items of the `rules` member of each document root.
func documentRuleItem(root string) (string, bool) {
	switch root {
	case "ProfileDocument":
		return "DocRule", true
	case "RulesDocument":
		return "RulesDocumentRule", true
	}
	return "", false
}

// DocumentRoots lists them, for the bounded-input lint.
func DocumentRoots() []string { return documentRoots() }

func compileComponents(d *openapi3.T) (map[string]*jsonschema.Schema, error) {
	out := map[string]*jsonschema.Schema{}
	if d.Components == nil {
		return out, nil
	}
	for _, name := range documentRoots() {
		ref := d.Components.Schemas[name]
		if ref == nil || ref.Value == nil {
			continue
		}
		clearRefs(ref, map[*openapi3.Schema]bool{})
		raw, err := json.Marshal(ref.Value)
		if err != nil {
			return nil, fmt.Errorf("httpx: component %s: %w", name, err)
		}
		if bytes.Contains(raw, []byte(`"$ref"`)) {
			return nil, fmt.Errorf("httpx: component %s still holds a $ref after inlining", name)
		}
		var doc map[string]any
		if err := json.Unmarshal(raw, &doc); err != nil {
			return nil, fmt.Errorf("httpx: component %s: %w", name, err)
		}
		c := jsonschema.NewCompiler()
		c.DefaultDraft(jsonschema.Draft2020)
		const url = "https://schema.invalid/component.json"
		if err := c.AddResource(url, doc); err != nil {
			return nil, fmt.Errorf("httpx: component %s: %w", name, err)
		}
		s, err := c.Compile(url)
		if err != nil {
			return nil, fmt.Errorf("httpx: component %s does not compile as a 2020-12 schema: %w", name, err)
		}
		out[name] = s
	}
	return out, nil
}

// clearRefs is inlineRefs for one root.
func clearRefs(r *openapi3.SchemaRef, seen map[*openapi3.Schema]bool) {
	if r == nil {
		return
	}
	r.Ref = ""
	s := r.Value
	if s == nil || seen[s] {
		return
	}
	seen[s] = true
	clearRefs(s.Items, seen)
	clearRefs(s.Not, seen)
	clearRefs(s.PropertyNames, seen)
	clearRefs(s.AdditionalProperties.Schema, seen)
	for _, c := range s.Properties {
		clearRefs(c, seen)
	}
	for _, c := range s.PatternProperties {
		clearRefs(c, seen)
	}
	for _, list := range [][]*openapi3.SchemaRef{s.AllOf, s.OneOf, s.AnyOf} {
		for _, c := range list {
			clearRefs(c, seen)
		}
	}
}

// SchemaProblem is one failed place of a value: the JSON pointer of the place, built from member names and array
// indexes of the schema, and the code of the keyword that failed, from the closed set of the spec (3.7).
type SchemaProblem struct {
	Pointer string
	Code    string
}

// documentProblems bounds the answer, not the work: at most this many problems are returned (spec 6.2).
const documentProblems = 100

// CheckComponent validates raw, which is JSON the handler already scanned, against a named component and returns the
// problems it has, at most 100, in document order. It never echoes a value or a name from the input: an unknown member
// is reported at its parent, and the keyword of a failure is mapped to a code: required and minLength to required,
// maxLength to too_long, minimum and maximum to out_of_range, maxItems and maxProperties to exceeded,
// additionalProperties to unknown_member, type to type, and every other keyword (pattern, enum, const, format) to invalid.
func (v *Validator) CheckComponent(name string, raw []byte) ([]SchemaProblem, error) {
	s, ok := v.components[name]
	if !ok {
		return nil, fmt.Errorf("httpx: no component %s", name)
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return []SchemaProblem{{Pointer: "", Code: "json_syntax"}}, nil
	}
	verr := s.Validate(inst)
	if verr == nil {
		return nil, nil
	}
	var ve *jsonschema.ValidationError
	if !errors.As(verr, &ve) {
		return nil, fmt.Errorf("httpx: component %s: %w", name, verr)
	}
	var out []SchemaProblem
	seen := map[SchemaProblem]bool{}
	var walk func(e *jsonschema.ValidationError)
	walk = func(e *jsonschema.ValidationError) {
		if len(e.Causes) > 0 {
			for _, c := range e.Causes {
				walk(c)
			}
			return
		}
		p := SchemaProblem{Pointer: pointerOf(e.InstanceLocation), Code: keywordCode(e.ErrorKind)}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	walk(ve)
	sort.SliceStable(out, func(i, j int) bool { return pointerLess(out[i].Pointer, out[j].Pointer) })
	if len(out) > documentProblems {
		out = out[:documentProblems]
	}
	return out, nil
}

// CheckDocument is CheckComponent for a document root, with the work of its rules bounded. A whole-document check builds
// the jsonschema tree of the file and the error tree of every failure before it cuts the answer to 100, and for 10,000
// bad rules that was tens of MiB of heap for one request. Here the document is checked with its rules taken out, then
// each rule on its own against the item component, and it stops at the first 100 problems; a rule's tree is garbage
// before the next one is read, so the peak does not grow with the number of rules. The problems are the same as
// CheckComponent gives, at the same pointers.
func (v *Validator) CheckDocument(name string, raw []byte) ([]SchemaProblem, error) {
	item, ok := documentRuleItem(name)
	var top map[string]json.RawMessage
	if !ok || json.Unmarshal(raw, &top) != nil {
		return v.CheckComponent(name, raw)
	}
	r, has := top["rules"]
	var rules []json.RawMessage
	if !has || !bytes.HasPrefix(bytes.TrimSpace(r), []byte("[")) || json.Unmarshal(r, &rules) != nil {
		// No rules member, or one that is not an array: the whole check reports it, and there is nothing big to bound.
		return v.CheckComponent(name, raw)
	}
	top["rules"] = json.RawMessage("[]")
	rest, err := json.Marshal(top)
	if err != nil {
		return nil, fmt.Errorf("httpx: component %s: %w", name, err)
	}
	out, err := v.CheckComponent(name, rest)
	if err != nil {
		return nil, err
	}
	maxRules := -1
	if s := v.components[name]; s != nil && s.Properties["rules"] != nil && s.Properties["rules"].MaxItems != nil {
		maxRules = *s.Properties["rules"].MaxItems
	}
	if maxRules >= 0 && len(rules) > maxRules {
		out = append(out, SchemaProblem{Pointer: "/rules", Code: "exceeded"})
	} else {
		found := 0
		for i, rule := range rules {
			if found >= documentProblems {
				break
			}
			ps, err := v.CheckComponent(item, rule)
			if err != nil {
				return nil, err
			}
			for _, p := range ps {
				out = append(out, SchemaProblem{Pointer: "/rules/" + strconv.Itoa(i) + p.Pointer, Code: p.Code})
			}
			found += len(ps)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return pointerLess(out[i].Pointer, out[j].Pointer) })
	if len(out) > documentProblems {
		out = out[:documentProblems]
	}
	return out, nil
}

// pointerOf joins the instance location. A segment that is not a schema member name or an index is dropped with
// everything under it, so no name from the file is echoed.
func pointerOf(loc []string) string {
	var b strings.Builder
	for _, seg := range loc {
		if !safeSegment(seg) {
			break
		}
		b.WriteByte('/')
		b.WriteString(seg)
	}
	return b.String()
}

func safeSegment(s string) bool {
	if s == "" || len(s) > 24 {
		return false
	}
	if s[0] >= '0' && s[0] <= '9' {
		for i := 0; i < len(s); i++ {
			if s[i] < '0' || s[i] > '9' {
				return false
			}
		}
		return len(s) <= 5
	}
	if s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

// pointerLess orders two pointers the way the document reads: segment by segment, indexes as numbers.
func pointerLess(a, b string) bool {
	as, bs := strings.Split(a, "/"), strings.Split(b, "/")
	for i := 0; i < len(as) && i < len(bs); i++ {
		if as[i] == bs[i] {
			continue
		}
		x, ex := strconv.Atoi(as[i])
		y, ey := strconv.Atoi(bs[i])
		if ex == nil && ey == nil {
			return x < y
		}
		return as[i] < bs[i]
	}
	return len(as) < len(bs)
}

func keywordCode(k jsonschema.ErrorKind) string {
	path := k.KeywordPath()
	kw := ""
	if len(path) > 0 {
		kw = path[len(path)-1]
	}
	switch kw {
	case "required", "minLength":
		return "required"
	case "maxLength":
		return "too_long"
	case "minimum", "maximum":
		return "out_of_range"
	case "maxItems", "maxProperties":
		return "exceeded"
	case "additionalProperties":
		return "unknown_member"
	case "type":
		return "type"
	}
	return "invalid"
}
