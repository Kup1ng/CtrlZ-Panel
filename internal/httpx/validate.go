package httpx

import (
	"bytes"
	"context"
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
	// budgets is, for each operation, the most values its JSON body can have (valueBudget), or unbounded.
	budgets map[string]int64
	// components are the named schemas a handler checks a value against by name (CheckComponent): the two document roots.
	components map[string]*jsonschema.Schema
	// docBudgets are, for each document root, the most values the document has without its rules and the most values one
	// rule item has (docBudget), so CheckDocument refuses a bigger one before it builds a tree of it (p2-B3-r7-3).
	docBudgets map[string]docBudget
	// bodies are the compiled schemas of the JSON request bodies, by operation key, built once here. A heavy operation
	// checks its body with one of them (CheckHeavy) and never through openapi3filter, which compiles the schema for each
	// request and builds the text of every error with the value quoted in it (6.5 property 7).
	bodies map[string]*jsonschema.Schema
	// bodyRequired says which operations need a body.
	bodyRequired map[string]bool
}

// docBudget is the value budget of a document root. rest is the document with every bounded array emptied (each key and
// its `[]` counted back in), items is the most values one item of each such array has, by member name, and total is the
// most values the whole document has. Each is unbounded (-1) when the schema does not bound it.
type docBudget struct {
	rest  int64
	items map[string]int64
	total int64
}

// documentBudgets computes docBudget for each root that has arrays CheckDocument takes out.
func documentBudgets(d *openapi3.T) map[string]docBudget {
	out := map[string]docBudget{}
	if d.Components == nil {
		return out
	}
	for _, root := range documentRoots() {
		arrays := documentArrays(root)
		ref := d.Components.Schemas[root]
		if len(arrays) == 0 || ref == nil || ref.Value == nil {
			continue
		}
		c := *ref.Value
		c.Properties = make(openapi3.Schemas, len(ref.Value.Properties))
		for k, p := range ref.Value.Properties {
			c.Properties[k] = p
		}
		b := docBudget{items: map[string]int64{}, total: valueBudget(ref.Value, 0)}
		extra := int64(0)
		for _, a := range arrays {
			item := d.Components.Schemas[a.item]
			if item == nil || item.Value == nil {
				continue
			}
			delete(c.Properties, a.key)
			b.items[a.key] = valueBudget(item.Value, 0)
			extra += 2
		}
		b.rest = valueBudget(&c, 0)
		if b.rest != unbounded {
			b.rest += extra
		}
		out[root] = b
	}
	return out
}

// DocumentValueBudget is the most values (keys, strings, numbers, literals, objects and arrays) a legal document of the
// named root has, or -1. A test holds profiles.DocValues, the cap of the scanner that runs before the schema check, at or
// above it, so the two never disagree about a legal file (p2-B3-r8-2).
func (v *Validator) DocumentValueBudget(root string) int64 {
	if b, ok := v.docBudgets[root]; ok {
		return b.total
	}
	return unbounded
}

// NewValidator reads an OpenAPI document. It fails on a document it cannot load, so
// a broken document stops the service at start-up and is never served unchecked.
func NewValidator(doc []byte) (*Validator, error) {
	d, err := openapi3.NewLoader().LoadFromData(doc)
	if err != nil {
		return nil, fmt.Errorf("httpx: load the OpenAPI document: %w", err)
	}
	inlineRefs(d)
	bodies, err := compileAll(d)
	if err != nil {
		return nil, err
	}
	comps, err := compileComponents(d)
	if err != nil {
		return nil, err
	}
	v := &Validator{doc: d, routes: map[string]*routers.Route{}, budgets: map[string]int64{}, components: comps, docBudgets: documentBudgets(d),
		bodies: bodies, bodyRequired: map[string]bool{}}
	for path, item := range d.Paths.Map() {
		for method, op := range item.Operations() {
			v.routes[method+" "+path] = &routers.Route{Spec: d, Path: path, PathItem: item, Method: method, Operation: op}
			v.budgets[method+" "+path] = bodyBudget(op)
			v.bodyRequired[method+" "+path] = op.RequestBody != nil && op.RequestBody.Value != nil && op.RequestBody.Value.Required
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
// the engine refuses. Failing here stops the service at start-up instead. It returns the
// compiled schema of each JSON request body, by operation key, which CheckHeavy checks with.
func compileAll(d *openapi3.T) (map[string]*jsonschema.Schema, error) {
	bodies := map[string]*jsonschema.Schema{}
	check := func(where string, s *openapi3.SchemaRef) (*jsonschema.Schema, error) {
		if s == nil || s.Value == nil {
			return nil, nil
		}
		raw, err := json.Marshal(s.Value)
		if err != nil {
			return nil, fmt.Errorf("httpx: %s: %w", where, err)
		}
		if bytes.Contains(raw, []byte(`"$ref"`)) {
			return nil, fmt.Errorf("httpx: %s still holds a $ref after inlining", where)
		}
		var doc map[string]any
		if err := json.Unmarshal(raw, &doc); err != nil {
			return nil, fmt.Errorf("httpx: %s: %w", where, err)
		}
		c := jsonschema.NewCompiler()
		c.DefaultDraft(jsonschema.Draft2020)
		registerFormats(c, doc)
		const url = "https://schema.invalid/request.json"
		if err := c.AddResource(url, doc); err != nil {
			return nil, fmt.Errorf("httpx: %s: %w", where, err)
		}
		compiled, err := c.Compile(url)
		if err != nil {
			return nil, fmt.Errorf("httpx: %s does not compile as a 2020-12 schema, so the library would check it with its older engine: %w", where, err)
		}
		return compiled, nil
	}
	for path, item := range d.Paths.Map() {
		for method, op := range item.Operations() {
			where := method + " " + path
			for _, p := range append(append(openapi3.Parameters{}, item.Parameters...), op.Parameters...) {
				if p != nil && p.Value != nil {
					if _, err := check(where+" parameter "+p.Value.Name, p.Value.Schema); err != nil {
						return nil, err
					}
				}
			}
			if op.RequestBody != nil && op.RequestBody.Value != nil {
				for mt, m := range op.RequestBody.Value.Content {
					compiled, err := check(where+" body "+mt, m.Schema)
					if err != nil {
						return nil, err
					}
					if compiled != nil && isJSONType(mt) {
						bodies[where] = compiled
					}
				}
			}
		}
	}
	return bodies, nil
}

// registerFormats makes the compiler assert the formats the schema names with the validators the library itself uses for a
// request body (openapi3.SchemaStringFormats and the number maps), so a body checked here is held to the formats it was
// when openapi3filter checked it. A format nobody defined is not asserted, as in the library.
func registerFormats(c *jsonschema.Compiler, node any) {
	formats := map[string]struct{}{}
	var walk func(n any)
	walk = func(n any) {
		switch n := n.(type) {
		case map[string]any:
			if f, ok := n["format"].(string); ok && f != "" {
				formats[f] = struct{}{}
			}
			for _, v := range n {
				walk(v)
			}
		case []any:
			for _, v := range n {
				walk(v)
			}
		}
	}
	walk(node)
	if len(formats) == 0 {
		return
	}
	for f := range formats {
		c.RegisterFormat(&jsonschema.Format{Name: f, Validate: func(v any) error {
			switch v := v.(type) {
			case string:
				if fv, ok := openapi3.SchemaStringFormats[f]; ok {
					return fv.Validate(v)
				}
			case json.Number:
				if i, err := v.Int64(); err == nil {
					if fv, ok := openapi3.SchemaIntegerFormats[f]; ok {
						return fv.Validate(i)
					}
				}
				if x, err := v.Float64(); err == nil {
					if fv, ok := openapi3.SchemaNumberFormats[f]; ok {
						return fv.Validate(x)
					}
				}
			}
			return nil
		}})
	}
	c.AssertFormat()
}

// Check validates r against the operation key (method and path as the document
// writes them). It returns the refusal to send, or nil. On success r.Body can be
// read again by the handler.
func (v *Validator) Check(r *http.Request, key string) *Error {
	route, params, e := v.prepare(r, key)
	if e != nil {
		return e
	}
	if route.Operation.RequestBody != nil && r.Body != nil && r.Body != http.NoBody {
		raw, e := ReadBody(r)
		if e != nil {
			return e
		}
		// Before the library builds the tree of the body (about twenty times its bytes for small values), the count of its
		// values is held to what the schema allows at most (p2-B3-r6-4).
		if b := v.budgets[key]; b != unbounded && !withinValues(raw, b) {
			return BadRequest()
		}
	}
	return v.validate(r, route, params, false)
}

// CheckHeavy is Check for a heavy operation (spec 6.5), on the bytes of the body that were spooled to a file. The
// parameters go through the library as they always did; the body does not: it is scanned for its shape on the raw bytes,
// then checked with the schema compiled when the validator was built, and a request that fails any step is 400 with no
// text of its own. raw is nil for a request with no body.
func (v *Validator) CheckHeavy(r *http.Request, key string, raw []byte) *Error {
	route, params, e := v.prepare(r, key)
	if e != nil {
		return e
	}
	if e := v.validate(r, route, params, true); e != nil {
		return e
	}
	if route.Operation.RequestBody == nil {
		return nil
	}
	if len(raw) == 0 {
		if v.bodyRequired[key] {
			return BadRequest()
		}
		return nil
	}
	schema := v.bodies[key]
	if schema == nil || !isJSONType(r.Header.Get("Content-Type")) {
		return BadRequest()
	}
	lim := heavyShape()
	if b := v.budgets[key]; b != unbounded {
		lim.values = b
	}
	if !scanShape(raw, lim) {
		return BadRequest()
	}
	// UseNumber decoding: a number is a literal here, not a float, and the shape scan has already held it to ten digits.
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return BadRequest()
	}
	// The error is never read: its text quotes the value that failed.
	if schema.Validate(inst) != nil {
		return BadRequest()
	}
	return nil
}

// prepare finds the route of key and refuses a query or path value that is not UTF-8.
func (v *Validator) prepare(r *http.Request, key string) (*routers.Route, map[string]string, *Error) {
	route, ok := v.routes[key]
	if !ok {
		// An operation the pipeline knows and the document does not cannot happen
		// when both come from the same bytes; fail closed if it ever does.
		return nil, nil, Internal()
	}

	// Invalid UTF-8 is refused before the schema looks at it. A JSON decoder would
	// replace the bad bytes with U+FFFD, which is a legal character, so the value
	// that reached the handler would no longer be the value that was sent.
	for k, vs := range r.URL.Query() {
		if !utf8.ValidString(k) {
			return nil, nil, BadRequest()
		}
		for _, s := range vs {
			if !utf8.ValidString(s) {
				return nil, nil, BadRequest()
			}
		}
	}
	params := map[string]string{}
	if rc := chi.RouteContext(r.Context()); rc != nil {
		for i, name := range rc.URLParams.Keys {
			if i < len(rc.URLParams.Values) {
				if !utf8.ValidString(rc.URLParams.Values[i]) {
					return nil, nil, BadRequest()
				}
				params[name] = rc.URLParams.Values[i]
			}
		}
	}

	return route, params, nil
}

// validate runs the library over the parameters of the request and, unless excludeBody, over its body.
func (v *Validator) validate(r *http.Request, route *routers.Route, params map[string]string, excludeBody bool) *Error {
	if excludeBody {
		// The library reads the body of the request it is given to hand it to an authentication function, and copies it. The
		// parameters need no body, so they are checked on a copy of the request that has none, and the spooled body is never
		// read twice (6.5 property 7).
		bare := r.WithContext(r.Context())
		bare.Body, bare.GetBody, bare.ContentLength = http.NoBody, nil, 0
		r = bare
	}
	err := openapi3filter.ValidateRequest(r.Context(), &openapi3filter.RequestValidationInput{
		Request: r, PathParams: params, Route: route,
		Options: &openapi3filter.Options{
			// Authentication is the pipeline's own (steps 8 to 10); the document's
			// security entry only says which cookie the route reads.
			AuthenticationFunc: openapi3filter.NoopAuthenticationFunc,
			ExcludeRequestBody: excludeBody,
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

// bufferedBody is a request body that has been read whole and checked to be UTF-8, and can be read again. An ordinary
// operation has such a body (at most 64 KiB); the body of a heavy one is spooled to a file and never goes through here
// (spec 6.5).
type bufferedBody struct {
	rd   *bytes.Reader
	data []byte
}

func (b *bufferedBody) Read(p []byte) (int, error) { return b.rd.Read(p) }

func (*bufferedBody) Close() error { return nil }

// ReadBody reads the body of r whole, checks that it is UTF-8 and puts it back, so that it can be read again at no cost.
// A body already read this way is returned as it is. What it holds while it reads follows the bytes that have arrived and
// never the length the client declared (readSized). The refusal is the one of Check: 413 for a body over its limit, 499
// for a client that left, 400 for any other read error or bad UTF-8. A request without a
// body returns nil and no refusal.
func ReadBody(r *http.Request) ([]byte, *Error) {
	if r.Body == nil || r.Body == http.NoBody {
		return nil, nil
	}
	if bb, ok := r.Body.(*bufferedBody); ok {
		return bb.data, nil
	}
	raw, err := readSized(r.Body)
	if err != nil {
		var mbe *http.MaxBytesError
		switch {
		case errors.As(err, &mbe):
			return nil, New(http.StatusRequestEntityTooLarge, CodeTooLarge)
		case r.Context().Err() != nil:
			return nil, clientGone()
		}
		return nil, BadRequest()
	}
	if !utf8.Valid(raw) {
		return nil, BadRequest()
	}
	r.Body = &bufferedBody{rd: bytes.NewReader(raw), data: raw}
	return raw, nil
}

// readChunk is the size of the pieces a body is read into.
const readChunk = 16 << 10

// readSized reads rd to its end into chunks of readChunk that are joined once, at the end, into a buffer of exactly the
// body's length. While it reads it holds the bytes that have arrived plus one chunk, and the join briefly doubles that:
// a bound of twice the bytes. A buffer sized from Content-Length would be allocated before a byte had arrived, and a client
// chooses what it declares (p2-B3-r7-1). Growing by doubling would copy the body again at every step.
func readSized(rd io.Reader) ([]byte, error) {
	var chunks [][]byte
	buf := make([]byte, readChunk)
	fill, total := 0, 0
	for {
		n, err := rd.Read(buf[fill:])
		fill += n
		total += n
		if err != nil {
			if err != io.EOF {
				return nil, err
			}
			break
		}
		if fill == len(buf) {
			chunks = append(chunks, buf)
			buf = make([]byte, readChunk)
			fill = 0
		}
	}
	out := make([]byte, 0, total)
	for _, c := range chunks {
		out = append(out, c...)
	}
	return append(out, buf[:fill]...), nil
}

// clientGone is the marker for a client that left while its body was read. The
// pipeline answers it with a bare 499 (API.fail).
func clientGone() *Error {
	return &Error{Status: StatusClientClosedRequest, Code: "client_closed_request"}
}

// documentRoots are the named schemas whose values a handler checks itself, with CheckComponent: the profile document
// and the rules document (spec 6.2), and the items of their arrays, which CheckDocument checks one at a time. They are
// roots of inlineRefs and compileAll like a request body is, so every member of them has the bounds and the alphabet of
// rule boundary-input under the same 2020-12 engine.
// A function, not a variable: nothing may change the list at run time (no package-level mutable state).
func documentRoots() []string {
	return []string{"ProfileDocument", "RulesDocument", "DocRule", "RulesDocumentRule", "DocFilter", "DocService", "DocFolder"}
}

// docArray names an array member of a document root and the component its items are checked against.
type docArray struct{ key, item string }

// documentArrays are the arrays of a document root that CheckDocument checks item by item.
func documentArrays(root string) []docArray {
	switch root {
	case "ProfileDocument":
		return []docArray{{"filters", "DocFilter"}, {"services", "DocService"}, {"folders", "DocFolder"}, {"rules", "DocRule"}}
	case "RulesDocument":
		return []docArray{{"rules", "RulesDocumentRule"}}
	}
	return nil
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

// CheckDocument is CheckComponent for a document root, with the work bounded. A whole-document check builds the
// jsonschema tree of the file and the error tree of every failure before it cuts the answer to 100, and for 10,000 bad
// rules that was tens of MiB of heap for one request. Here the document is checked with its arrays taken out, then each
// item of each array on its own against the item component, and each array stops at its first 100 problems; an item's
// tree is garbage before the next one is read, so the peak does not grow with the number of items. Every array the schema
// bounds is cut at its maxItems plus one the same way, and what is left (the document without its arrays, and each item)
// is refused with `exceeded` when it has more values than the schema allows at most, before a tree is built of it: a file
// of 75,000 folders of {"a":0} or of one unknown member of 300,000 values held 30 to 60 MiB of heap for a body of 0.8 MiB
// (p2-B3-r7-3), and 5,000 services, 1,000 filters and 500 folders of the wrong type built an error tree of some 30 MiB
// while only the rules were checked one by one (p2-B3-r8-3). The members of the document itself are counted by a scan
// that keeps nothing before any map is built of them (p2-B3-r8-5). The problems are the same as CheckComponent gives, at
// the same pointers, for every document the schema can hold.
func (v *Validator) CheckDocument(ctx context.Context, name string, raw []byte) ([]SchemaProblem, error) {
	arrays := documentArrays(name)
	bud, hasBud := v.docBudgets[name]
	if !hasBud {
		bud = docBudget{rest: unbounded}
	}
	s := v.components[name]
	if len(arrays) == 0 || !hasBud || s == nil {
		return v.checkBounded(name, raw, bud.rest)
	}
	// The members of the document itself were counted by the scan of the file (profiles.ScanJSON: 32 at most in an object)
	// before this runs, so the map below is a small one.
	var top map[string]json.RawMessage
	if json.Unmarshal(raw, &top) != nil {
		return v.checkBounded(name, raw, bud.rest)
	}
	var out []SchemaProblem
	type todo struct {
		key, item string
		items     []json.RawMessage
	}
	var pending []todo
	for _, a := range arrays {
		arr, has := top[a.key]
		if !has {
			continue
		}
		maxItems := -1
		if ps := s.Properties[a.key]; ps != nil && ps.MaxItems != nil {
			maxItems = *ps.MaxItems
		}
		items, isArr := splitRules(arr, maxItems)
		if !isArr {
			continue // not an array: it stays in the rest, and the check there says so
		}
		top[a.key] = json.RawMessage("[]")
		if maxItems >= 0 && len(items) > maxItems {
			out = append(out, SchemaProblem{Pointer: "/" + a.key, Code: "exceeded"})
			if a.key == "rules" {
				// Past maxItems the rules are not looked at (spec 6.2); the items of the other arrays that were read are
				// checked, as a whole-document check does.
				continue
			}
		}
		pending = append(pending, todo{key: a.key, item: a.item, items: items})
	}
	rest, err := json.Marshal(top)
	if err != nil {
		return nil, fmt.Errorf("httpx: component %s: %w", name, err)
	}
	ps, err := v.checkBounded(name, rest, bud.rest)
	if err != nil {
		return nil, err
	}
	out = append(out, ps...)
	for _, t := range pending {
		itemBudget, ok := bud.items[t.key]
		if !ok {
			itemBudget = unbounded
		}
		found := 0
		for i, item := range t.items {
			if found >= documentProblems {
				break
			}
			// The work has a deadline (6.5 property 5): the CPU part of the check looks at it between two items.
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			ps, err := v.checkBounded(t.item, item, itemBudget)
			if err != nil {
				return nil, err
			}
			for _, p := range ps {
				out = append(out, SchemaProblem{Pointer: "/" + t.key + "/" + strconv.Itoa(i) + p.Pointer, Code: p.Code})
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

// checkBounded is CheckComponent for a value that has no more than budget values when it is legal (budget < 0: no bound).
// A bigger one is `exceeded` at its root and no tree is built of it.
func (v *Validator) checkBounded(name string, raw []byte, budget int64) ([]SchemaProblem, error) {
	if budget >= 0 && !withinValues(raw, budget) {
		return []SchemaProblem{{Pointer: "", Code: "exceeded"}}, nil
	}
	return v.CheckComponent(name, raw)
}

// splitRules cuts the array of rules into its items, one raw value each, and stops at max+1 items (max < 0: no stop): a
// document of 149,000 empty rules costs the memory of 10,001 items and not of 149,000, because the check refuses it for
// its count and never looks at them. The boolean is false when raw is not an array.
func splitRules(raw json.RawMessage, max int) ([]json.RawMessage, bool) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if t, err := dec.Token(); err != nil || t != json.Delim('[') {
		return nil, false
	}
	var items []json.RawMessage
	for dec.More() {
		var m json.RawMessage
		if dec.Decode(&m) != nil {
			return nil, false
		}
		items = append(items, m)
		if max >= 0 && len(items) > max {
			return items, true
		}
	}
	return items, true
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
