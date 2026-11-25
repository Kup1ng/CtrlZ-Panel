// Package boundary generates the requests of the boundary-input fuzz (P1 auth
// review round 5, rules.md topic 9, spec 18.5): for every operation of an OpenAPI
// document, a baseline request that satisfies its schema and then one request for
// each way a client can break a bound it has, one at a time. The pipeline must refuse
// each of them with 400 (413 when the request is simply too large) before any
// handler, auth or database work, and must never answer a client's input with a 5xx
// or a WARN line.
//
// The requests are built from the document, not written per route, so a field added
// to the document is fuzzed the day it is added, and an operation whose baseline this
// package cannot build fails the test that uses it. The mutations do not come from
// the schema: a NUL, a bidi override or a 64 KiB value is wrong in every string
// whatever its schema says, which is the point. A schema that forgot to exclude them
// is a schema the lint (internal/lint TestOpenAPIBoundsEveryInput) already fails, and
// a validator that stopped reading a schema is what this fuzz catches.
//
// It is imported from test files only, like authtest.
package boundary

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/digits"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/session"
	"github.com/Kup1ng/CtrlZ-Panel/internal/httpx"
	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
)

// Case is one request.
type Case struct {
	Name   string // operation/where/what
	Op     string // operationId
	Method string
	Key    string // method and path template, as the document writes them
	Path   string // relative to /api/v1, query included, already escaped
	// PathParams are the unescaped values of the path template, for a test that
	// checks the request without a router.
	PathParams map[string]string
	Header     map[string]string
	Body       []byte // nil for none
	// Baseline says the request satisfies its schema: it must not be refused by the
	// validator. Every other case must be.
	Baseline bool
	// Edge marks a baseline that differs from the sample by one string made empty or blank,
	// because the schema accepts it. It must not be a server fault either: a value the
	// document lets through is a value a handler must answer (round 5, admin-r5-1).
	Edge bool
}

// Request-body mutations that are raw bytes, not JSON built by the encoder. The
// sentinel marks the place in the encoded document the bytes go.
const (
	sentinel    = "BOUNDARY-VALUE-MARK"
	keySentinel = "BOUNDARY-KEY-MARK"
)

// Cases builds the requests of every operation of raw outside the health tag.
func Cases(raw []byte) ([]Case, error) {
	// NewValidator also registers the string formats the document uses, which the
	// baseline needs to check its own samples.
	if _, err := httpx.NewValidator(raw); err != nil {
		return nil, err
	}
	doc, err := openapi3.NewLoader().LoadFromData(raw)
	if err != nil {
		return nil, err
	}
	var out []Case
	paths := make([]string, 0, len(doc.Paths.Map()))
	for p := range doc.Paths.Map() {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		item := doc.Paths.Value(p)
		ops := item.Operations()
		methods := make([]string, 0, len(ops))
		for m := range ops {
			methods = append(methods, m)
		}
		sort.Strings(methods)
		for _, m := range methods {
			op := ops[m]
			if isHealth(op) {
				continue
			}
			cs, err := forOperation(p, m, item, op)
			if err != nil {
				return nil, fmt.Errorf("boundary: %s %s: %w", m, p, err)
			}
			out = append(out, cs...)
		}
	}
	return out, nil
}

func isHealth(op *openapi3.Operation) bool {
	for _, t := range op.Tags {
		if t == "health" {
			return true
		}
	}
	return false
}

// param is a declared parameter with its baseline value.
type param struct {
	name, in string
	schema   *openapi3.Schema
	value    any
}

// built is what one operation's requests are made of.
type built struct {
	op, method, path string
	params           []param
	body             any // nil: no body
	bodySchema       *openapi3.Schema
}

func forOperation(path, method string, item *openapi3.PathItem, op *openapi3.Operation) ([]Case, error) {
	b := built{op: op.OperationID, method: method, path: path}
	all := append(openapi3.Parameters{}, item.Parameters...)
	all = append(all, op.Parameters...)
	for _, pr := range all {
		p := pr.Value
		if p == nil || p.Schema == nil || p.Schema.Value == nil {
			return nil, fmt.Errorf("parameter %q has no schema", p.Name)
		}
		v, err := sample(p.Schema.Value, 0)
		if err != nil {
			return nil, fmt.Errorf("parameter %s: %w", p.Name, err)
		}
		b.params = append(b.params, param{name: p.Name, in: p.In, schema: p.Schema.Value, value: v})
	}
	if op.RequestBody != nil && op.RequestBody.Value != nil {
		mt := op.RequestBody.Value.Content.Get("application/json")
		if mt == nil || mt.Schema == nil {
			return nil, fmt.Errorf("the request body is not application/json")
		}
		v, err := sample(mt.Schema.Value, 0)
		if err != nil {
			return nil, fmt.Errorf("body: %w", err)
		}
		b.body, b.bodySchema = v, mt.Schema.Value
	}

	var out []Case
	base, err := b.request("baseline", nil)
	if err != nil {
		return nil, err
	}
	base.Baseline = true
	out = append(out, base)

	// Parameters: one at a time.
	for i, p := range b.params {
		for _, m := range scalarMutations(p.schema, p.value) {
			c, err := b.request(p.in+":"+p.name+"/"+m.name, &mutation{param: i, raw: m.raw})
			if err != nil {
				return nil, err
			}
			out = append(out, c)
		}
		for _, e := range emptyValues() {
			if !contains(p.schema.Type.Slice(), "string") || p.schema.VisitJSON(e.value) != nil {
				continue
			}
			c, err := b.request(p.in+":"+p.name+"/"+e.name, &mutation{param: i, raw: e.value})
			if err != nil {
				return nil, err
			}
			c.Baseline, c.Edge = true, true
			out = append(out, c)
		}
	}
	// The body: every leaf, every container.
	if b.body != nil {
		for _, n := range walk(b.body, b.bodySchema, nil) {
			for _, m := range n.mutations() {
				c, err := b.request("body:"+n.label()+"/"+m.name, &mutation{node: &n, bodyRaw: m})
				if err != nil {
					return nil, err
				}
				c.Baseline, c.Edge = m.accepted, m.accepted
				out = append(out, c)
			}
		}
	}
	return out, nil
}

// mutation says what to change in a request.
type mutation struct {
	param   int    // index into params when raw is set
	raw     string // the parameter's text, escaped by the caller
	node    *node
	bodyRaw mut
}

func (b built) request(name string, m *mutation) (Case, error) {
	path := b.path
	var query []string
	header := map[string]string{}
	pathParams := map[string]string{}
	for i, p := range b.params {
		text := paramText(p.value)
		if m != nil && m.node == nil && m.param == i {
			text = m.raw
		}
		switch p.in {
		case "path":
			pathParams[p.name] = text
			path = strings.ReplaceAll(path, "{"+p.name+"}", url.PathEscape(text))
		case "query":
			query = append(query, url.QueryEscape(p.name)+"="+url.QueryEscape(text))
		case "header":
			header[p.name] = text
		}
	}
	if len(query) > 0 {
		path += "?" + strings.Join(query, "&")
	}
	c := Case{Name: b.op + "/" + name, Op: b.op, Method: b.method, Key: b.method + " " + b.path, Path: path, Header: header, PathParams: pathParams}
	if b.body != nil {
		body, err := b.encodeBody(m)
		if err != nil {
			return Case{}, err
		}
		c.Body = body
		c.Header["Content-Type"] = "application/json"
	}
	return c, nil
}

func paramText(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case int64:
		return strconv.FormatInt(x, 10)
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(x)
	}
	return fmt.Sprint(v)
}

func (b built) encodeBody(m *mutation) ([]byte, error) {
	if m == nil || m.node == nil {
		return json.Marshal(b.body)
	}
	tree := deepCopy(b.body)
	var rawSwap []byte // bytes that replace the sentinel after encoding
	var keySwap []byte
	switch {
	case m.bodyRaw.addKey != "":
		tree = addKeyAt(tree, m.node.path, m.bodyRaw.addKey, m.bodyRaw.value)
	case m.bodyRaw.value != nil || m.bodyRaw.isNull:
		tree = setAt(tree, m.node.path, m.bodyRaw.value)
	case m.bodyRaw.raw != "":
		tree = setAt(tree, m.node.path, sentinel)
		rawSwap = []byte(m.bodyRaw.raw)
	case m.bodyRaw.rawKey != "":
		tree = renameKey(tree, m.node.path, keySentinel)
		keySwap = []byte(m.bodyRaw.rawKey)
	case m.bodyRaw.drop:
		tree = dropAt(tree, m.node.path)
	default:
		return nil, fmt.Errorf("an empty mutation")
	}
	out, err := json.Marshal(tree)
	if err != nil {
		return nil, err
	}
	if rawSwap != nil {
		if !bytes.Contains(out, []byte(`"`+sentinel+`"`)) {
			return nil, fmt.Errorf("the sentinel is not in the encoded body")
		}
		out = bytes.Replace(out, []byte(`"`+sentinel+`"`), rawSwap, 1)
	}
	if keySwap != nil {
		out = bytes.Replace(out, []byte(keySentinel), keySwap, 1)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Samples

// stringCandidates are tried in order until one satisfies the schema, so a pattern
// the generator does not understand still gets a valid baseline if any of these
// fits it. A schema none of them fits has to carry an example.
func stringCandidates(s *openapi3.Schema) []string {
	cands := []string{}
	if s.Example != nil {
		if e, ok := s.Example.(string); ok {
			cands = append(cands, e)
		}
	}
	pad := func(base string) string {
		for uint64(len(base)) < s.MinLength {
			base += base[:1]
		}
		return base
	}
	for _, c := range []string{
		"a", "ab", "key", "abc", "Abc123", "1", "0912", "09121234567", "A", "ABCDEFGH", "a.b", "a-b",
		"public-key", "example", "AAAAAAAAAAAAAAAA", "00000000-0000-7000-8000-000000000001",
		"2026-11-09T12:00:00Z", "2026-11-09", "+989121234567",
	} {
		cands = append(cands, c, pad(c))
	}
	return cands
}

func sample(s *openapi3.Schema, depth int) (any, error) {
	if depth > 8 {
		return nil, fmt.Errorf("schema too deep")
	}
	if len(s.Enum) > 0 {
		return s.Enum[0], nil
	}
	if s.Const != nil {
		return s.Const, nil
	}
	types := s.Type.Slice()
	t := ""
	for _, c := range types {
		if c != "null" {
			t = c
			break
		}
	}
	switch t {
	case "string":
		for _, c := range stringCandidates(s) {
			if s.VisitJSON(c) == nil {
				return c, nil
			}
		}
		return nil, fmt.Errorf("no sample string satisfies pattern %q (give the schema an example)", s.Pattern)
	case "integer":
		v := int64(0)
		if s.Min != nil {
			v = int64(*s.Min)
		}
		if s.Max != nil && float64(v) > *s.Max {
			v = int64(*s.Max)
		}
		return v, nil
	case "number":
		v := 0.0
		if s.Min != nil {
			v = *s.Min
		}
		return v, nil
	case "boolean":
		return true, nil
	case "array":
		if s.Items == nil {
			return []any{}, nil
		}
		e, err := sample(s.Items.Value, depth+1)
		if err != nil {
			return nil, err
		}
		return []any{e}, nil
	case "object":
		m := map[string]any{}
		for name, ref := range s.Properties {
			v, err := sample(ref.Value, depth+1)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", name, err)
			}
			m[name] = v
		}
		if len(s.Properties) == 0 {
			if vs, key, ok := mapValue(s); ok {
				v, err := sample(vs, depth+1)
				if err != nil {
					return nil, err
				}
				m[key] = v
			}
		}
		return m, nil
	}
	return nil, fmt.Errorf("no sample for type %v", types)
}

// mapKeys are the keys tried, in order, for the entry of a map.
func mapKeys() []string { return []string{"k", "key", "a", "A1", "tour", "step", "x"} }

// mapValue finds the schema the values of a map follow and a key that is allowed:
// patternProperties first (the way the documents bound a map), then
// additionalProperties.
func mapValue(s *openapi3.Schema) (*openapi3.Schema, string, bool) {
	for _, pat := range sortedNames(s.PatternProperties) {
		re := regexp.MustCompile(pat)
		for _, k := range mapKeys() {
			if re.MatchString(k) {
				return s.PatternProperties[pat].Value, k, true
			}
		}
	}
	if s.AdditionalProperties.Schema != nil {
		return s.AdditionalProperties.Schema.Value, "k", true
	}
	return nil, "", false
}

// keyFor returns the n-th key of an oversize map that the schema's key pattern
// allows, or "" when none of the generated ones does.
func keyFor(s *openapi3.Schema, n int) string {
	k := "k" + strconv.Itoa(n)
	for _, pat := range sortedNames(s.PatternProperties) {
		return map[bool]string{true: k, false: ""}[regexp.MustCompile(pat).MatchString(k)]
	}
	return k
}

// ---------------------------------------------------------------------------
// Mutations

type mut struct {
	name string
	// accepted says the schema lets this value through, so the request is a baseline of
	// its own (an Edge) and not a refusal.
	accepted bool
	value    any    // an encodable replacement
	isNull   bool   // the replacement is JSON null
	raw      string // bytes that replace the value in the encoded body
	rawKey   string // bytes that replace a map key
	drop     bool   // remove the member
	// addKey adds a second member, value under a key that is not the declared one (a
	// case variant), to the object at the node's path.
	addKey string
}

type pmut struct {
	name string
	raw  string
}

// badChars are the characters no client text may carry: NUL, a control, a zero width
// space, a joiner, a right-to-left override, the byte order mark, a private-use
// code point and an unpaired high byte (invalid UTF-8).
func badChars() map[string]string {
	return map[string]string{
		"NUL": "\x00", "BEL": "\x07", "NEL": "\u0085", "ZWSP": "\u200b", "RLO": "\u202e", "BOM": "\ufeff",
		"PUA": "\ue000", "LRM": "\u200e", "ZWNJ": "\u200c", "ZWJ": "\u200d", "SHY": "\u00ad", "TAG": "\U000e0001",
	}
}

// emptyValues are the two values a client can send that hold nothing: the empty string and a
// blank one, which a handler that trims turns into the empty one. They are sent only where
// the schema accepts them, and then they are a request like any other that must not fault.
func emptyValues() []struct{ name, value string } {
	return []struct{ name, value string }{{"empty", ""}, {"blank", "   "}}
}

// scalarMutations are the ways to break a parameter, as text.
func scalarMutations(s *openapi3.Schema, base any) []pmut {
	var out []pmut
	types := s.Type.Slice()
	isStr, isInt := contains(types, "string"), contains(types, "integer")
	if isStr {
		text := paramText(base)
		for _, name := range sortedNames(badChars()) {
			if acceptedMark(s, name) {
				continue
			}
			out = append(out, pmut{name, text + badChars()[name]})
		}
		out = append(out, pmut{"invalid UTF-8", text + "\xff\xfe"})
		if s.MaxLength == nil || *s.MaxLength < 64<<10 {
			out = append(out, pmut{"64 KiB", strings.Repeat("a", 64<<10)})
		}
		if s.MaxLength != nil {
			out = append(out, pmut{"maxLength+1", strings.Repeat("a", int(*s.MaxLength)+1)})
		}
		if s.MinLength > 0 {
			out = append(out, pmut{"empty", ""})
		}
	}
	if isInt {
		if s.Min != nil {
			out = append(out, pmut{"below minimum", strconv.FormatInt(int64(*s.Min)-1, 10)})
		}
		if s.Max != nil {
			out = append(out, pmut{"above maximum", strconv.FormatInt(int64(*s.Max)+1, 10)})
		}
		out = append(out,
			pmut{"2^63", "9223372036854775808"}, pmut{"-2^63-1", "-9223372036854775809"},
			pmut{"1e308", "1e308"}, pmut{"fraction", "0.5"}, pmut{"text", "abc"}, pmut{"huge", strings.Repeat("9", 400)})
	}
	return out
}

func sortedNames[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// A node of the body tree: where it is and the schema that governs it.
type node struct {
	path   []any // string keys and int indexes from the root
	schema *openapi3.Schema
	value  any
	// required says the member is listed in its parent's required: dropping it must
	// be refused, and dropping any other member must not.
	required bool
}

func (n node) label() string {
	var parts []string
	for _, p := range n.path {
		parts = append(parts, fmt.Sprint(p))
	}
	if len(parts) == 0 {
		return "(root)"
	}
	return strings.Join(parts, ".")
}

func walk(v any, s *openapi3.Schema, path []any) []node {
	return walkAs(v, s, path, false)
}

func walkAs(v any, s *openapi3.Schema, path []any, required bool) []node {
	out := []node{{path: path, schema: s, value: v, required: required}}
	switch x := v.(type) {
	case map[string]any:
		keys := sortedNames(x)
		for _, k := range keys {
			var child *openapi3.Schema
			if ref, ok := s.Properties[k]; ok {
				child = ref.Value
			} else if vs, _, ok := mapValue(s); ok {
				child = vs
			}
			if child == nil {
				continue
			}
			out = append(out, walkAs(x[k], child, append(append([]any{}, path...), k), contains(s.Required, k))...)
		}
	case []any:
		if len(x) > 0 && s.Items != nil {
			out = append(out, walk(x[0], s.Items.Value, append(append([]any{}, path...), 0))...)
		}
	}
	return out
}

// mutations lists the ways to break this node.
func (n node) mutations() []mut {
	var out []mut
	s := n.schema
	types := s.Type.Slice()
	_, _, isMap := mapValue(s)
	isMap = isMap && contains(types, "object") && len(s.Properties) == 0

	// A value of another type, and null where null is not allowed.
	for _, c := range []struct {
		name string
		v    any
		null bool
	}{{"null", nil, true}, {"true", true, false}, {"string", "x", false}, {"number", 1, false}, {"array", []any{}, false}, {"object", map[string]any{}, false}} {
		if c.null && (contains(types, "null") || s.Default != nil) {
			continue // null is how a client leaves out a member that has a default
		}
		if !c.null && s.VisitJSON(c.v) == nil {
			continue // the schema accepts this one: not a mutation
		}
		out = append(out, mut{name: "type " + c.name, value: c.v, isNull: c.null})
	}
	if n.required {
		out = append(out, mut{name: "dropped", drop: true})
	}

	// The declared members again, spelled in another letter case. encoding/json binds a
	// key to a field without regard to case (and Unicode folding: the long s and the Kelvin
	// sign too), so a schema that does not close the object lets a value it never saw reach
	// the handler (round 5, tenant-r5-7). Each variant carries a NUL; the first of an object
	// also carries a 64 KiB value. All must be refused.
	if len(s.Properties) > 0 && contains(types, "object") {
		// A member the document does not declare, named like one a client would try to forge.
		out = append(out, mut{name: "unknown member tenant_id", addKey: "tenant_id", value: "x"})
		for i, p := range sortedNames(s.Properties) {
			for _, v := range caseVariants(p) {
				out = append(out, mut{name: "case variant " + v + " with NUL", addKey: v, value: "a\x00"})
				if i == 0 {
					out = append(out, mut{name: "case variant " + v + " 64 KiB", addKey: v, value: strings.Repeat("a", 64<<10)})
				}
			}
		}
	}

	if contains(types, "string") {
		base, _ := n.value.(string)
		for _, name := range sortedNames(badChars()) {
			if acceptedMark(s, name) {
				continue
			}
			out = append(out, mut{name: name, value: base + badChars()[name]})
		}
		out = append(out, mut{name: "invalid UTF-8", raw: `"` + base + "\xff\xfe" + `"`})
		// A string whose bound is above 64 KiB (a document of the P2 routes, 4 MiB as base64) accepts the value, so it is
		// no mutation.
		if s.MaxLength == nil || *s.MaxLength < 64<<10 {
			out = append(out, mut{name: "64 KiB", value: strings.Repeat("a", 64<<10)})
		}
		if s.MaxLength != nil && *s.MaxLength < 12000 {
			out = append(out, mut{name: "maxLength+1", value: strings.Repeat("a", int(*s.MaxLength)+1)})
		}
		if s.MinLength > 0 {
			out = append(out, mut{name: "empty", value: ""})
		}
		for _, e := range emptyValues() {
			if s.VisitJSON(e.value) == nil {
				out = append(out, mut{name: e.name, value: e.value, accepted: true})
			}
		}
	}
	if contains(types, "integer") || contains(types, "number") {
		if s.Min != nil {
			out = append(out, mut{name: "below minimum", raw: strconv.FormatFloat(*s.Min-1, 'f', -1, 64)})
		}
		if s.Max != nil {
			out = append(out, mut{name: "above maximum", raw: strconv.FormatFloat(*s.Max+1, 'f', -1, 64)})
		}
		out = append(out,
			mut{name: "2^63", raw: "9223372036854775808"}, mut{name: "-2^63-1", raw: "-9223372036854775809"},
			mut{name: "1e308", raw: "1e308"}, mut{name: "400 digits", raw: strings.Repeat("9", 400)})
		if contains(types, "integer") && !contains(types, "number") {
			out = append(out, mut{name: "fraction", raw: "0.5"})
		}
	}
	if contains(types, "array") && s.MaxItems != nil && *s.MaxItems < 200 && s.Items != nil {
		if e, err := sample(s.Items.Value, 0); err == nil {
			list := make([]any, int(*s.MaxItems)+1)
			for i := range list {
				list[i] = e
			}
			out = append(out, mut{name: "maxItems+1", value: list})
		}
	}
	if isMap {
		vs, _, _ := mapValue(s)
		if v, err := sample(vs, 0); err == nil && s.MaxProps != nil && *s.MaxProps < 200 {
			m := map[string]any{}
			for i := 0; i <= int(*s.MaxProps); i++ {
				if k := keyFor(s, i); k != "" {
					m[k] = v
				}
			}
			if len(m) > int(*s.MaxProps) {
				out = append(out, mut{name: "maxProperties+1", value: m})
			}
		}
		// The keys of a map are client strings too. They are mutated through the
		// first key the baseline holds.
		if m, ok := n.value.(map[string]any); ok && len(m) > 0 {
			for _, name := range sortedNames(badChars()) {
				if name == "ZWNJ" && false {
					continue
				}
				out = append(out, mut{name: "key " + name, rawKey: "k" + jsonEscape(badChars()[name])})
			}
			out = append(out, mut{name: "key invalid UTF-8", rawKey: "k\xff"}, mut{name: "key 64 KiB", rawKey: strings.Repeat("a", 64<<10)})
		}
	}
	return out
}

func jsonEscape(s string) string {
	b, _ := json.Marshal(s)
	return string(b[1 : len(b)-1])
}

// ---------------------------------------------------------------------------
// Tree edits

func deepCopy(v any) any {
	switch x := v.(type) {
	case map[string]any:
		m := make(map[string]any, len(x))
		for k, e := range x {
			m[k] = deepCopy(e)
		}
		return m
	case []any:
		l := make([]any, len(x))
		for i, e := range x {
			l[i] = deepCopy(e)
		}
		return l
	}
	return v
}

func setAt(root any, path []any, v any) any {
	if len(path) == 0 {
		return v
	}
	switch k := path[0].(type) {
	case string:
		m := root.(map[string]any)
		m[k] = setAt(m[k], path[1:], v)
	case int:
		l := root.([]any)
		l[k] = setAt(l[k], path[1:], v)
	}
	return root
}

func dropAt(root any, path []any) any {
	if len(path) == 1 {
		if k, ok := path[0].(string); ok {
			delete(root.(map[string]any), k)
		} else {
			root = []any{}
		}
		return root
	}
	switch k := path[0].(type) {
	case string:
		m := root.(map[string]any)
		m[k] = dropAt(m[k], path[1:])
	case int:
		l := root.([]any)
		l[k] = dropAt(l[k], path[1:])
	}
	return root
}

// renameKey replaces the first key of the map at path with name.
func renameKey(root any, path []any, name string) any {
	target := root
	for _, p := range path {
		switch k := p.(type) {
		case string:
			target = target.(map[string]any)[k]
		case int:
			target = target.([]any)[k]
		}
	}
	m, ok := target.(map[string]any)
	if !ok {
		return root
	}
	for _, k := range sortedNames(m) {
		m[name] = m[k]
		delete(m, k)
		break
	}
	return root
}

// Result is what a fired request got.
type Result struct {
	Status int
	Body   []byte
}

// Do sends c to h as a client at ip on host, with ctx as the request context (a
// cancelled one is a client that left), and no cookie. A route that needs a session
// answers 401 to it before it reads the body (tenant-r5-2), so use DoAs for those.
func Do(ctx context.Context, h http.Handler, host, ip string, c Case) Result {
	return DoAs(ctx, h, host, ip, c, nil)
}

// DoAs is Do with a cookie. The pipeline looks at the cookie of a session route first
// and checks the schema only for one that can be ours, so a test of the schema of a
// session route sends Cookie, a cookie whose tag checks and whose session need not
// exist. One cookie is one budget of the route's class, so each request gets its own.
func DoAs(ctx context.Context, h http.Handler, host, ip string, c Case, cookie *http.Cookie) Result {
	var body io.Reader
	if c.Body != nil {
		body = bytes.NewReader(c.Body)
	}
	req := httptest.NewRequest(c.Method, "/api/v1"+c.Path, body).WithContext(ctx)
	req.Host = host
	req.Header.Set("X-Forwarded-For", ip)
	req.Header.Set("User-Agent", "boundary-fuzz")
	if cookie != nil {
		req.AddCookie(cookie)
	}
	for k, v := range c.Header {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return Result{Status: w.Code, Body: w.Body.Bytes()}
}

// IP is an address on its own /24 for case number n, so the network-keyed buckets of
// one request never spend the budget of the next.
func IP(n int) string { return fmt.Sprintf("10.%d.%d.7", n/250+1, n%250+1) }

// Verdict checks one result against the case and returns what is wrong with it, or
// an empty string. A baseline must get past the check of the schema and must not be
// a server fault, except for the declared unavailable answers of a service whose
// gateway or database is not there. Every other case must be refused 400 (413 for a
// request that is simply too large).
func Verdict(c Case, r Result) string {
	switch {
	case c.Baseline && (r.Status == 400 || r.Status == 413):
		return fmt.Sprintf("the baseline was refused by the schema check (%d): the generator and the document disagree", r.Status)
	case c.Baseline && r.Status >= 500 && r.Status != 503:
		return fmt.Sprintf("the baseline got %d", r.Status)
	case !c.Baseline && r.Status != 400 && r.Status != 413:
		return fmt.Sprintf("status %d, want 400 or 413 before any handler ran", r.Status)
	}
	return ""
}

// AbortVerdict checks the baseline of an operation sent by a client that had
// already gone: never a 5xx, never a body for nobody to read. 499 is the usual
// answer, and a 4xx decided before the context was looked at is fine too.
func AbortVerdict(r Result) string {
	if r.Status >= 500 {
		return fmt.Sprintf("a client that left got a %d", r.Status)
	}
	return ""
}

// WarnLines returns the lines of a JSON log that are WARN or ERROR, for a test that
// asserts a client's input never put one there. A line is cut at 200 characters.
func WarnLines(log string) []string {
	var out []string
	for _, l := range strings.Split(log, "\n") {
		if strings.Contains(l, `"level":"WARN"`) || strings.Contains(l, `"level":"ERROR"`) {
			if len(l) > 200 {
				l = l[:200]
			}
			out = append(out, l)
		}
	}
	return out
}

// caseVariants returns spellings of a declared member name that differ from it and
// that encoding/json would still bind to it: the upper-case form, the form with the
// first letter changed, and one with the long s or the Kelvin sign where the name has
// an s or a k.
func caseVariants(name string) []string {
	seen := map[string]bool{name: true}
	var out []string
	add := func(v string) {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	add(strings.ToUpper(name))
	if name != "" {
		first := strings.ToUpper(name[:1])
		if first == name[:1] {
			first = strings.ToLower(name[:1])
		}
		add(first + name[1:])
	}
	if i := strings.IndexAny(name, "sS"); i >= 0 {
		add(name[:i] + "\u017f" + name[i+1:])
	}
	if i := strings.IndexAny(name, "kK"); i >= 0 {
		add(name[:i] + "\u212a" + name[i+1:])
	}
	return out
}

// addKeyAt adds key with value to the object at path.
func addKeyAt(root any, path []any, key string, v any) any {
	target := root
	for _, p := range path {
		switch k := p.(type) {
		case string:
			target = target.(map[string]any)[k]
		case int:
			target = target.([]any)[k]
		}
	}
	if m, ok := target.(map[string]any); ok {
		m[key] = v
	}
	return root
}

// Cookie makes a session cookie that session.Manager.Screen accepts, under the MAC
// domain of the service being tested (keyring.DomainAuthMAC for the tenant API,
// DomainAdminMAC for the admin API), whose session does not exist, with a made-up session id.
// It mirrors the layout of the session token (internal/auth/session/tag.go: the session id in 16
// bytes, 20 random bytes, the expiry in 4, an 8 byte tag over those 40). If that layout changes
// the cookie stops being plausible, every request of a session route answers 401 and the fuzz
// fails loudly, so the copy cannot drift in silence.
func Cookie(ring *keyring.Ring, domain, name string, expires time.Time) *http.Cookie {
	return CookieFor(ring, domain, name, uuid.New(), expires)
}

// CookieFor is Cookie for a given session id, for the tests that spend one session's budget
// with several cookies of it (the cookies of a rotation chain all name the one session).
func CookieFor(ring *keyring.Ring, domain, name string, sessionID uuid.UUID, expires time.Time) *http.Cookie {
	var raw [48]byte
	copy(raw[:16], sessionID[:])
	if _, err := rand.Read(raw[16:36]); err != nil {
		panic(err)
	}
	binary.BigEndian.PutUint32(raw[36:40], uint32(expires.Unix()))
	copy(raw[40:], ring.MAC(domain, keyring.LabelSession, raw[:40])[:8])
	return &http.Cookie{Name: name, Value: base64.RawURLEncoding.EncodeToString(raw[:])}
}

// TenantCookie and AdminCookie are Cookie for the two services.
func TenantCookie(ring *keyring.Ring, expires time.Time) *http.Cookie {
	return Cookie(ring, keyring.DomainAuthMAC, session.CookieSession, expires)
}

// AdminCookie is Cookie for the admin API.
func AdminCookie(ring *keyring.Ring, expires time.Time) *http.Cookie {
	return Cookie(ring, keyring.DomainAdminMAC, session.CookieAdmin, expires)
}

// acceptedMark says the schema is meant to accept this one of the badChars, so sending it is not
// a mutation: the zero width non-joiner in a prose field, and every paste mark (digits.PasteMark)
// in a field on the pasted patterns, which exist so that the fold of internal/auth/digits sees what
// a paste carries (round 14, primitives-r14-3). The NUL, the bell, NEL and the private-use code
// point stay refused there.
func acceptedMark(s *openapi3.Schema, name string) bool {
	if name == "ZWNJ" && strings.Contains(s.Pattern, "200C") {
		return true
	}
	if s.Pattern != digits.PastePattern && s.Pattern != digits.PasteContentPattern {
		return false
	}
	for _, r := range badChars()[name] {
		return digits.PasteMark(r)
	}
	return false
}
