// Package flood generates the requests of the proof-before-work flood test (P1 auth
// review round 5, rules.md topic 8): for an operation of an OpenAPI document that needs
// no session, requests whose proof is made up (an unknown ticket, a challenge nobody
// issued, an invite nobody made) and whose password, where the schema has one, is 100
// runes long. A route that scores, hashes, verifies or writes a row for such a request
// before it has checked the proof shows up in the meters.
//
// The bodies are generated from the schema and not written per route, so a route added
// to the document is covered the day it is added, and a route whose body this package
// cannot build fails the test that uses it. Each operation yields one request with every
// property filled and one request per optional property with only that property left out:
// register with a made-up invite token stops at the invite lookup, and the request without
// the token is the one that reaches the code.
//
// It is imported from test files only, like authtest.
package flood

import (
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/Kup1ng/CtrlZ-Panel/internal/apispec"
	"github.com/Kup1ng/CtrlZ-Panel/internal/authtest/oracle"
)

// Password is the 100-rune password of every request: long enough to be expensive to
// score and to hash, and not on any list.
func Password() string {
	const unit = "Qz7-vLm2-Rk9x-Tw4p-" // 20 runes
	return strings.Repeat(unit, 5)
}

// Ticket is a ticket-shaped value that names nothing; n makes each one different.
func Ticket(n int) string {
	return strings.Repeat(string(rune('A'+n%20)), 43)
}

// LongTicket is a value as long as a sealed ceremony ticket, in the alphabet of one, that
// names nothing.
func LongTicket(n int) string {
	return strings.Repeat(string(rune('a'+n%20)), 700)
}

// Request is one generated request and what it was made from.
type Request struct {
	Name string
	oracle.Request
}

type doc struct {
	root map[string]any
}

// Requests builds the requests of op from the OpenAPI document. seq makes made-up values
// differ between calls.
func Requests(raw []byte, op apispec.Operation, seq func() int) ([]Request, error) {
	var root map[string]any
	if err := yaml.Unmarshal(raw, &root); err != nil {
		return nil, err
	}
	d := doc{root}
	node := d.lookup("paths", op.Path, strings.ToLower(op.Method))
	m, ok := node.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("flood: %s has no operation in the document", op.Key())
	}
	headers := d.headerParams(m)
	body, bodyKind, err := d.bodySchema(m)
	if err != nil {
		return nil, fmt.Errorf("flood: %s: %w", op.Key(), err)
	}
	base := func(variant string, b any) Request {
		h := map[string]string{}
		for name := range headers {
			h[name] = Ticket(seq())
		}
		if len(headers) > 0 {
			h["Content-Type"] = "application/json"
		}
		r := oracle.Request{Method: op.Method, Path: op.Path, Body: b, Header: h}
		return Request{Name: op.ID + variant, Request: r}
	}
	var out []Request
	switch bodyKind {
	case "none":
		out = append(out, base("", nil))
	case "raw":
		out = append(out, base("", []byte(`{"id":"AAAA","rawId":"AAAA","type":"public-key","response":{}}`)))
		if len(headers) > 0 {
			long := base("/long-ticket", []byte(`{"id":"AAAA","rawId":"AAAA","type":"public-key","response":{}}`))
			for name := range headers {
				long.Header[name] = LongTicket(seq())
			}
			out = append(out, long)
		}
	default:
		props, required := d.properties(body)
		var names []string
		for n := range props {
			names = append(names, n)
		}
		sort.Strings(names)
		full := map[string]any{}
		for _, n := range names {
			full[n] = d.value(n, props[n])
		}
		out = append(out, base("", full))
		for _, n := range names {
			if required[n] {
				continue
			}
			part := map[string]any{}
			for k, v := range full {
				if k != n {
					part[k] = v
				}
			}
			out = append(out, base("/without-"+n, part))
		}
	}
	return out, nil
}

func (d doc) lookup(path ...string) any {
	var cur any = d.root
	for _, p := range path {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = m[p]
	}
	return cur
}

// resolve follows a $ref of this document.
func (d doc) resolve(n any) any {
	for i := 0; i < 8; i++ {
		m, ok := n.(map[string]any)
		if !ok {
			return n
		}
		ref, ok := m["$ref"].(string)
		if !ok {
			return n
		}
		n = d.lookup(strings.Split(strings.TrimPrefix(ref, "#/"), "/")...)
	}
	return n
}

// headerParams returns the header parameters of an operation.
func (d doc) headerParams(op map[string]any) map[string]bool {
	out := map[string]bool{}
	ps, _ := op["parameters"].([]any)
	for _, p := range ps {
		m, ok := d.resolve(p).(map[string]any)
		if ok && m["in"] == "header" {
			if name, _ := m["name"].(string); name != "" {
				out[name] = true
			}
		}
	}
	return out
}

// bodySchema returns the JSON schema of the request body, and "none", "raw" (an open
// object the handler takes untouched) or "object".
func (d doc) bodySchema(op map[string]any) (any, string, error) {
	rb, ok := d.resolve(op["requestBody"]).(map[string]any)
	if !ok {
		return nil, "none", nil
	}
	content, _ := rb["content"].(map[string]any)
	js, _ := content["application/json"].(map[string]any)
	if js == nil {
		return nil, "", fmt.Errorf("a request body that is not application/json")
	}
	schema := d.resolve(js["schema"])
	sm, _ := schema.(map[string]any)
	if sm == nil {
		return nil, "", fmt.Errorf("a request body with no schema")
	}
	if _, has := sm["properties"]; !has {
		return nil, "raw", nil
	}
	return schema, "object", nil
}

func (d doc) properties(schema any) (map[string]any, map[string]bool) {
	sm, _ := d.resolve(schema).(map[string]any)
	props := map[string]any{}
	if p, ok := sm["properties"].(map[string]any); ok {
		for k, v := range p {
			props[k] = d.resolve(v)
		}
	}
	req := map[string]bool{}
	if r, ok := sm["required"].([]any); ok {
		for _, v := range r {
			if s, ok := v.(string); ok {
				req[s] = true
			}
		}
	}
	return props, req
}

// value makes a made-up value for a property by what the schema and the name say it is.
func (d doc) value(name string, schema any) any {
	sm, _ := schema.(map[string]any)
	if en, ok := sm["enum"].([]any); ok && len(en) > 0 {
		return en[0]
	}
	switch sm["type"] {
	case "boolean":
		return false
	case "integer", "number":
		return 1
	case "array":
		return []any{}
	case "object":
		return map[string]any{}
	}
	if sm["format"] == "uuid" {
		return "6b1f3a4e-2c7d-4e0a-9d51-0a1b2c3d4e5f"
	}
	n := strings.ToLower(name)
	switch {
	case strings.Contains(n, "password"):
		return Password()
	case strings.Contains(n, "phone"):
		return "09129990001"
	case strings.Contains(n, "token"), strings.Contains(n, "ticket"):
		return Ticket(7)
	case strings.Contains(n, "recovery"):
		return "abcd-efgh-ijkl"
	case strings.Contains(n, "code"):
		return "000000"
	case strings.Contains(n, "user"):
		return "nobody"
	}
	return "x"
}
