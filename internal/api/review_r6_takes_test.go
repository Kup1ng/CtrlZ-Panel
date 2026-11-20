package api

import (
	"reflect"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

// TestTheHarnessSeesAnIDInTheBodyAtAnyDepth is tenant-r6-3 and -11, and tenant-r16-13: the detector that makes
// the isolation harness demand a Cross call read only path ids and the ticket header, so a session route
// that took a row id in its body (reauth's otp_challenge_id) needed none, and a future PATCH
// /account/passkeys {id, name} would not either. Then it read NAMES (id, or ending in _id), so a session
// route that took `{"credential": <uuid>}` needed none. A value is a row reference by its SCHEMA (format
// uuid, or the document's uuid pattern) or by a name that says id, under a $ref, an array item or an allOf;
// every place is listed; a body with none is not. The planted documents are one case for each way a
// document can spell a reference, and the expected lists are exact.
func TestTheHarnessSeesAnIDInTheBodyAtAnyDepth(t *testing.T) {
	const doc = `
openapi: 3.0.3
info: {title: t, version: "1"}
paths:
  /flat: {post: {operationId: flat, requestBody: {content: {application/json: {schema: {type: object, properties: {name: {type: string}, thing_id: {type: string}}}}}}, responses: {"204": {description: ok}}}}
  /deep: {post: {operationId: deep, requestBody: {content: {application/json: {schema: {type: object, properties: {outer: {type: array, items: {$ref: "#/components/schemas/Inner"}}}}}}}, responses: {"204": {description: ok}}}}
  /all: {post: {operationId: all, requestBody: {content: {application/json: {schema: {allOf: [{$ref: "#/components/schemas/Inner"}]}}}}, responses: {"204": {description: ok}}}}
  /none: {post: {operationId: none, requestBody: {content: {application/json: {schema: {type: object, properties: {ticket: {type: string}, identity: {type: string}, valid: {type: string}}}}}}, responses: {"204": {description: ok}}}}
  /nobody: {post: {operationId: nobody, responses: {"204": {description: ok}}}}
  /renamed: {post: {operationId: renamed, requestBody: {content: {application/json: {schema: {type: object, properties: {credential: {type: string, format: uuid}, label: {type: string}}}}}}, responses: {"204": {description: ok}}}}
  /patterned: {post: {operationId: patterned, requestBody: {content: {application/json: {schema: {type: object, properties: {target: {type: string, pattern: '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'}}}}}}, responses: {"204": {description: ok}}}}
  /hdr: {post: {operationId: hdr, parameters: [{name: X-Credential-Id, in: header, schema: {type: string, format: uuid}}, {name: X-Trace, in: header, schema: {type: string}}], responses: {"204": {description: ok}}}}
  /cookie: {post: {operationId: cookie, parameters: [{name: pick, in: cookie, schema: {type: string, format: uuid}}], responses: {"204": {description: ok}}}}
  /map: {post: {operationId: map, requestBody: {content: {application/json: {schema: {type: object, properties: {ids: {type: object, additionalProperties: {type: string, format: uuid}}}}}}}, responses: {"204": {description: ok}}}}
  /tuple: {post: {operationId: tuple, requestBody: {content: {application/json: {schema: {type: object, properties: {pair: {type: array, prefixItems: [{type: string, format: uuid}, {type: string}]}}}}}}, responses: {"204": {description: ok}}}}
  /qobj: {post: {operationId: qobj, parameters: [{name: filter, in: query, content: {application/json: {schema: {type: object, properties: {owner: {type: string, format: uuid}}}}}}], responses: {"204": {description: ok}}}}
  /notid: {post: {operationId: notid, parameters: [{name: X-Trace, in: header, schema: {type: string}}, {name: lang, in: cookie, schema: {type: string}}], responses: {"204": {description: ok}}}}
  /two/{id}: {post: {operationId: two, parameters: [{name: id, in: path, required: true, schema: {type: string}}, {name: scope, in: query, schema: {type: string, format: uuid}}], requestBody: {content: {application/json: {schema: {type: object, properties: {credential: {type: string, format: uuid}, request_id: {type: string}}}}}}, responses: {"204": {description: ok}}}}
components:
  schemas:
    Inner: {type: object, properties: {id: {type: string}}}
`
	d, err := openapi3.NewLoader().LoadFromData([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	session := map[string]bool{}
	for _, item := range d.Paths.Map() {
		for _, op := range item.Operations() {
			session[op.OperationID] = true
		}
	}
	want := map[string][]string{
		"flat":      {"body:thing_id"},
		"deep":      {"body:outer[].id"},
		"all":       {"body:id"},
		"renamed":   {"body:credential"},
		"patterned": {"body:target"},
		"two":       {"body:credential", "body:request_id", "path:id", "query:scope"},
		"hdr":       {"header:X-Credential-Id"},
		"cookie":    {"cookie:pick"},
		"map":       {"body:ids{}"},
		"tuple":     {"body:pair[]"},
		"qobj":      {"query:filter.owner"},
	}
	if got := idLocations(d, session); !reflect.DeepEqual(got, want) {
		t.Errorf("locations = %v, want %v", got, want)
	}
	// An operation with no session takes no id of its body or query: what it holds is a bearer proof.
	for k := range session {
		session[k] = false
	}
	if got := idLocations(d, session); len(got["renamed"]) != 0 || len(got["flat"]) != 0 || !reflect.DeepEqual(got["two"], []string{"path:id"}) {
		t.Errorf("without a session the locations were %v", got)
	}
	// And the real document: reauth is the case the review found.
	if got := opsThatTakeAnID(t)["reauth"]; len(got) == 0 {
		t.Error("reauth names a challenge by a body id and the detector does not see it")
	}
}

// TestTheSchemaWalkReadsEverySchemaField is tenant-r16-24. The walk that finds a row reference read the
// keywords somebody remembered (properties, items, allOf, oneOf, anyOf), so a map of uuids
// (additionalProperties) and a tuple (prefixItems) were not seen. It now reads every schema below a schema by
// reflection over openapi3.Schema, and it PANICS for a field that holds a schema in a shape it does not read,
// so a keyword the library adds is a failing test and not a hole. A schema with every sub-schema keyword set
// yields one child for each, with the path segment its keyword adds.
func TestTheSchemaWalkReadsEverySchemaField(t *testing.T) {
	leaf := func() *openapi3.SchemaRef { return &openapi3.SchemaRef{Value: &openapi3.Schema{Format: "uuid"}} }
	s := &openapi3.Schema{
		Properties:           openapi3.Schemas{"a": leaf()},
		Items:                leaf(),
		AdditionalProperties: openapi3.AdditionalProperties{Schema: leaf()},
		PrefixItems:          openapi3.SchemaRefs{leaf()},
		AllOf:                openapi3.SchemaRefs{leaf()},
		OneOf:                openapi3.SchemaRefs{leaf()},
		AnyOf:                openapi3.SchemaRefs{leaf()},
		Not:                  leaf(),
	}
	got := map[string]int{}
	for _, c := range subSchemas(s) {
		got[c.seg]++
	}
	want := map[string]int{".a": 1, "[]": 2, "{}": 1, "": 4}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("children by segment = %v, want %v", got, want)
	}
	// Every field of the library's Schema is read (or the walk panics here): a new schema keyword fails this
	// test until the walk is taught it.
	_ = subSchemas(&openapi3.Schema{})
}
