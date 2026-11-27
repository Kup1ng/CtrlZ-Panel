package api

import (
	"slices"

	apidoc "github.com/Kup1ng/CtrlZ-Panel/api"
	"github.com/Kup1ng/CtrlZ-Panel/internal/apispec"
	"github.com/Kup1ng/CtrlZ-Panel/internal/ratelimit"
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

// TestEverySessionStringIsClassified is tenant-r17-6 and -11. Round 16 found a row reference by its schema (a
// uuid) or its name (id) and recorded that a value that is neither is not found; the paging cursor was one. The
// document now classifies every string input of a session operation: a uuid, an enum or a constant needs
// nothing, and any other string carries x-ctrlz-rowref, true where it names a row (and the harness then asks
// for a Cross call at that place) and false where it does not. A string with no mark, or a mark that is not a
// boolean, is listed and fails; the real document has none.
func TestEverySessionStringIsClassified(t *testing.T) {
	const doc = `
openapi: 3.0.3
info: {title: t, version: "1"}
paths:
  /plain: {post: {operationId: plain, requestBody: {content: {application/json: {schema: {type: object, properties: {handle: {type: string, maxLength: 36}}}}}}, responses: {"204": {description: ok}}}}
  /marked: {post: {operationId: marked, requestBody: {content: {application/json: {schema: {type: object, properties: {handle: {type: string, x-ctrlz-rowref: true}, label: {type: string, x-ctrlz-rowref: false}}}}}}, responses: {"204": {description: ok}}}}
  /badmark: {post: {operationId: badmark, requestBody: {content: {application/json: {schema: {type: object, properties: {handle: {type: string, x-ctrlz-rowref: "yes"}}}}}}, responses: {"204": {description: ok}}}}
  /closed: {post: {operationId: closed, requestBody: {content: {application/json: {schema: {type: object, properties: {kind: {type: string, enum: [a, b]}, id: {type: string, format: uuid}}}}}}, responses: {"204": {description: ok}}}}
  /nullable: {post: {operationId: nullable, requestBody: {content: {application/json: {schema: {type: object, properties: {h: {type: [string, "null"]}}}}}}, responses: {"204": {description: ok}}}}
  /deep: {post: {operationId: deep, requestBody: {content: {application/json: {schema: {type: object, properties: {outer: {type: array, items: {type: string}}, m: {type: object, additionalProperties: {type: string}}}}}}}, responses: {"204": {description: ok}}}}
  /query: {get: {operationId: query, parameters: [{name: cursor, in: query, schema: {type: string}}, {name: seen, in: header, schema: {type: string, x-ctrlz-rowref: false}}], responses: {"200": {description: ok}}}}
  /nosession: {post: {operationId: nosession, requestBody: {content: {application/json: {schema: {type: object, properties: {code: {type: string}}}}}}, responses: {"204": {description: ok}}}}
`
	d, err := openapi3.NewLoader().LoadFromData([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	session := map[string]bool{}
	for _, item := range d.Paths.Map() {
		for _, op := range item.Operations() {
			session[op.OperationID] = op.OperationID != "nosession"
		}
	}
	want := []string{"badmark body.handle", "deep body.m{}", "deep body.outer[]", "nullable body.h", "plain body.handle", "query query:cursor"}
	if got := unclassifiedStrings(d, session); !reflect.DeepEqual(got, want) {
		t.Errorf("unclassified = %v, want %v", got, want)
	}
	// A mark of true is a location the harness asks a Cross call for, wherever the string is.
	if got := idLocations(d, session)["marked"]; !reflect.DeepEqual(got, []string{"body:handle"}) {
		t.Errorf("a string marked as a row reference is at %v, want body:handle", got)
	}
	if got := idLocations(d, session)["query"]; len(got) != 0 {
		t.Errorf("an unmarked string is a location: %v", got)
	}
	// A path value marked false is a catalog key and takes no Cross call, unless it is a uuid: a uuid names a row, whatever
	// the mark says (p2-B8-r1-15).
	const pathDoc = `
openapi: 3.0.3
info: {title: t, version: "1"}
paths:
  /slug/{slug}: {get: {operationId: bySlug, parameters: [{name: slug, in: path, required: true, schema: {type: string, x-ctrlz-rowref: false}}], responses: {"200": {description: ok}}}}
  /row/{endpoint_id}: {get: {operationId: byMarkedUUID, parameters: [{name: endpoint_id, in: path, required: true, schema: {type: string, format: uuid, x-ctrlz-rowref: false}}], responses: {"200": {description: ok}}}}
`
	pd, err := openapi3.NewLoader().LoadFromData([]byte(pathDoc))
	if err != nil {
		t.Fatal(err)
	}
	pathLocs := idLocations(pd, map[string]bool{"bySlug": true, "byMarkedUUID": true})
	if len(pathLocs["bySlug"]) != 0 || !reflect.DeepEqual(pathLocs["byMarkedUUID"], []string{"path:endpoint_id"}) {
		t.Errorf("path locations = %v, want none for the catalog key and path:endpoint_id for the uuid", pathLocs)
	}
	// And the real document, whose cursor is the case the review found.
	real, err := openapi3.NewLoader().LoadFromData(apidoc.Tenant())
	if err != nil {
		t.Fatal(err)
	}
	auth, err := apispec.Parse(apidoc.Tenant(), ratelimit.Tenant)
	if err != nil {
		t.Fatal(err)
	}
	needs := map[string]bool{}
	for _, op := range auth {
		needs[op.ID] = op.Auth != apispec.None
	}
	if got := unclassifiedStrings(real, needs); len(got) != 0 {
		t.Errorf("the tenant document has unclassified strings in session operations: %v (mark each x-ctrlz-rowref true or false)", got)
	}
	locs := idLocations(real, needs)
	for _, id := range []string{"listNotifications", "listAnnouncements"} {
		if !slices.Contains(locs[id], "query:cursor") {
			t.Errorf("%s takes a cursor, which names a row, and the harness does not see it: %v", id, locs[id])
		}
	}
}
