package api

import (
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

// TestTheHarnessSeesAnIDInTheBodyAtAnyDepth is tenant-r6-3 and -11: the detector that makes the
// isolation harness demand a Cross call read only path ids and the ticket header, so a session
// route that took a row id in its body (reauth's otp_challenge_id) needed none, and a future
// PATCH /account/passkeys {id, name} would not either. A property named id or ending in _id counts,
// under a $ref, an array item or an allOf; a body with none does not.
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
components:
  schemas:
    Inner: {type: object, properties: {id: {type: string}}}
`
	d, err := openapi3.NewLoader().LoadFromData([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"/flat": true, "/deep": true, "/all": true, "/none": false, "/nobody": false}
	for p, item := range d.Paths.Map() {
		if got := bodyID(item.Post) != ""; got != want[p] {
			t.Errorf("%s: takes an id = %v, want %v", p, got, want[p])
		}
	}
	// And the real document: reauth is the case the review found.
	if got := opsThatTakeAnID(t)["reauth"]; got == "" {
		t.Error("reauth names a challenge by a body id and the detector does not see it")
	}
}
