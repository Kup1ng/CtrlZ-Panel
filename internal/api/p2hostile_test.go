package api

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
)

// TestHostileCharactersInsideADocumentGiveACode: spec 10.5. A NUL, a C1 control, a bidi override and a zero width space in the
// name of a profile, the name of a folder or the comment of a rule, inside the file of an Import or an Upload, are refused
// with a code at the member that holds them, never a 5xx and never a stored row. The boundary fuzz mutates the members of
// the request, where the document is one base64 string, so it never reaches the members inside the file; this is the
// only test between those members and the text columns (p2-B8-r2-7).
func TestHostileCharactersInsideADocumentGiveACode(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A := f.env.A
	p := f.fresh(A.Tenant, A.User).mustProfile("Hostile", "custom")
	var fold struct {
		ID uuid.UUID `json:"id"`
	}
	f.fresh(A.Tenant, A.User).post("/profiles/"+p.ID.String()+"/folders", map[string]any{"name": "In", "kind": "standard"}).want(201, "").json(&fold)
	upload := "/profiles/" + p.ID.String() + "/folders/" + fold.ID.String() + ":upload"

	count := func(dst *int) {
		f.env.Scan(t, `SELECT (SELECT count(*) FROM ctrlz.profiles WHERE tenant_id = $1) + (SELECT count(*) FROM ctrlz.rules WHERE tenant_id = $1)`, []any{A.Tenant}, dst)
	}
	var before int
	count(&before)

	// Each is written as a JSON escape, so the file is valid text and only the value is hostile.
	chars := []struct{ name, esc string }{
		{"NUL", jsonEscape(0x0000)}, {"C1 control", jsonEscape(0x0085)}, {"bidi override", jsonEscape(0x202e)}, {"zero width space", jsonEscape(0x200b)},
	}
	n := 0
	for _, ch := range chars {
		bad := "a" + ch.esc + "b"
		head := `{"format":"ctrlz-profile","version":1,"kind":"custom","name":`
		imports := []struct{ where, pointer, doc string }{
			{"profile name", "/name", head + `"` + bad + `"}`},
			{"folder name", "/folders/0/name", head + `"ok","folders":[{"ref":"f1","name":"` + bad + `","kind":"standard"}]}`},
			{"rule comment", "/rules/0/comment", head + `"ok","rules":[{"pattern":"a.example","action":"block","comment":"` + bad + `"}]}`},
		}
		for _, c := range imports {
			n++
			r := f.fresh(A.Tenant, A.User).do("POST", "/profiles:import", map[string]any{"document": b64(c.doc)}, idem(fmt.Sprintf("hostile-%d", n)))
			var fl fieldList
			r.want(422, "validation_failed").json(&fl)
			if !fl.has(c.pointer, "invalid") {
				t.Errorf("import, %s with a %s: fields %+v, want invalid at %s", c.where, ch.name, fl.Fields, c.pointer)
			}
		}
		n++
		r := f.fresh(A.Tenant, A.User).do("POST", upload, map[string]any{
			"document": b64(`{"format":"ctrlz-rules","version":1,"rules":[{"pattern":"a.example","action":"block","comment":"` + bad + `"}]}`)},
			idem(fmt.Sprintf("hostile-%d", n)))
		var fl fieldList
		r.want(422, "validation_failed").json(&fl)
		if !fl.has("/rules/0/comment", "invalid") {
			t.Errorf("upload, rule comment with a %s: fields %+v, want invalid at /rules/0/comment", ch.name, fl.Fields)
		}
	}
	var after int
	count(&after)
	if after != before {
		t.Fatalf("refused documents left %d profiles and rules, there were %d", after, before)
	}
}

// jsonEscape is the six characters of the JSON escape of one code point, so the file under test is valid text.
func jsonEscape(r rune) string { return fmt.Sprintf("\\u%04x", r) }
