package api

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/bulkgate"
)

// Review round 4 of package B3 (routes and jobs), one test per finding that changed behaviour.

// TestTheRulesListPagesToTheEndUnderEverySort: the cursor of the rules list is longer than the 128 characters of the
// other lists, and the parameter that takes it back must allow that (p2-B3-r4-1). The first rule of the pattern sort has the longest key.
func TestTheRulesListPagesToTheEndUnderEverySort(t *testing.T) {
	f := newFrig(t, frigOpts{})
	a := f.makeSession(f.env.A.Tenant, f.env.A.User)
	p := a.mustProfile("Paging", "custom")
	base := "/profiles/" + p.ID.String()
	label := "0" + strings.Repeat("z", 62)                                          // sorts before the short keys, so a page of the pattern sort ends on it
	long := label + "." + label + "." + label + "." + "0" + strings.Repeat("y", 56) // 249 characters, near the 253 limit
	patterns := []string{"a.example", "b.example", long}
	a.post(base+"/rules", map[string]any{"patterns": patterns, "action": "block"}).want(201, "")
	for _, sort := range []string{"pattern", "created", "updated"} {
		var seen = map[string]bool{}
		cursor, longest := "", 0
		for page := 0; page < 10; page++ {
			path := base + "/rules?limit=1&sort=" + sort
			if cursor != "" {
				path += "&cursor=" + cursor
			}
			var out struct {
				Items []struct {
					ID uuid.UUID `json:"id"`
				} `json:"items"`
				NextCursor string `json:"next_cursor"`
			}
			a.get(path).want(200, "").json(&out)
			if len(out.Items) != 1 {
				t.Fatalf("sort %s page %d: %d items", sort, page, len(out.Items))
			}
			id := out.Items[0].ID.String()
			if seen[id] {
				t.Fatalf("sort %s: rule %s came twice", sort, id)
			}
			seen[id] = true
			longest = max(longest, len(out.NextCursor))
			if out.NextCursor == "" {
				break
			}
			cursor = out.NextCursor
		}
		if len(seen) != 3 {
			t.Errorf("sort %s reached %d of 3 rules", sort, len(seen))
		}
		if longest <= 128 {
			t.Errorf("sort %s: the longest cursor is %d characters, the test no longer covers the long form", sort, longest)
		}
	}
}

// TestACraftedPatternCursorIsBadRequest: a NUL or invalid UTF-8 in the position text would reach Postgres as a text
// parameter and fail with 22021, which answers 500 (p2-B3-r4-3).
func TestACraftedPatternCursorIsBadRequest(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A := f.env.A
	a := f.makeSession(A.Tenant, A.User)
	p := a.mustProfile("Cursor", "custom")
	base := "/profiles/" + p.ID.String()
	for _, text := range []string{"\x00", "a\x00b", "\xff", "ok\xc3"} {
		pos := base64.RawURLEncoding.EncodeToString([]byte(text))
		raw := "pattern|" + pos + "|" + uuid.NewString() + "|" + A.Tenant.String()
		c := base64.RawURLEncoding.EncodeToString([]byte(raw))
		a.get(base+"/rules?sort=pattern&cursor="+c).want(400, "bad_request")
	}
}

// TestADocumentExpiryBeforeYear1IsInvalidNot500: Postgres has no year 0, so the cast of the write failed with 22008 and
// answered 500 (or exhausted a job); the document check refuses it at its pointer (p2-B3-r4-2).
func TestADocumentExpiryBeforeYear1IsInvalidNot500(t *testing.T) {
	f := newFrig(t, frigOpts{})
	a := f.makeSession(f.env.A.Tenant, f.env.A.User)
	p := a.mustProfile("Year0", "custom")
	base := "/profiles/" + p.ID.String()
	var fold struct {
		ID uuid.UUID `json:"id"`
	}
	a.post(base+"/folders", map[string]any{"name": "In", "kind": "standard"}).want(201, "").json(&fold)
	up := base + "/folders/" + fold.ID.String() + ":upload"
	for i, at := range []string{"0000-01-01T00:00:00Z", "0000-12-31T23:59:59Z", "0001-01-01T00:00:00+01:00"} {
		rule := `{"pattern":"old.example","action":"block","expires_at":"` + at + `"}`
		var fl fieldList
		doc := `{"format":"ctrlz-profile","version":1,"kind":"custom","name":"Old","rules":[` + rule + `]}`
		a.do("POST", "/profiles:import", map[string]any{"document": b64(doc)}, idem(fmt.Sprintf("y0-imp-%d", i))).want(422, "validation_failed").json(&fl)
		if !fl.has("/rules/0/expires_at", "invalid") {
			t.Errorf("import %s: %+v, want /rules/0/expires_at invalid", at, fl.Fields)
		}
		rules := `{"format":"ctrlz-rules","version":1,"rules":[` + rule + `]}`
		fl = fieldList{}
		a.do("POST", up, map[string]any{"document": b64(rules)}, idem(fmt.Sprintf("y0-up-%d", i))).want(422, "validation_failed").json(&fl)
		if !fl.has("/rules/0/expires_at", "invalid") {
			t.Errorf("upload %s: %+v, want /rules/0/expires_at invalid", at, fl.Fields)
		}
	}
}

// TestExportsHoldTheBulkGateAndRefuseWhenItIsFull: an export builds its whole document in memory and keeps it until the
// client has read it, so it takes its weight in the bulk gate: a tenant with its share taken gets 503 server_busy on both
// export routes, another tenant is unaffected, and the weight is back after the answer (p2-B3-r4-4).
func TestExportsHoldTheBulkGateAndRefuseWhenItIsFull(t *testing.T) {
	f := newFrig(t, frigOpts{})
	gate := bulkgate.New(8<<20, 1<<20)
	f.deps.BulkGate = gate
	f.setLimiter(f.deps.Limiter)
	A, B := f.env.A, f.env.B
	a := f.makeSession(A.Tenant, A.User)
	b := f.makeSession(B.Tenant, B.User)
	pa := a.mustProfile("Exp", "custom")
	pb := b.mustProfile("Exp", "custom")
	var fold struct {
		ID uuid.UUID `json:"id"`
	}
	baseA, baseB := "/profiles/"+pa.ID.String(), "/profiles/"+pb.ID.String()
	a.post(baseA+"/folders", map[string]any{"name": "In", "kind": "standard"}).want(201, "").json(&fold)
	a.post(baseA+"/rules", map[string]any{"patterns": []string{"x.example"}, "action": "block"}).want(201, "")
	b.post(baseB+"/rules", map[string]any{"patterns": []string{"x.example"}, "action": "block"}).want(201, "")

	hold, ok := gate.Acquire(A.Tenant.String(), 1<<20)
	if !ok {
		t.Fatal("the test could not take A's share")
	}
	a.get(baseA+"/export").want(503, "server_busy")
	a.get(baseA+"/folders/"+fold.ID.String()+"/export").want(503, "server_busy")
	b.get(baseB+"/export").want(200, "")
	if _, mine := gate.Held(A.Tenant.String()); mine != 1<<20 {
		t.Fatalf("a refused export changed what A holds: %d", mine)
	}
	hold()
	a.get(baseA+"/export").want(200, "")
	a.get(baseA+"/folders/"+fold.ID.String()+"/export").want(200, "")
	a.get("/profiles/"+uuid.NewString()+"/export").want(404, "not_found")
	if all, _ := gate.Held(A.Tenant.String()); all != 0 {
		t.Fatalf("%d bytes are still held after the exports answered", all)
	}
}
