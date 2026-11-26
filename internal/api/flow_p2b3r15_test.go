package api

import (
	"testing"

	"github.com/google/uuid"
)

const nilID = "00000000-0000-0000-0000-000000000000"

// TestARuleBodyThatNamesNoRealFolderIsRefused: an all-zero folder or profile id in a body is 404, not "not sent", on
// every route that takes one; and a batch edit with a target and no action is a 422 that changes nothing
// (p2-B3-r15-1, r15-2).
func TestARuleBodyThatNamesNoRealFolderIsRefused(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A := f.env.A
	a := f.makeSession(A.Tenant, A.User)
	p := a.mustProfile("Nil", "custom")
	base := "/profiles/" + p.ID.String()
	var fold struct {
		ID uuid.UUID `json:"id"`
	}
	a.post(base+"/folders", map[string]any{"name": "In", "kind": "standard"}).want(201, "").json(&fold)
	var made struct {
		Rules []struct {
			ID uuid.UUID `json:"id"`
		} `json:"rules"`
	}
	a.post(base+"/rules", map[string]any{"patterns": []string{"in.example"}, "action": "block", "folder_id": fold.ID}).want(201, "").json(&made)
	rule := made.Rules[0].ID
	inFolder := func() int {
		var n int
		f.env.Scan(t, `SELECT count(*) FROM ctrlz.rules WHERE tenant_id = $1 AND profile_id = $2 AND folder_id IS NOT NULL`, []any{A.Tenant, p.ID}, &n)
		return n
	}

	a.post(base+"/rules", map[string]any{"patterns": []string{"new.example"}, "action": "block", "folder_id": nilID}).want(404, "not_found")
	a.do("PATCH", base+"/rules/"+rule.String(), map[string]any{"folder_id": nilID}).want(404, "not_found")
	a.do("POST", base+"/rules:batch", map[string]any{"op": "edit", "ids": []uuid.UUID{rule}, "set": map[string]any{"folder_id": nilID}}, idem("nil-1")).want(404, "not_found")
	a.do("POST", base+"/rules:batch", map[string]any{"op": "move", "ids": []uuid.UUID{rule}, "dest_profile_id": nilID, "dest_root": true}, idem("nil-2")).want(404, "not_found")
	a.do("POST", base+"/rules:batch", map[string]any{"op": "move", "ids": []uuid.UUID{rule}, "dest_folder_id": nilID}, idem("nil-3")).want(404, "not_found")
	a.post(base+"/rules/"+rule.String()+":transfer", map[string]any{"op": "move", "dest_profile_id": nilID, "dest_root": true}).want(404, "not_found")
	if got := inFolder(); got != 1 {
		t.Fatalf("%d rules are in a folder after the refused requests, want 1", got)
	}

	// A target without an action is the 422 of UpdateRule, whatever the other members say.
	var fl fieldList
	a.do("POST", base+"/rules:batch", map[string]any{"op": "edit", "ids": []uuid.UUID{rule}, "set": map[string]any{"target": map[string]any{"kind": "auto"}, "comment": "x"}}, idem("tgt-1")).
		want(422, "validation_failed").json(&fl)
	if !fl.has("/set/action", "required") {
		t.Errorf("fields %+v, want /set/action required", fl.Fields)
	}
	var n int
	f.env.Scan(t, `SELECT count(*) FROM ctrlz.rules WHERE tenant_id = $1 AND profile_id = $2 AND comment = 'x'`, []any{A.Tenant, p.ID}, &n)
	if n != 0 {
		t.Errorf("%d rules took the comment of a refused edit", n)
	}
}

// TestATransferAboveTheJobThresholdNeedsOneDestination: a copy or move of more than 1,000 rules with no destination, or
// with two, is the 422 of an inline one and holds no job slot (p2-B3-r15-3).
func TestATransferAboveTheJobThresholdNeedsOneDestination(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A := f.env.A
	a := f.makeSession(A.Tenant, A.User)
	f.env.Exec(t, `DELETE FROM ctrlz.batch_jobs`) // the fixture queues one job per tenant
	p := a.mustProfile("Dest", "custom")
	base := "/profiles/" + p.ID.String()
	var fold struct {
		ID uuid.UUID `json:"id"`
	}
	a.post(base+"/folders", map[string]any{"name": "In", "kind": "standard"}).want(201, "").json(&fold)

	var fl fieldList
	a.do("POST", base+"/rules:batch", map[string]any{"op": "move", "ids": uuids(1001)}, idem("dest-1")).want(422, "validation_failed").json(&fl)
	if !fl.has("/dest_folder_id", "required") {
		t.Errorf("fields %+v, want /dest_folder_id required", fl.Fields)
	}
	a.do("POST", base+"/rules:batch", map[string]any{"op": "move", "ids": uuids(1001), "dest_root": true, "dest_folder_id": fold.ID}, idem("dest-2")).want(422, "validation_failed")
	var n int
	f.env.Scan(t, `SELECT count(*) FROM ctrlz.batch_jobs WHERE tenant_id = $1`, []any{A.Tenant}, &n)
	if n != 0 {
		t.Fatalf("%d jobs queued by requests with no single destination", n)
	}
}
