package api

import (
	"fmt"
	"testing"
)

// bigBadRuleBody is bigRuleBody with an action the schema refuses: it is a heavy request and is answered 400 in its slot.
func bigBadRuleBody() map[string]any {
	b := bigRuleBody()
	b["action"] = "zzz"
	return b
}

// TestABigRuleCreatePaysNoDayToken: a rule create is of no bulk-write class, so a big one costs the tenant's 200 bulk
// requests a day nothing, whatever its size and however many sessions send it. What bounds it is the place: one heavy
// request of a tenant at a time (spec 6.5, Refusals and tokens).
func TestABigRuleCreatePaysNoDayToken(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A, B := f.env.A, f.env.B
	var sessions []*client
	for i := 0; i < 10; i++ {
		sessions = append(sessions, f.makeSession(A.Tenant, A.User))
	}
	b := f.makeSession(B.Tenant, B.User)
	pa := sessions[0].mustProfile("Budget", "custom")
	pb := b.mustProfile("Budget", "custom")
	path := "/profiles/" + pa.ID.String() + "/rules"
	for i := 0; i < 210; i++ {
		sessions[i%10].post(path, bigBadRuleBody()).want(400, "bad_request")
	}
	// The day budget is whole: 200 bulk requests still pass, from sessions that have used none of their own minute.
	bad := map[string]any{"document": b64(`{}`)}
	for i := 0; i < 20; i++ {
		f.makeSession(A.Tenant, A.User).do("POST", "/profiles:import", bad, idem(fmt.Sprintf("after-rules-%d", i))).want(422, "validation_failed")
	}
	b.post("/profiles/"+pb.ID.String()+"/rules", bigBadRuleBody()).want(400, "bad_request")
}
