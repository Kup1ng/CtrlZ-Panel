package api

import (
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
)

// TestRequestChallengeAndReleaseShareOneHourlyBudget: the three routes that touch a Plain DNS claim (request, open a
// challenge, release) are charged to the one class ip-claim, 30 an hour for the tenant, whichever of its sessions sends them. A
// loop of request, challenge and release from two sessions stops at the 31st charge with 429 rate_limited on each of the three
// routes; the refused calls write nothing, so the rows the loop left are bounded by the charges and a claim that was not released
// is still there; another tenant has its own hour; and the hour passing opens the budget again (spec P3 4.5, 11.5, T-529). Take
// x-ctrlz-rate-also off the release route and the 33rd call is a 204 and not a 429; make the loop's releases free and the 31st
// request goes through.
func TestRequestChallengeAndReleaseShareOneHourlyBudget(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A, B := f.env.A, f.env.B
	a := f.makeSession(A.Tenant, A.User)
	a2 := f.makeSession(A.Tenant, A.User)
	ep := f.newEndpoint(a, "ip-claim-budget")
	base := "/endpoints/" + ep + "/ip-claims"
	sessions := []*client{a, a2}
	turn := 0
	next := func() *client { turn++; return sessions[turn%2] }
	addr := 0
	request := func(c *client) *resp {
		addr++
		return c.post(base, map[string]any{"cidr": fmt.Sprintf("203.0.113.%d", addr)})
	}
	claimOf := func(r *resp) string {
		t.Helper()
		var c pClaim
		r.want(201, "").json(&c)
		return c.ID.String()
	}

	// 1 and 2: two claims that stay. 3 to 26: eight turns of request, challenge, release, each step from the other session.
	x := claimOf(request(next()))
	y := claimOf(request(next()))
	for i := 0; i < 8; i++ {
		id := claimOf(request(next()))
		next().post(base+"/"+id+"/challenges", nil).want(201, "")
		next().post(base+"/"+id+":release", map[string]any{}).want(204, "")
	}
	// 27 and 28: a challenge on x and its release. 29 and 30: two more requests.
	next().post(base+"/"+x+"/challenges", nil).want(201, "")
	next().post(base+"/"+x+":release", map[string]any{}).want(204, "")
	claimOf(request(next()))
	claimOf(request(next()))

	// ip_claim_release sets state = 'released' and never deletes the row (spec P3 11.5), so kept counts the claim only while it
	// is not released; counting the row alone would read 1 before and after the release and prove nothing.
	var rows, kept int
	count := func() {
		t.Helper()
		f.env.Scan(t, `SELECT count(*) FROM ctrlz.ip_claims WHERE tenant_id = $1 AND endpoint_id = $2`, []any{A.Tenant, uuid.MustParse(ep)}, &rows)
		f.env.Scan(t, `SELECT count(*) FROM ctrlz.ip_claims WHERE tenant_id = $1 AND endpoint_id = $2 AND id = $3 AND state <> 'released'`, []any{A.Tenant, uuid.MustParse(ep), uuid.MustParse(y)}, &kept)
	}
	count()
	if rows > 30 || kept != 1 {
		t.Fatalf("after 30 charges the endpoint has %d claim rows (at most 30) and the kept claim is %d", rows, kept)
	}
	before := rows

	// The 31st charge, on each of the three routes and from each session, is refused. A refused call still counts, so nothing
	// that follows is let through either.
	request(a).want(429, "rate_limited")
	a2.post(base+"/"+y+"/challenges", nil).want(429, "rate_limited")
	a.post(base+"/"+y+":release", map[string]any{}).want(429, "rate_limited")
	a2.post(base+"/"+y+":release", map[string]any{}).want(429, "rate_limited")
	count()
	if rows != before || kept != 1 {
		t.Errorf("the refused calls changed the claims: %d rows, was %d, and the kept claim is %d", rows, before, kept)
	}

	// Tenant B has an hour of its own.
	b := f.makeSession(B.Tenant, B.User)
	b.post("/endpoints/"+B.Endpoint.String()+"/ip-claims", map[string]any{"cidr": "203.0.113.200"}).want(201, "")

	// The hour passes: the release that was refused goes through now.
	f.ck.add(time.Hour + time.Minute)
	a.post(base+"/"+y+":release", map[string]any{}).want(204, "")
	count()
	if kept != 0 {
		t.Error("the release after the hour left the claim live")
	}
	var state string
	f.env.Scan(t, `SELECT state FROM ctrlz.ip_claims WHERE tenant_id = $1 AND id = $2`, []any{A.Tenant, uuid.MustParse(y)}, &state)
	if state != "released" {
		t.Errorf("the claim after the release is %q, want released", state)
	}
}
