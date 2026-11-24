package api

import "testing"

// TestAPhoneChangeOfOneTenantCannotUseAChallengeOfAnother is question 15 (migration 0061) at the route. The function
// that completes a phone change reads the two codes as ctrlz_scoped, which sees the challenges stamped with the tenant
// of its setting and no others, so a request whose new-number half is a consumed code of ANOTHER tenant is refused even
// when everything else about it lines up (the number, the purpose, the time). Before 0061 the predicate of the body
// on the phone and the purpose was all there was, and a code of tenant B for the number the request names would have
// passed.
//
// The cross request is built the only way it can exist, by editing the row: B changes its number (both of its codes
// are consumed and stamped with B), B's account goes back to its own number so the number is free, and A's request
// is bent to point at B's consumed new-number code and moved back in time to before B consumed it, because the body
// also asks that a code was consumed after its request was made, and that check alone refuses B's code (the first
// version of this test passed for that reason, with or without the policy). A's own old-number code is real, so the
// old half passes and the new half is the only thing that can refuse it. The old half cannot be bent the same way
// here: a challenge of B is for a phone of B, and the body checks the phone against A's account before the policy
// matters. TestAPhoneChangeCannotBorrowTheChallengesOfAnotherTenant (catalogtest) stamps either half with the other
// tenant under the right phone and carries that case.
func TestAPhoneChangeOfOneTenantCannotUseAChallengeOfAnother(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A, B := f.env.A, f.env.B
	const aNew, bNew = "+989128880101", "+989128880102"
	confirm := func(c *client, id, oldCode, newCode string) *resp {
		return c.post("/account/phone/change/"+id+"/confirm", map[string]any{"old_code": oldCode, "new_code": newCode})
	}
	a, b := f.client(), f.client()
	a.mustLogin(A.Phone, pwA)
	b.mustLogin(B.Phone, pwB)
	a.reauthPassword(pwA).want(204, "")
	b.reauthPassword(pwB).want(204, "")

	// B's change completes, which leaves its two codes consumed. Both carry B's tenant: the new-number code was issued
	// inside B's transaction (RequestNewPhone), the old-number one is stamped by the function from B's account.
	bReq, bOld, bNewCode := b.startChange(bNew)
	confirm(b, bReq.RequestID, bOld, bNewCode).want(204, "")
	if n := f.count(`SELECT count(*) FROM ctrlz.otp_challenges WHERE tenant_id = $1 AND purpose IN ('phone_old', 'phone_new') AND consumed_at IS NOT NULL`, B.Tenant); n != 2 {
		t.Fatalf("tenant B's phone change left %d consumed challenges stamped with its tenant, want 2", n)
	}
	if n := f.count(`SELECT count(*) FROM ctrlz.otp_challenges WHERE tenant_id = $1 AND purpose IN ('phone_old', 'phone_new')`, A.Tenant); n != 0 {
		t.Fatalf("a challenge of tenant B's change carries tenant A: %d", n)
	}
	f.env.Exec(t, `UPDATE ctrlz.users SET phone_e164 = $1 WHERE id = $2`, B.Phone, B.User)
	var bNewOTP string
	f.env.Scan(t, `SELECT new_otp_id::text FROM ctrlz.phone_change_requests WHERE id = $1`, []any{bReq.RequestID}, &bNewOTP)

	// A's request, bent: the new half is B's consumed code for B's number.
	aReq, aOld, _ := a.startChange(aNew)
	f.env.Exec(t, `UPDATE ctrlz.phone_change_requests SET new_otp_id = $2, new_phone_e164 = $3, created_at = now() - interval '1 hour' WHERE id = $1`, aReq.RequestID, bNewOTP, bNew)
	confirm(a, aReq.RequestID, aOld, bNewCode).want(401, "otp_invalid")
	if f.count(`SELECT count(*) FROM ctrlz.users WHERE id = $1 AND phone_e164 = $2`, A.User, A.Phone) != 1 {
		t.Fatal("tenant A's account moved to a number proved by a code of tenant B")
	}
	if f.count(`SELECT count(*) FROM ctrlz.phone_change_requests WHERE id = $1 AND completed_at IS NULL`, aReq.RequestID) != 1 {
		t.Fatal("the request that used tenant B's code was finished")
	}

	// The control: A's own change, with its own codes, still completes.
	own, ownOld, ownNew := a.startChange(aNew)
	confirm(a, own.RequestID, ownOld, ownNew).want(204, "")
	if f.count(`SELECT count(*) FROM ctrlz.users WHERE id = $1 AND phone_e164 = $2`, A.User, aNew) != 1 {
		t.Fatal("tenant A's own phone change did not complete")
	}
}
