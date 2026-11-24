package api

import (
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/session"
)

// TestARevivableSessionIsListedAndCanBeEnded is question 17 at the list (spec 3.3, 12.1, primitives-r19-2). A Remember
// me session that is past its idle limit but still has a refresh token that would bring it back is live: it is in
// GET /account/sessions, so an owner who sees a device they do not know can end it, and after that no refresh
// revives it. A session with no refresh token past its idle limit is dead and is not listed. Tenant B's list holds
// none of A's.
func TestARevivableSessionIsListedAndCanBeEnded(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A, B := f.env.A, f.env.B

	// The unknown device: a Remember me session whose browser has gone away.
	device := f.client()
	device.loginPassword(A.Phone, pwA, true).want(200, "")
	deviceRow := current(device.sessions())
	// A session with no refresh token, which dies at its idle limit.
	plain := f.client()
	plain.mustLogin(A.Phone, pwA)
	plainRow := current(plain.sessions())
	// The owner, on the newest session: it ends an older one with no more proof (3.5).
	owner := f.client()
	owner.mustLogin(A.Phone, pwA)
	bOwner := f.client()
	bOwner.mustLogin(B.Phone, pwB)

	// Two hours and a minute on: past the idle limit of all three, inside the absolute limit.
	f.ck.add(session.DefaultPolicy().Idle + time.Minute)
	device.get("/me").want(401, "session_expired")
	owner.get("/me").want(401, "session_expired")
	// The owner signs in again, as they would after the idle limit.
	owner = f.client()
	owner.mustLogin(A.Phone, pwA)

	listed := map[string]bool{}
	for _, r := range owner.sessions() {
		listed[r.ID] = true
	}
	if !listed[deviceRow.ID] {
		t.Fatal("a session that a refresh would bring back is not in the list")
	}
	if listed[plainRow.ID] {
		t.Fatal("a session with no refresh token, past its idle limit, is in the list")
	}
	for _, r := range bOwner.sessions() {
		if listed[r.ID] {
			t.Fatalf("tenant B lists the session %s of tenant A", r.ID)
		}
	}
	bOwner.do("DELETE", "/account/sessions/"+deviceRow.ID, nil).want(404, "not_found")

	owner.do("DELETE", "/account/sessions/"+deviceRow.ID, nil).want(204, "")
	for _, r := range owner.sessions() {
		if r.ID == deviceRow.ID {
			t.Fatal("the ended session is still listed")
		}
	}
	// The refresh token went with it: the browser that comes back finds nothing to revive.
	device.post("/auth/refresh", nil).want(401, "session_expired")
}
