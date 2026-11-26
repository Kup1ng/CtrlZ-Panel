package api

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
)

// The lock password presented through an Endpoint route is bounded by the same scopes as the unlock route (docs/specs/p3-endpoints.md
// 3.3, 11.5; review round 1 of D6, p3-D6-r1-10). lockVerifier.CheckLockPassword is the only brute-force bound of that path: a child
// with the parent's session could otherwise guess the password through PATCH /endpoints/{id} at the per-session write rate with no
// 429. These tests fail when either throttle.Charge is removed, or when a busy gate keeps its charges.

// lockedEndpoint makes an Endpoint of A on a profile that is locked with the password "correct horse", and returns the two ids.
func lockedEndpoint(t *testing.T, f *frig, a *client, name string) (profile uuid.UUID, endpoint string) {
	t.Helper()
	profile = uuid.Must(uuid.NewV7())
	f.env.Exec(t, `INSERT INTO ctrlz.profiles (tenant_id, id, name) VALUES ($1, $2, $3)`, f.env.A.Tenant, profile, name)
	var created struct {
		Endpoints []pEndpoint `json:"endpoints"`
	}
	a.do("POST", "/endpoints", map[string]any{"type": f.endpointType(), "names": []string{name}, "profile_id": profile.String()}, idem("throttle-"+name)).want(201, "").json(&created)
	hash, err := f.hasher.Hash(f.env.Ctx, secret.New("correct horse"))
	if err != nil {
		t.Fatal(err)
	}
	f.env.Exec(t, `UPDATE ctrlz.profiles SET lock_state = 'locked', lock_password_hash = $2 WHERE id = $1`, profile, hash.Reveal())
	return profile, created.Endpoints[0].ID.String()
}

func disableWith(profile uuid.UUID, password string) map[string]any {
	return map[string]any{"admin_state": "soft_disabled",
		"lock_passwords": []map[string]any{{"profile_id": profile.String(), "password": password}}}
}

// Wrong passwords through an Endpoint route and through the unlock route are one count: five failures in 15 minutes, then 429 on
// either, and the right password is refused too while the scope is full.
func TestEndpointRoutesAndUnlockShareTheLockPasswordThrottle(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A := f.env.A
	a := f.makeSession(A.Tenant, A.User)
	profile, ep := lockedEndpoint(t, f, a, "throttled")
	unlock := "/profiles/" + profile.String() + "/unlock"

	// Four wrong guesses through the Endpoint and the fifth through unlock make five; the sixth is 429 on either.
	for i := 0; i < 4; i++ {
		a.do("PATCH", "/endpoints/"+ep, disableWith(profile, "wrong horse battery")).want(401, "invalid_credentials")
	}
	a.reauthPassword(pwA).want(204, "")
	a.post(unlock, map[string]any{"password": "wrong horse battery"}).want(401, "invalid_credentials")
	a.do("PATCH", "/endpoints/"+ep, disableWith(profile, "wrong horse battery")).want(429, "too_many_attempts")
	a.do("PATCH", "/endpoints/"+ep, disableWith(profile, "correct horse")).want(429, "too_many_attempts")
	a.post(unlock, map[string]any{"password": "correct horse"}).want(429, "too_many_attempts")
	var state string
	f.env.Scan(t, `SELECT admin_state FROM ctrlz.endpoints WHERE tenant_id = $1 AND id = $2`, []any{A.Tenant, uuid.MustParse(ep)}, &state)
	if state != "enabled" {
		t.Errorf("a throttled request changed the state to %s", state)
	}
}

// The other way round: five failures at the unlock route close the Endpoint routes, a delete included.
func TestUnlockFailuresCloseTheEndpointRoutes(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A := f.env.A
	a := f.makeSession(A.Tenant, A.User)
	profile, ep := lockedEndpoint(t, f, a, "closed")
	a.reauthPassword(pwA).want(204, "")
	for i := 0; i < 5; i++ {
		a.post("/profiles/"+profile.String()+"/unlock", map[string]any{"password": "wrong horse battery"}).want(401, "invalid_credentials")
	}
	a.do("PATCH", "/endpoints/"+ep, disableWith(profile, "correct horse")).want(429, "too_many_attempts")
	a.post("/endpoints/"+ep+":delete", map[string]any{"lock_passwords": []map[string]any{{"profile_id": profile.String(), "password": "correct horse"}}}).want(429, "too_many_attempts")
	a.get("/endpoints/"+ep).want(200, "")
}

// With the Argon2 gate full an Endpoint route answers 503 server_busy and gives both charges back, as the unlock route does
// (TestBusyLockAndUnlockDoNotSpendTheThrottle): what a busy answer kept would close the profile to its owner.
func TestEndpointRouteTurnedAwayByTheGateSpendsNoThrottle(t *testing.T) {
	f, release := busyFrig(t, frigOpts{})
	A := f.env.A
	a := f.makeSession(A.Tenant, A.User)
	release() // the setup needs the hasher
	profile, ep := lockedEndpoint(t, f, a, "busy")
	held, err := f.hasher.Gate().Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer held()
	lockTenant, unlock := f.scopeCount("profile_lock_tenant"), f.scopeCount("profile_unlock")
	for i := 0; i < 4; i++ {
		a.do("PATCH", "/endpoints/"+ep, disableWith(profile, "correct horse")).want(503, "server_busy")
	}
	if n := f.scopeCount("profile_lock_tenant"); n != lockTenant {
		t.Errorf("profile_lock_tenant counts %d after only busy answers, was %d", n, lockTenant)
	}
	if n := f.scopeCount("profile_unlock"); n != unlock {
		t.Errorf("profile_unlock counts %d after only busy answers, was %d", n, unlock)
	}
}

// A right password through an Endpoint route clears profile_unlock for its profile and never profile_lock_tenant, and a refused request
// clears nothing (docs/specs/p3-endpoints.md 3.3; p3-D6-r2-5). Without the clear the sixth guess of a day of right and wrong ones is 429:
// the owner who edits a locked Endpoint with the right password five times is locked out of it by the right passwords alone.
func TestRightPasswordThroughAnEndpointRouteClearsOnlyTheUnlockScope(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A := f.env.A
	a := f.makeSession(A.Tenant, A.User)
	profile, ep := lockedEndpoint(t, f, a, "cleared")

	for i := 0; i < 4; i++ {
		a.do("PATCH", "/endpoints/"+ep, disableWith(profile, "wrong horse battery")).want(401, "invalid_credentials")
	}
	if n := f.scopeCount("profile_unlock"); n != 4 {
		t.Fatalf("profile_unlock counts %d after four wrong guesses, want 4: a refused request clears nothing", n)
	}
	a.do("PATCH", "/endpoints/"+ep, disableWith(profile, "correct horse")).want(200, "")
	if n := f.scopeCount("profile_unlock"); n != 0 {
		t.Errorf("profile_unlock counts %d after the right password, want 0", n)
	}
	if n := f.scopeCount("profile_lock_tenant"); n != 5 {
		t.Errorf("profile_lock_tenant counts %d after four wrong guesses and one right one, want 5: a success never clears it", n)
	}
	// The Endpoint is switched back on (adding needs no password) and the four next wrong guesses are 401, not 429.
	a.do("PATCH", "/endpoints/"+ep, map[string]any{"admin_state": "enabled"}).want(200, "")
	for i := 0; i < 4; i++ {
		a.do("PATCH", "/endpoints/"+ep, disableWith(profile, "wrong horse battery")).want(401, "invalid_credentials")
	}
	a.do("PATCH", "/endpoints/"+ep, disableWith(profile, "correct horse")).want(200, "")
}
