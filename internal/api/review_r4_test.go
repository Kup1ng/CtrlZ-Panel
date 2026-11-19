package api

import (
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
)

// Tests of the P1 auth review, round 4, area "crypto primitives, secrets and
// sessions".

// TestRegisterFloodWithMadeUpChallengesCostsNoHash is primitives-r4-3. A register
// request whose challenge does not exist has proved nothing, so it must reach
// neither the scoring gate nor the Argon2 gate that signed-in users share: the
// code is peeked first (auth_otp_check), and only a right code goes on. The
// hasher's run counter is the witness, and a signed-in password change that runs
// during the flood still succeeds.
func TestRegisterFloodWithMadeUpChallengesCostsNoHash(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A := f.env.A
	f.setMode("open")
	owner := f.client()
	owner.mustLogin(A.Phone, pwA)
	owner.reauthPassword(pwA).want(204, "")

	// Strong, so that nothing but the order of the checks keeps it from a hash.
	const strong = "Marble-Island-Copper-6620"
	// Long and l33t: the expensive case for zxcvbn.
	long := strings.Repeat("aZ9@kQ", 16) + "xY"

	before := f.hasher.Runs()
	const n = 20
	var wg sync.WaitGroup
	var wrong atomic.Int32
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pw := strong
			if i%2 == 1 {
				pw = long
			}
			r := f.client().post("/auth/register", map[string]any{
				"phone": "09125550777", "challenge_id": uuid.NewString(), "code": "000000", "password": pw,
			})
			// Not 422: scoring never ran. Not 503: no gate was queued on.
			if r.Code == 401 {
				wrong.Add(1)
			}
		}()
	}
	owner.post("/account/password", map[string]any{"new_password": "Cobalt-meadow-Falcon-4417"}).want(204, "")
	wg.Wait()
	if wrong.Load() != n {
		t.Fatalf("%d of %d made-up challenges answered 401 otp_invalid", wrong.Load(), n)
	}
	if runs := f.hasher.Runs() - before; runs != 1 {
		// The owner's own password change is the one hash.
		t.Fatalf("Argon2 ran %d times for %d made-up registrations and one password change, want 1", runs, n)
	}
	f.setPassword(A.Tenant, A.User, pwA)
}

// TestRegisterWeakPasswordWithRightCodeStillKeepsTheCode is the other half of 5.6
// under the peek: the right code with a weak password answers 422, hashes
// nothing, and the same code then registers.
func TestRegisterWeakPasswordWithRightCodeStillKeepsTheCode(t *testing.T) {
	f := newFrig(t, frigOpts{})
	f.setMode("open")
	c := f.client()
	var iss issued
	c.requestOTP("09125550991", "signup", nil).want(202, "").json(&iss)
	code := f.codes.Last()
	before := f.hasher.Runs()
	c.post("/auth/register", map[string]any{"phone": "09125550991", "challenge_id": iss.ID, "code": code, "password": "password123"}).want(422, "password_weak")
	if f.hasher.Runs() != before {
		t.Fatal("a weak password reached Argon2")
	}
	c.post("/auth/register", map[string]any{"phone": "09125550991", "challenge_id": iss.ID, "code": code, "password": "Marble-Island-Copper-6620"}).want(201, "")
}
