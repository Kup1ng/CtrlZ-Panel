package api

import (
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
)

// Tests of the P1 auth review round 5, rule budget-keying, on the tenant API. The
// bucket-by-bucket abuse tests are in internal/budget; these show the routes use them.

// TestLiveInviteBudgetFollowsTheInviteAcrossNetworks: whoever holds a live token and
// moves networks on every request gets no fresh budget (invite_use is keyed on the
// invite), while another invite, and strangers' junk on a shared network, are not
// touched by it (rule budget-keying; tenant-r2-7, tenant-r3-1).
func TestLiveInviteBudgetFollowsTheInviteAcrossNetworks(t *testing.T) {
	f := newFrig(t, frigOpts{})
	mine := f.plantInvite("+989125554001", time.Hour, false)
	other := f.plantInvite("+989125554002", time.Hour, false)

	allowed := 0
	for i := 0; i < 40; i++ {
		c := f.client()
		c.ip = f.freshIP() // a network of its own each time
		r := c.post("/auth/invites/lookup", map[string]any{"token": mine})
		if r.Code == 429 {
			r.want(429, "too_many_attempts")
			break
		}
		r.want(200, "")
		allowed++
		if i%15 == 14 {
			f.ck.add(time.Minute) // the auth class of a network that comes round again
		}
	}
	if allowed != 30 {
		t.Fatalf("a live token that moved networks was answered %d times, want the 30 of invite_use", allowed)
	}
	// Another invitation is another subject.
	c := f.client()
	c.post("/auth/invites/lookup", map[string]any{"token": other}).want(200, "")
}

// TestSignedInOTPRoutesAreNotChargedToTheNetwork: a signed-in user is a verified proof,
// so strangers who fill the network buckets of its /24 cannot refuse it, and the same
// cookie on a new network every time is still stopped by its own budget. Tenant A's
// user is the control: the other tenant's budget is never touched.
func TestSignedInOTPRoutesAreNotChargedToTheNetwork(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A, B := f.env.A, f.env.B
	f.env.Exec(t, `UPDATE ctrlz.users SET password_hash = NULL WHERE tenant_id = ANY($1)`, []uuid.UUID{A.Tenant, B.Tenant})
	const shared = "203.0.113.9"

	// Strangers on the shared /24 spend otp_verify_net (30), then otp-send (5 a minute).
	for i := 0; i < 35; i++ {
		s := f.client()
		s.ip = shared
		s.post("/auth/login/otp", map[string]any{"phone": A.Phone, "challenge_id": junkValue(t), "code": "000000"})
		if i%10 == 9 {
			f.ck.add(time.Minute)
		}
	}
	for i := 0; i < 12; i++ {
		s := f.client()
		s.ip = shared
		s.requestOTP(fmt.Sprintf("+98912555%04d", 5000+i), "login", nil)
	}
	s := f.client()
	s.ip = shared
	s.requestOTP("+989125559999", "login", nil).want(429, "rate_limited")

	// Both tenants' signed-in users, on that very network, still ask for a code and try one.
	for _, u := range []struct {
		tenant, user uuid.UUID
	}{{A.Tenant, A.User}, {B.Tenant, B.User}} {
		c := f.makeSession(u.tenant, u.user)
		c.ip = shared
		c.post("/auth/reauth/otp/request", nil).want(202, "")
		c.post("/auth/reauth", map[string]any{"otp_challenge_id": uuid.NewString(), "otp_code": "000000"}).want(401, "otp_invalid")
	}

	// One cookie that moves networks on every try: refused after its own five.
	c := f.makeSession(A.Tenant, A.User)
	answered := 0
	for i := 0; i < 8; i++ {
		c.ip = f.freshIP()
		r := c.post("/auth/reauth", map[string]any{"otp_challenge_id": uuid.NewString(), "otp_code": "000000"})
		if r.Code == 429 {
			r.want(429, "too_many_attempts")
			break
		}
		r.want(401, "otp_invalid")
		answered++
	}
	if answered != 5 { // the scope is keyed on the session since round 7: this cookie has all five of its own
		t.Fatalf("answered %d, want 5", answered)
	}
	// B, in the same moment, has all of its own.
	b := f.makeSession(B.Tenant, B.User)
	b.ip = f.freshIP()
	b.post("/auth/reauth", map[string]any{"otp_challenge_id": uuid.NewString(), "otp_code": "000000"}).want(401, "otp_invalid")
}

// TestReauthOTPRequestStopsAStolenCookieThatMovesNetworks: otp-send-user is keyed on the
// session, so a stolen cookie gets 5 codes a minute however many networks it uses.
func TestReauthOTPRequestStopsAStolenCookieThatMovesNetworks(t *testing.T) {
	f := newFrig(t, frigOpts{})
	B := f.env.B
	f.env.Exec(t, `UPDATE ctrlz.users SET password_hash = NULL WHERE tenant_id = $1`, B.Tenant)
	c := f.makeSession(B.Tenant, B.User)
	sent := 0
	for i := 0; i < 8; i++ {
		c.ip = f.freshIP()
		f.clearOTP() // the per-phone cooldown is not what is measured
		r := c.post("/auth/reauth/otp/request", nil)
		if r.Code == 429 {
			r.want(429, "rate_limited")
			break
		}
		r.want(202, "")
		sent++
	}
	if sent != 5 {
		t.Fatalf("%d codes were sent to a cookie that moved networks, want 5 a minute", sent)
	}
}
