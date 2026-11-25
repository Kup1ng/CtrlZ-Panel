package adminapi

import (
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/throttle"
	"github.com/Kup1ng/CtrlZ-Panel/internal/budget"
)

// TestEveryAdminBoundScopeIsChargedByItsRoute is tenant-r5-8 for the admin API: every BoundScope row
// of budget.Verifies is driven with wrong secrets, each moves the declared counter by one, exactly the
// policy's limit is let through and the next is 429. See the tenant test of the same name for why a
// declaration is not enough. A row with no driver fails.
func TestEveryAdminBoundScopeIsChargedByItsRoute(t *testing.T) {
	r := newRig(t)
	const wrong = "000000"

	type driver struct {
		scope throttle.Scope
		// prep returns the browser the sends are made from, or nil when every send makes its own.
		prep func() *browser
		send func(b *browser, i int) *aresp
	}
	drivers := map[string]driver{
		"adminLogin": {scope: throttle.AdminLoginUser,
			prep: func() *browser { r.setupAdmin(t, true); return nil },
			send: func(_ *browser, _ int) *aresp { return r.browser().login("wrong-wrong-wrong-1", "") }},
		"adminTotpFresh": {scope: throttle.AdminTOTPSession,
			prep: func() *browser { b, _ := r.admin(t); return b },
			send: func(b *browser, _ int) *aresp { return b.post("/auth/totp/fresh", map[string]any{"code": wrong}) }},
		"changeAdminPassword": {scope: throttle.AdminReauth,
			prep: func() *browser {
				r.setupAdmin(t, false)
				b := r.browser()
				b.login(adminPW, "").want(200, "")
				return b
			},
			send: func(b *browser, _ int) *aresp {
				return b.post("/me/password", map[string]any{"current_password": "wrong-wrong-wrong-1", "new_password": adminNewPW})
			}},
		"adminTotpConfirm": {scope: throttle.AdminTOTPSession,
			prep: func() *browser {
				r.setupAdmin(t, false)
				b := r.browser()
				b.login(adminPW, "").want(200, "")
				b.post("/me/password", map[string]any{"current_password": adminPW, "new_password": adminNewPW}).want(204, "")
				b.post("/me/totp/setup", map[string]any{}).want(200, "")
				return b
			},
			send: func(b *browser, _ int) *aresp { return b.post("/me/totp/confirm", map[string]any{"code": wrong}) }},
	}

	for _, v := range budget.Verifies() {
		if v.Service != budget.Admin || v.Bound != budget.BoundScope {
			continue
		}
		d, ok := drivers[v.Op]
		if !ok {
			t.Errorf("%s declares the bound %s and has no driver in this test: drive it, or the declaration is unproved", v.Op, v.Scope)
			continue
		}
		if string(d.scope) != v.Scope {
			t.Errorf("%s: budget.Verifies says %s and the test is built for %s; one of them is wrong", v.Op, v.Scope, d.scope)
			continue
		}
		t.Run(v.Op, func(t *testing.T) {
			r.env.Exec(t, `DELETE FROM ctrlz.auth_throttle`)
			b := d.prep()
			// The setup above may have counted (a login); the test counts from there.
			base := scopeSum(t, r, v.Scope)
			pol, _ := throttle.PolicyOf(d.scope)
			for i := 0; i < pol.Max; i++ {
				r.ck.add(time.Minute) // the rate classes of the route are not the bound under test
				res := d.send(b, i)
				if res.Code == 429 {
					t.Fatalf("attempt %d of %d was refused (%d %s) before the policy's limit", i+1, pol.Max, res.Code, res.Body)
				}
				// A scope with a daily ceiling (round 8, primitives-r8-4) counts every attempt twice, under the
				// database scope it is stored in: once in the window and once in the ceiling.
				per := 1
				if sb, _ := budget.FindScope(v.Scope); sb.CeilingMax > 0 {
					per = 2
				}
				if got := scopeSum(t, r, v.Scope) - base; got != per*(i+1) {
					t.Fatalf("after attempt %d (status %d) the counter of %s moved by %d, want %d: the route does not charge the scope it declares", i+1, res.Code, v.Scope, got, per*(i+1))
				}
			}
			r.ck.add(time.Minute)
			d.send(b, pol.Max).want(429, "too_many_attempts")
		})
	}
}

// scopeSum is the sum of the counters stored under a scope's database name.
func scopeSum(t *testing.T, r *rig, scope string) int {
	t.Helper()
	b, _ := budget.FindScope(scope)
	return r.count(t, `SELECT coalesce(sum(count), 0)::int FROM ctrlz.auth_throttle WHERE scope = $1`, b.StoreScope())
}
