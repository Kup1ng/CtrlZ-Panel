package api

import (
	"fmt"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/passkey/passkeytest"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/throttle"
	"github.com/Kup1ng/CtrlZ-Panel/internal/budget"
)

// TestEveryBoundScopeIsChargedByItsRoute is tenant-r5-8, for the tenant API. budget.Verifies is
// a declaration, and TestEveryVerifyPathHasASubjectKeyedBound checks only that the scope it names
// exists and is not keyed on the network; it never asked whether the route charges that scope
// (resetComplete named reauth_user and charged totp_user, and a route that dropped its charge, or
// moved it to a network scope, kept passing). Here every BoundScope row of the tenant service is
// driven: wrong secrets are sent to the route, each one moves the declared scope's counter by one,
// exactly as many are let through as the policy allows, and the next is 429. A row with no driver
// fails the test, so a new row cannot be added as a declaration alone. Each attempt comes from a
// new session or a new network where the route allows it, so the limit that stops the loop is the
// subject's and not the network's or the session's.
func TestEveryBoundScopeIsChargedByItsRoute(t *testing.T) {
	f := newFrig(t, frigOpts{passkey: true})
	A, B := f.env.A, f.env.B
	f.enableTOTP(A.Tenant, A.User)
	key := passkeytest.New(pkOrigin, pkRP)
	owner := f.makeSession(A.Tenant, A.User)
	f.env.Exec(t, `UPDATE ctrlz.sessions SET reauth_at = now() WHERE user_id = $1`, A.User)
	owner.addPasskey(key).want(201, "")
	const wrong = "000000"
	const newPw = "Cobalt-meadow-Falcon-4417"

	reauthed := func() *client {
		c := f.makeSession(A.Tenant, A.User)
		f.env.Exec(t, `UPDATE ctrlz.sessions SET reauth_at = $2 WHERE user_id = $1`, A.User, f.ck.now())
		return c
	}
	inv := f.plantInvite("+989125550001", time.Hour, false)
	// one is the session of a driver whose scope is keyed on the session; its prep makes it.
	var one *client
	var lockedProfile string

	type driver struct {
		scope throttle.Scope
		prep  func() func()
		send  func(i int) *resp
	}
	drivers := map[string]driver{
		"loginPassword": {scope: throttle.LoginPhone, send: func(int) *resp {
			return f.client().loginPassword(A.Phone, "wrong-Password-9999", false)
		}},
		"loginTotp": {scope: throttle.TOTPUser, send: func(int) *resp {
			c := f.client()
			tk := c.mfaLogin(A.Phone, pwA)
			return c.post("/auth/login/totp", map[string]any{"ticket": tk, "totp_code": wrong})
		}},
		"lookupInvite": {scope: throttle.InviteUse, send: func(int) *resp {
			return f.client().post("/auth/invites/lookup", map[string]any{"token": inv})
		}},
		"resetComplete": {scope: throttle.TOTPSMS, send: func(int) *resp {
			c := f.client()
			v := c.verifyReset(A.Phone)
			return c.post("/auth/password/reset/complete", map[string]any{"ticket": v.Ticket, "new_password": newPw, "totp_code": wrong})
		}},
		// The three session scopes are keyed on the session (tenant-r7-2): the loop keeps ONE session, so the
		// limit that stops it is the scope's own and not the pipeline's per-session class (10 a minute; the
		// clock moves a minute between attempts).
		"reauth": {scope: throttle.ReauthSession, prep: func() func() { one = f.makeSession(A.Tenant, A.User); return nil }, send: func(int) *resp {
			return one.post("/auth/reauth", map[string]any{"password": "wrong-Password-9999"})
		}},
		"resetPasskeyFinish": {scope: throttle.ResetPasskeyUser, send: func(int) *resp {
			c := f.client()
			v := c.verifyReset(A.Phone)
			var first, second ceremonyBody
			c.post("/auth/password/reset/passkey/begin", map[string]any{"ticket": v.Ticket}).want(200, "").json(&first)
			body, err := key.Get(first.Options)
			if err != nil {
				t.Fatal(err)
			}
			// A real assertion for another ceremony: it fails the challenge, after the charge, which is what is counted.
			c.post("/auth/password/reset/passkey/begin", map[string]any{"ticket": v.Ticket}).want(200, "").json(&second)
			return c.postT("/auth/password/reset/passkey/finish", second.Ticket, body)
		}},
		"reauthPasskeyFinish": {scope: throttle.ReauthPasskey, prep: func() func() { one = f.makeSession(A.Tenant, A.User); return nil }, send: func(int) *resp {
			c := one
			var first, second ceremonyBody
			c.post("/auth/reauth/passkey/begin", nil).want(200, "").json(&first)
			body, err := key.Get(first.Options)
			if err != nil {
				t.Fatal(err)
			}
			// A real assertion for another ceremony: it fails the challenge, after the charge.
			c.post("/auth/reauth/passkey/begin", nil).want(200, "").json(&second)
			return c.postT("/auth/reauth/passkey/finish", second.Ticket, body)
		}},
		"changePassword": {scope: throttle.TOTPSession,
			prep: func() func() {
				// A session that waives the reauth window (a one-time password) and a user with a
				// second factor is the one path of this route that counts a code.
				f.env.Exec(t, `UPDATE ctrlz.users SET must_reset = true, password_expires_at = now() + interval '72 hours' WHERE id = $1`, A.User)
				one = f.makeSession(A.Tenant, A.User)
				return func() {
					f.env.Exec(t, `UPDATE ctrlz.users SET must_reset = false, password_expires_at = NULL WHERE id = $1`, A.User)
				}
			},
			send: func(int) *resp {
				return one.post("/account/password", map[string]any{"new_password": newPw, "totp_code": wrong})
			}},
		"confirmPhoneChange": {scope: throttle.ReauthSession,
			prep: func() func() { one = reauthed(); return nil },
			send: func(i int) *resp {
				c := one
				f.env.Exec(t, `UPDATE ctrlz.sessions SET reauth_at = $2 WHERE user_id = $1`, A.User, f.ck.now()) // the clock moves between attempts
				b, _, _ := c.startChange(fmt.Sprintf("+98912888%04d", i))
				return c.post("/account/phone/change/"+b.RequestID+"/confirm", map[string]any{"old_code": wrong, "new_code": wrong})
			}},
		// The lock password of a profile (P2 spec 7): every attempt counts on the tenant-wide scope before it hashes or verifies, the unlock
		// also on the scope of its profile. The profile is the tenant's own; the password is the one the lock was set with or a wrong one.
		"lockProfile": {scope: throttle.ProfileLockTenant,
			prep: func() func() {
				one = reauthed()
				lockedProfile = one.mustProfile("Budget lock", "custom").ID.String()
				return nil
			},
			send: func(i int) *resp {
				f.env.Exec(t, `UPDATE ctrlz.sessions SET reauth_at = $2 WHERE user_id = $1`, A.User, f.ck.now()) // the clock moves between attempts
				return one.post("/profiles/"+lockedProfile+"/lock", map[string]any{"password": "lock-password-1"})
			}},
		"unlockProfile": {scope: throttle.ProfileUnlock,
			prep: func() func() {
				one = reauthed()
				f.clearThrottle() // the lock below is an attempt of the tenant's hourly budget, which the lock driver spent
				lockedProfile = one.mustProfile("Budget unlock", "custom").ID.String()
				one.post("/profiles/"+lockedProfile+"/lock", map[string]any{"password": "lock-password-1"}).want(204, "")
				return nil
			},
			send: func(i int) *resp {
				return one.post("/profiles/"+lockedProfile+"/unlock", map[string]any{"password": "wrong-password-1"})
			}},
		"totpConfirm": {scope: throttle.TOTPSession,
			prep: func() func() {
				one = f.makeSession(B.Tenant, B.User)
				f.env.Exec(t, `UPDATE ctrlz.sessions SET reauth_at = $2 WHERE user_id = $1`, B.User, f.ck.now())
				return nil
			},
			send: func(int) *resp {
				c := one
				f.env.Exec(t, `UPDATE ctrlz.sessions SET reauth_at = $2 WHERE user_id = $1`, B.User, f.ck.now())
				c.post("/account/totp/setup", nil).want(200, "")
				return c.post("/account/totp/confirm", map[string]any{"code": wrong, "saved": true})
			}},
	}

	for _, v := range budget.Verifies() {
		if v.Service != budget.Tenant || v.Bound != budget.BoundScope {
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
			if d.prep != nil {
				if undo := d.prep(); undo != nil {
					defer undo()
				}
			}
			f.clearThrottle()
			b, _ := budget.FindScope(v.Scope)
			pol, _ := throttle.PolicyOf(d.scope)
			for i := 0; i < pol.Max; i++ {
				f.ck.add(time.Minute) // the rate classes of the route are not the bound under test
				r := d.send(i)
				if r.Code == 429 {
					t.Fatalf("attempt %d of %d was refused (%d %s) before the policy's limit", i+1, pol.Max, r.Code, r.Body)
				}
				// A scope with a daily ceiling (round 8, primitives-r8-4) counts every attempt twice under its
				// database scope: once in the window and once in the ceiling.
				per := 1
				if b.CeilingMax > 0 {
					per = 2
				}
				if got := f.scopeCount(b.StoreScope()); got != per*(i+1) {
					t.Fatalf("after attempt %d (status %d) the counter of %s is %d, want %d: the route does not charge the scope it declares", i+1, r.Code, v.Scope, got, per*(i+1))
				}
			}
			f.ck.add(time.Minute)
			d.send(pol.Max).want(429, "too_many_attempts")
		})
	}
}
