package api

import (
	"fmt"
	"testing"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/passkey/passkeytest"
)

// Tests of the P1 auth review, round 6, area "HTTP spine and tenant API": the pool storm of
// spec 18.3 for the routes that TestParallelRequestsBeyondThePoolDoNotStall did not drive
// (tenant-r6-12). Each holds a transaction and the user row lock, so as many requests as the pool
// has connections hold every connection, and a handler that asks for a second connection while it
// holds one (a ticket, a throttle hit or a cache load on a fresh context) waits for ever, for every
// tenant. The test pool has 4 connections and n is 6; f.storm fails a 5xx, a wait near
// lock_timeout and another tenant's GET /me that is not answered at once.

// notServerFault accepts what a right or a wrong answer can be and refuses a 5xx, which storm
// already reports; the statuses here differ between the racers by design (one of them wins).
func notServerFault(t *testing.T, route string, statuses []int, allowed ...int) {
	t.Helper()
	for _, s := range statuses {
		ok := false
		for _, a := range allowed {
			ok = ok || s == a
		}
		if !ok {
			t.Errorf("%s answered %d, want one of %v", route, s, allowed)
		}
	}
}

// TestParallelRightPasswordLoginsOfATOTPUserDoNotStall is known item 1 and tenant-r11-3. Since tenant-r7-6 the gate
// keeps one hash per account and answers the rest 503, so six logins of ONE account put one request in the
// transaction (AfterFirstFactor holds the user lock and puts the mfa ticket inside it), and a throttle hit or a ticket
// Take added inside that callback would not wait on anything. The storm that exhausts the pool is six ACCOUNTS
// logging in at once, each with the right password and an authenticator, and it is counted: the answers that only the
// transaction gives (200 with mfa_required) must be pool-many, or the test fails. The one-account storm stays, to
// show the lane.
func TestParallelRightPasswordLoginsOfATOTPUserDoNotStall(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A, B := f.env.A, f.env.B
	f.enableTOTP(A.Tenant, A.User)
	probe := f.makeSession(B.Tenant, B.User)
	const n, pool = 6, 4 // the test pool has 4 connections

	t.Run("six accounts", func(t *testing.T) {
		phones := make([]string, n)
		for i := range phones {
			phones[i] = fmt.Sprintf("+98912700%04d", i)
			// A tenant has one owner, so six accounts are six tenants.
			tenant, user := uuid.New(), uuid.New()
			f.env.Exec(t, `INSERT INTO ctrlz.tenants (id, plan_id) SELECT $1::uuid, p.id FROM ctrlz.plans p WHERE p.is_default`, tenant)
			f.env.Exec(t, `INSERT INTO ctrlz.users (tenant_id, id, phone_e164, password_hash) VALUES ($1, $2, $3, 'x')`, tenant, user, phones[i])
			f.setPassword(tenant, user, pwA)
			f.enableTOTP(tenant, user)
		}
		clients := make([]*client, n)
		for i := range clients {
			clients[i] = f.client()
		}
		f.clearThrottle()
		got := f.stormTx(t, "login/password, six TOTP accounts", n, probe, inTxByCode("mfa_required"), pool, func(i int) *resp {
			return clients[i].loginPassword(phones[i], pwA, false)
		})
		notServerFault(t, "login/password", got, 200, 429)
	})

	t.Run("one account, behind its lane", func(t *testing.T) {
		clients := make([]*client, n)
		for i := range clients {
			clients[i] = f.client()
		}
		f.clearThrottle()
		got := f.stormTx(t, "login/password, one TOTP account", n, probe, inTxByCode("mfa_required"), 1, func(i int) *resp {
			return clients[i].loginPassword(A.Phone, pwA, false)
		})
		notServerFault(t, "login/password", got, 200, 429)
	})
}

func TestParallelPasskeyLoginsAndPhoneChangeConfirmsDoNotStall(t *testing.T) {
	f := newFrig(t, frigOpts{passkey: true})
	A, B := f.env.A, f.env.B
	probe := f.makeSession(B.Tenant, B.User)
	const n = 6

	t.Run("passkey/login/finish", func(t *testing.T) {
		key := passkeytest.New(pkOrigin, pkRP)
		owner := f.client()
		owner.mustLogin(A.Phone, pwA)
		owner.reauthPassword(pwA).want(204, "")
		owner.addPasskey(key).want(201, "")
		f.clearThrottle()
		type ceremony struct {
			ticket string
			body   []byte
		}
		cs := make([]ceremony, n)
		clients := make([]*client, n)
		for i := range cs {
			clients[i] = f.client()
			var cer ceremonyBody
			clients[i].post("/auth/passkey/login/begin", map[string]any{}).want(200, "").json(&cer)
			body, err := key.Get(cer.Options)
			if err != nil {
				t.Fatal(err)
			}
			cs[i] = ceremony{cer.Ticket, body}
		}
		// Assertions answer in any order, and the counter of a key moves forward: some are refused
		// 401, one or more succeed. What must not happen is a 5xx or a stall.
		got := f.stormTx(t, "passkey/login/finish", n, probe, inTxByStatus(200), 1, func(i int) *resp {
			return clients[i].postT("/auth/passkey/login/finish", cs[i].ticket, cs[i].body)
		})
		notServerFault(t, "passkey/login/finish", got, 200, 401, 429)
	})

	t.Run("account/phone/change/confirm", func(t *testing.T) {
		f.clearThrottle()
		f.env.Exec(t, `TRUNCATE ctrlz.sms_counters`)
		starter := f.makeSession(A.Tenant, A.User)
		f.env.Exec(t, `UPDATE ctrlz.sessions SET reauth_at = now() WHERE user_id = $1`, A.User)
		var pc phoneChangeBody
		starter.post("/account/phone/change", map[string]any{"new_phone": "+989128880003"}).want(202, "").json(&pc)
		newCode, oldCode := f.codes.Back(2), f.codes.Back(1)
		sess := make([]*client, n)
		for i := range sess {
			sess[i] = f.makeSession(A.Tenant, A.User)
		}
		f.env.Exec(t, `UPDATE ctrlz.sessions SET reauth_at = now() WHERE user_id = $1`, A.User)
		// The same request and the same codes from six sessions: one confirms, the others find it
		// done (or the account's sessions gone), and none of them may stall or fault.
		got := f.stormTx(t, "phone change confirm", n, probe, inTxByStatus(204), 1, func(i int) *resp {
			return sess[i].post("/account/phone/change/"+pc.RequestID+"/confirm", map[string]any{"old_code": oldCode, "new_code": newCode})
		})
		notServerFault(t, "phone change confirm", got, 204, 401, 404, 409, 429)
	})
}
