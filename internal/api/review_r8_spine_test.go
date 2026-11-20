package api

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/session"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/totp"
	"github.com/Kup1ng/CtrlZ-Panel/internal/authtest/boundary"
	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
	"github.com/Kup1ng/CtrlZ-Panel/internal/ratelimit"
)

// Tests of the P1 auth review, round 8, area "HTTP spine and tenant API".

// bodyIdentity is what the first 16 bytes of a session cookie name: the cookie's own copy of the id
// of the session it opens, which the tag covers. The test reads it from a REAL cookie so that it
// follows whatever the issuer puts there, and builds the dead cookies of an attacker from it.
func bodyIdentity(t *testing.T, cookieValue string) uuid.UUID {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(cookieValue)
	if err != nil || len(raw) < 16 {
		t.Fatalf("a session cookie is not base64 of a body: %v", err)
	}
	id, err := uuid.FromBytes(raw[:16])
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// TestDeadCookiesOfOneSessionCannotRefuseTheOwnersOtherSessions is tenant-r8-3. The session-miss
// budget (30 a minute, charged before the lookup and given back only for a live session) was keyed
// on the ACCOUNT the cookie was issued to, so the dead cookies of ONE stolen session (every rotation
// of it leaves one, and each stays valid under its tag for up to ninety days) spent the budget of
// EVERY session of that account: the owner's live sessions, and the ones he opened after logout-all,
// a new password and a new phone, all answered 429 before their lookup for as long as the thief kept
// sending. Nothing that is not proof of a live session may refuse one that is. The budget is the
// session's own now (the cookie carries the id of the session it opens; a rotation keeps the id).
//
// The attacker's cookies are built from the body of a real cookie of the stolen session, so the test
// attacks whatever the issuer puts in the body. The holder's own session pays (declared, spec 14.1);
// every other session of the account, one opened before and one opened after, and another tenant's, is
// served throughout.
func TestDeadCookiesOfOneSessionCannotRefuseTheOwnersOtherSessions(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A, B := f.env.A, f.env.B
	f.clearThrottle()

	stolen := f.makeSession(A.Tenant, A.User)
	before := f.makeSession(A.Tenant, A.User)
	bOwner := f.makeSession(B.Tenant, B.User)

	// The body of a cookie names the session it opens: the row it opens exists under that id.
	id := bodyIdentity(t, stolen.jar[session.CookieSession].Value)
	if f.count(`SELECT count(*) FROM ctrlz.sessions WHERE id = $1 AND user_id = $2`, id, A.User) != 1 {
		t.Fatalf("the session cookie does not carry the id of its own session row (%s)", id)
	}
	if bodyIdentity(t, before.jar[session.CookieSession].Value) == id {
		t.Fatal("two sessions of one account carry the same identity in their cookies")
	}

	// A thief's dead cookies of the stolen session: valid under the tag, no stored session behind them.
	miss, ok := ratelimit.Lookup(ratelimit.Tenant, ratelimit.SessionMiss)
	if !ok {
		t.Fatal("no session-miss class")
	}
	limit := miss.Limits[0].Max
	thief := f.client()
	refused := 0
	for i := 0; i < limit+20; i++ {
		thief.jar[session.CookieSession] = boundary.CookieFor(f.keys, keyring.DomainAuthMAC, session.CookieSession, id, f.ck.now().Add(24*time.Hour))
		if thief.get("/me").Code == http.StatusTooManyRequests {
			refused++
		}
	}
	if refused == 0 {
		t.Fatalf("%d dead cookies of one session were never refused: the test did not spend the budget and proves nothing", limit+20)
	}

	// The stolen session's holder is refused (declared); nobody else is.
	stolen.get("/me").want(429, "")
	before.get("/me").want(200, "")
	bOwner.get("/me").want(200, "")

	// The owner reacts: logs out everywhere, signs in again. The new session is on a new budget.
	before.post("/auth/logout-all", nil).want(204, "")
	after := f.makeSession(A.Tenant, A.User)
	after.get("/me").want(200, "")
	// And the thief goes on: still only the dead session's budget.
	for i := 0; i < limit+5; i++ {
		thief.jar[session.CookieSession] = boundary.CookieFor(f.keys, keyring.DomainAuthMAC, session.CookieSession, id, f.ck.now().Add(24*time.Hour))
		thief.get("/me")
	}
	after.get("/me").want(200, "")
	bOwner.get("/me").want(200, "")
}

// TestAKnownDeviceStillGetsALoginCodeWhenStrangersFillTheNetwork is tenant-r8-4. The otp-send class
// (5 a minute, 30 an hour, per source /24) was charged in the pipeline before the handler, with no proof
// to stand in for the network, so thirty junk requests an hour from anybody on the carrier /24 refused
// the owner's request for a login code from his KNOWN device too, and an account with no password and no
// passkey could not sign in. A device marker that holds for the phone asked for (same account, same
// credential generation) now takes the network's place, on the marker's own buckets; a marker for any
// other account, or for no account at all (an unknown phone), is worth nothing there, since any account
// holder can mint one. The flood comes first, and the plain bucket is shown untouched by the owner.
func TestAKnownDeviceStillGetsALoginCodeWhenStrangersFillTheNetwork(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A, B := f.env.A, f.env.B
	f.clearThrottle()

	owner := f.client()
	owner.mustLogin(A.Phone, pwA)
	ownerMarker := owner.jar[session.CookieDevice]
	bOwner := f.client()
	bOwner.mustLogin(B.Phone, pwB)
	bMarker := bOwner.jar[session.CookieDevice]
	if ownerMarker == nil || bMarker == nil {
		t.Fatal("a login gave no device marker")
	}

	// One carrier /24 for everybody below.
	on := func(c *client, last int) *client { c.ip = fmt.Sprintf("203.0.113.%d", last); return c }
	withMarker := func(c *client, m *http.Cookie) *client {
		c.jar[session.CookieDevice] = &http.Cookie{Name: session.CookieDevice, Value: m.Value}
		return c
	}
	ask := func(c *client, phone string) *resp {
		return c.post("/auth/otp/request", map[string]any{"phone": phone, "purpose": "login", "locale": "fa"})
	}
	junk := func(i int) string { return fmt.Sprintf("0912555%04d", i) }

	// The flood: strangers on the /24 fill the plain bucket with numbers nobody has.
	limited := 0
	for i := 0; i < 12; i++ {
		if ask(on(f.client(), 10+i), junk(i)).Code == http.StatusTooManyRequests {
			limited++
		}
	}
	if limited == 0 {
		t.Fatal("the strangers were never refused: the plain bucket was not filled and the test proves nothing")
	}
	f.clearOTP()
	ask(on(f.client(), 100), junk(500)).want(429, "")

	// The owner, from his known device, on the same /24.
	ask(on(withMarker(f.client(), ownerMarker), 101), A.Phone).want(202, "")
	// The controls: nothing else gets through the filled bucket.
	ask(on(f.client(), 102), A.Phone).want(429, "")                            // the same phone, no marker
	ask(on(withMarker(f.client(), bMarker), 103), A.Phone).want(429, "")       // a marker of another tenant's account
	ask(on(withMarker(f.client(), ownerMarker), 104), junk(501)).want(429, "") // his marker, a phone that is not his
	ask(on(withMarker(f.client(), ownerMarker), 105), B.Phone).want(429, "")   // his marker, another account's phone
	ask(on(withMarker(f.client(), bMarker), 106), junk(502)).want(429, "")     // a marker and a decoy

	// The marker's own bucket bounds the owner: the class's five a minute and no more. The two controls above
	// that carried his marker for a phone that is not his were charged to it too (a marker is free to mint, so
	// what it can make the service read is bounded by it), so three of the five are spent.
	answered := 1
	for i := 0; i < 12; i++ {
		f.clearOTP()
		if ask(on(withMarker(f.client(), ownerMarker), 110+i), A.Phone).Code == http.StatusAccepted {
			answered++
		}
	}
	if answered != 3 {
		t.Fatalf("a marker that holds was answered %d times in a minute from a filled network, want its own 5 less the 2 the controls spent", answered)
	}

	// A network that strangers have not filled: the owner's request does not spend the plain bucket. The first
	// marker's own bucket is spent, so this is another browser of his (a new login mints a new marker).
	f.clearThrottle()
	second := f.client()
	second.mustLogin(A.Phone, pwA)
	secondMarker := second.jar[session.CookieDevice]
	f.clearThrottle()
	f.clearOTP()
	for i := 0; i < 5; i++ {
		f.clearOTP()
		ask(withMarkerOn(f, secondMarker, 198, 50, 1+i), A.Phone).want(202, "")
	}
	for i := 0; i < 5; i++ {
		ask(withMarkerOn(f, nil, 198, 50, 20+i), junk(600+i)).want(202, "")
	}
	ask(withMarkerOn(f, nil, 198, 50, 30), junk(700)).want(429, "")
}

// withMarkerOn is a client on 198.51.<third>.<last>, carrying the device marker m when it is not nil.
func withMarkerOn(f *frig, m *http.Cookie, _, third, last int) *client {
	c := f.client()
	c.ip = fmt.Sprintf("198.51.%d.%d", third, last)
	if m != nil {
		c.jar[session.CookieDevice] = &http.Cookie{Name: session.CookieDevice, Value: m.Value}
	}
	return c
}

// TestTheCooldownTheClientIsToldIsTheOneTheAdminSet is tenant-r8-2. otp_cooldown_s is an admin setting
// (10 to 3600 seconds); the 202 of every code request said resend_after_s = 60 and the 429 otp_limited
// said Retry-After: 60 whatever it was, so a dashboard that waited the stated time for a 300 second
// cooldown was refused again, and one that waited it for a 30 second cooldown waited twice as long as
// it had to. The figure now comes from the configuration the api already reads and caches (the same for
// every phone), and is the same for a number with an account and one without.
func TestTheCooldownTheClientIsToldIsTheOneTheAdminSet(t *testing.T) {
	for _, cooldown := range []int{30, 300} {
		t.Run(fmt.Sprintf("%ds", cooldown), func(t *testing.T) {
			f := newFrig(t, frigOpts{})
			A := f.env.A
			f.env.Exec(t, `UPDATE ctrlz.system_settings SET otp_cooldown_s = $1`, cooldown)
			f.clearThrottle()

			type issued struct {
				Resend int `json:"resend_after_s"`
			}
			const unknown = "+989125550101"
			for _, phone := range []string{A.Phone, unknown} {
				var got issued
				c := f.client()
				c.post("/auth/otp/request", map[string]any{"phone": phone, "purpose": "login", "locale": "fa"}).want(202, "").json(&got)
				if got.Resend != cooldown {
					t.Fatalf("resend_after_s = %d for a cooldown of %d s", got.Resend, cooldown)
				}
				// Inside the cooldown the same phone is refused, and the 429 names the wait.
				r := c.post("/auth/otp/request", map[string]any{"phone": phone, "purpose": "login", "locale": "fa"}).want(429, "otp_limited")
				if ra := r.H.Get("Retry-After"); ra != fmt.Sprint(cooldown) {
					t.Fatalf("Retry-After = %q for a cooldown of %d s (phone with an account: %v)", ra, cooldown, phone == A.Phone)
				}
			}

			// The two signed-in routes state it too. Reauth by SMS is for an account with no password and no
			// authenticator (the other tenant's, here); the phone change is the first one's.
			f.env.Exec(t, `UPDATE ctrlz.users SET password_hash = NULL WHERE tenant_id = $1`, f.env.B.Tenant)
			bs := f.makeSession(f.env.B.Tenant, f.env.B.User)
			var got issued
			f.clearOTP()
			bs.post("/auth/reauth/otp/request", nil).want(202, "").json(&got)
			if got.Resend != cooldown {
				t.Fatalf("reauth: resend_after_s = %d for a cooldown of %d s", got.Resend, cooldown)
			}
			c := f.makeSession(A.Tenant, A.User)
			c.reauthPassword(pwA).want(204, "")
			f.clearOTP()
			f.ck.add(time.Minute)
			got = issued{}
			c.post("/account/phone/change", map[string]any{"new_phone": "+989128880077"}).want(202, "").json(&got)
			if got.Resend != cooldown {
				t.Fatalf("phone change: resend_after_s = %d for a cooldown of %d s", got.Resend, cooldown)
			}
		})
	}
}

// TestParallelRequestsThatReachTheTransactionBeyondThePoolDoNotStall is tenant-r8-1: spec 18.3, "the pool
// exhausted by the request itself", for the routes whose storm no longer reached its transaction.
// TestParallelRequestsBeyondThePoolDoNotStall sends a wrong second factor, and since then two things turn
// such a request away before any transaction opens: the Argon2 and scoring gates keep one hash per
// account (tenant-r7-6; the gate answers the rest 503 server_busy at once, and the storm relabelled that
// 429 and counted it a pass), and completeReset looks at the code first (tenant-r5-6, totp.Plausible: a
// wrong code is refused before the scoring, the hash and the transaction). Only login/totp and
// totp/confirm still put pool-many requests in a transaction. Someone who added a throttle hit or a
// ticket Take inside the transaction of the other routes (through a context from tx.Context(), so the
// lint passes) would have kept every test green.
//
// A request that is to reach the transaction needs a code that passes every look in front of it and is
// refused only there: a code that is right for the window and whose step is already spent. The
// transaction's own check then answers totp_step_reused, which nothing earlier can say, so the storm can
// count the requests it decided (frig.stormTx) and fail when too few got there. The pool of the test has
// four connections, so four requests in a transaction at once is the least that can exhaust it.
//
//   - reauth, for an account with an authenticator and no password (no Argon2 lane in front);
//   - reset/complete, five tickets of one account (the second factor's own limit lets five through);
//   - account/password, whose per-account Argon2 lane is the point: sessions of ONE account reach the
//     transaction one at a time, so the pool cannot be exhausted by an account however many sessions it
//     opens, and the test shows that bound (the rest are turned away at the gate) instead of a storm.
func TestParallelRequestsThatReachTheTransactionBeyondThePoolDoNotStall(t *testing.T) {
	const n, pool = 6, 4
	// setup gives a fresh fixture whose account A has an authenticator, the code of the current window,
	// and its step already spent.
	setup := func(t *testing.T) (f *frig, code string, probe *client) {
		t.Helper()
		f = newFrig(t, frigOpts{})
		A, B := f.env.A, f.env.B
		seed := f.enableTOTP(A.Tenant, A.User)
		f.env.Exec(t, `UPDATE ctrlz.users SET totp_last_step = $1 WHERE id = $2`, time.Now().Unix()/30+2, A.User)
		return f, totp.Generate(seed, time.Now()), f.makeSession(B.Tenant, B.User)
	}
	const txCode = "totp_step_reused"

	t.Run("reauth, an account with no password", func(t *testing.T) {
		f, code, probe := setup(t)
		A := f.env.A
		f.env.Exec(t, `UPDATE ctrlz.users SET password_hash = NULL WHERE id = $1`, A.User)
		f.clearThrottle()
		sess := make([]*client, n)
		for i := range sess {
			sess[i] = f.makeSession(A.Tenant, A.User)
		}
		got := f.stormTx(t, "reauth", n, probe, inTxByCode(txCode), pool, func(i int) *resp {
			return sess[i].post("/auth/reauth", map[string]any{"totp_code": code})
		})
		for _, s := range got {
			if s != 401 && s != 429 {
				t.Errorf("reauth answered %d", s)
			}
		}
	})

	t.Run("reset/complete, five tickets", func(t *testing.T) {
		f, code, probe := setup(t)
		A := f.env.A
		f.clearThrottle()
		ticks := make([]string, n)
		for i := range ticks {
			ticks[i] = f.client().verifyReset(A.Phone).Ticket
		}
		f.clearThrottle()
		cl := make([]*client, n)
		for i := range cl {
			cl[i] = f.client()
		}
		got := f.stormTx(t, "reset/complete", n, probe, inTxByCode(txCode), pool, func(i int) *resp {
			return cl[i].post("/auth/password/reset/complete", map[string]any{"ticket": ticks[i], "new_password": "Cobalt-meadow-Falcon-4417", "totp_code": code})
		})
		for _, s := range got {
			if s != 401 && s != 429 {
				t.Errorf("reset/complete answered %d", s)
			}
		}
	})

	t.Run("account/password, one account's sessions meet its Argon2 lane", func(t *testing.T) {
		f, code, probe := setup(t)
		A := f.env.A
		f.clearThrottle()
		f.env.Exec(t, `UPDATE ctrlz.users SET must_reset = true, password_expires_at = now() + interval '72 hours' WHERE id = $1`, A.User)
		sess := make([]*client, n)
		for i := range sess {
			sess[i] = f.makeSession(A.Tenant, A.User)
		}
		// At least one reaches the transaction, so the route is driven past its pre-checks; the others are
		// turned away at the gate or follow it one at a time, and none stalls.
		got := f.stormTx(t, "account/password", n, probe, inTxByCode(txCode), 1, func(i int) *resp {
			return sess[i].post("/account/password", map[string]any{"new_password": "Cobalt-meadow-Falcon-4417", "totp_code": code})
		})
		for _, s := range got {
			if s != 401 && s != 429 {
				t.Errorf("account/password answered %d", s)
			}
		}
	})
}
