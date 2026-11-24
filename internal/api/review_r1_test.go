package api

import (
	"encoding/base64"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	apidoc "github.com/Kup1ng/CtrlZ-Panel/api"
	"github.com/Kup1ng/CtrlZ-Panel/internal/apispec"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/credstate"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/passkey/passkeytest"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/session"
	"github.com/Kup1ng/CtrlZ-Panel/internal/credgen"
	"github.com/Kup1ng/CtrlZ-Panel/internal/ratelimit"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// Tests of the P1 auth review, round 1, area "HTTP spine and tenant API".

// stormTx sends n requests at the same instant and checks the three things a pool starvation breaks: no answer is a
// 5xx, none takes anywhere near the database's lock_timeout (10 s), and another tenant's GET /me, sent while the
// storm runs, is answered at once. Tenant-r1-1, -7, -11: the test pool has 4 connections, so a storm of pool+2 puts
// every connection in a transaction that waits for the same user row.
//
// It also checks how many of the requests were decided INSIDE the route's transaction, and there is no way to ask
// for less (round 11, tenant-r11-3; the helper once had a form without it, which three storms kept using after
// tenant-r8-1 had shown it proves nothing). reached says an answer is known to come from the transaction: it
// carries an error code that only the transaction's own check can give (for a second factor: totp_step_reused, a
// code that passes every earlier look and is refused for a step already spent), or a success that only a
// committed transaction yields (a login that opened the mfa ticket, a session). Without it a storm can be
// answered, and pass, while the gates and pre-checks in front of the transaction turn every request but one away,
// and then it proves nothing about the pool: the shape of the review round 8 finding tenant-r8-1 (the per-account
// Argon2 lane since tenant-r7-6, and the plausibility check of the second factor since tenant-r5-6, each refuse
// before any transaction, and the storm counted those as passes) and of round 11 (a throttle in front of the
// password login). minInTx is how many must have reached it, at least one; the test fails below that.
func (f *frig) stormTx(t *testing.T, name string, n int, probe *client, reached func(*resp) bool, minInTx int, call func(i int) *resp) []int {
	t.Helper()
	if reached == nil || minInTx < 1 {
		t.Fatalf("%s: a storm must say how it knows a request reached the transaction (reached) and how many must (minInTx >= 1)", name)
	}
	statuses := make([]int, n)
	inTx := make([]bool, n)
	var gateRefused atomic.Int64
	took := make([]time.Duration, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			r := call(i)
			statuses[i], took[i] = r.Code, r.Dur
			inTx[i] = reached(r)
			// The gate takes one hash per account at a time and refuses the others at once (tenant-r7-6),
			// and every request of a storm is the same account's. That answer is fast and holds no
			// connection, so it is a refusal like a 429 and not the stall this test looks for.
			if r.Code == 503 && strings.Contains(string(r.Body), `"server_busy"`) {
				statuses[i] = 429
				gateRefused.Add(1)
			}
		}()
	}
	var probeCode int
	var probeTook time.Duration
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		time.Sleep(20 * time.Millisecond)
		r := probe.get("/me")
		probeCode, probeTook = r.Code, r.Dur
	}()
	begin := time.Now()
	close(start)
	wg.Wait()
	if total := time.Since(begin); total > 6*time.Second {
		t.Errorf("%s: %d parallel requests took %v; a request must never wait out lock_timeout", name, n, total)
	}
	for i, s := range statuses {
		if s >= 500 {
			t.Errorf("%s: request %d answered %d after %v", name, i, s, took[i])
		}
	}
	if probeCode != 200 || probeTook > 3*time.Second {
		t.Errorf("%s: another tenant's GET /me answered %d after %v while the storm ran", name, probeCode, probeTook)
	}
	got := 0
	for _, b := range inTx {
		if b {
			got++
		}
	}
	if got < minInTx {
		t.Errorf("%s: only %d of %d requests were decided inside the transaction, %d were turned away at the gate; the storm needs %d to put the pool under the load it is meant to", name, got, n, gateRefused.Load(), minInTx)
	}
	return statuses
}

// inTxByCode says an answer came from the transaction when its body carries the error code that only the
// transaction can give.
func inTxByCode(code string) func(*resp) bool {
	return func(r *resp) bool { return strings.Contains(string(r.Body), `"`+code+`"`) }
}

// inTxByStatus is the same for a success that a committed transaction yields and a pre-check never does.
func inTxByStatus(status int) func(*resp) bool {
	return func(r *resp) bool { return r.Code == status }
}

// TestParallelRequestsBeyondThePoolDoNotStall is spec 18.3 "pool exhausted by
// the request itself" (review round 1, tenant-r1-1, -7, -11). Each route below
// holds a transaction and the user row lock and used to need a throttle hit or a ticket
// on a second connection. With one pool, as many requests as the pool has
// connections held every connection and the holder of the lock waited for a
// connection for ever (until lock_timeout), for every tenant. The hit is made before
// the transaction and the ticket on its own connection (rule one-connection-per-request),
// so the holder never asks for a second.
func TestParallelRequestsBeyondThePoolDoNotStall(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A, B := f.env.A, f.env.B
	const n = 6 // the test pool has 4 connections
	f.enableTOTP(A.Tenant, A.User)
	probe := f.makeSession(B.Tenant, B.User)
	const wrong = "000000"

	only := func(t *testing.T, route string, statuses []int) {
		t.Helper()
		for _, s := range statuses {
			if s != 401 && s != 429 {
				t.Errorf("%s answered %d, want 401 or 429", route, s)
			}
		}
	}

	t.Run("login/totp", func(t *testing.T) {
		tickets := make([]string, n)
		clients := make([]*client, n)
		for i := range clients {
			f.clearThrottle()
			clients[i] = f.client()
			tickets[i] = clients[i].mfaLogin(A.Phone, pwA)
		}
		f.clearThrottle()
		only(t, "login/totp", f.stormTx(t, "login/totp", n, probe, inTxByCode("totp_invalid"), 4, func(i int) *resp {
			return clients[i].post("/auth/login/totp", map[string]any{"ticket": tickets[i], "totp_code": wrong})
		}))
	})

	// reauth, account/password and reset/complete had storms here that sent a wrong code. Since tenant-r7-6 and
	// tenant-r5-6 a wrong code (or a second request of one account) is turned away in front of the transaction, so
	// those storms put one request in it and proved little; TestParallelRequestsThatReachTheTransactionBeyondThePoolDoNotStall
	// drives the three with a code that reaches it and counts the answers that came from there (tenant-r8-1), and
	// the helper no longer has a form that does not count (tenant-r11-3).

	t.Run("totp/confirm", func(t *testing.T) {
		f.clearThrottle()
		owner := f.makeSession(B.Tenant, B.User)
		f.env.Exec(t, `UPDATE ctrlz.sessions SET reauth_at = now() WHERE user_id = $1`, B.User)
		owner.post("/account/totp/setup", nil).want(200, "")
		sess := make([]*client, n)
		for i := range sess {
			sess[i] = f.makeSession(B.Tenant, B.User)
		}
		f.env.Exec(t, `UPDATE ctrlz.sessions SET reauth_at = now() WHERE user_id = $1`, B.User)
		other := f.makeSession(A.Tenant, A.User) // this round the storm is B's and the probe is A's
		only(t, "totp/confirm", f.stormTx(t, "totp/confirm", n, other, inTxByCode("totp_invalid"), 4, func(i int) *resp {
			return sess[i].post("/account/totp/confirm", map[string]any{"code": wrong, "saved": true})
		}))
	})
}

// restrictedSession opens a session the way a login of the given method would for
// a user who must set a password (3.5).
func (f *frig) restrictedSession(tenant, user uuid.UUID, method string) *client {
	f.t.Helper()
	c := f.client()
	err := f.st.WithTenant(f.env.Ctx, tenant, store.TxOpts{}, func(tx store.Tx) error {
		iss, err := f.m.Create(tx, session.NewSession{User: user, Method: method, Restricted: true, IP: netip.MustParseAddr("203.0.113.5"), UserAgent: "t"})
		c.jar[session.CookieSession] = iss.Cookies()[0]
		return err
	})
	if err != nil {
		f.t.Fatal(err)
	}
	return c
}

// TestRestrictedSessionByOTPOrPasskeyCannotSetAPassword is tenant-r1-3 and -8:
// the reauth waiver of 4.4 belongs to the session the one-time password itself
// opened. A session opened by an SMS code or a passkey for the same user is
// restricted too, but proved nothing about the password, and 3.5 says an SMS
// code never replaces it.
func TestRestrictedSessionByOTPOrPasskeyCannotSetAPassword(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A := f.env.A
	const newPw = "Cobalt-meadow-Falcon-4417"
	const oneTime = "One-Time-Pass-8842x"
	setOneTime := func(expiry string) {
		h, _ := f.hasher.Hash(f.env.Ctx, secretString(oneTime))
		f.env.Exec(t, `UPDATE ctrlz.users SET password_hash = $2, must_reset = true, password_expires_at = now() + $3::interval WHERE id = $1`, A.User, h.Reveal(), expiry)
	}
	restore := func() {
		f.env.Exec(t, `UPDATE ctrlz.users SET must_reset = false, password_expires_at = NULL WHERE id = $1`, A.User)
		f.setPassword(A.Tenant, A.User, pwA)
		f.clearThrottle()
	}
	otpLogin := func() *client {
		c := f.client()
		var iss issued
		c.requestOTP(A.Phone, "login", nil).want(202, "").json(&iss)
		r := c.post("/auth/login/otp", map[string]any{"phone": A.Phone, "challenge_id": iss.ID, "code": f.codes.Last()}).want(200, "")
		if r.cookie(session.CookieSession) == nil {
			t.Fatal("no session")
		}
		return c
	}

	for _, expiry := range []string{"72 hours", "-1 hour"} {
		t.Run("SMS login, one-time password "+expiry, func(t *testing.T) {
			defer restore()
			setOneTime(expiry)
			c := otpLogin()
			if !c.me().User.MustReset {
				t.Fatal("the session should be a setup session")
			}
			c.post("/account/password", map[string]any{"new_password": newPw}).want(403, "reauth_required")
			if f.count(`SELECT count(*) FROM ctrlz.users WHERE id = $1 AND must_reset`, A.User) != 1 {
				t.Fatal("the refused call changed the user")
			}
			if expiry == "72 hours" {
				// Knowing the live one-time password opens the window, as for any session.
				c.reauthPassword(oneTime).want(204, "")
				c.post("/account/password", map[string]any{"new_password": newPw}).want(204, "")
			} else {
				// An expired one proves nothing, by SMS or by password.
				c.reauthPassword(oneTime).want(401, "invalid_credentials")
				c.post("/account/password", map[string]any{"new_password": newPw}).want(403, "reauth_required")
			}
		})
	}

	t.Run("passkey login", func(t *testing.T) {
		defer restore()
		setOneTime("72 hours")
		c := f.restrictedSession(A.Tenant, A.User, "passkey")
		c.post("/account/password", map[string]any{"new_password": newPw}).want(403, "reauth_required")
	})

	t.Run("password login still needs no reauth, and a TOTP user still gives a code", func(t *testing.T) {
		defer restore()
		setOneTime("72 hours")
		seed := f.enableTOTP(A.Tenant, A.User)
		defer f.env.Exec(t, `UPDATE ctrlz.users SET totp_secret_ct = NULL, totp_enabled_at = NULL, totp_last_step = NULL WHERE id = $1`, A.User)
		cl := f.client()
		tk := cl.mfaLogin(A.Phone, oneTime)
		now := time.Now()
		cl.post("/auth/login/totp", map[string]any{"ticket": tk, "totp_code": codeAt(seed, now)}).want(200, "")
		cl.post("/account/password", map[string]any{"new_password": newPw}).want(401, "totp_invalid")
		cl.post("/account/password", map[string]any{"new_password": newPw, "totp_code": codeAt(seed, now)}).want(401, "totp_step_reused")
		cl.post("/account/password", map[string]any{"new_password": newPw, "totp_code": codeAt(seed, now.Add(30*time.Second))}).want(204, "")
	})
}

// TestReauthHashIsTheSessionUsers is tenant-r1-14: the hash a reauth checks is
// used only when the lookup by phone returned the session's own user.
func TestReauthHashIsTheSessionUsers(t *testing.T) {
	mine := credgen.Stamp{Tenant: uuid.New(), Subject: uuid.New(), Gen: 3}
	hash := secretString("$argon2id$x")
	// expired is what the database decided (UserLogin.State).
	row := func(tenant, user uuid.UUID, expired bool) store.UserLogin {
		state := credstate.Ready
		if expired {
			state = credstate.OneTimeExpired
		}
		return store.UserLogin{TenantID: tenant, UserID: user, PasswordHash: hash, State: state, Cred: credgen.Stamp{Tenant: tenant, Subject: user, Gen: mine.Gen}}
	}
	// A password that changed between the facts and the lookup is not the one to check.
	moved := row(mine.Tenant, mine.Subject, false)
	moved.Cred.Gen++
	for name, tc := range map[string]struct {
		login store.UserLogin
		found bool
		want  bool
	}{
		"own row":                            {row(mine.Tenant, mine.Subject, false), true, true},
		"own row, live one-time":             {row(mine.Tenant, mine.Subject, false), true, true},
		"own row, expired":                   {row(mine.Tenant, mine.Subject, true), true, false},
		"not found":                          {row(mine.Tenant, mine.Subject, false), false, false},
		"another tenant's user":              {row(uuid.New(), uuid.New(), false), true, false},
		"another user in the same tenant":    {row(mine.Tenant, uuid.New(), false), true, false},
		"same user id in another tenant":     {row(uuid.New(), mine.Subject, false), true, false},
		"the password moved since the facts": {moved, true, false},
	} {
		got := reauthHash(mine, tc.login, tc.found).Reveal() != ""
		if got != tc.want {
			t.Errorf("%s: hash used = %v, want %v", name, got, tc.want)
		}
	}
}

// TestPasswordChangeNeedsNoSecondCodeInsideAFreshReauth is tenant-r1-4 and -13:
// the code adds nothing, because the window that allows the change also allows
// POST /account/totp/disable, which asks for no code.
func TestPasswordChangeNeedsNoSecondCodeInsideAFreshReauth(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A := f.env.A
	seed := f.enableTOTP(A.Tenant, A.User)
	c := f.client()
	c.mfaLoginComplete(A.Phone, pwA, codeAt(seed, time.Now()))
	c.post("/auth/reauth", map[string]any{"password": pwA, "totp_code": codeAt(seed, time.Now().Add(30*time.Second))}).want(204, "")
	// The proof of the window is a password and a code; no further code is asked.
	c.post("/account/password", map[string]any{"new_password": "Cobalt-meadow-Falcon-4417"}).want(204, "")
	f.setPassword(A.Tenant, A.User, pwA)
	// And without a window, no code helps.
	f.clearThrottle()
	d := f.client()
	f.freeStep(A.Tenant)
	d.mfaLoginComplete(A.Phone, pwA, codeAt(seed, time.Now()))
	d.post("/account/password", map[string]any{"new_password": "Cobalt-meadow-Falcon-4417", "totp_code": codeAt(seed, time.Now().Add(30*time.Second))}).want(403, "reauth_required")
}

// TestCursorOutOfRangeIsABadRequest is tenant-r1-5.
func TestCursorOutOfRangeIsABadRequest(t *testing.T) {
	f := newFrig(t, frigOpts{})
	c := f.makeSession(f.env.B.Tenant, f.env.B.User)
	id := uuid.NewString()
	cursor := func(micro string) string {
		return base64.RawURLEncoding.EncodeToString([]byte(micro + "|" + id + "|" + f.env.B.Tenant.String()))
	}
	for _, us := range []string{"-300000000000000000", "-9223372036854775808", "9223372036854775807", "0", "99999999999999999"} {
		for _, path := range []string{"/notifications", "/announcements"} {
			c.get(path+"?cursor="+cursor(us)).want(400, "bad_request")
		}
	}
	// A real cursor of today is accepted.
	c.get("/notifications?cursor="+encodeCursor(f.env.B.Tenant, time.Now(), uuid.New())).want(200, "")
	c.get("/announcements?cursor="+encodeCursor(f.env.B.Tenant, time.Now(), uuid.New())).want(200, "")
}

// TestACursorBelongsToTheTenantThatGotIt is tenant-r17-6 and -11. The cursor names a row (the last one of a
// page) and is neither a uuid nor named like an id, so the isolation harness did not see it. It now carries
// the tenant it was made for and the other tenant's cursor, the form before round 17 and a form with a
// part more are all refused as bad_request on both lists, before the row is read by anything.
func TestACursorBelongsToTheTenantThatGotIt(t *testing.T) {
	f := newFrig(t, frigOpts{})
	b := f.makeSession(f.env.B.Tenant, f.env.B.User)
	at, id := time.Now(), uuid.New()
	enc := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	micro := strconv.FormatInt(at.UnixMicro(), 10)
	for _, cursor := range map[string]string{
		"another tenant's":      encodeCursor(f.env.A.Tenant, at, id),
		"the two-part form":     enc(micro + "|" + id.String()),
		"a part more":           enc(micro + "|" + id.String() + "|" + f.env.B.Tenant.String() + "|x"),
		"a tenant that is text": enc(micro + "|" + id.String() + "|b"),
		"an empty tenant":       enc(micro + "|" + id.String() + "|"),
	} {
		for _, path := range []string{"/notifications", "/announcements"} {
			b.get(path+"?cursor="+cursor).want(400, "bad_request")

		}
	}
	// Its own, round trip: the next_cursor of a page opens the next page of the same tenant.
	b.get("/notifications?cursor="+encodeCursor(f.env.B.Tenant, at, id)).want(200, "")
}

// TestSeveralInviteesOnOneNetworkAreAllServed is what tenant-r1-6 asked of invite_net, as D67 keeps it: honest
// invitations (lookup, code request, register, with a typo) from one carrier network do not use up anything a
// neighbour needs. The scope that counted bad tokens is gone: a link that does not open costs no throttle row
// at all, so there is nothing a stranger can spend (TestABadInviteLinkCostsNoReadAndNoThrottleRow).
func TestSeveralInviteesOnOneNetworkAreAllServed(t *testing.T) {
	f := newFrig(t, frigOpts{})
	c := f.client() // one network for everybody
	for i := 0; i < 5; i++ {
		phone := fmt.Sprintf("+98912555%04d", 2001+i)
		code := f.plantInvite(phone, time.Hour, false)
		c.post("/auth/invites/lookup", map[string]any{"token": code}).want(200, "")
		var iss issued
		c.requestOTP(phone, "invite", map[string]any{"invite_token": code}).want(202, "").json(&iss)
		reg := func(otp string) *resp {
			return c.post("/auth/register", map[string]any{"invite_token": code, "challenge_id": iss.ID, "code": otp, "password": "Marble-Island-Copper-6620"})
		}
		reg("000000").want(401, "otp_invalid") // a typo
		reg(f.codes.Last()).want(201, "")
		f.ck.add(time.Minute) // under the rate classes of the routes
	}
	// Every use counted on the invite it names and on nothing of the network: five invites, five rows.
	if n := f.count(`SELECT count(*) FROM ctrlz.auth_throttle WHERE scope = 'invite_net'`); n != 5 {
		t.Fatalf("%d invite throttle rows after five invitations, want one for each invite", n)
	}
}

// TestOTPReauthCountsOnReauthUser is tenant-r1-15: the OTP path of reauth is
// bounded per session (reauth_session, round 7), as the password path is.
func TestOTPReauthCountsOnReauthUser(t *testing.T) {
	f := newFrig(t, frigOpts{})
	B := f.env.B
	f.env.Exec(t, `UPDATE ctrlz.users SET password_hash = NULL WHERE tenant_id = $1`, B.Tenant)
	c := f.makeSession(B.Tenant, B.User)
	for i := 0; i < 5; i++ {
		// Each try from another network, so only the per-user scope can stop it.
		c.ip = f.freshIP()
		c.post("/auth/reauth", map[string]any{"otp_challenge_id": uuid.NewString(), "otp_code": "000000"}).want(401, "otp_invalid")
	}
	c.ip = f.freshIP()
	r := c.post("/auth/reauth", map[string]any{"otp_challenge_id": uuid.NewString(), "otp_code": "000000"}).want(429, "too_many_attempts")
	if r.H.Get("Retry-After") == "" {
		t.Error("429 without Retry-After")
	}
}

// TestPasskeyBeginHasNoBucketForTheWholeService is tenant-r1-17 after the budget-keying
// rule. The unauthenticated begin stores a row per call. Round 1 capped the whole api
// at 300 a minute, and strangers could empty that cap for every honest user (round 2,
// tenant-r2-5). A bucket for the whole service is not in the closed set of key sources
// any more: the begin is charged like every route of the auth class, to the network of
// a request with no proof, so many networks are not limited together and one network is.
func TestPasskeyBeginHasNoBucketForTheWholeService(t *testing.T) {
	f := newFrig(t, frigOpts{passkey: true})
	class, _ := ratelimit.Lookup(ratelimit.Tenant, "auth")
	whole := 300 // the old cap of the whole service
	for i := 0; i < whole+50; i++ {
		c := f.client()
		c.ip = f.freshIP()
		c.post("/auth/passkey/login/begin", map[string]any{}).want(200, "")
		// Another network per call, and a minute apart every 200 calls so a /24 that
		// comes round again has its tokens back: only the old global cap could refuse.
		if i%200 == 199 {
			f.ck.add(time.Minute + time.Second)
		}
	}
	// One network is still limited.
	one := f.client()
	one.ip = "203.0.113.9"
	refused := 0
	for i := 0; i < class.Limits[0].Max+5; i++ {
		r := one.post("/auth/passkey/login/begin", map[string]any{})
		if r.Code == 429 {
			refused++
			if r.H.Get("Retry-After") == "" {
				t.Fatal("429 without Retry-After")
			}
		}
	}
	if refused != 5 {
		t.Errorf("%d calls refused from one network, want 5 above the class limit of %d", refused, class.Limits[0].Max)
	}
	// The window moves on.
	f.ck.add(time.Minute + time.Second)
	one.post("/auth/passkey/login/begin", map[string]any{}).want(200, "")
}

// TestEveryRouteGoesThroughHostXFFAndCSRF is tenant-r1-9 and spec 18.5 "CSRF,
// each POST, login too": it walks the operations of api/openapi.yaml, so a route
// mounted outside the pipeline fails here. The checks are answered before any
// handler: no cookie is sent, so a handler reaching the session lookup would
// answer 401 instead.
func TestEveryRouteGoesThroughHostXFFAndCSRF(t *testing.T) {
	r := newRig(t, true)
	ops, err := apispec.Parse(apidoc.Tenant(), ratelimit.Tenant)
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range ops {
		path := "/api/v1" + strings.ReplaceAll(op.Path, "{id}", uuid.NewString())
		expect(t, r.do(t, r.h, call{method: op.Method, path: path, host: "evil.test", body: `{}`}), 400, "bad_request")
		expect(t, r.do(t, r.h, call{method: op.Method, path: path, xff: "-", body: `{}`}), 400, "bad_request")
		if op.Method == "GET" || op.Method == "HEAD" {
			continue
		}
		for _, hdr := range []map[string]string{
			{"Sec-Fetch-Site": "cross-site"}, {"Sec-Fetch-Site": "same-site"}, {"Origin": "https://evil.test"},
		} {
			w := r.do(t, r.h, call{method: op.Method, path: path, hdr: hdr, body: `{}`})
			if w.Code != 403 || errCode(t, w) != "csrf_rejected" {
				t.Errorf("%s %s with %v: %d %s, want 403 csrf_rejected", op.Method, op.Path, hdr, w.Code, w.Body)
			}
		}
	}
}

// TestTicketsDoNotCrossTenants is tenant-r1-10 and -16: a ceremony ticket that
// A's call minted is useless in B's session, and neither side changes. The
// harness of TestIsolation sends "junk" tickets; these are real.
func TestTicketsDoNotCrossTenants(t *testing.T) {
	f := newFrig(t, frigOpts{passkey: true})
	A, B := f.env.A, f.env.B
	aKey, bKey := passkeytest.New(pkOrigin, pkRP), passkeytest.New(pkOrigin, pkRP)
	a, b := f.client(), f.client()
	a.mustLogin(A.Phone, pwA)
	b.mustLogin(B.Phone, pwB)
	a.reauthPassword(pwA).want(204, "")
	b.reauthPassword(pwB).want(204, "")
	a.addPasskey(aKey).want(201, "")
	creds := func(tenant uuid.UUID) int {
		return f.count(`SELECT count(*) FROM ctrlz.webauthn_credentials WHERE tenant_id = $1`, tenant)
	}
	aBefore, bBefore := creds(A.Tenant), creds(B.Tenant)

	t.Run("a registration ticket of A in B's session", func(t *testing.T) {
		var cer ceremonyBody
		a.post("/account/passkeys/begin", nil).want(200, "").json(&cer)
		body, err := bKey.Create(cer.Options) // B's authenticator answers A's challenge
		if err != nil {
			t.Fatal(err)
		}
		if r := b.postT("/account/passkeys/finish", cer.Ticket, body); r.Code != 401 {
			t.Fatalf("B finished A's registration: %d %s", r.Code, r.Body)
		}
		if creds(A.Tenant) != aBefore || creds(B.Tenant) != bBefore {
			t.Error("a credential was added")
		}
		// Presenting the ticket spent it; no credential appears under either tenant.
		ownBody, _ := aKey.Create(cer.Options)
		a.postT("/account/passkeys/finish", cer.Ticket, ownBody).want(401, "ticket_invalid")
		if creds(A.Tenant) != aBefore || creds(B.Tenant) != bBefore {
			t.Error("a credential was added by the spent ticket")
		}
	})

	t.Run("a reauth ticket of A in B's session", func(t *testing.T) {
		f.clearThrottle()
		var cer ceremonyBody
		a.post("/auth/reauth/passkey/begin", nil).want(200, "").json(&cer)
		body, err := aKey.Get(cer.Options) // A's real key, A's real challenge
		if err != nil {
			t.Fatal(err)
		}
		fresh := f.makeSession(B.Tenant, B.User)
		if r := fresh.postT("/auth/reauth/passkey/finish", cer.Ticket, body); r.Code != 401 {
			t.Fatalf("B's session took A's reauth ticket: %d %s", r.Code, r.Body)
		}
		// B's session gained no reauth window.
		fresh.post("/account/totp/disable", nil).want(403, "reauth_required")
	})
}
