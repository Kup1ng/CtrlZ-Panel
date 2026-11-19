package api

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/passkey/passkeytest"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/password"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/pwstrength"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/session"
	"github.com/Kup1ng/CtrlZ-Panel/internal/budget"
)

// Tests of the P1 auth review, round 7, area "HTTP spine and tenant API".

// TestJunkRegistersCannotSpendTheCodeCheckOfALiveInvitee is tenant-r7-1. register charged
// otp_verify_net (30 a quarter of an hour for a whole /24) before it looked at the invite, so thirty
// junk tokens from one carrier address group refused every honest invitee behind it, in the closed
// mode where an invite is the only way in. A bad token never reaches a code check, so it counts on
// invite_net only; a live invite is a proof, bounded by invite_use and the five tries of its
// challenge. The round 3 test sent fifteen junk registers and stayed under the thirty; this one
// sends forty, well past it, and then registers a live invite from the same network.
func TestJunkRegistersCannotSpendTheCodeCheckOfALiveInvitee(t *testing.T) {
	f := newFrig(t, frigOpts{})
	c := f.client()
	phone := "+989125553002"
	code := f.plantInvite(phone, time.Hour, false)
	const bad = "AAAAA-AAAAA-AAAAA-AAAAA"

	for i := 0; i < 40; i++ {
		r := c.post("/auth/register", map[string]any{"invite_token": bad, "challenge_id": uuid.NewString(), "code": "000000"})
		if r.Code != 404 && r.Code != 429 {
			t.Fatalf("junk register %d: %d %s", i, r.Code, r.Body)
		}
		f.ck.add(20 * time.Second) // 13 minutes in all: inside the window of the scope
	}
	if n := f.scopeCount("otp_verify_net"); n != 0 {
		t.Fatalf("forty junk registers moved otp_verify_net to %d: a token that is not live must not count on the code check", n)
	}

	var iss issued
	c.requestOTP(phone, "invite", map[string]any{"invite_token": code}).want(202, "").json(&iss)
	c.post("/auth/register", map[string]any{
		"invite_token": code, "challenge_id": iss.ID, "code": f.codes.Last(), "password": "Marble-Island-Copper-6620",
	}).want(201, "")
}

// TestACopyOfTheCookieCannotSpendTheOwnersFrontDoor is tenant-r7-2 and -7, the tenant twin of the admin
// test of round 6. A thief holds a copy of a live session cookie and nothing else. Every scope that the
// registry says a bare cookie can spend (SessionReach) is spent from the copy, 12 times, and then the
// owner's other ways in must all still work: the TOTP step of a login (totp_user), a second session's
// reauth, and the passkey step of a password reset (reset_passkey_user, which used to share reauth_user
// with the cookie routes). The set of scopes is read from the registry, and a scope with no driver
// fails, so a new one cannot be declared without being driven here.
func TestACopyOfTheCookieCannotSpendTheOwnersFrontDoor(t *testing.T) {
	drivers := map[string]func(thief *client){
		"reauth_session": func(thief *client) {
			thief.post("/auth/reauth", map[string]any{"password": "wrong-Password-9999"})
		},
		// An assertion that fails its ticket is still counted (the charge comes first), which is all a copy of the
		// cookie can do with this route; it has no long ceiling, so it spends no more than its window.
		"reauth_passkey_session": func(thief *client) {
			thief.postT("/auth/reauth/passkey/finish", "junk-ticket", []byte("{}"))
		},
		"totp_session": func(thief *client) {
			// The code is counted before the route looks at the state, so a user who already has the
			// factor still pays for the attempt (see factorCharge).
			thief.post("/account/totp/confirm", map[string]any{"code": "000000", "saved": true})
		},
	}
	for _, b := range budget.Of(budget.Throttle, budget.Tenant) {
		if !b.SessionReach {
			continue
		}
		drive, ok := drivers[b.Name]
		if !ok {
			t.Errorf("%s can be spent by a bare session cookie and this test has no driver for it", b.Name)
			continue
		}
		t.Run(b.Name, func(t *testing.T) {
			f := newFrig(t, frigOpts{passkey: true})
			A := f.env.A
			seed := f.enableTOTP(A.Tenant, A.User)
			key := passkeytest.New(pkOrigin, pkRP)
			owner := f.makeSession(A.Tenant, A.User)
			f.env.Exec(t, `UPDATE ctrlz.sessions SET reauth_at = $2 WHERE user_id = $1`, A.User, f.ck.now())
			owner.addPasskey(key).want(201, "")
			other := f.makeSession(A.Tenant, A.User)

			thief := f.client()
			thief.jar[session.CookieSession] = owner.jar[session.CookieSession]
			f.clearThrottle()
			for i := 0; i < 12; i++ {
				f.ck.add(time.Minute) // the class of the route is not what is measured
				drive(thief)
			}

			// The TOTP step of a login.
			f.client().mustLoginTOTP(A.Phone, pwA, seed, f)
			// A second session of the owner reauthenticates.
			other.reauthTOTP(pwA, seed)
			// The passkey step of a password reset.
			rc := f.client()
			v := rc.verifyReset(A.Phone)
			var cer ceremonyBody
			rc.post("/auth/password/reset/passkey/begin", map[string]any{"ticket": v.Ticket}).want(200, "").json(&cer)
			body, err := key.Get(cer.Options)
			if err != nil {
				t.Fatal(err)
			}
			rc.postT("/auth/password/reset/passkey/finish", cer.Ticket, body).want(200, "")
		})
	}
}

// TestASessionThatCannotChangeThePasswordIsRefusedBeforeTheHeavyWork is tenant-r7-5. The pre-check
// of POST /account/password passed every user whose password is a one-time password, and only the
// transaction knew that the waiver is for a session that OPENED with that password: one opened by an
// SMS code is restricted too and is refused there with reauth_required. Before the move, such a
// session ran the scoring and an Argon2 hash on the signed-in gate (and charged the second factor)
// for an answer that was known from the first read. Now it is refused before any of it.
func TestASessionThatCannotChangeThePasswordIsRefusedBeforeTheHeavyWork(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A := f.env.A
	strong := pwstrength.NewWithLimit(2, 100*time.Millisecond)
	f.deps.Strength = strong
	f.setLimiter(f.deps.Limiter)
	f.clearThrottle()
	f.enableTOTP(A.Tenant, A.User)
	f.env.Exec(t, `UPDATE ctrlz.users SET must_reset = true, password_expires_at = now() + interval '72 hours' WHERE id = $1`, A.User)
	const newPw = "Cobalt-meadow-Falcon-4417"

	bySMS := f.makeSession(A.Tenant, A.User)
	f.env.Exec(t, `UPDATE ctrlz.sessions SET auth_method = 'otp' WHERE id = (SELECT id FROM ctrlz.sessions WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1)`, A.User)

	runs, scored := f.hasher.Runs(), strong.Scorings()
	for i := 0; i < 3; i++ {
		bySMS.post("/account/password", map[string]any{"new_password": newPw, "totp_code": "000000"}).want(403, "reauth_required")
	}
	if got := f.hasher.Runs() - runs; got != 0 {
		t.Errorf("a session opened by an SMS code cost %d Argon2 runs before it was refused", got)
	}
	if got := strong.Scorings() - scored; got != 0 {
		t.Errorf("a session opened by an SMS code cost %d scorings before it was refused", got)
	}
	if n := f.scopeCount("totp_user"); n != 0 {
		t.Errorf("a session that cannot change the password spent %d tries of the second factor", n)
	}
}

// TestOneAccountWithManySessionsCannotStarveStrangers is tenant-r7-6. The lane of the Argon2 gate is
// strict priority, and a session that passed its gate is in it. The only bound on a signed-in caller's
// hashes was the sensitive class, per session, and nothing caps the sessions of one account (every
// login mints one), so one account holder with eighty sessions looping a right-password reauth kept the
// proved queue full and every request without a proof, the login of another phone from a new browser
// among them, was refused with 503 at once. The lane now takes one hash per account at a time, so the
// flood holds one slot of the two and a stranger is served by the other.
func TestOneAccountWithManySessionsCannotStarveStrangers(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A, B := f.env.A, f.env.B
	heavy, err := password.NewHasher(password.Params{MemoryKiB: 32 * 1024, Time: 3, Threads: 1}, password.NewGate(2, 800*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	f.hasher, f.deps.Hasher = heavy, heavy
	f.setLimiter(f.deps.Limiter)
	f.setPassword(A.Tenant, A.User, pwA)
	f.setPassword(B.Tenant, B.User, pwB)
	f.clearThrottle()

	const sessions = 80
	flooders := make([]*client, sessions)
	for i := range flooders {
		flooders[i] = f.makeSession(A.Tenant, A.User)
	}
	var wg sync.WaitGroup
	var hashed, turnedAway, live atomic.Int64
	live.Store(int64(len(flooders)))
	for _, c := range flooders {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer live.Add(-1)
			for i := 0; i < 10; i++ { // the sensitive class allows ten a minute to a session
				switch c.reauthPassword(pwA).Code {
				case http.StatusNoContent:
					hashed.Add(1)
				case http.StatusServiceUnavailable:
					turnedAway.Add(1)
				}
			}
		}()
	}
	time.Sleep(100 * time.Millisecond) // the flood is running and the lane is busy

	// Strangers come ONE AT A TIME, each with a few tries. The earlier form sent six at once and asked that a
	// whole burst be served, and it failed on a loaded machine (rounds 8 and 13: a flake is a finding): the
	// unproved queue holds one waiter per slot and turns the rest away at once (spec 14.1), so of six
	// simultaneous strangers behind a flood that holds one slot, 503 for the rest is the design and not a
	// starved lane, and how many are served depends on how the arrivals bunch up, which is the machine's
	// load. What the lane promises a stranger is that a request which queues gets a grant (the floor of
	// plainEvery) within a few hashes, and that a 503 is an answer to retry (Retry-After), not a verdict.
	// So each stranger is allowed tries, and one that is never served in all of them is starved. This is not
	// what kills the mutant of this finding either (mutants.yaml: its killers hold the account slot and need
	// no timing); it is the end-to-end check that the flood does not lock a stranger out.
	const strangers, tries = 6, 8
	var served, servedUnderFlood int
	var refusals []string
	for i := 0; i < strangers; i++ {
		floodLive := live.Load() > 0
		done := false
		for try := 0; try < tries && !done; try++ {
			// A new browser: no marker, no session. A stranger to the gate.
			r := f.client().loginPassword(B.Phone, pwB, false)
			if r.Code == http.StatusOK {
				done = true
				continue
			}
			refusals = append(refusals, fmt.Sprintf("%d %s", r.Code, r.Body))
			time.Sleep(100 * time.Millisecond)
		}
		if done {
			served++
			if floodLive {
				servedUnderFlood++
			}
		}
	}
	if served != strangers {
		t.Errorf("a login of another phone, with one account flooding reauths: %d of %d served in %d tries each, the refusals were %v", served, strangers, tries, refusals)
	}
	if servedUnderFlood == 0 {
		t.Errorf("the flood was over before the first stranger was tried, so the test proved nothing")
	}
	wg.Wait()
	if hashed.Load() == 0 || turnedAway.Load() == 0 {
		t.Fatalf("the flood hashed %d times and was turned away %d times; it must have done both or the test proves nothing", hashed.Load(), turnedAway.Load())
	}
	t.Logf("flood: %d reauths hashed, %d turned away; %d strangers served, %d of them tried while the flood ran", hashed.Load(), turnedAway.Load(), served, servedUnderFlood)
}

// TestReauthTreatsAStoredHashItCannotReadAsAWrongPassword is primitives-r7-2. Hasher.Verify answers
// ErrMalformed for a stored hash that cannot be read, a hash whose memory is above the gate's
// ceiling included (spec 4.1: the owner resets the password). Login mapped that to a wrong password
// and reauth returned the raw error, so the owner of such an account, signed in some other way,
// got a 500 from POST /auth/reauth and spent a try each time. Both go through verifyStored now.
// The hash is damaged and then oversized (a 4 GiB memory cost, far above any budget).
func TestReauthTreatsAStoredHashItCannotReadAsAWrongPassword(t *testing.T) {
	for name, stored := range map[string]string{
		"damaged":   "not-a-hash",
		"oversized": "$argon2id$v=19$m=4194304,t=2,p=1$c2FsdHNhbHRzYWx0c2FsdA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	} {
		t.Run(name, func(t *testing.T) {
			f := newFrig(t, frigOpts{})
			f.clearThrottle()
			A := f.env.A
			owner := f.makeSession(A.Tenant, A.User)
			f.env.Exec(t, `UPDATE ctrlz.users SET password_hash = $3 WHERE tenant_id = $1 AND id = $2`, A.Tenant, A.User, stored)
			owner.reauthPassword(pwA).want(401, "invalid_credentials")
			// The primitive counts it (round 8, primitives-r8-5: the log line is the hook internal/app sets).
			if f.hasher.Unreadable() == 0 {
				t.Error("the hasher did not count the stored hash as unreadable")
			}
			// A second try is the same answer, never a 500, and a user of another tenant is untouched.
			owner.reauthPassword(pwA).want(401, "invalid_credentials")
			B := f.env.B
			f.makeSession(B.Tenant, B.User).reauthPassword(pwB).want(204, "")
		})
	}
}

// TestAPasswordWithACompatibilityCharacterIsScoredOnWhatWasTyped is primitives-r7-5 through the
// real route. 'qwerty123' plus U+FDFB, and 'Password1' plus U+FDFA, were accepted with score 4 when
// the scorer saw only the NFKC form that Prepare returned; typed, they are the top passwords with
// one character more.
func TestAPasswordWithACompatibilityCharacterIsScoredOnWhatWasTyped(t *testing.T) {
	f := newFrig(t, frigOpts{})
	f.clearThrottle()
	A := f.env.A
	owner := f.makeSession(A.Tenant, A.User)
	for _, pw := range []string{"qwerty123ﷻ", "Password1ﷺ"} {
		owner.reauthPassword(pwA).want(204, "")
		owner.post("/account/password", map[string]any{"new_password": pw}).want(422, "password_weak")
	}
}

// TestTheSessionResolverNamesTheAccountToTheGate is the deterministic half of tenant-r7-6. The flood
// test above proves the effect under load, and a loaded machine can hide it: when every hash is slow the
// strangers lose with or without the per-account bound, so a mutant that dropped the bound survived one
// full CI run. This one needs no timing. The account's one lane slot is held by the test itself, under
// the subject the resolver is meant to name (the user id), and a reauth of that account through the real
// route must be turned away at once with a slot to spare, while another account is served. Without the
// subject the route's hash is just a proved hash, takes the free slot and answers 204.
func TestTheSessionResolverNamesTheAccountToTheGate(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A, B := f.env.A, f.env.B
	gate := password.NewGate(2, 5*time.Second)
	hasher, err := password.NewHasher(password.Params{MemoryKiB: 8 * 1024, Time: 1, Threads: 1}, gate)
	if err != nil {
		t.Fatal(err)
	}
	f.hasher, f.deps.Hasher = hasher, hasher
	f.setLimiter(f.deps.Limiter)
	f.setPassword(A.Tenant, A.User, pwA)
	f.setPassword(B.Tenant, B.User, pwB)
	f.clearThrottle()

	owner := f.makeSession(A.Tenant, A.User)
	other := f.makeSession(B.Tenant, B.User)

	release, err := gate.Acquire(password.ProvedAs(context.Background(), A.User.String()))
	if err != nil {
		t.Fatal(err)
	}
	owner.reauthPassword(pwA).want(503, "")
	other.reauthPassword(pwB).want(204, "")
	release()
	owner.reauthPassword(pwA).want(204, "")
}
