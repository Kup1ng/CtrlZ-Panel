package api

import (
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/pwstrength"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/session"
	"github.com/Kup1ng/CtrlZ-Panel/internal/ratelimit"
)

// Tests of the P1 auth review, round 4, area "HTTP spine and tenant API".

// twin returns a client that holds the same cookies as c, from another network,
// for a request that must run at the same time as c's.
func (c *client) twin() *client {
	n := c.f.client()
	for k, v := range c.jar {
		cp := *v
		n.jar[k] = &cp
	}
	for k, v := range c.hdr {
		n.hdr[k] = v
	}
	return n
}

// TestPasskeyFinishesRaceForTheLastSlot is tenant-r4-1. Two begins that were
// started at 19 passkeys both reach finish at the same time; the cap is a count
// of rows and nothing in the schema holds it, so only the user row lock makes
// the second finish see the first one's row. Exactly one may add. The race is
// run several times, since it is a race.
func TestPasskeyFinishesRaceForTheLastSlot(t *testing.T) {
	f := newFrig(t, frigOpts{passkey: true})
	A := f.env.A
	bBefore := f.count(`SELECT count(*) FROM ctrlz.webauthn_credentials WHERE user_id = $1`, f.env.B.User)
	first := f.client()
	first.mustLogin(A.Phone, pwA)
	fillPasskeys(t, f, first, maxPasskeys-1-len(first.passkeys()), 32)

	for round := 0; round < 6; round++ {
		// Back to 19 passkeys, whatever the last round added.
		f.env.Exec(t, `DELETE FROM ctrlz.webauthn_credentials WHERE user_id = $1 AND id IN (
			SELECT id FROM ctrlz.webauthn_credentials WHERE user_id = $1 ORDER BY created_at ASC, id ASC OFFSET $2)`, A.User, maxPasskeys-1)
		c := f.client()
		c.mustLogin(A.Phone, pwA)
		c.reauthPassword(pwA).want(204, "")
		var c1, c2 ceremonyBody
		c.post("/account/passkeys/begin", nil).want(200, "").json(&c1)
		c.post("/account/passkeys/begin", nil).want(200, "").json(&c2)
		b1, err := longIDKey(32).Create(c1.Options)
		if err != nil {
			t.Fatal(err)
		}
		b2, err := longIDKey(32).Create(c2.Options)
		if err != nil {
			t.Fatal(err)
		}
		x, y := c.twin(), c.twin()
		var created, refused atomic.Int32
		var other [2]atomic.Int32
		var wg sync.WaitGroup
		for n, job := range []struct {
			c    *client
			tick string
			body []byte
		}{{x, c1.Ticket, b1}, {y, c2.Ticket, b2}} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				code := job.c.postT("/account/passkeys/finish", job.tick, job.body).Code
				switch code {
				case 201:
					created.Add(1)
				case 422:
					refused.Add(1)
				default:
					other[n].Store(int32(code))
				}
			}()
		}
		wg.Wait()
		// The loser is a 422 when it read the count under the lock, or a 401 when the
		// winner's rotation of the shared session reached it first; both are fine.
		// What must never happen is two creations.
		if created.Load() != 1 {
			t.Fatalf("round %d: %d created and %d refused (other %d %d), want exactly one created", round, created.Load(), refused.Load(), other[0].Load(), other[1].Load())
		}
		if n := f.count(`SELECT count(*) FROM ctrlz.webauthn_credentials WHERE user_id = $1`, A.User); n != maxPasskeys {
			t.Fatalf("round %d: %d passkeys stored, want %d", round, n, maxPasskeys)
		}
		if n := f.count(`SELECT count(*) FROM (SELECT name FROM ctrlz.webauthn_credentials WHERE user_id = $1 GROUP BY name HAVING count(*) > 1) d`, A.User); n != 0 {
			t.Fatalf("round %d: two passkeys got the same default name", round)
		}
	}
	// Tenant B's passkeys were never part of it.
	if n := f.count(`SELECT count(*) FROM ctrlz.webauthn_credentials WHERE user_id = $1`, f.env.B.User); n != bBefore {
		t.Fatalf("tenant B went from %d to %d passkeys", bBefore, n)
	}
}

// TestRegisterNeverScoresOnTheSignedInGate is tenant-r4-2 and -6. Whoever calls
// POST /auth/register has a right code at best and no account, so its scoring
// runs on the gate of the other route whose caller has proved nothing, and never
// on the one that signed-in password change and the admin routes share.
//
// Round 16 (tenant-r16-4): the signed-in gate used to be kept busy by three goroutines scoring a long
// password and a 30 ms sleep, which on a fast host ended before register ran, so a register that scored on
// the wrong gate passed. The test now takes the signed-in gate's only slot itself (no patience, so a
// register on that gate answers 503 at once) and requires the registration to succeed on the other gate:
// it needs no timing, and it fails when register scores on s.strength (mutant
// proof-before-work-register-scores-on-the-signed-in-gate). The reset twin does the same below.
func TestRegisterNeverScoresOnTheSignedInGate(t *testing.T) {
	f := newFrig(t, frigOpts{})
	f.setMode("open")
	signedIn := pwstrength.NewWithLimit(1, time.Nanosecond)
	anon := pwstrength.NewWithLimit(1, 5*time.Second)
	f.deps.Strength, f.deps.StrengthUnauthenticated = signedIn, anon
	f.setLimiter(f.deps.Limiter)

	c := f.client()
	var iss issued
	c.requestOTP("09125550992", "signup", nil).want(202, "").json(&iss)
	code := f.codes.Last()

	release, err := signedIn.Gate().Acquire(f.env.Ctx)
	if err != nil {
		t.Fatal(err) // the pressure is built by construction; no slot, no test
	}
	defer release()
	c.post("/auth/register", map[string]any{"phone": "09125550992", "challenge_id": iss.ID, "code": code, "password": "Marble-Island-Copper-6620"}).want(201, "")
	if signedIn.Scorings() != 1 { // the one Acquire above; register never asked this gate
		t.Errorf("the signed-in gate was asked %d times, only the test's own hold is expected", signedIn.Scorings())
	}
	if anon.Scorings() == 0 {
		t.Error("register did not score on the gate of callers who have proved nothing")
	}
}

// TestOldDeviceMarkerCannotBeTurnedAgainstTheOwner is tenant-r4-5. Mallory once
// signed in as Alice and kept the browser's device marker. After Alice changes
// her password: Mallory's marker is no longer a known device, so it does not
// spend Alice's trusted phone key; the passkey begin bucket of a marker is its
// own, so Mallory's floods leave Alice's browser alone; and Alice's browser got a
// fresh marker with the password change. Tenant B's marker never counted for A.
func TestOldDeviceMarkerCannotBeTurnedAgainstTheOwner(t *testing.T) {
	f := newFrig(t, frigOpts{passkey: true})
	A, B := f.env.A, f.env.B
	mallory, alice, bob := f.client(), f.client(), f.client()
	mallory.mustLogin(A.Phone, pwA)
	alice.mustLogin(A.Phone, pwA)
	bob.mustLogin(B.Phone, pwB)
	old := mallory.jar[session.CookieDevice]
	if old == nil || alice.jar[session.CookieDevice] == nil || bob.jar[session.CookieDevice] == nil {
		t.Fatal("a password login should leave a device marker")
	}
	if old.Value == alice.jar[session.CookieDevice].Value {
		t.Fatal("two logins share one marker")
	}
	trusted := func() int {
		return f.count(`SELECT coalesce(sum(count), 0) FROM ctrlz.sms_counters WHERE scope = 'phone' AND key = $1`, A.Phone+"|trusted")
	}

	// Before the change the marker is a known device.
	mallory.requestOTP(A.Phone, "login", nil).want(202, "")
	if trusted() != 1 {
		t.Fatalf("a fresh marker did not count on the trusted key (%d)", trusted())
	}

	// Alice changes her password and her browser gets a marker of the new generation.
	alice.reauthPassword(pwA).want(204, "")
	before := alice.jar[session.CookieDevice].Value
	const newPw = "Cobalt-meadow-Falcon-4417"
	alice.post("/account/password", map[string]any{"new_password": newPw}).want(204, "")
	if alice.jar[session.CookieDevice] == nil || alice.jar[session.CookieDevice].Value == before {
		t.Fatal("the password change did not hand the owner a marker of the new generation")
	}

	mallory.requestOTP(A.Phone, "login", nil).want(202, "")
	if trusted() != 0 {
		t.Fatalf("a marker from before the password change spent the owner's trusted key (%d)", trusted())
	}
	alice.requestOTP(A.Phone, "login", nil).want(202, "")
	if trusted() != 1 {
		t.Fatalf("the owner's new marker did not count on the trusted key (%d)", trusted())
	}
	// B's marker on A's phone was never a known device for A.
	bob.requestOTP(A.Phone, "login", nil).want(202, "")
	if trusted() != 0 {
		t.Fatalf("tenant B's marker counted on A's trusted key (%d)", trusted())
	}

	// The marker's bucket of the auth class belongs to one marker. Mallory empties
	// hers; the owner's browser, B's, and a second marker of the same user are
	// untouched.
	authClass, _ := ratelimit.Lookup(ratelimit.Tenant, "auth")
	empty := func(c *client) int {
		n := 0
		for range authClass.Limits[0].Max + 3 {
			c.ip = f.freshIP()
			if c.post("/auth/passkey/login/begin", map[string]any{}).Code == http.StatusTooManyRequests {
				n++
			}
		}
		return n
	}
	if got := empty(mallory); got != 3 {
		t.Fatalf("Mallory's marker was refused %d times, want 3", got)
	}
	alice.ip = f.freshIP()
	alice.post("/auth/passkey/login/begin", map[string]any{}).want(200, "")
	bob.ip = f.freshIP()
	bob.post("/auth/passkey/login/begin", map[string]any{}).want(200, "")
	second := f.client()
	second.mustLogin(A.Phone, newPw)
	second.ip = f.freshIP()
	second.post("/auth/passkey/login/begin", map[string]any{}).want(200, "")
	f.setPassword(A.Tenant, A.User, pwA)
}

// TestDeviceMarkerEndsWithAReissue pins the one-time password input of the
// credential generation: the console's re-issue (10.7) moves password_expires_at,
// and a marker made before it is no longer known.
func TestDeviceMarkerEndsWithAReissue(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A := f.env.A
	c := f.client()
	c.mustLogin(A.Phone, pwA)
	marker := c.jar[session.CookieDevice].Value
	trusted := func() int {
		return f.count(`SELECT coalesce(sum(count), 0) FROM ctrlz.sms_counters WHERE scope = 'phone' AND key = $1`, A.Phone+"|trusted")
	}
	withMarker := func() *client {
		n := f.client()
		n.jar[session.CookieDevice] = &http.Cookie{Name: session.CookieDevice, Value: marker}
		return n
	}
	withMarker().requestOTP(A.Phone, "login", nil).want(202, "")
	if trusted() != 1 {
		t.Fatalf("the marker was not known to begin with (%d)", trusted())
	}
	f.env.Exec(t, `UPDATE ctrlz.users SET password_expires_at = now() + interval '72 hours', must_reset = true WHERE id = $1`, A.User)
	withMarker().requestOTP(A.Phone, "login", nil).want(202, "")
	if trusted() != 0 {
		t.Fatalf("a marker from before the re-issue is still known (%d)", trusted())
	}
	f.env.Exec(t, `UPDATE ctrlz.users SET password_expires_at = NULL, must_reset = false WHERE id = $1`, A.User)
}
