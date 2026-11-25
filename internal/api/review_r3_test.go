package api

import (
	"crypto/rand"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/passkey/passkeytest"
)

// Tests of the P1 auth review, round 3, area "HTTP spine and tenant API".

// TestJunkInviteTokensDoNotBlockALiveInvite is tenant-r3-1: anyone on a network can send bad tokens, and a live
// invite must keep working beside them at the OTP request and at the register, which is the only signup route in
// the closed mode. Since D67 a bad token is a forged link: it is refused in process, writes no throttle row and
// spends no scope of the invite, so what it can fill is the plain bucket of its network, which a link that opens
// stands outside of (InviteProofHolds).
func TestJunkInviteTokensDoNotBlockALiveInvite(t *testing.T) {
	f := newFrig(t, frigOpts{})
	c := f.client()
	phone := "+989125553001"
	code := f.plantInvite(phone, time.Hour, false)
	bad := f.forgedInvite()
	f.clearThrottle() // what the set-up of the rig wrote is not what the junk tokens do

	// 15 junk code requests and 15 junk registers from the invitee's own network.
	refused := 0
	junk := func(r *resp) {
		if r.Code == 429 {
			refused++
		} else {
			r.want(404, "invite_invalid")
		}
	}
	for i := 0; i < 15; i++ {
		junk(c.requestOTP(phone, "invite", map[string]any{"invite_token": bad}))
		junk(c.post("/auth/register", map[string]any{"invite_token": bad, "challenge_id": junkValue(t), "code": "000000"}))
		f.ck.add(30 * time.Second)
	}
	if n := f.count(`SELECT count(*) FROM ctrlz.auth_throttle`); n != 0 {
		t.Fatalf("%d junk tokens wrote %d throttle rows, want none (%d were refused by a class)", 30, n, refused)
	}

	// The live invitation still goes all the way through from the same network.
	var iss issued
	c.requestOTP(phone, "invite", map[string]any{"invite_token": code}).want(202, "").json(&iss)
	c.post("/auth/register", map[string]any{
		"invite_token": code, "challenge_id": iss.ID, "code": "000000", "password": "Marble-Island-Copper-6620",
	}).want(401, "otp_invalid") // a typo is not a throttle answer either
	c.post("/auth/register", map[string]any{
		"invite_token": code, "challenge_id": iss.ID, "code": f.codes.Last(), "password": "Marble-Island-Copper-6620",
	}).want(201, "")
	// Bad links did not spend anything of the invitee: his invite has its own count, and only one.
	if n := f.count(`SELECT count(*) FROM ctrlz.auth_throttle WHERE scope = 'invite_net'`); n != 1 {
		t.Fatalf("%d invite throttle rows, want the one of the live invite", n)
	}
}

// TestMalformedPhonesDoNotSpendAGlobalBucket is tenant-r3-8: every malformed
// phone shared one login_phone key (20 an hour for the whole world), so junk
// from many networks turned another client's typo into a 429. A typo stays a
// 401 invalid_credentials (4.5 step 1), and one source is still bounded.
func TestMalformedPhonesDoNotSpendAGlobalBucket(t *testing.T) {
	f := newFrig(t, frigOpts{})
	// 25 junk logins, each from a network of its own: more than the old shared
	// limit of 20, and no single network near its own limit.
	for i := 0; i < 25; i++ {
		c := f.client()
		c.ip = f.freshIP()
		c.loginPassword("not-a-phone", "whatever-password", false).want(401, "invalid_credentials")
	}
	c := f.client()
	c.ip = f.freshIP()
	c.loginPassword("0912-12", "whatever-password", false).want(401, "invalid_credentials")

	// One source is still bounded: login_net allows 50 in 15 minutes.
	flood := f.client()
	flood.ip = f.freshIP()
	limited := false
	for i := 0; i < 60 && !limited; i++ {
		r := flood.loginPassword("not-a-phone", "whatever-password", false)
		if r.Code == 429 {
			limited = true
		} else {
			r.want(401, "invalid_credentials")
		}
	}
	if !limited {
		t.Error("one network was never limited for malformed phones")
	}
}

// longIDKey returns a virtual authenticator with a credential id of n bytes.
func longIDKey(n int) *passkeytest.Authenticator {
	a := passkeytest.New(pkOrigin, pkRP)
	a.CredID = make([]byte, n)
	_, _ = rand.Read(a.CredID)
	return a
}

// fillPasskeys adds n passkeys with credential ids of idLen bytes, keeping the
// reauth window and the sensitive rate class out of the way. It returns the
// authenticators.
func fillPasskeys(t *testing.T, f *frig, c *client, n, idLen int) []*passkeytest.Authenticator {
	t.Helper()
	var out []*passkeytest.Authenticator
	for i := 0; i < n; i++ {
		if i%3 == 0 {
			f.ck.add(time.Minute)
			c.reauthPassword(pwA).want(204, "")
		}
		a := longIDKey(idLen)
		c.addPasskey(a).want(201, "")
		out = append(out, a)
	}
	return out
}

// TestPasskeyCapAndLongCredentialIDs is tenant-r3-3 and tenant-r3-7. A user at
// the cap of 20 passkeys, each with the longest credential id WebAuthn allows
// (1023 bytes), still gets passkey reauth: the ticket carries no id list, so its
// size no longer depends on the credentials. The 21st is a 422 at begin, and a
// begin that was started below the cap cannot finish above it.
func TestPasskeyCapAndLongCredentialIDs(t *testing.T) {
	f := newFrig(t, frigOpts{passkey: true})
	c := f.client()
	c.mustLogin(f.env.A.Phone, pwA)
	keys := fillPasskeys(t, f, c, maxPasskeys-len(c.passkeys()), 1023)

	// The 21st: refused at begin, and nothing was stored for it.
	f.ck.add(time.Minute)
	c.reauthPassword(pwA).want(204, "")
	c.post("/account/passkeys/begin", nil).want(422, "validation_failed")
	if n := len(c.passkeys()); n != maxPasskeys {
		t.Fatalf("%d passkeys stored, want %d", n, maxPasskeys)
	}

	// Passkey reauth with 20 long ids in the allow list works end to end, and
	// only the user's own credentials do.
	f.ck.add(time.Minute)
	c.reauthPasskey(keys[7]).want(204, "")
	stranger := longIDKey(1023)
	var cer ceremonyBody
	f.ck.add(time.Minute)
	c.post("/auth/reauth/passkey/begin", nil).want(200, "").json(&cer)
	body, _ := stranger.Get(cer.Options)
	c.postT("/auth/reauth/passkey/finish", cer.Ticket, body).want(401, "passkey_invalid")
}

// TestPasskeyFinishRechecksTheCap covers the second half of tenant-r3-3: two
// begins started at 19 passkeys can both reach finish, and only one may add.
func TestPasskeyFinishRechecksTheCap(t *testing.T) {
	f := newFrig(t, frigOpts{passkey: true})
	c := f.client()
	c.mustLogin(f.env.A.Phone, pwA)
	fillPasskeys(t, f, c, maxPasskeys-1-len(c.passkeys()), 32)

	f.ck.add(time.Minute)
	c.reauthPassword(pwA).want(204, "")
	var c1, c2 ceremonyBody
	c.post("/account/passkeys/begin", nil).want(200, "").json(&c1)
	c.post("/account/passkeys/begin", nil).want(200, "").json(&c2)
	a1, a2 := longIDKey(32), longIDKey(32)
	b1, err := a1.Create(c1.Options)
	if err != nil {
		t.Fatal(err)
	}
	b2, err := a2.Create(c2.Options)
	if err != nil {
		t.Fatal(err)
	}
	c.postT("/account/passkeys/finish", c1.Ticket, b1).want(201, "")
	c.postT("/account/passkeys/finish", c2.Ticket, b2).want(422, "validation_failed")
	if n := len(c.passkeys()); n != maxPasskeys {
		t.Fatalf("%d passkeys stored, want %d", n, maxPasskeys)
	}
}

// TestPasskeyTransportsAreFiltered is tenant-r3-6, redone for rule boundary-input:
// the transports list is reported by the browser outside the signed attestation. A
// NUL byte used to be a 500, and any number of invented strings was stored. Now the
// schema of the finish route refuses a NUL, an upper-case or empty word and a list of
// more than 16 with a 400 before the library parses anything, and what the schema
// cannot judge, which words are real, is still filtered: only the defined ones are
// stored, once each, with the old "cable" read as "hybrid".
func TestPasskeyTransportsAreFiltered(t *testing.T) {
	f := newFrig(t, frigOpts{passkey: true})
	c := f.client()
	c.mustLogin(f.env.A.Phone, pwA)
	c.reauthPassword(pwA).want(204, "")

	stored := f.count(`SELECT count(*) FROM ctrlz.webauthn_credentials`) // the seeded rows
	many := make([]string, 0, 3000)
	for i := 0; i < 3000; i++ {
		many = append(many, fmt.Sprintf("invented-%d", i))
	}
	for name, bad := range map[string][]string{
		"a NUL":              {"usb\u0000x"},
		"an upper-case word": {"INTERNAL"},
		"an empty word":      {""},
		"thousands":          many,
	} {
		a := longIDKey(32)
		a.Transports = bad
		c.addPasskey(a).want(400, "bad_request")
		if f.count(`SELECT count(*) FROM ctrlz.webauthn_credentials`) != stored {
			t.Fatalf("%s: a credential was stored", name)
		}
	}
	if strings.Contains(f.logs.String(), "request failed") {
		t.Errorf("a transport value reached the database and was logged as a failure:\n%s", f.logs)
	}

	a := longIDKey(32)
	a.Transports = []string{"usb", "cable", "usb", "bogus", "hybrid", "internal"}
	c.addPasskey(a).want(201, "")
	if f.count(`SELECT count(*) FROM ctrlz.webauthn_credentials WHERE transports = ARRAY['usb','hybrid','internal']`) != 1 {
		t.Fatal("transports were not reduced to the defined values, once each")
	}
	// Only invented words: still a 201 with nothing stored.
	a2 := longIDKey(32)
	a2.Transports = []string{"bogus"}
	c.addPasskey(a2).want(201, "")
	if f.count(`SELECT count(*) FROM ctrlz.webauthn_credentials WHERE cardinality(transports) = 0`) < 1 {
		t.Fatal("a credential with only invented transports should store none")
	}
}
