package api

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"testing"
	"time"

	apidoc "github.com/Kup1ng/CtrlZ-Panel/api"
	"github.com/Kup1ng/CtrlZ-Panel/internal/apispec"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/session"
	"github.com/Kup1ng/CtrlZ-Panel/internal/ratelimit"
)

// Tests of P1 auth review round 19, tenant-r19-1 (D64 nat-proof-tag): a request that holds a ticket, an OTP challenge or a
// refresh token is charged to the account (or the challenge) its tag names, not to the client's /24, so one noisy neighbour
// on a carrier block cannot refuse the honest users who share it. Two tenants share the block in every test.

// junkValue is 64 base64url characters that pass the schema and carry no tag: what a stranger sends.
func junkValue(t *testing.T) string {
	t.Helper()
	var b [48]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:])
}

func TestTicketHoldersOnASharedNetworkAreNotRefusedWithTheNeighbour(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A, B := f.env.A, f.env.B
	f.enableTOTP(A.Tenant, A.User)
	f.enableTOTP(B.Tenant, B.User)
	const shared = "203.0.113.9"

	a, b := f.client(), f.client()
	a.ip, b.ip = shared, shared
	ticketA, ticketB := a.mfaLogin(A.Phone, pwA), b.mfaLogin(B.Phone, pwB)

	// One host on the block sends junk until the class refuses it: the plain network bucket is spent.
	n := f.client()
	n.ip = shared
	refused := false
	for i := 0; i < 40; i++ {
		r := n.post("/auth/login/totp", map[string]any{"ticket": junkValue(t), "totp_code": "000000"})
		if r.Code == http.StatusTooManyRequests {
			r.want(429, "rate_limited")
			refused = true
			break
		}
		r.want(401, "ticket_invalid")
	}
	if !refused {
		t.Fatal("the control did not hold: junk from the shared /24 was never refused by the class")
	}
	// Every route of the class shares that bucket, so a junk reset ticket is refused as well.
	n.post("/auth/password/reset/complete", map[string]any{"ticket": junkValue(t), "new_password": "Cobalt-meadow-Falcon-4417"}).want(429, "rate_limited")

	// The honest users of both tenants, on that very block, are answered by their own accounts' budgets.
	a.post("/auth/login/totp", map[string]any{"ticket": ticketA, "totp_code": "000000"}).want(401, "totp_invalid")
	b.post("/auth/login/totp", map[string]any{"ticket": ticketB, "totp_code": "000000"}).want(401, "totp_invalid")

	// A's own account bucket is its own: spending it (the ticket is read five times and then answers ticket_invalid) ends in A's
	// 429 and leaves B's account untouched, in the same minute and on the same network.
	got429 := false
	for i := 0; i < 30; i++ {
		r := a.post("/auth/login/totp", map[string]any{"ticket": ticketA, "totp_code": "000000"})
		if r.Code == http.StatusTooManyRequests && r.code() == "rate_limited" {
			got429 = true
			break
		}
	}
	if !got429 {
		t.Fatal("an account that sent thirty requests with its ticket was never refused: the ticket's bucket does not count")
	}
	b.post("/auth/login/totp", map[string]any{"ticket": ticketB, "totp_code": "000000"}).want(401, "totp_invalid")
}

func TestAChallengeHolderOnASharedNetworkIsNotRefusedWithTheNeighbour(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A, B := f.env.A, f.env.B
	const shared = "203.0.113.9"

	f.clearOTP()
	request := func(phone string) (*client, string) {
		c := f.client()
		c.ip = shared
		var iss struct {
			ID string `json:"challenge_id"`
		}
		c.post("/auth/otp/request", map[string]any{"phone": phone, "purpose": "login"}).want(202, "").json(&iss)
		if len(iss.ID) != 64 {
			t.Fatalf("challenge_id is %d characters, want the 64 of a tagged value", len(iss.ID))
		}
		return c, iss.ID
	}
	ca, idA := request(A.Phone)
	codeA := f.codes.Last()
	cb, idB := request(B.Phone)
	codeB := f.codes.Last()

	// Thirty-five wrong codes with made-up challenges: the network scope and the class are both spent for strangers.
	n := f.client()
	n.ip = shared
	for i := 0; i < 35; i++ {
		n.post("/auth/login/otp", map[string]any{"phone": A.Phone, "challenge_id": junkValue(t), "code": "000000"})
	}
	n.post("/auth/login/otp", map[string]any{"phone": A.Phone, "challenge_id": junkValue(t), "code": "000000"}).want(429, "")

	ca.post("/auth/login/otp", map[string]any{"phone": A.Phone, "challenge_id": idA, "code": codeA}).want(200, "")
	cb.post("/auth/login/otp", map[string]any{"phone": B.Phone, "challenge_id": idB, "code": codeB}).want(200, "")

	// A challenge nobody issued is answered like one the database does not know, with no database call.
	f.clearThrottle()
	f.client().post("/auth/login/otp", map[string]any{"phone": A.Phone, "challenge_id": junkValue(t), "code": "000000"}).want(401, "otp_invalid")
}

func TestAChallengeOfAnotherPhoneIsNoProofForThisOne(t *testing.T) {
	// The tag names a phone's hash and the row decides: B's challenge sent with A's phone is a free otp_invalid, and A's
	// own challenge stays usable (the invalid try is B's challenge's, not A's).
	f := newFrig(t, frigOpts{})
	A, B := f.env.A, f.env.B
	c := f.client()
	f.clearOTP()
	var iss struct {
		ID string `json:"challenge_id"`
	}
	c.post("/auth/otp/request", map[string]any{"phone": A.Phone, "purpose": "login"}).want(202, "").json(&iss)
	codeA := f.codes.Last()
	c.post("/auth/login/otp", map[string]any{"phone": B.Phone, "challenge_id": iss.ID, "code": codeA}).want(401, "otp_invalid")
	c.post("/auth/login/otp", map[string]any{"phone": A.Phone, "challenge_id": iss.ID, "code": codeA}).want(200, "")
}

func TestRefreshTokenHoldersOnASharedNetworkAreNotRefusedWithTheNeighbour(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A, B := f.env.A, f.env.B
	const shared = "203.0.113.9"
	a, b := f.client(), f.client()
	a.ip, b.ip = shared, shared
	for _, u := range []struct {
		c     *client
		phone string
		pw    string
	}{{a, A.Phone, pwA}, {b, B.Phone, pwB}} {
		r := u.c.loginPassword(u.phone, u.pw, true).want(200, "")
		if r.cookie(session.CookieRefresh) == nil {
			t.Fatal("no refresh cookie")
		}
		if v := r.cookie(session.CookieRefresh).Value; len(v) != 64 {
			t.Fatalf("the refresh cookie is %d characters, want the 64 of a tagged value", len(v))
		}
		u.c.forget(session.CookieDevice)
	}
	n := f.client()
	n.ip = shared
	n.jar[session.CookieRefresh] = &http.Cookie{Name: session.CookieRefresh, Value: junkValue(t)}
	refused := false
	for i := 0; i < 40; i++ {
		r := n.post("/auth/refresh", nil)
		if r.Code == http.StatusTooManyRequests {
			refused = true
			break
		}
		r.want(401, "session_expired")
		n.jar[session.CookieRefresh] = &http.Cookie{Name: session.CookieRefresh, Value: junkValue(t)}
	}
	if !refused {
		t.Fatal("the control did not hold: junk refresh cookies from the shared /24 were never refused")
	}
	// The honest browsers drop their session cookie (a browser restart) and renew from the refresh cookie alone.
	f.ck.add(time.Second)
	a.forget(session.CookieSession)
	b.forget(session.CookieSession)
	a.post("/auth/refresh", nil).want(204, "")
	b.post("/auth/refresh", nil).want(204, "")
}

// TestEveryAuthClassOperationHasItsProofDecided: an operation of the network-keyed `auth` class either carries a bearer value
// that Server.tokenProof opens, or is listed here with the reason it carries none. A new public route is therefore a decision
// somebody wrote, and cannot go live charged to the network by omission.
func TestEveryAuthClassOperationHasItsProofDecided(t *testing.T) {
	carries := map[string]string{
		"loginTotp":          "ticket in the body",
		"resetPasskeyBegin":  "ticket in the body",
		"resetComplete":      "ticket in the body",
		"resetPasskeyFinish": "ticket in the X-Ctrlz-Ticket header",
		"loginOtp":           "challenge_id in the body",
		"resetVerify":        "challenge_id in the body",
		"register":           "invite_token (a signed link) or challenge_id in the body",
		"lookupInvite":       "token in the body, a signed link (D67)",
		"refreshSession":     "refresh cookie",
	}
	carriesNone := map[string]string{
		"loginPassword":      "a phone and a password: nothing the server issued",
		"passkeyLoginBegin":  "no subject before the assertion",
		"passkeyLoginFinish": "the sealed ceremony ticket names no account before the assertion verifies",
		"getAuthConfig":      "public-read class",
		"getPublicFreeDns":   "public-free-dns class",
		"requestOtp":         "otp-send class",
		"reauthOtpRequest":   "session class",
	}
	ops, err := apispec.Parse(apidoc.Tenant(), ratelimit.Tenant)
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range ops {
		if op.Rate != "auth" {
			continue
		}
		_, a := carries[op.ID]
		_, b := carriesNone[op.ID]
		if a == b {
			t.Errorf("auth-class operation %s must be in exactly one of the two lists (carries a bearer value, or carries none) of this test", op.ID)
		}
	}
	for id := range carries {
		found := false
		for _, op := range ops {
			found = found || (op.ID == id && op.Rate == "auth")
		}
		if !found {
			t.Errorf("%s is listed as carrying a bearer value and is not an auth-class operation", id)
		}
	}
}

// Tests of tenant-r19-6: a bearer value is charged to ITSELF, not to the account it names. A stranger who holds one
// value of an account (a password-only login holds a ticket; a signed-in browser of the same account holds a refresh
// cookie) must not be able to spend what another value of the owner needs, from any network.

func TestAHolderOfOneTicketCannotRefuseTheOwnersOtherTickets(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A := f.env.A
	f.enableTOTP(A.Tenant, A.User)
	codes := f.recoveryCodesFor(A.Tenant, A.User)

	stranger := f.client()
	stranger.ip = "198.51.100.7"
	held := stranger.mfaLogin(A.Phone, pwA)
	// The ticket is good for five minutes at the pipeline whatever the database says of it, so he can send it for as long
	// as he likes. A body with no code costs the throttle nothing and reaches the class all the same.
	refused := 0
	for i := 0; i < 40; i++ {
		if stranger.post("/auth/login/totp", map[string]any{"ticket": held}).Code == http.StatusTooManyRequests {
			refused++
		}
	}
	if refused == 0 {
		t.Fatal("the control did not hold: forty requests with one ticket were never refused, so its own bucket is not what the test fills")
	}

	// The owner, on another network, signs in with the password and spends a recovery code: his ticket is another value.
	owner := f.client()
	owner.ip = "192.0.2.55"
	tk := owner.mfaLogin(A.Phone, pwA)
	if r := owner.post("/auth/login/totp", map[string]any{"ticket": tk, "recovery_code": codes[0]}); r.Code != http.StatusOK {
		t.Fatalf("the owner's recovery code got %d %s while a stranger sent his own ticket: one stranger's value spent the owner's bucket", r.Code, r.Body)
	}
}

func TestAHolderOfOneSessionCannotRefuseTheOwnersRefreshCookie(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A := f.env.A

	stranger := f.client()
	stranger.ip = "198.51.100.7"
	stranger.loginPassword(A.Phone, pwA, true).want(200, "")
	stranger.forget(session.CookieDevice)
	// Each renewal rotates his own cookie. The ceiling is the account's on his network, which holds a hundred a minute, so
	// thirty renewals are all served and none of them touches a bucket the owner's cookie is charged to.
	for i := 0; i < 30; i++ {
		stranger.forget(session.CookieSession)
		stranger.post("/auth/refresh", nil).want(204, "")
		f.ck.add(time.Millisecond)
	}

	owner := f.client()
	owner.ip = "192.0.2.55"
	owner.loginPassword(A.Phone, pwA, true).want(200, "")
	owner.forget(session.CookieDevice)
	owner.forget(session.CookieSession)
	owner.post("/auth/refresh", nil).want(204, "")

	// And one cookie sent again and again spends its own bucket and no other: the replay of a dead cookie is refused by the
	// class once it is full, and the owner's cookie is served in the same minute.
	dead := stranger.jar[session.CookieRefresh]
	for i := 0; i < 40; i++ {
		stranger.jar[session.CookieRefresh] = dead
		stranger.forget(session.CookieSession)
		stranger.post("/auth/refresh", nil)
	}
	owner.forget(session.CookieSession)
	owner.post("/auth/refresh", nil).want(204, "")
}
