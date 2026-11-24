package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/apispec"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/session"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/ticket"
)

// Tests of P1 auth review round 20, tenant-r20-1: a challenge_id this service issued, typed after its five minutes, is
// answered otp_expired (the client tells the user to ask for a new code), and not otp_invalid as a made-up id is. The
// answer needs no database call, and the request is still charged to the network, since a lapsed id proves nothing.

func TestAChallengePastItsLifeAnswersOtpExpiredOnEveryRouteThatTakesOne(t *testing.T) {
	f := newFrig(t, frigOpts{mode: "open"})
	A := f.env.A

	issue := func(c *client, phone, purpose string) string {
		t.Helper()
		var iss issued
		c.requestOTP(phone, purpose, nil).want(202, "").json(&iss)
		return iss.ID
	}
	c := f.client()
	login := issue(c, A.Phone, "login")
	loginCode := f.codes.Last()
	reset := issue(c, A.Phone, "reset")
	resetCode := f.codes.Last()
	const newPhone = "09125550002"
	signup := issue(c, newPhone, "signup")
	signupCode := f.codes.Last()

	f.ck.add(5*time.Minute + time.Second)
	f.clearThrottle()

	c.post("/auth/login/otp", map[string]any{"phone": A.Phone, "challenge_id": login, "code": loginCode}).want(401, "otp_expired")
	c.post("/auth/password/reset/verify", map[string]any{"phone": A.Phone, "challenge_id": reset, "code": resetCode}).want(401, "otp_expired")
	c.post("/auth/register", map[string]any{"phone": newPhone, "challenge_id": signup, "code": signupCode, "password": "Marble-Island-Copper-6620"}).want(401, "otp_expired")

	// A made-up id and a genuine id with one byte changed are still no challenge the service knows.
	raw, _ := base64.RawURLEncoding.DecodeString(login)
	raw[len(raw)-1] ^= 1
	forged := base64.RawURLEncoding.EncodeToString(raw)
	c.post("/auth/login/otp", map[string]any{"phone": A.Phone, "challenge_id": forged, "code": loginCode}).want(401, "otp_invalid")
	c.post("/auth/login/otp", map[string]any{"phone": A.Phone, "challenge_id": junkValue(t), "code": loginCode}).want(401, "otp_invalid")

	// The lapsed id is no proof: its attempts are charged to the network scope, as a made-up id's are, never to the id.
	n := f.client()
	n.ip = "203.0.113.77"
	for i := 0; i < 40; i++ {
		if r := n.post("/auth/login/otp", map[string]any{"phone": A.Phone, "challenge_id": login, "code": loginCode}); r.Code == 429 {
			r.want(429, "rate_limited")
			return
		}
	}
	t.Fatal("forty requests with a lapsed challenge id from one network were never refused: they are not charged to the network")
}

// tenant-r20-2 and tenant-r20-4: the challenge_id carries nothing of the phone. Round 19 put a keyed hash of the phone in
// the clear, the same bytes for every challenge of one number, so comparing the tokens of two requests told whether two
// numbers were equal (an invitee's masked number has about a thousand candidates) and made every challenge of a number
// share one proof-network bucket. The subject is the challenge's own row id now.
func TestTwoChallengesOfOnePhoneShareNoBytesAndAKnownAndAnUnknownPhoneLookAlike(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A := f.env.A
	c := f.client()

	head := func(phone string) (subject, ref []byte) {
		t.Helper()
		var iss issued
		c.requestOTP(phone, "login", nil).want(202, "").json(&iss)
		raw, err := base64.RawURLEncoding.DecodeString(iss.ID)
		if err != nil || len(raw) != 48 {
			t.Fatalf("challenge_id does not decode to 48 bytes: %v", err)
		}
		return raw[:16], raw[16:32]
	}
	s1, r1 := head(A.Phone)
	f.clearThrottle()
	s2, r2 := head(A.Phone)
	f.clearThrottle()
	s3, _ := head("09127776655") // a phone with no account: a decoy
	if bytes.Equal(s1, s2) || bytes.Equal(s1, s3) || bytes.Equal(s2, s3) {
		t.Fatal("two challenges share their subject bytes: the token links them to one phone")
	}
	if !bytes.Equal(s1, r1) || !bytes.Equal(s2, r2) {
		t.Fatal("the subject of a challenge is not its own id")
	}
}

// tenant-r20-3: every operation the document lists as carrying a bearer value reaches a proof in Server.tokenProof when it is
// sent a genuine one. TestEveryAuthClassOperationHasItsProofDecided holds the lists to the document, and this holds the
// switch to the lists: deleting a case sends its route back to the shared /24 and this fails.
func TestEveryOperationListedAsCarryingAValueIsProvedByTokenProof(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A := f.env.A
	f.enableTOTP(A.Tenant, A.User)
	c := f.client()

	ticketValue := c.mfaLogin(A.Phone, pwA)
	var iss issued
	c.requestOTP(A.Phone, "login", nil).want(202, "").json(&iss)
	// A user with no second factor holds a refresh cookie after a password login with remember_me.
	B := f.env.B
	cookie := f.client().loginPassword(B.Phone, pwB, true).want(200, "").cookie(session.CookieRefresh)
	if cookie == nil {
		t.Fatal("no refresh cookie to prove")
	}

	post := func(body map[string]any) *http.Request {
		raw, _ := json.Marshal(body)
		return httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(raw))
	}
	cases := map[string]*http.Request{
		"loginTotp":         post(map[string]any{"ticket": ticketValue}),
		"resetPasskeyBegin": post(map[string]any{"ticket": ticketValue}),
		"resetComplete":     post(map[string]any{"ticket": ticketValue}),
		"loginOtp":          post(map[string]any{"challenge_id": iss.ID}),
		"resetVerify":       post(map[string]any{"challenge_id": iss.ID}),
		"register":          post(map[string]any{"challenge_id": iss.ID}),
	}
	hdr := httptest.NewRequest(http.MethodPost, "/", nil)
	hdr.Header.Set(ticket.Header, ticketValue)
	cases["resetPasskeyFinish"] = hdr
	ref := httptest.NewRequest(http.MethodPost, "/", nil)
	ref.AddCookie(cookie)
	cases["refreshSession"] = ref

	for id, req := range cases {
		proofID, subject, ok := f.srv.tokenProof(req, apispec.Operation{ID: id})
		if !ok || proofID == "" || subject == "" {
			t.Errorf("%s: a genuine value is not proved by tokenProof (ok %v)", id, ok)
		}
	}
	// The control: a made-up value proves nothing on any of them.
	for id, req := range map[string]*http.Request{
		"loginTotp": post(map[string]any{"ticket": junkValue(t)}), "loginOtp": post(map[string]any{"challenge_id": junkValue(t)}),
	} {
		if _, _, ok := f.srv.tokenProof(req, apispec.Operation{ID: id}); ok {
			t.Errorf("%s: a made-up value is proved", id)
		}
	}
}
