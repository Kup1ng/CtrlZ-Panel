package api

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/invite"
	"github.com/Kup1ng/CtrlZ-Panel/internal/authtest"
)

// Tests of D67 on the tenant API: an invite is a signed link that the api opens in process, before any
// throttle row and any read (spec 11.3, 14.1).

// badLinks makes the links the api must refuse in process: each is a well-shaped token of 140 characters or a
// plain junk text, and none opens. Every one is a way a stranger, or an old link, can fail the check.
func (f *frig) badLinks(t *testing.T) map[string]string {
	t.Helper()
	live, _ := f.plantInviteID("+989125557001", time.Hour, false)
	other, _ := authtest.InviteRings(t)
	// A token for a real id signed by a key the api does not hold, with the right shape.
	foreign, _, err := invite.Mint(other, uuid.New(), f.ck.now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	// A genuine signature over a token whose expiry has gone.
	lapsed, _, err := invite.Mint(f.signer, uuid.New(), f.ck.now().Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	// One character of a live token changed: the signature no longer covers it.
	changed := []byte(live)
	if changed[70] == 'A' {
		changed[70] = 'B'
	} else {
		changed[70] = 'A'
	}
	return map[string]string{
		"signed by another key": foreign.Reveal(),
		"expired token":         lapsed.Reveal(),
		"one character changed": string(changed),
		"truncated":             live[:len(live)-1],
		"too long":              live + "A",
		"not a token":           "nope",
		"the old short code":    "AAAAA-AAAAA-AAAAA-AAAAA",
	}
}

// TestABadInviteLinkCostsNoReadAndNoThrottleRow is the point of D67 for the database: a link that does not open
// is answered 404 invite_invalid with no throttle row and no database call, on the lookup, the code request and
// the register alike. The proof that nothing was read is that the tenant pool is closed while they are sent: a call
// would fail with a server error and not the 404. The control is a live link, which does fail then.
func TestABadInviteLinkCostsNoReadAndNoThrottleRow(t *testing.T) {
	f := newFrig(t, frigOpts{})
	f.setMode("invite")
	bad := f.badLinks(t)
	live := f.plantInvite("+989125557002", time.Hour, false)
	f.clearThrottle()
	f.st.Close() // from here every read of the api fails

	// A client of its own for every request, so that no class of the pipeline ever refuses and the clock of the
	// public-config cache is not moved: what the test looks at is the handler, not the budget.
	if r := f.client().post("/auth/invites/lookup", map[string]any{"token": live}); r.Code < 500 {
		t.Fatalf("the control did not hold: a live link was answered %d with the database gone", r.Code)
	}
	for name, tok := range bad {
		f.client().post("/auth/invites/lookup", map[string]any{"token": tok}).want(404, "invite_invalid")
		f.client().requestOTP("09120000001", "invite", map[string]any{"invite_token": tok}).want(404, "invite_invalid")
		f.client().post("/auth/register", map[string]any{"invite_token": tok, "challenge_id": junkValue(t), "code": "000000", "password": "Marble-Island-Copper-6620"}).want(404, "invite_invalid")
		if n := f.count(`SELECT count(*) FROM ctrlz.auth_throttle`); n != 0 {
			t.Fatalf("%s: %d throttle rows were written", name, n)
		}
	}
}

// TestEveryUseOfASignedInviteCountsOnTheInvite: a link whose signature checks names its invite, and every use of it
// counts on invite_use before the row is read, whatever the row says: live, used, revoked, expired or swept. So a
// holder of a dead link buys at most the 30 reads of the scope and spends nobody else's budget, from any network.
func TestEveryUseOfASignedInviteCountsOnTheInvite(t *testing.T) {
	f := newFrig(t, frigOpts{})
	f.setMode("invite")
	type row struct {
		name   string
		plant  func() string
		answer int
	}
	rows := []row{
		{"live", func() string { return f.plantInvite("+989125557101", time.Hour, false) }, 200},
		{"used", func() string {
			tok, id := f.plantInviteID("+989125557102", time.Hour, false)
			f.env.Exec(t, `UPDATE ctrlz.invites SET used_at = now() WHERE id = $1`, id)
			return tok
		}, 404},
		{"revoked", func() string { return f.plantInvite("+989125557103", time.Hour, true) }, 404},
		{"expired", func() string { return f.plantInvite("+989125557104", -time.Minute, false) }, 404},
		{"swept", func() string {
			tok, id := f.plantInviteID("+989125557105", time.Hour, false)
			f.env.Exec(t, `DELETE FROM ctrlz.invites WHERE id = $1`, id)
			return tok
		}, 404},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			f.clearThrottle()
			tok := r.plant()
			answered := 0
			for i := 0; i < 40; i++ {
				c := f.client()
				c.ip = f.freshIP() // a network of its own each time: the count follows the invite
				resp := c.post("/auth/invites/lookup", map[string]any{"token": tok})
				if resp.Code == http.StatusTooManyRequests {
					resp.want(429, "too_many_attempts")
					break
				}
				resp.want(r.answer, map[int]string{404: "invite_invalid"}[r.answer])
				answered++
				if i%15 == 14 {
					f.ck.add(time.Minute) // the auth class of the invite's proof comes round again
				}
			}
			if answered != 30 {
				t.Fatalf("a %s link moving networks was answered %d times, want the 30 of invite_use", r.name, answered)
			}
			if n := f.count(`SELECT count(*) FROM ctrlz.auth_throttle WHERE scope = 'invite_net'`); n != 1 {
				t.Fatalf("%d invite throttle rows, want the one of the invite", n)
			}
			// Another invite is another subject, and the spent one does not refuse it.
			other := f.plantInvite("+989125557199", time.Hour, false)
			f.client().post("/auth/invites/lookup", map[string]any{"token": other}).want(200, "")
			f.env.Exec(t, `DELETE FROM ctrlz.invites WHERE phone_e164 = '+989125557199'`)
		})
	}
}

// TestTheInviteRowIsTheFinalAuthority: a link that opens is only a claim of the admin process. Single use, revoked,
// expired (on the database clock) and an id that is not the row's are the one 404, the phone comes from the row,
// and a code of another phone's challenge is no good.
func TestTheInviteRowIsTheFinalAuthority(t *testing.T) {
	f := newFrig(t, frigOpts{})
	f.setMode("closed")
	post := func(c *client, tok string) *resp { return c.post("/auth/invites/lookup", map[string]any{"token": tok}) }

	t.Run("single use", func(t *testing.T) {
		phone := "+989125557201"
		tok := f.plantInvite(phone, time.Hour, false)
		c := f.client()
		var iss issued
		c.requestOTP("09120000001", "invite", map[string]any{"invite_token": tok}).want(202, "").json(&iss)
		c.post("/auth/register", map[string]any{"invite_token": tok, "challenge_id": iss.ID, "code": f.codes.Last(), "password": "Marble-Island-Copper-6620"}).want(201, "")
		f.clearThrottle()
		post(f.client(), tok).want(404, "invite_invalid")
		f.client().requestOTP(phone, "invite", map[string]any{"invite_token": tok}).want(404, "invite_invalid")
	})

	t.Run("revoked and expired rows with a live token", func(t *testing.T) {
		f.clearThrottle()
		post(f.client(), f.plantInvite("+989125557202", time.Hour, true)).want(404, "invite_invalid")
		post(f.client(), f.plantInvite("+989125557203", -time.Minute, false)).want(404, "invite_invalid")
		// The row is revoked after the link was shown: the same token that answered 200 answers 404.
		tok, id := f.plantInviteID("+989125557204", time.Hour, false)
		post(f.client(), tok).want(200, "")
		f.env.Exec(t, `UPDATE ctrlz.invites SET revoked_at = now() WHERE id = $1`, id)
		post(f.client(), tok).want(404, "invite_invalid")
	})

	t.Run("a hash that belongs to another id", func(t *testing.T) {
		// The signer made a token for id X. The row found by its hash carries id Y: the claim and the row disagree.
		f.clearThrottle()
		x, y := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
		tok, hash, err := invite.Mint(f.signer, x, f.ck.now().Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		f.env.Exec(t, `INSERT INTO ctrlz.invites (id, token_hash, phone_e164, expires_at) VALUES ($1, $2, '+989125557205', now() + interval '1 hour')`, y, hash)
		post(f.client(), tok.Reveal()).want(404, "invite_invalid")
		f.client().requestOTP("09120000001", "invite", map[string]any{"invite_token": tok.Reveal()}).want(404, "invite_invalid")
	})

	t.Run("the phone is the row's and a challenge of another invite is no code", func(t *testing.T) {
		f.clearThrottle()
		p1, p2 := "+989125557206", "+989125557207"
		t1, t2 := f.plantInvite(p1, time.Hour, false), f.plantInvite(p2, time.Hour, false)
		c := f.client()
		var iss issued
		// The request names another phone: the row's phone is the one the code goes to.
		c.requestOTP("09120000009", "invite", map[string]any{"invite_token": t1}).want(202, "").json(&iss)
		if f.count(`SELECT count(*) FROM ctrlz.otp_challenges WHERE phone_e164 = $1 AND purpose = 'invite'`, p1) != 1 ||
			f.count(`SELECT count(*) FROM ctrlz.otp_challenges WHERE phone_e164 = '+989120000009'`) != 0 {
			t.Fatal("the challenge was not made for the phone of the invite row")
		}
		// The code of the first invite's phone does not register the second invite.
		c.post("/auth/register", map[string]any{"invite_token": t2, "challenge_id": iss.ID, "code": f.codes.Last(), "password": "Marble-Island-Copper-6620"}).want(401, "otp_invalid")
	})
}

// TestInviteHoldersOnASharedNetworkAreNotRefusedWithTheNeighbour is the invite half of D64 nat-proof-tag
// (tenant-r19-1), which D67 makes possible: a link whose signature checks is charged to its invite and not to the
// carrier /24, so strangers who spend the auth class and the otp-send bucket of the block refuse neither invitee.
// The flood comes first; the two invitees are on the block and on another network.
func TestInviteHoldersOnASharedNetworkAreNotRefusedWithTheNeighbour(t *testing.T) {
	f := newFrig(t, frigOpts{})
	f.setMode("closed")
	const shared = "203.0.113.9"
	f.clearThrottle()
	tokA := f.plantInvite("+989125557301", time.Hour, false)
	tokB := f.plantInvite("+989125557302", time.Hour, false)

	// Strangers on the block send forged links until the auth class refuses them, and fill otp-send as well.
	n := f.client()
	n.ip = shared
	refused := false
	for i := 0; i < 40; i++ {
		r := n.post("/auth/invites/lookup", map[string]any{"token": f.forgedInvite()})
		if r.Code == http.StatusTooManyRequests {
			refused = true
			break
		}
		r.want(404, "invite_invalid")
	}
	if !refused {
		t.Fatal("the control did not hold: forged links from the shared /24 were never refused by the class")
	}
	for i := 0; i < 12; i++ {
		s := f.client()
		s.ip = fmt.Sprintf("203.0.113.%d", 20+i)
		s.post("/auth/otp/request", map[string]any{"phone": fmt.Sprintf("0912555%04d", i), "purpose": "login"})
	}
	f.clearOTP()
	f.client().post("/auth/otp/request", map[string]any{"phone": "09125559991", "purpose": "login"}).want(429, "")

	// Invitee A is on the very block that was flooded, B is elsewhere: both go all the way through.
	for name, ip := range map[string]string{"A on the block": shared, "B elsewhere": "198.18.0.77"} {
		tok, phone := tokA, "+989125557301"
		if ip != shared {
			tok, phone = tokB, "+989125557302"
		}
		t.Run(name, func(t *testing.T) {
			c := f.client()
			c.ip = ip
			c.post("/auth/invites/lookup", map[string]any{"token": tok}).want(200, "")
			var iss issued
			c.requestOTP(phone, "invite", map[string]any{"invite_token": tok}).want(202, "").json(&iss)
			c.post("/auth/register", map[string]any{"invite_token": tok, "challenge_id": iss.ID, "code": "000000", "password": "Marble-Island-Copper-6620"}).want(401, "otp_invalid")
			r := c.post("/auth/register", map[string]any{"invite_token": tok, "challenge_id": iss.ID, "code": f.codes.Last(), "password": "Marble-Island-Copper-6620"})
			if r.Code != http.StatusCreated {
				t.Fatalf("an invitee on %s was answered %d %s", name, r.Code, strings.TrimSpace(string(r.Body)))
			}
		})
	}
	// And the strangers are still refused: the link did not open the block's bucket for them.
	n.post("/auth/invites/lookup", map[string]any{"token": f.forgedInvite()}).want(429, "")
}
