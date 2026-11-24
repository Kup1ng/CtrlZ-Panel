package api

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/passkey/passkeytest"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/session"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

const (
	pkOrigin = "https://panel.localhost"
	pkRP     = "panel.localhost"
)

type ceremonyBody struct {
	Ticket  string          `json:"ticket"`
	Options json.RawMessage `json:"options"`
}

type pkRow struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Stale          bool   `json:"stale"`
	BackupEligible bool   `json:"backup_eligible"`
}

// addPasskey registers the authenticator through the two routes of 7.3. The
// session needs a live reauth window.
func (c *client) addPasskey(a *passkeytest.Authenticator) *resp {
	c.f.t.Helper()
	var cer ceremonyBody
	c.post("/account/passkeys/begin", nil).want(200, "").json(&cer)
	body, err := a.Create(cer.Options)
	if err != nil {
		c.f.t.Fatal(err)
	}
	return c.postT("/account/passkeys/finish", cer.Ticket, body)
}

// passkeyLogin runs the discoverable login of 7.5 and returns the finish response.
func (c *client) passkeyLogin(a *passkeytest.Authenticator) *resp {
	c.f.t.Helper()
	var cer ceremonyBody
	c.post("/auth/passkey/login/begin", map[string]any{}).want(200, "").json(&cer)
	body, err := a.Get(cer.Options)
	if err != nil {
		c.f.t.Fatal(err)
	}
	return c.postT("/auth/passkey/login/finish", cer.Ticket, body)
}

func (c *client) reauthPasskey(a *passkeytest.Authenticator) *resp {
	c.f.t.Helper()
	var cer ceremonyBody
	c.post("/auth/reauth/passkey/begin", nil).want(200, "").json(&cer)
	body, _ := a.Get(cer.Options)
	return c.postT("/auth/reauth/passkey/finish", cer.Ticket, body)
}

func (c *client) passkeys() []pkRow {
	c.f.t.Helper()
	var out struct {
		Passkeys []pkRow `json:"passkeys"`
	}
	c.get("/account/passkeys").want(200, "").json(&out)
	return out.Passkeys
}

// makeSession opens a session straight through the manager, for a test that needs
// one at a moment the login routes would refuse it.
func (f *frig) makeSession(tenant, user uuid.UUID) *client {
	f.t.Helper()
	c := f.client()
	err := f.st.WithTenant(f.env.Ctx, tenant, store.TxOpts{}, func(tx store.Tx) error {
		iss, err := f.m.Create(tx, session.NewSession{User: user, Method: "password", IP: netip.MustParseAddr("203.0.113.5"), UserAgent: "t"})
		c.jar[session.CookieSession] = iss.Cookies()[0]
		return err
	})
	if err != nil {
		f.t.Fatal(err)
	}
	return c
}

// TestPasskey covers section 7 (T-103, T-104, T-106) with a virtual authenticator
// at panel.localhost.
func TestPasskey(t *testing.T) {
	f := newFrig(t, frigOpts{passkey: true})
	A, B := f.env.A, f.env.B
	aKey := passkeytest.New(pkOrigin, pkRP)
	bKey := passkeytest.New(pkOrigin, pkRP)

	owner := f.client()
	owner.mustLogin(A.Phone, pwA)
	bOwner := f.client()
	bOwner.mustLogin(B.Phone, pwB)

	t.Run("add, list and rename", func(t *testing.T) {
		var cfg struct {
			PK bool `json:"passkey_enabled"`
		}
		f.client().get("/auth/config").want(200, "").json(&cfg)
		if !cfg.PK {
			t.Fatal("passkey_enabled should be true")
		}
		owner.post("/account/passkeys/begin", nil).want(403, "reauth_required")
		owner.reauthPassword(pwA).want(204, "")
		bOwner.reauthPassword(pwB).want(204, "")

		live := f.count(`SELECT count(*) FROM ctrlz.sessions WHERE user_id = $1 AND revoked_at IS NULL`, A.User)
		r := owner.addPasskey(aKey).want(201, "")
		var added struct {
			Passkey pkRow `json:"passkey"`
			Ended   int   `json:"ended_sessions"`
		}
		r.json(&added)
		if added.Passkey.Name != "Passkey 2" || added.Passkey.Stale || added.Ended != live-1 {
			t.Fatalf("added = %+v (live before: %d)", added, live)
		}
		if f.count(`SELECT count(*) FROM ctrlz.webauthn_credentials WHERE user_id = $1 AND rp_id = $2 AND attestation_type = 'none'`, A.User, pkRP) != 1 {
			t.Fatal("the new credential should be stored for the RP ID (the seed row is for another RP ID)")
		}
		// The same authenticator twice is refused by the unique credential id.
		owner.addPasskey(aKey).want(401, "passkey_invalid")

		bOwner.addPasskey(bKey).want(201, "")
		// Adding a passkey tells the owner (tenant-r18-5): one notice each, in the tenant that added it. The refused
		// second attempt of A above wrote none (it is the same transaction as the credential).
		for name, tenant := range map[string]any{"A": A.Tenant, "B": B.Tenant} {
			if n := f.count(`SELECT count(*) FROM ctrlz.notifications WHERE tenant_id = $1 AND kind = 'passkey_added'`, tenant); n != 1 {
				t.Errorf("tenant %s has %d passkey_added notices, want 1", name, n)
			}
		}
		for _, row := range bOwner.passkeys() {
			if row.ID == added.Passkey.ID {
				t.Fatal("B lists A's passkey")
			}
		}
		bOwner.do("PATCH", "/account/passkeys/"+added.Passkey.ID, map[string]any{"name": "mine"}).want(404, "not_found")
		bOwner.do("DELETE", "/account/passkeys/"+added.Passkey.ID, nil).want(404, "not_found")

		owner.do("PATCH", "/account/passkeys/"+added.Passkey.ID, map[string]any{"name": "  "}).want(400, "bad_request")                    // blank: the schema now refuses it before the handler (tenant-r18-3)
		owner.do("PATCH", "/account/passkeys/"+added.Passkey.ID, map[string]any{"name": strings.Repeat("a", 65)}).want(400, "bad_request") // the schema, before the handler (rule boundary-input)
		owner.do("PATCH", "/account/passkeys/"+added.Passkey.ID, map[string]any{"name": "Laptop"}).want(200, "")
		// primitives-r18-3: the half-space of the Persian keyboard is let through by the schema and dropped from the
		// name by the handler; a name that is only half-spaces is empty and refused.
		owner.do("PATCH", "/account/passkeys/"+added.Passkey.ID, map[string]any{"name": "لپ\u200cتاپ"}).want(200, "")
		for _, row := range owner.passkeys() {
			if row.ID == added.Passkey.ID && row.Name != "لپتاپ" {
				t.Fatalf("the stored name is %q", row.Name)
			}
		}
		owner.do("PATCH", "/account/passkeys/"+added.Passkey.ID, map[string]any{"name": "\u200c\u200c"}).want(422, "validation_failed")
		owner.do("PATCH", "/account/passkeys/"+added.Passkey.ID, map[string]any{"name": "a\u200bb"}).want(400, "bad_request") // another invisible character is still refused by the schema
		if m := owner.me(); m.Security.Passkeys != 2 {                                                                        // the seed's row counts
			t.Fatalf("me.passkeys = %d", m.Security.Passkeys)
		}
	})

	t.Run("login", func(t *testing.T) {
		// The seed's own credential is for another RP ID and never matches.
		c := f.client()
		r := c.passkeyLogin(aKey).want(200, "")
		var res loginBody
		r.json(&res)
		if res.Status != "authenticated" {
			t.Fatalf("passkey login = %+v", res)
		}
		if m := c.me(); m.User.ID != A.User {
			t.Fatal("logged in as the wrong user")
		}
		if f.count(`SELECT count(*) FROM ctrlz.sessions WHERE user_id = $1 AND auth_method = 'passkey'`, A.User) != 1 {
			t.Fatal("the session must record the passkey method")
		}
		if f.count(`SELECT count(*) FROM ctrlz.webauthn_credentials WHERE user_id = $1 AND sign_count = 1`, A.User) != 1 {
			t.Fatal("sign_count not stored")
		}
		// B's passkey signs B in, never A.
		cb := f.client()
		cb.passkeyLogin(bKey).want(200, "")
		if m := cb.me(); m.User.ID != B.User || m.Tenant.ID != B.Tenant {
			t.Fatal("B's passkey did not give B's session")
		}
	})

	t.Run("refusals", func(t *testing.T) {
		clone := func(mutate func(*passkeytest.Authenticator)) *passkeytest.Authenticator {
			x := *aKey
			mutate(&x)
			return &x
		}
		f.client().passkeyLogin(clone(func(x *passkeytest.Authenticator) { x.UV = false })).want(401, "passkey_invalid")
		f.client().passkeyLogin(clone(func(x *passkeytest.Authenticator) { x.Origin = "https://evil.example" })).want(401, "passkey_invalid")
		f.client().passkeyLogin(clone(func(x *passkeytest.Authenticator) { x.RPID = "evil.example" })).want(401, "passkey_invalid")
		f.client().passkeyLogin(passkeytest.New(pkOrigin, pkRP)).want(401, "passkey_invalid") // not registered

		// A ticket is single use, and a wrong kind is no ticket.
		c := f.client()
		var cer ceremonyBody
		c.post("/auth/passkey/login/begin", nil).want(200, "").json(&cer)
		body, _ := aKey.Get(cer.Options)
		c.postT("/auth/passkey/login/finish", cer.Ticket, body).want(200, "")
		c.postT("/auth/passkey/login/finish", cer.Ticket, body).want(401, "ticket_invalid")
		c.postT("/auth/passkey/login/finish", "junk", body).want(401, "ticket_invalid")
		var reg ceremonyBody
		owner.post("/account/passkeys/begin", nil).want(200, "").json(&reg)
		c.postT("/auth/passkey/login/finish", reg.Ticket, body).want(401, "ticket_invalid")
		// A login ticket is no registration ticket.
		c.post("/auth/passkey/login/begin", nil).want(200, "").json(&cer)
		owner.postT("/account/passkeys/finish", cer.Ticket, body).want(401, "ticket_invalid")

		// The counter rule: a stored count above zero needs a higher new one.
		f.env.Exec(t, `UPDATE ctrlz.webauthn_credentials SET sign_count = 50 WHERE user_id = $1 AND rp_id = $2`, A.User, pkRP)
		f.client().passkeyLogin(clone(func(x *passkeytest.Authenticator) { x.SignCount = 10 })).want(401, "passkey_invalid")
		if f.count(`SELECT count(*) FROM ctrlz.tenant_audit_log WHERE action = 'passkey.clone_suspect'`) != 1 {
			t.Fatal("no passkey.clone_suspect row")
		}
		// A synced passkey that always reports zero passes while the store holds zero.
		f.env.Exec(t, `UPDATE ctrlz.webauthn_credentials SET sign_count = 0 WHERE user_id = $1 AND rp_id = $2`, A.User, pkRP)
		f.client().passkeyLogin(clone(func(x *passkeytest.Authenticator) { x.SignCount, x.Frozen = 0, true })).want(200, "")

		// Stale and other-RP credentials are refused.
		f.env.Exec(t, `UPDATE ctrlz.webauthn_credentials SET stale_at = now() WHERE user_id = $1 AND rp_id = $2`, A.User, pkRP)
		f.client().passkeyLogin(aKey).want(401, "passkey_invalid")
		if rows := owner.passkeys(); !rows[len(rows)-1].Stale && !rows[0].Stale {
			t.Fatal("a stale credential is listed with stale: true")
		}
		f.env.Exec(t, `UPDATE ctrlz.webauthn_credentials SET stale_at = NULL WHERE user_id = $1`, A.User)
		f.env.Exec(t, `UPDATE ctrlz.webauthn_credentials SET rp_id = 'old.localhost' WHERE user_id = $1 AND rp_id = $2`, A.User, pkRP)
		f.client().passkeyLogin(aKey).want(401, "passkey_invalid")
		f.env.Exec(t, `UPDATE ctrlz.webauthn_credentials SET rp_id = $2 WHERE user_id = $1 AND rp_id = 'old.localhost'`, A.User, pkRP)
		f.client().passkeyLogin(aKey).want(200, "")
	})

	t.Run("reauth by passkey is for the session's own user only", func(t *testing.T) {
		c := f.client()
		c.mustLogin(A.Phone, pwA)
		c.post("/account/passkeys/review", nil).want(403, "reauth_required")
		c.reauthPasskey(aKey).want(204, "")
		c.post("/account/passkeys/review", nil).want(204, "")
		if f.count(`SELECT count(*) FROM ctrlz.tenant_audit_log WHERE action = 'reauth.ok' AND params->>'method' = 'passkey'`) != 1 {
			t.Fatal("no reauth.ok row with method passkey")
		}

		// B's passkey on A's session: 401, and A's window is unchanged.
		x := f.client()
		x.mustLogin(A.Phone, pwA)
		var cer ceremonyBody
		x.post("/auth/reauth/passkey/begin", nil).want(200, "").json(&cer)
		body, _ := bKey.Get(cer.Options)
		x.postT("/auth/reauth/passkey/finish", cer.Ticket, body).want(401, "passkey_invalid")
		x.post("/account/passkeys/review", nil).want(403, "reauth_required")

		// A ticket issued for one session does not work on another.
		y, z := f.client(), f.client()
		y.mustLogin(A.Phone, pwA)
		z.mustLogin(A.Phone, pwA)
		y.post("/auth/reauth/passkey/begin", nil).want(200, "").json(&cer)
		body, _ = aKey.Get(cer.Options)
		z.postT("/auth/reauth/passkey/finish", cer.Ticket, body).want(401, "passkey_invalid")
		z.post("/account/passkeys/review", nil).want(403, "reauth_required")
		// Without a ticket header there is nothing to take.
		z.postT("/auth/reauth/passkey/finish", "", body).want(400, "")
	})

	t.Run("enforce preconditions", func(t *testing.T) {
		f.ck.add(time.Minute) // refill the per-session buckets of the steps before
		b := bOwner
		b.reauthPassword(pwB).want(204, "")
		// B has a live passkey and a password: Enforce may be turned on, then off.
		var out struct {
			Ended int `json:"ended_sessions"`
		}
		b.do("PUT", "/account/passkey-enforcement", map[string]any{"enabled": true}).want(200, "").json(&out)
		b.do("PUT", "/account/passkey-enforcement", map[string]any{"enabled": false}).want(200, "")

		// No live credential, no Enforce.
		f.env.Exec(t, `UPDATE ctrlz.webauthn_credentials SET stale_at = now() WHERE user_id = $1`, B.User)
		b.do("PUT", "/account/passkey-enforcement", map[string]any{"enabled": true}).want(409, "enforce_precondition_failed")
		f.env.Exec(t, `UPDATE ctrlz.webauthn_credentials SET stale_at = NULL WHERE user_id = $1`, B.User)
		f.ck.add(time.Minute)
		// No second way: no password and no verified phone.
		f.env.Exec(t, `UPDATE ctrlz.users SET password_hash = NULL WHERE id = $1`, B.User)
		b.do("PUT", "/account/passkey-enforcement", map[string]any{"enabled": true}).want(409, "enforce_precondition_failed")
		f.env.Exec(t, `UPDATE ctrlz.users SET phone_verified_at = now() WHERE id = $1`, B.User)
		b.do("PUT", "/account/passkey-enforcement", map[string]any{"enabled": true}).want(200, "")
		b.do("PUT", "/account/passkey-enforcement", map[string]any{"enabled": false}).want(200, "")
		f.setPassword(B.Tenant, B.User, pwB)
		// A review in progress blocks it.
		f.env.Exec(t, `UPDATE ctrlz.users SET passkey_review_at = now() WHERE id = $1`, B.User)
		b.do("PUT", "/account/passkey-enforcement", map[string]any{"enabled": true}).want(409, "enforce_precondition_failed")
		f.env.Exec(t, `UPDATE ctrlz.users SET passkey_review_at = NULL WHERE id = $1`, B.User)
	})

	t.Run("enforce and Forgot Password", func(t *testing.T) {
		f.ck.add(time.Minute)
		f.clearThrottle()
		c := f.client()
		c.mustLogin(A.Phone, pwA)
		c.reauthPassword(pwA).want(204, "")
		c.do("PUT", "/account/passkey-enforcement", map[string]any{"enabled": true}).want(200, "")

		// While Enforce is on, the first factor gives passkey_required and no session.
		var res loginBody
		r := f.client().loginPassword(A.Phone, pwA, false).want(200, "")
		r.json(&res)
		if res.Status != "passkey_required" || len(r.cookies()) != 0 {
			t.Fatalf("login with Enforce on = %+v, cookies %d", res, len(r.cookies()))
		}
		f.clearOTP()
		var iss struct {
			ID string `json:"challenge_id"`
		}
		fc := f.client()
		fc.post("/auth/otp/request", map[string]any{"phone": A.Phone, "purpose": "login"}).want(202, "").json(&iss)
		r = fc.post("/auth/login/otp", map[string]any{"phone": A.Phone, "challenge_id": iss.ID, "code": f.codes.Last()}).want(200, "")
		r.json(&res)
		if res.Status != "passkey_required" {
			t.Fatalf("otp login with Enforce on = %+v", res)
		}

		// SIM swap: the reset code alone does not clear Enforce.
		rc := f.client()
		v := rc.verifyReset(A.Phone)
		if v.SecondFactor != "passkey" {
			t.Fatalf("second_factor = %q", v.SecondFactor)
		}
		const newPw = "Cobalt-meadow-Falcon-4417"
		rc.post("/auth/password/reset/complete", map[string]any{"ticket": v.Ticket, "new_password": newPw}).want(401, "passkey_invalid")

		// With the passkey: a new ticket records the proof; the old one is spent.
		var cer ceremonyBody
		rc.post("/auth/password/reset/passkey/begin", map[string]any{"ticket": v.Ticket}).want(200, "").json(&cer)
		body, _ := aKey.Get(cer.Options)
		// B's key cannot prove A's reset.
		bBody, _ := bKey.Get(cer.Options)
		rc.postT("/auth/password/reset/passkey/finish", cer.Ticket, bBody).want(401, "passkey_invalid")
		rc.post("/auth/password/reset/passkey/begin", map[string]any{"ticket": v.Ticket}).want(200, "").json(&cer)
		body, _ = aKey.Get(cer.Options)
		var proved struct {
			Ticket string `json:"ticket"`
		}
		rc.postT("/auth/password/reset/passkey/finish", cer.Ticket, body).want(200, "").json(&proved)
		rc.post("/auth/password/reset/complete", map[string]any{"ticket": v.Ticket, "new_password": newPw}).want(401, "ticket_invalid")
		rc.post("/auth/password/reset/complete", map[string]any{"ticket": proved.Ticket, "new_password": newPw}).want(204, "")
		if f.count(`SELECT count(*) FROM ctrlz.users WHERE id = $1 AND enforce_passkey AND enforce_lift_at IS NULL AND passkey_review_at IS NULL`, A.User) != 1 {
			t.Fatal("after a passkey proof Enforce stays on, with no lift and no review")
		}
		f.clearThrottle()
		f.setPassword(A.Tenant, A.User, pwA)
	})

	t.Run("a lost passkey: defer_enforce and the 72 hour delay", func(t *testing.T) {
		f.clearThrottle()
		rc := f.client()
		v := rc.verifyReset(A.Phone)
		const newPw = "Cobalt-meadow-Falcon-4417"
		rc.post("/auth/password/reset/complete", map[string]any{"ticket": v.Ticket, "new_password": newPw, "defer_enforce": true}).want(204, "")
		var lift time.Time
		f.env.Scan(t, `SELECT enforce_lift_at FROM ctrlz.users WHERE id = $1`, []any{A.User}, &lift)
		if d := time.Until(lift); d < 71*time.Hour || d > 73*time.Hour {
			t.Fatalf("enforce_lift_at is %v away, want about 72 h", d)
		}
		for _, k := range []string{"password_reset", "enforce_lift_pending"} {
			if f.count(`SELECT count(*) FROM ctrlz.notifications WHERE tenant_id = $1 AND kind = $2`, A.Tenant, k) < 1 {
				t.Fatalf("no %s notification", k)
			}
		}
		// Repeating the step neither extends nor shortens the delay.
		v = rc.verifyReset(A.Phone)
		rc.post("/auth/password/reset/complete", map[string]any{"ticket": v.Ticket, "new_password": newPw, "defer_enforce": true}).want(204, "")
		var again time.Time
		f.env.Scan(t, `SELECT enforce_lift_at FROM ctrlz.users WHERE id = $1`, []any{A.User}, &again)
		if !again.Equal(lift) {
			t.Fatalf("lift moved from %v to %v", lift, again)
		}
		// During the delay the password gives passkey_required.
		var res loginBody
		f.client().loginPassword(A.Phone, newPw, false).want(200, "").json(&res)
		if res.Status != "passkey_required" {
			t.Fatalf("login during the delay = %q", res.Status)
		}
		// The owner comes back with the passkey: the delay ends and other sessions go.
		intruder := f.makeSession(A.Tenant, A.User)
		intruder.get("/me").want(200, "")
		owner := f.client()
		owner.passkeyLogin(aKey).want(200, "")
		intruder.get("/me").want(401, "session_expired")
		if f.count(`SELECT count(*) FROM ctrlz.users WHERE id = $1 AND enforce_passkey AND enforce_lift_at IS NULL`, A.User) != 1 {
			t.Fatal("a passkey login must end the delay and keep Enforce")
		}

		// A lift that has passed: the password logs in and Enforce clears.
		f.env.Exec(t, `UPDATE ctrlz.users SET enforce_lift_at = now() - interval '1 hour' WHERE id = $1`, A.User)
		f.clearThrottle()
		f.client().loginPassword(A.Phone, newPw, false).want(200, "").json(&res)
		if res.Status != "authenticated" {
			t.Fatalf("login after the delay = %q", res.Status)
		}
		if f.count(`SELECT count(*) FROM ctrlz.users WHERE id = $1 AND NOT enforce_passkey AND enforce_lift_at IS NULL`, A.User) != 1 {
			t.Fatal("the login after the delay must clear Enforce")
		}
		f.setPassword(A.Tenant, A.User, pwA)
	})

	t.Run("review after recovery", func(t *testing.T) {
		f.ck.add(time.Minute)
		f.clearThrottle()
		rc := f.client()
		v := rc.verifyReset(A.Phone)
		if v.SecondFactor != "none" {
			t.Fatalf("second_factor = %q with Enforce off", v.SecondFactor)
		}
		rc.post("/auth/password/reset/complete", map[string]any{"ticket": v.Ticket, "new_password": "Cobalt-meadow-Falcon-4417"}).want(204, "")
		f.setPassword(A.Tenant, A.User, pwA)
		if f.count(`SELECT count(*) FROM ctrlz.users WHERE id = $1 AND passkey_review_at IS NOT NULL`, A.User) != 1 {
			t.Fatal("a reset must mark the passkeys for review")
		}
		f.client().passkeyLogin(aKey).want(401, "passkey_invalid")
		c := f.client()
		c.mustLogin(A.Phone, pwA)
		if m := c.me(); !m.Security.PasskeyReviewRequired {
			t.Fatal("me.security.passkey_review_required should be true")
		}
		c.reauthPassword(pwA).want(204, "")
		c.do("PUT", "/account/passkey-enforcement", map[string]any{"enabled": true}).want(409, "enforce_precondition_failed")
		// A passkey reauth is refused while the flag is set.
		c.post("/auth/reauth/passkey/begin", nil).want(401, "passkey_invalid")
		c.post("/account/passkeys/review", nil).want(204, "")
		f.client().passkeyLogin(aKey).want(200, "")
		if f.count(`SELECT count(*) FROM ctrlz.tenant_audit_log WHERE action = 'passkey.review'`) != 2 { // the earlier reauth test cleared the flag once too
			t.Fatal("no passkey.review row")
		}
	})

	t.Run("deleting the last live passkey turns Enforce off", func(t *testing.T) {
		f.ck.add(time.Minute)
		c := f.client()
		c.mustLogin(B.Phone, pwB)
		c.reauthPassword(pwB).want(204, "")
		c.do("PUT", "/account/passkey-enforcement", map[string]any{"enabled": true}).want(200, "")
		for _, row := range c.passkeys() {
			if !row.Stale {
				c.do("DELETE", "/account/passkeys/"+row.ID, nil).want(204, "")
			}
		}
		if f.count(`SELECT count(*) FROM ctrlz.users WHERE id = $1 AND NOT enforce_passkey`, B.User) != 1 {
			t.Fatal("Enforce must go off with the last live passkey")
		}
	})

	t.Run("the RP ID change makes credentials stale at once", func(t *testing.T) {
		f.env.Exec(t, `UPDATE ctrlz.webauthn_config SET rp_id = 'other.localhost', allowed_origins = ARRAY['https://other.localhost']`)
		f.ck.add(31 * time.Second) // the public configuration is cached for 30 seconds
		f.client().passkeyLogin(aKey).want(401, "passkey_invalid")
		c := f.client()
		c.mustLogin(A.Phone, pwA)
		for _, row := range c.passkeys() {
			if !row.Stale {
				t.Fatalf("passkey %s should be stale under the new RP ID", row.ID)
			}
		}
		f.env.Exec(t, `UPDATE ctrlz.webauthn_config SET enabled = false`)
		f.ck.add(31 * time.Second)
		c.get("/account/passkeys").want(404, "passkey_unavailable")
		c.post("/auth/passkey/login/begin", nil).want(404, "passkey_unavailable")
	})
}

// TestPasskeyLoginCeremonyIsStateless is rule proof-before-work for POST
// /auth/passkey/login/begin (spec 7.5): the route needs no proof, so it writes no row, and
// the ticket is a sealed value that finish checks with one HMAC. The only row is the nonce
// that finish records once an assertion has verified.
func TestPasskeyLoginCeremonyIsStateless(t *testing.T) {
	f := newFrig(t, frigOpts{passkey: true})
	A := f.env.A
	key := passkeytest.New(pkOrigin, pkRP)
	owner := f.client()
	owner.mustLogin(A.Phone, pwA)
	owner.reauthPassword(pwA).want(204, "")
	owner.addPasskey(key).want(201, "")

	rows := func() int { return f.count(`SELECT count(*) FROM ctrlz.auth_tickets WHERE kind = 'passkey_login'`) }
	begin := func(c *client) (ceremonyBody, []byte) {
		var cer ceremonyBody
		c.post("/auth/passkey/login/begin", map[string]any{}).want(200, "").json(&cer)
		body, err := key.Get(cer.Options)
		if err != nil {
			t.Fatal(err)
		}
		return cer, body
	}

	t.Run("begin writes no row, however often it is called", func(t *testing.T) {
		before := rows()
		for i := 0; i < 30; i++ {
			c := f.client()
			c.ip = f.freshIP()
			if cer, _ := begin(c); len(cer.Ticket) <= 43 {
				t.Fatalf("ticket of %d characters: the session data is not in it", len(cer.Ticket))
			}
		}
		if got := rows() - before; got != 0 {
			t.Fatalf("30 begins wrote %d rows", got)
		}
	})
	t.Run("a made-up ticket costs no row", func(t *testing.T) {
		before := rows()
		_, body := begin(f.client())
		for i := 0; i < 20; i++ {
			c := f.client()
			c.ip = f.freshIP()
			c.postT("/auth/passkey/login/finish", strings.Repeat(string(rune('a'+i)), 300), body).want(401, "ticket_invalid")
		}
		if got := rows() - before; got != 0 {
			t.Fatalf("20 made-up tickets wrote %d rows", got)
		}
	})
	t.Run("one good login writes one row, a replay is refused and writes none", func(t *testing.T) {
		before := rows()
		c := f.client()
		cer, body := begin(c)
		c.postT("/auth/passkey/login/finish", cer.Ticket, body).want(200, "")
		if got := rows() - before; got != 1 {
			t.Fatalf("a login wrote %d rows, want 1", got)
		}
		f.client().postT("/auth/passkey/login/finish", cer.Ticket, body).want(401, "ticket_invalid")
		if got := rows() - before; got != 1 {
			t.Fatalf("a replay left %d rows, want 1", got)
		}
	})
	t.Run("a ticket nobody sealed, or one that was changed, is refused", func(t *testing.T) {
		c := f.client()
		cer, body := begin(c)
		last := cer.Ticket[len(cer.Ticket)-1]
		flipped := cer.Ticket[:len(cer.Ticket)-1] + string(rune('A'+(last-'A'+1)%26))
		if flipped == cer.Ticket {
			flipped = cer.Ticket[:len(cer.Ticket)-1] + "B"
		}
		before := rows()
		c.postT("/auth/passkey/login/finish", flipped, body).want(401, "ticket_invalid")
		c.postT("/auth/passkey/login/finish", cer.Ticket[:len(cer.Ticket)/2], body).want(401, "ticket_invalid")
		if rows() != before {
			t.Fatal("a refused ticket wrote a row")
		}
	})
	t.Run("a wrong assertion writes no row and does not burn the challenge", func(t *testing.T) {
		c := f.client()
		cer, body := begin(c)
		stranger := passkeytest.New(pkOrigin, pkRP)
		bad, err := stranger.Get(cer.Options)
		if err != nil {
			t.Fatal(err)
		}
		before := rows()
		c.postT("/auth/passkey/login/finish", cer.Ticket, bad).want(401, "passkey_invalid")
		if rows() != before {
			t.Fatal("a refused assertion wrote a row")
		}
		c.postT("/auth/passkey/login/finish", cer.Ticket, body).want(200, "")
	})
	t.Run("a ticket expires with the ceremony", func(t *testing.T) {
		c := f.client()
		cer, body := begin(c)
		f.ck.add(6 * time.Minute)
		c.postT("/auth/passkey/login/finish", cer.Ticket, body).want(401, "ticket_invalid")
	})
}
