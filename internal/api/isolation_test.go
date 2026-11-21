package api

import (
	"encoding/base32"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/google/uuid"

	apidoc "github.com/Kup1ng/CtrlZ-Panel/api"
	"github.com/Kup1ng/CtrlZ-Panel/internal/apispec"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/marker"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/passkey/passkeytest"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/session"
	"github.com/Kup1ng/CtrlZ-Panel/internal/authtest/boundary"
	"github.com/Kup1ng/CtrlZ-Panel/internal/authtest/isolation"
	"github.com/Kup1ng/CtrlZ-Panel/internal/credgen"
	"github.com/Kup1ng/CtrlZ-Panel/internal/ratelimit"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
)

// tn is one tenant of the two-tenant harness (rule isolation-success-coverage): its ids, the
// secrets only the fixture knows, and whatever the last Arrange made for the call to use.
type tn struct {
	who      isolation.Who
	pw       string
	newPhone string // the number a phone change moves to
	invPhone string // the number of an invite planted for it, new for every case
	// What Arrange made.
	sess       *client
	key        *passkeytest.Authenticator
	seed       secret.Bytes
	challenge  string // an OTP challenge id
	code       string // its code
	ticket     string // a login or reset ticket, or the ticket of a ceremony
	body       []byte // the assertion that goes with ticket
	oldCode    string
	newCode    string
	requestID  string
	otherSess  string // the id of a second session
	passkeyID  string
	notifID    string
	announceID string
	invite     string // the invite code a person would type
	notes      []string
}

// note remembers an identifier of this tenant that must never show up in the other's answers.
func (n *tn) note(s string) { n.notes = append(n.notes, s) }

// isoEnv is the fixture of spec 18.1: tenants A and B in one database, and the harness
// hooks that put both back to the same baseline before every case.
type isoEnv struct {
	f   *frig
	n   [2]*tn
	seq int
	db  *isolation.Tenants
}

func newIsoEnv(f *frig) *isoEnv {
	e := &isoEnv{f: f}
	e.db = &isolation.Tenants{Env: f.env, T: f.t, Phones: func(w isolation.Who) []string { return e.phones(e.n[w]) }}
	e.n[isolation.A] = &tn{who: isolation.A, pw: pwA, newPhone: "+989128880003"}
	e.n[isolation.B] = &tn{who: isolation.B, pw: pwB, newPhone: "+989128880002"}
	return e
}

func (e *isoEnv) ids(n *tn) (tenant, user uuid.UUID, phone string) {
	if n.who == isolation.A {
		return e.f.env.A.Tenant, e.f.env.A.User, e.f.env.A.Phone
	}
	return e.f.env.B.Tenant, e.f.env.B.User, e.f.env.B.Phone
}

func (e *isoEnv) phones(n *tn) []string {
	_, _, p := e.ids(n)
	out := []string{p, n.newPhone}
	if n.invPhone != "" {
		out = append(out, n.invPhone)
	}
	return out
}

// reset puts one tenant back to the baseline the fixtures start from. The database side is
// shared with the admin API's harness; what is left here is the API's own: the throttles and
// the SMS counters are global rows no digest holds, and the fake clock moves on so the rate
// buckets refill.
func (e *isoEnv) reset(w isolation.Who) {
	f := e.f
	n := e.n[w]
	e.seq++
	n.invPhone = fmt.Sprintf("+98912%07d", 5550000+e.seq*10+int(w))
	before := ""
	if w == isolation.A {
		// One tick per case, not per tenant.
		f.ck.add(time.Minute)
		before = `DELETE FROM ctrlz.auth_throttle; TRUNCATE ctrlz.sms_counters;`
	}
	e.db.Reset(w, before)
	// The phone is back, so a number the change moved to is free again.
	*n = tn{who: w, pw: n.pw, newPhone: n.newPhone, invPhone: n.invPhone}
}

// --- building blocks of Arrange ---------------------------------------------------------

// session opens a session of the tenant straight through the manager; reauthed stamps a live
// reauth window with the clock of the API, which is the one the gate reads.
func (e *isoEnv) session(n *tn, reauthed bool) *client {
	f := e.f
	tenant, user, _ := e.ids(n)
	c := f.makeSession(tenant, user)
	if reauthed {
		f.env.Exec(f.t, `UPDATE ctrlz.sessions SET reauth_at = $3 WHERE tenant_id = $1 AND id = (
			SELECT id FROM ctrlz.sessions WHERE user_id = $2 ORDER BY created_at DESC, id DESC LIMIT 1)`, tenant, user, f.ck.now())
	}
	return c
}

func (e *isoEnv) latestSessionID(n *tn) string {
	_, user, _ := e.ids(n)
	var id string
	e.f.env.Scan(e.f.t, `SELECT id::text FROM ctrlz.sessions WHERE user_id = $1 ORDER BY created_at DESC, id DESC LIMIT 1`, []any{user}, &id)
	return id
}

// addKey registers a passkey for the tenant through the routes, so the counter, the RP ID and
// the transports are the ones a real registration leaves.
func (e *isoEnv) addKey(n *tn) {
	f := e.f
	c := e.session(n, true)
	n.key = passkeytest.New(pkOrigin, pkRP)
	c.addPasskey(n.key).want(201, "")
	_, user, _ := e.ids(n)
	f.env.Scan(f.t, `SELECT id::text FROM ctrlz.webauthn_credentials WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1`, []any{user}, &n.passkeyID)
	n.note(n.passkeyID)
}

func (e *isoEnv) totpOn(n *tn) {
	tenant, user, _ := e.ids(n)
	n.seed = e.f.enableTOTP(tenant, user)
	e.f.freeStep(tenant)
}

// requestOTP asks for a code for the phone and keeps the challenge id and the code.
func (e *isoEnv) requestOTP(n *tn, phone, purpose string, extra map[string]any) (id, code string) {
	f := e.f
	f.env.Exec(f.t, `TRUNCATE ctrlz.sms_counters`)
	body := map[string]any{"phone": phone, "purpose": purpose}
	for k, v := range extra {
		body[k] = v
	}
	var iss issued
	f.client().post("/auth/otp/request", body).want(202, "").json(&iss)
	return iss.ID, f.codes.Last()
}

// verifyReset runs the first step of a password reset and returns the ticket.
func (e *isoEnv) verifyReset(n *tn) resetVerified {
	_, _, phone := e.ids(n)
	id, code := e.requestOTP(n, phone, "reset", nil)
	var v resetVerified
	e.f.client().post("/auth/password/reset/verify", map[string]any{"phone": phone, "challenge_id": id, "code": code}).want(200, "").json(&v)
	return v
}

// startChange asks for a phone change from the tenant's reauthed session.
func (e *isoEnv) startChange(n *tn) {
	f := e.f
	n.sess = e.session(n, true)
	f.env.Exec(f.t, `TRUNCATE ctrlz.sms_counters`)
	var pc phoneChangeBody
	n.sess.post("/account/phone/change", map[string]any{"new_phone": n.newPhone}).want(202, "").json(&pc)
	n.requestID, n.newCode, n.oldCode = pc.RequestID, f.codes.Back(2), f.codes.Back(1)
	n.note(pc.RequestID)
}

// forged used to add A's tenant and user ids to B's body, to show a handler ignores a member that
// names another tenant. Every request object is closed now (rule boundary-input, tenant-r5-7), so
// such a member is a 400 at the pipeline before any handler runs, and the generated fuzz
// (internal/authtest/boundary, "unknown member") sends one to every object of every
// operation. B's call here has to succeed, so the body is B's alone.
func (e *isoEnv) forged(m map[string]any) map[string]any {
	if m == nil {
		m = map[string]any{}
	}
	return m
}

func result(r *resp) isolation.Result {
	return isolation.Result{Status: r.Code, Body: r.Body, Cookies: strings.Join(r.H.Values("Set-Cookie"), "; "), Set: r.H.Values("Set-Cookie")}
}

// fixtures is one success case for every operation of api/openapi.yaml. Each brings B's call
// to a 2xx while A holds the same state, so a statement that lost its tenant predicate is the
// only thing that can keep A's rows from moving.
func (e *isoEnv) fixtures() map[string]isolation.Fixture {
	f := e.f
	A := f.env.A
	b := func() *tn { return e.n[isolation.B] }
	a := func() *tn { return e.n[isolation.A] }
	// begin starts a new ceremony for n and returns its ticket. A Cross call that needs a ticket of its own makes one here and
	// leaves the ticket Arrange made alone, because a ceremony ticket dies with its first answer and the real call comes
	// after the Cross calls (round 16, tenant-r16-13: one Cross call per place of a row id).
	begin := func(n *tn, path string) string {
		var cer ceremonyBody
		n.sess.post(path, nil).want(200, "").json(&cer)
		return cer.Ticket
	}
	each := func(fn func(n *tn)) func(w isolation.Who) { return func(w isolation.Who) { fn(e.n[w]) } }
	nothing := each(func(*tn) {})
	anon := func() *client { return f.client() }
	user := func(n *tn) (uuid.UUID, uuid.UUID, string) { return e.ids(n) }
	bPhone := func() string { _, _, p := user(b()); return p }
	bUser := func() string { _, u, _ := user(b()); return u.String() }
	// reauthed opens a session with a live reauth window and keeps it in n.sess.
	reauthed := each(func(n *tn) { n.sess = e.session(n, true) })
	plain := each(func(n *tn) { n.sess = e.session(n, false) })

	return map[string]isolation.Fixture{
		"getAuthConfig": {Effect: isolation.Shows, Status: 200, Arrange: nothing,
			Call: func() isolation.Result { return result(anon().get("/auth/config")) }},
		"loginPassword": {Effect: isolation.Changes, Status: 200, Arrange: nothing,
			Call: func() isolation.Result {
				return result(anon().post("/auth/login/password", e.forged(map[string]any{"phone": bPhone(), "password": pwB})))
			}},
		"requestOtp": {Effect: isolation.Changes, Status: 202, Arrange: nothing,
			Call: func() isolation.Result {
				return result(anon().post("/auth/otp/request", e.forged(map[string]any{"phone": bPhone(), "purpose": "login"})))
			}},
		"loginOtp": {Effect: isolation.Changes, Status: 200,
			Arrange: each(func(n *tn) { _, _, p := user(n); n.challenge, n.code = e.requestOTP(n, p, "login", nil) }),
			Call: func() isolation.Result {
				return result(anon().post("/auth/login/otp", e.forged(map[string]any{"phone": bPhone(), "challenge_id": b().challenge, "code": b().code})))
			}},
		"loginTotp": {Effect: isolation.Changes, Status: 200,
			Arrange: each(func(n *tn) {
				e.totpOn(n)
				_, _, p := user(n)
				n.ticket = anon().mfaLogin(p, n.pw)
			}),
			Call: func() isolation.Result {
				tenant, _, _ := user(b())
				f.freeStep(tenant)
				return result(anon().post("/auth/login/totp", e.forged(map[string]any{"ticket": b().ticket, "totp_code": codeAt(b().seed, time.Now())})))
			}},
		"passkeyLoginBegin": {Effect: isolation.Shows, Status: 200, Arrange: nothing,
			Reason: "the discoverable ceremony is sealed into its ticket and keeps no row until the assertion is verified (spec 7.5)",
			Call:   func() isolation.Result { return result(anon().post("/auth/passkey/login/begin", e.forged(nil))) }},
		"passkeyLoginFinish": {Effect: isolation.Changes, Status: 200, Arrange: each(e.addKey),
			Call: func() isolation.Result {
				// Begin and finish are one call of the browser; the assertion is the key's.
				return result(anon().passkeyLogin(b().key))
			}},
		"refreshSession": {Effect: isolation.Changes, Status: 204,
			Arrange: each(func(n *tn) {
				_, _, p := user(n)
				c := anon()
				c.loginPassword(p, n.pw, true).want(200, "")
				n.sess = c
			}),
			Call: func() isolation.Result {
				b().sess.forget(session.CookieSession)
				return result(b().sess.post("/auth/refresh", nil))
			}},
		"logout": {Effect: isolation.Changes, Status: 204, Arrange: plain,
			Call: func() isolation.Result { return result(b().sess.post("/auth/logout", nil)) }},
		"logoutAll": {Effect: isolation.Changes, Status: 204,
			Arrange: each(func(n *tn) { e.session(n, false); n.sess = e.session(n, false) }),
			Call:    func() isolation.Result { return result(b().sess.post("/auth/logout-all", nil)) }},
		// The SMS path, the one that names a row by a value the client chooses (otp_challenge_id, tenant-r6-3
		// and -11): an account with no password and no TOTP reauths by a code sent to its own number. The
		// password path has no id in it and is driven by the flow tests.
		"reauth": {Effect: isolation.Changes, Status: 204,
			Arrange: each(func(n *tn) {
				_, u, _ := user(n)
				f.env.Exec(f.t, `UPDATE ctrlz.users SET password_hash = NULL WHERE id = $1`, u)
				n.sess = e.session(n, false)
				f.env.Exec(f.t, `TRUNCATE ctrlz.sms_counters`)
				var iss issued
				n.sess.post("/auth/reauth/otp/request", nil).want(202, "").json(&iss)
				n.challenge, n.code = iss.ID, f.codes.Last()
			}),
			Call: func() isolation.Result {
				return result(b().sess.post("/auth/reauth", e.forged(map[string]any{"otp_challenge_id": b().challenge, "otp_code": b().code})))
			},
			// B's session posts A's challenge and A's code. The check binds the challenge to the session
			// user's own number, so it is a refusal that costs A nothing: A's challenge keeps its tries and
			// stays consumable by A (the digest of A is compared by the harness).
			CrossStatus: 401,
			CrossBMay:   []string{"tenant_audit_log"},
			CrossReason: "the refused attempt is B's own failed reauth, and the audit log records it for B",
			Cross: func() isolation.Result {
				return result(b().sess.post("/auth/reauth", e.forged(map[string]any{"otp_challenge_id": a().challenge, "otp_code": a().code})))
			}},
		"reauthOtpRequest": {Effect: isolation.Changes, Status: 202,
			Arrange: each(func(n *tn) {
				// Only an account with no password and no TOTP reauths by code (spec 3.5).
				_, u, _ := user(n)
				f.env.Exec(f.t, `UPDATE ctrlz.users SET password_hash = NULL WHERE id = $1`, u)
				n.sess = e.session(n, false)
				f.env.Exec(f.t, `TRUNCATE ctrlz.sms_counters`)
			}),
			Call: func() isolation.Result {
				return result(b().sess.do("POST", "/auth/reauth/otp/request", fmt.Sprintf(`{"phone":%q,"tenant_id":%q}`, A.Phone, A.Tenant)))
			}},
		"reauthPasskeyBegin": {Effect: isolation.Changes, Status: 200,
			Arrange: each(func(n *tn) { e.addKey(n); n.sess = e.session(n, false) }),
			Call:    func() isolation.Result { return result(b().sess.post("/auth/reauth/passkey/begin", nil)) }},
		"reauthPasskeyFinish": {Effect: isolation.Changes, Status: 204,
			Arrange: each(func(n *tn) {
				e.addKey(n)
				n.sess = e.session(n, false)
				// A ceremony begun and answered by the key but not yet finished: B's session
				// replays A's in Cross.
				var cer ceremonyBody
				n.sess.post("/auth/reauth/passkey/begin", nil).want(200, "").json(&cer)
				body, err := n.key.Get(cer.Options)
				if err != nil {
					f.t.Fatal(err)
				}
				n.ticket, n.body = cer.Ticket, body
			}),
			Call:        func() isolation.Result { return result(b().sess.reauthPasskey(b().key)) },
			CrossStatus: 401,
			CrossMay:    []string{"auth_tickets"},
			CrossBMay:   []string{"auth_tickets"},
			CrossReason: "a ceremony ticket dies with its first answer; the 256 bit ticket is held by its owner alone",
			Cross: func() isolation.Result {
				return result(b().sess.postT("/auth/reauth/passkey/finish", begin(b(), "/auth/reauth/passkey/begin"), a().body))
			},
			CrossAt: map[string]func() isolation.Result{"header:X-Ctrlz-Ticket": func() isolation.Result {
				return result(b().sess.postT("/auth/reauth/passkey/finish", begin(a(), "/auth/reauth/passkey/begin"), b().body))
			},
				// The body of A carries A's id, rawId and userHandle together, so B's session and ticket with it
				// put A's value in each of the three places the document marks as naming a row (tenant-r17-19).
				"body:rawId": func() isolation.Result {
					return result(b().sess.postT("/auth/reauth/passkey/finish", begin(b(), "/auth/reauth/passkey/begin"), a().body))
				},
				"body:response.userHandle": func() isolation.Result {
					return result(b().sess.postT("/auth/reauth/passkey/finish", begin(b(), "/auth/reauth/passkey/begin"), a().body))
				}}},
		"register": {Effect: isolation.Changes, Status: 201,
			Arrange: each(func(n *tn) {
				// An invite works in every mode (spec 11.1); the account it makes is a third tenant.
				n.invite = f.plantInvite(n.invPhone, time.Hour, false)
				n.challenge, n.code = e.requestOTP(n, "09120000001", "invite", map[string]any{"invite_token": n.invite, "locale": "fa"})
			}),
			Call: func() isolation.Result {
				return result(anon().post("/auth/register", e.forged(map[string]any{"invite_token": b().invite, "challenge_id": b().challenge,
					"code": b().code, "password": "Marble-Island-Copper-6620"})))
			}},
		"lookupInvite": {Effect: isolation.Shows, Status: 200,
			Reason:  "it reads one invite; the only row it writes is a rate counter that no tenant owns",
			Arrange: each(func(n *tn) { n.invite = f.plantInvite(n.invPhone, time.Hour, false) }),
			Call: func() isolation.Result {
				return result(anon().post("/auth/invites/lookup", e.forged(map[string]any{"token": b().invite})))
			}},
		"resetVerify": {Effect: isolation.Changes, Status: 200,
			Arrange: each(func(n *tn) { _, _, p := user(n); n.challenge, n.code = e.requestOTP(n, p, "reset", nil) }),
			Call: func() isolation.Result {
				return result(anon().post("/auth/password/reset/verify", e.forged(map[string]any{"phone": bPhone(), "challenge_id": b().challenge, "code": b().code})))
			}},
		"resetPasskeyBegin": {Effect: isolation.Changes, Status: 200,
			Arrange: each(func(n *tn) { e.addKey(n); n.ticket = e.verifyReset(n).Ticket }),
			Call: func() isolation.Result {
				return result(anon().post("/auth/password/reset/passkey/begin", e.forged(map[string]any{"ticket": b().ticket})))
			}},
		"resetPasskeyFinish": {Effect: isolation.Changes, Status: 200,
			Arrange: each(func(n *tn) {
				e.addKey(n)
				rt := e.verifyReset(n).Ticket
				var cer ceremonyBody
				anon().post("/auth/password/reset/passkey/begin", map[string]any{"ticket": rt}).want(200, "").json(&cer)
				body, err := n.key.Get(cer.Options)
				if err != nil {
					f.t.Fatal(err)
				}
				n.ticket, n.body = cer.Ticket, body
			}),
			Call: func() isolation.Result {
				return result(anon().postT("/auth/password/reset/passkey/finish", b().ticket, b().body))
			}},
		"resetComplete": {Effect: isolation.Changes, Status: 204,
			Arrange: each(func(n *tn) { n.ticket = e.verifyReset(n).Ticket }),
			Call: func() isolation.Result {
				return result(anon().post("/auth/password/reset/complete", e.forged(map[string]any{"ticket": b().ticket, "new_password": "Granite-Falcon-Meadow-4417"})))
			}},
		"getMe": {Effect: isolation.Shows, Status: 200, Arrange: plain, Sees: func() []string { return []string{bUser()} },
			Call: func() isolation.Result { return result(b().sess.get("/me")) }},
		"updatePreferences": {Effect: isolation.Changes, Status: 200, Arrange: plain,
			Call: func() isolation.Result {
				return result(b().sess.do("PATCH", "/account/preferences", e.forged(map[string]any{"locale": "en"})))
			}},
		"setHomeCountries": {Effect: isolation.Changes, Status: 200, Arrange: plain,
			Call: func() isolation.Result {
				return result(b().sess.do("PUT", "/account/home-countries", e.forged(map[string]any{"countries": []string{"DE"}})))
			}},
		"getLimits": {Effect: isolation.Shows, Status: 200, Arrange: plain,
			Call: func() isolation.Result { return result(b().sess.get("/account/limits")) }},
		"listSessions": {Effect: isolation.Shows, Status: 200,
			Arrange: each(func(n *tn) { n.sess = e.session(n, false); n.otherSess = e.latestSessionID(n); n.note(n.otherSess) }),
			Sees:    func() []string { return []string{b().otherSess} },
			Call:    func() isolation.Result { return result(b().sess.get("/account/sessions")) }},
		"deleteSession": {Effect: isolation.Changes, Status: 204,
			Arrange: each(func(n *tn) {
				e.session(n, false)
				n.otherSess = e.latestSessionID(n)
				n.note(n.otherSess)
				n.sess = e.session(n, false)
			}),
			Call:        func() isolation.Result { return result(b().sess.do("DELETE", "/account/sessions/"+b().otherSess, nil)) },
			CrossStatus: 404,
			Cross:       func() isolation.Result { return result(b().sess.do("DELETE", "/account/sessions/"+a().otherSess, nil)) }},
		"changePassword": {Effect: isolation.Changes, Status: 204, Arrange: reauthed,
			Call: func() isolation.Result {
				return result(b().sess.post("/account/password", e.forged(map[string]any{"new_password": "Granite-Falcon-Meadow-4417"})))
			}},
		"startPhoneChange": {Effect: isolation.Changes, Status: 202,
			Arrange: each(func(n *tn) { n.sess = e.session(n, true); f.env.Exec(f.t, `TRUNCATE ctrlz.sms_counters`) }),
			Call: func() isolation.Result {
				return result(b().sess.post("/account/phone/change", e.forged(map[string]any{"new_phone": b().newPhone})))
			}},
		"confirmPhoneChange": {Effect: isolation.Changes, Status: 204, Arrange: each(e.startChange),
			CrossStatus: 404,
			Cross: func() isolation.Result {
				return result(b().sess.post("/account/phone/change/"+a().requestID+"/confirm", map[string]any{"old_code": b().oldCode, "new_code": b().newCode}))
			},
			Call: func() isolation.Result {
				return result(b().sess.post("/account/phone/change/"+b().requestID+"/confirm", e.forged(map[string]any{"old_code": b().oldCode, "new_code": b().newCode})))
			}},
		"totpSetup": {Effect: isolation.Changes, Status: 200, Arrange: reauthed,
			Call: func() isolation.Result { return result(b().sess.post("/account/totp/setup", map[string]any{})) }},
		"totpConfirm": {Effect: isolation.Changes, Status: 200,
			Arrange: each(func(n *tn) {
				n.sess = e.session(n, true)
				var setup struct {
					Secret string `json:"secret"`
				}
				n.sess.post("/account/totp/setup", map[string]any{}).want(200, "").json(&setup)
				raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(setup.Secret)
				if err != nil {
					f.t.Fatal(err)
				}
				n.seed = secret.NewBytes(raw)
			}),
			Call: func() isolation.Result {
				return result(b().sess.post("/account/totp/confirm", e.forged(map[string]any{"code": codeAt(b().seed, time.Now()), "saved": true})))
			}},
		"totpDisable": {Effect: isolation.Changes, Status: 200, Arrange: each(func(n *tn) { e.totpOn(n); n.sess = e.session(n, true) }),
			Call: func() isolation.Result { return result(b().sess.post("/account/totp/disable", map[string]any{})) }},
		"regenerateRecoveryCodes": {Effect: isolation.Changes, Status: 200, Arrange: each(func(n *tn) { e.totpOn(n); n.sess = e.session(n, true) }),
			Call: func() isolation.Result {
				return result(b().sess.post("/account/totp/recovery-codes", map[string]any{}))
			}},
		"listPasskeys": {Effect: isolation.Shows, Status: 200, Arrange: each(func(n *tn) { e.addKey(n); n.sess = e.session(n, false) }),
			Sees: func() []string { return []string{b().passkeyID} },
			Call: func() isolation.Result { return result(b().sess.get("/account/passkeys")) }},
		"passkeyBegin": {Effect: isolation.Changes, Status: 200, Arrange: reauthed,
			Call: func() isolation.Result { return result(b().sess.post("/account/passkeys/begin", map[string]any{})) }},
		"passkeyFinish": {Effect: isolation.Changes, Status: 201,
			Arrange: each(func(n *tn) {
				n.sess = e.session(n, true)
				var cer ceremonyBody
				n.sess.post("/account/passkeys/begin", nil).want(200, "").json(&cer)
				n.key = passkeytest.New(pkOrigin, pkRP)
				body, err := n.key.Create(cer.Options)
				if err != nil {
					f.t.Fatal(err)
				}
				n.ticket, n.body = cer.Ticket, body
			}),
			Call: func() isolation.Result {
				return result(b().sess.postT("/account/passkeys/finish", b().ticket, b().body))
			},
			// One call for each place a row id is taken (Op.Locations): the credential id of the body, then the ticket header.
			// B's session answers its OWN new ceremony with A's attestation (A's id in the body, B's ticket), and answers
			// A's new ceremony with B's own attestation (A's ticket, B's id in the body).
			CrossStatus: 401,
			CrossMay:    []string{"auth_tickets"},
			CrossBMay:   []string{"auth_tickets"},
			CrossReason: "a ceremony ticket dies with its first answer; the 256 bit ticket is held by its owner alone",
			Cross: func() isolation.Result {
				return result(b().sess.postT("/account/passkeys/finish", begin(b(), "/account/passkeys/begin"), a().body))
			},
			CrossAt: map[string]func() isolation.Result{"header:X-Ctrlz-Ticket": func() isolation.Result {
				return result(b().sess.postT("/account/passkeys/finish", begin(a(), "/account/passkeys/begin"), b().body))
			},
				// As above: A's whole body carries A's id, rawId and userHandle (tenant-r17-19).
				"body:rawId": func() isolation.Result {
					return result(b().sess.postT("/account/passkeys/finish", begin(b(), "/account/passkeys/begin"), a().body))
				},
				"body:response.userHandle": func() isolation.Result {
					return result(b().sess.postT("/account/passkeys/finish", begin(b(), "/account/passkeys/begin"), a().body))
				}}},
		"reviewPasskeys": {Effect: isolation.Changes, Status: 204,
			Arrange: each(func(n *tn) {
				n.sess = e.session(n, true)
				_, u, _ := user(n)
				f.env.Exec(f.t, `UPDATE ctrlz.users SET passkey_review_at = now() WHERE id = $1`, u)
			}),
			Call: func() isolation.Result { return result(b().sess.post("/account/passkeys/review", map[string]any{})) }},
		"renamePasskey": {Effect: isolation.Changes, Status: 200, Arrange: each(func(n *tn) { e.addKey(n); n.sess = e.session(n, false) }),
			CrossStatus: 404,
			Cross: func() isolation.Result {
				return result(b().sess.do("PATCH", "/account/passkeys/"+a().passkeyID, map[string]any{"name": "phone of B"}))
			},
			Call: func() isolation.Result {
				return result(b().sess.do("PATCH", "/account/passkeys/"+b().passkeyID, e.forged(map[string]any{"name": "phone of B"})))
			}},
		"deletePasskey": {Effect: isolation.Changes, Status: 204, Arrange: each(func(n *tn) { e.addKey(n); n.sess = e.session(n, true) }),
			CrossStatus: 404,
			Cross:       func() isolation.Result { return result(b().sess.do("DELETE", "/account/passkeys/"+a().passkeyID, nil)) },
			Call:        func() isolation.Result { return result(b().sess.do("DELETE", "/account/passkeys/"+b().passkeyID, nil)) }},
		"setPasskeyEnforcement": {Effect: isolation.Changes, Status: 200, Arrange: each(func(n *tn) { e.addKey(n); n.sess = e.session(n, true) }),
			Call: func() isolation.Result {
				return result(b().sess.do("PUT", "/account/passkey-enforcement", e.forged(map[string]any{"enabled": true})))
			}},
		"listNotifications": {Effect: isolation.Shows, Status: 200,
			Arrange: each(func(n *tn) {
				tenant, _, _ := user(n)
				n.sess = e.session(n, false)
				f.env.Scan(f.t, `INSERT INTO ctrlz.notifications (tenant_id, kind) VALUES ($1, 'test.note') RETURNING id::text`, []any{tenant}, &n.notifID)
				n.note(n.notifID)
			}),
			Sees: func() []string { return []string{b().notifID} },
			Call: func() isolation.Result { return result(b().sess.get("/notifications")) },
			// The cursor names a row (the last of a page) and carries its tenant: A's cursor on B's list is refused.
			CrossStatus: 400,
			Cross: func() isolation.Result {
				return result(b().sess.get("/notifications?cursor=" + a().cursorOf(e.f.env.A.Tenant)))
			}},
		"readNotification": {Effect: isolation.Changes, Status: 204,
			Arrange: each(func(n *tn) {
				tenant, _, _ := user(n)
				n.sess = e.session(n, false)
				f.env.Scan(f.t, `INSERT INTO ctrlz.notifications (tenant_id, kind) VALUES ($1, 'test.note') RETURNING id::text`, []any{tenant}, &n.notifID)
				n.note(n.notifID)
			}),
			Call:        func() isolation.Result { return result(b().sess.post("/notifications/"+b().notifID+"/read", nil)) },
			CrossStatus: 404,
			Cross:       func() isolation.Result { return result(b().sess.post("/notifications/"+a().notifID+"/read", nil)) }},
		"listAnnouncements": {Effect: isolation.Shows, Status: 200,
			Arrange: each(func(n *tn) {
				tenant, _, _ := user(n)
				n.sess = e.session(n, false)
				f.env.Scan(f.t, `INSERT INTO ctrlz.announcements (audience, tenant_id, body) VALUES ('tenant', $1, $2) RETURNING id::text`,
					[]any{tenant, "only for tenant " + n.who.String()}, &n.announceID)
				n.note(n.announceID)
			}),
			Sees:        func() []string { return []string{"only for tenant B"} },
			Call:        func() isolation.Result { return result(b().sess.get("/announcements")) },
			CrossStatus: 400,
			Cross: func() isolation.Result {
				return result(b().sess.get("/announcements?cursor=" + a().cursorOf(e.f.env.A.Tenant)))
			}},
		"readAnnouncement": {Effect: isolation.Changes, Status: 204,
			Arrange: each(func(n *tn) {
				tenant, _, _ := user(n)
				n.sess = e.session(n, false)
				f.env.Scan(f.t, `INSERT INTO ctrlz.announcements (audience, tenant_id, body) VALUES ('tenant', $1, $2) RETURNING id::text`,
					[]any{tenant, "only for tenant " + n.who.String()}, &n.announceID)
				n.note(n.announceID)
			}),
			Call:        func() isolation.Result { return result(b().sess.post("/announcements/"+b().announceID+"/read", nil)) },
			CrossStatus: 404,
			Cross:       func() isolation.Result { return result(b().sess.post("/announcements/"+a().announceID+"/read", nil)) }},
	}
}

// TestIsolation is T-386 and spec 18.1, rule isolation-success-coverage: one harness over
// every operation of api/openapi.yaml. An operation with no success fixture fails, which is
// how a new route is caught; so does a fixture whose B call is not 2xx, or whose call leaves
// B's own rows as they were, or that finds A in a different state from B. The refusals the old
// cases ended in proved nothing: a statement that lost its tenant predicate answers a junk
// ticket exactly as before.
func TestIsolation(t *testing.T) {
	f := newFrig(t, frigOpts{passkey: true})
	e := newIsoEnv(f)

	docOps, err := apispec.Parse(apidoc.Tenant(), ratelimit.Tenant)
	if err != nil {
		t.Fatal(err)
	}
	var ops []isolation.Op
	takes := opsThatTakeAnID(t)
	for _, op := range docOps {
		ops = append(ops, isolation.Op{ID: op.ID, Method: op.Method, Takes: strings.Join(takes[op.ID], ", "), Locations: takes[op.ID]})
	}
	A := f.env.A
	isolation.Run(t, ops, e.fixtures(), isolation.Hooks{
		Reset:  e.reset,
		Digest: e.db.Digest,
		Shape:  e.db.Shape,
		Leaks: func() []string {
			a := e.n[isolation.A]
			return append([]string{A.Tenant.String(), A.User.String(), strings.TrimPrefix(A.Phone, "+98"), "only for tenant A"}, a.notes...)
		},
		ACookie: func() string { return A.Session },
		Before:  func(w isolation.Who) any { return e.credGen(e.n[w]) },
		After:   e.ownerKeepsTheirMarker(docOps),
	})
	if t.Failed() {
		return
	}

	// The other half of the harness: the gates, on every operation.
	baselines := map[string]boundary.Case{}
	bc, err := boundary.Cases(apidoc.Tenant())
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range bc {
		if c.Baseline {
			baselines[c.Op] = c
		}
	}
	t.Run("gates", func(t *testing.T) {
		e.reset(isolation.A)
		e.reset(isolation.B)
		restricted := e.session(e.n[isolation.B], false)
		plain := e.session(e.n[isolation.B], false)
		B := f.env.B
		// A session is restricted while its user's password is a one-time one (rule
		// one-time-state): the gate asks the state the user has now. The user is put in it for
		// the call that needs it and out of it for every other.
		oneTime := func(on bool) {
			if on {
				f.env.Exec(t, `UPDATE ctrlz.users SET must_reset = true, password_expires_at = now() + interval '72 hours' WHERE id = $1`, B.User)
			} else {
				f.env.Exec(t, `UPDATE ctrlz.users SET must_reset = false, password_expires_at = NULL WHERE id = $1`, B.User)
			}
		}
		for _, op := range docOps {
			// The request is the generated baseline of the operation: it satisfies the schema,
			// so it reaches the gate under test and not the check of the pipeline before it.
			base, ok := baselines[op.ID]
			if !ok {
				t.Fatalf("%s has no generated baseline", op.ID)
			}
			call := func(c *client) *resp {
				var body any
				if base.Body != nil {
					body = base.Body
				}
				return c.do(op.Method, base.Path, body, base.Header)
			}
			if op.Auth == apispec.None {
				// A cookie sent to a route with no session is never read.
				c := f.client()
				c.jar[session.CookieSession] = plain.jar[session.CookieSession]
				if r := call(c); r.Code == http.StatusForbidden && r.code() == "reauth_required" {
					t.Errorf("%s read a session cookie", op.ID)
				}
				continue
			}
			c := f.client()
			call(c) // no cookie at all
			if r := call(c); r.Code != 401 || r.code() != "session_expired" {
				t.Errorf("%s without a cookie: %d %s", op.ID, r.Code, r.Body)
			}
			// An admin cookie and an API token are no session on this host.
			adm := f.client()
			adm.jar[session.CookieAdmin] = &http.Cookie{Name: session.CookieAdmin, Value: "x"}
			adm.hdr["Authorization"] = "Bearer czt_junk"
			if r := call(adm); r.Code != 401 || r.code() != "session_expired" {
				t.Errorf("%s with an admin cookie and a token: %d %s", op.ID, r.Code, r.Body)
			}
			if op.Auth == apispec.Reauth {
				if r := call(plain); r.Code != 403 || r.code() != "reauth_required" {
					t.Errorf("%s with a stale reauth: %d %s", op.ID, r.Code, r.Body)
				}
			}
			if op.Auth == apispec.Session || op.Auth == apispec.Reauth {
				oneTime(true)
				if r := call(restricted); r.Code != 403 || r.code() != "password_change_required" {
					t.Errorf("%s on a restricted session: %d %s", op.ID, r.Code, r.Body)
				}
				oneTime(false)
			}
			f.ck.add(time.Minute) // keep the session-keyed buckets full for the next operation
		}
	})

	// The suspended-tenant gate on EVERY operation, not on the few that happened to have a test
	// (tenant-r13-1, spec 3.5 and 18.1): GET /me answers 200 and POST /auth/logout 204, and any other
	// route that needs a session answers 403 account_suspended. A widened allowedWhileSuspended, or a
	// class of route that skips the gate, fails here for the operation it let through. Tenant A is
	// active the whole time and must keep answering what it answered.
	t.Run("a suspended tenant reaches only /me and logout", func(t *testing.T) {
		e.reset(isolation.A)
		e.reset(isolation.B)
		B := f.env.B
		f.clearThrottle()
		// The refresh cookie of a browser that asked to be remembered, taken while the tenant is active.
		remembered := f.client()
		remembered.loginPassword(B.Phone, pwB, true).want(200, "")
		f.env.Exec(t, `UPDATE ctrlz.tenants SET status = 'suspended' WHERE id = $1`, B.Tenant)
		defer f.env.Exec(t, `UPDATE ctrlz.tenants SET status = 'active' WHERE id = $1`, B.Tenant)

		for _, op := range docOps {
			if op.Auth == apispec.None {
				continue
			}
			base, ok := baselines[op.ID]
			if !ok {
				t.Fatalf("%s has no generated baseline", op.ID)
			}
			// A session that satisfies the class of the operation, so only the tenant's state can refuse it.
			c := e.session(e.n[isolation.B], op.Auth == apispec.Reauth)
			var body any
			if base.Body != nil {
				body = base.Body
			}
			r := c.do(op.Method, base.Path, body, base.Header)
			switch {
			case op.Method == http.MethodGet && op.Path == "/me":
				if r.Code != 200 {
					t.Errorf("GET /me for a suspended tenant: %d %s", r.Code, r.Body)
				}
			case op.Method == http.MethodPost && op.Path == "/auth/logout":
				if r.Code != 204 {
					t.Errorf("POST /auth/logout for a suspended tenant: %d %s", r.Code, r.Body)
				}
			default:
				if r.Code != 403 || r.code() != "account_suspended" {
					t.Errorf("%s %s (%s) for a suspended tenant: %d %s, want 403 account_suspended", op.Method, op.Path, op.ID, r.Code, r.Body)
				}
			}
			f.ck.add(time.Minute)
		}

		// A session renewed from the refresh cookie is a session like any other: the renewal itself is
		// allowed (it only swaps cookies), and the new session reaches /me and nothing else.
		f.ck.add(3 * time.Hour) // the browser was restarted: only the refresh cookie remains
		delete(remembered.jar, session.CookieSession)
		remembered.post("/auth/refresh", nil).want(204, "")
		if remembered.jar[session.CookieSession] == nil {
			t.Fatal("refresh gave no session cookie")
		}
		remembered.get("/me").want(200, "")
		remembered.get("/account/limits").want(403, "account_suspended")
		remembered.post("/auth/logout-all", nil).want(403, "account_suspended")
	})
}

// opsThatTakeAnID reads the document for the operations whose caller names a row by a value
// the client chooses (rule isolation-success-coverage, tenant-r5-5 and tenant-r6-3, -11): a path
// parameter, a query parameter or a request body property (at any depth) that is an id on an operation
// that needs a session, or the ticket header of such an operation, whose ticket belongs to one user. A
// ticket, a challenge or an invite a caller holds with no session is a bearer proof and is not listed.
//
// Round 16 (tenant-r16-13): "is an id" was a NAME (id, or ending in _id), so a session route that took
// `{"credential": <uuid>}` needed no Cross call. It is now the SCHEMA: a value of format uuid, or a
// pattern that is the document's uuid pattern, is a row reference whatever it is called, and the name
// test stays as a second way in (a name that says id is listed even where the schema is a plain
// string, because a missed row is the worse error). Every place is listed, not the first, and the
// harness asks for a Cross call for each (isolation.Op.Locations, Fixture.CrossAt).
func opsThatTakeAnID(t *testing.T) map[string][]string {
	t.Helper()
	doc, err := openapi3.NewLoader().LoadFromData(apidoc.Tenant())
	if err != nil {
		t.Fatal(err)
	}
	auth, err := apispec.Parse(apidoc.Tenant(), ratelimit.Tenant)
	if err != nil {
		t.Fatal(err)
	}
	needsSession := map[string]bool{}
	for _, op := range auth {
		needsSession[op.ID] = op.Auth != apispec.None
	}
	return idLocations(doc, needsSession)
}

// idLocations is opsThatTakeAnID over a loaded document, so that a test can feed it a made-up one.
//
// Round 16 (tenant-r16-24): a parameter was a location only in path, query and the one ticket header, so a
// session route that took a uuid in another header or in a cookie needed no Cross call. Every parameter is
// judged whatever its `in:` is, by the schema of the parameter (or of its content), at any depth.
func idLocations(doc *openapi3.T, needsSession map[string]bool) map[string][]string {
	out := map[string][]string{}
	for _, item := range doc.Paths.Map() {
		for _, op := range item.Operations() {
			session := needsSession[op.OperationID]
			var locs []string
			params := append(openapi3.Parameters{}, item.Parameters...)
			params = append(params, op.Parameters...)
			for _, pr := range params {
				if pr.Value == nil {
					continue
				}
				name := pr.Value.Name
				base := pr.Value.In + ":" + name
				switch {
				case pr.Value.In == "path":
					locs = append(locs, base)
				case !session:
					// A ticket, a challenge or an invite a caller holds with no session is a bearer proof.
				case pr.Value.In == "header" && name == "X-Ctrlz-Ticket":
					locs = append(locs, base)
				default:
					if isIDName(name) {
						locs = append(locs, base)
					}
					roots := []*openapi3.SchemaRef{pr.Value.Schema}
					for _, mt := range pr.Value.Content {
						roots = append(roots, mt.Schema)
					}
					for _, root := range roots {
						for _, p := range schemaRefs(root, true) {
							locs = append(locs, base+p)
						}
					}
				}
			}
			if session {
				locs = append(locs, bodyIDs(op)...)
			}
			if len(locs) > 0 {
				sort.Strings(locs)
				out[op.OperationID] = slices.Compact(locs)
			}
		}
	}
	return out
}

// uuidPattern is the pattern the document gives a uuid (api/openapi.yaml, the *uuid anchor).
const uuidPattern = `^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`

// isUUIDSchema says a value is a uuid: it is declared as one, or it is held to the pattern of one.
func isUUIDSchema(s *openapi3.SchemaRef) bool {
	return s != nil && s.Value != nil && (s.Value.Format == "uuid" || s.Value.Pattern == uuidPattern)
}

// rowRefMark is the extension that classifies a string input of a session operation (round 17, tenant-r17-6 and
// -11). Round 16 found a row reference by its schema (a uuid) or its name (id), and said "a value that is a row
// reference but is neither is not found". That is a detector with a hole, so it is now an allow list: every
// string input of a session operation is a uuid, an enum, or carries this mark, true for a value that names a row
// (the harness then asks for a Cross call at that place) and false for one that does not (a password, a code, a
// label, a part of a WebAuthn answer). A string with no mark fails TestEverySessionStringIsClassified, so a
// handle, a token or a cursor of any name and shape is a decision somebody wrote in the document.
const rowRefMark = "x-ctrlz-rowref"

// rowRefMarked returns the value of the mark, and whether the schema carries one that is a boolean.
func rowRefMarked(s *openapi3.SchemaRef) (value, ok bool) {
	if s == nil || s.Value == nil {
		return false, false
	}
	v, present := s.Value.Extensions[rowRefMark]
	if !present {
		return false, false
	}
	// kin-openapi keeps an extension as raw JSON until it is read.
	switch x := v.(type) {
	case bool:
		return x, true
	case json.RawMessage:
		var b bool
		if json.Unmarshal(x, &b) == nil {
			return b, true
		}
	}
	return false, false
}

// isRowRefSchema says a value names a row: a uuid, or a string the document marks as one.
func isRowRefSchema(s *openapi3.SchemaRef) bool {
	if isUUIDSchema(s) {
		return true
	}
	v, ok := rowRefMarked(s)
	return ok && v
}

// unclassifiedStrings lists every string input of an operation that needs a session (a parameter's schema or
// content, a request body, at any depth) that is neither a uuid, nor an enum or a constant, nor marked. A type
// list that includes "string" (a nullable string) counts as a string.
func unclassifiedStrings(doc *openapi3.T, needsSession map[string]bool) []string {
	var out []string
	for _, item := range doc.Paths.Map() {
		for _, op := range item.Operations() {
			if !needsSession[op.OperationID] {
				continue
			}
			type root struct {
				name string
				ref  *openapi3.SchemaRef
			}
			var roots []root
			params := append(openapi3.Parameters{}, item.Parameters...)
			params = append(params, op.Parameters...)
			for _, pr := range params {
				if pr.Value == nil {
					continue
				}
				base := pr.Value.In + ":" + pr.Value.Name
				roots = append(roots, root{base, pr.Value.Schema})
				for _, mt := range pr.Value.Content {
					roots = append(roots, root{base, mt.Schema})
				}
			}
			if op.RequestBody != nil && op.RequestBody.Value != nil {
				for _, mt := range op.RequestBody.Value.Content {
					roots = append(roots, root{"body", mt.Schema})
				}
			}
			for _, r := range roots {
				seen := map[*openapi3.Schema]bool{}
				var walk func(s *openapi3.SchemaRef, path string)
				walk = func(s *openapi3.SchemaRef, path string) {
					if s == nil || s.Value == nil || seen[s.Value] {
						return
					}
					seen[s.Value] = true
					defer delete(seen, s.Value)
					sv := s.Value
					isString := sv.Type != nil && sv.Type.Includes("string")
					closed := len(sv.Enum) > 0 || sv.Const != nil
					if _, marked := rowRefMarked(s); isString && !closed && !isUUIDSchema(s) && !marked {
						out = append(out, op.OperationID+" "+r.name+path)
					}
					for _, sub := range subSchemas(sv) {
						walk(sub.ref, path+sub.seg)
					}
				}
				walk(r.ref, "")
			}
		}
	}
	sort.Strings(out)
	return slices.Compact(out)
}

// isIDName says a property or parameter name is one that names a row.
func isIDName(n string) bool { return n == "id" || strings.HasSuffix(n, "_id") }

// bodyIDs returns every property of the request body, at any depth, that is a row reference, as
// "body:outer.inner" (an array item adds "[]", a map value "{}").
func bodyIDs(op *openapi3.Operation) []string {
	if op.RequestBody == nil || op.RequestBody.Value == nil {
		return nil
	}
	var found []string
	for _, mt := range op.RequestBody.Value.Content {
		for _, p := range schemaRefs(mt.Schema, false) {
			found = append(found, "body:"+strings.TrimPrefix(p, "."))
		}
	}
	return found
}

// subSchema is a schema one keyword below another, and the path segment that keyword adds to a location: a
// property name adds ".name", an array item (items, prefixItems) adds "[]", an additionalProperties value
// adds "{}", and a combinator (allOf, oneOf, anyOf, not, if, then, ...) adds nothing.
type subSchema struct {
	ref *openapi3.SchemaRef
	seg string
}

var (
	schemaRefType  = reflect.TypeOf((*openapi3.SchemaRef)(nil))
	schemaRefsType = reflect.TypeOf(openapi3.SchemaRefs{})
	boolSchemaType = reflect.TypeOf(openapi3.BoolSchema{})
)

// subSchemas finds every schema below s by reflection over the fields of openapi3.Schema, so a keyword the
// library has or adds (additionalProperties, prefixItems, patternProperties, unevaluatedItems, not, ...) is
// walked without a line here (tenant-r16-24: the walk was a list of the keywords somebody remembered). A field
// whose type holds a SchemaRef in a shape this function does not read is an error and not a pass.
func subSchemas(s *openapi3.Schema) []subSchema {
	var out []subSchema
	v := reflect.ValueOf(s).Elem()
	for i := 0; i < v.NumField(); i++ {
		f, name := v.Field(i), v.Type().Field(i).Name
		seg := ""
		switch name {
		case "Items", "PrefixItems":
			seg = "[]"
		case "AdditionalProperties":
			seg = "{}"
		}
		switch f.Type() {
		case schemaRefType:
			if !f.IsNil() {
				out = append(out, subSchema{f.Interface().(*openapi3.SchemaRef), seg})
			}
		case schemaRefsType:
			for j := 0; j < f.Len(); j++ {
				out = append(out, subSchema{f.Index(j).Interface().(*openapi3.SchemaRef), seg})
			}
		case boolSchemaType:
			if b := f.Interface().(openapi3.BoolSchema); b.Schema != nil {
				out = append(out, subSchema{b.Schema, seg})
			}
		default:
			if f.Kind() == reflect.Map && f.Type().Elem() == schemaRefType {
				for _, k := range f.MapKeys() {
					out = append(out, subSchema{f.MapIndex(k).Interface().(*openapi3.SchemaRef), "." + k.String()})
				}
			} else if strings.Contains(f.Type().String(), "SchemaRef") || strings.Contains(f.Type().String(), "BoolSchema") {
				panic("the schema walk does not read the field " + name + " of type " + f.Type().String() + ": teach it, do not skip it")
			}
		}
	}
	return out
}

// schemaRefs returns the path of every row reference at or below a schema: a value of format uuid or of the
// document's uuid pattern, whatever it is called, and a property whose name says id (only on a property). The
// root counts when rootCounts is set (a parameter whose own schema is a uuid). Paths start with the first
// segment, "" for the root itself.
func schemaRefs(root *openapi3.SchemaRef, rootCounts bool) []string {
	var found []string
	seen := map[*openapi3.Schema]bool{}
	var walk func(s *openapi3.SchemaRef, path string, isRoot bool)
	walk = func(s *openapi3.SchemaRef, path string, isRoot bool) {
		if s == nil || s.Value == nil || seen[s.Value] {
			return
		}
		seen[s.Value] = true
		defer delete(seen, s.Value)
		if (!isRoot || rootCounts) && isRowRefSchema(s) {
			found = append(found, path)
		}
		for _, sub := range subSchemas(s.Value) {
			p := path + sub.seg
			if strings.HasPrefix(sub.seg, ".") && isIDName(sub.seg[1:]) {
				found = append(found, p)
			}
			walk(sub.ref, p, false)
		}
	}
	walk(root, "", true)
	return found
}

// credGen is credential_gen of the tenant's user.
func (e *isoEnv) credGen(n *tn) int64 {
	_, user, _ := e.ids(n)
	var g int64
	e.f.env.Scan(e.f.t, `SELECT credential_gen FROM ctrlz.users WHERE id = $1`, []any{user}, &g)
	return g
}

// ownerKeepsTheirMarker is the check of tenant-r5-10, over every operation: a call that is made
// from a signed-in browser and moves the credential generation of the account (a second factor,
// Enforce Passkey, the last passkey, the password, the phone) ends every device marker of the
// account, and so the owner's own. The browser that made the change must get a marker for the
// new generation back, or the owner loses the known-device exemption of 5.5 until the next login.
// A route that has no browser behind it (a reset, a login) is not asked.
func (e *isoEnv) ownerKeepsTheirMarker(ops []apispec.Operation) func(id string, w isolation.Who, before any, r isolation.Result) []string {
	auth := map[string]apispec.Auth{}
	for _, op := range ops {
		auth[op.ID] = op.Auth
	}
	markers := marker.New(e.f.keys, e.f.ck.now)
	return func(id string, w isolation.Who, before any, r isolation.Result) []string {
		n := e.n[w]
		g := e.credGen(n)
		if a, ok := auth[id]; !ok || a == apispec.None || g == before.(int64) {
			return nil
		}
		tenant, user, _ := e.ids(n)
		for _, c := range (&http.Response{Header: http.Header{"Set-Cookie": r.Set}}).Cookies() {
			if c.Name == session.CookieDevice && markers.Open(marker.User, c.Value).Holds(credgen.Stamp{Tenant: tenant, Subject: user, Gen: g}) {
				return nil
			}
		}
		return []string{fmt.Sprintf("%s moved the credential generation of the account from %d to %d and gave the browser no device marker for the new one", id, before, g)}
	}
}

// cursorOf is the cursor of a page that ends at the row this tenant's fixture planted (a notification, or an
// announcement), as the tenant that was given it would have received it.
func (n *tn) cursorOf(tenant uuid.UUID) string {
	id := n.notifID
	if id == "" {
		id = n.announceID
	}
	return encodeCursor(tenant, time.Now(), uuid.MustParse(id))
}
