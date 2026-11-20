package login_test

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/login"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/marker"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/otp"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/session"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/ticket"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/token"
	"github.com/Kup1ng/CtrlZ-Panel/internal/authtest"
	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

var cluster *testpg.Cluster

func TestMain(m *testing.M) {
	os.Exit(testpg.RunMain(m, func(c *testpg.Cluster) { cluster = c }))
}

var ip = netip.MustParseAddr("198.51.100.7")

const code = "012345"

type rig struct {
	t       *testing.T
	env     *authtest.Env
	tenant  *store.Store
	svc     *login.Service
	otp     *otp.Service
	tickets *ticket.Service
}

func newRig(t *testing.T) *rig {
	t.Helper()
	env := authtest.New(t, cluster)
	env.ResetSMS(t)
	ring, err := keyring.NewEphemeral(keyring.DomainAuthMAC, keyring.DomainOTPDelivery)
	if err != nil {
		t.Fatal(err)
	}
	wring, _ := keyring.NewEphemeral(keyring.DomainSMSCred)
	env.AddGateway(t, wring, authtest.Gateway{Provider: "noop", Role: "primary"})
	tenant := env.Tenant(t)
	cfg := func(ctx context.Context) (store.PublicConfig, error) { return tenant.Auth().PublicConfig(ctx) }
	o, err := otp.New(tenant.Auth(), ring, cfg, otp.WithCodeSource(func() (secret.String, error) { return secret.New(code), nil }))
	if err != nil {
		t.Fatal(err)
	}
	tk := ticket.New(tenant.Auth())
	return &rig{t: t, env: env, tenant: tenant, otp: o, tickets: tk, svc: &login.Service{
		DB: tenant, Auth: tenant.Auth(), OTP: o, Sessions: session.NewManager(tenant, session.DefaultPolicy(), nil), Tickets: tk, Markers: marker.New(ring, nil), Config: cfg,
	}}
}

func (r *rig) userLogin(phone string) store.UserLogin {
	r.t.Helper()
	u, ok, err := r.tenant.Auth().UserByPhone(r.env.Ctx, phone)
	if err != nil || !ok {
		r.t.Fatalf("UserByPhone: %v %v", ok, err)
	}
	return u
}

func (r *rig) password(phone string, remember bool) (login.Result, error) {
	return r.svc.AfterFirstFactor(r.env.Ctx, login.Input{
		User: r.userLogin(phone), Factor: login.Password, Remember: remember, IP: ip, UserAgent: "test-agent/1.0",
	})
}

func (r *rig) sessions(tenant, user uuid.UUID) []store.SessionRow {
	r.t.Helper()
	var out []store.SessionRow
	err := r.tenant.WithTenant(r.env.Ctx, tenant, store.TxOpts{ReadOnly: true}, func(tx store.Tx) (err error) {
		out, err = tx.SessionsList(user, time.Now())
		return err
	})
	if err != nil {
		r.t.Fatal(err)
	}
	return out
}

func (r *rig) liveCount(tenant, user uuid.UUID) int {
	n := 0
	for _, s := range r.sessions(tenant, user) {
		if s.RevokedAt == nil {
			n++
		}
	}
	return n
}

func (r *rig) count(sql string, args ...any) int {
	r.t.Helper()
	var n int
	if err := r.env.DB.Scan(r.env.Ctx, sql, args, &n); err != nil {
		r.t.Fatal(err)
	}
	return n
}

func cookie(cs []*http.Cookie, name string) *http.Cookie {
	for _, c := range cs {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func TestPasswordLoginOpensASession(t *testing.T) {
	r := newRig(t)
	a, b := r.env.A, r.env.B
	before := len(r.sessions(a.Tenant, a.User))
	beforeB := len(r.sessions(b.Tenant, b.User))

	res, err := r.password(a.Phone, false)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != login.Authenticated || res.Restricted {
		t.Fatalf("%+v", res)
	}
	rows := r.sessions(a.Tenant, a.User)
	if len(rows) != before+1 {
		t.Fatalf("sessions %d -> %d", before, len(rows))
	}
	// Cookies: the session, the device marker, and a deletion of the refresh
	// cookie rather than a refresh token (primitives-r3-7).
	s := cookie(res.Cookies, session.CookieSession)
	rc := cookie(res.Cookies, session.CookieRefresh)
	if s == nil || cookie(res.Cookies, session.CookieDevice) == nil || rc == nil || rc.Value != "" || rc.MaxAge >= 0 {
		t.Fatalf("cookies: %+v", res.Cookies)
	}
	// The cookie is the live session: the lookup finds it.
	info, ok, err := r.tenant.Auth().SessionByHash(r.env.Ctx, hashOf(s.Value))
	if err != nil || !ok || info.UserID != a.User || info.TenantID != a.Tenant || info.State.OneTime() {
		t.Errorf("lookup: %+v %v %v", info, ok, err)
	}
	if r.count(`SELECT count(*) FROM ctrlz.sessions WHERE auth_method = 'password' AND user_agent = 'test-agent/1.0' AND ip = '198.51.100.7'`) != 1 {
		t.Error("method, agent or address not recorded")
	}
	// last_login_at and the audit row, written with the session.
	if r.count(`SELECT count(*) FROM ctrlz.users WHERE id = $1 AND last_login_at IS NOT NULL`, a.User) != 1 {
		t.Error("last_login_at not set")
	}
	if r.count(`SELECT count(*) FROM ctrlz.tenant_audit_log WHERE tenant_id = $1 AND action = 'login.ok' AND params ->> 'method' = 'password'
	  AND params ->> 'session_id' = $2`, a.Tenant, res.Session.SessionID.String()) != 1 {
		t.Error("login.ok audit row missing or without its params")
	}
	// Tenant B did not move.
	if len(r.sessions(b.Tenant, b.User)) != beforeB || r.count(`SELECT count(*) FROM ctrlz.users WHERE id = $1 AND last_login_at IS NOT NULL`, b.User) != 0 {
		t.Error("tenant B changed")
	}
	// A session cookie sent by the browser before login is ignored: the new token
	// is a fresh one, and the only cookie we ever set (no fixation).
	res2, _ := r.password(a.Phone, false)
	if cookie(res2.Cookies, session.CookieSession).Value == s.Value {
		t.Error("a second login reused the token")
	}
}

func TestRememberMeAddsARefreshCookie(t *testing.T) {
	r := newRig(t)
	res, err := r.password(r.env.A.Phone, true)
	if err != nil {
		t.Fatal(err)
	}
	c := cookie(res.Cookies, session.CookieRefresh)
	if c == nil || c.MaxAge < int((29*24*time.Hour).Seconds()) {
		t.Fatalf("refresh cookie: %+v", c)
	}
	if r.count(`SELECT count(*) FROM ctrlz.refresh_tokens WHERE session_id = $1`, res.Session.SessionID) != 1 {
		t.Error("no refresh row")
	}
}

func TestMustResetOpensARestrictedSession(t *testing.T) {
	r := newRig(t)
	r.env.Exec(t, `UPDATE ctrlz.users SET must_reset = true, password_expires_at = now() + interval '72 hours' WHERE id = $1`, r.env.A.User)
	res, err := r.password(r.env.A.Phone, false)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != login.Authenticated || !res.Restricted {
		t.Fatalf("%+v", res)
	}
	info, _, _ := r.tenant.Auth().SessionByHash(r.env.Ctx, hashOf(cookie(res.Cookies, session.CookieSession).Value))
	if !info.State.OneTime() {
		t.Error("the session is not restricted")
	}
}

func TestTOTPUserGetsAnMFATicketAndNoSession(t *testing.T) {
	r := newRig(t)
	a := r.env.A
	r.env.Exec(t, `UPDATE ctrlz.users SET totp_enabled_at = now(), totp_secret_ct = '\x01' WHERE id = $1`, a.User)
	before := len(r.sessions(a.Tenant, a.User))
	res, err := r.password(a.Phone, true)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != login.MFARequired || res.Ticket.IsZero() || res.TicketTTL != 5*time.Minute || len(res.Methods) != 2 || res.Methods[0] != "totp" || res.Methods[1] != "recovery_code" {
		t.Fatalf("%+v", res)
	}
	if len(res.Cookies) != 0 || res.Session.SessionID != uuid.Nil {
		t.Error("a half-logged-in user got a cookie")
	}
	if len(r.sessions(a.Tenant, a.User)) != before {
		t.Error("a session was created before the second factor")
	}
	// The ticket belongs to this user and carries the choice made at the first factor.
	tk, ok, err := r.tickets.Take(r.env.Ctx, res.Ticket.Reveal(), store.TicketMFA)
	if err != nil || !ok || tk.User != a.User || tk.Tenant != a.Tenant || !tk.RememberMe || tk.FirstFactor != "password" {
		t.Fatalf("ticket: %+v %v %v", tk, ok, err)
	}
	if _, ok, _ := r.tickets.Take(r.env.Ctx, res.Ticket.Reveal(), store.TicketMFA); ok {
		t.Error("a ticket was taken twice")
	}
	// An mfa ticket is not a reset ticket.
	res2, _ := r.password(a.Phone, false)
	if _, ok, _ := r.tickets.Take(r.env.Ctx, res2.Ticket.Reveal(), store.TicketReset); ok {
		t.Error("the mfa ticket worked as a reset ticket")
	}
}

func TestEnforcePasskey(t *testing.T) {
	r := newRig(t)
	a := r.env.A
	// The seeded credential has rp_id example.test. Make it the live RP ID.
	r.env.Exec(t, `UPDATE ctrlz.webauthn_config SET rp_id = 'example.test', allowed_origins = '{https://example.test}', enabled = true`)
	r.env.Exec(t, `UPDATE ctrlz.users SET enforce_passkey = true WHERE id = $1`, a.User)
	before := len(r.sessions(a.Tenant, a.User))

	res, err := r.password(a.Phone, false)
	if err != nil || res.Status != login.PasskeyRequired || len(res.Cookies) != 0 || res.Ticket.Reveal() != "" {
		t.Fatalf("enforce: %+v %v", res, err)
	}
	if len(r.sessions(a.Tenant, a.User)) != before {
		t.Error("Enforce let a session through")
	}
	// Enforce comes before TOTP: a user with both gets the passkey prompt.
	r.env.Exec(t, `UPDATE ctrlz.users SET totp_enabled_at = now(), totp_secret_ct = '\x01' WHERE id = $1`, a.User)
	if res, _ := r.password(a.Phone, false); res.Status != login.PasskeyRequired {
		t.Errorf("enforce + totp: %v", res.Status)
	}
	r.env.Exec(t, `UPDATE ctrlz.users SET totp_enabled_at = NULL, totp_secret_ct = NULL WHERE id = $1`, a.User)

	// A lift that is still in the future leaves Enforce in force.
	r.env.Exec(t, `UPDATE ctrlz.users SET enforce_lift_at = now() + interval '1 hour' WHERE id = $1`, a.User)
	if res, _ := r.password(a.Phone, false); res.Status != login.PasskeyRequired {
		t.Errorf("pending lift: %v", res.Status)
	}
	// Once the lift time has passed, the login that opens the session also turns
	// Enforce off and forgets the lift (5.7).
	r.env.Exec(t, `UPDATE ctrlz.users SET enforce_lift_at = now() - interval '1 second' WHERE id = $1`, a.User)
	res, err = r.password(a.Phone, false)
	if err != nil || res.Status != login.Authenticated {
		t.Fatalf("after the lift: %+v %v", res, err)
	}
	if r.count(`SELECT count(*) FROM ctrlz.users WHERE id = $1 AND NOT enforce_passkey AND enforce_lift_at IS NULL`, a.User) != 1 {
		t.Error("the login did not clear Enforce")
	}
}

func TestEnforceWithNoLiveCredentialDoesNotLockOut(t *testing.T) {
	r := newRig(t)
	a := r.env.A
	r.env.Exec(t, `UPDATE ctrlz.users SET enforce_passkey = true WHERE id = $1`, a.User)

	// Passkeys are off: the credential is not live, so Enforce is not in force.
	if res, err := r.password(a.Phone, false); err != nil || res.Status != login.Authenticated {
		t.Errorf("passkeys disabled: %+v %v", res, err)
	}
	// On, but for another RP ID than the credential's (the RP ID changed and the
	// worker has not marked it stale yet): not live either (7.4).
	r.env.Exec(t, `UPDATE ctrlz.webauthn_config SET rp_id = 'other.test', allowed_origins = '{https://other.test}', enabled = true`)
	if res, err := r.password(a.Phone, false); err != nil || res.Status != login.Authenticated {
		t.Errorf("rp mismatch: %+v %v", res, err)
	}
	// A stale credential is not live.
	r.env.Exec(t, `UPDATE ctrlz.webauthn_config SET rp_id = 'example.test', allowed_origins = '{https://example.test}'`)
	r.env.Exec(t, `UPDATE ctrlz.webauthn_credentials SET stale_at = now() WHERE user_id = $1`, a.User)
	if res, err := r.password(a.Phone, false); err != nil || res.Status != login.Authenticated {
		t.Errorf("stale: %+v %v", res, err)
	}
}

func TestSuspendedTenant(t *testing.T) {
	r := newRig(t)
	a := r.env.A
	before := len(r.sessions(a.Tenant, a.User))
	r.env.Exec(t, `UPDATE ctrlz.tenants SET status = 'suspended' WHERE id = $1`, a.Tenant)
	if _, err := r.password(a.Phone, false); !errors.Is(err, login.ErrAccountSuspended) {
		t.Errorf("password: %v", err)
	}
	// The OTP path does not say it: a suspended tenant's OTP request was a decoy.
	_, err := r.svc.AfterFirstFactor(r.env.Ctx, login.Input{User: r.userLogin(a.Phone), Factor: login.OTP, IP: ip})
	if !errors.Is(err, login.ErrRefused) {
		t.Errorf("otp: %v", err)
	}
	r.env.Exec(t, `UPDATE ctrlz.tenants SET status = 'deleting' WHERE id = $1`, a.Tenant)
	if _, err := r.password(a.Phone, false); !errors.Is(err, login.ErrAccountSuspended) {
		t.Errorf("deleting: %v", err)
	}
	if len(r.sessions(a.Tenant, a.User)) != before {
		t.Error("a session was created for a tenant that may not log in")
	}
}

// TestReissueDuringLogin is 5.7's rule: a login that verified a one-time
// password cannot open a session after an admin replaced it.
func TestReissueAfterVerifyRefusesTheLogin(t *testing.T) {
	r := newRig(t)
	a := r.env.A
	// A user with a one-time password has no passkey (the re-issue refuses one, 10.7).
	r.env.Exec(t, `DELETE FROM ctrlz.webauthn_credentials WHERE user_id = $1`, a.User)
	r.env.Exec(t, `UPDATE ctrlz.users SET must_reset = true, password_expires_at = now() + interval '10 hours' WHERE id = $1`, a.User)
	snapshot := r.userLogin(a.Phone) // what the route verified the password against

	admin := r.env.Admin(t)
	if err := admin.WithTenant(r.env.Ctx, a.Tenant, store.TxOpts{}, func(tx store.Tx) error {
		if _, err := tx.OneTimePasswordSet(a.User, secret.New("argon2id$replacement")); err != nil {
			return err
		}
		_, err := tx.RevokeUserSessions(a.User)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	before := r.liveCount(a.Tenant, a.User)
	_, err := r.svc.AfterFirstFactor(r.env.Ctx, login.Input{User: snapshot, Factor: login.Password, IP: ip})
	if !errors.Is(err, login.ErrInvalidCredentials) {
		t.Fatalf("a login against a replaced one-time password: %v", err)
	}
	if r.liveCount(a.Tenant, a.User) != before {
		t.Error("a session was opened with the replaced password")
	}
	// The same snapshot over an OTP is not affected: an OTP proves the phone, and
	// the one-time password is not what was checked.
	otpRes, err := r.svc.AfterFirstFactor(r.env.Ctx, login.Input{User: snapshot, Factor: login.OTP, OTPChallenge: r.consumedChallenge(a.Phone), IP: ip})
	if err != nil || otpRes.Status != login.Authenticated || !otpRes.Restricted {
		t.Errorf("otp after a re-issue: %+v %v", otpRes, err)
	}
}

func (r *rig) consumedChallenge(phone string) uuid.UUID {
	r.t.Helper()
	ch, err := r.otp.Request(r.env.Ctx, otp.Request{Phone: phone, Purpose: otp.Login, Locale: "fa", IP: ip})
	if err != nil {
		r.t.Fatal(err)
	}
	if err := r.otp.Check(r.env.Ctx, ch.ID, phone, otp.Login, code); err != nil {
		r.t.Fatal(err)
	}
	return ch.ID
}

func TestOTPLogin(t *testing.T) {
	r := newRig(t)
	a, b := r.env.A, r.env.B
	ch, err := r.otp.Request(r.env.Ctx, otp.Request{Phone: a.Phone, Purpose: otp.Login, Locale: "fa", IP: ip})
	if err != nil {
		t.Fatal(err)
	}
	in := login.OTPLoginInput{Phone: a.Phone, ChallengeID: ch.ID, Code: "999999", IP: ip, UserAgent: "ua"}
	if _, err := r.svc.OTPLogin(r.env.Ctx, in); !errors.Is(err, otp.ErrInvalid) {
		t.Fatalf("wrong code: %v", err)
	}
	// A's challenge under B's phone: no.
	bad := in
	bad.Phone, bad.Code = b.Phone, code
	if _, err := r.svc.OTPLogin(r.env.Ctx, bad); !errors.Is(err, otp.ErrInvalid) {
		t.Errorf("another tenant's phone: %v", err)
	}
	if r.count(`SELECT count(*) FROM ctrlz.users WHERE phone_verified_at IS NOT NULL`) != 0 {
		t.Fatal("a failed login verified a phone")
	}

	in.Code = code
	in.Remember = true
	res, err := r.svc.OTPLogin(r.env.Ctx, in)
	if err != nil || res.Status != login.Authenticated {
		t.Fatalf("%+v %v", res, err)
	}
	if cookie(res.Cookies, session.CookieRefresh) == nil {
		t.Error("remember me: no refresh cookie")
	}
	if r.count(`SELECT count(*) FROM ctrlz.sessions WHERE id = $1 AND auth_method = 'otp'`, res.Session.SessionID) != 1 {
		t.Error("the session does not say it came from an OTP")
	}
	if r.count(`SELECT count(*) FROM ctrlz.users WHERE id = $1 AND phone_verified_at IS NOT NULL`, a.User) != 1 {
		t.Error("the phone was not marked verified")
	}
	if r.count(`SELECT count(*) FROM ctrlz.users WHERE id = $1 AND phone_verified_at IS NOT NULL`, b.User) != 0 {
		t.Error("B's phone was marked verified")
	}
	// The code is single use.
	if _, err := r.svc.OTPLogin(r.env.Ctx, in); !errors.Is(err, otp.ErrExpired) {
		t.Errorf("reuse: %v", err)
	}
}

func TestOTPLoginWithTOTPGivesATicketThatRemembersTheFactor(t *testing.T) {
	r := newRig(t)
	a := r.env.A
	r.env.Exec(t, `UPDATE ctrlz.users SET totp_enabled_at = now(), totp_secret_ct = '\x01' WHERE id = $1`, a.User)
	ch, _ := r.otp.Request(r.env.Ctx, otp.Request{Phone: a.Phone, Purpose: otp.Login, Locale: "fa", IP: ip})
	res, err := r.svc.OTPLogin(r.env.Ctx, login.OTPLoginInput{Phone: a.Phone, ChallengeID: ch.ID, Code: code, IP: ip})
	if err != nil || res.Status != login.MFARequired {
		t.Fatalf("%+v %v", res, err)
	}
	tk, ok, _ := r.tickets.Take(r.env.Ctx, res.Ticket.Reveal(), store.TicketMFA)
	if !ok || tk.FirstFactor != "otp" {
		t.Errorf("ticket: %+v", tk)
	}
	// The phone is proven even though the login is not finished.
	if r.count(`SELECT count(*) FROM ctrlz.users WHERE id = $1 AND phone_verified_at IS NOT NULL`, a.User) != 1 {
		t.Error("the phone was not marked verified")
	}
}

func TestOpenSessionAfterTheSecondFactor(t *testing.T) {
	r := newRig(t)
	a := r.env.A
	r.env.Exec(t, `UPDATE ctrlz.webauthn_config SET rp_id = 'example.test', allowed_origins = '{https://example.test}', enabled = true`)
	r.env.Exec(t, `UPDATE ctrlz.users SET must_reset = true, password_expires_at = now() + interval '1 hour',
	  enforce_passkey = true, enforce_lift_at = now() - interval '1 second' WHERE id = $1`, a.User)
	var iss session.Issued
	var restricted bool
	err := r.tenant.WithTenant(r.env.Ctx, a.Tenant, store.TxOpts{}, func(tx store.Tx) (err error) {
		iss, restricted, err = r.svc.OpenSession(tx, a.User, "password", false, ip, "ua")
		return err
	})
	if err != nil || !restricted || iss.SessionID == uuid.Nil {
		t.Fatalf("%+v %v %v", iss, restricted, err)
	}
	if r.count(`SELECT count(*) FROM ctrlz.sessions WHERE id = $1 AND restricted`, iss.SessionID) != 1 {
		t.Error("restricted not taken from the locked row")
	}
	if r.count(`SELECT count(*) FROM ctrlz.users WHERE id = $1 AND NOT enforce_passkey AND enforce_lift_at IS NULL`, a.User) != 1 {
		t.Error("an Enforce whose delay passed was not cleared")
	}
	// B's user id under A's tenant is not found.
	err = r.tenant.WithTenant(r.env.Ctx, a.Tenant, store.TxOpts{}, func(tx store.Tx) error {
		_, _, err := r.svc.OpenSession(tx, r.env.B.User, "password", false, ip, "ua")
		return err
	})
	if !errors.Is(err, login.ErrInvalidCredentials) {
		t.Errorf("another tenant's user: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Registration

func (r *rig) setMode(mode string) {
	r.env.Exec(r.t, `UPDATE ctrlz.system_settings SET registration_mode = $1`, mode)
}

func (r *rig) challenge(phone string, p otp.Purpose) uuid.UUID {
	r.t.Helper()
	ch, err := r.otp.Request(r.env.Ctx, otp.Request{Phone: phone, Purpose: p, Locale: "fa", IP: ip})
	if err != nil {
		r.t.Fatalf("request: %v", err)
	}
	return ch.ID
}

func TestRegisterInOpenMode(t *testing.T) {
	r := newRig(t)
	r.setMode("open")
	phone := "+989127000001"
	tenantsBefore := r.count(`SELECT count(*) FROM ctrlz.tenants`)
	id := r.challenge(phone, otp.Signup)

	// A wrong code creates nothing.
	_, err := r.svc.Register(r.env.Ctx, login.RegisterInput{Phone: phone, Via: "open", ChallengeID: id, Code: "999999", Locale: "en", IP: ip})
	if !errors.Is(err, otp.ErrInvalid) || r.count(`SELECT count(*) FROM ctrlz.tenants`) != tenantsBefore {
		t.Fatalf("wrong code: %v", err)
	}
	res, err := r.svc.Register(r.env.Ctx, login.RegisterInput{
		Phone: phone, Via: "open", ChallengeID: id, Code: code, PasswordHash: secret.New("argon2id$registered"), Locale: "en", IP: ip, UserAgent: "ua",
	})
	if err != nil || res.Status != login.Authenticated {
		t.Fatalf("%+v %v", res, err)
	}
	if r.count(`SELECT count(*) FROM ctrlz.tenants`) != tenantsBefore+1 {
		t.Error("no tenant was created")
	}
	if r.count(`SELECT count(*) FROM ctrlz.users WHERE phone_e164 = $1 AND password_hash = 'argon2id$registered' AND locale = 'en'
	  AND phone_verified_at IS NOT NULL AND NOT must_reset`, phone) != 1 {
		t.Error("the user row is not as registered")
	}
	if r.count(`SELECT count(*) FROM ctrlz.tenant_audit_log WHERE action = 'register' AND params ->> 'via' = 'open'`) != 1 ||
		r.count(`SELECT count(*) FROM ctrlz.tenant_audit_log WHERE action = 'login.ok' AND params ->> 'method' = 'otp'`) != 1 {
		t.Error("audit rows")
	}
	if cookie(res.Cookies, session.CookieSession) == nil || cookie(res.Cookies, session.CookieDevice) == nil {
		t.Errorf("cookies: %+v", res.Cookies)
	}
	// The new session belongs to the new tenant only.
	var tenant, user uuid.UUID
	r.env.Scan(t, `SELECT tenant_id, id FROM ctrlz.users WHERE phone_e164 = $1`, []any{phone}, &tenant, &user)
	if tenant == r.env.A.Tenant || tenant == r.env.B.Tenant || r.liveCount(tenant, user) != 1 {
		t.Error("session or tenant wrong")
	}
	if len(r.sessions(r.env.A.Tenant, r.env.A.User)) != 1 || len(r.sessions(r.env.B.Tenant, r.env.B.User)) != 1 {
		t.Error("A or B changed")
	}
}

func TestRegisterWithoutAPasswordIsOTPOnly(t *testing.T) {
	r := newRig(t)
	r.setMode("open")
	phone := "+989127000002"
	id := r.challenge(phone, otp.Signup)
	if _, err := r.svc.Register(r.env.Ctx, login.RegisterInput{Phone: phone, Via: "open", ChallengeID: id, Code: code, Locale: "fa", IP: ip}); err != nil {
		t.Fatal(err)
	}
	// NULL, not an empty string: auth_user_flags and the login path both read it as
	// "no password".
	if r.count(`SELECT count(*) FROM ctrlz.users WHERE phone_e164 = $1 AND password_hash IS NULL`, phone) != 1 {
		t.Error("an OTP-only account must have a NULL hash")
	}
	u := r.userLogin(phone)
	if !u.PasswordHash.IsZero() {
		t.Error("the login path sees a password")
	}
}

func TestRegisterRefusalsLookLikeAWrongCode(t *testing.T) {
	r := newRig(t)
	r.setMode("open")
	tenantsBefore := r.count(`SELECT count(*) FROM ctrlz.tenants`)

	// A taken number: the challenge carried an "account exists" message and its
	// code is known to nobody. Even a guess that happens to be right is refused
	// by the function, with the error of a wrong code.
	id := r.challenge(r.env.A.Phone, otp.Signup)
	_, err := r.svc.Register(r.env.Ctx, login.RegisterInput{Phone: r.env.A.Phone, Via: "open", ChallengeID: id, Code: code, Locale: "fa", IP: ip})
	if !errors.Is(err, otp.ErrInvalid) {
		t.Errorf("taken number: %v", err)
	}

	// The mode closed between the request and the register: the function refuses.
	phone := "+989127000003"
	id = r.challenge(phone, otp.Signup)
	r.setMode("closed")
	_, err = r.svc.Register(r.env.Ctx, login.RegisterInput{Phone: phone, Via: "open", ChallengeID: id, Code: code, Locale: "fa", IP: ip})
	if !errors.Is(err, otp.ErrInvalid) {
		t.Errorf("closed mode: %v", err)
	}
	if r.count(`SELECT count(*) FROM ctrlz.tenants`) != tenantsBefore {
		t.Error("a refused registration created a tenant")
	}
}

func TestRegisterByInviteWorksInEveryMode(t *testing.T) {
	r := newRig(t)
	r.setMode("closed")
	phone := "+989127000004"
	r.env.Exec(t, `INSERT INTO ctrlz.invites (token_hash, phone_e164, expires_at) VALUES (decode(repeat('0a', 32), 'hex'), $1, now() + interval '1 day')`, phone)
	var invite uuid.UUID
	r.env.Scan(t, `SELECT id FROM ctrlz.invites WHERE phone_e164 = $1`, []any{phone}, &invite)

	id := r.challenge(phone, otp.Invite)
	res, err := r.svc.Register(r.env.Ctx, login.RegisterInput{
		Phone: phone, Via: "invite", Invite: invite, ChallengeID: id, Code: code, Locale: "fa", IP: ip,
	})
	if err != nil || res.Status != login.Authenticated {
		t.Fatalf("%+v %v", res, err)
	}
	if r.count(`SELECT count(*) FROM ctrlz.invites WHERE id = $1 AND used_at IS NOT NULL`, invite) != 1 {
		t.Error("the invite was not used up")
	}
	if r.count(`SELECT count(*) FROM ctrlz.tenant_audit_log WHERE action = 'register' AND params ->> 'via' = 'invite'`) != 1 {
		t.Error("register audit row")
	}
	// An invite for another number is refused with the OTP it was not issued for.
	other := "+989127000005"
	r.env.Exec(t, `INSERT INTO ctrlz.invites (token_hash, phone_e164, expires_at) VALUES (decode(repeat('0b', 32), 'hex'), $1, now() + interval '1 day')`, other)
	var invite2 uuid.UUID
	r.env.Scan(t, `SELECT id FROM ctrlz.invites WHERE phone_e164 = $1`, []any{other}, &invite2)
	stranger := "+989127000006"
	id2 := r.challenge(stranger, otp.Invite)
	_, err = r.svc.Register(r.env.Ctx, login.RegisterInput{
		Phone: stranger, Via: "invite", Invite: invite2, ChallengeID: id2, Code: code, Locale: "fa", IP: ip,
	})
	if !errors.Is(err, otp.ErrInvalid) {
		t.Errorf("an invite used for another number: %v", err)
	}
	if r.count(`SELECT count(*) FROM ctrlz.users WHERE phone_e164 = '+989127000006'`) != 0 {
		t.Error("a user was created for a number the invite is not for")
	}
}

func hashOf(cookie string) []byte { return token.HashString(cookie) }

// TestRehashIsStoredUnlessThePasswordChangedMeanwhile covers Input.Rehash (4.1):
// a fresh hash goes in with the session, but never over a password the user
// changed after the password was verified, which would bring the old one back.
// The decision is the password_changed_at comparison under the row lock, not a
// clock, so a skewed clock between the app and the database cannot move it.
func TestRehashIsStoredUnlessThePasswordChangedMeanwhile(t *testing.T) {
	r := newRig(t)
	A := r.env.A
	hashOf := func() string {
		var h string
		r.env.Scan(t, `SELECT password_hash FROM ctrlz.users WHERE id = $1`, []any{A.User}, &h)
		return h
	}
	attempt := func(snapshot store.UserLogin) error {
		t.Helper()
		_, err := r.svc.AfterFirstFactor(r.env.Ctx, login.Input{
			User: snapshot, Factor: login.Password, IP: ip, UserAgent: "test-agent/1.0",
			Rehash: secret.New("$argon2id$fresh"),
		})
		return err
	}

	// A password never changed through the app: the rehash is stored.
	if err := attempt(r.userLogin(A.Phone)); err != nil {
		t.Fatal(err)
	}
	if hashOf() != "$argon2id$fresh" {
		t.Fatal("the fresh hash was not stored")
	}

	// A change after the password was verified: the rehash of the old password must
	// not win, and the login is refused.
	stale := r.userLogin(A.Phone)
	r.env.Exec(t, `UPDATE ctrlz.users SET password_hash = '$argon2id$new', password_changed_at = now() WHERE id = $1`, A.User)
	if err := attempt(stale); !errors.Is(err, login.ErrInvalidCredentials) {
		t.Fatalf("a login that verified the replaced password: %v", err)
	}
	if hashOf() != "$argon2id$new" {
		t.Fatalf("a rehash overwrote a password changed after the login began: %q", hashOf())
	}

	// A snapshot taken after the change is current: the rehash is stored, however
	// long ago the change was.
	r.env.Exec(t, `UPDATE ctrlz.users SET password_changed_at = now() - interval '1 day' WHERE id = $1`, A.User)
	if err := attempt(r.userLogin(A.Phone)); err != nil {
		t.Fatal(err)
	}
	if hashOf() != "$argon2id$fresh" {
		t.Fatal("the fresh hash was not stored after an old change")
	}
}

// TestOwnPasswordChangeAfterVerifyRefusesTheLogin is db-r1-1 and db-r1-7. The
// user replaces a leaked password while a login that verified the old one is in
// flight. must_reset and password_expires_at do not move on the user's own
// change, so only password_changed_at tells the login. It must be refused, for
// a plain user (no session) and for a TOTP user (no mfa ticket), and it must not
// outlive the revocation the change just did.
func TestOwnPasswordChangeAfterVerifyRefusesTheLogin(t *testing.T) {
	for _, withTOTP := range []bool{false, true} {
		name := "plain"
		if withTOTP {
			name = "totp"
		}
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			a, b := r.env.A, r.env.B
			if withTOTP {
				r.env.Exec(t, `UPDATE ctrlz.users SET totp_enabled_at = now(), totp_secret_ct = '\x01' WHERE id = $1`, a.User)
			}
			snapshot := r.userLogin(a.Phone) // what the route verified the old password against
			liveB := r.liveCount(b.Tenant, b.User)
			tickets := func() int {
				return r.count(`SELECT count(*) FROM ctrlz.auth_tickets WHERE kind = 'mfa' AND subject_user = $1 AND consumed_at IS NULL`, a.User)
			}
			ticketsBefore := tickets()

			// The change holds the row lock while the login arrives, as in the race: the
			// login's UserLock waits for the commit.
			locked := make(chan struct{})
			release := make(chan struct{})
			changed := make(chan error, 1)
			go func() {
				changed <- r.tenant.WithTenant(r.env.Ctx, a.Tenant, store.TxOpts{}, func(tx store.Tx) error {
					if _, ok, err := tx.UserLock(a.User); err != nil || !ok {
						return errors.Join(err, errors.New("no lock"))
					}
					if ok, err := tx.SetPassword(a.User, secret.New("$argon2id$replacement")); err != nil || !ok {
						return errors.Join(err, errors.New("no set"))
					}
					if _, err := tx.SessionsRevokeOthers(a.User, uuid.Nil, time.Now()); err != nil {
						return err
					}
					close(locked)
					<-release
					return nil
				})
			}()
			<-locked
			type out struct {
				res login.Result
				err error
			}
			got := make(chan out, 1)
			go func() {
				res, err := r.svc.AfterFirstFactor(r.env.Ctx, login.Input{User: snapshot, Factor: login.Password, IP: ip, UserAgent: "ua"})
				got <- out{res, err}
			}()
			time.Sleep(300 * time.Millisecond) // the login is now parked on the row lock
			close(release)
			if err := <-changed; err != nil {
				t.Fatal(err)
			}
			o := <-got
			if !errors.Is(o.err, login.ErrInvalidCredentials) {
				t.Fatalf("a login that verified the replaced password: %+v %v", o.res, o.err)
			}
			if o.res.Status != "" || len(o.res.Cookies) != 0 || !o.res.Ticket.IsZero() {
				t.Errorf("the refused login still produced something: %+v", o.res)
			}
			if n := r.liveCount(a.Tenant, a.User); n != 0 { // the change revoked all of them
				t.Errorf("%d session(s) live after the change: one was opened with the replaced password", n)
			}
			if tickets() != ticketsBefore {
				t.Error("an mfa ticket was issued for the replaced password")
			}
			if r.liveCount(b.Tenant, b.User) != liveB {
				t.Error("the other tenant's sessions moved")
			}

			// A login against the new password (a fresh snapshot) goes through.
			res, err := r.svc.AfterFirstFactor(r.env.Ctx, login.Input{User: r.userLogin(a.Phone), Factor: login.Password, IP: ip, UserAgent: "ua"})
			want := login.Authenticated
			if withTOTP {
				want = login.MFARequired
			}
			if err != nil || res.Status != want {
				t.Fatalf("the login with the new password: %+v %v", res, err)
			}
		})
	}
}
