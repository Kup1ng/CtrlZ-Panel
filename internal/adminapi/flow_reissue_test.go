package adminapi

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/audit"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/password"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/ticket"
	"github.com/Kup1ng/CtrlZ-Panel/internal/credgen"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testwait"
)

// The tests of T-536 (spec 10.7, 18.1, 18.2, 18.3, 18.4, 18.5). They drive the
// admin API and the tenant API together over one database, because the point of
// the re-issue is what it does to the user's own sessions and logins.

const userPW = "Quartz-lantern-Harbor-7391"

// otUser is a user made by POST /users.
type otUser struct {
	Tenant, User uuid.UUID
	Phone        string
	Password     string // the one-time password the admin was shown
}

var phoneSeq struct {
	sync.Mutex
	n int
}

func nextPhone() string {
	phoneSeq.Lock()
	defer phoneSeq.Unlock()
	phoneSeq.n++
	return "0913" + strings.Repeat("0", 7-len(itoa(phoneSeq.n))) + itoa(phoneSeq.n)
}

// newOTUser makes a user through the real route and returns the one-time password.
func (r *rig) newOTUser(t *testing.T, admin *browser) otUser {
	t.Helper()
	phone := nextPhone()
	var out struct {
		Tenant uuid.UUID `json:"tenant_id"`
		User   uuid.UUID `json:"user_id"`
		Pw     string    `json:"one_time_password"`
	}
	admin.post("/users", map[string]any{"phone": phone}).want(201, "").json(&out)
	return otUser{Tenant: out.Tenant, User: out.User, Phone: phone, Password: out.Pw}
}

// tenantLogin signs a user in on the panel API with a new browser.
func (r *rig) tenantLogin(phone, pw string, remember bool) (*browser, *aresp) {
	b := r.browser()
	res := b.callOn(r.tenant, panelHost, "POST", "/auth/login/password", map[string]any{"phone": phone, "password": pw, "remember_me": remember})
	return b, res
}

func (b *browser) tenant(method, path string, body any) *aresp {
	return b.callOn(b.r.tenant, panelHost, method, path, body)
}

func reissuePath(u otUser) string {
	return "/tenants/" + u.Tenant.String() + "/users/" + u.User.String() + "/one-time-password"
}

type issued struct {
	Password string    `json:"one_time_password"`
	Expires  time.Time `json:"expires_at"`
	Revoked  int       `json:"revoked_sessions"`
}

func (r *rig) reissue(t *testing.T, admin *browser, u otUser) (*aresp, issued) {
	t.Helper()
	res := admin.post(reissuePath(u), map[string]any{})
	var out issued
	if res.Code == 200 {
		res.json(&out)
	}
	return res, out
}

func (r *rig) reissueAudits(t *testing.T) int {
	return r.count(t, `SELECT count(*) FROM ctrlz.audit_log WHERE action = 'user.password_reissue'`)
}

// hashOf is a digest of the stored password hash, for "unchanged" assertions.
func (r *rig) hashOf(t *testing.T, u otUser) string {
	t.Helper()
	var h string
	r.env.Scan(t, `SELECT coalesce((SELECT coalesce(md5(password_hash), '') FROM ctrlz.users WHERE id = $1), 'missing')`, []any{u.User}, &h)
	return h
}

func (r *rig) liveSessions(t *testing.T, u otUser) int {
	return r.count(t, `SELECT count(*) FROM ctrlz.sessions WHERE user_id = $1 AND revoked_at IS NULL`, u.User)
}

// TestReissueExpiredAndLive is the main flow of 18.2: an expired and a live
// one-time password, the old one stops, the new one logs in restricted, the
// user sets a password and can no longer be re-issued.
func TestReissueExpiredAndLive(t *testing.T) {
	r := newRig(t)
	b, _ := r.admin(t)

	// Expired.
	u := r.newOTUser(t, b)
	r.env.Exec(t, `UPDATE ctrlz.users SET password_expires_at = now() - interval '1 minute' WHERE id = $1`, u.User)
	if _, res := r.tenantLogin(u.Phone, u.Password, false); res.Code != 401 || res.errCode() != "invalid_credentials" {
		t.Fatalf("expired one-time password: %d %s", res.Code, res.Body)
	}
	res, got := r.reissue(t, b, u)
	res.want(200, "")
	if got.Password == u.Password || got.Password != r.once.issued()[1] || got.Revoked != 0 {
		t.Fatalf("reissue = %+v", got)
	}
	// expires_at is the database's transaction time plus 72 hours, the same as POST /users.
	if d := time.Until(got.Expires); d < 71*time.Hour+55*time.Minute || d > 72*time.Hour+time.Minute {
		t.Fatalf("expires_at is %v away", d)
	}
	var inDB time.Time
	r.env.Scan(t, `SELECT password_expires_at FROM ctrlz.users WHERE id = $1`, []any{u.User}, &inDB)
	if !inDB.Equal(got.Expires) {
		t.Fatalf("expires_at %v differs from the row %v", got.Expires, inDB)
	}
	var mustReset bool
	var changed *time.Time
	r.env.Scan(t, `SELECT must_reset, password_changed_at FROM ctrlz.users WHERE id = $1`, []any{u.User}, &mustReset, &changed)
	if !mustReset || changed != nil {
		t.Fatalf("must_reset = %v, password_changed_at = %v (a re-issue is not the user's own change)", mustReset, changed)
	}
	// The old password stays dead, the new one logs in restricted.
	if _, res := r.tenantLogin(u.Phone, u.Password, false); res.Code != 401 {
		t.Fatalf("the replaced password logged in: %d", res.Code)
	}
	tb, res := r.tenantLogin(u.Phone, got.Password, false)
	res.want(200, "")
	tb.tenant("GET", "/account/sessions", nil).want(403, "password_change_required")
	var me struct {
		User struct {
			MustReset bool `json:"must_reset"`
		} `json:"user"`
	}
	tb.tenant("GET", "/me", nil).want(200, "").json(&me)
	if !me.User.MustReset {
		t.Fatal("the session is not restricted")
	}
	tb.tenant("POST", "/account/password", map[string]any{"new_password": userPW}).want(204, "")
	// Now the password is the user's own: no more re-issues.
	before := r.reissueAudits(t)
	r.reissue(t, b, u)
	res2, _ := r.reissue(t, b, u)
	res2.want(409, "password_not_one_time")
	if r.reissueAudits(t) != before {
		t.Fatalf("a refused re-issue wrote an audit row")
	}

	// Live and unused.
	v := r.newOTUser(t, b)
	_, g2 := r.reissue(t, b, v)
	if g2.Password == "" {
		t.Fatal("a live one-time password was refused")
	}
	if _, res := r.tenantLogin(v.Phone, v.Password, false); res.Code != 401 {
		t.Fatalf("the replaced live password logged in: %d", res.Code)
	}
	r.tenantLogin(v.Phone, g2.Password, false)

	// The audit rows carry exactly user_id, was_expired and revoked_sessions.
	rows := map[bool]map[string]any{}
	if err := r.adm.WithGlobal(r.env.Ctx, store.TxOpts{}, func(g store.GlobalTx) error {
		all, err := g.AuditChain(0, 1000)
		if err != nil {
			return err
		}
		if _, err := audit.VerifyChain(nil, all); err != nil {
			t.Errorf("the chain after the re-issues: %v", err)
		}
		for _, row := range all {
			if row.Action != "user.password_reissue" {
				continue
			}
			var p map[string]any
			if err := json.Unmarshal(row.Params, &p); err != nil {
				return err
			}
			rows[p["was_expired"].(bool)] = p
			if len(p) != 3 || p["user_id"] == nil || p["revoked_sessions"] == nil {
				t.Errorf("params = %v", p)
			}
			if !strings.HasPrefix(row.Target, "tenant:") {
				t.Errorf("target = %q", row.Target)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if rows[true] == nil || rows[false] == nil {
		t.Fatalf("expected one row for an expired and one for a live password: %v", rows)
	}
}

// TestReissueRevokesWhatItShould covers 3.7 / 10.7: sessions, the Remember me
// refresh token, and open mfa and reset tickets.
func TestReissueRevokesWhatItShould(t *testing.T) {
	r := newRig(t)
	b, _ := r.admin(t)
	u := r.newOTUser(t, b)

	s1, res := r.tenantLogin(u.Phone, u.Password, true) // Remember me: a refresh cookie too
	res.want(200, "")
	if s1.jar["__Host-ctrlz_refresh"] == nil {
		t.Fatal("no refresh cookie")
	}
	s2, _ := r.tenantLogin(u.Phone, u.Password, false)
	tickets := ticket.New(r.tst.Auth())
	var toks []string
	for _, kind := range []store.TicketKind{store.TicketMFA, store.TicketReset} {
		iss, err := tickets.Put(r.env.Ctx, ticket.Issue{Kind: kind, Tenant: u.Tenant, User: u.User, Cred: credgen.Stamp{Tenant: u.Tenant, Subject: u.User, Gen: 1}})
		if err != nil {
			t.Fatal(err)
		}
		toks = append(toks, iss.Token.Reveal())
	}
	// Another user's open ticket is not this user's to lose.
	other := r.newOTUser(t, b)
	oiss, err := tickets.Put(r.env.Ctx, ticket.Issue{Kind: store.TicketReset, Tenant: other.Tenant, User: other.User})
	if err != nil {
		t.Fatal(err)
	}

	_, got := r.reissue(t, b, u)
	if got.Revoked != 2 {
		t.Fatalf("revoked_sessions = %d, want 2", got.Revoked)
	}
	s1.tenant("GET", "/me", nil).want(401, "session_expired")
	s2.tenant("GET", "/me", nil).want(401, "session_expired")
	// The refresh cookie alone (as after a browser restart) is dead too.
	delete(s1.jar, "__Host-ctrlz_session")
	s1.tenant("POST", "/auth/refresh", nil).want(401, "session_expired")
	for i, kind := range []store.TicketKind{store.TicketMFA, store.TicketReset} {
		if _, ok, err := tickets.Peek(r.env.Ctx, toks[i], kind); err != nil || ok {
			t.Fatalf("a %s ticket survived the re-issue (ok=%v err=%v)", kind, ok, err)
		}
	}
	if _, ok, err := tickets.Peek(r.env.Ctx, oiss.Token.Reveal(), store.TicketReset); err != nil || !ok {
		t.Fatalf("another user's ticket was revoked (ok=%v err=%v)", ok, err)
	}
	// All of the user's rows are marked, and nothing is live.
	if n := r.liveSessions(t, u); n != 0 {
		t.Fatalf("%d live sessions", n)
	}
	if n := r.count(t, `SELECT count(*) FROM ctrlz.refresh_tokens WHERE user_id = $1 AND revoked_at IS NULL`, u.User); n != 0 {
		t.Fatalf("%d live refresh tokens", n)
	}
}

// TestReissueRefusals covers the 409, 404 and 200 cases of 18.2 and the
// takeover rows of 18.5: a user's own password is never replaced.
func TestReissueRefusals(t *testing.T) {
	r := newRig(t)
	b, _ := r.admin(t)

	refused := func(name string, u otUser, status int, code string) {
		t.Helper()
		before, audits, live := r.hashOf(t, u), r.reissueAudits(t), r.liveSessions(t, u)
		res, _ := r.reissue(t, b, u)
		res.want(status, code)
		if r.hashOf(t, u) != before || r.reissueAudits(t) != audits || r.liveSessions(t, u) != live {
			t.Errorf("%s: a refused re-issue changed something", name)
		}
	}
	seedA := otUser{Tenant: r.env.A.Tenant, User: r.env.A.User, Phone: r.env.A.Phone}
	// A user registered with a password of their own.
	r.env.Exec(t, `UPDATE ctrlz.users SET password_hash = $2 WHERE id = $1`, seedA.User, mustHash(t, r, "Any-long-password-1234"))
	refused("own password", seedA, 409, "password_not_one_time")
	// An OTP-only user.
	r.env.Exec(t, `UPDATE ctrlz.users SET password_hash = NULL WHERE id = $1`, seedA.User)
	refused("otp only", seedA, 409, "password_not_one_time")

	// A user who still has a one-time password but holds a second factor.
	withTOTP := r.newOTUser(t, b)
	r.env.Exec(t, `UPDATE ctrlz.users SET totp_secret_ct = '\x01', totp_enabled_at = now() WHERE id = $1`, withTOTP.User)
	refused("totp", withTOTP, 409, "password_not_one_time")
	// The same, with a passkey row (the seed gives tenant B's user one).
	seedB := otUser{Tenant: r.env.B.Tenant, User: r.env.B.User}
	r.env.Exec(t, `UPDATE ctrlz.users SET password_hash = $2, must_reset = true, password_expires_at = now() + interval '1 hour' WHERE id = $1`, seedB.User, mustHash(t, r, "Another-long-password-5678"))
	if r.count(t, `SELECT count(*) FROM ctrlz.webauthn_credentials WHERE user_id = $1`, seedB.User) == 0 {
		t.Fatal("the seed has no credential for tenant B's user")
	}
	refused("passkey row", seedB, 409, "password_not_one_time")
	withEnforce := r.newOTUser(t, b)
	r.env.Exec(t, `UPDATE ctrlz.users SET enforce_passkey = true WHERE id = $1`, withEnforce.User)
	refused("enforce passkey", withEnforce, 409, "password_not_one_time")

	// 404: an unknown user, a user of another tenant, a tenant being deleted.
	refused("unknown user", otUser{Tenant: seedA.Tenant, User: uuid.New()}, 404, "not_found")
	ok := r.newOTUser(t, b)
	refused("cross pair 1", otUser{Tenant: seedA.Tenant, User: ok.User}, 404, "not_found")
	refused("cross pair 2", otUser{Tenant: ok.Tenant, User: seedA.User}, 404, "not_found")
	r.env.Exec(t, `UPDATE ctrlz.tenants SET status = 'deleting' WHERE id = $1`, ok.Tenant)
	refused("deleting tenant", ok, 404, "not_found")
	// 200: a suspended tenant (its session reaches only GET /me and logout).
	r.env.Exec(t, `UPDATE ctrlz.tenants SET status = 'suspended' WHERE id = $1`, ok.Tenant)
	if res, got := r.reissue(t, b, ok); res.Code != 200 || got.Password == "" {
		t.Fatalf("suspended tenant: %d %s", res.Code, res.Body)
	}
	// The path takes UUIDs only.
	b.post("/tenants/not-a-uuid/users/"+ok.User.String()+"/one-time-password", map[string]any{}).want(400, "bad_request")
}

func mustHash(t *testing.T, r *rig, pw string) string {
	t.Helper()
	h, err := r.hasher.Hash(r.env.Ctx, secretOf(pw))
	if err != nil {
		t.Fatal(err)
	}
	return h.Reveal()
}

// TestReissueTwoTenants is the two-tenant test of 18.1: re-issuing for one
// tenant's user leaves the other's rows and logins alone, the cross pairs are
// 404, and the tenant API has no such route.
func TestReissueTwoTenants(t *testing.T) {
	r := newRig(t)
	b, _ := r.admin(t)
	a, bb := r.newOTUser(t, b), r.newOTUser(t, b)
	tickets := ticket.New(r.tst.Auth())
	bSess, res := r.tenantLogin(bb.Phone, bb.Password, true)
	res.want(200, "")
	aSess, _ := r.tenantLogin(a.Phone, a.Password, true)
	iss, err := tickets.Put(r.env.Ctx, ticket.Issue{Kind: store.TicketReset, Tenant: bb.Tenant, User: bb.User})
	if err != nil {
		t.Fatal(err)
	}
	snapshot := func(u otUser) string {
		var s string
		r.env.Scan(t, `SELECT concat_ws('|',
		  (SELECT coalesce(md5(password_hash), '') || coalesce(password_expires_at::text, '') FROM ctrlz.users WHERE id = $1),
		  (SELECT count(*) FROM ctrlz.sessions WHERE user_id = $1 AND revoked_at IS NULL),
		  (SELECT count(*) FROM ctrlz.refresh_tokens WHERE user_id = $1 AND revoked_at IS NULL),
		  (SELECT count(*) FROM ctrlz.auth_tickets WHERE subject_user = $1 AND consumed_at IS NULL))`, []any{u.User}, &s)
		return s
	}
	bBefore, aBefore := snapshot(bb), snapshot(a)
	audits := r.reissueAudits(t)

	// The cross pairs: no row of either tenant changes and no audit row is written.
	b.post("/tenants/"+a.Tenant.String()+"/users/"+bb.User.String()+"/one-time-password", map[string]any{}).want(404, "not_found")
	b.post("/tenants/"+bb.Tenant.String()+"/users/"+a.User.String()+"/one-time-password", map[string]any{}).want(404, "not_found")
	if snapshot(a) != aBefore || snapshot(bb) != bBefore || r.reissueAudits(t) != audits {
		t.Fatal("a cross-tenant re-issue changed something")
	}
	// The tenant API has no such operation, whatever the session.
	aSess.tenant("POST", reissuePath(a), map[string]any{}).want(404, "not_found")

	_, got := r.reissue(t, b, a)
	if got.Password == "" || got.Revoked != 1 {
		t.Fatalf("reissue for A: %+v", got)
	}
	if snapshot(bb) != bBefore {
		t.Fatalf("B's rows moved: %q -> %q", bBefore, snapshot(bb))
	}
	bSess.tenant("GET", "/me", nil).want(200, "")
	if _, ok, err := tickets.Peek(r.env.Ctx, iss.Token.Reveal(), store.TicketReset); err != nil || !ok {
		t.Fatal("B's reset ticket was revoked")
	}
	if _, res := r.tenantLogin(bb.Phone, bb.Password, false); res.Code != 200 {
		t.Fatalf("B's one-time password stopped working: %d", res.Code)
	}
}

// TestReissueGates covers the first rows of 18.5 for the stolen admin cookie: a
// stale TOTP window, a setup session and the admin-write bucket.
func TestReissueGates(t *testing.T) {
	r := newRig(t)
	b, _ := r.admin(t)
	u := r.newOTUser(t, b)

	r.env.Exec(t, `UPDATE ctrlz.admin_sessions SET totp_verified_at = now() - interval '10 minutes'`)
	before, audits := r.hashOf(t, u), r.reissueAudits(t)
	b.post(reissuePath(u), map[string]any{}).want(403, "totp_fresh_required")
	if r.hashOf(t, u) != before || r.reissueAudits(t) != audits {
		t.Fatal("a refused call changed something")
	}
	// No cookie at all.
	r.browser().post(reissuePath(u), map[string]any{}).want(401, "session_expired")
	// A setup session.
	r.setupAdmin(t, false)
	setup := r.browser()
	setup.login(adminPW, "").want(200, "")
	setup.post(reissuePath(u), map[string]any{}).want(403, "setup_required")

	// The admin-write bucket: 60 a minute per session.
	r.setupAdmin(t, true)
	c, _ := r.admin(t)
	missing := otUser{Tenant: u.Tenant, User: uuid.New()}
	ok, limited := 0, 0
	for i := 0; i < 62; i++ {
		switch c.post(reissuePath(missing), map[string]any{}).Code {
		case 404:
			ok++
		case 429:
			limited++
		}
	}
	if limited == 0 || ok > 60 {
		t.Fatalf("admin-write: %d answered, %d refused", ok, limited)
	}
}

// TestReissueCanary is the canary of 18.4: the generated password is in the
// response and nowhere else.
func TestReissueCanary(t *testing.T) {
	r := newRig(t)
	b, _ := r.admin(t)
	u := r.newOTUser(t, b)
	_, got := r.reissue(t, b, u)
	created := r.once.issued()[0]
	if got.Password != r.once.issued()[1] {
		t.Fatal("the response does not hold the generated password")
	}
	for _, canary := range []string{created, got.Password} {
		if strings.Contains(r.logs.String(), canary) {
			t.Errorf("the process log holds a one-time password")
		}
		for _, table := range []string{"audit_log", "tenant_audit_log", "sms_deliveries", "alerts", "job_outbox", "admin_jobs", "admin_sessions", "notifications"} {
			if n := r.count(t, `SELECT count(*) FROM ctrlz.`+table+` t WHERE row_to_json(t)::text LIKE '%' || $1 || '%'`, canary); n != 0 {
				t.Errorf("%s holds a one-time password", table)
			}
		}
	}
	// Nor its expiry, which the row's own time gives (13.3).
	var expires string
	r.env.Scan(t, `SELECT to_char(password_expires_at, 'YYYY-MM-DD"T"HH24:MI:SS') FROM ctrlz.users WHERE id = $1`, []any{u.User}, &expires)
	if n := r.count(t, `SELECT count(*) FROM ctrlz.audit_log WHERE row_to_json(audit_log)::text LIKE '%' || $1 || '%'`, expires); n != 0 {
		t.Error("the audit log holds the one-time password's expiry")
	}
}

// TestReissueRollsBackWhole is the fault row of 18.3: when the audit row cannot
// be written, nothing else commits.
func TestReissueRollsBackWhole(t *testing.T) {
	r := newRig(t)
	b, _ := r.admin(t)
	u := r.newOTUser(t, b)
	s, _ := r.tenantLogin(u.Phone, u.Password, true)
	tickets := ticket.New(r.tst.Auth())
	iss, err := tickets.Put(r.env.Ctx, ticket.Issue{Kind: store.TicketReset, Tenant: u.Tenant, User: u.User})
	if err != nil {
		t.Fatal(err)
	}
	r.env.Exec(t, `CREATE FUNCTION ctrlz.fail_reissue_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
	  IF NEW.action = 'user.password_reissue' THEN RAISE EXCEPTION 'injected'; END IF; RETURN NEW; END $$`)
	r.env.Exec(t, `CREATE TRIGGER fail_reissue_audit BEFORE INSERT ON ctrlz.audit_log FOR EACH ROW EXECUTE FUNCTION ctrlz.fail_reissue_audit()`)

	before := r.hashOf(t, u)
	res, _ := r.reissue(t, b, u)
	if res.Code < 500 {
		t.Fatalf("expected a server error, got %d %s", res.Code, res.Body)
	}
	if strings.Contains(string(res.Body), "injected") || strings.Contains(string(res.Body), r.once.issued()[1]) {
		t.Fatalf("the error body leaks: %s", res.Body)
	}
	if r.hashOf(t, u) != before || r.liveSessions(t, u) != 1 {
		t.Fatal("part of the re-issue committed")
	}
	s.tenant("GET", "/me", nil).want(200, "")
	if _, ok, _ := tickets.Peek(r.env.Ctx, iss.Token.Reveal(), store.TicketReset); !ok {
		t.Fatal("the ticket was revoked")
	}
	if r.count(t, `SELECT count(*) FROM ctrlz.refresh_tokens WHERE user_id = $1 AND revoked_at IS NOT NULL`, u.User) != 0 {
		t.Fatal("a refresh token was revoked")
	}
	if _, res := r.tenantLogin(u.Phone, u.Password, false); res.Code != 200 {
		t.Fatalf("the original one-time password stopped working: %d", res.Code)
	}
}

// TestReissueDatabaseDown is the other fault row: Postgres gone is a clean 503
// with no detail, and the replaced password still works afterwards.
func TestReissueDatabaseDown(t *testing.T) {
	r := newRig(t)
	b, _ := r.admin(t)
	u := r.newOTUser(t, b)

	stopCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := cluster.StopPostgres(stopCtx); err != nil {
		t.Fatalf("stop postgres: %v", err)
	}
	restarted := false
	restart := func() {
		if !restarted {
			restarted = true
			if err := cluster.StartPostgres(context.Background()); err != nil {
				t.Errorf("restart postgres: %v", err)
			}
		}
	}
	t.Cleanup(restart)

	res, _ := r.reissue(t, b, u)
	res.want(503, "service_unavailable")
	// The request id is random hex, and "5432" is a substring of one in a few thousand of them: a leak
	// of the database port is looked for in the rest of the body (a flake found in round 13).
	var parsed map[string]any
	if err := json.Unmarshal(res.Body, &parsed); err != nil {
		t.Fatalf("the 503 body is not JSON: %s", res.Body)
	}
	delete(parsed, "request_id")
	rest, _ := json.Marshal(parsed)
	body := strings.ToLower(string(rest))
	for _, leak := range []string{"sqlstate", "pgx", "refused", "5432", strings.ToLower(r.once.issued()[len(r.once.issued())-1])} {
		if strings.Contains(body, leak) {
			t.Errorf("the 503 body leaks %q", leak)
		}
	}
	restart()
	testwait.UntilEvery(t, 60*time.Second, time.Second, "the original one-time password to work after the restart", func() bool {
		_, res := r.tenantLogin(u.Phone, u.Password, false)
		return res.Code == 200
	})
}

// TestReissueArgonGateFull is the last fault row: a full gate is 503
// server_busy before any transaction.
func TestReissueArgonGateFull(t *testing.T) {
	r := newRig(t)
	b, _ := r.admin(t)
	u := r.newOTUser(t, b)
	gate := password.NewGate(1, 50*time.Millisecond)
	release, err := gate.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	busy, err := password.NewHasher(password.Params{MemoryKiB: 64, Time: 1, Threads: 1}, gate)
	if err != nil {
		t.Fatal(err)
	}
	h := r.handler(t, func(d *Deps) { d.Hasher = busy })
	before, audits := r.hashOf(t, u), r.reissueAudits(t)
	res := b.callOn(h, adminHost, "POST", reissuePath(u), map[string]any{}).want(503, "server_busy")
	if res.H.Get("Retry-After") == "" {
		t.Fatal("no Retry-After")
	}
	if r.hashOf(t, u) != before || r.reissueAudits(t) != audits {
		t.Fatal("a busy re-issue changed something")
	}
}

// race runs two calls at once behind a barrier and returns both results.
func race[A, B any](a func() A, b func() B) (A, B) {
	var ra A
	var rb B
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); <-start; ra = a() }()
	go func() { defer wg.Done(); <-start; rb = b() }()
	close(start)
	wg.Wait()
	return ra, rb
}

const raceRounds = 8

// TestReissueRacesWithThePasswordChange: whichever commits first wins, never
// both (10.7, 4.4).
func TestReissueRacesWithThePasswordChange(t *testing.T) {
	r := newRig(t)
	b, _ := r.admin(t)
	for round := 0; round < raceRounds; round++ {
		u := r.newOTUser(t, b)
		s, res := r.tenantLogin(u.Phone, u.Password, true)
		res.want(200, "")
		admin, user := race(
			func() *aresp { res, _ := r.reissue(t, b, u); return res },
			func() *aresp {
				return s.tenant("POST", "/account/password", map[string]any{"new_password": userPW})
			},
		)
		switch {
		case admin.Code == 200 && user.Code == 401 && user.errCode() == "session_expired":
			// The re-issue won: only the new one-time password is live.
			var got issued
			admin.json(&got)
			if _, res := r.tenantLogin(u.Phone, userPW, false); res.Code != 401 {
				t.Fatalf("round %d: the user's password was set although the re-issue won", round)
			}
			if _, res := r.tenantLogin(u.Phone, got.Password, false); res.Code != 200 {
				t.Fatalf("round %d: the re-issued password does not work: %d", round, res.Code)
			}
		case admin.Code == 409 && admin.errCode() == "password_not_one_time" && user.Code == 204:
			if _, res := r.tenantLogin(u.Phone, userPW, false); res.Code != 200 {
				t.Fatalf("round %d: the user's password does not work: %d", round, res.Code)
			}
		default:
			t.Fatalf("round %d: re-issue %d %s, password change %d %s", round, admin.Code, admin.Body, user.Code, user.Body)
		}
	}
}

// TestReissueRacesWithALogin: a login that verified the replaced password leaves
// no live session (10.7, 5.7).
func TestReissueRacesWithALogin(t *testing.T) {
	r := newRig(t)
	b, _ := r.admin(t)
	for round := 0; round < raceRounds; round++ {
		u := r.newOTUser(t, b)
		admin, login := race(
			func() *aresp { res, _ := r.reissue(t, b, u); return res },
			func() *aresp { _, res := r.tenantLogin(u.Phone, u.Password, true); return res },
		)
		admin.want(200, "")
		if login.Code != 200 && !(login.Code == 401 && login.errCode() == "invalid_credentials") {
			t.Fatalf("round %d: login %d %s", round, login.Code, login.Body)
		}
		if n := r.liveSessions(t, u); n != 0 {
			t.Fatalf("round %d: %d live sessions made with the replaced password (login %d)", round, n, login.Code)
		}
		if n := r.count(t, `SELECT count(*) FROM ctrlz.refresh_tokens WHERE user_id = $1 AND revoked_at IS NULL`, u.User); n != 0 {
			t.Fatalf("round %d: %d live refresh tokens", round, n)
		}
		var got issued
		admin.json(&got)
		if got.Revoked > 1 {
			t.Fatalf("round %d: revoked_sessions = %d", round, got.Revoked)
		}
	}
}

// TestTwoReissuesAtOnce: the row lock orders them, both answer 200, only the
// later password works, and two audit rows exist. No deadlock.
func TestTwoReissuesAtOnce(t *testing.T) {
	r := newRig(t)
	b, seed := r.admin(t)
	b2 := r.browser()
	b2.mustLogin(seed)
	for round := 0; round < raceRounds; round++ {
		u := r.newOTUser(t, b)
		audits := r.reissueAudits(t)
		x, y := race(
			func() *aresp { res, _ := r.reissue(t, b, u); return res },
			func() *aresp { res, _ := r.reissue(t, b2, u); return res },
		)
		x.want(200, "")
		y.want(200, "")
		var px, py issued
		x.json(&px)
		y.json(&py)
		working := 0
		for _, pw := range []string{px.Password, py.Password} {
			if _, res := r.tenantLogin(u.Phone, pw, false); res.Code == 200 {
				working++
			}
		}
		if working != 1 {
			t.Fatalf("round %d: %d of the two passwords work", round, working)
		}
		if got := r.reissueAudits(t) - audits; got != 2 {
			t.Fatalf("round %d: %d audit rows", round, got)
		}
	}
}
