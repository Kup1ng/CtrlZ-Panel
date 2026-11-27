package session_test

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/apispec"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/credstate"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/session"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/ticket"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/token"
	"github.com/Kup1ng/CtrlZ-Panel/internal/authtest"
	"github.com/Kup1ng/CtrlZ-Panel/internal/caps"
	"github.com/Kup1ng/CtrlZ-Panel/internal/credgen"
	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

var cluster *testpg.Cluster

func TestMain(m *testing.M) {
	os.Exit(testpg.RunMain(m, func(c *testpg.Cluster) { cluster = c }))
}

// clock is a fake wall clock. It starts at the real time, because the database
// stamps some columns itself (revoked_at, reauth_at) and the gates compare them
// with this clock.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock { return &clock{t: time.Now().UTC()} }
func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

var ip = netip.MustParseAddr("203.0.113.9")

// ---------------------------------------------------------------------------
// Cookies (no database)

func TestCookieAttributesAreExact(t *testing.T) {
	tok := secret.New("TOKEN")
	for name, tc := range map[string]struct {
		got  *http.Cookie
		want string
	}{
		"session": {session.SessionCookie(tok), "__Host-ctrlz_session=TOKEN; Path=/; HttpOnly; Secure; SameSite=Lax"},
		"refresh": {session.RefreshCookie(tok, 30*24*time.Hour), "__Host-ctrlz_refresh=TOKEN; Path=/; Max-Age=2592000; HttpOnly; Secure; SameSite=Lax"},
		"device":  {session.DeviceCookie("SEALED"), "__Host-ctrlz_device=SEALED; Path=/; Max-Age=31536000; HttpOnly; Secure; SameSite=Lax"},
		"admin":   {session.AdminCookie(tok), "__Host-ctrlz_admin=TOKEN; Path=/; HttpOnly; Secure; SameSite=Strict"},
	} {
		if got := tc.got.String(); got != tc.want {
			t.Errorf("%s:\n got  %s\n want %s", name, got, tc.want)
		}
	}
	for _, c := range session.ClearPanel() {
		if s := c.String(); !strings.Contains(s, "Max-Age=0") || !strings.Contains(s, "Path=/") || !strings.Contains(s, "Secure") || strings.Contains(s, "TOKEN") {
			t.Errorf("clearing cookie %s", s)
		}
	}
	if s := session.ClearAdmin().String(); !strings.Contains(s, "Max-Age=0") || !strings.Contains(s, "SameSite=Strict") {
		t.Errorf("clear admin %s", s)
	}
}

func TestNoCookieEverHasADomain(t *testing.T) {
	all := []*http.Cookie{session.SessionCookie(secret.New("x")), session.RefreshCookie(secret.New("x"), time.Hour),
		session.DeviceCookie("x"), session.AdminCookie(secret.New("x")), session.ClearAdmin()}
	all = append(all, session.ClearPanel()...)
	for _, c := range all {
		if c.Domain != "" || strings.Contains(strings.ToLower(c.String()), "domain") {
			t.Errorf("%s has a Domain", c.Name)
		}
		if !strings.HasPrefix(c.Name, "__Host-") || !c.Secure || !c.HttpOnly || c.Path != "/" {
			t.Errorf("%s breaks the __Host- rules", c.Name)
		}
	}
}

// ---------------------------------------------------------------------------
// Gates (no database)

func TestGatesInTheOrderOfTheTable(t *testing.T) {
	ck := newClock()
	m := session.NewManager(nil, session.DefaultPolicy(), ck.now)
	now := ck.now()
	live := func() store.SessionInfo {
		return store.SessionInfo{TenantStatus: "active", State: credstate.Ready, IdleExpiresAt: now.Add(time.Hour), AbsoluteExpiresAt: now.Add(10 * time.Hour)}
	}
	rv := now.Add(-time.Second)
	stale := now.Add(-11 * time.Minute)
	fresh := now.Add(-9 * time.Minute)
	edge := now.Add(-10 * time.Minute)
	// A stamp written before the host clock stepped back is in the future now.
	ahead3h := now.Add(3 * time.Hour)
	ahead4m := now.Add(4 * time.Minute)

	cases := []struct {
		name string
		mod  func(*store.SessionInfo)
		gate session.Gate
		want error
	}{
		{"live session", func(*store.SessionInfo) {}, session.Gate{Auth: apispec.Session}, nil},
		{"revoked", func(i *store.SessionInfo) { i.RevokedAt = &rv }, session.Gate{Auth: apispec.Session}, session.ErrExpired},
		{"past idle", func(i *store.SessionInfo) { i.IdleExpiresAt = now }, session.Gate{Auth: apispec.Session}, session.ErrExpired},
		{"past absolute", func(i *store.SessionInfo) { i.AbsoluteExpiresAt = now.Add(-time.Second) }, session.Gate{Auth: apispec.Session}, session.ErrExpired},
		{"suspended on a normal route", func(i *store.SessionInfo) { i.TenantStatus = "suspended" }, session.Gate{Auth: apispec.Session}, session.ErrSuspended},
		{"suspended on /me or logout", func(i *store.SessionInfo) { i.TenantStatus = "suspended" }, session.Gate{Auth: apispec.SessionSetup, AllowSuspended: true}, nil},
		{"deleting is expired, even for /me", func(i *store.SessionInfo) { i.TenantStatus = "deleting" }, session.Gate{Auth: apispec.SessionSetup, AllowSuspended: true}, session.ErrExpired},
		{"restricted on a session route", func(i *store.SessionInfo) { i.State = credstate.OneTimeLive }, session.Gate{Auth: apispec.Session}, session.ErrPasswordChange},
		{"restricted by an expired one-time password on a session route", func(i *store.SessionInfo) { i.State = credstate.OneTimeExpired }, session.Gate{Auth: apispec.Session}, session.ErrPasswordChange},
		{"an unknown state refuses", func(i *store.SessionInfo) { i.State = credstate.Unknown }, session.Gate{Auth: apispec.Session}, session.ErrPasswordChange},
		{"restricted on a reauth route", func(i *store.SessionInfo) { i.State = credstate.OneTimeLive }, session.Gate{Auth: apispec.Reauth}, session.ErrPasswordChange},
		{"restricted on session-setup", func(i *store.SessionInfo) { i.State = credstate.OneTimeLive }, session.Gate{Auth: apispec.SessionSetup}, nil},
		{"reauth with no window", func(*store.SessionInfo) {}, session.Gate{Auth: apispec.Reauth}, session.ErrReauth},
		{"reauth stale", func(i *store.SessionInfo) { i.ReauthAt = &stale }, session.Gate{Auth: apispec.Reauth}, session.ErrReauth},
		{"reauth exactly ten minutes old", func(i *store.SessionInfo) { i.ReauthAt = &edge }, session.Gate{Auth: apispec.Reauth}, session.ErrReauth},
		{"reauth fresh", func(i *store.SessionInfo) { i.ReauthAt = &fresh }, session.Gate{Auth: apispec.Reauth}, nil},
		{"reauth stamped 3 hours ahead is not fresh", func(i *store.SessionInfo) { i.ReauthAt = &ahead3h }, session.Gate{Auth: apispec.Reauth}, session.ErrReauth},
		{"reauth stamped 4 minutes ahead is inside the skew", func(i *store.SessionInfo) { i.ReauthAt = &ahead4m }, session.Gate{Auth: apispec.Reauth}, nil},
		{"a status this switch does not know refuses", func(i *store.SessionInfo) { i.TenantStatus = "pending_payment" }, session.Gate{Auth: apispec.Session}, session.ErrExpired},
		{"an empty status refuses", func(i *store.SessionInfo) { i.TenantStatus = "" }, session.Gate{Auth: apispec.Session}, session.ErrExpired},
		{"suspended wins over restricted", func(i *store.SessionInfo) { i.TenantStatus = "suspended"; i.State = credstate.OneTimeLive }, session.Gate{Auth: apispec.Session}, session.ErrSuspended},
	}
	for _, c := range cases {
		info := live()
		c.mod(&info)
		if got := m.Check(info, c.gate); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestNeedsTouchWritesAtMostOncePerMinute(t *testing.T) {
	ck := newClock()
	m := session.NewManager(nil, session.DefaultPolicy(), ck.now)
	now := ck.now()
	full := store.SessionInfo{IdleExpiresAt: now.Add(2 * time.Hour), AbsoluteExpiresAt: now.Add(24 * time.Hour)}
	if m.NeedsTouch(full) {
		t.Error("a session with a full idle period must not be touched")
	}
	if m.NeedsTouch(store.SessionInfo{IdleExpiresAt: now.Add(2*time.Hour - 30*time.Second), AbsoluteExpiresAt: now.Add(24 * time.Hour)}) {
		t.Error("30 seconds of slide is inside the margin")
	}
	if !m.NeedsTouch(store.SessionInfo{IdleExpiresAt: now.Add(2*time.Hour - 61*time.Second), AbsoluteExpiresAt: now.Add(24 * time.Hour)}) {
		t.Error("61 seconds of slide must touch")
	}
	// Capped at the absolute limit: sliding changes nothing, so no write.
	if m.NeedsTouch(store.SessionInfo{IdleExpiresAt: now.Add(time.Hour), AbsoluteExpiresAt: now.Add(time.Hour)}) {
		t.Error("a session at its absolute limit must not be touched")
	}
}

func TestAdminGates(t *testing.T) {
	ck := newClock()
	m := session.NewManager(nil, session.DefaultPolicy(), ck.now)
	now := ck.now()
	ready := func() store.AdminSessionInfo {
		te := now.Add(-time.Hour)
		return store.AdminSessionInfo{IdleExpiresAt: now.Add(10 * time.Minute), AbsoluteExpiresAt: now.Add(time.Hour), TOTPEnabledAt: &te, State: credstate.Ready}
	}
	old, recent := now.Add(-5*time.Minute), now.Add(-4*time.Minute)
	ahead3h := now.Add(3 * time.Hour)
	dis := now.Add(-time.Minute)
	for _, c := range []struct {
		name string
		mod  func(*store.AdminSessionInfo)
		auth apispec.Auth
		want error
	}{
		{"ready admin", func(*store.AdminSessionInfo) {}, apispec.Admin, nil},
		{"must change password", func(i *store.AdminSessionInfo) { i.State = credstate.OneTimeLive }, apispec.Admin, session.ErrSetupRequired},
		{"an expired one-time password", func(i *store.AdminSessionInfo) { i.State = credstate.OneTimeExpired }, apispec.Admin, session.ErrSetupRequired},
		{"chosen, no authenticator yet", func(i *store.AdminSessionInfo) { i.State = credstate.ChosenNoSecondFactor }, apispec.Admin, session.ErrSetupRequired},
		{"an unknown state", func(i *store.AdminSessionInfo) { i.State = credstate.Unknown }, apispec.AdminSetup, session.ErrSetupRequired},
		{"no TOTP yet", func(i *store.AdminSessionInfo) { i.TOTPEnabledAt = nil; i.State = credstate.ChosenNoSecondFactor }, apispec.Admin, session.ErrSetupRequired},
		{"setup route in setup", func(i *store.AdminSessionInfo) { i.State = credstate.OneTimeLive; i.TOTPEnabledAt = nil }, apispec.AdminSetup, nil},
		{"setup route when ready", func(*store.AdminSessionInfo) {}, apispec.AdminSetup, nil},
		{"fresh route in setup", func(i *store.AdminSessionInfo) { i.TOTPEnabledAt = nil; i.State = credstate.ChosenNoSecondFactor }, apispec.AdminFresh, session.ErrSetupRequired},
		{"fresh route with no check", func(*store.AdminSessionInfo) {}, apispec.AdminFresh, session.ErrFreshRequired},
		{"fresh route, check five minutes old", func(i *store.AdminSessionInfo) { i.TOTPVerifiedAt = &old }, apispec.AdminFresh, session.ErrFreshRequired},
		{"fresh route, check four minutes old", func(i *store.AdminSessionInfo) { i.TOTPVerifiedAt = &recent }, apispec.AdminFresh, nil},
		{"fresh route, check stamped 3 hours ahead", func(i *store.AdminSessionInfo) { i.TOTPVerifiedAt = &ahead3h }, apispec.AdminFresh, session.ErrFreshRequired},
		{"disabled", func(i *store.AdminSessionInfo) { i.DisabledAt = &dis }, apispec.Admin, session.ErrExpired},
		{"revoked", func(i *store.AdminSessionInfo) { i.RevokedAt = &dis }, apispec.AdminSetup, session.ErrExpired},
		{"idle", func(i *store.AdminSessionInfo) { i.IdleExpiresAt = now }, apispec.Admin, session.ErrExpired},
	} {
		info := ready()
		c.mod(&info)
		if got := m.AdminCheck(info, c.auth); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

// ---------------------------------------------------------------------------
// With Postgres

type rig struct {
	env *authtest.Env
	st  *store.Store
	m   *session.Manager
	ck  *clock
}

func newRig(t *testing.T) *rig {
	t.Helper()
	env := authtest.New(t, cluster)
	st := env.Tenant(t)
	ck := newClock()
	return &rig{env: env, st: st, m: session.NewManager(st, session.DefaultPolicy(), ck.now), ck: ck}
}

func (r *rig) create(t *testing.T, tenant, user uuid.UUID, remember, restricted bool) session.Issued {
	t.Helper()
	var iss session.Issued
	err := r.st.WithTenant(r.env.Ctx, tenant, store.TxOpts{}, func(tx store.Tx) (err error) {
		iss, err = r.m.Create(tx, session.NewSession{User: user, Remember: remember, Restricted: restricted, Method: "password", IP: ip, UserAgent: "test"})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return iss
}

func (r *rig) lookup(t *testing.T, tok secret.String) (store.SessionInfo, bool) {
	t.Helper()
	info, ok, err := r.m.Lookup(r.env.Ctx, tok.Reveal())
	if err != nil {
		t.Fatal(err)
	}
	return info, ok
}

func (r *rig) alive(t *testing.T, tok secret.String, gate session.Gate) bool {
	t.Helper()
	info, ok := r.lookup(t, tok)
	return ok && r.m.Check(info, gate) == nil
}

var plain = session.Gate{Auth: apispec.Session}

func TestCreateAndLifetimes(t *testing.T) {
	r := newRig(t)
	short := r.create(t, r.env.A.Tenant, r.env.A.User, false, false)
	long := r.create(t, r.env.A.Tenant, r.env.A.User, true, false)

	if !short.Refresh.IsZero() || long.Refresh.IsZero() {
		t.Fatal("only Remember me gets a refresh token")
	}
	// No Remember me: a session cookie with no Max-Age, and a deletion of the
	// refresh cookie so a left-over one of another account cannot take over the
	// browser on a later 401 (primitives-r3-7).
	if cs := short.Cookies(); len(cs) != 2 || cs[0].MaxAge != 0 || cs[1].Name != session.CookieRefresh ||
		cs[1].MaxAge >= 0 || cs[1].Value != "" || !strings.Contains(cs[1].String(), "Max-Age=0") || !strings.Contains(cs[1].String(), "Secure") {
		t.Fatalf("no Remember me: session cookie plus a refresh deletion, got %v", cs)
	}
	if cs := long.Cookies(); len(cs) != 2 || cs[1].Name != session.CookieRefresh || cs[1].MaxAge != int((30*24*time.Hour)/time.Second) {
		t.Fatalf("Remember me cookies: %v", cs)
	}

	// Without Remember me: idle at 2 h, absolute at 24 h.
	r.ck.add(2*time.Hour - time.Second)
	if !r.alive(t, short.Session, plain) {
		t.Fatal("alive just before the idle limit")
	}
	r.ck.add(2 * time.Second)
	if r.alive(t, short.Session, plain) {
		t.Fatal("dead at the idle limit")
	}
	// Sliding keeps it alive: touch every hour up to the absolute limit.
	r2 := r.create(t, r.env.A.Tenant, r.env.A.User, false, false)
	for i := 0; i < 23; i++ {
		r.ck.add(time.Hour)
		info, ok := r.lookup(t, r2.Session)
		if !ok || r.m.Check(info, plain) != nil {
			t.Fatalf("hour %d: dead too early", i)
		}
		if r.m.NeedsTouch(info) {
			if err := r.m.Touch(r.env.Ctx, info); err != nil {
				t.Fatal(err)
			}
		}
	}
	r.ck.add(2 * time.Hour)
	if r.alive(t, r2.Session, plain) {
		t.Fatal("dead after 24 h whatever the touches")
	}
	// Remember me: the session token still has the 2 h idle limit, the row 90 days.
	info, _ := r.lookup(t, long.Session)
	if got := info.AbsoluteExpiresAt.Sub(info.IdleExpiresAt); got < 89*24*time.Hour {
		t.Fatalf("Remember me row absolute limit is only %v past idle", got)
	}
}

func TestSessionOfOneTenantIsNotAnotherTenants(t *testing.T) {
	r := newRig(t)
	a := r.create(t, r.env.A.Tenant, r.env.A.User, false, false)
	b := r.create(t, r.env.B.Tenant, r.env.B.User, false, false)
	ia, _ := r.lookup(t, a.Session)
	ib, _ := r.lookup(t, b.Session)
	if ia.TenantID != r.env.A.Tenant || ib.TenantID != r.env.B.Tenant || ia.SessionID == ib.SessionID {
		t.Fatal("lookups must resolve each session to its own tenant")
	}
	// Acting on B's session through A's tenant finds nothing.
	err := r.st.WithTenant(r.env.Ctx, r.env.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
		if _, ok, err := tx.SessionByID(ib.SessionID); err != nil || ok {
			t.Errorf("A read B's session: ok=%v err=%v", ok, err)
		}
		if ok, err := tx.SessionRevoke(r.env.A.User, ib.SessionID); err != nil || ok {
			t.Errorf("A revoked B's session: ok=%v err=%v", ok, err)
		}
		_, err := r.m.Rotate(tx, ib.SessionID, store.ReauthKeep, false)
		if err != session.ErrGone {
			t.Errorf("A rotated B's session: %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !r.alive(t, b.Session, plain) {
		t.Fatal("B's session must be untouched")
	}
}

func TestRotateKeepsTheRowKillsTheOldTokenAndStartsANewRefreshFamily(t *testing.T) {
	r := newRig(t)
	old := r.create(t, r.env.A.Tenant, r.env.A.User, true, true)
	other := r.create(t, r.env.A.Tenant, r.env.A.User, false, false)
	createdBefore := createdAt(t, r, old.SessionID)

	var neu session.Issued
	r.ck.add(time.Minute)
	err := r.st.WithTenant(r.env.Ctx, r.env.A.Tenant, store.TxOpts{}, func(tx store.Tx) (err error) {
		neu, err = r.m.Rotate(tx, old.SessionID, store.ReauthSet, true)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := r.lookup(t, old.Session); ok {
		t.Fatal("the pre-rotation session cookie must be dead")
	}
	after, ok := r.lookup(t, neu.Session)
	if !ok || after.SessionID != old.SessionID {
		t.Fatal("the new token must resolve to the same row")
	}
	if after.ReauthAt == nil {
		t.Fatal("ReauthSet must start the reauth window")
	}
	err = r.st.WithTenant(r.env.Ctx, r.env.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
		row, _, err := tx.SessionByID(old.SessionID)
		if err != nil {
			return err
		}
		if row.Restricted {
			t.Error("clearRestricted must clear the record of the one-time password")
		}
		if !row.CreatedAt.Equal(createdBefore) {
			t.Error("rotation changed created_at, which the sessions page relies on")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// The old refresh cookie is dead and the new one works.
	res, err := r.m.Refresh(r.env.Ctx, old.Refresh.Reveal(), ip)
	if err != nil || res.Outcome != session.RefreshExpired {
		t.Fatalf("pre-rotation refresh cookie: %+v %v", res, err)
	}
	res, err = r.m.Refresh(r.env.Ctx, neu.Refresh.Reveal(), ip)
	if err != nil || res.Outcome != session.RefreshRotated {
		t.Fatalf("post-rotation refresh cookie: %+v %v", res, err)
	}
	if !r.alive(t, other.Session, plain) {
		t.Fatal("Rotate must not touch other sessions")
	}
}

func createdAt(t *testing.T, r *rig, id uuid.UUID) (at time.Time) {
	t.Helper()
	err := r.st.WithTenant(r.env.Ctx, r.env.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
		row, _, err := tx.SessionByID(id)
		at = row.CreatedAt
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return at
}

func TestApplyTable37(t *testing.T) {
	type want struct {
		currentRotates bool
		othersEnded    int  // sessions ended: o1, o2 and the one the seed gives the user, plus the current one where the event ends it
		tokensRevoked  bool // API tokens
		ticketClosed   bool
		reauthSet      bool
		currentDead    bool
	}
	cases := []struct {
		name string
		ev   session.Event
		want want
	}{
		{"reauth", session.EventReauth, want{currentRotates: true, reauthSet: true}},
		{"recovery regenerate", session.EventRecoveryRegenerate, want{currentRotates: true}},
		{"enforce disable", session.EventEnforceDisable, want{currentRotates: true}},
		{"totp enable", session.EventTOTPEnable, want{currentRotates: true, othersEnded: 3}},
		{"totp disable", session.EventTOTPDisable, want{currentRotates: true, othersEnded: 3, ticketClosed: true}},
		{"passkey add", session.EventPasskeyAdd, want{currentRotates: true, othersEnded: 3}},
		{"enforce enable", session.EventEnforceEnable, want{currentRotates: true, othersEnded: 3}},
		{"password change", session.EventPasswordChange, want{currentRotates: true, othersEnded: 3, tokensRevoked: true, ticketClosed: true}},
		{"phone change", session.EventPhoneChange, want{currentRotates: true, othersEnded: 3, tokensRevoked: true, ticketClosed: true}},
		{"forgot password complete", session.EventPasswordReset, want{othersEnded: 4, tokensRevoked: true, ticketClosed: true, currentDead: true}},
		{"logout", session.EventLogout, want{othersEnded: 1, currentDead: true}},
		{"logout all", session.EventLogoutAll, want{othersEnded: 4, currentDead: true}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newRig(t)
			tickets := ticket.New(r.st.Auth())
			ctx := r.env.Ctx
			cur := r.create(t, r.env.A.Tenant, r.env.A.User, true, false)
			o1 := r.create(t, r.env.A.Tenant, r.env.A.User, true, false)
			o2 := r.create(t, r.env.A.Tenant, r.env.A.User, false, false)
			bSess := r.create(t, r.env.B.Tenant, r.env.B.User, true, false)
			mfa, err := tickets.Put(ctx, ticket.Issue{Kind: store.TicketMFA, Tenant: r.env.A.Tenant, User: r.env.A.User, Cred: credgen.Stamp{Tenant: r.env.A.Tenant, Subject: r.env.A.User, Gen: 1}})
			if err != nil {
				t.Fatal(err)
			}
			mfaB, _ := tickets.Put(ctx, ticket.Issue{Kind: store.TicketMFA, Tenant: r.env.B.Tenant, User: r.env.B.User, Cred: credgen.Stamp{Tenant: r.env.B.Tenant, Subject: r.env.B.User, Gen: 1}})
			var out session.Outcome
			actor := session.Actor{User: r.env.A.User, Session: cur.SessionID}
			if c.ev == session.EventPasswordReset {
				actor.Session = uuid.Nil
			}
			err = r.st.WithTenant(ctx, r.env.A.Tenant, store.TxOpts{}, func(tx store.Tx) (err error) {
				out, err = r.m.Apply(tx, c.ev, actor)
				return err
			})
			if err != nil {
				t.Fatal(err)
			}

			if c.want.currentRotates {
				if out.Issued == nil || out.Issued.SessionID != cur.SessionID {
					t.Fatalf("expected a rotation of the current session: %+v", out)
				}
				info, ok := r.lookup(t, out.Issued.Session)
				if !ok || r.m.Check(info, plain) != nil {
					t.Fatal("the rotated session must work")
				}
				if (info.ReauthAt != nil) != c.want.reauthSet {
					t.Fatalf("reauth_at set = %v, want %v", info.ReauthAt != nil, c.want.reauthSet)
				}
				if r.alive(t, cur.Session, plain) {
					t.Fatal("the pre-rotation cookie must be dead")
				}
				// On a Remember me session the old refresh cookie is dead and the new one works.
				if res, _ := r.m.Refresh(ctx, cur.Refresh.Reveal(), ip); res.Outcome != session.RefreshExpired {
					t.Fatalf("old refresh cookie: %v", res.Outcome)
				}
				if out.Issued.Refresh.IsZero() {
					t.Fatal("a Remember me rotation must issue a new refresh cookie")
				}
				if res, _ := r.m.Refresh(ctx, out.Issued.Refresh.Reveal(), ip); res.Outcome != session.RefreshRotated {
					t.Fatalf("new refresh cookie: %v", res.Outcome)
				}
			} else {
				if out.Issued != nil {
					t.Fatal("no rotation expected")
				}
				if c.want.currentDead && r.alive(t, cur.Session, plain) {
					t.Fatal("the current session must be ended")
				}
			}
			if out.Ended != c.want.othersEnded {
				t.Fatalf("ended = %d, want %d", out.Ended, c.want.othersEnded)
			}
			// Others: alive exactly when the table says kept.
			othersAlive := r.alive(t, o1.Session, plain) || r.alive(t, o2.Session, plain)
			if (c.want.othersEnded > 0) == othersAlive && c.ev != session.EventLogout {
				t.Fatalf("others alive = %v", othersAlive)
			}
			if c.ev == session.EventLogout && (!r.alive(t, o1.Session, plain) || !r.alive(t, o2.Session, plain)) {
				t.Fatal("logout must keep the others")
			}
			// Tickets.
			_, mfaOK, _ := tickets.Peek(ctx, mfa.Token.Reveal(), store.TicketMFA)
			if mfaOK == c.want.ticketClosed {
				t.Fatalf("mfa ticket usable = %v, want %v", mfaOK, !c.want.ticketClosed)
			}
			// API tokens (R44): revoked by a password or phone change and by Forgot
			// Password, kept by everything else. B's are never touched.
			const qTokens = `SELECT count(*) FROM ctrlz.api_tokens WHERE revoked_at IS NULL`
			liveTokens := func(tenant uuid.UUID) (n int) {
				if err := r.st.WithTenant(ctx, tenant, store.TxOpts{}, func(tx store.Tx) error {
					return tx.DB().QueryRow(ctx, qTokens).Scan(&n)
				}); err != nil {
					t.Fatal(err)
				}
				return n
			}
			if got := liveTokens(r.env.A.Tenant); (got == 0) != c.want.tokensRevoked {
				t.Fatalf("A has %d live API tokens, revoked expected = %v", got, c.want.tokensRevoked)
			}
			if liveTokens(r.env.B.Tenant) == 0 {
				t.Fatal("B's API tokens were revoked")
			}
			// Two-tenant: B is never touched.
			if !r.alive(t, bSess.Session, plain) {
				t.Fatal("B's session died")
			}
			if _, ok, _ := tickets.Peek(ctx, mfaB.Token.Reveal(), store.TicketMFA); !ok {
				t.Fatal("B's ticket was closed")
			}
			if res, _ := r.m.Refresh(ctx, bSess.Refresh.Reveal(), ip); res.Outcome != session.RefreshRotated {
				t.Fatalf("B's refresh token: %v", res.Outcome)
			}
		})
	}
}

func TestApplyRefusesARevokedSessionAndChangesNothing(t *testing.T) {
	r := newRig(t)
	cur := r.create(t, r.env.A.Tenant, r.env.A.User, false, false)
	other := r.create(t, r.env.A.Tenant, r.env.A.User, false, false)
	err := r.st.WithTenant(r.env.Ctx, r.env.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
		_, err := tx.SessionRevoke(r.env.A.User, cur.SessionID)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	err = r.st.WithTenant(r.env.Ctx, r.env.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
		_, err := r.m.Apply(tx, session.EventPasswordChange, session.Actor{User: r.env.A.User, Session: cur.SessionID})
		return err
	})
	if err != session.ErrGone {
		t.Fatalf("got %v, want ErrGone", err)
	}
	if !r.alive(t, other.Session, plain) {
		t.Fatal("a failed event must not revoke the other sessions")
	}
}

func TestRefreshRotationGraceReuseAndExpiry(t *testing.T) {
	r := newRig(t)
	ctx := r.env.Ctx
	iss := r.create(t, r.env.A.Tenant, r.env.A.User, true, false)

	// A browser restart leaves only the refresh cookie: the session cookie is gone.
	r.ck.add(3 * time.Hour)
	if r.alive(t, iss.Session, plain) {
		t.Fatal("idle limit passed")
	}
	// A session reauth then a refresh: the refresh never inherits the window.
	res, err := r.m.Refresh(ctx, iss.Refresh.Reveal(), ip)
	if err != nil || res.Outcome != session.RefreshRotated {
		t.Fatalf("refresh: %+v %v", res, err)
	}
	if res.Issued.SessionID != iss.SessionID || res.Issued.Refresh.IsZero() {
		t.Fatal("refresh keeps the session row and issues a new refresh token")
	}
	info, ok := r.lookup(t, res.Issued.Session)
	if !ok || r.m.Check(info, plain) != nil || info.ReauthAt != nil {
		t.Fatalf("refreshed session: ok=%v reauth=%v", ok, info.ReauthAt)
	}

	// The same old token again, inside the grace: a concurrent tab, 204 with no cookies.
	r.ck.add(5 * time.Second)
	res2, err := r.m.Refresh(ctx, iss.Refresh.Reveal(), ip)
	if err != nil || res2.Outcome != session.RefreshGrace || !res2.Issued.Session.IsZero() {
		t.Fatalf("grace: %+v %v", res2, err)
	}
	// And the new token keeps working through further rotations.
	res3, err := r.m.Refresh(ctx, res.Issued.Refresh.Reveal(), ip)
	if err != nil || res3.Outcome != session.RefreshRotated {
		t.Fatalf("second rotation: %+v %v", res3, err)
	}

	// The first token again, past the grace: reuse. The family and the session end.
	r.ck.add(time.Minute)
	res4, err := r.m.Refresh(ctx, iss.Refresh.Reveal(), ip)
	if err != nil || res4.Outcome != session.RefreshReuse {
		t.Fatalf("reuse: %+v %v", res4, err)
	}
	if r.alive(t, res3.Issued.Session, plain) {
		t.Fatal("the session must be revoked by reuse")
	}
	if res5, _ := r.m.Refresh(ctx, res3.Issued.Refresh.Reveal(), ip); res5.Outcome != session.RefreshExpired {
		t.Fatalf("the whole family must be dead: %v", res5.Outcome)
	}
	// The reuse left an audit row, with no token in it.
	var n int
	const q = `SELECT count(*) FROM ctrlz.tenant_audit_log WHERE action = 'session.refresh_reuse' AND params::text NOT LIKE '%token%'`
	if err := r.st.WithTenant(ctx, r.env.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
		return tx.DB().QueryRow(ctx, q).Scan(&n)
	}); err != nil || n != 1 {
		t.Fatalf("audit rows: %d %v", n, err)
	}
}

func TestRefreshJunkExpiredAndPastAbsolute(t *testing.T) {
	r := newRig(t)
	ctx := r.env.Ctx
	for _, junk := range []string{"", "nope", strings.Repeat("A", 43)} {
		if res, err := r.m.Refresh(ctx, junk, ip); err != nil || res.Outcome != session.RefreshExpired {
			t.Errorf("Refresh(%q) = %+v %v", junk, res, err)
		}
	}
	iss := r.create(t, r.env.A.Tenant, r.env.A.User, true, false)
	r.ck.add(31 * 24 * time.Hour)
	if res, _ := r.m.Refresh(ctx, iss.Refresh.Reveal(), ip); res.Outcome != session.RefreshExpired {
		t.Fatalf("a refresh token past its 30 days: %v", res.Outcome)
	}
}

func TestRefreshParallelTabsOneWinsTheRestGetGrace(t *testing.T) {
	r := newRig(t)
	iss := r.create(t, r.env.A.Tenant, r.env.A.User, true, false)
	var wg sync.WaitGroup
	var mu sync.Mutex
	counts := map[session.RefreshOutcome]int{}
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := r.m.Refresh(r.env.Ctx, iss.Refresh.Reveal(), ip)
			if err != nil {
				t.Error(err)
				return
			}
			mu.Lock()
			counts[res.Outcome]++
			mu.Unlock()
		}()
	}
	wg.Wait()
	if counts[session.RefreshRotated] != 1 || counts[session.RefreshGrace] != 5 {
		t.Fatalf("outcomes: %v", counts)
	}
}

func TestRefreshOfAnotherTenantsTokenNeverCrosses(t *testing.T) {
	r := newRig(t)
	a := r.create(t, r.env.A.Tenant, r.env.A.User, true, false)
	b := r.create(t, r.env.B.Tenant, r.env.B.User, true, false)
	res, err := r.m.Refresh(r.env.Ctx, a.Refresh.Reveal(), ip)
	if err != nil || res.Outcome != session.RefreshRotated || res.Issued.SessionID != a.SessionID {
		t.Fatalf("%+v %v", res, err)
	}
	if !r.alive(t, b.Session, plain) {
		t.Fatal("B untouched")
	}
	info, _ := r.lookup(t, res.Issued.Session)
	if info.TenantID != r.env.A.Tenant || info.UserID != r.env.A.User {
		t.Fatal("the refreshed session must stay A's")
	}
	_ = token.Valid
}

func TestFixation(t *testing.T) {
	// Create never reads a cookie: the token is fresh whatever the request held.
	r := newRig(t)
	a := r.create(t, r.env.A.Tenant, r.env.A.User, false, false)
	b := r.create(t, r.env.A.Tenant, r.env.A.User, false, false)
	if a.Session.Equal(b.Session) || a.SessionID == b.SessionID {
		t.Fatal("every login is a new row with a new token")
	}
}

// ---------------------------------------------------------------------------
// Admin sessions

func TestAdminSessionLifecycle(t *testing.T) {
	env := authtest.New(t, cluster)
	adm := env.Admin(t)
	ck := newClock()
	m := session.NewManager(adm, session.DefaultPolicy(), ck.now)
	ctx := env.Ctx
	admin := uuid.MustParse("00000000-0000-7000-8000-0000000000e1")

	var iss session.AdminIssued
	if err := adm.WithGlobal(ctx, store.TxOpts{}, func(g store.GlobalTx) (err error) {
		iss, err = m.AdminCreate(g, session.AdminNew{Admin: admin, IP: ip, UserAgent: "test"})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	info, ok, err := m.AdminLookup(ctx, iss.Token.Reveal())
	if err != nil || !ok || info.AdminID != admin {
		t.Fatalf("lookup: %+v %v %v", info, ok, err)
	}
	// The seeded admin has no TOTP: setup state.
	if err := m.AdminCheck(info, apispec.Admin); err != session.ErrSetupRequired {
		t.Fatalf("seed admin without TOTP on an admin route: %v", err)
	}
	if err := m.AdminCheck(info, apispec.AdminSetup); err != nil {
		t.Fatalf("setup route: %v", err)
	}

	// Rotation kills the old token.
	var neu session.AdminIssued
	if err := adm.WithGlobal(ctx, store.TxOpts{}, func(g store.GlobalTx) (err error) {
		neu, err = m.AdminRotate(g, info)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := m.AdminLookup(ctx, iss.Token.Reveal()); ok {
		t.Fatal("the pre-rotation admin cookie must be dead")
	}
	if _, ok, _ := m.AdminLookup(ctx, neu.Token.Reveal()); !ok {
		t.Fatal("the rotated admin cookie must work")
	}

	// 15 minutes idle.
	ck.add(16 * time.Minute)
	info, _, _ = m.AdminLookup(ctx, neu.Token.Reveal())
	if err := m.AdminCheck(info, apispec.AdminSetup); err != session.ErrExpired {
		t.Fatalf("after 16 idle minutes: %v", err)
	}
}

func TestPanelCookieIsNotAnAdminCookie(t *testing.T) {
	// The two lookups read different tables: a panel session token presented to
	// the admin lookup finds nothing, and the reverse.
	r := newRig(t)
	a := r.create(t, r.env.A.Tenant, r.env.A.User, false, false)
	adm := r.env.Admin(t)
	m := session.NewManager(adm, session.DefaultPolicy(), r.ck.now)
	if _, ok, err := m.AdminLookup(r.env.Ctx, a.Session.Reveal()); err != nil || ok {
		t.Fatalf("a panel token resolved as an admin session: %v %v", ok, err)
	}
	var adminTok session.AdminIssued
	if err := adm.WithGlobal(r.env.Ctx, store.TxOpts{}, func(g store.GlobalTx) (err error) {
		adminTok, err = m.AdminCreate(g, session.AdminNew{Admin: uuid.MustParse("00000000-0000-7000-8000-0000000000e1")})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := r.m.Lookup(r.env.Ctx, adminTok.Token.Reveal()); err != nil || ok {
		t.Fatalf("an admin token resolved as a panel session: %v %v", ok, err)
	}
}

// TestRefreshRacingARotateGetsExpiredNotGrace is primitives-r1-4. A reauth
// (Rotate) holds the session row and revokes the refresh tokens; a refresh that
// passed its first read waits on the session row, and when it gets in the token
// is revoked, not rotated. It must answer expired (401, sign in again), where it
// used to answer grace (204 without cookies) and send the client back with a
// cookie that is dead. It also proves the lock order: the refresh waits on the
// session row first, so it cannot hold the refresh row Rotate needs.
func TestRefreshRacingARotateGetsExpiredNotGrace(t *testing.T) {
	r := newRig(t)
	iss := r.create(t, r.env.A.Tenant, r.env.A.User, true, false)

	rotating := make(chan struct{})
	proceed := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- r.st.WithTenant(r.env.Ctx, r.env.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
			if _, err := r.m.Rotate(tx, iss.SessionID, store.ReauthSet, false); err != nil {
				return err
			}
			close(rotating)
			<-proceed
			return nil
		})
	}()
	<-rotating

	got := make(chan session.RefreshResult, 1)
	go func() {
		res, err := r.m.Refresh(r.env.Ctx, iss.Refresh.Reveal(), ip)
		if err != nil {
			t.Error(err)
		}
		got <- res
	}()
	// The refresh is now blocked on the session row: wait for that, as a condition.
	r.env.WaitForLockWaiters(t, 1)
	close(proceed)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if res := <-got; res.Outcome != session.RefreshExpired {
		t.Fatalf("outcome %v, want RefreshExpired", res.Outcome)
	}
}

// TestRefreshAndRotateInParallelNeverDeadlock runs the two orders against each
// other on a Remember me session. With opposite lock orders Postgres kills one
// of them (40P01, ErrRetry) after the deadlock timeout.
func TestRefreshAndRotateInParallelNeverDeadlock(t *testing.T) {
	r := newRig(t)
	for i := 0; i < 8; i++ {
		iss := r.create(t, r.env.A.Tenant, r.env.A.User, true, false)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			if _, err := r.m.Refresh(r.env.Ctx, iss.Refresh.Reveal(), ip); err != nil {
				t.Errorf("refresh: %v", err)
			}
		}()
		go func() {
			defer wg.Done()
			err := r.st.WithTenant(r.env.Ctx, r.env.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
				_, err := r.m.Rotate(tx, iss.SessionID, store.ReauthSet, false)
				return err
			})
			if err != nil {
				t.Errorf("rotate: %v", err)
			}
		}()
		wg.Wait()
	}
}

// TestRefreshRacingARevokeAllNeverDeadlocks is db-r1-2 and db-r1-9. Log out all
// (SessionsRevokeOthers) and the admin's re-issue (RevokeUserSessions) lock the
// session row and then its refresh tokens (the admin's re-issue does it inside one
// function since migration 0020, see TestAdminRevokeRacingARefreshNeverDeadlocks). A refresh that took the refresh row
// first and the session row second formed a cycle with them: Postgres aborted
// the revoking transaction (40P01, a 503 and nothing revoked) while the thief's
// rotation committed. The revoker here holds the session lock, the refresh then
// starts, and only then does the revoker go on to the refresh rows; with the
// session locked first the refresh waits on it and finds the token revoked.
func TestRefreshRacingARevokeAllNeverDeadlocks(t *testing.T) {
	r := newRig(t)
	revokers := map[string]struct {
		db     *store.Store
		lock   func(tx store.Tx, session uuid.UUID) error
		revoke func(tx store.Tx, user uuid.UUID) error
	}{
		"log out all": {r.st, func(tx store.Tx, session uuid.UUID) error {
			_, ok, err := tx.SessionByIDForUpdate(session)
			if err == nil && !ok {
				err = errors.New("no session")
			}
			return err
		}, func(tx store.Tx, user uuid.UUID) error {
			_, err := tx.SessionsRevokeOthers(user, uuid.Nil, time.Now())
			return err
		}},
	}
	for name, rv := range revokers {
		t.Run(name, func(t *testing.T) {
			iss := r.create(t, r.env.A.Tenant, r.env.A.User, true, false)
			holding := make(chan struct{})
			proceed := make(chan struct{})
			done := make(chan error, 1)
			go func() {
				done <- rv.db.WithTenant(r.env.Ctx, r.env.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
					// The first statement of every revoker: the session row, not yet the refresh rows.
					if err := rv.lock(tx, iss.SessionID); err != nil {
						return err
					}
					close(holding)
					<-proceed
					return rv.revoke(tx, r.env.A.User)
				})
			}()
			select {
			case <-holding:
			case err := <-done:
				t.Fatalf("the revoking transaction failed before it held the session: %v", err)
			}

			got := make(chan session.RefreshResult, 1)
			refreshErr := make(chan error, 1)
			go func() {
				res, err := r.m.Refresh(r.env.Ctx, iss.Refresh.Reveal(), ip)
				refreshErr <- err
				got <- res
			}()
			time.Sleep(400 * time.Millisecond) // the refresh has run as far as it can without the session row
			close(proceed)
			if err := <-done; err != nil {
				t.Fatalf("the revoking transaction: %v (a deadlock victim is ErrRetry)", err)
			}
			if err := <-refreshErr; err != nil {
				t.Fatalf("refresh: %v", err)
			}
			if res := <-got; res.Outcome != session.RefreshExpired {
				t.Fatalf("outcome %v, want RefreshExpired: the revoked family must not rotate", res.Outcome)
			}
		})
	}
}

// TestRefreshRacingAUserLockHolderNeverDeadlocks is db-r4-1 and db-r4-2. Every
// writer that changes credentials locks the users row first (the user's own
// password change, reauth, the admin's one-time password re-issue) and then
// reaches the session. Refresh locks the session first, and the new refresh row it
// inserts takes FOR KEY SHARE on the users row through the composite foreign key. A
// users lock of FOR UPDATE strength conflicts with that, so the two formed a
// cycle: the holder waited for the session, the refresh for the user. The tests
// above never held the users lock, which is the production order.
//
// The holder takes the users lock, waits until the refresh has run as far as it
// can, and only then goes on to the session. The same race is run for the three
// holders, in a loop, and neither side may fail: a deadlock victim is ErrRetry,
// a 503 for the user, and the store retries nothing.
func TestRefreshRacingAUserLockHolderNeverDeadlocks(t *testing.T) {
	r := newRig(t)
	adm := r.env.Admin(t)
	holders := map[string]struct {
		db   *store.Store
		lock func(tx store.Tx, user uuid.UUID) error
		then func(tx store.Tx, user, session uuid.UUID) error
	}{
		"reauth": {r.st, func(tx store.Tx, user uuid.UUID) error {
			_, _, err := tx.UserLock(user)
			return err
		}, func(tx store.Tx, _, session uuid.UUID) error {
			_, err := r.m.Rotate(tx, session, store.ReauthSet, false)
			return err
		}},
		"password change": {r.st, func(tx store.Tx, user uuid.UUID) error {
			_, _, err := tx.UserLock(user)
			return err
		}, func(tx store.Tx, user, _ uuid.UUID) error {
			_, err := tx.SessionsRevokeOthers(user, uuid.Nil, time.Now())
			return err
		}},
		"admin re-issue": {adm, func(tx store.Tx, user uuid.UUID) error {
			_, _, err := tx.OneTimePasswordLock(user)
			return err
		}, func(tx store.Tx, user, _ uuid.UUID) error {
			_, err := tx.RevokeUserSessions(user)
			return err
		}},
	}
	for name, h := range holders {
		t.Run(name, func(t *testing.T) {
			for round := 0; round < 4; round++ {
				iss := r.create(t, r.env.A.Tenant, r.env.A.User, true, false)
				holding := make(chan struct{})
				proceed := make(chan struct{})
				done := make(chan error, 1)
				go func() {
					done <- h.db.WithTenant(r.env.Ctx, r.env.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
						if err := h.lock(tx, r.env.A.User); err != nil {
							return err
						}
						close(holding)
						<-proceed
						return h.then(tx, r.env.A.User, iss.SessionID)
					})
				}()
				select {
				case <-holding:
				case err := <-done:
					t.Fatalf("the holder failed before it held the users row: %v", err)
				}
				refreshed := make(chan error, 1)
				go func() {
					_, err := r.m.Refresh(r.env.Ctx, iss.Refresh.Reveal(), ip)
					refreshed <- err
				}()
				// The refresh has locked the session and gone on to its new refresh row, which
				// needs the users row the holder has locked.
				time.Sleep(400 * time.Millisecond)
				close(proceed)
				if err := <-done; err != nil {
					t.Fatalf("round %d: the lock holder failed: %v (a deadlock victim is ErrRetry)", round, err)
				}
				if err := <-refreshed; err != nil {
					t.Fatalf("round %d: the refresh failed: %v (a deadlock victim is ErrRetry)", round, err)
				}
			}
		})
	}
}

// TestRefreshLifeIsCappedAtTheAbsoluteLimit is primitives-r3-3. A refresh token
// lives 30 days from issue, capped at the row's absolute limit (3.3). The chain
// below keeps a Remember me session alive by refreshing every 27 to 29 days, so
// the token issued on day 85 would run to day 115 without the cap; with it, it
// ends on day 90 with the row, and Max-Age shrinks to the 5 days that are left.
// Past the limit, a token that is still unexpired (made by hand here, since the
// cap makes one impossible) is refused by Refresh itself.
func TestRefreshLifeIsCappedAtTheAbsoluteLimit(t *testing.T) {
	r := newRig(t)
	ctx := r.env.Ctx
	day := 24 * time.Hour
	iss := r.create(t, r.env.A.Tenant, r.env.A.User, true, false)
	if iss.RefreshMaxAge != 30*day {
		t.Fatalf("a refresh token on day 0 lives 30 days, got %v", iss.RefreshMaxAge)
	}
	cur := iss
	for _, step := range []time.Duration{29 * day, 29 * day, 27 * day} { // days 29, 58, 85
		r.ck.add(step)
		res, err := r.m.Refresh(ctx, cur.Refresh.Reveal(), ip)
		if err != nil || res.Outcome != session.RefreshRotated {
			t.Fatalf("refresh: %+v %v", res, err)
		}
		cur = res.Issued
	}
	if cur.RefreshMaxAge > 5*day || cur.RefreshMaxAge < 5*day-time.Minute {
		t.Fatalf("on day 85 the refresh token has the 5 days that are left, got %v", cur.RefreshMaxAge)
	}
	if cs := cur.Cookies(); cs[1].Name != session.CookieRefresh || time.Duration(cs[1].MaxAge)*time.Second > 5*day {
		t.Fatalf("Max-Age of the cookie %v", cs[1])
	}
	var over int
	r.env.Scan(t, `SELECT count(*) FROM ctrlz.refresh_tokens rt JOIN ctrlz.sessions s ON s.id = rt.session_id
		WHERE rt.session_id = $1 AND rt.expires_at > s.absolute_expires_at`, []any{iss.SessionID}, &over)
	if over != 0 {
		t.Fatalf("%d refresh rows outlive their session", over)
	}

	// Past the absolute limit, with a token the cap would never have made.
	r.env.Exec(t, `UPDATE ctrlz.refresh_tokens SET expires_at = expires_at + interval '60 days' WHERE session_id = $1`, iss.SessionID)
	r.ck.add(6 * day) // day 91
	res, err := r.m.Refresh(ctx, cur.Refresh.Reveal(), ip)
	if err != nil || res.Outcome != session.RefreshExpired || !res.Issued.Session.IsZero() {
		t.Fatalf("a refresh past the session's absolute limit: %+v %v", res, err)
	}
	if r.alive(t, cur.Session, plain) {
		t.Fatal("the session is past its absolute limit")
	}
}

// TestReauthWindowUsesTheApplicationClock is primitives-r3-4. reauth_at used to be
// stamped by the database clock and compared with the application clock, so a
// skew between the two stretched the 10 minute window or closed it on arrival.
// Both clocks are put 3 hours away from the database's here, in both directions.
func TestReauthWindowUsesTheApplicationClock(t *testing.T) {
	for name, skew := range map[string]time.Duration{"app ahead": 3 * time.Hour, "app behind": -3 * time.Hour} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			r.ck.add(skew)
			iss := r.create(t, r.env.A.Tenant, r.env.A.User, false, false)
			var neu session.Issued
			err := r.st.WithTenant(r.env.Ctx, r.env.A.Tenant, store.TxOpts{}, func(tx store.Tx) (err error) {
				neu, err = r.m.Rotate(tx, iss.SessionID, store.ReauthSet, false)
				return err
			})
			if err != nil {
				t.Fatal(err)
			}
			info, ok := r.lookup(t, neu.Session)
			if !ok || info.ReauthAt == nil {
				t.Fatalf("no reauth_at after ReauthSet: ok=%v", ok)
			}
			if d := info.ReauthAt.Sub(r.ck.now()); d > time.Second || d < -time.Second {
				t.Fatalf("reauth_at is %v from the application clock", d)
			}
			if !r.m.ReauthFresh(info.ReauthAt) {
				t.Fatal("a reauth just made must be fresh")
			}
			r.ck.add(9 * time.Minute)
			if !r.m.ReauthFresh(info.ReauthAt) {
				t.Fatal("still fresh after 9 minutes")
			}
			r.ck.add(2 * time.Minute)
			if r.m.ReauthFresh(info.ReauthAt) {
				t.Fatal("stale after 11 minutes, whatever the database clock says")
			}
		})
	}
}

// TestAdminRevokeRacingARefreshNeverDeadlocks is the admin half of the test above.
// ctrlz_admin holds no UPDATE on the session tables since migration 0020, so it cannot
// hold a session lock from outside; ctrlz_fn.admin_revoke_user_sessions takes the
// session rows and then the refresh rows inside one call, the order Refresh uses. The
// two overlap here with no lock held between them; whichever wins, neither may be a
// deadlock victim, and a revoke that ran leaves nothing live.
func TestAdminRevokeRacingARefreshNeverDeadlocks(t *testing.T) {
	r := newRig(t)
	adm := r.env.Admin(t)
	for i := 0; i < 6; i++ {
		iss := r.create(t, r.env.A.Tenant, r.env.A.User, true, false)
		start := make(chan struct{})
		revoked := make(chan error, 1)
		refreshed := make(chan error, 1)
		go func() {
			<-start
			revoked <- adm.WithTenant(r.env.Ctx, r.env.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
				_, err := tx.RevokeUserSessions(r.env.A.User)
				return err
			})
		}()
		go func() {
			<-start
			_, err := r.m.Refresh(r.env.Ctx, iss.Refresh.Reveal(), ip)
			refreshed <- err
		}()
		close(start)
		if err := <-revoked; err != nil {
			t.Fatalf("round %d: the admin revoke: %v (a deadlock victim is ErrRetry)", i, err)
		}
		if err := <-refreshed; err != nil {
			t.Fatalf("round %d: refresh: %v", i, err)
		}
	}
}

// Review round 5, db-r5-5. The foreign key (tenant_id, user_id, session_id) makes a refresh
// row that names another user than its session impossible to store (0026). Refresh compares
// the two anyway, because the key share, the new refresh row and the audit event all name the
// refresh row's user: the test takes the key away and plants the mismatch the day members
// arrive could produce, and expects the same answer as for a dead session, with the session
// left as it was.
func TestRefreshOfASessionThatBelongsToAnotherUserIsRefused(t *testing.T) {
	r := newRig(t)
	ctx := r.env.Ctx
	iss := r.create(t, r.env.A.Tenant, r.env.A.User, true, false)
	r.env.Exec(t, `DROP INDEX ctrlz.users_one_owner_uq`)
	r.env.Exec(t, `ALTER TABLE ctrlz.refresh_tokens DROP CONSTRAINT refresh_tokens_session_user_fkey`)
	r.env.Exec(t, `INSERT INTO ctrlz.users (tenant_id, id, phone_e164, password_hash) VALUES ($1, '00000000-0000-7000-8000-00000000aaaa', '+989000000077', 'argon2id$member')`, r.env.A.Tenant)
	r.env.Exec(t, `UPDATE ctrlz.refresh_tokens SET user_id = '00000000-0000-7000-8000-00000000aaaa' WHERE tenant_id = $1 AND session_id = $2`, r.env.A.Tenant, iss.SessionID)
	res, err := r.m.Refresh(ctx, iss.Refresh.Reveal(), ip)
	if err != nil || res.Outcome != session.RefreshExpired || !res.Issued.Session.IsZero() {
		t.Fatalf("a refresh row naming another user than its session: %+v %v, want expired and nothing issued", res, err)
	}
	if !r.alive(t, iss.Session, plain) {
		t.Error("the refused refresh touched the session")
	}
}

// TestEveryIssuerCarriesTheIDOfTheSessionItOpens is tenant-r8-3. The session-miss budget of a dead cookie
// is keyed on what the cookie's body names, so the body must name the SESSION (fixed for its life,
// a rotation and a refresh keep it) and nothing wider: a cookie that named the account would put the dead
// cookies of one stolen session on the budget of every session of the owner. Every way a cookie is
// made is held to it: Create (with and without a refresh), Rotate, Refresh, AdminCreate, AdminRotate.
func TestEveryIssuerCarriesTheIDOfTheSessionItOpens(t *testing.T) {
	r := newRig(t)
	if err := r.m.WithKeys(authtest.APIKeys(t), keyring.DomainAuthMAC); err != nil {
		t.Fatal(err)
	}
	opens := func(m *session.Manager, cookie secret.String, want uuid.UUID, what string) {
		t.Helper()
		_, id, ok := m.Screen(cookie.Reveal())
		if !ok || id != want.String() {
			t.Fatalf("%s: the cookie names %q (plausible %v), want the session %s", what, id, ok, want)
		}
		if want == r.env.A.User {
			t.Fatalf("%s: the session id is the account id", what)
		}
	}

	plainSession := r.create(t, r.env.A.Tenant, r.env.A.User, false, false)
	opens(r.m, plainSession.Session, plainSession.SessionID, "Create")
	remembered := r.create(t, r.env.A.Tenant, r.env.A.User, true, false)
	opens(r.m, remembered.Session, remembered.SessionID, "Create with Remember me")
	if plainSession.SessionID == remembered.SessionID {
		t.Fatal("two sessions share an id")
	}
	// The row is stored under the id the cookie carries.
	if info, ok := r.lookup(t, plainSession.Session); !ok || info.SessionID != plainSession.SessionID {
		t.Fatalf("the cookie does not resolve to the row it names: %+v %v", info, ok)
	}

	var rot session.Issued
	if err := r.st.WithTenant(r.env.Ctx, r.env.A.Tenant, store.TxOpts{}, func(tx store.Tx) (err error) {
		rot, err = r.m.Rotate(tx, remembered.SessionID, store.ReauthSet, false)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	opens(r.m, rot.Session, remembered.SessionID, "Rotate")

	res, err := r.m.Refresh(r.env.Ctx, rot.Refresh.Reveal(), ip)
	if err != nil || res.Outcome != session.RefreshRotated {
		t.Fatalf("refresh: %+v %v", res, err)
	}
	opens(r.m, res.Issued.Session, remembered.SessionID, "Refresh")

	// The admin side.
	adm := r.env.Admin(t)
	am := session.NewManager(adm, session.DefaultPolicy(), r.ck.now)
	if err := am.WithKeys(authtest.AdminKeys(t), keyring.DomainAdminMAC); err != nil {
		t.Fatal(err)
	}
	admin := uuid.MustParse("00000000-0000-7000-8000-0000000000e1")
	var iss session.AdminIssued
	if err := adm.WithGlobal(r.env.Ctx, store.TxOpts{}, func(g store.GlobalTx) (err error) {
		iss, err = am.AdminCreate(g, session.AdminNew{Admin: admin, IP: ip, UserAgent: "test"})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	opens(am, iss.Token, iss.SessionID, "AdminCreate")
	info, ok, err := am.AdminLookup(r.env.Ctx, iss.Token.Reveal())
	if err != nil || !ok || info.SessionID != iss.SessionID {
		t.Fatalf("admin lookup: %+v %v %v", info, ok, err)
	}
	var neu session.AdminIssued
	if err := adm.WithGlobal(r.env.Ctx, store.TxOpts{}, func(g store.GlobalTx) (err error) {
		neu, err = am.AdminRotate(g, info)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	opens(am, neu.Token, iss.SessionID, "AdminRotate")
}

// TestEveryEventHasADeclaredFateForTheReauthWindow is rule 5 (credential-generation) and
// round 10 (tenant-r10-1) applied to the window: no event chooses its own mode, and what each
// does to a window that is open is the table's word, seen on the database row.
func TestEveryEventHasADeclaredFateForTheReauthWindow(t *testing.T) {
	for _, ev := range session.Events() {
		fate, ok := session.WindowFateOf(ev)
		if !ok {
			t.Fatalf("event %d has no declared fate for the reauth window", ev)
		}
		// Only these two events may leave a window standing past a rise in what a reauth asks for.
		if ev == session.EventTOTPEnable && fate != session.WindowClear {
			t.Fatalf("TOTP enable must end the window, fate = %d", fate)
		}
	}
	for _, ev := range session.Events() {
		fate, _ := session.WindowFateOf(ev)
		if fate == session.WindowNone {
			continue // no surviving session to read
		}
		ev := ev
		t.Run("", func(t *testing.T) {
			r := newRig(t)
			ctx := r.env.Ctx
			cur := r.create(t, r.env.A.Tenant, r.env.A.User, false, false)
			actor := session.Actor{User: r.env.A.User, Session: cur.SessionID}
			var out session.Outcome
			apply := func(e session.Event) session.Outcome {
				var o session.Outcome
				err := r.st.WithTenant(ctx, r.env.A.Tenant, store.TxOpts{}, func(tx store.Tx) (err error) {
					// The factors do not change in this walk, so what the route would read before its
					// change is what is there now (an event that can change them keeps a window only on
					// that word, primitives-r11-4).
					before, err := session.FactorsOf(tx, r.env.A.User)
					if err != nil {
						return err
					}
					act := actor
					act.Before = &before
					o, err = r.m.Apply(tx, e, act)
					return err
				})
				if err != nil {
					t.Fatal(err)
				}
				return o
			}
			// Open the window, then let the event act on it.
			apply(session.EventReauth)
			if ev == session.EventReauth {
				fate = session.WindowSet
			}
			out = apply(ev)
			if out.Issued == nil {
				t.Fatalf("event %d rotated nothing", ev)
			}
			info, ok := r.lookup(t, out.Issued.Session)
			if !ok {
				t.Fatalf("event %d: the rotated session does not resolve", ev)
			}
			open := info.ReauthAt != nil
			switch fate {
			case session.WindowSet, session.WindowKeep:
				if !open {
					t.Fatalf("event %d is declared to leave the window open and it is closed", ev)
				}
			case session.WindowClear:
				if open {
					t.Fatalf("event %d is declared to end the window and it is open", ev)
				}
			}
		})
	}
}

// Spec 3.5 (round 10, primitives-r10-3): refresh reads no tenant status, so a Remember me browser of a
// suspended tenant is renewed, and the renewed session reaches GET /me and POST /auth/logout and nothing
// else; a tenant that is deleting renews a session that every route refuses. The tenant's status is read
// by Check on the session's lookup, never by Refresh, so a change that makes Refresh read it (and answer
// "expired" to a suspended owner, who then cannot reach the page that says why) or that renews a session
// past the gate fails here. Tenant B, active, is untouched.
func TestRefreshOfASuspendedOrDeletingTenantRenewsASessionTheGateStillRefuses(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		status        string
		normal, setup error
	}{
		{"suspended", session.ErrSuspended, nil},
		{"deleting", session.ErrExpired, session.ErrExpired},
	} {
		t.Run(tc.status, func(t *testing.T) {
			r := newRig(t)
			a := r.create(t, r.env.A.Tenant, r.env.A.User, true, false)
			b := r.create(t, r.env.B.Tenant, r.env.B.User, true, false)
			r.env.Exec(t, `UPDATE ctrlz.tenants SET status = $2 WHERE id = $1`, r.env.A.Tenant, tc.status)
			r.ck.add(3 * time.Hour) // a browser restart: the session cookie is gone, the refresh cookie is not

			res, err := r.m.Refresh(ctx, a.Refresh.Reveal(), ip)
			if err != nil || res.Outcome != session.RefreshRotated {
				t.Fatalf("refresh of a %s tenant: %+v %v, want a rotation (refresh reads no tenant status)", tc.status, res, err)
			}
			info, ok := r.lookup(t, res.Issued.Session)
			if !ok {
				t.Fatal("the renewed session is not found")
			}
			if got := r.m.Check(info, plain); !errors.Is(got, tc.normal) {
				t.Errorf("a normal route on the renewed session of a %s tenant: %v, want %v", tc.status, got, tc.normal)
			}
			if got := r.m.Check(info, session.Gate{Auth: apispec.SessionSetup, AllowSuspended: true}); !errors.Is(got, tc.setup) {
				t.Errorf("GET /me or logout on the renewed session of a %s tenant: %v, want %v", tc.status, got, tc.setup)
			}
			// The other tenant renews and serves as always.
			resB, err := r.m.Refresh(ctx, b.Refresh.Reveal(), ip)
			if err != nil || resB.Outcome != session.RefreshRotated {
				t.Fatalf("tenant B refresh: %+v %v", resB, err)
			}
			if !r.alive(t, resB.Issued.Session, plain) {
				t.Error("tenant B's renewed session is refused because tenant A is " + tc.status)
			}
		})
	}
}

// TestWindowOfEveryEventOverEveryFactorState is primitives-r11-4 on the database row. The reauth window is
// earned under what the account asked for at that moment, so what an event does to it depends on the state
// before the event as well as on the event: POST /account/password is a password change for a user who has a
// password and the FIRST password of one who has none, and the first password raises the bar from an SMS code
// to the password. The test walks every event over every starting state (none, password, password and TOTP,
// TOTP only), does the credential change the route does, opens a window first, and reads the window on the
// rotated session. The oracle is 3.5 as a sentence (an SMS code is the lowest bar; a window survives a row
// whose every proof it was asked for), written out here and not taken from the package.
func TestWindowOfEveryEventOverEveryFactorState(t *testing.T) {
	// What each event does to the factors, as its route does it. An event that is not here has no declared
	// effect and fails the test, so a new event has to say.
	type effect struct {
		applies    func(f session.Factors) bool
		after      func(f session.Factors) session.Factors
		saysBefore bool // the route hands Apply the factors it read before the change
	}
	same := effect{applies: func(session.Factors) bool { return true }, after: func(f session.Factors) session.Factors { return f }}
	effects := map[session.Event]effect{
		session.EventReauth:             same,
		session.EventRecoveryRegenerate: same,
		session.EventEnforceDisable:     same,
		session.EventPasskeyAdd:         same,
		session.EventEnforceEnable:      same,
		session.EventPhoneChange:        same,
		session.EventPasswordChange: {
			applies:    func(session.Factors) bool { return true },
			after:      func(f session.Factors) session.Factors { f.Password = true; return f },
			saysBefore: true,
		},
		session.EventTOTPEnable: {
			applies:    func(f session.Factors) bool { return !f.TOTP },
			after:      func(f session.Factors) session.Factors { f.TOTP = true; return f },
			saysBefore: true,
		},
		session.EventTOTPDisable: {
			applies:    func(f session.Factors) bool { return f.TOTP },
			after:      func(f session.Factors) session.Factors { f.TOTP = false; return f },
			saysBefore: true,
		},
	}
	table := func(f session.Factors) map[string]bool {
		switch {
		case f.Password && f.TOTP:
			return map[string]bool{"password": true, "totp": true}
		case f.Password:
			return map[string]bool{"password": true}
		case f.TOTP:
			return map[string]bool{"totp": true}
		}
		return map[string]bool{"sms": true}
	}
	survives := func(before, after session.Factors) bool {
		ra, rb := table(after), table(before)
		if ra["sms"] {
			return true
		}
		for k := range ra {
			if !rb[k] {
				return false
			}
		}
		return true
	}
	states := []session.Factors{{}, {Password: true}, {Password: true, TOTP: true}, {TOTP: true}}
	for _, ev := range session.Events() {
		fate, ok := session.WindowFateOf(ev)
		if !ok {
			t.Fatalf("event %d has no declared fate", ev)
		}
		if fate == session.WindowNone {
			continue
		}
		eff, ok := effects[ev]
		if !ok {
			t.Fatalf("event %d is not in this test's table of what an event does to the factors: say what it does", ev)
		}
		for _, start := range states {
			if !eff.applies(start) {
				continue
			}
			ev, start := ev, start
			t.Run("", func(t *testing.T) {
				r := newRig(t)
				ctx := r.env.Ctx
				setFactors := func(f session.Factors) {
					r.env.Exec(t, `UPDATE ctrlz.users SET password_hash = CASE WHEN $3::boolean THEN 'argon2id$planted' END,
						totp_enabled_at = CASE WHEN $4::boolean THEN now() END WHERE tenant_id = $1 AND id = $2`,
						r.env.A.Tenant, r.env.A.User, f.Password, f.TOTP)
				}
				setFactors(start)
				cur := r.create(t, r.env.A.Tenant, r.env.A.User, false, false)
				actor := session.Actor{User: r.env.A.User, Session: cur.SessionID}
				apply := func(e session.Event, a session.Actor) session.Outcome {
					var o session.Outcome
					if err := r.st.WithTenant(ctx, r.env.A.Tenant, store.TxOpts{}, func(tx store.Tx) (err error) {
						o, err = r.m.Apply(tx, e, a)
						return err
					}); err != nil {
						t.Fatal(err)
					}
					return o
				}
				first := apply(session.EventReauth, actor) // the window, earned under the row of start
				if ev == session.EventReauth {
					first = session.Outcome{}
				}
				_ = first
				// The route's credential change, and the factors it read before it.
				after := eff.after(start)
				a := actor
				if eff.saysBefore {
					before := start
					a.Before = &before
				}
				setFactors(after)
				out := apply(ev, a)
				if out.Issued == nil {
					t.Fatalf("event %d rotated nothing", ev)
				}
				info, ok := r.lookup(t, out.Issued.Session)
				if !ok {
					t.Fatalf("event %d: the rotated session does not resolve", ev)
				}
				open := info.ReauthAt != nil
				want := false
				switch fate {
				case session.WindowSet:
					want = true
				case session.WindowKeep:
					want = survives(start, after)
				}
				if open != want {
					t.Errorf("event %d from %+v to %+v: window open %v, want %v (an SMS code does not satisfy a password)", ev, start, after, open, want)
				}
				// The account of the other tenant is not touched by any of this.
				if _, ok, err := r.m.Lookup(ctx, "x"); err != nil || ok {
					t.Fatalf("lookup of a made-up cookie: %v %v", ok, err)
				}
			})
		}
	}
	// A caller that changes a password and does not say what the factors were gets no kept window.
	t.Run("no word about the factors", func(t *testing.T) {
		r := newRig(t)
		ctx := r.env.Ctx
		r.env.Exec(t, `UPDATE ctrlz.users SET password_hash = 'argon2id$planted' WHERE tenant_id = $1 AND id = $2`, r.env.A.Tenant, r.env.A.User)
		cur := r.create(t, r.env.A.Tenant, r.env.A.User, false, false)
		actor := session.Actor{User: r.env.A.User, Session: cur.SessionID}
		var out session.Outcome
		for _, ev := range []session.Event{session.EventReauth, session.EventPasswordChange} {
			if err := r.st.WithTenant(ctx, r.env.A.Tenant, store.TxOpts{}, func(tx store.Tx) (err error) {
				out, err = r.m.Apply(tx, ev, actor)
				return err
			}); err != nil {
				t.Fatal(err)
			}
		}
		if info, ok := r.lookup(t, out.Issued.Session); !ok || info.ReauthAt != nil {
			t.Fatalf("a password change with no word about the factors kept the window: ok=%v reauth=%v", ok, info.ReauthAt)
		}
	})
}

// TestTheCapOnLiveSessionsEndsTheOldestAndNeverRefusesTheLogin is tenant-r18-2 (D64 session-cap). Every login opens a
// session, and nothing capped them, so a loop of logins left tens of thousands of live rows and a list the size of the
// loop. The newest login now ends the oldest sessions of the account (and their refresh tokens) in its own transaction,
// and never refuses: refusing at the cap would let a holder of the password lock the owner out of the front door.
// Tenant B's sessions are never counted against A and never ended by A's logins.
func TestTheCapOnLiveSessionsEndsTheOldestAndNeverRefusesTheLogin(t *testing.T) {
	r := newRig(t)
	A, B := r.env.A, r.env.B
	liveRows := func(user uuid.UUID) int {
		var n int
		r.env.Scan(t, `SELECT count(*) FROM ctrlz.sessions WHERE user_id = $1 AND revoked_at IS NULL`, []any{user}, &n)
		return n
	}
	bFirst := r.create(t, B.Tenant, B.User, true, false)
	bBefore := liveRows(B.User) // the seed holds a session of its own
	var all []session.Issued
	for i := 0; i < caps.MaxSessions+5; i++ {
		// Remember me, so every session also holds a refresh token that must end with it.
		all = append(all, r.create(t, A.Tenant, A.User, true, false))
	}
	if n := liveRows(A.User); n != caps.MaxSessions {
		t.Fatalf("the account holds %d live sessions after %d logins, want the cap %d", n, caps.MaxSessions+5, caps.MaxSessions)
	}
	// The five oldest are gone and the newest is live: the login that went over the cap was not refused.
	for i, iss := range all {
		want := i >= 5
		if got := r.alive(t, iss.Session, plain); got != want {
			t.Errorf("session %d of %d: alive = %v, want %v", i, len(all), got, want)
		}
	}
	var stray int
	r.env.Scan(t, `SELECT count(*) FROM ctrlz.refresh_tokens r JOIN ctrlz.sessions s ON s.id = r.session_id WHERE s.user_id = $1 AND s.revoked_at IS NOT NULL AND r.revoked_at IS NULL`, []any{A.User}, &stray)
	if stray != 0 {
		t.Errorf("%d refresh tokens of ended sessions are still live", stray)
	}
	if n := liveRows(B.User); n != bBefore || !r.alive(t, bFirst.Session, plain) {
		t.Errorf("tenant B holds %d live sessions after A's logins, want its own %d, alive", n, bBefore)
	}
}

// TestAFailureInTheTrimRollsTheWholeLoginBack is the fault test of tenant-r18-2 (named by tenant-r18-21): a trim that
// fails halfway (here the refresh tokens of the ended sessions cannot be updated, after the sessions were) leaves
// nothing behind. The login gets an error, the new session is not there, no old session was ended, and when the
// fault is gone the next login trims as it should. Answering the login while keeping a session over the cap, or
// ending sessions of a login that failed, are the two wrong ways it could end.
func TestAFailureInTheTrimRollsTheWholeLoginBack(t *testing.T) {
	r := newRig(t)
	A := r.env.A
	liveRows := func() int {
		var n int
		r.env.Scan(t, `SELECT count(*) FROM ctrlz.sessions WHERE user_id = $1 AND revoked_at IS NULL`, []any{A.User}, &n)
		return n
	}
	var first session.Issued
	for i := 0; i < caps.MaxSessions; i++ {
		iss := r.create(t, A.Tenant, A.User, true, false)
		if i == 0 {
			first = iss
		}
	}
	if n := liveRows(); n < caps.MaxSessions {
		t.Fatalf("the account holds %d live sessions, want at least the cap %d before the fault", n, caps.MaxSessions)
	}
	before := liveRows()
	r.env.Exec(t, `CREATE FUNCTION ctrlz.fault_refuse_refresh_update() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected fault'; END $$`)
	r.env.Exec(t, `CREATE TRIGGER fault_refuse_refresh_update BEFORE UPDATE ON ctrlz.refresh_tokens FOR EACH ROW EXECUTE FUNCTION ctrlz.fault_refuse_refresh_update()`)
	err := r.st.WithTenant(r.env.Ctx, A.Tenant, store.TxOpts{}, func(tx store.Tx) (err error) {
		_, err = r.m.Create(tx, session.NewSession{User: A.User, Remember: true, Method: "password", IP: ip, UserAgent: "test"})
		return err
	})
	if err == nil {
		t.Fatal("a login whose trim failed was answered")
	}
	if n := liveRows(); n != before {
		t.Errorf("the account holds %d live sessions after the failed login, want the %d it had: the transaction was not rolled back", n, before)
	}
	if !r.alive(t, first.Session, plain) {
		t.Error("the oldest session was ended by a login that failed")
	}
	r.env.Exec(t, `DROP TRIGGER fault_refuse_refresh_update ON ctrlz.refresh_tokens`)
	r.create(t, A.Tenant, A.User, true, false)
	if n := liveRows(); n != caps.MaxSessions {
		t.Errorf("the account holds %d live sessions after the fault is gone, want the cap %d", n, caps.MaxSessions)
	}
	if r.alive(t, first.Session, plain) {
		t.Error("the oldest session survived a login over the cap once the fault was gone")
	}
}

// TestARevivableSessionCountsTowardTheCap is question 17 at the cap (spec 3.3, primitives-r19-2). A Remember me
// session past its idle limit is not a usable cookie, but its refresh token brings it back, so it is live: the
// cap counts it, and the login that goes over ends the OLDEST revivable session with its refresh token. Before
// the rule was one text, the cap counted only sessions inside the idle limit, and a thief's old session sat
// beside fifty live ones for ever. Tenant B's sessions are not counted against A and are not touched.
func TestARevivableSessionCountsTowardTheCap(t *testing.T) {
	r := newRig(t)
	A, B := r.env.A, r.env.B
	bSession := r.create(t, B.Tenant, B.User, true, false)
	first := r.create(t, A.Tenant, A.User, true, false)
	rest := make([]session.Issued, 0, caps.MaxSessions)
	for i := 1; i < caps.MaxSessions; i++ {
		rest = append(rest, r.create(t, A.Tenant, A.User, true, false))
	}
	// Past the idle limit, inside the absolute one: no cookie opens, every refresh token still does.
	r.ck.add(session.DefaultPolicy().Idle + time.Minute)
	if r.alive(t, first.Session, plain) {
		t.Fatal("a session past its idle limit passed the cookie gate: the premise of the test is gone")
	}
	revoked := func(id uuid.UUID) (ended bool, left int) {
		r.env.Scan(t, `SELECT revoked_at IS NOT NULL FROM ctrlz.sessions WHERE id = $1`, []any{id}, &ended)
		r.env.Scan(t, `SELECT count(*) FROM ctrlz.refresh_tokens WHERE session_id = $1 AND revoked_at IS NULL`, []any{id}, &left)
		return ended, left
	}
	newest := r.create(t, A.Tenant, A.User, true, false)
	if ended, left := revoked(first.SessionID); !ended || left != 0 {
		t.Errorf("the oldest revivable session: ended %v, %d live refresh tokens; want ended with none", ended, left)
	}
	for i, iss := range rest {
		if ended, left := revoked(iss.SessionID); ended || left != 1 {
			t.Errorf("revivable session %d: ended %v, %d live refresh tokens; want it left alone", i, ended, left)
		}
	}
	if ended, _ := revoked(newest.SessionID); ended {
		t.Error("the login that went over the cap was ended: it is never refused")
	}
	var live int
	r.env.Scan(t, `SELECT count(*) FROM ctrlz.sessions WHERE user_id = $1 AND revoked_at IS NULL`, []any{A.User}, &live)
	if live != caps.MaxSessions {
		t.Errorf("the account holds %d sessions that were not ended, want the cap %d", live, caps.MaxSessions)
	}
	if ended, left := revoked(bSession.SessionID); ended || left != 1 {
		t.Errorf("tenant B's session: ended %v, %d live refresh tokens; want it untouched by A's logins", ended, left)
	}
	// A session with no refresh token past its idle limit is dead: it is not counted, and the cap does not end it.
	short := r.create(t, A.Tenant, A.User, false, false)
	r.ck.add(session.DefaultPolicy().Idle + time.Minute)
	r.create(t, A.Tenant, A.User, true, false)
	r.env.Scan(t, `SELECT count(*) FROM ctrlz.sessions WHERE user_id = $1 AND revoked_at IS NULL AND id = $2`, []any{A.User, short.SessionID}, &live)
	if live != 1 {
		t.Error("the cap ended a session that was already dead: it counted a session that no refresh can bring back")
	}
}
