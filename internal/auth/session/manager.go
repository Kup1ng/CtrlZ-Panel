package session

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/apispec"
	"github.com/Kup1ng/CtrlZ-Panel/internal/appclock"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/credstate"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/token"
	"github.com/Kup1ng/CtrlZ-Panel/internal/caps"
	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// Policy holds the lifetimes of spec 3.3. All of them are provisional (D31).
type Policy struct {
	Idle             time.Duration // user session idle limit
	Absolute         time.Duration // user session, no Remember me
	RememberAbsolute time.Duration // user session with Remember me
	Refresh          time.Duration // life of one refresh token
	ReuseGrace       time.Duration // window in which a rotated refresh token is a concurrent tab
	Reauth           time.Duration // how long a reauth stays good
	TouchMargin      time.Duration // the idle limit slides at most once in this time

	AdminIdle     time.Duration
	AdminAbsolute time.Duration
	AdminFresh    time.Duration // how long a TOTP check makes admin-fresh routes available
}

// DefaultPolicy is the table of 3.3.
func DefaultPolicy() Policy {
	return Policy{
		Idle: 2 * time.Hour, Absolute: 24 * time.Hour, RememberAbsolute: keyring.LifeUserSession,
		Refresh: 30 * 24 * time.Hour, ReuseGrace: 10 * time.Second, Reauth: 10 * time.Minute, TouchMargin: time.Minute,
		AdminIdle: 15 * time.Minute, AdminAbsolute: keyring.LifeAdminSession, AdminFresh: 5 * time.Minute,
	}
}

// Manager applies the policy to the store. The clock is injectable so a test can
// walk through the limits without waiting.
type Manager struct {
	db  *store.Store
	pol Policy
	now func() time.Time
	// ring and tagDomain tag the session tokens (tag.go). Nil ring: untagged.
	ring      *keyring.Ring
	tagDomain string
}

// NewManager returns a Manager. A nil now means the wall clock.
func NewManager(db *store.Store, pol Policy, now func() time.Time) *Manager {
	if now == nil {
		now = appclock.Now
	}
	return &Manager{db: db, pol: pol, now: now}
}

// Policy returns the lifetimes in force.
func (m *Manager) Policy() Policy { return m.pol }

// Now is the manager's clock.
func (m *Manager) Now() time.Time { return m.now() }

func capTime(t, limit time.Time) time.Time {
	if t.After(limit) {
		return limit
	}
	return t
}

// Issued is a session (and refresh token) just made. The tokens exist only
// here, in memory: the database holds their hashes. A handler sets the cookies
// after its transaction commits and never logs the Issued value (secret.String
// prints as a marker anyway).
type Issued struct {
	SessionID     uuid.UUID
	Session       secret.String
	Refresh       secret.String // zero without Remember me
	RefreshMaxAge time.Duration
}

// Cookies are the Set-Cookie values for the tokens. A session without Remember
// me also deletes any refresh cookie the browser holds: that cookie belongs to
// an earlier Remember me login, maybe another account's on a shared computer, and
// api-client answers a 401 session_expired by posting /auth/refresh. Left in
// place it would swap this session for that account's (review round 3,
// primitives-r3-7).
func (i Issued) Cookies() []*http.Cookie {
	cs := []*http.Cookie{SessionCookie(i.Session)}
	if i.Refresh.IsZero() {
		return append(cs, Expire(base(CookieRefresh, "", http.SameSiteLaxMode)))
	}
	return append(cs, RefreshCookie(i.Refresh, i.RefreshMaxAge))
}

// NewSession is the input of Create.
type NewSession struct {
	User     uuid.UUID
	Remember bool
	// Restricted is the record of how the session began: opened under a one-time password.
	// No gate reads it. The gates ask the table of internal/auth/credstate with the state
	// the user has now (store.SessionInfo.State), so a copy written at login cannot drift.
	Restricted bool
	Method     string // password, otp or passkey
	IP         netip.Addr
	UserAgent  string
}

// Create opens a session in the caller's transaction (spec 5.7): a new row with
// a new token whatever cookie the request carried, so fixation fails, and a
// refresh row with a new family when Remember me. The caller writes the login
// audit row in the same transaction and sets the cookies after commit.
func (m *Manager) Create(tx store.Tx, p NewSession) (Issued, error) {
	now := m.now()
	abs := now.Add(m.pol.Absolute)
	if p.Remember {
		abs = now.Add(m.pol.RememberAbsolute)
	}
	// The id is made here, not by the database, because the cookie carries it under its tag (round 8,
	// tenant-r8-3): the budget for dead cookies is the session's own and is fixed for its life.
	sid, err := uuid.NewV7()
	if err != nil {
		return Issued{}, err
	}
	tok, err := m.newSessionToken(audienceTenant, abs, sid)
	if err != nil {
		return Issued{}, err
	}
	id, err := tx.SessionCreate(store.NewSession{
		ID: sid, UserID: p.User, TokenHash: token.Hash(tok), RememberMe: p.Remember,
		IdleExpiresAt: capTime(now.Add(m.pol.Idle), abs), AbsoluteExpiresAt: abs,
		Restricted: p.Restricted, AuthMethod: p.Method, IP: p.IP, UserAgent: p.UserAgent, At: now,
	})
	if err != nil {
		return Issued{}, err
	}
	// The cap on live sessions per account (tenant-r18-2): the newest login ends the oldest, here in the
	// login's own transaction and after the insert, so the new session is among the newest and the writes
	// stay in rank order (sessions, then refresh tokens).
	if _, err := tx.SessionsTrim(p.User, caps.MaxSessions, now); err != nil {
		return Issued{}, err
	}
	iss := Issued{SessionID: id, Session: tok}
	if p.Remember {
		if err := m.addRefresh(tx, &iss, p.User, uuid.New(), abs, now); err != nil {
			return Issued{}, err
		}
	}
	return iss, nil
}

// addRefresh inserts a refresh row of the given family and records the token in
// iss. Its life is 30 days, capped at the session's absolute limit, so a
// refresh can never outlive its session.
func (m *Manager) addRefresh(tx store.Tx, iss *Issued, user, family uuid.UUID, abs, now time.Time) error {
	rt, err := token.New()
	if err != nil {
		return err
	}
	exp := capTime(now.Add(m.pol.Refresh), abs)
	if _, err := tx.RefreshCreate(store.NewRefresh{
		SessionID: iss.SessionID, UserID: user, FamilyID: family, TokenHash: token.Hash(rt), ExpiresAt: exp,
	}); err != nil {
		return err
	}
	iss.Refresh = rt
	iss.RefreshMaxAge = exp.Sub(now)
	return nil
}

// ErrGone means the session to rotate or act on is revoked or unknown. The
// caller answers 401 session_expired and has changed nothing (4.4 step 3).
var ErrGone = errors.New("session: revoked or unknown")

// Rotate gives the session a new token in place (spec 3.7). The old cookie is
// dead at commit, every refresh token of the session is revoked, and on a
// Remember me session a new refresh row starts a new family, so a stolen refresh
// cookie cannot take the row back after the owner proves themselves. created_at
// is untouched, which the Account page's rule about older and newer sessions
// relies on (12.1).
func (m *Manager) Rotate(tx store.Tx, id uuid.UUID, reauth store.ReauthMode, clearRestricted bool) (Issued, error) {
	row, ok, err := tx.SessionByID(id)
	if err != nil {
		return Issued{}, err
	}
	if !ok || row.RevokedAt != nil {
		return Issued{}, ErrGone
	}
	// The user first, as every writer does (spec 4.4, internal/lockrank): the new
	// refresh row takes FOR KEY SHARE on it through its foreign key, and asking for
	// that after the session is written would wait behind a writer that holds the
	// user and wants this session. Callers that hold the user already (reauth, the
	// password change) ask for nothing new; the session read above took no lock.
	if live, err := tx.UserKeyShare(row.UserID); err != nil {
		return Issued{}, err
	} else if !live {
		return Issued{}, ErrGone
	}
	now := m.now()
	tok, err := m.newSessionToken(audienceTenant, row.AbsoluteExpiresAt, id)
	if err != nil {
		return Issued{}, err
	}
	rotated, err := tx.SessionRotate(id, token.Hash(tok), capTime(now.Add(m.pol.Idle), row.AbsoluteExpiresAt), reauth, now, clearRestricted)
	if err != nil {
		return Issued{}, err
	}
	if !rotated {
		return Issued{}, ErrGone
	}
	iss := Issued{SessionID: id, Session: tok}
	if row.RememberMe {
		if err := m.addRefresh(tx, &iss, row.UserID, uuid.New(), row.AbsoluteExpiresAt, now); err != nil {
			return Issued{}, err
		}
	}
	return iss, nil
}

// Event is something that happens to an account and moves its sessions. The
// rows of the table in spec 3.7 are the cases of Apply.
type Event int

// The events of 3.7 that act on a live session. Login creates a session with
// Create and keeps the others; refresh reuse is handled by Refresh.
const (
	EventReauth             Event = iota // POST /auth/reauth: rotate, open the reauth window
	EventRecoveryRegenerate              // rotate only
	EventEnforceDisable                  // rotate only
	EventTOTPEnable                      // rotate, revoke the others
	EventTOTPDisable                     // rotate, revoke the others, close open mfa and reset tickets
	EventPasskeyAdd                      // rotate, revoke the others
	EventEnforceEnable                   // rotate, revoke the others
	EventPasswordChange                  // rotate, revoke the others, API tokens, tickets; ends a restricted session
	EventPhoneChange                     // same as a password change; the passkey review is the caller's
	EventPasswordReset                   // Forgot Password complete: everything ends, no current session
	EventLogout                          // the current session
	EventLogoutAll                       // every session, the current one included

	// eventEnd is one past the last event. It exists so that a test can walk every event and
	// fail for one that has no declared fate for the reauth window (WindowFateOf).
	eventEnd
)

// WindowFate is what an event does to the reauth window of the session it rotates. It is
// declared once per event in windowFates and Apply reads it, so no event can choose its own
// mode at its call site and a new event cannot be added without choosing.
//
// Why a table: round 10 (tenant-r10-1) found that a window earned with the password alone
// survived the enrolment of TOTP. After that, every route that says "the window already
// proved the second factor" (POST /account/totp/disable, a password change that skips the
// code) was open to a holder of the new cookie with no code at all. Phone change had been
// fixed for its own case in round 5 (tenant-r5-4), by hand. The rule is: a window proves what
// the account asked for when it was earned, so an event that raises what a reauth asks for
// ends the window, and an event that does not may keep it.
type WindowFate int

// The fates. WindowNone is for an event that does not rotate a surviving session.
const (
	WindowNone WindowFate = iota
	WindowSet
	WindowKeep
	WindowClear
)

type windowRule struct {
	fate WindowFate
	// why is read by people: a Keep says why the bar did not rise, a Clear says what rose.
	why string
	// factors marks an event that can change which factors the account has, and so what a reauth asks for
	// (3.5). Such an event keeps a window only when the bar did not rise, which Apply decides from the factors
	// before the event (Actor.Before) and after it (read from the row), not from the event alone (round 11,
	// primitives-r11-4: POST /account/password is a password change for a user who has one and a FIRST
	// password for one who has none, and the second raises the bar from an SMS code to the password).
	factors bool
}

// windowFates is the one place that says what each event does to reauth_at. It is a function and not a
// package-level map, so that nothing can change it at run time.
func windowFates(ev Event) (windowRule, bool) {
	switch ev {
	case EventReauth:
		return windowRule{WindowSet, "the proof just given opens the window", false}, true
	case EventRecoveryRegenerate:
		return windowRule{WindowKeep, "a reauth route: the window it used already proved every factor the account has", false}, true
	case EventEnforceDisable:
		return windowRule{WindowKeep, "lowers what the account demands", false}, true
	case EventTOTPEnable:
		return windowRule{WindowClear, "raises what a reauth asks for: a window earned before the authenticator existed proved the password only", true}, true
	case EventTOTPDisable:
		return windowRule{WindowKeep, "lowers what a reauth asks for; the window proved password and code", true}, true
	case EventPasskeyAdd:
		return windowRule{WindowKeep, "a passkey adds a way to reauth and raises no bar", false}, true
	case EventEnforceEnable:
		return windowRule{WindowKeep, "Enforce changes how the account signs in and resets, not what a reauth asks for", false}, true
	case EventPasswordChange:
		return windowRule{WindowKeep, "a new password for an account that has one is no higher bar; a FIRST password raises it, and the factors check ends the window then", true}, true
	case EventPhoneChange:
		return windowRule{WindowKeep, "the phone is no reauth factor; a change that sets the passkey review mark ends the window itself (phonechange, tenant-r5-4)", false}, true
	case EventPasswordReset:
		return windowRule{WindowNone, "no session survives", false}, true
	case EventLogout:
		return windowRule{WindowNone, "the session ends", false}, true
	case EventLogoutAll:
		return windowRule{WindowNone, "every session ends", false}, true
	}
	return windowRule{}, false
}

// WindowFateOf returns the declared fate of an event, and false for an event that has none.
func WindowFateOf(ev Event) (WindowFate, bool) {
	r, ok := windowFates(ev)
	return r.fate, ok
}

// reauthMode is the rotation mode for an event. An event with no declared fate clears the
// window: failing closed is the safe default for a proof.
func reauthMode(ev Event) store.ReauthMode {
	r, _ := windowFates(ev)
	switch r.fate {
	case WindowSet:
		return store.ReauthSet
	case WindowKeep:
		return store.ReauthKeep
	}
	return store.ReauthClear
}

// Factors is what decides the row of the 3.5 table of what a reauth asks for: whether the account has a
// password and whether it has an authenticator. (The row for neither is the SMS code, and a passkey is an
// alternative to every row, so neither is a field.)
type Factors struct {
	Password bool
	TOTP     bool
}

// asks is the set of proofs a reauth asks for under the row of f, as bits: the password and the code. The
// row for neither asks for an SMS code, which is the lowest bar: any proof a window can hold is at least
// that, so it is the empty set here and every window satisfies it.
func (f Factors) asks() uint8 {
	var b uint8
	if f.Password {
		b |= 1
	}
	if f.TOTP {
		b |= 2
	}
	return b
}

// WindowSurvives says whether a window earned under the row of before still satisfies the row of after: it
// does when every proof the new row asks for was asked under the old one (3.5; round 11, primitives-r11-4).
// An SMS code earned a window for an account with neither factor, and it does not satisfy a password.
func WindowSurvives(before, after Factors) bool { return after.asks()&^before.asks() == 0 }

// FactorsOf reads the factors of a user as the transaction sees them now. A route that changes a factor reads
// it BEFORE the change and hands it to Apply as Actor.Before; Apply reads it again after.
func FactorsOf(tx store.Tx, user uuid.UUID) (Factors, error) {
	has, found, err := tx.UserFlags(user)
	if err != nil {
		return Factors{}, err
	}
	if !found {
		return Factors{}, ErrGone
	}
	u, ok, err := tx.User(user)
	if err != nil {
		return Factors{}, err
	}
	if !ok {
		return Factors{}, ErrGone
	}
	return Factors{Password: has, TOTP: u.TOTPEnabledAt != nil}, nil
}

// reauthModeFor is the rotation mode of an event given the factors around it: the declared fate, and for an
// event that can change the factors, a kept window ends unless it survives the change. before is nil when the
// caller did not say what the factors were, which for such an event fails closed. This function is pure, so
// the test can walk every event over every pair of states.
func reauthModeFor(ev Event, before *Factors, after Factors) store.ReauthMode {
	mode := reauthMode(ev)
	r, _ := windowFates(ev)
	if mode != store.ReauthKeep || !r.factors {
		return mode
	}
	if before == nil || !WindowSurvives(*before, after) {
		return store.ReauthClear
	}
	return mode
}

// Actor is who an event is about. Session is the nil uuid for Forgot Password,
// which has no session. Before is the factors of the user before the credential change of an event that
// can change them (an event of windowFates with factors set); the other events leave it nil.
type Actor struct {
	User    uuid.UUID
	Session uuid.UUID
	Before  *Factors
}

// Outcome is what Apply did. Issued is nil when the current session ended or
// stayed as it was. Ended counts the sessions that were live and were ended, for
// the ended_sessions of the response and the audit count.
type Outcome struct {
	Issued *Issued
	Ended  int
}

// Apply performs one row of the table in spec 3.7 in the caller's transaction.
// The caller changes the credential itself and writes its audit row in the same
// transaction; the cookies of Outcome.Issued go out after commit.
//
// What the table says about passkeys (kept, or marked for review) is not done
// here: it is a column of webauthn_credentials and users, and the route that
// knows the event sets it.
func (m *Manager) Apply(tx store.Tx, ev Event, a Actor) (Outcome, error) {
	var out Outcome
	rotate := func(mode store.ReauthMode, clear bool) error {
		iss, err := m.Rotate(tx, a.Session, mode, clear)
		if err != nil {
			return err
		}
		out.Issued = &iss
		return nil
	}
	revokeOthers := func() error {
		n, err := tx.SessionsRevokeOthers(a.User, a.Session, m.now())
		out.Ended = n
		return err
	}
	// revokeTickets closes the user's open mfa and reset tickets. Tickets rank after the user and
	// before the sessions (internal/lockrank), and the revoke closes the ticket a route has
	// just spent in the same transaction, so it is the first thing an event does, after the
	// user's key share (callers that hold the user ask for nothing new).
	revokeTickets := func() error {
		if live, err := tx.UserKeyShare(a.User); err != nil {
			return err
		} else if !live {
			return ErrGone
		}
		return tx.TicketsRevoke(a.User)
	}
	// modeNow is the rotation mode of the event. For an event that can change the factors it reads the
	// factors after the change, in this transaction, and compares them with what the caller read before it.
	modeNow := func() (store.ReauthMode, error) {
		if r, _ := windowFates(ev); !r.factors || reauthMode(ev) != store.ReauthKeep {
			return reauthMode(ev), nil
		}
		after, err := FactorsOf(tx, a.User)
		if err != nil {
			return "", err
		}
		return reauthModeFor(ev, a.Before, after), nil
	}
	switch ev {
	case EventReauth:
		return out, rotate(reauthMode(ev), false)
	case EventRecoveryRegenerate, EventEnforceDisable:
		return out, rotate(reauthMode(ev), false)
	case EventTOTPEnable, EventPasskeyAdd, EventEnforceEnable:
		if err := rotate(reauthMode(ev), false); err != nil {
			return out, err
		}
		return out, revokeOthers()
	case EventTOTPDisable:
		if err := revokeTickets(); err != nil {
			return out, err
		}
		mode, err := modeNow()
		if err != nil {
			return out, err
		}
		if err := rotate(mode, false); err != nil {
			return out, err
		}
		return out, revokeOthers()
	case EventPasswordChange, EventPhoneChange:
		if err := revokeTickets(); err != nil {
			return out, err
		}
		mode, err := modeNow()
		if err != nil {
			return out, err
		}
		if err := rotate(mode, ev == EventPasswordChange); err != nil {
			return out, err
		}
		if err := revokeOthers(); err != nil {
			return out, err
		}
		_, err = tx.APITokensRevoke(a.User)
		return out, err
	case EventPasswordReset:
		if err := revokeTickets(); err != nil {
			return out, err
		}
		n, err := tx.SessionsRevokeOthers(a.User, uuid.Nil, m.now())
		if err != nil {
			return out, err
		}
		out.Ended = n
		_, err = tx.APITokensRevoke(a.User)
		return out, err
	case EventLogout:
		ok, err := tx.SessionRevoke(a.User, a.Session)
		if ok {
			out.Ended = 1
		}
		return out, err
	case EventLogoutAll:
		n, err := tx.SessionsRevokeOthers(a.User, uuid.Nil, m.now())
		out.Ended = n
		return out, err
	}
	return out, errors.New("session: unknown event")
}

// ---------------------------------------------------------------------------
// Request-time lookup and gates

// Principal is the session of the request, put in the context by the router
// after the gates passed.
type Principal struct {
	TenantID     uuid.UUID
	UserID       uuid.UUID
	SessionID    uuid.UUID
	TenantStatus string
	ReauthAt     *time.Time
}

type principalKey struct{}

// WithPrincipal stores p in ctx.
func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// From returns the principal of the request, and false when the route has none.
func From(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(Principal)
	return p, ok
}

// Lookup resolves a session cookie value. A value that is not shaped like a
// token is "not found" without a database call. The lookup is one SECURITY
// DEFINER call; there is no cache, so a revocation takes effect on the next
// request (spec 2.1).
func (m *Manager) Lookup(ctx context.Context, cookie string) (store.SessionInfo, bool, error) {
	if _, _, ok := m.Screen(cookie); !ok {
		return store.SessionInfo{}, false, nil
	}
	return m.db.Auth().SessionByHash(ctx, token.HashString(cookie))
}

// The gate refusals of 3.5. The router maps each to its API error.
var (
	ErrExpired        = errors.New("session: expired or revoked")  // 401 session_expired
	ErrSuspended      = errors.New("session: tenant suspended")    // 403 account_suspended
	ErrPasswordChange = errors.New("session: password change due") // 403 password_change_required
	ErrReauth         = errors.New("session: reauth required")     // 403 reauth_required
)

// Gate says what a route needs of a session.
type Gate struct {
	Auth apispec.Auth
	// AllowSuspended is for GET /me and POST /auth/logout, which stay open to a
	// suspended tenant so /suspended can show why and a shared computer can be
	// signed out (3.5).
	AllowSuspended bool
}

// Check applies the gates of spec 3.5, in the order of its table.
func (m *Manager) Check(info store.SessionInfo, g Gate) error {
	now := m.now()
	if info.RevokedAt != nil || !info.IdleExpiresAt.After(now) || !info.AbsoluteExpiresAt.After(now) {
		return ErrExpired
	}
	switch info.TenantStatus {
	case "active":
	case "suspended":
		if !g.AllowSuspended {
			return ErrSuspended
		}
	default:
		// "deleting", and any status a later migration adds and this switch does not know: an
		// allow list that fails closed, so a new status cannot open every session of its tenants
		// until someone remembers this line (primitives-r5-12).
		return ErrExpired
	}
	// One row of one table (internal/auth/credstate): what the user's state allows this
	// class of route. A restricted session reaches the setup routes only; a reauth route
	// also needs the window.
	switch credstate.Class(credstate.Tenant, g.Auth, info.State) {
	case credstate.Allow:
	case credstate.Fresh:
		if !m.ReauthFresh(info.ReauthAt) {
			return ErrReauth
		}
	default:
		return ErrPasswordChange
	}
	return nil
}

// ReauthFresh reports whether a reauth_at is inside the window of 3.5. The
// window is closed at its far end: a reauth exactly ten minutes old is stale.
func (m *Manager) ReauthFresh(at *time.Time) bool {
	return at != nil && m.inWindow(*at, m.pol.Reauth)
}

// FutureStampSkew is how far ahead of the application clock a stamp may be and still count
// as made now: two hosts whose clocks differ by a few minutes. It is the figure the device
// marker uses for the same question.
const FutureStampSkew = 5 * time.Minute

// inWindow is the one answer to "was this stamp made less than window ago", for every
// window the session package decides in Go (the reauth window and the admin fresh window).
// A stamp from the future beyond FutureStampSkew is not fresh: with a plain now-at < window a
// stamp written before the clock stepped back would give a negative age and stay fresh until
// the clock caught up, hours long instead of minutes (primitives-r5-11). The far end is
// closed: a stamp exactly window old is stale.
func (m *Manager) inWindow(at time.Time, window time.Duration) bool {
	age := m.now().Sub(at)
	return age >= -FutureStampSkew && age < window
}

// NeedsTouch reports whether the idle limit should slide (3.3): when it is
// more than TouchMargin short of a full idle period, which is at most one write
// per session per minute. It uses only the lookup, so it costs no read.
func (m *Manager) NeedsTouch(info store.SessionInfo) bool {
	return info.IdleExpiresAt.Before(m.now().Add(m.pol.Idle-m.pol.TouchMargin)) && info.AbsoluteExpiresAt.After(info.IdleExpiresAt)
}

// Touch slides the idle limit in its own short transaction.
func (m *Manager) Touch(ctx context.Context, info store.SessionInfo) error {
	idle := capTime(m.now().Add(m.pol.Idle), info.AbsoluteExpiresAt)
	return m.db.WithTenant(ctx, info.TenantID, store.TxOpts{}, func(tx store.Tx) error {
		return tx.SessionTouch(info.SessionID, idle, m.now())
	})
}

// PrincipalOf converts a lookup result.
func PrincipalOf(info store.SessionInfo) Principal {
	return Principal{
		TenantID: info.TenantID, UserID: info.UserID, SessionID: info.SessionID, TenantStatus: info.TenantStatus,
		ReauthAt: info.ReauthAt,
	}
}

// Live reports whether a lookup result is a session that has not ended: not
// revoked, inside both limits, and its tenant not being deleted. A suspended
// tenant's session is live, since it can still read /me and log out. The router
// gives the session-lookup token back for a live session (spec 2.3 step 9).
func (m *Manager) Live(info store.SessionInfo) bool {
	return m.Check(info, Gate{Auth: apispec.SessionSetup, AllowSuspended: true}) == nil
}

// Events lists every event, for the test that holds each one to a declared window fate.
func Events() []Event {
	out := make([]Event, 0, int(eventEnd))
	for ev := Event(0); ev < eventEnd; ev++ {
		out = append(out, ev)
	}
	return out
}
