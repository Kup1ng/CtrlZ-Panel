package session

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/apispec"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/credstate"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/token"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// AdminIssued is an admin session just made. The admin has no Remember me and no
// refresh token (spec 3.3): 15 minutes idle, 8 hours absolute.
type AdminIssued struct {
	SessionID uuid.UUID
	Token     secret.String
}

// AdminNew is the input of AdminCreate.
type AdminNew struct {
	Admin        uuid.UUID
	TOTPVerified bool // a code was checked at login (10.2)
	IP           netip.Addr
	UserAgent    string
}

// AdminCreate opens an admin session in the caller's global transaction.
func (m *Manager) AdminCreate(g store.GlobalTx, p AdminNew) (AdminIssued, error) {
	now := m.now()
	abs := now.Add(m.pol.AdminAbsolute)
	sid, err := uuid.NewV7() // before the insert: the cookie carries it under its tag (round 8, tenant-r8-3)
	if err != nil {
		return AdminIssued{}, err
	}
	tok, err := m.newSessionToken(audienceAdmin, abs, sid)
	if err != nil {
		return AdminIssued{}, err
	}
	id, err := g.AdminSessionCreate(store.NewAdminSession{
		ID: sid, AdminID: p.Admin, TokenHash: token.Hash(tok),
		IdleExpiresAt: capTime(now.Add(m.pol.AdminIdle), abs), AbsoluteExpiresAt: abs,
		TOTPVerified: p.TOTPVerified, At: now, IP: p.IP, UserAgent: p.UserAgent,
	})
	if err != nil {
		return AdminIssued{}, err
	}
	return AdminIssued{SessionID: id, Token: tok}, nil
}

// AdminRotate gives the session a new token (password change, TOTP confirm,
// 10.4). It returns ErrGone for a revoked session.
func (m *Manager) AdminRotate(g store.GlobalTx, info store.AdminSessionInfo) (AdminIssued, error) {
	tok, err := m.newSessionToken(audienceAdmin, info.AbsoluteExpiresAt, info.SessionID)
	if err != nil {
		return AdminIssued{}, err
	}
	ok, err := g.AdminSessionRotate(info.SessionID, token.Hash(tok), capTime(m.now().Add(m.pol.AdminIdle), info.AbsoluteExpiresAt))
	if err != nil {
		return AdminIssued{}, err
	}
	if !ok {
		return AdminIssued{}, ErrGone
	}
	return AdminIssued{SessionID: info.SessionID, Token: tok}, nil
}

// AdminLookup resolves an admin cookie in one query that joins the admin row, so
// a reset or a disabled account takes effect on the next request (10.3).
func (m *Manager) AdminLookup(ctx context.Context, cookie string) (store.AdminSessionInfo, bool, error) {
	if _, _, ok := m.Screen(cookie); !ok {
		return store.AdminSessionInfo{}, false, nil
	}
	var info store.AdminSessionInfo
	var found bool
	err := m.db.WithGlobal(ctx, store.TxOpts{}, func(g store.GlobalTx) (err error) {
		info, found, err = g.AdminSessionByHash(token.HashString(cookie))
		return err
	})
	return info, found, err
}

// The admin gate refusals.
var (
	ErrSetupRequired = errors.New("session: admin setup not finished") // 403 setup_required
	ErrFreshRequired = errors.New("session: fresh TOTP required")      // 403 totp_fresh_required
)

// AdminCheck applies the admin gates (spec 10.3, 10.5). A disabled account is
// expired at once. An account that has not set its password or enrolled TOTP may
// use only the admin-setup routes. admin-fresh needs a TOTP check within five
// minutes on top of a ready account.
func (m *Manager) AdminCheck(info store.AdminSessionInfo, auth apispec.Auth) error {
	now := m.now()
	if info.RevokedAt != nil || info.DisabledAt != nil || !info.IdleExpiresAt.After(now) || !info.AbsoluteExpiresAt.After(now) {
		return ErrExpired
	}
	// One row of one table (internal/auth/credstate): an account that is not ready reaches
	// the setup routes and nothing else; admin-fresh also needs a TOTP check in the window.
	switch credstate.Class(credstate.Admin, auth, info.State) {
	case credstate.Allow:
	case credstate.Fresh:
		if info.TOTPVerifiedAt == nil || !m.inWindow(*info.TOTPVerifiedAt, m.pol.AdminFresh) {
			return ErrFreshRequired
		}
	default:
		return ErrSetupRequired
	}
	return nil
}

// AdminNeedsTouch is NeedsTouch for the admin idle limit.
func (m *Manager) AdminNeedsTouch(info store.AdminSessionInfo) bool {
	return info.IdleExpiresAt.Before(m.now().Add(m.pol.AdminIdle-m.pol.TouchMargin)) && info.AbsoluteExpiresAt.After(info.IdleExpiresAt)
}

// AdminTouch slides the admin idle limit.
func (m *Manager) AdminTouch(ctx context.Context, info store.AdminSessionInfo) error {
	idle := capTime(m.now().Add(m.pol.AdminIdle), info.AbsoluteExpiresAt)
	return m.db.WithGlobal(ctx, store.TxOpts{}, func(g store.GlobalTx) error {
		return g.AdminSessionTouch(info.SessionID, idle)
	})
}

// AdminPrincipal is the admin session of the request.
type AdminPrincipal struct {
	AdminID   uuid.UUID
	SessionID uuid.UUID
	Username  string
	// State is the credential state the account had when the request came in (rule
	// one-time-state). GET /me reports the setup it implies; no handler decides on it.
	State        credstate.State
	TOTPEnrolled bool
	// TOTPVerifiedAt is the last TOTP check on this session, nil when none: GET /me
	// derives fresh_until from it (10.5).
	// CreatedAt is when the session began. A notice made after it cannot be
	// acknowledged by this session (admin-r3-1).
	CreatedAt      time.Time
	TOTPVerifiedAt *time.Time
	// AbsoluteExpiresAt caps the idle limit when the session is rotated.
	AbsoluteExpiresAt time.Time
}

type adminKey struct{}

// WithAdmin stores p in ctx.
func WithAdmin(ctx context.Context, p AdminPrincipal) context.Context {
	return context.WithValue(ctx, adminKey{}, p)
}

// AdminFrom returns the admin principal of the request.
func AdminFrom(ctx context.Context) (AdminPrincipal, bool) {
	p, ok := ctx.Value(adminKey{}).(AdminPrincipal)
	return p, ok
}

// AdminPrincipalOf converts a lookup result.
func AdminPrincipalOf(info store.AdminSessionInfo) AdminPrincipal {
	return AdminPrincipal{
		AdminID: info.AdminID, SessionID: info.SessionID, Username: info.Username,
		State: info.State, TOTPEnrolled: info.TOTPEnabledAt != nil,
		TOTPVerifiedAt: info.TOTPVerifiedAt, CreatedAt: info.CreatedAt, AbsoluteExpiresAt: info.AbsoluteExpiresAt,
	}
}

// AdminFreshUntil is when a TOTP check made at t stops opening admin-fresh
// routes (10.5). It is the manager's policy and not a constant at the call
// site, so a test that shortens the window shortens it everywhere.
func (m *Manager) AdminFreshUntil(t time.Time) time.Time { return t.Add(m.pol.AdminFresh) }
