package api

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/apitoken"

	"github.com/Kup1ng/CtrlZ-Panel/internal/apispec"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/password"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/session"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/token"
	"github.com/Kup1ng/CtrlZ-Panel/internal/httpx"
)

// allowedWhileSuspended is the pair of routes that stay open to a suspended
// tenant (spec 3.5): GET /me so /suspended can say why, and POST /auth/logout so
// a shared computer can be signed out.
func allowedWhileSuspended(op apispec.Operation) bool {
	return (op.Method == http.MethodGet && op.Path == "/me") || (op.Method == http.MethodPost && op.Path == "/auth/logout")
}

// resolver is the tenant half of spec 2.3 step 9: cookie to session to principal.
type resolver struct{ m *session.Manager }

func (resolver) CookieName() string { return session.CookieSession }

func (r resolver) Screen(cookie string) (string, string, bool) { return r.m.Screen(cookie) }

func (r resolver) Resolve(ctx context.Context, cookie string, op apispec.Operation) (httpx.Resolved, error) {
	info, found, err := r.m.Lookup(ctx, cookie)
	if err != nil {
		return httpx.Resolved{}, err
	}
	if !found {
		// No row: revoked, rotated away or never there. It does not come back, so the pipeline
		// remembers the cookie and spares the lookup next time (primitives-r6-5).
		return httpx.Resolved{Dead: true}, httpx.SessionExpired()
	}
	// From here the cookie belongs to a real session, so its lookup token is
	// returned whatever a gate says next.
	// A row that exists and is expired has ended (revoked, past a limit, its tenant going away);
	// none of those is undone, so it is dead like a missing one. Only ErrExpired says so: a gate that
	// refuses for another reason (a password change due) belongs to a session that is alive.
	setupErr := r.m.Check(info, session.Gate{Auth: apispec.SessionSetup, AllowSuspended: true})
	res := httpx.Resolved{Live: setupErr == nil, Dead: errors.Is(setupErr, session.ErrExpired)}
	if res.Live {
		res.SessionID = info.SessionID.String() // the key that survives a rotation of the cookie (tenant-r6-5)
		res.Tenant = info.TenantID.String()
	}
	if err := r.m.Check(info, session.Gate{Auth: op.Auth, AllowSuspended: allowedWhileSuspended(op)}); err != nil {
		return res, gateError(err)
	}
	// The idle limit slides at most once a minute (3.3). A failure is the
	// database being unreachable, which the request would hit anyway.
	if r.m.NeedsTouch(info) {
		if err := r.m.Touch(ctx, info); err != nil {
			return res, err
		}
	}
	// A session that passed its gate is a proof: its hashes (reauth, a password change) are served
	// before any stranger's when the Argon2 gate is full (password.Proved, tenant-r6-1), and one account has one
	// hash in the lane at a time however many sessions it holds (password.ProvedAs, tenant-r7-6).
	pr := session.PrincipalOf(info)
	pr.CookieHash = token.HashString(cookie)
	res.Ctx = password.ProvedAs(session.WithPrincipal(ctx, pr), info.UserID.String())
	return res, nil
}

// gateError maps the session package's refusals to the API errors of spec 14.3.
func gateError(err error) *httpx.Error {
	switch {
	case errors.Is(err, session.ErrExpired):
		return httpx.SessionExpired()
	case errors.Is(err, session.ErrSuspended):
		return httpx.New(http.StatusForbidden, httpx.CodeAccountSuspended)
	case errors.Is(err, session.ErrPasswordChange):
		return httpx.New(http.StatusForbidden, httpx.CodePasswordChangeNeeded)
	case errors.Is(err, session.ErrReauth):
		return httpx.New(http.StatusForbidden, httpx.CodeReauthRequired)
	}
	return httpx.Internal()
}

// tokenReader is the API token half of spec 2.3 step 9 (P3 6.3): a bearer value to a principal that has a tenant and a user and
// no session.
type tokenReader struct {
	r     apitoken.Resolver
	now   func() time.Time
	touch *tokenToucher // nil in a test that has no store
}

func (t tokenReader) Screen(credential string) (string, bool) {
	id, ok := t.r.Screen(credential)
	if !ok {
		return "", false
	}
	return id.String(), true
}

func (t tokenReader) Resolve(ctx context.Context, credential string, op apispec.Operation, client netip.Addr) (httpx.Resolved, error) {
	info, out, err := t.r.Lookup(ctx, credential, client, op.Token == "write")
	res := httpx.Resolved{Live: out.Live, Dead: out.Dead}
	switch {
	case err == nil:
	case errors.Is(err, apitoken.ErrInvalid):
		return res, httpx.TokenInvalid()
	case errors.Is(err, apitoken.ErrSuspended):
		return res, httpx.New(http.StatusForbidden, httpx.CodeAccountSuspended)
	case errors.Is(err, apitoken.ErrIPNotAllowed):
		return res, httpx.TokenIPNotAllowed()
	case errors.Is(err, apitoken.ErrReadOnly):
		return res, httpx.TokenReadOnly()
	default:
		// The database being unreachable: the request would hit it anyway, and nothing here says the token is bad.
		return res, err
	}
	// The key of the operation's own class on this token, and the tenant of the tenant classes: both read from the row, never the request.
	res.SessionID = info.TokenID.String()
	res.Tenant = info.TenantID.String()
	p := session.Principal{TenantID: info.TenantID, UserID: info.UserID, TenantStatus: "active", TokenID: info.TokenID, TokenKind: info.Kind}
	// last_used_at is written here, best effort and in a transaction of its own, once the gates have passed (6.3 step 7).
	t.touch.touch(ctx, info.TenantID, info.TokenID, t.now())
	res.Ctx = session.WithPrincipal(ctx, p)
	return res, nil
}
