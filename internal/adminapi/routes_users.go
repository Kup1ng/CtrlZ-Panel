package adminapi

import (
	"context"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/adminapi/gen"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/audit"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/phone"
	"github.com/Kup1ng/CtrlZ-Panel/internal/httpx"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// ListUsers is GET /users (spec 10.6). It selects named columns of users and
// tenants only: never a hash, a secret or a log row (D19, T-334).
func (s *Server) ListUsers(ctx context.Context, req gen.ListUsersRequestObject) (gen.ListUsersResponseObject, error) {
	prefix := ""
	if q := strings.TrimSpace(deref(req.Params.Q)); q != "" {
		var err error
		if prefix, err = phone.SearchPrefix(q); err != nil {
			return nil, errValidation("q", "invalid")
		}
	}
	before, err := uuidCursor(req.Params.Cursor)
	if err != nil {
		return nil, err
	}
	limit := pageLimit(req.Params.Limit)
	out := gen.AdminUserPage{Items: []gen.AdminUserRow{}}
	err = s.readGlobal(ctx, func(g store.GlobalTx) error {
		rows, err := g.AdminUsersPage(prefix, before, limit+1) // one more, to know whether a next page exists
		if err != nil {
			return err
		}
		if len(rows) > limit {
			rows = rows[:limit]
			out.NextCursor = ptr(encodeKey(rows[len(rows)-1].UserID.String()))
		}
		for _, r := range rows {
			out.Items = append(out.Items, gen.AdminUserRow{
				TenantId: r.TenantID, UserId: r.UserID, PhoneE164: r.Phone, TenantStatus: r.TenantStatus,
				CreatedAt: r.CreatedAt, LastLoginAt: timePtr(r.LastLoginAt), OneTimePasswordExpiresAt: timePtr(r.OneTimePasswordExpiresAt),
			})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return gen.ListUsers200JSONResponse(out), nil
}

// CreateUser is POST /users (spec 10.6). It works with no SMS gateway, which
// makes it the way in while SMS is unavailable.
func (s *Server) CreateUser(ctx context.Context, req gen.CreateUserRequestObject) (gen.CreateUserResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.BadRequest()
	}
	p, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	e164, err := phone.Normalize(req.Body.Phone)
	if err != nil {
		return nil, errInvalidPhone()
	}
	locale := string(deref(req.Body.Locale))
	if locale != "" && locale != "fa" && locale != "en" {
		return nil, errValidation("locale", "invalid")
	}
	pw, err := s.d.NewOneTime()
	if err != nil {
		return nil, err
	}
	// Hashed outside the transaction, under the gate: Argon2 must not hold a
	// pool connection (10.6 step 1).
	hash, err := s.hasher.Hash(ctx, pw)
	if err != nil {
		return nil, adminError(err)
	}
	var reg store.Registered
	err = s.global(ctx, func(g store.GlobalTx) error {
		r, ok, err := g.CreateUser(e164, hash, locale)
		if err != nil {
			return err
		}
		if !ok {
			return httpx.New(http.StatusConflict, httpx.CodePhoneUnavailable)
		}
		reg = r
		_, err = audit.Admin(g, s.now(), p.AdminID, httpx.ClientIPFrom(g.Context()), audit.UserCreate{Tenant: r.TenantID})
		return err
	})
	if err != nil {
		return nil, err
	}
	// The one place the password is revealed: the JSON encoder writes it once.
	return gen.CreateUser201JSONResponse{TenantId: reg.TenantID, UserId: reg.UserID, OneTimePassword: pw.Reveal()}, nil
}

// ReissueOneTimePassword is POST /tenants/{tenant_id}/users/{user_id}/
// one-time-password (T-536, spec 10.7).
//
// It acts in one WithTenant transaction as ctrlz_admin on the tenant of the
// path, so tenant_isolation still applies to every statement and a user id from
// another tenant finds no row. The row lock comes first and the lock order is
// users, sessions, refresh tokens, the order the user's own password change and
// a login take, so none of them can deadlock with this route (10.7, 4.4, 5.7).
func (s *Server) ReissueOneTimePassword(ctx context.Context, req gen.ReissueOneTimePasswordRequestObject) (gen.ReissueOneTimePasswordResponseObject, error) {
	p, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	tenant, user := uuid.UUID(req.TenantId), uuid.UUID(req.UserId)
	pw, err := s.d.NewOneTime()
	if err != nil {
		return nil, err
	}
	// Argon2 under the gate, outside any transaction. A wait over 2 s is 503
	// server_busy before anything has changed.
	hash, err := s.hasher.Hash(ctx, pw)
	if err != nil {
		return nil, adminError(err)
	}
	out := gen.OneTimePasswordIssued{}
	err = adminError(s.d.Store.WithTenant(ctx, tenant, store.TxOpts{}, func(tx store.Tx) error {
		// a, b. The eligibility check and the update are one database function under
		// the row lock (ctrlz_fn.admin_reissue_one_time_password): ctrlz_admin has no
		// UPDATE on the password columns, so a user's own password cannot be replaced
		// by any other statement either. A missing user and a tenant being deleted
		// are 404; the reasons the user is not eligible are 409. Nothing has changed
		// at either, and no audit row is written. The new password has the same 72
		// hours as admin_create_user.
		re, err := tx.OneTimePasswordReissue(user, hash)
		if err != nil {
			return err
		}
		switch re.Outcome {
		case "ok":
		case "not_found":
			return httpx.NotFound()
		default:
			return httpx.New(http.StatusConflict, httpx.CodePasswordNotOneTime)
		}
		expires := re.ExpiresAt
		// e. Open mfa and reset tickets: no ticket outlives the credential it was
		// issued against (3.7). First of the revokes, because tickets rank before sessions
		// (internal/lockrank).
		if err := tx.TicketsRevoke(user); err != nil {
			return err
		}
		// c, d. Every session and refresh token of the user.
		revoked, err := tx.RevokeUserSessions(user)
		if err != nil {
			return err
		}
		// f. The chained audit row, in this transaction: the change cannot commit
		// without it. It holds neither the password nor its expiry (13.3).
		if _, err := audit.Admin(audit.OnTenant(tx), s.now(), p.AdminID, httpx.ClientIPFrom(tx.Context()), audit.UserPasswordReissue{
			Tenant: tenant, UserID: user, WasExpired: re.WasExpired, RevokedSessions: revoked,
		}); err != nil {
			return err
		}
		out.ExpiresAt, out.RevokedSessions = expires.UTC(), revoked
		return nil
	}))
	if err != nil {
		return nil, err
	}
	out.OneTimePassword = pw.Reveal()
	return gen.ReissueOneTimePassword200JSONResponse(out), nil
}
