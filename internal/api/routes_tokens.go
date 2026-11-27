package api

import (
	"context"
	"net/netip"
	"strconv"
	"time"

	"github.com/google/uuid"
	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/Kup1ng/CtrlZ-Panel/internal/api/gen"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/apitoken"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/audit"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/bearer"
	"github.com/Kup1ng/CtrlZ-Panel/internal/httpx"
	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// The management routes of API tokens (docs/specs/p3-endpoints.md 6.4). All four act on the tokens of the signed-in user; none can
// be called with a token (x-ctrlz-token: none), because a token must never be able to mint or widen another.

// tokenPrefixAt and tokenPrefixLen pick the six characters shown in the list: characters 24 to 29 of the value cover bytes 18 to 22,
// which are inside the 20 random bytes (16 to 35) and not the id before them, so the prefix tells tokens apart without being the
// part that anyone could guess.
const (
	tokenPrefixAt  = 24
	tokenPrefixLen = 6
)

// tokenOut is the view of a row: never the value or its hash.
func tokenOut(r store.APITokenRow) gen.ApiToken {
	o := gen.ApiToken{
		Id: openapi_types.UUID(r.ID), Name: r.Name, Kind: gen.ApiTokenKind(r.Kind), TokenPrefix: r.Prefix,
		AllowedIps: r.Allowed, CreatedAt: r.CreatedAt, ExpiresAt: r.ExpiresAt, LastUsedAt: r.LastUsedAt, Ended: r.RevokedAt != nil,
	}
	if o.AllowedIps == nil {
		o.AllowedIps = []string{}
	}
	return o
}

// parseAllowed reads the allowed list of a request. Each refused entry is named by its index, all of them in one answer, and a
// repeated entry is kept once.
func parseAllowed(in []string) ([]netip.Prefix, []httpx.FieldError) {
	var out []netip.Prefix
	var bad []httpx.FieldError
	seen := map[netip.Prefix]bool{}
	for i, v := range in {
		p, ok := apitoken.ParseAllowed(v)
		if !ok {
			bad = append(bad, httpx.FieldError{Name: "/allowed_ips/" + strconv.Itoa(i), Code: "invalid"})
			continue
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	if len(in) > apitoken.MaxAllowed {
		bad = append(bad, httpx.FieldError{Name: "/allowed_ips", Code: "exceeded"})
	}
	return out, bad
}

func invalidFields(f []httpx.FieldError) *httpx.Error {
	return httpx.New(422, httpx.CodeValidationFailed).WithFields(f...)
}

// ListApiTokens is GET /api-tokens.
func (s *Server) ListApiTokens(ctx context.Context, _ gen.ListApiTokensRequestObject) (gen.ListApiTokensResponseObject, error) {
	p, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	out := gen.ListApiTokens200JSONResponse{Tokens: []gen.ApiToken{}}
	err = s.readTenant(ctx, p.TenantID, func(tx store.Tx) error {
		rows, err := tx.APITokenList(p.UserID)
		for _, r := range rows {
			out.Tokens = append(out.Tokens, tokenOut(r))
		}
		return err
	})
	return out, err
}

// CreateApiToken is POST /api-tokens. The day budget of the tenant (token-create) was charged by the pipeline.
func (s *Server) CreateApiToken(ctx context.Context, req gen.CreateApiTokenRequestObject) (gen.CreateApiTokenResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.BadRequest()
	}
	p, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	var asked []string
	if req.Body.AllowedIps != nil {
		asked = *req.Body.AllowedIps
	}
	allowed, bad := parseAllowed(asked)
	if len(bad) > 0 {
		return nil, invalidFields(bad)
	}
	id, err := uuid.NewV7()
	if err != nil {
		return nil, httpx.Internal()
	}
	now := s.now()
	// The expiry the value carries and the one the row holds are one instant, to the second (6.2).
	expires := now.Add(keyring.LifeAPIToken).Truncate(time.Second)
	value, err := s.bearer.Mint(bearer.APIToken, id, expires)
	if err != nil {
		return nil, httpx.Internal()
	}
	text := value.Reveal()
	var row store.APITokenRow
	ip := httpx.ClientIPFrom(ctx)
	err = s.inTenant(ctx, p.TenantID, func(tx store.Tx) error {
		// The quota lock first, as every transaction that adds against a tenant-wide count, then the user's row (3.7).
		if err := tx.QuotaLock(); err != nil {
			return err
		}
		if _, ok, err := tx.UserLock(p.UserID); err != nil {
			return err
		} else if !ok {
			return httpx.SessionExpired()
		}
		// The session is read under the user's lock, so a credential change that committed while this request waited (it took
		// this lock, rotated the session and revoked the user's tokens) is seen here. A password or phone change does not revoke
		// the session that makes it: it gives it a new token and keeps its id, so "not revoked" is not enough and the hash of the
		// cookie this request came in with must still be the session's (RULES 5; 6.4; review round 1 of D5, p3-D5-r1-4).
		if held, err := tx.SessionHoldsCookie(p.SessionID, p.CookieHash); err != nil {
			return err
		} else if !held {
			return httpx.SessionExpired()
		}
		won, err := tx.APITokenInsert(store.APITokenNew{
			ID: id, User: p.UserID, Name: req.Body.Name, Kind: string(req.Body.Kind), Hash: bearer.Hash(text),
			Prefix: text[tokenPrefixAt : tokenPrefixAt+tokenPrefixLen], Allowed: allowed, Expires: expires,
		})
		if err != nil {
			return err
		}
		if !won.Yes() {
			return invalidFields([]httpx.FieldError{{Name: "max_api_tokens", Code: "exceeded"}})
		}
		if row, _, err = tx.APITokenGet(p.UserID, id); err != nil {
			return err
		}
		return audit.Tenant(tx, p.UserID, ip, audit.APITokenCreate{TokenID: id})
	})
	if err != nil {
		return nil, err
	}
	return gen.CreateApiToken201JSONResponse{Token: tokenOut(row), Value: apitoken.Shown(text)}, nil
}

// PatchApiToken is PATCH /api-tokens/{tid}.
func (s *Server) PatchApiToken(ctx context.Context, req gen.PatchApiTokenRequestObject) (gen.PatchApiTokenResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.BadRequest()
	}
	p, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	edit := store.APITokenEdit{Name: req.Body.Name}
	if req.Body.AllowedIps != nil {
		allowed, bad := parseAllowed(*req.Body.AllowedIps)
		if len(bad) > 0 {
			return nil, invalidFields(bad)
		}
		edit.SetAllowed, edit.Allowed = true, allowed
	}
	var row store.APITokenRow
	ip := httpx.ClientIPFrom(ctx)
	err = s.inTenant(ctx, p.TenantID, func(tx store.Tx) error {
		r, found, err := tx.APITokenUpdate(p.UserID, uuid.UUID(req.Tid), edit)
		if err != nil {
			return err
		}
		if !found {
			return httpx.NotFound()
		}
		row = r
		return audit.Tenant(tx, p.UserID, ip, audit.APITokenUpdate{TokenID: row.ID})
	})
	if err != nil {
		return nil, err
	}
	return gen.PatchApiToken200JSONResponse(tokenOut(row)), nil
}

// DeleteApiToken is DELETE /api-tokens/{tid}.
func (s *Server) DeleteApiToken(ctx context.Context, req gen.DeleteApiTokenRequestObject) (gen.DeleteApiTokenResponseObject, error) {
	p, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	ip := httpx.ClientIPFrom(ctx)
	err = s.inTenant(ctx, p.TenantID, func(tx store.Tx) error {
		found, err := tx.APITokenDelete(p.UserID, uuid.UUID(req.Tid))
		if err != nil {
			return err
		}
		if !found {
			return httpx.NotFound()
		}
		return audit.Tenant(tx, p.UserID, ip, audit.APITokenDelete{TokenID: uuid.UUID(req.Tid)})
	})
	if err != nil {
		return nil, err
	}
	return gen.DeleteApiToken204Response{}, nil
}
