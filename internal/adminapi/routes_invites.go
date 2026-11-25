package adminapi

import (
	"context"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/adminapi/gen"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/audit"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/invite"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/phone"
	"github.com/Kup1ng/CtrlZ-Panel/internal/httpx"
	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// Invite lifetimes (spec 11.3). The longest comes from the key registry: a link stays good until its
// expiry, so it is also how long the old line of invite_sign has to be kept.
const (
	defaultInviteHours = 72
	maxInviteHours     = int(keyring.LifeInvite / time.Hour)
	// inviteSkew is added to the expiry inside the token so that a clock a few minutes apart between the
	// admin and the api never makes the token the one that refuses a row that is still live. The row decides.
	inviteSkew = 5 * time.Minute
)

// ListInvites is GET /invites. A row never carries a link, only the state.
func (s *Server) ListInvites(ctx context.Context, req gen.ListInvitesRequestObject) (gen.ListInvitesResponseObject, error) {
	before, err := uuidCursor(req.Params.Cursor)
	if err != nil {
		return nil, err
	}
	limit := pageLimit(req.Params.Limit)
	out := gen.InvitePage{Items: []gen.InviteRow{}}
	err = s.readGlobal(ctx, func(g store.GlobalTx) error {
		rows, err := g.InvitesPage(before, limit+1)
		if err != nil {
			return err
		}
		if len(rows) > limit {
			rows = rows[:limit]
			out.NextCursor = ptr(encodeKey(rows[len(rows)-1].ID.String()))
		}
		for _, r := range rows {
			out.Items = append(out.Items, gen.InviteRow{
				Id: r.ID, PhoneE164: r.Phone, Locale: r.Locale, State: gen.InviteRowState(r.State),
				ExpiresAt: r.ExpiresAt.UTC(), CreatedAt: r.CreatedAt.UTC(),
			})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return gen.ListInvites200JSONResponse(out), nil
}

// CreateInvite is POST /invites (spec 11.3, D67). The link is in this response and nowhere else; the database
// holds the SHA-256 of its token and nothing sends it: the admin copies it and gives it to whomever they
// choose. The token is signed here, with a key only this process holds.
func (s *Server) CreateInvite(ctx context.Context, req gen.CreateInviteRequestObject) (gen.CreateInviteResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.BadRequest()
	}
	b := *req.Body
	p, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	e164, err := phone.Normalize(b.Phone)
	if err != nil {
		return nil, errInvalidPhone()
	}
	locale := string(deref(b.Locale))
	if locale == "" {
		locale = "fa"
	}
	if locale != "fa" && locale != "en" {
		return nil, errValidation("locale", "invalid")
	}
	hours := defaultInviteHours
	if b.TtlHours != nil {
		hours = *b.TtlHours
	}
	if hours < 1 || hours > maxInviteHours {
		return nil, errValidation("ttl_hours", "out_of_range")
	}
	// The id is inside the signed token, so it is made here and the row is inserted under it. The expiry in the
	// token is the row's life plus a margin; the database clock decides for the row.
	id, err := uuid.NewV7()
	if err != nil {
		return nil, err
	}
	ttl := time.Duration(hours) * time.Hour
	token, hash, err := invite.Mint(s.d.Keys, id, s.now().Add(ttl+inviteSkew))
	if err != nil {
		return nil, err
	}
	var host string
	err = s.global(ctx, func(g store.GlobalTx) error {
		taken, err := g.PhoneHasAccount(e164)
		if err != nil {
			return err
		}
		if taken {
			return httpx.New(http.StatusConflict, httpx.CodePhoneUnavailable)
		}
		if host, err = s.panelHost(g); err != nil {
			return err
		}
		if _, err = g.InviteCreate(store.NewInvite{
			ID: id, TokenHash: hash, Phone: e164, Locale: locale, CreatedBy: p.AdminID, TTL: ttl,
		}); err != nil {
			return err
		}
		_, err = audit.Admin(g, s.now(), p.AdminID, httpx.ClientIPFrom(g.Context()), audit.InviteCreate{Invite: id, TTLHours: hours})
		return err
	})
	if err != nil {
		return nil, err
	}
	// A fragment never reaches a server or a log (R21).
	return gen.CreateInvite201JSONResponse{Id: id, Link: "https://" + host + "/invite#" + token.Reveal()}, nil
}

// RevokeInvite is DELETE /invites/{id}.
func (s *Server) RevokeInvite(ctx context.Context, req gen.RevokeInviteRequestObject) (gen.RevokeInviteResponseObject, error) {
	p, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	err = s.global(ctx, func(g store.GlobalTx) error {
		ok, err := g.InviteRevoke(req.Id)
		if err != nil {
			return err
		}
		if !ok {
			return httpx.NotFound()
		}
		_, err = audit.Admin(g, s.now(), p.AdminID, httpx.ClientIPFrom(g.Context()), audit.InviteRevoke{Invite: req.Id})
		return err
	})
	if err != nil {
		return nil, err
	}
	return gen.RevokeInvite204Response{}, nil
}
