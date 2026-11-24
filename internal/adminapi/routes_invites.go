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
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// Invite lifetimes (spec 11.3).
const (
	defaultInviteHours = 72
	maxInviteHours     = 720
)

// ListInvites is GET /invites. A row never carries a code, only the state.
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

// CreateInvite is POST /invites (spec 11.3). The code is in this response and
// nowhere else; the database holds its SHA-256. Nothing sends it (D67): the admin copies the link.
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
	code, hash, err := invite.New()
	if err != nil {
		return nil, err
	}
	var id uuid.UUID
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
		id, err = g.InviteCreate(store.NewInvite{
			TokenHash: hash, Phone: e164, Locale: locale, CreatedBy: p.AdminID,
			TTL: time.Duration(hours) * time.Hour,
		})
		if err != nil {
			return err
		}
		_, err = audit.Admin(g, s.now(), p.AdminID, httpx.ClientIPFrom(g.Context()), audit.InviteCreate{Invite: id, SendSMS: b.SendSms, TTLHours: hours})
		return err
	})
	if err != nil {
		return nil, err
	}
	// A fragment never reaches a server or a log (R21).
	return gen.CreateInvite201JSONResponse{Id: id, Code: code.Reveal(), Link: "https://" + host + "/invite#" + code.Reveal()}, nil
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
