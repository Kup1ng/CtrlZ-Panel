package api

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/Kup1ng/CtrlZ-Panel/internal/api/gen"
	"github.com/Kup1ng/CtrlZ-Panel/internal/apispec"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/bearer"
	"github.com/Kup1ng/CtrlZ-Panel/internal/endpoints"
	"github.com/Kup1ng/CtrlZ-Panel/internal/httpx"
	"github.com/Kup1ng/CtrlZ-Panel/internal/setup"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// The routes of the Resolver view, the generators, the share links and the Apple profile (docs/specs/p3-endpoints.md 7 and 8). A
// handler decodes the request and calls internal/endpoints, which writes the link tables and opens the DoH token; nothing here
// touches either.

// linkKey is the pipeline's Bearer reader (P3 7.1): the value of a share or download link of the request, screened with no I/O,
// as the id of the row it names. A value that does not screen is the same 404 as every other refusal and charges nothing. The
// kind is part of the key, so a share row and a download row never meet in a budget.
func (s *Server) linkKey(r *http.Request, op apispec.Operation) (string, bool) {
	var kind bearer.Kind
	var text string
	switch op.ID {
	case "openShare", "createShareAppleProfile":
		kind, text = bearer.ShareLink, bodyField(r, "link")
	case "downloadAppleProfile":
		kind, text = bearer.DownloadLink, chi.URLParam(r, "link")
	default:
		return "", false
	}
	b, ok := s.bearer.Screen(kind, text)
	if !ok {
		return "", false
	}
	return string(rune(kind)) + ":" + b.ID.String(), true
}

// viaJSON copies a value into another type with the same JSON shape: the view of internal/setup is one source of every value a
// user is given, and the generated type is its document, so neither is written twice.
func viaJSON(from, to any) error {
	b, err := json.Marshal(from)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, to)
}

// ---------------------------------------------------------------------------
// The Resolver view and the generators (8.1, 8.2).

// GetEndpointResolvers is GET /endpoints/{id}/resolvers.
func (s *Server) GetEndpointResolvers(ctx context.Context, req gen.GetEndpointResolversRequestObject) (gen.GetEndpointResolversResponseObject, error) {
	pr, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	var v setup.ResolverView
	err = s.d.Store.WithTenant(ctx, pr.TenantID, store.TxOpts{ReadOnly: true}, func(tx store.Tx) (err error) {
		v, _, err = s.ep.ResolverFor(tx, uuid.UUID(req.Id), str(req.Params.Client))
		return err
	})
	if err != nil {
		return nil, profileError(err)
	}
	var out gen.GetEndpointResolvers200JSONResponse
	if err := viaJSON(v, &out); err != nil {
		return nil, httpx.Internal()
	}
	return out, nil
}

// textResponse is the body of GET /endpoints/{id}/generators/{generator}: the document gives it no schema (a script holds line
// breaks, which the boundary rules refuse in a string), so the response type is ours.
type textResponse struct{ body string }

func (r textResponse) VisitGetEndpointGeneratorResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, err := w.Write([]byte(r.body))
	return err
}

var _ gen.GetEndpointGeneratorResponseObject = textResponse{}

// GetEndpointGenerator is GET /endpoints/{id}/generators/{generator}.
func (s *Server) GetEndpointGenerator(ctx context.Context, req gen.GetEndpointGeneratorRequestObject) (gen.GetEndpointGeneratorResponseObject, error) {
	pr, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	var text string
	err = s.d.Store.WithTenant(ctx, pr.TenantID, store.TxOpts{ReadOnly: true}, func(tx store.Tx) (err error) {
		text, _, err = s.ep.Generate(tx, uuid.UUID(req.Id), str(req.Params.Client), req.Params.Generator)
		return err
	})
	if err != nil {
		return nil, profileError(err)
	}
	return textResponse{body: text}, nil
}

// ---------------------------------------------------------------------------
// Share links (7.2).

func shareLinkOut(r store.ShareLinkRow) gen.ShareLink {
	o := gen.ShareLink{Id: openapi_types.UUID(r.ID), ExpiresAt: r.ExpiresAt, Uses: r.Uses, MaxUses: r.MaxUses, Revoked: r.Revoked, CreatedAt: r.CreatedAt}
	if r.Client != "" {
		c := r.Client
		o.Client = &c
	}
	return o
}

// ListShareLinks is GET /endpoints/{id}/share-links.
func (s *Server) ListShareLinks(ctx context.Context, req gen.ListShareLinksRequestObject) (gen.ListShareLinksResponseObject, error) {
	pr, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	out := gen.ListShareLinks200JSONResponse{Links: []gen.ShareLink{}}
	err = s.readTenant(ctx, pr.TenantID, func(tx store.Tx) error {
		if _, ok, err := tx.EndpointGet(uuid.UUID(req.Id)); err != nil {
			return err
		} else if !ok {
			return httpx.NotFound()
		}
		rows, err := tx.ShareLinkList(uuid.UUID(req.Id))
		for _, r := range rows {
			out.Links = append(out.Links, shareLinkOut(r))
		}
		return err
	})
	return out, err
}

// CreateShareLink is POST /endpoints/{id}/share-links.
func (s *Server) CreateShareLink(ctx context.Context, req gen.CreateShareLinkRequestObject) (gen.CreateShareLinkResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.BadRequest()
	}
	pr, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	host, err := panelHost(s.cfg, s.d.PanelHost)(ctx)
	if err != nil {
		return nil, err
	}
	in := endpoints.ShareIn{Endpoint: uuid.UUID(req.Id), Client: str(req.Body.Client)}
	if req.Body.TtlHours != nil {
		in.TTLHours = *req.Body.TtlHours
	}
	made, err := s.ep.ShareCreate(ctx, s.d.Store, pr.TenantID, epWrite(), endpoints.Actor{User: pr.UserID, IP: httpx.ClientIPFrom(ctx)}, in)
	if err != nil {
		return nil, profileError(err)
	}
	return gen.CreateShareLink201JSONResponse{Link: shareLinkOut(made.Link), Url: "https://" + host + "/s/" + made.Value.Reveal()}, nil
}

// RevokeShareLink is DELETE /endpoints/{id}/share-links/{sid}.
func (s *Server) RevokeShareLink(ctx context.Context, req gen.RevokeShareLinkRequestObject) (gen.RevokeShareLinkResponseObject, error) {
	pr, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.ep.ShareRevoke(ctx, s.d.Store, pr.TenantID, epWrite(), endpoints.Actor{User: pr.UserID, IP: httpx.ClientIPFrom(ctx)},
		uuid.UUID(req.Id), uuid.UUID(req.Sid)); err != nil {
		return nil, profileError(err)
	}
	return gen.RevokeShareLink204Response{}, nil
}

// ---------------------------------------------------------------------------
// The Apple profile (7.3).

func appleRequest(client *string, protocol string, ssids, domains *[]string, common, prohibit *bool) endpoints.AppleRequest {
	r := endpoints.AppleRequest{Client: str(client), Protocol: protocol, ExcludeCommon: flag(common), ProhibitDisablement: flag(prohibit)}
	if ssids != nil {
		r.ExcludedSSIDs = *ssids
	}
	if domains != nil {
		r.ExcludedDomains = *domains
	}
	return r
}

// CreateAppleProfile is POST /endpoints/{id}/apple-profile.
func (s *Server) CreateAppleProfile(ctx context.Context, req gen.CreateAppleProfileRequestObject) (gen.CreateAppleProfileResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.BadRequest()
	}
	pr, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	host, err := panelHost(s.cfg, s.d.PanelHost)(ctx)
	if err != nil {
		return nil, err
	}
	b := req.Body
	out, err := s.ep.AppleCreate(ctx, s.d.Store, pr.TenantID, epWrite(), endpoints.AppleIn{
		Endpoint: uuid.UUID(req.Id), Folder: uid(b.FromFolderId),
		Request: appleRequest(b.Client, string(b.Protocol), b.ExcludedSsids, b.ExcludedDomains, b.ExcludeCommon, b.ProhibitDisablement),
	})
	if err != nil {
		return nil, profileError(err)
	}
	return gen.CreateAppleProfile201JSONResponse{Url: "https://" + host + "/p/" + out.Value.Reveal(), ExpiresAt: out.Expires}, nil
}

// ---------------------------------------------------------------------------
// The public routes (7.1). The pipeline has screened the value and charged the row it names; what is left is the lookup, which
// answers every refusal as 404 and says to the pipeline when no row exists at all.

// OpenShare is POST /public/share.
func (s *Server) OpenShare(ctx context.Context, req gen.OpenShareRequestObject) (gen.OpenShareResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.NotFound()
	}
	b, ok := s.bearer.Screen(bearer.ShareLink, req.Body.Link)
	if !ok {
		return nil, httpx.NotFound()
	}
	v, dead, err := s.ep.OpenShare(ctx, s.d.Store, epWrite(), b.ID, req.Body.Link)
	if err != nil {
		if dead {
			httpx.MarkLinkDead(ctx)
		}
		return nil, profileError(err)
	}
	var out gen.OpenShare200JSONResponse
	if err := viaJSON(v.Resolvers, &out.Resolvers); err != nil {
		return nil, httpx.Internal()
	}
	out.Endpoint.Name, out.Endpoint.Type, out.ExpiresAt = v.Name, v.Type, v.ExpiresAt
	return out, nil
}

// CreateShareAppleProfile is POST /public/share/apple-profile.
func (s *Server) CreateShareAppleProfile(ctx context.Context, req gen.CreateShareAppleProfileRequestObject) (gen.CreateShareAppleProfileResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.NotFound()
	}
	b, ok := s.bearer.Screen(bearer.ShareLink, req.Body.Link)
	if !ok {
		return nil, httpx.NotFound()
	}
	host, err := panelHost(s.cfg, s.d.PanelHost)(ctx)
	if err != nil {
		return nil, err
	}
	p := req.Body.Params
	out, dead, err := s.ep.OpenShareApple(ctx, s.d.Store, epWrite(), b.ID, req.Body.Link,
		appleRequest(p.Client, string(p.Protocol), p.ExcludedSsids, p.ExcludedDomains, p.ExcludeCommon, p.ProhibitDisablement))
	if err != nil {
		if dead {
			httpx.MarkLinkDead(ctx)
		}
		return nil, profileError(err)
	}
	return gen.CreateShareAppleProfile201JSONResponse{Url: "https://" + host + "/p/" + out.Value.Reveal(), ExpiresAt: out.Expires}, nil
}

// profileFile is the body of GET /public/apple-profile/{token}: the file, as an attachment with an ASCII name.
type profileFile struct {
	data []byte
	name string
}

func (r profileFile) VisitDownloadAppleProfileResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/x-apple-aspen-config")
	// The name is ASCII by construction (mobileconfig.Build), so it needs no escaping.
	w.Header().Set("Content-Disposition", `attachment; filename="`+r.name+`"`)
	w.WriteHeader(http.StatusOK)
	_, err := w.Write(r.data)
	return err
}

var _ gen.DownloadAppleProfileResponseObject = profileFile{}

// DownloadAppleProfile is GET /public/apple-profile/{token}.
func (s *Server) DownloadAppleProfile(ctx context.Context, req gen.DownloadAppleProfileRequestObject) (gen.DownloadAppleProfileResponseObject, error) {
	b, ok := s.bearer.Screen(bearer.DownloadLink, req.Link)
	if !ok {
		return nil, httpx.NotFound()
	}
	p, dead, err := s.ep.DownloadApple(ctx, s.d.Store, epWrite(), b.ID, req.Link)
	if err != nil {
		if dead {
			httpx.MarkLinkDead(ctx)
		}
		return nil, profileError(err)
	}
	return profileFile{data: p.Data, name: p.FileName}, nil
}
