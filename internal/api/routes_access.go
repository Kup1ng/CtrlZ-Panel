package api

import (
	"context"
	"net/netip"
	"strings"

	"github.com/google/uuid"
	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/Kup1ng/CtrlZ-Panel/internal/api/gen"
	"github.com/Kup1ng/CtrlZ-Panel/internal/endpoints"
	"github.com/Kup1ng/CtrlZ-Panel/internal/httpx"
	"github.com/Kup1ng/CtrlZ-Panel/internal/setup"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// The access routes of an Endpoint: Dynamic DNS hosts, Authorized IPs and Plain DNS claims (docs/specs/p3-endpoints.md 4, 5,
// 9.2). A handler decodes and calls internal/endpoints; nothing here writes a table.

// ---------------------------------------------------------------------------
// Conversions.

func authorizedOut(r store.AuthorizedRow) gen.AuthorizedIP {
	return gen.AuthorizedIP{Id: openapi_types.UUID(r.ID), Cidr: r.CIDR.String(), Source: gen.AuthorizedIPSource(r.Source), CleanupOptIn: r.CleanupOptIn,
		City: r.City, Isp: r.ISP, LastSeenAt: r.LastSeenAt, CreatedAt: r.CreatedAt, IsCurrent: r.IsCurrent}
}

func authorizedListOut(rows []store.AuthorizedRow) []gen.AuthorizedIP {
	out := make([]gen.AuthorizedIP, 0, len(rows))
	for _, r := range rows {
		out = append(out, authorizedOut(r))
	}
	return out
}

func ddnsOut(h store.DDNSHostRow) gen.DdnsHost {
	ips := h.LastIPs
	if ips == nil {
		ips = []string{}
	}
	return gen.DdnsHost{Id: openapi_types.UUID(h.ID), Hostname: h.Hostname, LastResolvedAt: h.LastResolvedAt, LastIps: ips, LastError: h.LastError}
}

func claimOut(c store.ClaimRow) gen.IPClaim {
	out := gen.IPClaim{Id: openapi_types.UUID(c.ID), Cidr: c.CIDR.String(), State: gen.IPClaimState(c.State), Proven: c.ProvenAt != nil,
		Source: gen.IPClaimSource(c.Source), GraceUntil: c.GraceUntil, LastSeenAt: c.LastSeenAt, NeedsAdmin: c.NeedsAdmin}
	if c.Method != nil {
		m := gen.IPClaimProofMethod(*c.Method)
		out.ProofMethod = &m
	}
	if ch := c.Challenge; ch != nil {
		o := gen.ClaimChallenge{Id: openapi_types.UUID(ch.ID), Label: ch.Label, ExpiresAt: ch.ExpiresAt, Observed: ch.Observed}
		if ch.Protocol != nil {
			p := gen.ClaimChallengeObservedProtocol(*ch.Protocol)
			o.ObservedProtocol = &p
		}
		out.Challenge = &o
	}
	return out
}

// challengeCommands is the part of the Resolver view a proof needs: the name to query and the pair's addresses, primary
// first (SC 8a.8). It is not ready while the admin has set no domain or the Endpoint has no pair, as the view of 8.1 is not.
func challengeCommands(label, zone string, primary, fallback netip.Addr) gen.ChallengeCommands {
	switch {
	case zone == "":
		r := gen.ChallengeCommandsReason(setup.ReasonZoneMissing)
		return gen.ChallengeCommands{Ready: false, Reason: &r}
	case !primary.IsValid():
		r := gen.ChallengeCommandsReason(setup.ReasonPairMissing)
		return gen.ChallengeCommands{Ready: false, Reason: &r}
	}
	host := label + ".verify." + strings.TrimSuffix(zone, ".")
	l := gen.ChallengeLegacy{Dns1: primary.String()}
	if fallback.IsValid() {
		l.Dns2 = fallback.String()
	}
	return gen.ChallengeCommands{Ready: true, VerifyHost: &host, Legacy: &l}
}

// ---------------------------------------------------------------------------
// DDNS hosts.

// ListDdnsHosts is GET /endpoints/{id}/ddns-hosts.
func (s *Server) ListDdnsHosts(ctx context.Context, req gen.ListDdnsHostsRequestObject) (gen.ListDdnsHostsResponseObject, error) {
	pr, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	out := gen.ListDdnsHosts200JSONResponse{Hosts: []gen.DdnsHost{}}
	err = s.readTenant(ctx, pr.TenantID, func(tx store.Tx) error {
		if _, ok, err := tx.EndpointGet(uuid.UUID(req.Id)); err != nil {
			return err
		} else if !ok {
			return httpx.NotFound()
		}
		rows, err := tx.DDNSHostList(uuid.UUID(req.Id))
		for _, h := range rows {
			out.Hosts = append(out.Hosts, ddnsOut(h))
		}
		return err
	})
	return out, err
}

// CreateDdnsHost is POST /endpoints/{id}/ddns-hosts.
func (s *Server) CreateDdnsHost(ctx context.Context, req gen.CreateDdnsHostRequestObject) (gen.CreateDdnsHostResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.BadRequest()
	}
	pr, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	h, err := s.ep.CreateDDNSHost(ctx, s.d.Store, pr.TenantID, epWrite(), uuid.UUID(req.Id), req.Body.Hostname)
	if err != nil {
		return nil, profileError(err)
	}
	return gen.CreateDdnsHost201JSONResponse(ddnsOut(h)), nil
}

// DeleteDdnsHost is POST /endpoints/{id}/ddns-hosts/{hid}:delete.
func (s *Server) DeleteDdnsHost(ctx context.Context, req gen.DeleteDdnsHostRequestObject) (gen.DeleteDdnsHostResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.BadRequest()
	}
	pr, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	a, err := s.endpointAuth(ctx, pr, req.Body.LockPasswords)
	if err != nil {
		return nil, err
	}
	if err := s.ep.DeleteDDNSHost(ctx, s.d.Store, pr.TenantID, epWrite(), a, uuid.UUID(req.Id), uuid.UUID(req.Hid), httpx.ClientIPFrom(ctx)); err != nil {
		return nil, profileError(err)
	}
	return gen.DeleteDdnsHost204Response{}, nil
}

// ---------------------------------------------------------------------------
// Authorized IPs.

// ListAuthorizedIps is GET /endpoints/{id}/authorized-ips.
func (s *Server) ListAuthorizedIps(ctx context.Context, req gen.ListAuthorizedIpsRequestObject) (gen.ListAuthorizedIpsResponseObject, error) {
	pr, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	cur, err := decodeOwnedCursor(req.Params.Cursor, pr.TenantID)
	if err != nil {
		return nil, err
	}
	f := store.AuthorizedFilter{Endpoint: uuid.UUID(req.Id), Q: str(req.Params.Q), Current: httpx.ClientIPFrom(ctx), Limit: pageLimit(req.Params.Limit) + 1,
		HasAfter: !cur.At.IsZero(), AfterAt: cur.At, AfterID: cur.ID}
	out := gen.ListAuthorizedIps200JSONResponse{Items: []gen.AuthorizedIP{}}
	err = s.snapshotTx(ctx, pr.TenantID, func(tx store.Tx) error {
		if _, ok, err := tx.EndpointGet(f.Endpoint); err != nil {
			return err
		} else if !ok {
			return httpx.NotFound()
		}
		rows, err := tx.AuthorizedList(f)
		if err != nil {
			return err
		}
		if len(rows) > f.Limit-1 {
			rows = rows[:f.Limit-1]
			c := encodeCursor(pr.TenantID, rows[len(rows)-1].CreatedAt, rows[len(rows)-1].ID)
			out.NextCursor = &c
		}
		out.Items = authorizedListOut(rows)
		return nil
	})
	return out, err
}

// AddAuthorizedIps is POST /endpoints/{id}/authorized-ips.
func (s *Server) AddAuthorizedIps(ctx context.Context, req gen.AddAuthorizedIpsRequestObject) (gen.AddAuthorizedIpsResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.BadRequest()
	}
	pr, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := s.ep.AddAuthorized(ctx, s.d.Store, pr.TenantID, epWrite(), uuid.UUID(req.Id), req.Body.Cidrs)
	if err != nil {
		return nil, profileError(err)
	}
	return gen.AddAuthorizedIps201JSONResponse{Items: authorizedListOut(rows)}, nil
}

// PatchAuthorizedIp is PATCH /endpoints/{id}/authorized-ips/{aid}.
func (s *Server) PatchAuthorizedIp(ctx context.Context, req gen.PatchAuthorizedIpRequestObject) (gen.PatchAuthorizedIpResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.BadRequest()
	}
	pr, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	a, err := s.endpointAuth(ctx, pr, req.Body.LockPasswords)
	if err != nil {
		return nil, err
	}
	row, err := s.ep.SetCleanupOptIn(ctx, s.d.Store, pr.TenantID, epWrite(), a, uuid.UUID(req.Id), uuid.UUID(req.Aid), req.Body.CleanupOptIn, httpx.ClientIPFrom(ctx))
	if err != nil {
		return nil, profileError(err)
	}
	return gen.PatchAuthorizedIp200JSONResponse(authorizedOut(row)), nil
}

// DeleteAuthorizedIps is POST /endpoints/{id}/authorized-ips:delete.
func (s *Server) DeleteAuthorizedIps(ctx context.Context, req gen.DeleteAuthorizedIpsRequestObject) (gen.DeleteAuthorizedIpsResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.BadRequest()
	}
	pr, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	a, err := s.endpointAuth(ctx, pr, req.Body.LockPasswords)
	if err != nil {
		return nil, err
	}
	if err := s.ep.DeleteAuthorized(ctx, s.d.Store, pr.TenantID, epWrite(), a, uuid.UUID(req.Id), uuidList(&req.Body.Ids), httpx.ClientIPFrom(ctx)); err != nil {
		return nil, profileError(err)
	}
	return gen.DeleteAuthorizedIps204Response{}, nil
}

// ---------------------------------------------------------------------------
// Plain DNS claims.

// ListIpClaims is GET /endpoints/{id}/ip-claims.
func (s *Server) ListIpClaims(ctx context.Context, req gen.ListIpClaimsRequestObject) (gen.ListIpClaimsResponseObject, error) {
	pr, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	out := gen.ListIpClaims200JSONResponse{Claims: []gen.IPClaim{}}
	err = s.readTenant(ctx, pr.TenantID, func(tx store.Tx) error {
		if _, ok, err := tx.EndpointGet(uuid.UUID(req.Id)); err != nil {
			return err
		} else if !ok {
			return httpx.NotFound()
		}
		rows, err := tx.ClaimList(uuid.UUID(req.Id))
		for _, c := range rows {
			out.Claims = append(out.Claims, claimOut(c))
		}
		return err
	})
	return out, err
}

// RequestIpClaim is POST /endpoints/{id}/ip-claims. The prefix is typed, or it is the address the panel saw this request come
// from, as a /32 with source browser (spec 4.2).
func (s *Server) RequestIpClaim(ctx context.Context, req gen.RequestIpClaimRequestObject) (gen.RequestIpClaimResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.BadRequest()
	}
	pr, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	ask := endpoints.ClaimAsk{Cidr: req.Body.Cidr, Mine: httpx.ClientIPFrom(ctx), UseMine: req.Body.UseMyAddress != nil && *req.Body.UseMyAddress}
	if e := ask.Check(); e != nil {
		return nil, profileError(e)
	}
	r, err := s.ep.RequestClaim(ctx, s.d.Store, pr.TenantID, epWrite(), uuid.UUID(req.Id), ask)
	if err != nil {
		return nil, profileError(err)
	}
	return gen.RequestIpClaim201JSONResponse(claimOut(r.Claim)), nil
}

// OpenIpClaimChallenge is POST /endpoints/{id}/ip-claims/{claim_id}/challenges.
func (s *Server) OpenIpClaimChallenge(ctx context.Context, req gen.OpenIpClaimChallengeRequestObject) (gen.OpenIpClaimChallengeResponseObject, error) {
	pr, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	c, err := s.ep.OpenChallenge(ctx, s.d.Store, pr.TenantID, epWrite(), uuid.UUID(req.Id), uuid.UUID(req.ClaimId))
	if err != nil {
		return nil, profileError(err)
	}
	return gen.OpenIpClaimChallenge201JSONResponse{Id: openapi_types.UUID(c.Challenge.ID), Label: c.Challenge.Label, ExpiresAt: c.Challenge.ExpiresAt,
		Commands: challengeCommands(c.Challenge.Label, c.Zone, c.Primary, c.Fallback)}, nil
}

// TakeIpClaim is POST /endpoints/{id}/ip-claims/{claim_id}:take.
func (s *Server) TakeIpClaim(ctx context.Context, req gen.TakeIpClaimRequestObject) (gen.TakeIpClaimResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.BadRequest()
	}
	pr, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	r, err := s.ep.TakeClaim(ctx, s.d.Store, pr.TenantID, epWrite(), uuid.UUID(req.Id), uuid.UUID(req.ClaimId), foldProofCode(str(req.Body.Code)))
	if err != nil {
		return nil, profileError(err)
	}
	return gen.TakeIpClaim200JSONResponse{Claim: claimOut(r.Claim), Outcome: gen.ClaimTakeOutcome(r.Outcome)}, nil
}

// ReleaseIpClaim is POST /endpoints/{id}/ip-claims/{claim_id}:release.
func (s *Server) ReleaseIpClaim(ctx context.Context, req gen.ReleaseIpClaimRequestObject) (gen.ReleaseIpClaimResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.BadRequest()
	}
	pr, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	a, err := s.endpointAuth(ctx, pr, req.Body.LockPasswords)
	if err != nil {
		return nil, err
	}
	if err := s.ep.ReleaseClaim(ctx, s.d.Store, pr.TenantID, epWrite(), a, uuid.UUID(req.Id), uuid.UUID(req.ClaimId)); err != nil {
		return nil, profileError(err)
	}
	return gen.ReleaseIpClaim204Response{}, nil
}

// foldProofCode keeps the letters and digits of a typed proof code: the schema lets the marks of a paste through (a right-to-left
// editor, a copied space or line break), and the database compares the code as typed with the SHA-256 of what the node sent.
func foldProofCode(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' {
			b.WriteRune(r)
		}
	}
	return b.String()
}
