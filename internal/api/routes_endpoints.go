package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/Kup1ng/CtrlZ-Panel/internal/api/gen"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/audit"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/proof"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/session"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/throttle"
	"github.com/Kup1ng/CtrlZ-Panel/internal/endpoints"
	"github.com/Kup1ng/CtrlZ-Panel/internal/httpx"
	"github.com/Kup1ng/CtrlZ-Panel/internal/profiles"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// The Endpoint routes (docs/specs/p3-endpoints.md 9). A handler decodes the request and calls internal/endpoints, which owns
// the lock order, the lock passwords, the destinations check, the caps and the outbox marks; nothing here writes an Endpoint,
// group, schedule or client table.

// endpointsError maps a refusal of the Endpoint write path to the API error of spec 9.4. It is called by profileError, which
// every write transaction of the api answers through, so the idempotent routes map it too.
func endpointsError(err error) (*httpx.Error, bool) {
	var ee *endpoints.Error
	if !errors.As(err, &ee) {
		return nil, false
	}
	fs := make([]httpx.FieldError, 0, len(ee.Fields))
	for _, f := range ee.Fields {
		fs = append(fs, httpx.FieldError{Name: f.Name, Code: f.Code})
	}
	var e *httpx.Error
	switch ee.Kind {
	case endpoints.KindNotFound:
		return httpx.NotFound(), true
	case endpoints.KindValidation:
		e = httpx.New(http.StatusUnprocessableEntity, httpx.CodeValidationFailed)
	case endpoints.KindLocked:
		e = httpx.New(statusLocked, httpx.CodeProfileLocked)
	case endpoints.KindInvalidCredentials:
		e = httpx.New(http.StatusUnauthorized, httpx.CodeInvalidCredentials)
	case endpoints.KindHeld:
		e = httpx.New(http.StatusConflict, httpx.CodeEndpointHeld)
	case endpoints.KindDestinationsLost:
		e = httpx.New(http.StatusConflict, httpx.CodeDestinationsLost)
	case endpoints.KindConflict:
		e = httpx.New(http.StatusConflict, httpx.CodeConflict)
	case endpoints.KindTokenNotAllowed:
		e = httpx.New(http.StatusForbidden, httpx.CodeTokenNotAllowed)
	case endpoints.KindKeyReused:
		e = httpx.New(http.StatusConflict, httpx.CodeKeyReused)
	case endpoints.KindIPSuspended:
		e = httpx.New(http.StatusConflict, httpx.CodeIPSuspended)
	case endpoints.KindIPUnavailable:
		// Generic on purpose: the same answer whoever holds the address (spec 4.3, D35).
		e = httpx.New(http.StatusConflict, httpx.CodeIPUnavailable)
	case endpoints.KindNeedsAdmin:
		e = httpx.New(http.StatusConflict, httpx.CodeNeedsAdminApproval)
	case endpoints.KindTooManyChallenges:
		e = httpx.New(http.StatusTooManyRequests, httpx.CodeTooManyAttempts).WithRetry(time.Duration(ee.RetryAfter) * time.Second)
	default:
		return httpx.Internal(), true
	}
	if len(fs) > 0 {
		e = e.WithFields(fs...)
	}
	return e, true
}

// lockVerifier is the endpoints.Verifier of a request: the throttle scopes of P2 7.2 and the Argon2 gate.
type lockVerifier struct {
	s      *Server
	tenant uuid.UUID
	user   uuid.UUID
	ip     netip.Addr
}

// CheckLockPassword charges the tenant-wide scope and the profile's own, in the order of the unlock route, then checks the password in
// the gate, outside any transaction. A busy gate gives both charges back.
func (v lockVerifier) CheckLockPassword(ctx context.Context, profile uuid.UUID, pw, stored secret.String) (bool, error) {
	who := throttle.Who{Tenant: v.tenant, Profile: profile}
	if err := v.s.throttle.Charge(ctx, throttle.ProfileLockTenant, who); err != nil {
		return false, apiError(err)
	}
	if err := v.s.throttle.Charge(ctx, throttle.ProfileUnlock, who); err != nil {
		_ = v.s.throttle.Refund(context.WithoutCancel(ctx), throttle.ProfileLockTenant, who)
		return false, apiError(err)
	}
	ok, err := v.s.verifyStored(ctx, pw, stored)
	if err != nil {
		if proof.Busy(err) {
			bg := context.WithoutCancel(ctx)
			_ = v.s.throttle.Refund(bg, throttle.ProfileUnlock, who)
			_ = v.s.throttle.Refund(bg, throttle.ProfileLockTenant, who)
		}
		return false, apiError(err)
	}
	return ok, nil
}

// LockPasswordFailed writes the audit row of a wrong password, in a transaction of its own: the request is refused, so nothing of its
// own is kept.
func (v lockVerifier) LockPasswordFailed(ctx context.Context, profile, endpoint uuid.UUID) error {
	return v.s.writeTx(ctx, v.tenant, func(tx store.Tx) error {
		return audit.Tenant(tx, v.user, v.ip, audit.ProfileLockPasswordFailed{ProfileID: profile, EndpointID: endpoint})
	})
}

// LockPasswordUsed writes the audit row of a verified password for a request that ends without a commit, in a transaction of its
// own (the write that commits writes it in its own transaction).
func (v lockVerifier) LockPasswordUsed(ctx context.Context, profile, endpoint uuid.UUID) error {
	return v.s.writeTx(ctx, v.tenant, func(tx store.Tx) error {
		return audit.Tenant(tx, v.user, v.ip, audit.ProfileLockPasswordUsed{ProfileID: profile, EndpointID: endpoint})
	})
}

// LockPasswordsAccepted clears profile_unlock for each profile whose password a committed write used, as the unlock route does
// after a right password: that scope counts failures, so right passwords must not use it up. profile_lock_tenant is not cleared
// (P3 spec 3.3). A convenience after the commit, not a gate.
func (v lockVerifier) LockPasswordsAccepted(ctx context.Context, profiles []uuid.UUID) {
	for _, p := range profiles {
		_ = v.s.throttle.Clear(ctx, throttle.ProfileUnlock, throttle.Who{Tenant: v.tenant, Profile: p})
	}
}

// endpointAuth builds what a write that may need lock passwords carries: the passwords, bounded as P2 7.1 bounds them
// before any charge, and who asks.
func (s *Server) endpointAuth(ctx context.Context, pr session.Principal, lp *gen.LockPasswords) (endpoints.Auth, error) {
	a := endpoints.Auth{
		Actor:    endpoints.Actor{User: pr.UserID, IP: httpx.ClientIPFrom(ctx)},
		Verifier: lockVerifier{s: s, tenant: pr.TenantID, user: pr.UserID, ip: httpx.ClientIPFrom(ctx)},
	}
	if lp == nil {
		return a, nil
	}
	if len(*lp) > endpoints.MaxLockPasswords {
		return a, profileError(&endpoints.Error{Kind: endpoints.KindValidation, Fields: []endpoints.Field{{Name: "/lock_passwords", Code: endpoints.CodeExceeded}}})
	}
	for i, p := range *lp {
		n, perr := profiles.NormalizeLockPassword(secret.New(p.Password))
		if perr != nil {
			code := endpoints.CodeInvalid
			if len(perr.Fields) > 0 {
				code = perr.Fields[0].Code
			}
			return a, profileError(&endpoints.Error{Kind: endpoints.KindValidation,
				Fields: []endpoints.Field{{Name: "/lock_passwords/" + strconv.Itoa(i) + "/password", Code: code}}})
		}
		a.Passwords = append(a.Passwords, endpoints.Password{Profile: uuid.UUID(p.ProfileId), Secret: n})
	}
	return a, nil
}

// epWrite is the options of every Endpoint write transaction: the bound on lock waits of 3.1.
func epWrite() store.TxOpts { return store.TxOpts{LockWait: writeLockWait} }

// ---------------------------------------------------------------------------
// Conversions.

func endpointOut(r store.EndpointRow) gen.Endpoint {
	e := gen.Endpoint{
		Id: openapi_types.UUID(r.ID), Name: r.Name, Type: r.Type, GroupId: uidp(r.GroupID), Comment: r.Comment, ResolverId: r.ResolverID,
		ProfileId: openapi_types.UUID(r.ProfileID), Profile2Id: uidp(r.Profile2ID), AnalyticsLevel: gen.EndpointAnalyticsLevel(r.AnalyticsLevel),
		AdminState: gen.EndpointAdminState(r.AdminState), AdminHold: r.AdminHold, Status: gen.EndpointStatus("pending"),
		LegacyDns: r.LegacyDNS, AuthorizeSecureDns: r.AuthorizeSecureDNS, AuthorizeDdns: r.AuthorizeDDNS, ExposeIp: r.ExposeIP,
		PreventDeactivation: r.PreventDeactivation, RequireAuthorizedIps: r.RequireAuthorizedIPs, ScheduleTimezone: r.ScheduleTimezone,
		HasSchedule: r.HasSchedule, FirstQueryAt: r.FirstQueryAt, LastQueryAt: r.LastQueryAt, AppleProfileStale: r.AppleStale,
		CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
		Counts: gen.EndpointCounts{Clients: r.Clients, AuthorizedIps: r.AuthorizedIPs, ClaimsWaiting: r.ClaimsWaiting},
	}
	if r.FirstQueryAt != nil {
		e.Status = gen.EndpointStatus("active")
	}
	return e
}

func endpointsOut(rows []store.EndpointRow) []gen.Endpoint {
	out := make([]gen.Endpoint, 0, len(rows))
	for _, r := range rows {
		out = append(out, endpointOut(r))
	}
	return out
}

func clientOut(c store.ClientRow) gen.Client {
	o := gen.Client{Id: openapi_types.UUID(c.ID), Label: c.Label, Alias: c.Alias, GroupName: c.GroupName, ProfileId: uidp(c.ProfileID),
		Profile2Id: uidp(c.Profile2ID), Source: gen.ClientSource(c.Source), IsCustom: c.IsCustom, Hostname: c.Hostname, Mac: c.MAC, Ip: c.IP,
		FirstSeenAt: c.FirstSeenAt, LastSeenAt: c.LastSeenAt}
	if c.AnalyticsLevel != nil {
		l := gen.ClientAnalyticsLevel(*c.AnalyticsLevel)
		o.AnalyticsLevel = &l
	}
	return o
}

func uuidList(p *[]openapi_types.UUID) []uuid.UUID {
	if p == nil {
		return nil
	}
	out := make([]uuid.UUID, len(*p))
	for i, id := range *p {
		out[i] = uuid.UUID(id)
	}
	return out
}

func uidPtr(p *openapi_types.UUID) *uuid.UUID {
	if p == nil {
		return nil
	}
	id := uuid.UUID(*p)
	return &id
}

// ---------------------------------------------------------------------------
// Reads that need no write path.

// ListEndpointTypes is GET /endpoint-types.
func (s *Server) ListEndpointTypes(ctx context.Context, _ gen.ListEndpointTypesRequestObject) (gen.ListEndpointTypesResponseObject, error) {
	pr, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	out := gen.ListEndpointTypes200JSONResponse{Types: []gen.EndpointType{}}
	err = s.readTenant(ctx, pr.TenantID, func(tx store.Tx) error {
		rows, err := tx.EndpointTypes()
		for _, r := range rows {
			out.Types = append(out.Types, gen.EndpointType{Key: r.Key, NameFa: r.NameFA, NameEn: r.NameEN, Position: r.Position, Icon: r.Icon})
		}
		return err
	})
	return out, err
}

// ListTimezones is GET /catalog/timezones.
func (s *Server) ListTimezones(context.Context, gen.ListTimezonesRequestObject) (gen.ListTimezonesResponseObject, error) {
	return gen.ListTimezones200JSONResponse{Zones: endpoints.Zones()}, nil
}

// listCursor is the position of an Endpoint list. The newest-first form carries the creation time; the alphabetical one the
// name, last, so that a "|" in it is no problem.
func encodeListCursor(tenant uuid.UUID, byName bool, at time.Time, name string, id uuid.UUID) string {
	if byName {
		return base64.RawURLEncoding.EncodeToString([]byte("n|" + id.String() + "|" + tenant.String() + "|" + name))
	}
	return base64.RawURLEncoding.EncodeToString([]byte("c|" + id.String() + "|" + tenant.String() + "|" + strconv.FormatInt(at.UnixMicro(), 10)))
}

func decodeListCursor(c *string, tenant uuid.UUID, byName bool) (at time.Time, name string, id uuid.UUID, has bool, err error) {
	if c == nil || *c == "" {
		return
	}
	raw, derr := base64.RawURLEncoding.DecodeString(*c)
	parts := strings.SplitN(string(raw), "|", 4)
	if derr != nil || len(parts) != 4 || (parts[0] == "n") != byName || (parts[0] != "n" && parts[0] != "c") {
		return at, name, id, false, httpx.BadRequest()
	}
	id, e1 := uuid.Parse(parts[1])
	owner, e2 := uuid.Parse(parts[2])
	if e1 != nil || e2 != nil {
		return at, name, uuid.Nil, false, httpx.BadRequest()
	}
	if owner != tenant {
		// A position made for another tenant names a row that is not this one's: the same answer as an id of theirs.
		return at, name, uuid.Nil, false, httpx.NotFound()
	}
	if byName {
		// The name goes to Postgres as text: bytes that are not UTF-8, or a NUL, are an error there (SQLSTATE 22021) and would
		// be answered 500, so a forged position is refused here. A name the panel wrote is at most NameLimit characters.
		if n := parts[3]; !utf8.ValidString(n) || strings.ContainsRune(n, 0) || utf8.RuneCountInString(n) > endpoints.NameLimit {
			return at, name, uuid.Nil, false, httpx.BadRequest()
		}
		return at, parts[3], id, true, nil
	}
	n, e3 := strconv.ParseInt(parts[3], 10, 64)
	if e3 != nil || n < cursorMinMicro || n > cursorMaxMicro {
		return at, name, uuid.Nil, false, httpx.BadRequest()
	}
	return time.UnixMicro(n).UTC(), "", id, true, nil
}

// ListEndpoints is GET /endpoints.
func (s *Server) ListEndpoints(ctx context.Context, req gen.ListEndpointsRequestObject) (gen.ListEndpointsResponseObject, error) {
	pr, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	p := req.Params
	byName := p.Sort != nil && *p.Sort == "name"
	at, name, after, has, err := decodeListCursor(p.Cursor, pr.TenantID, byName)
	if err != nil {
		return nil, err
	}
	f := store.EndpointFilter{Group: uid(uidPtrOf(p.Group)), Type: str(p.Type), Q: str(p.Q), Limit: pageLimit(p.Limit) + 1,
		ByName: byName, AfterAt: at, AfterName: name, AfterID: after, HasAfter: has}
	if p.Status != nil {
		f.Status = string(*p.Status)
	}
	out := gen.ListEndpoints200JSONResponse{Items: []gen.Endpoint{}}
	err = s.snapshotTx(ctx, pr.TenantID, func(tx store.Tx) error {
		if f.Group != uuid.Nil {
			if _, ok, err := tx.GroupGet(f.Group); err != nil {
				return err
			} else if !ok {
				return httpx.NotFound()
			}
		}
		rows, err := tx.EndpointList(f)
		if err != nil {
			return err
		}
		if len(rows) > f.Limit-1 {
			rows = rows[:f.Limit-1]
			last := rows[len(rows)-1]
			c := encodeListCursor(pr.TenantID, byName, last.CreatedAt, last.Name, last.ID)
			out.NextCursor = &c
		}
		out.Items = endpointsOut(rows)
		facets, err := tx.EndpointFacets()
		if err != nil {
			return err
		}
		out.ByType = map[string]interface{}{}
		for k, n := range facets.ByType {
			out.ByType[k] = n
		}
		out.ByStatus.Pending, out.ByStatus.Active = facets.Pending, facets.Active
		return nil
	})
	return out, err
}

func uidPtrOf(p *openapi_types.UUID) *openapi_types.UUID { return p }

// GetEndpoint is GET /endpoints/{id}.
func (s *Server) GetEndpoint(ctx context.Context, req gen.GetEndpointRequestObject) (gen.GetEndpointResponseObject, error) {
	pr, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	var out gen.Endpoint
	err = s.readTenant(ctx, pr.TenantID, func(tx store.Tx) error {
		r, ok, err := tx.EndpointGet(uuid.UUID(req.Id))
		if err != nil {
			return err
		}
		if !ok {
			return httpx.NotFound()
		}
		out = endpointOut(r)
		return nil
	})
	return gen.GetEndpoint200JSONResponse(out), err
}

// ---------------------------------------------------------------------------
// The CSV export.

// csvResponse is the body of GET /endpoints/export. The document carries no schema (a CSV holds line breaks, which the
// boundary rules refuse in a string), so the response type is ours.
type csvResponse struct{ body []byte }

func (r csvResponse) VisitExportEndpointsResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="endpoints.csv"`)
	w.WriteHeader(http.StatusOK)
	_, err := w.Write(r.body)
	return err
}

var _ gen.ExportEndpointsResponseObject = csvResponse{}

// csvCell neutralises a cell that a spreadsheet would read as a formula (T-231): a leading =, +, -, @, tab or carriage return
// gets an apostrophe in front.
func csvCell(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

// ExportEndpoints is GET /endpoints/export (T-231): UTF-8 with a byte order mark, never the DoH token.
func (s *Server) ExportEndpoints(ctx context.Context, _ gen.ExportEndpointsRequestObject) (gen.ExportEndpointsResponseObject, error) {
	pr, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	var buf strings.Builder
	buf.WriteString(string(rune(0xFEFF))) // the byte order mark of T-231, so a spreadsheet reads the Persian names as UTF-8
	err = s.snapshotTx(ctx, pr.TenantID, func(tx store.Tx) error {
		groups, err := tx.GroupList()
		if err != nil {
			return err
		}
		gname := map[uuid.UUID]string{}
		for _, g := range groups {
			gname[g.ID] = g.Name
		}
		ps, err := tx.ProfileList()
		if err != nil {
			return err
		}
		pname := map[uuid.UUID]string{}
		for _, p := range ps {
			pname[p.ID] = p.Name
		}
		zone, err := tx.DNSZone()
		if err != nil {
			return err
		}
		w := csvWriter{&buf}
		w.row([]string{"name", "type", "group", "profile", "profile 2", "status", "admin state", "analytics", "resolver id", "host", "Legacy DNS", "last query", "created"})
		f := store.EndpointFilter{ByName: true, Limit: 101}
		for {
			rows, err := tx.EndpointList(f)
			if err != nil {
				return err
			}
			page := rows
			if len(page) > 100 {
				page = page[:100]
			}
			for _, r := range page {
				status, host, last := "pending", "", ""
				if r.FirstQueryAt != nil {
					status = "active"
				}
				if zone != "" {
					host = r.ResolverID + "." + zone
				}
				if r.LastQueryAt != nil {
					last = r.LastQueryAt.UTC().Format(time.RFC3339)
				}
				w.row([]string{csvCell(r.Name), r.Type, csvCell(gname[r.GroupID]), csvCell(pname[r.ProfileID]), csvCell(pname[r.Profile2ID]),
					status, r.AdminState, r.AnalyticsLevel, r.ResolverID, host, strconv.FormatBool(r.LegacyDNS), last, r.CreatedAt.UTC().Format(time.RFC3339)})
			}
			if len(rows) <= 100 {
				break
			}
			lastRow := page[len(page)-1]
			f.HasAfter, f.AfterName, f.AfterID = true, lastRow.Name, lastRow.ID
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return csvResponse{body: []byte(buf.String())}, nil
}

// ---------------------------------------------------------------------------
// Endpoint writes.

// CreateEndpoints is POST /endpoints. The Idempotency-Key is required, because one request can create 50 Endpoints.
func (s *Server) CreateEndpoints(ctx context.Context, req gen.CreateEndpointsRequestObject) (gen.CreateEndpointsResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.BadRequest()
	}
	pr, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	b := req.Body
	in := endpoints.CreateIn{Type: b.Type, Names: b.Names, ProfileID: uuid.UUID(b.ProfileId), Profile2ID: uid(b.Profile2Id), GroupID: uid(b.GroupId),
		Comment: str(b.Comment), LegacyDNS: flag(b.LegacyDns), AuthorizeSecureDNS: flag(b.AuthorizeSecureDns), AuthorizeDDNS: flag(b.AuthorizeDdns),
		ExposeIP: flag(b.ExposeIp), PreventDeactivation: flag(b.PreventDeactivation), ConfirmDestinations: flag(b.ConfirmDestinations)}
	if b.AnalyticsLevel != nil {
		in.AnalyticsLevel = string(*b.AnalyticsLevel)
	}
	body, err := json.Marshal(b)
	if err != nil {
		return nil, httpx.Internal()
	}
	r := profiles.Request{Key: req.Params.IdempotencyKey, Method: http.MethodPost, Path: "/endpoints", Body: body}
	resp, err := s.idempotent(ctx, pr.TenantID, r, func(tx store.Tx) (int, []byte, error) {
		rows, err := s.ep.CreateTx(tx, in)
		if err != nil {
			return 0, nil, err
		}
		out, err := json.Marshal(gen.EndpointCreated{Endpoints: endpointsOut(rows)})
		return statusCreated, out, err
	})
	if err != nil {
		return nil, err
	}
	return createEndpointsResponse{resp}, nil
}

// createEndpointsResponse writes the stored or the fresh answer of POST /endpoints, with the status it first had.
type createEndpointsResponse struct{ jsonResponse }

func (r createEndpointsResponse) VisitCreateEndpointsResponse(w http.ResponseWriter) error {
	return r.write(w)
}

var _ gen.CreateEndpointsResponseObject = createEndpointsResponse{}

func flag(p *bool) bool { return p != nil && *p }

// patchOf turns the members of a request into the Patch of the write path. clear is the list of members that go back to none.
func patchOf(b *gen.EndpointPatch) endpoints.Patch {
	p := endpoints.Patch{Name: b.Name, Type: b.Type, GroupID: uidPtr(b.GroupId), ProfileID: uidPtr(b.ProfileId), Profile2ID: uidPtr(b.Profile2Id),
		Comment: b.Comment, LegacyDNS: b.LegacyDns, AuthorizeSecureDNS: b.AuthorizeSecureDns, AuthorizeDDNS: b.AuthorizeDdns, ExposeIP: b.ExposeIp,
		PreventDeactivation: b.PreventDeactivation, RequireAuthorizedIPs: b.RequireAuthorizedIps, ScheduleTimezone: b.ScheduleTimezone,
		ConfirmDestinations: flag(b.ConfirmDestinations)}
	if b.AnalyticsLevel != nil {
		v := string(*b.AnalyticsLevel)
		p.AnalyticsLevel = &v
	}
	if b.AdminState != nil {
		v := string(*b.AdminState)
		p.AdminState = &v
	}
	if b.Clear != nil {
		for _, c := range *b.Clear {
			switch c {
			case gen.EndpointPatchClearGroupId:
				p.ClearGroup = true
			case gen.EndpointPatchClearProfile2Id:
				p.ClearProfile2 = true
			case gen.EndpointPatchClearComment:
				p.ClearComment = true
			}
		}
	}
	return p
}

// PatchEndpoint is PATCH /endpoints/{id}.
func (s *Server) PatchEndpoint(ctx context.Context, req gen.PatchEndpointRequestObject) (gen.PatchEndpointResponseObject, error) {
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
	row, err := s.ep.Patch(ctx, s.d.Store, pr.TenantID, epWrite(), a, uuid.UUID(req.Id), patchOf(req.Body))
	if err != nil {
		return nil, profileError(err)
	}
	return gen.PatchEndpoint200JSONResponse(endpointOut(row)), nil
}

// BatchEndpoints is POST /endpoints:batch.
func (s *Server) BatchEndpoints(ctx context.Context, req gen.BatchEndpointsRequestObject) (gen.BatchEndpointsResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.BadRequest()
	}
	pr, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	b := req.Body
	a, err := s.endpointAuth(ctx, pr, b.LockPasswords)
	if err != nil {
		return nil, err
	}
	in := endpoints.BatchIn{IDs: make([]uuid.UUID, len(b.Ids)), Op: string(b.Op), Group: uid(b.GroupId), ConfirmDestinations: flag(b.ConfirmDestinations)}
	for i, id := range b.Ids {
		in.IDs[i] = uuid.UUID(id)
	}
	if b.Clear != nil {
		for _, c := range *b.Clear {
			switch c {
			case gen.EndpointBatchClearGroupId:
				in.ClearGroup = true
				in.Set.ClearGroup = true
			case gen.EndpointBatchClearProfile2Id:
				in.Set.ClearProfile2 = true
			}
		}
	}
	if b.Set != nil {
		in.Set.ProfileID, in.Set.Profile2ID = uidPtr(b.Set.ProfileId), uidPtr(b.Set.Profile2Id)
		if b.Set.AnalyticsLevel != nil {
			v := string(*b.Set.AnalyticsLevel)
			in.Set.AnalyticsLevel = &v
		}
		if b.Set.AdminState != nil {
			v := string(*b.Set.AdminState)
			in.Set.AdminState = &v
		}
	}
	n, err := s.ep.Batch(ctx, s.d.Store, pr.TenantID, epWrite(), a, in)
	if err != nil {
		return nil, profileError(err)
	}
	return gen.BatchEndpoints200JSONResponse{Affected: n}, nil
}

// DeleteEndpoint is POST /endpoints/{id}:delete.
func (s *Server) DeleteEndpoint(ctx context.Context, req gen.DeleteEndpointRequestObject) (gen.DeleteEndpointResponseObject, error) {
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
	if err := s.ep.Delete(ctx, s.d.Store, pr.TenantID, epWrite(), a, []uuid.UUID{uuid.UUID(req.Id)}); err != nil {
		return nil, profileError(err)
	}
	return gen.DeleteEndpoint204Response{}, nil
}

// RotateEndpointResolver is POST /endpoints/{id}:rotate-resolver.
func (s *Server) RotateEndpointResolver(ctx context.Context, req gen.RotateEndpointResolverRequestObject) (gen.RotateEndpointResolverResponseObject, error) {
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
	row, err := s.ep.Rotate(ctx, s.d.Store, pr.TenantID, epWrite(), a, uuid.UUID(req.Id))
	if err != nil {
		return nil, profileError(err)
	}
	return gen.RotateEndpointResolver200JSONResponse(endpointOut(row)), nil
}

// ---------------------------------------------------------------------------
// Schedule.

func scheduleOut(sc endpoints.Schedule) gen.Schedule {
	out := gen.Schedule{Timezone: sc.Timezone, Windows: make([]gen.ScheduleWindow, 0, len(sc.Windows))}
	for _, w := range sc.Windows {
		out.Windows = append(out.Windows, gen.ScheduleWindow{Id: openapi_types.UUID(w.ID), Start: w.Start, End: w.End,
			ProfileId: openapi_types.UUID(w.ProfileID), Profile2Id: uidp(w.Profile2ID)})
	}
	return out
}

// GetEndpointSchedule is GET /endpoints/{id}/schedule.
func (s *Server) GetEndpointSchedule(ctx context.Context, req gen.GetEndpointScheduleRequestObject) (gen.GetEndpointScheduleResponseObject, error) {
	pr, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	var out gen.Schedule
	err = s.readTenant(ctx, pr.TenantID, func(tx store.Tx) error {
		sc, ok, err := endpoints.ReadSchedule(tx, uuid.UUID(req.Id))
		if err != nil {
			return err
		}
		if !ok {
			return httpx.NotFound()
		}
		out = scheduleOut(sc)
		return nil
	})
	return gen.GetEndpointSchedule200JSONResponse(out), err
}

// PutEndpointSchedule is PUT /endpoints/{id}/schedule.
func (s *Server) PutEndpointSchedule(ctx context.Context, req gen.PutEndpointScheduleRequestObject) (gen.PutEndpointScheduleResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.BadRequest()
	}
	pr, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	b := req.Body
	a, err := s.endpointAuth(ctx, pr, b.LockPasswords)
	if err != nil {
		return nil, err
	}
	in := endpoints.ScheduleIn{Timezone: b.Timezone, ConfirmDestinations: flag(b.ConfirmDestinations)}
	for _, w := range b.Windows {
		in.Windows = append(in.Windows, endpoints.WindowIn{ID: uid(w.Id), Start: w.Start, End: w.End, ProfileID: uuid.UUID(w.ProfileId), Profile2ID: uid(w.Profile2Id)})
	}
	sc, err := s.ep.SetSchedule(ctx, s.d.Store, pr.TenantID, epWrite(), a, uuid.UUID(req.Id), in)
	if err != nil {
		return nil, profileError(err)
	}
	return gen.PutEndpointSchedule200JSONResponse(scheduleOut(sc)), nil
}

// ---------------------------------------------------------------------------
// Groups.

func groupOut(g store.GroupRow) gen.Group {
	return gen.Group{Id: openapi_types.UUID(g.ID), Name: g.Name, EndpointCount: g.EndpointCount}
}

// ListEndpointGroups is GET /endpoint-groups.
func (s *Server) ListEndpointGroups(ctx context.Context, _ gen.ListEndpointGroupsRequestObject) (gen.ListEndpointGroupsResponseObject, error) {
	pr, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	out := gen.ListEndpointGroups200JSONResponse{Groups: []gen.Group{}}
	err = s.readTenant(ctx, pr.TenantID, func(tx store.Tx) error {
		rows, err := tx.GroupList()
		for _, g := range rows {
			out.Groups = append(out.Groups, groupOut(g))
		}
		return err
	})
	return out, err
}

// CreateEndpointGroup is POST /endpoint-groups.
func (s *Server) CreateEndpointGroup(ctx context.Context, req gen.CreateEndpointGroupRequestObject) (gen.CreateEndpointGroupResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.BadRequest()
	}
	pr, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	g, err := s.ep.CreateGroup(ctx, s.d.Store, pr.TenantID, epWrite(), req.Body.Name, uuidList(req.Body.EndpointIds))
	if err != nil {
		return nil, profileError(err)
	}
	return gen.CreateEndpointGroup201JSONResponse(groupOut(g)), nil
}

// PatchEndpointGroup is PATCH /endpoint-groups/{gid}.
func (s *Server) PatchEndpointGroup(ctx context.Context, req gen.PatchEndpointGroupRequestObject) (gen.PatchEndpointGroupResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.BadRequest()
	}
	pr, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	g, err := s.ep.RenameGroup(ctx, s.d.Store, pr.TenantID, epWrite(), uuid.UUID(req.Gid), req.Body.Name)
	if err != nil {
		return nil, profileError(err)
	}
	return gen.PatchEndpointGroup200JSONResponse(groupOut(g)), nil
}

// DeleteEndpointGroup is DELETE /endpoint-groups/{gid}.
func (s *Server) DeleteEndpointGroup(ctx context.Context, req gen.DeleteEndpointGroupRequestObject) (gen.DeleteEndpointGroupResponseObject, error) {
	pr, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.ep.DeleteGroup(ctx, s.d.Store, pr.TenantID, epWrite(), uuid.UUID(req.Gid)); err != nil {
		return nil, profileError(err)
	}
	return gen.DeleteEndpointGroup204Response{}, nil
}

// ---------------------------------------------------------------------------
// Clients.

// ListClients is GET /endpoints/{id}/clients.
func (s *Server) ListClients(ctx context.Context, req gen.ListClientsRequestObject) (gen.ListClientsResponseObject, error) {
	pr, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	cur, err := decodeOwnedCursor(req.Params.Cursor, pr.TenantID)
	if err != nil {
		return nil, err
	}
	f := store.ClientFilter{Endpoint: uuid.UUID(req.Id), Q: str(req.Params.Q), Group: str(req.Params.Group), Now: s.now(), Limit: pageLimit(req.Params.Limit) + 1,
		AfterAt: cur.At, AfterID: cur.ID, HasAfter: !cur.At.IsZero()}
	if req.Params.InactiveDays != nil {
		f.InactiveDays = *req.Params.InactiveDays
	}
	out := gen.ListClients200JSONResponse{Items: []gen.Client{}}
	err = s.snapshotTx(ctx, pr.TenantID, func(tx store.Tx) error {
		if _, ok, err := tx.EndpointGet(f.Endpoint); err != nil {
			return err
		} else if !ok {
			return httpx.NotFound()
		}
		rows, pos, err := tx.ClientList(f)
		if err != nil {
			return err
		}
		if len(rows) > f.Limit-1 {
			rows, pos = rows[:f.Limit-1], pos[:f.Limit-1]
			c := encodeCursor(pr.TenantID, pos[len(pos)-1], rows[len(rows)-1].ID)
			out.NextCursor = &c
		}
		for _, c := range rows {
			out.Items = append(out.Items, clientOut(c))
		}
		out.Count, err = tx.ClientCount(f)
		return err
	})
	return out, err
}

// clientChange turns the members of a request into the change of the write path.
func clientChange(alias, group *string, p, p2 *openapi_types.UUID, analytics *string, clear []string, confirm bool) endpoints.ClientChange {
	c := endpoints.ClientChange{Alias: alias, GroupName: group, ProfileID: uidPtr(p), Profile2ID: uidPtr(p2), AnalyticsLevel: analytics, ConfirmDestinations: confirm}
	for _, x := range clear {
		switch x {
		case "alias":
			c.ClearAlias = true
		case "group_name":
			c.ClearGroupName = true
		case "profile_id":
			c.ClearProfile = true
		case "profile2_id":
			c.ClearProfile2 = true
		case "analytics_level":
			c.ClearAnalytics = true
		}
	}
	return c
}

func strPtr[T ~string](p *T) *string {
	if p == nil {
		return nil
	}
	v := string(*p)
	return &v
}

func strs[T ~string](p *[]T) []string {
	if p == nil {
		return nil
	}
	out := make([]string, len(*p))
	for i, v := range *p {
		out[i] = string(v)
	}
	return out
}

// CreateClient is POST /endpoints/{id}/clients.
func (s *Server) CreateClient(ctx context.Context, req gen.CreateClientRequestObject) (gen.CreateClientResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.BadRequest()
	}
	pr, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	b := req.Body
	a, err := s.endpointAuth(ctx, pr, b.LockPasswords)
	if err != nil {
		return nil, err
	}
	in := endpoints.ClientCreate{Label: str(b.Label), Alias: str(b.Alias), GroupName: str(b.GroupName), ProfileID: uid(b.ProfileId),
		Profile2ID: uid(b.Profile2Id), ConfirmDestinations: flag(b.ConfirmDestinations)}
	if b.AnalyticsLevel != nil {
		in.AnalyticsLevel = string(*b.AnalyticsLevel)
	}
	c, err := s.ep.CreateClient(ctx, s.d.Store, pr.TenantID, epWrite(), a, uuid.UUID(req.Id), in)
	if err != nil {
		return nil, profileError(err)
	}
	return gen.CreateClient201JSONResponse(clientOut(c)), nil
}

// PatchClient is PATCH /endpoints/{id}/clients/{cid}.
func (s *Server) PatchClient(ctx context.Context, req gen.PatchClientRequestObject) (gen.PatchClientResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.BadRequest()
	}
	pr, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	b := req.Body
	a, err := s.endpointAuth(ctx, pr, b.LockPasswords)
	if err != nil {
		return nil, err
	}
	ch := clientChange(b.Alias, b.GroupName, b.ProfileId, b.Profile2Id, strPtr(b.AnalyticsLevel), strs(b.Clear), flag(b.ConfirmDestinations))
	c, err := s.ep.PatchClient(ctx, s.d.Store, pr.TenantID, epWrite(), a, uuid.UUID(req.Id), uuid.UUID(req.Cid), ch)
	if err != nil {
		return nil, profileError(err)
	}
	return gen.PatchClient200JSONResponse(clientOut(c)), nil
}

// BatchClients is POST /endpoints/{id}/clients:batch.
func (s *Server) BatchClients(ctx context.Context, req gen.BatchClientsRequestObject) (gen.BatchClientsResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.BadRequest()
	}
	pr, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	b := req.Body
	a, err := s.endpointAuth(ctx, pr, b.LockPasswords)
	if err != nil {
		return nil, err
	}
	in := endpoints.ClientBatchIn{Op: string(b.Op), IDs: uuidList(b.Ids)}
	if b.Selector != nil {
		if b.Selector.InactiveDays != nil {
			in.InactiveDays = *b.Selector.InactiveDays
		}
		in.All = flag(b.Selector.All)
	}
	var alias, group, analytics *string
	var p, p2 *openapi_types.UUID
	if b.Set != nil {
		alias, group, p, p2, analytics = b.Set.Alias, b.Set.GroupName, b.Set.ProfileId, b.Set.Profile2Id, strPtr(b.Set.AnalyticsLevel)
	}
	in.Change = clientChange(alias, group, p, p2, analytics, strs(b.Clear), flag(b.ConfirmDestinations))
	n, more, err := s.ep.BatchClients(ctx, s.d.Store, pr.TenantID, epWrite(), a, uuid.UUID(req.Id), in)
	if err != nil {
		return nil, profileError(err)
	}
	return gen.BatchClients200JSONResponse{Affected: n, More: more}, nil
}

// decodeOwnedCursor is decodeCursor for a list whose route names the rows it lists by an id of the path: a position made for
// another tenant is not found, like the id of one of their rows, and any other bad cursor is bad_request.
func decodeOwnedCursor(c *string, tenant uuid.UUID) (store.Cursor, error) {
	cur, err := decodeCursor(c, tenant)
	if err == nil || c == nil {
		return cur, err
	}
	raw, derr := base64.RawURLEncoding.DecodeString(*c)
	parts := strings.Split(string(raw), "|")
	if derr == nil && len(parts) == 3 {
		if owner, perr := uuid.Parse(parts[2]); perr == nil && owner != tenant {
			return store.Cursor{}, httpx.NotFound()
		}
	}
	return cur, err
}

// csvWriter writes RFC 4180 rows with every cell quoted, so a comma, a quote or a line break in a name stays in its cell.
type csvWriter struct{ b *strings.Builder }

func (w csvWriter) row(cells []string) {
	for i, c := range cells {
		if i > 0 {
			w.b.WriteByte(',')
		}
		w.b.WriteByte('"')
		w.b.WriteString(strings.ReplaceAll(c, `"`, `""`))
		w.b.WriteByte('"')
	}
	w.b.WriteString("\r\n")
}
