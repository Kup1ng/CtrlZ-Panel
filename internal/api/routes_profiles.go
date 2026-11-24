package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	openapi_types "github.com/oapi-codegen/runtime/types"

	shared "github.com/Kup1ng/CtrlZ-Shared/locations"

	"github.com/Kup1ng/CtrlZ-Panel/internal/api/gen"
	"github.com/Kup1ng/CtrlZ-Panel/internal/httpx"
	"github.com/Kup1ng/CtrlZ-Panel/internal/locations"
	"github.com/Kup1ng/CtrlZ-Panel/internal/profiles"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// The profile routes (docs/specs/p2-profiles.md 8). A handler decodes the request and calls internal/profiles, which owns
// the guard, the quotas, the D42 refusal and the outbox marks; nothing here writes a profile table.

// writeLockWait bounds every lock wait of a write-path transaction in the api (D31, spec 3.1): a request queued behind a
// job or a twin frees its pooled connection at once, and the store answers 55P03 as a 503.
const writeLockWait = 200 * time.Millisecond

// writeTx runs a write-path transaction of the tenant and maps what the write path refused.
func (s *Server) writeTx(ctx context.Context, tenant uuid.UUID, fn func(store.Tx) error) error {
	return profileError(s.d.Store.WithTenant(ctx, tenant, store.TxOpts{LockWait: writeLockWait}, fn))
}

// profileError maps a refusal of the write path to the API error of spec 8.4; anything else goes the way of apiError.
func profileError(err error) error {
	if err == nil {
		return nil
	}
	var pe *profiles.Error
	if !errors.As(err, &pe) {
		return apiError(err)
	}
	switch pe.Kind {
	case profiles.KindNotFound:
		return httpx.NotFound()
	case profiles.KindLocked:
		return httpx.New(statusLocked, httpx.CodeProfileLocked)
	case profiles.KindInUse:
		return httpx.New(http.StatusConflict, httpx.CodeProfileInUse)
	case profiles.KindConflict:
		return httpx.New(http.StatusConflict, httpx.CodeConflict)
	case profiles.KindKeyReused:
		return httpx.New(http.StatusConflict, httpx.CodeKeyReused)
	case profiles.KindJobRunning:
		return httpx.New(http.StatusConflict, httpx.CodeJobRunning)
	case profiles.KindValidation:
		e := httpx.New(http.StatusUnprocessableEntity, httpx.CodeValidationFailed)
		fs := make([]httpx.FieldError, 0, len(pe.Fields))
		for _, f := range pe.Fields {
			fs = append(fs, httpx.FieldError{Name: f.Name, Code: f.Code})
		}
		return e.WithFields(fs...)
	}
	return httpx.Internal()
}

// ---------------------------------------------------------------------------
// Conversions between the wire and the write path.

func strp(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func str(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func uid(p *openapi_types.UUID) uuid.UUID {
	if p == nil {
		return uuid.Nil
	}
	return uuid.UUID(*p)
}

func uidp(id uuid.UUID) *openapi_types.UUID {
	if id == uuid.Nil {
		return nil
	}
	x := openapi_types.UUID(id)
	return &x
}

// targetIn is the target of a request: a location by id.
func targetIn(t *gen.Target) profiles.Target {
	if t == nil {
		return profiles.Target{}
	}
	return profiles.Target{Kind: string(t.Kind), LocationID: uid(t.LocationId), IPv4: str(t.Ipv4), IPv6: str(t.Ipv6), Host: str(t.Host)}
}

// locationKeys reads the location snapshot once and answers the key of a stored location id.
type locationKeys func(uuid.UUID) (shared.Key, bool)

func (s *Server) locKeys(tx store.Tx) (locationKeys, error) {
	snap, err := s.cat.Snapshot(tx)
	if err != nil {
		return nil, err
	}
	return func(id uuid.UUID) (shared.Key, bool) {
		r, ok := snap.ByID(id)
		return r.Key, ok
	}, nil
}

// targetOut is a stored target as a response shows it: a location by id and, so that a row whose location left the set
// can still be shown, by its key too.
func targetOut(t store.Target, keys locationKeys) *gen.Target {
	if t.Kind == "" {
		return nil
	}
	out := &gen.Target{Kind: gen.TargetKind(t.Kind), Ipv4: strp(t.IPv4), Ipv6: strp(t.IPv6), Host: strp(t.Host)}
	if t.Kind == "location" {
		out.LocationId = uidp(t.LocationID)
		if k, ok := keys(t.LocationID); ok {
			out.Location = &gen.LocationKey{Country: strp(k.Country), City: strp(k.City), Label: strp(k.Label)}
		}
	}
	return out
}

func actIn(action string, t *gen.Target) profiles.Act {
	return profiles.Act{Action: action, Target: targetIn(t)}
}

// ---------------------------------------------------------------------------
// The catalog.

// ListCatalogFilters is GET /catalog/filters.
func (s *Server) ListCatalogFilters(ctx context.Context, _ gen.ListCatalogFiltersRequestObject) (gen.ListCatalogFiltersResponseObject, error) {
	p, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	var rows []store.CatalogFilterRow
	if err := s.readTenant(ctx, p.TenantID, func(tx store.Tx) (e error) { rows, e = tx.CatalogFilterList(); return }); err != nil {
		return nil, err
	}
	out := gen.ListCatalogFilters200JSONResponse{Filters: make([]gen.CatalogFilter, 0, len(rows))}
	for _, f := range rows {
		cf := gen.CatalogFilter{Id: f.ID, Kind: gen.CatalogFilterKind(f.Kind), NameFa: f.NameFA, NameEn: f.NameEN,
			State: gen.CatalogFilterState(f.State), Modes: make([]gen.ModeRef, 0, len(f.Modes))}
		for _, m := range f.Modes {
			cf.Modes = append(cf.Modes, gen.ModeRef{Mode: m.Mode, Default: m.Default})
		}
		out.Filters = append(out.Filters, cf)
	}
	return out, nil
}

// ListCatalogServices is GET /catalog/services.
func (s *Server) ListCatalogServices(ctx context.Context, _ gen.ListCatalogServicesRequestObject) (gen.ListCatalogServicesResponseObject, error) {
	p, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	var cats []store.CategoryRow
	var svcs []store.CatalogServiceRow
	if err := s.readTenant(ctx, p.TenantID, func(tx store.Tx) (e error) {
		if cats, e = tx.CatalogCategories(); e != nil {
			return e
		}
		svcs, e = tx.CatalogServiceList()
		return e
	}); err != nil {
		return nil, err
	}
	out := gen.ListCatalogServices200JSONResponse{Categories: make([]gen.Category, 0, len(cats)), Services: make([]gen.CatalogService, 0, len(svcs))}
	for _, c := range cats {
		out.Categories = append(out.Categories, gen.Category{Id: c.ID, NameFa: c.NameFA, NameEn: c.NameEN})
	}
	for _, c := range svcs {
		out.Services = append(out.Services, gen.CatalogService{Slug: c.Slug, CategoryId: c.CategoryID, NameFa: c.NameFA, NameEn: c.NameEN,
			LogoRef: strp(c.LogoRef), RiskFlag: c.RiskFlag, RedirectAllowed: c.RedirectAllowed, RegionLimited: c.RegionLimited,
			State: gen.CatalogServiceState(c.State)})
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Profiles.

// profileOut builds the profile of a response: the row, its counters, and the Default Rule flag of the list (T-127).
func (s *Server) profileOut(tx store.Tx, p store.Profile, counts store.ProfileCounts, keys locationKeys) (gen.Profile, error) {
	o, _, err := tx.Options(p.ID)
	if err != nil {
		return gen.Profile{}, err
	}
	out := gen.Profile{Id: openapi_types.UUID(p.ID), Name: p.Name, Kind: gen.ProfileKind(p.Kind), UpdatedAt: p.UpdatedAt, CreatedAt: p.CreatedAt,
		Locked: p.Locked, DisabledUntil: p.DisabledUntil, LockMessage: p.LockMessage, LockedAt: p.LockedAt,
		Counts:    gen.ProfileCounts{Endpoints: counts.Endpoints, Filters: counts.Filters, Services: counts.Services, Rules: counts.Rules, Options: counts.Options},
		Endpoints: []gen.EndpointRef{}}
	if o.DefaultAction == "redirect" {
		d := &gen.DefaultRedirect{Kind: gen.DefaultRedirectKind(o.DefaultTarget.Kind)}
		if o.DefaultTarget.Kind == "location" {
			if k, ok := keys(o.DefaultTarget.LocationID); ok {
				d.Country, d.Label = strp(k.Country), strp(k.Label)
			}
		}
		out.DefaultRedirect = d
	}
	return out, nil
}

// profileView reads one profile with its counters.
func (s *Server) profileView(tx store.Tx, id uuid.UUID) (gen.Profile, error) {
	p, ok, err := tx.ProfileGet(id)
	if err != nil {
		return gen.Profile{}, err
	}
	if !ok {
		return gen.Profile{}, httpx.NotFound()
	}
	counts, err := tx.ProfileCounts()
	if err != nil {
		return gen.Profile{}, err
	}
	keys, err := s.locKeys(tx)
	if err != nil {
		return gen.Profile{}, err
	}
	return s.profileOut(tx, p, counts[id], keys)
}

// ListProfiles is GET /profiles.
func (s *Server) ListProfiles(ctx context.Context, _ gen.ListProfilesRequestObject) (gen.ListProfilesResponseObject, error) {
	pr, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	out := gen.ListProfiles200JSONResponse{Items: []gen.Profile{}}
	err = s.snapshotTx(ctx, pr.TenantID, func(tx store.Tx) error {
		ps, err := tx.ProfileList()
		if err != nil {
			return err
		}
		counts, err := tx.ProfileCounts()
		if err != nil {
			return err
		}
		keys, err := s.locKeys(tx)
		if err != nil {
			return err
		}
		for _, p := range ps {
			v, err := s.profileOut(tx, p, counts[p.ID], keys)
			if err != nil {
				return err
			}
			out.Items = append(out.Items, v)
		}
		return nil
	})
	return out, err
}

// CreateProfile is POST /profiles: Import of the document of the type, with the user's name and kind (spec 5).
func (s *Server) CreateProfile(ctx context.Context, req gen.CreateProfileRequestObject) (gen.CreateProfileResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.BadRequest()
	}
	pr, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	var out gen.CreateProfile201JSONResponse
	err = s.writeTx(ctx, pr.TenantID, func(tx store.Tx) error {
		res, err := s.prof.CreateFromType(tx, req.Body.Name, string(req.Body.Kind))
		if err != nil {
			return err
		}
		v, err := s.profileView(tx, res.Profile.ID)
		out = gen.CreateProfile201JSONResponse{Profile: v, Flagged: res.Flagged}
		return err
	})
	return out, err
}

// GetProfile is GET /profiles/{id}.
func (s *Server) GetProfile(ctx context.Context, req gen.GetProfileRequestObject) (gen.GetProfileResponseObject, error) {
	pr, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	var out gen.Profile
	err = s.snapshotTx(ctx, pr.TenantID, func(tx store.Tx) (e error) { out, e = s.profileView(tx, uuid.UUID(req.Id)); return })
	return gen.GetProfile200JSONResponse(out), err
}

// RenameProfile is PATCH /profiles/{id}. It marks nothing: the name is not compiled.
func (s *Server) RenameProfile(ctx context.Context, req gen.RenameProfileRequestObject) (gen.RenameProfileResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.BadRequest()
	}
	pr, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	var out gen.Profile
	err = s.writeTx(ctx, pr.TenantID, func(tx store.Tx) error {
		if _, err := s.prof.RenameProfile(tx, uuid.UUID(req.Id), req.Body.Name); err != nil {
			return err
		}
		out, err = s.profileView(tx, uuid.UUID(req.Id))
		return err
	})
	return gen.RenameProfile200JSONResponse(out), err
}

// DeleteProfile is DELETE /profiles/{id}. The delete opens its own transaction, which it retries on a deadlock.
func (s *Server) DeleteProfile(ctx context.Context, req gen.DeleteProfileRequestObject) (gen.DeleteProfileResponseObject, error) {
	pr, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	if err := profileError(s.prof.Delete(ctx, s.d.Store, pr.TenantID, uuid.UUID(req.Id), store.TxOpts{LockWait: writeLockWait})); err != nil {
		return nil, err
	}
	return gen.DeleteProfile204Response{}, nil
}

// DisableProfile is PUT /profiles/{id}/disabled.
func (s *Server) DisableProfile(ctx context.Context, req gen.DisableProfileRequestObject) (gen.DisableProfileResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.BadRequest()
	}
	pr, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	// A pointer: only nil means "not sent"; a moment of year 0001 is a sent value and is in_past.
	until := req.Body.Until
	forText := ""
	if req.Body.For != nil {
		forText = string(*req.Body.For)
	}
	var out gen.Profile
	err = s.writeTx(ctx, pr.TenantID, func(tx store.Tx) error {
		if _, err := s.prof.Disable(tx, uuid.UUID(req.Id), forText, until); err != nil {
			return err
		}
		out, err = s.profileView(tx, uuid.UUID(req.Id))
		return err
	})
	return gen.DisableProfile200JSONResponse(out), err
}

// EnableProfile is DELETE /profiles/{id}/disabled.
func (s *Server) EnableProfile(ctx context.Context, req gen.EnableProfileRequestObject) (gen.EnableProfileResponseObject, error) {
	pr, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	var out gen.Profile
	err = s.writeTx(ctx, pr.TenantID, func(tx store.Tx) error {
		if _, err := s.prof.Enable(tx, uuid.UUID(req.Id)); err != nil {
			return err
		}
		out, err = s.profileView(tx, uuid.UUID(req.Id))
		return err
	})
	return gen.EnableProfile200JSONResponse(out), err
}

// GetProfileLocations is GET /profiles/{id}/locations: the set the profile may use (spec 4.2), limited to the regions
// of the services named in ?services, whose sets are intersected as a group action does.
func (s *Server) GetProfileLocations(ctx context.Context, req gen.GetProfileLocationsRequestObject) (gen.GetProfileLocationsResponseObject, error) {
	pr, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	var slugs []string
	if req.Params.Services != nil && *req.Params.Services != "" {
		slugs = strings.Split(*req.Params.Services, ",")
		if len(slugs) > 100 {
			return nil, profileError(&profiles.Error{Kind: profiles.KindValidation, Fields: []profiles.Field{{Name: "/services", Code: profiles.CodeExceeded}}})
		}
	}
	out := gen.GetProfileLocations200JSONResponse{Locations: []gen.LocationRef{}}
	err = s.readTenant(ctx, pr.TenantID, func(tx store.Tx) error {
		if _, ok, err := tx.ProfileGet(uuid.UUID(req.Id)); err != nil {
			return err
		} else if !ok {
			return httpx.NotFound()
		}
		snap, err := s.cat.Snapshot(tx)
		if err != nil {
			return err
		}
		set, err := locations.Allowed(tx, snap, uuid.UUID(req.Id))
		if err != nil {
			return err
		}
		if len(slugs) > 0 {
			cat, err := tx.CatalogServices(slugs)
			if err != nil {
				return err
			}
			known := map[string]store.CatalogService{}
			for _, c := range cat {
				known[c.Slug] = c
			}
			var sets [][]shared.Key
			for _, sl := range slugs {
				c, ok := known[sl]
				if !ok {
					return profileError(&profiles.Error{Kind: profiles.KindValidation, Fields: []profiles.Field{{Name: "/services", Code: profiles.CodeUnknown}}})
				}
				sets = append(sets, locations.ForService(set, c.AllowedRegions))
			}
			set = locations.ForSelection(sets...)
		}
		for _, k := range set {
			if r, ok := snap.Find(k); ok {
				out.Locations = append(out.Locations, gen.LocationRef{Id: openapi_types.UUID(r.ID), Country: strp(r.Key.Country), City: strp(r.Key.City), Label: strp(r.Key.Label)})
			}
		}
		out.AutoRandom = locations.AutoRandom(set)
		return nil
	})
	return out, err
}

// ---------------------------------------------------------------------------
// Filters and services.

func (s *Server) requireProfile(tx store.Tx, id uuid.UUID) error {
	_, ok, err := tx.ProfileGet(id)
	if err != nil {
		return err
	}
	if !ok {
		return httpx.NotFound()
	}
	return nil
}

// ListProfileFilters is GET /profiles/{id}/filters.
func (s *Server) ListProfileFilters(ctx context.Context, req gen.ListProfileFiltersRequestObject) (gen.ListProfileFiltersResponseObject, error) {
	pr, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	out := gen.ListProfileFilters200JSONResponse{Filters: []gen.ProfileFilter{}}
	err = s.readTenant(ctx, pr.TenantID, func(tx store.Tx) error {
		if err := s.requireProfile(tx, uuid.UUID(req.Id)); err != nil {
			return err
		}
		rows, err := tx.Filters(uuid.UUID(req.Id))
		for _, f := range rows {
			out.Filters = append(out.Filters, gen.ProfileFilter{FilterId: f.FilterID, Enabled: f.Enabled, Mode: strp(f.Mode)})
		}
		return err
	})
	return out, err
}

// SetProfileFilter is PUT /profiles/{id}/filters/{filter_id}.
func (s *Server) SetProfileFilter(ctx context.Context, req gen.SetProfileFilterRequestObject) (gen.SetProfileFilterResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.BadRequest()
	}
	pr, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	var out gen.SetProfileFilter200JSONResponse
	err = s.writeTx(ctx, pr.TenantID, func(tx store.Tx) error {
		row, err := s.prof.SetFilter(tx, uuid.UUID(req.Id), req.FilterId, req.Body.Enabled, str(req.Body.Mode))
		out = gen.SetProfileFilter200JSONResponse{FilterId: row.FilterID, Enabled: row.Enabled, Mode: strp(row.Mode)}
		return err
	})
	return out, err
}

// serviceOut builds the service rows of a response. iranian_bypass is true for a Redirect on a service whose catalog row
// says redirect_allowed is false: it acts as Bypass at the node (spec 3.6).
func (s *Server) serviceOut(tx store.Tx, rows []store.ServiceRow) ([]gen.ProfileService, error) {
	keys, err := s.locKeys(tx)
	if err != nil {
		return nil, err
	}
	slugs := make([]string, 0, len(rows))
	for _, r := range rows {
		slugs = append(slugs, r.Slug)
	}
	allowed := map[string]bool{}
	if len(slugs) > 0 {
		cat, err := tx.CatalogServices(slugs)
		if err != nil {
			return nil, err
		}
		for _, c := range cat {
			allowed[c.Slug] = c.RedirectAllowed
		}
	}
	out := make([]gen.ProfileService, 0, len(rows))
	for _, r := range rows {
		out = append(out, gen.ProfileService{Slug: r.Slug, Enabled: r.Enabled, Action: gen.ProfileServiceAction(r.Action),
			Target: targetOut(r.Target, keys), LocationUnavailable: r.LocationUnavailable,
			IranianBypass: r.Action == "redirect" && !allowed[r.Slug]})
	}
	return out, nil
}

// ListProfileServices is GET /profiles/{id}/services.
func (s *Server) ListProfileServices(ctx context.Context, req gen.ListProfileServicesRequestObject) (gen.ListProfileServicesResponseObject, error) {
	pr, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	out := gen.ListProfileServices200JSONResponse{Services: []gen.ProfileService{}}
	err = s.readTenant(ctx, pr.TenantID, func(tx store.Tx) error {
		if err := s.requireProfile(tx, uuid.UUID(req.Id)); err != nil {
			return err
		}
		rows, err := tx.Services(uuid.UUID(req.Id))
		if err != nil {
			return err
		}
		out.Services, err = s.serviceOut(tx, rows)
		return err
	})
	return out, err
}

// SetProfileService is PUT /profiles/{id}/services/{slug}.
func (s *Server) SetProfileService(ctx context.Context, req gen.SetProfileServiceRequestObject) (gen.SetProfileServiceResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.BadRequest()
	}
	pr, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	var out gen.SetProfileService200JSONResponse
	err = s.writeTx(ctx, pr.TenantID, func(tx store.Tx) error {
		_, err := s.prof.SetServices(tx, uuid.UUID(req.Id), []string{req.Slug},
			profiles.ServiceState{Enabled: req.Body.Enabled, Act: actIn(string(req.Body.Action), req.Body.Target)})
		if err != nil {
			return err
		}
		rows, err := tx.Services(uuid.UUID(req.Id))
		if err != nil {
			return err
		}
		for _, r := range rows {
			if r.Slug == req.Slug {
				v, err := s.serviceOut(tx, []store.ServiceRow{r})
				if err != nil {
					return err
				}
				out = gen.SetProfileService200JSONResponse(v[0])
			}
		}
		return nil
	})
	return out, err
}

// DeleteProfileService is DELETE /profiles/{id}/services/{slug}.
func (s *Server) DeleteProfileService(ctx context.Context, req gen.DeleteProfileServiceRequestObject) (gen.DeleteProfileServiceResponseObject, error) {
	pr, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	err = s.writeTx(ctx, pr.TenantID, func(tx store.Tx) error {
		res, err := s.prof.DeleteServices(tx, uuid.UUID(req.Id), []string{req.Slug})
		if err != nil {
			return err
		}
		if res.Updated == 0 {
			return httpx.NotFound()
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return gen.DeleteProfileService204Response{}, nil
}

// BatchProfileServices is POST /profiles/{id}/services:batch.
func (s *Server) BatchProfileServices(ctx context.Context, req gen.BatchProfileServicesRequestObject) (gen.BatchProfileServicesResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.BadRequest()
	}
	pr, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	var res profiles.BatchResult
	err = s.writeTx(ctx, pr.TenantID, func(tx store.Tx) (e error) {
		b := req.Body
		if b.Op == gen.ServicesBatchOpDelete {
			res, e = s.prof.DeleteServices(tx, uuid.UUID(req.Id), b.Slugs)
			return e
		}
		if b.Action == nil {
			return &profiles.Error{Kind: profiles.KindValidation, Fields: []profiles.Field{{Name: "/action", Code: profiles.CodeRequired}}}
		}
		enabled := b.Enabled == nil || *b.Enabled
		res, e = s.prof.SetServices(tx, uuid.UUID(req.Id), b.Slugs, profiles.ServiceState{Enabled: enabled, Act: actIn(string(*b.Action), b.Target)})
		return e
	})
	return gen.BatchProfileServices200JSONResponse(batchOut(res)), err
}

func batchOut(r profiles.BatchResult) gen.BatchResult {
	out := gen.BatchResult{Created: r.Created, Updated: r.Updated, Skipped: r.Skipped, Conflict: r.Conflict, Flagged: r.Flagged, Items: make([]gen.BatchItem, 0, len(r.Items))}
	for _, it := range r.Items {
		out.Items = append(out.Items, gen.BatchItem{Index: it.Index, Outcome: gen.BatchItemOutcome(it.Outcome), Id: uidp(it.ID)})
	}
	return out
}

// The statuses the P2 routes answer beside the ones of net/http that the capability lint lists: named here, so no other
// member of net/http is reached for a number.
const (
	statusCreated  = 201
	statusAccepted = 202
	statusLocked   = 423
)
