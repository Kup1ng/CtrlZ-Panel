package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/api/gen"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/phone"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/phonechange"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/throttle"
	"github.com/Kup1ng/CtrlZ-Panel/internal/httpx"
	"github.com/Kup1ng/CtrlZ-Panel/internal/iso3166"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// maxHomeCountries is the cap of T-311, enforced by a CHECK and here.
const maxHomeCountries = 3

// buildMe is spec 12.1. It runs in the caller's transaction and reads no
// password hash: has_password comes from auth_user_flags.
func (s *Server) buildMe(tx store.Tx, user uuid.UUID) (gen.Me, error) {
	var m gen.Me
	u, ok, err := tx.User(user)
	if err != nil {
		return m, err
	}
	if !ok {
		return m, httpx.SessionExpired()
	}
	hasPassword, _, err := tx.UserFlags(user)
	if err != nil {
		return m, err
	}
	left, err := tx.RecoveryCodesLeft(user)
	if err != nil {
		return m, err
	}
	keys, err := tx.PasskeysList(user)
	if err != nil {
		return m, err
	}
	home, err := tx.HomeCountries()
	if err != nil {
		return m, err
	}
	status, err := tx.TenantStatus()
	if err != nil {
		return m, err
	}

	m.User.Id, m.User.PhoneMasked, m.User.PhoneVerified = u.ID, phone.Mask(u.Phone), u.PhoneVerifiedAt != nil
	m.User.Locale, m.User.Theme = gen.MeUserLocale(u.Locale), gen.MeUserTheme(u.Theme)
	m.User.HasPassword, m.User.MustReset, m.User.LastLoginAt = hasPassword, u.State.OneTime(), u.LastLoginAt
	// A missing "enabled" means the hints are on: the default of 0011 is true, and
	// an older row that kept the empty object of 0003 must not hide the checklist.
	var hints struct {
		Enabled *bool `json:"enabled"`
	}
	_ = json.Unmarshal(u.OnboardingHints, &hints)
	m.User.OnboardingHints.Enabled = hints.Enabled == nil || *hints.Enabled
	m.User.OnboardingState = map[string]interface{}{}
	_ = json.Unmarshal(u.OnboardingState, &m.User.OnboardingState)
	if m.User.OnboardingState == nil {
		m.User.OnboardingState = map[string]interface{}{}
	}

	m.Security.TotpEnabled, m.Security.RecoveryCodesLeft, m.Security.Passkeys = u.TOTPEnabledAt != nil, left, len(keys)
	m.Security.EnforcePasskey, m.Security.EnforceLiftAt = u.EnforcePasskey, u.EnforceLiftAt
	m.Security.PasskeyReviewRequired = u.PasskeyReviewAt != nil

	m.Tenant.Id, m.Tenant.Status = tx.TenantID(), gen.MeTenantStatus(status)
	m.Tenant.HomeCountries = home
	if m.Tenant.HomeCountries == nil {
		m.Tenant.HomeCountries = []string{}
	}
	return m, nil
}

// GetMe is GET /me.
func (s *Server) GetMe(ctx context.Context, _ gen.GetMeRequestObject) (gen.GetMeResponseObject, error) {
	p, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	var m gen.Me
	err = s.readTenant(ctx, p.TenantID, func(tx store.Tx) (err error) {
		m, err = s.buildMe(tx, p.UserID)
		return err
	})
	if err != nil {
		return nil, err
	}
	return gen.GetMe200JSONResponse{MeJSONResponse: gen.MeJSONResponse(m)}, nil
}

// UpdatePreferences is PATCH /account/preferences. The strict server does not
// validate enums, so they are checked here.
func (s *Server) UpdatePreferences(ctx context.Context, req gen.UpdatePreferencesRequestObject) (gen.UpdatePreferencesResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.BadRequest()
	}
	b := *req.Body
	p, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	var pref store.Preferences
	if b.Locale != nil {
		if *b.Locale != gen.PreferencesRequestLocaleFa && *b.Locale != gen.PreferencesRequestLocaleEn {
			return nil, errValidation("locale", "invalid")
		}
		v := string(*b.Locale)
		pref.Locale = &v
	}
	if b.Theme != nil {
		switch *b.Theme {
		case gen.PreferencesRequestThemeSystem, gen.PreferencesRequestThemeLight, gen.PreferencesRequestThemeDark:
		default:
			return nil, errValidation("theme", "invalid")
		}
		v := string(*b.Theme)
		pref.Theme = &v
	}
	if b.OnboardingHints != nil {
		pref.OnboardingHints, _ = json.Marshal(map[string]bool{"enabled": b.OnboardingHints.Enabled})
	}
	if b.OnboardingState != nil {
		pref.OnboardingState, _ = json.Marshal(*b.OnboardingState)
	}
	var m gen.Me
	err = s.inTenant(ctx, p.TenantID, func(tx store.Tx) error {
		if ok, err := tx.UpdatePreferences(p.UserID, pref); err != nil {
			return err
		} else if !ok {
			return httpx.SessionExpired()
		}
		m, err = s.buildMe(tx, p.UserID)
		return err
	})
	if err != nil {
		return nil, err
	}
	return gen.UpdatePreferences200JSONResponse{MeJSONResponse: gen.MeJSONResponse(m)}, nil
}

// SetHomeCountries is PUT /account/home-countries (T-311).
func (s *Server) SetHomeCountries(ctx context.Context, req gen.SetHomeCountriesRequestObject) (gen.SetHomeCountriesResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.BadRequest()
	}
	p, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	if len(req.Body.Countries) > maxHomeCountries {
		return nil, errValidation("countries", "too_many")
	}
	codes := make([]string, 0, len(req.Body.Countries))
	seen := map[string]bool{}
	for _, c := range req.Body.Countries {
		c = strings.ToUpper(c)
		if !iso3166.Valid(c) {
			return nil, errValidation("countries", "invalid")
		}
		if seen[c] {
			return nil, errValidation("countries", "duplicate")
		}
		seen[c] = true
		codes = append(codes, c)
	}
	if err := s.inTenant(ctx, p.TenantID, func(tx store.Tx) error { return tx.SetHomeCountries(codes) }); err != nil {
		return nil, err
	}
	return gen.SetHomeCountries200JSONResponse{Countries: codes}, nil
}

// GetLimits is GET /account/limits (spec 12.2).
func (s *Server) GetLimits(ctx context.Context, _ gen.GetLimitsRequestObject) (gen.GetLimitsResponseObject, error) {
	p, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	var l store.Limits
	if err := s.readTenant(ctx, p.TenantID, func(tx store.Tx) (err error) { l, err = tx.Limits(); return err }); err != nil {
		return nil, err
	}
	return gen.GetLimits200JSONResponse{
		MaxProfiles: l.MaxProfiles, MaxEndpoints: l.MaxEndpoints, MaxClientsPerEndpoint: l.MaxClientsPerEndpoint,
		MaxAuthorizedIps: l.MaxAuthorizedIPs, MaxApiTokens: l.MaxAPITokens, MaxRulesPerRequest: l.MaxRulesPerRequest,
		MaxRulesPerProfile: l.MaxRulesPerProfile, MaxWildcardsPerProfile: l.MaxWildcardsPerProfile,
		MaxRealtimeSessions: l.MaxRealtimeSessions, MaxPublishesPerHour: l.MaxPublishesPerHour, MaxIpClaims: l.MaxIPClaims,
	}, nil
}

// StartPhoneChange is POST /account/phone/change (spec 5.6). The reauth gate
// has run.
func (s *Server) StartPhoneChange(ctx context.Context, req gen.StartPhoneChangeRequestObject) (gen.StartPhoneChangeResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.BadRequest()
	}
	p, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	newPhone, err := phone.Normalize(req.Body.NewPhone)
	if err != nil {
		return nil, errInvalidPhone()
	}
	f, err := s.reauthFacts(ctx, p)
	if err != nil {
		return nil, err
	}
	locale := string(deref(req.Body.Locale))
	if locale == "" {
		locale = f.user.Locale
	}
	st, err := floored(ctx, floorOTPReq, func(ctx context.Context) (phonechange.Started, error) {
		return s.phoneChange.Start(ctx, phonechange.StartInput{
			Tenant: p.TenantID, User: p.UserID, NewPhone: newPhone, Locale: locale, IP: httpx.ClientIPFrom(ctx),
		})
	})
	if err != nil {
		return nil, apiError(err)
	}
	return gen.StartPhoneChange202JSONResponse{
		RequestId: st.RequestID, OldChallengeId: st.OldChallenge, NewChallengeId: st.NewChallenge,
		ExpiresInS: int(st.ExpiresIn / time.Second), ResendAfterS: int(st.ResendAfter / time.Second),
	}, nil
}

// ConfirmPhoneChange is POST /account/phone/change/{id}/confirm (spec 5.6). The
// request is looked up under the caller's tenant and user, so another tenant's
// id is a 404.
func (s *Server) ConfirmPhoneChange(ctx context.Context, req gen.ConfirmPhoneChangeRequestObject) (gen.ConfirmPhoneChangeResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.BadRequest()
	}
	p, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	b := *req.Body
	done, err := floored(ctx, floorVerify, func(ctx context.Context) (phonechange.Confirmed, error) {
		ip := httpx.ClientIPFrom(ctx)
		// The scope is keyed on the session, not on the user: a stolen cookie that moves networks gets no
		// fresh budget, strangers on the user's network cannot spend it, and a copy of the cookie cannot
		// spend what the owner's other sessions need (budget-keying, tenant-r7-2).
		if err := s.throttle.Charge(ctx, throttle.ReauthSession, throttle.Who{Session: p.SessionID}); err != nil {
			return phonechange.Confirmed{}, err
		}
		done, err := s.phoneChange.Confirm(ctx, phonechange.ConfirmInput{
			Tenant: p.TenantID, User: p.UserID, Session: p.SessionID, RequestID: req.Id,
			OldCode: b.OldCode, NewCode: b.NewCode, IP: ip,
		})
		if err == nil {
			_ = s.throttle.Clear(ctx, throttle.ReauthSession, throttle.Who{Session: p.SessionID})
		}
		return done, err
	})
	if err != nil {
		return nil, apiError(err)
	}
	setCookies(ctx, done.Issued.Cookies()...)
	if done.Device != nil {
		setCookies(ctx, done.Device)
	}
	return gen.ConfirmPhoneChange204Response{}, nil
}

// ---------------------------------------------------------------------------
// Notifications and announcements

// ListNotifications is GET /notifications.
func (s *Server) ListNotifications(ctx context.Context, req gen.ListNotificationsRequestObject) (gen.ListNotificationsResponseObject, error) {
	p, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	cur, err := decodeCursor(req.Params.Cursor, p.TenantID)
	if err != nil {
		return nil, err
	}
	limit := pageLimit(req.Params.Limit)
	out := gen.NotificationPage{Items: []gen.Notification{}, SecurityItems: []gen.Notification{}}
	err = s.readTenant(ctx, p.TenantID, func(tx store.Tx) error {
		rows, err := tx.NotificationsPage(cur, limit+1) // one more, to know whether there is a next page
		if err != nil {
			return err
		}
		if len(rows) > limit {
			rows = rows[:limit]
			last := rows[len(rows)-1]
			c := encodeCursor(p.TenantID, last.CreatedAt, last.ID)
			out.NextCursor = &c
		}
		for _, n := range rows {
			out.Items = append(out.Items, notificationItem(n))
		}
		out.UnreadCount, err = tx.NotificationsUnread()
		if err != nil {
			return err
		}
		// The unread security notices are apart from the list and the badge (question 19, spec 12.3), the same
		// on every page, each with whether this session may mark it.
		sec, err := tx.SecurityNotices(p.SessionID)
		if err != nil {
			return err
		}
		for _, n := range sec {
			out.SecurityItems = append(out.SecurityItems, notificationItem(n))
		}
		out.SecurityUnreadCount, err = tx.SecurityNoticesUnread()
		return err
	})
	if err != nil {
		return nil, err
	}
	return gen.ListNotifications200JSONResponse(out), nil
}

// notificationItem is the wire form of one notice.
func notificationItem(n store.Notification) gen.Notification {
	item := gen.Notification{
		Id: n.ID, Kind: n.Kind, Severity: gen.NotificationSeverity(n.Severity), CreatedAt: n.CreatedAt, ReadAt: n.ReadAt,
		Params: map[string]interface{}{}, Security: n.Security, Markable: n.Markable,
	}
	_ = json.Unmarshal(n.Params, &item.Params)
	if item.Params == nil {
		item.Params = map[string]interface{}{}
	}
	if n.Link != "" {
		l := n.Link
		item.Link = &l
	}
	return item
}

// ReadNotification is POST /notifications/{id}/read.
func (s *Server) ReadNotification(ctx context.Context, req gen.ReadNotificationRequestObject) (gen.ReadNotificationResponseObject, error) {
	p, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	err = s.inTenant(ctx, p.TenantID, func(tx store.Tx) error {
		res, err := tx.NotificationRead(req.Id, p.SessionID)
		if err != nil {
			return err
		}
		switch res {
		case store.NoticeMarked:
			return nil
		case store.NoticeLocked:
			// A security notice that this session existed before: the one that caused it could hide the
			// sign the owner would see, so only a newer session may read it (question 19, spec 12.3).
			return httpx.New(http.StatusConflict, httpx.CodeConflict)
		}
		return httpx.NotFound()
	})
	if err != nil {
		return nil, err
	}
	return gen.ReadNotification204Response{}, nil
}

// afterCursor reports whether (at, id) sorts after the cursor in the order
// starts_at descending, id descending, which is the page order.
func afterCursor(at time.Time, id uuid.UUID, c store.Cursor) bool {
	if c.At.IsZero() {
		return true
	}
	if !at.Equal(c.At) {
		return at.Before(c.At)
	}
	return bytes.Compare(id[:], c.ID[:]) < 0
}

// ListAnnouncements is GET /announcements. The table is reachable only through
// announcements_for_tenant(), which returns this tenant's and the general ones.
func (s *Server) ListAnnouncements(ctx context.Context, req gen.ListAnnouncementsRequestObject) (gen.ListAnnouncementsResponseObject, error) {
	p, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	cur, err := decodeCursor(req.Params.Cursor, p.TenantID)
	if err != nil {
		return nil, err
	}
	limit := pageLimit(req.Params.Limit)
	out := gen.AnnouncementPage{Items: []gen.Announcement{}}
	err = s.readTenant(ctx, p.TenantID, func(tx store.Tx) error {
		all, err := tx.AnnouncementsFor(p.UserID)
		if err != nil {
			return err
		}
		// The unread count covers every row, not one page, so the bell's badge
		// stays right on a long list.
		for _, a := range all {
			if !a.Read {
				out.UnreadCount++
			}
		}
		var page []store.AnnouncementItem
		for _, a := range all {
			if afterCursor(a.StartsAt, a.ID, cur) {
				page = append(page, a)
			}
		}
		if len(page) > limit {
			page = page[:limit]
			last := page[len(page)-1]
			c := encodeCursor(p.TenantID, last.StartsAt, last.ID)
			out.NextCursor = &c
		}
		for _, a := range page {
			out.Items = append(out.Items, gen.Announcement{Id: a.ID, Body: a.Body, StartsAt: a.StartsAt, EndsAt: a.EndsAt, Read: a.Read})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return gen.ListAnnouncements200JSONResponse(out), nil
}

// ReadAnnouncement is POST /announcements/{id}/read.
func (s *Server) ReadAnnouncement(ctx context.Context, req gen.ReadAnnouncementRequestObject) (gen.ReadAnnouncementResponseObject, error) {
	p, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	err = s.inTenant(ctx, p.TenantID, func(tx store.Tx) error {
		if ok, err := tx.AnnouncementRead(p.UserID, req.Id); err != nil {
			return err
		} else if !ok {
			return httpx.NotFound()
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return gen.ReadAnnouncement204Response{}, nil
}
