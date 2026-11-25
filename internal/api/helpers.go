package api

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/login"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/otp"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/passkey"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/password"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/phonechange"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/session"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/throttle"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/totp"
	"github.com/Kup1ng/CtrlZ-Panel/internal/httpx"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// floored runs fn inside httpx.Floor and returns its result. A handler that
// returns a typed response uses it so the floor wraps the whole decision, error
// paths included: an early return would be the shortcut a timing probe looks for.
func floored[T any](ctx context.Context, d time.Duration, fn func(context.Context) (T, error)) (T, error) {
	var out T
	err := httpx.Floor(ctx, d, func(ctx context.Context) (err error) {
		out, err = fn(ctx)
		return err
	})
	return out, err
}

// The floors of spec 4.5 and 5.4.
const (
	floorLogin  = 500 * time.Millisecond // password login
	floorOTPReq = 300 * time.Millisecond // POST /auth/otp/request and the phone-change start
	floorVerify = 200 * time.Millisecond // the routes that check a code, and passkey finish
)

// Retry-After values that go with refusals that have no clock of their own.
const (
	// retryOTPLimited is the Retry-After of an otp_limited that carries no figure of its own: the default
	// cooldown (5.1). A refusal from the OTP service carries the configured one (otp.LimitedError).
	retryOTPLimited = otp.DefaultResendAfter
	retryOTPLocked  = otp.Life // a locked challenge is dead; a new code needs the cooldown
)

// apiError turns the domain errors of the auth packages into the API errors of
// spec 14.3. An error it does not know is returned unchanged for httpx.FromError,
// which maps store errors and hides everything else as a 500 with no detail.
func apiError(err error) error {
	if err == nil {
		return nil
	}
	var he *httpx.Error
	if errors.As(err, &he) {
		return err
	}
	var tm *throttle.TooManyError
	var tt *totp.TooManyError
	var ce *phonechange.CodeError
	switch {
	case errors.As(err, &tm):
		return httpx.New(http.StatusTooManyRequests, httpx.CodeTooManyAttempts).WithRetry(tm.RetryAfter)
	case errors.As(err, &tt):
		return httpx.New(http.StatusTooManyRequests, httpx.CodeTooManyAttempts).WithRetry(tt.RetryAfter)
	case errors.As(err, &ce):
		code := "invalid"
		switch {
		case errors.Is(ce.Err, otp.ErrExpired):
			code = "expired"
		case errors.Is(ce.Err, otp.ErrLocked):
			code = "locked"
		}
		return httpx.New(http.StatusUnauthorized, httpx.CodeOTPInvalid).WithFields(httpx.FieldError{Name: ce.Field, Code: code})
	case errors.Is(err, totp.ErrInvalid):
		return httpx.New(http.StatusUnauthorized, httpx.CodeTOTPInvalid)
	case errors.Is(err, totp.ErrStepReused):
		return httpx.New(http.StatusUnauthorized, httpx.CodeTOTPStepReused)
	case errors.Is(err, otp.ErrInvalid), errors.Is(err, login.ErrRefused):
		return httpx.New(http.StatusUnauthorized, httpx.CodeOTPInvalid)
	case errors.Is(err, otp.ErrExpired):
		return httpx.New(http.StatusUnauthorized, httpx.CodeOTPExpired)
	case errors.Is(err, otp.ErrLocked):
		return httpx.New(http.StatusTooManyRequests, httpx.CodeOTPLocked).WithRetry(retryOTPLocked)
	case errors.Is(err, otp.ErrLimited):
		wait := retryOTPLimited
		var le *otp.LimitedError
		if errors.As(err, &le) && le.RetryAfter > 0 {
			wait = le.RetryAfter
		}
		return httpx.New(http.StatusTooManyRequests, httpx.CodeOTPLimited).WithRetry(wait)
	case errors.Is(err, otp.ErrSMSUnavailable):
		return httpx.New(http.StatusServiceUnavailable, httpx.CodeSMSUnavailable)
	case errors.Is(err, otp.ErrRegistrationClosed):
		return httpx.New(http.StatusForbidden, httpx.CodeRegistrationClosed)
	case errors.Is(err, login.ErrInvalidCredentials):
		return httpx.New(http.StatusUnauthorized, httpx.CodeInvalidCredentials)
	case errors.Is(err, login.ErrAccountSuspended):
		return httpx.New(http.StatusForbidden, httpx.CodeAccountSuspended)
	case errors.Is(err, password.ErrBusy):
		return httpx.New(http.StatusServiceUnavailable, httpx.CodeServerBusy).WithRetry(password.RetryAfterSeconds * time.Second)
	case errors.Is(err, session.ErrGone):
		return httpx.SessionExpired()
	case errors.Is(err, passkey.ErrDisabled):
		return httpx.New(http.StatusNotFound, httpx.CodePasskeyUnavailable)
	case errors.Is(err, passkey.ErrInvalid):
		return httpx.New(http.StatusUnauthorized, httpx.CodePasskeyInvalid)
	case errors.Is(err, phonechange.ErrNotFound):
		return httpx.NotFound()
	case errors.Is(err, phonechange.ErrSamePhone):
		return httpx.New(http.StatusUnprocessableEntity, httpx.CodeValidationFailed).WithFields(httpx.FieldError{Name: "new_phone", Code: "same_phone"})
	case errors.Is(err, phonechange.ErrPhoneUnavailable):
		return httpx.New(http.StatusConflict, httpx.CodePhoneUnavailable)
	}
	return err
}

// Constructors for the errors more than one route raises.
func errTicketInvalid() *httpx.Error {
	return httpx.New(http.StatusUnauthorized, httpx.CodeTicketInvalid)
}
func errInvalidCredentials() *httpx.Error {
	return httpx.New(http.StatusUnauthorized, httpx.CodeInvalidCredentials)
}
func errInviteInvalid() *httpx.Error { return httpx.New(http.StatusNotFound, httpx.CodeInviteInvalid) }
func errInvalidPhone() *httpx.Error {
	return httpx.New(http.StatusUnprocessableEntity, httpx.CodeInvalidPhone)
}
func errValidation(field, code string) *httpx.Error {
	return httpx.New(http.StatusUnprocessableEntity, httpx.CodeValidationFailed).WithFields(httpx.FieldError{Name: field, Code: code})
}
func errReauth() *httpx.Error { return httpx.New(http.StatusForbidden, httpx.CodeReauthRequired) }
func errSuspended() *httpx.Error {
	return httpx.New(http.StatusForbidden, httpx.CodeAccountSuspended)
}

// principal is the session of the request. Routes that need one are never
// reached without it (the pipeline refuses first); a missing principal is a
// wiring bug and answers like an expired session rather than panicking.
func principal(ctx context.Context) (session.Principal, error) {
	p, ok := session.From(ctx)
	if !ok {
		return session.Principal{}, httpx.SessionExpired()
	}
	return p, nil
}

// inTenant runs fn in one tenant transaction and maps the domain errors that
// fn returned.
func (s *Server) inTenant(ctx context.Context, tenant uuid.UUID, fn func(store.Tx) error) error {
	return apiError(s.d.Store.WithTenant(ctx, tenant, store.TxOpts{}, fn))
}

// inTenantOwner is inTenant for a route the signed-in owner calls on their own account, and the
// one way such a route runs when its transaction may change the credentials. The device marker
// is bound to the credential generation (rule credential-generation), so a change of any
// credential column ends every marker of the account, the owner's own in this browser
// included, and the owner would silently lose the known-device exemption of 5.5 (the trusted
// SMS key and the soft-breaker pass) until the next login: exactly when a stranger spending
// the phone's SMS caps needs it. So the generation is read before and after fn in the same
// transaction and, when it moved, a marker for the new one comes back for this browser: the
// route does not decide, and a new route that changes a credential gets it by being run here.
// internal/api TestOwnerKeepsTheirMarker holds every operation of the isolation fixtures to it.
// The cookie is to be set after the transaction commits.
func (s *Server) inTenantOwner(ctx context.Context, p session.Principal, fn func(store.Tx) error) (*http.Cookie, error) {
	var device *http.Cookie
	err := s.inTenant(ctx, p.TenantID, func(tx store.Tx) error {
		device = nil
		before, ok, err := tx.User(p.UserID)
		if err != nil {
			return err
		}
		if err := fn(tx); err != nil {
			return err
		}
		if after, there, err := tx.User(p.UserID); err == nil && there && ok && after.Stamp().Gen != before.Stamp().Gen {
			device = s.login.DeviceCookie(tx, p.UserID)
		}
		return nil
	})
	return device, err
}

// readTenant is inTenant for a read-only transaction.
func (s *Server) readTenant(ctx context.Context, tenant uuid.UUID, fn func(store.Tx) error) error {
	return apiError(s.d.Store.WithTenant(ctx, tenant, store.TxOpts{ReadOnly: true}, fn))
}

// ---------------------------------------------------------------------------
// Pagination (spec 14.2)

const (
	defaultLimit = 50
	maxLimit     = 100
)

func pageLimit(l *int) int {
	if l == nil {
		return defaultLimit
	}
	return min(max(*l, 1), maxLimit)
}

// encodeCursor is the opaque form of a sort key: base64url of "time|id|tenant". The tenant is part of it so
// that a cursor names a position in ONE tenant's list: it names a row (id) and a request that carries the
// cursor of another tenant is refused (decodeCursor) before any code can resolve that row, whatever a later
// change does with it (round 17, tenant-r17-6 and -11: the cursor was a row reference the isolation harness
// could not see, because it is neither a uuid nor named like an id). It is a position and not a proof, so it
// carries no MAC. The longest form is 16+1+36+1+36 = 90 bytes, 120 characters, inside the 128 of the schema. The rules list has its own, longer cursor (encodeRuleCursor, parameter RuleCursor, up to 572 characters).
func encodeCursor(tenant uuid.UUID, at time.Time, id uuid.UUID) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatInt(at.UnixMicro(), 10) + "|" + id.String() + "|" + tenant.String()))
}

// A cursor time outside this range cannot have come from encodeCursor: every
// sort key is a creation time of this service. Postgres refuses a timestamptz far
// outside its own range with an error that would answer 500 instead of 400
// (review round 1, tenant-r1-5), so the decoder refuses it first.
// 946684800000000 is 2000-01-01T00:00:00Z and 7258118400000000 is 2200-01-01T00:00:00Z.
const (
	cursorMinMicro int64 = 946684800000000
	cursorMaxMicro int64 = 7258118400000000
)

// decodeCursor reads one back for the tenant that sends it. An empty cursor is the first page; a cursor that
// does not decode, or was made for another tenant, or has the two-part form of before round 17, is 400
// bad_request.
func decodeCursor(c *string, tenant uuid.UUID) (store.Cursor, error) {
	if c == nil || *c == "" {
		return store.Cursor{}, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(*c)
	if err != nil {
		return store.Cursor{}, httpx.BadRequest()
	}
	parts := strings.Split(string(raw), "|")
	if len(parts) != 3 {
		return store.Cursor{}, httpx.BadRequest()
	}
	us, id := parts[0], parts[1]
	if owner, err := uuid.Parse(parts[2]); err != nil || owner != tenant {
		return store.Cursor{}, httpx.BadRequest()
	}
	n, err := strconv.ParseInt(us, 10, 64)
	if err != nil {
		return store.Cursor{}, httpx.BadRequest()
	}
	if n < cursorMinMicro || n > cursorMaxMicro {
		return store.Cursor{}, httpx.BadRequest()
	}
	u, err := uuid.Parse(id)
	if err != nil {
		return store.Cursor{}, httpx.BadRequest()
	}
	return store.Cursor{At: time.UnixMicro(n).UTC(), ID: u}, nil
}

// isWrongProof reports a second factor or password that was simply wrong, which
// the audit log records as reauth.failed. A throttle refusal or a database fault
// is not a wrong proof.
func isWrongProof(err error) bool {
	return errors.Is(err, totp.ErrInvalid) || errors.Is(err, totp.ErrStepReused)
}
