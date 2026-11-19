// Package httpx is the HTTP spine both services share (spec 2.3): panic
// recovery, request ids, client address, host and CSRF checks, body limits, the
// timing floor and the error body. It knows nothing about sessions or the
// database, so the order of the pipeline is the only thing that ties it to the
// auth code.
//
// Nothing here logs a request: no URL, no header, no body. A URL can carry a
// token, and a header a cookie (R21).
package httpx

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// The error codes of spec 14.3.
const (
	CodeBadRequest           = "bad_request"
	CodeSessionExpired       = "session_expired"
	CodeInvalidCredentials   = "invalid_credentials"
	CodeOTPInvalid           = "otp_invalid"
	CodeOTPExpired           = "otp_expired"
	CodeTOTPInvalid          = "totp_invalid"
	CodeTOTPStepReused       = "totp_step_reused"
	CodeTicketInvalid        = "ticket_invalid"
	CodePasskeyInvalid       = "passkey_invalid"
	CodeCSRFRejected         = "csrf_rejected"
	CodePasswordChangeNeeded = "password_change_required"
	CodeReauthRequired       = "reauth_required"
	CodeAccountSuspended     = "account_suspended"
	CodeRegistrationClosed   = "registration_closed"
	CodeSetupRequired        = "setup_required"
	CodeTOTPFreshRequired    = "totp_fresh_required"
	CodeNotFound             = "not_found"
	CodeInviteInvalid        = "invite_invalid"
	CodePasskeyUnavailable   = "passkey_unavailable"
	CodeConflict             = "conflict"
	CodePhoneUnavailable     = "phone_unavailable"
	CodeTOTPAlreadyEnabled   = "totp_already_enabled"
	CodeTOTPNotEnabled       = "totp_not_enabled"
	CodeTOTPNotPending       = "totp_not_pending"
	CodeEnforcePrecondition  = "enforce_precondition_failed"
	CodePasswordNotOneTime   = "password_not_one_time"
	CodeTooLarge             = "too_large"
	CodeValidationFailed     = "validation_failed"
	CodeInvalidPhone         = "invalid_phone"
	CodePasswordWeak         = "password_weak"
	CodeRateLimited          = "rate_limited"
	CodeTooManyAttempts      = "too_many_attempts"
	CodeOTPLimited           = "otp_limited"
	CodeOTPLocked            = "otp_locked"
	CodeInternal             = "internal"
	CodeServiceUnavailable   = "service_unavailable"
	CodeServerBusy           = "server_busy"
	CodeSMSUnavailable       = "sms_unavailable"
)

// FieldError names one invalid field. The code is a stable machine value, never
// the text the user typed.
type FieldError struct {
	Name string `json:"name"`
	Code string `json:"code"`
}

// Error is an API error: an HTTP status and a stable code. Handlers return it
// and the strict server writes it. Its text is the code, so it can be wrapped
// and logged without carrying request data.
type Error struct {
	Status     int
	Code       string
	RetryAfter time.Duration
	Fields     []FieldError
}

func (e *Error) Error() string { return e.Code }

// New makes an Error.
func New(status int, code string) *Error { return &Error{Status: status, Code: code} }

// WithRetry returns a copy that tells the client when to try again.
func (e *Error) WithRetry(d time.Duration) *Error {
	c := *e
	c.RetryAfter = d
	return &c
}

// WithFields returns a copy that names the invalid fields.
func (e *Error) WithFields(f ...FieldError) *Error {
	c := *e
	c.Fields = f
	return &c
}

// Constructors for the codes that more than one place raises.
func SessionExpired() *Error { return New(http.StatusUnauthorized, CodeSessionExpired) }
func BadRequest() *Error     { return New(http.StatusBadRequest, CodeBadRequest) }
func NotFound() *Error       { return New(http.StatusNotFound, CodeNotFound) }
func Internal() *Error       { return New(http.StatusInternalServerError, CodeInternal) }
func Unavailable() *Error    { return New(http.StatusServiceUnavailable, CodeServiceUnavailable) }
func RateLimited(d time.Duration) *Error {
	return New(http.StatusTooManyRequests, CodeRateLimited).WithRetry(d)
}

// body is the JSON of spec 14.3.
type body struct {
	Code        string       `json:"code"`
	RequestID   string       `json:"request_id,omitempty"`
	RetryAfterS int          `json:"retry_after_s,omitempty"`
	Fields      []FieldError `json:"fields,omitempty"`
}

// retrySeconds rounds up, and is never zero for a positive wait: a client told
// "0" would retry at once.
func retrySeconds(d time.Duration) int {
	if d <= 0 {
		return 0
	}
	return int((d + time.Second - 1) / time.Second)
}

// Write sends e as the response. A 429 or 503 with a wait carries Retry-After.
func Write(w http.ResponseWriter, r *http.Request, e *Error) {
	// Recover runs outside RequestID (step 1 before step 2), so a panic response
	// finds the id in the header RequestID already set on this writer.
	id := RequestIDFrom(r.Context())
	if id == "" {
		id = w.Header().Get("X-Request-Id")
	}
	b := body{Code: e.Code, RequestID: id, Fields: e.Fields}
	if s := retrySeconds(e.RetryAfter); s > 0 {
		b.RetryAfterS = s
		w.Header().Set("Retry-After", strconv.Itoa(s))
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(e.Status)
	// The encoder error is the client having gone; nothing to do about it.
	_ = json.NewEncoder(w).Encode(b)
}

// FromError maps any error a handler returns to the API error to send. It never
// echoes the error text: store errors are already stripped of driver detail, but
// an arbitrary error may not be, and the client needs only the class.
//
// The mapping of store errors is the one of PS section 10 and spec 14.3:
// conflict is 409, a lost connection 503, everything else 500.
func FromError(err error) *Error {
	var e *Error
	switch {
	case errors.As(err, &e):
		return e
	case errors.Is(err, store.ErrConflict):
		return New(http.StatusConflict, CodeConflict)
	case errors.Is(err, store.ErrConnection), errors.Is(err, store.ErrRetry),
		errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return Unavailable()
	}
	var mbe *http.MaxBytesError
	if errors.As(err, &mbe) {
		return New(http.StatusRequestEntityTooLarge, CodeTooLarge)
	}
	return Internal()
}

// failCode is the code of a server-side failure as a closed type for the log: the
// codes a 5xx answer carries. Anything else logs as failOther, so a code a handler
// made up from data cannot reach the log through the failure line.
type failCode string

const (
	failOther failCode = "other"
)

// failCodeOf maps a code to its member.
func failCodeOf(code string) failCode {
	switch code {
	case CodeInternal, CodeServiceUnavailable, CodeServerBusy, CodeSMSUnavailable:
		return failCode(code)
	}
	return failOther
}

// Valid reports membership.
func (c failCode) Valid() bool {
	switch string(c) {
	case CodeInternal, CodeServiceUnavailable, CodeServerBusy, CodeSMSUnavailable, string(failOther):
		return true
	}
	return false
}
