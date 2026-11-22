package adminapi

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/password"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/session"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/throttle"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/totp"
	"github.com/Kup1ng/CtrlZ-Panel/internal/httpx"
	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// floorLogin is the floor of spec 10.2.
const floorLogin = 500 * time.Millisecond

// adminError turns the domain errors of the auth packages into the API errors
// of spec 14.3. An error it does not know is returned unchanged for
// httpx.FromError, which maps store errors and hides everything else as a 500
// with no detail.
func adminError(err error) error {
	if err == nil {
		return nil
	}
	var he *httpx.Error
	if errors.As(err, &he) {
		return err
	}
	var tm *throttle.TooManyError
	var tt *totp.TooManyError
	switch {
	case errors.As(err, &tm):
		return httpx.New(http.StatusTooManyRequests, httpx.CodeTooManyAttempts).WithRetry(tm.RetryAfter)
	case errors.As(err, &tt):
		return httpx.New(http.StatusTooManyRequests, httpx.CodeTooManyAttempts).WithRetry(tt.RetryAfter)
	case errors.Is(err, totp.ErrInvalid):
		return httpx.New(http.StatusUnauthorized, httpx.CodeTOTPInvalid)
	case errors.Is(err, totp.ErrStepReused):
		return httpx.New(http.StatusUnauthorized, httpx.CodeTOTPStepReused)
	case errors.Is(err, password.ErrBusy):
		return httpx.New(http.StatusServiceUnavailable, httpx.CodeServerBusy).WithRetry(password.RetryAfterSeconds * time.Second)
	case errors.Is(err, session.ErrGone):
		return httpx.SessionExpired()
	}
	return err
}

func errInvalidCredentials() *httpx.Error {
	return httpx.New(http.StatusUnauthorized, httpx.CodeInvalidCredentials)
}
func errInvalidPhone() *httpx.Error {
	return httpx.New(http.StatusUnprocessableEntity, httpx.CodeInvalidPhone)
}
func errValidation(field, code string) *httpx.Error {
	return httpx.New(http.StatusUnprocessableEntity, httpx.CodeValidationFailed).WithFields(httpx.FieldError{Name: field, Code: code})
}

// principal is the admin session of the request. Routes that need one are never
// reached without it; a missing principal is a wiring bug and answers like an
// expired session rather than panicking.
func principal(ctx context.Context) (session.AdminPrincipal, error) {
	p, ok := session.AdminFrom(ctx)
	if !ok {
		return session.AdminPrincipal{}, httpx.SessionExpired()
	}
	return p, nil
}

// global runs fn in one global transaction and maps the domain errors fn
// returned.
func (s *Server) global(ctx context.Context, fn func(store.GlobalTx) error) error {
	return adminError(s.d.Store.WithGlobal(ctx, store.TxOpts{}, fn))
}

// readGlobal is global for a read-only transaction.
func (s *Server) readGlobal(ctx context.Context, fn func(store.GlobalTx) error) error {
	return adminError(s.d.Store.WithGlobal(ctx, store.TxOpts{ReadOnly: true}, fn))
}

// panelHost is the effective panel host of 7.2: domain_settings.panel_host when
// set, else CTRLZ_PANEL_HOST, in the spelling the Host gate compares (httpx.CanonicalHost):
// the Passkey origin and the invite link are built from it (round 13, admin-r13-1).
func (s *Server) panelHost(g store.GlobalTx) (string, error) {
	h, err := g.PanelHost()
	if err != nil {
		return "", err
	}
	if h != "" {
		return httpx.CanonicalHost(h), nil
	}
	return httpx.CanonicalHost(s.d.PanelHost), nil
}

// totpCharge is the proof that one attempt at a second factor was counted, and on which scope
// and for whom, so that the check and the reset that follow it name the same counter.
type totpCharge struct {
	proof throttle.Charged
	scope throttle.Scope
	who   throttle.Who
}

// totpHit counts one attempt on the admin_totp scope, for a request that has already proved the
// password (the login, and POST /me/password after its password check): admin_totp is what the
// login is refused by, so nothing that a bare session cookie can reach may charge it (round 6,
// admin-r6-5; use sessionTotpHit for those). It goes through the pool,
// that is a connection of its own, so it must run BEFORE the transaction that
// checks the code opens: a transaction that held one of the few admin
// connections (3 on the small profile) and then waited for a second one for the
// counter could starve the pool, and a handful of parallel requests with a
// ready cookie would then answer 503 to every admin call (review round 1).
// A refusal is a *throttle.TooManyError. The value it returns is the proof checkAdminTOTP
// demands, so a route cannot check a code it did not count (rule budget-keying, round 5).
func (s *Server) totpHit(ctx context.Context, admin uuid.UUID) (totpCharge, error) {
	return s.chargeTOTP(ctx, throttle.AdminTOTP, throttle.Who{Admin: admin})
}

// sessionTotpHit is totpHit for a route that asks for a code with nothing but a session cookie
// behind it (POST /auth/totp/fresh, POST /me/totp/confirm). It counts on admin_totp_session, keyed
// on the session, so a copy of the cookie spends only its own session's five tries and never the
// scope the owner's login is refused by (round 6, admin-r6-5).
func (s *Server) sessionTotpHit(ctx context.Context, p session.AdminPrincipal) (totpCharge, error) {
	return s.chargeTOTP(ctx, throttle.AdminTOTPSession, throttle.Who{Session: p.SessionID})
}

func (s *Server) chargeTOTP(ctx context.Context, sc throttle.Scope, w throttle.Who) (totpCharge, error) {
	c, err := s.throttle.ChargeProof(ctx, sc, w)
	return totpCharge{proof: c, scope: sc, who: w}, err
}

// totpReset clears the scope the charge was made on, after a code was accepted and the work
// committed. A failure to clear is not a failure of the request.
func (s *Server) totpReset(ctx context.Context, c totpCharge) {
	_ = s.throttle.Clear(ctx, c.scope, c.who)
}

// checkAdminTOTP verifies a code against an admin's sealed seed (spec 6.3) in
// the caller's transaction: the step is spent by the same transaction that acts
// on the result. c is the proof totpHit returned: without it, or with one made for
// another admin, the check refuses (throttle.ErrNotCharged) before it looks at the code.
// The caller calls totpReset after the commit. onStep, when set, receives the step
// that matched.
//
// The counter the charge must have been made on is decided from this call's own arguments and
// never read back from the charge: the code is checked against the seed of `admin`, so the proof
// must be for admin_totp keyed on that admin (round 7, primitives-r7-8: the expectation used to be
// built from the charge's own fields, so it always held and a route that charged one admin and
// checked another passed every test).
func (s *Server) checkAdminTOTP(g store.GlobalTx, c totpCharge, admin uuid.UUID, sealed []byte, code string, onStep func(int64)) error {
	return s.checkTOTPUnder(g, c, throttle.AdminTOTP, throttle.Who{Admin: admin}, admin, sealed, code, onStep)
}

// checkSessionTOTP is checkAdminTOTP for the two routes a bare session cookie reaches
// (POST /auth/totp/fresh, POST /me/totp/confirm): the proof is sessionTotpHit's, on
// admin_totp_session keyed on `session`, which the route takes from the principal. They are two
// functions, each naming one scope, so that the registry's walk of what a route spends (internal/budget
// TestWhatARouteSpendsFollowsTheRegistry) sees the one scope a route really spends.
func (s *Server) checkSessionTOTP(g store.GlobalTx, c totpCharge, admin, session uuid.UUID, sealed []byte, code string, onStep func(int64)) error {
	return s.checkTOTPUnder(g, c, throttle.AdminTOTPSession, throttle.Who{Session: session}, admin, sealed, code, onStep)
}

func (s *Server) checkTOTPUnder(g store.GlobalTx, c totpCharge, scope throttle.Scope, who throttle.Who, admin uuid.UUID, sealed []byte, code string, onStep func(int64)) error {
	if len(sealed) == 0 {
		return totp.ErrInvalid
	}
	seed, err := s.d.Keys.Open(keyring.DomainAdminTOTP, totp.AdminAAD(admin), sealed)
	if err != nil {
		return err
	}
	defer seed.Wipe()
	return totp.Check(g.Context(), throttle.Counted(c.proof, scope, who, func(_ context.Context, step int64) (bool, error) {
		if onStep != nil {
			onStep(step)
		}
		fresh, err := g.AdminTOTPStepAccept(admin, step)
		return fresh.Yes(), err
	}), seed, secret.New(code))
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

// A cursor is the opaque base64url of the last row's sort key, which no client
// parses. A cursor that does not decode is 400 bad_request.

func encodeKey(parts ...string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strings.Join(parts, "|")))
}

func decodeKey(c *string, n int) ([]string, error) {
	if c == nil || *c == "" {
		return nil, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(*c)
	if err != nil {
		return nil, httpx.BadRequest()
	}
	parts := strings.Split(string(raw), "|")
	if len(parts) != n {
		return nil, httpx.BadRequest()
	}
	return parts, nil
}

// uuidCursor is the cursor of lists sorted by id, newest first.
func uuidCursor(c *string) (uuid.UUID, error) {
	p, err := decodeKey(c, 1)
	if err != nil || p == nil {
		return uuid.Nil, err
	}
	id, err := uuid.Parse(p[0])
	if err != nil {
		return uuid.Nil, httpx.BadRequest()
	}
	return id, nil
}

// intCursor is the cursor of the audit log, whose id is a bigserial.
func intCursor(c *string) (int64, error) {
	p, err := decodeKey(c, 1)
	if err != nil || p == nil {
		return 0, err
	}
	n, err := strconv.ParseInt(p[0], 10, 64)
	if err != nil || n < 1 {
		return 0, httpx.BadRequest()
	}
	return n, nil
}

func deref[T any](p *T) T {
	var zero T
	if p == nil {
		return zero
	}
	return *p
}

func ptr[T any](v T) *T { return &v }

func timePtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}
