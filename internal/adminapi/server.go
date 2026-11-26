package adminapi

import (
	"context"
	"crypto/x509"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/Kup1ng/CtrlZ-Panel/api"
	"github.com/Kup1ng/CtrlZ-Panel/internal/adminapi/gen"
	"github.com/Kup1ng/CtrlZ-Panel/internal/apispec"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/marker"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/password"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/pwstrength"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/session"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/throttle"
	"github.com/Kup1ng/CtrlZ-Panel/internal/budget"
	"github.com/Kup1ng/CtrlZ-Panel/internal/httpx"
	"github.com/Kup1ng/CtrlZ-Panel/internal/intakeseal"
	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
	"github.com/Kup1ng/CtrlZ-Panel/internal/nodeadmin"
	"github.com/Kup1ng/CtrlZ-Panel/internal/ratelimit"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// The deployment kinds Deps.Env takes. They are the values of CTRLZ_ENV; this
// package cannot import internal/app (app imports it), so it holds the three
// words it needs.
const (
	EnvProduction = "production"
	EnvDev        = "dev"
	EnvTest       = "test"
)

// Intake is the two public keys of the intake: a wildcard certificate's private key is sealed to the first and the hub
// opens it; a panel or admin certificate's to the second and domain-apply opens it. The admin holds no private half.
type Intake struct {
	Wildcard intakeseal.PublicKey
	Web      intakeseal.PublicKey
}

// Deps is what the admin API needs.
type Deps struct {
	Log      *slog.Logger
	Store    *store.Store
	Sessions *session.Manager
	Limiter  *ratelimit.Limiter
	// Keys holds the admin's key domains (admin_totp, sms_cred, admin_mac, invite_sign). New
	// refuses to build without them, so a missing key stops the start-up and not
	// the first admin login.
	Keys *keyring.Ring
	// Hasher is the process's Argon2 hasher and its concurrency gate (CTRLZ_ARGON2_*,
	// concurrency 1 on admin, 17.2).
	Hasher *password.Hasher
	// AdminHost is CTRLZ_ADMIN_HOST. Unlike the panel host there is no database
	// value for it yet (spec 7.2 names admin_host, set in P4), so the variable is
	// the whole answer.
	AdminHost string
	// PanelHost is CTRLZ_PANEL_HOST. The effective panel host is
	// domain_settings.panel_host when set, else this (7.2). The admin needs it for
	// invite links and to validate the Passkey RP ID.
	PanelHost string
	// Env is CTRLZ_ENV: production, dev or test. It gates noop SMS (15.2) and
	// enabling Passkey (7.2).
	Env    string
	Strict bool
	// PlainHTTPOrigin accepts an http Origin on the service's own host: a development run over plain http only
	// (tenant-r18-18). The zero value is the strict one.
	PlainHTTPOrigin bool
	// Install makes the install command of a node enrolment (p4-nodes 4.2 step 1). Nil when the deployment has
	// no hub host or mounts no hub volumes; POST /node-enrollments then answers service_unavailable.
	Install *nodeadmin.Installer
	// Intake holds the public intake keys an uploaded certificate's private key is sealed to (p4-nodes 3.3). Nil when the
	// deployment mounts none; POST /certificates then answers service_unavailable.
	Intake *Intake
	// TrustedProxies are the peers that may set X-Forwarded-For (CTRLZ_TRUSTED_PROXY).
	TrustedProxies []netip.Prefix
	// NewOneTime replaces password.NewOneTime; only tests set it, to plant a
	// canary and prove the generated password reaches no log (18.4).
	NewOneTime func() (secret.String, error)

	// certRoots replaces the embedded public roots the upload route verifies a chain against. Only tests set it, with a
	// private root of their own; production leaves it nil.
	certRoots *x509.CertPool

	// between is a seam for tests: it runs after a settings route has decided from a lock-free read
	// and before it takes the row lock, the one gap where another admin can commit (admin-r7-2).
	between func()

	// limitsRead is a seam for tests: it runs in PUT /sms/limits after the old limits are read and
	// before they are written, the gap in which another admin's commit made the audit row wrong
	// (admin-r11-1). With the settings row locked by the read, a second request waits outside it.
	limitsRead func()

	// rehashGap is a seam for tests: it runs after the replacement hash is made and before it is
	// written, the window of 100 to 500 ms in which a console reset or the admin's own password
	// change can commit (admin-r10-1). The tenant side has the same case through Input.Rehash.
	rehashGap func()

	// lookupSlots is a seam for tests: a pool of slots already full or of another size, for the
	// deferred admin-login class (admin-r8-1). Production leaves it nil and New makes one of
	// deferredLookupSlots.
	lookupSlots lookupSlots
}

// beforeRehashWrite runs the test seam, if any.
func (d Deps) beforeRehashWrite() {
	if d.rehashGap != nil {
		d.rehashGap()
	}
}

// afterLimitsRead runs the test seam, if any.
func (d Deps) afterLimitsRead() {
	if d.limitsRead != nil {
		d.limitsRead()
	}
}

// betweenReadAndLock runs the test seam, if any.
func (d Deps) betweenReadAndLock() {
	if d.between != nil {
		d.between()
	}
}

// Server implements the generated strict interface.
type Server struct {
	d        Deps
	slots    lookupSlots
	hasher   *password.Hasher
	strength *pwstrength.Checker
	throttle *throttle.Service
	markers  *marker.Service
}

var _ gen.StrictServerInterface = (*Server)(nil)

// New builds the admin API: the same pipeline as the tenant API (spec 2.3) on
// the admin host, with admin sessions. health serves /healthz and /readyz.
func New(d Deps, health httpx.Health) (http.Handler, error) {
	if d.Keys == nil || d.Hasher == nil {
		return nil, errors.New("adminapi: Keys and Hasher are required")
	}
	if err := d.Keys.Require(keyring.DomainAdminTOTP, keyring.DomainSMSCred, keyring.DomainAdminMAC, keyring.DomainInviteSign); err != nil {
		return nil, err
	}
	if d.NewOneTime == nil {
		d.NewOneTime = password.NewOneTime
	}
	ops, err := apispec.Parse(api.Admin(), ratelimit.Admin)
	if err != nil {
		return nil, err
	}
	// The admin service takes no API token: every operation of its document says so (P3 6.5), and one that did not would be refused
	// at start-up and not found at the first request.
	for _, op := range ops {
		if err := apispec.CheckToken(ratelimit.Admin, op); err != nil {
			return nil, err
		}
	}
	markers := marker.New(d.Keys, d.Sessions.Now)
	pl := &httpx.Pipeline{
		Log: d.Log, Strict: d.Strict, PlainHTTPOrigin: d.PlainHTTPOrigin, TrustedProxies: d.TrustedProxies, Limiter: d.Limiter, Service: ratelimit.Admin, Ops: ops,
		Doc:      api.Admin(),
		Resolver: resolver{m: d.Sessions}, BaseURL: "/api/v1",
		Proof: markers.RequestProof(marker.Admin),
		Host:  httpx.StaticHost(d.AdminHost),
	}
	built, err := pl.Build()
	if err != nil {
		return nil, err
	}
	s := &Server{
		d: d, hasher: d.Hasher, strength: pwstrength.New(),
		throttle: throttle.NewAdmin(d.Store.Admin(), d.Keys).WithCeilingHook(throttle.CeilingLog(d.Log)).WithRefusalHook(throttle.RefusalLog(d.Log, budget.NewRefusals())),
		markers:  markers, slots: d.lookupSlots,
	}
	if s.slots == nil {
		s.slots = newLookupSlots(deferredLookupSlots)
	}
	strict := gen.NewStrictHandlerWithOptions(s, nil, gen.StrictHTTPServerOptions{
		RequestErrorHandlerFunc: built.RequestError, ResponseErrorHandlerFunc: built.ResponseError,
	})
	gen.HandlerWithOptions(strict, gen.ChiServerOptions{
		BaseURL: "/v1", BaseRouter: built.Router,
		Middlewares:      []gen.MiddlewareFunc{built.PerOp},
		ErrorHandlerFunc: built.ParamError,
	})
	root := chi.NewRouter()
	root.Mount("/api", built.Router)
	root.Handle("/*", health.Handler())
	return root, nil
}

// now is the clock of the session manager, so a test that moves it moves every
// rule of this package with it.
func (s *Server) now() time.Time { return s.d.Sessions.Now() }

// resolver is the admin half of spec 2.3 step 9.
type resolver struct{ m *session.Manager }

func (resolver) CookieName() string { return session.CookieAdmin }

func (r resolver) Screen(cookie string) (string, string, bool) { return r.m.Screen(cookie) }

func (r resolver) Resolve(ctx context.Context, cookie string, op apispec.Operation) (httpx.Resolved, error) {
	info, found, err := r.m.AdminLookup(ctx, cookie)
	if err != nil {
		return httpx.Resolved{}, err
	}
	if !found {
		return httpx.Resolved{Dead: true}, httpx.SessionExpired() // gone for good (primitives-r6-5)
	}
	res := httpx.Resolved{}
	// Live: a session the admin service would still honour on a setup route. One that is not has
	// ended (revoked, disabled, past a limit) and is remembered as dead.
	setupErr := r.m.AdminCheck(info, apispec.AdminSetup)
	res.Live = setupErr == nil
	if res.Live {
		res.SessionID = info.SessionID.String() // the key that survives a rotation of the cookie (tenant-r6-5)
	}
	res.Dead = errors.Is(setupErr, session.ErrExpired)
	if err := r.m.AdminCheck(info, op.Auth); err != nil {
		return res, gateError(err)
	}
	if r.m.AdminNeedsTouch(info) {
		if err := r.m.AdminTouch(ctx, info); err != nil {
			return res, err
		}
	}
	// A session that passed its gate is a proof: its hashes (a password change, a new account's
	// one-time password, a re-issue) are served before any stranger's when the Argon2 gate is full
	// (password.Proved, round 5 admin-r5-9).
	res.Ctx = password.Proved(session.WithAdmin(ctx, session.AdminPrincipalOf(info)))
	return res, nil
}

func gateError(err error) *httpx.Error {
	switch {
	case errors.Is(err, session.ErrExpired):
		return httpx.SessionExpired()
	case errors.Is(err, session.ErrSetupRequired):
		return httpx.New(http.StatusForbidden, httpx.CodeSetupRequired)
	case errors.Is(err, session.ErrFreshRequired):
		return httpx.New(http.StatusForbidden, httpx.CodeTOTPFreshRequired)
	}
	return httpx.Internal()
}
