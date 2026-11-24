package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/Kup1ng/CtrlZ-Panel/api"
	"github.com/Kup1ng/CtrlZ-Panel/internal/afterwork"
	"github.com/Kup1ng/CtrlZ-Panel/internal/api/gen"
	"github.com/Kup1ng/CtrlZ-Panel/internal/apispec"
	"github.com/Kup1ng/CtrlZ-Panel/internal/appclock"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/audit"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/bearer"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/login"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/marker"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/otp"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/passkey"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/password"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/phonechange"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/pwstrength"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/session"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/throttle"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/ticket"
	"github.com/Kup1ng/CtrlZ-Panel/internal/budget"
	"github.com/Kup1ng/CtrlZ-Panel/internal/bulkgate"
	"github.com/Kup1ng/CtrlZ-Panel/internal/cachex"
	"github.com/Kup1ng/CtrlZ-Panel/internal/endpoints"
	"github.com/Kup1ng/CtrlZ-Panel/internal/httpx"
	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
	"github.com/Kup1ng/CtrlZ-Panel/internal/locations"
	"github.com/Kup1ng/CtrlZ-Panel/internal/netpool"
	"github.com/Kup1ng/CtrlZ-Panel/internal/profiles"
	"github.com/Kup1ng/CtrlZ-Panel/internal/ratelimit"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// Deps is what the tenant API needs. The routes of later work packages take
// more fields; none of them is a database pool, which stays inside the store.
type Deps struct {
	Log      *slog.Logger
	Store    *store.Store
	Sessions *session.Manager
	Limiter  *ratelimit.Limiter
	// Keys holds the api's key domains (user_totp, otp_delivery, auth_mac). New
	// refuses to build without them: a route that needed a missing domain would
	// fail at its first request, in front of a user, instead of at start-up.
	Keys *keyring.Ring
	// Hasher is the process's Argon2 hasher and its concurrency gate.
	Hasher *password.Hasher
	// PanelHost is CTRLZ_PANEL_HOST, used until domain_settings.panel_host is set
	// (spec 7.2, finding 12).
	PanelHost string
	// Strict is true in every environment but test: a request without X-Forwarded-For is refused.
	Strict bool
	// PlainHTTPOrigin accepts an http Origin on the service's own host: a development run over plain http only
	// (tenant-r18-18). The zero value is the strict one.
	PlainHTTPOrigin bool
	// TrustedProxies are the peers that may set X-Forwarded-For (CTRLZ_TRUSTED_PROXY).
	TrustedProxies []netip.Prefix
	// Now is the clock of the public-config cache and of the OTP, login and
	// phone-change services; nil means the wall clock.
	Now func() time.Time
	// OTPOptions lets a test fix the code the OTP service makes.
	OTPOptions []otp.Option
	// StrengthUnauthenticated lets a test replace the scoring gate of the routes
	// whose caller holds a proof and no session (primitives-r3-6); nil builds the
	// production one.
	StrengthUnauthenticated *pwstrength.Checker
	// Strength lets a test replace the scoring gate of the signed-in routes; nil
	// builds the production one.
	Strength *pwstrength.Checker
	// After runs the work a handler owes once its floor has passed (afterwork). Nil builds the
	// production queue; a test passes its own to hold the work until it has looked at what the
	// request did on its own.
	After afterwork.Runner
	// Locations is where the write path learns which locations exist and which a profile may use (spec 4.1); nil builds
	// the production one, which reads the tables the tenant role may read.
	Locations locations.LocationCatalog
	// BulkGate bounds the memory of the bulk routes (spec 6.2); nil builds one of the default size.
	BulkGate *bulkgate.Gate
}

// Server implements the generated strict interface.
type Server struct {
	d Deps
	// gate is the pipeline's bulk gate: the exports hold their document in it until it is written (p2-B3-r4-4).
	gate *bulkgate.Gate
	cfg  *cachex.Loader[store.PublicConfig]
	auth store.AuthLookups
	now  func() time.Time

	keys         *keyring.Ring
	hasher       *password.Hasher
	strength     *pwstrength.Checker
	strengthAnon *pwstrength.Checker // reset/complete and register, after their proof is checked; its own gate (primitives-r3-6)
	throttle     *throttle.Service
	tickets      *ticket.Service
	otp          *otp.Service
	markers      *marker.Service
	login        *login.Service
	phoneChange  *phonechange.Service
	passkeys     *passkey.Provider
	inviteReads  *netpool.Pool    // reads of an invite for a request the otp-send bucket refused, bounded per network, per /48 and for the process (rounds 9 to 11)
	after        afterwork.Runner // what a floored handler owes after its answer: failed-login trail rows (tenant-r13-2)
	prof         *profiles.Env    // the one write path of a profile (spec 3)
	ep           *endpoints.Env   // the one write path of Endpoints, groups, schedules and clients (P3 spec 3)
	bearer       *bearer.Signer   // the share and download link values (P3 spec 6.2, 7)
	cat          locations.LocationCatalog
	docs         *httpx.Validator // the schema check of a document (spec 6.2)
}

var _ gen.StrictServerInterface = (*Server)(nil)

// New builds the tenant API: the pipeline of spec 2.3 around the generated
// router, mounted at /api. health serves /healthz and /readyz and everything
// else outside /api.
func New(d Deps, health httpx.Health) (http.Handler, error) {
	h, _, err := build(d, health)
	return h, err
}

// build is New that also hands back the Server, which a test reads the proof decisions of (tokenProof) off.
func build(d Deps, health httpx.Health) (http.Handler, *Server, error) {
	if d.Now == nil {
		d.Now = appclock.Now
	}
	if d.Keys == nil || d.Hasher == nil {
		return nil, nil, errors.New("api: Keys and Hasher are required")
	}
	if d.Log == nil {
		// The caches say their own failures to it (cachex.Config.Log is required, round 16).
		return nil, nil, errors.New("api: Log is required")
	}
	ops, err := apispec.Parse(api.Tenant(), ratelimit.Tenant)
	if err != nil {
		return nil, nil, err
	}
	auth := d.Store.Auth()
	cfg := newConfigCache(auth.PublicConfig, d.Now, d.Log)
	tickets := ticket.New(auth).WithSealing(d.Keys, d.Now)
	// The refusals of the throttle scopes and of the OTP caps are counted in one place per process, so the numbers
	// of the P4b gate come from data (tenant-r18-6 and -19; D64 net-bucket-numbers).
	refusals := budget.NewRefusals()
	capLog := throttle.CapRefusalLog(d.Log, refusals)
	otpSvc, err := otp.New(auth, d.Keys, cfg.Get, append([]otp.Option{otp.WithClock(d.Now), otp.WithCapRefusalHook(func() { capLog(budget.CapOTPIssue) })}, d.OTPOptions...)...)
	if err != nil {
		return nil, nil, err
	}
	markers := marker.New(d.Keys, d.Now)
	strength := d.Strength
	if strength == nil {
		strength = pwstrength.New()
	}
	strengthAnon := d.StrengthUnauthenticated
	if strengthAnon == nil {
		strengthAnon = pwstrength.NewUnauthenticated()
	}
	inviteRead, ok := budget.FindNetPool(budget.Tenant, "invite-read")
	if !ok {
		return nil, nil, errors.New("api: the invite-read pool is not in the budget registry")
	}
	after := d.After
	if after == nil {
		after = afterwork.New(0, 0, 0).WithLog(d.Log)
	}
	cat := d.Locations
	if cat == nil {
		cat = locations.Store{}
	}
	gate := d.BulkGate
	if gate == nil {
		gate = bulkgate.New(bulkgate.DefaultTotal, bulkgate.DefaultPerTenant)
	}
	docs, err := httpx.NewValidator(api.Tenant())
	if err != nil {
		return nil, nil, err
	}
	br, err := bearer.New(d.Keys, d.Now)
	if err != nil {
		return nil, nil, err
	}
	s := &Server{
		after: after, gate: gate,
		prof: &profiles.Env{Catalog: cat, Clock: d.Now}, ep: &endpoints.Env{Clock: d.Now, Keys: d.Keys, Catalog: cat, Bearer: br}, bearer: br, cat: cat, docs: docs,
		inviteReads: netpool.New(inviteRead, d.Now),
		d:           d, cfg: cfg, auth: auth, now: d.Now, keys: d.Keys, hasher: d.Hasher, strength: strength, strengthAnon: strengthAnon,
		throttle: throttle.NewUser(auth, d.Keys).WithCeilingHook(throttle.CeilingLog(d.Log)).WithRefusalHook(throttle.RefusalLog(d.Log, refusals)), tickets: tickets, otp: otpSvc, markers: markers,
		login: &login.Service{
			DB: d.Store, Auth: auth, OTP: otpSvc, Sessions: d.Sessions, Tickets: tickets, Markers: markers, Config: cfg.Get, Now: d.Now,
		},
		phoneChange: &phonechange.Service{DB: d.Store, OTP: otpSvc, Markers: markers, Sessions: d.Sessions, Config: cfg.Get, Now: d.Now},
		passkeys:    passkey.NewProvider(cfg.Get),
	}

	pl := &httpx.Pipeline{
		Log: d.Log, Strict: d.Strict, PlainHTTPOrigin: d.PlainHTTPOrigin, TrustedProxies: d.TrustedProxies, Limiter: d.Limiter, Service: ratelimit.Tenant, Ops: ops,
		Doc:      api.Tenant(),
		Resolver: resolver{m: d.Sessions}, BaseURL: "/api/v1",
		Proof: markers.RequestProof(marker.User), TokenProof: s.tokenProof, Bearer: s.linkKey,
		Host:     panelHost(s.cfg, d.PanelHost),
		BulkGate: gate,
	}
	built, err := pl.Build()
	if err != nil {
		return nil, nil, err
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
	return root, s, nil
}

// ---------------------------------------------------------------------------
// Routes

// GetAuthConfig is GET /auth/config.
func (s *Server) GetAuthConfig(ctx context.Context, _ gen.GetAuthConfigRequestObject) (gen.GetAuthConfigResponseObject, error) {
	c, err := s.cfg.Get(ctx)
	if err != nil {
		return nil, err
	}
	return gen.GetAuthConfig200JSONResponse{
		RegistrationMode: gen.PublicConfigRegistrationMode(c.RegistrationMode),
		SmsAvailable:     c.SMSAvailable,
		PasskeyEnabled:   c.PasskeyEnabled,
	}, nil
}

// setCookies sends cookies on the response of the request in ctx.
func setCookies(ctx context.Context, cs ...*http.Cookie) {
	for _, c := range cs {
		if c == nil { // a marker that was not due
			continue
		}
		httpx.SetCookie(ctx, c)
	}
}

// RefreshSession is POST /auth/refresh (spec 3.4).
func (s *Server) RefreshSession(ctx context.Context, _ gen.RefreshSessionRequestObject) (gen.RefreshSessionResponseObject, error) {
	// The refresh cookie is read from the request, which the strict interface does
	// not pass; the middleware stored the request's cookie header in the context.
	cookie := httpx.CookieFrom(ctx, session.CookieRefresh)
	res, err := s.d.Sessions.Refresh(ctx, cookie, httpx.ClientIPFrom(ctx))
	if err != nil {
		return nil, err
	}
	switch res.Outcome {
	case session.RefreshRotated:
		setCookies(ctx, res.Issued.Cookies()...)
		return gen.RefreshSession204Response{}, nil
	case session.RefreshGrace:
		return gen.RefreshSession204Response{}, nil
	}
	// Expired or reused: end the browser's login too, then 401.
	setCookies(ctx, session.ClearPanel()...)
	return nil, httpx.SessionExpired()
}

// Logout is POST /auth/logout.
func (s *Server) Logout(ctx context.Context, _ gen.LogoutRequestObject) (gen.LogoutResponseObject, error) {
	p, _ := session.From(ctx)
	err := s.d.Store.WithTenant(ctx, p.TenantID, store.TxOpts{}, func(tx store.Tx) error {
		out, err := s.d.Sessions.Apply(tx, session.EventLogout, session.Actor{User: p.UserID, Session: p.SessionID})
		if err != nil {
			return err
		}
		return audit.Tenant(tx, p.UserID, httpx.ClientIPFrom(tx.Context()), audit.Logout{Count: out.Ended})
	})
	if err != nil {
		return nil, err
	}
	setCookies(ctx, session.ClearPanel()...)
	return gen.Logout204Response{}, nil
}

// LogoutAll is POST /auth/logout-all.
func (s *Server) LogoutAll(ctx context.Context, _ gen.LogoutAllRequestObject) (gen.LogoutAllResponseObject, error) {
	p, _ := session.From(ctx)
	err := s.d.Store.WithTenant(ctx, p.TenantID, store.TxOpts{}, func(tx store.Tx) error {
		out, err := s.d.Sessions.Apply(tx, session.EventLogoutAll, session.Actor{User: p.UserID, Session: p.SessionID})
		if err != nil {
			return err
		}
		return audit.Tenant(tx, p.UserID, httpx.ClientIPFrom(tx.Context()), audit.LogoutAll{Count: out.Ended})
	})
	if err != nil {
		return nil, err
	}
	setCookies(ctx, session.ClearPanel()...)
	return gen.LogoutAll204Response{}, nil
}
