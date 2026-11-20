package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"

	"github.com/Kup1ng/CtrlZ-Panel/internal/adminapi"
	"github.com/Kup1ng/CtrlZ-Panel/internal/afterwork"
	"github.com/Kup1ng/CtrlZ-Panel/internal/api"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/session"
	"github.com/Kup1ng/CtrlZ-Panel/internal/httpx"
	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
	"github.com/Kup1ng/CtrlZ-Panel/internal/ratelimit"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// serviceHandler builds the API handler of the api and admin roles around the
// health mux (spec 2.3). Other roles, and a process with no database, keep the
// plain mux. The returned close function releases the rate limiter's connection.
func serviceHandler(cfg Config, rt *Runtime, st *store.Store, log *slog.Logger, health httpx.Health) (http.Handler, func(), error) {
	if !servesRoutes(cfg, st != nil) {
		// The health mux answers loopback peers only on every role (rule 28, admin-r11-4); the routers of
		// api and admin wrap it themselves where they mount it.
		return health.Handler(), func() {}, nil
	}
	svc := ratelimit.Tenant
	if cfg.Role == RoleAdmin {
		svc = ratelimit.Admin
	}
	lc := ratelimit.Config{Service: svc, Log: log}
	closeFn := func() {}
	switch {
	case cfg.ValkeyAddr != "":
		v := ratelimit.NewValkey(ratelimit.ValkeyConfig{Addr: cfg.ValkeyAddr, Username: cfg.ValkeyUsername, Password: cfg.ValkeyPassword, IndexKey: ratelimit.IndexKey(svc), Log: log})
		lc.Backend, closeFn = v, v.Close
	case cfg.Env != EnvProduction:
		// A development or test stack with no Valkey keeps its limits in process.
		// Production without Valkey treats it as down, so otp-send fails closed.
		lc.LocalOnly = true
	}
	limiter := ratelimit.New(lc)
	if cfg.Role == RoleAdmin {
		// The worker has no grant on admin_sessions, so the admin service sweeps its
		// own table (spec 10.4).
		sctx, stop := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { defer close(done); adminapi.RunSweep(sctx, st, log, adminapi.SweepEvery) }()
		prev := closeFn
		closeFn = func() { stop(); <-done; prev() }
	}
	sessions := session.NewManager(st, session.DefaultPolicy(), nil)
	// The tag in a session token is what lets a random cookie cost nothing before
	// the database (round 4, tenant-r4-4), so a service with no key for it does not
	// start: untagged, every junk cookie would get a budget of its own.
	tagDomain := keyring.DomainAuthMAC
	if cfg.Role == RoleAdmin {
		tagDomain = keyring.DomainAdminMAC
	}
	if err := sessions.WithKeys(rt.Keys, tagDomain); err != nil {
		closeFn()
		return nil, func() {}, err
	}
	// Outside the test environment a request must have come through Caddy, which
	// writes X-Forwarded-For; the test environment lets a bare client in.
	strict := cfg.Env != EnvTest
	if cfg.Env == EnvProduction && len(cfg.TrustedProxies) == 0 {
		closeFn()
		return nil, func() {}, errors.New("app: CTRLZ_TRUSTED_PROXY is required in production for api and admin")
	}

	var h http.Handler
	var err error
	if cfg.Role == RoleAPI {
		// The queue of work owed after an answer (failed-login trail rows) is built here and not
		// inside api.New so the process can wait for it: the close function runs after the server
		// has stopped taking requests and before the pool closes, and a row still queued then would
		// find a closed pool and vanish with no line (round 14, tenant-r14-3).
		after := afterwork.New(0, 0, 0).WithLog(log)
		prev := closeFn
		closeFn = func() {
			wait := cfg.ShutdownTimeout
			if wait <= 0 {
				wait = afterwork.DefaultBudget
			}
			if !after.Drain(wait) {
				log.Warn("work owed after an answer was still running at shutdown")
			}
			prev()
		}
		h, err = api.New(api.Deps{Log: log, Store: st, Sessions: sessions, Limiter: limiter, Keys: rt.Keys, Hasher: rt.Hasher, PanelHost: cfg.PanelHost, Strict: strict, TrustedProxies: cfg.TrustedProxies, After: after}, health)
	} else {
		h, err = adminapi.New(adminapi.Deps{
			Log: log, Store: st, Sessions: sessions, Limiter: limiter, Keys: rt.Keys, Hasher: rt.Hasher,
			AdminHost: cfg.AdminHost, PanelHost: cfg.PanelHost, Env: string(cfg.Env), Strict: strict, TrustedProxies: cfg.TrustedProxies,
		}, health)
	}
	if err != nil {
		closeFn()
		return nil, func() {}, err
	}
	return h, closeFn, nil
}

// servesRoutes says whether a process serves more than the health mux: the api and admin roles
// with a database. It is the one place that decides, for serviceHandler and for the listen check.
func servesRoutes(cfg Config, haveDB bool) bool {
	return haveDB && (cfg.Role == RoleAPI || cfg.Role == RoleAdmin)
}

// requireLoopbackIfHealthOnly refuses to start a process whose only handler is the health mux on an
// address other peers can reach (admin-r10-4). The mux answers /healthz with the role and the release
// and /readyz with a database ping on a pooled connection, with no authentication and no rate limit,
// so on a reachable address it fingerprints the deployment and lets any peer spend the role's pool;
// the container healthcheck runs inside the container and needs only loopback. The hub is the case
// that showed it: Compose published its port in P1, before any node listener existed. A role that
// gains real routes (the hub's node RPCs in P4) leaves this check by serving them, and keeps its
// health mux on a loopback listener of its own. Deciding here and not in Compose means a second
// health-only role, or a Compose file that forgets, cannot expose the mux by configuration.
func requireLoopbackIfHealthOnly(cfg Config, haveDB bool) error {
	if servesRoutes(cfg, haveDB) {
		return nil
	}
	host, _, err := net.SplitHostPort(cfg.Listen)
	if err != nil {
		return fmt.Errorf("app: CTRLZ_LISTEN is not a host and port")
	}
	if host == "localhost" {
		return nil
	}
	if ip, err := netip.ParseAddr(host); err == nil && ip.IsLoopback() {
		return nil
	}
	return fmt.Errorf("app: the %s role serves only the health endpoints here and must listen on a loopback address (CTRLZ_LISTEN=127.0.0.1:PORT), not on %q", cfg.Role, host)
}
