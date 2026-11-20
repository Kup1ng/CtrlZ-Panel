package api

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/cachex"
	"github.com/Kup1ng/CtrlZ-Panel/internal/httpx"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

const (
	// configTTL is how long the public configuration is cached (spec 14.2).
	configTTL = 30 * time.Second
	// configRetryAfter is the pause after a failed refresh. Without it every
	// request after the TTL would try the database again, and while the pool is
	// full or Postgres is down each try costs the acquire timeout (review round 1,
	// tenant-r1-2 and -12).
	configRetryAfter = 5 * time.Second
	// configLoadTimeout bounds one refresh. It runs on its own context, so a
	// client that gives up does not fail the refresh the others wait for.
	configLoadTimeout = 3 * time.Second
	// configStaleWait is the longest the request that starts a refresh waits for
	// it while a stale value exists. After that it answers with the stale value
	// and the refresh carries on for the next request, so a slow database costs
	// one request one second, not every request the acquire timeout.
	configStaleWait = time.Second
	// configServeStaleFor is how long the last good configuration is served while every refresh
	// fails. The value decides whether registration is open, whether SMS and Passkey are on and
	// which host and origins are trusted, so an operator who closed registration must not find it
	// still open an hour later because a refresh has been failing with nobody told. Past this the
	// cache answers with ErrStale: the routes that read it answer a 5xx instead of acting on an old
	// decision, and the host check answers 503 too and does not fall back to the environment's panel host (round 15,
	// tenant-r15-4; round 16, tenant-r16-5). Twenty refresh intervals: a database outage of a few minutes costs nothing.
	configServeStaleFor = 10 * time.Minute
)

// newConfigCache caches auth_public_config. HostCheck and the CSRF check read it on
// every request, before any rate limit, so it must never turn a slow or missing
// database into a wait for routes that need no database. That is what the
// generic loader does (rule cache-loader): a fresh value is returned at once, one
// refresh runs at a time outside any lock, requests get the last good value while
// it runs or after it failed, and only a process that has never loaded the value
// makes its requests wait for the single load.
func newConfigCache(load func(context.Context) (store.PublicConfig, error), now func() time.Time, log *slog.Logger) *cachex.Loader[store.PublicConfig] {
	return newConfigCacheWait(load, now, configStaleWait, log)
}

// newConfigCacheWait is newConfigCache with the stale wait a test shortens.
func newConfigCacheWait(load func(context.Context) (store.PublicConfig, error), now func() time.Time, staleWait time.Duration, log *slog.Logger) *cachex.Loader[store.PublicConfig] {
	return cachex.New(cachex.Config[store.PublicConfig]{
		Load: load, TTL: configTTL, RetryAfter: configRetryAfter, LoadTimeout: configLoadTimeout, StaleWait: staleWait, MaxStale: configServeStaleFor, Now: now, Name: cachex.NameAuthConfig, Log: log,
	})
}

// panelHost is the HostSource of the tenant pipeline: the database value wins once an operator sets
// it; until then the value of the variable that Caddy also reads (fallback).
func panelHost(cfg *cachex.Loader[store.PublicConfig], fallback string) httpx.HostSource {
	return func(ctx context.Context) (string, error) {
		c, err := cfg.Get(ctx)
		switch {
		case err == nil && c.PanelHost != "":
			return c.PanelHost, nil
		case err == nil:
			return fallback, nil
		default:
			// A boundary that cannot tell never guesses (round 16, tenant-r16-5 and -18). Whatever the reason, a
			// configuration too old (cachex.ErrStale), a load that panicked, a first load that failed because the
			// database was not up yet, or a context that ended: the environment's name is not the answer. When the
			// operator has set another host in the database, a fallback would answer 400 to every browser, which looks
			// like a wrong caller and not an outage, and keep the 5xx alert quiet. Say 503, and the first successful load
			// decides. The cause stays in the error chain (errors.Is still sees ErrStale) and the answer carries none of it.
			return "", fmt.Errorf("the panel host is not known: %w: %w", err, httpx.Unavailable())
		}
	}
}
