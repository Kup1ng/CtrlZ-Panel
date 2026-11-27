package api

import (
	"context"
	"log/slog"
	"net/netip"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/api/gen"
	"github.com/Kup1ng/CtrlZ-Panel/internal/cachex"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// GET /public/free-dns (p4-nodes 9.3, Plan T-556): whether free DNS is on and the advertised addresses of the global pair.
// The browser reads it (the server of the web tier never calls the API), so its source network is the visitor's own, and
// the class public-free-dns is sized for the CGNAT /24s that many visitors share. The answer is the same for everyone, so
// the database is asked at most once in five seconds whatever the number of visitors (the 5 s cache), and the browser may
// keep it 30 seconds.

const (
	// freeDNSTTL is how long a loaded answer is current (T-556).
	freeDNSTTL = 5 * time.Second
	// freeDNSCacheControl is the header of the 200 answer (T-556).
	freeDNSCacheControl = "public, max-age=30"
)

// newFreeDNSCache caches free_dns_public(). It is the generic loader of rule cache-loader: one load at a time outside any
// lock, the last good value kept for the bound of cachex.StalenessOf(NameFreeDNS) while a refresh fails.
func newFreeDNSCache(load func(context.Context) (store.PublicFreeDNS, error), now func() time.Time, log *slog.Logger) *cachex.Loader[store.PublicFreeDNS] {
	return cachex.New(cachex.Config[store.PublicFreeDNS]{
		Load: load, TTL: freeDNSTTL, RetryAfter: configRetryAfter, LoadTimeout: configLoadTimeout, StaleWait: configStaleWait, Now: now, Name: cachex.NameFreeDNS, Log: log,
	})
}

// advertised renders an advertised address of a node of the global pair: the operator's infrastructure, never a client's.
func advertised(a *netip.Addr) *string {
	if a == nil || !a.IsValid() {
		return nil
	}
	s := a.Unmap().String()
	return &s
}

// GetPublicFreeDns is GET /public/free-dns.
func (s *Server) GetPublicFreeDns(ctx context.Context, _ gen.GetPublicFreeDnsRequestObject) (gen.GetPublicFreeDnsResponseObject, error) {
	v, err := s.freeDNS.Get(ctx)
	if err != nil {
		return nil, err
	}
	return gen.GetPublicFreeDns200JSONResponse{
		Body:    gen.PublicFreeDns{Enabled: v.Enabled, PrimaryDnsIp: advertised(v.Primary), FallbackDnsIp: advertised(v.Fallback)},
		Headers: gen.GetPublicFreeDns200ResponseHeaders{CacheControl: freeDNSCacheControl},
	}, nil
}
