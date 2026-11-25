package httpx

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"

	"github.com/Kup1ng/CtrlZ-Panel/internal/logattr"
	"github.com/Kup1ng/CtrlZ-Panel/internal/netkey"
	"github.com/Kup1ng/CtrlZ-Panel/internal/reqledger"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

type ctxKey int

const (
	keyRequestID ctxKey = iota
	keyClientIP
	keyHeader
	keyReqHeader
	keyDeferred
	keyHeld
	keyLinkDead
	keyAnswer
)

// DefaultBodyLimit is the request body limit of spec 2.3 step 4. Only the
// passkey finish routes raise it, to 64 KiB, through SetBodyLimit.
const DefaultBodyLimit = 16 << 10

// RequestIDFrom returns the id RequestID made, or "".
func RequestIDFrom(ctx context.Context) string {
	s, _ := ctx.Value(keyRequestID).(string)
	return s
}

// ClientIPFrom returns the address ClientIP found. The zero Addr means the
// middleware did not run, which only a test should see.
func ClientIPFrom(ctx context.Context) netip.Addr {
	a, _ := ctx.Value(keyClientIP).(netip.Addr)
	return a
}

// Subject is the client's network keys for the rate limiter and the throttles.
func Subject(ctx context.Context) (network, wide string) {
	a := ClientIPFrom(ctx)
	network = netkey.Net(a)
	wide, _ = netkey.Wide(a)
	return network, wide
}

// ---------------------------------------------------------------------------
// Step 1: Recover

// Recover turns a panic into a 500. It logs the type of the panic value and a
// stack, and nothing of the request: the value can embed what the handler was
// reading (a token in a URL, a phone number in a body), and R21 forbids logging
// either. http.ErrAbortHandler is the one panic the server itself uses to cut a
// response, and it passes through.
func Recover(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				rec := recover()
				if rec == nil {
					return
				}
				if rec == http.ErrAbortHandler {
					panic(rec)
				}
				log.Error("handler panicked", logattr.TypeName("panic_type", rec), logattr.RequestID(w.Header().Get("X-Request-Id")), logattr.Stack())
				Write(w, r, Internal())
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// ---------------------------------------------------------------------------
// Step 2: RequestID

// RequestID gives the request a random id, returns it in X-Request-Id and puts
// it in the Error body, so a user can quote it and an operator can find the
// matching log line. It is random, not derived from the request, and a value the
// client sends is ignored.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b [8]byte
		_, _ = rand.Read(b[:])
		id := hex.EncodeToString(b[:])
		w.Header().Set("X-Request-Id", id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), keyRequestID, id)))
	})
}

// ---------------------------------------------------------------------------
// Step 3: no-store

// NoStore marks every response uncacheable: they carry session state and
// per-user data.
func NoStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// ---------------------------------------------------------------------------
// Step 4: body limit

// limitedBody is http.MaxBytesReader with a limit that can be raised before the
// body is read. The limit is applied before the route is known (step 4), and a
// route that needs more (a passkey finish) raises it after routing, in the
// per-operation chain. Nothing reads the body in between.
type limitedBody struct {
	rc    io.ReadCloser
	limit int64
	left  int64
	err   error
}

func (l *limitedBody) Read(p []byte) (int, error) {
	if l.err != nil {
		return 0, l.err
	}
	if len(p) == 0 {
		return 0, nil
	}
	// Read one byte more than allowed, so that exactly the limit is accepted
	// and one byte over is noticed.
	if int64(len(p))-1 > l.left {
		p = p[:l.left+1]
	}
	n, err := l.rc.Read(p)
	if int64(n) <= l.left {
		l.left -= int64(n)
		l.err = err
		return n, err
	}
	n = int(l.left)
	l.left = 0
	l.err = &http.MaxBytesError{Limit: l.limit}
	return n, l.err
}

func (l *limitedBody) Close() error { return l.rc.Close() }

// BodyLimit caps the request body at DefaultBodyLimit.
func BodyLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil && r.Body != http.NoBody {
			r.Body = &limitedBody{rc: r.Body, limit: DefaultBodyLimit, left: DefaultBodyLimit}
		}
		next.ServeHTTP(w, r)
	})
}

// bodyLimitOf is the limit BodyLimit (or SetBodyLimit) put on a body. A body
// that has none (a test's) reports false.
func bodyLimitOf(rc io.ReadCloser) (int64, bool) {
	switch b := rc.(type) {
	case *limitedBody:
		return b.limit, true
	}
	return 0, false
}

// declaredTooLarge says whether the client declared a body above the limit. Such a request is refused at once with 413:
// the limit only cuts the bytes as they are read, and a buffer sized from a declared length that nobody checked is a
// memory the client chooses, before it has sent a byte (p2-B3-r6-1, r6-3).
func declaredTooLarge(r *http.Request) bool {
	lim, ok := bodyLimitOf(r.Body)
	return ok && r.ContentLength > lim
}

// SetBodyLimit changes the limit BodyLimit set. Call it before the body is read.
func SetBodyLimit(r *http.Request, n int64) {
	if lb, ok := r.Body.(*limitedBody); ok {
		lb.left += n - lb.limit
		lb.limit = n
	}
}

// ---------------------------------------------------------------------------
// Step 5: client address

// ClientIP records the client's address (spec 2.3 step 5). Caddy is the only
// thing that can reach the port, and it appends the peer address to
// X-Forwarded-For, so the rightmost value is the one it wrote. Anything to its
// left is client-supplied and is ignored.
//
// With strict set (production) a request without the header is refused with 400:
// it did not come through Caddy, and the OTP function refuses a NULL address
// anyway. Without strict (development, tests) the connection's peer is used.
func ClientIP(strict bool, trusted []netip.Prefix) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// In production only Caddy may speak for a client. X-Forwarded-For is a
			// header any container on the same network can write, and the rightmost
			// value would then be whatever it chose: a fresh address per request
			// skips every per-network limit. So the peer is checked before the header
			// is read (review round 3, admin-r3-13). The answer is the one a missing
			// header gets.
			if strict && len(trusted) > 0 && !peerTrusted(r.RemoteAddr, trusted) {
				Write(w, r, BadRequest())
				return
			}
			addr, ok := forwardedClient(r.Header.Values("X-Forwarded-For"))
			if !ok && !strict && r.Header.Get("X-Forwarded-For") == "" {
				if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
					addr, ok = parseAddr(host)
				}
			}
			if !ok {
				Write(w, r, BadRequest())
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), keyClientIP, addr)))
		})
	}
}

// peerTrusted says whether the connection's peer is one of the trusted proxies.
func peerTrusted(remote string, trusted []netip.Prefix) bool {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return false
	}
	a, ok := parseAddr(host)
	if !ok {
		return false
	}
	for _, p := range trusted {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// ParseTrustedProxies reads a comma-separated list of addresses and prefixes
// (CTRLZ_TRUSTED_PROXY). A bare address is a single-host prefix.
func ParseTrustedProxies(list string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, f := range strings.Split(list, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if p, err := netip.ParsePrefix(f); err == nil {
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(f)
		if err != nil {
			return nil, errors.New("httpx: not an address or prefix in the trusted proxy list")
		}
		a = a.Unmap()
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}

// forwardedClient takes the last value of the last X-Forwarded-For line.
func forwardedClient(lines []string) (netip.Addr, bool) {
	if len(lines) == 0 {
		return netip.Addr{}, false
	}
	last := lines[len(lines)-1]
	if i := strings.LastIndexByte(last, ','); i >= 0 {
		last = last[i+1:]
	}
	return parseAddr(strings.TrimSpace(last))
}

func parseAddr(s string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, false
	}
	return a.WithZone("").Unmap(), true
}

// ---------------------------------------------------------------------------
// Step 6: host

// CanonicalHost is the one spelling of a configured or received host that the Host gate
// compares and that every other use of the panel host must use too: lower case, no
// surrounding space, no trailing dot on the name, the port kept. The Host gate served
// `Panel.Example.IR.` while the Passkey origin and the invite link took the configured string
// verbatim, so a host the gate served produced an origin no browser would send (round 13,
// admin-r13-1). A spelling normalised in one place only is a second source of truth.
func CanonicalHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	if name, port, err := net.SplitHostPort(h); err == nil {
		return net.JoinHostPort(strings.TrimSuffix(name, "."), port)
	}
	return strings.TrimSuffix(h, ".")
}

// HostName is CanonicalHost without its port: what a Passkey RP ID is compared with, since an
// RP ID is a domain and never carries a port.
func HostName(h string) string {
	h = CanonicalHost(h)
	if name, _, err := net.SplitHostPort(h); err == nil {
		return name
	}
	return h
}

// sameHost compares a request's Host (or an Origin's host) with the configured
// one. A configured host without a port matches any port, since a development
// stack listens on one; a configured host with a port must match it.
func sameHost(got, want string) bool {
	got, want = CanonicalHost(got), CanonicalHost(want)
	if want == "" || got == "" {
		return false
	}
	if _, _, err := net.SplitHostPort(want); err == nil {
		return got == want
	}
	if h, _, err := net.SplitHostPort(got); err == nil {
		got = h
	}
	return got == strings.Trim(want, "[]") || got == "["+strings.Trim(want, "[]")+"]"
}

// HostSource says which Host the service answers to. It is called per request, because the panel
// host can be set in the database after start (domain_settings.panel_host). An error means the
// service cannot tell right now (its configuration is too old to vouch for, round 16, tenant-r16-5):
// the request is answered 503 like any other dependency fault, and never 400, which says the CALLER is
// wrong and would hide an outage from every 5xx alert. A caller that went away while the source was
// being asked gets the bare 499 and not a 503 (writeFault): that is the caller's doing, and a crowd of
// clients that give up during a slow start must not read as server faults (round 17, tenant-r17-8).
type HostSource func(context.Context) (string, error)

// StaticHost is a HostSource for a host that never changes.
func StaticHost(host string) HostSource {
	return func(context.Context) (string, error) { return host, nil }
}

// HostCheck refuses a request whose Host is not the service's own. An empty answer refuses
// everything: a service that does not know its own host must not guess.
func HostCheck(want HostSource) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h, err := want(r.Context())
			if err != nil {
				writeFault(w, r, err)
				return
			}
			if !sameHost(r.Host, h) {
				Write(w, r, BadRequest())
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ---------------------------------------------------------------------------
// Step 7: CSRF

func safeMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions
}

// CSRF is layers 2 and 3 of spec 3.6. net/http's CrossOriginProtection refuses a
// non-safe request that a browser marks cross-origin or same-site (Sec-Fetch-Site),
// or, when the browser sends no such header, whose Origin differs from Host. No
// trusted origin is added. The second layer is the allow-list of R43: when an
// Origin is present on a non-safe request its host must be the service's own.
// A request with neither header (curl, a server) passes both, which is right:
// it carries no ambient credentials a third-party page could have attached.
//
// httpsOnly is the negation of Pipeline.PlainHTTPOrigin (true everywhere but a development run): the Origin must
// then be an https origin too, not only carry the service's host (tenant-r18-13). Both layers above compare the host
// and nothing else, so a browser that sends no Sec-Fetch-Site and has no HSTS entry yet could be
// shown a plain http page of the panel's own host by an on-path attacker, and that page's Origin
// (http://<host>) is "the service's own" by the host alone, while the session cookie is attached by
// SameSite=Lax without schemes. The service is only ever served over https behind the gateway, so
// an http Origin on a non-safe request is never an honest one. With httpsOnly false (a development
// run over plain http, which the zero value of the pipeline never is) the scheme is not judged.
func CSRF(want HostSource, httpsOnly bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		cop := http.NewCrossOriginProtection()
		cop.SetDenyHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			Write(w, r, New(http.StatusForbidden, CodeCSRFRejected))
		}))
		inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !safeMethod(r.Method) {
				if origin := r.Header.Get("Origin"); origin != "" {
					u, err := url.Parse(origin)
					if err != nil {
						Write(w, r, New(http.StatusForbidden, CodeCSRFRejected))
						return
					}
					h, herr := want(r.Context())
					if herr != nil {
						writeFault(w, r, herr)
						return
					}
					if !sameHost(u.Host, h) || (httpsOnly && u.Scheme != "https") {
						Write(w, r, New(http.StatusForbidden, CodeCSRFRejected))
						return
					}
				}
			}
			next.ServeHTTP(w, r)
		})
		return cop.Handler(inner)
	}
}

// ---------------------------------------------------------------------------
// Response header access for handlers

// Outbox puts the response header and the request header in the context. A
// strict handler returns a typed response and never sees the ResponseWriter or
// the Request, yet it must set cookies and read the refresh cookie and the user
// agent. Only headers are exposed this way, never the body or the URL. Callers
// set cookies last: the header is written when the strict server writes the
// status, after the handler returned.
func Outbox(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The book of the request (reqledger) is installed here, for every route, so a charge and a
		// refund of the same request meet in it whatever route made them (primitives-r6-2).
		// The scope of the request (store.WithRequestScope) is the runtime half of the one-connection rule: a
		// call that asks for a second connection while a transaction of this request holds one is refused,
		// whatever context it was handed (tenant-r18-8).
		ctx := reqledger.With(store.WithRequestScope(context.WithValue(r.Context(), keyHeader, w.Header())))
		ctx = context.WithValue(ctx, keyReqHeader, r.Header)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// CookieFrom returns a cookie of the request in ctx, or "".
func CookieFrom(ctx context.Context, name string) string {
	h, _ := ctx.Value(keyReqHeader).(http.Header)
	c, err := (&http.Request{Header: h}).Cookie(name)
	if err != nil {
		return ""
	}
	return c.Value
}

// UserAgentFrom returns the request's User-Agent, for the session row.
func UserAgentFrom(ctx context.Context) string {
	h, _ := ctx.Value(keyReqHeader).(http.Header)
	return h.Get("User-Agent")
}

// SetCookie adds a Set-Cookie header to the response of the request in ctx.
func SetCookie(ctx context.Context, c *http.Cookie) {
	if h, ok := ctx.Value(keyHeader).(http.Header); ok {
		if v := c.String(); v != "" {
			h.Add("Set-Cookie", v)
		}
	}
}

// DeferredRefusal returns the refusal that a deferred rate class (budget.Bucket.Deferred) would have
// answered with, or nil. The pipeline does not send it: a route of such a class decides, because it
// can tell one request the class must not refuse (the right console one-time password of the admin
// login, admin-r7-1), and must answer every other request with it.
func DeferredRefusal(ctx context.Context) *Error {
	e, _ := ctx.Value(keyDeferred).(*Error)
	return e
}

// heldProof is what the pipeline keeps for a class with budget.Bucket.HeldProof: the proof the request
// carries (a device marker whose seal checked) and a function that charges its buckets, and for a class with
// HeldInvite the function that charges a live invite's.
type heldProof struct {
	marker       bool
	settle       func() *Error
	settleInvite func(inviteID string) *Error
}

// HeldCarried says the request carries a device marker whose seal checked, on a class with HeldProof: the
// handler may find that it holds for the account asked about.
func HeldCarried(ctx context.Context) bool {
	h, ok := ctx.Value(keyHeld).(*heldProof)
	return ok && h.marker
}

// InviteProofHolds is called by the handler of a class with budget.Bucket.HeldInvite once it has shown that
// the invite the request carries is live. It charges the invite's own buckets and gives back the plain
// network token (when the pipeline took one), so a live invite is neither spent nor refused by the bucket
// strangers on its network fill. It returns the refusal of the invite's buckets, or nil. For a class without
// HeldInvite it returns the refusal the pipeline handed over (DeferredRefusal) and charges nothing.
func InviteProofHolds(ctx context.Context, inviteID string) *Error {
	h, ok := ctx.Value(keyHeld).(*heldProof)
	if !ok || h.settleInvite == nil {
		return DeferredRefusal(ctx)
	}
	return h.settleInvite(inviteID)
}

// HeldProofHolds is called by the handler of a route whose class has budget.Bucket.HeldProof, once it
// has shown that the proof the request carries holds for the account the request is about (for a device
// marker: the same subject and the same credential generation as the phone's account). It charges the
// proof's own buckets and the proof-network bucket and gives back the plain network token the pipeline
// took, so the request neither spends nor is refused by the bucket that strangers on its network fill.
// It returns the refusal of those buckets, or nil. A request with no proof, or a class without
// HeldProof, gets the refusal the pipeline handed over (DeferredRefusal) and nothing is charged, so a
// handler that calls it for a proof that does not hold costs that request nothing and opens nothing.
func HeldProofHolds(ctx context.Context) *Error {
	h, ok := ctx.Value(keyHeld).(*heldProof)
	if !ok || h.settle == nil {
		return DeferredRefusal(ctx)
	}
	return h.settle()
}

// loopbackOnly is the gate of Health (rule 28, admin-r11-4). The
// mux answers /healthz with the role and the release and /readyz with a database ping on one of the
// role's pooled connections, with no authentication, no rate limit and no peer check, because it
// sits at the server root beside the /api pipeline that does the peer check. api and admin listen on
// every interface of app and backend, so a neighbour there (the hub from P4, the worker, a node's
// compromised path) could hold the admin's five connections with a loop on /readyz and keep the
// owner out. Nothing legitimate reaches the mux from another address: the container healthcheck runs
// inside the container and Caddy never proxies it. A peer that is not loopback gets the answer of
// any path that does not exist and costs nothing.
func loopbackOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ap, err := netip.ParseAddrPort(r.RemoteAddr)
		if err != nil || !ap.Addr().Unmap().IsLoopback() {
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Health is the unauthenticated health mux of a role (/healthz, /readyz), held so that the only way
// to get an http.Handler out of it is the one that checks the peer (rule 28, admin-r12-2). The rule
// had been a lint over the call shapes that mount a handler at the root, and a shape it did not list
// (a chi Get, NotFound or Method, a path in a variable, an http.Server whose Handler is the mux) put
// the mux back on every interface. Here there is no ungated shape to miss: the handler is a private
// field, Health has no ServeHTTP, and Handler gates it. api.New, adminapi.New and app take a Health
// and not an http.Handler, so code that wants the mux on a second listener cannot compile without
// going through the gate. internal/lint TestHealthMuxHasOneExposureGate holds the type to that shape.
type Health struct{ h http.Handler }

// NewHealth wraps the mux. Only internal/app builds the real one (lint); tests build their own.
func NewHealth(h http.Handler) Health { return Health{h: h} }

// Handler is the mux behind the peer check: a peer that is not loopback gets the answer of any path
// that does not exist. A zero Health answers nothing but that.
func (h Health) Handler() http.Handler {
	if h.h == nil {
		return http.NotFoundHandler()
	}
	return loopbackOnly(h.h)
}

// MarkLinkDead tells the pipeline that the share or download link value of the request names no live row (no row, or a tenant
// that is not active): from now on the value is refused at the door, with no lookup, until the set forgets it (P3 7.1). It
// does nothing for a request that carries no such value. A value that is merely used up, revoked or past its expiry is dead
// as well, but only a lookup that found no row at all is reported here: the others cost one lookup each and are bounded by the
// row's own public-link budget.
func MarkLinkDead(ctx context.Context) {
	if m, ok := ctx.Value(keyLinkDead).(*linkDeadMark); ok {
		m.set.add(m.key)
	}
}

// linkDeadMark is what the pipeline keeps in the context for a route that carries a link value: the set to mark and the key to mark
// it under. A value and not a function, so no code of the pipeline runs in a goroutine of the handler's choosing.
type linkDeadMark struct {
	set *deadSet
	key string
}
