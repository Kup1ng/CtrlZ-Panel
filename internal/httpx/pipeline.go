package httpx

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/Kup1ng/CtrlZ-Panel/internal/apispec"
	"github.com/Kup1ng/CtrlZ-Panel/internal/logattr"
	"github.com/Kup1ng/CtrlZ-Panel/internal/ratelimit"
)

// Resolved is what a Resolver found for a request.
type Resolved struct {
	// Ctx carries the principal for the handler.
	Ctx context.Context
	// Live says the cookie belonged to a live session, whether or not a gate then
	// refused the request. A live session gets its session-lookup token back
	// (spec 2.3 step 9); only cookies that resolve to nothing stay charged.
	Live bool
	// Dead says the cookie names a session that is gone for good: no row, a revoked or an ended
	// one. The pipeline remembers its lookup key and refuses the cookie from then on without a
	// lookup (deadSet, primitives-r6-5). A lookup that failed (the database is down) is not dead.
	Dead bool
	// SessionID is the id of the live session the cookie belongs to. It does not change when
	// the cookie is rotated (reauth, refresh, a new factor), so it is the key of the route's
	// session class that a client cannot reset by asking for a new cookie (tenant-r6-5). Empty
	// for a cookie that is not a live session.
	SessionID string
}

// Resolver turns a cookie into a principal for one service (spec 2.3 step 9):
// the tenant API reads sessions, the admin API admin_sessions. It applies the
// gates of 3.5 or 10.3 and returns the *Error for a refusal.
type Resolver interface {
	// CookieName is the cookie the service reads.
	CookieName() string
	// Screen says, without any I/O, whether the cookie can have been issued by
	// this service, and returns the key its lookup is charged to. A cookie that
	// cannot have been (wrong shape, wrong tag) is answered 401 session_expired
	// and charged to nothing, so junk never spends a budget that live sessions
	// share (round 4, tenant-r4-4). tokenSession is the id of the session the cookie opens, read from the body its
	// tag covers, or empty when the service keeps no tag (a unit test): the miss budget is keyed on it, and on
	// nothing wider (a budget keyed on the account let one stolen session's dead cookies refuse every live
	// session of the owner, round 8, tenant-r8-3).
	Screen(cookie string) (lookupKey, tokenSession string, ok bool)
	Resolve(ctx context.Context, cookie string, op apispec.Operation) (Resolved, error)
}

// Pipeline is the request pipeline of spec 2.3 for one service. The same type
// serves the tenant and the admin API; only the resolver, the class table and
// the document differ.
type Pipeline struct {
	Log    *slog.Logger
	Strict bool // production: a request without X-Forwarded-For is refused
	// TrustedProxies are the peers allowed to set X-Forwarded-For. With Strict and
	// a non-empty list, a request from any other peer is refused before the header
	// is read.
	TrustedProxies []netip.Prefix
	Host           HostSource
	Limiter        *ratelimit.Limiter
	Service        ratelimit.Service
	Ops            []apispec.Operation
	Resolver       Resolver
	// BaseURL is the server URL of the document, "/api/v1".
	BaseURL string
	// Proof returns the id of a proof the request carries that can be checked
	// without I/O (a device marker whose seal checks), and false for none. A class
	// with ProofAlt is charged to that id instead of the network, so a request that
	// carries a proof neither spends nor is refused by a bucket that strangers on
	// its network share (rule budget-keying). Nil means no class takes a proof.
	Proof func(*http.Request) (id, subject string, ok bool)
	// Doc is the OpenAPI document the Ops were read from. Every request is checked
	// against its operation's schemas before any handler runs (Validator, rule
	// boundary-input), so the document and the check are the same bytes.
	Doc []byte
	// SkipRequestCheck is for the tests of the pipeline itself, whose operations are
	// stubs with no schemas. internal/lint fails for any non-test file that names it,
	// so a service cannot start without the check.
	SkipRequestCheck bool
	// DeadCapacity is how many dead cookies the pipeline remembers (0 is the default, deadCapacity). It is a field
	// so that the test of what a holder of more dead cookies than that can cost does not need sixty-five
	// thousand requests to fill the set.
	DeadCapacity int
}

// API is a built pipeline.
type API struct {
	// Router has the global steps 1 to 7 and the JSON 404 and 405. The generated
	// handlers are registered on it with BaseURL stripped of its mount point.
	Router chi.Router
	// PerOp is the middleware for steps 8 to 10. The generated code applies the
	// middlewares of its list in reverse (the last is outermost), so pass this
	// as the only element.
	PerOp func(http.Handler) http.Handler
	p     *Pipeline
	ops   map[string]apispec.Operation
	check *Validator
	dead  *deadSet // cookies whose session is gone for good (primitives-r6-5)
}

// Build assembles the pipeline. It fails when the class table and the document
// disagree, so a typo in x-ctrlz-rate stops the service at start-up and not at
// the first request.
func (p *Pipeline) Build() (*API, error) {
	idx := apispec.Index(p.Ops)
	for _, op := range p.Ops {
		c, ok := ratelimit.Lookup(p.Service, op.Rate)
		if !ok {
			return nil, errors.New("httpx: unknown rate class on " + op.ID)
		}
		if c.Key == ratelimit.BySession && !op.Auth.NeedsSession() {
			return nil, errors.New("httpx: session-keyed rate class on a route without a session: " + op.ID)
		}
		// A request that carries a session carries a verified proof, and a network
		// bucket is never charged by one: a stolen cookie would escape it by moving
		// networks, and strangers on the owner's network could fill it for the owner.
		if c.Key == ratelimit.ByNetwork && op.Auth.NeedsSession() {
			return nil, errors.New("httpx: network-keyed rate class on a route with a session: " + op.ID)
		}
	}
	a := &API{p: p, ops: idx, dead: newDeadSet(p.DeadCapacity)}
	switch {
	case p.Doc != nil:
		v, err := NewValidator(p.Doc)
		if err != nil {
			return nil, err
		}
		a.check = v
	case !p.SkipRequestCheck:
		return nil, errors.New("httpx: the pipeline has no OpenAPI document to check requests against")
	}
	r := chi.NewRouter()
	// Steps 1 to 7, in the order of the spec. Outbox is bookkeeping for the
	// strict handlers and runs after the checks that can refuse.
	r.Use(Recover(p.Log), RequestID, NoStore, BodyLimit, ClientIP(p.Strict, p.TrustedProxies), HostCheck(p.Host), CSRF(p.Host), Outbox)
	r.NotFound(func(w http.ResponseWriter, r *http.Request) { Write(w, r, NotFound()) })
	r.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) { Write(w, r, BadRequest()) })
	a.Router = r
	a.PerOp = a.perOp
	return a, nil
}

// operation finds the operation of the request from the route chi matched. The
// document's paths are relative to BaseURL; the router is mounted below it.
func (a *API) operation(r *http.Request) (apispec.Operation, bool) {
	rc := chi.RouteContext(r.Context())
	if rc == nil {
		return apispec.Operation{}, false
	}
	pat := strings.TrimPrefix(rc.RoutePattern(), a.p.BaseURL)
	op, ok := a.ops[r.Method+" "+pat]
	return op, ok
}

func (a *API) perOp(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		op, ok := a.operation(r)
		if !ok {
			// A route registered without a document entry. Fail closed: this is a
			// wiring bug, and serving it without its limits is worse than a 500.
			a.p.Log.Error("route without an operation in the document")
			Write(w, r, Internal())
			return
		}
		if op.MaxBody > 0 {
			SetBodyLimit(r, op.MaxBody)
		}
		class, _ := ratelimit.Lookup(a.p.Service, op.Rate)
		ctx := r.Context()
		network, wide := Subject(ctx)
		// A client address is required: ClientIP refuses a request without one, so a
		// missing one here is a wiring bug and every network key would be "".
		if network == "" {
			Write(w, r, BadRequest())
			return
		}

		// Step 8: network-keyed class of the operation, or the bucket of the proof the
		// request carries when the class takes one.
		if class.Key == ratelimit.ByNetwork {
			sub := ratelimit.Subject{Network: network, Wide: wide}
			if class.ProofAlt && a.p.Proof != nil {
				if id, subject, ok := a.p.Proof(r); ok {
					sub.Proof, sub.ProofSubject = id, subject
				}
			}
			var heldID, heldSubject string
			if class.Held && a.p.Proof != nil {
				if id, subject, ok := a.p.Proof(r); ok {
					heldID, heldSubject = id, subject
				}
			}
			if e := a.charge(ctx, class, sub); e != nil {
				// A Held class is handed over only for a request that carries a proof the handler may find
				// holds: every other request (no marker) is refused here as before, so a flood from a network
				// never costs the account read that the handler needs to tell.
				// A class that also takes a live invite (HeldInvite) hands every plain refusal over: only the
				// handler can read the invite token, and it answers the refusal before any I/O unless the request
				// is an invite request.
				if !class.Deferred || e.Status != http.StatusTooManyRequests || (class.Held && heldID == "" && !class.HeldInvite) {
					a.refuse(w, r, e)
					return
				}
				// A deferred class hands its refusal to the handler as a value (budget.Bucket.Deferred):
				// the handler lets one request through it. Only a plain refusal is handed on; a store
				// fault or a closed client still ends the request here.
				ctx = context.WithValue(ctx, keyDeferred, e)
				r = r.WithContext(ctx)
			}
			// A class that a proof can stand in for once the handler has shown it holds (HeldProof) keeps what
			// the handler needs to charge the proof's buckets, and to give the plain token back.
			if heldID != "" || class.HeldInvite {
				plainRefused := DeferredRefusal(ctx) != nil
				plain := sub
				charged := ctx
				hp := &heldProof{}
				if heldID != "" {
					held := ratelimit.Subject{Network: network, Wide: wide, Proof: heldID, ProofSubject: heldSubject}
					// A request the plain bucket refused still costs the handler an account read before it can
					// tell whether the marker holds, and a marker is free to mint, so it is charged to the
					// marker's own buckets now: what a marker can make the service read is bounded by them.
					// Otherwise the proof's buckets are charged when the handler says the marker holds.
					heldCharged := false
					if plainRefused {
						if e := a.charge(ctx, class, held); e != nil {
							a.refuse(w, r, e)
							return
						}
						heldCharged = true
					}
					hp.marker = true
					hp.settle = func() *Error {
						if heldCharged {
							return nil
						}
						if e := a.charge(charged, class, held); e != nil {
							return e
						}
						a.p.Limiter.Refund(charged, class, plain)
						return nil
					}
				}
				if class.HeldInvite {
					// The invite is charged when the handler has shown it live, never before: a junk token is
					// free to make. Its keys are the proof keys of the class, namespaced so that no marker id
					// can meet an invite id. When the plain bucket refused, nothing was taken from it, so
					// nothing is given back.
					hp.settleInvite = func(id string) *Error {
						key := "invite:" + id
						held := ratelimit.Subject{Network: network, Wide: wide, Proof: key, ProofSubject: key}
						if e := a.charge(charged, class, held); e != nil {
							return e
						}
						if !plainRefused {
							a.p.Limiter.Refund(charged, class, plain)
						}
						return nil
					}
				}
				ctx = context.WithValue(ctx, keyHeld, hp)
				r = r.WithContext(ctx)
			}
		}

		// A route that needs a session answers 401 before it reads or checks the body. A
		// session route carries no network bucket (Build forbids one), so a request with no
		// cookie that could be ours used to be charged to nothing and still paid a read of
		// up to 64 KiB and a schema check before the 401 (round 5, tenant-r5-2). The cookie
		// is looked at first, in-process: no cookie, or one with a wrong tag or past its
		// expiry, is refused here for the price of one MAC.
		needsSession := op.Auth.NeedsSession()
		var cookie, lookupKey, tokenSession string
		if needsSession {
			cookie = cookieValue(r, a.p.Resolver.CookieName())
			if cookie == "" {
				Write(w, r, SessionExpired())
				return
			}
			var plausible bool
			if lookupKey, tokenSession, plausible = a.p.Resolver.Screen(cookie); !plausible {
				Write(w, r, SessionExpired())
				return
			}
			// A cookie that was looked up and found gone for good costs a map read and nothing else.
			if a.dead.has(lookupKey) {
				Write(w, r, SessionExpired())
				return
			}
			// Step 8b: the route's own class, charged to the cookie BEFORE the body is read
			// and before the lookup, and never given back. It used to be charged after the
			// lookup, on the session id, while the lookup token was refunded for a live
			// session, so a live cookie could queue any number of SessionByHash calls on the
			// pool and be refused only after each of them (primitives-r5-7). Keyed on the
			// cookie's lookup key, the class is also the bound on body reads and lookups of a
			// cookie, live or not: at most its limit per minute.
			if class.Key == ratelimit.BySession {
				if e := a.charge(ctx, class, ratelimit.Subject{Session: lookupKey}); e != nil {
					a.refuse(w, r, e)
					return
				}
			}
		}

		// Step 8a: the request against its schema (rule boundary-input).
		if a.check != nil {
			if e := a.check.Check(r, op.Key()); e != nil {
				a.refuse(w, r, e)
				return
			}
		}

		// Steps 8 (session-lookup) and 9: a route that needs a session.
		if needsSession {
			lookup, _ := ratelimit.Lookup(a.p.Service, ratelimit.SessionLookup)
			sub := ratelimit.Subject{Session: lookupKey}
			if e := a.charge(ctx, lookup, sub); e != nil {
				a.refuse(w, r, e)
				return
			}
			// What a dead cookie can cost in lookups once deadSet has forgotten it (it forgets the oldest
			// at its capacity, so a holder of more dead cookies than that sends them round and round and
			// each is a lookup again): one budget per SESSION, taken before the lookup and given back
			// unless the session proved gone for good. The session id is in the body the tag covers, so it
			// cannot be changed to charge another session, no eviction resets it, and no other session's
			// cookie, of this account or another, ever touches it (primitives-r7-6; round 8, tenant-r8-3:
			// keyed on the account it let the dead cookies of one stolen session refuse every live session of
			// the owner, the ones opened after logout-all included; budget-keying: nothing that is not proof
			// of a live session may refuse one that is, and here only the session's own dead cookies fill it).
			miss, _ := ratelimit.Lookup(a.p.Service, ratelimit.SessionMiss)
			missSub := ratelimit.Subject{TokenSession: tokenSession}
			if tokenSession != "" {
				if e := a.charge(ctx, miss, missSub); e != nil {
					a.refuse(w, r, e)
					return
				}
			}
			res, err := a.p.Resolver.Resolve(ctx, cookie, op)
			if res.Live {
				a.p.Limiter.Refund(ctx, lookup, sub)
			}
			if tokenSession != "" && !res.Dead {
				a.p.Limiter.Refund(ctx, miss, missSub)
			}
			// A cookie whose session is gone for good is remembered, so the next request that
			// carries it is refused above with no lookup. There is no network bucket for misses:
			// whatever a network spends on cookies that are not proof must not refuse a cookie that is
			// (primitives-r6-5; the session-miss bucket of round 5 did, for every tenant behind a
			// shared carrier address).
			if res.Dead {
				a.dead.add(lookupKey)
			}
			if err != nil {
				a.fail(w, r, err)
				return
			}
			// Step 10: the route's own class again, on the session itself. The charge of step 8b is
			// keyed on the cookie, and every rotation (a reauth, a refresh, a new factor) issues a new
			// cookie and so a new bucket: a client that loops POST /auth/reauth with its own password
			// got 25 Argon2 runs a minute where the class says 10 (tenant-r6-5). The session id does
			// not change with the cookie, so this is the bound a rotating client meets. It is never
			// given back, and it comes after the checks that refuse for nothing, so it counts the
			// requests that reached a handler.
			if res.SessionID != "" && class.Key == ratelimit.BySession {
				if e := a.charge(ctx, class, ratelimit.Subject{SessionID: res.SessionID}); e != nil {
					a.refuse(w, r, e)
					return
				}
			}
			ctx = res.Ctx
			r = r.WithContext(ctx)
		}

		next.ServeHTTP(w, r)
	})
}

// refuse writes a refusal. A client that left while its request was being read
// gets the bare 499 of fail, and nothing else is a server fault.
func (a *API) refuse(w http.ResponseWriter, r *http.Request, e *Error) {
	if e.Status == StatusClientClosedRequest {
		w.WriteHeader(StatusClientClosedRequest)
		return
	}
	Write(w, r, e)
}

// charge takes one token and returns the refusal to send, or nil. A fail-closed
// class with Valkey down is 503 sms_unavailable: the only such classes are the SMS ones (otp-send, otp-send-user).
func (a *API) charge(ctx context.Context, c ratelimit.Class, s ratelimit.Subject) *Error {
	d, err := a.p.Limiter.Allow(ctx, c, s)
	switch {
	case err != nil && ctx.Err() != nil:
		// The client left while the limiter was being asked: nobody reads the answer, and it is not a fault of
		// the service. This case comes first: Limiter.Allow turns every backend error into ErrUnavailable for a
		// fail-closed class, so a client that left during the call of an SMS route would otherwise be counted as a
		// 503 sms_unavailable and hide the real outages in that noise (tenant-r12-2).
		return &Error{Status: StatusClientClosedRequest, Code: "client_closed_request"}
	case errors.Is(err, ratelimit.ErrUnavailable):
		return New(http.StatusServiceUnavailable, CodeSMSUnavailable)
	case err != nil:
		// An empty key is a wiring bug; refuse rather than skip the limit.
		a.p.Log.Error("rate limit could not be applied", logattr.Enum("class", c.LogName()))
		return Internal()
	case !d.Allowed:
		return RateLimited(d.RetryAfter)
	}
	return nil
}

func cookieValue(r *http.Request, name string) string {
	c, err := r.Cookie(name)
	if err != nil {
		return ""
	}
	return c.Value
}

// ParamError is the ErrorHandlerFunc of the generated wrapper: a path or query
// parameter that failed to bind. The text names the parameter and the value, so
// it is dropped; the client gets bad_request.
func (a *API) ParamError(w http.ResponseWriter, r *http.Request, _ error) { Write(w, r, BadRequest()) }

// RequestError is the strict server's handler for a body that did not decode.
// A body over the limit surfaces here as *http.MaxBytesError.
func (a *API) RequestError(w http.ResponseWriter, r *http.Request, err error) {
	var mbe *http.MaxBytesError
	if errors.As(err, &mbe) {
		Write(w, r, New(http.StatusRequestEntityTooLarge, CodeTooLarge))
		return
	}
	Write(w, r, BadRequest())
}

// ResponseError is the strict server's handler for an error a handler returned.
// Anything that is not an *Error or a mapped store error becomes 500, and the
// log line carries the class only: the error text of an unknown error may hold
// request data.
func (a *API) ResponseError(w http.ResponseWriter, r *http.Request, err error) {
	a.fail(w, r, err)
}

// StatusClientClosedRequest is the status nginx made up for a client that left
// before the answer, and the one the access logs of a proxy in front of this
// service expect. It is not a failure of the server and is never logged as one.
const StatusClientClosedRequest = 499

// fail answers a handler's or resolver's error. A client that dropped the
// connection while a database call was running makes that call return
// context.Canceled, and the request context is done: that is the client's own
// doing, so it gets a bare 499 (nobody reads it) and no WARN line and no 5xx for
// the log reader to take for a server fault (round 4, tenant-r4-3). A Canceled
// with a live request context is the server's own (shutdown, a derived context)
// and is a 503 like a deadline.
func (a *API) fail(w http.ResponseWriter, r *http.Request, err error) {
	if e := writeFault(w, r, err); e != nil && e.Status >= 500 {
		a.p.Log.Warn("request failed", logattr.Int("status", e.Status), logattr.Enum("code", failCodeOf(e.Code)), logattr.RequestID(RequestIDFrom(r.Context())))
	}
}

// writeFault is the one place an error of a dependency becomes a response, for the handler path (fail)
// and for the Host and Origin checks, which ask a source that can fail. A caller that left gets the bare
// 499 and the function returns nil; anything else is written through FromError and the error sent is
// returned, so the caller can log a 5xx. A path that wrote its own Write(FromError(err)) would answer
// 503 to a client that went away: the sibling of tenant-r12-2 that round 16 put in the Host and Origin
// checks (round 17, tenant-r17-8). TestAHostSourceThatFindsTheCallerGoneAnswers499 holds the Host and Origin checks to it.
func writeFault(w http.ResponseWriter, r *http.Request, err error) *Error {
	if errors.Is(err, context.Canceled) && r.Context().Err() != nil {
		w.WriteHeader(StatusClientClosedRequest)
		return nil
	}
	e := FromError(err)
	Write(w, r, e)
	return e
}
