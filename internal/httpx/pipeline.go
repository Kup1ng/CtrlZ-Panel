package httpx

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/Kup1ng/CtrlZ-Panel/internal/apispec"
	"github.com/Kup1ng/CtrlZ-Panel/internal/budget"
	"github.com/Kup1ng/CtrlZ-Panel/internal/bulkgate"
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
	// Tenant is the tenant id of a live session, for the budgets that count a whole tenant (bulk-write-tenant, the bulk
	// gate). Empty for a cookie that is not a live session.
	Tenant string
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
	Strict bool // a request without X-Forwarded-For is refused (every environment but test)
	// PlainHTTPOrigin is a development run over plain http: an Origin whose scheme is http is then accepted when its
	// host is the service's own. The zero value judges the scheme, so a service that forgets to set it is the
	// strict one (tenant-r18-18: the first form took the scheme from Strict, which is on in dev as well).
	PlainHTTPOrigin bool
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
	// TokenProof is Proof for the bearer values a person holds between two steps of a sign-in (a ticket, an OTP challenge id,
	// a refresh token): it reads the one the operation carries, checks its tag with no I/O, and returns the id and the
	// subject a ProofAlt class charges instead of the network (D64 nat-proof-tag; internal/auth/proofmac). It runs before
	// the class is charged, so a body it needs is read here through PeekBody, within the limit the operation sets, and left for
	// the schema check. A value that does not check is no proof and the request is charged to the network like any other.
	// It is asked before Proof; the Held classes never ask it, since a bearer value is no device marker.
	TokenProof func(r *http.Request, op apispec.Operation) (id, subject string, ok bool)
	// Bearer reads the share or download link value of an operation of a ByLink class, screens it with no I/O (internal/auth/bearer)
	// and returns the id of the row it names. A value that does not screen (junk, a wrong tag, past its expiry) is answered 404
	// at once and charges nothing; one that does is charged to the class on that id, and no network bucket is charged
	// (P3 7.1). Build refuses a document with such an operation when it is nil.
	Bearer func(r *http.Request, op apispec.Operation) (key string, ok bool)
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
	// BulkGate bounds the memory of the operations whose body limit is above BulkThreshold (spec 6.2). Build refuses a
	// document that has such an operation when it is nil, so a route cannot go live without the gate.
	BulkGate *bulkgate.Gate
}

// BulkThreshold is the body limit above which an operation takes the bulk gate: it reserves its limit in bytes after its
// session resolved and before its body is read, and its schema check moves behind the reservation (spec 6.2, AUTH 2.3).
const BulkThreshold = 64 << 10

func (a *API) bulk(op apispec.Operation) bool {
	return op.MaxBody > BulkThreshold && a.p.BulkGate != nil
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
	// refusals counts what the rate classes refuse, per class, for the log (tenant-r18-6; budget.Refusals).
	refusals *budget.Refusals
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
		// A link-keyed class is for a route that carries a bearer value and no session, and the pipeline must be able to read it.
		if c.Key == ratelimit.ByLink && (op.Auth.NeedsSession() || p.Bearer == nil) {
			return nil, errors.New("httpx: link-keyed rate class on a route with a session, or no Bearer reader: " + op.ID)
		}
		// A request that carries a session carries a verified proof, and a network
		// bucket is never charged by one: a stolen cookie would escape it by moving
		// networks, and strangers on the owner's network could fill it for the owner.
		if c.Key == ratelimit.ByNetwork && op.Auth.NeedsSession() {
			return nil, errors.New("httpx: network-keyed rate class on a route with a session: " + op.ID)
		}
		if op.MaxBody > BulkThreshold && p.BulkGate == nil {
			return nil, errors.New("httpx: an operation with a large body has no bulk gate: " + op.ID)
		}
	}
	a := &API{p: p, ops: idx, dead: newDeadSet(p.DeadCapacity), refusals: budget.NewRefusals()}
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
	r.Use(Recover(p.Log), RequestID, NoStore, BodyLimit, ClientIP(p.Strict, p.TrustedProxies), HostCheck(p.Host), CSRF(p.Host, !p.PlainHTTPOrigin), Outbox)
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

		// The page, the profile and every refusal of a route that carries a share or download link value are for one person and are
		// never kept or indexed or passed on in a Referer (P3 7.1): the headers are set before the first answer, so a refusal
		// carries them as a success does.
		if class.Key == ratelimit.ByLink {
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("X-Robots-Tag", "noindex")
			w.Header().Set("Referrer-Policy", "no-referrer")
		}

		// Step 8: network-keyed class of the operation, or the bucket of the proof the
		// request carries when the class takes one.
		if class.Key == ratelimit.ByNetwork {
			sub := ratelimit.Subject{Network: network, Wide: wide}
			if class.ProofAlt {
				if id, subject, ok := a.proofOf(r, op); ok {
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

		// Step 8 for a route that carries a share or download link value (P3 7.1), BEFORE the schema check: the value is screened with
		// no I/O, and one that fails, or that is in the dead set, is the same 404 as every other refusal (junk of any length or
		// alphabet included) and charges nothing. The check is not cheap (it rebuilds the operation's schema for every request) and
		// these routes have neither a session nor a network bucket, so a check ahead of the screen would be a cost that a stranger
		// who holds no link could make the service pay without limit (p3-D4-r1-5). One that passes is charged to the class on the
		// row it names, never to the network: a value is minted only by its tenant, so a stranger holds nothing that proves anything
		// about his network. The schema check, and with it the 400 for a body that is not the document's, follows for a value that
		// was charged.
		if class.Key == ratelimit.ByLink {
			key, ok := a.p.Bearer(r, op)
			if !ok {
				// A body over the limit cannot be read for its value, and it is 413 on every route: the size says nothing of a row,
				// and what is left to read is at most the operation's limit.
				if r.Body != nil && r.Body != http.NoBody {
					var mbe *http.MaxBytesError
					if _, err := io.Copy(io.Discard, r.Body); errors.As(err, &mbe) {
						Write(w, r, New(http.StatusRequestEntityTooLarge, CodeTooLarge))
						return
					}
				}
				Write(w, r, NotFound())
				return
			}
			if a.dead.has("link:" + key) {
				Write(w, r, NotFound())
				return
			}
			if e := a.charge(ctx, class, ratelimit.Subject{Network: network, Link: key}); e != nil {
				a.refuse(w, r, e)
				return
			}
			ctx = context.WithValue(ctx, keyLinkDead, &linkDeadMark{set: a.dead, key: "link:" + key})
			r = r.WithContext(ctx)
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

		// Step 8a: the request against its schema (rule boundary-input). An operation that takes the bulk gate is
		// checked behind its reservation instead (below), so no body of that size is read before the gate holds its memory.
		if a.check != nil && !a.bulk(op) {
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

			// The tenant's day budget (spec 8.1) is charged for every operation of the bulk-write class, not only for those
			// above the gate threshold: Duplicate has the default body limit and still reads and writes a whole profile.
			if op.Rate == ratelimit.BulkWrite {
				if e := a.chargeBulkTenant(ctx, res); e != nil {
					a.refuse(w, r, e)
					return
				}
			}
			// A second class of the operation, charged on the tenant of the live session (x-ctrlz-rate-also).
			if op.Also != "" {
				if e := a.chargeTenantClass(ctx, res, op.Also); e != nil {
					a.refuse(w, r, e)
					return
				}
			}
			// A route that makes a share or download link spends the tenant's day budget of links too (P3 9.1): it bounds how many
			// row ids can ever pass the check of a value, whatever the number of sessions the tenant holds.
			if op.Rate == ratelimit.LinkWrite {
				if e := a.chargeTenantDay(ctx, res, ratelimit.LinkCreate); e != nil {
					a.refuse(w, r, e)
					return
				}
			}
			// The bulk gate (spec 6.2): after the session resolved and its class was charged, before the body is read.
			if a.bulk(op) {
				rsv, gb, e := a.openBulk(res, r)
				if e != nil {
					a.refuse(w, r, e)
					return
				}
				defer rsv.Release()
				if r.Body != nil && r.Body != http.NoBody {
					r.Body = gb
				}
				if a.check != nil {
					e := a.check.Check(r, op.Key())
					if gb.busy {
						e = a.busyBulk(ctx, res, op.Rate == ratelimit.BulkWrite)
					}
					if e == nil && !rsv.To(gb.read*bulkgate.BodyWeight) {
						e = a.busyBulk(ctx, res, op.Rate == ratelimit.BulkWrite)
					}
					if e != nil {
						a.refuse(w, r, e)
						return
					}
				}
			}
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
		// The SMS classes say so; the other fail-closed class (link-create, P3 9.1) is a bound on rows and says only that the
		// service cannot count.
		if strings.HasPrefix(c.Name, "otp-send") {
			return New(http.StatusServiceUnavailable, CodeSMSUnavailable)
		}
		return New(http.StatusServiceUnavailable, CodeServiceUnavailable)
	case err != nil:
		// An empty key is a wiring bug; refuse rather than skip the limit.
		a.p.Log.Error("rate limit could not be applied", logattr.Enum("class", c.LogName()))
		return Internal()
	case !d.Allowed:
		a.noteRefusal(c)
		return RateLimited(d.RetryAfter)
	}
	return nil
}

// noteRefusal counts a refusal of a rate class and, when its count reaches a power of two, writes one closed line:
// the class, the kind of key it counts on and the count, no address and no key (tenant-r18-6, D64
// net-bucket-numbers: the numbers of the network buckets are set from this data at the P4b gate).
func (a *API) noteRefusal(c ratelimit.Class) {
	b, ok := budget.Find(budget.RateClass, budget.Service(a.p.Service), c.Name)
	if !ok || a.p.Log == nil {
		return
	}
	if n, due := a.refusals.Note(b); due {
		a.p.Log.Warn("a rate class refused a request", logattr.Enum("bucket", b.LogName()), logattr.Enum("key_kind", b.KeyKind()), logattr.Int("refusals", int(n)))
	}
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

// chargeBulkTenant charges the tenant's day budget of the bulk-write class. It comes before the gate, so a slow body from
// one of many sessions has paid it before it holds any memory. A refusal is the answer: 429 rate_limited.
func (a *API) chargeBulkTenant(ctx context.Context, res Resolved) *Error {
	return a.chargeTenantDay(ctx, res, ratelimit.BulkWriteTenant)
}

// chargeTenantDay charges a class that counts a whole tenant (bulk-write-tenant, link-create) for the tenant of the resolved session.
func (a *API) chargeTenantDay(ctx context.Context, res Resolved, class string) *Error {
	if res.Tenant == "" {
		// Such an operation always has a live session, whose resolver names the tenant: a missing one is a wiring bug.
		return Internal()
	}
	c, ok := ratelimit.Lookup(a.p.Service, class)
	if !ok {
		return Internal()
	}
	return a.charge(ctx, c, ratelimit.Subject{Tenant: res.Tenant})
}

// chargeTenantClass charges a second class of an operation to the tenant of the live session: 429 rate_limited when it is spent.
func (a *API) chargeTenantClass(ctx context.Context, res Resolved, name string) *Error {
	if res.Tenant == "" {
		return Internal()
	}
	c, ok := ratelimit.Lookup(a.p.Service, name)
	if !ok {
		return Internal()
	}
	return a.charge(ctx, c, ratelimit.Subject{Tenant: res.Tenant})
}

// openBulk opens the reservation of the request and wraps its body so that the reservation follows the bytes read. A
// request without a body holds nothing.
func (a *API) openBulk(res Resolved, r *http.Request) (*bulkgate.Reservation, *gatedBody, *Error) {
	if res.Tenant == "" {
		return nil, nil, Internal()
	}
	rsv := a.p.BulkGate.Reserve(res.Tenant)
	return rsv, &gatedBody{rc: r.Body, rsv: rsv}, nil
}

// busyBulk is the refusal of a request the gate has no room for: 503 server_busy. When the request paid the tenant's day
// budget, it gives it back, so a victim whose client retries these refusals does not spend its day on them (spec 6.2).
// paid is false for an operation that is gated by its body size but is not of the bulk-write class (a rule create): it
// never charged the budget, and a refund would mint a token and let a tenant refill its day budget at will (p2-B3-r3-3).
func (a *API) busyBulk(ctx context.Context, res Resolved, paid bool) *Error {
	if c, ok := ratelimit.Lookup(a.p.Service, ratelimit.BulkWriteTenant); ok && paid {
		a.p.Limiter.Refund(context.WithoutCancel(ctx), c, ratelimit.Subject{Tenant: res.Tenant})
	}
	return New(http.StatusServiceUnavailable, CodeServerBusy).WithRetry(5 * time.Second)
}

// gatedBody is a request body whose reservation grows with the bytes read. A sender that trickles its body holds what it
// has sent and no more, so a slow body cannot hold the gate; a read the gate has no room for ends with errBusy, and the
// pipeline answers 503 server_busy.
type gatedBody struct {
	rc   io.ReadCloser
	rsv  *bulkgate.Reservation
	read int64
	busy bool
}

var errBusy = errors.New("httpx: the bulk gate is full")

func (g *gatedBody) Read(p []byte) (int, error) {
	if g.rc == nil {
		return 0, io.EOF
	}
	n, err := g.rc.Read(p)
	if n > 0 {
		g.read += int64(n)
		if !g.rsv.To(g.read * bulkgate.ReadWeight) {
			g.busy = true
			return 0, errBusy
		}
	}
	return n, err
}

func (g *gatedBody) Close() error {
	if g.rc == nil {
		return nil
	}
	return g.rc.Close()
}

// proofOf is the proof a ProofAlt class charges instead of the network: the bearer value of the operation when its tag
// checks, else the device marker.
func (a *API) proofOf(r *http.Request, op apispec.Operation) (id, subject string, ok bool) {
	if a.p.TokenProof != nil {
		if id, subject, ok := a.p.TokenProof(r, op); ok {
			return id, subject, true
		}
	}
	if a.p.Proof != nil {
		return a.p.Proof(r)
	}
	return "", "", false
}

// PeekBody reads the body of r, which BodyLimit has already capped, and puts it back, so that a proof can be read from it
// before the schema check does the same. A body that cannot be read (over its limit, a client that left) is returned with
// ok false and the error is kept for the next reader, so the refusal is the one it always was (413, 499).
func PeekBody(r *http.Request) (raw []byte, ok bool) {
	if r.Body == nil || r.Body == http.NoBody {
		return nil, false
	}
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(raw), errReader{err}))
		return nil, false
	}
	r.Body = io.NopCloser(bytes.NewReader(raw))
	return raw, true
}

// errReader gives back the error a body read ended with.
type errReader struct{ err error }

func (e errReader) Read([]byte) (int, error) { return 0, e.err }
