package sms

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/cachex"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
)

// Gateway is one row of sms_gateways as the router needs it. Sender is nil when
// the gateway cannot be used, and Problem then says why in a fixed code that
// goes into an alert and a log line, never anything from the credentials.
type Gateway struct {
	ID       uuid.UUID
	Provider string
	Role     string // primary, fallback or disabled
	Sender   Sender
	Problem  Code // CodeCredentialsUnreadable, CodeNoCredentials, CodeNoopInProduction, ... (codes.go)
	// Price is the configured price of one message in Rial, nil until the owner
	// gives one. The worker adds it to the day's money counter on an accept.
	Price            *string
	BreakerOpenUntil *time.Time
	// Held is the refusal that put the gateway on hold, nil for a gateway that is not. A gateway
	// whose login the provider refused is not asked again by the traffic of users: every further
	// call is another failed login with the same credentials, and a provider can answer a run of
	// them by blocking the panel's address (Melipayamak -108), which only its support lifts
	// (sms-r11-9). The Source reads it from the gateway row (sms-r12-3), so every worker sees one state,
	// and ignores it once the credentials change; a pinned send (the SMS page's test send) goes
	// through regardless and is the explicit probe.
	Held *Error
	// Revision names the credentials the Sender was built from: a Source that can hold a gateway
	// gives each build its own number, so a hold applies to the credentials that were refused.
	Revision uint64
}

// TemplateRef names one mapping of sms_provider_templates.
type TemplateRef struct {
	Gateway uuid.UUID
	Key     string
	Locale  string
}

// Snapshot is everything the router reads from the database.
type Snapshot struct {
	Gateways  []Gateway
	Templates map[TemplateRef]ProviderTemplate
}

// Source loads a Snapshot. The worker's implementation reads sms_gateways and
// sms_provider_templates and opens the sealed credentials.
type Source interface {
	Load(ctx context.Context) (Snapshot, error)
}

// HoldAction is what an attempt asks the worker to do with the hold of its gateway. The router
// never writes one: it only says what it saw, and the worker writes it in the transaction that
// records the send (sms-r13-2, sms-r13-5). A write between two gateways took the fallback's time
// (a busy gateway row held the write for seconds, and the 6.6 seconds a call needs were gone) and
// ran outside the budget of the send.
type HoldAction uint8

const (
	HoldNone  HoldAction = iota // nothing to write
	HoldPlace                   // the provider refused this login: hold the gateway
	HoldLift                    // a pinned send was accepted on a held gateway: lift the hold
)

// Request is one message to send.
type Request struct {
	To       string // E.164
	Template string
	Locale   string
	Value    secret.String // the code; empty for account_exists
	// Gateway pins the send to one gateway, whatever its role or breaker. The
	// test send of the SMS page uses it: its purpose is to prove one gateway works.
	Gateway uuid.UUID
}

// Attempt is one try at one gateway, for the worker to record.
type Attempt struct {
	Gateway  uuid.UUID
	Provider string
	Price    *string
	// Local is true when the gateway was passed over without a network call
	// (unreadable credentials, no template mapping): there is nothing to log in
	// sms_deliveries, but an operator needs the alert.
	Local   bool
	Err     *Error // nil when the provider accepted the message
	Result  Result
	Latency time.Duration
	// Hold is what the record of this attempt writes to the gateway row, and Revision names the
	// credentials the call was made with (Gateway.Revision), so a hold lands on the credentials
	// that were refused and not on ones saved a moment later.
	Hold     HoldAction
	Revision uint64
}

// Accepted says the provider took the message.
func (a Attempt) Accepted() bool { return a.Err == nil }

// ProblemAttempt is the attempt a gateway that cannot be used produces without
// any network call: credentials that do not open, none stored, a noop row in
// production, an unknown provider. Send makes it when it passes over such a
// gateway, and the worker makes the same one at start (checkGateways), so the
// alert and the breaker step of the two are the same by construction and not by two
// copies of the same fallback to CodeUnusable.
//
// What the attempt means (a breaker step, a critical alert) is not decided here: it
// is the scope of its code in internal/sms/classify (rule sms-failure-classification).
func (g Gateway) ProblemAttempt() Attempt {
	problem := g.Problem
	if problem == CodeNone {
		problem = CodeUnusable
	}
	return Attempt{
		Gateway: g.ID, Provider: g.Provider, Price: g.Price, Local: true,
		Err: NewError(ParseProvider(g.Provider), Config, problem),
	}
}

// Policy is the one decision the router takes from the failure classification: whether
// an answer ends the send. It is an interface because the table that decides lives in
// internal/sms/classify, which imports this package; the router asks and does not read
// a class itself (rule sms-failure-classification). NewRouter requires one, so a
// router cannot be built that decides by its own reading.
type Policy interface {
	// Final says that no other gateway would change the answer, so the send ends here
	// (a refused number, 9.1).
	Final(*Error) bool
	// Refused says the provider refused the gateway's credentials, so asking again with the same
	// credentials can only repeat the refusal (an Auth answer). The router holds the gateway.
	Refused(*Error) bool
}

// Outcome is the result of Send. Attempts is in the order they were tried.
type Outcome struct {
	Attempts []Attempt
	// Skipped counts the routed gateways passed over without an attempt because
	// their breaker is open. They were not asked, so an answer from the other
	// gateway cannot speak for them: one Blacklisted reply while the fallback sat
	// behind an open breaker does not prove the number is refused (9.5, sms-r3-1).
	// A pinned send never skips.
	Skipped int
	// Pinned says the send was for one gateway (the SMS page's test send). What a
	// missing template means differs: for a routed send it can mean that no
	// gateway can send the message at all.
	Pinned bool
}

// Accepted returns the attempt the provider accepted, if any.
func (o Outcome) Accepted() (Attempt, bool) {
	for _, a := range o.Attempts {
		if a.Accepted() {
			return a, true
		}
	}
	return Attempt{}, false
}

// Last is the error that ended the send. With no attempt at all (every gateway
// disabled, or behind an open breaker) it is a Transient "no_gateway": nothing
// is wrong with the message, so a later pass may succeed.
func (o Outcome) Last() *Error {
	if _, ok := o.Accepted(); ok {
		return nil
	}
	if n := len(o.Attempts); n > 0 {
		return o.Attempts[n-1].Err
	}
	return NewError(ProviderNone, Transient, CodeNoGateway)
}

// Errors the router returns instead of an Outcome, for conditions that are not a
// provider failure.
var (
	// ErrNoSnapshot means the gateways have never loaded, or the last good snapshot is older than
	// reloadServeStaleFor and every reload since has failed (tenant-r16-12). The worker leaves its
	// claims to lapse and tries again.
	ErrNoSnapshot = errors.New("sms: gateways not loaded")
	// ErrBadRequest is a request that no gateway could ever send (an unknown
	// template, a value that does not fit it). It is the caller's bug or a
	// damaged payload, so the message is dropped.
	ErrBadRequest = errors.New("sms: bad request")
)

const (
	// DefaultCallTimeout bounds one provider call from the router's side: the drivers' own 6 s
	// client timeout (9.1) and half a second for a driver that forgets its own.
	DefaultCallTimeout = 6500 * time.Millisecond

	// deadlineSlack is what a call must have beyond its own timeout before it is started, so the
	// call's timer always fires before the deadline of the send that holds it.
	deadlineSlack = 100 * time.Millisecond
)

// ErrNoTime says the send ended because the time left to it could not finish another provider
// call. The gateways that were not asked are counted in Outcome.Skipped, and what was attempted
// before is in the Outcome. It is the budget's verdict and not a gateway's.
//
// A call is never started that its deadline cannot finish (rule caps-and-endings, sms-r8-5). A
// call cut by the deadline while the provider may already have taken the message used to be
// dropped: no delivery row, no breaker step, no price on the money counter, and the code was
// sent again by the next claim; a primary that hung was never counted against its breaker.
var ErrNoTime = errors.New("sms: the time left cannot finish another provider call")

// DefaultRefresh is how often the router reloads the gateways (9.1).
const DefaultRefresh = 30 * time.Second

const (
	// reloadRetry is how long a failed reload is left alone. Without it every Send
	// would repeat the failing query, one after another, while the database is slow
	// or the pool is full; a send would then start long after its claim.
	reloadRetry = 5 * time.Second
	// reloadTimeout bounds one reload. It runs on the loader's context, not on the
	// context of the send that happened to start it.
	reloadTimeout = 10 * time.Second
	// reloadStaleWait is the longest the send that starts a periodic reload waits for
	// it; after that it sends with the previous snapshot.
	reloadStaleWait = time.Second
	// reloadServeStaleFor is how long the last good snapshot is sent with while every reload fails. The
	// snapshot holds which gateways are enabled, their roles and their credentials, so a gateway the
	// operator has just disabled or whose key was rotated must not keep being used for ever because the
	// reload keeps failing with nobody told (round 16, tenant-r16-12). Twenty refresh intervals: a
	// database blip of a few minutes costs nothing, and past it the send answers ErrNoSnapshot and the
	// row waits for the next claim.
	reloadServeStaleFor = 10 * time.Minute
)

// Router holds the primary and the fallback and tries them in order (9.1).
//
// The snapshot is a cachex.Loader (rule cache-loader). It loads outside any lock,
// one load at a time; sends use the previous snapshot while a reload runs; a
// failed reload keeps the last good snapshot and is not repeated for reloadRetry;
// and an Invalidate that lands while a reload is in flight is kept (sms-r2-7,
// sms-r3-2).
//
// The breaker lives in the database (sms_gateways.breaker_open_until), because
// the api reads it for sms_available. The router honours the value of its last
// snapshot, and the worker calls Invalidate after it records a failure, so a
// gateway that has just opened its breaker is skipped at once and not after
// the next 30 second reload.
type Router struct {
	src         Source
	policy      Policy
	now         func() time.Time
	refresh     time.Duration
	callTimeout time.Duration
	log         *slog.Logger

	snaps *cachex.Loader[Snapshot]
}

// Option changes a Router.
type Option func(*Router)

// WithClock replaces the wall clock.
func WithClock(now func() time.Time) Option { return func(r *Router) { r.now = now } }

// WithRefresh sets how often the snapshot reloads.
func WithRefresh(d time.Duration) Option { return func(r *Router) { r.refresh = d } }

// WithLog sets where the snapshot cache says a reload that panics or keeps failing, and a snapshot
// refused as too old (round 16, tenant-r16-12). The default is slog.Default(), so a router built without
// it is never silent. The lines carry the cache name, a count and a class, never a credential.
func WithLog(l *slog.Logger) Option {
	return func(r *Router) {
		if l != nil {
			r.log = l
		}
	}
}

// WithCallTimeout replaces DefaultCallTimeout. Tests that run a send under a short budget use it
// with drivers whose own timeout is as short; production leaves the default.
func WithCallTimeout(d time.Duration) Option {
	return func(r *Router) {
		if d > 0 {
			r.callTimeout = d
		}
	}
}

// NewRouter returns a Router over src. policy is classify.Routing{} in every caller; it
// is a parameter, not an option, so that forgetting it does not compile.
func NewRouter(src Source, policy Policy, opts ...Option) *Router {
	r := &Router{src: src, policy: policy, now: time.Now, refresh: DefaultRefresh, callTimeout: DefaultCallTimeout, log: slog.Default()}
	for _, o := range opts {
		o(r)
	}
	r.snaps = cachex.New(cachex.Config[Snapshot]{
		Load: func(ctx context.Context) (Snapshot, error) { return src.Load(ctx) }, TTL: r.refresh, RetryAfter: reloadRetry, LoadTimeout: reloadTimeout, StaleWait: reloadStaleWait, MaxStale: reloadServeStaleFor, Now: r.now, Name: cachex.NameSMSSnapshot, Log: r.log,
	})
	return r
}

// CallNeed is the time a send must have left to start a provider call. A caller that owns the
// budget (the worker) sends nothing when it has less than this.
func (r *Router) CallNeed() time.Duration { return r.callTimeout + deadlineSlack }

// Invalidate makes the next Send reload the gateways.
func (r *Router) Invalidate() { r.snaps.Invalidate() }

// snapshot returns the current snapshot, reloading it when it is old or marked
// stale. A failed reload keeps the last good one: a database blip must not stop
// sending. With nothing ever loaded it is ErrNoSnapshot. A caller that gives up
// gets its own context's error.
func (r *Router) snapshot(ctx context.Context, fresh bool) (Snapshot, error) {
	get := r.snaps.Get
	if fresh {
		get = r.snaps.Fresh
	}
	s, err := get(ctx)
	switch {
	case err == nil:
		return s, nil
	case ctx.Err() != nil:
		return Snapshot{}, ctx.Err()
	}
	return Snapshot{}, ErrNoSnapshot
}

// Send tries the gateways in order and returns what happened. It stops at the
// first accept and at a Recipient error, which no other gateway would change
// (9.1). A cancelled ctx returns its error with the attempts made so far, and
// the caller then records nothing: a shutdown is not a gateway failure.
func (r *Router) Send(ctx context.Context, req Request) (Outcome, error) {
	if !ValidTemplate(req.Template) || !ValidLocale(req.Locale) || req.To == "" {
		return Outcome{}, ErrBadRequest
	}
	if want, _ := PlaceholderCount(req.Template); (want == 1) == req.Value.IsZero() {
		return Outcome{}, ErrBadRequest
	}
	// A pinned send is the SMS page's test send, and the admin sends it right
	// after saving the gateway's credentials, role or template mapping. Those
	// writes happen in another process, which cannot reach this router's
	// Invalidate, so a 30 second old snapshot may lack the gateway (it had no
	// credentials yet) or still hold its old key. Ordinary traffic can live with
	// that delay; a test whose whole point is "does what I just saved work" can
	// not, so it takes a snapshot read after the call (Loader.Fresh). If that read
	// fails, or a failed one is still inside reloadRetry, the send gets no
	// snapshot rather than the old one: running the test on credentials that may
	// have changed would answer a question nobody asked (sms-r4-1).
	snap, err := r.snapshot(ctx, req.Gateway != uuid.Nil)
	if err != nil {
		return Outcome{}, err
	}
	out := Outcome{Pinned: req.Gateway != uuid.Nil}
	short := false
	for _, gw := range r.order(snap, req.Gateway) {
		a, st := r.try(ctx, gw, snap, req)
		if st == tried {
			out.Attempts = append(out.Attempts, a)
		}
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		switch st {
		case stopped:
			continue
		case skipped:
			out.Skipped++ // skipped without an attempt: an open breaker
			continue
		case noTime:
			// Not asked, so it cannot speak for itself or for the other gateway: the same count as
			// an open breaker, and the caller is told why (sms-r8-5).
			out.Skipped++
			short = true
			continue
		}
		if a.Accepted() {
			return out, nil
		}
		if r.policy.Final(a.Err) {
			return out, nil
		}
	}
	if short {
		return out, ErrNoTime
	}
	return out, nil
}

// tryState is what try did with one gateway.
type tryState int

const (
	tried   tryState = iota // an attempt was made, or the gateway was passed over locally (an attempt without a call)
	skipped                 // not asked: its breaker is open
	noTime                  // not asked: the deadline cannot finish a call
	stopped                 // the caller gave up during the call (a shutdown): no verdict, nothing to record
)

// order lists the gateways to try. A pinned send tries that gateway only; a
// normal send tries the primary and then the fallback.
func (r *Router) order(s Snapshot, pinned uuid.UUID) []Gateway {
	if pinned != uuid.Nil {
		for _, g := range s.Gateways {
			if g.ID == pinned {
				return []Gateway{g}
			}
		}
		return nil
	}
	var out []Gateway
	for _, role := range []string{"primary", "fallback"} {
		for _, g := range s.Gateways {
			if g.Role == role {
				out = append(out, g)
			}
		}
	}
	return out
}

// try makes one attempt. The state is skipped when the gateway was passed over silently (its
// breaker is open) and noTime when the deadline of ctx cannot finish a provider call; neither is
// an attempt or an error of the gateway.
func (r *Router) try(ctx context.Context, gw Gateway, snap Snapshot, req Request) (a Attempt, st tryState) {
	a = Attempt{Gateway: gw.ID, Provider: gw.Provider, Price: gw.Price}
	if req.Gateway == uuid.Nil && gw.BreakerOpenUntil != nil && gw.BreakerOpenUntil.After(r.now()) {
		return a, skipped
	}
	// A gateway on hold is passed over locally, like one whose credentials cannot be used: the same
	// attempt, the same breaker step and alert, and no call (sms-r11-9). The step keeps the breaker
	// open, so sms_available stays false while no routed gateway can send. A pinned send is the
	// probe and ignores the hold.
	if req.Gateway == uuid.Nil && gw.Held != nil {
		a.Local = true
		a.Err = gw.Held
		return a, tried
	}
	a.Local = true
	if gw.Sender == nil {
		return gw.ProblemAttempt(), tried
	}
	tpl, found := snap.Templates[TemplateRef{gw.ID, req.Template, req.Locale}]
	if !found {
		// A locale with no mapping falls back to the other locale (9.4).
		tpl, found = snap.Templates[TemplateRef{gw.ID, req.Template, OtherLocale(req.Locale)}]
	}
	if !found {
		a.Err = NewError(ParseProvider(gw.Provider), Config, CodeNoTemplate)
		return a, tried
	}
	msg, err := Build(req.To, req.Template, req.Locale, tpl, req.Value)
	if err != nil {
		code := CodeBadMessage
		if errors.Is(err, ErrParamCount) {
			code = CodeParamCount // checked before any send (9.4)
		}
		a.Err = NewError(ParseProvider(gw.Provider), Config, code)
		return a, tried
	}

	// Never start a call the deadline cannot finish (sms-r8-5). A call cut by the deadline of the
	// send leaves nothing to record when the provider had already taken the message, and a
	// hanging gateway would never be counted against its breaker. Only the calls that need the
	// network are held to this; a gateway passed over locally above costs no time.
	if dl, ok := ctx.Deadline(); ok && time.Until(dl) < r.CallNeed() {
		return a, noTime
	}
	a.Local = false
	cctx, cancel := context.WithTimeout(ctx, r.callTimeout)
	defer cancel()
	start := r.now()
	res, err := gw.Sender.Send(cctx, msg, tpl)
	a.Latency = r.now().Sub(start)
	if err == nil {
		// Every accepted result passes through Scrubbed here, so a driver cannot store the
		// recipient's number or the code a provider echoed as its message id (sms-r5-8).
		a.Result = res.Scrubbed(msg)
		if gw.Held != nil {
			a.Hold, a.Revision = HoldLift, gw.Revision
		}
		return a, tried
	}
	if ctx.Err() != nil {
		// The caller gave up (shutdown). That is no verdict on the gateway.
		return a, stopped
	}
	var se *Error
	if errors.As(err, &se) {
		a.Err = se
	} else {
		// A driver that returns a plain error is a bug, and its text could hold
		// anything. Keep the class and drop the text.
		a.Err = NewError(ParseProvider(gw.Provider), Transient, CodeDriverErr)
	}
	if gw.Held == nil && r.policy.Refused(a.Err) {
		a.Hold, a.Revision = HoldPlace, gw.Revision
	}
	return a, tried
}

// Source returns the source the router loads from, for a worker that keeps the holds its attempts
// ask for in the same source.
func (r *Router) Source() Source { return r.src }

// Gateways returns the gateways of the current snapshot, loading it first when it
// has never loaded. The worker reads it at start to alert on a routed gateway
// that cannot be used, before any user has asked for a code. The returned slice
// is a copy; Sender values are shared and safe for concurrent use.
func (r *Router) Gateways(ctx context.Context) ([]Gateway, error) {
	snap, err := r.snapshot(ctx, false)
	if err != nil {
		return nil, err
	}
	return append([]Gateway(nil), snap.Gateways...), nil
}
