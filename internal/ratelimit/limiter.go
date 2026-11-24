package ratelimit

import (
	"context"
	"errors"
	"log/slog"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/logattr"
)

// ErrUnavailable is returned for a fail-closed class while Valkey cannot be
// reached. The route answers 503 sms_unavailable.
var ErrUnavailable = errors.New("ratelimit: backend unavailable")

// Backend is the shared bucket store. Valkey is the only implementation; tests
// add a fake that fails on demand.
type Backend interface {
	// Take removes one token from every slot or from none, and says how long to
	// wait when it refused. The backend's own clock decides, so instances with
	// skewed clocks agree.
	Take(ctx context.Context, slots []slot) (allowed bool, retry time.Duration, err error)
	// Give returns one token to every slot.
	Give(ctx context.Context, slots []slot) error
}

// Config builds a Limiter.
type Config struct {
	Service Service
	Backend Backend
	// LocalOnly makes the in-process bucket the only store and fail-closed
	// classes behave like the others. For tests and a development stack with no
	// Valkey. A nil Backend without LocalOnly is treated as Valkey being down.
	LocalOnly bool
	LocalKeys int
	Now       func() time.Time
	Log       *slog.Logger
	// Timeout bounds one backend call (default 250 ms); Cooldown is how long the
	// backend is left alone after a failure (default 3 s), so an outage costs
	// one timeout per cooldown and not one per request.
	Timeout  time.Duration
	Cooldown time.Duration
}

// Limiter charges requests to classes.
type Limiter struct {
	svc       Service
	backend   Backend
	localOnly bool
	local     *local
	now       func() time.Time
	log       *slog.Logger
	timeout   time.Duration
	cooldown  time.Duration

	downUntil atomic.Int64 // unix nanoseconds
	lastWarn  atomic.Int64
}

// New returns a Limiter.
func New(c Config) *Limiter {
	l := &Limiter{
		svc: c.Service, backend: c.Backend, localOnly: c.LocalOnly, local: newLocal(c.LocalKeys),
		now: c.Now, log: c.Log, timeout: c.Timeout, cooldown: c.Cooldown,
	}
	if l.now == nil {
		l.now = time.Now
	}
	if l.log == nil {
		l.log = slog.New(slog.DiscardHandler)
	}
	if l.timeout <= 0 {
		l.timeout = 250 * time.Millisecond
	}
	if l.cooldown <= 0 {
		l.cooldown = 3 * time.Second
	}
	return l
}

// Subject is who a request is, in the terms a class counts on.
type Subject struct {
	Network string // netkey.Net of the client; for ByNetwork classes
	Wide    string // netkey.Wide, set for IPv6 clients only
	Session string // the cookie's lookup key (a hash, never the cookie); for BySession classes
	// SessionID is the id of the session the cookie belongs to. It survives a rotation of the
	// cookie, which Session does not, so a class charged on both cannot be reset by rotating.
	SessionID string
	// Tenant is the tenant id of a live session, for the class that counts a whole tenant (bulk-write-tenant). It is read
	// from the resolved principal, never from the request.
	Tenant string
	// Link is the id of the row a share link or a download link names, read from a value whose tag checked (internal/auth/bearer).
	// The public-link class counts on it and on nothing else: not on the network, which a stranger with dead values could
	// fill for every honest holder behind the same carrier address (P3 7.1).
	Link string
	// TokenSession is the id of the session a cookie opens, read from the body its tag covers
	// (session.Manager.Screen). The session-miss class counts on it and on nothing else: not on the account,
	// or the dead cookies of one session would refuse every other session of it (round 8, tenant-r8-3).
	TokenSession string
	// Proof is the id of a verified proof (a device marker whose seal checked) for a
	// ByNetwork class with ProofAlt. When it is set the class is charged to it and
	// not to the network; Network must still be set, because a request with no
	// client address is refused whatever it carries.
	Proof string
	// ProofSubject is the account the proof was issued for (a device marker is sealed for one
	// subject, and the seal is ours, so it cannot be changed). The proof-network bucket is keyed
	// on it: a source that rotates markers of ONE account meets its ceiling, and the accounts of
	// everyone else on the same address group keep theirs (primitives-r6-5). Without it every
	// marker on a /24 shared one bucket, and an account holder who mints markers by signing in
	// could fill it for every returning browser behind the carrier address.
	ProofSubject string
}

// Decision is the answer of Allow.
type Decision struct {
	Allowed    bool
	RetryAfter time.Duration
}

// KeyPrefix is the front of every Valkey key a service's limiter makes. The ACL user of the service
// in Compose is limited to exactly this pattern (deploy/compose/docker-compose.yml, valkey), and
// `ctrlz-admin unlock` clears the admin's keys by it.
func KeyPrefix(svc Service) string { return "ctrlz:rl:" + string(svc) + ":" }

// IndexKey is the sorted set in which the admin service's limiter lists the keys it writes, so that
// `ctrlz-admin unlock` can delete them without scanning the instance (round 7, admin-r7-6). It sits
// under KeyPrefix, so the admin ACL user's key pattern covers it and the api's does not. Only the admin
// service keeps one: the api user has no command for it, and nothing of the api's is cleared from the
// console. A bucket key is KeyPrefix + class + ":" + ..., and no class is called "index", so the name
// meets no bucket.
func IndexKey(svc Service) string {
	if svc != Admin {
		return ""
	}
	return KeyPrefix(svc) + "index"
}

// slots turns a class and a subject into the buckets to take from. A class with
// two limits (otp-send) has two slots per key, named by their period, so the
// minute bucket and the hour bucket are independent entries in the store.
func (l *Limiter) slots(c Class, s Subject) []slot {
	prefix := KeyPrefix(l.svc) + c.Name + ":"
	var out []slot
	add := func(kind, id string, factor int) {
		for _, lim := range c.Limits {
			out = append(out, slot{
				key: prefix + kind + ":" + id + ":" + strconv.FormatInt(int64(lim.Per/time.Second), 10),
				max: lim.Max * factor, per: lim.Per,
			})
		}
	}
	switch c.Key {
	case ByNetwork:
		// No client address, no bucket: the pipeline refuses such a request before it
		// gets here, and this is the second wall.
		if s.Network == "" {
			break
		}
		if s.Proof != "" && s.ProofSubject != "" && (c.ProofAlt || c.Held) {
			add("p", s.Proof, 1)
			// A marker names a browser and any account holder can mint one by signing in
			// (a new random id at every login, good for a year), so it cannot stand in for the
			// network by itself: a source that rotates markers would pass every limit of the
			// class with a fresh bucket each time (primitives-r5-8). The request is also charged
			// to the network at a multiple, so returning browsers behind one carrier address keep
			// room and a rotating source meets a ceiling. The plain network bucket, the one
			// strangers fill, is not touched: these keys are their own.
			add("pn", s.Network+"|"+s.ProofSubject, ProofNetFactor)
			if s.Wide != "" {
				add("pw", s.Wide+"|"+s.ProofSubject, ProofNetFactor*WideFactor)
			}
			break
		}
		add("n", s.Network, 1)
		if s.Wide != "" {
			add("w", s.Wide, WideFactor)
		}
	case ByLink:
		if s.Link != "" {
			add("l", s.Link, 1)
		}
	case BySession:
		if s.Session != "" {
			add("s", s.Session, 1)
		}
		if s.TokenSession != "" {
			add("t", s.TokenSession, 1)
		}
		if s.SessionID != "" {
			add("i", s.SessionID, 1)
		}
		if s.Tenant != "" {
			add("T", s.Tenant, 1)
		}
	}
	return out
}

// ErrNoSubject is returned when the subject has no key for the class. The
// middleware that calls Allow has already resolved the address and the session,
// so this is a bug, and refusing is the safe way for a bug to show.
var ErrNoSubject = errors.New("ratelimit: no key for this class")

// Allow charges one request to the class.
func (l *Limiter) Allow(ctx context.Context, c Class, s Subject) (Decision, error) {
	slots := l.slots(c, s)
	if len(slots) == 0 {
		return Decision{}, ErrNoSubject
	}
	if ok, d, used, err := l.viaBackend(ctx, slots, false); used && err == nil {
		return Decision{Allowed: ok, RetryAfter: d}, nil
	}
	if c.FailClosed && !l.localOnly {
		return Decision{}, ErrUnavailable
	}
	ok, d := l.local.take(slots, l.now())
	return Decision{Allowed: ok, RetryAfter: d}, nil
}

// Refund gives back the token Allow took, for the session-lookup class once a
// cookie turned out to belong to a live session (spec 2.3 step 9). A failure is
// ignored: the cost is one token the client would have got back.
func (l *Limiter) Refund(ctx context.Context, c Class, s Subject) {
	slots := l.slots(c, s)
	if len(slots) == 0 {
		return
	}
	if _, _, used, err := l.viaBackend(ctx, slots, true); used && err == nil {
		return
	}
	l.local.give(slots, l.now())
}

// viaBackend runs the call on the backend unless it is absent or cooling down.
// used says whether the backend was asked; err says whether it failed.
func (l *Limiter) viaBackend(ctx context.Context, slots []slot, give bool) (allowed bool, retry time.Duration, used bool, err error) {
	if l.localOnly || l.backend == nil {
		return false, 0, false, nil
	}
	if l.now().UnixNano() < l.downUntil.Load() {
		return false, 0, false, nil
	}
	cctx, cancel := context.WithTimeout(ctx, l.timeout)
	defer cancel()
	if give {
		err = l.backend.Give(cctx, slots)
	} else {
		allowed, retry, err = l.backend.Take(cctx, slots)
	}
	if err != nil {
		if ctx.Err() == nil {
			l.markDown()
		}
		return false, 0, true, err
	}
	return allowed, retry, true, nil
}

// markDown starts the cooldown and warns at most once a minute. The message
// carries no error text: a driver error can name the address it dialled.
func (l *Limiter) markDown() {
	now := l.now()
	l.downUntil.Store(now.Add(l.cooldown).UnixNano())
	last := l.lastWarn.Load()
	if now.UnixNano()-last > int64(time.Minute) && l.lastWarn.CompareAndSwap(last, now.UnixNano()) {
		l.log.Warn("rate limit backend unavailable; using the in-process limiter", logattr.Enum("service", l.svc))
	}
}

// LocalSize is the number of buckets the fallback holds, for tests.
func (l *Limiter) LocalSize() int { return l.local.size() }
