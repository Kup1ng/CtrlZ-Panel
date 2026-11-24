// Package ratelimit is the request rate limiter of the api and admin services
// (spec 14.1, 15.1): a token bucket in Valkey, with an in-process bucket of the
// same numbers when Valkey is down.
//
// It is a speed bump, not the credential defence. Lockouts of passwords, codes
// and OTPs live in Postgres (auth_throttle, sms_counters) and hold without
// Valkey. This layer keeps one source from spending the pool and the Argon2
// gate, which is why the numbers are generous and provisional (D31).
//
// The classes are not declared here. internal/budget is the one registry of every
// bucket and its key source; Classes only turns its rows into Class values, and a
// test fails for a Class literal anywhere else (rule budget-keying).
package ratelimit

import (
	"github.com/Kup1ng/CtrlZ-Panel/internal/budget"
)

// Service names the process a class table belongs to. The two services have a
// class of the same name (session-lookup) with separate counters.
type Service string

// The services.
const (
	Tenant Service = "api"
	Admin  Service = "admin"
)

// KeyKind says what a class counts on.
type KeyKind int

const (
	// ByNetwork counts per source network (IPv4 /24, IPv6 /64, plus a /48 bucket
	// at four times the limit for IPv6). It is for requests with no proof: a class
	// with ProofAlt counts a request that carries a verified proof on the proof
	// instead, and never on the network.
	ByNetwork KeyKind = iota
	// BySession counts per subject or proof id: the resolved session id, or for
	// session-lookup a hash of the cookie. The raw cookie is never a key. There is
	// no key kind for "the whole service": a bucket every stranger can empty for
	// every honest user is not in the closed set of internal/budget.
	BySession
)

// SessionLookup is the class charged for a request that carries a session
// cookie that can have been issued here (its tag checks, session.Manager.Screen),
// before the cookie is looked up (spec 2.3 step 8). It counts per cookie and not
// per source network: a network bucket was shared by every user behind one
// carrier NAT, so one host's junk or one account holder's dead cookie locked the
// live sessions out (round 4, tenant-r4-4). A cookie that fails its tag is never
// charged at all. There is no network bucket for the cookies that miss: round 5 had one
// (session-miss) and it let an account holder who kept the cookies of his ended sessions
// empty the bucket of a shared carrier address and have every live cookie behind it refused
// before its lookup. A cookie that missed is remembered instead (httpx deadSet) and refused with
// no lookup, so what a dead cookie costs is one lookup, and nothing a network spends on cookies
// that prove nothing can refuse one that does (primitives-r6-5).
const SessionLookup = "session-lookup"

// IPClaim is the hourly budget of a tenant for the Plain DNS claim routes (P3 spec 4.5). A handler charges it, by the tenant of
// the live session, after the operation's own class has passed; no operation names it as its rate class.
const IPClaim = "ip-claim"

// ChargedByThePipeline says the pipeline (or, for ip-claim, the handler) charges the class itself, around the session
// lookup, and no operation names it as its rate class.
func ChargedByThePipeline(name string) bool {
	return name == SessionLookup || name == SessionMiss || name == BulkWriteTenant || name == IPClaim
}

// BulkWriteTenant is the day budget of a tenant for the bulk routes (spec 8.1). The pipeline charges it for an operation
// of the class BulkWrite once the session resolved, before the bulk gate takes any memory and before the body is read.
const (
	BulkWrite       = "bulk-write"
	BulkWriteTenant = "bulk-write-tenant"
)

// SessionMiss is the class charged to the session a cookie opens, before the cookie is looked up
// and given back unless the session turned out to be gone for good. It is what bounds the lookups that
// dead cookies can cause once the set that remembers them (httpx deadSet) has forgotten some: every
// dead cookie of one session draws on one budget, whatever number of cookies its rotations made,
// and the cookies of any other session never touch it, those of the same account included (round 7,
// primitives-r7-6; keyed on the account at first, round 8, tenant-r8-3).
const SessionMiss = "session-miss"

// WideFactor is how much larger the IPv6 /48 bucket is than the /64 one: a /48
// holds 65,536 /64s, so it gets room for a handful of honest users but not for
// a rotating attacker.
const WideFactor = 4

// ProofNetFactor is how much room the network gets for requests that carry a device
// marker, as a multiple of the class's limit. A marker is free to mint, so it is a proof of
// a browser and not of the network; five times the plain limit keeps returning browsers
// behind one carrier address from refusing each other and still bounds a source that
// rotates markers (primitives-r5-8). The bucket is the network's AND the account's the marker was
// sealed for (Subject.ProofSubject, primitives-r6-5): the account that rotates its markers meets
// the ceiling, and no other account on the address group is in it.
const ProofNetFactor = 5

// Limit is one bucket: Max requests per Per. A token bucket allows a burst of
// Max and refills at Max/Per.
type Limit = budget.Limit

// Class is a named set of limits. A request must pass every limit of its class.
type Class struct {
	Name   string
	Limits []Limit
	Key    KeyKind
	// FailClosed classes refuse, instead of falling back to the in-process
	// bucket, when Valkey cannot be reached. It is set for the SMS classes only: a
	// per process bucket multiplies the SMS budget by the number of instances (R44).
	FailClosed bool
	// ProofAlt is set on a ByNetwork class whose requests can carry a proof the
	// pipeline checks without I/O (a device marker). Such a request is charged to
	// the proof's bucket, with the same limits, and to a network bucket of its own at
	// ProofNetFactor times the limits, never to the bucket of requests without a proof.
	ProofAlt bool
	// Deferred says the pipeline charges the class and hands a refusal to the handler as a value
	// (httpx.DeferredRefusal) instead of answering with it.
	Deferred bool
	// Held is set on a Deferred ByNetwork class that a proof can stand in for once the handler has shown it
	// holds for the account asked about (budget.Bucket.HeldProof). The pipeline does not use the proof for it:
	// it charges the plain network bucket, and httpx.HeldProofHolds charges the proof's keys, which are the
	// ones ProofAlt classes use, so the limiter builds them for Held as well.
	Held bool
	// HeldInvite: a live invite stands in as well (budget.Bucket.HeldInvite); the pipeline hands every plain
	// refusal of the class over, a request with no marker included.
	HeldInvite bool
}

// Classes returns the class table of a service. All numbers are provisional
// (D31) and are the ones of spec 14.1 and 15.1.
func Classes(s Service) []Class {
	var out []Class
	for _, b := range budget.Of(budget.RateClass, budget.Service(s)) {
		c := Class{Name: b.Name, Limits: b.Limits, FailClosed: b.FailClosed, Deferred: b.Deferred != ""}
		if b.Source == budget.Network {
			c.Key, c.ProofAlt, c.Held, c.HeldInvite = ByNetwork, b.ProofPart != "", b.HeldProof != "", b.HeldInvite
		} else {
			c.Key = BySession
		}
		out = append(out, c)
	}
	return out
}

// Lookup finds a class by name.
func Lookup(s Service, name string) (Class, bool) {
	for _, c := range Classes(s) {
		if c.Name == name {
			return c, true
		}
	}
	return Class{}, false
}

// Valid reports whether s is one of the two services, so a log line may carry it.
func (s Service) Valid() bool { return s == Tenant || s == Admin }

// ClassName is a class name for a log line. The names come from the budget
// registry, which is code, so the set is closed; Valid asks the registry.
type ClassName string

// LogName is the class's name as a ClassName.
func (c Class) LogName() ClassName { return ClassName(c.Name) }

// Valid reports whether n names a class of either service.
func (n ClassName) Valid() bool {
	for _, s := range []Service{Tenant, Admin} {
		if _, ok := Lookup(s, string(n)); ok {
			return true
		}
	}
	return false
}
