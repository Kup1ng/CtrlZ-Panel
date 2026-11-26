// Package budget is the one registry of every bucket that counts requests or
// attempts in the api and admin services (P1 auth review round 5, rule
// budget-keying; spec 14.1, 15.1, 4.5).
//
// Two layers count, and both are declared here and nowhere else:
//
//   - rate classes (internal/ratelimit): token buckets in Valkey, a speed bump
//     per request;
//   - throttle scopes (internal/auth/throttle): counters in Postgres, the guess
//     limits of credentials and codes.
//
// Why a registry. Each route used to choose its own key and its own charge
// point, and the same findings came back for four rounds: a bucket that
// strangers could fill was shared with honest users (the invite network budget,
// the global passkey-begin cap, the malformed-phone key, the junk-cookie lookup,
// the admin username scope), a budget keyed on the network let a stolen cookie
// escape by moving networks, and `unlock` cleared a hand-written list. The rule
// that removes the class:
//
//  1. A bucket has a key SOURCE from a closed set: the subject (an account, a
//     session), a proof (a cookie whose tag or seal checked, a verified invite),
//     or the network, which is only for requests that carry no proof.
//  2. The key comes from the strongest proof the request carries, after a cheap
//     check (a MAC tag or a seal, no I/O). A network bucket is never charged by,
//     and never refuses, a request that carries a verified proof: that request
//     charges the bucket of its proof instead (ProofBucket, or ProofPart for a
//     rate class).
//  3. A client address is required and must be non-empty; the throttle refuses an
//     empty key part at its one choke point.
//  4. Every verify path has a subject-keyed bound (Verifies).
//  5. `unlock` and the resets clear scopes by walking this registry (Unlock).
//
// There is no "global" source. A bucket that the whole world shares is a bucket
// every stranger can empty for every honest user, so it is not in the closed set.
//
// The package imports nothing of the services. ratelimit.Classes and
// throttle.PolicyOf are built from it, so a bucket cannot exist without an
// entry, and internal/budget's tests walk the source tree and fail for a Class
// literal or a Scope constant that has none.
package budget

import (
	"sync"
	"time"
)

// Service is the process a bucket belongs to. The values are those of
// ratelimit.Service.
type Service string

// The services.
const (
	Tenant Service = "api"
	Admin  Service = "admin"
)

// Layer says which counter holds a bucket.
type Layer int

const (
	// RateClass is a token bucket of internal/ratelimit.
	RateClass Layer = iota + 1
	// Throttle is a scope of auth_throttle (internal/auth/throttle).
	Throttle
)

// Source is what a bucket counts on. The set is closed on purpose.
type Source int

const (
	// Subject is the thing the request acts for: an account, a phone number being
	// guessed at, a session. It does not change when the caller moves networks.
	Subject Source = iota + 1
	// Proof is a value the request carries that was checked cheaply (a MAC tag or
	// a seal) or looked up and found live: a session cookie, a device marker, an
	// invite.
	Proof
	// Network is the source network. It is for requests with no proof.
	Network
)

func (s Source) String() string {
	switch s {
	case Subject:
		return "subject"
	case Proof:
		return "proof"
	case Network:
		return "network"
	}
	return "invalid"
}

// Part is one component of a key. The set is closed, and a key is the list of
// parts the registry names for its bucket, in that order.
type Part string

// The parts.
const (
	PartNetwork      Part = "network"       // netkey.Net of the client: IPv4 /24, IPv6 /64
	PartWide         Part = "wide"          // netkey.Wide: the IPv6 /48
	PartPhone        Part = "phone"         // an E.164 number as typed, normalised
	PartUsername     Part = "username"      // an admin username, lower case
	PartUser         Part = "user"          // a tenant user id
	PartAdmin        Part = "admin"         // an admin id
	PartSession      Part = "session"       // a session, by the lookup key of its cookie (session.Manager.Screen)
	PartCookie       Part = "cookie"        // a hash of a session cookie whose tag checked
	PartTokenSession Part = "token_session" // the id of the session a cookie opens, read from the body its tag covers (session.Manager.Screen); live or dead
	PartMarker       Part = "marker"        // the random id inside a device marker whose seal checked
	PartAdminSession Part = "admin_session" // the id of an admin session whose cookie checked and that is live
	PartInvite       Part = "invite"        // the id inside an invite link whose signature checked
	PartUserSession  Part = "user_session"  // the id of a tenant session whose cookie checked and that is live (session.Principal.SessionID)
	PartTenant       Part = "tenant"        // the tenant id of a live session (the bulk-write day budget, the lock budget of a tenant, spec 7.1, 8.1)
	PartProfile      Part = "profile"       // a profile of the session's own tenant: the tenant id with the profile id (the unlock scope, spec 7.2)
	PartChallenge    Part = "challenge"     // the id of an OTP challenge whose tag checked (otp.Service.OpenChallenge)
	PartLink         Part = "link"          // the id of the row a share link or an Apple profile download link names, read from the value whose tag checked (internal/auth/bearer, P3 7.1)
	PartToken        Part = "token"         // the id of the API token a bearer value names, read from the value whose tag checked (internal/auth/bearer, P3 6.2, 6.3)
)

// IsNetwork says the part is made from the client address.
func (p Part) IsNetwork() bool { return p == PartNetwork || p == PartWide }

// Limit is one token bucket: Max requests per Per.
type Limit struct {
	Max int
	Per time.Duration
}

// Bucket is one declared counter.
type Bucket struct {
	Layer   Layer
	Service Service
	// Name is the class name or the scope name.
	Name string
	// Store is the scope as the database knows it, when it differs from Name. The
	// closed scope lists of auth_throttle_hit and auth_throttle_reset name the
	// scopes of migration 0011; a bucket that the rule added is kept under the
	// scope of the bucket it belongs with, with a key of its own (the logical name
	// is part of the key, so two buckets never share a counter).
	Store  string
	Source Source
	// Parts is what the key is made of, in order. A Network bucket has a network
	// part; a Subject or Proof bucket has none unless Narrow is set.
	Parts []Part
	// Narrow marks a Subject bucket whose key also holds the network, on purpose:
	// a stranger who learns the subject must not be able to lock the owner out from
	// the owner's own network (login_phone_net, admin_login). The subject-only
	// bucket beside it is the budget that bounds a guess spread over many networks.
	Narrow bool

	// Limits are the token buckets of a rate class (otp-send has two).
	Limits []Limit
	// FailClosed classes refuse when Valkey cannot be reached.
	FailClosed bool

	// Max, Window and ResetOnSuccess are the policy of a throttle scope.
	Max            int
	Window         time.Duration
	ResetOnSuccess bool

	// CeilingMax and CeilingWindow are the long ceiling of a throttle scope that only a holder of the first
	// factor or of a session can charge (round 8, primitives-r8-4). The scope's own window (15 minutes)
	// refills, so a patient guesser at a six digit code (three codes match out of a million) keeps 480
	// guesses a day for ever, which is about a 41% chance of a hit within a year; the ceiling is a second
	// count of the same attempts, on a key of its own, that a window restart does not refill: when it is
	// full the scope refuses until it ends, a success clears it (what is counted is the run of attempts
	// since the last success, as NIST SP 800-63B 5.2.2 asks), and `ctrlz-admin unlock` clears it for an
	// admin. throttle.Service.Charge, Refund and Clear apply it to every caller of the scope, so no route
	// can count the short window and forget the long one. The window is a day at most, the longest the
	// database function takes.
	CeilingMax    int
	CeilingWindow time.Duration
	// CeilingGroup names the scopes that count the guesses of ONE subject at ONE secret and differ only in WHAT
	// proved the first step (round 9, primitives-r9-4). The ceiling of a second factor is keyed on what the
	// charging request proved, never on the account alone: a request whose first step was an SMS code (an OTP
	// login, a reset ticket) is not the owner's password login, and an SMS-only holder (a SIM swap) who filled
	// the account's one ceiling locked the owner out of the second factor, recovery codes included, for a day at
	// a time with twenty requests. So a password ticket, an SMS ticket and a device marker that holds each have a
	// scope and a ceiling of their own, and the group says they are one run of guesses for the NIST rule "since
	// the last success": a success on any member ends the ceilings of the others (throttle.Service.Clear), which
	// is the owner's own way out of a full ceiling when no operator command exists for a tenant account. A
	// member that holds no ceiling (the recovery code, NoCeiling) is in the group too, because its success ends
	// the run as well.
	CeilingGroup string
	// Door names what proved the first step for a member of a CeilingGroup: DoorPassword (a password ticket), DoorSMS (a
	// ticket an SMS code opened) or DoorMarker (a device marker that holds). The code and the recovery code of one door
	// are counted on scopes of their own, and a test holds the two in step: a door that has a scope for the code and none
	// for the recovery code (or the reverse) is a window that every proof holder can fill for the owner (round 10,
	// tenant-r10-2: recovery_user was keyed on the account alone, so a password phisher or a SIM swapper kept the owner's
	// recovery codes refused, the one thing round 9 had promised he would keep).
	Door string
	// NoCeiling is the reason a scope that only a proof holder can charge has no long ceiling (what it
	// guesses at cannot be walked: a passkey assertion, a strong password). The registry test refuses a
	// scope of that kind with neither a ceiling nor a reason, so a new one cannot be added without
	// deciding.
	NoCeiling string

	// ProofPart: for a Network RATE CLASS, the proof that takes the network's place
	// when the request carries one. The class is then charged to a bucket keyed on
	// the proof, with the same limits, and the network is not charged.
	ProofPart Part
	// ProofBucket: for a Network or Narrow THROTTLE scope, the scope that a request
	// carrying a proof charges instead.
	ProofBucket string
	// HeldProof: for a Deferred Network RATE CLASS, the proof that takes the network's place once the HANDLER
	// has shown that it holds for the account the request is about (a device marker, held by the phone's
	// account: same subject, same credential generation). The pipeline cannot tell: the phone is in the
	// body, and reading it is the handler's job. So the pipeline charges the plain network bucket as for any
	// other request and hands the refusal over as a value (Deferred); a handler that finds the proof holds
	// asks httpx.HeldProofHolds, which charges the proof's own bucket and the proof-network bucket (the
	// ProofPart keys: the marker id, and the network with the account the seal names at ProofNetFactor times
	// the limit) and gives the plain token back, so the request neither spends nor is refused by the bucket
	// strangers on the network fill. A proof that does not hold for the account stands in for nothing: the
	// marker is free to mint for ANY account, so only a marker held by the phone asked for may take this
	// place (round 8, tenant-r8-4).
	HeldProof Part

	// HeldInvite: for a HeldProof class, says an invite link whose signature checks takes the network's place as well
	// (round 9, tenant-r9-1; D67). The pipeline cannot open the link of an otp request (the purpose and the token are
	// in the body, and the handler reads them), so it hands over the plain refusal of a request with no marker too
	// (it costs the schema check and the decode, in process, and no I/O), and the handler asks
	// httpx.InviteProofHolds once the link is opened in process: the invite's own buckets (keyed on the invite id, the
	// ProofPart keys of the class) are charged, the plain token is given back, and a token that does not open gets the
	// plain bucket's answer. A request that is not an invite request is answered with the refusal before anything is
	// read. Without it a closed-mode invitee on a carrier /24 that strangers had filled could not get the code that
	// registration needs (rule budget-keying: a network bucket never refuses a live proof).
	HeldInvite bool
	// NoProof is the reason a Network or Narrow bucket has neither: what the
	// requests behind it could prove, and why that is not enough to stand in for
	// the network. Exactly one of ProofPart, ProofBucket, HeldProof and NoProof is set on such
	// a bucket.
	NoProof string

	// Deferred is, for a Network RATE CLASS, the reason the pipeline does not refuse with it. The
	// class is charged before the body is read and the refusal is handed to the handler as a value
	// (httpx.DeferredRefusal), because only the handler can tell the one request this bucket must
	// let through: the right console-issued one-time password of the admin login, which no
	// pipeline step can see (round 7, admin-r7-1; the class form of admin-r2-7 and admin-r5-11).
	// A route of such a class must ask for the value, or the class never refuses it at all
	// (internal/budget TestADeferredClassIsAnsweredByItsHandler).
	Deferred string

	// DeferredGate names the function the handler of a deferred class (without HeldProof) calls to
	// decide, from the request alone, whether it can be the one request the class lets through. Every
	// other request is answered with the refusal BEFORE the handler reads the store, hashes or waits
	// out a floor: the pipeline used to answer at once, and the deferral must not turn a refused
	// request into database work (round 8, admin-r8-1 and -4). The gate may not depend on any
	// account, or it would be an oracle. internal/budget TestADeferredHandlerRefusesBeforeItWorks reads
	// the handler's calls in order, and requires the gate to be the condition of an `if !gate(...)`
	// that returns the refusal, with nothing but secret.New in its arguments.
	DeferredGate string

	// DeferredBound names the non-blocking bound (a slot, as `slots.try()`) that a request which
	// passed DeferredGate must take before the handler reads anything: the gate is a shape, and a
	// flood of well-shaped junk from one source would otherwise tie up the small pool of the service
	// (round 9, admin-r9-3; the per-source half of admin-r8-4). The handler must answer the refusal
	// when the bound says no. Declared with the gate and checked by the same test.
	DeferredBound string

	// SessionReach marks a scope that a request carrying nothing but a session cookie can charge: a
	// route behind a session that counts a guess at a second factor or a password before, or
	// instead of, proving anything the cookie does not already say. Whoever holds a copy of the
	// cookie can spend such a scope, so it must not be one that a login (a request with no
	// session) is refused by, or the cookie locks the account's owner out of the front door
	// (round 6, admin-r6-5; internal/budget TestNoScopeASessionCanSpendRefusesAPublicRoute).
	SessionReach bool

	// Unlock marks a scope that `ctrlz-admin unlock` and the reset commands clear.
	Unlock bool
}

// StoreScope is the scope the database stores the bucket under.
func (b Bucket) StoreScope() string {
	if b.Store != "" {
		return b.Store
	}
	return b.Name
}

// HasNetwork says the key holds the client's network.
func (b Bucket) HasNetwork() bool {
	for _, p := range b.Parts {
		if p.IsNetwork() {
			return true
		}
	}
	return false
}

func perMin(n int) []Limit { return []Limit{{Max: n, Per: time.Minute}} }

const (
	m15 = 15 * time.Minute
	d24 = 24 * time.Hour

	// The long ceilings of the second-factor scopes: tries since the last success, per day. A tenant account
	// gets twenty, an admin ten (the owner of the panel is the one account whose second factor is the whole
	// barrier once the password leaks, D12, and has `unlock`). A person who mistypes a code does it a few times
	// between two successes, and a success clears the count.
	ceilingTenant = 20
	ceilingAdmin  = 10

	// markerReason is shared by the buckets that a device marker cannot stand in for.
	markerReason = "a device marker names a browser, not the account being guessed at, and any account holder " +
		"can mint one by signing in, so it cannot take the place of the network in a limit on guesses"
)

// All returns every bucket. It is a function, not a variable, so that nothing can
// change the registry at run time. The numbers are provisional (D31).
func All() []Bucket {
	return []Bucket{
		// ---- tenant rate classes (spec 14.1) ----
		{Layer: RateClass, Service: Tenant, Name: "public-read", Source: Network, Parts: []Part{PartNetwork, PartWide}, Limits: perMin(60),
			NoProof: "GET /auth/config is public and asks for nothing, so there is nothing a request could prove"},
		// The page without a login reads it from the browser, behind carrier NAT where a /24 is shared by many people, so it
		// has a class of its own at ten times public-read's number (p4-nodes 9.3, Plan T-556). Open, like every read class.
		{Layer: RateClass, Service: Tenant, Name: "public-free-dns", Source: Network, Parts: []Part{PartNetwork, PartWide}, Limits: perMin(600),
			NoProof: "GET /public/free-dns is public and asks for nothing, so there is nothing a request could prove"},
		{Layer: RateClass, Service: Tenant, Name: "auth", Source: Network, Parts: []Part{PartNetwork, PartWide}, Limits: perMin(20),
			ProofPart: PartMarker},
		{Layer: RateClass, Service: Tenant, Name: "otp-send", Source: Network, Parts: []Part{PartNetwork, PartWide},
			Limits: []Limit{{Max: 5, Per: time.Minute}, {Max: 30, Per: time.Hour}}, FailClosed: true,
			// A marker is free to mint for ANY account, so a marker alone cannot stand in for the network here
			// (every message costs money). A marker that the phone's own account holds can: the owner on a known
			// device must not be refused by strangers who fill the carrier /24 with junk requests, or an account
			// with no password and no passkey cannot sign in at all (round 8, tenant-r8-4; spec 4.5, 5.5).
			HeldProof: PartMarker, HeldInvite: true,
			Deferred: "whether the marker holds for the account of the phone asked for is known only once the handler has read " +
				"the phone and the account, so the pipeline charges the plain bucket and hands the refusal over; a request whose " +
				"marker holds, and an invite link whose signature checks (purpose invite, the only way into a closed registration; the row is read after, and a used or revoked one still passes here), is let through on its own buckets and given its plain token back, every other is refused"},
		{Layer: RateClass, Service: Tenant, Name: "otp-send-user", Source: Subject, Parts: []Part{PartSession},
			Limits: []Limit{{Max: 5, Per: time.Minute}, {Max: 30, Per: time.Hour}}, FailClosed: true},
		{Layer: RateClass, Service: Tenant, Name: "user-read", Source: Subject, Parts: []Part{PartSession}, Limits: perMin(300)},
		{Layer: RateClass, Service: Tenant, Name: "user-write", Source: Subject, Parts: []Part{PartSession}, Limits: perMin(60)},
		{Layer: RateClass, Service: Tenant, Name: "sensitive", Source: Subject, Parts: []Part{PartSession}, Limits: perMin(10)},
		// Import, Duplicate, Upload and both batch routes (spec 8.1): 10 a minute per session, and 200 a day per tenant, so the
		// replays and job results a tenant keeps for 24 hours are bounded however many sessions it holds. The tenant bucket is
		// charged by the pipeline once the session resolved, before the bulk gate and the body.
		{Layer: RateClass, Service: Tenant, Name: "bulk-write", Source: Subject, Parts: []Part{PartSession}, Limits: perMin(10)},
		{Layer: RateClass, Service: Tenant, Name: "bulk-write-tenant", Source: Subject, Parts: []Part{PartTenant}, Limits: []Limit{{Max: 200, Per: d24}}},
		// Every claim request, release and challenge open of a tenant, from any of its sessions (P3 spec 4.5, T-529): the only bound on how
		// many released rows a tenant accumulates. The pipeline charges it after the operation's own class (x-ctrlz-rate-also), on the tenant of the live session.
		{Layer: RateClass, Service: Tenant, Name: "ip-claim", Source: Subject, Parts: []Part{PartTenant}, Limits: []Limit{{Max: 30, Per: time.Hour}}},
		// POST /feedback (P3 9.1, T-125): 20 a day per tenant from any of its sessions, so a tenant cannot fill feedback_items however many
		// sessions it holds. Charged by the pipeline after user-write (x-ctrlz-rate-also), on the tenant of the live session.
		{Layer: RateClass, Service: Tenant, Name: "feedback", Source: Subject, Parts: []Part{PartTenant}, Limits: []Limit{{Max: 20, Per: d24}}},
		// Share and download links (P3 7.1, 7.2, 9.1). The three public routes carry a bearer value whose tag the pipeline checks
		// with no I/O; a value that checks is charged to the row it names, 30 a minute, and no network bucket is charged
		// (a value is minted only by its tenant, so what a stranger holds is dead values, which cost at most this a minute per
		// row and are bounded in number by link-create). The create routes of a link are `link-write` (60 a minute per session,
		// as user-write) and the tenant's day budget `link-create`, 200 a day, which bounds the rows whose values can pass the
		// check; Valkey down refuses (503 service_unavailable) because a bound that fails open is no bound.
		{Layer: RateClass, Service: Tenant, Name: "public-link", Source: Proof, Parts: []Part{PartLink}, Limits: perMin(30)},
		{Layer: RateClass, Service: Tenant, Name: "link-write", Source: Subject, Parts: []Part{PartSession}, Limits: perMin(60)},
		{Layer: RateClass, Service: Tenant, Name: "link-create", Source: Subject, Parts: []Part{PartTenant}, Limits: []Limit{{Max: 200, Per: d24}}, FailClosed: true},
		// API tokens (P3 6.2, 6.3, 9.1). A bearer value whose tag and expiry check names its row, and that id is the key of the three
		// classes the pipeline charges before any lookup: the class of the operation (token-read or token-write), then token-miss, which
		// is given back for a token that proves live, so a holder of dead values spends only what each value's own row allows and never
		// a budget that another token shares. token-tenant is the one bound a tenant's tokens share (600 a minute), charged once the lookup
		// found the tenant. token-create (20 a day per tenant) bounds how many ids can ever pass the check, and is closed for the same
		// reason link-create is: a bound that fails open is no bound.
		{Layer: RateClass, Service: Tenant, Name: "token-miss", Source: Proof, Parts: []Part{PartToken}, Limits: perMin(30)},
		{Layer: RateClass, Service: Tenant, Name: "token-read", Source: Proof, Parts: []Part{PartToken}, Limits: perMin(300)},
		{Layer: RateClass, Service: Tenant, Name: "token-write", Source: Proof, Parts: []Part{PartToken}, Limits: perMin(60)},
		{Layer: RateClass, Service: Tenant, Name: "token-tenant", Source: Subject, Parts: []Part{PartTenant}, Limits: perMin(600)},
		{Layer: RateClass, Service: Tenant, Name: "token-create", Source: Subject, Parts: []Part{PartTenant}, Limits: []Limit{{Max: 20, Per: d24}}, FailClosed: true},
		{Layer: RateClass, Service: Tenant, Name: "session-lookup", Source: Proof, Parts: []Part{PartCookie}, Limits: perMin(120)},
		// What dead cookies can cost in lookups once the dead set has forgotten some: one budget per session, taken
		// before the lookup and given back unless the session is gone for good (round 7, primitives-r7-6; keyed on the
		// session and not the account, round 8, tenant-r8-3).
		{Layer: RateClass, Service: Tenant, Name: "session-miss", Source: Proof, Parts: []Part{PartTokenSession}, Limits: perMin(30)},

		// ---- admin rate classes (spec 15.1) ----
		{Layer: RateClass, Service: Admin, Name: "admin-login", Source: Network, Parts: []Part{PartNetwork, PartWide}, Limits: perMin(5),
			ProofPart: PartMarker,
			Deferred: "the first login after bootstrap or a console reset has no device marker, and the right console one-time " +
				"password (120 bits) is the one request a neighbour on the owner's /24 must not be able to refuse; only the " +
				"handler can tell it from the rest, so the pipeline hands it the refusal instead of answering 429 itself",
			DeferredGate: "MayBeOneTime", DeferredBound: "try"},
		{Layer: RateClass, Service: Admin, Name: "admin-read", Source: Subject, Parts: []Part{PartSession}, Limits: perMin(300)},
		{Layer: RateClass, Service: Admin, Name: "admin-write", Source: Subject, Parts: []Part{PartSession}, Limits: perMin(60)},
		{Layer: RateClass, Service: Admin, Name: "session-lookup", Source: Proof, Parts: []Part{PartCookie}, Limits: perMin(120)},
		{Layer: RateClass, Service: Admin, Name: "session-miss", Source: Proof, Parts: []Part{PartTokenSession}, Limits: perMin(30)},

		// ---- tenant throttle scopes (spec 4.5) ----
		{Layer: Throttle, Service: Tenant, Name: "login_phone_net", Source: Subject, Narrow: true, Parts: []Part{PartPhone, PartNetwork},
			Max: 5, Window: m15, ResetOnSuccess: true, NoProof: markerReason},
		{Layer: Throttle, Service: Tenant, Name: "login_phone", Source: Subject, Parts: []Part{PartPhone},
			Max: 20, Window: time.Hour, ResetOnSuccess: true},
		// A device marker that holds for the account takes the place of login_phone (and of nothing
		// else) for a password login. login_phone is keyed on the phone alone and anybody anywhere
		// can fill it; this one follows the owner's browser (round 5, tenant-r5-9). The scope is
		// stored under the name login_phone: the key is an HMAC over the scope's own name and the
		// marker id, so it cannot meet a phone's key, and the database needs no new name.
		{Layer: Throttle, Service: Tenant, Name: "login_marker", Store: "login_phone", Source: Proof, Parts: []Part{PartMarker},
			Max: 10, Window: m15, ResetOnSuccess: true},
		{Layer: Throttle, Service: Tenant, Name: "login_net", Source: Network, Parts: []Part{PartNetwork},
			Max: 50, Window: m15, NoProof: markerReason},
		{Layer: Throttle, Service: Tenant, Name: "login_net48", Source: Network, Parts: []Part{PartWide},
			Max: 200, Window: m15, NoProof: markerReason},
		// totp_user is what the login (POST /auth/login/totp) and the reset (POST /auth/password/reset/complete)
		// are refused by, so only a request that holds a proof of the account's first step may charge it:
		// a login ticket, a reset ticket. A request that holds a session cookie and nothing else charges
		// totp_session (round 7, tenant-r7-2: the tenant twin of admin-r6-5).
		//
		// The ceiling of the code is split by what proved the first step (round 9, primitives-r9-4; Bucket.CeilingGroup):
		// totp_user is the mfa ticket of a PASSWORD login (the owner's usual door, and the phisher's), totp_sms the
		// ticket that an SMS code opened (an OTP login of an account with an authenticator, a reset ticket: all an
		// SIM-swapper holds), totp_marker the browser whose device marker holds for the account (a proof of an earlier
		// full login, which no stranger can mint). Each has its own window and its own ceiling, so whoever fills one
		// does not touch the others.
		{Layer: Throttle, Service: Tenant, Name: "totp_user", Source: Subject, Parts: []Part{PartUser},
			Max: 5, Window: m15, ResetOnSuccess: true,
			CeilingMax: ceilingTenant, CeilingWindow: d24, CeilingGroup: groupTOTP, Door: DoorPassword},
		{Layer: Throttle, Service: Tenant, Name: "totp_sms", Store: "totp_user", Source: Subject, Parts: []Part{PartUser},
			Max: 5, Window: m15, ResetOnSuccess: true,
			CeilingMax: ceilingTenant, CeilingWindow: d24, CeilingGroup: groupTOTP, Door: DoorSMS},
		// The marker id is the key, and the handler charges it only for a marker that holds for the account (same
		// subject, same credential generation), so it is spent by the owner's browser and by nobody who is not in it.
		{Layer: Throttle, Service: Tenant, Name: "totp_marker", Store: "totp_user", Source: Proof, Parts: []Part{PartMarker},
			Max: 5, Window: m15, ResetOnSuccess: true,
			CeilingMax: ceilingTenant, CeilingWindow: d24, CeilingGroup: groupTOTP, Door: DoorMarker},
		// Recovery codes have scopes of their own: 80 bits cannot be walked, so no ceiling (the registry's own rule
		// for what cannot be walked), and a full ceiling of the code must not refuse the owner's escape route. The
		// window stays because a try costs a hash and a database read. The window is keyed by the DOOR, like the code
		// scopes above and for the same reason (round 10, tenant-r10-2): one scope per account let a password phisher
		// or a SIM swapper spend five tries every fifteen minutes and keep the owner's recovery code refused on every
		// door, the only way in for an owner who lost his authenticator. TestEveryDoorHasARecoveryScopeAndACodeScope
		// holds the two sets in step.
		{Layer: Throttle, Service: Tenant, Name: "recovery_user", Store: "totp_user", Source: Subject, Parts: []Part{PartUser},
			Max: 5, Window: m15, ResetOnSuccess: true, CeilingGroup: groupTOTP, Door: DoorPassword,
			NoCeiling: noCeilingRecovery},
		{Layer: Throttle, Service: Tenant, Name: "recovery_sms", Store: "totp_user", Source: Subject, Parts: []Part{PartUser},
			Max: 5, Window: m15, ResetOnSuccess: true, CeilingGroup: groupTOTP, Door: DoorSMS,
			NoCeiling: noCeilingRecovery},
		{Layer: Throttle, Service: Tenant, Name: "recovery_marker", Store: "totp_user", Source: Proof, Parts: []Part{PartMarker},
			Max: 5, Window: m15, ResetOnSuccess: true, CeilingGroup: groupTOTP, Door: DoorMarker}, // a marker scope needs no reason: a stranger cannot charge it
		// The second factor asked of a session that holds nothing but its cookie (POST /account/password
		// for a session with no reauth window, POST /account/totp/confirm, the code of a reauth). Keyed on
		// the session id, which a rotation of the cookie keeps; stored under totp_user (the key is an HMAC
		// over the scope's own name, so it meets no other key and the database needs no new name).
		{Layer: Throttle, Service: Tenant, Name: "totp_session", Store: "totp_user", Source: Subject, Parts: []Part{PartUserSession},
			Max: 5, Window: m15, ResetOnSuccess: true, SessionReach: true,
			CeilingMax: ceilingTenant, CeilingWindow: d24},
		// The password, the code or the passkey asked of a session that holds nothing but its cookie
		// (POST /auth/reauth, POST /auth/reauth/passkey/finish, POST /account/phone/change/{id}/confirm). It
		// was reauth_user, keyed on the user, and any copy of a cookie spent it for the owner's other
		// sessions and for the reset by passkey that shares it (tenant-r7-2, -7).
		{Layer: Throttle, Service: Tenant, Name: "reauth_session", Store: "reauth_user", Source: Subject, Parts: []Part{PartUserSession},
			Max: 5, Window: m15, ResetOnSuccess: true, SessionReach: true,
			CeilingMax: ceilingTenant, CeilingWindow: d24},
		// The passkey step of a password reset (POST /auth/password/reset/passkey/finish), charged by the
		// holder of a reset ticket after the ticket was read, keyed on the ticket's user. No session route
		// charges it, so no cookie can spend it.
		// The passkey assertion asked of a session that holds nothing but its cookie (POST /auth/reauth/passkey/finish):
		// a scope of its own, because the assertion cannot be walked and counted on reauth_session it spent the day's
		// ceiling of the PASSWORD and the code, so a copy of the cookie shut the owner's session out of reauth for a
		// day with twenty useless assertions (round 9, primitives-r9-4).
		{Layer: Throttle, Service: Tenant, Name: "reauth_passkey_session", Store: "reauth_user", Source: Subject, Parts: []Part{PartUserSession},
			Max: 5, Window: m15, ResetOnSuccess: true, SessionReach: true,
			NoCeiling: noCeilingPasskey},
		{Layer: Throttle, Service: Tenant, Name: "reset_passkey_user", Store: "reauth_user", Source: Subject, Parts: []Part{PartUser},
			Max: 5, Window: m15, ResetOnSuccess: true,
			NoCeiling: noCeilingPasskey},
		{Layer: Throttle, Service: Tenant, Name: "otp_verify_net", Source: Network, Parts: []Part{PartNetwork},
			Max: 30, Window: m15, ProofBucket: "otp_verify_challenge"},
		// What a code check counts on once the challenge id it carries has shown its tag (D64 nat-proof-tag, round 19): the
		// challenge, not the network, so strangers on a carrier /24 cannot refuse an honest user who holds a challenge. It is
		// keyed on the challenge and not on the phone it names: anybody can ask a challenge for any phone, so a phone's own
		// bucket would let a stranger who knows a number refuse its owner. Stored under otp_verify_net like login_marker is
		// stored under login_phone: the key is an HMAC over the scope's own name.
		{Layer: Throttle, Service: Tenant, Name: "otp_verify_challenge", Store: "otp_verify_net", Source: Proof, Parts: []Part{PartChallenge},
			Max: 30, Window: m15},
		// Every use of an invite link whose signature checks (D67), keyed on the id inside it. A link that does not check
		// is refused in process with no row, so there is no scope for a bad token: the network class of the route bounds
		// what a stranger can ask. The database scope stays "invite_net", the name its CHECK knows.
		{Layer: Throttle, Service: Tenant, Name: "invite_use", Store: "invite_net", Source: Proof, Parts: []Part{PartInvite},
			Max: 30, Window: m15},

		// The password of a locked profile (spec 7.2): five failures in 15 minutes per profile, keyed on the tenant of the
		// session and the profile, so another tenant's attempts land in its own bucket. A success clears it.
		{Layer: Throttle, Service: Tenant, Name: "profile_unlock", Source: Subject, Parts: []Part{PartProfile},
			Max: 5, Window: m15, ResetOnSuccess: true, SessionReach: true,
			NoCeiling: "the lock password is a convenience of the account's own user, bounded as a whole by profile_lock_tenant (20 attempts an hour for the tenant, never cleared by a success), so a walk over one profile is bounded by that"},
		// Every lock and unlock attempt of a tenant (spec 7.1), charged before any hash or verify, that no success clears:
		// lock and unlock cycles from many sessions of one tenant stop here, and another tenant's login keeps its gate slot.
		{Layer: Throttle, Service: Tenant, Name: "profile_lock_tenant", Source: Subject, Parts: []Part{PartTenant},
			Max: 20, Window: time.Hour, SessionReach: true,
			NoCeiling: "it is itself the long budget: 20 attempts an hour for the whole tenant, and no success clears it"},

		// ---- admin throttle scopes (spec 10.2) ----
		{Layer: Throttle, Service: Admin, Name: "admin_login", Source: Subject, Narrow: true, Parts: []Part{PartUsername, PartNetwork},
			Max: 5, Window: m15, ResetOnSuccess: true, Unlock: true, ProofBucket: "admin_login_marker"},
		{Layer: Throttle, Service: Admin, Name: "admin_login_user", Source: Subject, Parts: []Part{PartUsername},
			Max: 30, Window: m15, ResetOnSuccess: true, Unlock: true},
		{Layer: Throttle, Service: Admin, Name: "admin_login_net", Source: Network, Parts: []Part{PartNetwork},
			Max: 20, Window: m15, Unlock: true, ProofBucket: "admin_login_marker"},
		{Layer: Throttle, Service: Admin, Name: "admin_login_marker", Store: "admin_login", Source: Proof, Parts: []Part{PartMarker},
			Max: 10, Window: m15, ResetOnSuccess: true, Unlock: true},
		{Layer: Throttle, Service: Admin, Name: "admin_reauth", Store: "admin_login", Source: Subject, Parts: []Part{PartAdmin},
			Max: 5, Window: m15, ResetOnSuccess: true, Unlock: true, SessionReach: true,
			NoCeiling: "the password of an admin is at least 14 characters and scored (4.2, 4.3), so a walk over it is not feasible at 480 tries a day; the session is a copy of a cookie, and the scope is keyed on the admin"},
		// admin_totp is what the login is refused by after a right password, so only a request that has
		// proved the password may charge it (the login, and POST /me/password after its password check).
		{Layer: Throttle, Service: Admin, Name: "admin_totp", Source: Subject, Parts: []Part{PartAdmin},
			Max: 5, Window: m15, ResetOnSuccess: true, Unlock: true,
			CeilingMax: ceilingAdmin, CeilingWindow: d24},
		// The second factor asked of a live session that holds nothing but its cookie (POST
		// /auth/totp/fresh, POST /me/totp/confirm). A scope of its own, keyed on the session: charged
		// to admin_totp, a copy of the cookie with no authenticator behind it spent the owner's login
		// for as long as the session lived (round 6, admin-r6-5). Stored under admin_login like
		// admin_reauth (the key is an HMAC over the scope's own name, so it meets no other key and the
		// database needs no new name).
		{Layer: Throttle, Service: Admin, Name: "admin_totp_session", Store: "admin_login", Source: Subject, Parts: []Part{PartAdminSession},
			Max: 5, Window: m15, ResetOnSuccess: true, Unlock: true, SessionReach: true,
			CeilingMax: ceilingAdmin, CeilingWindow: d24},
	}
}

// bucketKey is how the index finds a bucket.
type bucketKey struct {
	l    Layer
	s    Service
	name string
}

// registryIndex is All() built once. All is a literal that allocates about sixty buckets with their parts, limits and reasons
// on every call, and Find and BucketName.Valid sit on the path of every refused request, which is the path a flood takes
// (tenant-r19-4). The index is read-only: nothing writes to it after it is built, and its buckets share their slices with the
// one copy, so a caller must not change what Find returns (no caller does; All still hands out a copy of its own).
var registryIndex = sync.OnceValue(func() (idx struct {
	by    map[bucketKey]Bucket
	all   []Bucket // every bucket in order, for BucketName.Valid (a scan of the names and no allocation)
	scope map[string]Bucket
}) {
	idx.by, idx.scope = map[bucketKey]Bucket{}, map[string]Bucket{}
	for _, b := range All() {
		if _, seen := idx.scope[b.Name]; !seen && b.Layer == Throttle {
			idx.scope[b.Name] = b // the first, as the loop it replaces found it
		}
		idx.by[bucketKey{b.Layer, b.Service, b.Name}] = b
		idx.all = append(idx.all, b)
	}
	return idx
})

// Find returns the bucket of a layer, service and name. The slices of the result belong to the registry: read them, do not change them.
func Find(l Layer, s Service, name string) (Bucket, bool) {
	b, ok := registryIndex().by[bucketKey{l, s, name}]
	return b, ok
}

// FindScope returns the throttle scope of that name in either service.
func FindScope(name string) (Bucket, bool) {
	b, ok := registryIndex().scope[name]
	return b, ok
}

// Group returns the throttle scopes of a ceiling group.
func Group(name string) []Bucket {
	var out []Bucket
	for _, b := range All() {
		if b.Layer == Throttle && b.CeilingGroup == name {
			out = append(out, b)
		}
	}
	return out
}

// Of returns the buckets of a layer and service.
func Of(l Layer, s Service) []Bucket {
	var out []Bucket
	for _, b := range All() {
		if b.Layer == l && b.Service == s {
			out = append(out, b)
		}
	}
	return out
}

func (l Layer) String() string {
	if l == RateClass {
		return "class"
	}
	return "scope"
}

// GateBucket is a bucket that is a pool of slots and not a counter: the Argon2 gate of a
// service (internal/auth/password.Gate). It is in the registry because it is the one bucket
// that the whole world shares by construction. Every unproved login runs a hash in it (an unknown
// username runs the dummy hash), so a stranger who keeps its slots busy refuses everybody else's
// hashes, the owner's included, with a 503. Rule budget-keying says a bucket never refuses a
// request that carries a verified proof, and the counters honour it by keying on the proof;
// a pool cannot be keyed, so it honours it by order: a request with a proof is served before any
// stranger, except on every plainEvery-th grant, which belongs to the strangers' queue, so a lane that
// holders of proofs keep full for ever cannot refuse every request without one (round 5, admin-r5-9;
// round 7, primitives-r7-4, TestAbuseAGateLaneNeverOwnsTheGate).
type GateBucket struct {
	Service Service
	Name    string
	// Proofs are the proofs that take the priority lane (password.Proved), from the closed
	// set of parts. Empty when the service has not wired the lane yet; NoLane then says why. The Work
	// step of a proof.Spec whose Check passed (a code, a ticket, an invite) is in the lane of both
	// services too: proof.Run gives it, once (proof TestOnlyAProofThatWasLookedAtTakesTheGateLane).
	Proofs []Part
	NoLane string
	// PerSubject says the lane takes one hash per account at a time (password.ProvedAs), so that one account
	// holder with many sessions cannot hold the lane. NoSubject is the reason a gate whose lane serves
	// proofs that can be used again does not (round 7, tenant-r7-6). A lane has exactly one of the two.
	PerSubject bool
	NoSubject  string
}

// Gates returns every gate. A service with no row fails TestGateRowsAreOnePerService, a row with neither a lane
// nor a reason fails TestAbuseGateServesProofsBeforeStrangers, and one whose lane is wired is driven
// there; the callers that may ask for the lane are a list, internal/lint TestGatePriorityIsGivenOnlyByProofs.
func Gates() []GateBucket {
	return []GateBucket{
		{Service: Admin, Name: "argon2", Proofs: []Part{PartMarker, PartSession},
			NoSubject: "admin accounts are made at the console by the owner and the gate has one slot, so a bound per account would be a bound on the owner"},
		{Service: Tenant, Name: "argon2", Proofs: []Part{PartMarker, PartSession}, PerSubject: true},
	}
}

// groupTOTP is the CeilingGroup of the tenant's second-factor scopes: one run of guesses at one account's code.
const groupTOTP = "totp"

// The doors of a CeilingGroup member (Bucket.Door).
const (
	DoorPassword = "password"
	DoorSMS      = "sms"
	DoorMarker   = "marker"
)

// noCeilingRecovery is the reason of the scope that counts recovery codes: 80 bits of a random code cannot be walked.
const noCeilingRecovery = "it counts recovery codes, which are 80 random bits and cannot be walked, and a full ceiling of the code must not refuse the owner's way out"

// noCeilingPasskey is the reason of the scopes that count passkey assertions: a signature over a
// 256-bit challenge cannot be walked, so the 15-minute window only bounds the cost of checking them.
const noCeilingPasskey = "it counts passkey assertions, which are signatures over a 256-bit challenge and cannot be walked"
