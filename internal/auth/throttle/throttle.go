// Package throttle is the attempt limiter of spec 4.5: counters in Postgres
// (auth_throttle), keyed by an HMAC, so that lockouts hold when Valkey is down
// and a stolen backup does not list who was guessed at.
//
// The service wraps the two function pairs of the store. The api uses the user
// scopes through store.Auth(), under the auth_mac key; the admin service uses the
// admin scopes through store.Admin(), under admin_mac, which the api does not
// hold. The database refuses the wrong pair for a scope as well, so a
// misconfigured call fails instead of resetting another service's counter.
//
// Every scope is declared in internal/budget, with the parts its key is made of.
// Charge and Clear build the key from those parts and from nothing else, and
// refuse an empty part, so a route cannot pick its own key or count on an empty
// address (rule budget-keying). The named entry points below are compositions of
// Charge for the routes that count several scopes together.
package throttle

import (
	"context"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/totp"
	"github.com/Kup1ng/CtrlZ-Panel/internal/budget"
	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
	"github.com/Kup1ng/CtrlZ-Panel/internal/logattr"
	"github.com/Kup1ng/CtrlZ-Panel/internal/netkey"
	"github.com/Kup1ng/CtrlZ-Panel/internal/reqledger"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// Scope is a row group of auth_throttle. Its policy, its key parts and its key
// source are in internal/budget; a test fails for a constant that has no entry
// there.
type Scope string

// The scopes of spec 4.5.
const (
	LoginPhoneNet    Scope = "login_phone_net"        // phone + source network
	LoginPhone       Scope = "login_phone"            // phone
	LoginNet         Scope = "login_net"              // source network
	LoginNet48       Scope = "login_net48"            // IPv6 /48
	LoginMarker      Scope = "login_marker"           // device marker id, for a marker that holds for the account
	TOTPUser         Scope = "totp_user"              // user id; the second factor of a login whose first step was a PASSWORD
	TOTPSMS          Scope = "totp_sms"               // user id; the second factor of a login or a reset whose first step was an SMS code
	TOTPMarker       Scope = "totp_marker"            // device marker id; the second factor asked of a browser whose marker holds for the account
	RecoveryUser     Scope = "recovery_user"          // user id; a recovery code on a PASSWORD ticket, which cannot be walked and has no ceiling
	RecoverySMS      Scope = "recovery_sms"           // user id; a recovery code on a ticket an SMS code opened
	RecoveryMarker   Scope = "recovery_marker"        // device marker id; a recovery code from a browser whose marker holds for the account
	ReauthPasskey    Scope = "reauth_passkey_session" // tenant session id; the passkey assertion asked of a bare session cookie
	ReauthSession    Scope = "reauth_session"         // tenant session id; the proof asked of a bare session cookie
	TOTPSession      Scope = "totp_session"           // tenant session id; the second factor asked of a bare session cookie
	ResetPasskeyUser Scope = "reset_passkey_user"     // user id of a reset ticket; the passkey step of a reset
	OTPVerifyNet     Scope = "otp_verify_net"         // source network
	InviteNet        Scope = "invite_net"             // source network, bad invite tokens only
	InviteNet48      Scope = "invite_net48"           // IPv6 /48, bad invite tokens only
	InviteUse        Scope = "invite_use"             // invite id, live invite tokens

	AdminLogin       Scope = "admin_login"        // username + source network
	AdminLoginUser   Scope = "admin_login_user"   // username
	AdminLoginNet    Scope = "admin_login_net"    // source network
	AdminLoginMarker Scope = "admin_login_marker" // device marker id
	AdminReauth      Scope = "admin_reauth"       // admin id
	AdminTOTP        Scope = "admin_totp"         // admin id; the login and the password change, which proved the password
	AdminTOTPSession Scope = "admin_totp_session" // admin session id; the second factor asked of a bare session cookie
)

// Policy is the limit of a scope.
type Policy struct {
	Max            int
	Window         time.Duration
	ResetOnSuccess bool
}

// PolicyOf returns the limit of a scope, and false for an unknown one.
func PolicyOf(s Scope) (Policy, bool) {
	b, ok := budget.FindScope(string(s))
	if !ok {
		return Policy{}, false
	}
	return Policy{b.Max, b.Window, b.ResetOnSuccess}, true
}

// ErrTooMany is a refused hit. The concrete error is a *TooManyError.
var ErrTooMany = errors.New("throttle: too many attempts")

// errNoClientAddress is a network key made from a zero address. netkey.Net gives
// "" for it, and a "" key would be one shared bucket for every caller without an
// address, so the choke point refuses instead (the route middleware already does;
// this is the second wall, round 4, primitives-r4-1).
var errNoClientAddress = errors.New("throttle: no client address")

// errEmptyKeyPart is any other key part that is missing: an empty phone, a zero
// id. The same reasoning: an empty part is one bucket for everybody who lacks it.
var errEmptyKeyPart = errors.New("throttle: empty key part")

// errUnknownScope is a scope the registry does not know: a bug, not an allowance.
var errUnknownScope = errors.New("throttle: unknown scope")

// TooManyError says how long the window has left.
type TooManyError struct{ RetryAfter time.Duration }

func (*TooManyError) Error() string        { return ErrTooMany.Error() }
func (*TooManyError) Is(target error) bool { return target == ErrTooMany }

// Who is everything a key can be made of. A scope reads the parts its registry
// entry names and nothing else; the caller fills what it has.
type Who struct {
	IP       netip.Addr
	Phone    string    // normalised E.164
	Username string    // an admin username; trimmed and lower-cased here
	User     uuid.UUID // a tenant user
	Admin    uuid.UUID
	Session  uuid.UUID // a session of the service that is live (principal.SessionID, tenant or admin)
	Marker   string    // the id inside a device marker whose seal and subject checked
	Invite   uuid.UUID // an invite that exists and is live
}

// part returns the value of one key part. skip says the part does not apply to
// this client (the IPv6 /48 of an IPv4 address), so the scope is not counted.
func (w Who) part(p budget.Part) (v string, skip bool, err error) {
	switch p {
	case budget.PartNetwork:
		if v = netkey.Net(w.IP); v == "" {
			return "", false, errNoClientAddress
		}
	case budget.PartWide:
		if netkey.Net(w.IP) == "" {
			return "", false, errNoClientAddress
		}
		var ok bool
		if v, ok = netkey.Wide(w.IP); !ok {
			return "", true, nil
		}
	case budget.PartPhone:
		v = w.Phone
	case budget.PartUsername:
		v = strings.ToLower(strings.TrimSpace(w.Username))
	case budget.PartUser:
		if w.User != uuid.Nil {
			v = w.User.String()
		}
	case budget.PartAdmin:
		if w.Admin != uuid.Nil {
			v = w.Admin.String()
		}
	case budget.PartMarker:
		v = w.Marker
	case budget.PartAdminSession, budget.PartUserSession:
		if w.Session != uuid.Nil {
			v = w.Session.String()
		}
	case budget.PartInvite:
		if w.Invite != uuid.Nil {
			v = w.Invite.String()
		}
	default:
		return "", false, errEmptyKeyPart
	}
	if v == "" {
		return "", false, errEmptyKeyPart
	}
	return v, false, nil
}

// Service counts attempts.
type Service struct {
	svc   budget.Service
	hit   func(ctx context.Context, scope string, key []byte, max int, window time.Duration) (store.ThrottleResult, error)
	reset func(ctx context.Context, scope string, key []byte) error
	mac   func(parts ...[]byte) []byte
	// refund gives one attempt back out of the window with this epoch (primitives-r6-2).
	refund func(ctx context.Context, scope string, key []byte, window time.Duration, epoch int64) error
	// onCeiling is told when the long ceiling of a scope refuses (WithCeilingHook).
	onCeiling func(Scope)
	// onRefuse is told, with the bucket and nothing else, each time a window refuses a hit (WithRefusalHook): the
	// data the network bucket numbers are set from (tenant-r18-6, D64 net-bucket-numbers).
	onRefuse func(budget.Bucket)
}

// NewUser is the api's throttle: user scopes, keys under auth_mac.
func NewUser(a store.AuthLookups, ring *keyring.Ring) *Service {
	return &Service{
		svc: budget.Tenant, hit: a.ThrottleHit, reset: a.ThrottleReset, refund: a.ThrottleRefund,
		mac: func(p ...[]byte) []byte { return ring.MAC(keyring.DomainAuthMAC, keyring.LabelThrottle, p...) },
	}
}

// NewAdmin is the admin service's throttle: admin scopes, keys under admin_mac.
func NewAdmin(a store.AdminFns, ring *keyring.Ring) *Service {
	return &Service{
		svc: budget.Admin, hit: a.ThrottleHit, reset: a.ThrottleReset, refund: a.ThrottleRefund,
		mac: func(p ...[]byte) []byte { return ring.MAC(keyring.DomainAdminMAC, keyring.LabelThrottle, p...) },
	}
}

// New builds a Service from parts, for tests. It belongs to no service, so Unlock
// is refused; NewFor names one.
func New(hit func(context.Context, string, []byte, int, time.Duration) (store.ThrottleResult, error),
	reset func(context.Context, string, []byte) error, mac func(...[]byte) []byte) *Service {
	return &Service{hit: hit, reset: reset, mac: mac}
}

// NewFor is New for a named service.
func NewFor(svc budget.Service, hit func(context.Context, string, []byte, int, time.Duration) (store.ThrottleResult, error),
	reset func(context.Context, string, []byte) error, mac func(...[]byte) []byte) *Service {
	return &Service{svc: svc, hit: hit, reset: reset, mac: mac}
}

// keyOf is the 32-byte HMAC of the scope and the registry's parts. The scope is
// part of the input, so one value used under two scopes (a network) has two
// unrelated keys. skip is true when a part does not apply to the client.
func (s *Service) keyOf(sc Scope, w Who) (key []byte, b budget.Bucket, skip bool, err error) {
	return s.keyLabelled(sc, string(sc), w)
}

// ceilingKeyOf is the key of the long ceiling of a scope (budget.Bucket.CeilingMax): the same parts under a
// label of their own, so it never meets the scope's short-window key, and stored under the scope's own
// database name, which the database function already takes.
func (s *Service) ceilingKeyOf(sc Scope, w Who) ([]byte, error) {
	key, _, _, err := s.keyLabelled(sc, ceilingLabel+string(sc), w)
	return key, err
}

// ceilingLabel is what the HMAC of a ceiling key starts with.
const ceilingLabel = "ceiling/"

func (s *Service) keyLabelled(sc Scope, label string, w Who) (key []byte, b budget.Bucket, skip bool, err error) {
	b, ok := budget.FindScope(string(sc))
	if !ok {
		return nil, b, false, errUnknownScope
	}
	in := make([][]byte, 0, len(b.Parts)+1)
	in = append(in, []byte(label))
	for _, p := range b.Parts {
		v, sk, err := w.part(p)
		if err != nil {
			return nil, b, false, err
		}
		if sk {
			return nil, b, true, nil
		}
		in = append(in, []byte(v))
	}
	return s.mac(in...), b, false, nil
}

// Charge counts one attempt on a scope and returns *TooManyError when the limit is
// reached. It is the one way to count: the key is made of the parts the registry
// names for the scope, an empty part is refused (so no caller can share a bucket
// by lacking an address or an id), and an unknown scope is a bug and an error, not
// an allowance. It counts before anything is verified, so a flood cannot reach
// Argon2 (4.5).
func (s *Service) Charge(ctx context.Context, sc Scope, w Who) error {
	key, b, skip, err := s.keyOf(sc, w)
	if err != nil || skip {
		return err
	}
	if err := s.hitKey(ctx, b, key); err != nil {
		return err
	}
	return s.chargeCeiling(ctx, sc, b, w)
}

// ceilingBucket is the bucket of the long ceiling of b: its own limit and window, the scope's database name.
func ceilingBucket(b budget.Bucket) budget.Bucket {
	b.Max, b.Window = b.CeilingMax, b.CeilingWindow
	return b
}

// chargeCeiling counts the attempt on the long ceiling of the scope, if it has one. It runs after the short
// window allowed the attempt: an attempt the short window refused is not a guess and costs the ceiling
// nothing. It is the same Charge for every caller (round 8, primitives-r8-4), so no route can count the
// 15 minutes and forget the day. A full ceiling is the same *TooManyError, with the time the ceiling has
// left, and the hook is told so that the operator sees a run of guesses that the short window alone
// would have let through for ever.
func (s *Service) chargeCeiling(ctx context.Context, sc Scope, b budget.Bucket, w Who) error {
	if b.CeilingMax < 1 {
		return nil
	}
	key, err := s.ceilingKeyOf(sc, w)
	if err != nil {
		return err
	}
	err = s.hitKey(ctx, ceilingBucket(b), key)
	if errors.Is(err, ErrTooMany) && s.onCeiling != nil {
		s.onCeiling(sc)
	}
	return err
}

func (s *Service) hitKey(ctx context.Context, b budget.Bucket, key []byte) error {
	r, err := s.hit(ctx, b.StoreScope(), key, b.Max, b.Window)
	if err != nil {
		return err
	}
	if !r.Allowed {
		if s.onRefuse != nil {
			s.onRefuse(b)
		}
		return &TooManyError{RetryAfter: r.RetryAfter}
	}
	// The window the attempt was counted in goes into the book of the request, so that a refund made
	// by the same request names it. A refused hit is not written: there is nothing to give back.
	if book, ok := reqledger.From(ctx); ok {
		book.Put(ledgerKey(b, key), r.Epoch)
	}
	return nil
}

// ledgerKey names a counted line in the request book: the database scope and the key, which is an
// HMAC, so it holds no phone number and no address.
func ledgerKey(b budget.Bucket, key []byte) string {
	return b.StoreScope() + "/" + hex.EncodeToString(key)
}

// errNoRefund is a refund asked of a service built without one (a test service). A defect of the
// caller, so it is an error and not a silent skip.
var errNoRefund = errors.New("throttle: this service gives no attempt back")

// errNoLedger is a refund made on a context that carries no request book (reqledger). Without one
// the window the attempt was counted in is not known, and a refund that guessed it could take the
// attempt of another request (primitives-r6-2), so it is refused and the attempt stays counted.
var errNoLedger = errors.New("throttle: no request book: the window of the attempt is not known")

// Refund gives one attempt back on a scope, out of the window it was counted in (the epoch the same
// request recorded when it charged, primitives-r6-2). It is for
// an attempt that did no work because the server was busy (proof.Spec.Refund calls it for
// password.ErrBusy and for nothing else): the count comes before the work, and an attempt the
// gate turned away must not stay spent (round 5, tenant-r5-1). It builds the key as Charge
// does, so it can only give back what a Charge with the same parts took. It is oracle neutral:
// the key does not depend on whether the account exists, and neither does the call.
func (s *Service) Refund(ctx context.Context, sc Scope, w Who) error {
	key, b, skip, err := s.keyOf(sc, w)
	if err != nil || skip {
		return err
	}
	if s.refund == nil {
		return errNoRefund
	}
	book, ok := reqledger.From(ctx)
	if !ok {
		return errNoLedger
	}
	// The epoch the same request recorded when it charged: a window that restarted, or a line that
	// was cleared, since the charge is another epoch and is not touched (primitives-r6-2). A request
	// that did not count this key, or whose hit was refused, has nothing to give back.
	epoch, ok := book.Take(ledgerKey(b, key))
	if !ok {
		return nil
	}
	if err := s.refund(ctx, b.StoreScope(), key, b.Window, epoch); err != nil {
		return err
	}
	// The ceiling counted the same attempt in the same request, so it gives it back too.
	if b.CeilingMax < 1 {
		return nil
	}
	ckey, err := s.ceilingKeyOf(sc, w)
	if err != nil {
		return err
	}
	cb := ceilingBucket(b)
	cepoch, ok := book.Take(ledgerKey(cb, ckey))
	if !ok {
		return nil
	}
	return s.refund(ctx, cb.StoreScope(), ckey, cb.Window, cepoch)
}

// Clear resets a scope after a success. Scopes that do not reset on success
// (4.5) are refused here, so a code path cannot clear a network counter.
func (s *Service) Clear(ctx context.Context, sc Scope, w Who) error {
	key, b, skip, err := s.keyOf(sc, w)
	if err != nil || skip {
		return err
	}
	if err := s.resetKey(ctx, b, key); err != nil {
		return err
	}
	// A success ends the run of attempts, so it ends the ceiling's count too (the run since the last success).
	var errs []error
	if b.CeilingMax > 0 {
		ckey, err := s.ceilingKeyOf(sc, w)
		if err != nil {
			return err
		}
		errs = append(errs, s.reset(ctx, b.StoreScope(), ckey))
	}
	return errors.Join(append(errs, s.clearGroup(ctx, b, w))...)
}

// clearGroup ends the long ceilings of the other scopes of b's CeilingGroup, for the same subject: the run of guesses
// at one account's code ends with a right code, whatever proved the first step it was given on (round 9,
// primitives-r9-4). It is the owner's own way out of a ceiling that somebody who held only part of the proofs
// filled, and the console has no command for a tenant account. A member whose key w cannot build (the marker's
// scope when the request carried no marker) is skipped on purpose and not an error: that ceiling belongs to
// one browser, and the same browser's next success ends it. Only the ceiling is ended, never the short window,
// which is the stranger's 15 minutes and not the day.
func (s *Service) clearGroup(ctx context.Context, b budget.Bucket, w Who) error {
	if b.CeilingGroup == "" {
		return nil
	}
	var errs []error
	for _, m := range budget.Group(b.CeilingGroup) {
		if m.Name == b.Name || m.CeilingMax < 1 {
			continue
		}
		ckey, err := s.ceilingKeyOf(Scope(m.Name), w)
		if errors.Is(err, errEmptyKeyPart) {
			continue
		}
		if err != nil {
			errs = append(errs, err)
			continue
		}
		errs = append(errs, s.reset(ctx, m.StoreScope(), ckey))
	}
	return errors.Join(errs...)
}

func (s *Service) resetKey(ctx context.Context, b budget.Bucket, key []byte) error {
	if !b.ResetOnSuccess {
		return errors.New("throttle: scope does not reset on success")
	}
	return s.reset(ctx, b.StoreScope(), key)
}

// Unlock clears every scope the registry marks Unlock for this service, for the
// console commands `unlock` and the two resets (10.1). A key that holds a network
// or a marker cannot be listed from the console, so the whole database scope goes;
// the others are cleared by the exact key from w. Walking the registry means a new
// admin scope is cleared the day it is declared (rule budget-keying).
func (s *Service) Unlock(ctx context.Context, w Who) error {
	if s.svc == "" {
		return errors.New("throttle: unlock needs a service")
	}
	var errs []error
	for _, b := range budget.Of(budget.Throttle, s.svc) {
		if !b.Unlock {
			continue
		}
		whole := false
		for _, p := range b.Parts {
			if p.IsNetwork() || p == budget.PartMarker || p == budget.PartAdminSession || p == budget.PartUserSession {
				whole = true
			}
		}
		if whole {
			// A stranger on the admin's own network (a carrier-grade NAT shares one
			// /24) can fill a network scope, and an `unlock` that prints "unlocked"
			// and leaves it full would be a lie. The counters of strangers on other
			// networks go as well, which costs nothing: the console is the operator.
			errs = append(errs, s.reset(ctx, b.StoreScope(), nil))
			continue
		}
		key, _, _, err := s.keyOf(Scope(b.Name), w)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		errs = append(errs, s.reset(ctx, b.StoreScope(), key))
		if b.CeilingMax > 0 {
			ckey, err := s.ceilingKeyOf(Scope(b.Name), w)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			errs = append(errs, s.reset(ctx, b.StoreScope(), ckey))
		}
	}
	return errors.Join(errs...)
}

// LoginHits counts a password login attempt that carries no device marker proof: the four
// scopes of 4.5, in the order of the table, stopping at the first refusal. phone is the
// normalised E.164 number, and the key does not depend on whether the number has an
// account, so the answer is no oracle. An IPv6 source also counts on its /48.
func (s *Service) LoginHits(ctx context.Context, phone string, ip netip.Addr) error {
	return s.LoginHitsFor(ctx, phone, ip, "")
}

// loginScopes is the one list of scopes a password login counts, and so the one list that is
// given back or cleared. markerID is the id of a device marker that the caller has opened AND
// matched with the account found (marker.Holds), or "": a proof, not a hint.
//
// A marker that holds for the account takes the place of login_phone and of nothing else.
// login_phone is keyed on the phone alone, so a stranger anywhere could spend its 20 an hour
// by typing wrong passwords for the owner's number, and four networks (or one IPv6 /48) were
// enough to keep the owner's right password at 429 for the rest of every hour (round 5,
// tenant-r5-9). The owner's browser holds a marker no stranger can make for this account (the
// seal is ours, the subject and the credential generation are the account's, and a password
// change or any other credential change ends it), so its guesses count on the marker's own
// scope, which follows the browser and not the number. The two network scopes and login_phone_net
// still count: a marker is no proof for a limit on guesses at a network (budget.markerReason),
// and a holder of an old marker still has only the five a network and a phone get.
func loginScopes(markerID string) []Scope {
	phoneScope := LoginPhone
	if markerID != "" {
		phoneScope = LoginMarker
	}
	return []Scope{LoginPhoneNet, phoneScope, LoginNet, LoginNet48}
}

// LoginHitsFor is LoginHits for a request whose device marker holds for the account (markerID,
// or "" for none).
func (s *Service) LoginHitsFor(ctx context.Context, phone string, ip netip.Addr, markerID string) error {
	w := Who{IP: ip, Phone: phone, Marker: markerID}
	for _, sc := range loginScopes(markerID) {
		if err := s.Charge(ctx, sc, w); err != nil {
			return err
		}
	}
	return nil
}

// LoginRefund gives back what LoginHitsFor took, for a login the Argon2 gate turned away. Every
// scope is refunded, the same four that were counted, and a failure of one does not stop the others.
func (s *Service) LoginRefund(ctx context.Context, phone string, ip netip.Addr, markerID string) error {
	w := Who{IP: ip, Phone: phone, Marker: markerID}
	var errs []error
	for _, sc := range loginScopes(markerID) {
		errs = append(errs, s.Refund(ctx, sc, w))
	}
	return errors.Join(errs...)
}

// LoginRefundMalformed is LoginRefund for LoginHitsMalformed.
func (s *Service) LoginRefundMalformed(ctx context.Context, ip netip.Addr) error {
	w := Who{IP: ip}
	return errors.Join(s.Refund(ctx, LoginNet, w), s.Refund(ctx, LoginNet48, w))
}

// LoginHitsMalformed counts a password login attempt whose phone does not
// normalise, on the two network scopes only. Every malformed value used to share
// one login_phone key, so 20 junk requests an hour from anywhere made every
// other client's typo a 429 instead of the 401 of 4.5 step 1 (review round 3,
// tenant-r3-8). A malformed value names no account, so there is no per-phone
// bucket to protect, and the source stays bounded by login_net and login_net48.
func (s *Service) LoginHitsMalformed(ctx context.Context, ip netip.Addr) error {
	w := Who{IP: ip}
	for _, sc := range []Scope{LoginNet, LoginNet48} {
		if err := s.Charge(ctx, sc, w); err != nil {
			return err
		}
	}
	return nil
}

// LoginSuccess is the end of a password login that verified: it clears the scopes marked
// "reset on success" and gives the attempt's own count back on the two network scopes, which
// do not reset (4.5). A network scope counts FAILED guesses: before this, every success also
// spent one, so fifty-one subscribers behind one carrier address group (a /24) who each signed
// in once inside 15 minutes made the fifty-first a 429 with the right password (round 5,
// tenant-r5-3). Giving back only the attempt that was right keeps the bound where it was
// meant to be: an account holder who signs in between guesses gets nothing for the guesses,
// which stay at 50 a window for the address group, and the charge came first so a spent scope
// still refuses the attempt before Argon2.
func (s *Service) LoginSuccess(ctx context.Context, phone string, ip netip.Addr, markerID string) error {
	if netkey.Net(ip) == "" { // before any reset: a half-cleared pair is worse than none
		return errNoClientAddress
	}
	w := Who{IP: ip, Phone: phone, Marker: markerID}
	errs := []error{s.Clear(ctx, LoginPhoneNet, w), s.Clear(ctx, LoginPhone, w)}
	if markerID != "" {
		errs = append(errs, s.Clear(ctx, LoginMarker, w))
	}
	errs = append(errs, s.Refund(ctx, LoginNet, w), s.Refund(ctx, LoginNet48, w))
	return errors.Join(errs...)
}

// OTPVerifyHit counts one OTP check on the network. Only the public routes call
// it (login, register without an invite, reset): a signed-in route has a subject to count on
// (reauth_session) and is never charged to the network.
func (s *Service) OTPVerifyHit(ctx context.Context, ip netip.Addr) error {
	return s.Charge(ctx, OTPVerifyNet, Who{IP: ip})
}

// OTPVerifyRefund gives the check back when it did what the scope is there to count against:
// the code was right, so the attempt was not a guess (round 5, tenant-r5-3), or the server was
// busy and looked at nothing (tenant-r5-1). A wrong code keeps its count. Whoever can send a
// right code has paid an SMS for it, and the five tries a challenge holds and the per-phone caps
// of 5.1 bound that; what the network scope bounds is wrong guesses.
func (s *Service) OTPVerifyRefund(ctx context.Context, ip netip.Addr) error {
	return s.Refund(ctx, OTPVerifyNet, Who{IP: ip})
}

// InviteHit counts one use of an invite token (lookup, code request, register). live is
// the id of the invite when the token turned out to be live, and uuid.Nil when it was
// unknown, used, revoked or expired.
//
// A live invite is a proof, and its uses count on the invite itself whatever network they
// come from: an honest invitee behind a carrier NAT shares nothing with strangers, and
// whoever holds the token and moves networks gets no fresh budget. Anything else is a
// request that proved nothing and counts on the network. The network scope is never
// charged by a live token and so never refuses one (rule budget-keying; rounds 1 to 3
// chose this charge point per route and each choice let somebody spend what an honest
// invitee needed). One entry point decides, so a route cannot choose the other.
func (s *Service) InviteHit(ctx context.Context, ip netip.Addr, live uuid.UUID) error {
	if netkey.Net(ip) == "" {
		return errNoClientAddress
	}
	if live != uuid.Nil {
		return s.Charge(ctx, InviteUse, Who{IP: ip, Invite: live})
	}
	// The /48 first, and its refusal ends the charge: a rotator through the /64s of one allocation spends the /48 and
	// then writes no row per /64 (round 11, tenant-r11-4). An IPv4 address has no /48 and Charge skips the scope.
	w := Who{IP: ip}
	if err := s.Charge(ctx, InviteNet48, w); err != nil {
		return err
	}
	return s.Charge(ctx, InviteNet, w)
}

// AdminLoginHits counts an admin login attempt (4.5, 10.2). markerID is the id of
// a device marker that the caller has opened AND matched with the account found
// (marker.Holds), or "": a proof, not a hint.
//
// Without a proof the attempt counts on three scopes. The first is keyed on the
// username and the network together, so a stranger who learns the username cannot
// lock the real admin out from another network. The second is keyed on the
// username alone and would let that stranger do exactly that from many networks.
// The third bounds the source.
//
// With a proof it counts on the marker's own scope and on none of those three: a
// network scope is never charged by, and never refuses, a request that carries a
// verified proof, and a marker that moves networks does not get a fresh budget
// because the scope is not keyed on one. It still needs the password and the code.
//
// All three scopes are counted on every attempt, and a refusal by any of them is returned as
// refused and not as err: the caller may let one kind of request through it, the right
// console-issued one-time password of an account that has one (120 bits, so nothing a stranger
// can guess, review round 2 admin-r2-7 for the username scope and round 5 admin-r5-11 for the
// two network scopes), and must answer every other request with refused. A stranger on the
// owner's carrier address group (a /24 or /64 shared by thousands) who sends twenty wrong
// logins every fifteen minutes spends admin_login_net, and used to keep the owner's very first
// login out with a 429 that `unlock` could not outrun, because the stranger refills the
// scope in a second. err is a failure of the store, or of a missing address or username.
func (s *Service) AdminLoginHits(ctx context.Context, username string, ip netip.Addr, markerID string) (refused, err error) {
	w := Who{IP: ip, Username: username, Marker: markerID}
	if netkey.Net(ip) == "" {
		return nil, errNoClientAddress
	}
	if markerID != "" {
		return nil, s.Charge(ctx, AdminLoginMarker, w)
	}
	// The narrow pair is charged first and a refusal by it ends the username scope's share: a
	// request that its own network's pair already turned away must not also spend admin_login_user,
	// or one address at its own rate fills the scope every browser without a marker shares, and the
	// owner on a new device (or after any credential change, which ends every marker) gets 429 with
	// the right password (round 6, admin-r6-4: the all-scopes loop of round 5 undid what the narrow
	// scope is for, spec 14.1). The network scope still counts every attempt, since the console
	// one-time password has to be refusable by it as well (admin-r5-11).
	for _, sc := range []Scope{AdminLogin, AdminLoginUser, AdminLoginNet} {
		if sc == AdminLoginUser && refused != nil {
			continue
		}
		switch err := s.Charge(ctx, sc, w); {
		case err == nil:
		case errors.Is(err, ErrTooMany):
			if refused == nil {
				refused = err
			}
		default:
			return nil, err
		}
	}
	return refused, nil
}

// AdminLoginRefund gives back what AdminLoginHits counted, for an attempt whose verify the
// Argon2 gate turned away (primitives-r6-9). Without it, strangers who keep the gate busy with
// unknown usernames spend the owner's five tries on a password nobody looked at. A scope that
// refused the attempt, or that the attempt skipped, has no entry in the request book and is left
// alone. A failure of one scope does not stop the others.
func (s *Service) AdminLoginRefund(ctx context.Context, username string, ip netip.Addr, markerID string) error {
	w := Who{IP: ip, Username: username, Marker: markerID}
	if markerID != "" {
		return s.Refund(ctx, AdminLoginMarker, w)
	}
	var errs []error
	for _, sc := range []Scope{AdminLogin, AdminLoginUser, AdminLoginNet} {
		errs = append(errs, s.Refund(ctx, sc, w))
	}
	return errors.Join(errs...)
}

// AdminLoginSuccess clears the admin scopes that reset on success.
func (s *Service) AdminLoginSuccess(ctx context.Context, username string, ip netip.Addr, markerID string) error {
	if netkey.Net(ip) == "" {
		return errNoClientAddress
	}
	w := Who{IP: ip, Username: username, Marker: markerID}
	if markerID != "" {
		return s.Clear(ctx, AdminLoginMarker, w)
	}
	return errors.Join(s.Clear(ctx, AdminLogin, w), s.Clear(ctx, AdminLoginUser, w))
}

// Spend is the atomic step update of 6.3, supplied by the caller because it runs
// in the caller's transaction: Tx.TOTPStepAccept for a user, GlobalTx.
// AdminTOTPStepAccept for an admin. fresh false means the step was already used.
type Spend func(ctx context.Context, step int64) (fresh bool, err error)

// Charged is the proof that one attempt was counted on a scope for a subject. Only
// ChargeProof makes one (its fields are not exported), so a check that runs inside a
// transaction can demand it and a route cannot reach the check without paying first. It
// replaces a comment ("must already be counted with totpHit") that no test could hold a
// fifth caller to (rule budget-keying, round 5: the charge is a type, on both services).
type Charged struct {
	sc Scope
	w  Who
	ok bool
}

// Holds says the charge was made on this scope for this subject. The zero Charged holds
// nothing, so a request that never charged, or charged another scope or another account,
// is refused.
func (c Charged) Holds(sc Scope, w Who) bool { return c.ok && c.sc == sc && c.w == w }

// ChargeProof counts one attempt like Charge and hands back the proof of it.
func (s *Service) ChargeProof(ctx context.Context, sc Scope, w Who) (Charged, error) {
	if err := s.Charge(ctx, sc, w); err != nil {
		return Charged{}, err
	}
	return Charged{sc: sc, w: w, ok: true}, nil
}

// ErrNotCharged is a check that was reached without the attempt being counted first.
// It is a defect of a route, never of a client, so it is not mapped to any client code.
var ErrNotCharged = errors.New("throttle: the attempt was not counted before the check")

// Counted is the totp.Guard of a check that runs inside a transaction. The attempt was
// counted before the transaction opened (Service.ChargeProof, whose value is c) and is
// cleared after it commits (Service.Clear), so the guard itself never touches the
// throttle: Hit says allowed when c holds for this scope and subject and refuses with
// ErrNotCharged when it does not, Reset does nothing, and Spend runs on the transaction's
// connection. A guard that counted inside the check would ask the pool for a second
// connection while the transaction holds the first (rule one-connection-per-request), and
// a count made on the transaction's own connection would be rolled back with a wrong code.
// There is no other guard: this is the only one a handler can build, and it cannot be
// built without the proof, so totp.Check keeps its "throttle first" order for every caller. That is
// a claim about the whole module, and Go cannot seal an interface across packages, so a lint holds it
// (internal/lint TestRFC6238StaysInsideTheTOTPPackage, round 6, primitives-r6-3 and -6): totp.Check
// and CheckAt are called from two files only, no type outside this package has Hit, Spend and Reset
// or embeds totp.Guard, and no one-time-code library is imported.
func Counted(c Charged, sc Scope, w Who, spend Spend) totp.Guard {
	return counted{spend: spend, charged: c.Holds(sc, w)}
}

type counted struct {
	spend   Spend
	charged bool
}

func (c counted) Hit(context.Context) (bool, time.Duration, error) {
	if !c.charged {
		return false, 0, ErrNotCharged
	}
	return true, 0, nil
}
func (c counted) Spend(ctx context.Context, step int64) (bool, error) {
	return c.spend(ctx, step)
}
func (counted) Reset(context.Context) error { return nil }

// WithCeilingHook returns the service with a function that is told, with the scope and nothing else, each time
// the long ceiling of a second-factor scope refuses (round 8, primitives-r8-4). The server wires it to one closed
// log line: it is how the operator hears of a patient guesser, who is otherwise a run of ordinary wrong codes.
func (s *Service) WithCeilingHook(f func(Scope)) *Service {
	c := *s
	c.onCeiling = f
	return &c
}

// Valid says the scope is one of the constants above, so a Scope can be logged as a closed value (it is a switch
// and not a registry lookup, as every closed type of the module is; a test holds the constants to the registry).
func (s Scope) Valid() bool {
	switch s {
	case LoginPhoneNet, LoginPhone, LoginNet, LoginNet48, LoginMarker, TOTPUser, TOTPSMS, TOTPMarker, RecoveryUser, RecoverySMS, RecoveryMarker, ReauthPasskey, ReauthSession, TOTPSession, ResetPasskeyUser,
		OTPVerifyNet, InviteNet, InviteNet48, InviteUse, AdminLogin, AdminLoginUser, AdminLoginNet, AdminLoginMarker, AdminReauth, AdminTOTP, AdminTOTPSession:
		return true
	}
	return false
}

// WithRefusalHook returns the service with a function that is told, with the bucket and nothing else, each time a
// window (the short one, or the long ceiling of a scope) refuses an attempt. It is what lets the operator count the
// refusals of every network and subject bucket, so that the numbers of the network buckets can be set from data at
// the P4b gate (tenant-r18-6). The hook gets no key, no phone number and no address.
func (s *Service) WithRefusalHook(f func(budget.Bucket)) *Service {
	c := *s
	c.onRefuse = f
	return &c
}

// RefusalLog is the hook both servers pass to WithRefusalHook: it counts the refusal (budget.Refusals) and writes
// one closed line when the count of the bucket reaches a power of two, with the bucket, the kind of key it counts
// on and the count, and nothing else. A nil logger or counter logs nothing and counts nothing.
func RefusalLog(log *slog.Logger, r *budget.Refusals) func(budget.Bucket) {
	return func(b budget.Bucket) {
		if log == nil {
			return
		}
		if n, due := r.Note(b); due {
			log.Warn("a bucket refused an attempt", logattr.Enum("bucket", b.LogName()), logattr.Enum("key_kind", b.KeyKind()), logattr.Int("refusals", int(n)))
		}
	}
}

// WithRefund returns the service with a refund function, for tests that build one from parts.
func (s *Service) WithRefund(f func(ctx context.Context, scope string, key []byte, window time.Duration, epoch int64) error) *Service {
	c := *s
	c.refund = f
	return &c
}

// CeilingLog is the hook both servers pass to WithCeilingHook: one closed line, the scope and nothing
// else (no account, no session, no address). A nil logger logs nothing.
func CeilingLog(log *slog.Logger) func(Scope) {
	return func(sc Scope) {
		if log != nil {
			log.Warn("the long attempt ceiling of a second-factor scope refused", logattr.Enum("scope", sc))
		}
	}
}

// CapRefusalLog is the hook of the OTP caps, which are not a bucket of the registry (the OTP caps of spec 5.1, which
// auth_otp_issue checks): it counts the refusal and writes one closed line at each power of two, with the cap and
// the count and nothing else, the same data RefusalLog gives for the buckets (tenant-r18-19).
func CapRefusalLog(log *slog.Logger, r *budget.Refusals) func(budget.CapName) {
	return func(c budget.CapName) {
		if log == nil {
			return
		}
		if n, due := r.NoteCap(c); due {
			log.Warn("the OTP caps refused a code request", logattr.Enum("cap", c), logattr.Int("refusals", int(n)))
		}
	}
}
