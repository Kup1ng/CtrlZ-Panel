// Package otp is the OTP side of login, registration, Forgot Password and phone
// change (spec 5): making a code, sealing it for the worker, asking the database
// to issue a challenge under the daily caps, and checking what the user typed.
//
// It owns four rules that must not be spread across routes.
//
//   - The decoy (5.3). A phone with no account, or a tenant that may not log in,
//     gets a real challenge row with a real code hash and no delivery payload.
//     The 202 body, the cooldown and the caps are the same as for a known phone,
//     so a request tells a stranger nothing. The worker never selects the row, so
//     nothing is sent.
//   - One shape of work (5.4). A known and an unknown phone make the same calls:
//     one UserByPhone and one OTPIssue. The send is always asynchronous. The
//     route wraps Request in its 300 ms floor; this package does not sleep.
//   - The known-device breaker (5.5). A sealed cookie that names the account lets
//     a request pass the soft global breaker and count on its own phone key.
//   - The code never leaves as a plain string. It is a secret.String from
//     crypto/rand until it is sealed, and the stored hash is a keyed MAC.
package otp

import (
	"context"
	"crypto/rand"
	"errors"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/marker"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/proofmac"
	"math/big"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/appclock"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/digits"
	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// Purpose is what a code is for. A code issued for one purpose is refused for
// another by the database (the purpose is part of the hash and of the row).
type Purpose string

// The purposes of otp_challenges.
const (
	Login    Purpose = "login"
	Signup   Purpose = "signup"
	Invite   Purpose = "invite"
	Reset    Purpose = "reset"
	PhoneOld Purpose = "phone_old"
	PhoneNew Purpose = "phone_new"
)

// Timing facts of the challenge. Life is fixed in auth_otp_issue. ResendAfter is
// the cooldown to state when the configuration does not carry one (a unit test); the admin can change it
// (system_settings.otp_cooldown_s, 10 to 3600 s) and auth_public_config hands the real figure to the api,
// which the 202 and the 429 state (round 8, tenant-r8-2).
const (
	CodeLength         = 6
	Life               = keyring.LifeOTP
	DefaultResendAfter = 60 * time.Second
)

// resendAfter is the cooldown to state to the client: the configured one, or the default when the
// configuration carries none.
func resendAfter(cooldown time.Duration) time.Duration {
	if cooldown <= 0 {
		return DefaultResendAfter
	}
	return cooldown
}

// LimitedError is ErrLimited with the wait to tell the client (errors.Is(err, ErrLimited) holds). The
// wait is the configured cooldown whatever the cap that refused (the cooldown, the daily cap of the
// phone or of the network, the soft breaker): the database answers one bit for all of them so that a
// known and an unknown number cannot be told apart by which one refused, and a client that retries
// after the cooldown is at worst refused again, never told more. The figure is the same for every
// phone (round 8, tenant-r8-2).
type LimitedError struct{ RetryAfter time.Duration }

func (*LimitedError) Error() string { return ErrLimited.Error() }

// Is makes a LimitedError match ErrLimited.
func (*LimitedError) Is(target error) bool { return target == ErrLimited }

// Errors. The route maps each to its API error (14.3).
var (
	// ErrLimited is a refused issue: a cap or the cooldown. It is the same for a
	// real and a decoy challenge (429 otp_limited).
	ErrLimited = errors.New("otp: limited")
	// ErrSMSUnavailable means no gateway can deliver, so the request is refused
	// before any cap is spent (503 sms_unavailable). The flag is public.
	ErrSMSUnavailable = errors.New("otp: sms unavailable")
	// ErrRegistrationClosed is a signup while registration_mode is not open (403
	// registration_closed). It is public information anyway.
	ErrRegistrationClosed = errors.New("otp: registration closed")
	// ErrBadPurpose is a purpose the entry point does not serve: a bug in the
	// caller, never a user error.
	ErrBadPurpose = errors.New("otp: purpose not served here")

	// ErrInvalid, ErrExpired and ErrLocked are the non-ok outcomes of Verify
	// (401 otp_invalid, 401 otp_expired, 429 otp_locked).
	ErrInvalid = errors.New("otp: invalid")
	ErrExpired = errors.New("otp: expired")
	ErrLocked  = errors.New("otp: locked")
)

// ConfigFunc reads the public configuration (auth_public_config), cached by the
// caller for 30 seconds. The service needs the SMS availability flag and the
// registration mode.
type ConfigFunc func(ctx context.Context) (store.PublicConfig, error)

// CodeFunc makes a code. It exists so a test can fix the code; production uses
// NewCode.
type CodeFunc func() (secret.String, error)

// Service issues and checks OTPs.
type Service struct {
	auth   store.AuthLookups
	ring   *keyring.Ring
	config ConfigFunc
	code   CodeFunc
	now    func() time.Time
	onCap  func() // told when a daily cap refuses a request (WithCapRefusalHook)
	// tags tags the challenge id the client holds (OpenChallenge), so a request that carries one is charged to it and not to its network.
	tags *proofmac.Signer
}

// Option changes a Service.
type Option func(*Service)

// WithCodeSource replaces the code generator (tests).
func WithCodeSource(f CodeFunc) Option { return func(s *Service) { s.code = f } }

// WithCapRefusalHook is told, with nothing, each time auth_otp_issue turns a code request away (cooldown or cap) (tenant-r18-19). The
// service does not know which cap it was (auth_otp_issue says only "not allowed"), and the hook gets no phone, no
// address and no challenge. It runs after the answer is decided and cannot change it.
func WithCapRefusalHook(f func()) Option { return func(s *Service) { s.onCap = f } }

// WithClock replaces the wall clock (device cookie age).
func WithClock(now func() time.Time) Option { return func(s *Service) { s.now = now } }

// New returns a Service. ring must hold auth_mac and otp_delivery, the two
// domains the api has for OTPs.
func New(auth store.AuthLookups, ring *keyring.Ring, config ConfigFunc, opts ...Option) (*Service, error) {
	if err := ring.Require(keyring.DomainAuthMAC, keyring.DomainOTPDelivery); err != nil {
		return nil, err
	}
	s := &Service{auth: auth, ring: ring, config: config, code: NewCode, now: appclock.Now}
	for _, o := range opts {
		o(s)
	}
	// After the options: the tag clock is the service's, and a test that moves it moves the expiry of the ids too.
	tags, err := proofmac.New(ring, func() time.Time { return s.now() })
	if err != nil {
		return nil, err
	}
	s.tags = tags
	return s, nil
}

// NewCode returns six digits, uniform, from crypto/rand. Leading zeros are kept:
// the code is text, and an integer would drop them (the reason SendOtp of
// Melipayamak is not used).
func NewCode() (secret.String, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return secret.String{}, err
	}
	d := n.String()
	return secret.New(strings.Repeat("0", CodeLength-len(d)) + d), nil
}

// hash is the stored form of a code: a keyed MAC over phone, purpose and code,
// under the auth_mac key. The raw key never leaves the keyring.
func (s *Service) hash(phone string, p Purpose, code string) []byte {
	return store.OTPCodeHash(func(b []byte) []byte {
		return s.ring.MAC(keyring.DomainAuthMAC, keyring.LabelOTP, b)
	}, phone, string(p), code)
}

// Challenge is the answer to an accepted request. The fields are the 202 body.
type Challenge struct {
	ID uuid.UUID
	// Token is what the client holds and sends back as challenge_id: the id under a tag that names the challenge's own row
	// id and the expiry (proofmac, D64 nat-proof-tag; never the phone, which would be an equality oracle). A decoy
	// carries one like a real one, so the tag says nothing about the account. Every public route takes the Token; ID is
	// the row the database knows.
	Token       string
	ExpiresIn   time.Duration
	ResendAfter time.Duration
}

// issue is the one place that talks to auth_otp_issue. template is the message
// to deliver; decoy means nothing is delivered at all.
func (s *Service) issue(ctx context.Context, cooldown time.Duration, phone string, p Purpose, template, locale string, decoy, trusted bool, ip netip.Addr) (Challenge, error) {
	code, err := s.code()
	if err != nil {
		return Challenge{}, err
	}
	// The hash the row will hold is also what the delivery text is bound to (sms.SealOTP), so it is
	// made once and handed to both.
	codeHash := s.hash(phone, p, code.Reveal())
	var ct []byte
	if !decoy {
		// account_exists carries no code, but the row still needs a code hash: the
		// real owner of the number gets a message, and nobody can ever consume this
		// challenge because nobody holds its code.
		send := code
		if n, _ := sms.PlaceholderCount(template); n == 0 {
			send = secret.String{}
		}
		ct, err = sms.SealOTP(s.ring, phone, string(p), codeHash, sms.OTPDelivery{Template: template, Locale: locale, Code: send})
		if err != nil {
			return Challenge{}, err
		}
	}
	res, err := s.auth.OTPIssue(ctx, phone, string(p), codeHash, ct, ip, trusted && !decoy)
	if err != nil {
		return Challenge{}, err
	}
	if !res.Allowed {
		if s.onCap != nil {
			s.onCap()
		}
		return Challenge{}, &LimitedError{RetryAfter: resendAfter(cooldown)}
	}
	tok, err := s.tags.Mint(proofmac.Challenge, res.ID, challengeRef(res.ID), s.now().Add(Life))
	if err != nil {
		return Challenge{}, err
	}
	return Challenge{ID: res.ID, Token: tok.Reveal(), ExpiresIn: Life, ResendAfter: resendAfter(cooldown)}, nil
}

// challengeRef is the reference part of a challenge token: the row id and four zero bytes, so one challenge has one
// spelling.
func challengeRef(id uuid.UUID) []byte {
	ref := make([]byte, proofmac.RefLen)
	copy(ref, id[:])
	return ref
}

// ChallengeRef is a challenge id the client sent back, once its tag and expiry check.
type ChallengeRef struct {
	// ID is the row to ask the database about.
	ID uuid.UUID
	// ProofID and Subject are what a rate class and a throttle scope charge the request to (proofmac.Body).
	ProofID, Subject string
}

// OpenChallenge reads the challenge_id of a request with no I/O. ok is false for a text this service did not issue or one
// past its life; the route charges the network, as for any request that proved nothing, and answers with
// ChallengeLapsed's verdict: otp_expired for a genuine id past its life, otp_invalid for anything else.
func (s *Service) OpenChallenge(text string) (ChallengeRef, bool) {
	b, ok := s.tags.Open(proofmac.Challenge, text)
	if !ok {
		return ChallengeRef{}, false
	}
	id, err := uuid.FromBytes(b.Ref[:16])
	if err != nil || id == uuid.Nil {
		return ChallengeRef{}, false
	}
	return ChallengeRef{ID: id, ProofID: b.ProofID(proofmac.Challenge), Subject: b.SubjectKey(proofmac.Challenge)}, true
}

// ChallengeLapsed reports whether text is a challenge_id this service issued whose life has run out. The tag expiry is
// taken after the row is written, so it is never earlier than the row's own, and a lapsed id is what the database would
// answer otp_expired for (5.4; P1 auth review round 20, tenant-r20-1).
func (s *Service) ChallengeLapsed(text string) bool {
	return s.tags.Lapsed(proofmac.Challenge, text)
}

// available is the check that runs before any lookup or cap (5.4).
func (s *Service) available(ctx context.Context) (store.PublicConfig, error) {
	cfg, err := s.config(ctx)
	if err != nil {
		return store.PublicConfig{}, err
	}
	if !cfg.SMSAvailable {
		return store.PublicConfig{}, ErrSMSUnavailable
	}
	return cfg, nil
}

// Request is POST /auth/otp/request for the purposes a visitor can ask for.
type Request struct {
	Phone   string  // E.164, already normalised
	Purpose Purpose // Login, Reset, Signup or Invite
	Locale  string  // fa or en
	IP      netip.Addr
	// Device is the marker the device cookie held, or the zero Marker. Pass the result of
	// marker.Service.Open(marker.User, ...); it counts only when it holds for the account
	// found, by subject and credential generation (internal/credgen).
	Device marker.Marker
	// NetworkGate is the network speed bump of the route, settled once the account of the phone is known
	// (budget.Bucket.HeldProof, round 8, tenant-r8-4). The route's pipeline charged the plain network
	// bucket before the handler and handed over its refusal; only here is it known whether the device
	// marker holds for this phone's account. held is that fact, and the gate answers with the refusal to
	// return (nil lets the request on): a marker that holds is charged to its own buckets and not to the
	// network's, anything else keeps the plain bucket's answer. It is called for every request that gets
	// this far, known phone or not, so the call itself says nothing about the account. Nil means no gate.
	NetworkGate func(held bool) error
}

// Request issues a challenge for login, reset, signup or invite, applying the
// table of 5.3. For an invite the caller has already checked the invite and
// takes the phone from it; this method never sees the request's own phone there.
func (s *Service) Request(ctx context.Context, r Request) (Challenge, error) {
	if !sms.ValidLocale(r.Locale) {
		r.Locale = "fa"
	}
	switch r.Purpose {
	case Login, Reset, Signup, Invite:
	default:
		return Challenge{}, ErrBadPurpose
	}
	cfg, err := s.available(ctx)
	if err != nil {
		return Challenge{}, err
	}
	if r.Purpose == Signup && cfg.RegistrationMode != "open" {
		return Challenge{}, ErrRegistrationClosed
	}
	user, known, err := s.auth.UserByPhone(ctx, r.Phone)
	if err != nil {
		return Challenge{}, err
	}
	template, decoy := plan(r.Purpose, known, user.TenantStatus)
	// A device cookie counts only for the account it was issued to, and only for
	// the purposes that act on that account.
	trusted := known && !decoy && (r.Purpose == Login || r.Purpose == Reset) && r.Device.Holds(user.Cred)
	if r.NetworkGate != nil {
		if err := r.NetworkGate(trusted); err != nil {
			return Challenge{}, err
		}
	}
	return s.issue(ctx, cfg.OTPCooldown, r.Phone, r.Purpose, template, r.Locale, decoy, trusted, r.IP)
}

// plan is the table of 5.3 for the four public purposes.
func plan(p Purpose, known bool, tenantStatus string) (template string, decoy bool) {
	switch p {
	case Login:
		if known && tenantStatus == "active" {
			return sms.TemplateOTP, false
		}
		return sms.TemplateOTP, true
	case Reset:
		if known && tenantStatus == "active" {
			return sms.TemplateOTPReset, false
		}
		return sms.TemplateOTPReset, true
	case Signup, Invite:
		// The real owner of a taken number gets a message saying so, and a
		// requester without the SIM learns nothing.
		if known {
			return sms.TemplateAccountExists, false
		}
		return sms.TemplateOTP, false
	}
	return "", true
}

// SessionPurpose is a challenge sent to the number of a signed-in user.
type SessionPurpose int

// The two challenges that go to the session's own number.
const (
	// ForReauth is POST /auth/reauth/otp/request: purpose login, template otp.
	ForReauth SessionPurpose = iota
	// ForPhoneOld is the old-number half of a phone change: purpose phone_old.
	ForPhoneOld
)

// RequestForSession issues a challenge to the signed-in user's own number. There
// is no decoy: the session proves the account, so nothing is learned from the
// answer. The request counts on the trusted phone key, since a signed-in user is
// a known device by definition, and passes the soft breaker.
func (s *Service) RequestForSession(ctx context.Context, kind SessionPurpose, phone, locale string, ip netip.Addr) (Challenge, error) {
	if !sms.ValidLocale(locale) {
		locale = "fa"
	}
	cfg, err := s.available(ctx)
	if err != nil {
		return Challenge{}, err
	}
	switch kind {
	case ForReauth:
		return s.issue(ctx, cfg.OTPCooldown, phone, Login, sms.TemplateOTP, locale, false, true, ip)
	case ForPhoneOld:
		return s.issue(ctx, cfg.OTPCooldown, phone, PhoneOld, sms.TemplateOTPPhone, locale, false, true, ip)
	}
	return Challenge{}, ErrBadPurpose
}

// RequestNewPhone issues the new-number half of a phone change. A number that
// belongs to someone else gets a decoy, so no message reaches a third party and
// the answer is the same (5.3). The caller has checked that the number differs
// from the current one.
func (s *Service) RequestNewPhone(ctx context.Context, newPhone, locale string, ip netip.Addr) (Challenge, error) {
	if !sms.ValidLocale(locale) {
		locale = "fa"
	}
	cfg, err := s.available(ctx)
	if err != nil {
		return Challenge{}, err
	}
	_, taken, err := s.auth.UserByPhone(ctx, newPhone)
	if err != nil {
		return Challenge{}, err
	}
	return s.issue(ctx, cfg.OTPCooldown, newPhone, PhoneNew, sms.TemplateOTPPhone, locale, taken, false, ip)
}

// Outcome is what auth_otp_consume said.
type Outcome string

// The outcomes of auth_otp_consume.
const (
	OK       Outcome = "ok"
	Invalid  Outcome = "invalid"
	Expired  Outcome = "expired"
	Consumed Outcome = "consumed"
	Locked   Outcome = "locked"
)

// Err turns an outcome into the error of 5.4: invalid is otp_invalid, expired and
// consumed are otp_expired, locked is otp_locked. OK is nil. An outcome the
// service does not know is invalid.
func (o Outcome) Err() error {
	switch o {
	case OK:
		return nil
	case Expired, Consumed:
		return ErrExpired
	case Locked:
		return ErrLocked
	}
	return ErrInvalid
}

// NormalizeCode folds the digits people type (Persian, Arabic, fullwidth) to
// ASCII and drops the spaces and hyphens they group them with. It does not
// check the length: a short or long code is hashed like any other and fails
// there, so a malformed code costs the same try as a wrong one.
func NormalizeCode(raw string) string {
	// Over-long input is refused, not cut (round 14, primitives-r14-1): cutting at 64 bytes read a code
	// behind a long run of invisible marks as junk and ignored whatever followed byte 64, while the
	// authenticator and recovery codes refused. The empty string is hashed like any wrong code.
	if len(raw) > digits.MaxTypedBytes {
		return ""
	}
	// digits.Typed is the fold every typed code shares (primitives-r13-1); what
	// is left here is the grouping people write digits with.
	var b strings.Builder
	for _, r := range digits.Typed(raw) {
		if r == ' ' || r == '-' {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// Verify checks a code against the challenge it was issued for. The database
// compares the id, phone and purpose with the row, spends one of five tries, and
// answers with an outcome; a wrong phone or purpose is a free "invalid". The
// caller has already counted otp_verify_net (5.4).
func (s *Service) Verify(ctx context.Context, id uuid.UUID, phone string, p Purpose, code string) (Outcome, error) {
	out, err := s.auth.OTPConsume(ctx, id, phone, string(p), s.hash(phone, p, NormalizeCode(code)))
	if err != nil {
		return "", err
	}
	return Outcome(out), nil
}

// Check is Verify reduced to an error: nil when the code is right.
func (s *Service) Check(ctx context.Context, id uuid.UUID, phone string, p Purpose, code string) error {
	o, err := s.Verify(ctx, id, phone, p, code)
	if err != nil {
		return err
	}
	return o.Err()
}

// Peek is Check that does not consume a right code. A wrong code spends a try as
// in Check. POST /auth/register calls it before it scores and hashes the password,
// so a made-up challenge never reaches the Argon2 and scoring gates that password
// logins share, and then calls Check to consume the code (review round 4,
// primitives-r4-3). A right code stays usable, so the route that peeks must also
// consume or fail.
func (s *Service) Peek(ctx context.Context, id uuid.UUID, phone string, p Purpose, code string) error {
	out, err := s.auth.OTPCheck(ctx, id, phone, string(p), s.hash(phone, p, NormalizeCode(code)))
	if err != nil {
		return err
	}
	return Outcome(out).Err()
}
