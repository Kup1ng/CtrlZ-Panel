// Package login is what happens once a first factor is proven (spec 5.7), and
// the flows that end in a first factor or a new account: login with an OTP and
// registration (5.6).
//
// One function, AfterFirstFactor, serves password and OTP login, so the rules
// that decide between "passkey required", "second factor needed" and "signed in"
// are written once. The password route (a later work package) calls it after it
// has verified the password.
//
// The transaction order is the point of this package. It opens by locking the
// user row. A re-issue of a one-time password (10.7) and a password change take
// the same lock, so of a login and a re-issue one commits first and the other
// sees it: a login that verified a replaced one-time password cannot open a
// session after the re-issue committed, and a session it opened before is
// revoked by the re-issue (5.7). The mfa ticket is put while the lock is held for
// the same reason: if it were put after the commit, a re-issue could slip in
// between and leave a live ticket for a credential that no longer exists.
package login

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/appclock"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/audit"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/marker"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/otp"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/session"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/ticket"
	"github.com/Kup1ng/CtrlZ-Panel/internal/credgen"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// Status is the "status" of the login response.
type Status string

// The three answers of 5.7.
const (
	Authenticated   Status = "authenticated"
	MFARequired     Status = "mfa_required"
	PasskeyRequired Status = "passkey_required"
)

// Methods offered after a password or OTP when the user has TOTP (6.6).
func mfaMethods() []string { return []string{"totp", "recovery_code"} }

// The first factors. The values are the sessions.auth_method values too.
const (
	Password = "password"
	OTP      = "otp"
)

// Errors. The route maps each to its API error.
var (
	// ErrInvalidCredentials is 401 invalid_credentials: the password path found
	// that what it verified is no longer current (a re-issue, a password change).
	ErrInvalidCredentials = errors.New("login: invalid credentials")
	// ErrAccountSuspended is 403 account_suspended. Only the password path says
	// it: the credentials were right, and the user needs to know why they are out.
	ErrAccountSuspended = errors.New("login: account suspended")
	// ErrRefused is the OTP path meeting a tenant that may not log in. The route
	// answers otp_invalid: a decoy challenge already made this unreachable, so it
	// can only be a state change between the code and its use.
	ErrRefused = errors.New("login: refused")
)

// Service performs login steps.
type Service struct {
	DB       *store.Store
	Auth     store.AuthLookups
	OTP      *otp.Service
	Sessions *session.Manager
	Tickets  *ticket.Service
	// Markers seals the known-device marker (internal/auth/marker).
	Markers *marker.Service
	// Config is the cached public configuration, for the current RP ID.
	Config otp.ConfigFunc
	Now    func() time.Time
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return appclock.Now()
}

// Input describes a proven first factor.
type Input struct {
	// User is what UserByPhone returned before the factor was verified. It is a
	// snapshot: the transaction re-reads what it depends on under the lock.
	User   store.UserLogin
	Factor string // Password or OTP
	// OTPChallenge is the challenge a code just consumed, for the OTP path (it
	// proves the phone, 5.6).
	OTPChallenge uuid.UUID
	Remember     bool
	IP           netip.Addr
	UserAgent    string
	// Rehash is a fresh hash of the password just verified, to store when the
	// stored parameters are out of date (4.1). It is written only with the stamp the
	// password was verified under (User.Cred), because a rehash of the old password
	// after a change would bring the old one back.
	Rehash secret.String
}

// Result is the answer of AfterFirstFactor.
type Result struct {
	Status Status

	// For MFARequired.
	Ticket    secret.String
	TicketTTL time.Duration
	Methods   []string

	// For Authenticated.
	Session    session.Issued
	Restricted bool // the password is a one-time one: the session may only set a new password (3.5)

	// Cookies is everything to set once the response is committed: the session and
	// refresh cookies and the device marker. Set it after the transaction, never
	// before.
	Cookies []*http.Cookie
}

// lock locks the user row. For a password, which was verified outside any transaction,
// the lock and the comparison with the stamp it was verified under are one call.
func (s *Service) lock(tx store.Tx, in Input) (store.UserLock, bool, error) {
	if in.Factor == Password {
		return tx.UserLockFor(in.User.UserID, in.User.Cred)
	}
	return tx.UserLock(in.User.UserID)
}

// AfterFirstFactor applies 5.7.
func (s *Service) AfterFirstFactor(ctx context.Context, in Input) (Result, error) {
	if in.User.TenantStatus != "active" {
		if in.Factor == Password {
			return Result{}, ErrAccountSuspended
		}
		return Result{}, ErrRefused
	}
	cfg, err := s.Config(ctx)
	if err != nil {
		return Result{}, err
	}

	var res Result
	var device credgen.Stamp
	err = s.DB.WithTenant(ctx, in.User.TenantID, store.TxOpts{}, func(tx store.Tx) error {
		res = Result{} // the callback may run only once, but a result must never carry over
		device = credgen.Stamp{}
		// What a password proved is worth what the credentials were when it ran. A
		// one-time password re-issued, a password changed or reset, a second factor enrolled
		// or cleared, the phone moved, the account's Enforce Passkey switched: any credential
		// column that moved moved the generation, by whichever route (internal/credgen).
		// An OTP login is not compared: the code proved the phone, which is what it is for,
		// and everything this transaction goes on to make (the restricted flag, the ticket,
		// the marker) is read from the locked row, not from the snapshot.
		lock, ok, err := s.lock(tx, in)
		if errors.Is(err, credgen.ErrStale) || (err == nil && !ok) {
			return ErrInvalidCredentials
		}
		if err != nil {
			return err
		}
		if in.Factor == OTP {
			out, err := tx.PhoneMarkVerified(in.User.UserID, in.OTPChallenge)
			if err != nil {
				return err
			}
			if out != "ok" {
				return ErrRefused
			}
		}
		// The rehash carries the stamp the password was verified under, and moves the
		// generation (it writes password_hash), so the row is read after it.
		if !in.Rehash.IsZero() && in.Factor == Password {
			if _, err := tx.RehashPassword(in.User.Cred, in.Rehash); errors.Is(err, credgen.ErrStale) {
				return ErrInvalidCredentials
			} else if err != nil {
				return err
			}
		}
		u, ok, err := tx.User(in.User.UserID)
		if err != nil || !ok {
			if err == nil {
				err = ErrInvalidCredentials
			}
			return err
		}

		// Enforce Passkey: in force when it is on, a live credential exists for the
		// current RP ID, and no lift is pending in the future. A stale credential
		// lifts the requirement at once (5.7, 7.4).
		live := 0
		if cfg.PasskeyEnabled && cfg.RPID != "" {
			if live, err = tx.PasskeyLiveCount(u.ID, cfg.RPID); err != nil {
				return err
			}
		}
		now := s.now()
		liftPending := u.EnforceLiftAt != nil && u.EnforceLiftAt.After(now)
		if u.EnforcePasskey && live > 0 && (u.EnforceLiftAt == nil || liftPending) {
			res.Status = PasskeyRequired
			return nil
		}

		if u.TOTPEnabledAt != nil {
			t, err := s.Tickets.PutTx(tx, ticket.Issue{
				Kind: store.TicketMFA, Tenant: tx.TenantID(), User: u.ID, RememberMe: in.Remember, FirstFactor: in.Factor,
				Cred: u.Stamp(),
			})
			if err != nil {
				return err
			}
			res.Status, res.Ticket, res.TicketTTL, res.Methods = MFARequired, t.Token, t.ExpiresIn, mfaMethods()
			return nil
		}

		iss, err := s.open(tx, openInput{
			user: u.ID, remember: in.Remember, method: in.Factor, ip: in.IP, ua: in.UserAgent,
			restricted: lock.State.OneTime(), clearLift: u.EnforcePasskey && u.EnforceLiftAt != nil && !liftPending,
		})
		if err != nil {
			return err
		}
		res.Status, res.Session, res.Restricted = Authenticated, iss, lock.State.OneTime()
		// The marker is bound to the credentials the row has once the session is open:
		// clearing a lapsed Enforce above is itself a credential change.
		if fresh, ok, err := tx.User(u.ID); err != nil {
			return err
		} else if ok {
			device = fresh.Stamp()
		}
		return nil
	})
	if err != nil {
		return Result{}, err
	}
	if res.Status == Authenticated {
		res.Cookies = res.Session.Cookies()
		// The device marker names the account, so the next OTP request from this
		// browser passes the soft breaker (5.5). A failure to seal it must not undo
		// a login that already committed.
		if c, err := s.Markers.Issue(marker.User, device); err == nil {
			res.Cookies = append(res.Cookies, c)
		}
	}
	return res, nil
}

type openInput struct {
	user       uuid.UUID
	remember   bool
	method     string
	ip         netip.Addr
	ua         string
	restricted bool
	// clearLift is true when Enforce was on and its delay has passed: the same
	// transaction turns it off and forgets the lift time (5.7).
	clearLift bool
}

// open creates the session, records the login and writes login.ok, in the
// caller's transaction.
func (s *Service) open(tx store.Tx, in openInput) (session.Issued, error) {
	if in.clearLift {
		if err := tx.SetEnforce(in.user, false); err != nil {
			return session.Issued{}, err
		}
	}
	if err := tx.MarkLogin(in.user); err != nil {
		return session.Issued{}, err
	}
	iss, err := s.Sessions.Create(tx, session.NewSession{
		User: in.user, Remember: in.remember, Restricted: in.restricted, Method: in.method, IP: in.ip, UserAgent: in.ua,
	})
	if err != nil {
		return session.Issued{}, err
	}
	if err := audit.Tenant(tx, in.user, in.ip, audit.LoginOK{Method: audit.MethodOf(in.method), SessionID: iss.SessionID}); err != nil {
		return session.Issued{}, err
	}
	return iss, nil
}

// DeviceCookie builds the known-device marker of a user who has just signed in,
// bound to the stamp the row has now (internal/credgen).
// Call it in the transaction that opened the session, so that a password change
// that lands between the commit and the call cannot hand an intruder a marker of
// the new generation. It returns nil when the marker cannot be made: that must
// not undo a login. Set the cookie after the transaction commits.
func (s *Service) DeviceCookie(tx store.Tx, user uuid.UUID) *http.Cookie {
	u, ok, err := tx.User(user)
	if err != nil || !ok {
		return nil
	}
	c, err := s.Markers.Issue(marker.User, u.Stamp())
	if err != nil {
		return nil
	}
	return c
}

// OpenSession creates a session for a user whose second factor has just passed
// (the TOTP step, a recovery code), in the caller's transaction. It locks the
// user row first, as AfterFirstFactor does, takes the restricted flag from the
// locked row, and clears an Enforce whose delay has passed.
func (s *Service) OpenSession(tx store.Tx, user uuid.UUID, method string, remember bool, ip netip.Addr, ua string) (session.Issued, bool, error) {
	lock, ok, err := tx.UserLock(user)
	if err != nil || !ok {
		if err == nil {
			err = ErrInvalidCredentials
		}
		return session.Issued{}, false, err
	}
	u, ok, err := tx.User(user)
	if err != nil || !ok {
		if err == nil {
			err = ErrInvalidCredentials
		}
		return session.Issued{}, false, err
	}
	lifted := u.EnforcePasskey && u.EnforceLiftAt != nil && !u.EnforceLiftAt.After(s.now())
	iss, err := s.open(tx, openInput{user: user, remember: remember, method: method, ip: ip, ua: ua, restricted: lock.State.OneTime(), clearLift: lifted})
	return iss, lock.State.OneTime(), err
}

// OTPLoginInput is POST /auth/login/otp after the route has counted
// otp_verify_net.
type OTPLoginInput struct {
	Phone       string
	ChallengeID uuid.UUID
	Code        string
	Remember    bool
	IP          netip.Addr
	UserAgent   string
}

// OTPLogin checks the code, finds the account and applies 5.7 with the OTP as
// the first factor (5.6). A non-ok code returns the otp error (ErrInvalid,
// ErrExpired, ErrLocked). The route runs it inside its 200 ms floor.
func (s *Service) OTPLogin(ctx context.Context, in OTPLoginInput) (Result, error) {
	if err := s.OTP.Check(ctx, in.ChallengeID, in.Phone, otp.Login, in.Code); err != nil {
		return Result{}, err
	}
	u, found, err := s.Auth.UserByPhone(ctx, in.Phone)
	if err != nil {
		return Result{}, err
	}
	if !found {
		// A real code for a phone that has no account: only a decoy has no
		// account, and a decoy cannot be consumed. A deleted account, perhaps.
		return Result{}, otp.ErrInvalid
	}
	return s.AfterFirstFactor(ctx, Input{
		User: u, Factor: OTP, OTPChallenge: in.ChallengeID, Remember: in.Remember, IP: in.IP, UserAgent: in.UserAgent,
	})
}

// RegisterInput is POST /auth/register after the route has counted
// otp_verify_net and has checked and hashed the password (a weak password must
// not burn the code, so those come first, 5.6).
type RegisterInput struct {
	Phone       string // for an invite, the invite's own phone
	Via         string // open or invite
	Invite      uuid.UUID
	ChallengeID uuid.UUID
	Code        string
	// PasswordHash is empty for an OTP-only account.
	PasswordHash secret.String
	Locale       string
	IP           netip.Addr
	UserAgent    string
}

// registerPurpose is the OTP purpose of a registration route.
func registerPurpose(via string) otp.Purpose {
	if via == "invite" {
		return otp.Invite
	}
	return otp.Signup
}

// PeekRegisterCode asks whether the challenge, the phone and the code of a
// registration are real, and consumes nothing (a wrong code spends a try). The
// route calls it before it scores and hashes the password: until the code is
// right the caller has proved nothing, and a made-up challenge must not take a
// scoring slot or an Argon2 slot that signed-in users need (review round 4,
// primitives-r4-3). Register then consumes the code as before.
func (s *Service) PeekRegisterCode(ctx context.Context, in RegisterInput) error {
	return s.OTP.Peek(ctx, in.ChallengeID, in.Phone, registerPurpose(in.Via), in.Code)
}

// Register consumes the OTP, creates the tenant and its owner through
// auth_register_user, and opens a session. A refusal of the function, whatever
// its reason (closed registration, a taken phone, a missing or wrong invite),
// is ErrInvalid, the same as a wrong code: only the holder of the SIM reaches
// this state, so it tells them nothing a stranger could use.
func (s *Service) Register(ctx context.Context, in RegisterInput) (Result, error) {
	if err := s.OTP.Check(ctx, in.ChallengeID, in.Phone, registerPurpose(in.Via), in.Code); err != nil {
		return Result{}, err
	}
	reg, ok, err := s.Auth.RegisterUser(ctx, in.Phone, in.PasswordHash.Reveal(), in.Locale, in.Invite, in.ChallengeID)
	if err != nil {
		return Result{}, err
	}
	if !ok {
		return Result{}, otp.ErrInvalid
	}
	var res Result
	var device *http.Cookie
	err = s.DB.WithTenant(ctx, reg.TenantID, store.TxOpts{}, func(tx store.Tx) error {
		if err := audit.Tenant(tx, reg.UserID, in.IP, audit.Register{Via: audit.ViaOf(in.Via)}); err != nil {
			return err
		}
		iss, err := s.open(tx, openInput{user: reg.UserID, method: OTP, ip: in.IP, ua: in.UserAgent})
		if err != nil {
			return err
		}
		res = Result{Status: Authenticated, Session: iss}
		device = s.DeviceCookie(tx, reg.UserID)
		return nil
	})
	if err != nil {
		return Result{}, err
	}
	res.Cookies = res.Session.Cookies()
	if device != nil {
		res.Cookies = append(res.Cookies, device)
	}
	return res, nil
}
