package api

import (
	"context"
	"errors"
	"net/http"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/api/gen"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/audit"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/login"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/marker"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/phone"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/proof"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/recovery"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/session"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/throttle"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/totp"
	"github.com/Kup1ng/CtrlZ-Panel/internal/credgen"
	"github.com/Kup1ng/CtrlZ-Panel/internal/httpx"
	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// factorCharge is the throttle charge of a second-factor check. The check itself runs in
// a transaction, and a transaction holds the request's one database connection (rule
// one-connection-per-request): a throttle hit made inside it would ask the pool for a
// second, and one made on its own connection would be rolled back with the wrong code it
// counts. So the attempt is counted before the transaction opens, by chargeFactor, the
// check inside takes this value as proof that it was, and clear runs after the commit. The
// three steps are one value, so a route cannot do one without the others: secondFactor
// refuses a code it has no charge for.
type factorCharge struct {
	s  *Server
	sc throttle.Scope
	// who is the key of the scope: the user for a request that holds a ticket, the session for one that holds
	// only its cookie (the scope says which, internal/budget). user is the subject the check is for.
	who  throttle.Who
	user uuid.UUID
	ch   throttle.Charged
	made bool
}

// chargeFactor counts one attempt on sc for user, when the request carries a code. recovery is the scope a request
// with a recovery code and no code is counted on instead (a recovery code is 80 random bits that nobody can walk,
// so it must not share a ceiling with the code: a full ceiling of the code refused the owner's escape route as
// well, round 9, primitives-r9-4), or "" for a route that keeps one scope for both (a session's reauth, which
// counts the password try once for the whole request). The scopes are named by the caller and not chosen in
// here, so what a route can spend stays readable from the route (internal/budget TestWhatARouteSpendsFollowsTheRegistry). prior
// is the proof of an earlier step of the same request that counted on this scope (reauth with a password and a code
// hits reauth_session once, in front of the password; counting the code again would give a
// user with a typo two tries instead of five). A zero or foreign proof counts again. A request with neither code is a wrong code
// and spends nothing.
func (s *Server) chargeFactor(ctx context.Context, sc, recovery throttle.Scope, who throttle.Who, user uuid.UUID, prior throttle.Charged, totpCode, recoveryCode string) (factorCharge, error) {
	if totpCode == "" && recoveryCode != "" && recovery != "" {
		// secondFactor reads the TOTP code first when both came, so only a request with a recovery code and no
		// code is a recovery attempt. Its scope is its own (round 9, primitives-r9-4) and it keeps the key of the
		// door the code would have been counted on (round 10, tenant-r10-2): keyed on the account alone, it was
		// one window that a holder of any single proof could fill for the owner.
		sc = recovery
	}
	c := factorCharge{s: s, sc: sc, who: who, user: user}
	if totpCode == "" && recoveryCode == "" {
		return c, nil
	}
	if !prior.Holds(sc, who) {
		var err error
		if prior, err = s.throttle.ChargeProof(ctx, sc, who); err != nil {
			return c, err
		}
	}
	c.ch = prior
	c.made = true
	return c, nil
}

// ticketFactorScope is the scope the second factor of a ticket is counted on, from what proved the first step
// (round 9, primitives-r9-4; internal/budget Bucket.CeilingGroup): a device marker that holds for the account
// (the browser logged in as this account before, which no stranger can make), else a password login, else an
// SMS code (an OTP login, a reset ticket). Whoever holds one proof and not the others fills that proof's
// counters only, so the owner's own door stays open. stamp is the account's credential stamp as the caller read
// it (the ticket's, or the row's), which is what a marker must hold under. A first step that is none of the
// known ones counts as the SMS code, the weakest.
func (s *Server) ticketFactorScope(ctx context.Context, user uuid.UUID, firstFactor string, stamp credgen.Stamp) (sc, recovery throttle.Scope, who throttle.Who) {
	if m := s.markers.Open(marker.User, httpx.CookieFrom(ctx, session.CookieDevice)); !m.Zero() && m.Holds(stamp) {
		// The user rides along so that a success on the marker clears the account's other ceilings of the group.
		return throttle.TOTPMarker, throttle.RecoveryMarker, throttle.Who{Marker: m.ID, User: user}
	}
	if firstFactor == login.Password {
		return throttle.TOTPUser, throttle.RecoveryUser, throttle.Who{User: user}
	}
	return throttle.TOTPSMS, throttle.RecoverySMS, throttle.Who{User: user}
}

// clear resets the scope after the commit of a request whose code was right. A failure
// to reset is not an error: the user is authenticated, and the next hit shows a real fault.
func (c factorCharge) clear(ctx context.Context) {
	if c.made {
		_ = c.s.throttle.Clear(ctx, c.sc, c.who)
	}
}

// errFactorNotCharged is a check the request did not count for: the facts the route
// decided from moved between its read and its transaction (a second factor enrolled in
// between). The client is asked to start again.
func errFactorNotCharged() error { return httpx.New(http.StatusConflict, httpx.CodeConflict) }

// checkTOTP verifies a code against the user's seed in the caller's transaction
// (spec 6.3). The seed is read under the same transaction as the step update, so
// the secret a code is checked against is the one whose step is then spent.
func (s *Server) checkTOTP(tx store.Tx, c factorCharge, user uuid.UUID, code string) error {
	if !c.made || c.user != user {
		return errFactorNotCharged()
	}
	ct, ok, err := tx.TOTPSeedCT(user)
	if err != nil {
		return err
	}
	if !ok {
		return totp.ErrInvalid
	}
	seed, err := s.keys.Open(keyring.DomainUserTOTP, totp.UserAAD(tx.TenantID(), user), ct)
	if err != nil {
		return err
	}
	defer seed.Wipe()
	g := throttle.Counted(c.ch, c.sc, c.who, func(_ context.Context, step int64) (bool, error) {
		fresh, err := tx.TOTPStepAccept(user, step)
		return fresh.Yes(), err
	})
	return totp.Check(tx.Context(), g, seed, secret.New(code))
}

// checkRecovery spends a recovery code (6.5). A text that is not a code costs the same
// attempt as a wrong one, which the charge made before the transaction already took.
func (s *Server) checkRecovery(tx store.Tx, c factorCharge, user uuid.UUID, code string) error {
	if !c.made || c.user != user {
		return errFactorNotCharged()
	}
	h, err := recovery.Hash(secret.New(code))
	if err != nil {
		return totp.ErrInvalid
	}
	used, err := tx.RecoveryCodeUse(user, h)
	if err != nil {
		return err
	}
	if !used.Yes() {
		return totp.ErrInvalid
	}
	left, err := tx.RecoveryCodesLeft(user)
	if err != nil {
		return err
	}
	return audit.Tenant(tx, user, httpx.ClientIPFrom(tx.Context()), audit.RecoveryUsed{Left: left})
}

// Methods a second factor was proven by, as the audit rows name them.
const (
	methodTOTP     = "totp"
	methodRecovery = "recovery"
)

// secondFactor checks whichever of a TOTP code and a recovery code was sent, in the
// transaction, against the charge chargeFactor made for the same codes before it. A request
// with neither is a wrong code and spends nothing.
func (s *Server) secondFactor(tx store.Tx, c factorCharge, user uuid.UUID, totpCode, recoveryCode string) (string, error) {
	switch {
	case totpCode != "":
		return methodTOTP, s.checkTOTP(tx, c, user, totpCode)
	case recoveryCode != "":
		return methodRecovery, s.checkRecovery(tx, c, user, recoveryCode)
	}
	return "", totp.ErrInvalid
}

// peekSecondFactor is the look of rule proof-before-work at the second factor of a reset: it says
// whether the code that came could be right, without counting, spending or changing anything. A
// caller who holds the SMS ticket and not the authenticator (a SIM swap) used to get the scoring
// and an Argon2 hash for every wrong code, up to the ticket's five reads, and burned the victim's
// totp_user while doing it (tenant-r5-6). The check that decides is still secondFactor, in the
// transaction, which spends the step or the code; this only keeps the heavy work for a caller who
// is not wrong at once. The attempt was counted before by chargeFactor, so it costs a try.
func (s *Server) peekSecondFactor(tx store.Tx, c factorCharge, user uuid.UUID, totpCode, recoveryCode string) error {
	if totpCode == "" && recoveryCode == "" {
		return totp.ErrInvalid
	}
	if !c.made || c.user != user {
		return errFactorNotCharged()
	}
	if totpCode != "" {
		ct, ok, err := tx.TOTPSeedCT(user)
		if err != nil {
			return err
		}
		if !ok {
			return totp.ErrInvalid
		}
		seed, err := s.keys.Open(keyring.DomainUserTOTP, totp.UserAAD(tx.TenantID(), user), ct)
		if err != nil {
			return err
		}
		defer seed.Wipe()
		if !totp.Plausible(seed, secret.New(totpCode)) {
			return totp.ErrInvalid
		}
		return nil
	}
	h, err := recovery.Hash(secret.New(recoveryCode))
	if err != nil {
		return totp.ErrInvalid
	}
	live, err := tx.RecoveryCodeLive(user, h)
	if err != nil {
		return err
	}
	if !live {
		return totp.ErrInvalid
	}
	return nil
}

// issuedCookies is the Set-Cookie list of a rotation, or none.
func issuedCookies(o session.Outcome) []*http.Cookie {
	if o.Issued == nil {
		return nil
	}
	return o.Issued.Cookies()
}

// LoginTotp is POST /auth/login/totp (spec 6.6). The mfa ticket is the proof: it is read
// first, which spends one of its five reads, so a stolen ticket cannot be used to guess
// codes beyond the throttle either (rule proof-before-work). The code, the consume of the
// ticket and the session are the Work step, in one transaction. The step stays in this
// function because the same function must lock the user row against the ticket's
// generation (rule credential-generation, internal/lint).
func (s *Server) LoginTotp(ctx context.Context, req gen.LoginTotpRequestObject) (gen.LoginTotpResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.BadRequest()
	}
	b := *req.Body
	var (
		tk store.Ticket
		fc factorCharge
	)
	res, err := proof.Run(ctx, proof.Spec[login.Result]{
		Kind: proof.Ticket,
		Check: func(ctx context.Context) error {
			var found bool
			var err error
			if tk, found, err = s.tickets.Peek(ctx, b.Ticket, store.TicketMFA); err != nil {
				return err
			} else if !found {
				return errTicketInvalid()
			}
			// The user is known only from the ticket, so the attempt is counted after it is read
			// and before the transaction opens (see factorCharge).
			sc, rec, who := s.ticketFactorScope(ctx, tk.User, tk.FirstFactor, tk.Cred)
			fc, err = s.chargeFactor(ctx, sc, rec, who, tk.User, throttle.Charged{}, deref(b.TotpCode), deref(b.RecoveryCode))
			return err
		},
		Work: func(ctx context.Context, _ proof.Proved) (login.Result, error) {
			ip := httpx.ClientIPFrom(ctx)
			var res login.Result
			var device *http.Cookie
			err := s.inTenant(ctx, tk.Tenant, func(tx store.Tx) error {
				// The password or the code already proved who this is; a tenant that was
				// suspended in between is still told why (5.7).
				if st, err := tx.TenantStatus(); err != nil {
					return err
				} else if st != "active" {
					return errSuspended()
				}
				// The ticket is worth what the credentials were when it was made: the row is
				// locked and compared with the generation the ticket carries (internal/credgen),
				// before the code is read, so a password, a second factor or a one-time
				// password that changed meanwhile ends the ticket whichever route changed it.
				if _, ok, err := tx.UserLockFor(tk.User, tk.Cred); errors.Is(err, credgen.ErrStale) || (err == nil && !ok) {
					return errTicketInvalid()
				} else if err != nil {
					return err
				}
				if _, err := s.secondFactor(tx, fc, tk.User, deref(b.TotpCode), deref(b.RecoveryCode)); err != nil {
					return err
				}
				// The code was right: spend the ticket. If another request took it first,
				// this transaction rolls back and the spent step and recovery code with it.
				if _, ok, err := s.tickets.TakeTx(tx, b.Ticket, store.TicketMFA); err != nil {
					return err
				} else if !ok {
					return errTicketInvalid()
				}
				iss, restricted, err := s.login.OpenSession(tx, tk.User, tk.FirstFactor, tk.RememberMe, ip, httpx.UserAgentFrom(tx.Context()))
				if err != nil {
					return err
				}
				res = login.Result{Status: login.Authenticated, Session: iss, Restricted: restricted, Cookies: iss.Cookies()}
				device = s.login.DeviceCookie(tx, tk.User)
				return nil
			})
			if err != nil {
				return login.Result{}, err
			}
			fc.clear(ctx)
			if device != nil {
				res.Cookies = append(res.Cookies, device)
			}
			return res, nil
		},
	})
	if err != nil {
		return nil, apiError(err)
	}
	setCookies(ctx, res.Cookies...)
	return gen.LoginTotp200JSONResponse{LoginResultJSONResponse: loginResult(res)}, nil
}

// TotpSetup is POST /account/totp/setup (spec 6.4).
func (s *Server) TotpSetup(ctx context.Context, _ gen.TotpSetupRequestObject) (gen.TotpSetupResponseObject, error) {
	p, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	var out gen.TotpSetup
	device, err := s.inTenantOwner(ctx, p, func(tx store.Tx) error {
		if _, ok, err := tx.UserLock(p.UserID); err != nil {
			return err
		} else if !ok {
			return httpx.SessionExpired()
		}
		u, _, err := tx.User(p.UserID)
		if err != nil {
			return err
		}
		if u.TOTPEnabledAt != nil {
			return httpx.New(http.StatusConflict, httpx.CodeTOTPAlreadyEnabled)
		}
		seed, err := totp.NewSecret()
		if err != nil {
			return err
		}
		defer seed.Wipe()
		ct, err := s.keys.Seal(keyring.DomainUserTOTP, totp.UserAAD(p.TenantID, p.UserID), seed.Reveal())
		if err != nil {
			return err
		}
		if ok, err := tx.TOTPSetPending(p.UserID, ct); err != nil {
			return err
		} else if !ok {
			return httpx.New(http.StatusConflict, httpx.CodeTOTPAlreadyEnabled)
		}
		out = gen.TotpSetup{
			Secret:     totp.Base32(seed).Reveal(),
			OtpauthUri: totp.URI(seed, phone.Mask(u.Phone)).Reveal(),
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	setCookies(ctx, device)
	return gen.TotpSetup200JSONResponse(out), nil
}

// TotpConfirm is POST /account/totp/confirm (spec 6.4).
func (s *Server) TotpConfirm(ctx context.Context, req gen.TotpConfirmRequestObject) (gen.TotpConfirmResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.BadRequest()
	}
	b := *req.Body
	if !b.Saved {
		return nil, errValidation("saved", "required")
	}
	p, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	// The attempt is counted before the transaction opens, whatever the transaction decides
	// (see factorCharge); a request that fails on state before it reads the code pays for it.
	fc, err := s.chargeFactor(ctx, throttle.TOTPSession, "", throttle.Who{Session: p.SessionID}, p.UserID, throttle.Charged{}, b.Code, "")
	if err != nil {
		return nil, apiError(err)
	}
	ip := httpx.ClientIPFrom(ctx)
	// Asked before the transaction, like the regeneration's: the cache may read the database (see wantNoticeSMS).
	smsNotice := s.wantNoticeSMS(ctx)
	var (
		codes   []string
		ended   int
		cookies []*http.Cookie
		stale   bool
	)
	var device *http.Cookie
	device, err = s.inTenantOwner(ctx, p, func(tx store.Tx) error {
		if _, ok, err := tx.UserLock(p.UserID); err != nil {
			return err
		} else if !ok {
			return httpx.SessionExpired()
		}
		u, _, err := tx.User(p.UserID)
		if err != nil {
			return err
		}
		if u.TOTPEnabledAt != nil {
			return httpx.New(http.StatusConflict, httpx.CodeTOTPAlreadyEnabled)
		}
		if !u.TOTPPending {
			return httpx.New(http.StatusConflict, httpx.CodeTOTPNotPending)
		}
		if u.TOTPPendingStale {
			// Clear it and commit that, then answer: returning the error would roll
			// the clearing back.
			stale = true
			return tx.TOTPClearPending(p.UserID)
		}
		if _, err := s.secondFactor(tx, fc, p.UserID, b.Code, ""); err != nil {
			return err
		}
		// An account that had a set of codes and lost it to a disable gets a new set here, and that is a
		// regeneration (D70, spec 12.3): a thief with a session and the password reaches the same end through
		// disable, set-up and confirm as through the regeneration route, and must not do it without a trace. The
		// first enrolment of an account that never had codes tells nobody. Read before the audit row of this
		// confirm exists, under the user lock taken above.
		replaces, err := tx.HadRecoveryCodes(p.UserID)
		if err != nil {
			return err
		}
		if ok, err := tx.TOTPEnable(p.UserID); err != nil {
			return err
		} else if !ok {
			return httpx.New(http.StatusConflict, httpx.CodeTOTPNotPending)
		}
		set, err := recovery.NewSet()
		if err != nil {
			return err
		}
		if err := tx.RecoveryCodesReplace(p.UserID, set.Hashes); err != nil {
			return err
		}
		out, err := s.d.Sessions.Apply(tx, session.EventTOTPEnable, session.Actor{User: p.UserID, Session: p.SessionID})
		if err != nil {
			return err
		}
		ended, cookies = out.Ended, issuedCookies(out)
		for _, c := range set.Codes {
			codes = append(codes, c.Reveal())
		}
		if replaces {
			// totp.enable first, then the regeneration row the daily cap of the SMS counts (once for this confirm).
			return recoveryCodesReplaced(tx, p.UserID, len(codes), smsNotice, audit.TOTPEnable{Left: len(codes)})
		}
		return audit.Tenant(tx, p.UserID, ip, audit.TOTPEnable{Left: len(codes)})
	})
	if err != nil {
		return nil, err
	}
	if stale {
		return nil, httpx.New(http.StatusConflict, httpx.CodeTOTPNotPending)
	}
	fc.clear(ctx)
	setCookies(ctx, append(cookies, device)...)
	return gen.TotpConfirm200JSONResponse{RecoveryCodes: codes, EndedSessions: ended}, nil
}

// TotpDisable is POST /account/totp/disable (spec 6.4). The reauth gate has
// already asked for the password and a code (3.5).
func (s *Server) TotpDisable(ctx context.Context, _ gen.TotpDisableRequestObject) (gen.TotpDisableResponseObject, error) {
	p, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	var (
		ended   int
		cookies []*http.Cookie
	)
	var device *http.Cookie
	device, err = s.inTenantOwner(ctx, p, func(tx store.Tx) error {
		if _, ok, err := tx.UserLock(p.UserID); err != nil {
			return err
		} else if !ok {
			return httpx.SessionExpired()
		}
		u, _, err := tx.User(p.UserID)
		if err != nil {
			return err
		}
		if u.TOTPEnabledAt == nil {
			return httpx.New(http.StatusConflict, httpx.CodeTOTPNotEnabled)
		}
		left, err := tx.RecoveryCodesLeft(p.UserID)
		if err != nil {
			return err
		}
		before, err := session.FactorsOf(tx, p.UserID) // before the change: Apply compares it with what is left (primitives-r11-4)
		if err != nil {
			return err
		}
		if err := tx.TOTPDisable(p.UserID); err != nil {
			return err
		}
		if err := tx.RecoveryCodesReplace(p.UserID, nil); err != nil {
			return err
		}
		out, err := s.d.Sessions.Apply(tx, session.EventTOTPDisable, session.Actor{User: p.UserID, Session: p.SessionID, Before: &before})
		if err != nil {
			return err
		}
		ended, cookies = out.Ended, issuedCookies(out)
		return audit.Tenant(tx, p.UserID, httpx.ClientIPFrom(tx.Context()), audit.TOTPDisable{Left: left})
	})
	if err != nil {
		return nil, err
	}
	setCookies(ctx, append(cookies, device)...)
	return gen.TotpDisable200JSONResponse{SessionsEndedJSONResponse: gen.SessionsEndedJSONResponse{EndedSessions: ended}}, nil
}

// RegenerateRecoveryCodes is POST /account/totp/recovery-codes (spec 6.5).
func (s *Server) RegenerateRecoveryCodes(ctx context.Context, _ gen.RegenerateRecoveryCodesRequestObject) (gen.RegenerateRecoveryCodesResponseObject, error) {
	p, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	var (
		codes   []string
		cookies []*http.Cookie
	)
	smsNotice := s.wantNoticeSMS(ctx)
	err = s.inTenant(ctx, p.TenantID, func(tx store.Tx) error {
		if _, ok, err := tx.UserLock(p.UserID); err != nil {
			return err
		} else if !ok {
			return httpx.SessionExpired()
		}
		u, _, err := tx.User(p.UserID)
		if err != nil {
			return err
		}
		if u.TOTPEnabledAt == nil {
			return httpx.New(http.StatusConflict, httpx.CodeTOTPNotEnabled)
		}
		set, err := recovery.NewSet()
		if err != nil {
			return err
		}
		if err := tx.RecoveryCodesReplace(p.UserID, set.Hashes); err != nil {
			return err
		}
		out, err := s.d.Sessions.Apply(tx, session.EventRecoveryRegenerate, session.Actor{User: p.UserID, Session: p.SessionID})
		if err != nil {
			return err
		}
		cookies = issuedCookies(out)
		for _, c := range set.Codes {
			codes = append(codes, c.Reveal())
		}
		// Replacing the codes does not move credential_gen, so a thief who passed reauth could mint a set only
		// they hold. The notice is what lets the owner learn of it (tenant-r18-14, D64 passkey-add-notice). In
		// rank order: after the session event, before the audit row.
		return recoveryCodesReplaced(tx, p.UserID, len(codes), smsNotice)
	})
	if err != nil {
		return nil, err
	}
	setCookies(ctx, cookies...)
	return gen.RegenerateRecoveryCodes200JSONResponse{RecoveryCodes: codes}, nil
}

// refund gives the attempt back when the request was turned away before any code was looked at
// (the Argon2 or scoring gate was full). A failure to give it back leaves the attempt counted, as
// it was before the refund existed.
func (c factorCharge) refund(ctx context.Context) {
	if c.made {
		_ = c.s.throttle.Refund(context.WithoutCancel(ctx), c.sc, c.who)
	}
}
