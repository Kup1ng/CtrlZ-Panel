package adminapi

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/Kup1ng/CtrlZ-Panel/internal/adminapi/gen"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/adminnotice"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/audit"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/credstate"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/marker"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/password"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/proof"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/pwstrength"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/session"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/throttle"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/totp"
	"github.com/Kup1ng/CtrlZ-Panel/internal/credgen"
	"github.com/Kup1ng/CtrlZ-Panel/internal/httpx"
	"github.com/Kup1ng/CtrlZ-Panel/internal/logattr"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// GetAdminMe is GET /me: the shell's bootstrap, open to a session still in setup.
func (s *Server) GetAdminMe(ctx context.Context, _ gen.GetAdminMeRequestObject) (gen.GetAdminMeResponseObject, error) {
	p, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	out := gen.AdminMe{
		Username: p.Username, MustChangePassword: p.State.OneTime(), TotpEnrolled: p.TOTPEnrolled,
		Notices: []gen.AdminNotice{},
	}
	if p.TOTPVerifiedAt != nil {
		if until := s.d.Sessions.AdminFreshUntil(*p.TOTPVerifiedAt); until.After(s.now()) {
			u := until.UTC()
			out.FreshUntil = &u
		}
	}
	err = s.readGlobal(ctx, func(g store.GlobalTx) error {
		user, ok, err := g.AdminUserByID(p.AdminID)
		if err != nil {
			return err
		}
		if !ok {
			return httpx.SessionExpired()
		}
		for _, n := range adminnotice.Parse(user.PendingNotice) {
			out.Notices = append(out.Notices, gen.AdminNotice{Kind: gen.AdminNoticeKind(n.Kind), At: n.At})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return gen.GetAdminMe200JSONResponse(out), nil
}

// AckAdminNotices is POST /me/notices/ack. It dismisses what the admin was shown
// before this session began and nothing newer. A notice made during the session
// is the one a thief's session produces (the SMS gateway change of 10.7), and the
// owner has to see it at the next login, so the session that caused it cannot
// clear it (review round 3, admin-r3-1, admin-r3-8). The same rule means a notice
// that landed after the client read GET /me is never dropped unseen.
func (s *Server) AckAdminNotices(ctx context.Context, _ gen.AckAdminNoticesRequestObject) (gen.AckAdminNoticesResponseObject, error) {
	p, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	err = s.global(ctx, func(g store.GlobalTx) error {
		cleared, kept, err := g.AdminNoticeAck(p.AdminID, p.CreatedAt)
		if err != nil {
			return err
		}
		// A row only when something was dismissed or refused: an ack with no banner
		// is the shell's routine call and would only fill the log.
		if cleared == 0 && kept == 0 {
			return nil
		}
		_, err = audit.Admin(g, s.now(), p.AdminID, httpx.ClientIPFrom(g.Context()), audit.AdminNoticesAck{Admin: p.AdminID, Cleared: cleared, Kept: kept})
		return err
	})
	if err != nil {
		return nil, err
	}
	return gen.AckAdminNotices204Response{}, nil
}

// preparePassword is the rule of 4.2 and 4.3 for an admin password: the longer
// minimum and a score of 4. It runs before anything is consumed, outside every
// transaction.
func (s *Server) preparePassword(ctx context.Context, raw, username string) (password.Prepared, error) {
	p, err := password.Prepare(secret.New(raw), password.Admin)
	if err != nil {
		code := "invalid"
		switch {
		case errors.Is(err, password.ErrTooShort):
			code = string(pwstrength.TooShort)
		case errors.Is(err, password.ErrTooLong):
			code = "too_long"
		}
		return password.Prepared{}, httpx.New(http.StatusUnprocessableEntity, httpx.CodePasswordWeak).WithFields(httpx.FieldError{Name: "new_password", Code: code})
	}
	r, err := s.strength.Check(ctx, p, pwstrength.Input{Username: username}, password.Admin)
	if err != nil {
		return password.Prepared{}, err
	}
	if !r.OK {
		return password.Prepared{}, httpx.New(http.StatusUnprocessableEntity, httpx.CodePasswordWeak).WithFields(httpx.FieldError{Name: "new_password", Code: string(r.Reason)})
	}
	return p, nil
}

// ChangeAdminPassword is POST /me/password (spec 10.3). The whole decision runs
// inside the floor of the login, for the same reason: a wrong password, a
// missing code and a wrong code must not be told apart by what they cost.
func (s *Server) ChangeAdminPassword(ctx context.Context, req gen.ChangeAdminPasswordRequestObject) (gen.ChangeAdminPasswordResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.BadRequest()
	}
	b := *req.Body
	p, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	err = httpx.Floor(ctx, floorLogin, func(ctx context.Context) error {
		return s.changePassword(ctx, p, b)
	})
	if err != nil {
		return nil, adminError(err)
	}
	return gen.ChangeAdminPassword204Response{}, nil
}

func (s *Server) changePassword(ctx context.Context, p session.AdminPrincipal, b gen.AdminPasswordRequest) error {
	ip := httpx.ClientIPFrom(ctx)
	// Plain input checks first. They tell the caller nothing about the account,
	// and a typo in the new password must not spend the budget below.
	newPW, err := s.preparePassword(ctx, b.NewPassword, p.Username)
	if err != nil {
		return err
	}
	// Count first: a stolen cookie must not be able to test passwords without
	// limit. The key is the admin, not the admin and a network: a session is not
	// tied to a network, so a thief who changes networks would otherwise get a
	// fresh budget every few tries (review round 1). The scope is admin_reauth, kept
	// under the database scope admin_login, and `ctrlz-admin unlock` and the reset
	// commands clear it by walking the registry.
	if err := s.throttle.Charge(ctx, throttle.AdminReauth, throttle.Who{Admin: p.AdminID}); err != nil {
		return err
	}
	var user store.AdminUser
	err = s.readGlobal(ctx, func(g store.GlobalTx) (err error) {
		var ok bool
		user, ok, err = g.AdminUserByID(p.AdminID)
		if err == nil && !ok {
			err = httpx.SessionExpired()
		}
		return err
	})
	if err != nil {
		return err
	}
	// The current password, then the hash of the new one on every path, so a right
	// password costs what a wrong one does. An expired one-time password counts as
	// a wrong one, as at login (10.2).
	// Either step can find the Argon2 gate full: a stored hash that is not a console one-time hash
	// takes a slot in the verify as well (VerifyGateFree skips the slot only for that one), and the
	// hash of the new password always does. In both cases no password was looked at, so the try on
	// admin_reauth goes back (tenant-r6-8, the same rule as the tenant reauth).
	giveBackIfBusy := func(err error) error {
		if proof.Busy(err) {
			// Best effort, as the tenant reauth and proof.Spec.Refund are: a refund that fails (a
			// dropped connection, a statement timeout) leaves the try spent, which is the safe side,
			// and must not turn the 503 the client is told to retry into a plain-text 500 with a stack
			// (round 7, admin-r7-4 and -8; it used to panic so that a missing request book would be
			// loud, and a test holds that now: TestAdminPasswordRefundWorksOnTheRoutesLedger). One
			// closed line says it happened, with no error text.
			if e := s.throttle.Refund(context.WithoutCancel(ctx), throttle.AdminReauth, throttle.Who{Admin: p.AdminID}); e != nil {
				s.d.Log.Warn("the busy password change could not give its try back", logattr.Enum("error_class", logattr.ErrOther))
			}
		}
		return err
	}
	ok, err := s.hasher.VerifyGateFree(ctx, secret.New(b.CurrentPassword), user.PasswordHash)
	if err != nil {
		return giveBackIfBusy(err)
	}
	hash, err := s.hasher.Hash(ctx, newPW.Normalized())
	if err != nil {
		return giveBackIfBusy(err)
	}
	verdict := credstate.Named(credstate.Admin, "changeAdminPassword", user.State)
	if !ok || !verdict.Permits() {
		return errInvalidCredentials()
	}
	// Once TOTP is enrolled and the password is the admin's own, a code is needed
	// too, so a stolen cookie plus the password is not enough (10.3). A missing
	// code, a wrong code and a spent attempt budget all answer like a wrong
	// password: otherwise the answer would say that the password was right.
	needCode := verdict == credstate.WithSecondFactor
	code := strings.TrimSpace(deref(b.TotpCode))
	var charge totpCharge
	if needCode {
		if code == "" {
			return errInvalidCredentials()
		}
		var err error
		if charge, err = s.totpHit(ctx, user.ID); err != nil {
			if errors.Is(err, throttle.ErrTooMany) {
				return errInvalidCredentials()
			}
			return err
		}
	}
	same := false
	if cur, nerr := password.Normalize(secret.New(b.CurrentPassword)); nerr == nil {
		same = cur.Reveal() == newPW.Normalized().Reveal()
	}
	var iss session.AdminIssued
	var device credgen.Stamp
	err = s.d.Store.WithGlobal(ctx, store.TxOpts{}, func(g store.GlobalTx) error {
		// The row may have changed while Argon2 ran (a console reset, another admin
		// session, an authenticator enrolled or cleared). The password verified above, and
		// the factor that was counted, belong to the row as it was read: the lock and the
		// comparison are one call, by generation (internal/credgen).
		cur, found, err := g.AdminUserLockFor(p.AdminID, user.Stamp())
		if errors.Is(err, credgen.ErrStale) || (err == nil && !found) {
			return errInvalidCredentials()
		}
		if err != nil {
			return err
		}
		if needCode {
			if err := s.checkAdminTOTP(g, charge, cur.ID, cur.TOTPSecretCT, code, nil); err != nil {
				if errors.Is(err, totp.ErrInvalid) {
					return errInvalidCredentials()
				}
				return err
			}
		}
		// Only after every factor passed: "same as current" is a fact about a
		// password that is now proven, not a way to test a guess.
		if same {
			return errValidation("new_password", "same_as_current")
		}
		// The edge is checked again by the function, on the row it holds locked.
		if _, ok, err := g.AdminSetPassword(p.AdminID, hash); err != nil {
			return err
		} else if !ok {
			return errInvalidCredentials()
		}
		if next, ok, err := g.AdminUserByID(p.AdminID); err != nil {
			return err
		} else if ok {
			device = next.Stamp()
		}
		if _, err := g.AdminSessionsRevokeOthers(p.AdminID, p.SessionID); err != nil {
			return err
		}
		iss, err = s.d.Sessions.AdminRotate(g, store.AdminSessionInfo{SessionID: p.SessionID, AdminID: p.AdminID, AbsoluteExpiresAt: p.AbsoluteExpiresAt})
		if err != nil {
			return err
		}
		_, err = audit.Admin(g, s.now(), p.AdminID, ip, audit.AdminPasswordChange{Admin: p.AdminID})
		return err
	})
	if err != nil {
		return err
	}
	_ = s.throttle.Clear(ctx, throttle.AdminReauth, throttle.Who{Admin: p.AdminID})
	if needCode {
		s.totpReset(ctx, charge)
	}
	httpx.SetCookie(ctx, session.AdminCookie(iss.Token))
	s.renewDevice(ctx, device)
	return nil
}

// AdminTotpSetup is POST /me/totp/setup (spec 6.4 for an admin): a sealed seed,
// not yet enabled. Calling it again replaces an unconfirmed one.
func (s *Server) AdminTotpSetup(ctx context.Context, _ gen.AdminTotpSetupRequestObject) (gen.AdminTotpSetupResponseObject, error) {
	p, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	if p.TOTPEnrolled {
		return nil, httpx.New(http.StatusConflict, httpx.CodeTOTPAlreadyEnabled)
	}
	seed, err := totp.NewSecret()
	if err != nil {
		return nil, err
	}
	defer seed.Wipe()
	ct, err := s.sealSeed(p.AdminID, seed)
	if err != nil {
		return nil, err
	}
	err = s.global(ctx, func(g store.GlobalTx) error {
		ok, err := g.AdminTOTPSetPending(p.AdminID, ct)
		if err != nil {
			return err
		}
		if !ok {
			return httpx.New(http.StatusConflict, httpx.CodeTOTPAlreadyEnabled)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	// The label is the username: unlike a user's phone it is not personal data,
	// and an admin may keep several authenticators.
	return gen.AdminTotpSetup200JSONResponse{
		Secret: totp.Base32(seed).Reveal(), OtpauthUri: totp.URI(seed, p.Username).Reveal(),
	}, nil
}

// AdminTotpConfirm is POST /me/totp/confirm (spec 10.3): the code proves the
// authenticator has the seed. It turns TOTP on, opens the fresh window (the code
// just proved the authenticator), rotates this session and ends the others.
func (s *Server) AdminTotpConfirm(ctx context.Context, req gen.AdminTotpConfirmRequestObject) (gen.AdminTotpConfirmResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.BadRequest()
	}
	p, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	// Counted before the transaction opens (see sessionTotpHit).
	charge, err := s.sessionTotpHit(ctx, p)
	if err != nil {
		return nil, adminError(err)
	}
	var iss session.AdminIssued
	var device credgen.Stamp
	err = s.global(ctx, func(g store.GlobalTx) error {
		user, ok, err := g.AdminUserLockByID(p.AdminID)
		if err != nil {
			return err
		}
		if !ok {
			return httpx.SessionExpired()
		}
		if user.TOTPEnabledAt != nil {
			return httpx.New(http.StatusConflict, httpx.CodeTOTPAlreadyEnabled)
		}
		if len(user.TOTPSecretCT) == 0 {
			return httpx.New(http.StatusConflict, httpx.CodeTOTPNotPending)
		}
		var step int64
		if err := s.checkSessionTOTP(g, charge, user.ID, p.SessionID, user.TOTPSecretCT, req.Body.Code, func(st int64) { step = st }); err != nil {
			return err
		}
		if _, ok, err := g.AdminTOTPEnable(user.ID, step); err != nil {
			return err
		} else if !ok {
			return httpx.New(http.StatusConflict, httpx.CodeTOTPNotPending)
		}
		if next, ok, err := g.AdminUserByID(user.ID); err != nil {
			return err
		} else if ok {
			device = next.Stamp()
		}
		if _, err := g.AdminSessionsRevokeOthers(user.ID, p.SessionID); err != nil {
			return err
		}
		if _, ok, err := g.AdminSessionFresh(p.SessionID, s.now()); err != nil {
			return err
		} else if !ok {
			return httpx.SessionExpired()
		}
		iss, err = s.d.Sessions.AdminRotate(g, store.AdminSessionInfo{SessionID: p.SessionID, AdminID: p.AdminID, AbsoluteExpiresAt: p.AbsoluteExpiresAt})
		if err != nil {
			return err
		}
		_, err = audit.Admin(g, s.now(), user.ID, httpx.ClientIPFrom(g.Context()), audit.AdminTOTPEnroll{Admin: user.ID})
		return err
	})
	if err != nil {
		return nil, err
	}
	s.totpReset(ctx, charge)
	httpx.SetCookie(ctx, session.AdminCookie(iss.Token))
	s.renewDevice(ctx, device)
	return gen.AdminTotpConfirm204Response{}, nil
}

// renewDevice re-issues the known-device marker after a change that moves the
// credential generation of the account (a chosen password, an enrolled
// authenticator), so the admin's own browser keeps its exemption while a marker
// issued before the change does not (review round 3, admin-r3-14). A failure only
// means the next login counts on every scope.
func (s *Server) renewDevice(ctx context.Context, st credgen.Stamp) {
	if st.Zero() {
		return
	}
	if c, err := s.markers.Issue(marker.Admin, st); err == nil {
		httpx.SetCookie(ctx, c)
	}
}
