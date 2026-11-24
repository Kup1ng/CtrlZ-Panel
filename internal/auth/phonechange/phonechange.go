// Package phonechange is the phone change flow of spec 5.6 (T-110): the account
// moves to a new number only when the holder of the old SIM and the holder of
// the new SIM both prove it.
//
// The route needs a reauth window to start. This package does not check it; the
// router's gate does (x-ctrlz-auth: reauth), the same as for every route that
// changes a credential.
//
// Why both numbers. A thief with a stolen session and a reauth can reach the
// request, but not the old SIM. A thief with the old SIM and no session cannot
// start it. Neither alone is enough.
package phonechange

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
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// Errors. The route maps each to its API error.
var (
	// ErrSamePhone is a new number equal to the current one (422 validation_failed).
	ErrSamePhone = errors.New("phonechange: same number")
	// ErrNotFound is a request that is not the caller's, or does not exist (404
	// not_found). Another tenant's id is the same.
	ErrNotFound = errors.New("phonechange: not found")
	// ErrPhoneUnavailable is a new number that belongs to someone else (409
	// phone_unavailable). It surfaces only to a person who holds that SIM (5.6).
	ErrPhoneUnavailable = errors.New("phonechange: phone unavailable")
)

// CodeError names the code that failed, for the `fields` of the 401 (5.6 step
// 5). Err is an otp error; the spec answers all of them as otp_invalid here.
type CodeError struct {
	Field string // old_code or new_code
	Err   error
}

func (e *CodeError) Error() string { return "phonechange: " + e.Field + ": " + e.Err.Error() }
func (e *CodeError) Unwrap() error { return e.Err }

// Service runs the two steps.
type Service struct {
	DB  *store.Store
	OTP *otp.Service
	// Markers seals the known-device marker handed to the browser that changed the number.
	Markers  *marker.Service
	Sessions *session.Manager
	// Config is the cached public configuration, for the RP ID the passkey review
	// compares with.
	Config otp.ConfigFunc
	Now    func() time.Time
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return appclock.Now()
}

// StartInput is POST /account/phone/change.
type StartInput struct {
	Tenant   uuid.UUID
	User     uuid.UUID
	NewPhone string // E.164, already normalised
	Locale   string
	IP       netip.Addr
}

// Started is the 202 body.
type Started struct {
	RequestID, OldChallenge, NewChallenge uuid.UUID
	ExpiresIn, ResendAfter                time.Duration
}

// Start issues both challenges and records the request.
//
// The new number is issued first, then the old one, so a refusal on the new
// number spends nothing on the old (5.6 step 3). Either refusal is
// otp.ErrLimited. An unavailable gateway is otp.ErrSMSUnavailable.
func (s *Service) Start(ctx context.Context, in StartInput) (Started, error) {
	var current string
	err := s.DB.WithTenant(ctx, in.Tenant, store.TxOpts{ReadOnly: true}, func(tx store.Tx) error {
		u, ok, err := tx.User(in.User)
		if err != nil {
			return err
		}
		if !ok {
			return ErrNotFound
		}
		current = u.Phone
		return nil
	})
	if err != nil {
		return Started{}, err
	}
	if in.NewPhone == current {
		return Started{}, ErrSamePhone
	}
	newCh, err := s.OTP.RequestNewPhone(ctx, in.Tenant, in.NewPhone, in.Locale, in.IP)
	if err != nil {
		return Started{}, err
	}
	oldCh, err := s.OTP.RequestForSession(ctx, otp.ForPhoneOld, current, in.Locale, in.IP)
	if err != nil {
		return Started{}, err
	}
	var id uuid.UUID
	err = s.DB.WithTenant(ctx, in.Tenant, store.TxOpts{}, func(tx store.Tx) (err error) {
		id, err = tx.PhoneChangeCreate(in.User, in.NewPhone, oldCh.ID, newCh.ID, otp.Life)
		return err
	})
	if err != nil {
		return Started{}, err
	}
	return Started{RequestID: id, OldChallenge: oldCh.ID, NewChallenge: newCh.ID, ExpiresIn: otp.Life, ResendAfter: max(oldCh.ResendAfter, newCh.ResendAfter)}, nil
}

// ConfirmInput is POST /account/phone/change/{id}/confirm, after the route has
// counted otp_verify_net.
type ConfirmInput struct {
	Tenant, User, Session uuid.UUID
	RequestID             uuid.UUID
	OldCode, NewCode      string
	IP                    netip.Addr
}

// Confirmed is what the route needs for its response and cookies.
type Confirmed struct {
	// Issued is the rotated session, to set once the transaction is out.
	Issued session.Issued
	// Ended is the number of other sessions ended (ended_sessions).
	Ended int
	// Device is a device marker for the current browser under the new credential
	// generation (the phone is part of it), or nil. The change ends every marker
	// issued before it, the owner's own browser included, and the owner is here, so
	// this browser gets a fresh one (review round 4, tenant-r4-5).
	Device *http.Cookie
}

// Confirm checks both codes and moves the account to the new number.
//
// A code that was already consumed counts as good when the other one is wrong,
// so a typo in one code lets the user retry without losing the other (5.6 step
// 5). The database then decides: auth_phone_change_complete accepts only two
// codes consumed after the request was made, for the right numbers and purposes.
func (s *Service) Confirm(ctx context.Context, in ConfirmInput) (Confirmed, error) {
	var req store.PhoneChange
	var current string
	err := s.DB.WithTenant(ctx, in.Tenant, store.TxOpts{ReadOnly: true}, func(tx store.Tx) error {
		r, ok, err := tx.PhoneChangeGet(in.User, in.RequestID)
		if err != nil {
			return err
		}
		if !ok {
			return ErrNotFound
		}
		u, ok, err := tx.User(in.User)
		if err != nil {
			return err
		}
		if !ok {
			return ErrNotFound
		}
		req, current = r, u.Phone
		return nil
	})
	if err != nil {
		return Confirmed{}, err
	}
	if req.CompletedAt != nil {
		return Confirmed{}, &CodeError{Field: "old_code", Err: otp.ErrExpired}
	}

	for _, c := range []struct {
		field string
		id    uuid.UUID
		phone string
		p     otp.Purpose
		code  string
	}{
		{"old_code", req.OldOTP, current, otp.PhoneOld, in.OldCode},
		{"new_code", req.NewOTP, req.NewPhone, otp.PhoneNew, in.NewCode},
	} {
		o, err := s.OTP.Verify(ctx, c.id, c.phone, c.p, c.code)
		if err != nil {
			return Confirmed{}, err
		}
		if o != otp.OK && o != otp.Consumed {
			return Confirmed{}, &CodeError{Field: c.field, Err: o.Err()}
		}
	}

	cfg, err := s.Config(ctx)
	if err != nil {
		return Confirmed{}, err
	}
	var done Confirmed
	err = s.DB.WithTenant(ctx, in.Tenant, store.TxOpts{}, func(tx store.Tx) error {
		out, err := tx.PhoneChangeComplete(in.RequestID)
		if err != nil {
			return err
		}
		switch out {
		case "ok":
		case "unavailable":
			return ErrPhoneUnavailable
		default:
			return &CodeError{Field: "new_code", Err: otp.ErrInvalid}
		}

		// 3.7: rotate, end the other sessions, revoke API tokens and close the open
		// mfa and reset tickets, all in this transaction.
		o, err := s.Sessions.Apply(tx, session.EventPhoneChange, session.Actor{User: in.User, Session: in.Session})
		if err != nil {
			return err
		}
		done.Ended = o.Ended
		if o.Issued != nil {
			done.Issued = *o.Issued
		}
		done.Device = nil
		switch u, ok, err := tx.User(in.User); {
		case err != nil:
			return err
		case ok:
			if c, err := s.Markers.Issue(marker.User, u.Stamp()); err == nil {
				done.Device = c
			}
		}
		if marked, err := s.reviewPasskeys(tx, in.User, cfg); err != nil {
			return err
		} else if marked {
			// The rotation above kept the reauth window, and the window may have come from a
			// passkey, which is no proof for clearing a review (7.7). The owner proves themselves
			// again, by something that cannot be a passkey while the flag is set (tenant-r5-4).
			if err := tx.SessionReauthClear(in.User, in.Session); err != nil {
				return err
			}
		}
		if err := audit.Tenant(tx, in.User, in.IP, audit.PhoneChange{
			OldMasked: audit.MaskPhone(current), NewMasked: audit.MaskPhone(req.NewPhone),
		}); err != nil {
			return err
		}
		return tx.NotificationAdd("phone_changed", "info", nil)
	})
	if err != nil {
		return Confirmed{}, err
	}
	return done, nil
}

// reviewPasskeys is 7.7: a recovery event marks the user's passkeys for review,
// so a passkey an earlier attacker added does not survive the owner's recovery.
// It is skipped while Enforce is in force, because Enforce leaves a passkey as
// the only way in and blocking it would lock the owner out.
func (s *Service) reviewPasskeys(tx store.Tx, user uuid.UUID, cfg store.PublicConfig) (marked bool, err error) {
	if !cfg.PasskeyEnabled || cfg.RPID == "" {
		return false, nil
	}
	live, err := tx.PasskeyLiveCount(user, cfg.RPID)
	if err != nil || live == 0 {
		return false, err
	}
	u, ok, err := tx.User(user)
	if err != nil || !ok {
		return false, err
	}
	if u.EnforcePasskey && (u.EnforceLiftAt == nil || u.EnforceLiftAt.After(s.now())) {
		return false, nil
	}
	if err := tx.SetPasskeyReview(user, true); err != nil {
		return false, err
	}
	return true, tx.NotificationAdd("passkey_review", "warning", nil)
}
