package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/api/gen"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/audit"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/otp"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/passkey"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/phone"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/proof"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/session"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/throttle"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/ticket"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/token"
	"github.com/Kup1ng/CtrlZ-Panel/internal/credgen"
	"github.com/Kup1ng/CtrlZ-Panel/internal/httpx"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// enforceDelay is how long a lost passkey's Enforce stays on after Forgot
// Password with defer_enforce (4.4, D46). Provisional like every number in the
// spec (D31); the owner chose 72 hours.
const enforceDelay = 72 * time.Hour

// resetPayload is what a reset ticket carries: the OTP challenge that proved
// the phone (so complete can mark it verified, 4.4 step 4) and whether a
// passkey proof was recorded (7.6).
type resetPayload struct {
	OTP     uuid.UUID `json:"otp"`
	Passkey bool      `json:"passkey,omitempty"`
}

// enforceInForce is 5.7: Enforce is on, a live credential exists for the current
// RP ID, and no lift is pending or the pending lift is still in the future.
func (s *Server) enforceInForce(tx store.Tx, u store.User, cfg store.PublicConfig) (bool, int, error) {
	live := 0
	if cfg.PasskeyEnabled && cfg.RPID != "" {
		var err error
		if live, err = tx.PasskeyLiveCount(u.ID, cfg.RPID); err != nil {
			return false, 0, err
		}
	}
	inForce := u.EnforcePasskey && live > 0 && (u.EnforceLiftAt == nil || u.EnforceLiftAt.After(s.now()))
	return inForce, live, nil
}

// secondFactorFor names the proof Forgot Password needs now (4.4 step 2).
func (s *Server) secondFactorFor(tx store.Tx, u store.User, cfg store.PublicConfig) (gen.ResetVerifiedSecondFactor, error) {
	if u.TOTPEnabledAt != nil {
		return gen.ResetVerifiedSecondFactorTotp, nil
	}
	inForce, _, err := s.enforceInForce(tx, u, cfg)
	if err != nil {
		return "", err
	}
	if inForce {
		return gen.ResetVerifiedSecondFactorPasskey, nil
	}
	return gen.ResetVerifiedSecondFactorNone, nil
}

// ResetVerify is POST /auth/password/reset/verify (spec 4.4 step 2).
func (s *Server) ResetVerify(ctx context.Context, req gen.ResetVerifyRequestObject) (gen.ResetVerifyResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.BadRequest()
	}
	b := *req.Body
	out, err := floored(ctx, floorVerify, func(ctx context.Context) (gen.ResetVerified, error) {
		challenge, tagged := s.otp.OpenChallenge(b.ChallengeId) // the zero ref for an id that does not check (D64 nat-proof-tag)
		if err := s.throttle.OTPVerifyHit(ctx, httpx.ClientIPFrom(ctx), challenge.ID); err != nil {
			return gen.ResetVerified{}, err
		}
		e164, err := phone.Normalize(b.Phone)
		if err != nil {
			return gen.ResetVerified{}, errInvalidPhone()
		}
		if !tagged {
			return gen.ResetVerified{}, otp.ErrInvalid // what a challenge the database does not know gets
		}
		if err := s.otp.Check(ctx, challenge.ID, e164, otp.Reset, b.Code); err != nil {
			return gen.ResetVerified{}, err
		}
		u, found, err := s.auth.UserByPhone(ctx, e164)
		if err != nil {
			return gen.ResetVerified{}, err
		}
		if !found || u.TenantStatus != "active" {
			// A decoy challenge can never be consumed, so this is a state change
			// between the code and now.
			return gen.ResetVerified{}, otp.ErrInvalid
		}
		cfg, err := s.cfg.Get(ctx)
		if err != nil {
			return gen.ResetVerified{}, err
		}
		var factor gen.ResetVerifiedSecondFactor
		err = s.readTenant(ctx, u.TenantID, func(tx store.Tx) error {
			row, ok, err := tx.User(u.UserID)
			if err != nil {
				return err
			}
			if !ok {
				return otp.ErrInvalid
			}
			factor, err = s.secondFactorFor(tx, row, cfg)
			return err
		})
		if err != nil {
			return gen.ResetVerified{}, err
		}
		raw, _ := json.Marshal(resetPayload{OTP: challenge.ID})
		t, err := s.tickets.Put(ctx, ticket.Issue{Kind: store.TicketReset, Tenant: u.TenantID, User: u.UserID, Payload: raw})
		if err != nil {
			return gen.ResetVerified{}, err
		}
		s.refundOTPVerify(ctx, httpx.ClientIPFrom(ctx), challenge.ID) // a right code is not a guess (tenant-r5-3)
		return gen.ResetVerified{Ticket: t.Token.Reveal(), SecondFactor: factor}, nil
	})
	if err != nil {
		return nil, apiError(err)
	}
	return gen.ResetVerify200JSONResponse(out), nil
}

// ResetPasskeyBegin is POST /auth/password/reset/passkey/begin (spec 7.6). The ticket is
// the proof: it is read first, and the credentials, the ceremony and the row of the new
// ticket are work for a caller who holds a live one.
func (s *Server) ResetPasskeyBegin(ctx context.Context, req gen.ResetPasskeyBeginRequestObject) (gen.ResetPasskeyBeginResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.BadRequest()
	}
	var (
		inst passkey.Instance
		rt   store.Ticket
	)
	c, err := proof.Run(ctx, proof.Spec[gen.PasskeyCeremonyJSONResponse]{
		Kind:  proof.Ticket,
		Shape: func(ctx context.Context) (err error) { inst, err = s.passkeys.Get(ctx); return err },
		Check: func(ctx context.Context) error {
			var ok bool
			var err error
			if rt, ok, err = s.tickets.Peek(ctx, req.Body.Ticket, store.TicketReset); err != nil {
				return err
			} else if !ok {
				return errTicketInvalid()
			}
			return nil
		},
		Work: func(ctx context.Context, _ proof.Proved) (gen.PasskeyCeremonyJSONResponse, error) {
			pu, live, _, err := s.passkeyUser(ctx, inst, rt.Tenant, rt.User)
			if err != nil {
				return gen.PasskeyCeremonyJSONResponse{}, err
			}
			if len(live) == 0 {
				return gen.PasskeyCeremonyJSONResponse{}, passkey.ErrInvalid
			}
			begin, err := inst.BeginLogin(pu)
			if err != nil {
				return gen.PasskeyCeremonyJSONResponse{}, err
			}
			// The ticket binds the assertion to this reset ticket by its hash; the raw
			// token never goes into a payload.
			pl := reauthPayload{ResetHash: hex.EncodeToString(token.HashString(req.Body.Ticket)), WebAuthn: begin.Session}
			return s.ceremony(ctx, ticket.Issue{Kind: store.TicketPasskeyReauth, Tenant: rt.Tenant, User: rt.User}, pl, begin.Options)
		},
	})
	if err != nil {
		return nil, apiError(err)
	}
	return gen.ResetPasskeyBegin200JSONResponse{PasskeyCeremonyJSONResponse: c}, nil
}

// ResetPasskeyFinish is POST /auth/password/reset/passkey/finish (spec 7.6).
func (s *Server) ResetPasskeyFinish(ctx context.Context, req gen.ResetPasskeyFinishRequestObject) (gen.ResetPasskeyFinishResponseObject, error) {
	var body []byte
	if req.Body != nil {
		body = *req.Body
	}
	out, err := floored(ctx, floorVerify, func(ctx context.Context) (gen.TicketOnly, error) {
		return s.resetPasskeyFinish(ctx, req.Params.XCtrlzTicket, body)
	})
	if err != nil {
		return nil, apiError(err)
	}
	return gen.ResetPasskeyFinish200JSONResponse(out), nil
}

// resetPasskeyFinish is the body of the floor, in the shape of rule proof-before-work.
// The ceremony ticket is read first (Check; it names the user, so the ticket user's reset_passkey_user
// budget is charged right after the read), and the assertion is verified only for a live
// ticket. The ceremony ticket is then taken at the start of Work and not at the end: a
// challenge dies with its first answer, right or wrong.
func (s *Server) resetPasskeyFinish(ctx context.Context, tick string, body []byte) (gen.TicketOnly, error) {
	var (
		inst      passkey.Instance
		tk        store.Ticket
		pl        reauthPayload
		resetHash []byte
	)
	return proof.Run(ctx, proof.Spec[gen.TicketOnly]{
		Kind:  proof.Ticket,
		Shape: func(ctx context.Context) (err error) { inst, err = s.passkeys.Get(ctx); return err },
		Check: func(ctx context.Context) error {
			var ok bool
			var err error
			if tk, ok, err = s.tickets.Peek(ctx, tick, store.TicketPasskeyReauth); err != nil {
				return err
			} else if !ok {
				return errTicketInvalid()
			}
			if json.Unmarshal(tk.Payload, &pl) != nil || pl.ResetHash == "" || pl.SessionID != uuid.Nil {
				return passkey.ErrInvalid
			}
			if resetHash, err = hex.DecodeString(pl.ResetHash); err != nil {
				return passkey.ErrInvalid
			}
			// The user is known only from the ticket, so the throttle is hit after it is read.
			return s.throttle.Charge(ctx, throttle.ResetPasskeyUser, throttle.Who{User: tk.User})
		},
		Work: func(ctx context.Context, _ proof.Proved) (gen.TicketOnly, error) {
			if _, ok, err := s.tickets.Take(ctx, tick, store.TicketPasskeyReauth); err != nil {
				return gen.TicketOnly{}, err
			} else if !ok {
				return gen.TicketOnly{}, errTicketInvalid()
			}
			ip := httpx.ClientIPFrom(ctx)
			refused := false
			err := s.inTenant(ctx, tk.Tenant, func(tx store.Tx) error {
				pu, live, _, err := s.passkeyUserTx(tx, inst, tk.User)
				if err != nil {
					return err
				}
				a, err := inst.FinishLogin(pu, pl.WebAuthn, body)
				if err != nil {
					refused = true
					return nil
				}
				used, err := s.useCredential(tx, tk.User, live, a, ip)
				refused = !used
				return err
			})
			if err != nil {
				return gen.TicketOnly{}, err
			}
			if refused {
				return gen.TicketOnly{}, passkey.ErrInvalid
			}
			// The reset ticket is spent and the one that carries the passkey proof is made in one
			// transaction, so a failure between the two does not leave the user with neither.
			var t ticket.Issued
			err = s.inTenant(ctx, tk.Tenant, func(tx store.Tx) error {
				rt, taken, err := tx.TicketTake(resetHash, store.TicketReset)
				if err != nil {
					return err
				}
				if !taken.Yes() || rt.Tenant != tk.Tenant || rt.User != tk.User {
					return errTicketInvalid()
				}
				var prev resetPayload
				_ = json.Unmarshal(rt.Payload, &prev)
				raw, _ := json.Marshal(resetPayload{OTP: prev.OTP, Passkey: true})
				t, err = s.tickets.PutTx(tx, ticket.Issue{Kind: store.TicketReset, Tenant: tk.Tenant, User: tk.User, Payload: raw})
				return err
			})
			if err != nil {
				return gen.TicketOnly{}, err
			}
			_ = s.throttle.Clear(ctx, throttle.ResetPasskeyUser, throttle.Who{User: tk.User})
			return gen.TicketOnly{Ticket: t.Token.Reveal()}, nil
		},
	})
}

// ResetComplete is POST /auth/password/reset/complete (spec 4.4 step 4).
func (s *Server) ResetComplete(ctx context.Context, req gen.ResetCompleteRequestObject) (gen.ResetCompleteResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.BadRequest()
	}
	b := *req.Body
	var (
		rt store.Ticket
		pl resetPayload
	)
	// The shape of rule proof-before-work. The password is checked for length only, which
	// costs nothing; the ticket is then read, which spends one of its five reads (its
	// charge) and shows the caller holds a ticket somebody made; and only for such a
	// caller are the password scored and hashed. Round 2 scored first so that a weak
	// password would not cost a read, and a flood of made-up tickets then took the scoring
	// gate (round 3, primitives-r3-6): the read is now the price of asking, and a weak
	// password spends one, as a wrong second factor does.
	_, err := proof.Run(ctx, proof.Spec[struct{}]{
		Kind:  proof.Ticket,
		Shape: func(context.Context) error { return checkPasswordLength(b.NewPassword, "new_password") },
		Check: func(ctx context.Context) error {
			var ok bool
			var err error
			if rt, ok, err = s.tickets.Peek(ctx, b.Ticket, store.TicketReset); err != nil {
				return err
			} else if !ok {
				return errTicketInvalid()
			}
			if json.Unmarshal(rt.Payload, &pl) != nil {
				return errTicketInvalid()
			}
			return nil
		},
		Work: func(ctx context.Context, _ proof.Proved) (struct{}, error) {
			return struct{}{}, s.completeReset(ctx, b, rt, pl)
		},
	})
	if err != nil {
		return nil, apiError(err)
	}
	return gen.ResetComplete204Response{}, nil
}

// completeReset is the Work step of ResetComplete: the scoring with the phone, the hash,
// the second factor, the consume of the ticket and the change, the last three in one
// transaction so a failure after the check does not burn the ticket.
func (s *Server) completeReset(ctx context.Context, b gen.ResetCompleteRequest, rt store.Ticket, pl resetPayload) error {
	cfg, err := s.cfg.Get(ctx)
	if err != nil {
		return err
	}
	var (
		phoneE164 string
		hasSecond bool
		stamp     credgen.Stamp
	)
	if err := s.readTenant(ctx, rt.Tenant, func(tx store.Tx) error {
		u, ok, err := tx.User(rt.User)
		if err != nil {
			return err
		}
		if !ok {
			return errTicketInvalid()
		}
		phoneE164, hasSecond, stamp = u.Phone, u.TOTPEnabledAt != nil, u.Stamp()
		return nil
	}); err != nil {
		return err
	}
	// A user with a second factor is asked for a code inside the transaction. The attempt is
	// counted here, before the password is scored and hashed and before the transaction opens
	// (see factorCharge): a flood of wrong codes is refused before it reaches Argon2. The code
	// is then looked at without being spent, so that the scoring and the hash are work for a
	// caller whose second factor could be right and not for one who holds only the SMS
	// (tenant-r5-6); the transaction below is still the check that decides.
	var fc factorCharge
	if hasSecond {
		var err error
		// A reset ticket comes from an SMS code and nothing else: it is counted on the SMS scope, or on the
		// marker's when this browser has signed in to the account before (round 9, primitives-r9-4).
		sc, rec, who := s.ticketFactorScope(ctx, rt.User, "", stamp)
		if fc, err = s.chargeFactor(ctx, sc, rec, who, rt.User, throttle.Charged{}, deref(b.TotpCode), deref(b.RecoveryCode)); err != nil {
			return err
		}
		if err := s.readTenant(ctx, rt.Tenant, func(tx store.Tx) error {
			return s.peekSecondFactor(tx, fc, rt.User, deref(b.TotpCode), deref(b.RecoveryCode))
		}); err != nil {
			return err
		}
	}
	// The caller holds a ticket and no session: the gate of such callers, not the one
	// signed-in password change shares.
	hash, err := s.preparePasswordOn(ctx, s.strengthAnon, b.NewPassword, phoneE164, "new_password")
	if err != nil {
		if hasSecond && proof.Busy(err) {
			// The gate turned the request away and looked at nothing: the try on totp_user goes
			// back (tenant-r5-1). The ticket's own read stays, which is the price of asking.
			fc.refund(ctx)
		}
		return err
	}

	ip := httpx.ClientIPFrom(ctx)
	deferEnforce := deref(b.DeferEnforce)
	err = s.inTenant(ctx, rt.Tenant, func(tx store.Tx) error {
		// The row lock first: a login and a password change take it too, so of
		// two events on the same user one commits first and the other sees it.
		if _, ok, err := tx.UserLock(rt.User); err != nil {
			return err
		} else if !ok {
			return errTicketInvalid()
		}
		u, _, err := tx.User(rt.User)
		if err != nil {
			return err
		}
		// The proof is decided from the state now, not from what verify saw.
		inForce, live, err := s.enforceInForce(tx, u, cfg)
		if err != nil {
			return err
		}
		viaPasskey := false
		switch {
		case u.TOTPEnabledAt != nil:
			if _, err := s.secondFactor(tx, fc, rt.User, deref(b.TotpCode), deref(b.RecoveryCode)); err != nil {
				return err
			}
		case inForce:
			viaPasskey = true
			if !pl.Passkey && !deferEnforce {
				return apiError(passkey.ErrInvalid) // the ticket is kept: it is not taken yet
			}
		}
		// The code was right: spend the ticket. It comes before Apply, whose revoke closes every
		// open reset ticket of the user, this one included, and tickets rank before sessions
		// (internal/lockrank). The user row lock taken first already serialises two requests
		// with one ticket, and the spend commits or rolls back with the change it guards: a
		// failure below no longer burns the ticket.
		if _, ok, err := s.tickets.TakeTx(tx, b.Ticket, store.TicketReset); err != nil {
			return err
		} else if !ok {
			return errTicketInvalid()
		}
		if _, err := tx.SetPassword(rt.User, hash); err != nil {
			return err
		}
		if _, err := s.d.Sessions.Apply(tx, session.EventPasswordReset, session.Actor{User: rt.User}); err != nil {
			return err
		}
		if err := s.applyResetEnforce(tx, rt.User, viaPasskey, pl.Passkey, live); err != nil {
			return err
		}
		// The code proved a phone, and it must be the phone the user has now (db-r6-7). A phone
		// change that committed between the code and this step has moved the number and revoked
		// the tickets that existed, but not one made from a verify that was already running, so
		// the function refuses a code for another number and the whole transaction rolls back,
		// the new password with it. 'stale' (a code too old to mark the phone verified) goes on:
		// the ticket outlives the ten minutes, and the number is still the one the code named.
		if pl.OTP == uuid.Nil {
			return errTicketInvalid()
		}
		if out, err := tx.PhoneMarkVerified(rt.User, pl.OTP); err != nil {
			return err
		} else if out != "ok" && out != "stale" {
			return errTicketInvalid()
		}
		if err := audit.Tenant(tx, rt.User, ip, audit.PasswordReset{}); err != nil {
			return err
		}
		return tx.NotificationAdd("password_reset", "warning", nil)
	})
	if err == nil {
		fc.clear(ctx)
	}
	return err
}

// applyResetEnforce is the table of 4.4 and the review rule of 7.7.
//
//   - With no passkey in the way (nothing or TOTP proved it): Enforce is cleared,
//     since nothing live is lost, and a user with a live credential goes to
//     review: an attacker who once held the account could have added one.
//   - With a passkey proof: Enforce stays on, the delay ends, no review.
//   - With defer_enforce for a lost passkey: Enforce stays on, and from 72 hours
//     on it counts as off. Repeating the step does not move the time.
func (s *Server) applyResetEnforce(tx store.Tx, user uuid.UUID, viaPasskey, proved bool, live int) error {
	if viaPasskey {
		if proved {
			return tx.ClearEnforceLift(user)
		}
		at, ok, err := tx.DeferEnforceLift(user, enforceDelay, s.now())
		if err != nil || !ok {
			return err
		}
		params, _ := json.Marshal(map[string]any{"lift_at": at.UTC().Format(time.RFC3339)})
		return tx.NotificationAdd("enforce_lift_pending", "warning", params)
	}
	if err := tx.SetEnforce(user, false); err != nil {
		return err
	}
	if live > 0 {
		if err := tx.SetPasskeyReview(user, true); err != nil {
			return err
		}
		return tx.NotificationAdd("passkey_review", "warning", nil)
	}
	return nil
}
