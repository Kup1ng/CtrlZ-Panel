package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/api/gen"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/audit"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/login"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/passkey"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/proof"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/session"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/ticket"
	"github.com/Kup1ng/CtrlZ-Panel/internal/caps"
	"github.com/Kup1ng/CtrlZ-Panel/internal/httpx"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// The number of credentials one user holds is a cap (caps.MaxPasskeys): the list is sent
// in every set of options and every PasskeysList, and a user with a handful of passkeys
// is the real case. It no longer protects the 4096 byte ticket payload (the session data
// carries no credential ids since review round 3, tenant-r3-7), so it is a sanity bound
// and not a size calculation. It is decided by the INSERT of Tx.PasskeyAdd, once, and
// not compared again here (rule caps-and-endings).

// ceremony stores a ceremony's session data in a ticket and builds the response
// that carries the ticket and the browser's options.
func (s *Server) ceremony(ctx context.Context, iss ticket.Issue, payload any, options json.RawMessage) (gen.PasskeyCeremonyJSONResponse, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return gen.PasskeyCeremonyJSONResponse{}, err
	}
	iss.Payload = raw
	t, err := s.tickets.Put(ctx, iss)
	if err != nil {
		return gen.PasskeyCeremonyJSONResponse{}, err
	}
	return gen.PasskeyCeremonyJSONResponse{Ticket: t.Token.Reveal(), Options: options}, nil
}

// passkeyUserTx loads the library's view of a user: the credentials that are
// live for the current RP ID. review says passkey_review_at is set (7.7).
func (s *Server) passkeyUserTx(tx store.Tx, inst passkey.Instance, user uuid.UUID) (*passkey.User, []store.Credential, bool, error) {
	u, ok, err := tx.User(user)
	if err != nil {
		return nil, nil, false, err
	}
	if !ok {
		return nil, nil, false, httpx.SessionExpired()
	}
	all, err := tx.PasskeysList(user)
	if err != nil {
		return nil, nil, false, err
	}
	live := passkey.Live(all, inst.RPID)
	return passkey.NewUser(user, u.Phone, live), live, u.PasskeyReviewAt != nil, nil
}

func (s *Server) passkeyUser(ctx context.Context, inst passkey.Instance, tenant, user uuid.UUID) (pu *passkey.User, live []store.Credential, review bool, err error) {
	err = s.readTenant(ctx, tenant, func(tx store.Tx) (err error) {
		pu, live, review, err = s.passkeyUserTx(tx, inst, user)
		return err
	})
	return pu, live, review, err
}

func passkeyRow(c store.Credential, rpID string) gen.PasskeyRow {
	return gen.PasskeyRow{
		Id: c.ID, Name: c.Name, CreatedAt: c.CreatedAt, LastUsedAt: c.LastUsedAt,
		Stale: c.StaleAt != nil || c.RPID != rpID, BackupEligible: c.BackupEligible,
	}
}

// PasskeyLoginBegin is POST /auth/passkey/login/begin (spec 7.5). The route needs no
// proof, so under rule proof-before-work it writes no row: the WebAuthn session data
// travels in the ticket itself, under a tag only the api can make (ticket.SealCeremony),
// and finish records the ticket's nonce once, after the assertion has verified. What
// bounds a flood of begins is the pipeline's charge (the device marker of the browser,
// its network otherwise), and what they cost is one HMAC.
func (s *Server) PasskeyLoginBegin(ctx context.Context, req gen.PasskeyLoginBeginRequestObject) (gen.PasskeyLoginBeginResponseObject, error) {
	inst, err := s.passkeys.Get(ctx)
	if err != nil {
		return nil, apiError(err)
	}
	begin, err := inst.BeginDiscoverable()
	if err != nil {
		return nil, apiError(err)
	}
	remember := req.Body != nil && deref(req.Body.RememberMe)
	t, err := s.tickets.SealCeremony(begin.Session, remember, ticket.TTL(store.TicketPasskeyLogin))
	if err != nil {
		return nil, err
	}
	return gen.PasskeyLoginBegin200JSONResponse{PasskeyCeremonyJSONResponse: gen.PasskeyCeremonyJSONResponse{Ticket: t.Reveal(), Options: begin.Options}}, nil
}

// PasskeyLoginFinish is POST /auth/passkey/login/finish (spec 7.5).
func (s *Server) PasskeyLoginFinish(ctx context.Context, req gen.PasskeyLoginFinishRequestObject) (gen.PasskeyLoginFinishResponseObject, error) {
	var body []byte
	if req.Body != nil {
		body = *req.Body
	}
	res, err := floored(ctx, floorVerify, func(ctx context.Context) (login.Result, error) {
		return s.passkeyLogin(ctx, req.Params.XCtrlzTicket, body)
	})
	if err != nil {
		return nil, apiError(err)
	}
	setCookies(ctx, res.Cookies...)
	return gen.PasskeyLoginFinish200JSONResponse{LoginResultJSONResponse: loginResult(res)}, nil
}

// passkeyLogin is the body of the floor, in the shape of rule proof-before-work. The
// ticket is its own proof: the tag is checked (one HMAC, no database), and a value that no
// api made, or that has expired, ends the request before the assertion is looked at. The
// assertion is Work, and the ticket is recorded as used only once it has verified, in the
// same step that opens the session: a flood of finishes with made-up tickets writes
// nothing, and a replay of a good one meets the unique index and is refused.
func (s *Server) passkeyLogin(ctx context.Context, tick string, body []byte) (login.Result, error) {
	var (
		inst passkey.Instance
		cer  ticket.Ceremony
	)
	return proof.Run(ctx, proof.Spec[login.Result]{
		Kind:  proof.Sealed,
		Shape: func(ctx context.Context) (err error) { inst, err = s.passkeys.Get(ctx); return err },
		Check: func(context.Context) error {
			var ok bool
			if cer, ok = s.tickets.OpenCeremony(tick); !ok {
				return errTicketInvalid()
			}
			return nil
		},
		Work: func(ctx context.Context, _ proof.Proved) (login.Result, error) {
			// The handler trusts nothing the browser sent but the credential id: the
			// stored row says which user it belongs to, which RP ID it was made for and
			// whether it is stale. Any mismatch refuses.
			var (
				info  store.PasskeyInfo
				dbErr error
			)
			resolve := func(rawID, handle []byte) (*passkey.User, error) {
				i, found, err := s.auth.PasskeyByCredential(ctx, rawID)
				if err != nil {
					dbErr = err // the library hides it; the route must answer 503, not 401
					return nil, err
				}
				if !found || i.StaleAt != nil || i.RPID != inst.RPID || !bytes.Equal(handle, i.UserID[:]) {
					return nil, passkey.ErrInvalid
				}
				info = i
				return passkey.FromInfo(rawID, i), nil
			}
			_, a, err := inst.FinishDiscoverable(resolve, cer.Session, body)
			if dbErr != nil {
				return login.Result{}, dbErr
			}
			if err != nil {
				return login.Result{}, passkey.ErrInvalid
			}
			// A challenge is single-use: of two requests that carry the same ticket and
			// a valid assertion, one records the nonce and the other is refused.
			if spent, err := s.auth.TicketSpend(ctx, cer.Spend, cer.Left); err != nil {
				return login.Result{}, err
			} else if !spent.Yes() {
				return login.Result{}, errTicketInvalid()
			}
			return s.openPasskeySession(ctx, inst, info, a, cer.Remember)
		},
	})
}

// openPasskeySession is steps 3 and 4 of 7.5: the review check, the counter
// rule, and the session. UV was required by the library, so the TOTP step is
// skipped (T-106).
func (s *Server) openPasskeySession(ctx context.Context, inst passkey.Instance, info store.PasskeyInfo, a passkey.Asserted, remember bool) (login.Result, error) {
	ip := httpx.ClientIPFrom(ctx)
	var (
		res     login.Result
		refused bool
		device  *http.Cookie
	)
	err := s.inTenant(ctx, info.TenantID, func(tx store.Tx) error {
		if st, err := tx.TenantStatus(); err != nil {
			return err
		} else if st != "active" {
			return errSuspended()
		}
		if _, ok, err := tx.UserLock(info.UserID); err != nil {
			return err
		} else if !ok {
			refused = true
			return nil
		}
		u, _, err := tx.User(info.UserID)
		if err != nil {
			return err
		}
		if u.PasskeyReviewAt != nil {
			refused = true
			return nil
		}
		all, err := tx.PasskeysList(info.UserID)
		if err != nil {
			return err
		}
		used, err := s.useCredential(tx, info.UserID, passkey.Live(all, inst.RPID), a, ip)
		if err != nil || !used {
			refused = !used
			return err
		}
		pending := u.EnforceLiftAt != nil && u.EnforceLiftAt.After(s.now())
		iss, restricted, err := s.login.OpenSession(tx, info.UserID, "passkey", remember, ip, httpx.UserAgentFrom(tx.Context()))
		if err != nil {
			return err
		}
		if pending {
			// The owner is back with the passkey: the delay ends, and whoever ran
			// Forgot Password is out (4.4, 7.5).
			if err := tx.ClearEnforceLift(info.UserID); err != nil {
				return err
			}
			if _, err := tx.SessionsRevokeOthers(info.UserID, iss.SessionID, s.now()); err != nil {
				return err
			}
		}
		device = s.login.DeviceCookie(tx, info.UserID)
		res = login.Result{Status: login.Authenticated, Session: iss, Restricted: restricted, Cookies: iss.Cookies()}
		return nil
	})
	if err != nil {
		return login.Result{}, err
	}
	if refused {
		return login.Result{}, passkey.ErrInvalid
	}
	if device != nil {
		res.Cookies = append(res.Cookies, device)
	}
	return res, nil
}

// PasskeyBegin is POST /account/passkeys/begin (spec 7.3).
func (s *Server) PasskeyBegin(ctx context.Context, _ gen.PasskeyBeginRequestObject) (gen.PasskeyBeginResponseObject, error) {
	p, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	inst, err := s.passkeys.Get(ctx)
	if err != nil {
		return nil, apiError(err)
	}
	var (
		pu   *passkey.User
		room bool
	)
	err = s.readTenant(ctx, p.TenantID, func(tx store.Tx) error {
		var err error
		if pu, _, _, err = s.passkeyUserTx(tx, inst, p.UserID); err != nil {
			return err
		}
		// Advice only: it spares a ceremony that cannot end. PasskeyAdd decides.
		room, err = tx.PasskeyHasRoom(p.UserID, caps.MaxPasskeys)
		return err
	})
	if err != nil {
		return nil, err
	}
	if !room {
		return nil, errValidation("passkeys", "too_many")
	}
	begin, err := inst.BeginRegistration(pu)
	if err != nil {
		return nil, apiError(err)
	}
	c, err := s.ceremony(ctx, ticket.Issue{Kind: store.TicketPasskeyRegister, Tenant: p.TenantID, User: p.UserID}, reauthPayload{WebAuthn: begin.Session}, begin.Options)
	if err != nil {
		return nil, err
	}
	return gen.PasskeyBegin200JSONResponse{PasskeyCeremonyJSONResponse: c}, nil
}

// PasskeyFinish is POST /account/passkeys/finish (spec 7.3).
func (s *Server) PasskeyFinish(ctx context.Context, req gen.PasskeyFinishRequestObject) (gen.PasskeyFinishResponseObject, error) {
	p, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	inst, err := s.passkeys.Get(ctx)
	if err != nil {
		return nil, apiError(err)
	}
	tk, ok, err := s.tickets.Take(ctx, req.Params.XCtrlzTicket, store.TicketPasskeyRegister)
	if err != nil {
		return nil, apiError(err)
	}
	if !ok {
		return nil, errTicketInvalid()
	}
	var pl reauthPayload
	if json.Unmarshal(tk.Payload, &pl) != nil || tk.Tenant != p.TenantID || tk.User != p.UserID {
		return nil, apiError(passkey.ErrInvalid)
	}
	var body []byte
	if req.Body != nil {
		body = *req.Body
	}
	var (
		row     store.Credential
		ended   int
		cookies []*http.Cookie
	)
	// The insert is the only statement here that can fail on a constraint (a
	// credential id that already exists in any tenant), and a failed statement
	// aborts the transaction, so a collision is the whole call's failure.
	smsNotice := s.wantNoticeSMS(ctx)
	err = s.inTenant(ctx, p.TenantID, func(tx store.Tx) error {
		// The user row lock first, the order of the other routes (internal/lockrank):
		// Apply later locks the session row. The cap is not decided here: PasskeyAdd
		// takes the same lock itself and compares the count inside the INSERT, so a
		// finish that forgot this line would still not pass the cap (round 4,
		// tenant-r4-1; round 5, rule caps-and-endings).
		if _, ok, err := tx.UserLock(p.UserID); err != nil {
			return err
		} else if !ok {
			return httpx.SessionExpired()
		}
		pu, _, _, err := s.passkeyUserTx(tx, inst, p.UserID)
		if err != nil {
			return err
		}
		reg, err := inst.FinishRegistration(pu, pl.WebAuthn, body)
		if err != nil {
			return err
		}
		// Begin checked the room before the ceremony; parallel begins can all pass it, so
		// the cap is decided where the row is written, by the INSERT itself (tenant-r3-3).
		// The default name comes from the same statement.
		row = reg.Credential
		row.UserID, row.Name = p.UserID, ""
		var added store.Won
		if row.ID, row.Name, added, err = tx.PasskeyAdd(row, caps.MaxPasskeys); err != nil {
			return err
		}
		if !added.Yes() {
			return errValidation("passkeys", "too_many")
		}
		out, err := s.d.Sessions.Apply(tx, session.EventPasskeyAdd, session.Actor{User: p.UserID, Session: p.SessionID})
		if err != nil {
			return err
		}
		ended, cookies = out.Ended, issuedCookies(out)
		// A passkey is a way back in that ending the other sessions does not remove, so the owner is told (tenant-r18-5,
		// D64 passkey-add-notice). credential_gen is not moved: that would only sign the owner out, and the new passkey
		// would stay. The audit row below is the trail and this is what the owner sees. It comes after the session event
		// and before the audit row, which is the order of the lock ranks (notifications 440, audit 460).
		noticeID, err := tx.SecurityNoticeAdd("passkey_added")
		if err != nil {
			return err
		}
		if err := audit.Tenant(tx, p.UserID, httpx.ClientIPFrom(tx.Context()), audit.PasskeyAdd{CredentialRowID: row.ID}); err != nil {
			return err
		}
		// The SMS to the account phone is the sign a thief in the panel cannot hide (question 19, spec 12.3):
		// after the audit row, whose count the daily cap reads, and in this transaction, so a rolled back
		// change queues nothing.
		if smsNotice {
			return noticeSMS(tx, p.UserID, noticeID)
		}
		return nil
	})
	if errors.Is(err, store.ErrConflict) {
		return nil, apiError(passkey.ErrInvalid)
	}
	if err != nil {
		return nil, err
	}
	setCookies(ctx, cookies...)
	row.CreatedAt = s.now()
	return gen.PasskeyFinish201JSONResponse{Passkey: passkeyRow(row, inst.RPID), EndedSessions: ended}, nil
}

// ListPasskeys is GET /account/passkeys.
func (s *Server) ListPasskeys(ctx context.Context, _ gen.ListPasskeysRequestObject) (gen.ListPasskeysResponseObject, error) {
	p, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	inst, err := s.passkeys.Get(ctx)
	if err != nil {
		return nil, apiError(err)
	}
	out := gen.PasskeyList{Passkeys: []gen.PasskeyRow{}}
	err = s.readTenant(ctx, p.TenantID, func(tx store.Tx) error {
		all, err := tx.PasskeysList(p.UserID)
		for _, c := range all {
			out.Passkeys = append(out.Passkeys, passkeyRow(c, inst.RPID))
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	return gen.ListPasskeys200JSONResponse(out), nil
}

// RenamePasskey is PATCH /account/passkeys/{id}.
func (s *Server) RenamePasskey(ctx context.Context, req gen.RenamePasskeyRequestObject) (gen.RenamePasskeyResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.BadRequest()
	}
	p, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	inst, err := s.passkeys.Get(ctx)
	if err != nil {
		return nil, apiError(err)
	}
	// The half-space of the Persian keyboard is dropped from a name (round 18, primitives-r18-3, D64
	// zwnj-fields): the schema lets it through so a person is not refused for a key they did not know
	// they pressed, and the stored name never holds it.
	name := strings.TrimSpace(strings.ReplaceAll(req.Body.Name, "\u200c", ""))
	if n := utf8.RuneCountInString(name); n < 1 || n > 64 {
		return nil, errValidation("name", "length")
	}
	var out gen.PasskeyRow
	err = s.inTenant(ctx, p.TenantID, func(tx store.Tx) error {
		if ok, err := tx.PasskeyRename(p.UserID, req.Id, name); err != nil {
			return err
		} else if !ok {
			return httpx.NotFound()
		}
		all, err := tx.PasskeysList(p.UserID)
		if err != nil {
			return err
		}
		for _, c := range all {
			if c.ID == req.Id {
				out = passkeyRow(c, inst.RPID)
			}
		}
		return audit.Tenant(tx, p.UserID, httpx.ClientIPFrom(tx.Context()), audit.PasskeyRename{CredentialRowID: req.Id})
	})
	if err != nil {
		return nil, err
	}
	return gen.RenamePasskey200JSONResponse(out), nil
}

// DeletePasskey is DELETE /account/passkeys/{id} (spec 7.3). Deleting the last
// live credential turns Enforce off in the same transaction, so the user is not
// left requiring something they no longer have.
func (s *Server) DeletePasskey(ctx context.Context, req gen.DeletePasskeyRequestObject) (gen.DeletePasskeyResponseObject, error) {
	p, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	inst, err := s.passkeys.Get(ctx)
	if err != nil {
		return nil, apiError(err)
	}
	device, err := s.inTenantOwner(ctx, p, func(tx store.Tx) error {
		// The user first: deleting the last live passkey writes the user (Enforce off),
		// and the user ranks before its credentials (spec 4.4).
		if _, ok, err := tx.UserLock(p.UserID); err != nil {
			return err
		} else if !ok {
			return httpx.SessionExpired()
		}
		if ok, err := tx.PasskeyDelete(p.UserID, req.Id); err != nil {
			return err
		} else if !ok {
			return httpx.NotFound()
		}
		live, err := tx.PasskeyLiveCount(p.UserID, inst.RPID)
		if err != nil {
			return err
		}
		if live == 0 {
			if err := tx.SetEnforce(p.UserID, false); err != nil {
				return err
			}
		}
		return audit.Tenant(tx, p.UserID, httpx.ClientIPFrom(tx.Context()), audit.PasskeyDelete{CredentialRowID: req.Id})
	})
	if err != nil {
		return nil, err
	}
	setCookies(ctx, device)
	return gen.DeletePasskey204Response{}, nil
}

// ReviewPasskeys is POST /account/passkeys/review (spec 7.7). The reauth that
// gets here cannot have been a passkey: passkey reauth is refused while the
// review flag is set.
func (s *Server) ReviewPasskeys(ctx context.Context, _ gen.ReviewPasskeysRequestObject) (gen.ReviewPasskeysResponseObject, error) {
	p, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := s.passkeys.Get(ctx); err != nil {
		return nil, apiError(err)
	}
	err = s.inTenant(ctx, p.TenantID, func(tx store.Tx) error {
		if err := tx.SetPasskeyReview(p.UserID, false); err != nil {
			return err
		}
		return audit.Tenant(tx, p.UserID, httpx.ClientIPFrom(tx.Context()), audit.PasskeyReview{})
	})
	if err != nil {
		return nil, err
	}
	return gen.ReviewPasskeys204Response{}, nil
}

// SetPasskeyEnforcement is PUT /account/passkey-enforcement (spec 7.5).
func (s *Server) SetPasskeyEnforcement(ctx context.Context, req gen.SetPasskeyEnforcementRequestObject) (gen.SetPasskeyEnforcementResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.BadRequest()
	}
	enable := req.Body.Enabled
	p, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	precondition := httpx.New(http.StatusConflict, httpx.CodeEnforcePrecondition)
	var rpID string
	smsUp := false
	if enable {
		inst, err := s.passkeys.Get(ctx)
		if errors.Is(err, passkey.ErrDisabled) {
			return nil, precondition
		}
		if err != nil {
			return nil, err
		}
		rpID = inst.RPID
		cfg, err := s.cfg.Get(ctx)
		if err != nil {
			return nil, err
		}
		smsUp = cfg.SMSAvailable
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
		ev := session.EventEnforceDisable
		if enable {
			u, _, err := tx.User(p.UserID)
			if err != nil {
				return err
			}
			live, err := tx.PasskeyLiveCount(p.UserID, rpID)
			if err != nil {
				return err
			}
			hasPassword, _, err := tx.UserFlags(p.UserID)
			if err != nil {
				return err
			}
			// A working second way (7.5): a password, or a verified phone with SMS up.
			secondWay := hasPassword || (u.PhoneVerifiedAt != nil && smsUp)
			if live == 0 || !secondWay || u.PasskeyReviewAt != nil {
				return precondition
			}
			ev = session.EventEnforceEnable
		}
		if err := tx.SetEnforce(p.UserID, enable); err != nil {
			return err
		}
		out, err := s.d.Sessions.Apply(tx, ev, session.Actor{User: p.UserID, Session: p.SessionID})
		if err != nil {
			return err
		}
		ended, cookies = out.Ended, issuedCookies(out)
		return audit.Tenant(tx, p.UserID, httpx.ClientIPFrom(tx.Context()), audit.PasskeyEnforce{Enabled: enable})
	})
	if err != nil {
		return nil, err
	}
	setCookies(ctx, append(cookies, device)...)
	return gen.SetPasskeyEnforcement200JSONResponse{SessionsEndedJSONResponse: gen.SessionsEndedJSONResponse{EndedSessions: ended}}, nil
}
