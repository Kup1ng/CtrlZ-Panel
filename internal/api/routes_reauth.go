package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"slices"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/api/gen"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/audit"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/credstate"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/otp"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/passkey"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/proof"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/session"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/throttle"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/ticket"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/totp"
	"github.com/Kup1ng/CtrlZ-Panel/internal/credgen"
	"github.com/Kup1ng/CtrlZ-Panel/internal/httpx"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// reauthFacts is what decides which proof a reauth needs (spec 3.5).
type reauthFacts struct {
	user        store.User
	hasPassword bool
	hasTOTP     bool
	// sessionMethod is how the session opened (sessions.auth_method), read with the rest so that a route
	// which waives the reauth window only for a session opened by the password itself can refuse the
	// others before it does any heavy work (tenant-r7-5). The transaction still decides, under the lock.
	sessionMethod string
}

func (s *Server) reauthFacts(ctx context.Context, p session.Principal) (reauthFacts, error) {
	var f reauthFacts
	err := s.readTenant(ctx, p.TenantID, func(tx store.Tx) error {
		u, ok, err := tx.User(p.UserID)
		if err != nil {
			return err
		}
		if !ok {
			return httpx.SessionExpired()
		}
		has, _, err := tx.UserFlags(p.UserID)
		if err != nil {
			return err
		}
		me, ok, err := tx.SessionByID(p.SessionID)
		if err != nil {
			return err
		}
		if !ok || me.RevokedAt != nil {
			return httpx.SessionExpired()
		}
		f = reauthFacts{user: u, hasPassword: has, hasTOTP: u.TOTPEnabledAt != nil, sessionMethod: me.AuthMethod}
		return nil
	})
	return f, err
}

// reauthFailed records a failed proof. Its own transaction, so it survives the
// refusal that follows; a failure to write it does not change the answer.
func (s *Server) reauthFailed(ctx context.Context, p session.Principal, method audit.Method) {
	_ = s.d.Store.WithTenant(ctx, p.TenantID, store.TxOpts{}, func(tx store.Tx) error {
		return audit.Tenant(tx, p.UserID, httpx.ClientIPFrom(tx.Context()), audit.ReauthFailed{Method: method})
	})
}

// Reauth is POST /auth/reauth (spec 3.5).
func (s *Server) Reauth(ctx context.Context, req gen.ReauthRequestObject) (gen.ReauthResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.BadRequest()
	}
	p, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	b := *req.Body
	cookies, err := floored(ctx, floorVerify, func(ctx context.Context) ([]*http.Cookie, error) { return s.reauth(ctx, p, b) })
	if err != nil {
		return nil, apiError(err)
	}
	setCookies(ctx, cookies...)
	return gen.Reauth204Response{}, nil
}

// reauthHash is the hash a reauth password is checked against: the session
// user's own, or an empty one (the dummy verify, so a miss costs the same).
//
// The row comes from a lookup by phone. A phone can move between accounts (a phone
// change) between the read of the session user's number and this lookup, so the hash is
// used only when the row's stamp is the session user's own (internal/credgen: the same
// subject in the same tenant, under the generation the facts were read at): another
// tenant's hash must never decide this session's reauth (review round 1, tenant-r1-14),
// and a password that changed between the two reads is not the one to verify. A
// one-time password past its expiry counts as wrong (4.5).
func reauthHash(want credgen.Stamp, login store.UserLogin, found bool) secret.String {
	if !found || !login.Cred.Holds(want) {
		return secret.String{}
	}
	if !credstate.Named(credstate.Tenant, "reauth", login.State).Permits() {
		return secret.String{}
	}
	return login.PasswordHash
}

func (s *Server) reauth(ctx context.Context, p session.Principal, b gen.ReauthRequest) ([]*http.Cookie, error) {
	f, err := s.reauthFacts(ctx, p)
	if err != nil {
		return nil, err
	}
	ip := httpx.ClientIPFrom(ctx)
	var method audit.Method       // what has been proved so far
	var pwCharge throttle.Charged // the attempt the password step counted, if it ran

	// The password is checked first and outside the transaction (Argon2 time).
	if f.hasPassword {
		method = audit.MethodPassword
		if pwCharge, err = s.throttle.ChargeProof(ctx, throttle.ReauthSession, throttle.Who{Session: p.SessionID}); err != nil {
			return nil, err
		}
		login, found, err := s.auth.UserByPhone(ctx, f.user.Phone)
		if err != nil {
			return nil, err
		}
		stored := reauthHash(f.user.Stamp(), login, found)
		ok, err := s.verifyStored(ctx, secret.New(deref(b.Password)), stored)
		if err != nil {
			if proof.Busy(err) {
				// The gate turned the request away and looked at no password: the try goes back, or
				// five busy answers lock the owner out of reauth for the window once the load has gone
				// (tenant-r6-8; the same rule as proof.Spec.Refund, for a route that is not a Spec).
				_ = s.throttle.Refund(context.WithoutCancel(ctx), throttle.ReauthSession, throttle.Who{Session: p.SessionID})
			}
			return nil, err
		}
		if !ok {
			s.reauthFailed(ctx, p, method)
			return nil, errInvalidCredentials()
		}
		if !f.hasTOTP {
			_ = s.throttle.Clear(ctx, throttle.ReauthSession, throttle.Who{Session: p.SessionID})
		}
	}

	// SMS opens a reauth only for a user with neither a password nor TOTP.
	if !f.hasPassword && !f.hasTOTP {
		method = audit.MethodOTP
		// The per-user scope the password path uses (3.5): a stolen cookie cannot try
		// codes at the pace of many networks and many challenges.
		// Only the user scope: a signed-in caller has a subject, and a network scope is
		// never charged by a request that carries a verified proof (budget-keying).
		if err := s.throttle.Charge(ctx, throttle.ReauthSession, throttle.Who{Session: p.SessionID}); err != nil {
			return nil, err
		}
		if b.OtpChallengeId == nil {
			return nil, otp.ErrInvalid
		}
		if err := s.otp.Check(ctx, *b.OtpChallengeId, f.user.Phone, otp.Login, deref(b.OtpCode)); err != nil {
			s.reauthFailed(ctx, p, audit.MethodOTP)
			return nil, err
		}
		_ = s.throttle.Clear(ctx, throttle.ReauthSession, throttle.Who{Session: p.SessionID})
	}

	// The code is counted before the transaction opens, after the password it follows (a wrong
	// password never reaches the second factor), on the scope the password already counted on.
	var fc factorCharge
	if f.hasTOTP {
		if fc, err = s.chargeFactor(ctx, throttle.ReauthSession, "", throttle.Who{Session: p.SessionID}, p.UserID, pwCharge, deref(b.TotpCode), deref(b.RecoveryCode)); err != nil {
			return nil, err
		}
	}
	var cookies []*http.Cookie
	err = s.inTenant(ctx, p.TenantID, func(tx store.Tx) error {
		// The proof asked for was decided from a read before the password check, and the
		// password was verified against the row of that read. If any credential moved
		// since (TOTP enabled, a first password set, a password changed), the proof sent
		// may no longer be enough or no longer be the right one: ask the client to start
		// again. One call, by generation, whichever column moved.
		if _, ok, err := tx.UserLockFor(p.UserID, f.user.Stamp()); errors.Is(err, credgen.ErrStale) {
			return httpx.New(http.StatusConflict, httpx.CodeConflict)
		} else if err != nil {
			return err
		} else if !ok {
			return httpx.SessionExpired()
		}
		if f.hasTOTP {
			m, err := s.secondFactor(tx, fc, p.UserID, deref(b.TotpCode), deref(b.RecoveryCode))
			if err != nil {
				return err
			}
			method = method.WithSecondFactor(audit.MethodOf(m))
		}
		out, err := s.d.Sessions.Apply(tx, session.EventReauth, session.Actor{User: p.UserID, Session: p.SessionID})
		if err != nil {
			return err
		}
		cookies = issuedCookies(out)
		return audit.Tenant(tx, p.UserID, ip, audit.ReauthOK{Method: method})
	})
	if err != nil {
		if isWrongProof(err) {
			// A failed second factor: the one the request tried, after what was proved.
			tried := audit.MethodUnknown
			switch {
			case deref(b.TotpCode) != "":
				tried = audit.MethodTOTP
			case deref(b.RecoveryCode) != "":
				tried = audit.MethodRecovery
			}
			s.reauthFailed(ctx, p, method.WithSecondFactor(tried))
		}
		return nil, err
	}
	fc.clear(ctx)
	return cookies, nil
}

// ReauthOtpRequest is POST /auth/reauth/otp/request (spec 3.5): a code to the
// session's own number. The number comes from the database row of the session's
// user, never from the request, so a body or query cannot aim it elsewhere.
func (s *Server) ReauthOtpRequest(ctx context.Context, _ gen.ReauthOtpRequestRequestObject) (gen.ReauthOtpRequestResponseObject, error) {
	p, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	f, err := s.reauthFacts(ctx, p)
	if err != nil {
		return nil, err
	}
	if f.hasPassword || f.hasTOTP {
		return nil, httpx.New(http.StatusConflict, httpx.CodeConflict)
	}
	ch, err := floored(ctx, floorOTPReq, func(ctx context.Context) (otp.Challenge, error) {
		return s.otp.RequestForSession(ctx, otp.ForReauth, f.user.Phone, f.user.Locale, httpx.ClientIPFrom(ctx))
	})
	if err != nil {
		return nil, apiError(err)
	}
	return gen.ReauthOtpRequest202JSONResponse{SessionOtpIssuedJSONResponse: sessionOtpIssued(ch)}, nil
}

// reauthPayload is the ticket payload of a passkey_reauth ticket: the WebAuthn
// session data, and what the ticket is bound to (7.6).
type reauthPayload struct {
	SessionID uuid.UUID       `json:"session_id,omitempty"`
	ResetHash string          `json:"reset_hash,omitempty"`
	WebAuthn  json.RawMessage `json:"webauthn"`
}

// ReauthPasskeyBegin is POST /auth/reauth/passkey/begin (spec 7.6). It never
// calls the discoverable flow: the user is known from the session.
func (s *Server) ReauthPasskeyBegin(ctx context.Context, _ gen.ReauthPasskeyBeginRequestObject) (gen.ReauthPasskeyBeginResponseObject, error) {
	p, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	inst, err := s.passkeys.Get(ctx)
	if err != nil {
		return nil, apiError(err)
	}
	pu, _, review, err := s.passkeyUser(ctx, inst, p.TenantID, p.UserID)
	if err != nil {
		return nil, err
	}
	if review || len(pu.WebAuthnCredentials()) == 0 {
		return nil, httpx.New(http.StatusUnauthorized, httpx.CodePasskeyInvalid)
	}
	begin, err := inst.BeginLogin(pu)
	if err != nil {
		return nil, apiError(err)
	}
	c, err := s.ceremony(ctx, ticket.Issue{Kind: store.TicketPasskeyReauth, Tenant: p.TenantID, User: p.UserID}, reauthPayload{SessionID: p.SessionID, WebAuthn: begin.Session}, begin.Options)
	if err != nil {
		return nil, err
	}
	return gen.ReauthPasskeyBegin200JSONResponse{PasskeyCeremonyJSONResponse: c}, nil
}

// ReauthPasskeyFinish is POST /auth/reauth/passkey/finish (spec 7.6).
func (s *Server) ReauthPasskeyFinish(ctx context.Context, req gen.ReauthPasskeyFinishRequestObject) (gen.ReauthPasskeyFinishResponseObject, error) {
	p, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	var body []byte
	if req.Body != nil {
		body = *req.Body
	}
	cookies, err := floored(ctx, floorVerify, func(ctx context.Context) ([]*http.Cookie, error) {
		return s.reauthPasskeyFinish(ctx, p, req.Params.XCtrlzTicket, body)
	})
	if err != nil {
		return nil, apiError(err)
	}
	setCookies(ctx, cookies...)
	return gen.ReauthPasskeyFinish204Response{}, nil
}

func (s *Server) reauthPasskeyFinish(ctx context.Context, p session.Principal, tick string, body []byte) ([]*http.Cookie, error) {
	inst, err := s.passkeys.Get(ctx)
	if err != nil {
		return nil, err
	}
	ip := httpx.ClientIPFrom(ctx)
	// A scope of its own: an assertion cannot be walked, so it has no ceiling, and it must not spend the one the
	// password and the code of the same session share (round 9, primitives-r9-4).
	if err := s.throttle.Charge(ctx, throttle.ReauthPasskey, throttle.Who{Session: p.SessionID}); err != nil {
		return nil, err
	}
	tk, ok, err := s.tickets.Take(ctx, tick, store.TicketPasskeyReauth)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errTicketInvalid()
	}
	var pl reauthPayload
	if json.Unmarshal(tk.Payload, &pl) != nil || tk.Tenant != p.TenantID || tk.User != p.UserID || pl.SessionID != p.SessionID || pl.ResetHash != "" {
		return nil, passkey.ErrInvalid
	}
	var cookies []*http.Cookie
	refused := false
	err = s.inTenant(ctx, p.TenantID, func(tx store.Tx) error {
		pu, creds, review, err := s.passkeyUserTx(tx, inst, p.UserID)
		if err != nil {
			return err
		}
		if review {
			refused = true
			return nil
		}
		a, err := inst.FinishLogin(pu, pl.WebAuthn, body)
		if err != nil {
			refused = true
			return nil
		}
		used, err := s.useCredential(tx, p.UserID, creds, a, ip)
		if err != nil || !used {
			refused = !used
			return err
		}
		out, err := s.d.Sessions.Apply(tx, session.EventReauth, session.Actor{User: p.UserID, Session: p.SessionID})
		if err != nil {
			return err
		}
		cookies = issuedCookies(out)
		return audit.Tenant(tx, p.UserID, ip, audit.ReauthOK{Method: audit.MethodPasskey})
	})
	if err != nil {
		return nil, err
	}
	if refused {
		return nil, passkey.ErrInvalid
	}
	// The owner's authenticator answered: the run of guesses at the password and the code ends as well.
	_ = s.throttle.Clear(ctx, throttle.ReauthPasskey, throttle.Who{Session: p.SessionID})
	_ = s.throttle.Clear(ctx, throttle.ReauthSession, throttle.Who{Session: p.SessionID})
	return cookies, nil
}

// useCredential applies the counter rule of 7.5 step 3 in the transaction. false
// means refused; a refusal for a counter that did not advance also writes
// passkey.clone_suspect, so the caller commits the transaction and then answers.
func (s *Server) useCredential(tx store.Tx, user uuid.UUID, live []store.Credential, a passkey.Asserted, ip netip.Addr) (bool, error) {
	// The user first (spec 4.4, internal/lockrank): the credential row ranks after it,
	// and a reauth goes on to rotate the session, whose new refresh row needs the
	// key share anyway. A caller that locked the user already asks for nothing new.
	if held, err := tx.UserKeyShare(user); err != nil || !held {
		return false, err
	}
	var row *store.Credential
	for i := range live {
		if bytes.Equal(live[i].CredentialID, a.CredentialID) {
			row = &live[i]
		}
	}
	if row == nil {
		return false, nil
	}
	used, err := tx.PasskeyUsed(user, row.ID, a.SignCount, a.BackupState)
	if err != nil || used {
		return used, err
	}
	return false, audit.Tenant(tx, user, ip, audit.PasskeyCloneSuspect{CredentialRowID: row.ID})
}

// ---------------------------------------------------------------------------
// Password change and sessions

// ChangePassword is POST /account/password (spec 4.4).
func (s *Server) ChangePassword(ctx context.Context, req gen.ChangePasswordRequestObject) (gen.ChangePasswordResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.BadRequest()
	}
	b := *req.Body
	p, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	f, err := s.reauthFacts(ctx, p)
	if err != nil {
		return nil, err
	}
	// The one-time password just proved knowledge, so a restricted session needs
	// no reauth window, for as long as it is live; every other session needs one (4.4).
	// One row of the table says which (internal/auth/credstate).
	//
	// The waiver is for a session that OPENED with the one-time password, and that is read here
	// as well as in the transaction: a session opened by an SMS code or a passkey is restricted
	// too but is refused in the transaction, so letting it through to the scoring and the Argon2
	// hash (and the code charge below) spent a slot of the signed-in gate and a try of the
	// second factor for an answer that was already known (tenant-r7-5, rule proof-before-work:
	// decide whether the caller may proceed before the heavy work).
	v := credstate.Named(credstate.Tenant, "changePassword", f.user.State)
	if !s.d.Sessions.ReauthFresh(p.ReauthAt) && !(v == credstate.FreshUnlessPassword && f.sessionMethod == "password") {
		return nil, errReauth()
	}
	// A session that is not fresh and has a second factor is asked for a code inside the
	// transaction (decided under the row lock); the attempt is counted here, before it opens,
	// for every request that may be asked. The code is then looked at without being spent, BEFORE the
	// scoring and the hash (rule proof-before-work, as in the reset): a request with no code, or one that
	// cannot be right, used to pay for both, and a slot of the signed-in gate, before it ended here (round 9,
	// tenant-r9-2). The transaction below is still the check that decides.
	var fc factorCharge
	if f.user.TOTPEnabledAt != nil && !s.d.Sessions.ReauthFresh(p.ReauthAt) {
		if deref(b.TotpCode) == "" {
			// No code is a wrong code and spends nothing (chargeFactor); nothing is read for it either.
			return nil, apiError(totp.ErrInvalid)
		}
		if fc, err = s.chargeFactor(ctx, throttle.TOTPSession, "", throttle.Who{Session: p.SessionID}, p.UserID, throttle.Charged{}, deref(b.TotpCode), ""); err != nil {
			return nil, apiError(err)
		}
		if err := s.readTenant(ctx, p.TenantID, func(tx store.Tx) error {
			return s.peekSecondFactor(tx, fc, p.UserID, deref(b.TotpCode), "")
		}); err != nil {
			return nil, apiError(err)
		}
	}
	hash, err := s.preparePassword(ctx, b.NewPassword, f.user.Phone, "new_password")
	if err != nil {
		if fc.made && proof.Busy(err) {
			// The gate turned the request away and looked at nothing: the try goes back (as in the reset).
			fc.refund(ctx)
		}
		return nil, apiError(err)
	}
	var (
		cookies []*http.Cookie
		device  *http.Cookie
		ip      = httpx.ClientIPFrom(ctx)
	)
	err = s.inTenant(ctx, p.TenantID, func(tx store.Tx) error {
		// The row lock first, then the session read inside Apply: of this and an
		// admin's re-issue of a one-time password, whichever commits first wins
		// (4.4). A session the re-issue revoked cannot set a password.
		lock, ok, err := tx.UserLock(p.UserID)
		if err != nil {
			return err
		}
		if !ok {
			return httpx.SessionExpired()
		}
		// The reauth window is waived only for a session that opened with the
		// one-time password itself. A session opened by an SMS code or a passkey
		// is restricted too, but nothing there proved knowledge of the password,
		// and 3.5 says an SMS code never stands in for it (review round 1,
		// tenant-r1-3). Read under the row lock, so a re-issue that revoked the
		// session is seen.
		me, ok, err := tx.SessionByID(p.SessionID)
		if err != nil {
			return err
		}
		if !ok || me.RevokedAt != nil {
			return httpx.SessionExpired()
		}
		fresh := s.d.Sessions.ReauthFresh(p.ReauthAt)
		// The one-time password must still be live: its proof does not outlast it,
		// and a Remember me session can (round 2, tenant-r2-6).
		verdict := credstate.Named(credstate.Tenant, "changePassword", lock.State)
		waived := verdict == credstate.FreshUnlessPassword && me.AuthMethod == "password"
		if !verdict.Permits() || (!fresh && !waived) {
			return errReauth()
		}
		locked, _, err := tx.User(p.UserID)
		if err != nil {
			return err
		}
		// A fresh reauth already proved the second factor (3.5), so asking for a
		// code again protects nothing: POST /account/totp/disable needs only the
		// same window. A waived reauth proved no second factor, so it is asked
		// for here (review round 1, tenant-r1-4 and -13).
		if waived && !fresh && locked.TOTPEnabledAt != nil {
			if _, err := s.secondFactor(tx, fc, p.UserID, deref(b.TotpCode), ""); err != nil {
				return err
			}
		}
		// What a reauth asks for, before the change: this route is a password change for a user who has a
		// password and the FIRST password of one who has none, and the second raises the bar from an SMS code to
		// the password, so Apply ends a window earned by SMS (round 11, primitives-r11-4).
		before, err := session.FactorsOf(tx, p.UserID)
		if err != nil {
			return err
		}
		if _, err := tx.SetPassword(p.UserID, hash); err != nil {
			return err
		}
		out, err := s.d.Sessions.Apply(tx, session.EventPasswordChange, session.Actor{User: p.UserID, Session: p.SessionID, Before: &before})
		if err != nil {
			return err
		}
		cookies = issuedCookies(out)
		// The change moves the credential generation and so ends every device marker
		// issued before it, an intruder's included (tenant-r4-5). The owner is here:
		// this browser gets one for the new generation.
		device = s.login.DeviceCookie(tx, p.UserID)
		return audit.Tenant(tx, p.UserID, ip, audit.PasswordChange{})
	})
	if err != nil {
		return nil, err
	}
	fc.clear(ctx)
	setCookies(ctx, cookies...)
	if device != nil {
		setCookies(ctx, device)
	}
	return gen.ChangePassword204Response{}, nil
}

// ListSessions is GET /account/sessions (spec 12.1).
func (s *Server) ListSessions(ctx context.Context, _ gen.ListSessionsRequestObject) (gen.ListSessionsResponseObject, error) {
	p, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	out := gen.SessionList{Sessions: []gen.SessionRow{}}
	err = s.readTenant(ctx, p.TenantID, func(tx store.Tx) error {
		rows, err := tx.SessionsList(p.UserID, s.now())
		if err != nil {
			return err
		}
		// The list is the newest sessions and the caller's own may be older than all of them: it is still shown,
		// in the place of the oldest listed (it is older still, so the order holds), and the count stays inside
		// the maxItems of the document.
		if len(rows) == store.SessionListLimit && !slices.ContainsFunc(rows, func(r store.SessionRow) bool { return r.ID == p.SessionID }) {
			if cur, ok, err := tx.SessionByID(p.SessionID); err != nil {
				return err
			} else if ok {
				rows[len(rows)-1] = cur
			}
		}
		for _, r := range rows {
			ip := ""
			if r.IP != nil {
				ip = r.IP.String()
			}
			out.Sessions = append(out.Sessions, gen.SessionRow{
				Id: r.ID, Current: r.ID == p.SessionID, CreatedAt: r.CreatedAt, LastSeenAt: r.LastSeenAt,
				AuthMethod: gen.SessionRowAuthMethod(r.AuthMethod), Ip: ip, UserAgent: r.UserAgent,
			})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return gen.ListSessions200JSONResponse(out), nil
}

// DeleteSession is DELETE /account/sessions/{id} (spec 12.1). A session older
// than the caller's can be ended with no more proof; a newer one needs a live
// reauth window. Rotation keeps created_at, so an owner who has just logged in
// can remove a thief at once, and the thief cannot throw the owner out.
func (s *Server) DeleteSession(ctx context.Context, req gen.DeleteSessionRequestObject) (gen.DeleteSessionResponseObject, error) {
	p, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	if req.Id == p.SessionID {
		return nil, errValidation("id", "current_session")
	}
	err = s.inTenant(ctx, p.TenantID, func(tx store.Tx) error {
		target, ok, err := tx.SessionByID(req.Id)
		if err != nil {
			return err
		}
		if !ok || target.UserID != p.UserID || target.RevokedAt != nil {
			return httpx.NotFound()
		}
		me, ok, err := tx.SessionByID(p.SessionID)
		if err != nil {
			return err
		}
		if !ok || me.RevokedAt != nil {
			return httpx.SessionExpired()
		}
		if target.CreatedAt.After(me.CreatedAt) && !s.d.Sessions.ReauthFresh(p.ReauthAt) {
			return errReauth()
		}
		if ended, err := tx.SessionRevoke(p.UserID, req.Id); err != nil {
			return err
		} else if !ended {
			return httpx.NotFound()
		}
		return audit.Tenant(tx, p.UserID, httpx.ClientIPFrom(tx.Context()), audit.SessionRevoke{SessionID: req.Id})
	})
	if err != nil {
		return nil, err
	}
	return gen.DeleteSession204Response{}, nil
}
