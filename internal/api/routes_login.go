package api

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/afterwork"
	"github.com/Kup1ng/CtrlZ-Panel/internal/api/gen"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/audit"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/credstate"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/invite"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/login"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/marker"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/otp"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/password"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/phone"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/proof"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/pwstrength"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/session"
	"github.com/Kup1ng/CtrlZ-Panel/internal/httpx"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// loginResult builds the body of every route that ends in a first factor or a
// session. The ticket is revealed here and nowhere else: it is the one secret a
// login response carries, and it is shown to the client that earned it.
func loginResult(r login.Result) gen.LoginResultJSONResponse {
	out := gen.LoginResultJSONResponse{Status: gen.LoginResultStatus(r.Status)}
	if r.Status == login.MFARequired {
		t := r.Ticket.Reveal()
		secs := int(r.TicketTTL / time.Second)
		out.Ticket, out.TicketExpiresInS = &t, &secs
		var ms []gen.LoginResultMethods
		for _, m := range r.Methods {
			ms = append(ms, gen.LoginResultMethods(m))
		}
		out.Methods = &ms
	}
	return out
}

func otpIssued(c otp.Challenge) gen.OtpIssuedJSONResponse {
	return gen.OtpIssuedJSONResponse{
		ChallengeId: c.Token, ExpiresInS: int(c.ExpiresIn / time.Second), ResendAfterS: int(c.ResendAfter / time.Second),
	}
}

func deref[T any](p *T) T {
	var zero T
	if p == nil {
		return zero
	}
	return *p
}

// preparePassword is the rule of 4.2 and 4.3 for a password a signed-in user is setting:
// length, then strength against what the password must not resemble, then the hash. It
// runs before anything is consumed (a weak password must not burn an OTP, 5.6) and outside
// every transaction (4.4). field names the JSON field in the 422. A route whose caller has
// no session calls preparePasswordOn from the Work step of a proof.Spec instead.
func (s *Server) preparePassword(ctx context.Context, pw, e164, field string) (secret.String, error) {
	return s.preparePasswordOn(ctx, s.strength, pw, e164, field)
}

// preparePasswordOn is preparePassword with the scoring gate named. A route whose caller
// has proved a credential but holds no session (registration, Forgot Password) passes
// strengthAnon, so it never takes a slot of the gate that signed-in password change and
// the admin routes share (review round 4, tenant-r4-2 and -6). Such a caller reaches it
// only from the Work step of a proof.Spec, after the code or the ticket was checked (rule
// proof-before-work).
func (s *Server) preparePasswordOn(ctx context.Context, gate *pwstrength.Checker, pw, e164, field string) (secret.String, error) {
	p, err := password.Prepare(secret.New(pw), password.User)
	if err != nil {
		return secret.String{}, passwordWeak(err, field)
	}
	r, err := gate.Check(ctx, p, pwstrength.Input{Phone: e164}, password.User)
	if err != nil {
		return secret.String{}, err
	}
	if !r.OK {
		return secret.String{}, httpx.New(422, httpx.CodePasswordWeak).WithFields(httpx.FieldError{Name: field, Code: string(r.Reason)})
	}
	return s.hasher.Hash(ctx, p.Normalized())
}

// checkPasswordLength is the shape check of a password somebody is setting: the length
// rules of 4.2, which cost nothing, and not the scoring, which does (rule proof-before-work:
// the scoring waits for the proof). It names the 422 so a password that cannot be right is
// refused before the proof is looked at.
func checkPasswordLength(pw, field string) error {
	if _, err := password.Prepare(secret.New(pw), password.User); err != nil {
		return passwordWeak(err, field)
	}
	return nil
}

// passwordWeak turns a password.Prepare error into the 422.
func passwordWeak(err error, field string) *httpx.Error {
	code := "invalid"
	switch {
	case errors.Is(err, password.ErrTooShort):
		code = string(pwstrength.TooShort)
	case errors.Is(err, password.ErrTooLong):
		code = "too_long"
	}
	return httpx.New(422, httpx.CodePasswordWeak).WithFields(httpx.FieldError{Name: field, Code: code})
}

// LoginPassword is POST /auth/login/password (spec 4.5, 5.7).
func (s *Server) LoginPassword(ctx context.Context, req gen.LoginPasswordRequestObject) (gen.LoginPasswordResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.BadRequest()
	}
	b := *req.Body
	var owed afterwork.Owed
	res, err := floored(ctx, floorLogin, func(ctx context.Context) (login.Result, error) { return s.loginPassword(ctx, b, &owed) })
	// The trail row of a wrong password is written now, off the request: inside the floor it would
	// be an acquisition of the pool that only a phone with an account makes (tenant-r13-2).
	owed.Run(ctx, s.after)
	if err != nil {
		return nil, apiError(err)
	}
	setCookies(ctx, res.Cookies...)
	return gen.LoginPassword200JSONResponse{LoginResultJSONResponse: loginResult(res)}, nil
}

// loginPassword is the body of the 500 ms floor, in the shape of rule proof-before-work.
// A first factor has no proof to look at before it is verified, so the Spec is of Kind
// Password: the budget is charged first, and the one Argon2 verify, which runs on every
// path (a malformed number, an unknown phone, an OTP-only account and an expired one-time
// password all verify against the dummy), is the first thing in Work.
func (s *Server) loginPassword(ctx context.Context, b gen.LoginPasswordRequest, owed *afterwork.Owed) (login.Result, error) {
	ip := httpx.ClientIPFrom(ctx)
	e164, perr := phone.Normalize(b.Phone)
	// markerID is set only for a device marker that holds for the account typed (tenant-r5-9),
	// and read is the account read to decide that, so Work does not read it again.
	var (
		markerID string
		read     *accountRead
	)
	return proof.Run(ctx, proof.Spec[login.Result]{
		Kind: proof.Password,
		Charge: func(ctx context.Context) error {
			if perr != nil {
				// A bad format must not vary the response (4.5), so it is verified like
				// any other attempt. It is counted on the network scopes only: one shared
				// per-phone key let anybody spend it for every client (tenant-r3-8).
				return s.throttle.LoginHitsMalformed(ctx, ip)
			}
			// A device marker that passed its seal costs one indexed read to match it with the
			// account, as on the admin login. It is the marker of THIS account or it is nothing:
			// a marker minted for another account by signing in does not hold, and the attempt
			// counts on login_phone like anyone's.
			if m := s.markers.Open(marker.User, httpx.CookieFrom(ctx, session.CookieDevice)); !m.Zero() {
				u, found, err := s.auth.UserByPhone(ctx, e164)
				if err != nil {
					return err
				}
				read = &accountRead{u, found}
				if found && m.Holds(u.Cred) {
					markerID = m.ID
				}
			}
			return s.throttle.LoginHitsFor(ctx, e164, ip, markerID)
		},
		// An attempt the Argon2 gate turned away looked at no password: it gets its count back on
		// every scope it was counted on (tenant-r5-1). The scopes are the same whether or not the
		// number has an account, so this cannot tell one from the other.
		Refund: func(ctx context.Context) {
			if perr != nil {
				_ = s.throttle.LoginRefundMalformed(ctx, ip)
				return
			}
			_ = s.throttle.LoginRefund(ctx, e164, ip, markerID)
		},
		Work: func(ctx context.Context, _ proof.Proved) (login.Result, error) {
			// A browser whose device marker opened under its seal and holds for the account found is a
			// proof: its verify is served before any stranger when the gate is full (tenant-r6-1, as on
			// the admin login). markerID is set only in that case.
			// A marker is minted by every login, so it is a proof a holder can reuse for ever: the lane is
			// bounded per account (ProvedAs, tenant-r7-6).
			if markerID != "" && read != nil {
				ctx = password.ProvedAs(ctx, read.u.UserID.String())
			}
			return s.passwordLogin(ctx, b, e164, perr == nil, ip, markerID, read, owed)
		},
	})
}

// passwordLogin is the Work step of loginPassword: the lookup, the one verify, and the
// session. The rehash of a hash written under older parameters is after the verify, so it
// is work for a caller who proved the password. read is the account the Charge step read
// to match a device marker, or nil.
func (s *Server) passwordLogin(ctx context.Context, b gen.LoginPasswordRequest, e164 string, wellFormed bool, ip netip.Addr, markerID string, read *accountRead, owed *afterwork.Owed) (login.Result, error) {
	var u store.UserLogin
	var found bool
	switch {
	case read != nil:
		u, found = read.u, read.found
	case wellFormed:
		var err error
		if u, found, err = s.auth.UserByPhone(ctx, e164); err != nil {
			return login.Result{}, err
		}
	}
	stored := u.PasswordHash
	// A one-time password past its expiry is a wrong password: the stored hash is not used and
	// the dummy is verified instead (4.5). The table says which states may use it.
	if !found || !credstate.Named(credstate.Tenant, "loginPassword", u.State).Permits() {
		stored = secret.String{}
	}
	pw := secret.New(b.Password)
	ok, err := s.verifyStored(ctx, pw, stored)
	if err != nil {
		return login.Result{}, err
	}
	if !ok {
		if found {
			// A failed login is recorded in a transaction of its own, so it stays whatever happens next,
			// and AFTER the floor: this branch is chosen by the account's existence, and a second
			// acquisition of the pool inside the floor is a wait only a phone with an account pays
			// (tenant-r13-2, rule known-unknown-oracle). Failing to write it does not change the answer.
			tenant, user := u.TenantID, u.UserID
			owed.Add(func(ctx context.Context) {
				_ = s.d.Store.WithTenant(ctx, tenant, store.TxOpts{}, func(tx store.Tx) error {
					return audit.Tenant(tx, user, ip, audit.LoginFailed{Method: audit.MethodPassword})
				})
			})
		}
		return login.Result{}, errInvalidCredentials()
	}
	_ = s.throttle.LoginSuccess(ctx, e164, ip, markerID) // clearing is a convenience, not a gate

	in := login.Input{
		User: u, Factor: login.Password, Remember: deref(b.RememberMe), IP: ip, UserAgent: httpx.UserAgentFrom(ctx),
	}
	if s.hasher.NeedsRehash(stored) {
		// Parameters changed since this hash was written: store a fresh one in
		// the same transaction as the session (4.1).
		if h, err := s.hasher.Hash(ctx, pw); err == nil {
			in.Rehash = h
		}
	}
	return s.login.AfterFirstFactor(ctx, in)
}

// RequestOtp is POST /auth/otp/request (spec 5.3, 5.4).
func (s *Server) RequestOtp(ctx context.Context, req gen.RequestOtpRequestObject) (gen.RequestOtpResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.BadRequest()
	}
	b := *req.Body
	// The otp-send class is deferred (budget.Bucket.Deferred, HeldProof, HeldInvite): when the plain bucket of
	// the network was spent the pipeline handed over its refusal, and this handler lets through the two requests
	// that carry a proof of their own. It answers the refusal here, before the floor and before any I/O, for
	// every other request: the deferral must not turn a refused request into work (round 8, admin-r8-1).
	//   - a device marker that holds for the phone's account is settled in otp.Request (HeldProofHolds);
	//   - an invite link whose signature checks is settled in requestOTP (InviteProofHolds; round 9, tenant-r9-1):
	//     a closed registration has no other way in, and the strangers who fill a carrier /24 must not be able to
	//     keep an invitee from his code. The link is opened here in process (D67), so a token that does not open
	//     gets the plain bucket's answer with no read and no throttle row, which is what the pool of rounds 9 to
	//     11 bounded and no longer exists.
	if refusal := httpx.DeferredRefusal(ctx); refusal != nil {
		isInvite := otp.Purpose(b.Purpose) == otp.Invite
		if !isInvite && !httpx.HeldCarried(ctx) {
			return nil, apiError(refusal)
		}
		if isInvite {
			if _, ok := s.openInvite(deref(b.InviteToken)); !ok {
				return nil, apiError(refusal)
			}
		}
	}
	ch, err := floored(ctx, floorOTPReq, func(ctx context.Context) (otp.Challenge, error) { return s.requestOTP(ctx, b) })
	if err != nil {
		return nil, apiError(err)
	}
	return gen.RequestOtp202JSONResponse{OtpIssuedJSONResponse: otpIssued(ch)}, nil
}

func (s *Server) requestOTP(ctx context.Context, b gen.OtpRequest) (otp.Challenge, error) {
	ip := httpx.ClientIPFrom(ctx)
	purpose := otp.Purpose(b.Purpose)
	var e164 string
	switch purpose {
	case otp.Invite:
		// The phone comes from the invite row, never from the request (5.3). The link is opened in process
		// first: one that does not open is the plain 404 with no read and no throttle row (D67). One that does
		// is a proof, so its own buckets stand in for the network's and the plain token goes back, BEFORE
		// anything is read; liveInviteRef then counts invite_use and asks the row.
		ref, ok := s.openInvite(deref(b.InviteToken))
		if !ok {
			return otp.Challenge{}, errInviteInvalid()
		}
		if e := httpx.InviteProofHolds(ctx, ref.ID.String()); e != nil {
			return otp.Challenge{}, e
		}
		info, err := s.liveInviteRef(ctx, ref)
		if err != nil {
			return otp.Challenge{}, err
		}
		e164 = info.Phone
	case otp.Login, otp.Reset, otp.Signup:
		n, err := phone.Normalize(deref(b.Phone))
		if err != nil {
			return otp.Challenge{}, errInvalidPhone()
		}
		e164 = n
	default:
		return otp.Challenge{}, httpx.BadRequest()
	}
	return s.otp.Request(ctx, otp.Request{
		Phone: e164, Purpose: purpose, Locale: string(deref(b.Locale)), IP: ip,
		Device: s.markers.Open(marker.User, httpx.CookieFrom(ctx, session.CookieDevice)),
		// An invite request was settled above, and a marker is no proof for it (trusted is false for the
		// invite purpose), so the gate has nothing left to decide for it.
		NetworkGate: func(held bool) error {
			if purpose == otp.Invite {
				return nil
			}
			return networkGate(ctx, held)
		},
	})
}

// openInvite opens the link a person pasted: the one place the api reads an invite token, with no I/O (D67).
func (s *Server) openInvite(text string) (invite.Ref, bool) {
	return invite.Open(s.d.Invites, s.now(), text)
}

// liveInvite finds an invite that can still be used. A link that does not open, and a row that is unknown, used,
// revoked, expired or another invite's, are all the same 404 invite_invalid (11.3).
//
// The link is opened first, in process: one that does not open costs no throttle row and no read (D67), and the
// network class of the route is what bounds a flood of them, as for any request with no proof. One that opens names
// its invite, so every use of it counts on invite_use BEFORE the row is read (rule budget-keying: the id is a proof
// and the count is the invite's, whatever network asks), and then the row decides.
func (s *Server) liveInvite(ctx context.Context, text string) (store.InviteInfo, error) {
	ref, ok := s.openInvite(text)
	if !ok {
		return store.InviteInfo{}, errInviteInvalid()
	}
	return s.liveInviteRef(ctx, ref)
}

// liveInviteRef is liveInvite for a link that was opened already. The row is the final authority: the id in the row
// found by the hash must be the id in the link, and used, revoked and expired (on the database clock) are the same
// 404 as a link that never was.
func (s *Server) liveInviteRef(ctx context.Context, ref invite.Ref) (store.InviteInfo, error) {
	if err := s.throttle.InviteHit(ctx, httpx.ClientIPFrom(ctx), ref.ID); err != nil {
		return store.InviteInfo{}, err
	}
	info, found, err := s.auth.InviteByHash(ctx, ref.Hash)
	if err != nil {
		return store.InviteInfo{}, err
	}
	if !found || info.ID != ref.ID || info.UsedAt != nil || info.RevokedAt != nil || info.Expired {
		return store.InviteInfo{}, errInviteInvalid()
	}
	return info, nil
}

// LoginOtp is POST /auth/login/otp (spec 5.6).
func (s *Server) LoginOtp(ctx context.Context, req gen.LoginOtpRequestObject) (gen.LoginOtpResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.BadRequest()
	}
	b := *req.Body
	res, err := floored(ctx, floorVerify, func(ctx context.Context) (login.Result, error) {
		ip := httpx.ClientIPFrom(ctx)
		// A challenge id whose tag checks is counted on the challenge and one that does not on the network (D64 nat-proof-tag).
		challenge, tagged := s.otp.OpenChallenge(b.ChallengeId)
		if err := s.throttle.OTPVerifyHit(ctx, ip, challenge.ID); err != nil {
			return login.Result{}, err
		}
		e164, err := phone.Normalize(b.Phone)
		if err != nil {
			return login.Result{}, errInvalidPhone()
		}
		if !tagged {
			return login.Result{}, s.untaggedChallenge(b.ChallengeId)
		}
		res, err := s.login.OTPLogin(ctx, login.OTPLoginInput{
			Phone: e164, ChallengeID: challenge.ID, Code: b.Code, Remember: deref(b.RememberMe),
			IP: ip, UserAgent: httpx.UserAgentFrom(ctx),
		})
		if err == nil {
			s.refundOTPVerify(ctx, ip, challenge.ID) // a right code is not a guess (tenant-r5-3)
		}
		return res, err
	})
	if err != nil {
		return nil, apiError(err)
	}
	setCookies(ctx, res.Cookies...)
	return gen.LoginOtp200JSONResponse{LoginResultJSONResponse: loginResult(res)}, nil
}

// Register is POST /auth/register (spec 5.6, 11).
func (s *Server) Register(ctx context.Context, req gen.RegisterRequestObject) (gen.RegisterResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.BadRequest()
	}
	b := *req.Body
	res, err := floored(ctx, floorVerify, func(ctx context.Context) (login.Result, error) { return s.register(ctx, b) })
	if err != nil {
		return nil, apiError(err)
	}
	setCookies(ctx, res.Cookies...)
	return gen.Register201JSONResponse{LoginResultJSONResponse: loginResult(res)}, nil
}

// register is the body of the floor, in the shape of rule proof-before-work (spec 5.6):
//
//   - Shape: the locale. The column accepts fa and en only, and an absent locale is the
//     default, not an empty string the CHECK would refuse.
//   - Charge: the invite (a link that opens is charged to its own budget, one that does not is refused with no
//     charge, see liveInvite; neither touches otp_verify_net) or, with no invite, otp_verify_net,
//     then the registration mode and the phone.
//   - Check: the code is peeked, which consumes nothing and spends a try if it is wrong.
//     A made-up challenge or a wrong code ends here, so it costs one database call and
//     never a scoring slot or an Argon2 run (round 4, primitives-r4-3).
//   - Work: the password is scored once, with the phone, on the gate of callers who hold a
//     right code and no session (strengthAnon), then hashed, and only then is the code
//     consumed, so a weak password does not burn it.
func (s *Server) register(ctx context.Context, b gen.RegisterRequest) (login.Result, error) {
	ip := httpx.ClientIPFrom(ctx)
	challenge, tagged := s.otp.OpenChallenge(b.ChallengeId) // the zero ref for an id that does not check (D64 nat-proof-tag)
	var in login.RegisterInput
	return proof.Run(ctx, proof.Spec[login.Result]{
		Kind: proof.OneTimeCode,
		Shape: func(context.Context) error {
			locale := string(deref(b.Locale))
			switch locale {
			case "":
				locale = "fa"
			case "fa", "en":
			default:
				return errValidation("locale", "invalid")
			}
			in = login.RegisterInput{
				ChallengeID: challenge.ID, Code: b.Code, Locale: locale, IP: ip, UserAgent: httpx.UserAgentFrom(ctx),
			}
			return nil
		},
		Charge: func(ctx context.Context) error {
			if token := deref(b.InviteToken); token != "" {
				// An invite works in every mode (11.1); its phone is its own. The invite comes FIRST and
				// the network count of the code check is not taken for it at all: an invite link is a
				// proof, bounded by invite_use and by the five tries of the challenge, and a token that
				// does not open ends here with no charge and never reaches a code check. Charged the other
				// way round, thirty junk tokens from one carrier /24 spent otp_verify_net and refused
				// every honest invitee behind it for fifteen minutes, in closed mode, which is the only
				// signup route there (tenant-r7-1; rule budget-keying: a network bucket never refuses a
				// request that carries a proof, and a bad token never counts there).
				info, err := s.liveInvite(ctx, token)
				if err != nil {
					return err
				}
				in.Via, in.Invite, in.Phone = "invite", info.ID, info.Phone
				return nil
			}
			// No invite: the code being checked is the only proof the request has, so the network counts it.
			if err := s.throttle.OTPVerifyHit(ctx, ip, challenge.ID); err != nil {
				return err
			}
			cfg, err := s.cfg.Get(ctx)
			if err != nil {
				return err
			}
			if cfg.RegistrationMode != "open" {
				return otp.ErrRegistrationClosed
			}
			e164, err := phone.Normalize(deref(b.Phone))
			if err != nil {
				return errInvalidPhone()
			}
			in.Via, in.Phone = "open", e164
			return nil
		},
		Check: func(ctx context.Context) error {
			if !tagged {
				return s.untaggedChallenge(b.ChallengeId) // with no database call
			}
			return s.login.PeekRegisterCode(ctx, in)
		},
		// The caller proved a right code before Work, so a busy answer is the server's and not a guess:
		// the network count of the check is given back. The invite's own count stays (an invite link whose signature checked is
		// a proof, keyed on the invite, and bounded by what the invite is worth).
		Refund: func(ctx context.Context) { _ = s.throttle.OTPVerifyRefund(ctx, ip, challenge.ID) },
		Work: func(ctx context.Context, _ proof.Proved) (login.Result, error) {
			if pw := deref(b.Password); pw != "" {
				h, err := s.preparePasswordOn(ctx, s.strengthAnon, pw, in.Phone, "password")
				if err != nil {
					return login.Result{}, err
				}
				in.PasswordHash = h
			}
			res, err := s.login.Register(ctx, in)
			if err == nil {
				s.refundOTPVerify(ctx, ip, challenge.ID) // a right code is not a guess (tenant-r5-3)
			}
			return res, err
		},
	})
}

// LookupInvite is POST /auth/invites/lookup (spec 11.3).
func (s *Server) LookupInvite(ctx context.Context, req gen.LookupInviteRequestObject) (gen.LookupInviteResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.BadRequest()
	}
	info, err := s.liveInvite(ctx, req.Body.Token)
	if err != nil {
		return nil, apiError(err)
	}
	return gen.LookupInvite200JSONResponse{PhoneMasked: phone.Mask(info.Phone), ExpiresAt: info.ExpiresAt}, nil
}

// accountRead is the answer of the lookup the Charge step made to match a device marker, so
// that Work asks for nothing twice and an unknown number costs the same reads as a known one.
type accountRead struct {
	u     store.UserLogin
	found bool
}

// refundOTPVerify gives back the network count of an OTP check whose code was right. It runs
// without the request's cancellation (a client that left after the answer was made still gets it)
// and its failure changes nothing: the attempt simply stays counted, as it did before.
func (s *Server) refundOTPVerify(ctx context.Context, ip netip.Addr, challenge uuid.UUID) {
	_ = s.throttle.OTPVerifyRefund(context.WithoutCancel(ctx), ip, challenge)
}

// verifyStored is the one way the tenant API checks a password against a stored hash. Whether a hash
// nobody can read is a wrong password is decided inside Hasher.Verify now (round 8, primitives-r8-5),
// for every caller; this wrapper stays because the refund rule treats it as the gate of a request.
func (s *Server) verifyStored(ctx context.Context, pw secret.String, stored secret.String) (bool, error) {
	return s.hasher.Verify(ctx, pw, stored)
}

// networkGate settles the otp-send class for a code request once the phone's account is known (round 8,
// tenant-r8-4). The class is deferred (budget.Bucket.HeldProof): the pipeline charged the plain network
// bucket, which strangers on a carrier /24 can fill, and handed over its refusal. A device marker that
// holds for the account of the phone asked for is the owner on a known device, who must not be refused
// by it: it is charged to its own buckets (httpx.HeldProofHolds) and the plain token is given back.
// Every other request keeps what the plain bucket said. A marker that holds for some other account is
// worth nothing here, since any account holder can mint one.
func networkGate(ctx context.Context, held bool) error {
	var e *httpx.Error
	if held {
		e = httpx.HeldProofHolds(ctx)
	} else {
		e = httpx.DeferredRefusal(ctx)
	}
	if e != nil {
		return e
	}
	return nil
}

// sessionOtpIssued is otpIssued for the signed-in reauth: the session proves the account, so its challenge id is the plain row
// id and needs no tag (the route is charged to the session, never to the network).
func sessionOtpIssued(c otp.Challenge) gen.SessionOtpIssuedJSONResponse {
	return gen.SessionOtpIssuedJSONResponse{
		ChallengeId: c.ID, ExpiresInS: int(c.ExpiresIn / time.Second), ResendAfterS: int(c.ResendAfter / time.Second),
	}
}
