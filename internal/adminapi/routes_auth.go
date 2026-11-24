package adminapi

import (
	"context"
	"errors"
	"strings"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/adminapi/gen"
	"github.com/Kup1ng/CtrlZ-Panel/internal/apispec"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/audit"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/credstate"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/marker"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/password"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/proof"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/session"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/throttle"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/totp"
	"github.com/Kup1ng/CtrlZ-Panel/internal/credgen"
	"github.com/Kup1ng/CtrlZ-Panel/internal/httpx"
	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// AdminLogin is POST /auth/login (spec 10.2). The whole decision runs inside a
// 500 ms floor, so a known and an unknown username, and a wrong password and a
// wrong code, cannot be told apart by how long the answer took.
//
// One exception is accepted and recorded in spec 10.2 (review round 4,
// admin-r4-6): while the Argon2 gate is held full, an account that holds a console
// one-time password is answered at once (its hash is cheap and takes no slot,
// admin-r3-11) while an unknown name or a chosen password waits and gets 503.
// Closing it would put the owner's first login back behind a gate strangers can
// fill.
func (s *Server) AdminLogin(ctx context.Context, req gen.AdminLoginRequestObject) (gen.AdminLoginResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.BadRequest()
	}
	b := *req.Body
	// A request the deferred class admin-login turned away is answered here, before the floor and
	// before anything is read, unless it can be the one request the class lets through (the console
	// one-time password, which has a fixed shape). The class is the cut in front of the database, and
	// the deferral only moved its answer to this handler, so the handler must not give the cost back
	// (round 8, admin-r8-1 and -4; rule budget-keying, deferred classes). The test is a function of the
	// typed text alone, so it tells a known username from an unknown one no better than the 429 did. A
	// request that has the shape reads the account in one of a few slots and is refused at once when
	// none is free; the slot is held for the read only, not for the floor.
	deferred := httpx.DeferredRefusal(ctx)
	release := func() {}
	if d := deferred; d != nil {
		if !password.MayBeOneTime(secret.New(b.Password)) {
			return nil, adminError(d)
		}
		rel, ok := s.slots.try()
		if !ok {
			return nil, adminError(d)
		}
		release = rel
	}
	defer release()
	var out gen.AdminLoginResult
	err := httpx.Floor(ctx, floorLogin, func(ctx context.Context) (err error) {
		out, err = s.loginHolding(ctx, b, deferred, release)
		return err
	})
	if err != nil {
		return nil, adminError(err)
	}
	return gen.AdminLogin200JSONResponse(out), nil
}

// login is the body of the floor, for a caller that holds no lookup slot.
func (s *Server) login(ctx context.Context, b gen.AdminLoginRequest) (gen.AdminLoginResult, error) {
	return s.loginHolding(ctx, b, nil, func() {})
}

// loginHolding is login for a request that may hold one of the slots of the deferred class: slot is
// given back as soon as the account has been read, so the slots bound the reads and not the floor.
func (s *Server) loginHolding(ctx context.Context, b gen.AdminLoginRequest, deferred *httpx.Error, slot func()) (gen.AdminLoginResult, error) {
	ip := httpx.ClientIPFrom(ctx)
	// 1. Count the attempt before anything is hashed, so a flood never reaches Argon2.
	// A browser the admin signed in from before carries a marker that holds for this
	// account; it counts on the marker's own scope and on none of the three scopes
	// a stranger can fill, so strangers cannot keep the admin out (10.2, rule
	// budget-keying).
	//
	// The marker is bound to the credential generation of the account (admin-r3-14),
	// so a marker that passed its seal is checked against the row. The read is made
	// only for a marker nobody else could have forged, and is used again as the
	// account lookup below.
	var user store.AdminUser
	var found, read bool
	lookup := func() error {
		read = true
		defer slot()
		return s.readGlobal(ctx, func(g store.GlobalTx) (err error) {
			user, found, err = g.AdminUserByName(strings.TrimSpace(b.Username))
			return err
		})
	}
	markerID := "" // set only for a marker that holds for the account typed: a proof, not a hint
	var refused error
	// The shape of rule proof-before-work for a first factor: the attempt is charged, and
	// everything after it is Work, which holds the one Argon2 verify (gate-free for a console
	// one-time password) and, last, the rehash.
	return proof.Run(ctx, proof.Spec[gen.AdminLoginResult]{
		Kind: proof.Password,
		// Only a console one-time hash is gate-free (VerifyGateFree). Every ordinary admin password,
		// and the dummy hash of a username nobody has, waits for a slot and can answer 503 without
		// looking at the password, so the attempt is given back like the tenant login's (round 6,
		// primitives-r6-9; round 5 said "gate-free", which was true of one hash). It is the same
		// scopes the charge took, for a known and an unknown username alike.
		Refund: func(ctx context.Context) {
			_ = s.throttle.AdminLoginRefund(ctx, b.Username, ip, markerID)
		},
		Charge: func(ctx context.Context) error {
			// A username that is empty once trimmed names no account and no key: the schema refuses it
			// (pattern content), and this is the second line for a document that is changed or a
			// caller that is not the pipeline. The throttle cannot key an attempt on nothing, and that
			// error is a defect of the server, not an answer for a client (round 5, admin-r5-1). It
			// is the same 401 as a wrong password and costs no Argon2 run.
			if strings.TrimSpace(b.Username) == "" {
				return errInvalidCredentials()
			}
			// The speed bump of the class admin-login (5 a minute on the network) is a deferred class:
			// the pipeline charged it and handed the refusal over instead of answering. It is a value
			// like the three scopes of AdminLoginHits, so Work lets the one console one-time password
			// through it and answers everyone else with it (round 7, admin-r7-1: the pipeline used to
			// answer 429 itself, and a neighbour sending five logins a minute kept the owner's first
			// login out). The scopes are not counted for a request the class turned away, as before. A
			// refused request that cannot be that password never gets here: AdminLogin answered it before
			// the floor, with no read (admin-r8-1).
			if d := deferred; d != nil {
				refused = d
				return nil
			}
			if m := s.markers.Open(marker.Admin, httpx.CookieFrom(ctx, session.CookieAdminDevice)); !m.Zero() {
				if err := lookup(); err != nil {
					return err
				}
				if found && m.Holds(user.Stamp()) {
					markerID = m.ID
				}
			}
			var err error
			refused, err = s.throttle.AdminLoginHits(ctx, b.Username, ip, markerID)
			return err
		},
		Work: func(ctx context.Context, _ proof.Proved) (gen.AdminLoginResult, error) {
			// A browser whose device marker holds for this account is a proof: its Argon2 verify is
			// served before any stranger's when the gate is full, so strangers cannot keep the owner out
			// by keeping the one slot busy (password.Proved, round 5 admin-r5-9). markerID is set only
			// for a marker that opened under its seal and holds for the account found.
			if markerID != "" {
				ctx = password.Proved(ctx)
			}
			// 2. The account. An unknown username verifies against the dummy hash, so the
			// work is the same (Hasher.Verify runs Argon2 exactly once on every path).
			if !read {
				if err := lookup(); err != nil {
					return gen.AdminLoginResult{}, err
				}
			}
			// A spent scope (admin_login, admin_login_user or admin_login_net: strangers, or a browser
			// with no marker) keeps out everyone but one request: the right console-issued one-time
			// password of an account that has one. The network scopes are in it since round 5
			// (admin-r5-11): a neighbour on the owner's carrier address group refills admin_login_net
			// faster than `unlock` clears it, and the first login after bootstrap has no marker. It has 120 bits, so the scope has nothing to protect
			// there, and without this a stranger who knows the username could keep the
			// owner out of the very first login, with `unlock` losing the race (review
			// round 2, admin-r2-7). Every other request gets the 429 the scope gives, with
			// no Argon2 spent on it. The one-time hash is itself cheap and takes no slot of
			// the Argon2 gate (password.HashOneTime), so these requests cannot fill the gate
			// and make the owner's login wait for a slot either (review round 3, admin-r3-11).
			// The table says which state that is: a console one-time password that is live.
			oneTimeOpen := found && user.DisabledAt == nil &&
				credstate.Named(credstate.Admin, "adminLogin/past-spent-scope", user.State).Permits()
			if refused != nil && !oneTimeOpen {
				return gen.AdminLoginResult{}, refused
			}
			stored := secret.String{}
			if found {
				stored = user.PasswordHash
			}
			ok, err := s.hasher.VerifyGateFree(ctx, secret.New(b.Password), stored)
			if err != nil {
				return gen.AdminLoginResult{}, err
			}
			if refused != nil && !ok {
				return gen.AdminLoginResult{}, refused
			}
			// 3. A wrong password, a disabled account and a one-time password past its
			// expiry are one answer.
			now := s.now()
			valid := found && ok && user.DisabledAt == nil && credstate.Named(credstate.Admin, "adminLogin", user.State).Permits()
			if !valid {
				s.recordFailure(ctx, user.ID, found)
				return gen.AdminLoginResult{}, errInvalidCredentials()
			}
			// 4. The second factor, once enrolled. A missing code is a wrong one.
			enrolled := user.TOTPEnabledAt != nil
			code := strings.TrimSpace(deref(b.TotpCode))
			if enrolled && code == "" {
				s.recordFailure(ctx, user.ID, true)
				return gen.AdminLoginResult{}, errInvalidCredentials()
			}
			var charge totpCharge
			if enrolled {
				// Counted before the transaction opens (see totpHit). A spent admin_totp
				// scope after a right password must not tell a right password from a wrong
				// one, so it is the same 401 with no Retry-After; the lock on the scope
				// is what keeps the attacker out, and the log row says what happened.
				var herr error
				if charge, herr = s.totpHit(ctx, user.ID); herr != nil {
					if errors.Is(herr, throttle.ErrTooMany) {
						s.recordFailure(ctx, user.ID, true)
						return gen.AdminLoginResult{}, errInvalidCredentials()
					}
					return gen.AdminLoginResult{}, herr
				}
			}
			var iss session.AdminIssued
			var cur store.AdminUser
			err = s.d.Store.WithGlobal(ctx, store.TxOpts{}, func(g store.GlobalTx) error {
				// The row is locked and compared with the one that was verified. Argon2
				// ran outside any transaction, and a console reset that committed meanwhile
				// has revoked the sessions that existed: a session inserted now would
				// survive the reset, and after reset-totp it would be a setup session in the
				// hands of whoever held the old password (review round 3, admin-r3-2). A
				// mismatch (a moved generation) is a wrong password, whichever column moved:
				// the lock and the comparison are one call (internal/credgen). The lock is taken
				// before the audit lock, the order of every writer of admin_users (admin-r3-3).
				var ok bool
				var err error
				cur, ok, err = g.AdminUserLockFor(user.ID, user.Stamp())
				if errors.Is(err, credgen.ErrStale) || (err == nil && !ok) {
					return errInvalidCredentials()
				}
				if err != nil {
					return err
				}
				// The state is read again under the lock: a one-time password can run out
				// while Argon2 runs, and the same table decides.
				if !credstate.Named(credstate.Admin, "adminLogin", cur.State).Permits() {
					return errInvalidCredentials()
				}
				if enrolled {
					if err := s.checkAdminTOTP(g, charge, cur.ID, cur.TOTPSecretCT, code, nil); err != nil {
						return err
					}
				}
				iss, err = s.d.Sessions.AdminCreate(g, session.AdminNew{
					Admin: cur.ID, TOTPVerified: enrolled, IP: ip, UserAgent: httpx.UserAgentFrom(g.Context()),
				})
				if err != nil {
					return err
				}
				if err := g.AdminMarkLogin(cur.ID); err != nil {
					return err
				}
				_, err = audit.Admin(g, now, cur.ID, ip, audit.AdminLogin{Admin: cur.ID})
				return err
			})
			if err != nil {
				// A wrong code is the same answer as a wrong password. A spent step is told
				// apart (18.2), which is safe: it needs the right password first.
				if errors.Is(err, totp.ErrInvalid) {
					s.recordFailure(ctx, user.ID, true)
					return gen.AdminLoginResult{}, errInvalidCredentials()
				}
				if errors.Is(err, totp.ErrStepReused) {
					s.recordFailure(ctx, user.ID, true)
				}
				return gen.AdminLoginResult{}, err
			}
			// A hash written under older Argon2 parameters is replaced by one of the same
			// password under the current ones (4.1). It is made here, after the second
			// factor passed and the session exists, and not before: a right password with
			// a wrong code must cost what a wrong password costs, one Argon2 run, or the
			// response time tells the two apart (review round 3, admin-r3-5). It is best
			// effort: a busy gate only postpones it to the next login, and it compares the
			// old hash, so a password change that committed meanwhile is never overwritten.
			stamp := cur.Stamp()
			if s.hasher.NeedsRehash(cur.PasswordHash) {
				stamp = s.rehash(ctx, stamp, b.Password)
			}
			// The scopes that reset on success; a failure to reset is not a failure to log in.
			_ = s.throttle.AdminLoginSuccess(ctx, b.Username, ip, markerID)
			if enrolled {
				s.totpReset(ctx, charge)
			}
			httpx.SetCookie(ctx, session.AdminCookie(iss.Token))
			// The marker of 10.2, renewed at each login. A failure to make it only means
			// the next login counts on every scope.
			if !stamp.Zero() {
				if c, derr := s.markers.Issue(marker.Admin, stamp); derr == nil {
					httpx.SetCookie(ctx, c)
				}
			}
			state := gen.Ready
			if credstate.Class(credstate.Admin, apispec.Admin, cur.State) != credstate.Allow {
				state = gen.SetupRequired
			}
			return gen.AdminLoginResult{State: state}, nil
		},
	})
}

// rehash stores a fresh hash of a password that has just been proven, with the stamp it
// was proven under, and returns the stamp the account has afterwards: the same one when
// nothing was written (a busy gate, a database fault: the next login tries again), the
// new one when the write moved the generation, and the zero stamp when the row had
// already moved on (a password change that committed meanwhile is never overwritten, and
// the browser gets no marker for credentials that no longer exist). Nothing in it can
// fail the login.
func (s *Server) rehash(ctx context.Context, issued credgen.Stamp, pw string) credgen.Stamp {
	fresh, err := s.hasher.Hash(ctx, secret.New(pw))
	if err != nil {
		return issued
	}
	after := issued
	s.d.beforeRehashWrite()
	if err := s.d.Store.WithGlobal(ctx, store.TxOpts{}, func(g store.GlobalTx) error {
		next, ok, err := g.AdminRehash(issued, fresh)
		if err != nil {
			return err
		}
		if ok {
			after = next
		} else {
			after = credgen.Stamp{}
		}
		return nil
	}); err != nil {
		return issued
	}
	return after
}

// recordFailure writes admin.login_failed. The row names the admin when the
// username exists and nothing when it does not, and never the username: a
// password typed into the username box is a classic leak (13.2). The throttle
// bounds how many rows an attacker can make, and a failure to write one never
// changes the answer.
func (s *Server) recordFailure(ctx context.Context, admin uuid.UUID, known bool) {
	if !known {
		admin = uuid.Nil
	}
	_ = s.d.Store.WithGlobal(ctx, store.TxOpts{}, func(g store.GlobalTx) error {
		_, err := audit.Admin(g, s.now(), uuid.Nil, httpx.ClientIPFrom(g.Context()), audit.AdminLoginFailed{Admin: admin})
		return err
	})
}

// AdminLogout is POST /auth/logout.
func (s *Server) AdminLogout(ctx context.Context, _ gen.AdminLogoutRequestObject) (gen.AdminLogoutResponseObject, error) {
	p, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	err = s.global(ctx, func(g store.GlobalTx) error {
		if err := g.AdminSessionRevoke(p.SessionID); err != nil {
			return err
		}
		_, err := audit.Admin(g, s.now(), p.AdminID, httpx.ClientIPFrom(g.Context()), audit.AdminLogout{Admin: p.AdminID})
		return err
	})
	if err != nil {
		return nil, err
	}
	httpx.SetCookie(ctx, session.ClearAdmin())
	return gen.AdminLogout204Response{}, nil
}

// AdminTotpFresh is POST /auth/totp/fresh (spec 10.5): a code opens the
// five-minute window the admin-fresh routes need.
func (s *Server) AdminTotpFresh(ctx context.Context, req gen.AdminTotpFreshRequestObject) (gen.AdminTotpFreshResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.BadRequest()
	}
	p, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	// Counted first, on its own connection, so the transaction below never waits
	// for a second pooled connection (see sessionTotpHit).
	charge, err := s.sessionTotpHit(ctx, p)
	if err != nil {
		return nil, adminError(err)
	}
	var until gen.FreshWindow
	err = s.global(ctx, func(g store.GlobalTx) error {
		user, ok, err := g.AdminUserByID(p.AdminID)
		if err != nil {
			return err
		}
		if !ok {
			return httpx.SessionExpired()
		}
		if err := s.checkSessionTOTP(g, charge, user.ID, p.SessionID, user.TOTPSecretCT, req.Body.Code, nil); err != nil {
			return err
		}
		at, ok, err := g.AdminSessionFresh(p.SessionID, s.now())
		if err != nil {
			return err
		}
		if !ok {
			return httpx.SessionExpired()
		}
		until.FreshUntil = s.d.Sessions.AdminFreshUntil(at).UTC()
		_, err = audit.Admin(g, s.now(), p.AdminID, httpx.ClientIPFrom(g.Context()), audit.AdminTOTPFresh{Admin: p.AdminID})
		return err
	})
	if err != nil {
		return nil, err
	}
	s.totpReset(ctx, charge)
	return gen.AdminTotpFresh200JSONResponse(until), nil
}

// sealSeed seals a new TOTP seed for an admin under admin_totp (6.2).
func (s *Server) sealSeed(admin uuid.UUID, seed secret.Bytes) ([]byte, error) {
	return s.d.Keys.Seal(keyring.DomainAdminTOTP, totp.AdminAAD(admin), seed.Reveal())
}
