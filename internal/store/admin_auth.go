package store

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/adminnotice"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/credstate"
	"github.com/Kup1ng/CtrlZ-Panel/internal/credgen"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
)

// AdminFns are the calls of the admin service that go through a SECURITY
// DEFINER function in ctrlz_fn, the way AuthLookups is for the tenant side. One
// method per function. Postgres holds EXECUTE (only ctrlz_admin has it), and
// each method also refuses any other role in Go, so a wrong wiring fails at the
// first call and not by a permission error that looks like a database fault.
type AdminFns struct{ s *Store }

// Admin returns the admin calls. They return ErrWrongRole unless the store
// logged in as ctrlz_admin.
func (s *Store) Admin() AdminFns { return AdminFns{s: s} }

const qAdminCreateUser = `SELECT tenant_id, user_id FROM ctrlz_fn.admin_create_user($1, $2, $3)`

// CreateUser makes a tenant with its owner for POST /users (T-327): no OTP and
// no registration mode, since the admin is the authority. The password is a
// one-time password (hashed by the caller): the user is created with must_reset,
// no verified phone, and a password that stops working after 72 hours. ok is
// false for a taken phone.
func (a AdminFns) CreateUser(ctx context.Context, phone string, oneTimeHash secret.String, locale string) (Registered, bool, error) {
	if a.s.role != RoleAdmin {
		return Registered{}, false, ErrWrongRole
	}
	return one(ctx, a.s, qAdminCreateUser, func(r pgx.Row) (v Registered, err error) {
		err = r.Scan(&v.TenantID, &v.UserID)
		return v, err
	}, phone, oneTimeHash.Reveal(), emptyNull(locale))
}

const qAdminThrottleHit = `SELECT allowed, retry_after_s, window_epoch FROM ctrlz_fn.admin_throttle_hit($1, $2, $3, $4)`

// ThrottleHit counts one attempt on an admin scope (admin_login,
// admin_login_user, admin_login_net, admin_totp). The key is an HMAC under
// admin_mac. The user pair of functions refuses these scopes and this one
// refuses theirs, so the api cannot reset an admin key between guesses.
func (a AdminFns) ThrottleHit(ctx context.Context, scope string, key []byte, max int, window time.Duration) (ThrottleResult, error) {
	if a.s.role != RoleAdmin {
		return ThrottleResult{}, ErrWrongRole
	}
	v, _, err := one(ctx, a.s, qAdminThrottleHit, scanThrottle, scope, key, int32(max), int32(window/time.Second))
	return v, err
}

const qAdminThrottleRefund = `SELECT 1 FROM ctrlz_fn.admin_throttle_refund($1, $2, $3, $4)`

// ThrottleRefund gives one attempt back on an admin login scope, for an attempt whose verify the
// Argon2 gate turned away (primitives-r6-9). epoch is the one ThrottleHit returned for it.
func (a AdminFns) ThrottleRefund(ctx context.Context, scope string, key []byte, window time.Duration, epoch int64) error {
	if a.s.role != RoleAdmin {
		return ErrWrongRole
	}
	_, _, err := one(ctx, a.s, qAdminThrottleRefund, scanOne, scope, key, int32(window/time.Second), epoch)
	return err
}

const qAdminThrottleReset = `SELECT 1 FROM ctrlz_fn.admin_throttle_reset($1, $2)`

// ThrottleReset clears an admin key after a success. A nil key clears the whole
// scope: a key bound to a network cannot be listed, and `ctrlz-admin unlock`
// and the reset commands need to clear admin_login (10.1).
func (a AdminFns) ThrottleReset(ctx context.Context, scope string, key []byte) error {
	if a.s.role != RoleAdmin {
		return ErrWrongRole
	}
	var k any
	if key != nil {
		k = key
	}
	_, _, err := one(ctx, a.s, qAdminThrottleReset, scanOne, scope, k)
	return err
}

// ---------------------------------------------------------------------------
// Admin accounts

// AdminUser is a row of admin_users.
type AdminUser struct {
	ID                uuid.UUID
	Username          string
	PasswordHash      secret.String
	TOTPSecretCT      []byte
	TOTPLastStep      *int64
	DisabledAt        *time.Time
	TOTPEnabledAt     *time.Time
	PasswordChangedAt *time.Time
	LastLoginAt       *time.Time
	PendingNotice     []byte // jsonb, nil when none
	// State is the one-time credential state on the database clock (rule one-time-state,
	// internal/auth/credstate), as of the statement that read the row.
	State credstate.State
	// CredentialGen is credential_gen of the row (migration 0022). Use Stamp, never the number.
	CredentialGen int64
}

// Stamp is the credentials of the row as read: the admin and its generation.
func (a AdminUser) Stamp() credgen.Stamp {
	return credgen.Stamp{Subject: a.ID, Gen: a.CredentialGen}
}

const adminUserColumns = `id, username, password_hash, totp_secret_ct, totp_last_step, disabled_at,
  totp_enabled_at, password_changed_at, last_login_at, pending_notice, credential_gen, ` + adminStateSQL

func scanAdminUser(r pgx.Row) (a AdminUser, err error) {
	var hash, state string
	err = r.Scan(&a.ID, &a.Username, &hash, &a.TOTPSecretCT, &a.TOTPLastStep, &a.DisabledAt,
		&a.TOTPEnabledAt, &a.PasswordChangedAt, &a.LastLoginAt, &a.PendingNotice, &a.CredentialGen, &state)
	if err != nil {
		return a, err
	}
	a.PasswordHash = secret.New(hash)
	a.State, err = credstate.Parse(state)
	return a, err
}

const qAdminUserByName = `SELECT ` + adminUserColumns + ` FROM ctrlz.admin_users WHERE username = $1`

// AdminUserByName finds an admin by username.
func (g GlobalTx) AdminUserByName(username string) (AdminUser, bool, error) {
	a, err := scanAdminUser(g.tx.QueryRow(g.ctx, qAdminUserByName, username))
	ok, err := notFound(err)
	return a, ok, err
}

const qAdminUserByID = `SELECT ` + adminUserColumns + ` FROM ctrlz.admin_users WHERE id = $1`

// AdminUserByID finds an admin by id.
func (g GlobalTx) AdminUserByID(id uuid.UUID) (AdminUser, bool, error) {
	a, err := scanAdminUser(g.tx.QueryRow(g.ctx, qAdminUserByID, id))
	ok, err := notFound(err)
	return a, ok, err
}

const qAdminUserBootstrap = `SELECT ctrlz_fn.admin_account_bootstrap($1, $2)`

// AdminBootstrap creates the first admin, and only if no admin exists, with a console
// one-time password that lives 24 hours (the edge credstate.AdminBootstrap; the lifetime
// is in the function, as password.AdminOneTimeLife says). Run it at Serializable and
// retry ErrRetry, so two parallel runs cannot both win (10.1). ok is false when an admin
// exists already.
func (g GlobalTx) AdminBootstrap(username string, oneTimeHash secret.String) (uuid.UUID, bool, error) {
	var id *uuid.UUID
	if err := g.tx.QueryRow(g.ctx, qAdminUserBootstrap, username, oneTimeHash.Reveal()).Scan(&id); err != nil {
		return uuid.Nil, false, sanitize(err)
	}
	if id == nil {
		return uuid.Nil, false, nil
	}
	return *id, true, nil
}

const qAdminSetPassword = `SELECT ok, cred_state FROM ctrlz_fn.admin_account_set_password($1, $2)`

// AdminSetPassword stores a password the admin chose (the edge credstate.AdminSetPass,
// decided by the definer function). An expired password is a wrong one: ok is false and
// nothing changes. While no authenticator is enrolled the chosen password lives an hour,
// lifted by AdminTOTPEnable: D12 makes TOTP mandatory, and a password that alone opens a
// setup session would let whoever phished it enrol their own authenticator, the hole
// reset-totp is built to close (review round 2, admin-r2-2). The state the account has
// afterwards is returned.
//
// The expiry is stamped by the database clock, the clock credential_state compares it
// with (review round 5, rule one-time-state; round 4, admin-r4-1 had it on the
// application clock, which the function cannot take).
func (g GlobalTx) AdminSetPassword(id uuid.UUID, hash secret.String) (credstate.State, bool, error) {
	var ok bool
	var state *string
	if err := g.tx.QueryRow(g.ctx, qAdminSetPassword, id, hash.Reveal()).Scan(&ok, &state); err != nil {
		return credstate.Unknown, false, sanitize(err)
	}
	return parseOutcome(ok, state)
}

// parseOutcome reads the (ok, state) pair of the admin transition functions.
func parseOutcome(ok bool, state *string) (credstate.State, bool, error) {
	if !ok || state == nil {
		return credstate.Unknown, false, nil
	}
	st, err := credstate.Parse(*state)
	return st, err == nil, sanitize(err)
}

const qAdminRehash = `UPDATE ctrlz.admin_users SET password_hash = $3 WHERE id = $1 AND credential_gen = $2
RETURNING credential_gen`

// AdminRehash replaces a hash written under older Argon2 parameters with one of the
// same password under the current parameters (spec 4.1). It touches no other column, so
// must_change_password, the expiry and password_changed_at keep saying what the admin
// did. It carries the stamp of the password that was verified, so a password change or
// console reset that committed in between is never overwritten: that is a row whose
// generation is not the stamp's, and ok is false. The rehash changes password_hash and
// so moves the generation; the new stamp is returned for the device marker.
func (g GlobalTx) AdminRehash(issued credgen.Stamp, newHash secret.String) (next credgen.Stamp, ok bool, err error) {
	if issued.Zero() || issued.Tenant != uuid.Nil {
		return credgen.Stamp{}, false, nil
	}
	next = issued
	err = g.tx.QueryRow(g.ctx, qAdminRehash, issued.Subject, issued.Gen, newHash.Reveal()).Scan(&next.Gen)
	if ok, err = notFound(err); err != nil || !ok {
		return credgen.Stamp{}, false, err
	}
	return next, true, nil
}

const qAdminReset = `SELECT ctrlz_fn.admin_account_reset($1, $2, $3)`

// AdminReset is `ctrlz-admin reset-password` and, with dropTOTP, `reset-totp` (the edges
// credstate.AdminReset and AdminResetTOTP): a new console one-time password that lives 24
// hours, whatever state the account is in. dropTOTP forgets the authenticator too, so the
// old password cannot be used to enrol another (10.1). ok is false for no such admin.
func (g GlobalTx) AdminReset(id uuid.UUID, oneTimeHash secret.String, dropTOTP bool) (bool, error) {
	var ok bool
	if err := g.tx.QueryRow(g.ctx, qAdminReset, id, oneTimeHash.Reveal(), dropTOTP).Scan(&ok); err != nil {
		return false, sanitize(err)
	}
	return ok, nil
}

const qAdminTOTPSetPending = `UPDATE ctrlz.admin_users SET totp_secret_ct = $2, totp_last_step = NULL
WHERE id = $1 AND totp_enabled_at IS NULL`

// AdminTOTPSetPending stores a secret sealed under admin_totp, not yet enabled.
// false when TOTP is already enabled.
func (g GlobalTx) AdminTOTPSetPending(id uuid.UUID, secretCT []byte) (bool, error) {
	tag, err := g.tx.Exec(g.ctx, qAdminTOTPSetPending, id, secretCT)
	if err != nil {
		return false, sanitize(err)
	}
	return tag.RowsAffected() == 1, nil
}

const qAdminTOTPEnable = `SELECT ok, cred_state FROM ctrlz_fn.admin_account_totp_enable($1, $2)`

// AdminTOTPEnable confirms the pending secret (the edge credstate.AdminTOTPEnable); step
// is the step of the code that confirmed it, so that code cannot be replayed. ok is false
// when there is nothing pending or the account is ready already.
//
// The function lifts the one-hour expiry that AdminSetPassword put on a password the
// admin chose, and only that one. The setup routes run in any order, so an admin can
// enrol the authenticator while the password is still the console's one-time password:
// the 24-hour expiry of a one-time password is what stops one that nobody used (10.1),
// and the enrolment must not remove it (review round 3, admin-r3-4, admin-r3-12).
func (g GlobalTx) AdminTOTPEnable(id uuid.UUID, step int64) (credstate.State, bool, error) {
	var ok bool
	var state *string
	if err := g.tx.QueryRow(g.ctx, qAdminTOTPEnable, id, step).Scan(&ok, &state); err != nil {
		return credstate.Unknown, false, sanitize(err)
	}
	return parseOutcome(ok, state)
}

const qAdminTOTPStepAccept = `UPDATE ctrlz.admin_users SET totp_last_step = $2
WHERE id = $1 AND (totp_last_step IS NULL OR totp_last_step < $2)`

// AdminTOTPStepAccept is the replay rule of 6.3 for an admin: zero rows means
// the step was spent.
func (g GlobalTx) AdminTOTPStepAccept(id uuid.UUID, step int64) (Won, error) {
	tag, err := g.tx.Exec(g.ctx, qAdminTOTPStepAccept, id, step)
	if err != nil {
		return Won{}, sanitize(err)
	}
	return wonRows(tag), nil
}

const qAdminMarkLogin = `UPDATE ctrlz.admin_users SET last_login_at = now() WHERE id = $1`

// AdminMarkLogin records a login.
func (g GlobalTx) AdminMarkLogin(id uuid.UUID) error {
	_, err := g.tx.Exec(g.ctx, qAdminMarkLogin, id)
	return sanitize(err)
}

const qAdminNoticeSet = `UPDATE ctrlz.admin_users SET pending_notice = $2 WHERE id = $1`

// AdminNoticeSet sets the banner shown at the next login (a reset from the
// server console). notice is JSON; nil clears it (POST /me/notices/ack).
func (g GlobalTx) AdminNoticeSet(id uuid.UUID, notice []byte) error {
	var n any
	if notice != nil {
		n = notice
	}
	_, err := g.tx.Exec(g.ctx, qAdminNoticeSet, id, n)
	return sanitize(err)
}

// ---------------------------------------------------------------------------
// Admin sessions

// NewAdminSession is the input of AdminSessionCreate.
type NewAdminSession struct {
	// ID is the id of the session row, made by the session manager before the insert because the cookie
	// carries it under its tag (round 8, tenant-r8-3). The nil uuid lets the database choose.
	ID                uuid.UUID
	AdminID           uuid.UUID
	TokenHash         []byte
	IdleExpiresAt     time.Time
	AbsoluteExpiresAt time.Time
	TOTPVerified      bool // a code was checked at login
	// At is the application clock at creation. It stamps created_at and
	// totp_verified_at, which are compared with the application clock (the five
	// minute window, the notice ack cutoff). A database now() would let a skew
	// between the two clocks stretch or close the window (review round 4,
	// admin-r4-1).
	At        time.Time
	IP        netip.Addr
	UserAgent string
}

const qAdminSessionCreate = `INSERT INTO ctrlz.admin_sessions
  (id, admin_id, token_hash, idle_expires_at, absolute_expires_at, totp_verified_at, ip, user_agent, created_at)
VALUES (COALESCE($9::uuid, uuidv7()), $1, $2, $3, $4, CASE WHEN $5 THEN $8::timestamptz ELSE NULL END, $6, $7, $8::timestamptz)
RETURNING id`

// AdminSessionCreate inserts an admin session.
func (g GlobalTx) AdminSessionCreate(s NewAdminSession) (uuid.UUID, error) {
	var id uuid.UUID
	err := g.tx.QueryRow(g.ctx, qAdminSessionCreate, s.AdminID, s.TokenHash, s.IdleExpiresAt, s.AbsoluteExpiresAt,
		s.TOTPVerified, addrArg(s.IP), emptyNull(clipUserAgent(s.UserAgent)), s.At, nilUUID(s.ID)).Scan(&id)
	return id, sanitize(err)
}

// AdminSessionInfo is the session lookup of 10.3: the session and the admin it
// belongs to, in one query, so a reset takes effect on the next request.
type AdminSessionInfo struct {
	SessionID         uuid.UUID
	CreatedAt         time.Time
	IdleExpiresAt     time.Time
	AbsoluteExpiresAt time.Time
	TOTPVerifiedAt    *time.Time
	RevokedAt         *time.Time
	AdminID           uuid.UUID
	Username          string
	TOTPEnabledAt     *time.Time
	DisabledAt        *time.Time
	// State is the admin's credential state now (rule one-time-state), so a console reset
	// takes effect on the next request.
	State credstate.State
}

const qAdminSessionByHash = `SELECT s.id, s.created_at, s.idle_expires_at, s.absolute_expires_at, s.totp_verified_at, s.revoked_at,
  a.id, a.username, a.totp_enabled_at, a.disabled_at
FROM ctrlz.admin_sessions s JOIN ctrlz.admin_users a ON a.id = s.admin_id
WHERE s.token_hash = $1`

// qAdminStateByID is the state in a statement of its own: the session row above carries
// application-clock columns, and one statement does not read two clocks (clocks.yaml).
const qAdminStateByID = `SELECT ` + adminStateSQL + ` FROM ctrlz.admin_users WHERE id = $1`

// AdminSessionByHash finds an admin session by the SHA-256 of its cookie.
func (g GlobalTx) AdminSessionByHash(hash []byte) (AdminSessionInfo, bool, error) {
	var v AdminSessionInfo
	err := g.tx.QueryRow(g.ctx, qAdminSessionByHash, hash).Scan(&v.SessionID, &v.CreatedAt, &v.IdleExpiresAt, &v.AbsoluteExpiresAt,
		&v.TOTPVerifiedAt, &v.RevokedAt, &v.AdminID, &v.Username, &v.TOTPEnabledAt, &v.DisabledAt)
	ok, err := notFound(err)
	if err != nil || !ok {
		return v, ok, err
	}
	var state string
	if err := g.tx.QueryRow(g.ctx, qAdminStateByID, v.AdminID).Scan(&state); err != nil {
		return v, false, sanitize(err)
	}
	v.State, err = credstate.Parse(state)
	return v, true, sanitize(err)
}

const qAdminSessionTouch = `UPDATE ctrlz.admin_sessions SET idle_expires_at = LEAST($2, absolute_expires_at)
WHERE id = $1 AND revoked_at IS NULL`

// AdminSessionTouch slides the idle limit.
func (g GlobalTx) AdminSessionTouch(id uuid.UUID, idleExpiresAt time.Time) error {
	_, err := g.tx.Exec(g.ctx, qAdminSessionTouch, id, idleExpiresAt)
	return sanitize(err)
}

const qAdminSessionRotate = `UPDATE ctrlz.admin_sessions SET token_hash = $2, idle_expires_at = $3
WHERE id = $1 AND revoked_at IS NULL`

// AdminSessionRotate gives the session a new token (password change, TOTP
// confirm).
func (g GlobalTx) AdminSessionRotate(id uuid.UUID, newHash []byte, idleExpiresAt time.Time) (bool, error) {
	tag, err := g.tx.Exec(g.ctx, qAdminSessionRotate, id, newHash, idleExpiresAt)
	if err != nil {
		return false, sanitize(err)
	}
	return tag.RowsAffected() == 1, nil
}

const qAdminSessionFresh = `UPDATE ctrlz.admin_sessions SET totp_verified_at = $2 WHERE id = $1 AND revoked_at IS NULL
RETURNING totp_verified_at`

// AdminSessionFresh records a TOTP check on the session (10.5) at the
// application time now and returns it, the time from which the five minute
// window runs. The window is compared with the application clock, so the
// database's now() is not used (review round 4, admin-r4-1).
func (g GlobalTx) AdminSessionFresh(id uuid.UUID, now time.Time) (time.Time, bool, error) {
	var at time.Time
	err := g.tx.QueryRow(g.ctx, qAdminSessionFresh, id, now).Scan(&at)
	ok, err := notFound(err)
	return at, ok, err
}

const qAdminSessionRevoke = `UPDATE ctrlz.admin_sessions SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL`

// AdminSessionRevoke ends one session (log out).
func (g GlobalTx) AdminSessionRevoke(id uuid.UUID) error {
	_, err := g.tx.Exec(g.ctx, qAdminSessionRevoke, id)
	return sanitize(err)
}

const qAdminSessionsRevokeOthers = `UPDATE ctrlz.admin_sessions SET revoked_at = now()
WHERE revoked_at IS NULL AND id = ANY (ARRAY(SELECT id FROM ctrlz.admin_sessions WHERE admin_id = $1 AND id <> $2 AND revoked_at IS NULL` + orderedUpdate + `))`

// AdminSessionsRevokeOthers ends the admin's other sessions; pass the nil uuid
// to end all of them (the reset commands do).
func (g GlobalTx) AdminSessionsRevokeOthers(admin, keep uuid.UUID) (int, error) {
	tag, err := g.tx.Exec(g.ctx, qAdminSessionsRevokeOthers, admin, keep)
	if err != nil {
		return 0, sanitize(err)
	}
	return int(tag.RowsAffected()), nil
}

const qAdminSessionsDeleteExpired = `DELETE FROM ctrlz.admin_sessions WHERE id = ANY (ARRAY(SELECT id FROM ctrlz.admin_sessions
   WHERE absolute_expires_at < $1::timestamptz - interval '1 day' OR (revoked_at IS NOT NULL AND revoked_at < $1::timestamptz - interval '1 day')
   ` + keyOrder + ` LIMIT $2` + lockUpdateSkipLocked + `))
  AND (absolute_expires_at < $1::timestamptz - interval '1 day' OR (revoked_at IS NOT NULL AND revoked_at < $1::timestamptz - interval '1 day'))`

// AdminSessionsDeleteExpiredBatch is one batch of the hourly sweep of the admin service
// itself (the worker has no grant on admin_sessions): it deletes at most limit sessions a
// day past their end and returns how many; fewer than limit means none are left. The
// caller runs it in its own transaction through sweepbatch.Drain.
func (g GlobalTx) AdminSessionsDeleteExpiredBatch(now time.Time, limit int) (int, error) {
	if limit < 1 {
		return 0, errors.New("store: sweep batch size must be positive")
	}
	tag, err := g.tx.Exec(g.ctx, qAdminSessionsDeleteExpired, now, int32(limit))
	if err != nil {
		return 0, sanitize(err)
	}
	return int(tag.RowsAffected()), nil
}

// ---------------------------------------------------------------------------
// Admin audit log (13.1)

// AuditEntry is one row of audit_log. The chain is entry_hash = SHA-256(prev
// || Canonical), where Canonical is the canonical JSON of {at, admin_id, action,
// target, params, ip} that internal/auth/audit builds (sorted keys, no spaces,
// RFC 3339 UTC to microseconds). The store hashes it; it does not build it, so
// there is one definition of the canonical form.
type AuditEntry struct {
	At        time.Time
	AdminID   uuid.UUID // the nil uuid for none (the CLI bootstrap)
	Action    string
	Target    string
	Params    []byte // JSON, the same object that is in Canonical
	IP        netip.Addr
	Canonical []byte
}

const qAuditPrev = `SELECT entry_hash FROM ctrlz.audit_log ORDER BY id DESC LIMIT 1`
const qAuditInsert = `INSERT INTO ctrlz.audit_log (at, admin_id, action, target, params, ip, prev_hash, entry_hash)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id`

// auditAppend writes a chained row. The advisory lock is per transaction, so
// two writers are serialised until commit and the chain has no fork. The caller
// is in the transaction of the change the row records, so the change cannot
// commit without it.
func auditAppend(ctx context.Context, tx *guardTx, e AuditEntry) (int64, error) {
	if err := lockAudit(ctx, tx); err != nil {
		return 0, err
	}
	var prev []byte
	if err := tx.QueryRow(ctx, qAuditPrev).Scan(&prev); err != nil {
		if ok, err := notFound(err); err != nil || ok {
			return 0, err
		}
	}
	h := sha256.New()
	h.Write(prev)
	h.Write(e.Canonical)
	params := e.Params
	if params == nil {
		params = []byte("{}")
	}
	var id int64
	err := tx.QueryRow(ctx, qAuditInsert, e.At, nilUUID(e.AdminID), e.Action, emptyNull(e.Target), params, addrArg(e.IP),
		prev, h.Sum(nil)).Scan(&id)
	return id, sanitize(err)
}

// AuditAppend writes an admin audit row in a global transaction.
func (g GlobalTx) AuditAppend(e AuditEntry) (int64, error) { return auditAppend(g.ctx, g.tx, e) }

// AdminAuditAppend writes an admin audit row from inside WithTenant. The
// re-issue of a user's one-time password (10.7) changes one tenant's row and
// must write the admin's chained entry in the same transaction.
func (t Tx) AdminAuditAppend(e AuditEntry) (int64, error) { return auditAppend(t.ctx, t.tx, e) }

// AuditRow is a row of audit_log as GET /audit and `audit verify` read it.
type AuditRow struct {
	ID      int64
	At      time.Time
	AdminID *uuid.UUID
	// AdminName is the user name of AdminID as the page of the log reads it (T-352). It is empty when the row has no
	// admin or when the admin has since been deleted: audit_log.admin_id has no foreign key on purpose, so a row
	// outlives the admin it names, and the page then shows the id alone. It is not part of the chain hash.
	AdminName string
	Action    string
	Target    string
	Params    []byte
	IP        *netip.Addr
	PrevHash  []byte
	EntryHash []byte
}

// The join is a LEFT one so a row whose admin was deleted stays in the page, and it is on the primary key so a row
// matches at most one admin: the page keeps its size and its order, and the cursor (an id) stays exact.
const qAuditPage = `SELECT a.id, a.at, a.admin_id, COALESCE(u.username, ''), a.action, COALESCE(a.target, ''), a.params, a.ip, a.prev_hash, a.entry_hash
FROM ctrlz.audit_log a LEFT JOIN ctrlz.admin_users u ON u.id = a.admin_id
WHERE ($1::bigint = 0 OR a.id < $1) AND ($2::text = '' OR a.action = $2)
ORDER BY a.id DESC LIMIT $3`

// AuditPage returns up to limit rows, newest first, with an id below before
// (0 for the newest). action filters by exact name when not empty.
func (g GlobalTx) AuditPage(before int64, action string, limit int) ([]AuditRow, error) {
	return scanAudit(g.tx.Query(g.ctx, qAuditPage, before, action, int32(limit)))
}

const qAuditChain = `SELECT id, at, admin_id, ''::text, action, COALESCE(target, ''), params, ip, prev_hash, entry_hash
FROM ctrlz.audit_log WHERE id > $1 ORDER BY id LIMIT $2`

// AuditChain returns rows in chain order after the given id, for `audit
// verify`, which recomputes each hash.
func (g GlobalTx) AuditChain(after int64, limit int) ([]AuditRow, error) {
	return scanAudit(g.tx.Query(g.ctx, qAuditChain, after, int32(limit)))
}

func scanAudit(rows pgx.Rows, err error) ([]AuditRow, error) {
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []AuditRow
	for rows.Next() {
		var r AuditRow
		if err := rows.Scan(&r.ID, &r.At, &r.AdminID, &r.AdminName, &r.Action, &r.Target, &r.Params, scanAddr(&r.IP), &r.PrevHash, &r.EntryHash); err != nil {
			return nil, sanitize(err)
		}
		out = append(out, r)
	}
	return out, sanitize(rows.Err())
}

// ---------------------------------------------------------------------------
// Registration, Passkey configuration and admin jobs

// Registration is the registration settings (11).
type Registration struct {
	Mode             string
	OpenGraceDays    int
	TakeoverIdleDays int
}

const qRegistrationGet = `SELECT registration_mode, open_grace_days, takeover_idle_days FROM ctrlz.system_settings`

// RegistrationGet reads the settings.
func (g GlobalTx) RegistrationGet() (Registration, error) {
	var r Registration
	err := g.tx.QueryRow(g.ctx, qRegistrationGet).Scan(&r.Mode, &r.OpenGraceDays, &r.TakeoverIdleDays)
	return r, sanitize(err)
}

const qRegistrationSet = `UPDATE ctrlz.system_settings SET registration_mode = $1, open_grace_days = COALESCE($2::integer, open_grace_days)`

// RegistrationSet changes the mode and, when graceDays is not nil, the grace.
func (g GlobalTx) RegistrationSet(mode string, graceDays *int) error {
	_, err := g.tx.Exec(g.ctx, qRegistrationSet, mode, graceDays)
	return sanitize(err)
}

const qRegistrationGraceSet = `UPDATE ctrlz.system_settings SET open_grace_days = $1`

// RegistrationGraceSet changes only the grace days.
func (g GlobalTx) RegistrationGraceSet(days int) error {
	_, err := g.tx.Exec(g.ctx, qRegistrationGraceSet, days)
	return sanitize(err)
}

// RegistrationImpact is what moving to open does to claims that were never
// proven (11.4): the ones that get a grace, and the ones that already had their
// one grace and are suspended at once.
type RegistrationImpact struct {
	Graced          int
	SuspendedAtOnce int
}

const qRegistrationImpact = `SELECT count(*) FILTER (WHERE first_grace_at IS NULL), count(*) FILTER (WHERE first_grace_at IS NOT NULL)
FROM ctrlz.ip_claims WHERE state = 'active' AND proven_at IS NULL`

// RegistrationImpact counts the claims affected by moving to open, across all
// tenants, through the admin_read policy.
func (g GlobalTx) RegistrationImpact() (RegistrationImpact, error) {
	var r RegistrationImpact
	err := g.tx.QueryRow(g.ctx, qRegistrationImpact).Scan(&r.Graced, &r.SuspendedAtOnce)
	return r, sanitize(err)
}

// WebauthnConfig is the singleton webauthn_config.
type WebauthnConfig struct {
	RPID           string
	AllowedOrigins []string
	Enabled        bool
}

const qWebauthnConfigGet = `SELECT COALESCE(rp_id, ''), allowed_origins, enabled FROM ctrlz.webauthn_config`

// WebauthnConfigGet reads the configuration.
func (g GlobalTx) WebauthnConfigGet() (WebauthnConfig, error) {
	var c WebauthnConfig
	err := g.tx.QueryRow(g.ctx, qWebauthnConfigGet).Scan(&c.RPID, &c.AllowedOrigins, &c.Enabled)
	return c, sanitize(err)
}

const qWebauthnConfigSet = `UPDATE ctrlz.webauthn_config SET rp_id = $1, allowed_origins = $2, enabled = $3`

// WebauthnConfigSet writes the configuration. The origins are the server's:
// exactly https://<effective panel host>, never the admin's input (7.2).
func (g GlobalTx) WebauthnConfigSet(c WebauthnConfig) error {
	origins := c.AllowedOrigins
	if origins == nil {
		origins = []string{}
	}
	_, err := g.tx.Exec(g.ctx, qWebauthnConfigSet, emptyNull(c.RPID), origins, c.Enabled)
	return sanitize(err)
}

// WebauthnImpact is the count behind the RP ID page.
type WebauthnImpact struct {
	Credentials   int // live credentials with another RP ID
	Users         int // users who hold one
	EnforcedUsers int // of those, the ones with Enforce Passkey on
}

const qWebauthnImpact = `SELECT count(*), count(DISTINCT (w.tenant_id, w.user_id)),
  count(DISTINCT (w.tenant_id, w.user_id)) FILTER (WHERE u.enforce_passkey)
FROM ctrlz.webauthn_credentials w
JOIN ctrlz.users u ON u.tenant_id = w.tenant_id AND u.id = w.user_id
WHERE w.stale_at IS NULL AND w.rp_id <> $1`

// WebauthnImpact counts the credentials a change to rpID would make stale,
// through the admin_read policy.
func (g GlobalTx) WebauthnImpact(rpID string) (WebauthnImpact, error) {
	var r WebauthnImpact
	err := g.tx.QueryRow(g.ctx, qWebauthnImpact, rpID).Scan(&r.Credentials, &r.Users, &r.EnforcedUsers)
	return r, sanitize(err)
}

// AdminJob is a row of admin_jobs.
type AdminJob struct {
	ID         uuid.UUID
	Kind       string // registration_transition or webauthn_rp_change
	Params     []byte
	State      string
	Progress   []byte
	CreatedAt  time.Time
	StartedAt  *time.Time
	FinishedAt *time.Time
}

const qAdminJobInsert = `INSERT INTO ctrlz.admin_jobs (kind, params, created_by) VALUES ($1, $2, $3) RETURNING id`

// AdminJobInsert queues a job. At most one job of a kind is queued or running,
// so a second is ErrConflict. params is JSON.
func (g GlobalTx) AdminJobInsert(kind string, params []byte, createdBy uuid.UUID) (uuid.UUID, error) {
	if params == nil {
		params = []byte("{}")
	}
	var id uuid.UUID
	err := g.tx.QueryRow(g.ctx, qAdminJobInsert, kind, params, nilUUID(createdBy)).Scan(&id)
	return id, sanitize(err)
}

const qAdminJobsSupersede = `UPDATE ctrlz.admin_jobs SET state = 'failed', progress = progress || '{"superseded": true}'::jsonb, finished_at = now()
WHERE state IN ('queued', 'running') AND id = ANY (ARRAY(SELECT id FROM ctrlz.admin_jobs WHERE kind = $1 AND state IN ('queued', 'running')` + orderedUpdate + `))`

// AdminJobsSupersede ends the queued or running job of a kind that a newer change makes
// obsolete, and says how many it ended (0 or 1: the index admin_jobs_one_active_uq). Without it
// a stopped worker, or a job that keeps failing, made every later change of the kind a 409, and
// the owner could not close registration while abuse went on (round 5, admin-r5-2). A job is a
// function of the target state and not of the change that queued it, so the newer change loses
// nothing by it.
//
// It must be the first statement of the transaction that queues the replacement: admin_jobs
// ranks before the settings rows (rule lock-order), and a worker still walking the job holds
// its row FOR SHARE (AdminJobHold) so this waits for that tenant's short transaction and the
// worker's next AdminJobHold finds the job ended. The worker's own AdminJobFinish then loses.
func (g GlobalTx) AdminJobsSupersede(kind string) (int, error) {
	tag, err := g.tx.Exec(g.ctx, qAdminJobsSupersede, kind)
	if err != nil {
		return 0, sanitize(err)
	}
	return int(tag.RowsAffected()), nil
}

// ---------------------------------------------------------------------------
// Users and invites (the minimum admin, T-327)

// AdminUserRow is a row of GET /users.
type AdminUserRow struct {
	TenantID                 uuid.UUID
	UserID                   uuid.UUID
	Phone                    string
	TenantStatus             string
	CreatedAt                time.Time
	LastLoginAt              *time.Time
	OneTimePasswordExpiresAt *time.Time
}

const qAdminUsersPage = `SELECT u.tenant_id, u.id, u.phone_e164, t.status, u.created_at, u.last_login_at,
  ctrlz.one_time_expiry(u.must_reset, u.password_expires_at)
FROM ctrlz.users u JOIN ctrlz.tenants t ON t.id = u.tenant_id
WHERE ($1::text = '' OR starts_with(u.phone_e164, $1)) AND ($2::uuid IS NULL OR u.id < $2)
ORDER BY u.id DESC LIMIT $3`

// AdminUsersPage lists users newest first, by phone prefix, under the admin_read
// policies. It selects named columns only: never a hash, a secret or a log row.
func (g GlobalTx) AdminUsersPage(prefix string, before uuid.UUID, limit int) ([]AdminUserRow, error) {
	rows, err := g.tx.Query(g.ctx, qAdminUsersPage, prefix, nilUUID(before), int32(limit))
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []AdminUserRow
	for rows.Next() {
		var r AdminUserRow
		if err := rows.Scan(&r.TenantID, &r.UserID, &r.Phone, &r.TenantStatus, &r.CreatedAt, &r.LastLoginAt, &r.OneTimePasswordExpiresAt); err != nil {
			return nil, sanitize(err)
		}
		out = append(out, r)
	}
	return out, sanitize(rows.Err())
}

const qPhoneHasAccount = `SELECT EXISTS (SELECT 1 FROM ctrlz.users WHERE phone_e164 = $1)`

// PhoneHasAccount says whether a user holds the number, for the 409 on an
// invite to a taken phone.
func (g GlobalTx) PhoneHasAccount(phone string) (bool, error) {
	var b bool
	err := g.tx.QueryRow(g.ctx, qPhoneHasAccount, phone).Scan(&b)
	return b, sanitize(err)
}

// NewInvite is the input of InviteCreate.
type NewInvite struct {
	// ID is made by the caller because it is inside the signed link (spec 11.3, D67), which is minted before the row exists.
	// The zero value leaves it to the column default, as every other writer of the table does.
	ID        uuid.UUID
	TokenHash []byte // SHA-256 of the 140 characters of the link
	Phone     string
	Locale    string
	CreatedBy uuid.UUID
	// TTL is how long the invite lives. The database adds it to its own clock:
	// auth_register_user compares the expiry with now() (clocks.yaml, db).
	TTL time.Duration
}

const qInviteCreate = `INSERT INTO ctrlz.invites (id, token_hash, phone_e164, locale, created_by, expires_at)
VALUES (COALESCE($1::uuid, uuidv7()), $2, $3, $4, $5, now() + make_interval(secs => $6)) RETURNING id`

// InviteCreate stores an invite.
func (g GlobalTx) InviteCreate(i NewInvite) (uuid.UUID, error) {
	var id uuid.UUID
	err := g.tx.QueryRow(g.ctx, qInviteCreate, nilUUID(i.ID), i.TokenHash, i.Phone, i.Locale, nilUUID(i.CreatedBy), i.TTL.Seconds()).Scan(&id)
	return id, sanitize(err)
}

// InviteRow is a row of GET /invites. It carries no code.
type InviteRow struct {
	ID        uuid.UUID
	Phone     string
	Locale    string
	State     string // pending, used, revoked or expired
	ExpiresAt time.Time
	CreatedAt time.Time
}

const qInvitesPage = `SELECT id, phone_e164, locale,
  CASE WHEN used_at IS NOT NULL THEN 'used' WHEN revoked_at IS NOT NULL THEN 'revoked'
       WHEN expires_at <= now() THEN 'expired' ELSE 'pending' END,
  expires_at, created_at
FROM ctrlz.invites WHERE ($1::uuid IS NULL OR id < $1) ORDER BY id DESC LIMIT $2`

// InvitesPage lists invites newest first.
func (g GlobalTx) InvitesPage(before uuid.UUID, limit int) ([]InviteRow, error) {
	rows, err := g.tx.Query(g.ctx, qInvitesPage, nilUUID(before), int32(limit))
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []InviteRow
	for rows.Next() {
		var r InviteRow
		if err := rows.Scan(&r.ID, &r.Phone, &r.Locale, &r.State, &r.ExpiresAt, &r.CreatedAt); err != nil {
			return nil, sanitize(err)
		}
		out = append(out, r)
	}
	return out, sanitize(rows.Err())
}

const qInviteRevoke = `UPDATE ctrlz.invites SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL AND used_at IS NULL`

// InviteRevoke revokes an unused invite; false when there is nothing to revoke.
func (g GlobalTx) InviteRevoke(id uuid.UUID) (bool, error) {
	tag, err := g.tx.Exec(g.ctx, qInviteRevoke, id)
	if err != nil {
		return false, sanitize(err)
	}
	return tag.RowsAffected() == 1, nil
}

// ---------------------------------------------------------------------------
// Alerts

// AlertRow is a row of GET /alerts.
type AlertRow struct {
	ID         uuid.UUID
	Severity   string
	Kind       string
	Params     []byte
	CreatedAt  time.Time
	ResolvedAt *time.Time
}

const qAlertsPage = `SELECT id, severity, kind, params, created_at, resolved_at FROM ctrlz.alerts
WHERE ($1::uuid IS NULL OR id < $1)
ORDER BY (resolved_at IS NOT NULL), id DESC LIMIT $2`

// AlertsPage lists alerts, unresolved first.
func (g GlobalTx) AlertsPage(before uuid.UUID, limit int) ([]AlertRow, error) {
	rows, err := g.tx.Query(g.ctx, qAlertsPage, nilUUID(before), int32(limit))
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []AlertRow
	for rows.Next() {
		var r AlertRow
		if err := rows.Scan(&r.ID, &r.Severity, &r.Kind, &r.Params, &r.CreatedAt, &r.ResolvedAt); err != nil {
			return nil, sanitize(err)
		}
		out = append(out, r)
	}
	return out, sanitize(rows.Err())
}

const qAlertAck = `UPDATE ctrlz.alerts SET resolved_at = now() WHERE id = $1 AND resolved_at IS NULL RETURNING kind`

// AlertAck resolves an alert and returns its kind for the audit row.
func (g GlobalTx) AlertAck(id uuid.UUID) (string, bool, error) {
	var kind string
	err := g.tx.QueryRow(g.ctx, qAlertAck, id).Scan(&kind)
	ok, err := notFound(err)
	return kind, ok, err
}

// ---------------------------------------------------------------------------
// Re-issue of a user's one-time password (T-536, 10.7). These run inside
// WithTenant on the tenant from the route's path, as ctrlz_admin.

// OneTimeState is what step 3a of 10.7 reads under the row lock.
type OneTimeState struct {
	State          credstate.State
	NoSecondFactor bool
	TenantStatus   string
}

const qOneTimeState = `SELECT cred_state, no_second_factor, tenant_status
FROM ctrlz_fn.admin_one_time_state($1)`

// OneTimePasswordLock locks the user row and reads what decides whether a
// re-issue is allowed. It is the first statement of the transaction, so the
// user's own password change and a login take the same lock in the same order.
// ctrlz_admin has no UPDATE on users, which SELECT ... FOR UPDATE needs, so the
// lock is taken inside ctrlz_fn.admin_one_time_state (migration 0014), on the
// tenant of the transaction setting.
func (t Tx) OneTimePasswordLock(user uuid.UUID) (OneTimeState, bool, error) {
	var s OneTimeState
	var state string
	err := t.tx.QueryRow(t.ctx, qOneTimeState, user).Scan(&state, &s.NoSecondFactor, &s.TenantStatus)
	ok, err := notFound(err)
	if err != nil || !ok {
		return s, ok, err
	}
	s.State, err = credstate.Parse(state)
	return s, true, sanitize(err)
}

const qOneTimeReissue = `SELECT outcome, was_expired, expires_at FROM ctrlz_fn.admin_reissue_one_time_password($1, $2)`

// OneTimeReissue is what the database function of 10.7 steps a and b decided.
type OneTimeReissue struct {
	// Outcome is "ok", "not_found" (no such user in the tenant, or the tenant is
	// being deleted) or "not_one_time" (the password is the user's own, or a
	// second factor exists). Nothing changed unless it is "ok".
	Outcome    string
	WasExpired bool
	ExpiresAt  time.Time
}

// OneTimePasswordReissue is steps a and b of 10.7 in one call. The eligibility
// rule and the update live in ctrlz_fn.admin_reissue_one_time_password under the
// row lock, because ctrlz_admin has no UPDATE on password_hash, must_reset or
// password_expires_at: the rule binds code that is not this handler too (review
// round 1). The 72 hours are those of admin_create_user (D31); password_changed_at
// is not touched. The tenant is the one WithTenant set.
func (t Tx) OneTimePasswordReissue(user uuid.UUID, oneTimeHash secret.String) (OneTimeReissue, error) {
	var r OneTimeReissue
	var at *time.Time
	if err := t.tx.QueryRow(t.ctx, qOneTimeReissue, user, oneTimeHash.Reveal()).Scan(&r.Outcome, &r.WasExpired, &at); err != nil {
		return OneTimeReissue{}, sanitize(err)
	}
	if at != nil {
		r.ExpiresAt = *at
	}
	return r, nil
}

// OneTimePasswordSet replaces the user's one-time password and returns its new
// expiry: OneTimePasswordReissue with the refusals as errors. A user of another
// tenant, or one being deleted, is ErrNotFound; a user who is not eligible is
// ErrConflict. Nothing changes in either case.
func (t Tx) OneTimePasswordSet(user uuid.UUID, oneTimeHash secret.String) (time.Time, error) {
	r, err := t.OneTimePasswordReissue(user, oneTimeHash)
	if err != nil {
		return time.Time{}, err
	}
	switch r.Outcome {
	case "ok":
		return r.ExpiresAt, nil
	case "not_found":
		return time.Time{}, ErrNotFound
	}
	return time.Time{}, ErrConflict
}

// The admin role holds no UPDATE on sessions or refresh_tokens: revoked_at is a
// guarded column (role-reach), and ctrlz_fn.admin_revoke_user_sessions sets it for one
// user of the tenant of the transaction, sessions first and then refresh tokens.
const qAdminRevokeSessions = `SELECT ctrlz_fn.admin_revoke_user_sessions($1)`

// RevokeUserSessions revokes every session and refresh token of the user.
// It reads only the key columns ctrlz_admin may select, so it counts rows that
// may already have expired and are not yet swept (10.7 step c).
func (t Tx) RevokeUserSessions(user uuid.UUID) (int, error) {
	var n int32
	if err := t.tx.QueryRow(t.ctx, qAdminRevokeSessions, user).Scan(&n); err != nil {
		return 0, sanitize(err)
	}
	return int(n), nil
}

// AdminNoticeAppendAll adds a notice to every enabled admin's banner in one
// transaction, under the row locks, so two changes at once both show. It is how
// a change of the SMS gateway credentials or routing reaches the owner even when
// a stolen session made it (spec 10.7, review round 2 admin-r2-8). It returns the
// number of admins notified.
func (g GlobalTx) AdminNoticeAppendAll(n adminnotice.Notice) (int, error) {
	type row struct {
		id  uuid.UUID
		cur []byte
	}
	rows, err := g.tx.Query(g.ctx, qAdminNoticeRows)
	if err != nil {
		return 0, sanitize(err)
	}
	var all []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.cur); err != nil {
			rows.Close()
			return 0, sanitize(err)
		}
		all = append(all, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, sanitize(err)
	}
	for _, r := range all {
		next, err := adminnotice.Append(r.cur, n)
		if err != nil {
			return 0, err
		}
		if err := g.AdminNoticeSet(r.id, next); err != nil {
			return 0, err
		}
	}
	return len(all), nil
}

// AdminNoticeAck removes the notices an admin session may dismiss: those dated
// before the session was created. A notice made during the session (the SMS
// gateway change a stolen session just made) stays, so the session that caused a
// warning cannot erase it before the owner sees it, and a notice that arrived
// after the client last read GET /me is never dropped unseen (review round 3,
// admin-r3-1, admin-r3-8). The comparison is on milliseconds, the precision a notice
// is stored with, and rounds the session down: a notice made in the millisecond
// the session was created counts as made during it.
//
// It returns how many notices it removed and how many it kept. The row is locked,
// so an append from another transaction is either seen here or applied after.
func (g GlobalTx) AdminNoticeAck(id uuid.UUID, sessionCreated time.Time) (cleared, kept int, err error) {
	var cur []byte
	if err := g.tx.QueryRow(g.ctx, qAdminNoticeLock, id).Scan(&cur); err != nil {
		if _, e := notFound(err); e == nil {
			return 0, 0, nil
		}
		return 0, 0, sanitize(err)
	}
	cutoff := sessionCreated.UTC().Truncate(time.Millisecond)
	all := adminnotice.Parse(cur)
	var keep []adminnotice.Notice
	for _, n := range all {
		if n.At.Before(cutoff) {
			cleared++
			continue
		}
		keep = append(keep, n)
	}
	if cleared == 0 {
		return 0, len(all), nil
	}
	var next []byte
	if len(keep) > 0 {
		if next, err = adminnotice.Marshal(keep); err != nil {
			return 0, 0, err
		}
	}
	if err := g.AdminNoticeSet(id, next); err != nil {
		return 0, 0, err
	}
	return cleared, len(keep), nil
}
