package store

import (
	"errors"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/credstate"
	"github.com/Kup1ng/CtrlZ-Panel/internal/credgen"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
)

// This file holds the tenant-scoped SQL of P1: users, sessions, refresh
// tokens, TOTP, recovery codes, passkeys, phone changes, notifications and the
// tenant audit log. Every method runs inside WithTenant, so row level security
// already limits it to the tenant of the transaction; each statement also names
// the tenant, so a mistake in a policy would not be the only thing between two
// tenants. Ids that a request supplies (a session id, a passkey id) are always
// matched together with the tenant, and a row of another tenant is "not found",
// never "forbidden".
//
// The roles that run these differ: ctrlz_tenant for the user's own requests,
// ctrlz_worker for sweeps and ctrlz_admin for the re-issue of a one-time
// password. The grants of migration 0011 are what each of them may do, and a
// method that a role has no grant for fails with ErrPermission.

// maxUserAgent is the length the sessions table accepts (a CHECK).
const maxUserAgent = 256

func clipUserAgent(ua string) string {
	r := []rune(ua)
	if len(r) > maxUserAgent {
		r = r[:maxUserAgent]
	}
	return string(r)
}

// nilUUID is NULL for the nil uuid.
func nilUUID(id uuid.UUID) any {
	if id == uuid.Nil {
		return nil
	}
	return id
}

// emptyNull is NULL for the empty string.
func emptyNull(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// notFound turns pgx.ErrNoRows into found=false.
func notFound(err error) (bool, error) {
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, sanitize(err)
	}
	return true, nil
}

// ---------------------------------------------------------------------------
// Users

// User is the account row the shell and the Account page need. It never holds
// password_hash or totp_secret_ct, which the tenant role cannot select.
type User struct {
	Tenant uuid.UUID
	// CredentialGen is credential_gen of the row (migration 0022). Use Stamp, never the number.
	CredentialGen   int64
	ID              uuid.UUID
	Phone           string
	PhoneVerifiedAt *time.Time
	TOTPEnabledAt   *time.Time
	// TOTPPending and TOTPPendingStale are decided in SQL on the database clock
	// (totp_pending_at is a db column, clocks.yaml): a setup is pending, and it is
	// older than the 15 minutes it lives.
	TOTPPending       bool
	TOTPPendingStale  bool
	EnforcePasskey    bool
	EnforceLiftAt     *time.Time
	PasskeyReviewAt   *time.Time
	Locale            string
	Theme             string
	OnboardingHints   []byte // jsonb
	OnboardingState   []byte // jsonb
	LastLoginAt       *time.Time
	PasswordChangedAt *time.Time
	// State is the one-time credential state on the database clock (rule one-time-state,
	// internal/auth/credstate). It is read in the statement of the other database-clock
	// decisions, not in qUser, because that one carries enforce_lift_at (application clock).
	State credstate.State
}

const qUser = `SELECT tenant_id, credential_gen, id, phone_e164, phone_verified_at, totp_enabled_at, enforce_passkey, enforce_lift_at,
  passkey_review_at, locale, theme, onboarding_hints, onboarding_state, last_login_at,
  password_changed_at
FROM ctrlz.users WHERE tenant_id = $1 AND id = $2`

// qUserDecisions are the two decisions on the database clock. They are a statement of
// their own because qUser carries enforce_lift_at, an application-clock column, and
// one statement does not read two clocks (clocks.yaml).
const qUserDecisions = `SELECT totp_pending_at IS NOT NULL,
  COALESCE(totp_pending_at <= now() - interval '15 minutes', false),
  ` + userStateSQL + `
FROM ctrlz.users WHERE tenant_id = $1 AND id = $2`

// User reads one user of the tenant.
func (t Tx) User(id uuid.UUID) (User, bool, error) {
	var u User
	err := t.tx.QueryRow(t.ctx, qUser, t.tenant, id).Scan(&u.Tenant, &u.CredentialGen, &u.ID, &u.Phone, &u.PhoneVerifiedAt, &u.TOTPEnabledAt,
		&u.EnforcePasskey, &u.EnforceLiftAt, &u.PasskeyReviewAt, &u.Locale, &u.Theme, &u.OnboardingHints, &u.OnboardingState,
		&u.LastLoginAt, &u.PasswordChangedAt)
	ok, err := notFound(err)
	if err != nil || !ok {
		return u, ok, err
	}
	var state string
	err = t.tx.QueryRow(t.ctx, qUserDecisions, t.tenant, id).Scan(&u.TOTPPending, &u.TOTPPendingStale, &state)
	if err != nil {
		return u, true, sanitize(err)
	}
	u.State, err = credstate.Parse(state)
	return u, true, sanitize(err)
}

// Stamp is the credentials of the row as read: the subject and its generation.
func (u User) Stamp() credgen.Stamp {
	return credgen.Stamp{Tenant: u.Tenant, Subject: u.ID, Gen: u.CredentialGen}
}

// UserLock is what a login or a password change must see under the row lock.
type UserLock struct {
	// Cred is the stamp of the locked row (internal/credgen). Whatever was derived from a
	// first-factor check is compared with it by UserLockFor, not by field.
	Cred credgen.Stamp
	// State is the credential state of the locked row (rule one-time-state).
	State credstate.State
}

// Preferences is a partial update of the Account page's settings; a nil field
// is left as it is.
type Preferences struct {
	Locale          *string
	Theme           *string
	OnboardingHints []byte // jsonb, nil to keep
	OnboardingState []byte // jsonb, nil to keep
}

const qUpdatePreferences = `UPDATE ctrlz.users
SET locale = COALESCE($3::text, locale), theme = COALESCE($4::text, theme),
    onboarding_hints = COALESCE($5::jsonb, onboarding_hints), onboarding_state = COALESCE($6::jsonb, onboarding_state)
WHERE tenant_id = $1 AND id = $2`

// UpdatePreferences changes the user's locale, theme and onboarding state.
func (t Tx) UpdatePreferences(id uuid.UUID, p Preferences) (bool, error) {
	tag, err := t.tx.Exec(t.ctx, qUpdatePreferences, t.tenant, id, p.Locale, p.Theme, p.OnboardingHints, p.OnboardingState)
	if err != nil {
		return false, sanitize(err)
	}
	return tag.RowsAffected() == 1, nil
}

const qMarkLogin = `UPDATE ctrlz.users SET last_login_at = now() WHERE tenant_id = $1 AND id = $2`

// MarkLogin records a login.
func (t Tx) MarkLogin(id uuid.UUID) error {
	_, err := t.tx.Exec(t.ctx, qMarkLogin, t.tenant, id)
	return sanitize(err)
}

const qSetPassword = `SELECT ctrlz_fn.tenant_set_password($1, $2)`

// SetPassword stores a password the user chose, from any state: the hash, the time it
// was chosen, and the end of the one-time password move together in one definer
// function (the edge credstate.UserSetPassword), and the tenant role can write none of
// the one-time columns itself. The function acts on the tenant WithTenant set.
func (t Tx) SetPassword(id uuid.UUID, hash secret.String) (bool, error) {
	var ok bool
	if err := t.tx.QueryRow(t.ctx, qSetPassword, id, hash.Reveal()).Scan(&ok); err != nil {
		return false, sanitize(err)
	}
	return ok, nil
}

const qRehashPassword = `UPDATE ctrlz.users SET password_hash = $4 WHERE tenant_id = $1 AND id = $2 AND credential_gen = $3
RETURNING credential_gen`

// RehashPassword replaces the hash after a login whose stored parameters are not the
// current ones (4.1). The write carries the stamp of the password that was verified:
// a rehash of an old password after a change would bring the old password back, so a
// row whose generation or subject is not the stamp's is not written (credgen.ErrStale).
// The rehash itself changes password_hash and so moves the generation; the new stamp is
// returned, for the ticket and the marker this login goes on to make.
func (t Tx) RehashPassword(issued credgen.Stamp, hash secret.String) (credgen.Stamp, error) {
	if issued.Zero() || issued.Tenant != t.tenant {
		return credgen.Stamp{}, credgen.ErrStale
	}
	next := issued
	err := t.tx.QueryRow(t.ctx, qRehashPassword, t.tenant, issued.Subject, issued.Gen, hash.Reveal()).Scan(&next.Gen)
	if ok, err := notFound(err); err != nil {
		return credgen.Stamp{}, err
	} else if !ok {
		return credgen.Stamp{}, credgen.ErrStale
	}
	return next, nil
}

const qSetEnforce = `UPDATE ctrlz.users SET enforce_passkey = $3, enforce_lift_at = NULL WHERE tenant_id = $1 AND id = $2`

// SetEnforce turns Enforce Passkey on or off. Either way a pending lift ends.
func (t Tx) SetEnforce(id uuid.UUID, on bool) error {
	_, err := t.tx.Exec(t.ctx, qSetEnforce, t.tenant, id, on)
	return sanitize(err)
}

const qDeferEnforceLift = `UPDATE ctrlz.users
SET enforce_lift_at = COALESCE(enforce_lift_at, $4::timestamptz + make_interval(secs => $3))
WHERE tenant_id = $1 AND id = $2 AND enforce_passkey
RETURNING enforce_lift_at`

// DeferEnforceLift starts the delay after which Enforce counts as off (4.4,
// D46). COALESCE keeps an earlier value, so repeating the step neither extends
// nor shortens the delay. It returns the time the lift takes effect. now is the
// application clock: enforce_lift_at is compared with it (clocks.yaml, app).
func (t Tx) DeferEnforceLift(id uuid.UUID, delay time.Duration, now time.Time) (time.Time, bool, error) {
	var at time.Time
	err := t.tx.QueryRow(t.ctx, qDeferEnforceLift, t.tenant, id, delay.Seconds(), now).Scan(&at)
	ok, err := notFound(err)
	return at, ok, err
}

const qClearEnforceLift = `UPDATE ctrlz.users SET enforce_lift_at = NULL WHERE tenant_id = $1 AND id = $2`

// ClearEnforceLift ends a pending lift: the owner came back with the passkey.
func (t Tx) ClearEnforceLift(id uuid.UUID) error {
	_, err := t.tx.Exec(t.ctx, qClearEnforceLift, t.tenant, id)
	return sanitize(err)
}

const qSetPasskeyReview = `UPDATE ctrlz.users SET passkey_review_at = CASE WHEN $3 THEN now() ELSE NULL END WHERE tenant_id = $1 AND id = $2`

// SetPasskeyReview sets or clears the review flag of 7.7.
func (t Tx) SetPasskeyReview(id uuid.UUID, on bool) error {
	_, err := t.tx.Exec(t.ctx, qSetPasskeyReview, t.tenant, id, on)
	return sanitize(err)
}

// ---------------------------------------------------------------------------
// TOTP and recovery codes

const qTOTPSetPending = `UPDATE ctrlz.users SET totp_secret_ct = $3, totp_pending_at = now(), totp_last_step = NULL
WHERE tenant_id = $1 AND id = $2 AND totp_enabled_at IS NULL`

// TOTPSetPending stores a new, unconfirmed secret sealed under user_totp,
// replacing an earlier unconfirmed one. It does nothing (false) when TOTP is
// already enabled.
func (t Tx) TOTPSetPending(id uuid.UUID, secretCT []byte) (bool, error) {
	tag, err := t.tx.Exec(t.ctx, qTOTPSetPending, t.tenant, id, secretCT)
	if err != nil {
		return false, sanitize(err)
	}
	return tag.RowsAffected() == 1, nil
}

const qTOTPEnable = `UPDATE ctrlz.users SET totp_enabled_at = now(), totp_pending_at = NULL
WHERE tenant_id = $1 AND id = $2 AND totp_enabled_at IS NULL AND totp_pending_at > now() - interval '15 minutes'`

// TOTPEnable confirms the pending secret. A pending secret lives 15 minutes;
// false means there is none or it is older (6.4).
func (t Tx) TOTPEnable(id uuid.UUID) (bool, error) {
	tag, err := t.tx.Exec(t.ctx, qTOTPEnable, t.tenant, id)
	if err != nil {
		return false, sanitize(err)
	}
	return tag.RowsAffected() == 1, nil
}

const qTOTPClearPending = `UPDATE ctrlz.users SET totp_secret_ct = NULL, totp_pending_at = NULL
WHERE tenant_id = $1 AND id = $2 AND totp_enabled_at IS NULL`

// TOTPClearPending drops an unconfirmed secret.
func (t Tx) TOTPClearPending(id uuid.UUID) error {
	_, err := t.tx.Exec(t.ctx, qTOTPClearPending, t.tenant, id)
	return sanitize(err)
}

const qTOTPDisable = `UPDATE ctrlz.users
SET totp_secret_ct = NULL, totp_enabled_at = NULL, totp_last_step = NULL, totp_pending_at = NULL
WHERE tenant_id = $1 AND id = $2`

// TOTPDisable removes TOTP. The caller deletes the recovery codes in the same
// transaction.
func (t Tx) TOTPDisable(id uuid.UUID) error {
	_, err := t.tx.Exec(t.ctx, qTOTPDisable, t.tenant, id)
	return sanitize(err)
}

const qTOTPStepAccept = `UPDATE ctrlz.users SET totp_last_step = $3
WHERE tenant_id = $1 AND id = $2 AND (totp_last_step IS NULL OR totp_last_step < $3)`

// TOTPStepAccept records that a code of the given step was used. A loss means the step
// (or a later one) was already spent, which is a replay (6.3). The UPDATE is the
// decision, so two parallel requests with one code cannot both win.
func (t Tx) TOTPStepAccept(id uuid.UUID, step int64) (Won, error) {
	tag, err := t.tx.Exec(t.ctx, qTOTPStepAccept, t.tenant, id, step)
	if err != nil {
		return Won{}, sanitize(err)
	}
	return wonRows(tag), nil
}

const qRecoveryDelete = `DELETE FROM ctrlz.recovery_codes WHERE tenant_id = $1 AND id = ANY (ARRAY(SELECT id FROM ctrlz.recovery_codes WHERE tenant_id = $1 AND user_id = $2` + orderedDelete + `))`
const qRecoveryInsert = `INSERT INTO ctrlz.recovery_codes (tenant_id, user_id, code_hash)
SELECT $1, $2, h FROM unnest($3::bytea[]) AS h ORDER BY h`

// RecoveryCodesReplace deletes the user's recovery codes and stores the given
// hashes (SHA-256 of the canonical text). Pass none to only delete.
func (t Tx) RecoveryCodesReplace(user uuid.UUID, hashes [][]byte) error {
	if _, err := t.tx.Exec(t.ctx, qRecoveryDelete, t.tenant, user); err != nil {
		return sanitize(err)
	}
	if len(hashes) == 0 {
		return nil
	}
	_, err := t.tx.Exec(t.ctx, qRecoveryInsert, t.tenant, user, hashes)
	return sanitize(err)
}

const qRecoveryUse = `UPDATE ctrlz.recovery_codes SET used_at = now()
WHERE tenant_id = $1 AND used_at IS NULL AND id = ANY (ARRAY(SELECT id FROM ctrlz.recovery_codes WHERE tenant_id = $1 AND user_id = $2 AND code_hash = $3 AND used_at IS NULL` + orderedUpdate + `))`

// RecoveryCodeUse spends a recovery code. A win means accepted; the UPDATE is
// the decision, so two parallel requests with one code cannot both win.
func (t Tx) RecoveryCodeUse(user uuid.UUID, hash []byte) (Won, error) {
	tag, err := t.tx.Exec(t.ctx, qRecoveryUse, t.tenant, user, hash)
	if err != nil {
		return Won{}, sanitize(err)
	}
	return wonRows(tag), nil
}

const qRecoveryLeft = `SELECT count(*) FROM ctrlz.recovery_codes WHERE tenant_id = $1 AND user_id = $2 AND used_at IS NULL`

// RecoveryCodesLeft counts the unused codes.
func (t Tx) RecoveryCodesLeft(user uuid.UUID) (int, error) {
	var n int
	if err := t.tx.QueryRow(t.ctx, qRecoveryLeft, t.tenant, user).Scan(&n); err != nil {
		return 0, sanitize(err)
	}
	return n, nil
}

// ---------------------------------------------------------------------------
// Sessions

// NewSession is the input of SessionCreate. The token is hashed by the caller
// (SHA-256 of the cookie value); the times come from the caller's clock.
type NewSession struct {
	// ID is the id of the session row. The session manager makes it BEFORE the insert because the cookie
	// carries it under its tag (internal/auth/session/tag.go: the session-miss budget is keyed on it, round 8,
	// tenant-r8-3). The nil uuid lets the database choose, for the tests that need no cookie.
	ID                uuid.UUID
	UserID            uuid.UUID
	TokenHash         []byte
	RememberMe        bool
	IdleExpiresAt     time.Time
	AbsoluteExpiresAt time.Time
	Restricted        bool
	AuthMethod        string // password, otp or passkey
	IP                netip.Addr
	UserAgent         string
	// At is the application clock at creation. It stamps last_seen_at, which the
	// session list shows and a touch moves, on the same clock as the expiries.
	At time.Time
}

const qSessionCreate = `INSERT INTO ctrlz.sessions
  (id, tenant_id, user_id, token_hash, remember_me, idle_expires_at, absolute_expires_at, restricted, auth_method, ip, user_agent, last_seen_at)
VALUES (COALESCE($12::uuid, uuidv7()), $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
RETURNING id`

// SessionCreate inserts a session and returns its id.
func (t Tx) SessionCreate(s NewSession) (uuid.UUID, error) {
	var id uuid.UUID
	err := t.tx.QueryRow(t.ctx, qSessionCreate, t.tenant, s.UserID, s.TokenHash, s.RememberMe, s.IdleExpiresAt,
		s.AbsoluteExpiresAt, s.Restricted, s.AuthMethod, addrArg(s.IP), emptyNull(clipUserAgent(s.UserAgent)), s.At, nilUUID(s.ID)).Scan(&id)
	return id, sanitize(err)
}

// SessionRow is a session as the Account page and the refresh route read it.
type SessionRow struct {
	ID                uuid.UUID
	UserID            uuid.UUID
	RememberMe        bool
	IdleExpiresAt     time.Time
	AbsoluteExpiresAt time.Time
	RevokedAt         *time.Time
	LastSeenAt        time.Time
	CreatedAt         time.Time
	Restricted        bool
	ReauthAt          *time.Time
	AuthMethod        string
	IP                *netip.Addr
	UserAgent         string
}

const sessionColumns = `id, user_id, remember_me, idle_expires_at, absolute_expires_at, revoked_at, last_seen_at, created_at,
  restricted, reauth_at, auth_method, ip, COALESCE(user_agent, '')`

func scanSession(r pgx.Row) (s SessionRow, err error) {
	err = r.Scan(&s.ID, &s.UserID, &s.RememberMe, &s.IdleExpiresAt, &s.AbsoluteExpiresAt, &s.RevokedAt, &s.LastSeenAt,
		&s.CreatedAt, &s.Restricted, &s.ReauthAt, &s.AuthMethod, scanAddr(&s.IP), &s.UserAgent)
	return s, err
}

const qSessionByID = `SELECT ` + sessionColumns + ` FROM ctrlz.sessions WHERE tenant_id = $1 AND id = $2`

// SessionByID reads one session of the tenant.
func (t Tx) SessionByID(id uuid.UUID) (SessionRow, bool, error) {
	s, err := scanSession(t.tx.QueryRow(t.ctx, qSessionByID, t.tenant, id))
	ok, err := notFound(err)
	return s, ok, err
}

const qSessionsList = `SELECT ` + sessionColumns + ` FROM ctrlz.sessions
WHERE tenant_id = $1 AND user_id = $2 AND revoked_at IS NULL AND absolute_expires_at > $3 AND idle_expires_at > $3
ORDER BY created_at DESC, id DESC
LIMIT $4`

// SessionListLimit is the most sessions one list returns, and is the maxItems of SessionList.sessions in
// api/openapi.yaml (a test holds the two together). A login past caps.MaxSessions ends the oldest session of the
// account (tenant-r18-2), so a live account holds few; the list still must not read and serialise every row of
// an account that holds tens of thousands by any other way (a lowered cap, rows written outside the login;
// round 17, tenant-r17-2). It is the newest ones: the caller adds
// its own session when that is older than all of them (ListSessions).
const SessionListLimit = 1000

// SessionsList returns the user's newest live sessions at the application time now, newest first, at most
// SessionListLimit of them.
func (t Tx) SessionsList(user uuid.UUID, now time.Time) ([]SessionRow, error) {
	rows, err := t.tx.Query(t.ctx, qSessionsList, t.tenant, user, now, SessionListLimit)
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []SessionRow
	for rows.Next() {
		s, err := scanSession(rows)
		if err != nil {
			return nil, sanitize(err)
		}
		out = append(out, s)
	}
	return out, sanitize(rows.Err())
}

const qSessionTouch = `UPDATE ctrlz.sessions
SET last_seen_at = $4, idle_expires_at = LEAST($3, absolute_expires_at)
WHERE tenant_id = $1 AND id = $2 AND revoked_at IS NULL`

// SessionTouch slides the idle limit (3.3). The caller does it at most once a
// minute per session. now is the application clock, like every session time.
func (t Tx) SessionTouch(id uuid.UUID, idleExpiresAt, now time.Time) error {
	_, err := t.tx.Exec(t.ctx, qSessionTouch, t.tenant, id, idleExpiresAt, now)
	return sanitize(err)
}

// ReauthMode says what a rotation does to the reauth window.
type ReauthMode string

// The three things a rotation can do to reauth_at.
const (
	ReauthKeep  ReauthMode = "keep"
	ReauthSet   ReauthMode = "set"   // POST /auth/reauth
	ReauthClear ReauthMode = "clear" // a refresh never inherits a window (3.4)
)

const qSessionRotate = `UPDATE ctrlz.sessions
SET token_hash = $3, idle_expires_at = $4, last_seen_at = $7::timestamptz,
    reauth_at = CASE $5::text WHEN 'set' THEN $7::timestamptz WHEN 'clear' THEN NULL ELSE reauth_at END,
    restricted = restricted AND NOT $6::boolean
WHERE tenant_id = $1 AND id = $2 AND revoked_at IS NULL`
const qSessionRotateRefresh = `UPDATE ctrlz.refresh_tokens SET revoked_at = now()
WHERE tenant_id = $1 AND revoked_at IS NULL AND id = ANY (ARRAY(SELECT id FROM ctrlz.refresh_tokens WHERE tenant_id = $1 AND session_id = $2 AND revoked_at IS NULL` + orderedUpdate + `))`

// SessionRotate gives a session a new token (3.7): the old cookie is dead at
// commit, and every refresh token of the session is revoked, so a stolen refresh
// cookie cannot take the row back. The caller inserts the new refresh row with
// RefreshCreate when the session is Remember me. clearRestricted is for the
// password change that ends a one-time password session. now is the application
// clock: it stamps last_seen_at and, for ReauthSet, reauth_at, because the gate
// compares them with that clock and a database clock that is off would shorten or
// stretch the window (review round 3, primitives-r3-4; clocks.yaml). It returns false for a
// revoked or foreign session, and then changes nothing.
func (t Tx) SessionRotate(id uuid.UUID, newHash []byte, idleExpiresAt time.Time, reauth ReauthMode, now time.Time, clearRestricted bool) (bool, error) {
	tag, err := t.tx.Exec(t.ctx, qSessionRotate, t.tenant, id, newHash, idleExpiresAt, string(reauth), clearRestricted, now)
	if err != nil {
		return false, sanitize(err)
	}
	if tag.RowsAffected() != 1 {
		return false, nil
	}
	if _, err := t.tx.Exec(t.ctx, qSessionRotateRefresh, t.tenant, id); err != nil {
		return false, sanitize(err)
	}
	return true, nil
}

const qSessionReauthClear = `UPDATE ctrlz.sessions SET reauth_at = NULL
WHERE tenant_id = $1 AND user_id = $2 AND id = $3 AND revoked_at IS NULL`

// SessionReauthClear ends the reauth window of one session of the user without touching its
// token. A route that has just set the passkey review calls it, so that a window obtained by
// passkey reauth before the event cannot clear the review that only a proof other than a
// passkey may clear (7.7, review round 5, tenant-r5-4).
func (t Tx) SessionReauthClear(user, id uuid.UUID) error {
	_, err := t.tx.Exec(t.ctx, qSessionReauthClear, t.tenant, user, id)
	return sanitize(err)
}

const qSessionRefreshToken = `UPDATE ctrlz.sessions
SET token_hash = $3, idle_expires_at = $4, last_seen_at = $5, reauth_at = NULL
WHERE tenant_id = $1 AND id = $2 AND revoked_at IS NULL AND absolute_expires_at > $5`

// SessionRefreshToken is the session half of POST /auth/refresh (3.4): a new
// token and a fresh idle limit, and no reauth window. It does not revoke the
// refresh tokens, because the one in use must survive its 10 second grace. now is
// the application clock.
func (t Tx) SessionRefreshToken(id uuid.UUID, newHash []byte, idleExpiresAt, now time.Time) (bool, error) {
	tag, err := t.tx.Exec(t.ctx, qSessionRefreshToken, t.tenant, id, newHash, idleExpiresAt, now)
	if err != nil {
		return false, sanitize(err)
	}
	return tag.RowsAffected() == 1, nil
}

const qSessionRevoke = `UPDATE ctrlz.sessions SET revoked_at = now() WHERE tenant_id = $1 AND user_id = $2 AND id = $3 AND revoked_at IS NULL`
const qSessionRevokeRefresh = `UPDATE ctrlz.refresh_tokens SET revoked_at = now()
WHERE tenant_id = $1 AND revoked_at IS NULL AND id = ANY (ARRAY(SELECT id FROM ctrlz.refresh_tokens WHERE tenant_id = $1 AND session_id = $2 AND revoked_at IS NULL` + orderedUpdate + `))`

// SessionRevoke ends one session of the user, with its refresh tokens. false for
// a session that is not the user's, already revoked or unknown.
func (t Tx) SessionRevoke(user, id uuid.UUID) (bool, error) {
	tag, err := t.tx.Exec(t.ctx, qSessionRevoke, t.tenant, user, id)
	if err != nil {
		return false, sanitize(err)
	}
	if tag.RowsAffected() != 1 {
		return false, nil
	}
	if _, err := t.tx.Exec(t.ctx, qSessionRevokeRefresh, t.tenant, id); err != nil {
		return false, sanitize(err)
	}
	return true, nil
}

// The count of live sessions (application clock) and the revocation (a stamp of the
// database clock) are two statements, because one does not read two clocks. Both run
// under the user row lock of the caller, so the number can differ from what the
// revocation ends only by a session that expires between them, which the response
// does not promise to the second.
const qSessionsLiveOthers = `SELECT count(*) FROM ctrlz.sessions
WHERE tenant_id = $1 AND user_id = $2 AND id <> $3 AND revoked_at IS NULL AND idle_expires_at > $4 AND absolute_expires_at > $4`
const qSessionsRevokeOthers = `UPDATE ctrlz.sessions SET revoked_at = now()
WHERE tenant_id = $1 AND revoked_at IS NULL AND id = ANY (ARRAY(SELECT id FROM ctrlz.sessions WHERE tenant_id = $1 AND user_id = $2 AND id <> $3 AND revoked_at IS NULL` + orderedUpdate + `))`
const qRefreshRevokeOthers = `UPDATE ctrlz.refresh_tokens SET revoked_at = now()
WHERE tenant_id = $1 AND revoked_at IS NULL AND id = ANY (ARRAY(SELECT id FROM ctrlz.refresh_tokens WHERE tenant_id = $1 AND user_id = $2 AND session_id <> $3 AND revoked_at IS NULL` + orderedUpdate + `))`

// SessionsRevokeOthers ends every session of the user except keep, with their
// refresh tokens, and returns how many live ones that was (the ended_sessions
// of the response) at the application time now. Pass the nil uuid to end all of
// them, the current one included (log out all).
func (t Tx) SessionsRevokeOthers(user, keep uuid.UUID, now time.Time) (int, error) {
	var n int
	if err := t.tx.QueryRow(t.ctx, qSessionsLiveOthers, t.tenant, user, keep, now).Scan(&n); err != nil {
		return 0, sanitize(err)
	}
	if _, err := t.tx.Exec(t.ctx, qSessionsRevokeOthers, t.tenant, user, keep); err != nil {
		return 0, sanitize(err)
	}
	if _, err := t.tx.Exec(t.ctx, qRefreshRevokeOthers, t.tenant, user, keep); err != nil {
		return 0, sanitize(err)
	}
	return n, nil
}

// qSessionsLiveFilter is what makes a session live: not revoked and inside both expiries on the application
// clock $4 (the clock of every session time, qSessionsList).
const qSessionsLiveFilter = `tenant_id = $1 AND user_id = $2 AND revoked_at IS NULL AND absolute_expires_at > $4 AND idle_expires_at > $4`

// qSessionsTrimPick chooses the live sessions of one user that are not among the newest $3 (created_at, then id, newest
// first), on the application clock $4. It only reads: a statement reads one clock, and the revocation stamps the
// database clock (the same two statements as SessionsRevokeOthers, qSessionsLiveOthers and qSessionsRevokeOthers).
const qSessionsTrimPick = `SELECT id FROM ctrlz.sessions WHERE ` + qSessionsLiveFilter + `
  AND id NOT IN (SELECT id FROM ctrlz.sessions WHERE ` + qSessionsLiveFilter + ` ORDER BY created_at DESC, id DESC LIMIT $3)
ORDER BY id`

// qSessionsTrim ends the picked sessions, locking the rows in key order like every multi-row write (rule lock-order),
// and gives back the ids it ended so that their refresh tokens end in the next statement (sessions, then refresh
// tokens, in rank order).
const qSessionsTrim = `UPDATE ctrlz.sessions SET revoked_at = now()
WHERE tenant_id = $1 AND revoked_at IS NULL AND id = ANY (ARRAY(SELECT id FROM ctrlz.sessions WHERE tenant_id = $1 AND id = ANY ($2::uuid[]) AND revoked_at IS NULL` + orderedUpdate + `))
RETURNING id`
const qSessionsTrimRefresh = `UPDATE ctrlz.refresh_tokens SET revoked_at = now()
WHERE tenant_id = $1 AND revoked_at IS NULL AND id = ANY (ARRAY(SELECT id FROM ctrlz.refresh_tokens WHERE tenant_id = $1 AND session_id = ANY ($2::uuid[]) AND revoked_at IS NULL` + orderedUpdate + `))`

// sessionIDs reads the rows of a statement that returns session ids, one per row. The statement is a constant at the
// call (the SQL lint reads it there), so the rows come in and not the text.
func sessionIDs(rows pgx.Rows, err error) ([]uuid.UUID, error) {
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, sanitize(err)
		}
		out = append(out, id)
	}
	return out, sanitize(rows.Err())
}

// SessionsTrim is the cap on live sessions per account (tenant-r18-2, D64 session-cap; caps.MaxSessions): it
// keeps the newest keep live sessions of the user and ends every older one, with its refresh tokens, and returns
// the ids it ended. It ends the OLDEST and never refuses the new login: refusing at the cap would let a holder of
// the password lock the owner out of the front door, while the oldest session is the one the owner is least
// likely to be using. The user row lock is taken here, so two logins of one user trim one after the other (the
// second counts the first's commit), and the caller needs no lock of its own. Call it after the new session is
// inserted, so the new one is among the newest and the order of writes stays sessions, then refresh tokens.
func (t Tx) SessionsTrim(user uuid.UUID, keep int, now time.Time) ([]uuid.UUID, error) {
	if keep < 1 {
		return nil, ErrConstraint // trimming to nothing would end the session being opened
	}
	if _, ok, err := t.UserLock(user); err != nil || !ok {
		return nil, err
	}
	picked, err := sessionIDs(t.tx.Query(t.ctx, qSessionsTrimPick, t.tenant, user, int32(keep), now))
	if err != nil || len(picked) == 0 {
		return nil, err
	}
	ended, err := sessionIDs(t.tx.Query(t.ctx, qSessionsTrim, t.tenant, picked))
	if err != nil || len(ended) == 0 {
		return nil, err
	}
	if _, err := t.tx.Exec(t.ctx, qSessionsTrimRefresh, t.tenant, ended); err != nil {
		return nil, sanitize(err)
	}
	return ended, nil
}

const qAPITokensRevoke = `UPDATE ctrlz.api_tokens SET revoked_at = now()
WHERE tenant_id = $1 AND revoked_at IS NULL AND id = ANY (ARRAY(SELECT id FROM ctrlz.api_tokens WHERE tenant_id = $1 AND user_id = $2 AND revoked_at IS NULL` + orderedUpdate + `))`

// APITokensRevoke revokes the user's API tokens (a password or phone change
// does, R44). It returns how many it revoked.
func (t Tx) APITokensRevoke(user uuid.UUID) (int, error) {
	tag, err := t.tx.Exec(t.ctx, qAPITokensRevoke, t.tenant, user)
	if err != nil {
		return 0, sanitize(err)
	}
	return int(tag.RowsAffected()), nil
}

// ---------------------------------------------------------------------------
// Refresh tokens

// NewRefresh is the input of RefreshCreate.
type NewRefresh struct {
	SessionID uuid.UUID
	UserID    uuid.UUID
	FamilyID  uuid.UUID
	TokenHash []byte
	ExpiresAt time.Time
}

const qRefreshCreate = `INSERT INTO ctrlz.refresh_tokens (tenant_id, user_id, session_id, family_id, token_hash, expires_at)
VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`

// RefreshCreate inserts a refresh token. A new login uses a new family id; a
// rotation keeps the family.
func (t Tx) RefreshCreate(r NewRefresh) (uuid.UUID, error) {
	var id uuid.UUID
	err := t.tx.QueryRow(t.ctx, qRefreshCreate, t.tenant, r.UserID, r.SessionID, r.FamilyID, r.TokenHash, r.ExpiresAt).Scan(&id)
	return id, sanitize(err)
}

const qRefreshRotate = `UPDATE ctrlz.refresh_tokens SET rotated_at = $4, reuse_grace_until = $3
WHERE tenant_id = $1 AND id = $2 AND rotated_at IS NULL AND revoked_at IS NULL`

// RefreshRotate marks a refresh token used and opens its reuse grace. Zero rows
// (false) means it was rotated already: the caller decides between a concurrent
// tab (inside the grace) and reuse (past it), per 3.4. now is the application clock,
// which graceUntil is measured on.
func (t Tx) RefreshRotate(id uuid.UUID, graceUntil, now time.Time) (bool, error) {
	tag, err := t.tx.Exec(t.ctx, qRefreshRotate, t.tenant, id, graceUntil, now)
	if err != nil {
		return false, sanitize(err)
	}
	return tag.RowsAffected() == 1, nil
}

const qRefreshRevoked = `SELECT revoked_at IS NOT NULL FROM ctrlz.refresh_tokens WHERE tenant_id = $1 AND id = $2`

// RefreshRevoked reports whether the refresh token has been revoked. A rotate
// that matched no row uses it to tell a token that a reauth or log out all ended
// (the client must sign in again) from one a concurrent tab rotated (the client
// retries with the new cookies). A missing row counts as revoked.
func (t Tx) RefreshRevoked(id uuid.UUID) (bool, error) {
	var revoked bool
	err := t.tx.QueryRow(t.ctx, qRefreshRevoked, t.tenant, id).Scan(&revoked)
	found, err := notFound(err)
	return !found || revoked, err
}

const qRefreshRevokeFamily = `UPDATE ctrlz.refresh_tokens SET revoked_at = now()
WHERE tenant_id = $1 AND revoked_at IS NULL AND id = ANY (ARRAY(SELECT id FROM ctrlz.refresh_tokens WHERE tenant_id = $1 AND family_id = $2 AND revoked_at IS NULL` + orderedUpdate + `))`
const qRefreshRevokeFamilySession = `UPDATE ctrlz.sessions SET revoked_at = now()
WHERE tenant_id = $1 AND revoked_at IS NULL AND id = ANY (ARRAY(SELECT id FROM ctrlz.sessions WHERE tenant_id = $1 AND revoked_at IS NULL
     AND id IN (SELECT session_id FROM ctrlz.refresh_tokens WHERE tenant_id = $1 AND family_id = $2)` + orderedUpdate + `))`

// RefreshRevokeFamily is the answer to reuse of a refresh token: the whole
// family and its session end.
func (t Tx) RefreshRevokeFamily(family uuid.UUID) error {
	if _, err := t.tx.Exec(t.ctx, qRefreshRevokeFamilySession, t.tenant, family); err != nil {
		return sanitize(err)
	}
	_, err := t.tx.Exec(t.ctx, qRefreshRevokeFamily, t.tenant, family)
	return sanitize(err)
}

// ---------------------------------------------------------------------------
// Passkeys

// Credential is a passkey row without the credential id's secrecy needs: the
// public key is public by design.
type Credential struct {
	ID              uuid.UUID
	UserID          uuid.UUID
	CredentialID    []byte
	PublicKey       []byte
	SignCount       int64
	Transports      []string
	Name            string
	RPID            string
	StaleAt         *time.Time
	LastUsedAt      *time.Time
	CreatedAt       time.Time
	AAGUID          *uuid.UUID
	AttestationType string
	BackupEligible  bool
	BackupState     bool
}

const credentialColumns = `id, user_id, credential_id, public_key, sign_count, transports, name, rp_id, stale_at, last_used_at,
  created_at, aaguid, attestation_type, backup_eligible, backup_state`

func scanCredential(r pgx.Row) (c Credential, err error) {
	err = r.Scan(&c.ID, &c.UserID, &c.CredentialID, &c.PublicKey, &c.SignCount, &c.Transports, &c.Name, &c.RPID, &c.StaleAt,
		&c.LastUsedAt, &c.CreatedAt, &c.AAGUID, &c.AttestationType, &c.BackupEligible, &c.BackupState)
	return c, err
}

const qPasskeysList = `SELECT ` + credentialColumns + ` FROM ctrlz.webauthn_credentials
WHERE tenant_id = $1 AND user_id = $2 ORDER BY created_at, id`

// PasskeysList returns all of the user's passkeys, stale ones included (they
// stay listed so the user can delete them, 7.4).
func (t Tx) PasskeysList(user uuid.UUID) ([]Credential, error) {
	rows, err := t.tx.Query(t.ctx, qPasskeysList, t.tenant, user)
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []Credential
	for rows.Next() {
		c, err := scanCredential(rows)
		if err != nil {
			return nil, sanitize(err)
		}
		out = append(out, c)
	}
	return out, sanitize(rows.Err())
}

const qPasskeyLiveCount = `SELECT count(*) FROM ctrlz.webauthn_credentials
WHERE tenant_id = $1 AND user_id = $2 AND stale_at IS NULL AND rp_id = $3`

// PasskeyLiveCount counts the credentials that work against the current RP ID
// (5.7).
func (t Tx) PasskeyLiveCount(user uuid.UUID, rpID string) (int, error) {
	var n int
	if err := t.tx.QueryRow(t.ctx, qPasskeyLiveCount, t.tenant, user, rpID).Scan(&n); err != nil {
		return 0, sanitize(err)
	}
	return n, nil
}

// The cap is part of the INSERT: the row is written only when the user holds fewer than
// $13 credentials, and the name defaults to the next number in the same statement, so a
// count read earlier cannot be stale. The statement is not enough alone: under READ
// COMMITTED two of them that start together both count 19. PasskeyAdd takes the user's
// row lock in an earlier statement, so the count of the second is taken after the first
// has committed (a statement's snapshot is taken when it starts, after the lock wait).
const qPasskeyAdd = `INSERT INTO ctrlz.webauthn_credentials
  (tenant_id, user_id, credential_id, public_key, sign_count, transports, name, rp_id, aaguid, attestation_type, backup_eligible, backup_state)
SELECT $1::uuid, $2::uuid, $3::bytea, $4::bytea, $5::bigint, $6::text[], COALESCE(NULLIF($7::text, ''), 'Passkey ' || (n.count + 1)), $8::text, $9::uuid, $10::text, $11::boolean, $12::boolean
FROM (SELECT count(*) AS count FROM ctrlz.webauthn_credentials WHERE tenant_id = $1 AND user_id = $2) n
WHERE NOT ctrlz.cap_reached(n.count, $13::int)
RETURNING id, name`

const qPasskeyRoom = `SELECT NOT ctrlz.cap_reached(count(*), $3::int) FROM ctrlz.webauthn_credentials WHERE tenant_id = $1 AND user_id = $2`

// PasskeyAdd stores a new credential unless the user already holds limit of them
// (caps.MaxPasskeys). A loss is the cap; the credential is not written, and the
// returned id and name are empty. An empty c.Name becomes "Passkey N". A credential id
// that already exists (in any tenant) is ErrConflict. A user that is not in the tenant
// is a loss as well. The user row lock is taken here and not left to the caller, so no
// caller can forget it.
func (t Tx) PasskeyAdd(c Credential, limit int) (id uuid.UUID, name string, _ Won, _ error) {
	if _, ok, err := t.UserLock(c.UserID); err != nil || !ok {
		return uuid.Nil, "", Won{}, err
	}
	transports := c.Transports
	if transports == nil {
		transports = []string{}
	}
	att := c.AttestationType
	if att == "" {
		att = "none"
	}
	w, err := wonRow(t.tx.QueryRow(t.ctx, qPasskeyAdd, t.tenant, c.UserID, c.CredentialID, c.PublicKey, c.SignCount, transports,
		c.Name, c.RPID, c.AAGUID, att, c.BackupEligible, c.BackupState, int32(limit)).Scan(&id, &name))
	if err != nil || !w.Yes() {
		return uuid.Nil, "", Won{}, err
	}
	return id, name, w, nil
}

// PasskeyHasRoom says whether the user could add one more credential under limit. It is
// advice for the begin of a ceremony, which answers early what PasskeyAdd decides at the
// end; it permits nothing, and it compares with the same expression as the INSERT.
func (t Tx) PasskeyHasRoom(user uuid.UUID, limit int) (bool, error) {
	var room bool
	err := t.tx.QueryRow(t.ctx, qPasskeyRoom, t.tenant, user, int32(limit)).Scan(&room)
	return room, sanitize(err)
}

const qPasskeyRename = `UPDATE ctrlz.webauthn_credentials SET name = $4 WHERE tenant_id = $1 AND user_id = $2 AND id = $3`

// PasskeyRename renames a passkey of the user; false when it is not theirs.
func (t Tx) PasskeyRename(user, id uuid.UUID, name string) (bool, error) {
	tag, err := t.tx.Exec(t.ctx, qPasskeyRename, t.tenant, user, id, name)
	if err != nil {
		return false, sanitize(err)
	}
	return tag.RowsAffected() == 1, nil
}

const qPasskeyDelete = `DELETE FROM ctrlz.webauthn_credentials WHERE tenant_id = $1 AND user_id = $2 AND id = $3`

// PasskeyDelete removes a passkey of the user; false when it is not theirs.
func (t Tx) PasskeyDelete(user, id uuid.UUID) (bool, error) {
	tag, err := t.tx.Exec(t.ctx, qPasskeyDelete, t.tenant, user, id)
	if err != nil {
		return false, sanitize(err)
	}
	return tag.RowsAffected() == 1, nil
}

const qPasskeyUsed = `UPDATE ctrlz.webauthn_credentials
SET sign_count = $4, backup_state = $5, last_used_at = now()
WHERE tenant_id = $1 AND user_id = $2 AND id = $3 AND ((sign_count = 0 AND $4 = 0) OR $4 > sign_count)`

// PasskeyUsed records a successful assertion. The counter rule of 7.5 is in the
// WHERE clause, so it is atomic: a stored count above zero needs a higher new
// one, and a synced passkey that always reports zero passes. Zero rows (false)
// is a refusal: the credential is not the user's, or the counter did not
// advance, which the caller records as passkey.clone_suspect.
func (t Tx) PasskeyUsed(user, id uuid.UUID, signCount int64, backupState bool) (bool, error) {
	tag, err := t.tx.Exec(t.ctx, qPasskeyUsed, t.tenant, user, id, signCount, backupState)
	if err != nil {
		return false, sanitize(err)
	}
	return tag.RowsAffected() == 1, nil
}

// ---------------------------------------------------------------------------
// Phone change

// PhoneChange is a pending phone change request.
type PhoneChange struct {
	ID          uuid.UUID
	UserID      uuid.UUID
	NewPhone    string
	OldOTP      uuid.UUID
	NewOTP      uuid.UUID
	CompletedAt *time.Time
}

const qPhoneChangeCreate = `INSERT INTO ctrlz.phone_change_requests (tenant_id, user_id, new_phone_e164, old_otp_id, new_otp_id, expires_at)
VALUES ($1, $2, $3, $4, $5, now() + make_interval(secs => $6)) RETURNING id`

// PhoneChangeCreate records a request with both challenge ids. life is how long it
// lives (five minutes, the life of the two OTPs; the table caps it at 15). The
// database stamps the expiry, because auth_phone_change_complete compares it with the
// database clock (clocks.yaml, db).
func (t Tx) PhoneChangeCreate(user uuid.UUID, newPhone string, oldOTP, newOTP uuid.UUID, life time.Duration) (uuid.UUID, error) {
	var id uuid.UUID
	err := t.tx.QueryRow(t.ctx, qPhoneChangeCreate, t.tenant, user, newPhone, oldOTP, newOTP, life.Seconds()).Scan(&id)
	return id, sanitize(err)
}

const qPhoneChangeGet = `SELECT id, user_id, new_phone_e164, old_otp_id, new_otp_id, completed_at
FROM ctrlz.phone_change_requests WHERE tenant_id = $1 AND user_id = $2 AND id = $3`

// PhoneChangeGet reads a request of the user. A request of another user or
// tenant is not found.
func (t Tx) PhoneChangeGet(user, id uuid.UUID) (PhoneChange, bool, error) {
	var p PhoneChange
	err := t.tx.QueryRow(t.ctx, qPhoneChangeGet, t.tenant, user, id).Scan(&p.ID, &p.UserID, &p.NewPhone, &p.OldOTP, &p.NewOTP,
		&p.CompletedAt)
	ok, err := notFound(err)
	return p, ok, err
}

// ---------------------------------------------------------------------------
// Notifications and announcements

// Notification is a row of the bell.
type Notification struct {
	ID        uuid.UUID
	Kind      string
	Severity  string
	Params    []byte // jsonb
	Link      string
	ReadAt    *time.Time
	CreatedAt time.Time
}

const qNotificationAdd = `INSERT INTO ctrlz.notifications (tenant_id, kind, severity, params) VALUES ($1, $2, $3, $4)`

// NotificationAdd writes a notice in the transaction that changes the thing it
// reports (a credential event, a stale passkey). params is JSON. It returns no
// id: the worker holds INSERT on the table without SELECT, and RETURNING needs it.
func (t Tx) NotificationAdd(kind, severity string, params []byte) error {
	if params == nil {
		params = []byte("{}")
	}
	_, err := t.tx.Exec(t.ctx, qNotificationAdd, t.tenant, kind, severity, params)
	return sanitize(err)
}

// Cursor is the sort key of the last row of a page: the caller encodes it as
// opaque base64url. The zero value starts at the newest row.
type Cursor struct {
	At time.Time
	ID uuid.UUID
}

func (c Cursor) args() (any, any) {
	if c.At.IsZero() {
		return nil, nil
	}
	return c.At, c.ID
}

const qNotificationsPage = `SELECT id, kind, severity, params, COALESCE(link, ''), read_at, created_at
FROM ctrlz.notifications
WHERE tenant_id = $1 AND ($2::timestamptz IS NULL OR (created_at, id) < ($2::timestamptz, $3::uuid))
ORDER BY created_at DESC, id DESC LIMIT $4`

// NotificationsPage returns up to limit notices, newest first, after the cursor.
func (t Tx) NotificationsPage(after Cursor, limit int) ([]Notification, error) {
	at, id := after.args()
	rows, err := t.tx.Query(t.ctx, qNotificationsPage, t.tenant, at, id, int32(limit))
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []Notification
	for rows.Next() {
		var n Notification
		if err := rows.Scan(&n.ID, &n.Kind, &n.Severity, &n.Params, &n.Link, &n.ReadAt, &n.CreatedAt); err != nil {
			return nil, sanitize(err)
		}
		out = append(out, n)
	}
	return out, sanitize(rows.Err())
}

const qNotificationsUnread = `SELECT count(*) FROM ctrlz.notifications WHERE tenant_id = $1 AND read_at IS NULL`

// NotificationsUnread counts unread notices over all rows, not one page.
func (t Tx) NotificationsUnread() (int, error) {
	var n int
	if err := t.tx.QueryRow(t.ctx, qNotificationsUnread, t.tenant).Scan(&n); err != nil {
		return 0, sanitize(err)
	}
	return n, nil
}

const qNotificationRead = `UPDATE ctrlz.notifications SET read_at = COALESCE(read_at, now()) WHERE tenant_id = $1 AND id = $2`

// NotificationRead marks a notice read; false when it is not the tenant's.
func (t Tx) NotificationRead(id uuid.UUID) (bool, error) {
	tag, err := t.tx.Exec(t.ctx, qNotificationRead, t.tenant, id)
	if err != nil {
		return false, sanitize(err)
	}
	return tag.RowsAffected() == 1, nil
}

// AnnouncementItem is an announcement with the user's read flag.
type AnnouncementItem struct {
	Announcement
	Read bool
}

const qAnnouncementsFor = `SELECT a.id, a.audience, a.body, a.starts_at, a.ends_at, (r.announcement_id IS NOT NULL)
FROM ctrlz_fn.announcements_for_tenant() a
LEFT JOIN ctrlz.announcement_reads r ON r.tenant_id = $1 AND r.user_id = $2 AND r.announcement_id = a.id
ORDER BY a.starts_at DESC, a.id DESC`

// AnnouncementsFor lists the live announcements addressed to the tenant, with
// whether this user has read each. The function is the only way the role reaches
// the table, and it returns the tenant's own and the general ones.
func (t Tx) AnnouncementsFor(user uuid.UUID) ([]AnnouncementItem, error) {
	rows, err := t.tx.Query(t.ctx, qAnnouncementsFor, t.tenant, user)
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []AnnouncementItem
	for rows.Next() {
		var a AnnouncementItem
		if err := rows.Scan(&a.ID, &a.Audience, &a.Body, &a.StartsAt, &a.EndsAt, &a.Read); err != nil {
			return nil, sanitize(err)
		}
		out = append(out, a)
	}
	return out, sanitize(rows.Err())
}

const qAnnouncementVisible = `SELECT 1 FROM ctrlz_fn.announcements_for_tenant() WHERE id = $1`
const qAnnouncementRead = `INSERT INTO ctrlz.announcement_reads (tenant_id, announcement_id, user_id) VALUES ($1, $2, $3)
ON CONFLICT DO NOTHING`

// AnnouncementRead marks an announcement read by the user. false when the
// announcement is not live for this tenant (someone else's notice included).
func (t Tx) AnnouncementRead(user, announcement uuid.UUID) (bool, error) {
	var one int
	if ok, err := notFound(t.tx.QueryRow(t.ctx, qAnnouncementVisible, announcement).Scan(&one)); err != nil || !ok {
		return false, err
	}
	if _, err := t.tx.Exec(t.ctx, qAnnouncementRead, t.tenant, announcement, user); err != nil {
		return false, sanitize(err)
	}
	return true, nil
}

// ---------------------------------------------------------------------------
// Tenant audit log

// TenantAudit is a row for tenant_audit_log. Params is JSON built by
// internal/auth/audit from a typed struct, which keeps secrets out (13.3).
type TenantAudit struct {
	UserID uuid.UUID // the nil uuid for none
	Action string
	Target string
	Params []byte
	IP     netip.Addr
}

const qTenantAuditAdd = `INSERT INTO ctrlz.tenant_audit_log (tenant_id, user_id, action, target, params, ip)
VALUES ($1, $2, $3, $4, $5, $6)`

// AuditAdd writes an audit row in the transaction of the change it records.
func (t Tx) AuditAdd(e TenantAudit) error {
	params := e.Params
	if params == nil {
		params = []byte("{}")
	}
	_, err := t.tx.Exec(t.ctx, qTenantAuditAdd, t.tenant, nilUUID(e.UserID), e.Action, emptyNull(e.Target), params, addrArg(e.IP))
	return sanitize(err)
}

// ---------------------------------------------------------------------------
// Tenant settings

const qHomeCountries = `SELECT home_countries::text[] FROM ctrlz.tenants WHERE id = $1`

// HomeCountries reads the tenant's home countries.
func (t Tx) HomeCountries() ([]string, error) {
	var out []string
	if err := t.tx.QueryRow(t.ctx, qHomeCountries, t.tenant).Scan(&out); err != nil {
		return nil, sanitize(err)
	}
	return out, nil
}

const qSetHomeCountries = `UPDATE ctrlz.tenants SET home_countries = $2::text[]::char(2)[] WHERE id = $1`

// SetHomeCountries stores up to three ISO 3166-1 alpha-2 codes (a CHECK
// enforces the count).
func (t Tx) SetHomeCountries(codes []string) error {
	if codes == nil {
		codes = []string{}
	}
	_, err := t.tx.Exec(t.ctx, qSetHomeCountries, t.tenant, codes)
	return sanitize(err)
}

const qTenantStatus = `SELECT status FROM ctrlz.tenants WHERE id = $1`

// TenantStatus reads the tenant's status (active, suspended or deleting).
func (t Tx) TenantStatus() (string, error) {
	var s string
	if err := t.tx.QueryRow(t.ctx, qTenantStatus, t.tenant).Scan(&s); err != nil {
		return "", sanitize(err)
	}
	return s, nil
}

// Limits is one value per limit column of plans: the tenant's own override in tenant_entitlements
// where it has one, the value of its plan otherwise (D56, spec P3 2.4).
type Limits struct {
	MaxProfiles            int
	MaxEndpoints           int
	MaxClientsPerEndpoint  int
	MaxAuthorizedIPs       int
	MaxAPITokens           int
	MaxRulesPerRequest     int
	MaxRulesPerProfile     int
	MaxWildcardsPerProfile int
	MaxRealtimeSessions    int
	MaxPublishesPerHour    int
	MaxIPClaims            int
}

const qLimits = `SELECT max_profiles, max_endpoints, max_clients_per_endpoint, max_authorized_ips, max_api_tokens, max_rules_per_request,
  max_rules_per_profile, max_wildcards_per_profile, max_realtime_sessions, max_publishes_per_hour, max_ip_claims
FROM ctrlz_fn.tenant_plan()`

// Limits reads the tenant's effective quotas. ctrlz_fn.tenant_plan() applies the order: the tenant's own
// value, then its plan's.
func (t Tx) Limits() (Limits, error) {
	var l Limits
	err := t.tx.QueryRow(t.ctx, qLimits).Scan(&l.MaxProfiles, &l.MaxEndpoints, &l.MaxClientsPerEndpoint,
		&l.MaxAuthorizedIPs, &l.MaxAPITokens, &l.MaxRulesPerRequest, &l.MaxRulesPerProfile, &l.MaxWildcardsPerProfile,
		&l.MaxRealtimeSessions, &l.MaxPublishesPerHour, &l.MaxIPClaims)
	return l, sanitize(err)
}

const qTOTPSeedCT = `SELECT totp_secret_ct FROM ctrlz_fn.auth_totp_seed($1, $2)`

// TOTPSeedCT reads the user's sealed TOTP seed inside the transaction, through
// the same function the login path uses (the tenant role cannot select the
// column). Reading it under the row lock a route already holds means the seed
// that a code is checked against is the one the transaction then enables or
// spends a step on: a second setup call cannot swap it in between. found is
// false when the user has no seed.
func (t Tx) TOTPSeedCT(id uuid.UUID) ([]byte, bool, error) {
	var ct []byte
	err := t.tx.QueryRow(t.ctx, qTOTPSeedCT, id, t.tenant).Scan(&ct)
	ok, err := notFound(err)
	return ct, ok && ct != nil, err
}

const qRecoveryLive = `SELECT EXISTS (SELECT 1 FROM ctrlz.recovery_codes
WHERE tenant_id = $1 AND user_id = $2 AND code_hash = $3 AND used_at IS NULL)`

// RecoveryCodeLive reports whether the hash is an unused recovery code of the user, without
// spending it. It is a look, never the decision: RecoveryCodeUse is. A route uses it to refuse a
// caller who holds no live code before it does heavy work (tenant-r5-6).
func (t Tx) RecoveryCodeLive(user uuid.UUID, hash []byte) (bool, error) {
	var live bool
	if err := t.tx.QueryRow(t.ctx, qRecoveryLive, t.tenant, user, hash).Scan(&live); err != nil {
		return false, sanitize(err)
	}
	return live, nil
}
