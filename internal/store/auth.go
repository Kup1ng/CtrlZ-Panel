package store

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/credstate"
	"github.com/Kup1ng/CtrlZ-Panel/internal/credgen"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
)

// AuthLookups are the calls that must work before the tenant is known: login,
// session and token checks, invites, passkeys, share links. Each method calls
// exactly one SECURITY DEFINER function in ctrlz_fn and nothing else, which
// is how the allow-list (R3) stays the complete list of what can read across
// tenants. They run outside WithTenant, as single statements.
//
// Hashes are SHA-256 of a high-entropy token. A method returns found=false for
// an unknown key, and never says why a key did not match.
type AuthLookups struct{ s *Store }

// Auth returns the lookups.
func (s *Store) Auth() AuthLookups { return AuthLookups{s: s} }

// one runs a query that returns at most one row on a connection of its own.
//
// It refuses a context that belongs to an open transaction (ErrNested), before it asks
// the pool for anything. A request holds at most one connection at any moment (rule
// one-connection-per-request): a call made while a transaction is open would hold the
// transaction's connection and ask for a second, and N requests on a pool of N would wait
// for each other. The earlier answer was a second pool for these calls, which doubled
// every role's connection footprint. What must happen during a transaction is a method
// of Tx or GlobalTx instead, and a throttle hit, which must outlive a rollback, is made
// before the transaction opens.
func one[T any](ctx context.Context, s *Store, sql string, scan func(pgx.Row) (T, error), args ...any) (T, bool, error) {
	if ctx.Value(txMarker{}) != nil || scopeBusy(ctx) { // the marker sees the chain, the scope sees the request (scope.go)
		var zero T
		return zero, false, ErrNested
	}
	// The deadline covers the wait for a connection and the single-row query: an
	// exhausted pool answers in the connect timeout, not when the client leaves.
	s.asked.Add(1)
	qctx, release := s.acquireCtx(ctx)
	defer release()
	v, err := scan(s.pool.QueryRow(qctx, sql, args...)) // lint:sql-const callers of one pass constants
	if err != nil {
		var zero T
		if errors.Is(err, pgx.ErrNoRows) {
			return zero, false, nil
		}
		return zero, false, sanitize(err)
	}
	return v, true, nil
}

// UserLogin is the result of UserByPhone. PasswordHash is a secret.String, so a
// %+v of the struct prints the marker and not the hash. The zero value (no
// password) is an OTP-only account.
type UserLogin struct {
	TenantID       uuid.UUID
	UserID         uuid.UUID
	PasswordHash   secret.String
	TenantStatus   string
	TOTPEnabled    bool
	EnforcePasskey bool
	EnforceLiftAt  *time.Time // set while a lost passkey's Enforce delay runs (4.4)
	// State is the one-time credential state on the database clock (internal/auth/credstate,
	// rule one-time-state). A login asks the table what it may do with it; nobody reads
	// the columns it is made of.
	State credstate.State
	// Cred is the generation of the credentials this row had when it was read, with the
	// subject. A login that verifies the password outside any transaction hands it to
	// Tx.UserLockFor, which refuses the session if any credential moved since (spec 5.7;
	// internal/credgen). It replaces the field-by-field comparison of earlier rounds.
	Cred credgen.Stamp
}

const qUserByPhone = `SELECT tenant_id, user_id, password_hash, status, totp_enabled, enforce_passkey,
  enforce_lift_at, cred_state, credential_gen
FROM ctrlz_fn.auth_user_by_phone($1)`

// UserByPhone finds a user for login by E.164 phone number.
func (a AuthLookups) UserByPhone(ctx context.Context, phone string) (UserLogin, bool, error) {
	return one(ctx, a.s, qUserByPhone, func(r pgx.Row) (u UserLogin, err error) {
		var hash *string // NULL until the user sets a password (OTP-only account)
		var state string
		err = r.Scan(&u.TenantID, &u.UserID, &hash, &u.TenantStatus, &u.TOTPEnabled, &u.EnforcePasskey,
			&u.EnforceLiftAt, &state, &u.Cred.Gen)
		if err != nil {
			return u, err
		}
		if hash != nil {
			u.PasswordHash = secret.New(*hash)
		}
		u.Cred.Tenant, u.Cred.Subject = u.TenantID, u.UserID
		u.State, err = credstate.Parse(state)
		return u, err
	}, phone)
}

// SessionInfo is the result of SessionByHash.
type SessionInfo struct {
	TenantID          uuid.UUID
	UserID            uuid.UUID
	SessionID         uuid.UUID
	TenantStatus      string
	IdleExpiresAt     time.Time
	AbsoluteExpiresAt time.Time
	RevokedAt         *time.Time
	// State is the user's credential state now, not a flag written when the session began:
	// the gates of 3.5 ask the table of internal/auth/credstate with it.
	State    credstate.State
	ReauthAt *time.Time // start of the reauth window, nil when there is none
}

const qSessionByHash = `SELECT tenant_id, user_id, session_id, status, idle_expires_at, absolute_expires_at, revoked_at, reauth_at, cred_state
FROM ctrlz_fn.auth_session_by_hash($1)`

// SessionByHash finds a session by the SHA-256 of its cookie value.
func (a AuthLookups) SessionByHash(ctx context.Context, hash []byte) (SessionInfo, bool, error) {
	return one(ctx, a.s, qSessionByHash, func(r pgx.Row) (v SessionInfo, err error) {
		var state string
		err = r.Scan(&v.TenantID, &v.UserID, &v.SessionID, &v.TenantStatus, &v.IdleExpiresAt, &v.AbsoluteExpiresAt, &v.RevokedAt, &v.ReauthAt, &state)
		if err != nil {
			return v, err
		}
		v.State, err = credstate.Parse(state)
		return v, err
	}, hash)
}

// TokenInfo is the result of TokenByHash.
type TokenInfo struct {
	TenantID     uuid.UUID
	UserID       uuid.UUID
	TokenID      uuid.UUID
	Kind         string // "read" or "write"
	AllowedIPs   []netip.Prefix
	TenantStatus string
	RevokedAt    *time.Time
}

const qTokenByHash = `SELECT tenant_id, user_id, token_id, kind, allowed_ips, status, revoked_at
FROM ctrlz_fn.auth_token_by_hash($1)`

// TokenByHash finds an API token by the SHA-256 of its value.
func (a AuthLookups) TokenByHash(ctx context.Context, hash []byte) (TokenInfo, bool, error) {
	return one(ctx, a.s, qTokenByHash, func(r pgx.Row) (v TokenInfo, err error) {
		err = r.Scan(&v.TenantID, &v.UserID, &v.TokenID, &v.Kind, scanPrefixes(&v.AllowedIPs), &v.TenantStatus, &v.RevokedAt)
		return v, err
	}, hash)
}

// RefreshInfo is the result of RefreshByHash.
type RefreshInfo struct {
	TenantID        uuid.UUID
	UserID          uuid.UUID
	ID              uuid.UUID
	FamilyID        uuid.UUID
	RotatedAt       *time.Time
	ReuseGraceUntil *time.Time
	ExpiresAt       time.Time
	RevokedAt       *time.Time
}

const qRefreshByHash = `SELECT tenant_id, user_id, id, family_id, rotated_at, reuse_grace_until, expires_at, revoked_at
FROM ctrlz_fn.auth_refresh_by_hash($1)`

// RefreshByHash finds a refresh token by hash.
func (a AuthLookups) RefreshByHash(ctx context.Context, hash []byte) (RefreshInfo, bool, error) {
	return one(ctx, a.s, qRefreshByHash, func(r pgx.Row) (v RefreshInfo, err error) {
		err = r.Scan(&v.TenantID, &v.UserID, &v.ID, &v.FamilyID, &v.RotatedAt, &v.ReuseGraceUntil, &v.ExpiresAt, &v.RevokedAt)
		return v, err
	}, hash)
}

// InviteInfo is the result of InviteByHash.
type InviteInfo struct {
	ID    uuid.UUID
	Phone string
	// ExpiresAt is shown to the invitee. Expired is the decision, made on the
	// database clock that stamped the expiry (clocks.yaml, invites.expires_at).
	ExpiresAt time.Time
	UsedAt    *time.Time
	RevokedAt *time.Time
	Expired   bool
}

const qInviteByHash = `SELECT id, phone_e164, expires_at, used_at, revoked_at, expired FROM ctrlz_fn.auth_invite_by_hash($1)`

// InviteByHash finds an invite by the hash of its token.
func (a AuthLookups) InviteByHash(ctx context.Context, hash []byte) (InviteInfo, bool, error) {
	return one(ctx, a.s, qInviteByHash, func(r pgx.Row) (v InviteInfo, err error) {
		err = r.Scan(&v.ID, &v.Phone, &v.ExpiresAt, &v.UsedAt, &v.RevokedAt, &v.Expired)
		return v, err
	}, hash)
}

// PasskeyInfo is the result of PasskeyByCredential.
type PasskeyInfo struct {
	TenantID  uuid.UUID
	UserID    uuid.UUID
	ID        uuid.UUID
	PublicKey []byte
	SignCount int64
	RPID      string
	StaleAt   *time.Time
	// The flags go-webauthn keeps on a credential and checks on every assertion.
	Transports     []string
	AAGUID         *uuid.UUID
	BackupEligible bool
	BackupState    bool
}

const qPasskeyByCredential = `SELECT tenant_id, user_id, id, public_key, sign_count, rp_id, stale_at,
  transports, aaguid, backup_eligible, backup_state
FROM ctrlz_fn.auth_passkey_by_credential($1)`

// PasskeyByCredential finds a passkey by its credential id.
func (a AuthLookups) PasskeyByCredential(ctx context.Context, credentialID []byte) (PasskeyInfo, bool, error) {
	return one(ctx, a.s, qPasskeyByCredential, func(r pgx.Row) (v PasskeyInfo, err error) {
		err = r.Scan(&v.TenantID, &v.UserID, &v.ID, &v.PublicKey, &v.SignCount, &v.RPID, &v.StaleAt,
			&v.Transports, &v.AAGUID, &v.BackupEligible, &v.BackupState)
		return v, err
	}, credentialID)
}

// Registered is the result of RegisterUser.
type Registered struct {
	TenantID uuid.UUID
	UserID   uuid.UUID
}

const qRegisterUser = `SELECT tenant_id, user_id FROM ctrlz_fn.auth_register_user($1, $2, $3, $4, $5)`

// RegisterUser creates a tenant with its owner. ok is false for every kind of
// refusal (closed registration, bad invite, taken phone, an OTP that is not a
// recently consumed one for this phone) without telling them apart. invite may
// be uuid.Nil for open registration. An empty passwordHash registers an OTP-only
// account: the column stays NULL, which auth_user_flags and the login path both
// read as "no password". otp is the challenge that proved the
// phone: purpose signup, or invite when an invite is given. The database
// checks it, so a route cannot register a number nobody verified.
func (a AuthLookups) RegisterUser(ctx context.Context, phone, passwordHash, locale string, invite, otp uuid.UUID) (Registered, bool, error) {
	var inv any // NULL, not the nil uuid
	if invite != uuid.Nil {
		inv = invite
	}
	return one(ctx, a.s, qRegisterUser, func(r pgx.Row) (v Registered, err error) {
		err = r.Scan(&v.TenantID, &v.UserID)
		return v, err
	}, phone, emptyNull(passwordHash), locale, inv, otpArg(otp))
}

// otpArg is NULL, not the nil uuid, for "no challenge".
func otpArg(id uuid.UUID) any {
	if id == uuid.Nil {
		return nil
	}
	return id
}

// OTPCodeHash is what goes into OTPIssue and OTPConsume as codeHash: a keyed
// MAC over the phone, the purpose and the code. An OTP is a handful of digits,
// so a bare SHA-256 of it falls to a table lookup the moment a row leaks (a
// server log, a backup). With the key it does not.
//
// mac is the keyed function, supplied by internal/keyring (HMAC-SHA256 under
// the auth_mac domain, label "otp"), so the raw key bytes never reach this
// package (8.2). The input is text with a NUL between the fields, and phones
// and purposes never hold a NUL, so moving a character from one field to the
// next changes the input. The challenge id is not in it because the database
// makes it at insert; OTPConsume is bound to the id, the phone and the purpose
// in SQL.
func OTPCodeHash(mac func([]byte) []byte, phone, purpose, code string) []byte {
	return mac([]byte("ctrlz-otp-v1\x00" + phone + "\x00" + purpose + "\x00" + code))
}

// OTPIssued is the result of OTPIssue.
type OTPIssued struct {
	ID      uuid.UUID
	Allowed bool
}

const qOTPIssue = `SELECT id, allowed FROM ctrlz_fn.auth_otp_issue($1, $2, $3, $4, $5, $6)`

// OTPIssue records an OTP challenge, subject to the daily caps. When Allowed
// is false nothing was stored, no counter moved, and the ID is the nil uuid.
// The caps count messages sent, per phone, per source network and overall. A
// missing or invalid ip is refused: there is no shared bucket for it. An
// IPv4-mapped IPv6 address is the same client as its IPv4 form.
//
// A nil deliveryCT is a decoy for a phone that has no account: the row is real,
// so the response and the caps are the same, but nothing is sent. trusted says
// the request came from a device we issued a cookie to for this account (5.5);
// it counts on its own phone key and passes the soft breaker. Decoys pass
// false.
func (a AuthLookups) OTPIssue(ctx context.Context, phone, purpose string, codeHash, deliveryCT []byte, ip netip.Addr, trusted bool) (OTPIssued, error) {
	v, _, err := one(ctx, a.s, qOTPIssue, scanOTPIssued, phone, purpose, codeHash, deliveryCT, addrArg(ip), trusted)
	return v, err
}

// scanOTPIssued reads the one row of auth_otp_issue. A refusal answers a NULL id, which stays the nil uuid.
func scanOTPIssued(r pgx.Row) (v OTPIssued, err error) {
	var id *uuid.UUID
	err = r.Scan(&id, &v.Allowed)
	if id != nil {
		v.ID = *id
	}
	return v, err
}

// OTPIssueForTenant is OTPIssue made inside the transaction of one tenant, on that transaction's one connection
// (no second connection is taken, so it cannot nest). It exists for the one challenge that has an owner before it has
// an account: the code for the NEW number of a phone change (question 15, migration 0061). auth_otp_issue stamps
// otp_challenges.tenant_id itself, from the account of the phone for the other purposes and from the setting of the
// transaction for phone_new; the function that completes the change reads the challenge as ctrlz_scoped, which sees
// only the rows of the tenant of its setting, so a phone_new code issued with no setting could never be used.
// The caller is the tenant API, so the refusals of the caps and the cooldown are answered as for OTPIssue (Allowed
// false, nothing stored) and the transaction commits with nothing in it.
func (a AuthLookups) OTPIssueForTenant(ctx context.Context, tenant uuid.UUID, phone, purpose string, codeHash, deliveryCT []byte, ip netip.Addr, trusted bool) (OTPIssued, error) {
	var out OTPIssued
	err := a.s.WithTenant(ctx, tenant, TxOpts{}, func(tx Tx) error {
		var err error
		out, err = scanOTPIssued(tx.tx.QueryRow(tx.ctx, qOTPIssue, phone, purpose, codeHash, deliveryCT, addrArg(ip), trusted))
		return sanitize(err)
	})
	return out, err
}

const qOTPCheck = `SELECT outcome FROM ctrlz_fn.auth_otp_check($1, $2, $3, $4)`

// OTPCheck is OTPConsume that leaves a right code alone: the same binding to id,
// phone and purpose, the same outcomes, a wrong code spends a try, and a right
// one consumes nothing. POST /auth/register asks it before the expensive work on
// the password and consumes afterwards (review round 4, primitives-r4-3).
func (a AuthLookups) OTPCheck(ctx context.Context, id uuid.UUID, phone, purpose string, codeHash []byte) (string, error) {
	v, _, err := one(ctx, a.s, qOTPCheck, func(r pgx.Row) (s string, err error) {
		err = r.Scan(&s)
		return s, err
	}, id, phone, purpose, codeHash)
	return v, err
}

const qOTPConsume = `SELECT outcome FROM ctrlz_fn.auth_otp_consume($1, $2, $3, $4)`

// OTPConsume checks a code for the phone and purpose the challenge was issued
// for; the database compares all three with the id, and a mismatch is the
// generic "invalid". The outcome is one of ok, invalid, expired, consumed or
// locked.
func (a AuthLookups) OTPConsume(ctx context.Context, id uuid.UUID, phone, purpose string, codeHash []byte) (string, error) {
	v, _, err := one(ctx, a.s, qOTPConsume, func(r pgx.Row) (s string, err error) {
		err = r.Scan(&s)
		return s, err
	}, id, phone, purpose, codeHash)
	return v, err
}

// LinkInfo is the result of ShareByHash and DownloadByHash. Client is set for
// share links, ParamsHash for download links.
type LinkInfo struct {
	TenantID   uuid.UUID
	EndpointID uuid.UUID
	Client     string
	ParamsHash []byte
	ExpiresAt  time.Time
	UsesLeft   int
}

const qShareByHash = `SELECT tenant_id, endpoint_id, client, expires_at, uses_left FROM ctrlz_fn.auth_share_by_hash($1)`

// ShareByHash resolves /s/<token>. The caller then spends one use inside
// WithTenant, with WHERE uses < max_uses.
func (a AuthLookups) ShareByHash(ctx context.Context, hash []byte) (LinkInfo, bool, error) {
	return one(ctx, a.s, qShareByHash, func(r pgx.Row) (v LinkInfo, err error) {
		var client *string
		var left int32
		err = r.Scan(&v.TenantID, &v.EndpointID, &client, &v.ExpiresAt, &left)
		if client != nil {
			v.Client = *client
		}
		v.UsesLeft = int(left)
		return v, err
	}, hash)
}

const qDownloadByHash = `SELECT tenant_id, endpoint_id, params_hash, expires_at, uses_left FROM ctrlz_fn.auth_download_by_hash($1)`

// DownloadByHash resolves /p/<token>.
func (a AuthLookups) DownloadByHash(ctx context.Context, hash []byte) (LinkInfo, bool, error) {
	return one(ctx, a.s, qDownloadByHash, func(r pgx.Row) (v LinkInfo, err error) {
		var left int32
		err = r.Scan(&v.TenantID, &v.EndpointID, &v.ParamsHash, &v.ExpiresAt, &left)
		v.UsesLeft = int(left)
		return v, err
	}, hash)
}

// PublicConfig is what the login page needs before a tenant is known. It holds
// no user data, and the api caches it for 30 seconds.
type PublicConfig struct {
	RegistrationMode string // closed, invite or open
	PanelHost        string // empty until a domain is set (P4); the caller falls back to CTRLZ_PANEL_HOST
	RPID             string // empty until a Passkey RP ID is set
	AllowedOrigins   []string
	PasskeyEnabled   bool
	SMSAvailable     bool // a routed gateway with usable credentials exists: configuration alone, never a send's outcome (sms-r18-2)
	// OTPCooldown is system_settings.otp_cooldown_s, the wait between two codes for one phone (10 s to 1 h,
	// an admin setting). The 202 of a code request says it as resend_after_s and the 429 otp_limited as
	// Retry-After, the same for every phone, so it says nothing about an account (round 8, tenant-r8-2).
	OTPCooldown time.Duration
}

const qPublicConfig = `SELECT registration_mode, panel_host, rp_id, allowed_origins, passkey_enabled, sms_available, otp_cooldown_s
FROM ctrlz_fn.auth_public_config()`

// PublicConfig reads the settings the login page needs. ctrlz_tenant has no
// grant on the tables, and WithGlobal refuses that role, so this is the way.
func (a AuthLookups) PublicConfig(ctx context.Context) (PublicConfig, error) {
	v, ok, err := one(ctx, a.s, qPublicConfig, func(r pgx.Row) (c PublicConfig, err error) {
		var host, rp *string
		var cooldown int32
		err = r.Scan(&c.RegistrationMode, &host, &rp, &c.AllowedOrigins, &c.PasskeyEnabled, &c.SMSAvailable, &cooldown)
		c.OTPCooldown = time.Duration(cooldown) * time.Second
		if host != nil {
			c.PanelHost = *host
		}
		if rp != nil {
			c.RPID = *rp
		}
		return c, err
	})
	if err == nil && !ok {
		err = ErrDriver // the settings singletons always exist; no row is a broken database
	}
	return v, err
}

// TicketKind is the kind of a login ticket (the CHECK of auth_tickets).
type TicketKind string

// The kinds of auth_tickets.
const (
	TicketMFA             TicketKind = "mfa"
	TicketReset           TicketKind = "reset"
	TicketPasskeyLogin    TicketKind = "passkey_login"
	TicketPasskeyRegister TicketKind = "passkey_register"
	TicketPasskeyReauth   TicketKind = "passkey_reauth"
)

// NewTicket is the input of TicketPut. TokenHash is the SHA-256 of the raw
// token the client holds, so the table never holds a usable token.
type NewTicket struct {
	TokenHash   []byte
	Kind        TicketKind
	Tenant      uuid.UUID // the nil uuid for a ticket with no subject (passkey_login)
	User        uuid.UUID
	RememberMe  bool
	FirstFactor string // "password", "otp" or empty
	Payload     []byte // at most 4096 bytes; WebAuthn session data for the passkey kinds
	TTL         time.Duration
	// Cred is the stamp of the first factor an mfa ticket comes from. It is required for
	// the mfa kind (the table says so too) and is read back by Tx.UserLockFor when the
	// ticket is spent.
	Cred credgen.Stamp
}

// Ticket is a ticket as TicketPeek and TicketTake return it.
type Ticket struct {
	Tenant      uuid.UUID // the nil uuid when the ticket has no subject
	User        uuid.UUID
	RememberMe  bool
	FirstFactor string
	Payload     []byte
	// Cred is the stamp the ticket was made with (zero for the kinds that carry none).
	Cred credgen.Stamp
}

func scanTicket(r pgx.Row) (t Ticket, err error) {
	var tenant, user *uuid.UUID
	var ff *string
	var sgen *int64
	err = r.Scan(&tenant, &user, &t.RememberMe, &ff, &t.Payload, &sgen)
	if tenant != nil {
		t.Tenant = *tenant
	}
	if user != nil {
		t.User = *user
	}
	if ff != nil {
		t.FirstFactor = *ff
	}
	if sgen != nil {
		t.Cred = credgen.Stamp{Tenant: t.Tenant, Subject: t.User, Gen: *sgen}
	}
	return t, err
}

const qTicketPut = `SELECT id FROM ctrlz_fn.auth_ticket_put($1, $2, $3, $4, $5, $6, $7, $8, $9)`

// TicketPut stores a login ticket and returns its id. The lifetime is capped at
// 10 minutes by the function and the table. The tenant and the user are values
// the api passes in, for a phase where no tenant setting exists; the table is
// global and reading a ticket needs the raw token, so this adds no reach across
// tenants. ok is false for input the function refuses (no hash, no lifetime).
func (a AuthLookups) TicketPut(ctx context.Context, t NewTicket) (uuid.UUID, bool, error) {
	args, err := t.args()
	if err != nil {
		return uuid.Nil, false, err
	}
	return one(ctx, a.s, qTicketPut, scanTicketID, args...)
}

func scanTicketID(r pgx.Row) (id uuid.UUID, err error) {
	err = r.Scan(&id)
	return id, err
}

// args is the argument list of auth_ticket_put. A stamp of another subject is a bug in the
// caller and is refused before any statement, so the two ways to put a ticket (a single
// statement, or inside a transaction) cannot differ on it.
func (t NewTicket) args() ([]any, error) {
	var tenant, user, ff any
	if t.Tenant != uuid.Nil {
		tenant = t.Tenant
	}
	if t.User != uuid.Nil {
		user = t.User
	}
	if t.FirstFactor != "" {
		ff = t.FirstFactor
	}
	var sgen any
	if !t.Cred.Zero() {
		if t.Cred.Tenant != t.Tenant || t.Cred.Subject != t.User {
			return nil, ErrConstraint // a stamp of another subject is a bug in the caller
		}
		sgen = t.Cred.Gen
	}
	secs := int32(t.TTL / time.Second)
	if t.TTL > 0 && secs == 0 {
		secs = 1
	}
	return []any{t.TokenHash, string(t.Kind), tenant, user, t.RememberMe, ff, t.Payload, secs, sgen}, nil
}

const qTicketPeek = `SELECT subject_tenant, subject_user, remember_me, first_factor, payload, subject_gen
FROM ctrlz_fn.auth_ticket_peek($1, $2)`

// TicketPeek reads a ticket of the given kind and spends one of its five
// attempts. found is false when the ticket is unknown, of another kind,
// consumed, expired or already read five times, without saying which.
func (a AuthLookups) TicketPeek(ctx context.Context, hash []byte, kind TicketKind) (Ticket, bool, error) {
	return one(ctx, a.s, qTicketPeek, scanTicket, hash, string(kind))
}

const qTicketTake = `SELECT subject_tenant, subject_user, remember_me, first_factor, payload, subject_gen
FROM ctrlz_fn.auth_ticket_take($1, $2)`

// TicketTake uses a ticket. The function sets consumed_at in one UPDATE, so of
// two racing requests with the same ticket exactly one wins; the row it returns is the
// ticket, and only the winner may act on it.
func (a AuthLookups) TicketTake(ctx context.Context, hash []byte, kind TicketKind) (Ticket, Won, error) {
	t, found, err := one(ctx, a.s, qTicketTake, scanTicket, hash, string(kind))
	return t, won(found), err
}

// TicketSpend records that a stateless ticket (a sealed passkey login ceremony, which has no
// row until it is used) has been used, and answers whether this call was the first. The
// hash is the SHA-256 of the ticket's nonce and the unique index on token_hash decides
// between racing requests: the insert that lands wins, every other one meets the
// unique violation and loses (rule proof-before-work: the begin writes no row, the finish
// writes this one, and only after the assertion verified). The row lives for ttl so the
// sweeper removes it with the other tickets. A ticket of a kind with a subject is not
// spent this way.
func (a AuthLookups) TicketSpend(ctx context.Context, hash []byte, ttl time.Duration) (Won, error) {
	_, ok, err := a.TicketPut(ctx, NewTicket{TokenHash: hash, Kind: TicketPasskeyLogin, TTL: ttl})
	if errors.Is(err, ErrConflict) {
		return won(false), nil
	}
	if err != nil {
		return won(false), err
	}
	if !ok {
		return won(false), ErrConstraint // the function refuses only malformed input: a bug in the caller
	}
	return won(true), nil
}

// ThrottleResult is the answer of a throttle hit.
type ThrottleResult struct {
	Allowed    bool
	RetryAfter time.Duration // the rest of the window, set only when refused
	// Epoch names the window the hit was counted in. It moves when the window restarts and when the
	// line is cleared, and a refund works only on the epoch it is given, so an attempt can be given
	// back out of the window it was counted in and out of no other (primitives-r6-2). It is a
	// number and not a time: nothing of the database clock reaches Go.
	Epoch int64
}

const qThrottleHit = `SELECT allowed, retry_after_s, window_epoch FROM ctrlz_fn.auth_throttle_hit($1, $2, $3, $4)`

// ThrottleHit counts one attempt on a user scope (login_phone_net, login_phone,
// login_net, login_net48, totp_user, reauth_user, otp_verify_net, invite_net).
// key is a 32-byte HMAC under auth_mac, never a phone number. The function is
// one statement outside any transaction, so a failed login does not roll the
// count back. A scope outside the user list, or a malformed key, is refused
// (Allowed false).
func (a AuthLookups) ThrottleHit(ctx context.Context, scope string, key []byte, max int, window time.Duration) (ThrottleResult, error) {
	v, _, err := one(ctx, a.s, qThrottleHit, scanThrottle, scope, key, int32(max), int32(window/time.Second))
	return v, err
}

func scanThrottle(r pgx.Row) (res ThrottleResult, err error) {
	var retry int32
	err = r.Scan(&res.Allowed, &retry, &res.Epoch)
	res.RetryAfter = time.Duration(retry) * time.Second
	return res, err
}

const qThrottleReset = `SELECT 1 FROM ctrlz_fn.auth_throttle_reset($1, $2)`

// ThrottleReset clears a key after a success (login_phone_net, login_phone,
// totp_user, reauth_user: the scopes marked "reset on success" in 4.5).
func (a AuthLookups) ThrottleReset(ctx context.Context, scope string, key []byte) error {
	_, _, err := one(ctx, a.s, qThrottleReset, scanOne, scope, key)
	return err
}

const qThrottleRefund = `SELECT 1 FROM ctrlz_fn.auth_throttle_refund($1, $2, $3, $4)`

// ThrottleRefund gives one attempt back on a user scope, inside the window it was counted in:
// epoch is the one ThrottleHit returned for that attempt. It is for an attempt that did no work
// (the Argon2 gate was full): the count comes before the work, so without this a refused attempt
// would stay spent (tenant-r5-1). The count never goes below zero, and a window that has restarted
// or a line that has been cleared since (another epoch) is not touched (primitives-r6-2).
func (a AuthLookups) ThrottleRefund(ctx context.Context, scope string, key []byte, window time.Duration, epoch int64) error {
	_, _, err := one(ctx, a.s, qThrottleRefund, scanOne, scope, key, int32(window/time.Second), epoch)
	return err
}

// scanOne reads a single int column, for the calls whose result is only
// "it ran" (a void function selected as a row).
func scanOne(r pgx.Row) (n int, err error) {
	err = r.Scan(&n)
	return n, err
}
