package store

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/credstate"
	"github.com/Kup1ng/CtrlZ-Panel/internal/credgen"
	"github.com/Kup1ng/CtrlZ-Panel/internal/lockrank"
)

// This file is the only place in the store that spells a lock (P1 auth review,
// round 5, rule lock-order; spec 4.4). TestLockOrderRule fails for a FOR UPDATE,
// FOR SHARE, FOR KEY SHARE or pg_advisory_xact_lock literal anywhere else, so
// reading this file shows every row a transaction of the store can lock, and
// internal/lockrank says in which order it may take them:
//
//	users and admin_users (FOR NO KEY UPDATE or FOR KEY SHARE, never FOR UPDATE),
//	sessions, refresh_tokens, the other per-user rows, sms_counters (a refund
//	locks at most one shard of the day's global count, never waiting, one statement a message, days in order), the settings rows, sms_gateways, and the audit advisory
//	lock last.
//
// Why a rank and not a list of the pairs that deadlocked: five rounds each found
// a pair nobody had thought of, because the locks of a transaction came from
// what its statements happened to do (a foreign key's key share, a multi-row
// UPDATE, the audit lock). guardTx reads every statement before it runs and
// refuses one that would take a lock below one the transaction holds.

const (
	lockUpdate           = " FOR UPDATE"
	lockNoKeyUpdate      = " FOR NO KEY UPDATE"
	lockKeyShare         = " FOR KEY SHARE"
	lockShare            = " FOR SHARE"
	lockUpdateSkipLocked = " FOR UPDATE SKIP LOCKED"
)

// The rows of one table (db-r16-19; spec 4.4). The rank orders the TABLES a transaction locks; inside a table
// a statement that can touch several rows takes them through one shape, so two such statements meet in the
// same order whatever plan each one scans by:
//
//	id = ANY (ARRAY(SELECT id FROM <table> WHERE <predicate> ORDER BY id [LIMIT n] FOR [NO KEY] UPDATE [SKIP LOCKED]))
//
// ARRAY(...) and not IN (SELECT ...): the array is an InitPlan, evaluated ONCE, so the rows are picked and locked
// once and in key order. An IN over a subselect that locks and limits is a semi-join the planner may rescan for
// each row the outer statement visits, and a rescan after the outer statement has changed rows picks the NEXT
// rows: the stale-outbox sweep ended six rows for a batch of two (TestFastEndsStaleOutboxInBatchesAndSparesALiveClaim).
//
// The constants below are its tail (a sweep writes keyOrder + " LIMIT $n" + lockUpdateSkipLocked). An UPDATE of non-key columns takes FOR NO KEY UPDATE on each row
// anyway, so that is the lock it asks for here (FOR UPDATE would conflict with the FOR KEY SHARE that every
// insert of a child row takes through its foreign key, the db-r4-1 cycle); a DELETE takes FOR UPDATE; a
// sweep skips rows somebody holds (it never waits, so it cannot be the waiting side of a cycle, and a row it
// skipped is found by the next pass). internal/lint TestMultiRowWritesLockInKeyOrder fails for a write that
// can touch several rows and does not carry one of them (or name its row by id), so a statement added
// tomorrow is judged by itself.
const (
	keyOrder      = " ORDER BY id"
	orderedUpdate = keyOrder + lockNoKeyUpdate
	orderedDelete = keyOrder + lockUpdate
)

// ErrLockOrder is returned instead of running a statement that would take a
// row lock below one the transaction already holds, or whose locks cannot be
// ranked at all (a table, function or advisory key missing from lockrank and
// functions.yaml). It is a defect of the code, not of the request: a caller
// answers it as an internal error. It carries table names and ranks, never a
// statement or a value.
var ErrLockOrder = errors.New("store: lock order violated")

// guardTx is the pgx transaction plus what it holds. Tx and GlobalTx keep only
// this, so no statement reaches the connection without being read first.
type guardTx struct {
	tx  pgx.Tx
	st  lockrank.State
	own *sync.Map // statement text to its touches, shared by the Store
}

// analysis is what a statement text was classified as, kept per text: the texts
// are constants, so the cache is bounded by the size of the program.
type analysis struct {
	touches []lockrank.Touch
	err     error
}

func (g *guardTx) admit(sql string) error {
	var a analysis
	if v, ok := g.own.Load(sql); ok {
		a = v.(analysis)
	} else {
		a.touches, a.err = lockrank.Analyze(sql)
		g.own.Store(sql, a)
	}
	if a.err != nil {
		return fmt.Errorf("%w: %s", ErrLockOrder, a.err)
	}
	if err := g.st.Acquire(a.touches); err != nil {
		return fmt.Errorf("%w: %s", ErrLockOrder, err)
	}
	return nil
}

func (g *guardTx) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	if err := g.admit(sql); err != nil {
		return pgconn.CommandTag{}, err
	}
	return g.tx.Exec(ctx, sql, args...) // lint:sql-const forwarded; every caller is checked
}

func (g *guardTx) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	if err := g.admit(sql); err != nil {
		return nil, err
	}
	return g.tx.Query(ctx, sql, args...) // lint:sql-const forwarded; every caller is checked
}

func (g *guardTx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	if err := g.admit(sql); err != nil {
		return errRow{err}
	}
	return g.tx.QueryRow(ctx, sql, args...) // lint:sql-const forwarded; every caller is checked
}

type errRow struct{ err error }

func (e errRow) Scan(...any) error { return e.err }

// ---------------------------------------------------------------------------
// Users: the first rank.

// FOR NO KEY UPDATE and not FOR UPDATE: the key of a user (tenant_id, id) never
// changes here, and FOR UPDATE conflicts with the FOR KEY SHARE that every insert
// into sessions or refresh_tokens takes on this row through its foreign key. A
// holder of the stronger lock that then touched a session Refresh had locked
// formed a cycle with it (40P01, a 503 for one of them; review round 4, db-r4-1).
// The weaker lock still excludes every other UserLock, the admin re-issue and the
// user's own UPDATEs, which is all the ordering of 4.4 needs.
const qUserLock = `SELECT tenant_id, credential_gen, ` + userStateSQL + ` FROM ctrlz.users WHERE tenant_id = $1 AND id = $2` + lockNoKeyUpdate

const qUserKeyShare = `SELECT 1 FROM ctrlz.users WHERE tenant_id = $1 AND id = $2` + lockKeyShare

// UserKeyShare takes the weakest row lock on the user. Refresh calls it first,
// before it locks the session: the refresh row it inserts later needs this lock
// anyway (foreign key), and taking it up front puts Refresh behind any writer that
// holds a key-strength lock on the row (a phone change moves phone_e164, a unique
// column, and so locks like FOR UPDATE) before it holds the session, so the two
// cannot wait for each other. It never blocks on UserLock, which is FOR NO KEY
// UPDATE. A missing user is false.
func (t Tx) UserKeyShare(id uuid.UUID) (bool, error) {
	var one int
	err := t.tx.QueryRow(t.ctx, qUserKeyShare, t.tenant, id).Scan(&one)
	return notFound(err)
}

// UserLock locks the user's row and reads the columns that a re-issue of a one-time
// password and the user's own password change move. A login creates its session after this, and a
// password change re-reads its session after it, so the re-issue and either of
// them are ordered by the lock (spec 4.4, 5.7, 10.7).
func (t Tx) UserLock(id uuid.UUID) (UserLock, bool, error) {
	var l UserLock
	var tenant uuid.UUID
	var state string
	err := t.tx.QueryRow(t.ctx, qUserLock, t.tenant, id).Scan(&tenant, &l.Cred.Gen, &state)
	ok, err := notFound(err)
	if err != nil || !ok {
		return l, ok, err
	}
	l.Cred.Tenant, l.Cred.Subject = tenant, id
	l.State, err = credstate.Parse(state)
	return l, true, sanitize(err)
}

// UserLockFor is UserLock for something derived from a first-factor check: the
// session a login is about to open after Argon2, an mfa ticket being spent, a rehash,
// a reauth. issued is the stamp it carries (User.Stamp, UserLogin.Cred, Ticket.Cred).
// The row is locked first and then compared, by generation and by subject, here and
// nowhere else (internal/credgen): a credential that changed after the check, by any
// route or none, is credgen.ErrStale. A user that is not there is ok false, as for
// UserLock.
func (t Tx) UserLockFor(id uuid.UUID, issued credgen.Stamp) (UserLock, bool, error) {
	l, ok, err := t.UserLock(id)
	if err != nil || !ok {
		return l, ok, err
	}
	if err := issued.Check(l.Cred); err != nil {
		return UserLock{}, true, err
	}
	return l, true, nil
}

// ---------------------------------------------------------------------------
// Sessions.

const qSessionByIDForUpdate = qSessionByID + lockUpdate

// SessionByIDForUpdate is SessionByID with a row lock. Every transaction that
// touches a session and its refresh tokens locks the session row first (spec
// 4.4: users, then sessions, then refresh tokens), so that POST /auth/refresh
// and a reauth or log out all cannot wait on each other's rows.
func (t Tx) SessionByIDForUpdate(id uuid.UUID) (SessionRow, bool, error) {
	s, err := scanSession(t.tx.QueryRow(t.ctx, qSessionByIDForUpdate, t.tenant, id))
	ok, err := notFound(err)
	return s, ok, err
}

// ---------------------------------------------------------------------------
// Admin rows.

const qAdminUserLockByID = `SELECT ` + adminUserColumns + ` FROM ctrlz.admin_users WHERE id = $1` + lockNoKeyUpdate

// AdminUserLockByID reads an admin row and holds it until the transaction ends.
// A login uses it to prove, after Argon2 and before it opens a session, that the
// row is still the one it verified: a console reset that committed in between
// has changed the password hash or cleared the authenticator, and the reset has
// already revoked the sessions that existed, so a session inserted after it
// would outlive it (review round 3, admin-r3-2). FOR NO KEY UPDATE, not FOR SHARE:
// the same transaction goes on to update the row (last_login_at), and a
// share lock upgraded to an update lock is how two logins deadlock. And not FOR
// UPDATE: the admin session the login inserts next takes FOR KEY SHARE on this
// row through its foreign key, which FOR UPDATE would make a wait for itself
// across transactions (the rule of internal/lockrank: the user tables never get
// FOR UPDATE).
func (g GlobalTx) AdminUserLockByID(id uuid.UUID) (AdminUser, bool, error) {
	a, err := scanAdminUser(g.tx.QueryRow(g.ctx, qAdminUserLockByID, id))
	ok, err := notFound(err)
	return a, ok, err
}

// AdminUserLockFor is AdminUserLockByID for something derived from a first-factor check:
// the admin login that verified a password and a code outside any transaction. The row
// is locked, then compared with the stamp by generation and by subject, here and
// nowhere else (internal/credgen). A console reset, a password change, an enrolment or
// a disable that committed meanwhile is credgen.ErrStale.
func (g GlobalTx) AdminUserLockFor(id uuid.UUID, issued credgen.Stamp) (AdminUser, bool, error) {
	a, ok, err := g.AdminUserLockByID(id)
	if err != nil || !ok {
		return a, ok, err
	}
	if err := issued.Check(a.Stamp()); err != nil {
		return AdminUser{}, true, err
	}
	return a, true, nil
}

// qAdminNoticeRows locks every enabled admin in id order (a multi-row lock in
// one fixed order, so two of them cannot cross).
const qAdminNoticeRows = `SELECT id, pending_notice FROM ctrlz.admin_users WHERE disabled_at IS NULL ORDER BY id` + lockNoKeyUpdate

const qAdminNoticeLock = `SELECT pending_notice FROM ctrlz.admin_users WHERE id = $1` + lockNoKeyUpdate

// ---------------------------------------------------------------------------
// Singletons of the settings band.

const qRegistrationLock = `SELECT registration_mode, open_grace_days, takeover_idle_days FROM ctrlz.system_settings` + lockUpdate

// RegistrationLock reads the settings and locks the row, which is step 1 of the
// mode change: two admins changing it at once are ordered.
func (g GlobalTx) RegistrationLock() (Registration, error) {
	var r Registration
	err := g.tx.QueryRow(g.ctx, qRegistrationLock).Scan(&r.Mode, &r.OpenGraceDays, &r.TakeoverIdleDays)
	return r, sanitize(err)
}

const qSMSSettingsLock = `SELECT 1 FROM ctrlz.system_settings` + lockNoKeyUpdate

// SMSSettingsLock locks the settings row until the transaction ends. It is the one row every
// writer of the money-cap invariant (a cap needs a price on every routed gateway) takes before it
// reads the other side: the limits writer holds it through its UPDATE, and the gateway and
// routing writers take it after their own write (a gateway is rank 495 and the settings 600, so
// the order is the global one). Under Read Committed a check made without it saw the other
// writer's old state, and a cap and an unpriced primary were both committed (round 6, admin-r6-3).
// With it, the second writer waits for the first's commit and its check reads the result.
func (g GlobalTx) SMSSettingsLock() error {
	var one int
	return sanitize(g.tx.QueryRow(g.ctx, qSMSSettingsLock).Scan(&one))
}

const qWebauthnConfigLock = `SELECT COALESCE(rp_id, ''), allowed_origins, enabled FROM ctrlz.webauthn_config` + lockUpdate

// WebauthnConfigLock reads the configuration and locks the row.
func (g GlobalTx) WebauthnConfigLock() (WebauthnConfig, error) {
	var c WebauthnConfig
	err := g.tx.QueryRow(g.ctx, qWebauthnConfigLock).Scan(&c.RPID, &c.AllowedOrigins, &c.Enabled)
	return c, sanitize(err)
}

// ---------------------------------------------------------------------------
// Jobs.

const qAdminJobHold = `SELECT 1 FROM ctrlz.admin_jobs WHERE id = $1 AND state IN ('queued', 'running')` + lockShare

// AdminJobHold says whether the job is still queued or running, and holds its
// row with a share lock until this transaction ends. A job that acts on a
// tenant calls it first in the tenant's transaction: finishing the job (an
// UPDATE) waits for the lock, and a new job of the same kind cannot be queued
// before the old one is finished (admin_jobs_one_active_uq). So no tenant
// transaction of a job that has been finished, and possibly replaced, can
// commit after its replacement began. This is what stops a second worker that
// is still walking the tenants with an old RP ID from marking the passkeys made
// under the new one stale (sms-r2-12).
func (t Tx) AdminJobHold(id uuid.UUID) (bool, error) {
	var one int
	err := t.tx.QueryRow(t.ctx, qAdminJobHold, id).Scan(&one)
	return notFound(err)
}

// ---------------------------------------------------------------------------
// The audit log: last.

// qAuditLock is a call of ctrlz_fn.audit_lock() and not the advisory call itself (db-r14-3): the
// admin role holds no advisory function. Postgres grants those to PUBLIC, and a login role that
// can call pg_advisory_lock with the key of this chain, which anyone can compute, holds every
// audited admin write (and so the owner's own login) for as long as it stays connected. The
// function locks this one key, so the role that takes the lock cannot take another.
const qAuditLock = `SELECT ctrlz_fn.audit_lock()`

// lockAudit takes the audit chain's advisory lock. Every admin write takes it
// after its own rows and before it appends, so it is the last lock a
// transaction takes (rank 90): taking it earlier would hold the whole audit
// chain while waiting for an admin or gateway row (admin-r3-3).
func lockAudit(ctx context.Context, tx *guardTx) error {
	_, err := tx.Exec(ctx, qAuditLock)
	return sanitize(err)
}
