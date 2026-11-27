package store

import (
	"context"
	"net/netip"
	"time"

	"github.com/google/uuid"
)

// API tokens (docs/specs/p3-endpoints.md 6). The table holds only the SHA-256 of the bearer value (internal/auth/bearer) and a
// prefix of six characters of its random part; the value is shown once, at creation, and never read back.
//
// The rules of this file, all in statements:
//
//   - The cap max_api_tokens is decided by the INSERT that adds the row, under the tenant quota lock (QuotaLock), and counts
//     every row of the tenant, expired and ended ones included: a person deletes a token they no longer want, which is the one
//     way to give a slot back (6.4).
//   - Every statement names the tenant and the user, so a user reads and changes only the tokens it made. A token of another
//     tenant is not found at all, since row level security hides it before the predicate looks.
//   - last_used_at is written from the application clock and compared with it (clocks.yaml): no statement here reads now().

// MaxAPITokenListed bounds the list of a user's tokens. The plan's limit is far below it; the bound is only a ceiling for a
// plan that is raised without a thought for this page (the list has no cursor, 6.4).
const MaxAPITokenListed = 500

// TokenTouchEvery is how stale last_used_at may be before a request of the token writes it again (D31, spec 6.3 step 7): one
// write per token per ten minutes, however many requests it makes.
const TokenTouchEvery = 10 * time.Minute

// APITokenNew is a token to add.
type APITokenNew struct {
	ID   uuid.UUID
	User uuid.UUID
	Name string
	// Kind is "read" or "write".
	Kind string
	// Hash is the SHA-256 of the value (bearer.Hash); Prefix its six shown characters.
	Hash   []byte
	Prefix string
	// Allowed is the list the token is limited to; empty means any address. It is never nil, so the column is '{}' and not NULL.
	Allowed []netip.Prefix
	// Expires is the instant the value carries (365 days after creation, from the application clock).
	Expires time.Time
}

const qAPITokenInsert = `WITH lim AS (SELECT * FROM ctrlz_fn.tenant_plan())
INSERT INTO ctrlz.api_tokens (tenant_id, id, user_id, name, kind, token_hash, token_prefix, allowed_ips, expires_at)
SELECT $1::uuid, $2::uuid, $3::uuid, $4::text, $5::text, $6::bytea, $7::text, $8::cidr[], $9::timestamptz
WHERE NOT ctrlz.cap_reached((SELECT count(*) FROM ctrlz.api_tokens t WHERE t.tenant_id = $1),
  COALESCE((SELECT lim.max_api_tokens FROM lim), 0))
RETURNING id`

// APITokenInsert adds a token unless the tenant already holds its limit (max_api_tokens). A loss is that cap. The caller holds
// the tenant quota lock (QuotaLock) and the user's row (UserLock), in that order.
func (t Tx) APITokenInsert(n APITokenNew) (Won, error) {
	allowed := n.Allowed
	if allowed == nil {
		allowed = []netip.Prefix{}
	}
	var id uuid.UUID
	w, err := wonRow(t.tx.QueryRow(t.ctx, qAPITokenInsert, t.tenant, n.ID, n.User, n.Name, n.Kind, n.Hash, n.Prefix,
		prefixesArg(allowed), n.Expires).Scan(&id))
	if err != nil || !w.Yes() {
		return Won{}, err
	}
	return w, nil
}

// APITokenRow is a token as its owner reads it: never the value or its hash.
type APITokenRow struct {
	ID     uuid.UUID
	Name   string
	Kind   string
	Prefix string
	// Allowed is the list as the database writes it (an address is a /32 or a /128), so no handler cuts an address.
	Allowed    []string
	LastUsedAt *time.Time
	RevokedAt  *time.Time
	ExpiresAt  time.Time
	CreatedAt  time.Time
}

const apiTokenColumns = `id, name, kind, token_prefix, allowed_ips::text[], last_used_at, revoked_at, expires_at, created_at`

const qAPITokenList = `SELECT ` + apiTokenColumns + ` FROM ctrlz.api_tokens
WHERE tenant_id = $1 AND user_id = $2 ORDER BY created_at DESC, id DESC LIMIT 500`

// APITokenList reads the user's tokens, newest first.
func (t Tx) APITokenList(user uuid.UUID) ([]APITokenRow, error) {
	rows, err := t.tx.Query(t.ctx, qAPITokenList, t.tenant, user)
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []APITokenRow
	for rows.Next() {
		var r APITokenRow
		if err := rows.Scan(&r.ID, &r.Name, &r.Kind, &r.Prefix, &r.Allowed, &r.LastUsedAt, &r.RevokedAt, &r.ExpiresAt, &r.CreatedAt); err != nil {
			return nil, sanitize(err)
		}
		out = append(out, r)
	}
	return out, sanitize(rows.Err())
}

const qAPITokenGet = `SELECT ` + apiTokenColumns + ` FROM ctrlz.api_tokens WHERE tenant_id = $1 AND user_id = $2 AND id = $3`

// APITokenGet reads one token of the user; found is false for an id that is not the user's.
func (t Tx) APITokenGet(user, id uuid.UUID) (APITokenRow, bool, error) {
	var r APITokenRow
	err := t.tx.QueryRow(t.ctx, qAPITokenGet, t.tenant, user, id).Scan(&r.ID, &r.Name, &r.Kind, &r.Prefix, &r.Allowed,
		&r.LastUsedAt, &r.RevokedAt, &r.ExpiresAt, &r.CreatedAt)
	ok, err := notFound(err)
	return r, ok, err
}

// APITokenEdit is the change of a PATCH: a field that is nil is left as it is. SetAllowed says Allowed is to be written, so an
// empty list can be told from an absent one.
type APITokenEdit struct {
	Name       *string
	SetAllowed bool
	Allowed    []netip.Prefix
}

const qAPITokenUpdate = `UPDATE ctrlz.api_tokens SET name = COALESCE($4::text, name),
  allowed_ips = CASE WHEN $5::bool THEN $6::cidr[] ELSE allowed_ips END
WHERE tenant_id = $1 AND user_id = $2 AND id = $3
RETURNING ` + apiTokenColumns

// APITokenUpdate changes the name or the allowed addresses of a token (its kind never changes, 6.1); found is false for an id
// that is not the user's. A token that is ended or expired can still be renamed.
func (t Tx) APITokenUpdate(user, id uuid.UUID, e APITokenEdit) (APITokenRow, bool, error) {
	allowed := e.Allowed
	if allowed == nil {
		allowed = []netip.Prefix{}
	}
	var r APITokenRow
	err := t.tx.QueryRow(t.ctx, qAPITokenUpdate, t.tenant, user, id, e.Name, e.SetAllowed, prefixesArg(allowed)).Scan(&r.ID, &r.Name, &r.Kind,
		&r.Prefix, &r.Allowed, &r.LastUsedAt, &r.RevokedAt, &r.ExpiresAt, &r.CreatedAt)
	ok, err := notFound(err)
	return r, ok, err
}

const qAPITokenDelete = `DELETE FROM ctrlz.api_tokens WHERE tenant_id = $1 AND user_id = $2 AND id = $3`

// APITokenDelete removes a token of the user; found is false for an id that is not the user's. The value stops working at its
// next request: the lookup finds no row, and the value joins the dead set of the pipeline (6.3).
func (t Tx) APITokenDelete(user, id uuid.UUID) (bool, error) {
	tag, err := t.tx.Exec(t.ctx, qAPITokenDelete, t.tenant, user, id)
	if err != nil {
		return false, sanitize(err)
	}
	return tag.RowsAffected() == 1, nil
}

// ---------------------------------------------------------------------------
// last_used_at (6.3 step 7).
//
// The write is best effort and runs in a transaction of its own, never inside the one a handler uses. Inside it, the single
// api_tokens row of a token would be a lock that every request of that token holds from its first statement to its commit: a
// second write of the token would wait for the first on an unrelated profile, a REPEATABLE READ read would fail with a
// serialization error when a sibling request committed the touch after its snapshot began, and a read would sit on a pooled
// connection and an ordinary turn behind a long import of the same token (review round 1 of D5, p3-D5-r1-5). A touch that is
// skipped costs a stale "last used" in a list; none of those costs is worth it.

// Two statements, so that each is a plain one the lints can read: the first takes the row only if it is stale and nobody holds it
// (SKIP LOCKED, so no row means "nothing to do", whether it was fresh or busy), the second writes the row it now holds by its id.
const qAPITokenTouchLock = `SELECT id FROM ctrlz.api_tokens
WHERE tenant_id = $1 AND id = $2 AND (last_used_at IS NULL OR last_used_at < $3::timestamptz)` + lockNoKeyUpdate + ` SKIP LOCKED`

const qAPITokenTouch = `UPDATE ctrlz.api_tokens SET last_used_at = $3::timestamptz WHERE tenant_id = $1 AND id = $2`

// APITokenTouch writes at as the last use of the token when it is NULL or older than TokenTouchEvery, and does nothing when
// another transaction holds the row: it never waits, so it cannot be a side of a lock cycle or hold a connection for a lock. at
// is the application clock.
func (t Tx) APITokenTouch(id uuid.UUID, at time.Time) error {
	var held uuid.UUID
	err := t.tx.QueryRow(t.ctx, qAPITokenTouchLock, t.tenant, id, at.Add(-TokenTouchEvery)).Scan(&held)
	if ok, err := notFound(err); err != nil || !ok {
		return err
	}
	_, err = t.tx.Exec(t.ctx, qAPITokenTouch, t.tenant, id, at)
	return sanitize(err)
}

// TouchAPIToken is APITokenTouch in a short transaction of its own, for the tenant of the token. A caller that is answering a
// request calls it before its handler runs and ignores the error: the use of a token is never refused for want of this write.
func (s *Store) TouchAPIToken(ctx context.Context, tenant, id uuid.UUID, at time.Time) error {
	return s.WithTenant(ctx, tenant, TxOpts{}, func(tx Tx) error { return tx.APITokenTouch(id, at) })
}
