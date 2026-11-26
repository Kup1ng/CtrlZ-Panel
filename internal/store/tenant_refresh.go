package store

import "github.com/google/uuid"

const qRefreshSession = `SELECT session_id FROM ctrlz.refresh_tokens WHERE tenant_id = $1 AND id = $2`

// RefreshSession returns the session a refresh token belongs to. auth_refresh_by_hash
// does not return it (it is a P0 function and the session id is not needed to
// decide between rotation and reuse), but the rotation of 3.4 must read that
// session in the same transaction. A refresh token of another tenant is not
// found: the query is scoped by tenant_id and by RLS.
func (t Tx) RefreshSession(refresh uuid.UUID) (uuid.UUID, bool, error) {
	var id uuid.UUID
	err := t.tx.QueryRow(t.ctx, qRefreshSession, t.tenant, refresh).Scan(&id)
	ok, err := notFound(err)
	return id, ok, err
}
