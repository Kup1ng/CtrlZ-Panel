package session

import (
	"context"
	"net/netip"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/audit"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/token"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// RefreshOutcome is the answer of Refresh. The route maps it: Rotated sends the
// new cookies with 204, Grace sends 204 with no cookies, Expired and Reuse clear
// the cookies and answer 401 session_expired.
type RefreshOutcome int

const (
	RefreshExpired RefreshOutcome = iota // unknown, revoked, expired, or its session is gone
	RefreshRotated                       // a new token pair was issued
	RefreshGrace                         // a concurrent tab already rotated it, within the grace window
	RefreshReuse                         // an old token came back after the grace: the family and session were revoked
)

// RefreshResult is the outcome and, for RefreshRotated, the new tokens.
type RefreshResult struct {
	Outcome RefreshOutcome
	Issued  Issued
}

// Refresh implements POST /auth/refresh (spec 3.4). The refresh cookie alone is
// enough to ask, because after a browser restart it is all that is left.
//
// Rotation is one transaction: the old token is marked rotated and given a 10
// second grace, a new token of the same family is inserted, and the session gets
// a new token, a fresh idle limit and no reauth window, so a refresh never
// inherits one. The grace exists for two tabs refreshing together: the second
// request finds the token rotated and gets 204 without cookies, and its client
// retries with the cookies the first response set. After the grace the same
// token is a thief's, and the whole family and its session end.
func (m *Manager) Refresh(ctx context.Context, cookie string, ip netip.Addr) (RefreshResult, error) {
	if _, _, ok := m.ScreenRefresh(cookie); !ok {
		return RefreshResult{Outcome: RefreshExpired}, nil
	}
	info, ok, err := m.db.Auth().RefreshByHash(ctx, token.HashString(cookie))
	if err != nil {
		return RefreshResult{}, err
	}
	now := m.now()
	if !ok || info.RevokedAt != nil || !info.ExpiresAt.After(now) {
		return RefreshResult{Outcome: RefreshExpired}, nil
	}
	if info.RotatedAt != nil {
		return m.rotatedAlready(ctx, info, ip)
	}

	var res RefreshResult
	err = m.db.WithTenant(ctx, info.TenantID, store.TxOpts{}, func(tx store.Tx) error {
		// The users row first, the order every credential writer uses (4.4): the new
		// refresh row takes FOR KEY SHARE on it through its foreign key, so asking for
		// it after the session lock would wait behind a writer that holds the user and
		// wants this session (db-r4-1).
		if live, err := tx.UserKeyShare(info.UserID); err != nil {
			return err
		} else if !live {
			res = RefreshResult{Outcome: RefreshExpired}
			return nil
		}
		session, found, err := tx.RefreshSession(info.ID)
		if err != nil {
			return err
		}
		if !found {
			res = RefreshResult{Outcome: RefreshExpired}
			return nil
		}
		// The session row is locked first, as Rotate and the revoke paths do (4.4), so
		// two tabs and a reauth in flight cannot hold each other's rows.
		row, found, err := tx.SessionByIDForUpdate(session)
		if err != nil {
			return err
		}
		// The session must be the refresh row's user's. The foreign key refresh_tokens
		// (tenant_id, user_id, session_id) -> sessions (tenant_id, user_id, id) makes a
		// mismatch impossible to store (0026), and this compares them anyway: the key
		// share, the new refresh row and the audit event all name info.UserID, and a
		// row that named another user would rotate that user's session under the wrong
		// name. Refusing is the same answer as a dead session.
		if !found || row.UserID != info.UserID || row.RevokedAt != nil || !row.AbsoluteExpiresAt.After(now) {
			res = RefreshResult{Outcome: RefreshExpired}
			return nil
		}
		// The rotate UPDATE comes after the session read so a dead session costs no
		// write; the UPDATE's own predicate (rotated_at IS NULL) is what decides a
		// race between two tabs.
		won, err := tx.RefreshRotate(info.ID, now.Add(m.pol.ReuseGrace), now)
		if err != nil {
			return err
		}
		if !won {
			// Zero rows is either a concurrent tab (rotated: grace) or a token that a
			// reauth or log out all revoked in the meantime. The second client must
			// sign in again; telling it "grace" would send it back with a cookie that
			// is dead.
			revoked, err := tx.RefreshRevoked(info.ID)
			if err != nil {
				return err
			}
			if revoked {
				res = RefreshResult{Outcome: RefreshExpired}
			} else {
				res = RefreshResult{Outcome: RefreshGrace}
			}
			return nil
		}
		iss := Issued{SessionID: session}
		tok, err := m.newSessionToken(audienceTenant, row.AbsoluteExpiresAt, session)
		if err != nil {
			return err
		}
		iss.Session = tok
		ok, err := tx.SessionRefreshToken(session, token.Hash(tok), capTime(now.Add(m.pol.Idle), row.AbsoluteExpiresAt), now)
		if err != nil {
			return err
		}
		if !ok {
			res = RefreshResult{Outcome: RefreshExpired}
			return nil
		}
		// Same family: reuse detection follows a family across rotations.
		if err := m.addRefresh(tx, &iss, info.UserID, info.FamilyID, row.AbsoluteExpiresAt, now); err != nil {
			return err
		}
		res = RefreshResult{Outcome: RefreshRotated, Issued: iss}
		return nil
	})
	if err != nil {
		return RefreshResult{}, err
	}
	return res, nil
}

// rotatedAlready decides between a concurrent tab and reuse for a token that was
// rotated.
func (m *Manager) rotatedAlready(ctx context.Context, info store.RefreshInfo, ip netip.Addr) (RefreshResult, error) {
	if info.ReuseGraceUntil != nil && !m.now().After(*info.ReuseGraceUntil) {
		return RefreshResult{Outcome: RefreshGrace}, nil
	}
	err := m.db.WithTenant(ctx, info.TenantID, store.TxOpts{}, func(tx store.Tx) error {
		if err := tx.RefreshRevokeFamily(info.FamilyID); err != nil {
			return err
		}
		return audit.Tenant(tx, info.UserID, ip, audit.RefreshReuse{FamilyID: info.FamilyID})
	})
	if err != nil {
		return RefreshResult{}, err
	}
	return RefreshResult{Outcome: RefreshReuse}, nil
}
