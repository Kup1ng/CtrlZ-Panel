package api

import (
	"context"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/audit"
	"github.com/Kup1ng/CtrlZ-Panel/internal/caps"
	"github.com/Kup1ng/CtrlZ-Panel/internal/httpx"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// wantNoticeSMS says whether a security notice should also try to queue its SMS (question 19, spec 12.3). It is
// asked BEFORE the transaction: the cache may read the database, and the change must not hold row locks while
// it does. With no routed gateway nothing is queued and the change still goes through, the notice in the panel
// standing as the sign. A cache that cannot answer counts as "queue": a row waiting for a gateway is retried
// for an hour and ends failed, which costs less than a thief's change that nobody was told about.
func (s *Server) wantNoticeSMS(ctx context.Context) bool {
	cfg, err := s.cfg.Get(ctx)
	if err != nil {
		return true
	}
	return cfg.SMSAvailable
}

// noticeSMS queues the SMS of a security notice inside the transaction of the change it reports. It comes AFTER
// the audit row (the outbox ranks after the audit log, and the function counts that row). Its answer is not an
// error: a spent cap or a phone that was never verified queues nothing and the change stands.
func noticeSMS(tx store.Tx, user, notice uuid.UUID) error {
	_, err := tx.SecurityNoticeSMS(user, notice, caps.MaxNoticeSMS)
	return err
}

// recoveryCodesReplaced is what a set of recovery codes that takes the place of another leaves behind: the security
// notice, the audit row recovery.regenerate, and the SMS, in the transaction that stored the codes. Two routes make
// such a set, the regeneration and the confirm of a TOTP set-up of an account that had codes before (spec 12.3, D70),
// and a thief who passes either holds a set only they know, so both must tell the owner the same way. Replacing the
// codes does not move credential_gen, which is why a notice is the only sign.
//
// with are the audit rows of the change itself that belong before the regeneration row (the confirm's totp.enable).
// They are written here, after the notice, because the lock order puts notifications before the audit log
// (internal/lockrank), and the SMS comes after every audit row because the cap counts the recovery.regenerate row
// this call writes: one replaced set is one row, so it is counted once whatever else the route audits.
func recoveryCodesReplaced(tx store.Tx, user uuid.UUID, left int, sms bool, with ...audit.TenantEvent) error {
	noticeID, err := tx.SecurityNoticeAdd("recovery_codes_regenerated")
	if err != nil {
		return err
	}
	ip := httpx.ClientIPFrom(tx.Context())
	for _, ev := range with {
		if err := audit.Tenant(tx, user, ip, ev); err != nil {
			return err
		}
	}
	if err := audit.Tenant(tx, user, ip, audit.RecoveryRegenerate{Left: left}); err != nil {
		return err
	}
	if sms {
		return noticeSMS(tx, user, noticeID)
	}
	return nil
}
