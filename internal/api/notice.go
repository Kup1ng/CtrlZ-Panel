package api

import (
	"context"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/caps"
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
