package store_test

import (
	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// activate gives a gateway ACTIVE credentials the way the product does since round 18 (admin-r18-1):
// they are staged as pending, as the PUT route does, and made active as the console does. A test that
// needs a gateway that can send and be routed to calls this and not a write of its own, so the only
// path to credentials_ct it uses is the one the product has.
func activate(g store.GlobalTx, id uuid.UUID, provider string, ct []byte, hint string) (bool, error) {
	if ok, err := g.SMSGatewayStageCredentials(id, ct, hint); err != nil || !ok {
		return false, err
	}
	_, ok, err := g.SMSGatewayConfirmCredentials(provider, hint)
	return ok, err
}
