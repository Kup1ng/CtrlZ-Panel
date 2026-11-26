package app

import (
	"context"
	"errors"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/ratelimit"
)

// ipClaimBudget charges the `ip-claim` class of a tenant (P3 4.5) for the DDNS job's claim requests. The class is the api's
// table row, so the numbers are the routes' (30 an hour). The worker sits on no Valkey zone, so the bucket is the worker's own,
// in process: it bounds how fast a host whose address keeps changing can open claims, which is what the class is for, and
// it is not shared with the api's count of the same tenant's requests by hand.
type ipClaimBudget struct {
	limiter *ratelimit.Limiter
	class   ratelimit.Class
}

func newIPClaimBudget() (ipClaimBudget, error) {
	c, ok := ratelimit.Lookup(ratelimit.Tenant, ratelimit.IPClaim)
	if !ok {
		return ipClaimBudget{}, errors.New("app: the ip-claim class is not in the table")
	}
	return ipClaimBudget{limiter: ratelimit.New(ratelimit.Config{Service: ratelimit.Tenant, LocalOnly: true}), class: c}, nil
}

// Allow charges one request.
func (b ipClaimBudget) Allow(ctx context.Context, tenant uuid.UUID) (bool, error) {
	d, err := b.limiter.Allow(ctx, b.class, ratelimit.Subject{Tenant: tenant.String()})
	return d.Allowed, err
}
