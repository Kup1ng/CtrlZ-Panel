package ratelimit

import (
	"context"
	"fmt"

	"github.com/google/uuid"
)

// LocalBudget charges one class of the table to a tenant for work a process starts on its own, with no request in front of it
// (the worker's DDNS pass opens ip-claim requests for a host whose address changed). The bucket is the process's own and in
// memory: such a process sits on no Valkey zone. It lives in this package, beside the limiter, because the limiter is charged by
// the pipeline and by nothing else: a caller outside that holds a class by name and a tenant, and never a limiter to spend by
// hand under a key of its own choosing.
type LocalBudget struct {
	limiter *Limiter
	class   Class
}

// NewLocalBudget builds the budget of a class of a service. A class that is not in the table is an error at start-up, so a
// renamed class stops the process instead of leaving the work unmetered.
func NewLocalBudget(svc Service, class string) (*LocalBudget, error) {
	c, ok := Lookup(svc, class)
	if !ok {
		return nil, fmt.Errorf("ratelimit: the class %q is not in the table", class)
	}
	return &LocalBudget{limiter: New(Config{Service: svc, LocalOnly: true}), class: c}, nil
}

// Allow charges one unit of the class to the tenant.
func (b *LocalBudget) Allow(ctx context.Context, tenant uuid.UUID) (bool, error) {
	d, err := b.limiter.Allow(ctx, b.class, Subject{Tenant: tenant.String()})
	return d.Allowed, err
}
