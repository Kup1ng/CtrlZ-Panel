package endpoints

import (
	"context"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// Public lets the tests of endpoints_test run the transaction of a public route with a body of their own.
func (e *Env) Public(ctx context.Context, st *store.Store, tenant uuid.UUID, opts store.TxOpts, body func(tx store.Tx) error) error {
	return e.public(ctx, st, tenant, opts, body)
}
