package endpoints

import (
	"context"
	"errors"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

func isConflict(err error) bool   { return errors.Is(err, store.ErrConflict) }
func isConstraint(err error) bool { return errors.Is(err, store.ErrConstraint) }

// CreateGroup adds an Endpoint group, and moves the named Endpoints into it (T-229). The tenant quota lock is first, the
// Endpoints are locked in id order before the one statement that writes them, and the cap of 100 groups is decided by the
// statement that adds the group. A group is not compiled, so nothing is marked.
func (e *Env) CreateGroup(ctx context.Context, st *store.Store, tenant uuid.UUID, opts store.TxOpts, name string, endpointIDs []uuid.UUID) (store.GroupRow, error) {
	if err := CheckGroupName(name); err != nil {
		return store.GroupRow{}, err
	}
	if len(endpointIDs) > MaxIDsPerBatch {
		return store.GroupRow{}, invalid(Field{"/endpoint_ids", CodeExceeded})
	}
	if len(endpointIDs) > 0 {
		if err := checkIDs(endpointIDs); err != nil {
			return store.GroupRow{}, invalid(Field{"/endpoint_ids", CodeDuplicate})
		}
	}
	var out store.GroupRow
	err := e.Plain(ctx, st, tenant, opts, func(tx store.Tx) error {
		if err := tx.QuotaLock(); err != nil {
			return err
		}
		if len(endpointIDs) > 0 {
			found, err := tx.EndpointsLock(endpointIDs)
			if err != nil {
				return err
			}
			if len(found) != len(endpointIDs) {
				return notFound()
			}
		}
		id, won, err := tx.GroupInsert(name)
		if err != nil {
			return err
		}
		if !won.Yes() {
			return invalid(Field{"max_endpoint_groups", CodeExceeded})
		}
		if len(endpointIDs) > 0 {
			if err := tx.EndpointsSetGroup(endpointIDs, id); err != nil {
				return err
			}
		}
		g, _, err := tx.GroupGet(id)
		out = g
		return err
	})
	return out, err
}

// RenameGroup renames a group of the tenant.
func (e *Env) RenameGroup(ctx context.Context, st *store.Store, tenant uuid.UUID, opts store.TxOpts, id uuid.UUID, name string) (store.GroupRow, error) {
	if err := CheckGroupName(name); err != nil {
		return store.GroupRow{}, err
	}
	var out store.GroupRow
	err := e.Plain(ctx, st, tenant, opts, func(tx store.Tx) error {
		ok, err := tx.GroupRename(id, name)
		if err != nil {
			return err
		}
		if !ok {
			return notFound()
		}
		out, _, err = tx.GroupGet(id)
		return err
	})
	return out, err
}

// DeleteGroup deletes a group: its Endpoints keep everything but the group (ON DELETE SET NULL), so they are locked in id
// order first, as the cascade writes them (spec 3.7 step 5).
func (e *Env) DeleteGroup(ctx context.Context, st *store.Store, tenant uuid.UUID, opts store.TxOpts, id uuid.UUID) error {
	return e.Plain(ctx, st, tenant, opts, func(tx store.Tx) error {
		if _, err := tx.GroupEndpointsLock(id); err != nil {
			return err
		}
		ok, err := tx.GroupDelete(id)
		if err != nil {
			return err
		}
		if !ok {
			return notFound()
		}
		return nil
	})
}
