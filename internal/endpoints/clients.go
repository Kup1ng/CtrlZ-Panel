package endpoints

import (
	"context"
	"slices"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// ClientCreate is a manual (custom) client: a name for a device or a group of them (T-258, D8). hostname, mac and ip are
// the app's, later, and no request sets them.
type ClientCreate struct {
	Label               string
	Alias               string
	GroupName           string
	ProfileID           uuid.UUID
	Profile2ID          uuid.UUID
	AnalyticsLevel      string
	ConfirmDestinations bool
}

func checkClientValues(alias, group, analytics string, p, p2 uuid.UUID) []Field {
	var fs []Field
	if tooLong(alias, AliasLimit) {
		fs = append(fs, Field{"/alias", CodeTooLong})
	}
	if tooLong(group, AliasLimit) {
		fs = append(fs, Field{"/group_name", CodeTooLong})
	}
	if analytics != "" && !inSet(analytics, analyticsLevels()) {
		fs = append(fs, Field{"/analytics_level", CodeInvalid})
	}
	switch {
	case p2 != uuid.Nil && p == uuid.Nil:
		fs = append(fs, Field{"/profile_id", CodeRequired})
	case p2 != uuid.Nil && p2 == p:
		fs = append(fs, Field{"/profile2_id", CodeSameProfile})
	}
	return fs
}

// stackChanged says a client row moved something the compiler reads: a client with a profile or an Analytics level of its
// own is a record (spec 3.2).
func clientCompiled(r store.ClientRow) bool {
	return r.ProfileID != uuid.Nil || r.AnalyticsLevel != nil
}

// clientCompiledDiffers says an edit moved a value the compiler reads: the client's profiles and its Analytics level. The
// alias and the group name are not compiled (spec 3.2), so renaming a client that has a profile marks nothing.
func clientCompiledDiffers(a, b store.ClientRow) bool {
	return a.ProfileID != b.ProfileID || a.Profile2ID != b.Profile2ID || !sameText(a.AnalyticsLevel, b.AnalyticsLevel)
}

// sameClientValues says the change leaves every member the owner can change as it was.
func sameClientValues(a, b store.ClientRow) bool {
	return !clientCompiledDiffers(a, b) && sameText(a.Alias, b.Alias) && sameText(a.GroupName, b.GroupName)
}

func sameText(a, b *string) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

// CreateClient adds a manual client to an Endpoint, under the Endpoint's row: max_clients_per_endpoint is decided by the
// statement that adds it and counts the manual clients of that Endpoint. Giving a client its own stack removes the Endpoint's
// stack from that label, which needs the lock passwords of spec 3.3.
func (e *Env) CreateClient(ctx context.Context, st *store.Store, tenant uuid.UUID, opts store.TxOpts, a Auth, endpoint uuid.UUID, in ClientCreate) (store.ClientRow, error) {
	var fs []Field
	label, lf := ClientLabel(in.Label, in.Alias)
	if lf != nil {
		fs = append(fs, *lf)
	}
	fs = append(fs, checkClientValues(in.Alias, in.GroupName, in.AnalyticsLevel, in.ProfileID, in.Profile2ID)...)
	if fs != nil {
		return store.ClientRow{}, invalid(fs...)
	}
	named := uniqueIDs([]uuid.UUID{in.ProfileID, in.Profile2ID})
	members := map[uuid.UUID]string{in.ProfileID: "/profile_id", in.Profile2ID: "/profile2_id"}
	var out store.ClientRow
	err := e.Run(ctx, st, tenant, opts, a, func(tx store.Tx, g *Guard) error {
		if err := g.Begin(tx, []uuid.UUID{endpoint}, named...); err != nil {
			return err
		}
		found, err := tx.EndpointsLock([]uuid.UUID{endpoint})
		if err != nil {
			return err
		}
		if len(found) != 1 {
			return notFound()
		}
		before, err := g.InputsFor(tx, []uuid.UUID{endpoint}, []string{label})
		if err != nil {
			return err
		}
		d, err := e.watchProfiles(tx, append(slices.Clone(named), before[endpoint].Profiles()...), members)
		if err != nil {
			return err
		}
		id, won, err := tx.ClientInsert(store.ClientNew{Endpoint: endpoint, Label: label, Alias: in.Alias, GroupName: in.GroupName,
			ProfileID: in.ProfileID, Profile2ID: in.Profile2ID, AnalyticsLevel: in.AnalyticsLevel})
		switch {
		case isConflict(err):
			return invalid(Field{"/label", CodeExists})
		case err != nil:
			return err
		case !won.Yes():
			return invalid(Field{"max_clients_per_endpoint", CodeExceeded})
		}
		after, err := g.InputsFor(tx, []uuid.UUID{endpoint}, []string{label})
		if err != nil {
			return err
		}
		if err := d.check(in.ConfirmDestinations); err != nil {
			return err
		}
		if err := g.Check(tx, before, after); err != nil {
			return err
		}
		c, _, err := tx.ClientGet(endpoint, id)
		if err != nil {
			return err
		}
		if clientCompiled(c) {
			if err := store.MarkDirty(tx, store.AggregateEndpointSet, tx.TenantID()); err != nil {
				return err
			}
		}
		out = c
		return nil
	})
	return out, err
}

// ClientChange is the change of a client: a nil member is unchanged and a Clear names the members that go back to none.
// Clearing the enforced profile clears Profile 2 with it (the table refuses a Profile 2 alone).
type ClientChange struct {
	Alias               *string
	GroupName           *string
	ProfileID           *uuid.UUID
	Profile2ID          *uuid.UUID
	AnalyticsLevel      *string
	ClearAlias          bool
	ClearGroupName      bool
	ClearProfile        bool
	ClearProfile2       bool
	ClearAnalytics      bool
	ConfirmDestinations bool
}

func (c ClientChange) named() []uuid.UUID {
	var out []uuid.UUID
	if c.ProfileID != nil {
		out = append(out, *c.ProfileID)
	}
	if c.Profile2ID != nil {
		out = append(out, *c.Profile2ID)
	}
	return out
}

func (c ClientChange) empty() bool {
	return c.Alias == nil && c.GroupName == nil && c.ProfileID == nil && c.Profile2ID == nil && c.AnalyticsLevel == nil &&
		!c.ClearAlias && !c.ClearGroupName && !c.ClearProfile && !c.ClearProfile2 && !c.ClearAnalytics
}

// pre checks the values of a change that need no row.
func (c ClientChange) pre(prefix string) []Field {
	var fs []Field
	at := func(m string) string { return prefix + "/" + m }
	if c.Alias != nil && tooLong(*c.Alias, AliasLimit) {
		fs = append(fs, Field{at("alias"), CodeTooLong})
	}
	if c.GroupName != nil && tooLong(*c.GroupName, AliasLimit) {
		fs = append(fs, Field{at("group_name"), CodeTooLong})
	}
	if c.AnalyticsLevel != nil && !inSet(*c.AnalyticsLevel, analyticsLevels()) {
		fs = append(fs, Field{at("analytics_level"), CodeInvalid})
	}
	return fs
}

// apply changes the row and returns what the result refuses.
func (c ClientChange) apply(r *store.ClientRow, prefix string) []Field {
	at := func(m string) string { return prefix + "/" + m }
	switch {
	case c.ClearAlias:
		r.Alias = nil
	case c.Alias != nil:
		v := *c.Alias
		r.Alias = &v
	}
	switch {
	case c.ClearGroupName:
		r.GroupName = nil
	case c.GroupName != nil:
		v := *c.GroupName
		r.GroupName = &v
	}
	switch {
	case c.ClearProfile:
		r.ProfileID, r.Profile2ID = uuid.Nil, uuid.Nil
	case c.ProfileID != nil:
		r.ProfileID = *c.ProfileID
	}
	switch {
	case c.ClearProfile2:
		r.Profile2ID = uuid.Nil
	case c.Profile2ID != nil:
		r.Profile2ID = *c.Profile2ID
	}
	switch {
	case c.ClearAnalytics:
		r.AnalyticsLevel = nil
	case c.AnalyticsLevel != nil:
		v := *c.AnalyticsLevel
		r.AnalyticsLevel = &v
	}
	var fs []Field
	switch {
	case r.Profile2ID != uuid.Nil && r.ProfileID == uuid.Nil:
		fs = append(fs, Field{at("profile_id"), CodeRequired})
	case r.Profile2ID != uuid.Nil && r.Profile2ID == r.ProfileID:
		fs = append(fs, Field{at("profile2_id"), CodeSameProfile})
	}
	return fs
}

// editClients is the body shared by the patch of one client and the batch edit: the clients are locked first (step 3), the
// profiles the change names next, the Endpoint's row after them.
func (e *Env) editClients(ctx context.Context, st *store.Store, tenant uuid.UUID, opts store.TxOpts, a Auth, endpoint uuid.UUID,
	lock func(tx store.Tx) ([]store.ClientRow, bool, error), change ClientChange, del bool, prefix func(i int) string, fin func(tx store.Tx) error) (affected int, more bool, err error) {
	named := uniqueIDs(change.named())
	members := map[uuid.UUID]string{}
	if change.ProfileID != nil {
		members[*change.ProfileID] = prefix(-1) + "/profile_id"
	}
	if change.Profile2ID != nil {
		members[*change.Profile2ID] = prefix(-1) + "/profile2_id"
	}
	err = e.Run(ctx, st, tenant, opts, a, func(tx store.Tx, g *Guard) error {
		affected, more = 0, false
		rows, hasMore, err := lock(tx)
		if err != nil {
			return err
		}
		if err := g.Begin(tx, []uuid.UUID{endpoint}, append(slices.Clone(named), clientProfiles(rows)...)...); err != nil {
			return err
		}
		found, err := tx.EndpointsLock([]uuid.UUID{endpoint})
		if err != nil {
			return err
		}
		if len(found) != 1 {
			return notFound()
		}
		before, err := g.InputsFor(tx, []uuid.UUID{endpoint}, clientLabels(rows))
		if err != nil {
			return err
		}
		d, err := e.watchProfiles(tx, append(slices.Clone(named), before[endpoint].Profiles()...), members)
		if err != nil {
			return err
		}
		mark := false
		var fs []Field
		ids := make([]uuid.UUID, len(rows))
		for i, r := range rows {
			ids[i] = r.ID
			if del {
				// A client that held a record goes with it.
				if clientCompiled(r) {
					mark = true
				}
				continue
			}
			nr := r
			fs = append(fs, change.apply(&nr, prefix(i))...)
			if clientCompiledDiffers(r, nr) {
				mark = true
			}
			if fs == nil && !sameClientValues(r, nr) {
				if err := tx.ClientUpdate(nr); err != nil {
					return err
				}
			}
		}
		if fs != nil {
			return invalid(fs...)
		}
		if del && len(ids) > 0 {
			if err := tx.ClientsDelete(endpoint, ids); err != nil {
				return err
			}
		}
		after, err := g.InputsFor(tx, []uuid.UUID{endpoint}, clientLabels(rows))
		if err != nil {
			return err
		}
		if err := d.check(change.ConfirmDestinations); err != nil {
			return err
		}
		if err := g.Check(tx, before, after); err != nil {
			return err
		}
		if mark {
			if err := store.MarkDirty(tx, store.AggregateEndpointSet, tx.TenantID()); err != nil {
				return err
			}
		}
		if fin != nil {
			// Read inside the transaction that wrote, so the answer is the row this request left and not what a later request made of it.
			if err := fin(tx); err != nil {
				return err
			}
		}
		affected, more = len(rows), hasMore
		return nil
	})
	return affected, more, err
}

// PatchClient changes one client of an Endpoint.
func (e *Env) PatchClient(ctx context.Context, st *store.Store, tenant uuid.UUID, opts store.TxOpts, a Auth, endpoint, client uuid.UUID, c ClientChange) (store.ClientRow, error) {
	if fs := c.pre(""); fs != nil {
		return store.ClientRow{}, invalid(fs...)
	}
	var out store.ClientRow
	_, _, err := e.editClients(ctx, st, tenant, opts, a, endpoint, func(tx store.Tx) ([]store.ClientRow, bool, error) {
		rows, err := tx.ClientsLockIDs(endpoint, []uuid.UUID{client})
		if err != nil {
			return nil, false, err
		}
		if len(rows) != 1 {
			return nil, false, notFound()
		}
		return rows, false, nil
	}, c, false, func(int) string { return "" }, func(tx store.Tx) error {
		row, found, err := tx.ClientGet(endpoint, client)
		if err != nil {
			return err
		}
		if !found {
			return notFound()
		}
		out = row
		return nil
	})
	if err != nil {
		return store.ClientRow{}, err
	}
	return out, nil
}

// ClientBatchIn is a batch over the clients of one Endpoint: named by ids, or by a selector (T-259).
type ClientBatchIn struct {
	// Op is "edit" or "delete".
	Op  string
	IDs []uuid.UUID
	// Selector: exactly one of IDs and the selector. InactiveDays is 1 to 3650; All selects every client.
	InactiveDays int
	All          bool
	Change       ClientChange
}

// BatchClients runs a batch over the clients of one Endpoint. Over a selector it resolves at most 500 clients in the write
// transaction, under their locks, and says whether matches remain, so the caller repeats.
func (e *Env) BatchClients(ctx context.Context, st *store.Store, tenant uuid.UUID, opts store.TxOpts, a Auth, endpoint uuid.UUID, in ClientBatchIn) (affected int, more bool, err error) {
	var fs []Field
	switch {
	case len(in.IDs) > 0 && (in.InactiveDays != 0 || in.All):
		fs = append(fs, Field{"/selector", CodeInvalid})
	case len(in.IDs) == 0 && in.InactiveDays == 0 && !in.All:
		fs = append(fs, Field{"/ids", CodeRequired})
	case len(in.IDs) > MaxIDsPerBatch:
		fs = append(fs, Field{"/ids", CodeExceeded})
	case in.InactiveDays != 0 && in.All:
		fs = append(fs, Field{"/selector", CodeInvalid})
	case in.InactiveDays < 0 || in.InactiveDays > 3650:
		fs = append(fs, Field{"/selector/inactive_days", CodeOutOfRange})
	}
	if in.Op != "edit" && in.Op != "delete" {
		fs = append(fs, Field{"/op", CodeInvalid})
	}
	if in.Op == "edit" {
		if in.Change.empty() {
			fs = append(fs, Field{"/set", CodeRequired})
		}
		fs = append(fs, in.Change.pre("/set")...)
	}
	if fs != nil {
		return 0, false, invalid(fs...)
	}
	if len(in.IDs) > 0 {
		if err := checkIDs(in.IDs); err != nil {
			return 0, false, err
		}
	}
	now := e.now()
	lock := func(tx store.Tx) ([]store.ClientRow, bool, error) {
		if len(in.IDs) > 0 {
			rows, err := tx.ClientsLockIDs(endpoint, in.IDs)
			if err != nil {
				return nil, false, err
			}
			if len(rows) != len(in.IDs) {
				return nil, false, notFound()
			}
			return rows, false, nil
		}
		// An edit by selector acts on the clients the change would alter and skips those that already hold the values. Without
		// that, the repeat that "more" asks for would select the same first 500 again (the selector orders by id and an edit
		// moves neither id nor the inactivity), the rest would never be reached and "more" would stay true. A delete takes every
		// match, since a deleted client is not selected again.
		var picked []store.ClientRow
		after := uuid.Nil
		for {
			page, err := tx.ClientsLockSelector(endpoint, in.InactiveDays, now, after, store.MaxClientsPerSelector+1)
			if err != nil {
				return nil, false, err
			}
			for _, r := range page {
				if in.Op == "edit" {
					nr := r
					in.Change.apply(&nr, "/set")
					if sameClientValues(r, nr) {
						continue
					}
				}
				picked = append(picked, r)
				if len(picked) > store.MaxClientsPerSelector {
					return picked[:store.MaxClientsPerSelector], true, nil
				}
			}
			if len(page) <= store.MaxClientsPerSelector {
				return picked, false, nil
			}
			after = page[len(page)-1].ID
		}
	}
	return e.editClients(ctx, st, tenant, opts, a, endpoint, lock, in.Change, in.Op == "delete", func(int) string { return "/set" }, nil)
}

// clientProfiles lists the profiles the clients hold now, which the write key-shares before the Endpoint's lock (Guard.Begin).
func clientProfiles(rows []store.ClientRow) []uuid.UUID {
	var out []uuid.UUID
	for _, r := range rows {
		out = append(out, r.ProfileID, r.Profile2ID)
	}
	return out
}

// clientLabels lists the labels of the clients a write touches: Guard.InputsFor reads those one by one and every other client of
// the Endpoint as distinct stacks, so what the stack check sees of the rows the write changes is exact (p3-D6-r1-8).
func clientLabels(rows []store.ClientRow) []string {
	out := make([]string, len(rows))
	for i, r := range rows {
		out[i] = r.Label
	}
	return out
}
