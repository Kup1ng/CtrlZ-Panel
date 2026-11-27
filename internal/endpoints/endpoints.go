package endpoints

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Shared/identity"

	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// TokenAAD is the context a DoH token is sealed under: the Endpoint's id (spec 8.1), so a ciphertext copied to another row
// does not open.
func TokenAAD(endpoint uuid.UUID) keyring.Context { return keyring.RowContext([]uuid.UUID{endpoint}) }

// credential draws a resolver id and a DoH token for the Endpoint and seals the token. The token itself never leaves this
// function: only its ciphertext and the hash the node compares.
func (e *Env) credential(id uuid.UUID) (resolverID string, ct, hash []byte, err error) {
	if e.Keys == nil {
		return "", nil, nil, errors.New("endpoints: no key ring")
	}
	if resolverID, err = identity.NewResolverID(); err != nil {
		return "", nil, nil, fmt.Errorf("endpoints: resolver id: %w", err)
	}
	token, err := identity.NewDoHToken()
	if err != nil {
		return "", nil, nil, fmt.Errorf("endpoints: doh token: %w", err)
	}
	if ct, err = e.Keys.Seal(keyring.DomainDOHToken, TokenAAD(id), []byte(token)); err != nil {
		return "", nil, nil, fmt.Errorf("endpoints: seal doh token: %w", err)
	}
	h := identity.TokenHash(token)
	return resolverID, ct, h[:], nil
}

// ---------------------------------------------------------------------------
// Create.

// CreateIn is a create: one Endpoint per name, all with the same values (T-220).
type CreateIn struct {
	Type                string
	Names               []string
	ProfileID           uuid.UUID
	Profile2ID          uuid.UUID
	GroupID             uuid.UUID
	AnalyticsLevel      string
	Comment             string
	LegacyDNS           bool
	AuthorizeSecureDNS  bool
	AuthorizeDDNS       bool
	ExposeIP            bool
	PreventDeactivation bool
	ConfirmDestinations bool
}

func (in CreateIn) check(known bool) *Error {
	var fs []Field
	if len(in.Names) == 0 {
		fs = append(fs, Field{"/names", CodeRequired})
	} else if len(in.Names) > MaxNamesPerCreate {
		fs = append(fs, Field{"/names", CodeExceeded})
	}
	for i, n := range in.Names {
		if i >= MaxNamesPerCreate {
			break
		}
		if f := checkName(n, fmt.Sprintf("/names/%d", i)); f != nil {
			fs = append(fs, *f)
		}
	}
	if !known {
		fs = append(fs, Field{"/type", CodeUnknown})
	}
	if in.ProfileID == uuid.Nil {
		fs = append(fs, Field{"/profile_id", CodeRequired})
	} else if in.Profile2ID == in.ProfileID {
		fs = append(fs, Field{"/profile2_id", CodeSameProfile})
	}
	if in.AnalyticsLevel != "" && !inSet(in.AnalyticsLevel, analyticsLevels()) {
		fs = append(fs, Field{"/analytics_level", CodeInvalid})
	}
	if tooLong(in.Comment, CommentLimit) {
		fs = append(fs, Field{"/comment", CodeTooLong})
	}
	if fs != nil {
		return invalid(fs...)
	}
	return nil
}

// Create adds one Endpoint per name in one transaction (T-220, T-222). The tenant quota lock is the first lock, the profiles
// are key-shared before any row is added, and max_endpoints is decided by the statement that adds them all: a request that
// would pass it adds none.
func (e *Env) CreateTx(tx store.Tx, in CreateIn) ([]store.EndpointRow, error) {
	known, err := tx.EndpointTypeKnown(in.Type)
	if err != nil {
		return nil, err
	}
	if err := in.check(known); err != nil {
		return nil, err
	}
	analytics := in.AnalyticsLevel
	if analytics == "" {
		analytics = "full"
	}
	var out []store.EndpointRow
	err = func() error {
		if err := tx.QuotaLock(); err != nil {
			return err
		}
		named := uniqueIDs([]uuid.UUID{in.ProfileID, in.Profile2ID})
		found, err := tx.ProfilesKeyShare(named)
		if err != nil {
			return err
		}
		if len(found) != len(named) {
			return notFound()
		}
		if in.GroupID != uuid.Nil {
			ok, err := tx.GroupKeyShare(in.GroupID)
			if err != nil {
				return err
			}
			if !ok {
				return notFound()
			}
		}
		d, err := e.watchProfiles(tx, named, map[uuid.UUID]string{in.ProfileID: "/profile_id", in.Profile2ID: "/profile2_id"})
		if err != nil {
			return err
		}
		rows := make([]store.EndpointNew, len(in.Names))
		for i, name := range in.Names {
			id, err := uuid.NewV7()
			if err != nil {
				return fmt.Errorf("endpoints: id: %w", err)
			}
			rid, ct, hash, err := e.credential(id)
			if err != nil {
				return err
			}
			rows[i] = store.EndpointNew{ID: id, Name: name, ResolverID: rid, TokenCT: ct, TokenHash: hash, Type: in.Type, GroupID: in.GroupID,
				Comment: in.Comment, ProfileID: in.ProfileID, Profile2ID: in.Profile2ID, AnalyticsLevel: analytics, LegacyDNS: in.LegacyDNS,
				AuthorizeSecureDNS: in.AuthorizeSecureDNS, AuthorizeDDNS: in.AuthorizeDDNS, ExposeIP: in.ExposeIP,
				PreventDeactivation: in.PreventDeactivation, ScheduleTimezone: DefaultTimezone}
		}
		ids, won, err := tx.EndpointsInsert(rows)
		switch {
		case errors.Is(err, store.ErrConflict):
			return &Error{Kind: KindConflict} // a resolver id that exists: drawn again by the client's retry
		case err != nil:
			return err
		case !won.Yes():
			return invalid(Field{"max_endpoints", CodeExceeded})
		}
		if err := d.check(in.ConfirmDestinations); err != nil {
			return err
		}
		if err := store.MarkDirty(tx, store.AggregateEndpointSet, tx.TenantID()); err != nil {
			return err
		}
		out, err = tx.EndpointsGet(ids)
		return err
	}()
	return out, err
}

// Create is CreateTx in a transaction of its own.
func (e *Env) Create(ctx context.Context, st *store.Store, tenant uuid.UUID, opts store.TxOpts, in CreateIn) (out []store.EndpointRow, err error) {
	err = e.Plain(ctx, st, tenant, opts, func(tx store.Tx) (err error) {
		out, err = e.CreateTx(tx, in)
		return err
	})
	return out, err
}

// ---------------------------------------------------------------------------
// Update: Patch, batch move and batch edit.

// Patch is the change of one Endpoint (spec 9.3). A nil member is unchanged. Clear names the members that go back to none.
type Patch struct {
	Name                 *string
	Type                 *string
	GroupID              *uuid.UUID
	ProfileID            *uuid.UUID
	Profile2ID           *uuid.UUID
	AnalyticsLevel       *string
	Comment              *string
	LegacyDNS            *bool
	AuthorizeSecureDNS   *bool
	AuthorizeDDNS        *bool
	ExposeIP             *bool
	PreventDeactivation  *bool
	AdminState           *string
	RequireAuthorizedIPs *bool
	ScheduleTimezone     *string
	ClearGroup           bool
	ClearProfile2        bool
	ClearComment         bool
	ConfirmDestinations  bool
}

// pre checks what needs no row: the values of the members. prefix is the JSON pointer of the object that holds them.
func (p Patch) pre(prefix string, typeKnown bool) []Field {
	var fs []Field
	at := func(m string) string { return prefix + "/" + m }
	if p.Name != nil {
		if f := checkName(*p.Name, at("name")); f != nil {
			fs = append(fs, *f)
		}
	}
	if p.Type != nil && !typeKnown {
		fs = append(fs, Field{at("type"), CodeUnknown})
	}
	if p.Comment != nil && tooLong(*p.Comment, CommentLimit) {
		fs = append(fs, Field{at("comment"), CodeTooLong})
	}
	if p.AnalyticsLevel != nil && !inSet(*p.AnalyticsLevel, analyticsLevels()) {
		fs = append(fs, Field{at("analytics_level"), CodeInvalid})
	}
	if p.AdminState != nil && !inSet(*p.AdminState, adminStates()) {
		fs = append(fs, Field{at("admin_state"), CodeInvalid})
	}
	if p.ScheduleTimezone != nil && !ValidZone(*p.ScheduleTimezone) {
		fs = append(fs, Field{at("schedule_timezone"), CodeUnknown})
	}
	if p.ProfileID != nil && *p.ProfileID == uuid.Nil {
		fs = append(fs, Field{at("profile_id"), CodeRequired})
	}
	if p.Profile2ID != nil && p.ClearProfile2 {
		fs = append(fs, Field{at("profile2_id"), CodeInvalid})
	}
	return fs
}

// named are the profiles the patch names, which the write key-shares before any Endpoint lock.
func (p Patch) named() []uuid.UUID {
	var out []uuid.UUID
	if p.ProfileID != nil {
		out = append(out, *p.ProfileID)
	}
	if p.Profile2ID != nil {
		out = append(out, *p.Profile2ID)
	}
	return out
}

// apply changes the row and returns the refusals the row decides (spec 3.8). prefix is as for pre.
func (p Patch) apply(r *store.EndpointRow, prefix string) []Field {
	var fs []Field
	at := func(m string) string { return prefix + "/" + m }
	if p.Name != nil {
		r.Name = *p.Name
	}
	if p.Type != nil {
		r.Type = *p.Type
	}
	switch {
	case p.ClearGroup:
		r.GroupID = uuid.Nil
	case p.GroupID != nil:
		r.GroupID = *p.GroupID
	}
	if p.ProfileID != nil {
		r.ProfileID = *p.ProfileID
	}
	switch {
	case p.ClearProfile2:
		r.Profile2ID = uuid.Nil
	case p.Profile2ID != nil:
		r.Profile2ID = *p.Profile2ID
	}
	if r.Profile2ID != uuid.Nil && r.Profile2ID == r.ProfileID {
		name := at("profile2_id")
		if p.Profile2ID == nil && p.ProfileID != nil {
			name = at("profile_id")
		}
		fs = append(fs, Field{name, CodeSameProfile})
	}
	if p.AnalyticsLevel != nil {
		r.AnalyticsLevel = *p.AnalyticsLevel
	}
	switch {
	case p.ClearComment:
		r.Comment = nil
	case p.Comment != nil:
		c := *p.Comment
		r.Comment = &c
	}
	setBool := func(dst *bool, src *bool) {
		if src != nil {
			*dst = *src
		}
	}
	setBool(&r.LegacyDNS, p.LegacyDNS)
	setBool(&r.AuthorizeSecureDNS, p.AuthorizeSecureDNS)
	setBool(&r.AuthorizeDDNS, p.AuthorizeDDNS)
	setBool(&r.ExposeIP, p.ExposeIP)
	setBool(&r.PreventDeactivation, p.PreventDeactivation)
	if p.AdminState != nil {
		r.AdminState = *p.AdminState
	}
	if p.RequireAuthorizedIPs != nil {
		if *p.RequireAuthorizedIPs && !r.RequireAuthorizedIPs && r.AuthorizedIPs == 0 {
			fs = append(fs, Field{at("require_authorized_ips"), CodeNeedsAuthorizedIP})
		}
		r.RequireAuthorizedIPs = *p.RequireAuthorizedIPs
	}
	if p.ScheduleTimezone != nil {
		r.ScheduleTimezone = *p.ScheduleTimezone
	}
	return fs
}

func cols(r store.EndpointRow) EndpointCols {
	return EndpointCols{ProfileID: r.ProfileID, Profile2ID: r.Profile2ID, AdminState: r.AdminState, LegacyDNS: r.LegacyDNS,
		RequireAuthorizedIPs: r.RequireAuthorizedIPs, ExposeIP: r.ExposeIP, AuthorizeSecureDNS: r.AuthorizeSecureDNS,
		AnalyticsLevel: r.AnalyticsLevel, ScheduleTimezone: r.ScheduleTimezone}
}

// awayOf is what a change does to the identities (spec 3.3): switching to Soft or Hard Disabled from any other value, and
// turning Require Authorized IPs on, turn every identity away.
func awayOf(old, now store.EndpointRow) Away {
	if now.AdminState != old.AdminState && now.AdminState != "enabled" {
		return AwayAll
	}
	if now.RequireAuthorizedIPs && !old.RequireAuthorizedIPs {
		return AwayAll
	}
	return AwayNone
}

// update is the body shared by Patch and the batch moves and edits: every Endpoint of ids gets the same change, one
// transaction, one probe.
func (e *Env) update(ctx context.Context, st *store.Store, tenant uuid.UUID, opts store.TxOpts, a Auth, ids []uuid.UUID,
	prefix func(i int) string, patch Patch, extraNamed []uuid.UUID) ([]store.EndpointRow, error) {
	var out []store.EndpointRow
	named := uniqueIDs(append(patch.named(), extraNamed...))
	members := map[uuid.UUID]string{}
	if patch.ProfileID != nil {
		members[*patch.ProfileID] = prefix(-1) + "/profile_id"
	}
	if patch.Profile2ID != nil {
		members[*patch.Profile2ID] = prefix(-1) + "/profile2_id"
	}
	err := e.Run(ctx, st, tenant, opts, a, func(tx store.Tx, g *Guard) error {
		out = nil
		if err := g.Begin(tx, ids, named...); err != nil {
			return err
		}
		found, err := tx.EndpointsLock(ids)
		if err != nil {
			return err
		}
		if len(found) != len(ids) {
			return notFound()
		}
		if patch.GroupID != nil && !patch.ClearGroup && *patch.GroupID != uuid.Nil {
			ok, err := tx.GroupKeyShare(*patch.GroupID)
			if err != nil {
				return err
			}
			if !ok {
				return notFound()
			}
		}
		before, err := g.Inputs(tx, ids)
		if err != nil {
			return err
		}
		rows, err := tx.EndpointsGet(ids)
		if err != nil {
			return err
		}
		watch := slices.Clone(named)
		for _, in := range before {
			watch = append(watch, in.Profiles()...)
		}
		d, err := e.watchProfiles(tx, watch, members)
		if err != nil {
			return err
		}
		var fs []Field
		changed := make([]store.EndpointRow, len(rows))
		away := map[uuid.UUID]Away{}
		mark := false
		for i, r := range rows {
			old := r
			fs = append(fs, patch.apply(&r, prefix(slices.Index(ids, r.ID)))...)
			changed[i] = r
			away[r.ID] = awayOf(old, r)
			if compiledChanged(cols(old), cols(r)) {
				mark = true
			}
		}
		if fs != nil {
			return invalid(fs...)
		}
		for _, r := range changed {
			if err := tx.EndpointUpdate(r); err != nil {
				return err
			}
		}
		after, err := g.Inputs(tx, ids)
		if err != nil {
			return err
		}
		for id, av := range away {
			after[id].Away = av
		}
		if err := d.check(patch.ConfirmDestinations); err != nil {
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
		out, err = tx.EndpointsGet(ids)
		return err
	})
	return out, err
}

// typeKnown reads whether the type of a patch is one of the seeded ones.
func (e *Env) typeKnown(ctx context.Context, st *store.Store, tenant uuid.UUID, opts store.TxOpts, key *string) (bool, error) {
	if key == nil {
		return true, nil
	}
	var ok bool
	err := e.Plain(ctx, st, tenant, store.TxOpts{ReadOnly: true, LockWait: opts.LockWait}, func(tx store.Tx) (err error) {
		ok, err = tx.EndpointTypeKnown(*key)
		return
	})
	return ok, err
}

// Patch changes one Endpoint (T-222).
func (e *Env) Patch(ctx context.Context, st *store.Store, tenant uuid.UUID, opts store.TxOpts, a Auth, id uuid.UUID, p Patch) (store.EndpointRow, error) {
	known, err := e.typeKnown(ctx, st, tenant, opts, p.Type)
	if err != nil {
		return store.EndpointRow{}, err
	}
	if fs := p.pre("", known); fs != nil {
		return store.EndpointRow{}, invalid(fs...)
	}
	rows, err := e.update(ctx, st, tenant, opts, a, []uuid.UUID{id}, func(int) string { return "" }, p, nil)
	if err != nil {
		return store.EndpointRow{}, err
	}
	return rows[0], nil
}

// BatchIn is a batch operation over up to 500 Endpoints (spec 9.3).
type BatchIn struct {
	IDs []uuid.UUID
	// Op is "move", "edit" or "delete".
	Op string
	// Group is the target of a move; ClearGroup sends the Endpoints to no group.
	Group      uuid.UUID
	ClearGroup bool
	// Set and Clear are the members of an edit.
	Set                 Patch
	ConfirmDestinations bool
}

func checkIDs(ids []uuid.UUID) *Error {
	switch {
	case len(ids) == 0:
		return invalid(Field{"/ids", CodeRequired})
	case len(ids) > MaxIDsPerBatch:
		return invalid(Field{"/ids", CodeExceeded})
	}
	seen := map[uuid.UUID]bool{}
	for i, id := range ids {
		if seen[id] {
			return invalid(Field{fmt.Sprintf("/ids/%d", i), CodeDuplicate})
		}
		seen[id] = true
	}
	return nil
}

// Batch runs move, edit and delete over the Endpoints. It returns how many it changed.
func (e *Env) Batch(ctx context.Context, st *store.Store, tenant uuid.UUID, opts store.TxOpts, a Auth, in BatchIn) (int, error) {
	if err := checkIDs(in.IDs); err != nil {
		return 0, err
	}
	switch in.Op {
	case "delete":
		return len(in.IDs), e.Delete(ctx, st, tenant, opts, a, in.IDs)
	case "move":
		p := Patch{ConfirmDestinations: in.ConfirmDestinations, ClearGroup: in.ClearGroup}
		if !in.ClearGroup {
			if in.Group == uuid.Nil {
				return 0, invalid(Field{"/group_id", CodeRequired})
			}
			p.GroupID = &in.Group
		}
		_, err := e.update(ctx, st, tenant, opts, a, in.IDs, func(int) string { return "/set" }, p, nil)
		return len(in.IDs), err
	case "edit":
		p := in.Set
		p.ConfirmDestinations = in.ConfirmDestinations
		if p.Name != nil || p.Type != nil || p.GroupID != nil || p.Comment != nil || p.LegacyDNS != nil || p.AuthorizeSecureDNS != nil ||
			p.AuthorizeDDNS != nil || p.ExposeIP != nil || p.PreventDeactivation != nil || p.RequireAuthorizedIPs != nil ||
			p.ScheduleTimezone != nil || p.ClearComment {
			// The members of a batch edit are the four of EndpointBatch.set and the two of clear.
			return 0, invalid(Field{"/set", CodeInvalid})
		}
		if fs := p.pre("/set", true); fs != nil {
			return 0, invalid(fs...)
		}
		if p.ProfileID == nil && p.Profile2ID == nil && p.AnalyticsLevel == nil && p.AdminState == nil && !p.ClearGroup && !p.ClearProfile2 {
			return 0, invalid(Field{"/set", CodeRequired})
		}
		_, err := e.update(ctx, st, tenant, opts, a, in.IDs, func(int) string { return "/set" }, p, nil)
		return len(in.IDs), err
	}
	return 0, invalid(Field{"/op", CodeInvalid})
}

// ---------------------------------------------------------------------------
// Delete.

// Delete deletes the Endpoints (T-233, T-531, spec 3.6): the clients are locked first, in id order, then the Endpoints, and
// the delete needs the lock passwords of every locked profile the Endpoints' identities lose. An Endpoint an admin holds, or
// that has a suspended claim, makes the whole request KindHeld with the indexes of the ones that did.
func (e *Env) Delete(ctx context.Context, st *store.Store, tenant uuid.UUID, opts store.TxOpts, a Auth, ids []uuid.UUID) error {
	if err := checkIDs(ids); err != nil {
		return err
	}
	return e.Run(ctx, st, tenant, opts, a, func(tx store.Tx, g *Guard) error {
		if err := tx.ClientsLockOf(ids); err != nil {
			return err
		}
		if err := g.Begin(tx, ids); err != nil {
			return err
		}
		found, err := tx.EndpointsLock(ids)
		if err != nil {
			return err
		}
		if len(found) != len(ids) {
			return notFound()
		}
		before, err := g.Inputs(tx, ids)
		if err != nil {
			return err
		}
		held, err := tx.EndpointsHeld(ids)
		if err != nil {
			return err
		}
		if len(held) > 0 {
			return heldError(ids, held)
		}
		gone, won, err := tx.EndpointsDelete(ids)
		if err != nil {
			var se *store.Error
			if errors.Is(err, store.ErrConflict) && errors.As(err, &se) && se.SQLState() == "CZ001" {
				return heldError(ids, ids)
			}
			return err
		}
		if !won.Yes() {
			var missing []uuid.UUID
			for _, id := range ids {
				if !slices.Contains(gone, id) {
					missing = append(missing, id)
				}
			}
			return heldError(ids, missing)
		}
		if err := g.Check(tx, before, map[uuid.UUID]*Input{}); err != nil {
			return err
		}
		return store.MarkDirty(tx, store.AggregateEndpointSet, tx.TenantID())
	})
}

func heldError(ids, held []uuid.UUID) *Error {
	var fs []Field
	for _, h := range held {
		if i := slices.Index(ids, h); i >= 0 {
			fs = append(fs, Field{fmt.Sprintf("/ids/%d", i), CodeInvalid})
		}
	}
	return &Error{Kind: KindHeld, Fields: fs}
}

// ---------------------------------------------------------------------------
// Rotate.

// Rotate draws a new resolver id and DoH token for the Endpoint, revokes its live share links and deletes its download links
// in the same transaction, and marks the endpoint_set (spec 8.1). Every device must be set up again, so it needs the lock
// passwords of the profiles the identities that carry the old values lose.
func (e *Env) Rotate(ctx context.Context, st *store.Store, tenant uuid.UUID, opts store.TxOpts, a Auth, id uuid.UUID) (store.EndpointRow, error) {
	var out store.EndpointRow
	err := e.Run(ctx, st, tenant, opts, a, func(tx store.Tx, g *Guard) error {
		if err := g.Begin(tx, []uuid.UUID{id}); err != nil {
			return err
		}
		found, err := tx.EndpointsLock([]uuid.UUID{id})
		if err != nil {
			return err
		}
		if len(found) != 1 {
			return notFound()
		}
		before, err := g.Inputs(tx, []uuid.UUID{id})
		if err != nil {
			return err
		}
		rid, ct, hash, err := e.credential(id)
		if err != nil {
			return err
		}
		if err := tx.EndpointRotate(id, rid, ct, hash); err != nil {
			if errors.Is(err, store.ErrConflict) {
				return &Error{Kind: KindConflict}
			}
			return err
		}
		if err := tx.ShareLinksRevoke(id); err != nil {
			return err
		}
		if err := tx.DownloadLinksDelete(id); err != nil {
			return err
		}
		after, err := g.Inputs(tx, []uuid.UUID{id})
		if err != nil {
			return err
		}
		after[id].Away = AwayEncrypted
		if err := g.Check(tx, before, after); err != nil {
			return err
		}
		if err := store.MarkDirty(tx, store.AggregateEndpointSet, tx.TenantID()); err != nil {
			return err
		}
		out, _, err = tx.EndpointGet(id)
		return err
	})
	return out, err
}
