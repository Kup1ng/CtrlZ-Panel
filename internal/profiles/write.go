package profiles

import (
	"context"
	"errors"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	shared "github.com/Kup1ng/CtrlZ-Shared/locations"

	"github.com/Kup1ng/CtrlZ-Panel/internal/locations"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// wtx is one guarded write of a profile inside the caller's transaction: the permission the guard gave
// (spec 3.1), and what the checks read once and reuse (the location snapshot and the profile's set).
type wtx struct {
	e  *Env
	tx store.Tx
	pw store.ProfileWrite

	loaded bool
	snap   locations.Snapshot
	set    []shared.Key
	setOK  bool
}

// begin opens a guarded write. items is how many items the request carries, which max_rules_per_request
// bounds (spec 3.4); it is checked before any work, and a limit below the schema's bound is the handler's.
// A profile that is missing or locked is refused here, before anything is read for the request.
func (e *Env) begin(tx store.Tx, profile uuid.UUID, items int) (*wtx, error) {
	if items > 0 {
		lim, err := tx.Limits()
		if err != nil {
			return nil, err
		}
		if items > lim.MaxRulesPerRequest {
			return nil, invalid(Field{"max_rules_per_request", CodeExceeded})
		}
	}
	pw, won, err := tx.ProfileGuard(profile)
	if err != nil {
		return nil, err
	}
	if !won.Yes() {
		return nil, refusedGuard(tx, profile)
	}
	if e.gate != nil {
		if err := e.gate(tx); err != nil {
			return nil, err
		}
	}
	return &wtx{e: e, tx: tx, pw: pw}, nil
}

// refusedGuard tells a missing profile (404) from a locked one (423) after a guard that lost.
func refusedGuard(tx store.Tx, profile uuid.UUID) error {
	locked, found, err := tx.ProfileLocked(profile)
	switch {
	case err != nil:
		return err
	case !found:
		return notFound()
	case locked:
		return &Error{Kind: KindLocked}
	}
	// Unlocked and present, yet the guard returned no row: it changed between two statements of one
	// transaction, which only a lock taken and cleared in between can do. The caller may retry.
	return &Error{Kind: KindConflict}
}

// mark records that the profile must be recompiled, once however many rows the transaction wrote (spec 3.2).
func (w *wtx) mark() error {
	return store.MarkDirty(w.tx, store.AggregateProfile, w.pw.ID())
}

// load reads the location snapshot once.
func (w *wtx) load() error {
	if w.loaded {
		return nil
	}
	if w.e.Catalog == nil {
		w.snap = locations.Snapshot{}.Index()
	} else {
		s, err := w.e.Catalog.Snapshot(w.tx)
		if err != nil {
			return err
		}
		w.snap = s
	}
	w.loaded = true
	return nil
}

// allowed is the set of locations the profile may use (spec 4.2).
func (w *wtx) allowed() ([]shared.Key, error) {
	if w.setOK {
		return w.set, nil
	}
	if err := w.load(); err != nil {
		return nil, err
	}
	s, err := locations.Allowed(w.tx, w.snap, w.pw.ID())
	if err != nil {
		return nil, err
	}
	w.set, w.setOK = s, true
	return s, nil
}

// ---------------------------------------------------------------------------
// Profiles.

// Kinds are the seven profile types (spec 5).
func Kinds() []string {
	return []string{"custom", "developer", "gaming", "kids", "privacy", "productivity", "vpn_replacement"}
}

func validKind(k string) bool {
	for _, x := range Kinds() {
		if x == k {
			return true
		}
	}
	return false
}

// NameLimit is how long a profile name may be, in characters.
const NameLimit = 64

// CreateProfile adds an empty, unlocked profile. The count of the tenant's profiles is decided by the
// statement that inserts it (max_profiles), so racing creators of one tenant get exactly the limit.
func (e *Env) CreateProfile(tx store.Tx, name, kind string) (store.Profile, error) {
	var fs []Field
	if f := checkName(name, "/name", NameLimit); f != nil {
		fs = append(fs, *f)
	}
	if !validKind(kind) {
		fs = append(fs, Field{"/kind", CodeInvalid})
	}
	if fs != nil {
		return store.Profile{}, invalid(fs...)
	}
	pw, won, err := tx.ProfileCreate(name, kind)
	if err != nil {
		return store.Profile{}, err
	}
	if !won.Yes() {
		return store.Profile{}, invalid(Field{"max_profiles", CodeExceeded})
	}
	if err := store.MarkDirty(tx, store.AggregateProfile, pw.ID()); err != nil {
		return store.Profile{}, err
	}
	p, _, err := tx.ProfileGet(pw.ID())
	return p, err
}

// RenameProfile changes the name. It marks nothing: the name is not compiled (spec 3.2).
func (e *Env) RenameProfile(tx store.Tx, id uuid.UUID, name string) (store.Profile, error) {
	if f := checkName(name, "/name", NameLimit); f != nil {
		return store.Profile{}, invalid(*f)
	}
	w, err := e.begin(tx, id, 0)
	if err != nil {
		return store.Profile{}, err
	}
	if err := tx.ProfileRename(w.pw, name); err != nil {
		return store.Profile{}, err
	}
	p, _, err := tx.ProfileGet(id)
	return p, err
}

// Disable switches the profile off until a time (T-138): the end is stamped from the application clock and the
// node compares it with its own.
func (e *Env) Disable(tx store.Tx, id uuid.UUID, forText string, until *time.Time) (store.Profile, error) {
	end, refusal := e.DisableUntil(forText, until)
	if refusal != nil {
		return store.Profile{}, refusal
	}
	w, err := e.begin(tx, id, 0)
	if err != nil {
		return store.Profile{}, err
	}
	if err := tx.ProfileDisable(w.pw, &end); err != nil {
		return store.Profile{}, err
	}
	if err := w.mark(); err != nil {
		return store.Profile{}, err
	}
	p, _, err := tx.ProfileGet(id)
	return p, err
}

// Enable ends a Disable.
func (e *Env) Enable(tx store.Tx, id uuid.UUID) (store.Profile, error) {
	w, err := e.begin(tx, id, 0)
	if err != nil {
		return store.Profile{}, err
	}
	if err := tx.ProfileDisable(w.pw, nil); err != nil {
		return store.Profile{}, err
	}
	if err := w.mark(); err != nil {
		return store.Profile{}, err
	}
	p, _, err := tx.ProfileGet(id)
	return p, err
}

// deleteAttempts is how often a delete that lost a deadlock is run again (spec 3.3).
const deleteAttempts = 3

// Delete removes an unlocked profile of the tenant, in one transaction that this function opens, because it
// retries the whole transaction on a deadlock (40P01) up to three times: it locks the clients that name the
// profile in id order, then deletes it, then marks the profile and the tenant's endpoint_set (the database moves
// Profile 2 up and clears dead references without writing an outbox row of its own, spec 3.2).
// A profile an Endpoint or a schedule window uses is KindInUse.
func (e *Env) Delete(ctx context.Context, st *store.Store, tenant, id uuid.UUID, opts store.TxOpts) error {
	var err error
	for attempt := 0; attempt < deleteAttempts; attempt++ {
		err = st.WithTenant(ctx, tenant, opts, func(tx store.Tx) error { return e.deleteIn(tx, id) })
		if !lostARace(err) {
			return err
		}
	}
	return err
}

// lostARace is a transaction the database rolled back for a conflict that a second run may not meet: a deadlock (40P01) or
// a serialization failure (40001). The two other kinds of ErrRetry are not: a lock timeout (55P03, the 200 ms of 3.1) says
// the profile's guard is held, so a second run would wait the same 200 ms again, and a statement timeout (57014) would run
// the delete for up to 30 s again. Each is the first answer, a 503 the client retries after the Retry-After it is given,
// and not three transactions on a pooled connection that change nothing (p2-B3-r13-5).
func lostARace(err error) bool {
	var se *store.Error
	if !errors.As(err, &se) || !errors.Is(err, store.ErrRetry) {
		return false
	}
	c := se.SQLState()
	return c == "40P01" || c == "40001"
}

// restricted is the refusal of the RESTRICT foreign keys of endpoints and schedule_windows (SQLSTATE 23001): an
// Endpoint or a window still uses the profile.
func restricted(err error) bool {
	var se *store.Error
	return errors.As(err, &se) && se.SQLState() == "23001"
}

func (e *Env) deleteIn(tx store.Tx, id uuid.UUID) error {
	if err := tx.ProfileClientsLock(id); err != nil {
		return err
	}
	_, won, err := tx.ProfileDelete(id)
	switch {
	case restricted(err):
		return &Error{Kind: KindInUse}
	case err != nil:
		return err
	case !won.Yes():
		return refusedGuard(tx, id)
	}
	if err := store.MarkDirty(tx, store.AggregateProfile, id); err != nil {
		return err
	}
	return store.MarkDirty(tx, store.AggregateEndpointSet, tx.TenantID())
}

// commentLimit is how long a rule comment may be (T-180).
const commentLimit = 64

// folderNameLimit is how long a folder name may be (T-189).
const folderNameLimit = 31

func tooLong(s string, limit int) bool { return utf8.RuneCountInString(s) > limit }
