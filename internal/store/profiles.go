package store

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// This file is the profile side of the write path (docs/specs/p2-profiles.md 3.1 to 3.4). The
// rules of it, all enforced by statements and not by callers:
//
//   - One statement is the permission to write a profile: ProfileGuard. Its row is a Won and a
//     ProfileWrite, and every method that writes a profile or its content takes the ProfileWrite
//     and bounds its statement by the profile id inside it, so a rule, folder or selector id of
//     another profile matches no row.
//   - A cap is decided by the statement that adds the row (ctrlz.cap_reached under the lock that
//     serialises the writers), never by Go comparing a count it read.
//   - The new profile of a Create has a ProfileWrite of its own, made by the INSERT.

// ErrNoProfileWrite is returned for a ProfileWrite that was not made by this transaction's guard or
// insert: the zero value, or one made in another tenant's transaction. It is a defect of the
// caller, not of the request.
var ErrNoProfileWrite = errors.New("store: no profile write permission")

// ProfileWrite is the permission to write one profile of the transaction's tenant. Only the three
// statements named in the spec make one: ProfileGuard, ProfileCreate and ProfileDelete. The fields
// are private so that no caller can conjure one for an id it chose.
type ProfileWrite struct {
	tenant uuid.UUID
	// batch is the id of the transaction that made the permission (Tx.batch is new for every WithTenant), so a
	// permission kept past its transaction cannot write in a later one, where no guard ran and the lock could
	// have been taken since.
	batch uuid.UUID
	id    uuid.UUID
}

// ID is the profile this permission is for.
func (w ProfileWrite) ID() uuid.UUID { return w.id }

// check refuses a permission that does not belong to this transaction.
func (t Tx) check(w ProfileWrite) error {
	if w.id == uuid.Nil || w.tenant != t.tenant || w.batch != t.batch || t.batch == uuid.Nil {
		return ErrNoProfileWrite
	}
	return nil
}

// Profile is a row of ctrlz.profiles, without the lock hash and the compiled hash.
type Profile struct {
	ID            uuid.UUID
	Name          string
	Kind          string
	Version       int64
	DisabledUntil *time.Time
	Locked        bool
	LockMessage   *string
	LockedAt      *time.Time
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

const profileColumns = `id, name, kind, version, disabled_until, lock_state = 'locked', lock_message, locked_at, created_at, updated_at`

func scanProfile(r interface{ Scan(...any) error }) (Profile, error) {
	var p Profile
	err := r.Scan(&p.ID, &p.Name, &p.Kind, &p.Version, &p.DisabledUntil, &p.Locked, &p.LockMessage, &p.LockedAt, &p.CreatedAt, &p.UpdatedAt)
	return p, err
}

const qProfileGet = `SELECT ` + profileColumns + ` FROM ctrlz.profiles WHERE tenant_id = $1 AND id = $2`

// ProfileGet reads one profile of the tenant. found is false for an id that is not the tenant's.
func (t Tx) ProfileGet(id uuid.UUID) (Profile, bool, error) {
	p, err := scanProfile(t.tx.QueryRow(t.ctx, qProfileGet, t.tenant, id))
	ok, err := notFound(err)
	return p, ok, err
}

const qProfileList = `SELECT ` + profileColumns + ` FROM ctrlz.profiles WHERE tenant_id = $1 ORDER BY id`

// ProfileList reads every profile of the tenant, oldest first (ids are time ordered).
func (t Tx) ProfileList() ([]Profile, error) {
	rows, err := t.tx.Query(t.ctx, qProfileList, t.tenant)
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []Profile
	for rows.Next() {
		p, err := scanProfile(rows)
		if err != nil {
			return nil, sanitize(err)
		}
		out = append(out, p)
	}
	return out, sanitize(rows.Err())
}

const qProfileLockState = `SELECT lock_state = 'locked' FROM ctrlz.profiles WHERE tenant_id = $1 AND id = $2`

// ProfileLocked tells a missing profile from a locked one after a guard that lost: found false is
// 404 and locked true is 423. It reads and decides nothing; the guard did.
func (t Tx) ProfileLocked(id uuid.UUID) (locked, found bool, err error) {
	err = t.tx.QueryRow(t.ctx, qProfileLockState, t.tenant, id).Scan(&locked)
	found, err = notFound(err)
	return locked, found, err
}

// qProfileGuard is the one statement that is the permission to write a profile (spec 3.1): the
// version steps once for every guarded transaction, the row lock it takes serialises every writer
// of the profile until commit, and a locked profile matches no row. The columns are named, never *
// (a profile row holds the lock hash).
const qProfileGuard = `UPDATE ctrlz.profiles SET version = version + 1
WHERE tenant_id = $1 AND id = $2 AND lock_state = 'unlocked'
RETURNING id`

// ProfileGuard opens a write to the profile. A loss is a profile that is missing or locked, and
// ProfileLocked says which. Every guarded write of a transaction starts here, and a transaction
// that guards a profile twice steps its version twice, which is harmless: the version only has to
// change.
func (t Tx) ProfileGuard(id uuid.UUID) (ProfileWrite, Won, error) {
	var got uuid.UUID
	w, err := wonRow(t.tx.QueryRow(t.ctx, qProfileGuard, t.tenant, id).Scan(&got))
	if err != nil || !w.Yes() {
		return ProfileWrite{}, Won{}, err
	}
	return ProfileWrite{tenant: t.tenant, batch: t.batch, id: got}, w, nil
}

const qProfileTenantLock = `SELECT ctrlz_fn.profile_tenant_lock()`

// qProfileCreate adds a profile unless the tenant already holds its limit. The count and the
// compare are inside the INSERT, under the tenant lock that ProfileCreate takes first (a statement
// of its own, since the snapshot of the INSERT is taken after the lock wait).
const qProfileCreate = `INSERT INTO ctrlz.profiles (tenant_id, name, kind)
SELECT $1::uuid, $2::text, $3::text
WHERE NOT ctrlz.cap_reached((SELECT count(*) FROM ctrlz.profiles p WHERE p.tenant_id = $1),
  (SELECT COALESCE(te.max_profiles, d.max_profiles) FROM ctrlz.entitlement_defaults d LEFT JOIN ctrlz.tenant_entitlements te ON te.tenant_id = $1))
RETURNING id`

// ProfileCreate adds an unlocked, empty profile. A loss is the tenant's limit (max_profiles). The
// returned permission is for the new profile: its creator may fill it in the same transaction.
// Create, Import and Duplicate all come through here, so one lock and one statement decide the cap
// for the API and for a job.
func (t Tx) ProfileCreate(name, kind string) (ProfileWrite, Won, error) {
	var locked bool
	if err := t.tx.QueryRow(t.ctx, qProfileTenantLock).Scan(&locked); err != nil {
		return ProfileWrite{}, Won{}, sanitize(err)
	}
	if !locked {
		return ProfileWrite{}, Won{}, ErrNilTenant // the function answers false only when the transaction has no tenant
	}
	var id uuid.UUID
	w, err := wonRow(t.tx.QueryRow(t.ctx, qProfileCreate, t.tenant, name, kind).Scan(&id))
	if err != nil || !w.Yes() {
		return ProfileWrite{}, Won{}, err
	}
	return ProfileWrite{tenant: t.tenant, batch: t.batch, id: id}, w, nil
}

// The two lookups ride on clients_profile_idx and clients_profile2_idx (migration 0091), so the lock reads the clients that name
// the profile and not every client of the tenant (p2-B3-r13-4). The locking read is the outer one, by primary key, in id order.
const qProfileClientsLock = `SELECT id FROM ctrlz.clients WHERE tenant_id = $1 AND id IN (
  SELECT c.id FROM ctrlz.clients c WHERE c.tenant_id = $1 AND c.profile_id = $2
  UNION SELECT c.id FROM ctrlz.clients c WHERE c.tenant_id = $1 AND c.profile2_id = $2)` + orderedDelete

// ProfileClientsLock locks the clients that name the profile, in id order, before the profile is
// deleted: the foreign keys write them (ON DELETE SET NULL, and promote_profile2), and a writer of
// a client that took them in another order made a deadlock (spec 3.3, PS test 27).
func (t Tx) ProfileClientsLock(id uuid.UUID) error {
	rows, err := t.tx.Query(t.ctx, qProfileClientsLock, t.tenant, id)
	if err != nil {
		return sanitize(err)
	}
	defer rows.Close()
	for rows.Next() {
	}
	return sanitize(rows.Err())
}

const qProfileDelete = `DELETE FROM ctrlz.profiles WHERE tenant_id = $1 AND id = $2 AND lock_state = 'unlocked' RETURNING id`

// ProfileDelete removes an unlocked profile. The row it returns is the permission of the delete (the
// outbox marks of the caller go with it). A loss is a missing or locked profile. A profile an Endpoint
// or a schedule window still uses is ErrConstraint (the RESTRICT foreign keys): the caller answers it
// as profile_in_use. Call ProfileClientsLock first.
func (t Tx) ProfileDelete(id uuid.UUID) (ProfileWrite, Won, error) {
	var got uuid.UUID
	w, err := wonRow(t.tx.QueryRow(t.ctx, qProfileDelete, t.tenant, id).Scan(&got))
	if err != nil || !w.Yes() {
		return ProfileWrite{}, Won{}, err
	}
	return ProfileWrite{tenant: t.tenant, batch: t.batch, id: got}, w, nil
}

const qProfileRename = `UPDATE ctrlz.profiles SET name = $3 WHERE tenant_id = $1 AND id = $2`

// ProfileRename sets the name. Rename marks nothing: the name is not compiled.
func (t Tx) ProfileRename(w ProfileWrite, name string) error {
	if err := t.check(w); err != nil {
		return err
	}
	_, err := t.tx.Exec(t.ctx, qProfileRename, t.tenant, w.id, name)
	return sanitize(err)
}

const qProfileDisable = `UPDATE ctrlz.profiles SET disabled_until = $3 WHERE tenant_id = $1 AND id = $2`

// ProfileDisable sets the end of a Disable, stamped by the caller from the application clock, or
// clears it with nil (T-138).
func (t Tx) ProfileDisable(w ProfileWrite, until *time.Time) error {
	if err := t.check(w); err != nil {
		return err
	}
	_, err := t.tx.Exec(t.ctx, qProfileDisable, t.tenant, w.id, until)
	return sanitize(err)
}
