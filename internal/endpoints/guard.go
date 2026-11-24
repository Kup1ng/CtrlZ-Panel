package endpoints

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/appclock"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/audit"
	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
	"github.com/Kup1ng/CtrlZ-Panel/internal/locations"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// MaxLockPasswords is how many lock passwords one request carries (D31, spec 3.3). A request that needs more is 422 exceeded.
const MaxLockPasswords = 8

// Env is the write path. The zero value is not usable: it needs a clock for the times it compares, the key ring that holds
// the doh_token domain, and the catalog that tells which locations a profile may use.
type Env struct {
	Clock   func() time.Time
	Keys    *keyring.Ring
	Catalog locations.LocationCatalog
}

func (e *Env) now() time.Time {
	if e.Clock != nil {
		return e.Clock()
	}
	return appclock.Now()
}

// Password is one lock password of a request, for one profile. It is a secret from decode on.
type Password struct {
	Profile uuid.UUID
	Secret  secret.String
}

// Verifier checks one lock password. The api implements it with the throttle scopes and the Argon2 gate of P2 7.2; this
// package decides which passwords are checked and what the answer means.
type Verifier interface {
	// CheckLockPassword charges profile_lock_tenant and profile_unlock for the profile, checks pw against the stored hash inside the
	// Argon2 gate and outside any transaction, and gives every charge of the attempt back when the gate is busy. ok is false
	// for a wrong password; an error is final (429 too_many_attempts, 503 server_busy).
	CheckLockPassword(ctx context.Context, profile uuid.UUID, pw, stored secret.String) (ok bool, err error)
	// LockPasswordFailed records a wrong password for the audit log, in a transaction of its own (the request is refused, so nothing
	// of its own transaction is kept).
	LockPasswordFailed(ctx context.Context, profile, endpoint uuid.UUID) error
	// LockPasswordUsed records a verified password for the audit log, in a transaction of its own, for a request that ends
	// without a commit: a committed write records it in its own transaction (Guard.Check). Without it, a guess that is
	// right for one profile and wrong for the next would leave a failure row only, and the audit trail would not show which
	// password was confirmed.
	LockPasswordUsed(ctx context.Context, profile, endpoint uuid.UUID) error
	// LockPasswordsAccepted is called after a write that used these passwords has committed. The unlock route clears the
	// profile_unlock scope after a right password, since that scope counts failures (P2 7.2); a right password here must not
	// count against the profile either, or a tenant that edits its own Endpoints with the right password runs into 429.
	// profile_lock_tenant stays charged. It is a convenience after the commit and not a gate, so it has no error.
	LockPasswordsAccepted(ctx context.Context, profiles []uuid.UUID)
}

// Actor is who asks.
type Actor struct {
	User uuid.UUID
	IP   netip.Addr
	// Token is true for a request made with an API token, which can never present a lock password (spec 3.3).
	Token bool
}

// Auth is what a request that may need lock passwords carries.
type Auth struct {
	Passwords []Password
	Actor     Actor
	Verifier  Verifier
}

// probeResult is returned from the body of a request that runs as a probe: the transaction is rolled back and the answer
// carries what the request would have needed.
type probeResult struct{ needed []needed }

func (*probeResult) Error() string { return "endpoints: probe" }

type needed struct {
	Profile  uuid.UUID
	Endpoint uuid.UUID // the first Endpoint, by id, on which the profile was needed
}

// Guard is what the body of a write holds while it runs: the verified passwords and the checks of 3.3. A body calls Begin at
// step 4 of the lock order, Inputs before and after its writes, and Check last.
type Guard struct {
	e        *Env
	actor    Actor
	probe    bool
	verified map[uuid.UUID]secret.String // profile to the hash that was verified
	// verifiedOn lists the verified profiles with the Endpoint each was needed on at the probe, in the order they were checked.
	// Check records a used row for every one of them, whether or not the write still needs it: the rows may have changed
	// between the probe and the write, and a password that was confirmed and charged belongs in the trail all the same.
	verifiedOn []needed
}

// Begin takes step 4 of the lock order (spec 3.7): every profile the request names, key-shared in id order, and every
// verified one FOR SHARE with its hash compared with the one that was verified. A named profile that is not the tenant's is
// KindNotFound. Call it before the first Endpoint lock.
func (g *Guard) Begin(tx store.Tx, endpoints []uuid.UUID, named ...uuid.UUID) error {
	all := slices.Clone(named)
	// The profiles the Endpoints hold now are key-shared too, though the request does not name them: an UPDATE or INSERT that
	// lists a profile column takes the key share of its parent in the statement's own text (lockrank reads it so), and that
	// must not come after the Endpoint's lock. The read is unlocked; the rows are read again under the lock.
	if len(endpoints) > 0 {
		rows, err := tx.EndpointsGet(endpoints)
		if err != nil {
			return err
		}
		for _, r := range rows {
			all = append(all, r.ProfileID, r.Profile2ID)
		}
	}
	for p := range g.verified {
		all = append(all, p)
	}
	all = uniqueIDs(all)
	if len(all) == 0 {
		return nil
	}
	found, err := tx.ProfilesKeyShare(all)
	if err != nil {
		return err
	}
	if len(found) != len(all) {
		return notFound()
	}
	if len(g.verified) == 0 {
		return nil
	}
	want := make([]uuid.UUID, 0, len(g.verified))
	for p := range g.verified {
		want = append(want, p)
	}
	locked, err := tx.ProfilesShare(want)
	if err != nil {
		return err
	}
	if len(locked) != len(want) {
		// A verified profile was unlocked or deleted since: the password that was checked stands for nothing.
		return &Error{Kind: KindConflict}
	}
	hashes, err := tx.ProfileLockHashes(want)
	if err != nil {
		return err
	}
	for _, h := range hashes {
		if !g.verified[h.ID].Equal(h.Hash) {
			return &Error{Kind: KindConflict}
		}
	}
	return nil
}

func uniqueIDs(in []uuid.UUID) []uuid.UUID {
	out := slices.Clone(in)
	out = slices.DeleteFunc(out, func(id uuid.UUID) bool { return id == uuid.Nil })
	slices.SortFunc(out, func(a, b uuid.UUID) int { return slices.Compare(a[:], b[:]) })
	return slices.Compact(out)
}

// Inputs reads the inputs of the stack that applies for the Endpoints, from the rows as they are in this transaction. An id
// that is not an Endpoint of the tenant is absent from the answer.
func (g *Guard) Inputs(tx store.Tx, endpoints []uuid.UUID) (map[uuid.UUID]*Input, error) {
	rows, err := tx.EndpointsGet(endpoints)
	if err != nil {
		return nil, err
	}
	ids := make([]uuid.UUID, len(rows))
	for i, r := range rows {
		ids[i] = r.ID
	}
	ws, err := tx.WindowsOf(ids)
	if err != nil {
		return nil, err
	}
	cs, err := tx.StackClients(ids)
	if err != nil {
		return nil, err
	}
	claims, err := tx.StackClaims(ids)
	if err != nil {
		return nil, err
	}
	out := make(map[uuid.UUID]*Input, len(rows))
	for _, r := range rows {
		out[r.ID] = &Input{Zone: r.ScheduleTimezone, Base: Stack{r.ProfileID, r.Profile2ID}, Clients: map[string]Stack{}}
	}
	for _, w := range ws {
		in := out[w.EndpointID]
		in.Windows = append(in.Windows, Window{ID: w.ID, Start: w.Start, End: w.End, Stack: Stack{w.ProfileID, w.Profile2ID}})
	}
	for _, c := range cs {
		out[c.Endpoint].Clients[c.Label] = Stack{c.ProfileID, c.Profile2ID}
	}
	legacy := map[uuid.UUID]bool{}
	for _, r := range rows {
		legacy[r.ID] = r.LegacyDNS
	}
	for _, c := range claims {
		if legacy[c.Endpoint] {
			out[c.Endpoint].Plain = append(out[c.Endpoint].Plain, c.ID)
		}
	}
	return out, nil
}

// Check is the last step of the body of a write (spec 3.3): it computes, for every Endpoint of before, which locked profiles
// the change removes, and
//
//   - in a probe, returns the answer for the caller to roll back;
//   - otherwise requires every one of them to be a profile whose password was verified (KindConflict if not: the rows changed
//     between the check and the write), and records which passwords the write used.
//
// after has no entry for an Endpoint the request deleted. The caller sets Away on the after inputs that turn identities away.
func (g *Guard) Check(tx store.Tx, before, after map[uuid.UUID]*Input) error {
	any, err := tx.AnyProfileLocked()
	if err != nil {
		return err
	}
	var need []needed
	if any {
		union := map[uuid.UUID]uuid.UUID{} // profile to the first Endpoint, by id, it was needed on
		eps := make([]uuid.UUID, 0, len(before))
		for id := range before {
			eps = append(eps, id)
		}
		slices.SortFunc(eps, func(a, b uuid.UUID) int { return slices.Compare(a[:], b[:]) })
		now := g.e.now()
		for _, id := range eps {
			for _, p := range Needed(now, before[id], after[id]) {
				if _, ok := union[p]; !ok {
					union[p] = id
				}
			}
		}
		cand := make([]uuid.UUID, 0, len(union))
		for p := range union {
			cand = append(cand, p)
		}
		locked, err := tx.ProfilesLockedAmong(cand)
		if err != nil {
			return err
		}
		for _, p := range locked {
			need = append(need, needed{Profile: p, Endpoint: union[p]})
		}
	}
	if g.probe {
		return &probeResult{needed: need}
	}
	recorded := map[uuid.UUID]bool{}
	for _, n := range need {
		if _, ok := g.verified[n.Profile]; !ok {
			return &Error{Kind: KindConflict}
		}
		if err := audit.Tenant(tx, g.actor.User, g.actor.IP, audit.ProfileLockPasswordUsed{ProfileID: n.Profile, EndpointID: n.Endpoint}); err != nil {
			return err
		}
		recorded[n.Profile] = true
	}
	// A verified password the write no longer needs (the rows moved between the probe and the write) is recorded too.
	for _, n := range g.verifiedOn {
		if recorded[n.Profile] {
			continue
		}
		if err := audit.Tenant(tx, g.actor.User, g.actor.IP, audit.ProfileLockPasswordUsed{ProfileID: n.Profile, EndpointID: n.Endpoint}); err != nil {
			return err
		}
	}
	return nil
}

// retries is how often a body that lost a deadlock is run again (spec 3.6, 3.7).
const retries = 3

// Run executes the body of a write that may need lock passwords, in the order of spec 3.3:
//
//  1. the shape of the passwords is checked (at most 8, one per profile);
//  2. when the tenant has a locked profile, the body runs once as a probe, in a transaction that is rolled back, which
//     reports which locked profiles the change would remove (the body validates the request first, so a request that is
//     refused for its own values is refused before anything is charged);
//  3. a needed profile with no password is KindLocked and charges nothing, and an API token never presents one;
//  4. each needed password is verified outside any transaction, and a wrong one is KindInvalidCredentials;
//  5. the body runs again as the write, holding the verified profiles FOR SHARE.
//
// A body returns an error to refuse. It must be free of effects outside its transaction, since it can run twice.
func (e *Env) Run(ctx context.Context, st *store.Store, tenant uuid.UUID, opts store.TxOpts, a Auth, body func(tx store.Tx, g *Guard) error) error {
	if len(a.Passwords) > MaxLockPasswords {
		return invalid(Field{"/lock_passwords", CodeExceeded})
	}
	byProfile := map[uuid.UUID]int{}
	for i, p := range a.Passwords {
		if p.Profile == uuid.Nil {
			return invalid(Field{fmt.Sprintf("/lock_passwords/%d/profile_id", i), CodeRequired})
		}
		if _, dup := byProfile[p.Profile]; dup {
			return invalid(Field{fmt.Sprintf("/lock_passwords/%d/profile_id", i), CodeDuplicate})
		}
		byProfile[p.Profile] = i
	}
	if a.Actor.Token && len(a.Passwords) > 0 {
		return &Error{Kind: KindTokenNotAllowed}
	}

	var any bool
	if err := withRetry(ctx, st, tenant, store.TxOpts{ReadOnly: true, LockWait: opts.LockWait}, func(tx store.Tx) error {
		// A password for a profile that is not the tenant's is refused whatever the change needs (spec 3.8: profile ids are the tenant's).
		if len(byProfile) > 0 {
			named := make([]uuid.UUID, 0, len(byProfile))
			for p := range byProfile {
				named = append(named, p)
			}
			found, err := tx.ProfilesExist(named)
			if err != nil {
				return err
			}
			if len(found) != len(named) {
				return notFound()
			}
		}
		var err error
		any, err = tx.AnyProfileLocked()
		return err
	}); err != nil {
		return err
	}
	verified := map[uuid.UUID]secret.String{}
	// used lists the passwords that were verified, in the order they were checked. A write that commits records them in its
	// own transaction (Guard.Check); a request that ends without a commit, whatever the reason, records them here, so the
	// audit trail shows which password was confirmed even when a later one was wrong or the write was refused.
	var used []needed
	recordUsed := func() error {
		for _, n := range used {
			if err := a.Verifier.LockPasswordUsed(context.WithoutCancel(ctx), n.Profile, n.Endpoint); err != nil {
				return err
			}
		}
		used = nil
		return nil
	}
	refuse := func(err error) error {
		if aerr := recordUsed(); aerr != nil {
			return aerr
		}
		return err
	}
	if any {
		var pr *probeResult
		err := withRetry(ctx, st, tenant, opts, func(tx store.Tx) error {
			return body(tx, &Guard{e: e, actor: a.Actor, probe: true})
		})
		if !errors.As(err, &pr) {
			if err != nil {
				return err
			}
			return errors.New("endpoints: a probe finished without a check")
		}
		if len(pr.needed) > 0 {
			if a.Actor.Token {
				return &Error{Kind: KindTokenNotAllowed}
			}
			// More than the request can carry: no list of passwords will ever satisfy it, so it is refused as too many and
			// not asked for the missing ones (spec 3.3), which would send the owner to supply what they cannot supply.
			if len(pr.needed) > MaxLockPasswords {
				return invalid(Field{"/lock_passwords", CodeExceeded})
			}
			var missing []Field
			for _, n := range pr.needed {
				if _, ok := byProfile[n.Profile]; !ok {
					missing = append(missing, Field{"/lock_passwords", CodeRequired})
					break
				}
			}
			if missing != nil {
				return &Error{Kind: KindLocked, Fields: missing}
			}
			ids := make([]uuid.UUID, len(pr.needed))
			for i, n := range pr.needed {
				ids[i] = n.Profile
			}
			var hashes []store.LockHash
			if err := withRetry(ctx, st, tenant, store.TxOpts{ReadOnly: true, LockWait: opts.LockWait}, func(tx store.Tx) (err error) {
				hashes, err = tx.ProfileLockHashes(ids)
				return
			}); err != nil {
				return err
			}
			stored := map[uuid.UUID]secret.String{}
			for _, h := range hashes {
				stored[h.ID] = h.Hash
			}
			for _, n := range pr.needed {
				hash, ok := stored[n.Profile]
				if !ok {
					// Unlocked since the probe: nothing to verify, and the write will find it so.
					continue
				}
				i := byProfile[n.Profile]
				good, err := a.Verifier.CheckLockPassword(ctx, n.Profile, a.Passwords[i].Secret, hash)
				if err != nil {
					return refuse(err)
				}
				if !good {
					if err := recordUsed(); err != nil {
						return err
					}
					if err := a.Verifier.LockPasswordFailed(context.WithoutCancel(ctx), n.Profile, n.Endpoint); err != nil {
						return err
					}
					return &Error{Kind: KindInvalidCredentials, Fields: []Field{{fmt.Sprintf("/lock_passwords/%d", i), CodeInvalid}}}
				}
				verified[n.Profile] = hash
				used = append(used, n)
			}
		}
	}
	if err := withRetry(ctx, st, tenant, opts, func(tx store.Tx) error {
		return body(tx, &Guard{e: e, actor: a.Actor, verified: verified, verifiedOn: used})
	}); err != nil {
		return refuse(err)
	}
	if len(verified) > 0 {
		// The write has committed, and with it the used rows of its own transaction: the right passwords no longer count.
		accepted := make([]uuid.UUID, 0, len(verified))
		for p := range verified {
			accepted = append(accepted, p)
		}
		slices.SortFunc(accepted, func(x, y uuid.UUID) int { return slices.Compare(x[:], y[:]) })
		a.Verifier.LockPasswordsAccepted(context.WithoutCancel(ctx), accepted)
	}
	return nil
}

// withRetry runs one transaction, again on a deadlock or a lock timeout up to three times in all.
func withRetry(ctx context.Context, st *store.Store, tenant uuid.UUID, opts store.TxOpts, fn func(store.Tx) error) error {
	var err error
	for attempt := 0; attempt < retries; attempt++ {
		err = st.WithTenant(ctx, tenant, opts, fn)
		if !errors.Is(err, store.ErrRetry) {
			return err
		}
	}
	return err
}

// Plain runs a write that can never need a lock password (a group, an Endpoint's name): the same retry, no probe.
func (e *Env) Plain(ctx context.Context, st *store.Store, tenant uuid.UUID, opts store.TxOpts, body func(tx store.Tx) error) error {
	return withRetry(ctx, st, tenant, opts, body)
}
