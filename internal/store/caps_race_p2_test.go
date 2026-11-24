package store_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/caps"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// The race drivers of the profile write path (docs/specs/p2-profiles.md 3.4, 10.2 S3). Each one runs
// more spenders than the limit allows on a barrier, against the real database, and checks that exactly
// the limit got through. A spender keeps its transaction open until every other one has run its
// statement or a short time has passed (settle), as the passkey driver does: with the lock that
// serialises the writers the others are waiting for it and cannot arrive, so the barrier gives up and
// the winner commits; without it every spender counts the same rows and writes.

func p2Drivers() map[string]func(*testing.T, *raceEnv) {
	return map[string]func(*testing.T, *raceEnv){
		"max_profiles":              driveMaxProfiles,
		"max_rules_per_profile":     driveMaxRules,
		"max_wildcards_per_profile": driveMaxWildcards,
		"max_folders_per_profile":   driveMaxFolders,
		"profile.guard":             driveProfileGuard,
		"profile.delete":            driveProfileDelete,
		"profile.lock":              driveProfileLock,
		"profile.unlock":            driveProfileUnlock,
		"batch_job.claim":           driveJobClaim,
		"batch_job.finish":          driveJobFinish,
		"idempotency.key":           driveIdempotency,
	}
}

// clearJobs removes the job the seed gave each tenant, which would be the one active job.
func (e *raceEnv) clearJobs(t *testing.T) {
	e.exec(t, `DELETE FROM ctrlz.batch_jobs`)
}

func driveMaxProfiles(t *testing.T, e *raceEnv) {
	have := e.count(t, `SELECT count(*) FROM ctrlz.profiles WHERE tenant_id = $1`, e.A.Tenant)
	e.exec(t, `UPDATE ctrlz.tenant_entitlements SET max_profiles = $2 WHERE tenant_id = $1`, e.A.Tenant, have+3)
	settle := newBarrier(spenders, 400*time.Millisecond)
	got := wins(t, spenders, func(i int, hold func()) (bool, error) {
		var w store.Won
		err := e.tenant.WithTenant(e.ctx, e.A.Tenant, store.TxOpts{}, func(tx store.Tx) (err error) {
			hold()
			_, w, err = tx.ProfileCreate(fmt.Sprintf("race-%d", i), "custom")
			settle()
			return err
		})
		return w.Yes(), err
	})
	if got != 3 {
		t.Errorf("%d profiles were created into 3 free slots", got)
	}
	if n := e.count(t, `SELECT count(*) FROM ctrlz.profiles WHERE tenant_id = $1`, e.A.Tenant); n != have+3 {
		t.Errorf("the tenant holds %d profiles, want %d", n, have+3)
	}
	// B's limit is its own: A being full costs it nothing (T-338).
	if err := e.tenant.WithTenant(e.ctx, e.B.Tenant, store.TxOpts{}, func(tx store.Tx) error {
		_, w, err := tx.ProfileCreate("b-first", "custom")
		if err == nil && !w.Yes() {
			t.Error("tenant B was refused a profile because A is full")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

// guarded runs fn inside a guarded write of the profile and settles before it commits.
func guarded(e *raceEnv, tenant, profile uuid.UUID, settle, hold func(), fn func(tx store.Tx, w store.ProfileWrite) (bool, error)) (bool, error) {
	var ok bool
	err := e.tenant.WithTenant(e.ctx, tenant, store.TxOpts{}, func(tx store.Tx) error {
		hold()
		pw, g, err := tx.ProfileGuard(profile)
		if err != nil {
			return err
		}
		if !g.Yes() {
			return fmt.Errorf("the guard lost on an unlocked profile")
		}
		ok, err = fn(tx, pw)
		settle()
		return err
	})
	return ok, err
}

func driveMaxRules(t *testing.T, e *raceEnv) {
	have := e.count(t, `SELECT count(*) FROM ctrlz.rules WHERE profile_id = $1`, e.A.Profile)
	e.exec(t, `UPDATE ctrlz.tenant_entitlements SET max_rules_per_profile = $2 WHERE tenant_id = $1`, e.A.Tenant, have+3)
	settle := newBarrier(spenders, 400*time.Millisecond)
	got := wins(t, spenders, func(i int, hold func()) (bool, error) {
		return guarded(e, e.A.Tenant, e.A.Profile, settle, hold, func(tx store.Tx, w store.ProfileWrite) (bool, error) {
			_, won, err := tx.RulesInsert(w, []store.NewRule{{Key: fmt.Sprintf("race-%d.test", i), MatchKind: "domain", Action: "block", Enabled: true}})
			return won.Yes(), err
		})
	})
	if got != 3 {
		t.Errorf("%d rules were added into 3 free slots", got)
	}
	if n := e.count(t, `SELECT count(*) FROM ctrlz.rules WHERE profile_id = $1`, e.A.Profile); n != have+3 {
		t.Errorf("the profile holds %d rules, want %d", n, have+3)
	}
}

func driveMaxWildcards(t *testing.T, e *raceEnv) {
	e.exec(t, `UPDATE ctrlz.tenant_entitlements SET max_wildcards_per_profile = 3 WHERE tenant_id = $1`, e.A.Tenant)
	for i := 0; i < spenders; i++ {
		e.exec(t, `INSERT INTO ctrlz.rules (tenant_id, profile_id, rule_key, match_kind, action) VALUES ($1, $2, $3, 'domain', 'block')`,
			e.A.Tenant, e.A.Profile, fmt.Sprintf("plain-%d.example.com", i))
	}
	ids := map[int]uuid.UUID{}
	for i := 0; i < spenders; i++ {
		var id uuid.UUID
		if err := e.super.QueryRow(e.ctx, `SELECT id FROM ctrlz.rules WHERE profile_id = $1 AND rule_key = $2`, e.A.Profile, fmt.Sprintf("plain-%d.example.com", i)).Scan(&id); err != nil {
			t.Fatal(err)
		}
		ids[i] = id
	}
	settle := newBarrier(spenders, 400*time.Millisecond)
	// The spenders turn plain rules into wildcards: each one is a new wildcard of the profile.
	got := wins(t, spenders, func(i int, hold func()) (bool, error) {
		return guarded(e, e.A.Tenant, e.A.Profile, settle, hold, func(tx store.Tx, w store.ProfileWrite) (bool, error) {
			won, err := tx.RuleUpdate(w, store.RuleRow{ID: ids[i], Key: fmt.Sprintf("*.wild-%d.example.com", i), MatchKind: "subdomains", Action: "block", Enabled: true})
			return won.Yes(), err
		})
	})
	if got != 3 {
		t.Errorf("%d rules became wildcards into 3 free slots", got)
	}
	if n := e.count(t, `SELECT count(*) FROM ctrlz.rules WHERE profile_id = $1 AND match_kind = 'subdomains'`, e.A.Profile); n != 3 {
		t.Errorf("the profile holds %d wildcards, want 3", n)
	}
	// The same cap stops a batch insert: the wildcards a batch brings count with the ones in place.
	if _, err := guarded(e, e.A.Tenant, e.A.Profile, func() {}, func() {}, func(tx store.Tx, w store.ProfileWrite) (bool, error) {
		_, won, err := tx.RulesInsert(w, []store.NewRule{{Key: "*.again.example.com", MatchKind: "subdomains", Action: "block", Enabled: true}})
		if won.Yes() {
			t.Error("a wildcard was inserted past its cap")
		}
		return won.Yes(), err
	}); err != nil {
		t.Fatal(err)
	}
}

func driveMaxFolders(t *testing.T, e *raceEnv) {
	have := e.count(t, `SELECT count(*) FROM ctrlz.rule_folders WHERE profile_id = $1`, e.A.Profile)
	e.exec(t, `INSERT INTO ctrlz.rule_folders (tenant_id, profile_id, name) SELECT $1, $2, 'f' || g FROM generate_series(1, $3::int) g`,
		e.A.Tenant, e.A.Profile, caps.MaxFoldersPerProfile-have-3)
	settle := newBarrier(spenders, 400*time.Millisecond)
	got := wins(t, spenders, func(i int, hold func()) (bool, error) {
		return guarded(e, e.A.Tenant, e.A.Profile, settle, hold, func(tx store.Tx, w store.ProfileWrite) (bool, error) {
			_, won, err := tx.FolderInsert(w, store.FolderRow{Name: fmt.Sprintf("race%d", i), Kind: "standard"})
			return won.Yes(), err
		})
	})
	if got != 3 {
		t.Errorf("%d folders were added into 3 free slots", got)
	}
	if n := e.count(t, `SELECT count(*) FROM ctrlz.rule_folders WHERE profile_id = $1`, e.A.Profile); n != caps.MaxFoldersPerProfile {
		t.Errorf("the profile holds %d folders, want %d", n, caps.MaxFoldersPerProfile)
	}
}

func driveProfileGuard(t *testing.T, e *raceEnv) {
	var before int64
	if err := e.super.QueryRow(e.ctx, `SELECT version FROM ctrlz.profiles WHERE id = $1`, e.A.Profile).Scan(&before); err != nil {
		t.Fatal(err)
	}
	got := wins(t, spenders, func(i int, hold func()) (bool, error) {
		return guarded(e, e.A.Tenant, e.A.Profile, func() {}, hold, func(tx store.Tx, w store.ProfileWrite) (bool, error) { return true, nil })
	})
	if got != spenders {
		t.Errorf("%d of %d writers passed the guard of an unlocked profile", got, spenders)
	}
	var after int64
	if err := e.super.QueryRow(e.ctx, `SELECT version FROM ctrlz.profiles WHERE id = $1`, e.A.Profile).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after != before+int64(spenders) {
		t.Errorf("the version went from %d to %d for %d writers, want one step each", before, after, spenders)
	}
	// A lock taken first stops every writer that comes after it.
	e.exec(t, `UPDATE ctrlz.profiles SET lock_state = 'locked', lock_password_hash = 'h' WHERE id = $1`, e.A.Profile)
	passed := wins(t, spenders, func(i int, hold func()) (bool, error) {
		var ok bool
		err := e.tenant.WithTenant(e.ctx, e.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
			hold()
			_, g, err := tx.ProfileGuard(e.A.Profile)
			ok = g.Yes()
			return err
		})
		return ok, err
	})
	if passed != 0 {
		t.Errorf("%d writers passed the guard of a locked profile", passed)
	}
}

func driveProfileDelete(t *testing.T, e *raceEnv) {
	victim := uuid.Must(uuid.NewV7())
	e.exec(t, `INSERT INTO ctrlz.profiles (tenant_id, id, name) VALUES ($1, $2, 'victim')`, e.A.Tenant, victim)
	settle := newBarrier(spenders, 400*time.Millisecond)
	got := wins(t, spenders, func(i int, hold func()) (bool, error) {
		var w store.Won
		err := e.tenant.WithTenant(e.ctx, e.A.Tenant, store.TxOpts{}, func(tx store.Tx) (err error) {
			hold()
			if err := tx.ProfileClientsLock(victim); err != nil {
				return err
			}
			_, w, err = tx.ProfileDelete(victim)
			settle()
			return err
		})
		return w.Yes(), err
	})
	if got != 1 {
		t.Errorf("%d deletes of one profile won, want exactly 1", got)
	}
	// A relock between the read and the delete: a locked profile is not deleted.
	locked := uuid.Must(uuid.NewV7())
	e.exec(t, `INSERT INTO ctrlz.profiles (tenant_id, id, name, lock_state, lock_password_hash) VALUES ($1, $2, 'locked', 'locked', 'h')`, e.A.Tenant, locked)
	if err := e.tenant.WithTenant(e.ctx, e.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
		if err := tx.ProfileClientsLock(locked); err != nil {
			return err
		}
		_, w, err := tx.ProfileDelete(locked)
		if w.Yes() {
			t.Error("a locked profile was deleted")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

// queueJob makes the tenant's one active job by the tenant's own role, as a request does.
func queueJob(t *testing.T, e *raceEnv) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := e.tenant.WithTenant(e.ctx, e.A.Tenant, store.TxOpts{}, func(tx store.Tx) (err error) {
		id, err = tx.JobQueue("rules_batch", e.A.Profile, 2000, []byte(`{"items":[]}`))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return id
}

func driveJobClaim(t *testing.T, e *raceEnv) {
	e.clearJobs(t)
	id := queueJob(t, e)
	// A claim makes a queued job running, and a second claim of a running job is the retry of the same
	// work, so every one of them proceeds; what no claim may do is revive a job that has ended.
	got := wins(t, spenders, func(i int, hold func()) (bool, error) {
		var w store.Won
		err := e.worker.WithTenant(e.ctx, e.A.Tenant, store.TxOpts{}, func(tx store.Tx) (err error) {
			hold()
			_, w, err = tx.JobClaim(id)
			return err
		})
		return w.Yes(), err
	})
	if got != spenders {
		t.Errorf("%d of %d claims of a live job proceeded", got, spenders)
	}
	if err := e.worker.WithTenant(e.ctx, e.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
		w, err := tx.JobFinish(id, []byte(`{}`), uuid.Nil)
		if err == nil && !w.Yes() {
			t.Error("a running job could not be finished")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	over := wins(t, spenders, func(i int, hold func()) (bool, error) {
		var w store.Won
		err := e.worker.WithTenant(e.ctx, e.A.Tenant, store.TxOpts{}, func(tx store.Tx) (err error) {
			hold()
			_, w, err = tx.JobClaim(id)
			return err
		})
		return w.Yes(), err
	})
	if over != 0 {
		t.Errorf("%d claims revived a finished job", over)
	}
}

func driveJobFinish(t *testing.T, e *raceEnv) {
	for _, finish := range []string{"finish", "fail"} {
		e.clearJobs(t)
		id := queueJob(t, e)
		if err := e.worker.WithTenant(e.ctx, e.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
			_, w, err := tx.JobClaim(id)
			if err == nil && !w.Yes() {
				t.Error("claim lost")
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
		// Finish and mark-failed race for the end of one job: exactly one of the spenders ends it.
		got := wins(t, spenders, func(i int, hold func()) (bool, error) {
			var w store.Won
			err := e.worker.WithTenant(e.ctx, e.A.Tenant, store.TxOpts{}, func(tx store.Tx) (err error) {
				hold()
				if (i%2 == 0) == (finish == "finish") {
					w, err = tx.JobFinish(id, []byte(`{}`), uuid.Nil)
				} else {
					w, err = tx.JobFail(id, []byte(`{"code":"x"}`))
				}
				return err
			})
			return w.Yes(), err
		})
		if got != 1 {
			t.Errorf("%s: %d spenders ended one job, want exactly 1", finish, got)
		}
		if n := e.count(t, `SELECT count(*) FROM ctrlz.batch_jobs WHERE id = $1 AND input IS NULL AND state IN ('done', 'failed')`, id); n != 1 {
			t.Errorf("%s: the job is not ended with its input cleared", finish)
		}
	}
}

func driveIdempotency(t *testing.T, e *raceEnv) {
	hash := []byte{1, 2, 3}
	settle := newBarrier(spenders, 400*time.Millisecond)
	got := wins(t, spenders, func(i int, hold func()) (bool, error) {
		var w store.Won
		err := e.tenant.WithTenant(e.ctx, e.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
			hold()
			won, replay, err := tx.IdempotencyBegin("twin", "/x", hash, time.Now(), time.Now().Add(time.Hour))
			if err != nil {
				return err
			}
			w = won
			if !won.Yes() {
				if !replay.Same || replay.Status != 201 {
					t.Errorf("a twin did not find the stored answer: %+v", replay)
				}
				return nil
			}
			// The effect, and the answer, in one transaction.
			if err := tx.NotificationAdd("idem.test", "info", []byte(`{}`)); err != nil {
				return err
			}
			settle() // the twins are waiting on the key by now, so the barrier gives up and this transaction commits
			return tx.IdempotencyFinish("twin", 201, []byte(`{"ok":true}`))
		})
		return w.Yes(), err
	})
	if got != 1 {
		t.Errorf("%d twins ran the effect, want exactly 1", got)
	}
	if n := e.count(t, `SELECT count(*) FROM ctrlz.notifications WHERE kind = 'idem.test'`); n != 1 {
		t.Errorf("%d effects, want 1", n)
	}
	// Another body under the same key is not a replay.
	if err := e.tenant.WithTenant(e.ctx, e.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
		_, replay, err := tx.IdempotencyBegin("twin", "/x", []byte{9}, time.Now(), time.Now().Add(time.Hour))
		if err == nil && replay.Same {
			t.Error("a key reused with another request was taken for a replay")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	// The same key in another tenant is another key.
	if err := e.tenant.WithTenant(e.ctx, e.B.Tenant, store.TxOpts{}, func(tx store.Tx) error {
		w, _, err := tx.IdempotencyBegin("twin", "/x", hash, time.Now(), time.Now().Add(time.Hour))
		if err == nil && !w.Yes() {
			t.Error("tenant B met tenant A's key")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

// driveProfileLock: of N lockers of one unlocked profile exactly one wins, and the lock is the winner's.
func driveProfileLock(t *testing.T, e *raceEnv) {
	settle := newBarrier(spenders, 400*time.Millisecond)
	got := wins(t, spenders, func(i int, hold func()) (bool, error) {
		var w store.Won
		err := e.tenant.WithTenant(e.ctx, e.A.Tenant, store.TxOpts{}, func(tx store.Tx) (err error) {
			hold()
			w, err = tx.ProfileLock(e.A.Profile, secret.New(fmt.Sprintf("hash-%d", i)), "", e.A.User)
			settle()
			return err
		})
		return w.Yes(), err
	})
	if got != 1 {
		t.Errorf("%d locks of one profile won, want exactly 1", got)
	}
	if n := e.count(t, `SELECT count(*) FROM ctrlz.profiles WHERE id = $1 AND lock_state = 'locked' AND lock_password_hash LIKE 'hash-%'`, e.A.Profile); n != 1 {
		t.Errorf("the profile is not locked by one of the lockers (%d)", n)
	}
}

// driveProfileUnlock: of N unlockers with the hash that was read one wins, and an unlock whose hash was replaced by a
// relock clears nothing.
func driveProfileUnlock(t *testing.T, e *raceEnv) {
	e.exec(t, `UPDATE ctrlz.profiles SET lock_state = 'locked', lock_password_hash = 'h1' WHERE id = $1`, e.A.Profile)
	settle := newBarrier(spenders, 400*time.Millisecond)
	got := wins(t, spenders, func(i int, hold func()) (bool, error) {
		var w store.Won
		err := e.tenant.WithTenant(e.ctx, e.A.Tenant, store.TxOpts{}, func(tx store.Tx) (err error) {
			hold()
			w, err = tx.ProfileUnlock(e.A.Profile, secret.New("h1"))
			settle()
			return err
		})
		return w.Yes(), err
	})
	if got != 1 {
		t.Errorf("%d unlocks of one lock won, want exactly 1", got)
	}
	e.exec(t, `UPDATE ctrlz.profiles SET lock_state = 'locked', lock_password_hash = 'h2' WHERE id = $1`, e.A.Profile)
	if err := e.tenant.WithTenant(e.ctx, e.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
		w, err := tx.ProfileUnlock(e.A.Profile, secret.New("h1"))
		if w.Yes() {
			t.Error("an unlock with a replaced hash cleared the lock")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if n := e.count(t, `SELECT count(*) FROM ctrlz.profiles WHERE id = $1 AND lock_state = 'locked'`, e.A.Profile); n != 1 {
		t.Error("the relock was lost")
	}
}
