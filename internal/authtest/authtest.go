// Package authtest is the test fixture of the P1 auth packages: a migrated
// Postgres with two seeded tenants, A and B, and a store for each database role
// the services use. Two tenants are the point: every tenant-scoped test in P1
// acts as one and checks that the other did not move (T-386).
//
// Like testpg it is imported from test files only, and it fakes nothing.
package authtest

import (
	"context"
	"crypto/rand"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/password"
	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store/catalogtest"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

// Env is one database for one test.
type Env struct {
	Ctx  context.Context
	DB   *testpg.DB
	A, B catalogtest.SeedIDs
}

// New migrates a fresh database from the cluster and seeds tenants A and B. The
// context lives for twelve minutes, which bounds a hung test. Two minutes was
// enough until TestIsolation, which walks every route on one database, ran next
// to the rest of the suite and used all of it.
func New(t *testing.T, c *testpg.Cluster) *Env {
	t.Helper()
	c = testpg.Need(t, c)
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	t.Cleanup(cancel)
	db := c.NewDB(ctx, t)
	super, err := db.Super(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer super.Close(ctx)
	e := &Env{Ctx: ctx, DB: db, A: catalogtest.NewSeedIDs(1), B: catalogtest.NewSeedIDs(2)}
	if err := catalogtest.SeedGlobal(ctx, super); err != nil {
		t.Fatal(err)
	}
	for _, ids := range []catalogtest.SeedIDs{e.A, e.B} {
		if err := catalogtest.SeedTenant(ctx, super, ids); err != nil {
			t.Fatal(err)
		}
	}
	return e
}

// Tenant opens the store as ctrlz_tenant, the role of the api.
func (e *Env) Tenant(t *testing.T) *store.Store { return e.DB.Store(e.Ctx, t, store.RoleTenant) }

// Admin opens the store as ctrlz_admin.
func (e *Env) Admin(t *testing.T) *store.Store { return e.DB.Store(e.Ctx, t, store.RoleAdmin) }

// Worker opens the store as ctrlz_worker.
func (e *Env) Worker(t *testing.T) *store.Store { return e.DB.Store(e.Ctx, t, store.RoleWorker) }

// Keytool is the store of the one-shot key tool (rekey and declare-lost of user_totp), which has a
// database login of its own so the long-running worker cannot reach the seeds.
func (e *Env) Keytool(t *testing.T) *store.Store { return e.DB.Store(e.Ctx, t, store.RoleKeytool) }

// APIKeys is a key ring with the domains the api holds, on throw-away keys.
func APIKeys(t *testing.T) *keyring.Ring {
	t.Helper()
	r, err := keyring.NewEphemeral(keyring.DomainUserTOTP, keyring.DomainOTPDelivery, keyring.DomainAuthMAC)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// FastHasher is an Argon2 hasher with parameters small enough for a test. The
// code paths are the production ones; only the cost differs.
func FastHasher(t *testing.T) *password.Hasher {
	t.Helper()
	h, err := password.NewHasher(password.Params{MemoryKiB: 64, Time: 1, Threads: 1}, password.NewGate(4, 5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// AdminKeys is a key ring with the domains the admin service holds, on
// throw-away keys.
func AdminKeys(t *testing.T) *keyring.Ring {
	t.Helper()
	r, err := keyring.NewEphemeral(keyring.DomainAdminTOTP, keyring.DomainSMSCred, keyring.DomainAdminMAC, keyring.DomainInviteSign)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// InvitesOf is the public half of the invite_sign key of an admin ring, which is what the api of a test
// holds when the same test makes links with that ring (D67). One test, one signer, one verifier.
func InvitesOf(t *testing.T, admin *keyring.Ring) *keyring.PublicRing {
	t.Helper()
	p, err := admin.Public(keyring.DomainInviteSign)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// InviteRings is a signer holding only invite_sign and the public ring that opens what it signs, for a test of
// the api that makes links itself and has no admin service.
func InviteRings(t *testing.T) (*keyring.Ring, *keyring.PublicRing) {
	t.Helper()
	r, err := keyring.NewEphemeral(keyring.DomainInviteSign)
	if err != nil {
		t.Fatal(err)
	}
	return r, InvitesOf(t, r)
}

// SharedRings returns the admin service's key ring and the worker's, derived
// from one root, so what the admin seals under sms_cred the worker can open. A
// test that sends an SMS from the admin API through the worker needs this; the
// per-role helpers above use independent throw-away keys.
func SharedRings(t *testing.T) (admin, worker *keyring.Ring) {
	t.Helper()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	root := secret.NewBytes(raw)
	clear(raw)
	admin, err := keyring.FromRoot(root, map[string][]uint16{
		keyring.DomainAdminTOTP: {1}, keyring.DomainSMSCred: {1}, keyring.DomainAdminMAC: {1}, keyring.DomainInviteSign: {1},
	})
	if err != nil {
		t.Fatal(err)
	}
	worker, err = keyring.FromRoot(root, map[string][]uint16{keyring.DomainSMSCred: {1}, keyring.DomainOTPDelivery: {1}})
	if err != nil {
		t.Fatal(err)
	}
	return admin, worker
}

// count adapts the store of the environment to the waits of testpg (see testpg.AwaitLockWaiters).
func (e *Env) count(ctx context.Context, sql string) (int, error) {
	var n int
	err := e.DB.Scan(ctx, sql, nil, &n)
	return n, err
}

// AwaitLockWaiters returns when at least n backends of this test database are waiting for a lock, or says why
// it did not. It calls no testing function, so a goroutine other than the test's (the hook of a worker) may use
// it; the caller reports the error with t.Error.
func (e *Env) AwaitLockWaiters(n int) error { return testpg.AwaitLockWaiters(e.Ctx, e.count, n) }

// AwaitSleepers returns when at least n backends are inside pg_sleep, which is what a holder statement of a
// test is doing once it has taken its row. Same contract as AwaitLockWaiters.
func (e *Env) AwaitSleepers(n int) error { return testpg.AwaitSleepers(e.Ctx, e.count, n) }

// WaitForLockWaiters returns when at least n backends of this test database are waiting for a lock, which is
// the condition a test means by "the other call is now parked on the row": it reads pg_stat_activity as the
// superuser, so a wait of any role is seen. A test that slept for a while here passed vacuously on a runner
// that was slow to schedule the goroutine, because the race it was written for never ran (round 17,
// tenant-r17-13). It gives up after about thirty seconds and fails the test, so a call that never parks is
// a failure and not a hang. It counts iterations and reads no clock.
func (e *Env) WaitForLockWaiters(t *testing.T, n int) {
	t.Helper()
	if err := e.AwaitLockWaiters(n); err != nil {
		t.Fatal(err)
	}
}

// WaitForSleepers is AwaitSleepers for the goroutine of the test: it fails the test when the holder never got
// to pg_sleep.
func (e *Env) WaitForSleepers(t *testing.T, n int) {
	t.Helper()
	if err := e.AwaitSleepers(n); err != nil {
		t.Fatal(err)
	}
}
