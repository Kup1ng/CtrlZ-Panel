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
	r, err := keyring.NewEphemeral(keyring.DomainAdminTOTP, keyring.DomainSMSCred, keyring.DomainAdminMAC)
	if err != nil {
		t.Fatal(err)
	}
	return r
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
		keyring.DomainAdminTOTP: {1}, keyring.DomainSMSCred: {1}, keyring.DomainAdminMAC: {1},
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
