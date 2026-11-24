package app_test

import (
	"context"
	"errors"
	"runtime"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/app"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/password"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

// TestConnectAdminRunsNoFullCostArgon2 covers admin-r4-2. `docker compose exec
// admin ctrlz-admin ...` shares the cgroup of the live admin service, and the
// service's own hasher used to compute a dummy hash at the configured cost (46 MiB)
// when it was built; no hasher does any more (rule argon2-memory-budget, and
// TestNoEntryPointAllocatesArgon2 covers it without a database). The console tools
// only make one-time hashes, so starting one must allocate nothing near that,
// whatever the configured cost, and its hasher must refuse to store a chosen
// password under the cheap parameters.
func TestConnectAdminRunsNoFullCostArgon2(t *testing.T) {
	c := testpg.Need(t, cluster)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	d := c.NewDB(ctx, t)
	vars := dbEnv(t, d, "ctrlz_admin")
	vars["CTRLZ_ARGON2_M_KIB"] = "47104" // the production default, written out

	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, rt, st, err := app.ConnectAdmin(ctx, env(vars))
	runtime.ReadMemStats(&after)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	// One 46 MiB Argon2 run adds 46 MiB to TotalAlloc; connecting adds well under 10.
	if grew := after.TotalAlloc - before.TotalAlloc; grew > 20<<20 {
		t.Fatalf("ConnectAdmin allocated %d MiB, an Argon2 run at the configured cost", grew>>20)
	}
	if rt.Hasher == nil {
		t.Fatal("no hasher for the one-time passwords")
	}
	if m := rt.Hasher.Params().MemoryKiB; m > 64 {
		t.Fatalf("the console hasher is built at %d KiB", m)
	}
	// It does its one job.
	pw, err := password.NewOneTime()
	if err != nil {
		t.Fatal(err)
	}
	hash, err := rt.Hasher.HashOneTime(pw)
	if err != nil {
		t.Fatalf("HashOneTime: %v", err)
	}
	if ok, err := rt.Hasher.Verify(ctx, pw, hash); err != nil || !ok {
		t.Fatalf("verify of its own one-time hash: %v %v", ok, err)
	}
	// And only that: a chosen password is never stored under the cheap cost.
	if _, err := rt.Hasher.Hash(ctx, secret.New("a chosen password, not generated")); !errors.Is(err, password.ErrOneTimeOnly) {
		t.Fatalf("Hash on the console hasher: %v, want ErrOneTimeOnly", err)
	}
}
