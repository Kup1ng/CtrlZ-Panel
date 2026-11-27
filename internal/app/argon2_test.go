package app_test

import (
	"runtime"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/app"
)

// TestNoEntryPointAllocatesArgon2 is the entry-point half of the argon2-memory-budget
// rule (P1 auth review round 5, rules.md topic 22). Every way a process starts, each
// role and the console tool of the admin role (ctrlz-admin, which runs inside the
// live admin container's cgroup), is built at the production cost of 46 MiB, and none
// may run Argon2 before its first use. The counter is the gate's; the allocator is
// read as well, so an allocation made around the gate would show too. A role added
// to app.Roles is covered without a line here.
func TestNoEntryPointAllocatesArgon2(t *testing.T) {
	type entry struct {
		role    app.Role
		console bool
	}
	var entries []entry
	for _, r := range app.Roles() {
		entries = append(entries, entry{r, false})
	}
	entries = append(entries, entry{app.RoleAdmin, true}) // ctrlz-admin
	hashers := 0
	for _, e := range entries {
		name := string(e.role)
		if e.console {
			name += " console tool"
		}
		t.Run(name, func(t *testing.T) {
			cfg, err := app.LoadConfig(e.role, env(map[string]string{"CTRLZ_ARGON2_M_KIB": "47104", "CTRLZ_ARGON2_T": "2", "CTRLZ_DB_HOST": "db.invalid", "CTRLZ_DB_PASSWORD_FILE": writeSecret(t, "pw", "x")}))
			if err != nil {
				t.Fatal(err)
			}
			var before, after runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&before)
			rt, err := app.NewRuntimeForTest(cfg, e.console)
			runtime.ReadMemStats(&after)
			if err != nil {
				t.Fatal(err)
			}
			if grew := after.TotalAlloc - before.TotalAlloc; grew > 20<<20 {
				t.Errorf("starting allocated %d MiB: an Argon2 run happens before first use", grew>>20)
			}
			if rt.Hasher == nil {
				return
			}
			hashers++
			if n := rt.Hasher.Gate().Computed(); n != 0 {
				t.Errorf("%d Argon2 runs before first use", n)
			}
			if e.console && rt.Hasher.Gate().CeilingKiB() > 8 {
				t.Errorf("the console tool's gate lets a run use %d KiB; it only makes 8 KiB one-time hashes", rt.Hasher.Gate().CeilingKiB())
			}
		})
	}
	if hashers < 3 {
		t.Errorf("only %d entry points had a hasher (api, admin and the console tool expected): the test looks at the wrong thing", hashers)
	}
}
