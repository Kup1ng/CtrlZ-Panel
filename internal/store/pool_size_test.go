package store

import "testing"

// A store has one pool and the pool is the footprint (rule one-connection-per-request,
// db-r2-3, db-r2-6). The second pool that served single-statement calls made from inside a
// transaction doubled every role's connections and needed its own sizing; the pool size a
// service is configured with is now the number of connections it can hold, for every role,
// and the deploy profiles count that number and the one-connection command-line tools
// against each role's CONNECTION LIMIT (internal/lint, compose test).
func TestPoolSizeIsTheWholeFootprint(t *testing.T) {
	for _, role := range []Role{RoleTenant, RoleAdmin, RoleWorker, RoleHub, RoleCompiler, RoleKeytool} {
		for _, n := range []int32{1, 3, 8, 40} {
			got, err := PoolSize(Config{MaxConns: n}, role)
			if err != nil {
				t.Fatal(err)
			}
			if got != n {
				t.Errorf("%s: configured %d connections, the pool allows %d", role, n, got)
			}
		}
	}
}

// A cold pool's first statement must not pay for JIT compilation. The first
// login after a restart loads ctrlz_fn.auth_public_config() on a new connection;
// with JIT on that one-row query took 350 to 850 ms (more than 2 s on a loaded
// host) because the planner estimates a never-analysed singleton table at
// hundreds of rows. The pool must ask for jit=off at connect time, whatever the
// server's own default is.
func TestPoolConnectsWithJITOff(t *testing.T) {
	for _, role := range []Role{RoleTenant, RoleAdmin, RoleWorker, RoleHub, RoleCompiler, RoleKeytool} {
		pc, err := poolConfig("host=localhost port=1 dbname=x user="+string(role), Config{}, role)
		if err != nil {
			t.Fatal(err)
		}
		if got := pc.ConnConfig.RuntimeParams["jit"]; got != "off" {
			t.Errorf("%s: jit runtime parameter = %q, want off", role, got)
		}
	}
}
