package store_test

import (
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// throttleLine is the two ends of the refund under test: a hit and a refund, tenant or admin.
type throttleLine struct {
	name   string
	scope  string
	hit    func(t *testing.T, key []byte, max int, window time.Duration) store.ThrottleResult
	refund func(t *testing.T, key []byte, window time.Duration, epoch int64)
	reset  func(t *testing.T, key []byte)
}

// TestRefundNeverReachesAnotherWindow is primitives-r6-2. A refund names the window its attempt
// was counted in (the epoch the hit returned), and a window that restarted or a line that was
// cleared since is another epoch: the attempt of the request that restarted it is not given back.
// Both the tenant pair and the admin pair are held to it.
func TestRefundNeverReachesAnotherWindow(t *testing.T) {
	f := newFixture(t)
	tenant := f.db.Store(f.ctx, t, store.RoleTenant).Auth()
	admin := f.db.Store(f.ctx, t, store.RoleAdmin).Admin()
	lines := []throttleLine{
		{
			name: "tenant", scope: "login_net",
			hit: func(t *testing.T, k []byte, m int, w time.Duration) store.ThrottleResult {
				r, err := tenant.ThrottleHit(f.ctx, "login_net", k, m, w)
				if err != nil {
					t.Fatal(err)
				}
				return r
			},
			refund: func(t *testing.T, k []byte, w time.Duration, e int64) {
				if err := tenant.ThrottleRefund(f.ctx, "login_net", k, w, e); err != nil {
					t.Fatal(err)
				}
			},
			reset: func(t *testing.T, k []byte) {
				if err := tenant.ThrottleReset(f.ctx, "login_net", k); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "admin", scope: "admin_login_net",
			hit: func(t *testing.T, k []byte, m int, w time.Duration) store.ThrottleResult {
				r, err := admin.ThrottleHit(f.ctx, "admin_login_net", k, m, w)
				if err != nil {
					t.Fatal(err)
				}
				return r
			},
			refund: func(t *testing.T, k []byte, w time.Duration, e int64) {
				if err := admin.ThrottleRefund(f.ctx, "admin_login_net", k, w, e); err != nil {
					t.Fatal(err)
				}
			},
			reset: func(t *testing.T, k []byte) {
				if err := admin.ThrottleReset(f.ctx, "admin_login_net", k); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for i, ln := range lines {
		t.Run(ln.name, func(t *testing.T) {
			const max = 2
			// The window of one second: long enough for the three hits, short enough to wait out.
			win := time.Second
			// In the same window the refund works: hit, give back, and the line has its two again.
			k := sha32(byte(150 + i*10))
			a := ln.hit(t, k, max, win)
			ln.refund(t, k, win, a.Epoch)
			for n := 1; n <= max; n++ {
				if r := ln.hit(t, k, max, win); !r.Allowed {
					t.Fatalf("hit %d after a refund in its own window was refused", n)
				}
			}

			// The window rolls over and another request restarts it. The first request refunds with
			// its epoch: nothing is given back, so the line has one used and not none.
			k = sha32(byte(151 + i*10))
			a = ln.hit(t, k, max, win)
			time.Sleep(win + 200*time.Millisecond)
			b := ln.hit(t, k, max, win)
			if b.Epoch == a.Epoch {
				t.Fatalf("a restarted window kept epoch %d", a.Epoch)
			}
			ln.refund(t, k, win, a.Epoch)
			if r := ln.hit(t, k, max, win); !r.Allowed {
				t.Fatal("the second hit of the new window was refused")
			}
			if r := ln.hit(t, k, max, win); r.Allowed {
				t.Error("a refund of the old window gave back the attempt that restarted the new one")
			}

			// A line that was cleared is another epoch too: the success of one request must not let an
			// earlier attempt be taken out of the count that follows it.
			k = sha32(byte(152 + i*10))
			a = ln.hit(t, k, max, 10*time.Minute)
			ln.reset(t, k)
			b = ln.hit(t, k, max, 10*time.Minute)
			if b.Epoch == a.Epoch {
				t.Fatalf("a cleared line kept epoch %d", a.Epoch)
			}
			ln.refund(t, k, 10*time.Minute, a.Epoch)
			if r := ln.hit(t, k, max, 10*time.Minute); !r.Allowed {
				t.Fatal("the second hit after the clear was refused")
			}
			if r := ln.hit(t, k, max, 10*time.Minute); r.Allowed {
				t.Error("a refund from before the clear gave back an attempt counted after it")
			}
			// And the right epoch still works, so the test cannot pass by the refund doing nothing.
			k = sha32(byte(153 + i*10))
			a = ln.hit(t, k, max, 10*time.Minute)
			b = ln.hit(t, k, max, 10*time.Minute)
			ln.refund(t, k, 10*time.Minute, b.Epoch)
			if r := ln.hit(t, k, max, 10*time.Minute); !r.Allowed {
				t.Error("a refund with the live epoch gave nothing back")
			}
		})
	}
}

// TestARefusedHitDoesNotCostARefund is primitives-r7-7. A refused hit used to raise the count to
// max + 1, so the refund of an earlier allowed attempt only brought it back to max and the line
// stayed full: the owner whose login was busy at the Argon2 gate kept the attempt spent whenever a
// stranger on the same network was refused between his charge and the gate's answer. A refused hit
// leaves the line as it found it now, on both pairs.
func TestARefusedHitDoesNotCostARefund(t *testing.T) {
	f := newFixture(t)
	tenant := f.db.Store(f.ctx, t, store.RoleTenant).Auth()
	admin := f.db.Store(f.ctx, t, store.RoleAdmin).Admin()
	type pair struct {
		name   string
		hit    func(k []byte, max int, w time.Duration) (store.ThrottleResult, error)
		refund func(k []byte, w time.Duration, e int64) error
	}
	pairs := []pair{
		{"tenant",
			func(k []byte, m int, w time.Duration) (store.ThrottleResult, error) {
				return tenant.ThrottleHit(f.ctx, "login_net", k, m, w)
			},
			func(k []byte, w time.Duration, e int64) error {
				return tenant.ThrottleRefund(f.ctx, "login_net", k, w, e)
			},
		},
		{"admin",
			func(k []byte, m int, w time.Duration) (store.ThrottleResult, error) {
				return admin.ThrottleHit(f.ctx, "admin_login_net", k, m, w)
			},
			func(k []byte, w time.Duration, e int64) error {
				return admin.ThrottleRefund(f.ctx, "admin_login_net", k, w, e)
			},
		},
	}
	for i, p := range pairs {
		t.Run(p.name, func(t *testing.T) {
			const max = 3
			win := 10 * time.Minute
			k := sha32(byte(170 + i))
			mustHit := func(want bool) store.ThrottleResult {
				t.Helper()
				r, err := p.hit(k, max, win)
				if err != nil {
					t.Fatal(err)
				}
				if r.Allowed != want {
					t.Fatalf("hit allowed = %v, want %v", r.Allowed, want)
				}
				return r
			}
			mustHit(true) // the line stands at max - 1 ...
			mustHit(true)
			owner := mustHit(true) // ... the owner's login is counted: max
			for n := 0; n < 5; n++ {
				mustHit(false) // strangers are refused, and spend nothing
			}
			// The gate answered busy: the owner's attempt goes back, and his retry passes.
			if err := p.refund(k, win, owner.Epoch); err != nil {
				t.Fatal(err)
			}
			mustHit(true)
			mustHit(false)
			// The count is not past max in the table, so the refund of the one attempt left is the
			// same arithmetic whatever was refused in between.
			var n int
			super, err := f.db.Super(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer super.Close(f.ctx)
			if err := super.QueryRow(f.ctx, `SELECT count FROM ctrlz.auth_throttle WHERE key = $1`, k).Scan(&n); err != nil {
				t.Fatal(err)
			}
			if n != max {
				t.Errorf("the line holds %d, want exactly its maximum %d", n, max)
			}
		})
	}
}
