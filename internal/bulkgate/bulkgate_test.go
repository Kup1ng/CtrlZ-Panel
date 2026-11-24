package bulkgate_test

import (
	"sync"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/bulkgate"
)

// The gate refuses without waiting, holds one tenant to its share, and gives memory back exactly once (spec 6.2).
func TestTheGateBoundsTheProcessAndTheTenant(t *testing.T) {
	g := bulkgate.New(20<<20, 8<<20)
	r1, ok := g.Acquire("a", 6<<20)
	if !ok {
		t.Fatal("the first Import was refused")
	}
	if _, ok := g.Acquire("a", 6<<20); ok {
		t.Fatal("a tenant held more than its share")
	}
	r2, ok := g.Acquire("a", 1<<20)
	if !ok {
		t.Fatal("a 1 MiB body beside one Import was refused: the share is 8 MiB")
	}
	if _, ok := g.Acquire("b", 6<<20); !ok {
		t.Fatal("another tenant was refused by A's share")
	}
	if _, ok := g.Acquire("c", 8<<20); ok {
		t.Fatal("the process held more than its total")
	}
	r1()
	r1() // a second release gives nothing back
	if all, mine := g.Held("a"); mine != 1<<20 || all != 7<<20 {
		t.Fatalf("held %d, %d after one release", all, mine)
	}
	r2()
	if _, mine := g.Held("a"); mine != 0 {
		t.Fatalf("tenant A still holds %d", mine)
	}
}

func TestTheGateIsSafeUnderRacingTenants(t *testing.T) {
	g := bulkgate.New(64<<20, 8<<20)
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if rel, ok := g.Acquire("t", 6<<20); ok {
				rel()
			}
		}()
	}
	wg.Wait()
	if all, mine := g.Held("t"); all != 0 || mine != 0 {
		t.Fatalf("held %d, %d after every request answered", all, mine)
	}
}

// A reservation follows the bytes of a body: a body that has sent little holds little, it can be raised to the weight
// of its work, a refused raise changes nothing, and a release gives back what is held now (spec 6.2).
func TestAReservationFollowsItsBytes(t *testing.T) {
	g := bulkgate.New(20<<20, 8<<20)
	r := g.Reserve("a")
	if all, _ := g.Held("a"); all != 0 {
		t.Fatalf("an opened reservation holds %d", all)
	}
	if !r.To(100) {
		t.Fatal("a trickle was refused")
	}
	if all, mine := g.Held("a"); all != 100 || mine != 100 {
		t.Fatalf("a body that sent 100 bytes holds %d, %d", all, mine)
	}
	if r.To(9 << 20) {
		t.Fatal("a body above the tenant's share was taken")
	}
	if _, mine := g.Held("a"); mine != 100 {
		t.Fatalf("a refused raise changed what is held: %d", mine)
	}
	if !r.To(8 << 20) {
		t.Fatal("the whole share was refused")
	}
	if !r.To(1 << 20) {
		t.Fatal("a reservation could not shrink")
	}
	if _, mine := g.Held("a"); mine != 1<<20 {
		t.Fatalf("a shrunk reservation holds %d", mine)
	}
	r.Release()
	r.Release()
	if r.To(10) {
		t.Fatal("a released reservation took memory again")
	}
	if all, mine := g.Held("a"); all != 0 || mine != 0 {
		t.Fatalf("held %d, %d after release", all, mine)
	}
}
