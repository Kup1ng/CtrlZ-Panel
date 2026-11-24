package password

import (
	"context"
	"errors"
	"testing"
	"time"
)

// The gate's own refusals, below the checks of the Hasher: derive is the last line
// of the rule, so it is tested with the Hasher out of the way (rule
// argon2-memory-budget).
func TestGateDeriveRefusesWhatDoesNotFit(t *testing.T) {
	ctx := context.Background()
	g := NewGateBudget(2, 20*time.Millisecond, 128) // 64 MiB a slot
	in, salt := []byte("password"), make([]byte, saltLen)

	if _, err := g.derive(ctx, in, salt, Params{MemoryKiB: 65537, Time: 1, Threads: 1}, hashLen, inSlot); !errors.Is(err, ErrOverBudget) {
		t.Errorf("one KiB over a slot: %v", err)
	}
	if g.Computed() != 0 {
		t.Errorf("a refused run was counted: %d", g.Computed())
	}
	if _, err := g.derive(ctx, in, salt, Params{MemoryKiB: 64, Time: 1, Threads: 1}, hashLen, inSlot); err != nil {
		t.Errorf("a small run: %v", err)
	}

	// tinyFree is a request, not a right: only a run of tinyMemKiB or less skips
	// the slot, however the caller asked.
	r1, _ := g.Acquire(ctx)
	r2, _ := g.Acquire(ctx)
	defer r1()
	defer r2()
	if _, err := g.derive(ctx, in, salt, Params{MemoryKiB: 64, Time: 1, Threads: 1}, hashLen, tinyFree); !errors.Is(err, ErrBusy) {
		t.Errorf("a 64 KiB run that asked for no slot, gate full: %v, want ErrBusy", err)
	}
	if _, err := g.derive(ctx, in, salt, oneTimeParams(), hashLen, tinyFree); err != nil {
		t.Errorf("the one-time run that asked for no slot, gate full: %v", err)
	}
	if _, err := g.derive(ctx, in, salt, oneTimeParams(), hashLen, inSlot); !errors.Is(err, ErrBusy) {
		t.Errorf("the one-time run that did not ask, gate full: %v, want ErrBusy", err)
	}
}

func TestCeilingIsTheBudgetPerSlot(t *testing.T) {
	for _, c := range []struct {
		slots     int
		budgetMiB uint64
		want      uint32
	}{
		{1, 64, 65536},
		{2, 128, 65536},
		{4, 192, 49152},
		{1, 1 << 20, maxStoredMemKiB}, // never above the absolute bound on a stored hash
	} {
		if got := NewGateBudget(c.slots, 0, c.budgetMiB).CeilingKiB(); got != c.want {
			t.Errorf("%d slots in %d MiB: ceiling %d KiB, want %d", c.slots, c.budgetMiB, got, c.want)
		}
	}
}
