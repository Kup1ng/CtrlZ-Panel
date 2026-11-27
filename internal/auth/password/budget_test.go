package password_test

import (
	"context"
	"errors"
	"runtime"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/password"
)

// The argon2-memory-budget rule (P1 auth review round 5, rules.md topic 22, spec
// 4.1). Its lint (internal/lint TestArgon2OnlyInTheGate) keeps argon2.IDKey inside
// Gate.derive; these tests show the other half: what the gate does with it.

// TestHasherAllocatesNothingBeforeFirstUse: building a hasher at the production
// cost, a service's or a console tool's, runs no Argon2 at all. The first run
// happens on first use, inside the gate, and is counted there. Both a counter and
// the allocator are read, because the counter sees only what went through the gate
// and an allocation made around it would not move it.
func TestHasherAllocatesNothingBeforeFirstUse(t *testing.T) {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	gate := password.NewGate(2, time.Second)
	h, err := password.NewHasher(password.DefaultParams(), gate)
	if err != nil {
		t.Fatal(err)
	}
	st := password.Settings{Params: password.DefaultParams(), Concurrency: 2, BudgetMiB: 192}
	sh, err := st.NewHasher()
	if err != nil {
		t.Fatal(err)
	}
	oh, err := password.NewOneTimeHasher()
	if err != nil {
		t.Fatal(err)
	}
	runtime.ReadMemStats(&after)
	for name, g := range map[string]*password.Gate{"NewHasher": gate, "Settings.NewHasher": sh.Gate(), "NewOneTimeHasher": oh.Gate()} {
		if g.Computed() != 0 {
			t.Errorf("%s: %d Argon2 runs while building", name, g.Computed())
		}
	}
	// One 46 MiB run adds 46 MiB to TotalAlloc; three hashers add a few KiB.
	if grew := after.TotalAlloc - before.TotalAlloc; grew > 4<<20 {
		t.Errorf("building hashers allocated %d KiB: an Argon2 run is hiding in a constructor", grew>>10)
	}
	// The counter can move: the dummy path of the first unknown phone is the first
	// run, it is one, and it went through the gate.
	if ok, err := h.Verify(context.Background(), pw("not a password"), pw("")); ok || err != nil {
		t.Fatalf("verify against nothing: %v %v", ok, err)
	}
	if gate.Computed() != 1 || h.Runs() != 1 {
		t.Errorf("first use: gate %d, hasher %d runs, want one each", gate.Computed(), h.Runs())
	}
}

// TestEveryRunWaitsForTheGate: with every slot held, each way of making an Argon2
// run is refused with ErrBusy, the dummy and a malformed stored hash included. The
// only runs that pass are the ones of the declared exception, an 8 KiB one-time
// hash made or checked by a caller that asked for no slot (4.1, 10.2 step 2).
func TestEveryRunWaitsForTheGate(t *testing.T) {
	ctx := context.Background()
	gate := password.NewGate(1, 20*time.Millisecond)
	h, err := password.NewHasher(fast, gate)
	if err != nil {
		t.Fatal(err)
	}
	normal, err := newHasher(t, fast, 1).Hash(ctx, pw("a password of some length"))
	if err != nil {
		t.Fatal(err)
	}
	oneTimePW, err := password.NewOneTime()
	if err != nil {
		t.Fatal(err)
	}
	oneTime, err := h.HashOneTime(oneTimePW)
	if err != nil {
		t.Fatal(err)
	}
	release, err := gate.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	before := gate.Computed()
	for name, call := range map[string]func() error{
		"Hash":                      func() error { _, err := h.Hash(ctx, pw("a password of some length")); return err },
		"Verify":                    func() error { _, err := h.Verify(ctx, pw("a password of some length"), normal); return err },
		"Verify, no stored hash":    func() error { _, err := h.Verify(ctx, pw("x"), pw("")); return err },
		"Verify, malformed hash":    func() error { _, err := h.Verify(ctx, pw("x"), pw("$argon2id$v=19$m=x")); return err },
		"Verify, a one-time hash":   func() error { _, err := h.Verify(ctx, oneTimePW, oneTime); return err },
		"VerifyGateFree, a normal":  func() error { _, err := h.VerifyGateFree(ctx, pw("a password of some length"), normal); return err },
		"VerifyGateFree, malformed": func() error { _, err := h.VerifyGateFree(ctx, pw("x"), pw("$argon2id$v=19$m=x")); return err },
	} {
		if err := call(); !errors.Is(err, password.ErrBusy) {
			t.Errorf("%s with the gate full: %v, want ErrBusy", name, err)
		}
	}
	if gate.Computed() != before {
		t.Errorf("%d runs started while the gate was full", gate.Computed()-before)
	}
	// The declared exception passes, and only for the tiny run.
	if ok, err := h.VerifyGateFree(ctx, oneTimePW, oneTime); err != nil || !ok {
		t.Errorf("VerifyGateFree of a one-time hash with a full gate: %v %v", ok, err)
	}
	if _, err := h.HashOneTime(oneTimePW); err != nil {
		t.Errorf("HashOneTime with a full gate: %v", err)
	}
}

// TestSettingsAreCheckedWhereverTheyComeFrom: the floor and the budget are the
// Settings' own, so a literal is held to the same rules as the environment.
func TestSettingsAreCheckedWhereverTheyComeFrom(t *testing.T) {
	ok := password.Settings{Params: password.DefaultParams(), Concurrency: 2, BudgetMiB: 192}
	if _, err := ok.NewHasher(); err != nil {
		t.Fatalf("the defaults: %v", err)
	}
	mod := func(f func(*password.Settings)) password.Settings { s := ok; f(&s); return s }
	for name, s := range map[string]password.Settings{
		"memory below OWASP":        mod(func(s *password.Settings) { s.Params.MemoryKiB = 8192 }),
		"19 MiB with t=1":           mod(func(s *password.Settings) { s.Params.MemoryKiB, s.Params.Time = 19456, 1 }),
		"no budget":                 mod(func(s *password.Settings) { s.BudgetMiB = 0 }),
		"no slots":                  mod(func(s *password.Settings) { s.Concurrency = 0 }),
		"slots times memory":        mod(func(s *password.Settings) { s.Concurrency = 5 }),
		"a row-sized memory":        mod(func(s *password.Settings) { s.Params.MemoryKiB = 262144 }),
		"no threads":                mod(func(s *password.Settings) { s.Params.Threads = 0 }),
		"time of zero":              mod(func(s *password.Settings) { s.Params.Time = 0 }),
		"a budget under one hash":   mod(func(s *password.Settings) { s.BudgetMiB, s.Concurrency = 40, 1 }),
		"relaxed does not lift it":  mod(func(s *password.Settings) { s.Relaxed, s.Concurrency = true, 5 }),
		"relaxed keeps the minimum": mod(func(s *password.Settings) { s.Relaxed, s.Params.MemoryKiB = true, 4 }),
	} {
		if _, err := s.NewHasher(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := mod(func(s *password.Settings) { s.Relaxed, s.Params.MemoryKiB = true, 64 }).NewHasher(); err != nil {
		t.Errorf("a relaxed 64 KiB: %v", err)
	}
}
