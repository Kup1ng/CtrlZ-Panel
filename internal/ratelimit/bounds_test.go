package ratelimit

import (
	"os"
	"regexp"
	"slices"
	"strconv"
	"testing"
	"time"
)

// luaConst reads `local NAME = 123` out of one of the embedded scripts.
func luaConst(t *testing.T, file, name string) int64 {
	t.Helper()
	b, err := os.ReadFile("lua/" + file)
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^local ` + name + ` = (\d+)$`).FindSubmatch(b)
	if m == nil {
		t.Fatalf("%s has no `local %s = <number>`", file, name)
	}
	n, err := strconv.ParseInt(string(m[1]), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// TestScriptBoundsAreThoseOfTheGoLimiter is admin-r14-4. The scripts refuse a call outside the numbers
// below, and the Go limiter must never send one: so the constants of both sides are equal, and the worst
// subject of every class of both services, with every key it can have, fits inside them.
func TestScriptBoundsAreThoseOfTheGoLimiter(t *testing.T) {
	// Every script of the directory is held to the bounds: a script added later that is not in this
	// list fails here and not in production, where the services may EVALSHA it with any arguments.
	entries, err := os.ReadDir("lua")
	if err != nil {
		t.Fatal(err)
	}
	checked := []string{"take.lua", "give.lua"}
	for _, e := range entries {
		if !slices.Contains(checked, e.Name()) {
			t.Errorf("lua/%s has no bounds check pinned here (admin-r14-4): add it to this test and give it the MAX_* constants", e.Name())
		}
	}
	for _, f := range checked {
		for name, want := range map[string]int64{"MAX_SLOTS": scriptMaxSlots, "MAX_CAP": scriptMaxCap, "MAX_PER": scriptMaxPerMs} {
			if got := luaConst(t, f, name); got != want {
				t.Errorf("%s: %s = %d, Go says %d", f, name, got, want)
			}
		}
	}
	every := Subject{Network: "n", Wide: "w", Session: "s", SessionID: "i", TokenSession: "t", Proof: "p", ProofSubject: "u"}
	for _, svc := range []Service{Tenant, Admin} {
		l := New(Config{Service: svc, LocalOnly: true})
		for _, c := range Classes(svc) {
			// A class with a proof in two spellings: the plain one and the proof-alternative one.
			for _, s := range []Subject{every, {Network: "n", Wide: "w"}} {
				slots := l.slots(c, s)
				if len(slots) > scriptMaxSlots {
					t.Errorf("%s/%s names %d slots, the scripts take %d", svc, c.Name, len(slots), scriptMaxSlots)
				}
				for _, sl := range slots {
					if sl.max < 1 || sl.max > scriptMaxCap {
						t.Errorf("%s/%s: capacity %d outside 1..%d", svc, c.Name, sl.max, scriptMaxCap)
					}
					if sl.per < time.Millisecond || sl.per.Milliseconds() > scriptMaxPerMs {
						t.Errorf("%s/%s: period %v outside the scripts' range", svc, c.Name, sl.per)
					}
				}
			}
		}
	}
}
