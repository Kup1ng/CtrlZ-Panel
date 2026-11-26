package api

import (
	"testing"

	"github.com/google/uuid"
)

// The cache answers for the exact version it was given, never for another, and keeps tenants apart (p2-B3-r14-1).
func TestRuleCountCacheAnswersOnlyForTheVersionItSaw(t *testing.T) {
	var c ruleCountCache // the zero value works
	tenA, tenB, prof := uuid.New(), uuid.New(), uuid.New()
	if _, ok := c.get(tenA, prof, 1); ok {
		t.Fatal("an empty cache answered")
	}
	c.put(tenA, prof, 3, 10)
	if n, ok := c.get(tenA, prof, 3); !ok || n != 10 {
		t.Fatalf("same version: %d, %v", n, ok)
	}
	for _, v := range []int64{2, 4} {
		if _, ok := c.get(tenA, prof, v); ok {
			t.Fatalf("answered for version %d, which it did not see", v)
		}
	}
	if _, ok := c.get(tenB, prof, 3); ok {
		t.Fatal("tenant B read a count of tenant A")
	}
	// A reader with an older snapshot does not push out the newer count; a newer one replaces it.
	c.put(tenA, prof, 2, 7)
	if n, ok := c.get(tenA, prof, 3); !ok || n != 10 {
		t.Fatalf("an older put replaced the newer entry: %d, %v", n, ok)
	}
	c.put(tenA, prof, 5, 12)
	if _, ok := c.get(tenA, prof, 3); ok {
		t.Fatal("the old version still answers after a newer put")
	}
	if n, ok := c.get(tenA, prof, 5); !ok || n != 12 {
		t.Fatalf("newer put: %d, %v", n, ok)
	}
}

// At its bound the cache empties instead of growing, and an entry already held is replaced without emptying it.
func TestRuleCountCacheIsBounded(t *testing.T) {
	var c ruleCountCache
	ten := uuid.New()
	first := uuid.New()
	c.put(ten, first, 1, 1)
	for i := 1; i < ruleCountCacheMax; i++ {
		c.put(ten, uuid.New(), 1, i)
	}
	if len(c.m) != ruleCountCacheMax {
		t.Fatalf("%d entries, want %d", len(c.m), ruleCountCacheMax)
	}
	c.put(ten, first, 2, 5) // a replacement at the bound keeps the rest
	if len(c.m) != ruleCountCacheMax {
		t.Fatalf("a replacement changed the size to %d", len(c.m))
	}
	c.put(ten, uuid.New(), 1, 1)
	if len(c.m) != 1 {
		t.Fatalf("%d entries after a new key at the bound, want the cache emptied and the new entry in", len(c.m))
	}
}
