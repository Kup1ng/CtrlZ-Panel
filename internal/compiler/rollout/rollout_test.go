package rollout

import (
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time      { return c.t }
func (c *clock) add(d time.Duration) { c.t = c.t.Add(d) }

func newQ(c *clock, nodes ...string) *Queue {
	q := New(Config{Now: c.now})
	q.SetOrder(nodes)
	for _, n := range nodes {
		q.Stream(n, true)
	}
	return q
}

func TestPolicyGoesNodeByNode(t *testing.T) {
	c := &clock{t: time.Unix(1000, 0)}
	q := newQ(c, "fallback", "primary", "third")
	q.Written(1, Policy)
	if q.Cursor("fallback") != 1 || q.Cursor("primary") != 0 || q.Cursor("third") != 0 {
		t.Fatalf("cursors %d %d %d, want 1 0 0", q.Cursor("fallback"), q.Cursor("primary"), q.Cursor("third"))
	}
	// The next node follows when the one before acks.
	q.Ack("fallback", 1, true)
	if q.Cursor("primary") != 1 || q.Cursor("third") != 0 {
		t.Fatalf("after the ack: %d %d", q.Cursor("primary"), q.Cursor("third"))
	}
	// Or after 5 s with no ack.
	c.add(4 * time.Second)
	if q.Cursor("third") != 0 {
		t.Fatal("moved before 5 s")
	}
	c.add(1100 * time.Millisecond)
	if q.Cursor("third") != 1 {
		t.Fatal("did not move after 5 s")
	}
}

func TestANodeWithoutAStreamHoldsNobody(t *testing.T) {
	c := &clock{t: time.Unix(1000, 0)}
	q := newQ(c, "a", "b", "c")
	q.Stream("a", false)
	q.Written(1, Policy)
	if q.Cursor("b") != 1 || q.Cursor("c") != 0 {
		t.Fatalf("b %d c %d, want 1 and 0 (c waits for b)", q.Cursor("b"), q.Cursor("c"))
	}
	q.Ack("b", 1, true)
	if q.Cursor("c") != 1 {
		t.Fatal("c did not follow b")
	}
}

func TestCatalogHoldsTheFleetBehindACanary(t *testing.T) {
	c := &clock{t: time.Unix(1000, 0)}
	q := newQ(c, "fallback", "primary")
	q.Written(1, Policy)
	q.Ack("fallback", 1, true)
	q.Ack("primary", 1, true)
	q.Written(2, Catalog)
	q.Written(3, Policy)
	if q.Release() != 1 {
		t.Fatalf("release %d, want 1 (everything behind the catalog entry waits)", q.Release())
	}
	if q.Cursor("fallback") != 2 || q.Cursor("primary") != 1 {
		t.Fatalf("canary %d, other %d, want 2 and 1", q.Cursor("fallback"), q.Cursor("primary"))
	}
	// The canary applies it and stays healthy for 60 s: the entry is released.
	q.Ack("fallback", 2, true)
	q.Heartbeat("fallback", Health{ResolveHealthy: true})
	c.add(59 * time.Second)
	if q.Release() != 1 {
		t.Fatal("released before the soak")
	}
	c.add(2 * time.Second)
	if q.Release() != 3 {
		t.Fatalf("release %d after the soak, want 3", q.Release())
	}
}

func TestACanaryFailureOnlyDelaysUpToTheCap(t *testing.T) {
	c := &clock{t: time.Unix(1000, 0)}
	q := newQ(c, "fallback", "primary")
	q.Written(1, Catalog)
	q.Ack("fallback", 1, true)
	q.Heartbeat("fallback", Health{ResolveHealthy: true, Quarantined: 0})
	q.Heartbeat("fallback", Health{ResolveHealthy: true, Quarantined: 1}) // a new quarantine
	c.add(90 * time.Second)
	if q.Release() != 0 || len(q.Held()) != 1 {
		t.Fatalf("a failed canary released the entry at 90 s: release %d", q.Release())
	}
	c.add(31 * time.Second)
	if q.Release() != 1 || len(q.Held()) != 0 {
		t.Fatalf("the cap of 120 s did not release it: release %d", q.Release())
	}
}

func TestACanaryThatNeverAcksIsReleasedAtTheCap(t *testing.T) {
	c := &clock{t: time.Unix(1000, 0)}
	q := newQ(c, "fallback", "primary")
	q.Written(1, Catalog)
	c.add(119 * time.Second)
	if q.Release() != 0 {
		t.Fatal("released early")
	}
	c.add(2 * time.Second)
	if q.Release() != 1 {
		t.Fatal("not released at 120 s")
	}
}

func TestACatalogEntryWithNoStreamIsReleasedAtOnce(t *testing.T) {
	c := &clock{t: time.Unix(1000, 0)}
	q := New(Config{Now: c.now})
	q.SetOrder([]string{"a", "b"})
	q.Written(1, Catalog)
	if q.Release() != 1 || len(q.Held()) != 0 {
		t.Fatalf("release %d with no stream", q.Release())
	}
}

func TestARestartStartsAtTheReleasePoint(t *testing.T) {
	c := &clock{t: time.Unix(1000, 0)}
	q := New(Config{Now: c.now})
	q.Written(7, Policy) // a hub that starts reads the head: no node is behind the queue
	q.SetOrder([]string{"a", "b", "c"})
	for _, n := range []string{"a", "b", "c"} {
		if q.Cursor(n) != 7 {
			t.Fatalf("%s starts at %d, want 7", n, q.Cursor(n))
		}
	}
}

// W4-r1-7: the soak ends early only for a canary that heartbeat after it applied and still has its stream.
func TestASilentCanaryIsNotReleasedEarly(t *testing.T) {
	c := &clock{t: time.Unix(1000, 0)}
	q := newQ(c, "fallback", "primary")
	q.Written(1, Catalog)
	q.Ack("fallback", 1, true) // applied, and no heartbeat after it
	c.add(61 * time.Second)
	if q.Release() != 0 {
		t.Fatal("a canary that never heartbeat after its ack ended the soak")
	}
	c.add(60 * time.Second)
	if q.Release() != 1 {
		t.Fatal("the cap did not release it")
	}

	q = newQ(c, "fallback", "primary")
	q.Written(2, Catalog)
	q.Ack("fallback", 2, true)
	q.Heartbeat("fallback", Health{ResolveHealthy: true})
	q.Stream("fallback", false) // it died
	c.add(61 * time.Second)
	if q.Release() != 1 {
		t.Fatalf("a canary with no stream ended the soak: release %d", q.Release())
	}
}

// W4-r3-11: an ack above what was written, or above what the node may read, is ignored and reported: one node cannot take the
// stagger away from the nodes behind it.
func TestAnAckAboveWhatWasServedIsIgnored(t *testing.T) {
	c := &clock{t: time.Unix(1000, 0)}
	q := newQ(c, "fallback", "primary", "third")
	q.Written(1, Policy)
	if q.Ack("fallback", 1<<63, true) {
		t.Fatal("an ack of seq 2^63 was believed")
	}
	if q.Cursor("primary") != 0 {
		t.Fatalf("the node behind the liar moved to %d", q.Cursor("primary"))
	}
	// Above its own cursor but not above what is written: also not served to it yet.
	q.Written(2, Policy)
	if q.Ack("primary", 2, true) {
		t.Fatal("an ack of an entry the node was never allowed to read was believed")
	}
	if !q.Ack("fallback", 2, true) || q.Cursor("primary") != 2 {
		t.Fatal("a true ack was refused")
	}
}
