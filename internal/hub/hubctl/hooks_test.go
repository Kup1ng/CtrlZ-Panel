package hubctl_test

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubctl"
)

// The start event runs before the hub accepts a Control stream (SC 8a.4 Versions): until the hub says it is accepting, a stream is
// answered UNAVAILABLE, which a node retries with backoff, and nothing about it is kept.
func TestAStreamIsRefusedUntilTheHubIsAccepting(t *testing.T) {
	var accepting atomic.Bool
	w := newWorld(t, free{}, func(c *hubctl.Config) { c.Accepting = accepting.Load })
	n := newNode(t)
	w.active(n)
	if err := w.srv.Control(n); status.Code(err) != codes.Unavailable {
		t.Fatalf("before the start event: %v", err)
	}
	if w.srv.Streams() != 0 {
		t.Fatal("a refused stream was registered")
	}
	accepting.Store(true)
	done := w.open(n)
	n.in <- heartbeat(0)
	if m := next(t, n); m.GetServerTime() == nil {
		t.Fatalf("an accepted stream starts with ServerTime, got %T", m.Body)
	}
	n.cancel()
	<-done
}

// The revocations go out after the first ServerTime and before any HeadNotice, once per stream, and every HeadNotice is told to the
// evaluator with its seq (fit(X) reads them).
func TestOpenedComesAfterTheFirstServerTimeAndBeforeTheFirstHeadNotice(t *testing.T) {
	var mu sync.Mutex
	var order []string
	var heads []uint64
	var w *world
	w = newWorld(t, free{}, func(c *hubctl.Config) {
		// What Opened does in the hub: put a Revocation on the stream. It goes through the stream's own queue, so its place among the
		// messages is the place the hook was called at.
		c.Opened = func(id uuid.UUID) {
			w.srv.Send(id, &hubv1.HubMessage{Body: &hubv1.HubMessage_Revocation{Revocation: &policyv1.Revocation{RevSeq: 1}}})
		}
		c.HeadSent = func(_ uuid.UUID, seq uint64, _ time.Time) { mu.Lock(); heads = append(heads, seq); mu.Unlock() }
		inner := c.WriterHook
		c.WriterHook = func(n uuid.UUID, m *hubv1.HubMessage) {
			mu.Lock()
			switch {
			case m.GetServerTime() != nil:
				order = append(order, "server_time")
			case m.GetRevocation() != nil:
				order = append(order, "revocation")
			case m.GetHeadNotice() != nil:
				order = append(order, "head_notice")
			}
			mu.Unlock()
			inner(n, m)
		}
	})
	n := newNode(t)
	w.active(n)
	w.roll.Written(3, "policy")
	done := w.open(n)
	n.in <- heartbeat(0)
	for got := false; !got; {
		got = next(t, n).GetHeadNotice() != nil
	}
	time.Sleep(80 * time.Millisecond) // several more ServerTimes: Opened must not repeat
	mu.Lock()
	defer mu.Unlock()
	opened := 0
	for _, o := range order {
		if o == "revocation" {
			opened++
		}
	}
	if opened != 1 || len(order) < 3 || order[0] != "server_time" || order[1] != "revocation" {
		t.Fatalf("order %v", order)
	}
	for i, o := range order {
		if o == "head_notice" && i < 2 {
			t.Fatalf("a HeadNotice before the revocations: %v", order)
		}
	}
	if len(heads) != 1 || heads[0] != 3 {
		t.Fatalf("heads told %v", heads)
	}
	n.cancel()
	<-done
}
