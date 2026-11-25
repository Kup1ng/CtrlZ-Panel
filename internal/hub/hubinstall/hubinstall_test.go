package hubinstall

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// endless gives bytes for as long as it is read, a little slowly: a file that is never finished.
type endless struct{}

func (endless) Read(p []byte) (int, error) {
	time.Sleep(5 * time.Millisecond)
	return len(p), nil
}

// A download ends at its total time even when every single write succeeds (W3-r1-3): a peer that takes
// a byte at a time must not hold a bundle slot for as long as it likes.
func TestCopyPacedEndsAtItsMaxTime(t *testing.T) {
	h := New(Config{})
	done := make(chan struct{})
	go func() {
		h.copyPaced(context.Background(), httptest.NewRecorder(), endless{}, "bundle", 100*time.Millisecond, nil)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the download did not end at its maximum time")
	}
}

// A download whose token has died or been used stops, not only at the next request (W3-r1-6).
func TestCopyPacedEndsWhenTheTokenDies(t *testing.T) {
	h := New(Config{})
	h.recheck = 20 * time.Millisecond
	live := make(chan bool, 1)
	live <- true
	alive := func() bool {
		select {
		case v := <-live:
			live <- v
			return v
		default:
			return true
		}
	}
	done := make(chan struct{})
	go func() {
		h.copyPaced(context.Background(), httptest.NewRecorder(), endless{}, "bundle", time.Minute, alive)
		close(done)
	}()
	time.Sleep(60 * time.Millisecond)
	<-live
	live <- false
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the download went on after its token died")
	}
}

// Static responses in progress are capped hub-wide and per source network, and a place is given back.
func TestStaticResponsesInProgressAreCapped(t *testing.T) {
	h := New(Config{})
	var rels []func()
	for i := 0; i < StaticPerSource; i++ {
		rel, ok := h.enterStatic(httptest.NewRecorder(), "10.0.0.0/24")
		if !ok {
			t.Fatalf("place %d refused", i)
		}
		rels = append(rels, rel)
	}
	w := httptest.NewRecorder()
	if _, ok := h.enterStatic(w, "10.0.0.0/24"); ok || w.Code != http.StatusTooManyRequests {
		t.Fatalf("a place past the per-source cap: ok %v, status %d", ok, w.Code)
	}
	// Another network is not held back, until the hub-wide cap.
	for i := 0; i < StaticInFlight-StaticPerSource; i++ {
		rel, ok := h.enterStatic(httptest.NewRecorder(), fmt.Sprintf("172.16.%d.0/24", i/StaticPerSource))
		if !ok {
			t.Fatalf("place %d of other networks refused", i)
		}
		rels = append(rels, rel)
	}
	w = httptest.NewRecorder()
	if _, ok := h.enterStatic(w, "192.0.2.0/24"); ok || w.Code != http.StatusServiceUnavailable {
		t.Fatalf("a place past the hub-wide cap: ok %v, status %d", ok, w.Code)
	}
	for _, r := range rels {
		r()
	}
	rel, ok := h.enterStatic(httptest.NewRecorder(), "10.0.0.0/24")
	if !ok {
		t.Fatal("released places were not given back")
	}
	rel()
}
