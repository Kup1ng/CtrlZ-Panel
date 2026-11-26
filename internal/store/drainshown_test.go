package store

import (
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Shared/zone"
)

// A row the hub left as "draining" before it restarted is shown as done once the drain's time has passed, and never before; a row
// that is none or done is left alone. Fails if drainShown returns the stored state unchanged for an old draining row (GP-r1-5).
func TestDrainShownAppliesTheDrainRuleToARowNoHubWatches(t *testing.T) {
	if drainDoneAfter != zone.Inputs().DrainDone {
		t.Fatalf("drainDoneAfter %v differs from zone.Inputs().DrainDone %v", drainDoneAfter, zone.Inputs().DrainDone)
	}
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	str := func(s string) *string { return &s }
	at := func(ago time.Duration) *time.Time { v := now.Add(-ago); return &v }
	for _, c := range []struct {
		name  string
		state *string
		since *time.Time
		want  string
	}{
		{"draining, drain time not yet passed", str("draining"), at(drainDoneAfter - time.Second), "draining"},
		{"draining, exactly the drain time", str("draining"), at(drainDoneAfter), "done"},
		{"draining, long ago (the hub restarted in the middle)", str("draining"), at(48 * time.Hour), "done"},
		{"draining with no start is left as it is", str("draining"), nil, "draining"},
		{"none is never promoted", str("none"), at(48 * time.Hour), "none"},
		{"done stays done", str("done"), at(48 * time.Hour), "done"},
	} {
		got := drainShown(c.state, c.since, true, now)
		if got == nil || *got != c.want {
			t.Errorf("%s: got %v, want %s", c.name, got, c.want)
		}
	}
	// A node back in the answer keeps the stored row as it is, however old the drain (GW2-r1-3): fails if drainShown ignores it.
	if got := drainShown(str("draining"), at(48*time.Hour), false, now); got == nil || *got != "draining" {
		t.Errorf("an advertised node's old draining row must not be shown as done, got %v", got)
	}
	if drainShown(nil, nil, true, now) != nil {
		t.Error("a node with no hub row must stay without a state")
	}
}
