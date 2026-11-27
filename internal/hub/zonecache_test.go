package hub

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

type zoneStore struct {
	ControlStore // only HubLiveZones is called
	zones        store.HubZones
	err          error
	reads        int
}

func (z *zoneStore) HubLiveZones(context.Context) (store.HubZones, error) {
	z.reads++
	return z.zones, z.err
}

// H-r1-5 and H-r1-10: a read that fails is not "no zone". Until one read has succeeded the answer is unknown, which the hub
// reads as probing (so Ready waits for probe rounds that cannot complete), and a failed read is not tried again by every caller.
func TestZoneCacheTellsUnknownFromNoneAndDoesNotReadOnEveryCall(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	zs := &zoneStore{err: errors.New("down")}
	d := Deps{Stores: Stores{Control: zs}, Now: func() time.Time { return now }}
	var c zoneCache
	for i := 0; i < 5; i++ {
		if zone, known := c.get(d); zone != "" || known {
			t.Fatalf("a failed read answers (%q, %v), want unknown", zone, known)
		}
	}
	if zs.reads != 1 {
		t.Fatalf("a failed read was repeated by every caller: %d reads", zs.reads)
	}
	now = now.Add(zoneRetry)
	zs.err, zs.zones = nil, store.HubZones{DNSZone: "dns.example.ir"}
	if zone, known := c.get(d); zone != "dns.example.ir" || !known || zs.reads != 2 {
		t.Fatalf("after the retry window: (%q, %v) after %d reads", zone, known, zs.reads)
	}
	// A later failure keeps the last answer, and the window is the short one.
	now = now.Add(zoneEvery)
	zs.err = errors.New("down")
	for i := 0; i < 3; i++ {
		if zone, known := c.get(d); zone != "dns.example.ir" || !known {
			t.Fatalf("the last answer stands: (%q, %v)", zone, known)
		}
	}
	if zs.reads != 3 {
		t.Fatalf("reads %d, want 3", zs.reads)
	}
}
