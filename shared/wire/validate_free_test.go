package wire

import (
	"errors"
	"testing"

	commonv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/common/v1"
	telemetryv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/telemetry/v1"
	"github.com/Kup1ng/CtrlZ-Shared/reason"
)

func freeBatch(mut func(*telemetryv1.CountersBatch)) *telemetryv1.CountersBatch {
	b := &telemetryv1.CountersBatch{
		BatchId: 1, BucketStart: telNow - 600,
		Free: []*telemetryv1.FreeCounter{
			{Protocol: commonv1.Protocol_PROTOCOL_UDP, Outcome: telemetryv1.FreeOutcome_FREE_OUTCOME_ANSWERED, Rcode: 0, Count: 10},
			{Protocol: commonv1.Protocol_PROTOCOL_UDP, Outcome: telemetryv1.FreeOutcome_FREE_OUTCOME_HOP, Rcode: 0, Count: 1},
			{Protocol: commonv1.Protocol_PROTOCOL_TCP, Outcome: telemetryv1.FreeOutcome_FREE_OUTCOME_ANSWERED, Rcode: 3, Count: 2},
		},
	}
	if mut != nil {
		mut(b)
	}
	return b
}

func TestValidateFreeCounters(t *testing.T) {
	item := func(p commonv1.Protocol, o telemetryv1.FreeOutcome, rc uint32, n uint64) *telemetryv1.FreeCounter {
		return &telemetryv1.FreeCounter{Protocol: p, Outcome: o, Rcode: rc, Count: n}
	}
	udp, tcp := commonv1.Protocol_PROTOCOL_UDP, commonv1.Protocol_PROTOCOL_TCP
	ans := telemetryv1.FreeOutcome_FREE_OUTCOME_ANSWERED
	cases := []struct {
		name string
		m    func(*telemetryv1.CountersBatch)
		ok   bool
	}{
		{"good", nil, true},
		{"no free part", func(b *telemetryv1.CountersBatch) { b.Free = nil; b.BucketStart = 7 }, true},
		{"count at 2^63-1", func(b *telemetryv1.CountersBatch) { b.Free[0].Count = MaxFreeCount }, true},
		{"count above 2^63-1", func(b *telemetryv1.CountersBatch) { b.Free[0].Count = MaxFreeCount + 1 }, false},
		{"rcode 23 (BADCOOKIE)", func(b *telemetryv1.CountersBatch) { b.Free[0].Rcode = 23 }, true},
		{"rcode 24", func(b *telemetryv1.CountersBatch) { b.Free[0].Rcode = 24 }, false},
		{"DoT", func(b *telemetryv1.CountersBatch) { b.Free[0].Protocol = commonv1.Protocol_PROTOCOL_DOT }, false},
		{"DoH3", func(b *telemetryv1.CountersBatch) { b.Free[0].Protocol = commonv1.Protocol_PROTOCOL_DOH3 }, false},
		{"protocol unspecified", func(b *telemetryv1.CountersBatch) { b.Free[0].Protocol = 0 }, false},
		{"outcome unspecified", func(b *telemetryv1.CountersBatch) { b.Free[0].Outcome = 0 }, false},
		{"outcome 15", func(b *telemetryv1.CountersBatch) { b.Free[0].Outcome = 15 }, false},
		{"outcome myip", func(b *telemetryv1.CountersBatch) { b.Free[0].Outcome = telemetryv1.FreeOutcome_FREE_OUTCOME_MYIP }, true},
		{"same key twice", func(b *telemetryv1.CountersBatch) { b.Free = append(b.Free, item(udp, ans, 0, 1)) }, false},
		{"same outcome, other rcode", func(b *telemetryv1.CountersBatch) { b.Free = append(b.Free, item(udp, ans, 2, 1)) }, true},
		{"bucket not a multiple of 300", func(b *telemetryv1.CountersBatch) { b.BucketStart = telNow - 601 }, false},
		{"bucket 25 h old", func(b *telemetryv1.CountersBatch) { b.BucketStart = telNow - MaxFreeAge }, true},
		{"bucket 25 h and 5 min old", func(b *telemetryv1.CountersBatch) { b.BucketStart = telNow - MaxFreeAge - 300 }, false},
		{"bucket 5 min ahead", func(b *telemetryv1.CountersBatch) { b.BucketStart = telNow + 300 }, true},
		{"bucket 10 min ahead", func(b *telemetryv1.CountersBatch) { b.BucketStart = telNow + 600 }, false},
		{"negative bucket", func(b *telemetryv1.CountersBatch) { b.BucketStart = -300 }, false},
	}
	for _, c := range cases {
		err := ValidateFreeCounters(freeBatch(c.m), telNow)
		if (err == nil) != c.ok {
			t.Errorf("%s: err = %v, want ok=%v", c.name, err, c.ok)
		}
	}

	// 672 items, one more than every (protocol, outcome, rcode) a node can count.
	full := &telemetryv1.CountersBatch{BucketStart: telNow}
	for _, p := range []commonv1.Protocol{udp, tcp} {
		for o := telemetryv1.FreeOutcome(1); o <= 14; o++ {
			for rc := uint32(0); rc <= MaxFreeRCode; rc++ {
				full.Free = append(full.Free, item(p, o, rc, 1))
			}
		}
	}
	if len(full.Free) != MaxFreeCounters {
		t.Fatalf("%d items, want %d", len(full.Free), MaxFreeCounters)
	}
	if err := ValidateFreeCounters(full, telNow); err != nil {
		t.Errorf("672 items: %v", err)
	}
	full.Free = append(full.Free, item(udp, ans, 0, 1))
	if ValidateFreeCounters(full, telNow) == nil {
		t.Error("673 items accepted")
	}
}

// The free part is judged apart from the rest of the batch: a bad free part must
// not turn a good counters part into a refusal, and a free-only batch is a batch.
func TestCountersBatchWithAFreePart(t *testing.T) {
	if err := ValidateCountersBatch(freeBatch(nil), telNow); err != nil {
		t.Errorf("a free-only batch: %v", err)
	}
	// A free part that fails ValidateFreeCounters does not fail ValidateCountersBatch.
	bad := freeBatch(func(b *telemetryv1.CountersBatch) { b.Free[0].Count = MaxFreeCount + 1 })
	if ValidateFreeCounters(bad, telNow) == nil {
		t.Fatal("setup: the free part should fail")
	}
	if err := ValidateCountersBatch(bad, telNow); err != nil {
		t.Errorf("a bad free part failed the whole batch: %v", err)
	}
	if ValidateCountersBatch(&telemetryv1.CountersBatch{BucketStart: telNow}, telNow) == nil {
		t.Error("a batch with neither counters nor free accepted")
	}
	// Through the door of the upload stream.
	if err := ValidateTelemetryMessage(freeBatch(nil), telNow); err != nil {
		t.Errorf("door: %v", err)
	}
	// A bad free part is refused at the door with the typed error, so a handler that
	// calls only the door cannot add it into free_dns, and one that follows 5.2a can
	// tell it from a batch that is bad as a whole.
	err := ValidateTelemetryMessage(bad, telNow)
	if !errors.Is(err, ErrFreePartInvalid) {
		t.Fatalf("door on a bad free part: %v", err)
	}
	if reason.CodeOf(err) != reason.BadEnum {
		t.Errorf("the free part's reason is lost: %q", reason.CodeOf(err))
	}
	bad.Free = nil
	bad.Counters = []*telemetryv1.Counter{{EndpointId: b(16, 1), Protocol: commonv1.Protocol_PROTOCOL_UDP, Action: commonv1.Action_ACTION_BLOCK, Count: 1}}
	if err := ValidateTelemetryMessage(bad, telNow); err != nil {
		t.Errorf("the batch with its free part cleared: %v", err)
	}
	// A counters batch that is bad in itself is not the free-part error.
	if err := ValidateTelemetryMessage(&telemetryv1.CountersBatch{BucketStart: -1}, telNow); err == nil || errors.Is(err, ErrFreePartInvalid) {
		t.Errorf("a bad counters part: %v", err)
	}
}

// Every FreeOutcome the proto defines has a place in the validator, so a value added
// to the enum without a decision here fails the build.
func TestEveryFreeOutcomeIsAccepted(t *testing.T) {
	n := 0
	for v := range telemetryv1.FreeOutcome_name {
		if v == 0 {
			continue
		}
		n++
		b := freeBatch(func(b *telemetryv1.CountersBatch) {
			b.Free = []*telemetryv1.FreeCounter{{Protocol: commonv1.Protocol_PROTOCOL_UDP, Outcome: telemetryv1.FreeOutcome(v), Count: 1}}
		})
		if err := ValidateFreeCounters(b, telNow); err != nil {
			t.Errorf("outcome %d: %v", v, err)
		}
	}
	if n != 14 {
		t.Errorf("%d outcomes, section 12 lists 14 and MaxFreeCounters is built on 14", n)
	}
}
