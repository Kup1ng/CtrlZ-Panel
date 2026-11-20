package sweepbatch_test

import (
	"context"
	"errors"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/sweepbatch"
)

func TestDrainStopsWhenABatchIsShort(t *testing.T) {
	left, calls := 25, 0
	n, err := sweepbatch.Drain(context.Background(), sweepbatch.Plan{Size: 10, Max: 100}, func(_ context.Context, size int) (int, bool, error) {
		calls++
		take := min(size, left)
		left -= take
		return take, take == size, nil
	})
	if err != nil || n != 25 || calls != 3 {
		t.Fatalf("n %d calls %d err %v, want 25 3 nil", n, calls, err)
	}
}

func TestDrainTakesAtMostMaxBatches(t *testing.T) {
	calls := 0
	n, _ := sweepbatch.Drain(context.Background(), sweepbatch.Plan{Size: 5, Max: 4}, func(_ context.Context, size int) (int, bool, error) {
		calls++
		return size, true, nil
	})
	if calls != 4 || n != 20 {
		t.Fatalf("calls %d n %d, want 4 and 20", calls, n)
	}
}

func TestDrainKeepsWhatItDidAndReturnsTheFailure(t *testing.T) {
	boom := errors.New("boom")
	calls := 0
	n, err := sweepbatch.Drain(context.Background(), sweepbatch.Plan{Size: 5, Max: 10}, func(_ context.Context, size int) (int, bool, error) {
		calls++
		if calls == 3 {
			return 0, false, boom
		}
		return size, true, nil
	})
	if !errors.Is(err, boom) || n != 10 || calls != 3 {
		t.Fatalf("n %d calls %d err %v, want 10 3 boom", n, calls, err)
	}
}

func TestDrainStopsWhenTheContextEnds(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	n, err := sweepbatch.Drain(ctx, sweepbatch.Plan{Size: 5, Max: 100}, func(_ context.Context, size int) (int, bool, error) {
		calls++
		cancel()
		return size, true, nil
	})
	if err != nil || calls != 1 || n != 5 {
		t.Fatalf("calls %d n %d err %v, want 1 5 nil", calls, n, err)
	}
}
