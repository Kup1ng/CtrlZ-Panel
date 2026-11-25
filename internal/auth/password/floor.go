package password

import (
	"context"
	"math/rand/v2"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/appclock"
)

// MaxJitter is the random extra added to every floor (spec 2.3).
const MaxJitter = 50 * time.Millisecond

// Timing is the clock behind Floor, replaceable so a test does not sleep.
type Timing struct {
	Now    func() time.Time
	Sleep  func(ctx context.Context, d time.Duration) error
	Jitter func() time.Duration
}

// RealTiming is the wall clock with up to MaxJitter of jitter. The jitter is not
// a secret, it only blurs the floor, so math/rand is enough.
func RealTiming() Timing {
	return Timing{
		Now: appclock.Now,
		Sleep: func(ctx context.Context, d time.Duration) error {
			t := time.NewTimer(d)
			defer t.Stop()
			select {
			case <-t.C:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		},
		Jitter: func() time.Duration { return rand.N(MaxJitter) },
	}
}

// Floor runs fn and returns no sooner than d plus up to MaxJitter after it was
// called, whatever fn returned (spec 2.3, 4.5). The floor sits above the slowest
// expected hash, so a fast failure (a wrong format, a refused throttle hit) and a
// slow one (an Argon2 run) cannot be told apart by their time. An fn that fails
// still waits: a database outage must not make a response quicker.
//
// If the request context ends while waiting, Floor returns at once with fn's
// result: nobody is left to measure.
//
// httpx.Floor wraps this for handlers. It lives here, with no HTTP in it,
// because the same floor serves the admin CLI's checks.
func Floor(ctx context.Context, d time.Duration, fn func(context.Context) error) error {
	return RealTiming().Floor(ctx, d, fn)
}

// Floor is Floor on this clock.
func (t Timing) Floor(ctx context.Context, d time.Duration, fn func(context.Context) error) error {
	start := t.Now()
	err := fn(ctx)
	wait := d + t.Jitter() - t.Now().Sub(start)
	if wait > 0 {
		_ = t.Sleep(ctx, wait)
	}
	return err
}
