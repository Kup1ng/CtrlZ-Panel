package smssend_test

import (
	"context"
	"strings"
	"time"
)

// startAndAwaitFirstDrain starts w.Run and returns when its FIRST drain has finished. It seeds one code for
// the other tenant before the start, so the first drain has something to send and logs "sms drained" when it
// returns (the line is written after Drain returns, in drainLogged). A request made after this can only be found
// by a poll, never by the drain that was already running: the sleep it replaces ("let Run finish its first
// drain") passed on a runner that was slow, with the new request found by the first drain and the poll
// property never tried (round 17, tenant-r17-18). It counts iterations and reads no clock.
func (r *rig) startAndAwaitFirstDrain(ctx context.Context, run func(context.Context) error) <-chan error {
	r.t.Helper()
	before := strings.Count(r.logs.String(), "sms drained")
	r.request(r.env.B.Phone)
	done := make(chan error, 1)
	go func() { done <- run(ctx) }()
	for i := 0; i < 3000; i++ {
		if strings.Count(r.logs.String(), "sms drained") > before {
			return done
		}
		time.Sleep(10 * time.Millisecond)
	}
	r.t.Fatal("the worker never finished its first drain")
	return done
}
