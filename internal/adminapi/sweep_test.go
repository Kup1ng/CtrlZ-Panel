package adminapi

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// RunSweep is the admin service's own delete of old admin sessions (spec 10.4):
// the worker has no grant on the table, so if this loop stopped, nothing would
// say so and the table would grow for ever (review round 1, admin-r1-10).
func TestRunSweepRunsAtStartRepeatsAndStops(t *testing.T) {
	r := newRig(t)
	// A session that ended two days ago, and one that is live.
	r.adminSession(t)
	r.adminSession(t)
	r.env.Exec(t, `UPDATE ctrlz.admin_sessions SET absolute_expires_at = now() - interval '2 days',
	  idle_expires_at = now() - interval '2 days' WHERE id = (SELECT id FROM ctrlz.admin_sessions ORDER BY id LIMIT 1)`)
	if n := r.count(t, `SELECT count(*) FROM ctrlz.admin_sessions`); n != 2 {
		t.Fatalf("%d sessions planted", n)
	}

	var logs syncLog
	log := slog.New(slog.NewJSONHandler(&logs, nil))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); RunSweep(ctx, r.adm, log, 50*time.Millisecond) }()

	// Once at start: the old row goes without waiting for an hour.
	waitFor(t, 10*time.Second, "the first pass", func() bool { return r.count(t, `SELECT count(*) FROM ctrlz.admin_sessions`) == 1 })
	// On the tick: a row that ends later is swept by a later pass.
	r.env.Exec(t, `UPDATE ctrlz.admin_sessions SET revoked_at = now() - interval '2 days' WHERE true`)
	waitFor(t, 10*time.Second, "a later pass", func() bool { return r.count(t, `SELECT count(*) FROM ctrlz.admin_sessions`) == 0 })

	// On cancel the loop returns.
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("RunSweep did not stop when its context ended")
	}
	if strings.Contains(logs.String(), "failed") {
		t.Errorf("a healthy sweep logged a failure: %s", logs.String())
	}
}

// A store that cannot connect (the database is down or still starting, the case
// OpenLazy is for) is a logged class and a retry, never a crash or a hang: the
// sweep is tried again at the next tick, and a cancelled context ends it.
func TestRunSweepSurvivesAStoreThatCannotConnect(t *testing.T) {
	r := newRig(t)
	cfg := r.env.DB.StoreConfig(store.RoleAdmin)
	cfg.Port = 1 // nothing listens here
	cfg.ConnectTimeout = 200 * time.Millisecond
	lazy, err := store.OpenLazy(r.env.Ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(lazy.Close)

	var logs syncLog
	log := slog.New(slog.NewJSONHandler(&logs, nil))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); RunSweep(ctx, lazy, log, 50*time.Millisecond) }()
	waitFor(t, 10*time.Second, "the failure to be logged", func() bool { return strings.Contains(logs.String(), "admin session sweep failed") })
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("RunSweep did not stop")
	}
	// The log says the class only.
	if strings.Contains(logs.String(), "password") {
		t.Errorf("the sweep failure logged more than a class: %s", logs.String())
	}
}
