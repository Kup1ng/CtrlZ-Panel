package app_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/app"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testwait"
)

// TestPostgresDownAtStart is the "Postgres down at start" row of 18.3: the HTTP
// roles come up anyway, /healthz answers, /readyz is 503 and a route that needs
// the database is a 503 with no detail, and when Postgres returns the same
// process becomes ready with no restart.
func TestPostgresDownAtStart(t *testing.T) {
	c := testpg.Need(t, cluster)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	d := c.NewDB(ctx, t)

	if err := c.StopPostgres(ctx); err != nil {
		t.Fatalf("stop postgres: %v", err)
	}
	restarted := false
	restart := func() {
		if !restarted {
			restarted = true
			if err := c.StartPostgres(context.Background()); err != nil {
				t.Errorf("start postgres: %v", err)
			}
		}
	}
	t.Cleanup(restart) // never leave the cluster down for the tests that follow

	for _, role := range []app.Role{app.RoleAPI, app.RoleAdmin} {
		t.Run(string(role), func(t *testing.T) {
			dbRole := map[app.Role]string{app.RoleAPI: "ctrlz_tenant", app.RoleAdmin: "ctrlz_admin"}[role]
			addr, _, log := start(t, role, dbEnv(t, d, dbRole))
			if code, _ := get(t, "http://"+addr+"/healthz"); code != 200 {
				t.Errorf("/healthz with the database down: %d", code)
			}
			if code, _ := get(t, "http://"+addr+"/readyz"); code != 503 {
				t.Errorf("/readyz with the database down: %d, want 503", code)
			}
			if out := log.String(); !strings.Contains(out, "database unreachable at start") {
				t.Errorf("the log does not say why the role is not ready: %s", out)
			}
			// The lazy open made no connection, so no line may say there is one (round 5, admin-r5-8).
			if out := log.String(); strings.Contains(out, "database connected") {
				t.Errorf("the log says the database is connected while it is down: %s", out)
			}
			restart()
			code := 0
			if !testwait.Holds(90*time.Second, time.Second, func() bool {
				code, _ = get(t, "http://"+addr+"/readyz")
				return code == 200
			}) {
				t.Fatalf("/readyz is still %d after Postgres came back", code)
			}
			// The next role starts with the database down again.
			if role == app.RoleAPI {
				restarted = false
				if err := c.StopPostgres(ctx); err != nil {
					t.Fatalf("stop postgres: %v", err)
				}
			}
		})
	}
}

// TestWrongRoleIsNotALazyStart: the lazy start is only for an unreachable
// server. A refused login still stops the process (see also
// TestWrongPasswordRefusesToStart).
// TestWrongPasswordRefusesToStart).
func TestWrongRoleIsNotALazyStart(t *testing.T) {
	c := testpg.Need(t, cluster)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	d := c.NewDB(ctx, t)
	// The admin password with the api role: the server refuses the login.
	vars := dbEnv(t, d, "ctrlz_admin")
	vars["CTRLZ_LISTEN"] = "127.0.0.1:0"
	var log syncBuffer
	if err := app.Run(ctx, app.RoleAPI, app.Options{Getenv: env(vars), Stdout: &log}); err == nil {
		t.Fatal("the api started with the admin's password")
	}
}
