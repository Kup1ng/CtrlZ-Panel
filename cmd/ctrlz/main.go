// Command ctrlz is the one binary of the Panel. The first argument picks the
// role it runs as:
//
//	ctrlz api        tenant-facing API and sessions   (database role ctrlz_tenant)
//	ctrlz admin      admin API                        (ctrlz_admin)
//	ctrlz worker     background jobs and sweeps       (ctrlz_worker, ctrlz_compiler)
//	ctrlz hub        node-facing hub                  (ctrlz_hub)
//	ctrlz migrate    apply database migrations, exit  (ctrlz_migrator)
//	ctrlz migrate-analytics   apply the ClickHouse migrations, exit (ClickHouse ctrlz_migrator)
//
//	ctrlz healthcheck URL   exit 0 if URL answers 200 (container healthchecks)
//	ctrlz keys derive       write the per-domain key files from kek_root (no database)
//	ctrlz rekey user_totp   re-encrypt TOTP seeds under the newest key (one-shot, worker role)
//	ctrlz declare-lost user_totp --key-number N --yes   clear seeds of a lost key (one-shot, worker role)
//	ctrlz ctrlz-admin ...   the admin command line (the same as running it as ctrlz-admin)
//
// One binary keeps the image small and the version of every role identical.
// The roles stay separate processes with separate credentials.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	_ "time/tzdata" // Asia/Tehran and friends, in an image with no zoneinfo

	"github.com/Kup1ng/CtrlZ-Panel/internal/admincli"
	"github.com/Kup1ng/CtrlZ-Panel/internal/app"
	"github.com/Kup1ng/CtrlZ-Panel/internal/migrate"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// The image has one binary and a ctrlz-admin link to it (spec 17.1), so the
	// admin command line is chosen by the name it was started under.
	if adminName(os.Args[0]) {
		return admincli.Run(ctx, args)
	}
	if len(args) == 0 {
		return usage()
	}

	if args[0] == "healthcheck" {
		if len(args) != 2 {
			return usage()
		}
		if err := app.HealthCheck(ctx, args[1]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return 0
	}
	switch args[0] {
	case "ctrlz-admin":
		// The image's entrypoint is ctrlz, so `docker compose run admin ctrlz-admin ...`
		// arrives here.
		return admincli.Run(ctx, args[1:])
	case "keys":
		return admincli.RunKeys(ctx, args[1:], admincli.Env{})
	case "rekey":
		return admincli.RunRekey(ctx, args[1:], admincli.Env{})
	case "declare-lost":
		return admincli.RunDeclareLost(ctx, args[1:], admincli.Env{})
	case "migrate-analytics":
		// Not a role: it has no Postgres connection and no listener. Compose runs it as a one-shot that
		// no service waits for, so a ClickHouse that is down or a migration that fails stops no login.
		return runMigrateAnalytics(ctx)
	}
	role, err := app.ParseRole(args[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return usage()
	}
	if err := app.Run(ctx, role, app.Options{}); err != nil {
		// Errors never carry secrets: configuration errors name variables,
		// not values, and store errors drop driver detail.
		fmt.Fprintf(os.Stderr, "ctrlz %s: %v\n", role, err)
		return 1
	}
	return 0
}

// runMigrateAnalytics applies the ClickHouse migrations as ctrlz_migrator. The address, the user and the
// path of the password file come from the environment; the password itself is only ever read from the file.
// It waits up to 10 minutes for the server and then fails, so that Compose's restart policy tries again.
func runMigrateAnalytics(ctx context.Context) int {
	addr, user, file := os.Getenv("CTRLZ_CH_ADDR"), os.Getenv("CTRLZ_CH_USER"), os.Getenv("CTRLZ_CH_PASSWORD_FILE")
	if addr == "" || user == "" || file == "" {
		fmt.Fprintln(os.Stderr, "ctrlz migrate-analytics: CTRLZ_CH_ADDR, CTRLZ_CH_USER and CTRLZ_CH_PASSWORD_FILE must be set")
		return 2
	}
	if err := migrate.RunAnalytics(ctx, addr, user, file, 10*time.Minute); err != nil {
		fmt.Fprintf(os.Stderr, "ctrlz migrate-analytics: %v\n", err)
		return 1
	}
	return 0
}

func usage() int {
	var names []string
	for _, r := range app.Roles() {
		names = append(names, string(r))
	}
	fmt.Fprintf(os.Stderr, "usage: ctrlz {%s}\n", strings.Join(names, "|"))
	fmt.Fprintln(os.Stderr, "       ctrlz healthcheck URL")
	fmt.Fprintln(os.Stderr, "       ctrlz migrate-analytics")
	fmt.Fprintln(os.Stderr, "       ctrlz keys derive [--dir DIR] [--rotate DOMAIN]")
	fmt.Fprintln(os.Stderr, "       ctrlz rekey <domain>")
	fmt.Fprintln(os.Stderr, "       ctrlz declare-lost user_totp --key-number N --yes")
	fmt.Fprintln(os.Stderr, "       ctrlz ctrlz-admin <command>")
	return 2
}

// adminName reports whether the binary was started as ctrlz-admin. On Windows
// the name carries .exe.
func adminName(argv0 string) bool {
	base := filepath.Base(argv0)
	return base == "ctrlz-admin" || base == "ctrlz-admin.exe"
}
