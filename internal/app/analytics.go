package app

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/migrate"
)

// analyticsWait is how long the one-shot waits for ClickHouse to answer before it fails, so that Compose's
// restart policy tries again. Ten minutes covers a first start that is still creating its data directory.
const analyticsWait = 10 * time.Minute

// MigrateAnalytics applies the ClickHouse migrations as ctrlz_migrator. It is not a role: it has no Postgres
// connection, no listener and no LoadConfig, so ClickHouse being down or a migration failing stops no login
// (P5 3.4). The address, the user and the path of the password file come from the environment, read here
// with the other commands' environment (the lint lets only this package and admincli read it); the password
// itself is only ever read from the file.
func MigrateAnalytics(ctx context.Context, opts Options) error {
	if opts.Getenv == nil {
		opts.Getenv = os.Getenv
	}
	addr, user, file := opts.Getenv("CTRLZ_CH_ADDR"), opts.Getenv("CTRLZ_CH_USER"), opts.Getenv("CTRLZ_CH_PASSWORD_FILE")
	if addr == "" || user == "" || file == "" {
		return errors.New("CTRLZ_CH_ADDR, CTRLZ_CH_USER and CTRLZ_CH_PASSWORD_FILE must be set")
	}
	return migrate.RunAnalytics(ctx, addr, user, file, analyticsWait)
}
