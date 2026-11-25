package app_test

import (
	"context"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/app"
)

// TestMigrateAnalyticsNeedsItsEnvironment holds the three variables the one-shot reads. The Compose file and
// this code name them separately, so a rename in only one place would otherwise show only in a live run; an
// empty value is the same failure as a missing one (an unset Compose substitution gives an empty string).
// The error is returned before any connection is tried, so the test needs no ClickHouse.
func TestMigrateAnalyticsNeedsItsEnvironment(t *testing.T) {
	full := map[string]string{
		"CTRLZ_CH_ADDR":          "clickhouse:9000",
		"CTRLZ_CH_USER":          "ctrlz_migrator",
		"CTRLZ_CH_PASSWORD_FILE": "/run/secrets/ch_migrator_password",
	}
	for name := range full {
		for _, how := range []string{"missing", "empty"} {
			vars := map[string]string{}
			for k, v := range full {
				vars[k] = v
			}
			if how == "empty" {
				vars[name] = ""
			} else {
				delete(vars, name)
			}
			if err := app.MigrateAnalytics(context.Background(), app.Options{Getenv: env(vars)}); err == nil {
				t.Errorf("%s %s: the one-shot went on without it", name, how)
			}
		}
	}
}
