package catalogtest_test

import (
	"context"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

// TestNoLargeObjectExists is the standing half of db-r16-15. The probes of
// TestNoLoginRoleHoldsTheAuditChainOrWatchesOthers show that no login role can make a large object
// (lo_from_bytea, lo_create, lo_open are refused with 42501 for each of them); this asks the database
// that none exists, since a large object lives in pg_largeobject, outside every table of ours, outside
// every retention sweep, and outlives the session that made it. The module has no use for them.
func TestNoLargeObjectExists(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	var n int
	if err := h.super.QueryRow(h.ctx, `SELECT count(*) FROM pg_catalog.pg_largeobject_metadata`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("%d large object(s) exist: nothing of ours makes one, so a role did, or a restore brought it", n)
	}
}

// TestNoSpellingOfPgNotifyWorksInAFunctionOfTheAuthRole is the construction half of db-r16-17. The text
// checks of rule no-notify (catalog check 32, the Go lint) judge the spellings they know, and a function
// call has more: a quoted identifier, a Unicode-escaped one (U&"pg\005Fnotify"), a call built at run time
// by EXECUTE. pg_notify is revoked from PUBLIC (family wal-writes-and-notifications), so a definer
// function owned by ctrlz_auth that reaches it by ANY spelling fails with 42501 the first time it runs,
// whatever its text says. The NOTIFY and LISTEN statements are keywords and cannot be spelled around,
// which is what the text checks read.
func TestNoSpellingOfPgNotifyWorksInAFunctionOfTheAuthRole(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	for name, body := range map[string]string{
		"a quoted identifier":     `PERFORM pg_catalog."pg_notify"('ctrlz_sms', '');`,
		"a Unicode escape":        `PERFORM pg_catalog.U&"pg\005Fnotify"('ctrlz_sms', '');`,
		"a call built at runtime": `EXECUTE 'SELECT pg_catalog.' || 'pg_' || 'notify(''ctrlz_sms'', '''')';`,
		"a search_path lookup":    `PERFORM pg_notify('ctrlz_sms', '');`,
	} {
		t.Run(name, func(t *testing.T) {
			fn := "zz_notify_" + strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(name, " ", "_"), "-", "_"))
			for _, sql := range []string{
				`CREATE FUNCTION ctrlz_fn.` + fn + `() RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $f$ BEGIN ` + body + ` END $f$`,
				`ALTER FUNCTION ctrlz_fn.` + fn + `() OWNER TO ctrlz_auth`,
			} {
				if _, err := h.super.Exec(h.ctx, sql); err != nil {
					t.Fatalf("%s: %v", sql, err)
				}
			}
			defer h.super.Exec(context.Background(), `DROP FUNCTION IF EXISTS ctrlz_fn.`+fn+`()`)
			_, err := h.super.Exec(h.ctx, `SELECT ctrlz_fn.`+fn+`()`)
			var pe *pgconn.PgError
			if !errors.As(err, &pe) || pe.Code != "42501" {
				t.Errorf("a definer function of ctrlz_auth that notifies (%s) ran: %v, want 42501", name, err)
			}
		})
	}
}
