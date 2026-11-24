package catalogtest_test

import (
	"context"
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store/catalogtest"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

// TestClockCheckCanFail applies, one at a time, the changes check 24 exists to
// stop (rule clock-source). Each must be reported by the check on its own, so a check
// that quietly stopped looking would fail here. The mutants of the rule itself are
// the first three: a timestamp column nobody gave a clock, a default that reads the
// wrong clock, and a definer function that reads two.
func TestClockCheckCanFail(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	run := func(sql ...string) []string {
		tx, err := h.super.Begin(h.ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(context.Background())
		for _, s := range sql {
			if _, err := tx.Exec(h.ctx, s); err != nil {
				t.Fatalf("mutation %.80q does not apply: %v", s, err)
			}
		}
		v, err := catalogtest.CheckClocks(h.ctx, tx, h.fx)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	if v := run(); len(v) != 0 {
		t.Fatalf("the migrated database is not clean for check 24: %v", v)
	}
	for _, m := range []struct {
		name, want string
		sql        []string
	}{
		{"a timestamp column nobody gave a clock", "sessions.probe_at (timestamp with time zone) has no clock",
			[]string{"ALTER TABLE ctrlz.sessions ADD COLUMN probe_at timestamptz"}},
		{"a date column nobody gave a clock", "otp_challenges.probe_day (date) has no clock",
			[]string{"ALTER TABLE ctrlz.otp_challenges ADD COLUMN probe_day date"}},
		{"an application-clock column defaults to now()", "sessions.last_seen_at is on the application clock and its DEFAULT reads the database clock",
			[]string{"ALTER TABLE ctrlz.sessions ALTER COLUMN last_seen_at SET DEFAULT now()"}},
		{"an application-clock column defaults to CURRENT_TIMESTAMP", "admin_sessions.created_at is on the application clock and its DEFAULT",
			[]string{"ALTER TABLE ctrlz.admin_sessions ALTER COLUMN created_at SET DEFAULT CURRENT_TIMESTAMP"}},
		{"a definer function reads two clocks", "zz_two_clocks: app-clock: sessions.idle_expires_at",
			[]string{`CREATE FUNCTION ctrlz_fn.zz_two_clocks() RETURNS integer LANGUAGE sql AS $$ SELECT count(*)::integer FROM ctrlz.sessions WHERE idle_expires_at > pg_catalog.now() $$`}},
		{"a definer function takes a time from Go", "zz_takes_time takes a timestamp with time zone",
			[]string{`CREATE FUNCTION ctrlz_fn.zz_takes_time(p timestamptz) RETURNS integer LANGUAGE sql AS $$ SELECT 1 $$`}},
		{"a definer function returns a time nobody mapped", "functions has no entry for zz_returns_time.x",
			[]string{`CREATE FUNCTION ctrlz_fn.zz_returns_time() RETURNS TABLE (x timestamptz) LANGUAGE sql AS $$ SELECT pg_catalog.now() $$`}},
		{"a registered column is gone", "clocks.yaml: sessions.reauth_at does not exist",
			[]string{"ALTER TABLE ctrlz.sessions DROP COLUMN reauth_at CASCADE"}},
	} {
		t.Run(m.name, func(t *testing.T) {
			v := run(m.sql...)
			if !strings.Contains(strings.Join(v, "\n"), m.want) {
				t.Errorf("check 24 did not report %q after %v; it said %v", m.want, m.sql, v)
			}
		})
	}
}
