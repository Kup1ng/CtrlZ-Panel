package catalogtest_test

import (
	"context"
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store/catalogtest"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

// TestCapsCheckCanFail applies, one at a time, the changes check 26 exists to stop (rule
// caps-and-endings): a cap column nobody registered, a function that compares a cap by
// hand, and an OTP issue that stopped using the shared expression. Each must be reported
// by the check on its own, so a check that quietly stopped looking would fail here.
func TestCapsCheckCanFail(t *testing.T) {
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
		v, err := catalogtest.CheckCaps(h.ctx, tx, h.fx)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	if v := run(); len(v) != 0 {
		t.Fatalf("the migrated database is not clean for check 26: %v", v)
	}
	for _, m := range []struct {
		name, want string
		sql        []string
	}{
		{"a cap column nobody registered", "unexpected system_settings.otp_cap_probe",
			[]string{`ALTER TABLE ctrlz.system_settings ADD COLUMN otp_cap_probe integer`}},
		{"a cap column on another table", "unexpected tenants.probe_cap",
			[]string{`ALTER TABLE ctrlz.tenants ADD COLUMN probe_cap integer`}},
		{"a function that compares a cap by hand", "compares a *_cap* value without ctrlz.cap_reached",
			[]string{`CREATE FUNCTION ctrlz_fn.zz_probe(p_count integer) RETURNS boolean LANGUAGE sql STABLE AS
$$ SELECT p_count < (SELECT s.otp_cap_ip FROM ctrlz.system_settings s) $$`}},
		{"the cap on the left", "compares a *_cap* value without ctrlz.cap_reached",
			[]string{`CREATE FUNCTION ctrlz_fn.zz_probe(p_count integer) RETURNS boolean LANGUAGE sql STABLE AS
$$ SELECT (SELECT s.otp_cap_ip FROM ctrlz.system_settings s) > p_count $$`}},
		// sms-r16-4, sms-r16-17: the guard reads no spelling. A limit called anything, and a comparison
		// through an alias, a CTE, BETWEEN or a variable, are met by what the database holds.
		{"a numeric column of system_settings that is neither a limit nor declared not to be", "unexpected system_settings.sms_burst_limit",
			[]string{`ALTER TABLE ctrlz.system_settings ADD COLUMN sms_burst_limit integer`}},
		{"a numeric column of the per-tenant entitlements nobody decided about", "unexpected tenant_entitlements.max_probe",
			[]string{`ALTER TABLE ctrlz.tenant_entitlements ADD COLUMN max_probe integer`}},
		{"a numeric column of the entitlement defaults nobody decided about", "unexpected entitlement_defaults.burst_probe",
			[]string{`ALTER TABLE ctrlz.entitlement_defaults ADD COLUMN burst_probe integer`}},
		{"a limit compared through a CTE alias", "names the limit sms_outbox_cap_daily and does not call ctrlz.cap_reached",
			[]string{`CREATE FUNCTION ctrlz_fn.zz_probe(p_count integer) RETURNS boolean LANGUAGE sql STABLE AS
$$ WITH s AS (SELECT sms_outbox_cap_daily AS c FROM ctrlz.system_settings) SELECT p_count < (SELECT c FROM s) $$`}},
		{"a limit compared with BETWEEN", "names the limit otp_cap_ip and does not call ctrlz.cap_reached",
			[]string{`CREATE FUNCTION ctrlz_fn.zz_probe(p_count integer) RETURNS boolean LANGUAGE sql STABLE AS
$$ SELECT p_count BETWEEN 0 AND (SELECT otp_cap_ip FROM ctrlz.system_settings) $$`}},
		{"a limit read into a variable", "names the limit otp_cap_phone and does not call ctrlz.cap_reached",
			[]string{`CREATE FUNCTION ctrlz_fn.zz_probe(p_count integer) RETURNS boolean LANGUAGE plpgsql STABLE AS
$$ DECLARE v integer; BEGIN SELECT otp_cap_phone INTO v FROM ctrlz.system_settings; RETURN p_count >= v; END $$`}},
		{"the OTP issue goes back to its own comparison", "compares a *_cap* value without ctrlz.cap_reached",
			[]string{`CREATE OR REPLACE FUNCTION ctrlz_fn.auth_otp_issue(p_phone text, p_purpose text, p_code_hash bytea, p_delivery_ct bytea, p_ip inet, p_trusted boolean)
RETURNS TABLE (id uuid, allowed boolean) LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS
$$ DECLARE v_cfg ctrlz.system_settings%ROWTYPE; v_n integer := 0; BEGIN
  SELECT * INTO v_cfg FROM ctrlz.system_settings;
  IF v_n >= v_cfg.otp_cap_global THEN RETURN QUERY SELECT NULL::uuid, false; END IF;
  RETURN QUERY SELECT NULL::uuid, false; END $$`}},
	} {
		t.Run(m.name, func(t *testing.T) {
			v := run(m.sql...)
			if !strings.Contains(strings.Join(v, "\n"), m.want) {
				t.Errorf("check 26 did not report %q after %v; it said %v", m.want, m.sql, v)
			}
		})
	}
	// The shared expression itself: a NULL cap is none, a missing counter is 0, a cap of
	// 0 is reached before the first spend, and the limit is reached at the cap.
	for _, c := range []struct {
		spent, cap string
		want       bool
	}{
		{"NULL", "NULL", false}, {"5", "NULL", false}, {"NULL", "0", true}, {"NULL", "1", false},
		{"2", "3", false}, {"3", "3", true}, {"4", "3", true}, {"0", "0", true},
	} {
		var got bool
		if err := h.super.QueryRow(h.ctx, `SELECT ctrlz.cap_reached(`+c.spent+`, `+c.cap+`)`).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != c.want {
			t.Errorf("cap_reached(%s, %s) = %v, want %v", c.spent, c.cap, got, c.want)
		}
	}
}
