package catalogtest_test

import (
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store/catalogtest"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

// TestNoDefinerBodyRunsDynamicSQL is db-r18-5 (D64 lint-residual-shapes, the cheap closure). The live
// database has none, and the check reports each form a definer body can take: a plpgsql EXECUTE, one in a
// function of another schema that runs as its owner, one in a function owned by ctrlz_auth that is not
// SECURITY DEFINER, and a language the checks cannot read. A static body is what lets the lock-order,
// reach and trail checks say what a function writes.
func TestNoDefinerBodyRunsDynamicSQL(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	if got, err := catalogtest.DefinerDynamicSQL(h.ctx, h.super); err != nil || len(got) != 0 {
		t.Fatalf("the migrated database holds definer bodies that run dynamic SQL: %v %v", got, err)
	}
	for _, sql := range []string{
		`CREATE FUNCTION ctrlz_fn.planted_dynamic() RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $f$ BEGIN EXECUTE 'UPDATE ctrlz.sessions SET revoked_at = now()'; END $f$`,
		`CREATE FUNCTION ctrlz_fn.planted_dynamic_lower() RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $f$ BEGIN execute format('DELETE FROM ctrlz.%I', 'sessions'); END $f$`,
		`CREATE FUNCTION ctrlz.planted_definer_elsewhere() RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $f$ BEGIN EXECUTE 'SELECT 1'; END $f$`,
		`CREATE FUNCTION ctrlz.planted_owned_by_auth() RETURNS void LANGUAGE plpgsql SET search_path = pg_catalog AS $f$ BEGIN EXECUTE 'SELECT 1'; END $f$`,
		`ALTER FUNCTION ctrlz.planted_owned_by_auth() OWNER TO ctrlz_auth`,
		`CREATE FUNCTION ctrlz_fn.planted_static() RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $f$ BEGIN PERFORM 1; END $f$`,
		`CREATE FUNCTION ctrlz_fn.planted_c_language() RETURNS int LANGUAGE internal SECURITY DEFINER AS 'int4pl' STRICT`,
	} {
		if _, err := h.super.Exec(h.ctx, sql); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	got, err := catalogtest.DefinerDynamicSQL(h.ctx, h.super)
	if err != nil {
		t.Fatal(err)
	}
	all := strings.Join(got, "\n")
	for _, want := range []string{"planted_dynamic()", "planted_dynamic_lower()", "planted_definer_elsewhere()", "planted_owned_by_auth()", "planted_c_language()"} {
		if !strings.Contains(all, want) {
			t.Errorf("the check did not report %s:\n%s", want, all)
		}
	}
	if strings.Contains(all, "planted_static()") {
		t.Errorf("the check reported a static body:\n%s", all)
	}
}
