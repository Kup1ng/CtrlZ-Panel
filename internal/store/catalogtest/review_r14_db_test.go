package catalogtest_test

import (
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store/catalogtest"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

// checkByID returns the catalog check with the spec's number.
func checkByID(t *testing.T, id string) checkFn {
	t.Helper()
	for _, ck := range catalogtest.Checks() {
		if ck.ID == id {
			return ck.Run
		}
	}
	t.Fatalf("no catalog check %s", id)
	return nil
}

// TestTriggerStateIsRead is db-r14-2. Check 11 listed only the triggers whose tgenabled is 'O', so
// an unlisted trigger that is ENABLE ALWAYS or ENABLE REPLICA was in neither the live list nor the
// golden and nothing was reported, while pg_get_triggerdef does not carry the state and the
// definitions could not show it. The trigger fires under session_replication_role = replica, the
// mode in which every ordinary guard is skipped. Every non-internal trigger of ctrlz now has to be
// 'O', whatever its function, and an unlisted one is reported by its definition whatever its state.
func TestTriggerStateIsRead(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	check := checkByID(t, "11")
	if v := runCheck(t, h, check, h.fx); len(v) != 0 {
		t.Fatalf("the migrated database is not clean for check 11: %v", v)
	}
	// revocation_stays() is a listed helper, so the only thing wrong with these triggers is the
	// one the case names.
	plant := `CREATE TRIGGER zz_probe BEFORE INSERT ON ctrlz.sessions FOR EACH ROW EXECUTE FUNCTION ctrlz.revocation_stays()`
	for _, m := range []struct {
		name string
		want []string
		sql  []string
	}{
		{"an unlisted trigger, enabled for origin", []string{"zz_probe"}, []string{plant}},
		{"an unlisted trigger, ENABLE ALWAYS", []string{"zz_probe", "ENABLE ALWAYS (A)"}, []string{plant, `ALTER TABLE ctrlz.sessions ENABLE ALWAYS TRIGGER zz_probe`}},
		{"an unlisted trigger, ENABLE REPLICA", []string{"zz_probe", "ENABLE REPLICA (R)"}, []string{plant, `ALTER TABLE ctrlz.sessions ENABLE REPLICA TRIGGER zz_probe`}},
		// The definition of a listed trigger is unchanged by ENABLE ALWAYS, which is why the state has its own line.
		{"a listed guard, ENABLE ALWAYS", []string{"revocation_stays on sessions", "ENABLE ALWAYS (A)"}, []string{`ALTER TABLE ctrlz.sessions ENABLE ALWAYS TRIGGER revocation_stays`}},
		{"a listed guard, ENABLE REPLICA", []string{"revocation_stays on sessions", "ENABLE REPLICA (R)"}, []string{`ALTER TABLE ctrlz.sessions ENABLE REPLICA TRIGGER revocation_stays`}},
		{"a listed guard, disabled", []string{"revocation_stays on sessions", "disabled (D)"}, []string{`ALTER TABLE ctrlz.sessions DISABLE TRIGGER revocation_stays`}},
		{"an exempt trigger, ENABLE ALWAYS", []string{"credential_gen_bump on users", "ENABLE ALWAYS (A)"}, []string{`ALTER TABLE ctrlz.users ENABLE ALWAYS TRIGGER credential_gen_bump`}},
	} {
		t.Run(m.name, func(t *testing.T) {
			v := strings.Join(runCheck(t, h, check, h.fx, m.sql...), "\n")
			for _, w := range m.want {
				if !strings.Contains(v, w) {
					t.Errorf("check 11 did not report %q; it said %q", w, v)
				}
			}
		})
	}
}
