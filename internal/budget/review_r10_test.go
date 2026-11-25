package budget_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/budget"
)

// TestEveryDoorHasARecoveryScopeAndACodeScope is tenant-r10-2 as a property of the registry (rule 6, budget-keying).
// The code of the second factor was counted per door in round 9 and the recovery code stayed on one scope keyed on
// the account alone, so a holder of the password (or of the SIM) filled the owner's recovery window with five junk
// codes every fifteen minutes. A member of a CeilingGroup names its Door; each door has exactly one scope for the
// code and exactly one for the recovery code, keyed the same way, so a scope charged from more than one door cannot
// be added without this test saying so.
func TestEveryDoorHasARecoveryScopeAndACodeScope(t *testing.T) {
	code := map[string]budget.Bucket{}
	rec := map[string]budget.Bucket{}
	for _, b := range budget.All() {
		if b.Layer != budget.Throttle || b.CeilingGroup == "" {
			continue
		}
		if b.Door == "" {
			t.Errorf("%s is in ceiling group %q and names no door: a scope that more than one door can charge is one window that a holder of any single proof can fill", b.Name, b.CeilingGroup)
			continue
		}
		m := code
		if strings.HasPrefix(b.Name, "recovery_") {
			m = rec
		}
		if prev, dup := m[b.Door]; dup {
			t.Errorf("%s and %s count the same thing on the %s door", prev.Name, b.Name, b.Door)
		}
		m[b.Door] = b
	}
	if len(code) < 3 || len(rec) < 3 {
		t.Fatalf("doors: %d code scopes, %d recovery scopes, want the password, SMS and marker doors of each", len(code), len(rec))
	}
	for door, c := range code {
		r, ok := rec[door]
		if !ok {
			t.Errorf("the %s door has a scope for the code (%s) and none for the recovery code", door, c.Name)
			continue
		}
		if r.Source != c.Source || !reflect.DeepEqual(r.Parts, c.Parts) {
			t.Errorf("%s is keyed differently from %s: the recovery code of a door is counted on that door's key and on nothing wider", r.Name, c.Name)
		}
	}
	for door, r := range rec {
		if _, ok := code[door]; !ok {
			t.Errorf("the %s door has a scope for the recovery code (%s) and none for the code", door, r.Name)
		}
	}
}
