package budget_test

import (
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/budget"
)

// TestEveryScopeAProofHolderChargesHasALongCeilingOrAReason is the enforcement of rule
// second-factor-ceiling (P1 auth review round 8, primitives-r8-4). A throttle scope keyed on an account or
// a session can only be charged by someone who already holds the first factor or a session cookie, so the
// 15 minute window is the only thing between that holder and a walk over a six digit code, and it refills
// 96 times a day. Every such scope must declare a ceiling that a window restart does not refill
// (CeilingMax, CeilingWindow), or say in NoCeiling why what it guesses at cannot be walked. A scope that
// a stranger can charge (a phone, a network, a username) is not in the class: a ceiling on it would be a
// lock-out lever for the stranger, which budget-keying forbids.
func TestEveryScopeAProofHolderChargesHasALongCeilingOrAReason(t *testing.T) {
	proofHolder := func(b budget.Bucket) bool {
		if b.Layer != budget.Throttle || b.Narrow {
			return false
		}
		for _, p := range b.Parts {
			switch p {
			case budget.PartUser, budget.PartAdmin, budget.PartUserSession, budget.PartAdminSession:
				continue
			default:
				return false
			}
		}
		return len(b.Parts) > 0
	}
	// A ceiling may also sit on a device marker that the handler has shown holds for the account: it is spent by
	// the owner's browser only, since a marker is made by a full sign-in as that account (round 9,
	// primitives-r9-4). Such a scope is not REQUIRED to declare one (login_marker counts passwords and has
	// none), but one that does is no lock-out lever for a stranger.
	markerCeiling := func(b budget.Bucket) bool {
		return b.Layer == budget.Throttle && b.Source == budget.Proof && len(b.Parts) == 1 && b.Parts[0] == budget.PartMarker && b.CeilingMax > 0
	}
	n := 0
	for _, b := range budget.All() {
		if markerCeiling(b) {
			if b.CeilingGroup == "" {
				t.Errorf("%s: a ceiling on a marker must say which group of scopes it is one run of guesses with, or a success elsewhere cannot end it", b.Name)
			}
			continue
		}
		if !proofHolder(b) {
			if b.CeilingMax != 0 || b.CeilingWindow != 0 || b.NoCeiling != "" {
				t.Errorf("%s is reachable by a stranger and declares a ceiling or a reason; a ceiling on it is a lock-out lever", b.Name)
			}
			continue
		}
		n++
		switch {
		case b.CeilingMax > 0 && b.NoCeiling != "":
			t.Errorf("%s declares a ceiling and a reason for having none", b.Name)
		case b.CeilingMax > 0:
			if b.CeilingMax < b.Max {
				t.Errorf("%s: a ceiling of %d is below the window's %d, so the window could never be used", b.Name, b.CeilingMax, b.Max)
			}
			// The database function takes a window of a day at most, and a ceiling shorter than a day
			// is the short window again.
			if b.CeilingWindow != 24*time.Hour {
				t.Errorf("%s: ceiling window %v, want a day", b.Name, b.CeilingWindow)
			}
			if !b.ResetOnSuccess {
				t.Errorf("%s: a ceiling counts the run since the last success, so the scope must reset on success", b.Name)
			}
		case b.NoCeiling == "":
			t.Errorf("%s is charged by a holder of the first factor or of a session and has neither a long ceiling nor a reason for none", b.Name)
		}
	}
	// The scopes of the finding are in the class: if the filter above ever stopped matching them the
	// test would pass on nothing.
	if n < 7 {
		t.Errorf("the class holds %d scopes, want at least the seven of totp_user, totp_session, reauth_session, reset_passkey_user, admin_reauth, admin_totp and admin_totp_session", n)
	}
	for _, name := range []string{"totp_user", "totp_session", "reauth_session", "admin_totp", "admin_totp_session"} {
		if b, ok := budget.FindScope(name); !ok || b.CeilingMax < 1 {
			t.Errorf("%s counts second-factor codes and has no long ceiling", name)
		}
	}
}
