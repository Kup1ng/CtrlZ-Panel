package session

import (
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// rowOf is the 3.5 table of what a reauth must present, written out a second time and as sets of proofs, so
// that WindowSurvives (a bit comparison) is checked against the table as the spec words it and not against
// itself. The row for neither factor is the SMS code.
func rowOf(f Factors) map[string]bool {
	switch {
	case f.Password && f.TOTP:
		return map[string]bool{"password": true, "totp": true}
	case f.Password:
		return map[string]bool{"password": true}
	case f.TOTP:
		return map[string]bool{"totp": true}
	}
	return map[string]bool{"sms": true}
}

// survivesByTheTable is the sentence of 3.5 as a predicate: a window earned under one row satisfies another
// when every proof the other asks for was asked of the first, and an SMS code is the lowest bar, which any
// proof exceeds. ("SMS never satisfies reauth when a password or TOTP exists.")
func survivesByTheTable(before, after Factors) bool {
	ra := rowOf(after)
	if ra["sms"] {
		return true
	}
	rb := rowOf(before)
	for k := range ra {
		if !rb[k] {
			return false
		}
	}
	return true
}

func allFactors() []Factors {
	return []Factors{{}, {Password: true}, {TOTP: true}, {Password: true, TOTP: true}}
}

// TestWindowSurvivesIsTheTableOf35 walks every pair of states: the function and the spec's table agree, and
// the cases the finding names are in it (primitives-r11-4).
func TestWindowSurvivesIsTheTableOf35(t *testing.T) {
	for _, b := range allFactors() {
		for _, a := range allFactors() {
			if got, want := WindowSurvives(b, a), survivesByTheTable(b, a); got != want {
				t.Errorf("window earned under %+v, row now %+v: survives %v, the table says %v", b, a, got, want)
			}
		}
	}
	if WindowSurvives(Factors{}, Factors{Password: true}) {
		t.Error("a window earned by an SMS code survives the first password")
	}
	if WindowSurvives(Factors{TOTP: true}, Factors{Password: true, TOTP: true}) {
		t.Error("a window earned by a code survives the first password of a TOTP-only account")
	}
	if !WindowSurvives(Factors{Password: true}, Factors{Password: true}) {
		t.Error("a password change ended the window of an account that had one")
	}
}

// TestEveryEventOverEveryFactorStateKeepsOrEndsTheWindowByTheBar walks the pure decision: every event, every
// state before and every state after, with and without the caller's word about the factors before. An event
// that sets or clears keeps doing so; an event that keeps does it only when the bar did not rise, and an event
// that can change the factors and was not told what they were fails closed.
func TestEveryEventOverEveryFactorStateKeepsOrEndsTheWindowByTheBar(t *testing.T) {
	// The events that change which factors an account has, named here and not read from the table: each must
	// either end the window by its fate or be marked as one whose bar is compared, or a row that loses the
	// mark would pass a test that reads the mark.
	changesFactors := map[Event]bool{EventPasswordChange: true, EventTOTPEnable: true, EventTOTPDisable: true}
	for _, ev := range Events() {
		rule, ok := windowFates(ev)
		if !ok {
			t.Fatalf("event %d has no declared fate", ev)
		}
		if changesFactors[ev] && rule.fate == WindowKeep && !rule.factors {
			t.Errorf("event %d changes the factors, keeps the window and is not marked to compare the bar", ev)
		}
		for _, b := range allFactors() {
			for _, a := range allFactors() {
				b := b
				got := reauthModeFor(ev, &b, a)
				switch {
				case rule.fate == WindowSet:
					if got != store.ReauthSet {
						t.Errorf("event %d set the window and it is %s", ev, got)
					}
				case rule.fate != WindowKeep:
					if got != store.ReauthClear {
						t.Errorf("event %d (no fate to keep) gives %s, want clear", ev, got)
					}
				case !rule.factors:
					if got != store.ReauthKeep {
						t.Errorf("event %d keeps the window by its table and it is %s", ev, got)
					}
				default:
					want := store.ReauthClear
					if survivesByTheTable(b, a) {
						want = store.ReauthKeep
					}
					if got != want {
						t.Errorf("event %d, factors %+v then %+v: %s, want %s", ev, b, a, got, want)
					}
				}
			}
			// The caller said nothing about the factors before.
			if rule.fate == WindowKeep && rule.factors {
				if got := reauthModeFor(ev, nil, b); got != store.ReauthClear {
					t.Errorf("event %d with no word about the factors before keeps the window (%s)", ev, got)
				}
			}
		}
	}
}
