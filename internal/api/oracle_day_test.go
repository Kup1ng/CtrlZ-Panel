package api

import (
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/authtest/oracle"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

// TestTheOracleSnapshotDoesNotMoveWhenTheTehranDayTurns is the test of the fix to the CI failure
// of round 13: a run that crossed Tehran midnight read minus one row in every SMS scope the
// preparation had touched, for the one subject whose window straddled it, and the table of
// differences called that an oracle. The same keys and counts on the next day must read as no
// movement at all.
func TestTheOracleSnapshotDoesNotMoveWhenTheTehranDayTurns(t *testing.T) {
	f := newFrig(t, frigOpts{})
	f.env.Exec(t, `TRUNCATE ctrlz.sms_counters`)
	f.env.Exec(t, testpg.PlantCounters(`INSERT INTO ctrlz.sms_counters (day, scope, key, count, cost) VALUES
	  ((now() AT TIME ZONE 'Asia/Tehran')::date, 'phone', 'p1', 2, 0),
	  ((now() AT TIME ZONE 'Asia/Tehran')::date, 'ip', 'i1', 1, 0),
	  ((now() AT TIME ZONE 'Asia/Tehran')::date, 'global', 'all', 3, 0.5)`))
	before := oracle.Take(t, f.env)
	if len(before.SMS) != 3 {
		t.Fatalf("the snapshot saw %d scopes of SMS counters, want 3: %+v", len(before.SMS), before.SMS)
	}

	// Midnight: every count is now on the next day, as the writer of the next request would put it.
	f.env.Exec(t, testpg.PlantCounters(`UPDATE ctrlz.sms_counters SET day = day + 1`))
	after := oracle.Take(t, f.env)
	if sms, _, _ := after.Since(before); len(sms) != 0 {
		t.Errorf("the turn of the day moved the snapshot: %+v", sms)
	}

	// And a key counted on both days is one key, with the sum of both.
	f.env.Exec(t, testpg.PlantCounters(`INSERT INTO ctrlz.sms_counters (day, scope, key, count) VALUES ((now() AT TIME ZONE 'Asia/Tehran')::date, 'phone', 'p1', 1)`))
	got := oracle.Take(t, f.env).SMS["phone"]
	if got.Rows != 1 || got.Sum != 3 {
		t.Errorf("a key on two days read as %+v, want one row with a sum of 3", got)
	}
}
