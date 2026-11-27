package hubtrust_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubtrust"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// flaky fails its first n inserts, as a database in a failover would.
type flaky struct {
	alerts
	fail int
}

func (f *flaky) HubAlert(ctx context.Context, sev string, k store.HubAlertKind, p map[string]string) error {
	if f.fail > 0 {
		f.fail--
		return errors.New("database unavailable")
	}
	return f.alerts.HubAlert(ctx, sev, k, p)
}

// GP-r1-6, GP-r1-9: a leaf written while the alert insert fails still gets its "restart chrony" alert on a later pass, and only
// one: chrony reads the files only at start, so a lost alert leaves the old leaf in force with nobody told.
func TestNTSAlertThatFailedIsRaisedOnALaterPass(t *testing.T) {
	now := time.Date(2026, 11, 26, 10, 0, 0, 0, time.UTC)
	al := &flaky{fail: 2}
	n := newNTS(t, now, al)
	ctx := context.Background()

	if wrote, err := n.Ensure(ctx); !wrote || err == nil {
		t.Fatalf("first pass: wrote %v, err %v; want the leaf written and the alert error", wrote, err)
	}
	// The leaf is now usable, so nothing is rewritten, but the alert is still owed (and fails once more).
	if wrote, err := n.Ensure(ctx); wrote || err == nil {
		t.Fatalf("second pass: wrote %v, err %v; want no write and the alert error", wrote, err)
	}
	if wrote, err := n.Ensure(ctx); wrote || err != nil || len(al.kinds) != 1 {
		t.Fatalf("third pass: wrote %v, err %v, alerts %d; want the alert raised once", wrote, err, len(al.kinds))
	}
	if wrote, err := n.Ensure(ctx); wrote || err != nil || len(al.kinds) != 1 {
		t.Fatalf("fourth pass raised another alert (wrote %v, err %v, alerts %d)", wrote, err, len(al.kinds))
	}
}

func newNTS(t *testing.T, now time.Time, al hubtrust.Alerter) *hubtrust.NTS {
	t.Helper()
	return &hubtrust.NTS{CA: newCA(t, now), Dir: t.TempDir(), Hosts: "hub.example.net", Now: func() time.Time { return now }, Alerts: al}
}

// GP-r1-3: a pass that cannot write the key must not delete the debt an earlier pass left. Pass 1 writes a leaf and its alert
// insert fails, so the marker stays; then the leaf becomes unusable and the key cannot be written (a non-empty directory sits at
// its path). The marker of pass 1 must still be on disk, and the alert is raised once the disk is repaired.
func TestNTSFailedKeyWriteKeepsTheDebtOfAnEarlierPass(t *testing.T) {
	now := time.Date(2026, 11, 26, 10, 0, 0, 0, time.UTC)
	al := &flaky{fail: 1}
	n := newNTS(t, now, al)
	ctx := context.Background()
	if wrote, err := n.Ensure(ctx); !wrote || err == nil {
		t.Fatalf("first pass: wrote %v, err %v; want the leaf written and the alert error", wrote, err)
	}
	owed := filepath.Join(n.Dir, ".nts-restart-owed")
	if _, err := os.Stat(owed); err != nil {
		t.Fatalf("the debt of the first pass is not on disk: %v", err)
	}

	key := filepath.Join(n.Dir, hubtrust.NTSKeyFile)
	if err := os.Remove(key); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(key, "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	if wrote, err := n.Ensure(ctx); wrote || err == nil {
		t.Fatalf("second pass: wrote %v, err %v; want the key write to fail", wrote, err)
	}
	if _, err := os.Stat(owed); err != nil {
		t.Fatalf("a failed key write deleted the debt of an earlier pass: %v", err)
	}

	if err := os.RemoveAll(key); err != nil {
		t.Fatal(err)
	}
	if _, err := n.Ensure(ctx); err != nil || len(al.kinds) != 1 {
		t.Fatalf("after the repair: err %v, alerts %d; want one alert", err, len(al.kinds))
	}
}
