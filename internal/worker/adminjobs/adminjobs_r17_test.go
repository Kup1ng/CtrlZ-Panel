package adminjobs_test

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/safego"
	"github.com/Kup1ng/CtrlZ-Panel/internal/worker/adminjobs"
)

// sms-r17-17: a poll of the admin job loop keeps its panic, so the loop goes on at the next poll (every
// handler is safe to run again) and the process does not end under the SMS rows in flight.
func TestAPanicInOneAdminJobPassStaysWithThatPass(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	escaped := func() (out bool) {
		defer func() { out = recover() != nil }() // the test's own: a missing guard fails here
		adminjobs.KeptPass(context.Background(), log)
		return false
	}()
	if escaped {
		t.Fatal("the panic left the pass")
	}
	if strings.Count(buf.String(), safego.Msg) != 1 {
		t.Errorf("the panic was not logged once: %s", buf.String())
	}
}
