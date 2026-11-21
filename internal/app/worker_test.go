package app_test

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/app"
	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testwait"
)

// queueOTP puts a sealed code for a phone in the queue, the way auth_otp_issue
// does, and returns its id.
func queueOTP(t *testing.T, ctx context.Context, d *testpg.DB, ring *keyring.Ring, phone, code string) uuid.UUID {
	t.Helper()
	ct, err := sms.SealOTP(ring, phone, "login", sms.OTPDelivery{Template: "otp", Locale: "fa", Code: secret.New(code)})
	if err != nil {
		t.Fatal(err)
	}
	tenant := d.Store(ctx, t, store.RoleTenant)
	res, err := tenant.Auth().OTPIssue(ctx, phone, "login", []byte("not-a-real-hash-0123456789abcdef"), ct, netip.MustParseAddr("198.51.100.7"), false)
	if err != nil || !res.Allowed {
		t.Fatalf("OTPIssue: %+v %v", res, err)
	}
	return res.ID
}

func plantNoop(t *testing.T, ctx context.Context, d *testpg.DB) {
	t.Helper()
	id := uuid.Must(uuid.NewV7())
	if err := d.Exec(ctx, `INSERT INTO ctrlz.sms_gateways (id, provider, role) VALUES ($1, 'noop', 'primary')`, id); err != nil {
		t.Fatal(err)
	}
	if err := d.Exec(ctx, `INSERT INTO ctrlz.sms_provider_templates (gateway_id, key, locale, provider_template_id, param_names) VALUES ($1, 'otp', 'fa', '1', '{CODE}')`, id); err != nil {
		t.Fatal(err)
	}
}

func sealed(t *testing.T, ctx context.Context, d *testpg.DB, id uuid.UUID) bool {
	t.Helper()
	var ct []byte
	if err := d.Scan(ctx, `SELECT delivery_ct FROM ctrlz.otp_challenges WHERE id = $1`, []any{id}, &ct); err != nil {
		t.Fatal(err)
	}
	return ct != nil
}

// TestWorkerRoleSendsQueuedSMS runs the real worker role: it reads its key files,
// opens the database as ctrlz_worker, picks up an OTP that was queued, and
// writes it through the noop gateway to the file a test reads. It stops on cancel.
func TestWorkerRoleSendsQueuedSMS(t *testing.T) {
	c := testpg.Need(t, cluster)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	d := c.NewDB(ctx, t)
	plantNoop(t, ctx, d)

	dir := keyDir(t, keyring.DomainSMSCred, keyring.DomainOTPDelivery)
	ring, err := keyring.Load(dir, keyring.DomainSMSCred, keyring.DomainOTPDelivery)
	if err != nil {
		t.Fatal(err)
	}
	const phone, code = "+989121234567", "135790"
	id := queueOTP(t, ctx, d, ring, phone, code)

	out := filepath.Join(t.TempDir(), "sms.jsonl")
	vars := dbEnv(t, d, "ctrlz_worker")
	vars["CTRLZ_KEK_DIR"] = dir
	vars["CTRLZ_NOOP_SMS_FILE"] = out
	_, stop, log := start(t, app.RoleWorker, vars)

	if !testwait.Holds(15*time.Second, 200*time.Millisecond, func() bool { return !sealed(t, ctx, d, id) }) {
		t.Fatalf("the worker did not send within 15 s:\n%s", log.String())
	}
	b, err := os.ReadFile(out)
	if err != nil || !strings.Contains(string(b), code) || !strings.Contains(string(b), phone) {
		t.Errorf("noop file: %q %v", b, err)
	}

	// A second code queued while it runs goes out on the notification or the poll.
	id2 := queueOTP(t, ctx, d, ring, "+989127654321", "864200")
	if !testwait.Holds(10*time.Second, 200*time.Millisecond, func() bool { return !sealed(t, ctx, d, id2) }) {
		t.Error("a code queued while the worker runs was not sent")
	}

	if err := stop(); err != nil {
		t.Errorf("stop: %v", err)
	}
	logs := log.String()
	if !strings.Contains(logs, "worker loops started") {
		t.Errorf("the loops did not announce themselves: %s", logs)
	}
	// 8.6: no code and no number in the log.
	for _, bad := range []string{code, "864200", "989121234567", "989127654321", "0912123"} {
		if strings.Contains(logs, bad) {
			t.Errorf("the log holds %q", bad)
		}
	}
}

// TestWorkerInProductionTreatsNoopAsDisabled is 9.3: a production start with a
// noop gateway in role primary raises an alert and sends nothing.
func TestWorkerInProductionTreatsNoopAsDisabled(t *testing.T) {
	c := testpg.Need(t, cluster)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	d := c.NewDB(ctx, t)
	plantNoop(t, ctx, d)

	dir := keyDir(t, keyring.DomainSMSCred, keyring.DomainOTPDelivery)
	ring, _ := keyring.Load(dir, keyring.DomainSMSCred, keyring.DomainOTPDelivery)
	id := queueOTP(t, ctx, d, ring, "+989121234567", "135790")

	vars := dbEnv(t, d, "ctrlz_worker")
	vars["CTRLZ_KEK_DIR"] = dir
	vars["CTRLZ_ENV"] = "production"
	_, stop, log := start(t, app.RoleWorker, vars)

	var alerts int
	if !testwait.Holds(15*time.Second, 200*time.Millisecond, func() bool {
		_ = d.Scan(ctx, `SELECT count(*) FROM ctrlz.alerts WHERE kind = 'sms_gateway' AND params ->> 'code' = 'noop_in_production'`, nil, &alerts)
		return alerts > 0
	}) || alerts != 1 {
		t.Fatalf("no alert for a noop gateway in production (%d):\n%s", alerts, log.String())
	}
	if !sealed(t, ctx, d, id) && !gaveUp(t, ctx, d, id) {
		t.Error("the code left the queue although no gateway could send it")
	}
	if err := stop(); err != nil {
		t.Errorf("stop: %v", err)
	}
	// And the noop file cannot even be configured in production.
	if _, err := app.LoadConfig(app.RoleWorker, env(map[string]string{"CTRLZ_ENV": "production", "CTRLZ_NOOP_SMS_FILE": "/tmp/x"})); err == nil {
		t.Error("CTRLZ_NOOP_SMS_FILE accepted in production")
	}
}

// gaveUp is true when the worker ended the row after its attempts (then the
// sealed code is gone but nothing was delivered): the delivery log has no
// accepted row.
func gaveUp(t *testing.T, ctx context.Context, d *testpg.DB, id uuid.UUID) bool {
	t.Helper()
	var accepted int
	if err := d.Scan(ctx, `SELECT count(*) FROM ctrlz.sms_deliveries WHERE source_id = $1 AND outcome = 'accepted'`, []any{id}, &accepted); err != nil {
		t.Fatal(err)
	}
	return accepted == 0
}

// TestWorkerRefusesToStartWithoutItsKeys: the worker needs sms_cred and
// otp_delivery, and says which is missing.
func TestWorkerRefusesToStartWithoutItsKeys(t *testing.T) {
	dir := keyDir(t, keyring.DomainSMSCred) // otp_delivery missing
	_, err := runRole(t, app.RoleWorker, map[string]string{"CTRLZ_ENV": "production", "CTRLZ_KEK_DIR": dir})
	if err == nil || !strings.Contains(err.Error(), "otp_delivery") {
		t.Errorf("err = %v", err)
	}
}
